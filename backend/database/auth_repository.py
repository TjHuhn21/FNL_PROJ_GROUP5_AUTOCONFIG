"""Authentication data access on MySQL (runtime account: SELECT/INSERT/UPDATE, and on
audit_log only SELECT/INSERT).

Persistence only: no password hashing, OTP generation, email or session checks here
(later phases). Every method:
  * checks its values first (auth_records): nothing is sent for an invalid value, and a
    plaintext password / code / token where a hash belongs is refused;
  * runs in ONE short transaction on its own connection: committed, or rolled back on any
    error. Driver errors become DuplicateEmail / InvalidValue (the same errors the
    in-memory repository raises for the same mistake) or BackendDatabaseUnavailable /
    BackendDatabaseError; messages never contain values;
  * passes every value as a %s parameter; times come from the database (UTC_TIMESTAMP(6),
    the connection's time zone is UTC), so all workstations share one clock.

Privileged changes (role, status, approval) write their audit record in the SAME
transaction: both are saved or neither. Changes that would leave no active admin raise
LastActiveAdmin; the active-admin rows are locked first, always in id order, so two
concurrent changes cannot both pass the check (and cannot deadlock on it).

Rows returned for users never include password_hash (get_password_hash() is separate),
and session rows never include token_hash.
"""
import secrets

from backend.database import auth_records as R
from backend.database.connection import close_quietly, connect_runtime, driver_error_code, \
    is_driver_error, translate
from backend.database.errors import DuplicateEmail, InvalidValue, LastActiveAdmin

_USER_COLUMNS = ('id, email, full_name, role, status, email_verified_at, approved_by, '
                 'approved_at, failed_logins, locked_until, created_at, updated_at')
_CHALLENGE_COLUMNS = ('id, public_id, user_id, purpose, code_hmac, attempts, max_attempts, '
                      'created_at, expires_at, consumed_at, invalidated_at, requester_ip, '
                      'workstation_label, (expires_at <= UTC_TIMESTAMP(6)) AS expired')
_SESSION_COLUMNS = ('s.id, s.user_id, s.workstation_label, s.client_ip, s.created_at, '
                    's.last_seen_at, s.expires_at, s.revoked_at, s.revoked_reason')
_AUDIT_COLUMNS = ('id, created_at, actor_user_id, actor_email, action, target_type, '
                  'target_id, outcome, client_ip, workstation_label, detail')
NOW = 'UTC_TIMESTAMP(6)'

USER_NOT_FOUND = 'The user does not exist.'
TOKEN_IN_USE = 'This session token hash is already in use.'
LAST_ADMIN = 'This change would leave no active admin. Nothing was changed.'


class AuthRepository:
    def __init__(self, connect):
        """connect(): a new DB-API connection (PyMySQL, DictCursor, autocommit off)."""
        self._connect = connect

    @classmethod
    def from_settings(cls, settings):
        return cls(lambda: connect_runtime(settings))

    # ------------------------------------------------------------ transactions
    def _tx(self, work):
        conn = self._connect()
        committing = False
        try:
            with conn.cursor() as cur:
                result = work(cur)
            committing = True
            conn.commit()
            return result
        except BaseException as err:
            try:
                conn.rollback()
            except Exception:
                pass
            if isinstance(err, Exception) and is_driver_error(err):
                raise self._translate(err, committing) from None
            raise
        finally:
            close_quietly(conn)

    @staticmethod
    def _translate(err, committing):
        """Constraint errors -> the same errors the in-memory repository raises."""
        code, text = driver_error_code(err), str(err)
        if code == 1062 and 'uq_users_email' in text:
            return DuplicateEmail('An account with this email address already exists.')
        if code == 1062 and 'uq_sessions_token_hash' in text:
            return InvalidValue(TOKEN_IN_USE)
        if code == 1452:                  # foreign key: the user row does not exist
            return InvalidValue(USER_NOT_FOUND)
        return translate(err, uncertain=committing)

    # ------------------------------------------------------------ users
    def create_user(self, email, full_name, password_hash, role='viewer',
                    status='pending_verification'):
        email, normalized = R.check_email(email), R.normalize_email(email)
        name = R.check_full_name(full_name)
        R.check_password_hash(password_hash)
        R.check_choice(role, R.ROLES, 'role')
        R.check_choice(status, R.STATUSES, 'status')

        def work(cur):
            cur.execute('INSERT INTO users (email, email_normalized, full_name, password_hash, '
                        f'role, status, created_at, updated_at) VALUES (%s, %s, %s, %s, %s, %s, '
                        f'{NOW}, {NOW})', (email, normalized, name, password_hash, role, status))
            return cur.lastrowid
        return self._tx(work)

    def get_user(self, user_id):
        R.check_id(user_id, 'user_id')
        return self._tx(lambda cur: self._one(cur, f'SELECT {_USER_COLUMNS} FROM users '
                                                   f'WHERE id = %s', (user_id,)))

    def find_user_by_email(self, email):
        normalized = R.normalize_email(email)
        return self._tx(lambda cur: self._one(cur, f'SELECT {_USER_COLUMNS} FROM users '
                                                   f'WHERE email_normalized = %s', (normalized,)))

    def get_password_hash(self, user_id):
        R.check_id(user_id, 'user_id')
        row = self._tx(lambda cur: self._one(cur, 'SELECT password_hash FROM users WHERE id = %s',
                                             (user_id,)))
        return row['password_hash'] if row else None

    def set_status(self, user_id, status, expected_status=None, *, actor_user_id,
                   client_ip=None, workstation_label=None):
        """Change the status (only from expected_status, when given) and audit it in the same
        transaction. True if changed; False if the user is missing, already has it, or is
        not in expected_status. LastActiveAdmin if it would leave no active admin."""
        R.check_id(user_id, 'user_id')
        R.check_choice(status, R.STATUSES, 'status')
        if expected_status is not None:
            R.check_choice(expected_status, R.STATUSES, 'expected_status')
        audit = R.audit_context(actor_user_id, client_ip, workstation_label)

        def work(cur):
            admins = self._lock_active_admins(cur)
            row = self._one(cur, 'SELECT role, status FROM users WHERE id = %s FOR UPDATE',
                            (user_id,))
            if (not row or row['status'] == status
                    or (expected_status is not None and row['status'] != expected_status)):
                return False
            if row['role'] == 'admin' and row['status'] == 'active' and status != 'active':
                self._guard_last_admin(admins, user_id)
            cur.execute(f'UPDATE users SET status = %s, updated_at = {NOW} WHERE id = %s',
                        (status, user_id))
            self._insert_audit(cur, 'user.status_changed', 'success', target_type='user',
                               target_id=str(user_id), detail=f"status {row['status']} -> {status}",
                               **audit)
            return True
        return self._tx(work)

    def set_role(self, user_id, role, *, actor_user_id, client_ip=None, workstation_label=None):
        """Change the role and audit it in the same transaction. True if changed.
        LastActiveAdmin if it would leave no active admin."""
        R.check_id(user_id, 'user_id')
        R.check_choice(role, R.ROLES, 'role')
        audit = R.audit_context(actor_user_id, client_ip, workstation_label)

        def work(cur):
            admins = self._lock_active_admins(cur)
            row = self._one(cur, 'SELECT role, status FROM users WHERE id = %s FOR UPDATE',
                            (user_id,))
            if not row or row['role'] == role:
                return False
            if row['role'] == 'admin' and row['status'] == 'active':
                self._guard_last_admin(admins, user_id)
            cur.execute(f'UPDATE users SET role = %s, updated_at = {NOW} WHERE id = %s',
                        (role, user_id))
            self._insert_audit(cur, 'user.role_changed', 'success', target_type='user',
                               target_id=str(user_id), detail=f"role {row['role']} -> {role}",
                               **audit)
            return True
        return self._tx(work)

    def mark_email_verified(self, user_id):
        """pending_verification -> pending_approval, with the verification time."""
        R.check_id(user_id, 'user_id')
        return self._tx(lambda cur: self._changed(
            cur, f"UPDATE users SET email_verified_at = {NOW}, status = 'pending_approval', "
                 f"updated_at = {NOW} WHERE id = %s AND status = 'pending_verification'",
            (user_id,)))

    def approve_user(self, user_id, approved_by, role=None, *, client_ip=None,
                     workstation_label=None):
        """pending_approval -> active, audited in the same transaction. approved_by must be
        another, active admin (checked and locked in that transaction). True if approved."""
        R.check_id(user_id, 'user_id')
        R.check_id(approved_by, 'approved_by')
        if role is not None:
            R.check_choice(role, R.ROLES, 'role')
        if user_id == approved_by:
            raise InvalidValue('An account cannot approve itself.')
        audit = R.audit_context(approved_by, client_ip, workstation_label)

        def work(cur):
            approver = self._one(cur, 'SELECT role, status FROM users WHERE id = %s FOR UPDATE',
                                 (approved_by,))
            if not approver or approver['role'] != 'admin' or approver['status'] != 'active':
                raise InvalidValue('Only an active admin can approve an account.')
            changed = self._changed(cur, f"UPDATE users SET status = 'active', approved_by = %s, "
                                         f"approved_at = {NOW}, role = COALESCE(%s, role), "
                                         f"updated_at = {NOW} WHERE id = %s "
                                         f"AND status = 'pending_approval'",
                                    (approved_by, role, user_id))
            if changed:
                self._insert_audit(cur, 'user.approved', 'success', target_type='user',
                                   target_id=str(user_id),
                                   detail=f'role {role}' if role else None, **audit)
            return changed
        return self._tx(work)

    @staticmethod
    def _lock_active_admins(cur):
        """Lock every active admin row, in id order (a fixed order: no deadlock between two
        admin changes), and return their ids. Every privileged change takes this lock first,
        so last-admin checks never race."""
        cur.execute("SELECT id FROM users WHERE role = 'admin' AND status = 'active' "
                    "ORDER BY id FOR UPDATE", ())
        return [r['id'] for r in cur.fetchall()]

    @staticmethod
    def _guard_last_admin(active_admin_ids, user_id):
        if not [i for i in active_admin_ids if i != user_id]:
            raise LastActiveAdmin(LAST_ADMIN)

    # ------------------------------------------------------------ email challenges
    def create_challenge(self, user_id, purpose, code_hmac, ttl_seconds, max_attempts=5,
                         requester_ip=None, workstation_label=None):
        """A new challenge; returns its random public id (given to that workstation only).
        Other challenges of the same user are NOT touched (workstations are independent)."""
        R.check_id(user_id, 'user_id')
        R.check_choice(purpose, R.PURPOSES, 'purpose')
        R.check_hex64(code_hmac, 'code_hmac')
        R.check_seconds(ttl_seconds, R.MAX_CHALLENGE_TTL, 'ttl_seconds')
        R.check_max_attempts(max_attempts)
        ip = R.check_optional_text(requester_ip, R.IP_MAX, 'requester_ip')
        label = R.check_optional_text(workstation_label, R.LABEL_MAX, 'workstation_label')
        public_id = secrets.token_urlsafe(32)

        def work(cur):
            self._require_user(cur, user_id)
            cur.execute('INSERT INTO email_challenges (public_id, user_id, purpose, code_hmac, '
                        'max_attempts, created_at, expires_at, requester_ip, workstation_label) '
                        f'VALUES (%s, %s, %s, %s, %s, {NOW}, {NOW} + INTERVAL %s SECOND, %s, %s)',
                        (public_id, user_id, purpose, code_hmac, max_attempts, ttl_seconds,
                         ip, label))
            return public_id
        return self._tx(work)

    def get_challenge(self, public_id):
        R.check_public_id(public_id)
        row = self._tx(lambda cur: self._one(cur, f'SELECT {_CHALLENGE_COLUMNS} FROM '
                                                  f'email_challenges WHERE public_id = %s',
                                             (public_id,)))
        if row:
            row['expired'] = bool(row['expired'])
        return row

    def record_failed_attempt(self, public_id):
        """Count one wrong code; the challenge is invalidated when it reaches max_attempts.
        Returns {'attempts', 'invalidated'} or None if the challenge is no longer open."""
        R.check_public_id(public_id)

        def work(cur):
            # MySQL applies these assignments left to right: the IF sees the new count.
            changed = self._changed(cur, f'UPDATE email_challenges SET attempts = attempts + 1, '
                                         f'invalidated_at = IF(attempts >= max_attempts, {NOW}, '
                                         f'invalidated_at) WHERE public_id = %s '
                                         f'AND consumed_at IS NULL AND invalidated_at IS NULL',
                                    (public_id,))
            if not changed:
                return None
            row = self._one(cur, 'SELECT attempts, invalidated_at FROM email_challenges '
                                 'WHERE public_id = %s', (public_id,))
            return {'attempts': row['attempts'], 'invalidated': row['invalidated_at'] is not None}
        return self._tx(work)

    def consume_challenge(self, public_id, purpose, user_id):
        """Use the challenge once: True only if it belongs to this user and purpose and is
        open, unexpired and under its attempt limit. One atomic UPDATE, so two simultaneous
        uses cannot both succeed, and a register code can never complete a login."""
        R.check_public_id(public_id)
        R.check_choice(purpose, R.PURPOSES, 'purpose')
        R.check_id(user_id, 'user_id')
        return self._tx(lambda cur: self._changed(
            cur, f'UPDATE email_challenges SET consumed_at = {NOW} WHERE public_id = %s '
                 f'AND purpose = %s AND user_id = %s '
                 f'AND consumed_at IS NULL AND invalidated_at IS NULL '
                 f'AND expires_at > {NOW} AND attempts < max_attempts',
            (public_id, purpose, user_id)))

    def invalidate_challenge(self, public_id):
        R.check_public_id(public_id)
        return self._tx(lambda cur: self._changed(
            cur, f'UPDATE email_challenges SET invalidated_at = {NOW} WHERE public_id = %s '
                 f'AND consumed_at IS NULL AND invalidated_at IS NULL', (public_id,)))

    def invalidate_user_challenges(self, user_id, purpose):
        """Close every open challenge of this user and purpose (for example when the account
        is disabled). Returns how many were closed."""
        R.check_id(user_id, 'user_id')
        R.check_choice(purpose, R.PURPOSES, 'purpose')
        return self._tx(lambda cur: self._count(
            cur, f'UPDATE email_challenges SET invalidated_at = {NOW} WHERE user_id = %s '
                 f'AND purpose = %s AND consumed_at IS NULL AND invalidated_at IS NULL',
            (user_id, purpose)))

    # ------------------------------------------------------------ sessions
    def create_session(self, user_id, token_hash, lifetime_seconds, workstation_label=None,
                       client_ip=None):
        R.check_id(user_id, 'user_id')
        R.check_hex64(token_hash, 'token_hash')
        R.check_seconds(lifetime_seconds, R.MAX_SESSION_LIFETIME, 'lifetime_seconds')
        label = R.check_optional_text(workstation_label, R.LABEL_MAX, 'workstation_label')
        ip = R.check_optional_text(client_ip, R.IP_MAX, 'client_ip')

        def work(cur):
            self._require_user(cur, user_id)
            cur.execute('INSERT INTO sessions (user_id, token_hash, workstation_label, client_ip, '
                        f'created_at, last_seen_at, expires_at) VALUES (%s, %s, %s, %s, {NOW}, '
                        f'{NOW}, {NOW} + INTERVAL %s SECOND)',
                        (user_id, token_hash, label, ip, lifetime_seconds))
            return cur.lastrowid
        return self._tx(work)

    def get_active_session(self, token_hash, idle_timeout_seconds):
        """The session with this token hash if it is not revoked, not past its absolute
        expiry, not idle for longer than idle_timeout_seconds, and its user is active."""
        R.check_hex64(token_hash, 'token_hash')
        R.check_seconds(idle_timeout_seconds, R.MAX_SESSION_LIFETIME, 'idle_timeout_seconds')
        return self._tx(lambda cur: self._one(
            cur, f'SELECT {_SESSION_COLUMNS}, u.role, u.status AS user_status FROM sessions s '
                 f'JOIN users u ON u.id = s.user_id WHERE s.token_hash = %s '
                 f'AND s.revoked_at IS NULL AND s.expires_at > {NOW} '
                 f'AND s.last_seen_at > {NOW} - INTERVAL %s SECOND AND u.status = \'active\'',
            (token_hash, idle_timeout_seconds)))

    def touch_session(self, session_id, idle_timeout_seconds):
        """Record activity: True only if the session is not revoked, not past its absolute
        expiry, and NOT already idle for longer than idle_timeout_seconds (an idle-expired
        session can never be brought back)."""
        R.check_id(session_id, 'session_id')
        R.check_seconds(idle_timeout_seconds, R.MAX_SESSION_LIFETIME, 'idle_timeout_seconds')
        return self._tx(lambda cur: self._changed(
            cur, f'UPDATE sessions SET last_seen_at = {NOW} WHERE id = %s AND revoked_at IS NULL '
                 f'AND expires_at > {NOW} AND last_seen_at > {NOW} - INTERVAL %s SECOND',
            (session_id, idle_timeout_seconds)))

    def revoke_session(self, session_id, reason='logout'):
        R.check_id(session_id, 'session_id')
        R.check_reason(reason)
        return self._tx(lambda cur: self._changed(
            cur, f'UPDATE sessions SET revoked_at = {NOW}, revoked_reason = %s WHERE id = %s '
                 f'AND revoked_at IS NULL', (reason, session_id)))

    def revoke_user_sessions(self, user_id, reason):
        R.check_id(user_id, 'user_id')
        R.check_reason(reason)
        return self._tx(lambda cur: self._count(
            cur, f'UPDATE sessions SET revoked_at = {NOW}, revoked_reason = %s WHERE user_id = %s '
                 f'AND revoked_at IS NULL', (reason, user_id)))

    def list_sessions(self, user_id):
        R.check_id(user_id, 'user_id')
        return self._tx(lambda cur: self._all(
            cur, f'SELECT {_SESSION_COLUMNS} FROM sessions s WHERE s.user_id = %s '
                 f'ORDER BY s.id DESC', (user_id,)))

    # ------------------------------------------------------------ audit log
    def write_audit(self, action, outcome, actor_user_id=None, actor_email=None,
                    target_type=None, target_id=None, client_ip=None, workstation_label=None,
                    detail=None):
        """Append one audit record (rows are never changed: no method here updates or deletes
        them, the runtime account has no such grant, and the triggers refuse it)."""
        values = R.audit_values(action, outcome, actor_user_id, actor_email, target_type,
                                target_id, client_ip, workstation_label, detail)
        return self._tx(lambda cur: self._insert_audit(cur, **values))

    @staticmethod
    def _insert_audit(cur, action, outcome, actor_user_id=None, actor_email=None,
                      target_type=None, target_id=None, client_ip=None, workstation_label=None,
                      detail=None):
        values = R.audit_values(action, outcome, actor_user_id, actor_email, target_type,
                                target_id, client_ip, workstation_label, detail)
        cur.execute('INSERT INTO audit_log (created_at, actor_user_id, actor_email, action, '
                    'target_type, target_id, outcome, client_ip, workstation_label, detail) '
                    f'VALUES ({NOW}, %s, %s, %s, %s, %s, %s, %s, %s, %s)',
                    (values['actor_user_id'], values['actor_email'], values['action'],
                     values['target_type'], values['target_id'], values['outcome'],
                     values['client_ip'], values['workstation_label'], values['detail']))
        return cur.lastrowid

    def list_audit(self, limit=100, actor_user_id=None, action=None):
        if not isinstance(limit, int) or isinstance(limit, bool) or not 1 <= limit <= 1000:
            raise InvalidValue('limit must be from 1 to 1000.')
        sql, params = f'SELECT {_AUDIT_COLUMNS} FROM audit_log WHERE 1 = 1', []
        if actor_user_id is not None:
            R.check_id(actor_user_id, 'actor_user_id')
            sql += ' AND actor_user_id = %s'
            params.append(actor_user_id)
        if action is not None:
            R.check_action(action)
            sql += ' AND action = %s'
            params.append(action)
        sql += ' ORDER BY id DESC LIMIT %s'
        params.append(limit)
        return self._tx(lambda cur: self._all(cur, sql, params))

    # ------------------------------------------------------------ helpers
    @staticmethod
    def _require_user(cur, user_id):
        cur.execute('SELECT id FROM users WHERE id = %s FOR SHARE', (user_id,))
        if not cur.fetchone():
            raise InvalidValue(USER_NOT_FOUND)

    @staticmethod
    def _one(cur, sql, params):
        cur.execute(sql, tuple(params))
        return cur.fetchone()

    @staticmethod
    def _all(cur, sql, params):
        cur.execute(sql, tuple(params))
        return list(cur.fetchall())

    @staticmethod
    def _changed(cur, sql, params):
        cur.execute(sql, tuple(params))
        return cur.rowcount == 1

    @staticmethod
    def _count(cur, sql, params):
        cur.execute(sql, tuple(params))
        return cur.rowcount
