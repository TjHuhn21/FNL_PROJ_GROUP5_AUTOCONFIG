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

Password attempts and lockout (begin_password_attempt / record_password_success): an
attempt is COUNTED BEFORE the password is checked, under a row lock on the user, and is
refused while the account is locked. The attempt that reaches the threshold locks the
account at once. So however many attempts run at the same time, at most `threshold`
passwords are ever checked per lockout period; a correct password then clears the count
(and a lock set by its own attempt). Locking and clearing a lock are audited in the same
transaction.

Resend cooldown: create_challenge(..., resend_cooldown_seconds=N) locks the user row and
refuses (ResendTooSoon) when a code for the same purpose was created less than N seconds
ago, so two simultaneous requests cannot both send a code.
"""
import secrets

from backend.auth import device_lockout as DL
from backend.database import auth_records as R
from backend.database.connection import close_quietly, connect_runtime, driver_error_code, \
    is_driver_error, translate
from backend.database.errors import (AdminExists, DuplicateEmail, InvalidValue, LastActiveAdmin,
                                     ResendTooSoon, SetupBusy)

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
# list_users(): what an admin needs to review accounts. No password hash and no failure
# counter; 'locked' (true/false) instead of the lock time.
LIST_USER_FIELDS = ('id', 'email', 'full_name', 'role', 'status', 'email_verified_at',
                    'approved_by', 'approved_at', 'created_at', 'updated_at', 'locked',
                    'security_lock', 'security_locked_until')
_LOCK_ACTIVE = f'(locked_until IS NOT NULL AND locked_until > {NOW})'
# A lock after too many failed DEVICE logins (migration 5; rules: auth/device_lockout.py).
_STATE_COLUMNS = ('user_id, failed_count, first_failed_at, locked_until, permanent_locked_at, '
                  'lockouts_reset_at')
_SECURITY_LOCKED = (f'EXISTS (SELECT 1 FROM security_device_login_state st WHERE st.user_id = '
                    f'u.id AND (st.permanent_locked_at IS NOT NULL OR st.locked_until > {NOW}))')

USER_NOT_FOUND = 'The user does not exist.'
TOKEN_IN_USE = 'This session token hash is already in use.'
LAST_ADMIN = 'This change would leave no active admin. Nothing was changed.'
ADMIN_EXISTS = 'An active administrator already exists. Nothing was created.'
SETUP_BUSY = ('Another first-administrator setup is running on this database. Nothing was '
              'created; try again in a moment.')
# One named lock per database (GET_LOCK names are server-wide, at most 64 characters).
FIRST_ADMIN_LOCK = "LEFT(CONCAT('netcommand.first_admin.', DATABASE()), 64)"
LOCK_WAIT_SECONDS = 10


class AuthRepository:
    def __init__(self, connect):
        """connect(): a new DB-API connection (PyMySQL, DictCursor, autocommit off)."""
        self._connect = connect

    @classmethod
    def from_settings(cls, settings):
        return cls(lambda: connect_runtime(settings))

    # ------------------------------------------------------------ transactions
    def _tx(self, work, named_lock=None):
        """One transaction. named_lock (an SQL expression for a GET_LOCK name): taken
        BEFORE the work and released only AFTER the commit or rollback, so whoever waits
        for it next sees everything this transaction committed."""
        conn = self._connect()
        committing, locked = False, False
        try:
            with conn.cursor() as cur:
                if named_lock is not None:
                    cur.execute(f'SELECT GET_LOCK({named_lock}, %s) AS got', (LOCK_WAIT_SECONDS,))
                    row = cur.fetchone()
                    if not row or row.get('got') != 1:
                        raise SetupBusy(SETUP_BUSY)
                    locked = True
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
            if locked:
                try:
                    with conn.cursor() as cur:
                        cur.execute(f'SELECT RELEASE_LOCK({named_lock}) AS released', ())
                except Exception:
                    pass                      # the server also releases it when we disconnect
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
                    status='pending_verification', *, email_verified=False):
        """A new account. Registration creates pending_verification accounts.
        email_verified=True (the address was proved with a one-time code) records the
        verification time; it is REQUIRED for an active or pending_approval account
        (EmailNotVerified otherwise)."""
        email, normalized = R.check_email(email), R.normalize_email(email)
        name = R.check_full_name(full_name)
        R.check_password_hash(password_hash)
        R.check_choice(role, R.ROLES, 'role')
        R.check_choice(status, R.STATUSES, 'status')
        R.check_verified_for_status(status, email_verified)
        verified_at = NOW if email_verified else 'NULL'

        def work(cur):
            cur.execute('INSERT INTO users (email, email_normalized, full_name, password_hash, '
                        f'role, status, email_verified_at, created_at, updated_at) VALUES (%s, '
                        f'%s, %s, %s, %s, %s, {verified_at}, {NOW}, {NOW})',
                        (email, normalized, name, password_hash, role, status))
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
        not in expected_status. LastActiveAdmin if it would leave no active admin;
        EmailNotVerified when making an unverified account active or pending approval."""
        R.check_id(user_id, 'user_id')
        R.check_choice(status, R.STATUSES, 'status')
        if expected_status is not None:
            R.check_choice(expected_status, R.STATUSES, 'expected_status')
        audit = R.audit_context(actor_user_id, client_ip, workstation_label)

        def work(cur):
            admins = self._lock_active_admins(cur)
            row = self._one(cur, 'SELECT role, status, email_verified_at FROM users '
                                 'WHERE id = %s FOR UPDATE', (user_id,))
            if (not row or row['status'] == status
                    or (expected_status is not None and row['status'] != expected_status)):
                return False
            R.check_verified_for_status(status, row.get('email_verified_at') is not None)
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
                                         f"AND status = 'pending_approval' "
                                         f"AND email_verified_at IS NOT NULL",
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

    def create_first_admin(self, email, full_name, password_hash, *, workstation_label=None):
        """The first administrator (role admin, status active), for the local bootstrap
        command only. AdminExists if an active admin exists; SetupBusy if another setup
        holds the lock. Protected against two simultaneous runs twice over: a per-database
        GET_LOCK held until after the commit, and the active admin rows read with FOR
        UPDATE (a locking read, so it sees committed rows). The account and its audit
        record are one transaction. Returns {'user_id', 'inactive_admins'}."""
        email, normalized = R.check_email(email), R.normalize_email(email)
        name = R.check_full_name(full_name)
        R.check_password_hash(password_hash)
        label = R.check_optional_text(workstation_label, R.LABEL_MAX, 'workstation_label')

        def work(cur):
            if self._lock_active_admins(cur):
                raise AdminExists(ADMIN_EXISTS)
            cur.execute("SELECT COUNT(*) AS n FROM users WHERE role = 'admin'", ())
            inactive = int((cur.fetchone() or {}).get('n') or 0)
            cur.execute('INSERT INTO users (email, email_normalized, full_name, password_hash, '
                        f"role, status, email_verified_at, created_at, updated_at) VALUES (%s, "
                        f"%s, %s, %s, 'admin', 'active', {NOW}, {NOW}, {NOW})",
                        (email, normalized, name, password_hash))
            uid = cur.lastrowid
            self._insert_audit(cur, 'user.bootstrap_admin', 'success', actor_email=normalized,
                               target_type='user', target_id=str(uid), workstation_label=label,
                               detail=f'first administrator created by the local bootstrap '
                                      f'command after its email address was verified with a '
                                      f'one-time code; {inactive} inactive admin account(s) '
                                      f'existed')
            return {'user_id': uid, 'inactive_admins': inactive}
        return self._tx(work, named_lock=FIRST_ADMIN_LOCK)

    def mark_existing_admin_email_verified(self, user_id, *, workstation_label=None):
        """For the local verify-existing command, after the administrator entered the code
        emailed to the account's address: record the verification time of an ACTIVE ADMIN
        whose address was never verified. Nothing else changes (not the status, role,
        password or updated_at). Audited in the same transaction. True if it was marked;
        False if the account is not an active admin or is already verified."""
        R.check_id(user_id, 'user_id')
        label = R.check_optional_text(workstation_label, R.LABEL_MAX, 'workstation_label')

        def work(cur):
            changed = self._changed(
                cur, f"UPDATE users SET email_verified_at = {NOW} WHERE id = %s "
                     f"AND role = 'admin' AND status = 'active' AND email_verified_at IS NULL",
                (user_id,))
            if changed:
                self._insert_audit(cur, 'auth.email_verified', 'success',
                                   actor_user_id=user_id, target_type='user',
                                   target_id=str(user_id), workstation_label=label,
                                   detail='existing administrator verified its email address '
                                          'with a one-time code (local command)')
            return changed
        return self._tx(work)

    def list_users(self, status=None, limit=100, after_id=None):
        """Accounts for an admin, oldest first (status='pending_approval' is the approval
        queue). Fields: LIST_USER_FIELDS. Page with after_id = the last id received."""
        if status is not None:
            R.check_choice(status, R.STATUSES, 'status')
        R.check_limit(limit)
        if after_id is not None:
            R.check_id(after_id, 'after_id')
        columns = ', '.join(f'u.{c}' for c in LIST_USER_FIELDS[:-3])
        sql = (f'SELECT {columns}, (u.locked_until IS NOT NULL AND u.locked_until > {NOW}) AS '
               f'locked, (CASE WHEN st.permanent_locked_at IS NOT NULL THEN \'permanent\' '
               f'WHEN st.locked_until > {NOW} THEN \'temporary\' END) AS security_lock, '
               f'(CASE WHEN st.permanent_locked_at IS NULL AND st.locked_until > {NOW} THEN '
               f'st.locked_until END) AS security_locked_until FROM users u '
               f'LEFT JOIN security_device_login_state st ON st.user_id = u.id WHERE 1 = 1')
        params = []
        if status is not None:
            sql += ' AND u.status = %s'
            params.append(status)
        if after_id is not None:
            sql += ' AND u.id > %s'
            params.append(after_id)
        sql += ' ORDER BY u.id LIMIT %s'
        params.append(limit)
        rows = self._tx(lambda cur: self._all(cur, sql, params))
        for row in rows:
            row['locked'] = bool(row['locked'])
        return rows

    # ------------------------------------------------------------ failed device logins
    def device_login_state(self, user_id):
        """(state, now, recent_lockouts) for this user: the stored state (or an empty one),
        the database's current UTC time, and the lockouts that count towards a permanent
        lock (since device_lockout.lockouts_since)."""
        R.check_id(user_id, 'user_id')

        def work(cur):
            now = self._one(cur, f'SELECT {NOW} AS now', ())['now']
            row = self._one(cur, f'SELECT {_STATE_COLUMNS} FROM security_device_login_state '
                                 f'WHERE user_id = %s', (user_id,))
            state = dict(row) if row else DL.empty_state(user_id)
            n = self._one(cur, 'SELECT COUNT(*) AS n FROM security_lockouts WHERE user_id = %s '
                               'AND created_at > %s',
                          (user_id, DL.lockouts_since(state, now)))['n']
            return state, now, n
        return self._tx(work)

    def record_device_login(self, user_id, outcome, device_ip=None,
                            policy=DL.DEFAULT_DEVICE_POLICY):
        """Apply one reported device login (device_lockout.decide) in ONE transaction with
        the user's state row locked, so simultaneous reports are counted one after the
        other. A new lockout is recorded (append-only) in the same transaction.
        Returns decide()'s result plus 'now' (the database's UTC time)."""
        R.check_id(user_id, 'user_id')
        R.check_choice(outcome, DL.OUTCOMES, 'outcome')
        ip = R.check_optional_text(device_ip, R.IP_MAX, 'device_ip')

        def work(cur):
            self._require_user(cur, user_id)
            cur.execute(f'INSERT IGNORE INTO security_device_login_state (user_id, updated_at) '
                        f'VALUES (%s, {NOW})', (user_id,))
            now = self._one(cur, f'SELECT {NOW} AS now', ())['now']
            state = dict(self._one(cur, f'SELECT {_STATE_COLUMNS} FROM '
                                        f'security_device_login_state WHERE user_id = %s '
                                        f'FOR UPDATE', (user_id,)))
            recent = self._one(cur, 'SELECT COUNT(*) AS n FROM security_lockouts WHERE '
                                    'user_id = %s AND created_at > %s',
                               (user_id, DL.lockouts_since(state, now, policy)))['n']
            new, result = DL.decide(state, recent, outcome, now, policy)
            if new != state:
                self._save_state(cur, new)
            if result['event'] in ('temporary', 'permanent'):
                cur.execute('INSERT INTO security_lockouts (user_id, created_at, kind, '
                            'locked_until, device_ip, reason) VALUES (%s, %s, %s, %s, %s, %s)',
                            (user_id, now, result['event'], result['locked_until'], ip,
                             DL.REASONS.get(outcome)))
            return dict(result, now=now)
        return self._tx(work)

    def unlock_device_security(self, user_id):
        """Clear a device-login lock, the failure count and the lockout count (older
        lockouts stay as history but stop counting). Returns the lock that was cleared
        ('temporary' / 'permanent') or None when the account was not locked; the counts
        are cleared either way."""
        R.check_id(user_id, 'user_id')

        def work(cur):
            self._require_user(cur, user_id)
            now = self._one(cur, f'SELECT {NOW} AS now', ())['now']
            row = self._one(cur, f'SELECT {_STATE_COLUMNS} FROM security_device_login_state '
                                 f'WHERE user_id = %s FOR UPDATE', (user_id,))
            if not row:
                return None
            state = dict(row)
            self._save_state(cur, DL.unlocked_state(state, now))
            return DL.is_locked(state, now)
        return self._tx(work)

    def reset_all_device_security(self):
        """TESTING MODE only (device_lockout.DEV_RESET_LOCKS_ON_RESTART): clear every
        account's failure count, temporary and permanent lock and lockout count (lockouts
        before now stop counting; their history rows are kept). Nothing else changes.
        Returns how many accounts had something to clear."""
        def work(cur):
            n = self._one(cur, f'SELECT COUNT(*) AS n FROM security_device_login_state st '
                               f'WHERE st.failed_count > 0 OR st.locked_until IS NOT NULL OR '
                               f'st.permanent_locked_at IS NOT NULL OR EXISTS (SELECT 1 FROM '
                               f'security_lockouts l WHERE l.user_id = st.user_id AND '
                               f'l.created_at > COALESCE(st.lockouts_reset_at, \'1000-01-01\'))',
                          ())['n']
            cur.execute(f'UPDATE security_device_login_state SET failed_count = 0, '
                        f'first_failed_at = NULL, locked_until = NULL, permanent_locked_at = '
                        f'NULL, lockouts_reset_at = {NOW}, updated_at = {NOW}', ())
            return n
        return self._tx(work)

    @staticmethod
    def _save_state(cur, st):
        cur.execute(f'UPDATE security_device_login_state SET failed_count = %s, '
                    f'first_failed_at = %s, locked_until = %s, permanent_locked_at = %s, '
                    f'lockouts_reset_at = %s, updated_at = {NOW} WHERE user_id = %s',
                    (st['failed_count'], st['first_failed_at'], st['locked_until'],
                     st['permanent_locked_at'], st['lockouts_reset_at'], st['user_id']))

    # ------------------------------------------------------------ password attempts
    def begin_password_attempt(self, user_id, threshold, lockout_seconds, *, client_ip=None,
                               workstation_label=None):
        """Call BEFORE checking a password. Returns None if the user does not exist, else
        {'allowed', 'failed_logins', 'locked_until', 'newly_locked'}:
          * allowed False: the account is locked; do not check the password. Nothing changes.
          * allowed True: this attempt has been counted. If it reached `threshold`, the
            account is now locked for lockout_seconds (newly_locked True, audited); check
            the password, and on success call record_password_success().
        A lock that has expired starts a fresh count. One transaction, user row locked."""
        R.check_id(user_id, 'user_id')
        R.check_lockout(threshold, lockout_seconds)
        audit = R.audit_context(None, client_ip, workstation_label)

        def work(cur):
            row = self._one(cur, f'SELECT failed_logins, locked_until, {_LOCK_ACTIVE} AS locked '
                                 f'FROM users WHERE id = %s FOR UPDATE', (user_id,))
            if not row:
                return None
            if row['locked']:
                return {'allowed': False, 'failed_logins': row['failed_logins'],
                        'locked_until': row['locked_until'], 'newly_locked': False}
            count = (0 if row['locked_until'] is not None else row['failed_logins']) + 1
            if count < threshold:
                cur.execute('UPDATE users SET failed_logins = %s, locked_until = NULL '
                            'WHERE id = %s', (count, user_id))
                return {'allowed': True, 'failed_logins': count, 'locked_until': None,
                        'newly_locked': False}
            cur.execute(f'UPDATE users SET failed_logins = %s, locked_until = {NOW} + INTERVAL '
                        f'%s SECOND WHERE id = %s', (count, lockout_seconds, user_id))
            self._insert_audit(cur, 'auth.account_locked', 'denied', target_type='user',
                               target_id=str(user_id),
                               detail=f'{count} password attempts; locked for {lockout_seconds} s '
                                      f'unless this attempt succeeds', **audit)
            until = self._one(cur, 'SELECT locked_until FROM users WHERE id = %s', (user_id,))
            return {'allowed': True, 'failed_logins': count, 'locked_until': until['locked_until'],
                    'newly_locked': True}
        return self._tx(work)

    def record_password_success(self, user_id, *, client_ip=None, workstation_label=None):
        """Call after the password was verified for an attempt that begin_password_attempt()
        allowed: clears the failure count and lock. Clearing an active lock is audited in
        the same transaction. True if the user exists."""
        R.check_id(user_id, 'user_id')
        audit = R.audit_context(user_id, client_ip, workstation_label)

        def work(cur):
            row = self._one(cur, f'SELECT failed_logins, locked_until, {_LOCK_ACTIVE} AS locked '
                                 f'FROM users WHERE id = %s FOR UPDATE', (user_id,))
            if not row:
                return False
            if row['failed_logins'] or row['locked_until'] is not None:
                cur.execute('UPDATE users SET failed_logins = 0, locked_until = NULL '
                            'WHERE id = %s', (user_id,))
            if row['locked']:
                self._insert_audit(cur, 'auth.lock_cleared', 'success', target_type='user',
                                   target_id=str(user_id),
                                   detail='correct password on an allowed attempt; failure '
                                          'count and lock cleared',
                                   **audit)
            return True
        return self._tx(work)

    # ------------------------------------------------------------ email challenges
    def create_challenge(self, user_id, purpose, code_hmac, ttl_seconds, max_attempts=5,
                         requester_ip=None, workstation_label=None,
                         resend_cooldown_seconds=None):
        """A new challenge; returns its random public id (given to that workstation only).
        Other challenges of the same user are NOT touched (workstations are independent).
        With resend_cooldown_seconds: the user row is locked and ResendTooSoon is raised
        (nothing created) if a code for this purpose was created within the cooldown."""
        R.check_id(user_id, 'user_id')
        R.check_choice(purpose, R.PURPOSES, 'purpose')
        R.check_hex64(code_hmac, 'code_hmac')
        R.check_seconds(ttl_seconds, R.MAX_CHALLENGE_TTL, 'ttl_seconds')
        R.check_max_attempts(max_attempts)
        if resend_cooldown_seconds is not None:
            R.check_resend(resend_cooldown_seconds)
        ip = R.check_optional_text(requester_ip, R.IP_MAX, 'requester_ip')
        label = R.check_optional_text(workstation_label, R.LABEL_MAX, 'workstation_label')
        public_id = secrets.token_urlsafe(32)

        def work(cur):
            if resend_cooldown_seconds is None:
                self._require_user(cur, user_id)
            else:
                # FOR UPDATE (not FOR SHARE): a second request for the same user waits here
                # until the first has committed, then sees its code and is refused.
                cur.execute('SELECT id FROM users WHERE id = %s FOR UPDATE', (user_id,))
                if not cur.fetchone():
                    raise InvalidValue(USER_NOT_FOUND)
                state = self._resend_facts(cur, user_id, purpose, resend_cooldown_seconds)
                wait = R.retry_after(state['seconds_since_last'], resend_cooldown_seconds)
                if wait:
                    raise ResendTooSoon(wait)
            cur.execute('INSERT INTO email_challenges (public_id, user_id, purpose, code_hmac, '
                        'max_attempts, created_at, expires_at, requester_ip, workstation_label) '
                        f'VALUES (%s, %s, %s, %s, %s, {NOW}, {NOW} + INTERVAL %s SECOND, %s, %s)',
                        (public_id, user_id, purpose, code_hmac, max_attempts, ttl_seconds,
                         ip, label))
            return public_id
        return self._tx(work)

    def challenge_resend_state(self, user_id, purpose, cooldown_seconds, window_seconds=3600):
        """For the resend button: {'recent_count' (codes for this user and purpose created
        in the last window_seconds), 'seconds_since_last' (the newest of those, whole
        seconds, or None), 'retry_after_seconds' (0 = a code may be sent now)}. Never
        returns codes, HMACs or challenge ids. create_challenge(resend_cooldown_seconds=)
        enforces the same rule atomically."""
        R.check_id(user_id, 'user_id')
        R.check_choice(purpose, R.PURPOSES, 'purpose')
        R.check_resend(cooldown_seconds, window_seconds)
        facts = self._tx(lambda cur: self._resend_facts(cur, user_id, purpose, window_seconds))
        return {'recent_count': facts['recent_count'],
                'seconds_since_last': facts['seconds_since_last'],
                'retry_after_seconds': R.retry_after(facts['seconds_since_last'],
                                                     cooldown_seconds)}

    @staticmethod
    def _resend_facts(cur, user_id, purpose, window_seconds):
        cur.execute(f'SELECT COUNT(*) AS recent_count, TIMESTAMPDIFF(SECOND, MAX(created_at), '
                    f'{NOW}) AS seconds_since_last FROM email_challenges WHERE user_id = %s '
                    f'AND purpose = %s AND created_at > {NOW} - INTERVAL %s SECOND',
                    (user_id, purpose, window_seconds))
        row = cur.fetchone() or {}
        last = row.get('seconds_since_last')
        return {'recent_count': int(row.get('recent_count') or 0),
                'seconds_since_last': None if last is None else max(0, int(last))}

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
        expiry, not idle for longer than idle_timeout_seconds, and its user is active with
        a verified email address."""
        R.check_hex64(token_hash, 'token_hash')
        R.check_seconds(idle_timeout_seconds, R.MAX_SESSION_LIFETIME, 'idle_timeout_seconds')
        return self._tx(lambda cur: self._one(
            cur, f'SELECT {_SESSION_COLUMNS}, u.role, u.status AS user_status FROM sessions s '
                 f'JOIN users u ON u.id = s.user_id WHERE s.token_hash = %s '
                 f'AND s.revoked_at IS NULL AND s.expires_at > {NOW} '
                 f'AND s.last_seen_at > {NOW} - INTERVAL %s SECOND AND u.status = \'active\' '
                 f'AND u.email_verified_at IS NOT NULL AND NOT {_SECURITY_LOCKED}',
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
