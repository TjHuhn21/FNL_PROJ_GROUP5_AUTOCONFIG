"""In-memory authentication repository: the same methods, values, rules, results AND error
types as AuthRepository, for tests and later phases. Nothing is persisted.

Times come from clock() (UTC, naive datetime), injectable so tests can move time forward.
One lock makes every method one atomic step (the SQL version uses one transaction), so
the last-admin check and a privileged change plus its audit record are atomic here too.
"""
import copy
import secrets
import threading
from datetime import datetime, timedelta, timezone

from backend.auth import device_lockout as DL
from backend.database import auth_records as R
from backend.database.auth_repository import (ADMIN_EXISTS, LAST_ADMIN, LIST_USER_FIELDS,
                                              TOKEN_IN_USE, USER_NOT_FOUND)
from backend.database.errors import (AdminExists, DuplicateEmail, InvalidValue, LastActiveAdmin,
                                     ResendTooSoon)


def utc_now():
    return datetime.now(timezone.utc).replace(tzinfo=None)


_USER_PUBLIC = ('id', 'email', 'full_name', 'role', 'status', 'email_verified_at', 'approved_by',
                'approved_at', 'failed_logins', 'locked_until', 'created_at', 'updated_at')
_SESSION_PUBLIC = ('id', 'user_id', 'workstation_label', 'client_ip', 'created_at',
                   'last_seen_at', 'expires_at', 'revoked_at', 'revoked_reason')


class InMemoryAuthRepository:
    def __init__(self, clock=utc_now):
        self.clock = clock
        self._lock = threading.RLock()
        self._users, self._challenges, self._sessions, self._audit = {}, {}, {}, []
        self._security, self._lockouts = {}, []         # migration 5 (device logins)
        self._next = {'user': 1, 'challenge': 1, 'session': 1, 'audit': 1}

    def _id(self, kind):
        value = self._next[kind]
        self._next[kind] += 1
        return value

    # ------------------------------------------------------------ users
    def create_user(self, email, full_name, password_hash, role='viewer',
                    status='pending_verification', *, email_verified=False):
        email, normalized = R.check_email(email), R.normalize_email(email)
        name = R.check_full_name(full_name)
        R.check_password_hash(password_hash)
        R.check_choice(role, R.ROLES, 'role')
        R.check_choice(status, R.STATUSES, 'status')
        R.check_verified_for_status(status, email_verified)
        with self._lock:
            if any(u['email_normalized'] == normalized for u in self._users.values()):
                raise DuplicateEmail('An account with this email address already exists.')
            now, uid = self.clock(), self._id('user')
            self._users[uid] = {'id': uid, 'email': email, 'email_normalized': normalized,
                                'full_name': name, 'password_hash': password_hash, 'role': role,
                                'status': status, 'email_verified_at': now if email_verified
                                else None, 'approved_by': None,
                                'approved_at': None, 'failed_logins': 0, 'locked_until': None,
                                'created_at': now, 'updated_at': now}
            return uid

    def _public_user(self, u):
        return {k: copy.copy(u[k]) for k in _USER_PUBLIC} if u else None

    def get_user(self, user_id):
        R.check_id(user_id, 'user_id')
        with self._lock:
            return self._public_user(self._users.get(user_id))

    def find_user_by_email(self, email):
        normalized = R.normalize_email(email)
        with self._lock:
            return self._public_user(next((u for u in self._users.values()
                                           if u['email_normalized'] == normalized), None))

    def get_password_hash(self, user_id):
        R.check_id(user_id, 'user_id')
        with self._lock:
            u = self._users.get(user_id)
            return u['password_hash'] if u else None

    def _active_admins(self):
        return [u['id'] for u in self._users.values()
                if u['role'] == 'admin' and u['status'] == 'active']

    def _guard_last_admin(self, user_id):
        if not [i for i in self._active_admins() if i != user_id]:
            raise LastActiveAdmin(LAST_ADMIN)

    def set_status(self, user_id, status, expected_status=None, *, actor_user_id,
                   client_ip=None, workstation_label=None):
        R.check_id(user_id, 'user_id')
        R.check_choice(status, R.STATUSES, 'status')
        if expected_status is not None:
            R.check_choice(expected_status, R.STATUSES, 'expected_status')
        audit = R.audit_context(actor_user_id, client_ip, workstation_label)
        with self._lock:
            u = self._users.get(user_id)
            if (not u or u['status'] == status
                    or (expected_status is not None and u['status'] != expected_status)):
                return False
            R.check_verified_for_status(status, u['email_verified_at'] is not None)
            if u['role'] == 'admin' and u['status'] == 'active' and status != 'active':
                self._guard_last_admin(user_id)
            record = R.audit_values('user.status_changed', 'success', target_type='user',
                                    target_id=user_id, detail=f"status {u['status']} -> {status}",
                                    **audit)
            u.update(status=status, updated_at=self.clock())
            self._append_audit(record)
            return True

    def set_role(self, user_id, role, *, actor_user_id, client_ip=None, workstation_label=None):
        R.check_id(user_id, 'user_id')
        R.check_choice(role, R.ROLES, 'role')
        audit = R.audit_context(actor_user_id, client_ip, workstation_label)
        with self._lock:
            u = self._users.get(user_id)
            if not u or u['role'] == role:
                return False
            if u['role'] == 'admin' and u['status'] == 'active':
                self._guard_last_admin(user_id)
            record = R.audit_values('user.role_changed', 'success', target_type='user',
                                    target_id=user_id, detail=f"role {u['role']} -> {role}",
                                    **audit)
            u.update(role=role, updated_at=self.clock())
            self._append_audit(record)
            return True

    def mark_email_verified(self, user_id):
        R.check_id(user_id, 'user_id')
        with self._lock:
            u = self._users.get(user_id)
            if not u or u['status'] != 'pending_verification':
                return False
            now = self.clock()
            u.update(email_verified_at=now, status='pending_approval', updated_at=now)
            return True

    def approve_user(self, user_id, approved_by, role=None, *, client_ip=None,
                     workstation_label=None):
        R.check_id(user_id, 'user_id')
        R.check_id(approved_by, 'approved_by')
        if role is not None:
            R.check_choice(role, R.ROLES, 'role')
        if user_id == approved_by:
            raise InvalidValue('An account cannot approve itself.')
        audit = R.audit_context(approved_by, client_ip, workstation_label)
        with self._lock:
            approver = self._users.get(approved_by)
            if not approver or approver['role'] != 'admin' or approver['status'] != 'active':
                raise InvalidValue('Only an active admin can approve an account.')
            u = self._users.get(user_id)
            if not u or u['status'] != 'pending_approval' or u['email_verified_at'] is None:
                return False
            record = R.audit_values('user.approved', 'success', target_type='user',
                                    target_id=user_id, detail=f'role {role}' if role else None,
                                    **audit)
            now = self.clock()
            u.update(status='active', approved_by=approved_by, approved_at=now,
                     role=role or u['role'], updated_at=now)
            self._append_audit(record)
            return True

    def create_first_admin(self, email, full_name, password_hash, *, workstation_label=None):
        email, normalized = R.check_email(email), R.normalize_email(email)
        name = R.check_full_name(full_name)
        R.check_password_hash(password_hash)
        label = R.check_optional_text(workstation_label, R.LABEL_MAX, 'workstation_label')
        with self._lock:                               # check and create: one atomic step
            if self._active_admins():
                raise AdminExists(ADMIN_EXISTS)
            inactive = sum(1 for u in self._users.values() if u['role'] == 'admin')
            uid = self.create_user(email, name, password_hash, role='admin', status='active',
                                   email_verified=True)
            self._append_audit(R.audit_values(
                'user.bootstrap_admin', 'success', actor_email=normalized, target_type='user',
                target_id=uid, workstation_label=label,
                detail=f'first administrator created by the local bootstrap command after its '
                       f'email address was verified with a one-time code; {inactive} inactive '
                       f'admin account(s) existed'))
            return {'user_id': uid, 'inactive_admins': inactive}

    def mark_existing_admin_email_verified(self, user_id, *, workstation_label=None):
        R.check_id(user_id, 'user_id')
        label = R.check_optional_text(workstation_label, R.LABEL_MAX, 'workstation_label')
        with self._lock:
            u = self._users.get(user_id)
            if (not u or u['role'] != 'admin' or u['status'] != 'active'
                    or u['email_verified_at'] is not None):
                return False
            record = R.audit_values(
                'auth.email_verified', 'success', actor_user_id=user_id, target_type='user',
                target_id=user_id, workstation_label=label,
                detail='existing administrator verified its email address with a one-time '
                       'code (local command)')
            u['email_verified_at'] = self.clock()          # nothing else changes
            self._append_audit(record)
            return True

    def list_users(self, status=None, limit=100, after_id=None):
        if status is not None:
            R.check_choice(status, R.STATUSES, 'status')
        R.check_limit(limit)
        if after_id is not None:
            R.check_id(after_id, 'after_id')
        with self._lock:
            now, rows = self.clock(), []
            for uid in sorted(self._users):
                u = self._users[uid]
                if (status is not None and u['status'] != status) or (
                        after_id is not None and uid <= after_id):
                    continue
                row = {k: copy.copy(u[k]) for k in LIST_USER_FIELDS[:-3]}
                row['locked'] = self._lock_active(u, now)
                state = self._security.get(uid)
                row['security_lock'] = DL.is_locked(state, now)
                row['security_locked_until'] = (state['locked_until']
                                                if row['security_lock'] == 'temporary' else None)
                rows.append(row)
                if len(rows) == limit:
                    break
            return rows

    # ------------------------------------------------------------ password attempts
    @staticmethod
    def _lock_active(u, now):
        return u['locked_until'] is not None and u['locked_until'] > now

    def begin_password_attempt(self, user_id, threshold, lockout_seconds, *, client_ip=None,
                               workstation_label=None):
        R.check_id(user_id, 'user_id')
        R.check_lockout(threshold, lockout_seconds)
        audit = R.audit_context(None, client_ip, workstation_label)
        with self._lock:
            u, now = self._users.get(user_id), self.clock()
            if not u:
                return None
            if self._lock_active(u, now):
                return {'allowed': False, 'failed_logins': u['failed_logins'],
                        'locked_until': u['locked_until'], 'newly_locked': False}
            count = (0 if u['locked_until'] is not None else u['failed_logins']) + 1
            if count < threshold:
                u.update(failed_logins=count, locked_until=None)
                return {'allowed': True, 'failed_logins': count, 'locked_until': None,
                        'newly_locked': False}
            record = R.audit_values('auth.account_locked', 'denied', target_type='user',
                                    target_id=user_id,
                                    detail=f'{count} password attempts; locked for '
                                           f'{lockout_seconds} s unless this attempt succeeds',
                                    **audit)
            u.update(failed_logins=count, locked_until=now + timedelta(seconds=lockout_seconds))
            self._append_audit(record)
            return {'allowed': True, 'failed_logins': count, 'locked_until': u['locked_until'],
                    'newly_locked': True}

    def record_password_success(self, user_id, *, client_ip=None, workstation_label=None):
        R.check_id(user_id, 'user_id')
        audit = R.audit_context(user_id, client_ip, workstation_label)
        with self._lock:
            u, now = self._users.get(user_id), self.clock()
            if not u:
                return False
            record = None
            if self._lock_active(u, now):
                record = R.audit_values('auth.lock_cleared', 'success', target_type='user',
                                        target_id=user_id,
                                        detail='correct password on an allowed attempt; failure '
                                               'count and lock cleared', **audit)
            u.update(failed_logins=0, locked_until=None)
            if record:
                self._append_audit(record)
            return True

    # ------------------------------------------------------------ email challenges
    def _resend_facts(self, user_id, purpose, window_seconds, now):
        since = now - timedelta(seconds=window_seconds)
        recent = [c['created_at'] for c in self._challenges.values()
                  if c['user_id'] == user_id and c['purpose'] == purpose
                  and c['created_at'] > since]
        last = None if not recent else max(0, int((now - max(recent)).total_seconds()))
        return {'recent_count': len(recent), 'seconds_since_last': last}

    def challenge_resend_state(self, user_id, purpose, cooldown_seconds, window_seconds=3600):
        R.check_id(user_id, 'user_id')
        R.check_choice(purpose, R.PURPOSES, 'purpose')
        R.check_resend(cooldown_seconds, window_seconds)
        with self._lock:
            facts = self._resend_facts(user_id, purpose, window_seconds, self.clock())
        return {'recent_count': facts['recent_count'],
                'seconds_since_last': facts['seconds_since_last'],
                'retry_after_seconds': R.retry_after(facts['seconds_since_last'],
                                                     cooldown_seconds)}

    def create_challenge(self, user_id, purpose, code_hmac, ttl_seconds, max_attempts=5,
                         requester_ip=None, workstation_label=None,
                         resend_cooldown_seconds=None):
        R.check_id(user_id, 'user_id')
        R.check_choice(purpose, R.PURPOSES, 'purpose')
        R.check_hex64(code_hmac, 'code_hmac')
        R.check_seconds(ttl_seconds, R.MAX_CHALLENGE_TTL, 'ttl_seconds')
        R.check_max_attempts(max_attempts)
        if resend_cooldown_seconds is not None:
            R.check_resend(resend_cooldown_seconds)
        ip = R.check_optional_text(requester_ip, R.IP_MAX, 'requester_ip')
        label = R.check_optional_text(workstation_label, R.LABEL_MAX, 'workstation_label')
        with self._lock:
            if user_id not in self._users:
                raise InvalidValue(USER_NOT_FOUND)
            if resend_cooldown_seconds is not None:
                facts = self._resend_facts(user_id, purpose, resend_cooldown_seconds, self.clock())
                wait = R.retry_after(facts['seconds_since_last'], resend_cooldown_seconds)
                if wait:
                    raise ResendTooSoon(wait)
            now, public_id = self.clock(), secrets.token_urlsafe(32)
            self._challenges[public_id] = {
                'id': self._id('challenge'), 'public_id': public_id, 'user_id': user_id,
                'purpose': purpose, 'code_hmac': code_hmac, 'attempts': 0,
                'max_attempts': max_attempts, 'created_at': now,
                'expires_at': now + timedelta(seconds=ttl_seconds), 'consumed_at': None,
                'invalidated_at': None, 'requester_ip': ip, 'workstation_label': label}
            return public_id

    def get_challenge(self, public_id):
        R.check_public_id(public_id)
        with self._lock:
            c = self._challenges.get(public_id)
            if not c:
                return None
            row = dict(c)
            row['expired'] = c['expires_at'] <= self.clock()
            return row

    def record_failed_attempt(self, public_id):
        R.check_public_id(public_id)
        with self._lock:
            c = self._challenges.get(public_id)
            if not c or c['consumed_at'] or c['invalidated_at']:
                return None
            c['attempts'] += 1
            if c['attempts'] >= c['max_attempts']:
                c['invalidated_at'] = self.clock()
            return {'attempts': c['attempts'], 'invalidated': c['invalidated_at'] is not None}

    def consume_challenge(self, public_id, purpose, user_id):
        R.check_public_id(public_id)
        R.check_choice(purpose, R.PURPOSES, 'purpose')
        R.check_id(user_id, 'user_id')
        with self._lock:
            c = self._challenges.get(public_id)
            now = self.clock()
            if (not c or c['purpose'] != purpose or c['user_id'] != user_id
                    or c['consumed_at'] or c['invalidated_at'] or c['expires_at'] <= now
                    or c['attempts'] >= c['max_attempts']):
                return False
            c['consumed_at'] = now
            return True

    def invalidate_challenge(self, public_id):
        R.check_public_id(public_id)
        with self._lock:
            c = self._challenges.get(public_id)
            if not c or c['consumed_at'] or c['invalidated_at']:
                return False
            c['invalidated_at'] = self.clock()
            return True

    def invalidate_user_challenges(self, user_id, purpose):
        R.check_id(user_id, 'user_id')
        R.check_choice(purpose, R.PURPOSES, 'purpose')
        with self._lock:
            n, now = 0, self.clock()
            for c in self._challenges.values():
                if (c['user_id'] == user_id and c['purpose'] == purpose
                        and not c['consumed_at'] and not c['invalidated_at']):
                    c['invalidated_at'] = now
                    n += 1
            return n

    # ------------------------------------------------------------ sessions
    def create_session(self, user_id, token_hash, lifetime_seconds, workstation_label=None,
                       client_ip=None):
        R.check_id(user_id, 'user_id')
        R.check_hex64(token_hash, 'token_hash')
        R.check_seconds(lifetime_seconds, R.MAX_SESSION_LIFETIME, 'lifetime_seconds')
        label = R.check_optional_text(workstation_label, R.LABEL_MAX, 'workstation_label')
        ip = R.check_optional_text(client_ip, R.IP_MAX, 'client_ip')
        with self._lock:
            if user_id not in self._users:
                raise InvalidValue(USER_NOT_FOUND)
            if any(s['token_hash'] == token_hash for s in self._sessions.values()):
                raise InvalidValue(TOKEN_IN_USE)
            now, sid = self.clock(), self._id('session')
            self._sessions[sid] = {'id': sid, 'user_id': user_id, 'token_hash': token_hash,
                                   'workstation_label': label, 'client_ip': ip,
                                   'created_at': now, 'last_seen_at': now,
                                   'expires_at': now + timedelta(seconds=lifetime_seconds),
                                   'revoked_at': None, 'revoked_reason': None}
            return sid

    def _usable(self, s, now, idle_timeout_seconds):
        return (s and not s['revoked_at'] and s['expires_at'] > now
                and s['last_seen_at'] > now - timedelta(seconds=idle_timeout_seconds))

    def get_active_session(self, token_hash, idle_timeout_seconds):
        R.check_hex64(token_hash, 'token_hash')
        R.check_seconds(idle_timeout_seconds, R.MAX_SESSION_LIFETIME, 'idle_timeout_seconds')
        with self._lock:
            now = self.clock()
            s = next((x for x in self._sessions.values() if x['token_hash'] == token_hash), None)
            if not self._usable(s, now, idle_timeout_seconds):
                return None
            u = self._users.get(s['user_id'])
            if not u or u['status'] != 'active' or u['email_verified_at'] is None:
                return None
            if DL.is_locked(self._security.get(u['id']), now):
                return None
            row = {k: s[k] for k in _SESSION_PUBLIC}
            row.update(role=u['role'], user_status=u['status'])
            return row

    def touch_session(self, session_id, idle_timeout_seconds):
        R.check_id(session_id, 'session_id')
        R.check_seconds(idle_timeout_seconds, R.MAX_SESSION_LIFETIME, 'idle_timeout_seconds')
        with self._lock:
            s, now = self._sessions.get(session_id), self.clock()
            if not self._usable(s, now, idle_timeout_seconds):
                return False
            s['last_seen_at'] = now
            return True

    def revoke_session(self, session_id, reason='logout'):
        R.check_id(session_id, 'session_id')
        R.check_reason(reason)
        with self._lock:
            s = self._sessions.get(session_id)
            if not s or s['revoked_at']:
                return False
            s.update(revoked_at=self.clock(), revoked_reason=reason)
            return True

    def revoke_user_sessions(self, user_id, reason):
        R.check_id(user_id, 'user_id')
        R.check_reason(reason)
        with self._lock:
            n, now = 0, self.clock()
            for s in self._sessions.values():
                if s['user_id'] == user_id and not s['revoked_at']:
                    s.update(revoked_at=now, revoked_reason=reason)
                    n += 1
            return n

    def list_sessions(self, user_id):
        R.check_id(user_id, 'user_id')
        with self._lock:
            return [{k: s[k] for k in _SESSION_PUBLIC} for s in
                    sorted(self._sessions.values(), key=lambda x: -x['id'])
                    if s['user_id'] == user_id]

    # ------------------------------------------------------------ audit log
    def _append_audit(self, record):
        row = dict(record, id=self._id('audit'), created_at=self.clock())
        self._audit.append(row)
        return row['id']

    def write_audit(self, action, outcome, actor_user_id=None, actor_email=None,
                    target_type=None, target_id=None, client_ip=None, workstation_label=None,
                    detail=None):
        record = R.audit_values(action, outcome, actor_user_id, actor_email, target_type,
                                target_id, client_ip, workstation_label, detail)
        with self._lock:
            return self._append_audit(record)

    def list_audit(self, limit=100, actor_user_id=None, action=None):
        if not isinstance(limit, int) or isinstance(limit, bool) or not 1 <= limit <= 1000:
            raise InvalidValue('limit must be from 1 to 1000.')
        if actor_user_id is not None:
            R.check_id(actor_user_id, 'actor_user_id')
        if action is not None:
            R.check_action(action)
        with self._lock:
            rows = [dict(r) for r in reversed(self._audit)
                    if (actor_user_id is None or r['actor_user_id'] == actor_user_id)
                    and (action is None or r['action'] == action)]
            return rows[:limit]

    # ------------------------------------------------------------ failed device logins
    def _recent_lockouts(self, user_id, state, now, policy=DL.DEFAULT_DEVICE_POLICY):
        since = DL.lockouts_since(state, now, policy)
        return sum(1 for x in self._lockouts if x['user_id'] == user_id and x['created_at'] > since)

    def device_login_state(self, user_id):
        R.check_id(user_id, 'user_id')
        with self._lock:
            now = self.clock()
            state = dict(self._security.get(user_id) or DL.empty_state(user_id))
            return state, now, self._recent_lockouts(user_id, state, now)

    def record_device_login(self, user_id, outcome, device_ip=None,
                            policy=DL.DEFAULT_DEVICE_POLICY):
        R.check_id(user_id, 'user_id')
        R.check_choice(outcome, DL.OUTCOMES, 'outcome')
        ip = R.check_optional_text(device_ip, R.IP_MAX, 'device_ip')
        with self._lock:
            if user_id not in self._users:
                raise InvalidValue(USER_NOT_FOUND)
            now = self.clock()
            state = dict(self._security.get(user_id) or DL.empty_state(user_id))
            new, result = DL.decide(state, self._recent_lockouts(user_id, state, now, policy),
                                    outcome, now, policy)
            self._security[user_id] = new
            if result['event'] in ('temporary', 'permanent'):
                self._lockouts.append({'id': len(self._lockouts) + 1, 'user_id': user_id,
                                       'created_at': now, 'kind': result['event'],
                                       'locked_until': result['locked_until'],
                                       'device_ip': ip, 'reason': DL.REASONS.get(outcome)})
            return dict(result, now=now)

    def unlock_device_security(self, user_id):
        R.check_id(user_id, 'user_id')
        with self._lock:
            if user_id not in self._users:
                raise InvalidValue(USER_NOT_FOUND)
            state = self._security.get(user_id)
            if not state:
                return None
            now = self.clock()
            self._security[user_id] = DL.unlocked_state(state, now)
            return DL.is_locked(state, now)

    def list_lockouts(self, user_id):
        """Every recorded lockout of this user (tests and reports)."""
        with self._lock:
            return [dict(x) for x in self._lockouts if x['user_id'] == user_id]

    def reset_all_device_security(self):
        """TESTING MODE only: as AuthRepository.reset_all_device_security."""
        with self._lock:
            now, n = self.clock(), 0
            for uid, state in list(self._security.items()):
                since = state.get('lockouts_reset_at')
                had_lockouts = any(x['user_id'] == uid and (since is None or x['created_at'] > since)
                                   for x in self._lockouts)
                if (state['failed_count'] or state['locked_until'] is not None
                        or state['permanent_locked_at'] is not None or had_lockouts):
                    n += 1
                self._security[uid] = DL.unlocked_state(state, now)
            return n
