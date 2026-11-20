"""The authentication service: registration, login with an email code, sessions and the
account actions an admin needs. No HTTP here (that is the API phase).

  register(email, full_name, password, ...)       -> CodeSent (a registration code is emailed)
  verify_registration(challenge_id, code, ...)    -> 'pending_approval'
  resend_registration_code(email, ...)            -> CodeSent
  login(email, password, ...)                     -> CodeSent (a login code is emailed)
  verify_login(challenge_id, code, ...)           -> LoginSucceeded (the session token, ONCE)
  resend_login_code(challenge_id, ...)            -> CodeSent
  validate_session(token)                         -> SessionInfo   (or NotAuthenticated)
  logout(token)                                   -> True / False
  list_accounts / approve_account / reject_account / disable_account (admin sessions only)

What a client can learn
  * Whether an email address is registered: nothing. register() and
    resend_registration_code() answer the same way for every address (a random challenge
    id that can never be verified, and no email, when the address is taken or not
    eligible); login() gives the same LoginFailed for an unknown address, a wrong password
    and a locked account, after the same Argon2id work (dummy_verify for unknown or
    locked accounts). Only someone who knows the password learns more (for example that
    the account still awaits approval).
  * Rate limits are keyed on what the client sent (address and IP), so unknown addresses
    are limited exactly like registered ones.

Order of the security checks
  * Password: begin_password_attempt() is called BEFORE the password is checked; a
    refused (locked) attempt never checks it. record_password_success() only after a
    correct password on an allowed attempt.
  * A session is created ONLY in verify_login(), after a correct, unexpired, unused LOGIN
    code for that user, and only for an active account. The raw token is returned once
    (LoginSucceeded.token); only its SHA-256 is stored.
  * Codes: the purposes never mix (the challenge's purpose is checked AND the HMAC is
    bound to the purpose and the user). Every code check is RESERVED first
    (record_failed_attempt) and the challenge stores max_attempts = policy + 1, so at most
    `otp_max_attempts` checks ever happen per code, however many requests run at once;
    consume_challenge() then uses it exactly once.
  * A code that could not be emailed is invalidated at once.
  * Login codes can be resent only with the open login challenge (proof that the
    password was just entered), never with the email address alone.

Audit: every security event is written to audit_log with fixed wording; passwords,
codes, tokens, peppers and hashes are never part of it.
"""
import logging
import secrets
from dataclasses import dataclass, field

from backend.auth import passwords
from backend.auth.errors import (AccountNotActive, AuthError, CodeInvalid,  # noqa: F401
                                 DeliveryFailed, InvalidRequest, LoginFailed,
                                 NotAuthenticated, NotPermitted, RetryLater,
                                 ServiceUnavailable)
from backend.auth.otp import issue_otp, verify_otp, _pepper_bytes
from backend.auth.policy import DEFAULT_POLICY
from backend.auth.rate_limit import Limit, SlidingWindowLimiter
from backend.auth.tokens import InvalidSessionToken, hash_session_token, issue_session_token
from backend.database import auth_records as R
from backend.database.errors import DuplicateEmail, InvalidValue, ResendTooSoon
from backend.mail.delivery import MailError, send_otp_email
from backend.mail.messages import NotEligibleForCode

log = logging.getLogger('backend.auth')

CODES_PER_HOUR = 5                  # codes per account and purpose in any hour


@dataclass(frozen=True)
class RateLimits:
    login_per_email: Limit = Limit(10, 15 * 60)
    login_per_ip: Limit = Limit(50, 15 * 60)
    register_per_email: Limit = Limit(3, 3600)
    register_per_ip: Limit = Limit(10, 3600)
    resend_cooldown_per_email: Limit = Limit(1, 60)        # = the policy's resend cooldown
    resend_per_email: Limit = Limit(CODES_PER_HOUR, 3600)
    resend_per_ip: Limit = Limit(20, 3600)
    verify_per_ip: Limit = Limit(30, 15 * 60)
    verify_per_challenge: Limit = Limit(10, 15 * 60)


# ---------------------------------------------------------------- results and errors
@dataclass(frozen=True)
class CodeSent:
    """A code was emailed (or, for an address that cannot receive one, nothing was sent
    and the challenge id is random): the answer looks the same either way."""
    challenge_id: str
    expires_in_seconds: int


@dataclass(frozen=True)
class LoginSucceeded:
    token: str = field(repr=False)        # give to the client once; never store or log it
    session_id: int
    user_id: int
    role: str
    expires_in_seconds: int
    idle_timeout_seconds: int

    def __repr__(self):
        return (f'LoginSucceeded(token=[hidden], session_id={self.session_id}, '
                f'user_id={self.user_id}, role={self.role})')

    __str__ = __repr__


@dataclass(frozen=True)
class SessionInfo:
    session_id: int
    user_id: int
    role: str


def may_sign_in(user):
    """Only an active account whose email address has been verified may sign in or keep a
    session (get_active_session applies the same rule)."""
    return bool(user) and user['status'] == 'active' and user.get('email_verified_at') is not None


def why_not_signed_in(user):
    if not user:
        return 'account missing'
    if user['status'] != 'active':
        return f"account status {user['status']}"
    return 'email address not verified'


# ---------------------------------------------------------------- the service
class AuthService:
    def __init__(self, repository, mailer, otp_pepper, policy=DEFAULT_POLICY,
                 limits=RateLimits(), limiter=None):
        _pepper_bytes(otp_pepper)              # OtpConfigurationError now, not mid-login
        self.repo, self.mailer, self._pepper = repository, mailer, otp_pepper
        self.policy, self.limits = policy, limits
        self.limiter = limiter or SlidingWindowLimiter()

    @classmethod
    def from_settings(cls, settings, repository=None, mailer=None):
        if repository is None:
            from backend.database.auth_repository import AuthRepository
            repository = AuthRepository.from_settings(settings)
        if mailer is None:
            from backend.mail.delivery import create_mailer
            mailer = create_mailer(settings)
        return cls(repository, mailer, settings.otp_pepper, policy=settings.auth_policy)

    # ------------------------------------------------------------ registration
    def register(self, email, full_name, password, *, client_ip=None, workstation_label=None):
        ctx = self._context(client_ip, workstation_label)
        normalized = self._email(email)
        try:
            name = R.check_full_name(full_name)
            passwords.check_new_password(password, self.policy)
        except (InvalidValue, passwords.PasswordPolicyError) as err:
            raise InvalidRequest(str(err)) from None
        self._limit(('register-ip', ctx['client_ip']), self.limits.register_per_ip)
        self._limit(('register-email', normalized), self.limits.register_per_email)
        pw_hash = passwords.hash_password(password, self.policy)   # taken or not: same work
        try:
            uid = self.repo.create_user(email, name, pw_hash)
        except DuplicateEmail:
            self._audit('auth.register', 'denied', actor_email=normalized,
                        detail='email address already registered; nothing sent', **ctx)
            return self._decoy()
        self._audit('auth.register', 'success', actor_user_id=uid, actor_email=normalized,
                    target_id=uid, detail='account created, awaiting email verification', **ctx)
        return self._send_code(self.repo.get_user(uid), 'register', ctx)

    def verify_registration(self, challenge_id, code, *, client_ip=None,
                            workstation_label=None):
        ctx = self._context(client_ip, workstation_label)
        uid = self._check_code(challenge_id, code, 'register', ctx)
        if not self.repo.mark_email_verified(uid):
            self._audit('auth.email_verified', 'denied', actor_user_id=uid, target_id=uid,
                        detail='account was no longer awaiting verification', **ctx)
            raise CodeInvalid()
        self._audit('auth.email_verified', 'success', actor_user_id=uid, target_id=uid,
                    detail='email verified; awaiting administrator approval', **ctx)
        return 'pending_approval'

    def resend_registration_code(self, email, *, client_ip=None, workstation_label=None):
        ctx = self._context(client_ip, workstation_label)
        normalized = self._email(email)
        self._resend_limits(normalized, ctx)
        user = self.repo.find_user_by_email(normalized)
        if not user or user['status'] != 'pending_verification':
            return self._decoy()
        return self._send_code(user, 'register', ctx, cooldown=True)

    # ------------------------------------------------------------ login
    def login(self, email, password, *, client_ip=None, workstation_label=None):
        ctx = self._context(client_ip, workstation_label)
        try:
            normalized = R.normalize_email(email)
        except InvalidValue:
            passwords.dummy_verify(password)
            raise LoginFailed() from None
        self._limit(('login-ip', ctx['client_ip']), self.limits.login_per_ip)
        self._limit(('login-email', normalized), self.limits.login_per_email)

        user = self.repo.find_user_by_email(normalized)
        if not user:
            passwords.dummy_verify(password)
            self._audit('auth.login', 'failure', actor_email=normalized,
                        detail='unknown email address', **ctx)
            raise LoginFailed()
        uid = user['id']
        attempt = self.repo.begin_password_attempt(
            uid, self.policy.lockout_threshold, self.policy.lockout_seconds, **ctx)
        if not attempt or not attempt['allowed']:
            passwords.dummy_verify(password)            # locked: never check the password
            self._audit('auth.login', 'denied', actor_email=normalized, target_id=uid,
                        detail='account locked; password not checked', **ctx)
            raise LoginFailed()
        try:
            correct = passwords.verify_password(self.repo.get_password_hash(uid), password)
        except passwords.PasswordHashError:
            log.error('Unusable stored password hash for user %s', uid)
            correct = False
        if not correct:
            self._audit('auth.login', 'failure', actor_email=normalized, target_id=uid,
                        detail=f"wrong password (attempt {attempt['failed_logins']} of "
                               f'{self.policy.lockout_threshold})', **ctx)
            raise LoginFailed()

        self.repo.record_password_success(uid, **ctx)
        user = self.repo.get_user(uid)                   # the status as it is now
        if not may_sign_in(user):
            self._audit('auth.login', 'denied', actor_user_id=uid, target_id=uid,
                        detail=f'{why_not_signed_in(user)}; no code sent', **ctx)
            raise AccountNotActive()
        self._audit('auth.login_password_ok', 'success', actor_user_id=uid, target_id=uid,
                    detail='password correct; login code required', **ctx)
        return self._send_code(user, 'login', ctx, cooldown=True)

    def verify_login(self, challenge_id, code, *, client_ip=None, workstation_label=None):
        ctx = self._context(client_ip, workstation_label)
        uid = self._check_code(challenge_id, code, 'login', ctx)
        user = self.repo.get_user(uid)
        if not may_sign_in(user):
            self._audit('auth.login', 'denied', actor_user_id=uid, target_id=uid,
                        detail=f'{why_not_signed_in(user)}; no session created', **ctx)
            raise AccountNotActive()
        issued = issue_session_token()
        session_id = self.repo.create_session(uid, issued.token_hash,
                                              self.policy.session_lifetime_seconds,
                                              workstation_label=ctx['workstation_label'],
                                              client_ip=ctx['client_ip'])
        self._audit('auth.login', 'success', actor_user_id=uid, target_id=uid,
                    target_type='session', detail=f'session {session_id} created', **ctx)
        return LoginSucceeded(token=issued.token, session_id=session_id, user_id=uid,
                              role=user['role'],
                              expires_in_seconds=self.policy.session_lifetime_seconds,
                              idle_timeout_seconds=self.policy.idle_timeout_seconds)

    def resend_login_code(self, challenge_id, *, client_ip=None, workstation_label=None):
        """A new login code, only with the login challenge from login() that is still
        open (not used, not expired, not exhausted). The old one stops working."""
        ctx = self._context(client_ip, workstation_label)
        self._limit(('resend-ip', ctx['client_ip']), self.limits.resend_per_ip)
        old = self._open_challenge(challenge_id, 'login')
        if not old:
            self._audit('auth.code_resend', 'denied',
                        detail='login resend without an open login challenge', **ctx)
            raise CodeInvalid()
        user = self.repo.get_user(old['user_id'])
        if not may_sign_in(user):
            raise AccountNotActive()
        self._limit(('resend-email', R.normalize_email(user['email'])),
                    self.limits.resend_cooldown_per_email)
        sent = self._send_code(user, 'login', ctx, cooldown=True)
        self.repo.invalidate_challenge(challenge_id)
        return sent

    # ------------------------------------------------------------ sessions
    def validate_session(self, token):
        """SessionInfo for a valid token (and the idle timer is restarted); otherwise
        NotAuthenticated. Revoked, expired, idle and disabled-account sessions fail."""
        try:
            token_hash = hash_session_token(token)
        except InvalidSessionToken:
            raise NotAuthenticated() from None
        idle = self.policy.idle_timeout_seconds
        session = self.repo.get_active_session(token_hash, idle)
        if not session or not self.repo.touch_session(session['id'], idle):
            raise NotAuthenticated()
        return SessionInfo(session_id=session['id'], user_id=session['user_id'],
                           role=session['role'])

    def logout(self, token, *, client_ip=None, workstation_label=None):
        ctx = self._context(client_ip, workstation_label)
        try:
            info = self.validate_session(token)
        except NotAuthenticated:
            return False
        revoked = self.repo.revoke_session(info.session_id, 'logout')
        if revoked:
            self._audit('auth.logout', 'success', actor_user_id=info.user_id,
                        target_type='session', target_id=info.session_id, **ctx)
        return revoked

    # ------------------------------------------------------------ admin
    def authorize(self, token, roles, *, action='auth.authorize', client_ip=None,
                  workstation_label=None):
        """SessionInfo if the token is valid and its role is one of `roles`; NotAuthenticated
        or NotPermitted otherwise (a refusal is audited as `action`, outcome denied)."""
        for role in roles:
            R.check_choice(role, R.ROLES, 'role')
        ctx = self._context(client_ip, workstation_label)
        info = self.validate_session(token)
        if info.role not in roles:
            self._audit(action, 'denied', actor_user_id=info.user_id,
                        detail=f'role {info.role} is not allowed', **ctx)
            raise NotPermitted()
        return info

    def _admin(self, token, ctx, action):
        return self.authorize(token, ('admin',), action=action, **ctx)

    def list_accounts(self, token, status=None, limit=100, after_id=None):
        self._admin(token, {'client_ip': None, 'workstation_label': None},
                    'admin.list_accounts')
        try:
            return self.repo.list_users(status=status, limit=limit, after_id=after_id)
        except InvalidValue as err:
            raise InvalidRequest(str(err)) from None

    def approve_account(self, token, user_id, role=None, *, client_ip=None,
                        workstation_label=None):
        ctx = self._context(client_ip, workstation_label)
        admin = self._admin(token, ctx, 'user.approved')
        try:
            return self.repo.approve_user(user_id, admin.user_id, role, **ctx)
        except InvalidValue as err:
            raise InvalidRequest(str(err)) from None

    def reject_account(self, token, user_id, *, client_ip=None, workstation_label=None):
        ctx = self._context(client_ip, workstation_label)
        admin = self._admin(token, ctx, 'user.status_changed')
        try:
            return self.repo.set_status(user_id, 'rejected', expected_status='pending_approval',
                                        actor_user_id=admin.user_id, **ctx)
        except InvalidValue as err:
            raise InvalidRequest(str(err)) from None

    def change_role(self, token, user_id, role, *, client_ip=None, workstation_label=None):
        """An admin changes another account's role (viewer / operator / admin).

        * Only an active admin's session may do it (NotPermitted otherwise, audited).
        * Never one's own role: an admin cannot demote (or otherwise change) themselves
          here, so nobody locks themselves out by accident; another admin must do it.
        * The last active admin can never be demoted: the repository locks the active
          admins and checks inside the same transaction (two admins demoting each other at
          the same time cannot both succeed).
        * The role and its audit record ('user.role_changed': acting admin, target, old ->
          new) are one transaction. Then every session of that account is ended (audited),
          so it signs in again with the new role. (Even before that, every request already
          uses the account's current role.)
        * Nothing else about the account changes.
        Returns {'user_id', 'previous_role', 'role', 'sessions_ended'}, or None when the
        account already has that role."""
        ctx = self._context(client_ip, workstation_label)
        admin = self._admin(token, ctx, 'user.role_changed')
        if role not in R.ROLES:
            raise InvalidRequest(f'role must be one of: {", ".join(R.ROLES)}.')
        try:
            R.check_id(user_id, 'user_id')
        except InvalidValue as err:
            raise InvalidRequest(str(err)) from None
        if user_id == admin.user_id:
            self._audit('user.role_changed', 'denied', actor_user_id=admin.user_id,
                        target_id=user_id, detail='an administrator cannot change their own '
                                                  'role', **ctx)
            raise InvalidRequest('You cannot change your own role. Ask another administrator.')
        target = self.repo.get_user(user_id)
        if target is None:
            raise InvalidRequest('The account does not exist.')
        previous = target['role']
        try:
            changed = self.repo.set_role(user_id, role, actor_user_id=admin.user_id, **ctx)
        except InvalidValue as err:                   # LastActiveAdmin
            self._audit('user.role_changed', 'denied', actor_user_id=admin.user_id,
                        target_id=user_id, detail=f'role {previous} -> {role} refused: it '
                                                  f'would leave no active admin', **ctx)
            raise InvalidRequest(str(err)) from None
        if not changed:
            return None
        ended = self.repo.revoke_user_sessions(user_id, 'role_changed')
        self._audit('auth.sessions_revoked', 'success', actor_user_id=admin.user_id,
                    target_id=user_id, detail=f'role changed; {ended} session(s) ended', **ctx)
        return {'user_id': user_id, 'previous_role': previous, 'role': role,
                'sessions_ended': ended}

    def disable_account(self, token, user_id, *, client_ip=None, workstation_label=None):
        """Disable the account, end all its sessions and cancel its open codes."""
        ctx = self._context(client_ip, workstation_label)
        admin = self._admin(token, ctx, 'user.status_changed')
        try:
            changed = self.repo.set_status(user_id, 'disabled', actor_user_id=admin.user_id,
                                           **ctx)
        except InvalidValue as err:                   # includes LastActiveAdmin
            raise InvalidRequest(str(err)) from None
        revoked = self.repo.revoke_user_sessions(user_id, 'account_disabled')
        for purpose in R.PURPOSES:
            self.repo.invalidate_user_challenges(user_id, purpose)
        self._audit('auth.sessions_revoked', 'success', actor_user_id=admin.user_id,
                    target_id=user_id, detail=f'account disabled; {revoked} session(s) ended',
                    **ctx)
        return changed

    # ------------------------------------------------------------ helpers
    @staticmethod
    def _context(client_ip, workstation_label):
        try:
            return {'client_ip': R.check_optional_text(client_ip, R.IP_MAX, 'client_ip'),
                    'workstation_label': R.check_optional_text(workstation_label, R.LABEL_MAX,
                                                               'workstation_label')}
        except InvalidValue as err:
            raise InvalidRequest(str(err)) from None

    @staticmethod
    def _email(email):
        try:
            return R.normalize_email(email)
        except InvalidValue as err:
            raise InvalidRequest(str(err)) from None

    def _limit(self, key, limit):
        wait = self.limiter.hit(key, limit)
        if wait:
            log.warning('Rate limit reached: %s', key[0])
            raise RetryLater(wait)

    def _resend_limits(self, normalized, ctx):
        self._limit(('resend-ip', ctx['client_ip']), self.limits.resend_per_ip)
        self._limit(('resend-email', normalized), self.limits.resend_cooldown_per_email)
        self._limit(('resend-hour', normalized), self.limits.resend_per_email)

    def _decoy(self):
        """The answer for an address that gets no email: indistinguishable from CodeSent."""
        return CodeSent(challenge_id=secrets.token_urlsafe(32),
                        expires_in_seconds=self.policy.otp_ttl_seconds)

    def _audit(self, action, outcome, *, actor_user_id=None, actor_email=None,
               target_type='user', target_id=None, client_ip=None, workstation_label=None,
               detail=None):
        self.repo.write_audit(action, outcome, actor_user_id=actor_user_id,
                              actor_email=actor_email, target_type=target_type,
                              target_id=None if target_id is None else str(target_id),
                              client_ip=client_ip, workstation_label=workstation_label,
                              detail=detail)

    def _send_code(self, user, purpose, ctx, cooldown=False):
        uid = user['id']
        state = self.repo.challenge_resend_state(uid, purpose, self.policy.resend_cooldown_seconds)
        if state['recent_count'] >= CODES_PER_HOUR:
            self._audit('auth.code_sent', 'denied', actor_user_id=uid, target_id=uid,
                        detail=f'{purpose} code: hourly limit reached', **ctx)
            raise RetryLater(max(state['retry_after_seconds'], 60))
        issued = issue_otp(self._pepper, purpose, uid)
        try:
            public_id = self.repo.create_challenge(
                uid, purpose, issued.code_hmac, self.policy.otp_ttl_seconds,
                max_attempts=self.policy.otp_max_attempts + 1,      # see the module notes
                requester_ip=ctx['client_ip'], workstation_label=ctx['workstation_label'],
                resend_cooldown_seconds=self.policy.resend_cooldown_seconds if cooldown else None)
        except ResendTooSoon as err:
            raise RetryLater(err.retry_after_seconds) from None
        try:
            send_otp_email(self.mailer, user, purpose, issued.code,
                           self.policy.otp_ttl_seconds, ctx['workstation_label'])
        except (MailError, NotEligibleForCode) as err:
            self.repo.invalidate_challenge(public_id)                # an unsent code is void
            self._audit('auth.code_email_failed', 'failure', actor_user_id=uid, target_id=uid,
                        detail=f'{purpose} code not sent ({type(err).__name__}); code voided',
                        **ctx)
            raise DeliveryFailed() from None
        self._audit('auth.code_sent', 'success', actor_user_id=uid, target_id=uid,
                    detail=f'{purpose} code sent', **ctx)
        return CodeSent(challenge_id=public_id, expires_in_seconds=self.policy.otp_ttl_seconds)

    def _open_challenge(self, challenge_id, purpose):
        try:
            c = self.repo.get_challenge(challenge_id)
        except InvalidValue:
            return None
        if (not c or c['purpose'] != purpose or c['consumed_at'] or c['invalidated_at']
                or c['expired'] or c['attempts'] >= self.policy.otp_max_attempts):
            return None
        return c

    def _check_code(self, challenge_id, code, purpose, ctx):
        """The user id if `code` is right for this open challenge of this purpose; the
        challenge is then used up. CodeInvalid otherwise (always the same message)."""
        self._limit(('verify-ip', ctx['client_ip']), self.limits.verify_per_ip)
        self._limit(('verify-challenge', str(challenge_id)[:64]), self.limits.verify_per_challenge)
        c = self._open_challenge(challenge_id, purpose)
        if not c:
            self._audit('auth.code_failed', 'failure',
                        detail=f'{purpose} code for an unknown, used, expired or exhausted '
                               f'challenge', **ctx)
            raise CodeInvalid()
        uid = c['user_id']
        reserved = self.repo.record_failed_attempt(challenge_id)     # reserve this check
        if not reserved or reserved['invalidated']:
            self._audit('auth.code_failed', 'denied', actor_user_id=uid, target_id=uid,
                        detail=f'{purpose} code: attempt limit reached', **ctx)
            raise CodeInvalid()
        try:
            correct = verify_otp(self._pepper, purpose, uid, code, c['code_hmac'])
        except InvalidValue:
            correct = False
        if not correct:
            if reserved['attempts'] >= self.policy.otp_max_attempts:
                self.repo.invalidate_challenge(challenge_id)
            self._audit('auth.code_failed', 'failure', actor_user_id=uid, target_id=uid,
                        detail=f"wrong {purpose} code (attempt {reserved['attempts']} of "
                               f'{self.policy.otp_max_attempts})', **ctx)
            raise CodeInvalid()
        if not self.repo.consume_challenge(challenge_id, purpose, uid):
            self._audit('auth.code_failed', 'failure', actor_user_id=uid, target_id=uid,
                        detail=f'{purpose} code was already used or expired', **ctx)
            raise CodeInvalid()
        return uid
