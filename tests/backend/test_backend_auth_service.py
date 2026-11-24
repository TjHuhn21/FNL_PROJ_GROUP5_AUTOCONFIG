"""The authentication service (backend/auth/service.py) end to end, with the in-memory
repository, a fake mailer and a controllable clock. No database, no network, no real
email; every password, pepper and address is test-only."""
import hashlib
import logging
import re
import threading
from datetime import datetime, timedelta

import pytest

from backend.auth import passwords
from backend.auth import service as service_module
from backend.auth.otp import OtpConfigurationError
from backend.auth.policy import DEFAULT_POLICY
from backend.auth.rate_limit import Limit, SlidingWindowLimiter
from backend.auth.service import (AccountNotActive, AuthService, CodeInvalid, CodeSent,
                                  DeliveryFailed, InvalidRequest, LoginFailed, LoginSucceeded,
                                  NotAuthenticated, NotPermitted, RateLimits, RetryLater)
from backend.database.memory_repository import InMemoryAuthRepository
from backend.mail.delivery import MailDeliveryError
from backend.settings import Secret, parse_settings

PEPPER = Secret('test-only-service-pepper-' + 'x' * 32)
PASSWORD = 'Test-only correct horse 42'
WRONG = 'Test-only wrong password 42'
T0 = datetime(2026, 11, 19, 8, 0, 0)
P = DEFAULT_POLICY


class Clock:
    def __init__(self):
        self.now = T0

    def __call__(self):
        return self.now

    def seconds(self):
        return (self.now - T0).total_seconds()

    def advance(self, seconds):
        self.now += timedelta(seconds=seconds)


class FakeMailer:
    def __init__(self):
        self.sent, self.fail = [], None

    def send(self, outgoing):
        if self.fail:
            raise self.fail
        self.sent.append(outgoing)


def code_of(outgoing):
    return re.search(r'^ {4}([0-9]{6})$', outgoing.text, re.M).group(1)


@pytest.fixture(scope='module')
def hashed():
    return passwords.hash_password(PASSWORD)


class Env:
    def __init__(self, hashed, limits=RateLimits()):
        self.clock = Clock()
        self.repo = InMemoryAuthRepository(clock=self.clock)
        self.mailer = FakeMailer()
        self.hashed = hashed
        self.svc = AuthService(self.repo, self.mailer, PEPPER, limits=limits,
                               limiter=SlidingWindowLimiter(clock=self.clock.seconds))

    def user(self, email='user@example.com', status='active', role='viewer'):
        return self.repo.create_user(email, 'Test User', self.hashed, role=role, status=status,
                                     email_verified=status in ('active', 'pending_approval'))

    def last_code(self):
        return code_of(self.mailer.sent[-1])

    def actions(self):
        return [a['action'] for a in reversed(self.repo.list_audit(limit=1000))]

    def sign_in(self, email='user@example.com', **kw):
        sent = self.svc.login(email, PASSWORD, **kw)
        return self.svc.verify_login(sent.challenge_id, self.last_code(), **kw)


@pytest.fixture
def env(hashed):
    return Env(hashed)


BIG = RateLimits(**{name: Limit(10000, 60) for name in RateLimits.__dataclass_fields__})


# ================================================================ registration
def test_full_registration_verification_and_approval(env):
    admin_id = env.user('admin@example.com', role='admin')
    admin = env.sign_in('admin@example.com')
    sent = env.svc.register('New.Person@Example.com', 'New Person', PASSWORD,
                            client_ip='10.0.0.8', workstation_label='LAB-PC-3')
    assert isinstance(sent, CodeSent) and sent.expires_in_seconds == 300
    mail = env.mailer.sent[-1]
    assert mail.purpose == 'register' and mail.to == 'New.Person@Example.com'
    uid = env.repo.find_user_by_email('new.person@example.com')['id']
    assert env.repo.get_user(uid)['status'] == 'pending_verification'
    assert passwords.verify_password(env.repo.get_password_hash(uid), PASSWORD)
    assert env.svc.verify_registration(sent.challenge_id, env.last_code()) == 'pending_approval'
    user = env.repo.get_user(uid)
    assert user['status'] == 'pending_approval' and user['email_verified_at'] == T0
    with pytest.raises(AccountNotActive):                   # not before approval
        env.svc.login('new.person@example.com', PASSWORD)
    assert [u['id'] for u in env.svc.list_accounts(admin.token, status='pending_approval')] == [uid]
    assert env.svc.approve_account(admin.token, uid, role='operator') is True
    assert env.repo.get_user(uid)['approved_by'] == admin_id
    env.clock.advance(61)
    assert env.sign_in('new.person@example.com').role == 'operator'
    for action in ('auth.register', 'auth.code_sent', 'auth.email_verified', 'user.approved'):
        assert action in env.actions()


def test_taken_addresses_get_the_same_answer_and_no_email(env):
    uid = env.user('taken@example.com')
    before = env.repo.get_password_hash(uid)
    fresh = env.svc.register('fresh@example.com', 'A', PASSWORD)
    env.clock.advance(1)
    taken = env.svc.register('TAKEN@example.com', 'B', PASSWORD)
    assert type(taken) is type(fresh) and len(taken.challenge_id) == len(fresh.challenge_id)
    assert taken.expires_in_seconds == fresh.expires_in_seconds
    assert [m.to for m in env.mailer.sent] == ['fresh@example.com']       # nothing to 'taken'
    assert env.repo.get_password_hash(uid) == before                      # untouched
    with pytest.raises(CodeInvalid):
        env.svc.verify_registration(taken.challenge_id, '123456')
    assert ('auth.register' in env.actions()
            and any(a['outcome'] == 'denied' for a in env.repo.list_audit(action='auth.register')))


@pytest.mark.parametrize('email, name, password, problem', [
    ('not-an-email', 'A', PASSWORD, 'email address'),
    ('a@example.com', '', PASSWORD, 'full name'),
    ('a@example.com', 'A', 'short-pw', 'at least 12'),
    ('a@example.com', 'A', None, 'required'),
])
def test_registration_values_are_checked(env, email, name, password, problem):
    with pytest.raises(InvalidRequest) as err:
        env.svc.register(email, name, password)
    assert problem in str(err.value) and (password or 'x') not in str(err.value)
    assert env.mailer.sent == []


def test_registration_and_login_codes_never_mix(env):
    reg = env.svc.register('mix@example.com', 'Mix', PASSWORD)
    reg_code = env.last_code()
    with pytest.raises(CodeInvalid):
        env.svc.verify_login(reg.challenge_id, reg_code)              # register code: no login
    assert env.svc.verify_registration(reg.challenge_id, reg_code) == 'pending_approval'
    env.user('active@example.com')
    login = env.svc.login('active@example.com', PASSWORD)
    with pytest.raises(CodeInvalid):
        env.svc.verify_registration(login.challenge_id, env.last_code())   # login code
    assert env.svc.verify_login(login.challenge_id, env.last_code()).user_id


def test_resend_registration_code(env):
    env.svc.register('pending@example.com', 'P', PASSWORD)
    env.user('active@example.com')
    env.clock.advance(61)
    resent = env.svc.resend_registration_code('pending@example.com')
    assert env.mailer.sent[-1].to == 'pending@example.com' and len(env.mailer.sent) == 2
    for email in ('pending@example.com', 'nobody@example.com'):     # known or not: same rule
        if email == 'nobody@example.com':
            env.svc.resend_registration_code(email)
        with pytest.raises(RetryLater) as err:
            env.svc.resend_registration_code(email)
        assert err.value.retry_after_seconds == 60 or err.value.retry_after_seconds <= 60
    decoy = env.svc.resend_registration_code('active@example.com')     # not eligible
    assert isinstance(decoy, CodeSent) and len(env.mailer.sent) == 2
    assert env.svc.verify_registration(resent.challenge_id, code_of(env.mailer.sent[1]))


def test_registration_email_failure(env):
    env.mailer.fail = MailDeliveryError('connection')
    with pytest.raises(DeliveryFailed) as err:
        env.svc.register('late@example.com', 'Late', PASSWORD)
    assert str(err.value) == 'The code could not be sent. Try again later.'
    uid = env.repo.find_user_by_email('late@example.com')['id']
    assert env.repo.get_user(uid)['status'] == 'pending_verification'
    (failed,) = env.repo.list_audit(action='auth.code_email_failed')
    assert 'code voided' in failed['detail']
    assert all(c['invalidated_at'] for c in env.repo._challenges.values())   # unsent = void
    env.mailer.fail = None
    env.clock.advance(61)
    sent = env.svc.resend_registration_code('late@example.com')
    assert env.svc.verify_registration(sent.challenge_id, env.last_code()) == 'pending_approval'


# ================================================================ login
def test_full_login_creates_a_session_only_after_the_code(env):
    uid = env.user()
    sent = env.svc.login('USER@example.com', PASSWORD, client_ip='10.0.0.9',
                         workstation_label='LAB-PC-9')
    mail = env.mailer.sent[-1]
    assert mail.purpose == 'login' and 'LAB-PC-9' in mail.text
    assert env.repo.list_sessions(uid) == []                       # password alone: no session
    result = env.svc.verify_login(sent.challenge_id, env.last_code(), client_ip='10.0.0.9')
    assert isinstance(result, LoginSucceeded) and len(result.token) == 43
    assert (result.user_id, result.role, result.expires_in_seconds,
            result.idle_timeout_seconds) == (uid, 'viewer', 28800, 1800)
    (session,) = env.repo._sessions.values()
    assert session['token_hash'] == hashlib.sha256(result.token.encode()).hexdigest()
    assert result.token not in str(env.repo.__dict__)              # only the hash is stored
    assert result.token not in repr(result)
    info = env.svc.validate_session(result.token)
    assert (info.user_id, info.role, info.session_id) == (uid, 'viewer', result.session_id)
    assert env.actions()[-3:] == ['auth.login_password_ok', 'auth.code_sent', 'auth.login']


def test_wrong_password_and_unknown_address_look_the_same(env):
    env.user()
    with pytest.raises(LoginFailed) as wrong:
        env.svc.login('user@example.com', WRONG)
    with pytest.raises(LoginFailed) as unknown:
        env.svc.login('nobody@example.com', PASSWORD)
    with pytest.raises(LoginFailed) as malformed:
        env.svc.login('not an address', PASSWORD)
    assert str(wrong.value) == str(unknown.value) == str(malformed.value)
    assert env.mailer.sent == []
    details = [a['detail'] for a in env.repo.list_audit(action='auth.login')]
    assert any('unknown email' in d for d in details) and any('wrong password' in d for d in details)


def test_every_failure_path_does_one_argon2_check(env, monkeypatch):
    """Unknown address, wrong password and locked account all run exactly one Argon2id
    verification, so their timing does not reveal which case it was."""
    env.user()
    real = passwords._hasher
    calls = []

    class Counting:
        def verify(self, h, p):
            calls.append(1)
            return real.verify(h, p)

        def __getattr__(self, name):
            return getattr(real, name)
    monkeypatch.setattr(passwords, '_hasher', Counting())
    for email, pw in [('nobody@example.com', PASSWORD), ('user@example.com', WRONG)]:
        calls.clear()
        with pytest.raises(LoginFailed):
            env.svc.login(email, pw)
        assert len(calls) == 1
    for _ in range(4):
        with pytest.raises(LoginFailed):
            env.svc.login('user@example.com', WRONG)
    calls.clear()
    with pytest.raises(LoginFailed):                               # locked now
        env.svc.login('user@example.com', PASSWORD)
    assert len(calls) == 1


def test_lockout_after_five_wrong_passwords(env, monkeypatch):
    env.user()
    for _ in range(P.lockout_threshold):
        with pytest.raises(LoginFailed):
            env.svc.login('user@example.com', WRONG)
    assert env.repo.list_audit(action='auth.account_locked')
    monkeypatch.setattr(passwords, 'verify_password',
                        lambda *a: pytest.fail('password checked while locked'))
    with pytest.raises(LoginFailed):
        env.svc.login('user@example.com', PASSWORD)                # right password, still no
    assert env.mailer.sent == []
    monkeypatch.undo()
    env.clock.advance(P.lockout_seconds)
    env.svc.limiter.reset()                                        # the per-email limit, too
    assert env.svc.login('user@example.com', PASSWORD)
    assert env.repo.get_user(1)['failed_logins'] == 0


@pytest.mark.parametrize('status', ['pending_verification', 'pending_approval', 'rejected',
                                    'disabled'])
def test_inactive_accounts_get_no_code(env, status):
    env.user(status=status)
    with pytest.raises(AccountNotActive):
        env.svc.login('user@example.com', PASSWORD)
    with pytest.raises(LoginFailed):
        env.svc.login('user@example.com', WRONG)
    assert env.mailer.sent == [] and env.repo._challenges == {}


def test_login_code_expires(env):
    env.user()
    sent = env.svc.login('user@example.com', PASSWORD)
    env.clock.advance(P.otp_ttl_seconds)
    with pytest.raises(CodeInvalid):
        env.svc.verify_login(sent.challenge_id, env.last_code())
    assert env.repo._sessions == {}


def test_wrong_codes_use_up_the_challenge(env):
    env.user()
    sent = env.svc.login('user@example.com', PASSWORD)
    right = env.last_code()
    wrong = '000000' if right != '000000' else '111111'
    for _ in range(P.otp_max_attempts):
        with pytest.raises(CodeInvalid):
            env.svc.verify_login(sent.challenge_id, wrong)
    with pytest.raises(CodeInvalid):
        env.svc.verify_login(sent.challenge_id, right)             # too late, even if right
    assert env.repo._sessions == {}
    assert env.repo.get_challenge(sent.challenge_id)['invalidated_at'] is not None
    details = [a['detail'] for a in env.repo.list_audit(action='auth.code_failed')]
    assert any('attempt 5 of 5' in d for d in details)


def test_a_code_works_once(env):
    env.user()
    sent = env.svc.login('user@example.com', PASSWORD)
    code = env.last_code()
    env.svc.verify_login(sent.challenge_id, code)
    with pytest.raises(CodeInvalid):
        env.svc.verify_login(sent.challenge_id, code)
    assert len(env.repo._sessions) == 1


def test_parallel_code_guesses_get_at_most_five_checks(hashed, monkeypatch):
    env = Env(hashed, limits=BIG)
    env.user()
    sent = env.svc.login('user@example.com', PASSWORD)
    checks = []
    real = service_module.verify_otp
    monkeypatch.setattr(service_module, 'verify_otp',
                        lambda *a: checks.append(1) or real(*a))
    barrier, outcomes = threading.Barrier(40), []

    def guess(n):
        barrier.wait()
        try:
            env.svc.verify_login(sent.challenge_id, f'{n:06d}')
            outcomes.append('ok')
        except CodeInvalid:
            outcomes.append('no')
    threads = [threading.Thread(target=guess, args=(n,)) for n in range(40)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert len(checks) <= P.otp_max_attempts and len(outcomes) == 40


def test_resend_login_code(env):
    env.user()
    first = env.svc.login('user@example.com', PASSWORD)
    old_code = env.last_code()
    with pytest.raises(RetryLater):
        env.svc.resend_login_code(first.challenge_id)                # within the cooldown
    env.clock.advance(61)
    second = env.svc.resend_login_code(first.challenge_id)
    assert second.challenge_id != first.challenge_id and len(env.mailer.sent) == 2
    with pytest.raises(CodeInvalid):
        env.svc.verify_login(first.challenge_id, old_code)          # the old one stopped
    assert env.svc.verify_login(second.challenge_id, env.last_code())


def test_login_resend_needs_an_open_login_challenge(env):
    reg = env.svc.register('r@example.com', 'R', PASSWORD)
    env.clock.advance(61)
    for bogus in ('x' * 43, 'not valid!', reg.challenge_id):
        with pytest.raises(CodeInvalid):
            env.svc.resend_login_code(bogus)
    assert len(env.mailer.sent) == 1


def test_codes_per_hour_are_capped(env):
    env.user()
    for _ in range(service_module.CODES_PER_HOUR):
        env.svc.login('user@example.com', PASSWORD)
        env.clock.advance(61)
    with pytest.raises(RetryLater):
        env.svc.login('user@example.com', PASSWORD)
    assert len(env.mailer.sent) == service_module.CODES_PER_HOUR


def test_unknown_addresses_are_rate_limited_like_known_ones(env):
    env.user()
    for email in ('nobody@example.com', 'user@example.com'):
        outcomes = []
        for _ in range(RateLimits().login_per_email.count + 1):
            try:
                env.svc.login(email, WRONG)
            except (LoginFailed, RetryLater) as err:
                outcomes.append(type(err).__name__)
        assert outcomes[-1] == 'RetryLater' and outcomes[:-1] == ['LoginFailed'] * 10


def test_login_email_failure_voids_the_code_and_creates_no_session(env):
    env.user()
    env.mailer.fail = MailDeliveryError('authentication')
    with pytest.raises(DeliveryFailed):
        env.svc.login('user@example.com', PASSWORD)
    assert all(c['invalidated_at'] for c in env.repo._challenges.values())
    assert env.repo._sessions == {}
    assert env.repo.list_audit(action='auth.code_email_failed')


# ================================================================ sessions
def test_idle_timeout(env):
    env.user()
    token = env.sign_in().token
    env.clock.advance(P.idle_timeout_seconds - 1)
    env.svc.validate_session(token)                                # activity restarts the timer
    env.clock.advance(P.idle_timeout_seconds - 1)
    env.svc.validate_session(token)
    env.clock.advance(P.idle_timeout_seconds)
    with pytest.raises(NotAuthenticated):
        env.svc.validate_session(token)
    env.clock.advance(1)
    with pytest.raises(NotAuthenticated):
        env.svc.validate_session(token)


def test_absolute_expiry_even_with_activity(env):
    env.user()
    token = env.sign_in().token
    for _ in range(int(P.session_lifetime_seconds / 1200) - 1):
        env.clock.advance(1200)
        env.svc.validate_session(token)
    env.clock.advance(1200)                                        # 8 hours reached
    with pytest.raises(NotAuthenticated):
        env.svc.validate_session(token)


def test_logout(env):
    uid = env.user()
    result = env.sign_in()
    assert env.svc.logout(result.token, client_ip='10.0.0.9') is True
    with pytest.raises(NotAuthenticated):
        env.svc.validate_session(result.token)
    assert env.svc.logout(result.token) is False
    (row,) = env.repo.list_audit(action='auth.logout')
    assert row['actor_user_id'] == uid and row['target_id'] == str(result.session_id)


@pytest.mark.parametrize('token', ['', None, 'x' * 42, 'x' * 43, 42])
def test_invalid_tokens(env, token):
    with pytest.raises(NotAuthenticated):
        env.svc.validate_session(token)


def test_disabling_an_account_ends_its_sessions_and_codes(env):
    env.user('admin@example.com', role='admin')
    admin = env.sign_in('admin@example.com')
    uid = env.user()
    token = env.sign_in().token
    env.clock.advance(61)
    pending = env.svc.login('user@example.com', PASSWORD)
    assert env.svc.disable_account(admin.token, uid) is True
    with pytest.raises(NotAuthenticated):
        env.svc.validate_session(token)
    assert all(s['revoked_reason'] == 'account_disabled'
               for s in env.repo._sessions.values() if s['user_id'] == uid)
    with pytest.raises(CodeInvalid):
        env.svc.verify_login(pending.challenge_id, env.last_code())
    assert 'auth.sessions_revoked' in env.actions()


def test_a_status_change_outside_the_service_also_ends_access(env):
    env.user('admin@example.com', role='admin')
    uid = env.user()
    token = env.sign_in().token
    env.repo.set_status(uid, 'disabled', actor_user_id=1)
    with pytest.raises(NotAuthenticated):
        env.svc.validate_session(token)


def test_admin_actions_need_an_admin(env):
    env.user()
    viewer = env.sign_in()
    target = env.user('p@example.com', status='pending_approval')
    for call in (lambda: env.svc.approve_account(viewer.token, target),
                 lambda: env.svc.reject_account(viewer.token, target),
                 lambda: env.svc.disable_account(viewer.token, target),
                 lambda: env.svc.list_accounts(viewer.token)):
        with pytest.raises(NotPermitted):
            call()
    with pytest.raises(NotAuthenticated):
        env.svc.approve_account('x' * 43, target)
    assert env.repo.get_user(target)['status'] == 'pending_approval'
    assert any(a['outcome'] == 'denied' for a in env.repo.list_audit())


def test_reject_and_last_admin_protection(env):
    admin_id = env.user('admin@example.com', role='admin')
    admin = env.sign_in('admin@example.com')
    target = env.user('p@example.com', status='pending_approval')
    assert env.svc.reject_account(admin.token, target) is True
    assert env.repo.get_user(target)['status'] == 'rejected'
    with pytest.raises(InvalidRequest, match='your own account'):
        env.svc.disable_account(admin.token, admin_id)     # never oneself
    assert env.repo.get_user(admin_id)['status'] == 'active'
    # the last active admin cannot be disabled by anyone: the repository refuses it
    with pytest.raises(Exception, match='at least one active admin'):
        env.repo.set_status(admin_id, 'disabled', actor_user_id=None)


# ================================================================ secrets
def test_no_secret_reaches_the_audit_log_or_the_logs(env, caplog):
    with caplog.at_level(logging.DEBUG):
        reg = env.svc.register('s@example.com', 'S', PASSWORD)
        reg_code = env.last_code()
        with pytest.raises(CodeInvalid):
            env.svc.verify_registration(reg.challenge_id,
                                        '000000' if reg_code != '000000' else '1' * 6)
        env.svc.verify_registration(reg.challenge_id, reg_code)
        env.user()
        with pytest.raises(LoginFailed):
            env.svc.login('user@example.com', WRONG)
        sent = env.svc.login('user@example.com', PASSWORD)
        login_code = env.last_code()
        result = env.svc.verify_login(sent.challenge_id, login_code)
        env.svc.logout(result.token)
    audit_text = str(env.repo.list_audit(limit=1000))
    hashes = [env.repo.get_password_hash(1)] + [c['code_hmac'] for c in env.repo._challenges.values()]
    for secret in [PASSWORD, WRONG, reg_code, login_code, result.token, PEPPER.reveal(), *hashes,
                   hashlib.sha256(result.token.encode()).hexdigest()]:
        assert secret not in audit_text and secret not in caplog.text


def test_results_and_errors_reveal_nothing(env):
    env.user()
    sent = env.svc.login('user@example.com', PASSWORD)
    code = env.last_code()
    assert code not in repr(sent) and code not in str(sent.__dict__)
    result = env.svc.verify_login(sent.challenge_id, code)
    assert result.token not in repr(result) and result.token not in str(result)
    for err in (LoginFailed(), CodeInvalid(), AccountNotActive(), DeliveryFailed(),
                NotAuthenticated(), RetryLater(30)):
        assert code not in str(err) and PASSWORD not in str(err)


def test_service_requires_a_pepper_and_builds_from_settings(env):
    with pytest.raises(OtpConfigurationError):
        AuthService(env.repo, env.mailer, None)
    with pytest.raises(OtpConfigurationError):
        AuthService(env.repo, env.mailer, Secret('too-short'))
    settings = parse_settings({'BACKEND_OTP_PEPPER': PEPPER.reveal(),
                               'BACKEND_AUTH_OTP_TTL_SECONDS': '120'})
    svc = AuthService.from_settings(settings, repository=env.repo, mailer=env.mailer)
    assert svc.policy.otp_ttl_seconds == 120
    with pytest.raises(OtpConfigurationError):
        AuthService.from_settings(parse_settings({}), repository=env.repo, mailer=env.mailer)
