"""The security lockout for failed DEVICE logins, through the real API and AuthService with
the in-memory repository and a test clock. No database, network or real email."""
import pytest

from backend.auth import device_lockout as DL
from test_backend_auth_api import PASSWORD, Api, hashed, no_real_mysql  # noqa: F401

DEVICE = '127.0.0.11'


@pytest.fixture
def api(hashed):  # noqa: F811
    return Api(hashed)


def report(api, token, outcome='auth_failed', ip=DEVICE):
    return api.post('/security/device-login', {'device_ip': ip, 'outcome': outcome}, token=token)


def fail(api, token, times, outcome='auth_failed'):
    answers = []
    for _ in range(times):
        r = report(api, token, outcome)
        assert r.status_code == 200, r.text
        answers.append(r.json())
    return answers


def lock_once(api, email='user@example.com'):
    """Sign in and fail five times: the account is locked (returns the 5th answer)."""
    token = api.sign_in(email)
    return fail(api, token, DL.MAX_FAILED_DEVICE_LOGINS)[-1], token


def audit(api, action):
    return api.repo.list_audit(action=action)


# ---------------------------------------------------------------- limits in one place
def test_the_limits_are_the_approved_ones():
    assert (DL.MAX_FAILED_DEVICE_LOGINS, DL.FAILED_WINDOW_MINUTES, DL.LOCKOUT_MINUTES,
            DL.MAX_LOCKOUTS_BEFORE_PERMANENT, DL.LOCKOUT_COUNT_WINDOW_HOURS) == (5, 10, 15, 3, 24)


# ---------------------------------------------------------------- counting and warnings
def test_each_failure_says_how_many_attempts_are_left(api):
    api.user()
    token = api.sign_in()
    answers = fail(api, token, 4, 'auth_failed')
    assert [a['remaining'] for a in answers] == [4, 3, 2, 1]
    assert all(a['event'] == 'failed' and a['locked'] is None for a in answers)
    rows = audit(api, 'security.device_login_failed')
    assert len(rows) == 4
    assert 'u*****@example.com' in rows[0]['detail'] and DEVICE in rows[0]['detail']
    assert 'wrong username or password' in rows[0]['detail']
    assert 'user@example.com' not in rows[0]['detail']                # masked


def test_unreachable_devices_count_too_and_success_resets(api):
    api.user()
    token = api.sign_in()
    assert fail(api, token, 3, 'unreachable')[-1]['remaining'] == 2
    assert 'no answer' in audit(api, 'security.device_login_failed')[0]['detail']
    ok = report(api, token, 'success').json()
    assert ok['event'] == 'reset' and ok['failed_count'] == 0
    assert fail(api, token, 1)[0]['remaining'] == 4                   # counting starts again


def test_failures_count_only_within_ten_minutes(api):
    api.user()
    token = api.sign_in()
    fail(api, token, 4)
    api.clock.advance(DL.FAILED_WINDOW_MINUTES * 60 + 1)
    token = api.sign_in()                                    # (the idle timer is not the point)
    assert fail(api, token, 1)[0]['remaining'] == 4          # a new window


# ---------------------------------------------------------------- the 15-minute lock
def test_fifth_failure_locks_for_15_minutes_and_signs_out(api):
    api.user()
    answer, token = lock_once(api)
    assert answer['event'] == 'temporary' and answer['locked'] == 'temporary'
    assert answer['lockouts'] == 1 and answer['lockouts_left'] == 2
    assert 'locked for 15 minutes' in answer['message'] and '2 more lockouts' in answer['message']
    assert 'after 3 lockouts in 24 hours' in answer['message']
    assert api.get('/auth/session', token=token).status_code == 401      # signed out
    assert audit(api, 'security.account_locked') and audit(api, 'auth.sessions_revoked')
    assert api.repo.list_sessions(1)[0]['revoked_reason'] == 'security_lock'

    sent = len(api.mailer.sent)
    r = api.post('/auth/login', {'email': 'user@example.com', 'password': PASSWORD})
    assert r.status_code == 403 and r.json()['error'] == 'account_locked'
    assert 'locked for 15 more minutes' in r.json()['detail']
    assert len(api.mailer.sent) == sent                                   # no code sent
    api.clock.advance(10 * 60)
    r = api.post('/auth/login', {'email': 'user@example.com', 'password': PASSWORD})
    assert 'locked for 5 more minutes' in r.json()['detail']
    api.clock.advance(5 * 60 + 1)                                         # expires by itself
    assert api.sign_in()


def test_a_code_sent_before_the_lock_cannot_open_a_session(api):
    api.user()
    token = api.sign_in()
    api.clock.advance(61)                                        # the resend cooldown
    r = api.post('/auth/login', {'email': 'user@example.com', 'password': PASSWORD})
    challenge, code = r.json()['challenge_id'], api.code()
    fail(api, token, 5)                                          # locked meanwhile
    v = api.post('/auth/login/verify', {'challenge_id': challenge, 'code': code})
    assert v.status_code in (400, 403) and 'token' not in v.text


def test_a_wrong_password_on_a_locked_account_still_says_nothing_more(api):
    api.user()
    lock_once(api)
    r = api.post('/auth/login', {'email': 'user@example.com', 'password': 'Test-only wrong 123'})
    assert r.status_code == 401 and r.json()['error'] == 'login_failed'


# ---------------------------------------------------------------- the permanent lock
def lock_three_times(api):
    for i in range(DL.MAX_LOCKOUTS_BEFORE_PERMANENT):
        answer, _ = lock_once(api)
        if i < DL.MAX_LOCKOUTS_BEFORE_PERMANENT - 1:
            api.clock.advance(DL.LOCKOUT_MINUTES * 60 + 1)
    return answer


def test_third_lockout_in_24_hours_is_permanent(api):
    api.user()
    answer = lock_three_times(api)
    assert answer['event'] == 'permanent' and answer['locked'] == 'permanent'
    assert answer['message'] == DL.PERMANENT_MESSAGE
    assert answer['lockouts'] == 3 and answer['lockouts_left'] == 0
    assert [x['kind'] for x in api.repo.list_lockouts(1)] == ['temporary', 'temporary', 'permanent']
    assert audit(api, 'security.account_locked_permanent')
    for days in (0, 3):
        api.clock.advance(days * 24 * 3600)
        sent = len(api.mailer.sent)
        r = api.post('/auth/login', {'email': 'user@example.com', 'password': PASSWORD})
        assert r.status_code == 403 and r.json()['detail'] == DL.PERMANENT_MESSAGE
        assert len(api.mailer.sent) == sent


def test_lockouts_older_than_24_hours_do_not_count(api):
    api.user()
    lock_once(api)
    api.clock.advance(DL.LOCKOUT_MINUTES * 60 + 1)
    lock_once(api)
    api.clock.advance(DL.LOCKOUT_COUNT_WINDOW_HOURS * 3600)      # the first two are now old
    answer, _ = lock_once(api)
    assert answer['event'] == 'temporary' and answer['lockouts'] == 1


# ---------------------------------------------------------------- unlocking
def admin_token(api, email='boss@example.com'):
    api.user(email, role='admin')
    return api.sign_in(email)


def test_only_an_admin_can_unlock_and_it_resets_everything(api):
    api.user()
    lock_three_times(api)
    boss = admin_token(api)
    api.user('op@example.com', role='operator')
    op = api.sign_in('op@example.com')
    r = api.post('/admin/users/1/unlock', token=op)
    assert r.status_code == 403                                    # server-side rule
    listed = {u['id']: u for u in api.get('/admin/users', token=boss).json()['users']}
    assert listed[1]['security_lock'] == 'permanent'
    r = api.post('/admin/users/1/unlock', token=boss)
    assert r.status_code == 200 and r.json()['cleared'] == 'permanent'
    rows = audit(api, 'security.unlocked')
    assert rows[0]['actor_user_id'] == 2 and 'b*****@example.com' in rows[0]['detail']
    api.clock.advance(61)                                          # the resend cooldown
    token = api.sign_in()                                          # works again
    answer = fail(api, token, 5)[-1]
    assert answer['event'] == 'temporary' and answer['lockouts'] == 1   # lockout count reset


def test_temporary_lock_shows_until_when_and_unlocks(api):
    api.user()
    lock_once(api)
    boss = admin_token(api)
    listed = {u['id']: u for u in api.get('/admin/users', token=boss).json()['users']}
    assert listed[1]['security_lock'] == 'temporary' and listed[1]['security_locked_until']
    assert api.post('/admin/users/1/unlock', token=boss).json()['cleared'] == 'temporary'
    api.clock.advance(61)                                          # the resend cooldown
    assert api.sign_in()


def test_an_admin_cannot_unlock_themselves(api):
    boss = admin_token(api, 'boss@example.com')
    r = api.post('/admin/users/1/unlock', token=boss)
    assert r.status_code == 400 and 'your own account' in r.json()['detail']


def test_recovery_command_unlocks_the_only_admin(api):
    import manage
    api.user('boss@example.com', role='admin')
    for i in range(DL.MAX_LOCKOUTS_BEFORE_PERMANENT):
        lock_once(api, 'boss@example.com')
        if i < DL.MAX_LOCKOUTS_BEFORE_PERMANENT - 1:
            api.clock.advance(DL.LOCKOUT_MINUTES * 60 + 1)
    r = api.post('/auth/login', {'email': 'boss@example.com', 'password': PASSWORD})
    assert r.json()['detail'] == DL.PERMANENT_MESSAGE
    out = []
    assert manage.run(['lock-status', 'boss@example.com'], out.append, api.svc) == 0
    assert 'LOCKED until an administrator unlocks it' in out[-1]
    assert manage.run(['unlock-user', 'boss@example.com'], out.append, api.svc) == 0
    assert 'The permanent lock was cleared' in out[-1]
    assert 'recovery command' in audit(api, 'security.unlocked')[0]['detail']
    api.clock.advance(61)                                          # the resend cooldown
    assert api.sign_in('boss@example.com')
    assert manage.run(['unlock-user', 'nobody@example.com'], out.append, api.svc) == 1
    assert manage.run(['bad'], out.append, api.svc) == 2


# ---------------------------------------------------------------- input
@pytest.mark.parametrize('body', [{'device_ip': DEVICE, 'outcome': 'maybe'},
                                  {'device_ip': 'x' * 46, 'outcome': 'auth_failed'},
                                  {'outcome': 'auth_failed', 'extra': 1}])
def test_report_input_is_validated(api, body):
    api.user()
    token = api.sign_in()
    assert api.post('/security/device-login', body, token=token).status_code in (400, 422)


def test_report_needs_a_session(api):
    assert report(api, None).status_code == 401


# ---------------------------------------------------------------- TESTING MODE (dev reset)
def test_dev_flag_is_one_setting_and_production_never_resets():
    assert DL.DEV_RESET_LOCKS_ON_RESTART in (True, False)
    assert DL.dev_reset_enabled('production') is False


def test_dev_reset_endpoint_clears_attempts_and_both_locks(api, monkeypatch):
    monkeypatch.setattr(DL, 'DEV_RESET_LOCKS_ON_RESTART', True)
    api.user()
    api.user('other@example.com')
    for i in range(DL.MAX_LOCKOUTS_BEFORE_PERMANENT):                # user 1: permanent
        lock_once(api)
        if i < DL.MAX_LOCKOUTS_BEFORE_PERMANENT - 1:
            api.clock.advance(DL.LOCKOUT_MINUTES * 60 + 1)
    fail(api, api.sign_in('other@example.com'), 2)                   # user 2: 2 attempts
    r = api.post('/dev/reset-locks')
    assert r.status_code == 200 and r.json() == {'testing_mode': True, 'reset_users': 2}
    for uid in (1, 2):
        state, now, lockouts = api.repo.device_login_state(uid)
        assert DL.is_locked(state, now) is None and state['failed_count'] == 0 and lockouts == 0
    assert len(api.repo.list_lockouts(1)) == 3                       # history kept
    assert api.repo.get_user(1) is not None                          # nothing deleted
    assert audit(api, 'security.dev_reset')
    api.clock.advance(61)
    token = api.sign_in()                                            # can sign in again
    assert fail(api, token, 1)[0]['remaining'] == 4


def test_dev_endpoint_is_absent_or_refused_when_testing_mode_is_off(hashed, monkeypatch):  # noqa: F811
    monkeypatch.setattr(DL, 'DEV_RESET_LOCKS_ON_RESTART', False)
    assert Api(hashed).post('/dev/reset-locks').status_code == 404    # not even registered
    monkeypatch.setattr(DL, 'DEV_RESET_LOCKS_ON_RESTART', True)
    api = Api(hashed)
    monkeypatch.setattr(DL, 'DEV_RESET_LOCKS_ON_RESTART', False)     # turned off later
    assert api.post('/dev/reset-locks').status_code == 403


def test_dev_endpoint_only_answers_this_computer(hashed, monkeypatch):  # noqa: F811
    from fastapi.testclient import TestClient
    monkeypatch.setattr(DL, 'DEV_RESET_LOCKS_ON_RESTART', True)
    api = Api(hashed)
    remote = TestClient(api.app, client=('10.0.0.5', 50000))
    assert remote.post('/dev/reset-locks').status_code == 403


def test_dev_endpoint_is_never_registered_in_production(monkeypatch):
    from backend.app import create_app
    from backend.settings import parse_settings
    from fastapi.testclient import TestClient
    monkeypatch.setattr(DL, 'DEV_RESET_LOCKS_ON_RESTART', True)
    app = create_app(parse_settings({'BACKEND_ENV': 'production'}), auth_service=object())
    assert not any(getattr(r, 'path', '') == '/dev/reset-locks' for r in app.routes)


def test_backend_start_prints_the_dev_line(api, monkeypatch):
    from backend import __main__ as start
    from backend.auth import service as service_module
    monkeypatch.setattr(DL, 'DEV_RESET_LOCKS_ON_RESTART', True)
    api.user()
    lock_once(api)
    monkeypatch.setattr(service_module.AuthService, 'from_settings',
                        classmethod(lambda cls, settings, **k: api.svc))

    class Settings:
        environment, database = 'development', object()
    out = []
    assert start.dev_reset_on_start(Settings, out.append) == 1
    assert out == ['[DEV] Lockout reset on startup: cleared attempts and locks for 1 user. '
                   'Set DEV_RESET_LOCKS_ON_RESTART = False to disable.']
    state, now, _ = api.repo.device_login_state(1)
    assert DL.is_locked(state, now) is None
    monkeypatch.setattr(DL, 'DEV_RESET_LOCKS_ON_RESTART', False)
    out.clear()
    assert start.dev_reset_on_start(Settings, out.append) is None and out == []
