"""The authentication API (backend/api/auth_routes.py) over the real AuthService with the
in-memory repository and a fake mailer. No database, no network, no real email; every
password, pepper and address is test-only."""
import logging
import re
from datetime import datetime, timedelta

import pymysql
import pytest
from fastapi import Depends
from fastapi.testclient import TestClient

from backend.api import auth_routes
from backend.app import create_app
from backend.auth import passwords
from backend.auth.policy import DEFAULT_POLICY as P
from backend.auth.rate_limit import Limit, SlidingWindowLimiter
from backend.auth.service import AuthService
from backend.database.errors import BackendDatabaseUnavailable
from backend.database.memory_repository import InMemoryAuthRepository
from backend.mail.delivery import MailDeliveryError
from backend.settings import Secret, parse_settings

PEPPER = Secret('test-only-api-pepper-' + 'y' * 32)
PASSWORD = 'Test-only api password 77'
WRONG = 'Test-only wrong api password'
T0 = datetime(2026, 11, 19, 9, 0, 0)
NOT_AUTH = {'detail': 'Sign in again.', 'error': 'not_authenticated'}
LOGIN_FAILED = {'detail': 'The email address or password is incorrect, or the account is '
                          'locked.', 'error': 'login_failed'}


@pytest.fixture(autouse=True)
def no_real_mysql(monkeypatch):
    monkeypatch.setattr(pymysql, 'connect',
                        lambda *a, **k: pytest.fail('tried to open a real MySQL connection'))


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


@pytest.fixture(scope='module')
def hashed():
    return passwords.hash_password(PASSWORD)


class Api:
    def __init__(self, hashed):
        self.clock = Clock()
        self.repo = InMemoryAuthRepository(clock=self.clock)
        self.mailer = FakeMailer()
        self.hashed = hashed
        self.svc = AuthService(self.repo, self.mailer, PEPPER,
                               limiter=SlidingWindowLimiter(clock=self.clock.seconds))
        self.app = create_app(parse_settings({}), auth_service=self.svc)
        self.client = TestClient(self.app)

    def user(self, email='user@example.com', status='active', role='viewer'):
        return self.repo.create_user(email, 'Api User', self.hashed, role=role, status=status,
                                     email_verified=status in ('active', 'pending_approval'))

    def code(self):
        return re.search(r'^ {4}([0-9]{6})$', self.mailer.sent[-1].text, re.M).group(1)

    def post(self, path, json=None, token=None, **kw):
        headers = kw.pop('headers', {})
        if token:
            headers['Authorization'] = f'Bearer {token}'
        return self.client.post(path, json=json, headers=headers, **kw)

    def get(self, path, token=None, **kw):
        headers = kw.pop('headers', {})
        if token:
            headers['Authorization'] = f'Bearer {token}'
        return self.client.get(path, headers=headers, **kw)

    def sign_in(self, email='user@example.com'):
        r = self.post('/auth/login', {'email': email, 'password': PASSWORD})
        assert r.status_code == 202, r.text
        v = self.post('/auth/login/verify', {'challenge_id': r.json()['challenge_id'],
                                             'code': self.code()})
        assert v.status_code == 200, v.text
        return v.json()['token']


@pytest.fixture
def api(hashed):
    return Api(hashed)


# ================================================================ registration
def test_registration_and_verification(api):
    r = api.post('/auth/register', {'email': 'new@example.com', 'full_name': 'New',
                                    'password': PASSWORD},
                 headers={'X-NetCommand-Workstation': 'LAB-PC-2'})
    assert r.status_code == 202 and r.headers['cache-control'] == 'no-store'
    body = r.json()
    assert set(body) == {'challenge_id', 'expires_in_seconds', 'message'}
    assert body['expires_in_seconds'] == 300 and api.mailer.sent[-1].purpose == 'register'
    v = api.post('/auth/register/verify', {'challenge_id': body['challenge_id'],
                                           'code': api.code()})
    assert v.status_code == 200 and v.json() == {'status': 'pending_approval'}
    user = api.repo.find_user_by_email('new@example.com')
    assert user['status'] == 'pending_approval'
    (audit,) = api.repo.list_audit(action='auth.register')
    assert audit['workstation_label'] == 'LAB-PC-2' and audit['client_ip'] == 'testclient'


def test_duplicate_registration_looks_like_a_new_one(api):
    api.user('taken@example.com')
    fresh = api.post('/auth/register', {'email': 'fresh@example.com', 'full_name': 'F',
                                        'password': PASSWORD})
    taken = api.post('/auth/register', {'email': 'Taken@Example.com', 'full_name': 'T',
                                        'password': PASSWORD})
    assert fresh.status_code == taken.status_code == 202
    assert fresh.json()['message'] == taken.json()['message']
    assert set(fresh.json()) == set(taken.json())
    assert len(taken.json()['challenge_id']) == len(fresh.json()['challenge_id'])
    assert [m.to for m in api.mailer.sent] == ['fresh@example.com']
    bad = api.post('/auth/register/verify', {'challenge_id': taken.json()['challenge_id'],
                                             'code': '123456'})
    assert bad.status_code == 400 and bad.json()['error'] == 'code_invalid'


def test_registration_resend_is_the_same_for_any_address(api):
    api.post('/auth/register', {'email': 'p@example.com', 'full_name': 'P', 'password': PASSWORD})
    api.clock.advance(61)
    for email in ('p@example.com', 'nobody@example.com'):
        first = api.post('/auth/register/resend', {'email': email})
        second = api.post('/auth/register/resend', {'email': email})
        assert first.status_code == 202 and second.status_code == 429
        assert int(second.headers['retry-after']) > 0
        assert second.json()['error'] == 'rate_limited'
    assert [m.to for m in api.mailer.sent] == ['p@example.com', 'p@example.com']


def test_registration_validation(api):
    r = api.post('/auth/register', {'email': 'a@example.com', 'full_name': 'A',
                                    'password': 'short-pw'})
    assert r.status_code == 400 and r.json()['error'] == 'invalid_request'
    assert 'at least 12' in r.json()['detail'] and 'short-pw' not in r.text


# ================================================================ login
def test_login_then_code_then_session(api):
    uid = api.user()
    r = api.post('/auth/login', {'email': 'user@example.com', 'password': PASSWORD})
    assert r.status_code == 202 and 'token' not in r.text
    assert api.repo.list_sessions(uid) == []                    # no session yet
    v = api.post('/auth/login/verify', {'challenge_id': r.json()['challenge_id'],
                                        'code': api.code()})
    assert v.status_code == 200
    assert v.headers['cache-control'] == 'no-store' and v.headers['pragma'] == 'no-cache'
    body = v.json()
    assert body['token_type'] == 'bearer' and len(body['token']) == 43
    assert (body['user_id'], body['role'], body['expires_in_seconds'],
            body['idle_timeout_seconds']) == (uid, 'viewer', 28800, 1800)
    s = api.get('/auth/session', token=body['token'])
    assert s.status_code == 200 and s.json() == {'user_id': uid, 'role': 'viewer',
                                                 'session_id': body['session_id']}
    assert body['token'] not in s.text


def test_wrong_password_unknown_and_malformed_addresses_answer_alike(api):
    api.user()
    answers = [api.post('/auth/login', {'email': e, 'password': p})
               for e, p in [('user@example.com', WRONG), ('nobody@example.com', PASSWORD),
                            ('not an address', PASSWORD)]]
    for r in answers:
        assert r.status_code == 401 and r.json() == LOGIN_FAILED
        assert r.headers['www-authenticate'] == 'Bearer'


def test_locked_account(api):
    api.user()
    for _ in range(P.lockout_threshold):
        api.post('/auth/login', {'email': 'user@example.com', 'password': WRONG})
    r = api.post('/auth/login', {'email': 'user@example.com', 'password': PASSWORD})
    assert r.status_code == 401 and r.json() == LOGIN_FAILED
    assert api.mailer.sent == []


@pytest.mark.parametrize('status', ['pending_verification', 'pending_approval', 'rejected',
                                    'disabled'])
def test_inactive_accounts(api, status):
    api.user(status=status)
    r = api.post('/auth/login', {'email': 'user@example.com', 'password': PASSWORD})
    assert r.status_code == 403 and r.json()['error'] == 'account_not_active'
    wrong = api.post('/auth/login', {'email': 'user@example.com', 'password': WRONG})
    assert wrong.status_code == 401
    assert api.mailer.sent == []


def test_wrong_expired_and_reused_codes(api):
    api.user()
    r = api.post('/auth/login', {'email': 'user@example.com', 'password': PASSWORD})
    cid, code = r.json()['challenge_id'], api.code()
    wrong = api.post('/auth/login/verify', {'challenge_id': cid,
                                            'code': '000000' if code != '000000' else '111111'})
    assert wrong.status_code == 400 and wrong.json()['error'] == 'code_invalid'
    ok = api.post('/auth/login/verify', {'challenge_id': cid, 'code': code})
    assert ok.status_code == 200
    again = api.post('/auth/login/verify', {'challenge_id': cid, 'code': code})
    assert again.status_code == 400
    api.clock.advance(61)
    r2 = api.post('/auth/login', {'email': 'user@example.com', 'password': PASSWORD})
    api.clock.advance(P.otp_ttl_seconds)
    expired = api.post('/auth/login/verify', {'challenge_id': r2.json()['challenge_id'],
                                              'code': api.code()})
    assert expired.status_code == 400 and expired.json() == wrong.json()


def test_login_resend(api):
    api.user()
    r = api.post('/auth/login', {'email': 'user@example.com', 'password': PASSWORD})
    cid = r.json()['challenge_id']
    assert api.post('/auth/login/resend', {'challenge_id': cid}).status_code == 429
    api.clock.advance(61)
    again = api.post('/auth/login/resend', {'challenge_id': cid})
    assert again.status_code == 202 and again.json()['challenge_id'] != cid
    bogus = api.post('/auth/login/resend', {'challenge_id': 'A' * 43})
    assert bogus.status_code == 400 and bogus.json()['error'] == 'code_invalid'


# ================================================================ sessions and bearer tokens
def test_logout(api):
    api.user()
    token = api.sign_in()
    r = api.post('/auth/logout', token=token)
    assert r.status_code == 204 and r.content == b''
    assert api.get('/auth/session', token=token).json() == NOT_AUTH
    assert api.post('/auth/logout', token=token).status_code == 204       # nothing left to end
    assert api.post('/auth/logout').status_code == 401


def test_idle_and_absolute_expiry(api):
    api.user()
    token = api.sign_in()
    api.clock.advance(P.idle_timeout_seconds)
    assert api.get('/auth/session', token=token).status_code == 401
    api.clock.advance(61)
    token = api.sign_in()
    for _ in range(int(P.session_lifetime_seconds / 1200) - 1):
        api.clock.advance(1200)
        assert api.get('/auth/session', token=token).status_code == 200
    api.clock.advance(1200)
    assert api.get('/auth/session', token=token).status_code == 401


@pytest.mark.parametrize('header', [None, 'Basic dXNlcjpwYXNz', 'Bearer', 'Bearer ',
                                    'Bearer a b', 'Bearer ' + 'x' * 500, 'Bearer ' + 'x' * 43,
                                    'bearer ' + 'A' * 43, 'Token abc'])
def test_missing_malformed_and_invalid_bearer_tokens(api, header):
    headers = {'Authorization': header} if header is not None else {}
    r = api.client.get('/auth/session', headers=headers)
    assert r.status_code == 401 and r.json() == NOT_AUTH
    assert r.headers['www-authenticate'] == 'Bearer'


def test_tokens_are_never_read_from_the_url(api):
    api.user()
    token = api.sign_in()
    assert api.client.get(f'/auth/session?token={token}').status_code == 401
    assert api.client.get(f'/auth/session?access_token={token}').status_code == 401
    spec = api.client.get('/openapi.json').json()
    params = [p['name'] for path in spec['paths'].values() for op in path.values()
              for p in op.get('parameters', [])]
    assert not any('token' in p.lower() for p in params)


def test_disabled_accounts_lose_their_sessions(api):
    uid = api.user()
    token = api.sign_in()
    api.repo.set_status(uid, 'disabled', actor_user_id=None)
    assert api.get('/auth/session', token=token).status_code == 401


# ================================================================ roles and admin
def signed_in_roles(api):
    tokens = {}
    for role in ('viewer', 'operator', 'admin'):
        api.user(f'{role}@example.com', role=role)
        tokens[role] = api.sign_in(f'{role}@example.com')
    return tokens


def test_only_admins_reach_admin_endpoints(api):
    tokens = signed_in_roles(api)
    target = api.user('pending@example.com', status='pending_approval')
    calls = [('get', '/admin/users'), ('post', f'/admin/users/{target}/approve'),
             ('post', f'/admin/users/{target}/reject'), ('post', f'/admin/users/{target}/disable')]
    for role in ('viewer', 'operator'):
        for method, path in calls:
            r = getattr(api, method)(path, token=tokens[role])
            assert r.status_code == 403 and r.json()['error'] == 'not_permitted', (role, path)
    for method, path in calls:
        assert getattr(api, method)(path).status_code == 401
    assert api.repo.get_user(target)['status'] == 'pending_approval'
    denied = [a for a in api.repo.list_audit(limit=1000) if a['outcome'] == 'denied']
    assert len(denied) >= 8


def test_admin_list_approve_reject_disable(api):
    tokens = signed_in_roles(api)
    a = api.user('a@example.com', status='pending_approval')
    b = api.user('b@example.com', status='pending_approval')
    listed = api.get('/admin/users?status=pending_approval', token=tokens['admin'])
    assert listed.status_code == 200
    rows = listed.json()['users']
    assert [r['id'] for r in rows] == [a, b]
    for row in rows:
        assert set(row) == {'id', 'email', 'full_name', 'role', 'status', 'email_verified_at',
                            'approved_by', 'approved_at', 'created_at', 'updated_at', 'locked'}
    assert api.hashed not in listed.text
    ok = api.post(f'/admin/users/{a}/approve', {'role': 'operator'}, token=tokens['admin'])
    assert ok.status_code == 200 and ok.json() == {'user_id': a, 'status': 'active'}
    assert api.repo.get_user(a)['role'] == 'operator'
    assert api.post(f'/admin/users/{a}/approve', token=tokens['admin']).status_code == 409
    assert api.post(f'/admin/users/{b}/reject', token=tokens['admin']).json()['status'] == 'rejected'
    viewer_id = api.repo.find_user_by_email('viewer@example.com')['id']
    assert api.post(f'/admin/users/{viewer_id}/disable', token=tokens['admin']).status_code == 200
    assert api.get('/auth/session', token=tokens['viewer']).status_code == 401
    assert api.post(f'/admin/users/{viewer_id}/disable', token=tokens['admin']).status_code == 409
    admin_id = api.repo.find_user_by_email('admin@example.com')['id']
    last = api.post(f'/admin/users/{admin_id}/disable', token=tokens['admin'])
    assert last.status_code == 400 and 'no active admin' in last.json()['detail']


@pytest.mark.parametrize('path, body', [('/admin/users/0/approve', None),
                                        ('/admin/users/abc/approve', None),
                                        ('/admin/users/1/approve', {'role': 'superuser'}),
                                        ('/admin/users/1/approve', {'role': 'admin', 'x': 1})])
def test_admin_input_validation(api, path, body):
    tokens = signed_in_roles(api)
    assert api.post(path, body, token=tokens['admin']).status_code == 422


def test_admin_list_query_validation(api):
    tokens = signed_in_roles(api)
    for query in ('status=enabled', 'limit=0', 'limit=1001', 'after_id=0'):
        assert api.get(f'/admin/users?{query}', token=tokens['admin']).status_code == 422


def test_role_dependencies(api):
    @api.app.get('/test/operator-only')
    def operator_only(info=Depends(auth_routes.require_operator)):
        return {'role': info.role}

    @api.app.get('/test/any-role')
    def any_role(info=Depends(auth_routes.require_viewer)):
        return {'role': info.role}
    tokens = signed_in_roles(api)
    assert api.get('/test/operator-only', token=tokens['viewer']).status_code == 403
    for role in ('operator', 'admin'):
        assert api.get('/test/operator-only', token=tokens[role]).json() == {'role': role}
    for role in tokens:
        assert api.get('/test/any-role', token=tokens[role]).status_code == 200
    assert api.get('/test/any-role').status_code == 401
    with pytest.raises(ValueError):
        auth_routes.require_roles('superuser')


# ================================================================ rate limiting
def test_unknown_addresses_are_rate_limited(api):
    codes = [api.post('/auth/login', {'email': 'nobody@example.com', 'password': WRONG}).status_code
             for _ in range(11)]
    assert codes == [401] * 10 + [429]


def test_per_ip_limit_on_auth_routes_only(api, monkeypatch):
    monkeypatch.setattr(auth_routes, 'API_LIMIT_PER_IP', Limit(3, 60))
    codes = [api.post('/auth/login', {'email': f'n{i}@example.com', 'password': WRONG}).status_code
             for i in range(4)]
    assert codes == [401, 401, 401, 429]
    r = api.get('/auth/session')
    assert r.status_code == 429 and 'retry-after' in r.headers
    assert api.client.get('/health').status_code == 200            # not limited


# ================================================================ input validation
@pytest.mark.parametrize('path, body', [
    ('/auth/login', {'email': 'a@example.com'}),                             # missing
    ('/auth/login', {'email': 'a@example.com', 'password': PASSWORD, 'extra': 1}),
    ('/auth/login', {'email': 'a@example.com', 'password': 'p' * 513}),      # oversized
    ('/auth/login', {'email': 'a' * 250 + '@example.com', 'password': PASSWORD}),
    ('/auth/login', {'email': 'a@example.com', 'password': 12345678901234}),
    ('/auth/register', {'email': 'a@example.com', 'full_name': 'n' * 101, 'password': PASSWORD}),
    ('/auth/login/verify', {'challenge_id': 'bad id with spaces!!', 'code': '123456'}),
    ('/auth/login/verify', {'challenge_id': 'A' * 43, 'code': '1' * 33}),
    ('/auth/register/resend', {}),
])
def test_malformed_bodies_are_refused_without_echoing_them(api, path, body):
    r = api.post(path, body)
    assert r.status_code == 422
    assert PASSWORD not in r.text and 'p' * 513 not in r.text and '12345678901234' not in r.text


def test_non_json_and_oversized_bodies(api):
    r = api.client.post('/auth/login', content=b'email=a&password=b',
                        headers={'Content-Type': 'application/x-www-form-urlencoded'})
    assert r.status_code == 422
    big = api.client.post('/auth/login', content=b'{"email": "' + b'a' * 9000 + b'"}',
                          headers={'Content-Type': 'application/json'})
    assert big.status_code == 413 and big.json()['error'] == 'too_large'

    def chunks():                                                  # no Content-Length
        yield b'{"email": "'
        for _ in range(10):
            yield b'a' * 1000
        yield b'", "password": "x"}'
    streamed = api.client.post('/auth/login', content=chunks(),
                               headers={'Content-Type': 'application/json'})
    assert streamed.status_code == 413


# ================================================================ failures and secrets
def test_database_and_mail_failures_are_503_without_details(api, monkeypatch, caplog):
    api.user()
    monkeypatch.setattr(api.repo, 'find_user_by_email', lambda e: (_ for _ in ()).throw(
        BackendDatabaseUnavailable('Could not connect to 127.0.0.1:3307/netcommand_test')))
    with caplog.at_level(logging.WARNING):
        r = api.post('/auth/login', {'email': 'user@example.com', 'password': PASSWORD})
    assert r.status_code == 503 and r.json()['error'] == 'unavailable'
    assert '127.0.0.1' not in r.text and 'netcommand' not in r.text
    assert 'BackendDatabaseUnavailable' in caplog.text and '3307' not in caplog.text
    monkeypatch.undo()
    api.mailer.fail = MailDeliveryError('authentication')
    r = api.post('/auth/login', {'email': 'user@example.com', 'password': PASSWORD})
    assert r.status_code == 503 and r.json()['error'] == 'delivery_failed'


def test_secrets_never_leave_where_they_belong(api, caplog):
    api.user()
    with caplog.at_level(logging.DEBUG):
        r = api.post('/auth/login', {'email': 'user@example.com', 'password': PASSWORD})
        code = api.code()
        v = api.post('/auth/login/verify', {'challenge_id': r.json()['challenge_id'],
                                            'code': code})
        token = v.json()['token']
        responses = [r, api.get('/auth/session', token=token), api.post('/auth/logout', token=token),
                     api.get('/auth/session', token=token)]
    for resp in responses:
        for secret in (PASSWORD, code, token, PEPPER.reveal(), api.hashed):
            assert secret not in resp.text
    for secret in (PASSWORD, code, token, PEPPER.reveal(), api.hashed):
        assert secret not in caplog.text
        assert secret not in str(api.repo.list_audit(limit=1000))


# ================================================================ app behaviour unchanged
def test_health_and_ready_are_unchanged(api):
    h = api.client.get('/health')
    assert h.status_code == 200 and h.json() == {'status': 'ok'}
    ready = api.client.get('/ready')
    assert ready.status_code == 503 and ready.json() == {'status': 'not_ready',
                                                         'reason': 'database_not_configured'}


def test_no_database_connection_until_an_auth_route_is_called(tmp_path, monkeypatch):
    """With the database, pepper and development outbox configured: creating the app,
    /health, /docs and /openapi.json connect to nothing and build no service. The first
    auth request builds it; a refused connection is a generic 503."""
    calls = []

    def refused(*a, **k):
        calls.append(1)
        raise pymysql.err.OperationalError(2003, "Can't connect to MySQL server on '127.0.0.1'")
    monkeypatch.setattr(pymysql, 'connect', refused)
    settings = parse_settings({'BACKEND_DB_ENABLED': 'true', 'BACKEND_DB_HOST': '127.0.0.1',
                               'BACKEND_DB_PORT': '3307', 'BACKEND_DB_USER': 'netcommand_api',
                               'BACKEND_DB_PASSWORD': 'Test-only-db-password-1',
                               'BACKEND_DB_NAME': 'netcommand_test',
                               'BACKEND_OTP_PEPPER': PEPPER.reveal(),
                               'BACKEND_MAIL_BACKEND': 'outbox',
                               'BACKEND_MAIL_OUTBOX_DIR': str(tmp_path)})
    app = create_app(settings)
    client = TestClient(app)
    for path in ('/health', '/docs', '/openapi.json'):
        assert client.get(path).status_code == 200
    assert calls == [] and app.state.auth_service is None
    r = client.post('/auth/login', json={'email': 'user@example.com', 'password': PASSWORD})
    assert r.status_code == 503 and r.json()['error'] == 'unavailable'
    assert '127.0.0.1' not in r.text and 'Test-only-db-password-1' not in r.text
    assert len(calls) == 1 and app.state.auth_service is not None


def test_without_database_settings_auth_is_unavailable():
    client = TestClient(create_app(parse_settings({})))
    r = client.post('/auth/login', json={'email': 'a@example.com', 'password': PASSWORD})
    assert r.status_code == 503 and r.json()['error'] == 'unavailable'
