"""Desktop sign-in client (desktop_auth) against the real backend API in-process.
No network, no database, no real email; every secret is test-only."""
import io
import json
import os
import pickle
import sys
import urllib.error
import urllib.request

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))
import pytest

from desktop_auth import api_client
from desktop_auth.api_client import (ApiConfigError, ApiError, ApiUnavailable, AuthApiClient,
                                     BadResponse, api_url_from_environment, check_api_url)
from desktop_auth.session import PERMISSIONS, Access, AuthSession
from auth_api_harness import PASSWORD, Backend, FakeResponse


@pytest.fixture
def backend():
    return Backend()


# ================================================================ configuration
@pytest.mark.parametrize('url, expected', [
    ('http://127.0.0.1:8000', 'http://127.0.0.1:8000'),
    ('http://localhost:8000/', 'http://localhost:8000'),
    ('http://[::1]:8000', 'http://[::1]:8000'),
    ('https://netcommand.example.edu', 'https://netcommand.example.edu'),
    ('https://netcommand.example.edu/api/', 'https://netcommand.example.edu/api'),
])
def test_accepted_api_urls(url, expected):
    assert check_api_url(url) == expected


@pytest.mark.parametrize('url, problem', [
    ('', 'empty'), ('ftp://127.0.0.1', 'http:// or https://'), ('127.0.0.1:8000', 'http'),
    ('http://192.168.1.10:8000', 'https://'), ('http://netcommand.example.edu', 'https://'),
    ('https://user:secret@example.edu', 'user name or password'),
    ('https://example.edu/?token=x', '? or #'), ('https://example.edu/#x', '? or #'),
])
def test_refused_api_urls(url, problem):
    with pytest.raises(ApiConfigError) as err:
        check_api_url(url)
    assert problem in str(err.value) and 'secret' not in str(err.value)


def test_api_url_comes_from_the_environment_then_dotenv_then_default(tmp_path, monkeypatch):
    env_file = tmp_path / '.env'
    env_file.write_text('DB_PASSWORD=not-read-here\nNETCOMMAND_API_URL=https://srv.example.edu\n',
                        encoding='utf-8')
    monkeypatch.delenv('NETCOMMAND_API_URL', raising=False)
    assert api_url_from_environment(str(env_file)) == 'https://srv.example.edu'
    assert 'DB_PASSWORD' not in os.environ or os.environ['DB_PASSWORD'] != 'not-read-here'
    assert api_url_from_environment(str(tmp_path / 'missing.env')) == 'http://127.0.0.1:8000'
    monkeypatch.setenv('NETCOMMAND_API_URL', 'http://localhost:9000')
    assert api_url_from_environment(str(env_file)) == 'http://localhost:9000'


def test_the_default_opener_uses_no_proxy_and_follows_no_redirect():
    client = AuthApiClient('http://127.0.0.1:8000')
    opener = client._open.__self__
    kinds = [type(h) for h in opener.handlers]
    assert api_client._NoRedirect in kinds
    assert urllib.request.HTTPRedirectHandler not in kinds          # only ours, which refuses
    # ProxyHandler({}) replaces the default one and handles nothing: no proxy is ever used
    # (not even one from the system settings).
    assert not any(isinstance(h, urllib.request.ProxyHandler) for h in opener.handlers)
    assert api_client._NoRedirect().redirect_request(None, None, 302, 'Found', {}, 'http://x') \
        is None


# ================================================================ the flows, end to end
def test_registration_and_verification(backend):
    challenge = backend.client.register('new@example.com', 'New Person', PASSWORD)
    assert set(challenge) == {'challenge_id', 'expires_in_seconds', 'message'}
    assert backend.mailer.sent[-1].purpose == 'register'
    assert backend.client.verify_registration(challenge['challenge_id'],
                                              backend.mailer.last_code()) == 'pending_approval'
    assert backend.repo.find_user_by_email('new@example.com')['status'] == 'pending_approval'


def test_login_code_session_and_logout(backend):
    uid = backend.user()
    challenge = backend.client.login('user@example.com', PASSWORD)
    assert backend.repo.list_sessions(uid) == []                       # no session yet
    data = backend.client.verify_login(challenge['challenge_id'], backend.mailer.last_code())
    token = data['token']
    assert backend.client.get_session(token)['role'] == 'viewer'
    backend.client.logout(token)
    with pytest.raises(ApiError) as err:
        backend.client.get_session(token)
    assert err.value.status == 401 and err.value.session_ended


def test_the_token_only_ever_travels_in_the_authorization_header(backend):
    backend.user()
    token = backend.sign_in_data()['token']
    backend.client.get_session(token)
    backend.client.logout(token)
    for method, url, headers in backend.opener.requests:
        assert token not in url
        bodies = [h for k, h in headers.items() if k.lower() != 'authorization']
        assert all(token not in str(v) for v in bodies)
    sent_with_token = [h for _m, _u, h in backend.opener.requests if 'Authorization' in h]
    assert sent_with_token and all(h['Authorization'] == f'Bearer {token}'
                                   for h in sent_with_token)


def test_errors_carry_the_servers_fixed_message_and_code(backend):
    backend.user()
    with pytest.raises(ApiError) as err:
        backend.client.login('user@example.com', 'Test-only wrong password')
    assert (err.value.status, err.value.code) == (401, 'login_failed')
    assert 'Test-only wrong password' not in str(err.value)
    with pytest.raises(ApiError) as unknown:
        backend.client.login('nobody@example.com', PASSWORD)
    assert str(unknown.value) == str(err.value)
    for _ in range(20):
        try:
            backend.client.login('nobody@example.com', PASSWORD)
        except ApiError as e:
            last = e
    assert last.status == 429 and last.retry_after and last.code == 'rate_limited'


def test_admin_calls(backend):
    backend.user('admin@example.com', role='admin')
    token = backend.sign_in_data('admin@example.com')['token']
    target = backend.user('pending@example.com', status='pending_approval')
    users = backend.client.list_users(token, status='pending_approval')
    assert [u['id'] for u in users] == [target] and 'password_hash' not in users[0]
    assert backend.client.approve_user(token, target, 'operator')['status'] == 'active'
    other = backend.user('p2@example.com', status='pending_approval')
    assert backend.client.reject_user(token, other)['status'] == 'rejected'
    assert backend.client.disable_user(token, target)['status'] == 'disabled'
    with pytest.raises(ApiError) as err:
        backend.client.approve_user(token, other)
    assert err.value.status == 409


def test_viewers_are_refused_by_the_api_itself(backend):
    backend.user()
    token = backend.sign_in_data()['token']
    with pytest.raises(ApiError) as err:
        backend.client.list_users(token)
    assert (err.value.status, err.value.code) == (403, 'not_permitted')


# ================================================================ unavailable and malformed
def opener_returning(status, body, headers=None):
    def opener(request, timeout=None):
        if status >= 400:
            raise urllib.error.HTTPError(request.full_url, status, 'x', headers or {},
                                         io.BytesIO(body))
        return FakeResponse(status, body)
    return opener


@pytest.mark.parametrize('error, message', [
    (urllib.error.URLError('refused'), api_client.UNREACHABLE),
    (ConnectionRefusedError(), api_client.REFUSED),           # Phase B: a more precise message
    (TimeoutError(), api_client.TIMED_OUT),                   # Phase B: a more precise message
    (OSError('down'), api_client.UNREACHABLE)])
def test_unreachable_server(error, message):
    def opener(request, timeout=None):
        raise error
    client = AuthApiClient('http://127.0.0.1:8000', opener=opener)
    with pytest.raises(ApiUnavailable) as err:
        client.login('a@example.com', PASSWORD)
    assert str(err.value) == message and PASSWORD not in str(err.value)


@pytest.mark.parametrize('status, body', [
    (200, b'not json'), (200, b'[1, 2]'), (200, b'{"unexpected": true}'),
    (202, json.dumps({'challenge_id': 5, 'expires_in_seconds': 300}).encode()),
    (200, b'x' * (api_client.MAX_RESPONSE_BYTES + 10)), (302, b''),
    (200, json.dumps({'token': 't' * 43, 'user_id': 1, 'role': 'superuser', 'session_id': 1,
                      'expires_in_seconds': 1, 'idle_timeout_seconds': 1}).encode()),
], ids=['not-json', 'list', 'wrong-keys', 'wrong-types', 'too-large', 'redirect', 'bad-role'])
def test_malformed_answers(status, body):
    client = AuthApiClient('http://127.0.0.1:8000', opener=opener_returning(status, body))
    with pytest.raises(BadResponse):
        client.login('a@example.com', PASSWORD)
    with pytest.raises(BadResponse):
        client.verify_login('A' * 43, '123456')


def test_server_errors_are_generic_and_503_is_unavailable():
    leaky = json.dumps({'detail': 'Traceback ... password=Test-only-x', 'error': 'x'}).encode()
    client = AuthApiClient('http://127.0.0.1:8000', opener=opener_returning(500, leaky))
    with pytest.raises(ApiError) as err:
        client.login('a@example.com', PASSWORD)
    assert 'Traceback' not in str(err.value) and 'Test-only-x' not in str(err.value)
    down = json.dumps({'detail': 'Sign-in is temporarily unavailable.', 'error': 'unavailable'})
    client = AuthApiClient('http://127.0.0.1:8000', opener=opener_returning(503, down.encode()))
    with pytest.raises(ApiUnavailable):
        client.login('a@example.com', PASSWORD)


# ================================================================ the session object
def test_session_keeps_the_token_in_memory_only(monkeypatch, tmp_path):
    monkeypatch.chdir(tmp_path)
    token = 'T' * 43
    s = AuthSession(token=token, user_id=3, role='operator', email='op@example.com')
    assert s.token() == token and s.active
    for text in (repr(s), str(s), f'{s}'):
        assert token not in text and '[hidden]' in text
    with pytest.raises(TypeError):
        pickle.dumps(s)
    assert token not in str(os.environ)
    assert list(tmp_path.iterdir()) == []
    s.clear()
    assert s.token() is None and not s.active


def test_access_by_role():
    assert Access('viewer').can_open('devices') and not Access('viewer').can_open('scan')
    assert not Access('viewer').can('devices.edit') and not Access('viewer').can('findings.run')
    assert Access('operator').can_open('scan') and Access('operator').can_open('configure')
    assert not Access('operator').can_open('accounts')
    assert Access('admin').can_open('accounts') and Access('admin').can('devices.edit')
    demo = Access(None, demo=True)
    assert demo.demo and demo.title == 'DEMO MODE' and not demo.can_open('accounts')
    assert PERMISSIONS['admin'] > PERMISSIONS['operator'] > PERMISSIONS['viewer']
    with pytest.raises(ValueError):
        Access('superuser')


def test_desktop_auth_never_touches_device_credentials_or_the_database():
    import ast
    from pathlib import Path
    root = Path(__file__).resolve().parents[1]
    files = list((root / 'desktop_auth').glob('*.py')) + [
        root / 'gui' / name for name in ('auth_window.py', 'accounts_page.py',
                                         'session_watch.py', 'background.py')]
    for path in files:
        for node in ast.walk(ast.parse(path.read_text(encoding='utf-8'))):
            names = ([a.name for a in node.names] if isinstance(node, ast.Import) else
                     [node.module or ''] if isinstance(node, ast.ImportFrom) else [])
            for name in names:
                assert name.split('.')[0] not in ('security', 'db', 'db_fake', 'pymysql',
                                                  'cryptography', 'backend'), (path.name, name)
