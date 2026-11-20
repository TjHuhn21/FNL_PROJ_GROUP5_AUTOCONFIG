"""The rule: every account must verify its email address (an emailed one-time code)
before it may be active, await approval, sign in or keep a session. Checked in both
repositories, the service, the mail layer and the API. No MySQL, no real email."""
import re

import pymysql
import pytest
from fastapi.testclient import TestClient

from backend.app import create_app
from backend.auth import passwords
from backend.auth.errors import AccountNotActive, NotAuthenticated
from backend.auth.service import AuthService, may_sign_in
from backend.database.auth_repository import AuthRepository
from backend.database.errors import EmailNotVerified, InvalidValue
from backend.database.memory_repository import InMemoryAuthRepository
from backend.mail.messages import NotEligibleForCode, check_eligibility
from backend.settings import Secret, parse_settings

PASSWORD = 'Test-only rule password 3'
PEPPER = Secret('test-only-rule-pepper-' + 'r' * 32)


@pytest.fixture(autouse=True)
def no_real_mysql(monkeypatch):
    monkeypatch.setattr(pymysql, 'connect',
                        lambda *a, **k: pytest.fail('tried to open a real MySQL connection'))


@pytest.fixture(scope='module')
def hashed():
    return passwords.hash_password(PASSWORD)


class FakeMailer:
    def __init__(self):
        self.sent = []

    def send(self, outgoing):
        self.sent.append(outgoing)

    def code(self):
        return re.search(r'^ {4}([0-9]{6})$', self.sent[-1].text, re.M).group(1)


def unverify(repo, uid):
    repo._users[uid]['email_verified_at'] = None          # an account from before the rule


# ================================================================ repositories
@pytest.mark.parametrize('status', ['active', 'pending_approval'])
def test_accounts_cannot_be_created_active_or_awaiting_approval_unverified(hashed, status):
    with pytest.raises(EmailNotVerified):
        InMemoryAuthRepository().create_user('a@example.com', 'A', hashed, status=status)
    with pytest.raises(EmailNotVerified):                 # SQL: refused before connecting
        AuthRepository(lambda: pytest.fail('connected')).create_user(
            'a@example.com', 'A', hashed, status=status)


@pytest.mark.parametrize('status', ['pending_verification', 'rejected', 'disabled'])
def test_other_statuses_need_no_verification(hashed, status):
    repo = InMemoryAuthRepository()
    uid = repo.create_user('a@example.com', 'A', hashed, status=status)
    assert repo.get_user(uid)['email_verified_at'] is None


def test_verified_creation_records_the_time(hashed):
    repo = InMemoryAuthRepository()
    uid = repo.create_user('a@example.com', 'A', hashed, status='active', email_verified=True)
    assert repo.get_user(uid)['email_verified_at'] is not None


def test_email_not_verified_is_an_invalid_value():
    assert issubclass(EmailNotVerified, InvalidValue)


def test_set_status_refuses_to_activate_an_unverified_account(hashed):
    repo = InMemoryAuthRepository()
    admin = repo.create_user('admin@example.com', 'A', hashed, role='admin', status='active',
                             email_verified=True)
    uid = repo.create_user('u@example.com', 'U', hashed)          # pending_verification
    for target in ('active', 'pending_approval'):
        with pytest.raises(EmailNotVerified):
            repo.set_status(uid, target, actor_user_id=admin)
    assert repo.get_user(uid)['status'] == 'pending_verification'
    assert repo.list_audit(action='user.status_changed') == []      # nothing changed
    assert repo.set_status(uid, 'disabled', actor_user_id=admin) is True   # other moves ok


def test_approve_requires_a_verified_address(hashed):
    repo = InMemoryAuthRepository()
    admin = repo.create_user('admin@example.com', 'A', hashed, role='admin', status='active',
                             email_verified=True)
    uid = repo.create_user('p@example.com', 'P', hashed, status='pending_approval',
                           email_verified=True)
    unverify(repo, uid)
    assert repo.approve_user(uid, admin) is False
    assert repo.get_user(uid)['status'] == 'pending_approval'


def test_registration_still_verifies_then_waits_for_approval(hashed):
    repo = InMemoryAuthRepository()
    uid = repo.create_user('r@example.com', 'R', hashed)
    assert repo.mark_email_verified(uid) is True
    user = repo.get_user(uid)
    assert user['status'] == 'pending_approval' and user['email_verified_at'] is not None


class SqlCursor:
    def __init__(self, conn):
        self.conn, self.rowcount, self.lastrowid, self._rows = conn, 1, 9, []

    def __enter__(self):
        return self

    def __exit__(self, *e):
        return False

    def execute(self, sql, params=()):
        self.conn.sent.append((sql, params))
        answer = self.conn.answer(sql)
        self._rows = answer if isinstance(answer, list) else ([answer] if answer else [])

    def fetchone(self):
        return self._rows[0] if self._rows else None

    def fetchall(self):
        return list(self._rows)


class SqlConn:
    def __init__(self, answer=lambda sql: None):
        self.answer, self.sent, self.commits, self.rollbacks = answer, [], 0, 0

    def cursor(self):
        return SqlCursor(self)

    def commit(self):
        self.commits += 1

    def rollback(self):
        self.rollbacks += 1

    def close(self):
        pass


def test_sql_set_status_reads_the_verification_and_refuses(hashed):
    conn = SqlConn(lambda sql: ({'role': 'viewer', 'status': 'pending_verification',
                                 'email_verified_at': None}
                                if sql.startswith('SELECT role, status, email_verified_at') else
                                [] if "role = 'admin'" in sql else None))
    with pytest.raises(EmailNotVerified):
        AuthRepository(lambda: conn).set_status(5, 'active', actor_user_id=1)
    assert not any(sql.startswith('UPDATE') for sql, _ in conn.sent)
    assert conn.rollbacks == 1 and conn.commits == 0


def test_sql_create_approve_and_session_queries_carry_the_rule(hashed):
    conn = SqlConn(lambda sql: {'role': 'admin', 'status': 'active'})
    repo = AuthRepository(lambda: conn)
    repo.create_user('a@example.com', 'A', hashed)
    assert 'email_verified_at' in conn.sent[0][0] and 'NULL' in conn.sent[0][0]
    repo.create_user('b@example.com', 'B', hashed, status='active', email_verified=True)
    assert 'UTC_TIMESTAMP(6), UTC_TIMESTAMP(6), UTC_TIMESTAMP(6)' in conn.sent[1][0]
    repo.approve_user(7, 2)
    assert any('AND email_verified_at IS NOT NULL' in sql for sql, _ in conn.sent
               if sql.startswith('UPDATE users SET status'))
    repo.get_active_session('c' * 64, 1800)
    assert 'u.email_verified_at IS NOT NULL' in conn.sent[-1][0]


# ================================================================ service, mail, API
def test_active_but_unverified_accounts_cannot_sign_in(hashed):
    repo, mailer = InMemoryAuthRepository(), FakeMailer()
    uid = repo.create_user('old@example.com', 'Old', hashed, role='admin', status='active',
                           email_verified=True)
    unverify(repo, uid)
    svc = AuthService(repo, mailer, PEPPER)
    with pytest.raises(AccountNotActive):
        svc.login('old@example.com', PASSWORD)
    assert mailer.sent == [] and repo._challenges == {}
    denied = repo.list_audit(action='auth.login')[0]
    assert denied['outcome'] == 'denied' and 'email address not verified' in denied['detail']
    assert not may_sign_in(repo.get_user(uid))


def test_a_session_ends_when_the_account_is_not_verified(hashed):
    repo, mailer = InMemoryAuthRepository(), FakeMailer()
    uid = repo.create_user('u@example.com', 'U', hashed, status='active', email_verified=True)
    svc = AuthService(repo, mailer, PEPPER)
    sent = svc.login('u@example.com', PASSWORD)
    token = svc.verify_login(sent.challenge_id, mailer.code()).token
    assert svc.validate_session(token).user_id == uid
    unverify(repo, uid)
    with pytest.raises(NotAuthenticated):
        svc.validate_session(token)


def test_the_login_code_step_also_checks(hashed):
    repo, mailer = InMemoryAuthRepository(), FakeMailer()
    uid = repo.create_user('u@example.com', 'U', hashed, status='active', email_verified=True)
    svc = AuthService(repo, mailer, PEPPER)
    sent = svc.login('u@example.com', PASSWORD)
    unverify(repo, uid)                                    # between password and code
    with pytest.raises(AccountNotActive):
        svc.verify_login(sent.challenge_id, mailer.code())
    assert repo._sessions == {}


def test_login_codes_are_only_mailed_to_verified_accounts():
    account = {'email': 'a@example.com', 'status': 'active', 'email_verified_at': None}
    with pytest.raises(NotEligibleForCode):
        check_eligibility('login', account)
    assert check_eligibility('login', dict(account, email_verified_at='2026-11-19')) == \
        'a@example.com'
    assert check_eligibility('register', dict(account, status='pending_verification')) == \
        'a@example.com'


def test_the_api_answers_403_for_an_unverified_active_account(hashed):
    repo = InMemoryAuthRepository()
    uid = repo.create_user('old@example.com', 'Old', hashed, role='admin', status='active',
                           email_verified=True)
    unverify(repo, uid)
    client = TestClient(create_app(parse_settings({}),
                                   auth_service=AuthService(repo, FakeMailer(), PEPPER)))
    r = client.post('/auth/login', json={'email': 'old@example.com', 'password': PASSWORD})
    assert r.status_code == 403 and r.json()['error'] == 'account_not_active'
    wrong = client.post('/auth/login', json={'email': 'old@example.com',
                                             'password': 'Test-only wrong password'})
    assert wrong.status_code == 401                        # still no hint without the password


def test_the_full_registration_path_still_works(hashed):
    repo, mailer = InMemoryAuthRepository(), FakeMailer()
    admin = repo.create_user('admin@example.com', 'A', hashed, role='admin', status='active',
                             email_verified=True)
    svc = AuthService(repo, mailer, PEPPER)
    sent = svc.register('new@example.com', 'New', PASSWORD)
    assert svc.verify_registration(sent.challenge_id, mailer.code()) == 'pending_approval'
    uid = repo.find_user_by_email('new@example.com')['id']
    assert repo.approve_user(uid, admin) is True
    sent = svc.login('new@example.com', PASSWORD)
    assert svc.verify_login(sent.challenge_id, mailer.code()).user_id == uid
