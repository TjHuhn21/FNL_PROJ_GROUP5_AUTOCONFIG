"""Local administrator commands (python -m backend.auth.bootstrap_admin [verify-existing])
and the repository methods behind them. No MySQL (pymysql.connect fails the test), no real
email (a fake mailer); every password is test-only."""
import logging
import os
import re
import subprocess
import sys
import threading
from pathlib import Path

import pymysql
import pytest

from backend.auth import bootstrap_admin, passwords
from backend.auth.bootstrap_admin import (EXIT_CANCELLED, EXIT_DONE, EXIT_INVALID,
                                          EXIT_NOT_CONFIRMED, EXIT_REFUSED, EXIT_UNAVAILABLE, run)
from backend.auth.service import AuthService
from backend.database.auth_repository import AuthRepository
from backend.database.errors import (AdminExists, BackendDatabaseUnavailable, DuplicateEmail,
                                     SetupBusy)
from backend.database.memory_repository import InMemoryAuthRepository
from backend.mail.delivery import MailDeliveryError
from backend.mail.messages import ADMIN_SUBJECT
from backend.settings import Secret, parse_settings

ROOT = Path(__file__).resolve().parents[2]
PASSWORD = 'Test-only admin password 9'
DB_SECRET = 'Test-only-db-password-77'
CODE = object()                    # in the answers: "the code from the latest email"


@pytest.fixture(autouse=True)
def no_real_mysql(monkeypatch):
    monkeypatch.setattr(pymysql, 'connect',
                        lambda *a, **k: pytest.fail('tried to open a real MySQL connection'))


@pytest.fixture(scope='module')
def admin_hash():
    return passwords.hash_password(PASSWORD)


def settings(name='netcommand_test', **extra):
    raw = {'BACKEND_DB_ENABLED': 'true', 'BACKEND_DB_HOST': '127.0.0.1',
           'BACKEND_DB_PORT': '3307', 'BACKEND_DB_USER': 'netcommand_api',
           'BACKEND_DB_PASSWORD': DB_SECRET, 'BACKEND_DB_NAME': name}
    raw.update(extra)
    return parse_settings(raw)


class FakeMailer:
    def __init__(self, fail=None):
        self.sent, self.fail = [], fail

    def send(self, outgoing):
        if self.fail:
            raise self.fail
        self.sent.append(outgoing)

    def code_for(self, email=None):
        for m in reversed(self.sent):
            if email is None or m.to.lower() == email.lower():
                return re.search(r'^ {4}([0-9]{6})$', m.text, re.M).group(1)


class Clock:
    def __init__(self):
        self.now = 1000.0

    def __call__(self):
        return self.now


class Prompts:
    """Scripted answers. CODE = the code of the latest email to this run's address; a
    callable is called (to move the clock, check state ...) and its result used."""

    def __init__(self, answers, secrets, mailer):
        self.answers, self.secrets, self.mailer, self.asked = list(answers), list(secrets), \
            mailer, []
        self.email = None

    def _next(self, queue, prompt):
        self.asked.append(prompt)
        value = queue.pop(0)
        if callable(value) and value is not CODE:
            value = value()
        if value is CODE:
            value = self.mailer.code_for(self.email)
        if isinstance(value, BaseException):
            raise value
        if prompt.startswith('Administrator email'):
            self.email = value.strip()
        return value

    def ask(self, prompt):
        return self._next(self.answers, prompt)

    def ask_secret(self, prompt):
        return self._next(self.secrets, prompt)


def bootstrap(repo, answers=('admin@example.com', 'First Admin', CODE),
              secrets=(PASSWORD, PASSWORD), argv=(), cfg=None, mailer=None, clock=None):
    mailer = mailer if mailer is not None else FakeMailer()
    prompts, lines = Prompts(answers, secrets, mailer), []
    code = run(list(argv), settings=cfg or settings(), repository=repo, mailer=mailer,
               ask=prompts.ask, ask_secret=prompts.ask_secret, out=lines.append,
               clock=clock or Clock())
    return code, '\n'.join(lines), prompts, mailer


def legacy_admin(repo, admin_hash, email='old.admin@example.com'):
    """An administrator created before the email rule: active, address never verified."""
    uid = repo.create_user(email, 'Old Admin', admin_hash, role='admin', status='active',
                           email_verified=True)
    repo._users[uid]['email_verified_at'] = None          # as the old bootstrap left it
    return uid


# ================================================================ create
def test_creates_the_first_admin_only_after_the_emailed_code(caplog):
    repo = InMemoryAuthRepository()
    seen_before_code = []

    def code_after_checking_nothing_was_written():
        seen_before_code.append(len(repo.list_users()))
        return CODE
    with caplog.at_level(logging.DEBUG):
        code, text, prompts, mailer = bootstrap(
            repo, answers=(' Admin@Example.com ', 'First Admin',
                           code_after_checking_nothing_was_written))
    assert code == EXIT_DONE and seen_before_code == [0]          # nothing before the code
    (mail,) = mailer.sent
    assert mail.to == 'admin@example.com' and mail.subject == ADMIN_SUBJECT
    assert mail.purpose == 'admin_setup' and 'being set up' in mail.text
    user = repo.find_user_by_email('admin@example.com')
    assert (user['role'], user['status']) == ('admin', 'active')
    assert user['email_verified_at'] is not None                  # verified
    stored = repo.get_password_hash(user['id'])
    assert stored.startswith('$argon2id$') and passwords.verify_password(stored, PASSWORD)
    actions = [(a['action'], a['outcome']) for a in reversed(repo.list_audit())]
    assert actions == [('auth.code_sent', 'success'), ('user.bootstrap_admin', 'success')]
    created = repo.list_audit(action='user.bootstrap_admin')[0]
    assert 'verified with a one-time code' in created['detail']
    sent_code = mailer.code_for()
    for secret in (PASSWORD, stored, DB_SECRET, sent_code):
        assert secret not in text and secret not in caplog.text
        assert secret not in str(repo.list_audit())
    assert 'email address verified' in text


def test_the_new_admin_can_sign_in(admin_hash):
    repo, mailer = InMemoryAuthRepository(), FakeMailer()
    assert bootstrap(repo, mailer=mailer)[0] == EXIT_DONE
    svc = AuthService(repo, mailer, Secret('test-only-pepper-' + 'q' * 32))
    sent = svc.login('admin@example.com', PASSWORD)
    assert svc.verify_login(sent.challenge_id, mailer.code_for()).role == 'admin'


@pytest.mark.parametrize('typed', ['123 456', ' 123-456 '])
def test_typed_variants_of_the_code(monkeypatch, typed):
    monkeypatch.setattr('backend.auth.otp.generate_otp', lambda: '123456')
    repo = InMemoryAuthRepository()
    code, _, _, _ = bootstrap(repo, answers=('admin@example.com', 'A', typed))
    assert code == EXIT_DONE


def test_wrong_codes_create_nothing(monkeypatch):
    monkeypatch.setattr(bootstrap_admin, 'MAX_NEW_CODES', 0)
    repo = InMemoryAuthRepository()
    answers = ['admin@example.com', 'A'] + ['000000'] * 5 + ['111111']
    monkeypatch.setattr('backend.auth.otp.generate_otp', lambda: '424242')
    code, text, _, mailer = bootstrap(repo, answers=answers)
    assert code == EXIT_NOT_CONFIRMED and 'Nothing was created' in text
    assert repo.list_users() == [] and '424242' not in text
    fails = repo.list_audit(action='auth.code_failed')
    assert len(fails) == 5 and 'attempt 5 of 5' in fails[0]['detail']


def test_expired_code_then_a_new_one(monkeypatch):
    clock = Clock()
    repo = InMemoryAuthRepository()
    first = {}

    def late_old_code():
        first['code'] = CODE
        clock.now += 300                                      # the policy's 5 minutes
        return mailer_ref[0].code_for()

    def new_code_request():
        return 'R'
    mailer = FakeMailer()
    mailer_ref = [mailer]
    code, text, _, _ = bootstrap(repo, answers=['admin@example.com', 'A', late_old_code,
                                                new_code_request, CODE],
                                 mailer=mailer, clock=clock)
    assert code == EXIT_DONE and len(mailer.sent) == 2
    assert 'can no longer be used' in text


def test_a_new_code_needs_the_cooldown_and_replaces_the_old_one(monkeypatch):
    clock = Clock()
    codes = iter(['111111', '222222'])
    monkeypatch.setattr('backend.auth.otp.generate_otp', lambda: next(codes))
    repo = InMemoryAuthRepository()

    def later():
        clock.now += 60
        return 'R'
    code, text, _, mailer = bootstrap(repo, answers=['admin@example.com', 'A', 'R', later,
                                                     '111111', '222222'], clock=clock)
    assert 'Wait 60 seconds' in text and 'Wrong code' in text      # the old code is dead
    assert code == EXIT_DONE and len(mailer.sent) == 2


def test_email_failure_creates_nothing():
    repo = InMemoryAuthRepository()
    code, text, _, _ = bootstrap(repo, mailer=FakeMailer(fail=MailDeliveryError('authentication')),
                                 answers=('admin@example.com', 'A'))
    assert code == EXIT_UNAVAILABLE and 'could not be emailed' in text
    assert repo.list_users() == []
    assert repo.list_audit(action='auth.code_email_failed')[0]['outcome'] == 'failure'


def test_mail_not_configured_stops_before_asking():
    lines = []
    code = run([], settings=settings(), repository=InMemoryAuthRepository(),
               ask=lambda p: pytest.fail('asked'), ask_secret=lambda p: pytest.fail('asked'),
               out=lines.append)
    assert code == EXIT_UNAVAILABLE and 'BACKEND_MAIL_BACKEND' in '\n'.join(lines)


@pytest.mark.parametrize('answers', [('not-an-email', 'A'), ('ä@example.com', 'A'),
                                     ('', 'A'), ('a@example.com', ''),
                                     ('a@example.com', 'line\nbreak')])
def test_invalid_email_or_name(answers):
    repo = InMemoryAuthRepository()
    code, text, prompts, mailer = bootstrap(repo, answers=answers, secrets=())
    assert code == EXIT_INVALID and 'Nothing was created' in text
    assert repo.list_users() == [] and mailer.sent == []
    assert not any('Password' in p for p in prompts.asked)


@pytest.mark.parametrize('password, problem', [('short-pw', 'at least 12'),
                                               (' ' * 14, 'only spaces'),
                                               ('tab\tinside-password', 'control characters')])
def test_invalid_password(password, problem):
    repo = InMemoryAuthRepository()
    code, text, prompts, mailer = bootstrap(repo, secrets=(password,))
    assert code == EXIT_INVALID and problem in text and mailer.sent == []
    assert not password.strip() or password.strip() not in text
    assert not any('again' in p for p in prompts.asked)


def test_confirmation_mismatch():
    repo = InMemoryAuthRepository()
    code, text, _, mailer = bootstrap(repo, secrets=(PASSWORD, PASSWORD + 'x'))
    assert code == EXIT_INVALID and 'not the same' in text and mailer.sent == []
    assert repo.list_users() == []


def test_refused_when_an_active_admin_exists(admin_hash):
    repo = InMemoryAuthRepository()
    repo.create_user('boss@example.com', 'Boss', admin_hash, role='admin', status='active',
                     email_verified=True)
    code, text, prompts, mailer = bootstrap(repo)
    assert code == EXIT_REFUSED and 'already exists' in text
    assert prompts.asked == [] and mailer.sent == []


def test_an_admin_created_meanwhile_is_still_caught_atomically(admin_hash):
    repo = InMemoryAuthRepository()

    def other_admin_appears():
        repo.create_user('other@example.com', 'Other', admin_hash, role='admin',
                         status='active', email_verified=True)
        return CODE
    code, text, _, _ = bootstrap(repo, answers=('admin@example.com', 'A', other_admin_appears))
    assert code == EXIT_REFUSED and 'already exists' in text
    assert repo.find_user_by_email('admin@example.com') is None
    denied = repo.list_audit(action='user.bootstrap_admin')[0]
    assert denied['outcome'] == 'denied' and 'active admin already exists' in denied['detail']


@pytest.mark.parametrize('status', ['disabled', 'rejected'])
def test_inactive_admins_do_not_block_recovery(admin_hash, status):
    repo = InMemoryAuthRepository()
    old = repo.create_user('old@example.com', 'Old', admin_hash, role='admin', status=status)
    code, text, _, _ = bootstrap(repo)
    assert code == EXIT_DONE and '1 disabled or inactive admin' in text
    assert repo.get_user(old)['status'] == status


def test_taken_email_address_is_refused_before_any_email(admin_hash):
    repo = InMemoryAuthRepository()
    repo.create_user('admin@example.com', 'Viewer', admin_hash)    # a pending registration
    code, text, _, mailer = bootstrap(repo)
    assert code == EXIT_REFUSED and 'already exists' in text and mailer.sent == []
    assert repo.find_user_by_email('admin@example.com')['role'] == 'viewer'


def test_two_simultaneous_commands_create_one_admin():
    repo, mailer = InMemoryAuthRepository(), FakeMailer()
    barrier, codes = threading.Barrier(2), []

    def one(email):
        def wait_for_both():
            barrier.wait()                                        # both have their code
            return CODE
        codes.append(bootstrap(repo, answers=(email, 'Admin', wait_for_both), mailer=mailer)[0])
    threads = [threading.Thread(target=one, args=(f'a{i}@example.com',)) for i in range(2)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert sorted(codes) == [EXIT_DONE, EXIT_REFUSED]
    assert [u['role'] for u in repo.list_users()] == ['admin']


def test_many_simultaneous_repository_calls_create_one_admin(admin_hash):
    repo = InMemoryAuthRepository()
    barrier, results = threading.Barrier(20), []

    def one(i):
        barrier.wait()
        try:
            results.append(repo.create_first_admin(f'a{i}@example.com', 'A', admin_hash))
        except AdminExists:
            results.append('refused')
    threads = [threading.Thread(target=one, args=(i,)) for i in range(20)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert results.count('refused') == 19 and len(repo.list_users()) == 1


# ================================================================ verify-existing
def verify(repo, email='old.admin@example.com', answers=None, mailer=None, cfg=None):
    return bootstrap(repo, answers=answers or (email, CODE), secrets=(),
                     argv=('verify-existing',), mailer=mailer, cfg=cfg)


def test_verify_existing_admin_keeps_everything_else(admin_hash):
    repo = InMemoryAuthRepository()
    uid = legacy_admin(repo, admin_hash)
    before = dict(repo._users[uid])
    mailer = FakeMailer()
    svc = AuthService(repo, mailer, Secret('test-only-pepper-' + 'v' * 32))
    from backend.auth.errors import AccountNotActive
    with pytest.raises(AccountNotActive):                         # cannot sign in yet
        svc.login('old.admin@example.com', PASSWORD)
    code, text, prompts, _ = verify(repo, mailer=mailer)
    assert code == EXIT_DONE and 'Email address verified' in text
    (mail,) = mailer.sent
    assert mail.purpose == 'admin_verify' and 'existing NetCommand administrator' in mail.text
    after = repo._users[uid]
    assert after['email_verified_at'] is not None
    for key in ('id', 'email', 'full_name', 'password_hash', 'role', 'status', 'created_at',
                'updated_at', 'approved_by', 'approved_at', 'failed_logins', 'locked_until'):
        assert after[key] == before[key], key
    assert all('Password' not in p for p in prompts.asked)       # no password needed
    (audit,) = repo.list_audit(action='auth.email_verified')
    assert (audit['outcome'], audit['actor_user_id'], audit['target_id']) == (
        'success', uid, str(uid))
    sent = svc.login('old.admin@example.com', PASSWORD)           # now it can
    assert svc.verify_login(sent.challenge_id, mailer.code_for()).user_id == uid


def test_verify_existing_with_wrong_codes_changes_nothing(admin_hash, monkeypatch):
    monkeypatch.setattr(bootstrap_admin, 'MAX_NEW_CODES', 0)
    repo = InMemoryAuthRepository()
    uid = legacy_admin(repo, admin_hash)
    code, text, _, _ = verify(repo, answers=['old.admin@example.com'] + ['000000'] * 5 + ['1'])
    assert code == EXIT_NOT_CONFIRMED and 'Nothing was changed' in text
    assert repo._users[uid]['email_verified_at'] is None


@pytest.mark.parametrize('setup, expected, message', [
    ('missing', EXIT_REFUSED, 'No account uses'),
    ('viewer', EXIT_REFUSED, 'only verifies ACTIVE ADMINISTRATOR'),
    ('disabled_admin', EXIT_REFUSED, 'only verifies ACTIVE ADMINISTRATOR'),
    ('verified_admin', EXIT_DONE, 'already verified'),
])
def test_verify_existing_refusals(admin_hash, setup, expected, message):
    repo = InMemoryAuthRepository()
    if setup == 'viewer':
        repo.create_user('old.admin@example.com', 'V', admin_hash, status='active',
                         email_verified=True)
    elif setup == 'disabled_admin':
        repo.create_user('old.admin@example.com', 'D', admin_hash, role='admin',
                         status='disabled')
    elif setup == 'verified_admin':
        repo.create_user('old.admin@example.com', 'A', admin_hash, role='admin',
                         status='active', email_verified=True)
    code, text, _, mailer = verify(repo)
    assert code == expected and message in text and mailer.sent == []


def test_verify_existing_email_failure(admin_hash):
    repo = InMemoryAuthRepository()
    uid = legacy_admin(repo, admin_hash)
    code, text, _, _ = verify(repo, mailer=FakeMailer(fail=MailDeliveryError('connection')))
    assert code == EXIT_UNAVAILABLE and repo._users[uid]['email_verified_at'] is None


def test_verify_existing_account_changed_meanwhile(admin_hash):
    repo = InMemoryAuthRepository()
    uid = legacy_admin(repo, admin_hash)

    def disabled_meanwhile():
        repo._users[uid]['status'] = 'disabled'
        return CODE
    code, text, _, _ = verify(repo, answers=('old.admin@example.com', disabled_meanwhile))
    assert code == EXIT_REFUSED and 'changed while' in text
    assert repo._users[uid]['email_verified_at'] is None


# ================================================================ settings and the database
def test_database_not_configured():
    code, text, prompts, _ = bootstrap(InMemoryAuthRepository(), cfg=parse_settings({}))
    assert code == EXIT_UNAVAILABLE and 'not configured' in text and prompts.asked == []


def test_invalid_settings_are_reported_without_values(monkeypatch, tmp_path):
    monkeypatch.setenv('NETCOMMAND_BACKEND_ENV_FILE', str(tmp_path / 'none.env'))
    monkeypatch.setenv('BACKEND_DB_ENABLED', 'true')
    monkeypatch.setenv('BACKEND_DB_PASSWORD', DB_SECRET)
    lines = []
    code = run([], ask=lambda p: pytest.fail('asked'), ask_secret=lambda p: pytest.fail('asked'),
               out=lines.append)
    assert code == EXIT_UNAVAILABLE and 'BACKEND_DB_HOST is required' in '\n'.join(lines)
    assert DB_SECRET not in '\n'.join(lines)


@pytest.mark.parametrize('name, argv, expected', [
    ('netcommand', (), EXIT_REFUSED),
    ('netcommand', ('--authorize-database', 'netcommand'), EXIT_REFUSED),
    ('netcommand', ('--authorize-database', 'netcommand', '--allow-main-database'), EXIT_DONE),
    ('production', (), EXIT_REFUSED),
    ('production', ('--authorize-database', 'production'), EXIT_DONE),
    ('netcommand_test', (), EXIT_DONE),
])
def test_database_names_need_approval_like_migrations(name, argv, expected):
    code, text, _, _ = bootstrap(InMemoryAuthRepository(), argv=argv, cfg=settings(name))
    assert code == expected
    if expected == EXIT_REFUSED:
        assert 'create an administrator in' in text and 'Nothing was changed' in text


def test_verify_existing_also_checks_the_database_name(admin_hash):
    code, text, _, _ = verify(InMemoryAuthRepository(), cfg=settings('netcommand'))
    assert code == EXIT_REFUSED and 'verify an administrator in' in text


class Broken:
    def __init__(self, fail_on):
        self.fail_on, self.repo = fail_on, InMemoryAuthRepository()

    def __getattr__(self, name):
        if name == self.fail_on:
            def fail(*a, **k):
                raise BackendDatabaseUnavailable(
                    'Could not connect to the backend database at 127.0.0.1:3307/'
                    'netcommand_test (MySQL error 2003).')
            return fail
        return getattr(self.repo, name)


@pytest.mark.parametrize('fail_on', ['list_users', 'find_user_by_email', 'create_first_admin'])
def test_database_unavailable(fail_on):
    code, text, _, _ = bootstrap(Broken(fail_on))
    assert code == EXIT_UNAVAILABLE and 'MySQL error 2003' in text
    assert PASSWORD not in text and DB_SECRET not in text


@pytest.mark.parametrize('where', ['ask', 'ask_secret', 'code'])
@pytest.mark.parametrize('error', [KeyboardInterrupt(), EOFError()])
def test_cancelled(where, error):
    repo = InMemoryAuthRepository()
    answers = {'ask': (error,), 'ask_secret': ('a@example.com', 'A'),
               'code': ('a@example.com', 'A', error)}[where]
    secrets = (error,) if where == 'ask_secret' else (PASSWORD, PASSWORD)
    code, text, _, _ = bootstrap(repo, answers=answers, secrets=secrets)
    assert code == EXIT_CANCELLED and 'Nothing was created' in text and repo.list_users() == []


def test_the_real_command_line(tmp_path):
    env = {k: v for k, v in os.environ.items() if not k.startswith('BACKEND_')}
    env['NETCOMMAND_BACKEND_ENV_FILE'] = str(tmp_path / 'none.env')
    cmd = [sys.executable, '-m', 'backend.auth.bootstrap_admin']
    helped = subprocess.run(cmd + ['--help'], cwd=ROOT, env=env, capture_output=True, text=True,
                            timeout=120)
    assert helped.returncode == 0 and 'verify-existing' in helped.stdout
    for extra in ([], ['verify-existing']):
        refused = subprocess.run(cmd + extra, cwd=ROOT, env=env, capture_output=True, text=True,
                                 timeout=120, input='')
        assert refused.returncode == EXIT_UNAVAILABLE and 'not configured' in refused.stdout
    bad = subprocess.run(cmd + ['--no-such-option'], cwd=ROOT, env=env, capture_output=True,
                         text=True, timeout=120)
    assert bad.returncode == 2


def test_there_is_no_api_endpoint_for_creating_or_verifying_admins():
    from fastapi.testclient import TestClient
    from backend.app import create_app
    spec = TestClient(create_app(parse_settings({}))).get('/openapi.json').json()
    for path, methods in spec['paths'].items():
        assert 'bootstrap' not in path and 'verify-existing' not in path
        if path == '/admin/users':
            assert set(methods) == {'get'}
    routes = (ROOT / 'backend' / 'api' / 'auth_routes.py').read_text(encoding='utf-8')
    assert 'create_first_admin' not in routes and 'mark_existing_admin' not in routes


# ================================================================ SQL repository
class Cursor:
    def __init__(self, conn):
        self.conn, self.rowcount, self.lastrowid, self._rows = conn, conn.rowcount, None, []

    def __enter__(self):
        return self

    def __exit__(self, *e):
        return False

    def execute(self, sql, params=()):
        self.conn.events.append(('sql', sql, params))
        if self.conn.error is not None and self.conn.fail_on in sql:
            raise self.conn.error
        self.lastrowid = 7
        answer = self.conn.answer(sql)
        self._rows = answer if isinstance(answer, list) else ([answer] if answer else [])

    def fetchone(self):
        return self._rows[0] if self._rows else None

    def fetchall(self):
        return list(self._rows)


class Conn:
    def __init__(self, got=1, admins=(), inactive=0, error=None, fail_on='', commit_error=None,
                 rowcount=1):
        self.got, self.admins, self.inactive = got, list(admins), inactive
        self.error, self.fail_on, self.commit_error = error, fail_on, commit_error
        self.rowcount, self.events, self.closed = rowcount, [], False

    def answer(self, sql):
        if 'GET_LOCK' in sql:
            return {'got': self.got}
        if "role = 'admin' AND status = 'active'" in sql and sql.endswith('FOR UPDATE'):
            return [{'id': i} for i in self.admins]
        if 'COUNT(*)' in sql:
            return {'n': self.inactive}
        return None

    def cursor(self):
        return Cursor(self)

    def commit(self):
        self.events.append(('commit',))
        if self.commit_error:
            raise self.commit_error

    def rollback(self):
        self.events.append(('rollback',))

    def close(self):
        self.closed = True


def steps(conn):
    out = []
    for event in conn.events:
        if event[0] != 'sql':
            out.append(event[0])
            continue
        sql = event[1]
        out.append('GET_LOCK' if 'GET_LOCK' in sql else 'RELEASE_LOCK' if 'RELEASE_LOCK' in sql
                   else 'LOCK ADMINS' if sql.endswith('FOR UPDATE') else
                   'COUNT' if 'COUNT(*)' in sql else
                   'INSERT users' if sql.startswith('INSERT INTO users') else
                   'UPDATE users' if sql.startswith('UPDATE users') else
                   'INSERT audit' if sql.startswith('INSERT INTO audit_log') else sql)
    return out


def test_sql_lock_check_create_audit_commit_then_release(admin_hash):
    conn = Conn()
    result = AuthRepository(lambda: conn).create_first_admin(
        'Admin@Example.com', 'First Admin', admin_hash, workstation_label='local bootstrap command')
    assert result == {'user_id': 7, 'inactive_admins': 0}
    assert steps(conn) == ['GET_LOCK', 'LOCK ADMINS', 'COUNT', 'INSERT users', 'INSERT audit',
                           'commit', 'RELEASE_LOCK']
    assert "CONCAT('netcommand.first_admin.', DATABASE())" in conn.events[0][1]
    insert_sql, insert_params = conn.events[3][1], conn.events[3][2]
    assert "'admin', 'active', UTC_TIMESTAMP(6)" in insert_sql          # email verified now
    assert 'email_verified_at' in insert_sql
    assert insert_params == ('Admin@Example.com', 'admin@example.com', 'First Admin', admin_hash)
    audit_params = conn.events[4][2]
    assert audit_params[:3] == (None, 'admin@example.com', 'user.bootstrap_admin')
    assert audit_params[4:6] == ('7', 'success') and admin_hash not in str(audit_params)


def test_sql_refuses_when_an_active_admin_exists(admin_hash):
    conn = Conn(admins=[1])
    with pytest.raises(AdminExists):
        AuthRepository(lambda: conn).create_first_admin('a@example.com', 'A', admin_hash)
    assert steps(conn) == ['GET_LOCK', 'LOCK ADMINS', 'rollback', 'RELEASE_LOCK']


@pytest.mark.parametrize('got', [0, None])
def test_sql_busy_lock_creates_nothing(admin_hash, got):
    conn = Conn(got=got)
    with pytest.raises(SetupBusy):
        AuthRepository(lambda: conn).create_first_admin('a@example.com', 'A', admin_hash)
    assert steps(conn) == ['GET_LOCK', 'rollback']


def test_sql_duplicate_email_rolls_back_and_releases(admin_hash):
    conn = Conn(error=pymysql.err.IntegrityError(1062, "Duplicate entry for key "
                                                       "'users.uq_users_email'"),
                fail_on='INSERT INTO users')
    with pytest.raises(DuplicateEmail):
        AuthRepository(lambda: conn).create_first_admin('a@example.com', 'A', admin_hash)
    assert steps(conn)[-2:] == ['rollback', 'RELEASE_LOCK'] and 'commit' not in steps(conn)


def test_sql_lost_commit_is_uncertain_and_still_releases(admin_hash):
    conn = Conn(commit_error=pymysql.err.OperationalError(2013, 'Lost connection'))
    with pytest.raises(BackendDatabaseUnavailable) as err:
        AuthRepository(lambda: conn).create_first_admin('a@example.com', 'A', admin_hash)
    assert err.value.uncertain and steps(conn)[-1] == 'RELEASE_LOCK'


def test_sql_values_are_checked_before_connecting():
    repo = AuthRepository(lambda: pytest.fail('connected'))
    from backend.database.errors import InvalidValue
    for call in (lambda: repo.create_first_admin('bad', 'A', '$argon2id$' + 'x' * 40),
                 lambda: repo.create_first_admin('a@example.com', 'A', PASSWORD),
                 lambda: repo.create_first_admin('a@example.com', '', '$argon2id$' + 'x' * 40),
                 lambda: repo.mark_existing_admin_email_verified(0)):
        with pytest.raises(InvalidValue):
            call()


def test_sql_mark_existing_admin_changes_only_the_verification_time():
    conn = Conn(rowcount=1)
    assert AuthRepository(lambda: conn).mark_existing_admin_email_verified(
        5, workstation_label='local bootstrap command') is True
    assert steps(conn) == ['UPDATE users', 'INSERT audit', 'commit']
    sql, params = conn.events[0][1], conn.events[0][2]
    assert sql.startswith('UPDATE users SET email_verified_at = UTC_TIMESTAMP(6) WHERE id = %s')
    for condition in ("role = 'admin'", "status = 'active'", 'email_verified_at IS NULL'):
        assert condition in sql
    assert 'updated_at' not in sql and 'password' not in sql and params == (5,)
    assert conn.events[1][2][2] == 'auth.email_verified'


def test_sql_mark_existing_admin_no_match_writes_no_audit():
    conn = Conn(rowcount=0)
    assert AuthRepository(lambda: conn).mark_existing_admin_email_verified(5) is False
    assert steps(conn) == ['UPDATE users', 'commit']


def test_other_transactions_take_no_named_lock():
    conn = Conn()
    AuthRepository(lambda: conn).write_audit('auth.login', 'success')
    assert 'GET_LOCK' not in steps(conn) and 'RELEASE_LOCK' not in steps(conn)


# ================================================================ production database (Phase 1)
PROD_UUID = '3e11fa47-71ca-11e1-9e33-c80aa9429562'
PROD_FLAGS = ['--production', '--authorize-database', 'netcommand_backend',
              '--confirm-database', 'netcommand_backend']


def production_settings():
    return settings('netcommand_backend', BACKEND_ENV='production',
                    BACKEND_DB_SERVER_UUID=PROD_UUID)


class IdentityConn:
    def __init__(self, db='netcommand_backend', uuid=PROD_UUID):
        self.db, self.uuid, self.sent, self.closed = db, uuid, [], False

    def cursor(self):
        conn = self

        class Cur:
            def __enter__(self):
                return self

            def __exit__(self, *e):
                return False

            def execute(self, sql, params=()):
                conn.sent.append(sql)

            def fetchone(self):
                return {'db': conn.db, 'server_uuid': conn.uuid}
        return Cur()

    def close(self):
        self.closed = True


def run_production(argv, conn=None):
    lines, mailer = [], FakeMailer()
    prompts = Prompts(('admin@example.com', 'First Admin', CODE), (PASSWORD, PASSWORD), mailer)
    code = run(list(argv), settings=production_settings(), repository=InMemoryAuthRepository(),
               mailer=mailer, ask=prompts.ask, ask_secret=prompts.ask_secret,
               out=lines.append, clock=Clock(),
               identity_connect=(lambda s: conn) if conn else
               (lambda s: pytest.fail('connected for the identity check')))
    return code, '\n'.join(lines), prompts


@pytest.mark.parametrize('action', [[], ['verify-existing']])
@pytest.mark.parametrize('drop', ['--production', '--authorize-database', '--confirm-database'])
def test_production_needs_every_flag_before_anything_is_asked(action, drop):
    args = list(PROD_FLAGS)
    i = args.index(drop)
    del args[i:i + (1 if drop == '--production' else 2)]
    code, text, prompts = run_production(action + args)
    assert code == EXIT_REFUSED and 'PRODUCTION database' in text and prompts.asked == []


def test_production_identity_is_checked_first():
    conn = IdentityConn()
    code, text, _ = run_production(PROD_FLAGS, conn)
    assert code == EXIT_DONE and 'Identity checked' in text
    assert conn.sent == ['SELECT DATABASE() AS db, @@server_uuid AS server_uuid'] and conn.closed


@pytest.mark.parametrize('make_conn', [
    lambda: IdentityConn(db='netcommand_test'),
    lambda: IdentityConn(uuid='00000000-1111-2222-3333-444444444444')],
    ids=['wrong-database', 'wrong-server'])
def test_production_wrong_server_is_refused_before_anything_is_asked(make_conn):
    code, text, prompts = run_production(PROD_FLAGS, make_conn())
    assert code == EXIT_REFUSED and 'not proof of identity' in text and prompts.asked == []


def test_production_flag_is_refused_on_test_databases():
    code, text, prompts, _ = bootstrap(InMemoryAuthRepository(), argv=('--production',))
    assert code == EXIT_REFUSED and '--production was given' in text and prompts.asked == []
