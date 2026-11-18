"""Phase 4C (+ hardening): the authentication repository.

* InMemoryAuthRepository: behaviour (duplicates, roles/statuses, last-admin protection,
  audited privileged changes, one-use challenges bound to user and purpose, expiry,
  independent workstations, sessions with idle and absolute expiry, audit) with a
  controllable clock.
* AuthRepository (MySQL): the SQL it sends, its transactions, locking order and error
  translation, with a stand-in connection. No MySQL is contacted.
* Both raise the same error types for the same mistakes.
"""
import threading
from datetime import datetime, timedelta

import pymysql
import pytest

from backend.database.auth_repository import AuthRepository
from backend.database.errors import (BackendDatabaseError, BackendDatabaseUnavailable,
                                     DuplicateEmail, InvalidValue, LastActiveAdmin)
from backend.database.memory_repository import InMemoryAuthRepository
from backend.logging_config import REDACTED

HASH = '$argon2id$v=19$m=65536,t=3,p=4$' + 'c2FsdHNhbHRzYWx0' + '$' + 'h' * 43
HMAC = 'a' * 64
HMAC2 = 'b' * 64
TOKEN_HASH = 'c' * 64
PLAIN_PASSWORD = 'Plain-Password-123'
CID = 'A' * 43


class Clock:
    def __init__(self):
        self.now = datetime(2026, 11, 18, 8, 0, 0)

    def __call__(self):
        return self.now

    def advance(self, seconds):
        self.now += timedelta(seconds=seconds)


@pytest.fixture
def clock():
    return Clock()


@pytest.fixture
def repo(clock):
    return InMemoryAuthRepository(clock=clock)


def admin(repo, email='admin@example.com'):
    return repo.create_user(email, 'Admin', HASH, role='admin', status='active')


# ================================================================ users (in memory)
def test_create_get_and_find_by_email_ignoring_case(repo):
    uid = repo.create_user('  Alice@Example.COM ', 'Alice Cruz', HASH)
    u = repo.get_user(uid)
    assert (u['email'], u['full_name'], u['role'], u['status']) == (
        'Alice@Example.COM', 'Alice Cruz', 'viewer', 'pending_verification')
    assert 'password_hash' not in u
    assert repo.find_user_by_email('alice@example.com')['id'] == uid
    assert repo.get_password_hash(uid) == HASH
    assert repo.get_user(99) is None and repo.find_user_by_email('nobody@example.com') is None


@pytest.mark.parametrize('email', ['alice@example.com', 'ALICE@EXAMPLE.COM', ' Alice@example.com'])
def test_duplicate_email_is_refused(repo, email):
    repo.create_user('alice@example.com', 'Alice', HASH)
    with pytest.raises(DuplicateEmail):
        repo.create_user(email, 'Other', HASH)


@pytest.mark.parametrize('kwargs, message', [
    ({'password_hash': PLAIN_PASSWORD}, 'Argon2id'),
    ({'password_hash': '$argon2i$v=19$m=65536,t=3,p=4$' + 'x' * 40}, 'Argon2id'),
    ({'password_hash': '$ARGON2ID$v=19$m=65536,t=3,p=4$' + 'x' * 40}, 'Argon2id'),
    ({'role': 'superuser'}, 'role must be one of'),
    ({'status': 'enabled'}, 'status must be one of'),
    ({'email': 'not-an-email'}, 'email address is not valid'),
    ({'email': 'josé@example.com'}, 'plain ASCII'),
    ({'email': 'İnfo@example.com'}, 'plain ASCII'),
    ({'full_name': '   '}, 'full name is required'),
    ({'full_name': 'Line\nbreak'}, 'one line'),
])
def test_invalid_user_values_are_refused(repo, kwargs, message):
    args = dict(email='bob@example.com', full_name='Bob', password_hash=HASH)
    args.update(kwargs)
    with pytest.raises(InvalidValue) as err:
        repo.create_user(**args)
    assert message in str(err.value) and PLAIN_PASSWORD not in str(err.value)


def test_status_and_role_changes_are_audited(repo):
    boss = admin(repo)
    uid = repo.create_user('carl@example.com', 'Carl', HASH)
    assert repo.set_status(uid, 'disabled', expected_status='active', actor_user_id=boss) is False
    assert repo.set_status(uid, 'disabled', actor_user_id=boss, client_ip='10.0.0.7')
    assert repo.set_status(uid, 'disabled', actor_user_id=boss) is False       # no change
    assert repo.set_role(uid, 'operator', actor_user_id=boss, workstation_label='WS-1')
    assert repo.set_role(uid, 'operator', actor_user_id=boss) is False
    assert repo.set_role(999, 'viewer', actor_user_id=boss) is False
    u = repo.get_user(uid)
    assert (u['status'], u['role']) == ('disabled', 'operator')
    rows = repo.list_audit()
    assert [(r['action'], r['detail'], r['actor_user_id'], r['target_id']) for r in rows] == [
        ('user.role_changed', 'role viewer -> operator', boss, str(uid)),
        ('user.status_changed', 'status pending_verification -> disabled', boss, str(uid))]
    assert rows[0]['workstation_label'] == 'WS-1' and rows[1]['client_ip'] == '10.0.0.7'


def test_privileged_changes_require_the_actor_argument(repo):
    uid = repo.create_user('x@example.com', 'X', HASH)
    with pytest.raises(TypeError):
        repo.set_role(uid, 'operator')
    with pytest.raises(TypeError):
        repo.set_status(uid, 'disabled')
    with pytest.raises(InvalidValue):
        repo.set_role(uid, 'root', actor_user_id=1)


def test_the_last_active_admin_cannot_be_demoted_or_disabled(repo):
    a = admin(repo)
    for change in (lambda: repo.set_role(a, 'operator', actor_user_id=a),
                   lambda: repo.set_status(a, 'disabled', actor_user_id=a)):
        with pytest.raises(LastActiveAdmin):
            change()
    assert repo.get_user(a)['role'] == 'admin' and repo.list_audit() == []     # nothing changed
    b = admin(repo, 'b@example.com')
    assert repo.set_role(a, 'operator', actor_user_id=b)                       # b remains
    with pytest.raises(LastActiveAdmin):
        repo.set_status(b, 'disabled', actor_user_id=b)
    disabled_admin = repo.create_user('c@example.com', 'C', HASH, role='admin', status='disabled')
    with pytest.raises(LastActiveAdmin):                                       # c is not active
        repo.set_role(b, 'viewer', actor_user_id=b)
    assert repo.set_role(disabled_admin, 'viewer', actor_user_id=b)            # not active: fine


def test_concurrent_demotions_keep_one_active_admin(repo):
    admins = [admin(repo, f'a{i}@example.com') for i in range(6)]
    start, results = threading.Barrier(len(admins)), []

    def demote(uid):
        start.wait()
        try:
            results.append(repo.set_role(uid, 'viewer', actor_user_id=uid))
        except LastActiveAdmin:
            results.append('refused')
    threads = [threading.Thread(target=demote, args=(a,)) for a in admins]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert results.count(True) == 5 and results.count('refused') == 1
    assert sum(1 for a in admins if repo.get_user(a)['role'] == 'admin') == 1


def test_verification_then_approval_is_audited(repo):
    boss = admin(repo)
    uid = repo.create_user('dana@example.com', 'Dana', HASH)
    assert repo.approve_user(uid, boss) is False
    assert repo.mark_email_verified(uid) and not repo.mark_email_verified(uid)
    assert repo.approve_user(uid, boss, role='operator', client_ip='10.0.0.1')
    u = repo.get_user(uid)
    assert (u['status'], u['role'], u['approved_by']) == ('active', 'operator', boss)
    (row,) = repo.list_audit(action='user.approved')
    assert (row['actor_user_id'], row['target_id'], row['detail']) == (boss, str(uid),
                                                                       'role operator')


def test_only_another_active_admin_can_approve(repo):
    boss = admin(repo)
    second = admin(repo, 'second@example.com')
    viewer = repo.create_user('v@example.com', 'V', HASH, status='active')
    uid = repo.create_user('e@example.com', 'E', HASH, status='pending_approval')
    with pytest.raises(InvalidValue):
        repo.approve_user(uid, viewer)
    with pytest.raises(InvalidValue):
        repo.approve_user(boss, boss)
    repo.set_status(boss, 'disabled', actor_user_id=second)
    with pytest.raises(InvalidValue):
        repo.approve_user(uid, boss)
    assert repo.get_user(uid)['status'] == 'pending_approval'


# ================================================================ challenges (in memory)
def test_challenge_is_consumed_once_and_only_for_its_user_and_purpose(repo):
    uid = repo.create_user('f@example.com', 'F', HASH)
    other = repo.create_user('g@example.com', 'G', HASH)
    cid = repo.create_challenge(uid, 'register', HMAC, ttl_seconds=300, workstation_label='WS-1')
    assert repo.consume_challenge(cid, 'login', uid) is False          # wrong purpose
    assert repo.consume_challenge(cid, 'register', other) is False     # wrong user
    assert repo.consume_challenge(cid, 'register', uid) is True
    assert repo.consume_challenge(cid, 'register', uid) is False       # single use


def test_expired_challenge_cannot_be_consumed(repo, clock):
    uid = repo.create_user('h@example.com', 'H', HASH)
    cid = repo.create_challenge(uid, 'login', HMAC, ttl_seconds=300)
    clock.advance(299)
    assert not repo.get_challenge(cid)['expired']
    clock.advance(1)
    assert repo.get_challenge(cid)['expired'] and not repo.consume_challenge(cid, 'login', uid)


def test_wrong_codes_invalidate_the_challenge_at_the_limit(repo):
    uid = repo.create_user('i@example.com', 'I', HASH)
    cid = repo.create_challenge(uid, 'login', HMAC, ttl_seconds=300, max_attempts=3)
    assert repo.record_failed_attempt(cid) == {'attempts': 1, 'invalidated': False}
    assert repo.record_failed_attempt(cid) == {'attempts': 2, 'invalidated': False}
    assert repo.record_failed_attempt(cid) == {'attempts': 3, 'invalidated': True}
    assert repo.record_failed_attempt(cid) is None
    assert repo.consume_challenge(cid, 'login', uid) is False


def test_workstations_do_not_interfere(repo):
    uid = repo.create_user('j@example.com', 'J', HASH)
    one = repo.create_challenge(uid, 'login', HMAC, ttl_seconds=300, workstation_label='WS-1')
    two = repo.create_challenge(uid, 'login', HMAC2, ttl_seconds=300, workstation_label='WS-2')
    for _ in range(5):
        repo.record_failed_attempt(one)
    assert not repo.consume_challenge(one, 'login', uid)
    assert repo.consume_challenge(two, 'login', uid)


def test_challenges_can_be_invalidated(repo):
    uid = repo.create_user('k@example.com', 'K', HASH)
    a = repo.create_challenge(uid, 'login', HMAC, ttl_seconds=300)
    b = repo.create_challenge(uid, 'login', HMAC2, ttl_seconds=300)
    r = repo.create_challenge(uid, 'register', HMAC, ttl_seconds=300)
    assert repo.invalidate_challenge(a) and not repo.invalidate_challenge(a)
    assert repo.invalidate_user_challenges(uid, 'login') == 1
    assert not repo.consume_challenge(b, 'login', uid) and repo.consume_challenge(r, 'register', uid)


@pytest.mark.parametrize('kwargs', [{'code_hmac': '123456'}, {'code_hmac': 'A' * 64},
                                    {'purpose': 'reset'}, {'ttl_seconds': 0},
                                    {'ttl_seconds': 7200}, {'max_attempts': 0}])
def test_invalid_challenge_values_are_refused(repo, kwargs):
    uid = repo.create_user('l@example.com', 'L', HASH)
    args = dict(user_id=uid, purpose='login', code_hmac=HMAC, ttl_seconds=300)
    args.update(kwargs)
    with pytest.raises(InvalidValue):
        repo.create_challenge(**args)


def test_simultaneous_consumption_succeeds_once(repo):
    uid = repo.create_user('m@example.com', 'M', HASH)
    cid = repo.create_challenge(uid, 'login', HMAC, ttl_seconds=300)
    results, start = [], threading.Barrier(8)

    def use():
        start.wait()
        results.append(repo.consume_challenge(cid, 'login', uid))
    threads = [threading.Thread(target=use) for _ in range(8)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert sorted(results) == [False] * 7 + [True]


# ================================================================ sessions (in memory)
def active_user(repo, email='n@example.com'):
    return repo.create_user(email, 'N', HASH, status='active')


def test_session_lifecycle_and_revocation(repo):
    uid = active_user(repo)
    sid = repo.create_session(uid, TOKEN_HASH, lifetime_seconds=8 * 3600, workstation_label='WS-1')
    s = repo.get_active_session(TOKEN_HASH, idle_timeout_seconds=1800)
    assert s['id'] == sid and s['role'] == 'viewer' and 'token_hash' not in s
    assert repo.revoke_session(sid, 'logout') and not repo.revoke_session(sid, 'logout')
    assert repo.get_active_session(TOKEN_HASH, 1800) is None
    assert repo.touch_session(sid, 1800) is False                         # revoked
    assert 'token_hash' not in repo.list_sessions(uid)[0]


def test_touch_enforces_idle_and_absolute_expiry(repo, clock):
    uid = active_user(repo)
    sid = repo.create_session(uid, TOKEN_HASH, lifetime_seconds=8 * 3600)
    clock.advance(29 * 60)
    assert repo.touch_session(sid, 1800)                                  # within 30 minutes
    clock.advance(31 * 60)
    assert repo.touch_session(sid, 1800) is False                         # idle too long...
    assert repo.get_active_session(TOKEN_HASH, 1800) is None              # ...and stays dead
    sid2 = repo.create_session(uid, 'd' * 64, lifetime_seconds=3600)
    for _ in range(3):
        clock.advance(19 * 60)                                            # 57 minutes in total
        assert repo.touch_session(sid2, 1800)
    clock.advance(3 * 60)                                                 # 1 hour: absolute end
    assert repo.touch_session(sid2, 1800) is False
    assert repo.get_active_session('d' * 64, 1800) is None


def test_sessions_of_disabled_users_are_not_active(repo):
    boss, uid = admin(repo), active_user(repo)
    repo.create_session(uid, TOKEN_HASH, lifetime_seconds=3600)
    repo.set_status(uid, 'disabled', actor_user_id=boss)
    assert repo.get_active_session(TOKEN_HASH, 1800) is None


def test_revoke_all_sessions_of_a_user(repo):
    uid, other = active_user(repo), active_user(repo, 'o@example.com')
    repo.create_session(uid, 'e' * 64, 3600, workstation_label='WS-1')
    repo.create_session(uid, 'f' * 64, 3600, workstation_label='WS-2')
    repo.create_session(other, '1' * 64, 3600)
    assert repo.revoke_user_sessions(uid, 'password_changed') == 2
    assert repo.get_active_session('1' * 64, 1800) is not None


@pytest.mark.parametrize('token', ['raw-session-token-value', 'C' * 64, 'c' * 63])
def test_raw_tokens_are_refused(repo, token):
    uid = active_user(repo)
    with pytest.raises(InvalidValue) as err:
        repo.create_session(uid, token, 3600)
    assert token not in str(err.value)


# ================================================================ audit (in memory)
def test_audit_records_are_kept_newest_first_and_redacted(repo):
    repo.write_audit('auth.login', 'failure', actor_email='x@example.com',
                     detail=f'bad password={PLAIN_PASSWORD} from WS-1', client_ip='10.0.0.5')
    repo.write_audit('admin.approve', 'success', actor_user_id=1, target_type='user', target_id=7)
    rows = repo.list_audit()
    assert [r['action'] for r in rows] == ['admin.approve', 'auth.login']
    assert PLAIN_PASSWORD not in rows[1]['detail'] and REDACTED in rows[1]['detail']
    assert rows[0]['target_id'] == '7'


def test_audit_cannot_be_changed_or_deleted_through_the_repository(repo):
    for r in (repo, AuthRepository(lambda: None)):
        for name in dir(r):
            assert not ('audit' in name and any(w in name for w in ('delete', 'update', 'clear',
                                                                     'remove', 'purge')))


@pytest.mark.parametrize('kwargs', [{'outcome': 'ok'}, {'action': 'Login Now'},
                                    {'actor_user_id': 0}])
def test_invalid_audit_values(repo, kwargs):
    args = dict(action='auth.login', outcome='success')
    args.update(kwargs)
    with pytest.raises(InvalidValue):
        repo.write_audit(**args)


# ================================================================ AuthRepository (SQL)
class Cursor:
    def __init__(self, conn):
        self.conn, self.rowcount, self.lastrowid, self._rows = conn, 0, None, []

    def __enter__(self):
        return self

    def __exit__(self, *e):
        return False

    def execute(self, sql, params=()):
        self.conn.sent.append((sql, params))
        if self.conn.error is not None and self.conn.fail_on in sql:
            raise self.conn.error
        self.rowcount = self.conn.rowcount
        self.lastrowid = 41
        answer = self.conn.answer(sql)
        self._rows = answer if isinstance(answer, list) else ([answer] if answer else [])

    def fetchone(self):
        return self._rows[0] if self._rows else None

    def fetchall(self):
        return list(self._rows)


class Conn:
    def __init__(self, rowcount=1, answer=lambda sql: None, error=None, fail_on='',
                 commit_error=None):
        self.rowcount, self.answer, self.error, self.fail_on = rowcount, answer, error, fail_on
        self.commit_error = commit_error
        self.sent, self.commits, self.rollbacks, self.closed = [], 0, 0, False

    def cursor(self):
        return Cursor(self)

    def commit(self):
        if self.commit_error:
            raise self.commit_error
        self.commits += 1

    def rollback(self):
        self.rollbacks += 1

    def close(self):
        self.closed = True


def sql_repo(conn):
    return AuthRepository(lambda: conn)


def never_connect():
    return AuthRepository(lambda: pytest.fail('connected to the database'))


def kinds(conn):
    return [sql.split()[0] + (' FOR UPDATE' if sql.endswith('FOR UPDATE') else '')
            for sql, _ in conn.sent]


def test_sql_create_user_is_parameterised_and_committed():
    conn = Conn()
    assert sql_repo(conn).create_user('Ann@Example.com', 'Ann', HASH, role='operator') == 41
    (sql, params), = conn.sent
    assert sql.startswith('INSERT INTO users') and params == (
        'Ann@Example.com', 'ann@example.com', 'Ann', HASH, 'operator', 'pending_verification')
    assert HASH not in sql and conn.commits == 1 and conn.closed


def test_sql_constraint_errors_match_the_memory_repository():
    cases = [(pymysql.err.IntegrityError(1062, "Duplicate entry 'x' for key 'users.uq_users_email'"),
              'INSERT INTO users', lambda r: r.create_user('a@example.com', 'A', HASH), DuplicateEmail),
             (pymysql.err.IntegrityError(1062, "Duplicate entry 'x' for key "
                                               "'sessions.uq_sessions_token_hash'"),
              'INSERT INTO sessions', lambda r: r.create_session(1, TOKEN_HASH, 3600), InvalidValue),
             (pymysql.err.IntegrityError(1452, 'Cannot add or update a child row: a foreign key '
                                               'constraint fails'),
              'INSERT INTO email_challenges', lambda r: r.create_challenge(1, 'login', HMAC, 300),
              InvalidValue)]
    for error, fail_on, call, expected in cases:
        conn = Conn(error=error, fail_on=fail_on, answer=lambda sql: {'id': 1})
        with pytest.raises(expected) as err:
            call(sql_repo(conn))
        assert "Duplicate entry" not in str(err.value) and conn.rollbacks == 1


def test_sql_and_memory_raise_the_same_error_for_a_missing_user(repo):
    with pytest.raises(InvalidValue) as mem:
        repo.create_challenge(99, 'login', HMAC, 300)
    conn = Conn(answer=lambda sql: None)                  # SELECT ... FOR SHARE finds nothing
    with pytest.raises(InvalidValue) as sql:
        sql_repo(conn).create_challenge(99, 'login', HMAC, 300)
    assert str(mem.value) == str(sql.value) == 'The user does not exist.'
    assert kinds(conn) == ['SELECT'] and conn.rollbacks == 1          # no INSERT sent
    with pytest.raises(InvalidValue) as mem2:
        repo.create_session(99, TOKEN_HASH, 3600)
    with pytest.raises(InvalidValue) as sql2:
        sql_repo(Conn(answer=lambda sql: None)).create_session(99, TOKEN_HASH, 3600)
    assert str(mem2.value) == str(sql2.value)


@pytest.mark.parametrize('error, expected', [
    (pymysql.err.OperationalError(2013, 'Lost connection'), BackendDatabaseUnavailable),
    (pymysql.err.OperationalError(3819, 'Check constraint violated'), BackendDatabaseError),
])
def test_sql_errors_are_translated_and_rolled_back(error, expected):
    conn = Conn(error=error, fail_on='INSERT')
    with pytest.raises(expected) as err:
        sql_repo(conn).write_audit('auth.login', 'failure', detail=f'password={PLAIN_PASSWORD}')
    assert PLAIN_PASSWORD not in str(err.value) and conn.rollbacks == 1 and conn.closed


def test_sql_lost_commit_is_uncertain():
    conn = Conn(commit_error=pymysql.err.OperationalError(2013, 'Lost'))
    with pytest.raises(BackendDatabaseUnavailable) as err:
        sql_repo(conn).revoke_session(5, 'logout')
    assert err.value.uncertain


def test_sql_invalid_values_never_reach_the_database():
    repo = never_connect()
    for call in (lambda: repo.create_user('a@example.com', 'A', PLAIN_PASSWORD),
                 lambda: repo.create_user('ä@example.com', 'A', HASH),
                 lambda: repo.create_challenge(1, 'login', '123456', 300),
                 lambda: repo.create_session(1, 'raw-token', 3600),
                 lambda: repo.set_role(1, 'superuser', actor_user_id=2),
                 lambda: repo.consume_challenge(CID, 'reset', 1),
                 lambda: repo.get_challenge("x' OR '1'='1"),
                 lambda: repo.write_audit('auth.login', 'maybe')):
        with pytest.raises(InvalidValue):
            call()


def admin_answer(active_admins, target):
    def answer(sql):
        if "role = 'admin' AND status = 'active'" in sql:
            return [{'id': i} for i in active_admins]
        if sql.startswith('SELECT role, status FROM users WHERE id'):
            return target
        return None
    return answer


def test_sql_role_change_locks_admins_first_then_updates_and_audits_together():
    conn = Conn(answer=admin_answer([1, 2], {'role': 'admin', 'status': 'active'}))
    assert sql_repo(conn).set_role(2, 'operator', actor_user_id=1, client_ip='10.0.0.1') is True
    assert kinds(conn) == ['SELECT FOR UPDATE', 'SELECT FOR UPDATE', 'UPDATE', 'INSERT']
    assert 'ORDER BY id FOR UPDATE' in conn.sent[0][0]                   # fixed lock order
    insert_sql, params = conn.sent[3]
    assert insert_sql.startswith('INSERT INTO audit_log')
    assert params[:3] == (1, None, 'user.role_changed') and params[-1] == 'role admin -> operator'
    assert conn.commits == 1                                             # one transaction


def test_sql_last_admin_change_is_refused_inside_the_transaction():
    for call in (lambda r: r.set_role(1, 'viewer', actor_user_id=1),
                 lambda r: r.set_status(1, 'disabled', actor_user_id=1)):
        conn = Conn(answer=admin_answer([1], {'role': 'admin', 'status': 'active'}))
        with pytest.raises(LastActiveAdmin):
            call(sql_repo(conn))
        assert kinds(conn) == ['SELECT FOR UPDATE', 'SELECT FOR UPDATE']   # no UPDATE, no audit
        assert conn.rollbacks == 1 and conn.commits == 0


def test_sql_failed_audit_insert_rolls_back_the_change():
    conn = Conn(answer=admin_answer([1, 2], {'role': 'viewer', 'status': 'active'}),
                error=pymysql.err.OperationalError(2013, 'Lost'), fail_on='INSERT INTO audit_log')
    with pytest.raises(BackendDatabaseUnavailable):
        sql_repo(conn).set_status(5, 'disabled', actor_user_id=1)
    assert 'UPDATE' in kinds(conn) and conn.rollbacks == 1 and conn.commits == 0


def test_sql_no_change_writes_no_audit():
    conn = Conn(answer=admin_answer([1], {'role': 'viewer', 'status': 'active'}))
    assert sql_repo(conn).set_role(5, 'viewer', actor_user_id=1) is False
    assert kinds(conn) == ['SELECT FOR UPDATE', 'SELECT FOR UPDATE']


def test_sql_approval_locks_the_approver_refuses_non_admins_and_audits():
    conn = Conn(answer=lambda sql: {'role': 'viewer', 'status': 'active'} if 'FOR UPDATE' in sql else None)
    with pytest.raises(InvalidValue):
        sql_repo(conn).approve_user(7, 2)
    assert kinds(conn) == ['SELECT FOR UPDATE'] and conn.rollbacks == 1
    conn2 = Conn(answer=lambda sql: {'role': 'admin', 'status': 'active'})
    assert sql_repo(conn2).approve_user(7, 2, role='operator') is True
    assert kinds(conn2) == ['SELECT FOR UPDATE', 'UPDATE', 'INSERT'] and conn2.commits == 1
    assert conn2.sent[2][1][2] == 'user.approved'


def test_sql_consume_checks_id_purpose_and_user_atomically():
    conn = Conn(rowcount=1)
    assert sql_repo(conn).consume_challenge(CID, 'login', 7) is True
    (sql, params), = conn.sent
    for condition in ('public_id = %s', 'purpose = %s', 'user_id = %s', 'consumed_at IS NULL',
                      'invalidated_at IS NULL', 'expires_at > UTC_TIMESTAMP(6)',
                      'attempts < max_attempts'):
        assert condition in sql
    assert params == (CID, 'login', 7)
    conn.rowcount = 0
    assert sql_repo(conn).consume_challenge(CID, 'login', 7) is False


def test_sql_touch_enforces_idle_timeout():
    conn = Conn(rowcount=0)
    assert sql_repo(conn).touch_session(5, 1800) is False
    sql, params = conn.sent[0]
    for condition in ('revoked_at IS NULL', 'expires_at > UTC_TIMESTAMP(6)',
                      'last_seen_at > UTC_TIMESTAMP(6) - INTERVAL %s SECOND'):
        assert condition in sql
    assert params == (5, 1800)


def test_sql_create_challenge_checks_the_user_then_inserts_with_database_time():
    conn = Conn(answer=lambda sql: {'id': 3})
    cid = sql_repo(conn).create_challenge(3, 'login', HMAC, 300, requester_ip='10.0.0.9')
    assert kinds(conn) == ['SELECT', 'INSERT']
    assert conn.sent[0][0].endswith('FOR SHARE')
    sql, params = conn.sent[1]
    assert 'UTC_TIMESTAMP(6) + INTERVAL %s SECOND' in sql and params[0] == cid and 300 in params


def test_sql_active_session_checks_every_condition():
    conn = Conn()
    assert sql_repo(conn).get_active_session(TOKEN_HASH, 1800) is None
    sql, params = conn.sent[0]
    for condition in ('s.revoked_at IS NULL', 's.expires_at > UTC_TIMESTAMP(6)',
                      's.last_seen_at > UTC_TIMESTAMP(6) - INTERVAL %s SECOND',
                      "u.status = 'active'"):
        assert condition in sql
    assert 'token_hash' not in sql.split('FROM')[0] and params == (TOKEN_HASH, 1800)


def test_sql_user_rows_never_include_the_password_hash():
    conn = Conn(answer=lambda sql: {'id': 1})
    repo = sql_repo(conn)
    repo.get_user(1)
    repo.find_user_by_email('Ann@Example.com')
    assert all('password_hash' not in sql for sql, _ in conn.sent)


def test_sql_audit_detail_is_redacted_and_list_is_limited():
    conn = Conn()
    repo = sql_repo(conn)
    repo.write_audit('auth.login', 'failure', detail=f'token={TOKEN_HASH} password={PLAIN_PASSWORD}')
    assert PLAIN_PASSWORD not in str(conn.sent[0][1]) and TOKEN_HASH not in str(conn.sent[0][1])
    repo.list_audit(limit=50, actor_user_id=3, action='auth.login')
    sql, params = conn.sent[1]
    assert sql.endswith('ORDER BY id DESC LIMIT %s') and params == (3, 'auth.login', 50)
    with pytest.raises(InvalidValue):
        repo.list_audit(limit=100000)
