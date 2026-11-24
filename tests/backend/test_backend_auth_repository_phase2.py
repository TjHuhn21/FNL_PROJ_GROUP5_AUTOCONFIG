"""Authentication repository additions (Phase 2): password attempts and lockout, user
listing for the approval workflow, and resend-cooldown support.

* InMemoryAuthRepository: behaviour with a controllable clock, including real threads.
* AuthRepository (MySQL): the SQL it sends, locking, transactions and audit, with a
  stand-in connection. No MySQL is contacted.
* Both: the same results, error types and messages for the same inputs.
"""
import threading
from datetime import datetime, timedelta

import pymysql
import pytest

from backend.auth.policy import DEFAULT_POLICY
from backend.database import auth_records as R
from backend.database.auth_repository import LIST_USER_FIELDS, AuthRepository
from backend.database.errors import BackendDatabaseUnavailable, InvalidValue, ResendTooSoon
from backend.database.memory_repository import InMemoryAuthRepository

HASH = '$argon2id$v=19$m=65536,t=3,p=4$' + 'c2FsdHNhbHRzYWx0' + '$' + 'h' * 43
HMAC = 'a' * 64
THRESHOLD, LOCKOUT = DEFAULT_POLICY.lockout_threshold, DEFAULT_POLICY.lockout_seconds
COOLDOWN = DEFAULT_POLICY.resend_cooldown_seconds
T0 = datetime(2026, 11, 19, 8, 0, 0)


class Clock:
    def __init__(self):
        self.now = T0

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


def user(repo, email='u@example.com', status='active', role='viewer'):
    return repo.create_user(email, 'Test User', HASH, role=role, status=status,
                            email_verified=status in ('active', 'pending_approval'))


def attempt(repo, uid, **kw):
    return repo.begin_password_attempt(uid, THRESHOLD, LOCKOUT, **kw)


# ================================================================ lockout (in memory)
def test_policy_values_are_the_approved_ones():
    assert (THRESHOLD, LOCKOUT, COOLDOWN) == (5, 900, 60)


def test_attempts_are_counted_and_the_fifth_locks(repo):
    uid = user(repo)
    for n in range(1, THRESHOLD):
        assert attempt(repo, uid) == {'allowed': True, 'failed_logins': n, 'locked_until': None,
                                      'newly_locked': False}
    assert repo.list_audit() == []                       # ordinary failures: no lock audit
    fifth = attempt(repo, uid, client_ip='10.0.0.5', workstation_label='LAB-PC-1')
    assert fifth == {'allowed': True, 'failed_logins': 5,
                     'locked_until': T0 + timedelta(seconds=LOCKOUT), 'newly_locked': True}
    assert repo.get_user(uid)['locked_until'] == T0 + timedelta(seconds=LOCKOUT)
    (audit,) = repo.list_audit()
    assert (audit['action'], audit['outcome'], audit['target_type'], audit['target_id'],
            audit['actor_user_id'], audit['client_ip'], audit['workstation_label']) == (
        'auth.account_locked', 'denied', 'user', str(uid), None, '10.0.0.5', 'LAB-PC-1')
    assert '5 password attempts' in audit['detail'] and '900 s' in audit['detail']


def test_a_locked_account_refuses_attempts_without_counting_them(repo):
    uid = user(repo)
    for _ in range(THRESHOLD):
        attempt(repo, uid)
    for _ in range(3):
        result = attempt(repo, uid)
        assert result['allowed'] is False and result['failed_logins'] == THRESHOLD
        assert result['newly_locked'] is False
    assert len(repo.list_audit()) == 1                   # the lock was audited once
    assert repo.get_user(uid)['locked_until'] == T0 + timedelta(seconds=LOCKOUT)   # not extended


def test_the_lock_expires_after_the_lockout_and_counting_restarts(repo, clock):
    uid = user(repo)
    for _ in range(THRESHOLD):
        attempt(repo, uid)
    clock.advance(LOCKOUT - 1)
    assert attempt(repo, uid)['allowed'] is False
    clock.advance(1)                                      # exactly at locked_until: expired
    assert attempt(repo, uid) == {'allowed': True, 'failed_logins': 1, 'locked_until': None,
                                  'newly_locked': False}
    for _ in range(THRESHOLD - 1):
        last = attempt(repo, uid)
    assert last['newly_locked'] is True                   # a fresh lock after 5 more


def test_success_clears_the_count(repo):
    uid = user(repo)
    for _ in range(3):
        attempt(repo, uid)
    assert repo.record_password_success(uid) is True
    u = repo.get_user(uid)
    assert (u['failed_logins'], u['locked_until']) == (0, None)
    assert repo.list_audit() == []                         # nothing was locked: no audit
    assert attempt(repo, uid)['failed_logins'] == 1


def test_success_on_the_locking_attempt_clears_the_lock_and_is_audited(repo):
    uid = user(repo)
    for _ in range(THRESHOLD):
        attempt(repo, uid)
    assert repo.record_password_success(uid, client_ip='10.0.0.5') is True
    assert repo.get_user(uid)['locked_until'] is None
    cleared, locked = repo.list_audit()
    assert (locked['action'], cleared['action'], cleared['outcome']) == (
        'auth.account_locked', 'auth.lock_cleared', 'success')
    assert cleared['actor_user_id'] == uid and cleared['client_ip'] == '10.0.0.5'
    assert attempt(repo, uid)['allowed'] is True


def test_success_after_an_expired_lock_is_not_audited_as_clearing_it(repo, clock):
    uid = user(repo)
    for _ in range(THRESHOLD):
        attempt(repo, uid)
    clock.advance(LOCKOUT)
    repo.record_password_success(uid)
    assert [a['action'] for a in repo.list_audit()] == ['auth.account_locked']
    assert repo.get_user(uid)['locked_until'] is None


def test_unknown_user(repo):
    assert attempt(repo, 99) is None
    assert repo.record_password_success(99) is False


def test_concurrent_attempts_cannot_exceed_the_threshold(repo):
    """50 simultaneous attempts: exactly `threshold` may check a password, exactly one
    locks the account, and the lock is audited once."""
    uid = user(repo)
    barrier, results = threading.Barrier(50), []

    def worker():
        barrier.wait()
        results.append(attempt(repo, uid))
    threads = [threading.Thread(target=worker) for _ in range(50)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert sum(r['allowed'] for r in results) == THRESHOLD
    assert sum(r['newly_locked'] for r in results) == 1
    assert sorted(r['failed_logins'] for r in results if r['allowed']) == list(range(1, 6))
    assert len(repo.list_audit(action='auth.account_locked')) == 1


def test_a_correct_password_cannot_get_through_once_locked(repo):
    """The decision is made before the password is checked: after the lock, even the
    right password is never checked, so guessing in parallel gains nothing."""
    uid = user(repo)
    for _ in range(THRESHOLD):
        attempt(repo, uid)
    assert attempt(repo, uid)['allowed'] is False


# ================================================================ listing (in memory)
def test_list_users_filters_by_status_oldest_first_without_secrets(repo, clock):
    a = user(repo, 'a@example.com', status='pending_approval')
    user(repo, 'b@example.com', status='active')
    c = user(repo, 'c@example.com', status='pending_approval')
    user(repo, 'd@example.com', status='pending_verification')
    rows = repo.list_users(status='pending_approval')
    assert [r['id'] for r in rows] == [a, c]
    for r in rows:
        assert tuple(r) == LIST_USER_FIELDS
        for hidden in ('password_hash', 'email_normalized', 'failed_logins', 'locked_until'):
            assert hidden not in r
        assert HASH not in str(r)
    assert len(repo.list_users()) == 4


def test_list_users_reports_active_locks_only(repo, clock):
    uid = user(repo)
    assert repo.list_users()[0]['locked'] is False
    for _ in range(THRESHOLD):
        attempt(repo, uid)
    assert repo.list_users()[0]['locked'] is True
    clock.advance(LOCKOUT)
    assert repo.list_users()[0]['locked'] is False


def test_list_users_pages_with_limit_and_after_id(repo):
    ids = [user(repo, f'p{i}@example.com', status='pending_approval') for i in range(5)]
    first = repo.list_users(status='pending_approval', limit=2)
    second = repo.list_users(status='pending_approval', limit=2, after_id=first[-1]['id'])
    rest = repo.list_users(status='pending_approval', limit=10, after_id=second[-1]['id'])
    assert [r['id'] for r in first + second + rest] == ids


def test_list_users_returns_copies(repo):
    uid = user(repo)
    repo.list_users()[0]['status'] = 'disabled'
    assert repo.get_user(uid)['status'] == 'active'


# ================================================================ resend cooldown (in memory)
@pytest.mark.parametrize('since, expected', [(None, 0), (0, 60), (1, 59), (59, 1), (59.9, 1),
                                             (60, 0), (61, 0), (10000, 0), (-5, 60)])
def test_retry_after_calculation(since, expected):
    assert R.retry_after(since, 60) == expected


def test_resend_state_follows_the_cooldown(repo, clock):
    uid = user(repo)
    assert repo.challenge_resend_state(uid, 'login', COOLDOWN) == {
        'recent_count': 0, 'seconds_since_last': None, 'retry_after_seconds': 0}
    repo.create_challenge(uid, 'login', HMAC, 300)
    assert repo.challenge_resend_state(uid, 'login', COOLDOWN)['retry_after_seconds'] == 60
    clock.advance(30)
    assert repo.challenge_resend_state(uid, 'login', COOLDOWN) == {
        'recent_count': 1, 'seconds_since_last': 30, 'retry_after_seconds': 30}
    clock.now += timedelta(seconds=29, milliseconds=900)    # 59.9 s: still 1 s to wait
    assert repo.challenge_resend_state(uid, 'login', COOLDOWN)['retry_after_seconds'] == 1
    clock.now += timedelta(milliseconds=100)                # 60 s
    assert repo.challenge_resend_state(uid, 'login', COOLDOWN)['retry_after_seconds'] == 0


def test_resend_state_is_per_user_and_purpose_and_counts_the_window(repo, clock):
    uid, other = user(repo), user(repo, 'o@example.com')
    for _ in range(3):
        public_id = repo.create_challenge(uid, 'register', HMAC, 300)
        clock.advance(120)
    repo.consume_challenge(public_id, 'register', uid)       # used codes still count
    assert repo.challenge_resend_state(uid, 'register', COOLDOWN)['recent_count'] == 3
    assert repo.challenge_resend_state(uid, 'register', COOLDOWN, window_seconds=300)[
        'recent_count'] == 2                                  # created 120 s and 240 s ago
    assert repo.challenge_resend_state(uid, 'login', COOLDOWN)['recent_count'] == 0
    assert repo.challenge_resend_state(other, 'register', COOLDOWN)['recent_count'] == 0


def test_resend_state_never_returns_codes_or_ids(repo):
    uid = user(repo)
    public_id = repo.create_challenge(uid, 'login', HMAC, 300)
    state = repo.challenge_resend_state(uid, 'login', COOLDOWN)
    assert set(state) == {'recent_count', 'seconds_since_last', 'retry_after_seconds'}
    assert HMAC not in str(state) and public_id not in str(state)


def test_create_challenge_enforces_the_cooldown(repo, clock):
    uid = user(repo)
    repo.create_challenge(uid, 'login', HMAC, 300, resend_cooldown_seconds=COOLDOWN)
    clock.advance(20)
    with pytest.raises(ResendTooSoon) as err:
        repo.create_challenge(uid, 'login', HMAC, 300, resend_cooldown_seconds=COOLDOWN)
    assert err.value.retry_after_seconds == 40 and '40 seconds' in str(err.value)
    assert HMAC not in str(err.value)
    assert repo.challenge_resend_state(uid, 'login', COOLDOWN)['recent_count'] == 1   # none made
    repo.create_challenge(uid, 'register', HMAC, 300, resend_cooldown_seconds=COOLDOWN)
    repo.create_challenge(uid, 'login', HMAC, 300)       # no cooldown asked: unchanged behaviour
    clock.advance(60)
    assert repo.create_challenge(uid, 'login', HMAC, 300, resend_cooldown_seconds=COOLDOWN)


def test_concurrent_resend_requests_create_one_code(repo):
    uid = user(repo)
    barrier, created, refused = threading.Barrier(20), [], []

    def worker():
        barrier.wait()
        try:
            created.append(repo.create_challenge(uid, 'login', HMAC, 300,
                                                 resend_cooldown_seconds=COOLDOWN))
        except ResendTooSoon:
            refused.append(1)
    threads = [threading.Thread(target=worker) for _ in range(20)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert (len(created), len(refused)) == (1, 19)


# ================================================================ invalid values (both)
def never_connect():
    return AuthRepository(lambda: pytest.fail('connected to the database'))


INVALID_CALLS = [
    lambda r: r.begin_password_attempt(0, 5, 900),
    lambda r: r.begin_password_attempt(1, 0, 900),
    lambda r: r.begin_password_attempt(1, 101, 900),
    lambda r: r.begin_password_attempt(1, True, 900),
    lambda r: r.begin_password_attempt(1, '5', 900),
    lambda r: r.begin_password_attempt(1, 5, 0),
    lambda r: r.begin_password_attempt(1, 5, 86401),
    lambda r: r.begin_password_attempt(1, 5, 900, client_ip='x' * 46),
    lambda r: r.record_password_success(-1),
    lambda r: r.record_password_success(1, workstation_label='a\nb'),
    lambda r: r.list_users(status='enabled'),
    lambda r: r.list_users(limit=0),
    lambda r: r.list_users(limit=1001),
    lambda r: r.list_users(limit=True),
    lambda r: r.list_users(after_id=0),
    lambda r: r.challenge_resend_state(1, 'reset', 60),
    lambda r: r.challenge_resend_state(1, 'login', 0),
    lambda r: r.challenge_resend_state(1, 'login', 3601),
    lambda r: r.challenge_resend_state(1, 'login', 60, window_seconds=59),
    lambda r: r.challenge_resend_state(1, 'login', 60, window_seconds=86401),
    lambda r: r.create_challenge(1, 'login', HMAC, 300, resend_cooldown_seconds=0),
    lambda r: r.create_challenge(1, 'login', HMAC, 300, resend_cooldown_seconds=True),
]


@pytest.mark.parametrize('index', range(len(INVALID_CALLS)))
def test_invalid_values_give_the_same_error_and_never_reach_the_database(repo, index):
    call = INVALID_CALLS[index]
    with pytest.raises(InvalidValue) as mem:
        call(repo)
    with pytest.raises(InvalidValue) as sql:
        call(never_connect())
    assert type(mem.value) is type(sql.value) and str(mem.value) == str(sql.value)


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
        self.rowcount, self.lastrowid = 1, 41
        answer = self.conn.answer(sql)
        self._rows = answer if isinstance(answer, list) else ([answer] if answer else [])

    def fetchone(self):
        return self._rows[0] if self._rows else None

    def fetchall(self):
        return list(self._rows)


class Conn:
    def __init__(self, answer=lambda sql: None, error=None, fail_on=''):
        self.answer, self.error, self.fail_on = answer, error, fail_on
        self.sent, self.commits, self.rollbacks, self.closed = [], 0, 0, False

    def cursor(self):
        return Cursor(self)

    def commit(self):
        self.commits += 1

    def rollback(self):
        self.rollbacks += 1

    def close(self):
        self.closed = True


def sql_repo(conn):
    return AuthRepository(lambda: conn)


def kinds(conn):
    return [sql.split()[0] + (' FOR UPDATE' if sql.endswith('FOR UPDATE') else '')
            for sql, _ in conn.sent]


def user_row(failed=0, locked_until=None, locked=0):
    until = T0 + timedelta(seconds=LOCKOUT)

    def answer(sql):
        if sql.startswith('SELECT failed_logins'):
            return {'failed_logins': failed, 'locked_until': locked_until, 'locked': locked}
        if sql.startswith('SELECT locked_until'):
            return {'locked_until': until}
        return None
    return answer


def test_sql_attempt_locks_the_row_and_counts_with_database_time():
    conn = Conn(answer=user_row(failed=2))
    result = sql_repo(conn).begin_password_attempt(7, THRESHOLD, LOCKOUT)
    assert result == {'allowed': True, 'failed_logins': 3, 'locked_until': None,
                      'newly_locked': False}
    assert kinds(conn) == ['SELECT FOR UPDATE', 'UPDATE']
    select, update = conn.sent
    assert 'locked_until > UTC_TIMESTAMP(6)' in select[0] and select[1] == (7,)
    assert update == ('UPDATE users SET failed_logins = %s, locked_until = NULL WHERE id = %s',
                      (3, 7))
    assert conn.commits == 1 and conn.closed


def test_sql_threshold_attempt_locks_and_audits_in_one_transaction():
    conn = Conn(answer=user_row(failed=4))
    result = sql_repo(conn).begin_password_attempt(7, THRESHOLD, LOCKOUT, client_ip='10.0.0.5')
    assert result == {'allowed': True, 'failed_logins': 5,
                      'locked_until': T0 + timedelta(seconds=LOCKOUT), 'newly_locked': True}
    assert kinds(conn) == ['SELECT FOR UPDATE', 'UPDATE', 'INSERT', 'SELECT']
    update_sql, update_params = conn.sent[1]
    assert 'locked_until = UTC_TIMESTAMP(6) + INTERVAL %s SECOND' in update_sql
    assert update_params == (5, LOCKOUT, 7)
    audit_sql, audit_params = conn.sent[2]
    assert audit_sql.startswith('INSERT INTO audit_log')
    assert audit_params[:3] == (None, None, 'auth.account_locked')
    assert audit_params[3:7] == ('user', '7', 'denied', '10.0.0.5')
    assert conn.commits == 1


def test_sql_locked_account_changes_nothing():
    conn = Conn(answer=user_row(failed=5, locked_until=T0, locked=1))
    result = sql_repo(conn).begin_password_attempt(7, THRESHOLD, LOCKOUT)
    assert result['allowed'] is False and result['failed_logins'] == 5
    assert kinds(conn) == ['SELECT FOR UPDATE']


def test_sql_expired_lock_restarts_the_count():
    conn = Conn(answer=user_row(failed=5, locked_until=T0, locked=0))
    assert sql_repo(conn).begin_password_attempt(7, THRESHOLD, LOCKOUT)['failed_logins'] == 1
    assert conn.sent[1][1] == (1, 7)


def test_sql_missing_user():
    conn = Conn()
    assert sql_repo(conn).begin_password_attempt(7, THRESHOLD, LOCKOUT) is None
    assert sql_repo(conn).record_password_success(7) is False
    assert kinds(conn) == ['SELECT FOR UPDATE', 'SELECT FOR UPDATE']


def test_sql_failed_lock_audit_rolls_back_the_lock():
    conn = Conn(answer=user_row(failed=4), error=pymysql.err.OperationalError(2013, 'Lost'),
                fail_on='INSERT INTO audit_log')
    with pytest.raises(BackendDatabaseUnavailable):
        sql_repo(conn).begin_password_attempt(7, THRESHOLD, LOCKOUT)
    assert 'UPDATE' in kinds(conn) and conn.rollbacks == 1 and conn.commits == 0


@pytest.mark.parametrize('row, expected_kinds', [
    (dict(failed=3), ['SELECT FOR UPDATE', 'UPDATE']),
    (dict(failed=0), ['SELECT FOR UPDATE']),                             # nothing to clear
    (dict(failed=5, locked_until=T0, locked=0), ['SELECT FOR UPDATE', 'UPDATE']),   # expired
    (dict(failed=5, locked_until=T0, locked=1), ['SELECT FOR UPDATE', 'UPDATE', 'INSERT']),
])
def test_sql_success_clears_and_audits_only_an_active_lock(row, expected_kinds):
    conn = Conn(answer=user_row(**row))
    assert sql_repo(conn).record_password_success(7, client_ip='10.0.0.5') is True
    assert kinds(conn) == expected_kinds and conn.commits == 1
    if 'UPDATE' in expected_kinds:
        assert conn.sent[1] == ('UPDATE users SET failed_logins = 0, locked_until = NULL '
                                'WHERE id = %s', (7,))
    if 'INSERT' in expected_kinds:
        assert conn.sent[2][1][:3] == (7, None, 'auth.lock_cleared')


def test_sql_list_users_selects_no_secrets_and_is_parameterised():
    conn = Conn(answer=lambda sql: [{**{f: None for f in LIST_USER_FIELDS}, 'id': 3,
                                     'locked': 1}])
    rows = sql_repo(conn).list_users(status='pending_approval', limit=50, after_id=2)
    assert rows[0]['locked'] is True and tuple(rows[0]) == LIST_USER_FIELDS
    (sql, params), = conn.sent
    for hidden in ('password_hash', 'failed_logins', 'email_normalized'):
        assert hidden not in sql
    assert 'status = %s' in sql and 'id > %s' in sql and sql.endswith('ORDER BY u.id LIMIT %s')
    assert params == ('pending_approval', 2, 50)
    sql_repo(conn).list_users()
    assert conn.sent[1][1] == (100,)


def test_sql_resend_state_query():
    conn = Conn(answer=lambda sql: {'recent_count': 2, 'seconds_since_last': 30})
    assert sql_repo(conn).challenge_resend_state(7, 'login', COOLDOWN) == {
        'recent_count': 2, 'seconds_since_last': 30, 'retry_after_seconds': 30}
    (sql, params), = conn.sent
    assert 'TIMESTAMPDIFF(SECOND, MAX(created_at), UTC_TIMESTAMP(6))' in sql
    assert 'created_at > UTC_TIMESTAMP(6) - INTERVAL %s SECOND' in sql
    for hidden in ('code_hmac', 'public_id'):
        assert hidden not in sql
    assert params == (7, 'login', 3600)
    empty = Conn(answer=lambda sql: {'recent_count': 0, 'seconds_since_last': None})
    assert sql_repo(empty).challenge_resend_state(7, 'login', COOLDOWN) == {
        'recent_count': 0, 'seconds_since_last': None, 'retry_after_seconds': 0}


def test_sql_cooldown_is_checked_under_a_row_lock_before_inserting():
    def answer(since):
        return lambda sql: ({'id': 7} if sql.startswith('SELECT id FROM users') else
                            {'recent_count': 1 if since is not None else 0,
                             'seconds_since_last': since})
    conn = Conn(answer=answer(10))
    with pytest.raises(ResendTooSoon) as err:
        sql_repo(conn).create_challenge(7, 'login', HMAC, 300, resend_cooldown_seconds=COOLDOWN)
    assert err.value.retry_after_seconds == 50
    assert kinds(conn) == ['SELECT FOR UPDATE', 'SELECT']          # no INSERT
    assert conn.sent[1][1] == (7, 'login', COOLDOWN) and conn.rollbacks == 1
    ok = Conn(answer=answer(None))
    assert sql_repo(ok).create_challenge(7, 'login', HMAC, 300, resend_cooldown_seconds=COOLDOWN)
    assert kinds(ok) == ['SELECT FOR UPDATE', 'SELECT', 'INSERT'] and ok.commits == 1
    missing = Conn()
    with pytest.raises(InvalidValue, match='does not exist'):
        sql_repo(missing).create_challenge(7, 'login', HMAC, 300, resend_cooldown_seconds=60)


def test_sql_create_challenge_without_cooldown_is_unchanged():
    conn = Conn(answer=lambda sql: {'id': 7})
    sql_repo(conn).create_challenge(7, 'login', HMAC, 300)
    assert kinds(conn) == ['SELECT', 'INSERT'] and conn.sent[0][0].endswith('FOR SHARE')


# ================================================================ both: same results
def test_both_repositories_return_the_same_shapes(repo):
    uid = user(repo)
    mem_attempt = attempt(repo, uid)
    sql_attempt = sql_repo(Conn(answer=user_row())).begin_password_attempt(1, THRESHOLD, LOCKOUT)
    assert mem_attempt == sql_attempt
    assert set(repo.challenge_resend_state(uid, 'login', COOLDOWN)) == set(
        sql_repo(Conn(answer=lambda s: {'recent_count': 0, 'seconds_since_last': None}))
        .challenge_resend_state(1, 'login', COOLDOWN))
    assert tuple(repo.list_users()[0]) == LIST_USER_FIELDS


def test_audit_log_stays_append_only():
    """Phase 2 adds no way to change or remove audit records, in either repository."""
    for cls in (AuthRepository, InMemoryAuthRepository):
        names = [n for n in dir(cls) if 'audit' in n.lower()]
        assert set(names) <= {'write_audit', 'list_audit', '_insert_audit', '_append_audit'}
    import inspect
    source = inspect.getsource(AuthRepository)
    for statement in ('UPDATE audit_log', 'DELETE FROM', 'TRUNCATE', 'DROP ', 'REPLACE INTO',
                      'ON DUPLICATE KEY'):
        assert statement not in source.upper()
