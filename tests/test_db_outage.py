"""Phase 3C-4: the database becoming unavailable (store layer, monitor, startup).

* db.py turns driver errors into DatabaseUnavailable (connection) or DatabaseError (the
  server refused one statement), with our own messages: never a password, an encrypted
  login, the key, or the SQL values. Validation errors stay ValueErrors.
* After a connection failure every call fails at once for RETRY_AFTER seconds (no
  repeated 5-second waits); ping() always tries for real and clears it.
* A connection lost while COMMITTING is reported as 'uncertain' (it may have been saved).
* The monitor reports a failure streak once and never records anything during it.
* Startup fallback to sample mode says why; --demo does not touch the database.

pymysql.connect is replaced in EVERY test here: no MySQL server is ever contacted.
"""
import os
import sys
import threading
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

import pymysql
import pytest
from cryptography.fernet import Fernet

import db
import db_fake
import security
from monitor import monitor
from store_errors import (DATABASE_ERRORS, DatabaseError, DatabaseUnavailable,
                          DeletedDeviceExists, outcome_text)

DB_SECRET = 'Db-Pa55word-Marker-7731'          # stands in for DB_PASSWORD
LOGIN_SECRET = 'Login-Pa55word-Marker-4410'     # a device login password


def lost(code=2013):
    return pymysql.err.OperationalError(code, 'Lost connection to MySQL server during query')


@pytest.fixture(autouse=True)
def no_mysql(monkeypatch, tmp_path):
    """Every test: no real connection possible, a temporary key, a clean outage state."""
    def refuse(**kwargs):
        raise AssertionError('a test tried to open a real MySQL connection')
    monkeypatch.setattr(pymysql, 'connect', refuse)
    monkeypatch.setattr(security, 'ENV_PATH', str(tmp_path / '.env'))
    monkeypatch.setenv('FERNET_KEY', Fernet.generate_key().decode())
    monkeypatch.setenv('DB_PASSWORD', DB_SECRET)
    monkeypatch.setenv('DB_HOST', '127.0.0.1')
    monkeypatch.setenv('DB_PORT', '3307')
    monkeypatch.setattr(db, 'load_dotenv', lambda *a, **k: None)   # never read the real .env
    db._mark_up()
    yield
    db._mark_up()


class Cursor:
    def __init__(self, conn):
        self.conn = conn
        self.lastrowid, self.rowcount, self._row = 1, 1, None

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False

    def execute(self, sql, params=()):
        self.conn.statements.append((sql, params))
        n = len(self.conn.statements)
        if self.conn.fail_at == n:
            raise self.conn.error
        key = 'NAME' if 'LOWER(name)' in sql else sql.split()[0]   # 3C-5 name check
        self._row = self.conn.rows.get(key, None)

    def executemany(self, sql, params):
        self.execute(sql, params)

    def fetchone(self):
        return self._row

    def fetchall(self):
        return [self._row] if self._row else []


class Conn:
    """Stands in for a PyMySQL connection: fail_at = the statement number that raises
    error; commit_error raises on commit()."""

    def __init__(self, fail_at=None, error=None, commit_error=None, rows=None):
        self.fail_at, self.error, self.commit_error = fail_at, error, commit_error
        self.rows = rows or {}
        self.statements, self.committed, self.rolled_back, self.closed = [], False, False, False

    def cursor(self):
        return Cursor(self)

    def commit(self):
        if self.commit_error:
            raise self.commit_error
        self.committed = True

    def rollback(self):
        self.rolled_back = True
        if self.error is not None and isinstance(self.error, pymysql.err.OperationalError):
            raise lost(2006)                     # a dead connection cannot roll back either

    def close(self):
        self.closed = True


def connect_with(monkeypatch, conn):
    calls = []

    def fake_connect(**kwargs):
        calls.append(kwargs)
        return conn
    monkeypatch.setattr(pymysql, 'connect', fake_connect)
    return calls


def connect_failing(monkeypatch, error):
    calls = []

    def fake_connect(**kwargs):
        calls.append(kwargs)
        raise error
    monkeypatch.setattr(pymysql, 'connect', fake_connect)
    return calls


def assert_safe(message):
    for secret in (DB_SECRET, LOGIN_SECRET, os.environ['FERNET_KEY']):
        assert secret not in message
    assert 'gAAAA' not in message                # no Fernet token either


# ---------------------------------------------------------------- the error types
def test_database_errors_are_not_validation_errors():
    assert not issubclass(DatabaseUnavailable, ValueError)
    assert not issubclass(DatabaseError, ValueError)
    assert issubclass(DeletedDeviceExists, ValueError)            # unchanged
    assert set(DATABASE_ERRORS) == {DatabaseUnavailable, DatabaseError}


def test_outcome_text_is_honest_about_a_lost_commit():
    assert outcome_text(DatabaseUnavailable('x')) == 'Nothing was saved.'
    assert outcome_text(DatabaseError('x'), 'Nothing was deleted.') == 'Nothing was deleted.'
    assert outcome_text(ValueError('x')) == 'Nothing was saved.'
    assert 'may or may not have been saved' in outcome_text(DatabaseUnavailable('x', uncertain=True))


# ---------------------------------------------------------------- connecting
def test_connection_refused_is_database_unavailable(monkeypatch):
    connect_failing(monkeypatch, pymysql.err.OperationalError(
        2003, f"Can't connect to MySQL server on '127.0.0.1' ([WinError 10061]) {DB_SECRET}"))
    with pytest.raises(DatabaseUnavailable) as err:
        db.get_conn()
    msg = str(err.value)
    assert err.value.code == 2003 and not err.value.uncertain
    assert '127.0.0.1:3307' in msg and 'MySQL error 2003' in msg and 'running' in msg
    assert 'WinError' not in msg                  # our own text, not the driver's
    assert_safe(msg)
    assert err.value.__suppress_context__         # the driver error is not chained into it
    assert db.is_marked_down()


def test_access_denied_gives_advice_without_the_password(monkeypatch):
    connect_failing(monkeypatch, pymysql.err.OperationalError(
        1045, "Access denied for user 'netcommand_app'@'localhost' (using password: YES)"))
    with pytest.raises(DatabaseUnavailable) as err:
        db.get_conn()
    msg = str(err.value)
    assert 'DB_USER and DB_PASSWORD' in msg and 'netcommand_app' not in msg
    assert_safe(msg)


def test_network_level_errors_are_unavailable(monkeypatch):
    connect_failing(monkeypatch, ConnectionRefusedError(10061, 'refused'))
    with pytest.raises(DatabaseUnavailable):
        db.get_conn()


def test_connection_uses_finite_timeouts(monkeypatch):
    calls = connect_with(monkeypatch, Conn())
    db.get_conn().close()
    kw = calls[0]
    assert kw['connect_timeout'] == db.CONNECT_TIMEOUT
    assert kw['read_timeout'] == db.IO_TIMEOUT and kw['write_timeout'] == db.IO_TIMEOUT


def test_fail_fast_during_an_outage_then_tries_again(monkeypatch):
    calls = connect_failing(monkeypatch, lost(2003))
    with pytest.raises(DatabaseUnavailable):
        db.get_conn()
    started = time.monotonic()
    for _ in range(5):                           # all fail at once: no new connection attempt
        with pytest.raises(DatabaseUnavailable):
            db.get_devices()
    assert len(calls) == 1 and time.monotonic() - started < 1
    monkeypatch.setattr(db, 'RETRY_AFTER', 0.0)  # the window is over: a real attempt again
    conn = Conn()
    connect_with(monkeypatch, conn)
    assert db.get_conn() is conn and not db.is_marked_down()


def test_ping_ignores_the_window_and_clears_it(monkeypatch):
    connect_failing(monkeypatch, lost(2003))
    with pytest.raises(DatabaseUnavailable):
        db.ping()
    assert db.is_marked_down()
    conn = Conn(rows={'SELECT': {'1': 1}})
    connect_with(monkeypatch, conn)
    assert db.ping() is True
    assert not db.is_marked_down() and conn.statements == [('SELECT 1', ())] and conn.closed


def test_ping_reports_a_lost_connection(monkeypatch):
    connect_with(monkeypatch, Conn(fail_at=1, error=lost(2013)))
    with pytest.raises(DatabaseUnavailable):
        db.ping()


# ---------------------------------------------------------------- one statement (_run)
def test_sql_error_is_database_error_and_not_an_outage(monkeypatch):
    conn = Conn(fail_at=1, error=pymysql.err.ProgrammingError(
        1064, f"You have an error in your SQL syntax near '{LOGIN_SECRET}'"))
    connect_with(monkeypatch, conn)
    with pytest.raises(DatabaseError) as err:
        db.get_devices()
    msg = str(err.value)
    assert err.value.code == 1064 and 'MySQL error 1064' in msg and 'syntax' not in msg
    assert_safe(msg)
    assert not isinstance(err.value, DatabaseUnavailable)
    assert not db.is_marked_down() and conn.closed


def test_integrity_error_is_database_error(monkeypatch):
    connect_with(monkeypatch, Conn(fail_at=1, error=pymysql.err.IntegrityError(
        1062, "Duplicate entry '10.0.0.1' for key 'ip'")))
    with pytest.raises(DatabaseError) as err:
        db.add_log(1, 'Configuration', 'success', 'x')
    assert '10.0.0.1' not in str(err.value)


def test_lost_during_a_read_is_unavailable_and_certain(monkeypatch):
    conn = Conn(fail_at=1, error=lost(2013))
    connect_with(monkeypatch, conn)
    with pytest.raises(DatabaseUnavailable) as err:
        db.count_devices()
    assert not err.value.uncertain and db.is_marked_down() and conn.closed


@pytest.mark.parametrize('code', [2006, 2013, 2055])
def test_lost_before_commit_means_nothing_saved(monkeypatch, code):
    connect_with(monkeypatch, Conn(fail_at=1, error=lost(code)))
    with pytest.raises(DatabaseUnavailable) as err:
        db.delete_device(5)
    assert not err.value.uncertain and outcome_text(err.value) == 'Nothing was saved.'


def test_lost_during_commit_is_uncertain(monkeypatch):
    conn = Conn(commit_error=lost(2013))
    connect_with(monkeypatch, conn)
    with pytest.raises(DatabaseUnavailable) as err:
        db.set_status(5, 'down')
    assert err.value.uncertain


def test_interface_error_is_unavailable(monkeypatch):
    connect_with(monkeypatch, Conn(fail_at=1, error=pymysql.err.InterfaceError(0, '')))
    with pytest.raises(DatabaseUnavailable):
        db.get_logs()


def test_non_driver_errors_are_not_translated(monkeypatch):
    connect_with(monkeypatch, Conn(fail_at=1, error=RuntimeError('a bug')))
    with pytest.raises(RuntimeError):
        db.get_devices()
    assert not db.is_marked_down()


def test_a_failed_close_does_not_hide_the_result(monkeypatch):
    conn = Conn(rows={'SELECT': {'n': 4}})
    conn.close = lambda: (_ for _ in ()).throw(pymysql.err.Error('Already closed'))
    connect_with(monkeypatch, conn)
    assert db.count_devices() == 4


# ---------------------------------------------------------------- transactions
def dev(ip='10.9.0.1'):
    return {'name': 'SW1', 'ip': ip, 'mac': '', 'type': 'switch', 'managed': True,
            'status': 'up'}


@pytest.mark.parametrize('step', [1, 2, 3])
def test_save_device_lost_mid_transaction_rolls_back(monkeypatch, step):
    conn = Conn(fail_at=step, error=lost(2013))
    connect_with(monkeypatch, conn)
    with pytest.raises(DatabaseUnavailable) as err:
        db.save_device(None, dev(), 'admin', LOGIN_SECRET)
    assert not conn.committed and conn.rolled_back and conn.closed
    assert not err.value.uncertain and outcome_text(err.value) == 'Nothing was saved.'
    assert_safe(str(err.value))
    assert db.is_marked_down()


def test_save_device_lost_during_commit_is_uncertain(monkeypatch):
    conn = Conn(commit_error=lost(2013))
    connect_with(monkeypatch, conn)
    with pytest.raises(DatabaseUnavailable) as err:
        db.save_device(None, dev(), 'admin', LOGIN_SECRET)
    assert err.value.uncertain and 'may or may not' in outcome_text(err.value)
    assert_safe(str(err.value))


def test_save_device_sql_error_is_database_error(monkeypatch):
    conn = Conn(fail_at=2, error=pymysql.err.DataError(1406, f"Data too long '{LOGIN_SECRET}'"))
    connect_with(monkeypatch, conn)
    with pytest.raises(DatabaseError) as err:
        db.save_device(None, dev(), 'admin', LOGIN_SECRET)
    assert conn.rolled_back and not conn.committed and not db.is_marked_down()
    assert_safe(str(err.value))


def test_save_device_validation_is_still_a_value_error_before_connecting(monkeypatch):
    calls = connect_with(monkeypatch, Conn())
    with pytest.raises(ValueError) as err:
        db.save_device(None, dev(), 'admin', '')
    assert not isinstance(err.value, DATABASE_ERRORS) and calls == []


def test_save_device_during_outage_fails_at_once_without_connecting(monkeypatch):
    connect_failing(monkeypatch, lost(2003))
    with pytest.raises(DatabaseUnavailable):
        db.get_conn()
    calls = connect_with(monkeypatch, Conn())
    with pytest.raises(DatabaseUnavailable):
        db.save_device(None, dev(), 'admin', LOGIN_SECRET)
    with pytest.raises(DatabaseUnavailable):
        db.restore_device(3, dev(), credentials='keep')
    with pytest.raises(DatabaseUnavailable):
        db.delete_device(3)
    assert calls == []


def test_deleted_device_check_still_raises_its_own_error(monkeypatch):
    conn = Conn(rows={'SELECT': {'id': 9, 'name': 'OLD', 'ip': '10.9.0.1', 'type': 'switch',
                                 'has_login': 1}})
    connect_with(monkeypatch, conn)
    with pytest.raises(DeletedDeviceExists):
        db.save_device(None, dev())
    assert conn.rolled_back and not conn.committed


@pytest.mark.parametrize('step', [1, 2])
def test_restore_device_lost_mid_transaction_rolls_back(monkeypatch, step):
    conn = Conn(fail_at=step, error=lost(2013),
                rows={'SELECT': {'id': 3, 'name': 'SW1', 'ip': '10.9.0.1', 'is_deleted': 1}})
    connect_with(monkeypatch, conn)
    with pytest.raises(DatabaseUnavailable) as err:
        db.restore_device(3, dev(), credentials='replace', username='admin',
                          password=LOGIN_SECRET)
    assert conn.rolled_back and not conn.committed and not err.value.uncertain
    assert_safe(str(err.value))


def test_restore_device_lost_during_commit_is_uncertain(monkeypatch):
    conn = Conn(commit_error=lost(2013),
                rows={'SELECT': {'id': 3, 'name': 'SW1', 'ip': '10.9.0.1', 'is_deleted': 1}})
    connect_with(monkeypatch, conn)
    with pytest.raises(DatabaseUnavailable) as err:
        db.restore_device(3, dev(), credentials='keep')
    assert err.value.uncertain


def test_fail_fast_state_is_thread_safe(monkeypatch):
    connect_failing(monkeypatch, lost(2003))
    errors = []

    def worker():
        for _ in range(50):
            try:
                db.get_devices()
            except DatabaseUnavailable:
                pass
            except Exception as err:             # anything else would be a bug
                errors.append(err)
    threads = [threading.Thread(target=worker) for _ in range(4)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert errors == [] and db.is_marked_down()


def test_sample_store_has_the_same_ping():
    assert db_fake.ping() is True


# ---------------------------------------------------------------- monitoring
class FlakyStore:
    """db_fake with a switchable outage; records every write."""

    def __init__(self):
        self.down, self.writes = False, []

    def get_devices(self, *a):
        if self.down:
            raise DatabaseUnavailable('The database at test is not available.')
        return db_fake.get_devices(*a)

    def set_status(self, *a):
        if self.down:
            raise DatabaseUnavailable('x')
        self.writes.append(('set_status', a))
        db_fake.set_status(*a)

    def add_event(self, *a):
        if self.down:
            raise DatabaseUnavailable('x')
        self.writes.append(('add_event', a))
        db_fake.add_event(*a)


def wait_for(cond, timeout=5):
    end = time.time() + timeout
    while time.time() < end:
        if cond():
            return True
        time.sleep(0.01)
    return False


def test_monitor_reports_an_outage_once_and_records_nothing():
    db_fake.reset()
    db_fake.upsert_device({'name': 'SW1', 'ip': '10.0.0.1', 'type': 'switch', 'managed': True})
    store, reported = FlakyStore(), []
    store.down = True
    up = {'value': False}
    stop = monitor.start_monitor(store, interval=0.02, check=lambda ip: up['value'],
                                 on_error=reported.append)
    try:
        time.sleep(0.3)                           # many failed rounds...
        assert len(reported) == 1 and isinstance(reported[0], DatabaseUnavailable)  # ...one report
        assert store.writes == [] and db_fake.get_events() == []
        store.down = False                        # back: the monitor carries on by itself
        assert wait_for(lambda: db_fake.get_device(1)['status'] == 'down')
        store.down = True                         # a new outage is reported again
        assert wait_for(lambda: len(reported) == 2)
    finally:
        stop.set()


def test_monitor_survives_a_failing_error_callback():
    store = FlakyStore()
    store.down = True
    calls = []

    def bad(err):
        calls.append(err)
        raise RuntimeError('callback bug')
    stop = monitor.start_monitor(store, interval=0.02, on_error=bad)
    try:
        time.sleep(0.15)
        store.down = False
        time.sleep(0.1)
        store.down = True
        assert wait_for(lambda: len(calls) == 2)  # still running after the callback failed
    finally:
        stop.set()


# ---------------------------------------------------------------- startup
def test_startup_fallback_says_why(monkeypatch):
    import main
    monkeypatch.setattr(db, 'ping', lambda: (_ for _ in ()).throw(
        DatabaseUnavailable('The database at 127.0.0.1:3307 is not available (MySQL error 2003).')))
    store, demo, problem = main.choose_store()
    assert store is db_fake and demo is True
    assert 'MySQL error 2003' in problem
    assert_safe(problem)


def test_startup_with_the_database(monkeypatch):
    import main
    monkeypatch.setattr(db, 'ping', lambda: True)
    assert main.choose_store() == (db, False, None)


def test_explicit_demo_never_touches_the_database(monkeypatch):
    import main
    monkeypatch.setattr(db, 'ping', lambda: pytest.fail('--demo must not connect'))
    assert main.choose_store(force_demo=True) == (db_fake, True, None)


def test_startup_unexpected_error_shows_only_its_type(monkeypatch):
    import main
    monkeypatch.setattr(db, 'ping', lambda: (_ for _ in ()).throw(KeyError(DB_SECRET)))
    store, demo, problem = main.choose_store()
    assert store is db_fake and problem == 'KeyError while connecting.'
