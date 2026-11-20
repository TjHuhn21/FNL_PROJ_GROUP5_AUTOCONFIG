"""The MySQL test guard (tests/mysql_guard.py): the tests that wipe tables may only run
on a separate database whose name ends in '_test', set explicitly in the shell.

Nothing here connects to MySQL: pymysql.connect and db.get_conn are replaced by
recorders, and the guard must refuse BEFORE either is called.
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))
sys.path.insert(0, os.path.dirname(__file__))

import pymysql
import pytest

import db
import mysql_guard


@pytest.fixture
def connections(monkeypatch):
    """Records every attempt to connect; a real connection is impossible."""
    attempts = []

    def refuse(*a, **k):
        attempts.append('pymysql.connect')
        raise AssertionError('tried to connect to MySQL')
    monkeypatch.setattr(pymysql, 'connect', refuse)
    monkeypatch.setattr(db, 'get_conn', lambda *a, **k: attempts.append('db.get_conn')
                        or pytest.fail('db.get_conn was called'))
    return attempts


def shell(monkeypatch, name):
    """As if pytest had been started in a shell with DB_NAME=name (None: not set)."""
    monkeypatch.setattr(mysql_guard, 'PROCESS_DB_NAME', name)
    if name is None:
        monkeypatch.delenv('DB_NAME', raising=False)
    else:
        monkeypatch.setenv('DB_NAME', name)


# ---------------------------------------------------------------- the rule
@pytest.mark.parametrize('name', ['netcommand_test', 'NetCommand_TEST', 'lab_test',
                                  'netcommand_ci_test'])
def test_test_databases_are_accepted(monkeypatch, name):
    shell(monkeypatch, name)
    assert mysql_guard.problem_with(name) is None
    assert mysql_guard.require_test_database() == name


@pytest.mark.parametrize('name', ['netcommand', 'NETCOMMAND', 'NetCommand'])
def test_the_main_database_is_always_refused(monkeypatch, name):
    shell(monkeypatch, name)
    with pytest.raises(mysql_guard.UnsafeTestDatabase) as err:
        mysql_guard.require_test_database()
    assert 'main NetCommand database' in str(err.value)
    assert 'separate test database' in str(err.value)
    assert 'No connection was opened and nothing was deleted' in str(err.value)


@pytest.mark.parametrize('name', [None, ''])
def test_a_missing_db_name_is_refused(monkeypatch, name):
    shell(monkeypatch, name)
    with pytest.raises(mysql_guard.UnsafeTestDatabase) as err:
        mysql_guard.require_test_database()
    assert 'DB_NAME is not set' in str(err.value)


@pytest.mark.parametrize('name', ['production', 'netcommand_prod', 'test', 'testing',
                                  'netcommand_testing', 'test_netcommand', '_test',
                                  'netcommand-test', ' netcommand_test', 'net command_test'])
def test_other_names_are_refused(monkeypatch, name):
    shell(monkeypatch, name)
    with pytest.raises(mysql_guard.UnsafeTestDatabase):
        mysql_guard.require_test_database()


def test_a_value_filled_in_from_env_file_is_not_trusted(monkeypatch):
    """DB_NAME missing in the shell, but present in os.environ afterwards (as db.py's
    load_dotenv() would put it there from .env): refused."""
    monkeypatch.setattr(mysql_guard, 'PROCESS_DB_NAME', None)
    monkeypatch.setenv('DB_NAME', 'netcommand_test')
    with pytest.raises(mysql_guard.UnsafeTestDatabase) as err:
        mysql_guard.require_test_database()
    assert 'not set in this shell' in str(err.value)


def test_a_name_changed_after_start_is_refused(monkeypatch):
    monkeypatch.setattr(mysql_guard, 'PROCESS_DB_NAME', 'netcommand_test')
    monkeypatch.setenv('DB_NAME', 'netcommand')
    with pytest.raises(mysql_guard.UnsafeTestDatabase) as err:
        mysql_guard.require_test_database()
    assert 'changed after the tests started' in str(err.value)


def test_the_shell_value_is_recorded_before_db_is_imported():
    """tests/conftest.py imports the guard first: it was loaded before db.py.
    (Read by path: `import conftest` could find another folder's conftest.py.)"""
    path = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'conftest.py')
    source = open(path, encoding='utf-8').read()
    assert 'import mysql_guard' in source and 'import db' not in source
    assert 'mysql_guard' in sys.modules


# ---------------------------------------------------------------- refused before connecting
@pytest.mark.parametrize('name', ['netcommand', None, 'production'])
def test_integration_test_stops_before_connecting(monkeypatch, connections, name):
    tk = pytest.importorskip('tkinter')
    import test_integration_mysql
    shell(monkeypatch, name)
    with pytest.raises(pytest.fail.Exception) as err:
        test_integration_mysql.test_scan_register_review_configure_on_mysql(monkeypatch)
    assert 'separate test database' in str(err.value)
    assert connections == []                      # no connection, so no DELETE either


@pytest.mark.parametrize('name', ['netcommand', None, 'production'])
def test_store_contract_mysql_stops_before_connecting(monkeypatch, connections, name):
    import test_store_contract
    shell(monkeypatch, name)
    with pytest.raises(pytest.fail.Exception) as err:
        test_store_contract.mysql_store(monkeypatch)
    assert 'separate test database' in str(err.value)
    assert connections == []


def test_store_contract_mysql_goes_ahead_on_a_test_database(monkeypatch):
    """Accepted name: the guard lets it through to the (stand-in) connection, and only
    then are the tables emptied."""
    import test_store_contract
    shell(monkeypatch, 'netcommand_test')
    sent = []

    class Cur:
        def __enter__(self):
            return self

        def __exit__(self, *e):
            return False

        def execute(self, sql, params=()):
            sent.append(sql)

    class Conn:
        def cursor(self):
            return Cur()

        def commit(self):
            sent.append('COMMIT')

        def close(self):
            pass
    monkeypatch.setattr(db, 'get_conn', lambda *a, **k: Conn())
    assert test_store_contract.mysql_store(monkeypatch) is db
    assert sent[0] == 'SET FOREIGN_KEY_CHECKS = 0' and 'DELETE FROM devices' in sent


# ---------------------------------------------------------------- ordinary runs
def test_without_the_flag_only_the_in_memory_store_is_tested():
    if os.getenv('NETCOMMAND_TEST_DB'):
        pytest.skip('this run was started with NETCOMMAND_TEST_DB set')
    import test_store_contract
    assert test_store_contract.stores == ['fake']
