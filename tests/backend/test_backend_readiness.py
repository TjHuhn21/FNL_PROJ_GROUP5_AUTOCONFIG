"""Runtime database readiness (backend/database/health.py, GET /ready and
`migrate check-runtime-connection`). No real database: every connection is a stand-in, and
pymysql.connect itself fails the test if anything tries to open a real one."""
import json
import logging
import os
import subprocess
import sys
from pathlib import Path

import pymysql
import pytest
from fastapi.testclient import TestClient

from backend.app import create_app
from backend.database import health, migrate
from backend.database.errors import BackendDatabaseUnavailable
from backend.database.migrations import ALL_TABLES, MIGRATIONS, TRACKING_TABLE
from backend.settings import parse_settings

ROOT = Path(__file__).resolve().parents[2]
SECRET = 'Runtime-Db-Secret-5531'
M1 = MIGRATIONS[0]


def settings(enabled=True, name='netcommand_test'):
    if not enabled:
        return parse_settings({})
    return parse_settings({'BACKEND_DB_ENABLED': 'true', 'BACKEND_DB_HOST': '127.0.0.1',
                           'BACKEND_DB_PORT': '3307', 'BACKEND_DB_USER': 'netcommand_api',
                           'BACKEND_DB_PASSWORD': SECRET, 'BACKEND_DB_NAME': name,
                           'BACKEND_MIGRATE_USER': 'netcommand_migrator'})


@pytest.fixture(autouse=True)
def no_real_mysql(monkeypatch):
    monkeypatch.setattr(pymysql, 'connect',
                        lambda *a, **k: pytest.fail('tried to open a real MySQL connection'))


class Cursor:
    def __init__(self, conn):
        self.conn, self._rows = conn, []

    def __enter__(self):
        return self

    def __exit__(self, *e):
        return False

    def execute(self, sql, params=()):
        self.conn.sent.append(sql)
        if self.conn.fail_on and self.conn.fail_on in sql:
            raise self.conn.error
        if sql.startswith('SELECT 1'):
            self._rows = list(self.conn.select_one)
        elif 'information_schema.TABLES' in sql:
            self._rows = [{'name': t} for t in sorted(self.conn.tables)]
        elif 'FROM schema_migrations' in sql:
            self._rows = list(self.conn.applied)
        else:
            self._rows = []

    def fetchone(self):
        return self._rows[0] if self._rows else None

    def fetchall(self):
        return list(self._rows)


class Conn:
    """A healthy database by default: migration 1 applied, all tables present."""

    def __init__(self, **kw):
        self.tables = set(ALL_TABLES) | {TRACKING_TABLE, 'devices', 'links'}
        self.applied = [{'version': 1, 'name': M1.name, 'checksum': M1.checksum}]
        self.select_one = [{'ok': 1}]
        self.fail_on, self.error = None, None
        self.sent, self.rollbacks, self.commits, self.closed = [], 0, 0, False
        for k, v in kw.items():
            setattr(self, k, v)

    def cursor(self):
        return Cursor(self)

    def rollback(self):
        self.rollbacks += 1

    def commit(self):
        self.commits += 1

    def close(self):
        self.closed = True


def check(conn):
    return health.check_database(settings(), connect=lambda: conn)


# ---------------------------------------------------------------- the checker
def test_ready_when_connected_and_schema_matches():
    conn = Conn()
    result = check(conn)
    assert result == health.Readiness(True, 'ready') and result.public() == {'status': 'ready'}
    assert conn.sent[0] == 'SELECT 1 AS ok'
    assert all(sql.lstrip().upper().startswith('SELECT') for sql in conn.sent)   # read-only
    assert conn.commits == 0 and conn.rollbacks == 1 and conn.closed


@pytest.mark.parametrize('change', [
    {'tables': set(ALL_TABLES)},                                       # no schema_migrations
    {'applied': []},                                                   # migration 1 missing
    {'applied': [{'version': 1, 'name': M1.name, 'checksum': '0' * 64}]},   # wrong checksum
    {'applied': [{'version': 1, 'name': 'renamed', 'checksum': M1.checksum}]},
    {'applied': [{'version': 1, 'name': M1.name, 'checksum': M1.checksum},
                 {'version': 2, 'name': 'future', 'checksum': 'f' * 64}]},   # unknown version
])
def test_schema_problems_are_not_ready(change):
    conn = Conn(**change)
    result = check(conn)
    assert result == health.Readiness(False, 'schema_not_ready')
    assert result.public() == {'status': 'not_ready', 'reason': 'schema_not_ready'}
    assert conn.closed and conn.commits == 0


@pytest.mark.parametrize('table', sorted(ALL_TABLES))
def test_each_missing_authentication_table_is_detected(table):
    conn = Conn(tables=(set(ALL_TABLES) | {TRACKING_TABLE}) - {table})
    assert check(conn).reason == 'schema_not_ready'


def test_not_configured_never_connects():
    result = health.check_database(settings(enabled=False),
                                   connect=lambda: pytest.fail('connected'))
    assert result == health.Readiness(False, 'database_not_configured')


@pytest.mark.parametrize('error', [
    pymysql.err.OperationalError(2003, f"Can't connect to MySQL server on '127.0.0.1:3307' "
                                       f"(10061) {SECRET}"),                   # refused
    pymysql.err.OperationalError(2003, "Can't connect to MySQL server on '127.0.0.1:3307' "
                                       "(timed out)"),                           # connect timeout
    pymysql.err.OperationalError(1045, "Access denied for user 'netcommand_api'@'127.0.0.1' "
                                       "(using password: YES)"),
])
def test_connection_failures_are_unavailable_through_the_real_connect_path(monkeypatch, error,
                                                                         caplog):
    monkeypatch.setattr(pymysql, 'connect', lambda *a, **k: (_ for _ in ()).throw(error))
    with caplog.at_level(logging.WARNING, logger='backend.database.health'):
        result = health.check_database(settings())          # uses connect_runtime for real
    assert result == health.Readiness(False, 'database_unavailable')
    body = json.dumps(result.public())
    for leak in (SECRET, '127.0.0.1', '3307', 'netcommand_test', 'netcommand_api', 'MySQL server',
                 'Access denied'):
        assert leak not in body
    assert SECRET not in caplog.text and 'Access denied' not in caplog.text
    assert 'database_unavailable' in caplog.text and 'connect failed' in caplog.text


def test_query_timeout_or_lost_connection_is_unavailable():
    conn = Conn(fail_on='information_schema',
                error=pymysql.err.OperationalError(2013, 'Lost connection to MySQL server during '
                                                         'query (timed out)'))
    result = check(conn)
    assert result.reason == 'database_unavailable' and conn.closed


def test_sql_error_is_unavailable_and_says_nothing_about_it(caplog):
    conn = Conn(fail_on='schema_migrations',
                error=pymysql.err.ProgrammingError(1142, f"SELECT command denied to user "
                                                         f"'netcommand_api' {SECRET}"))
    with caplog.at_level(logging.WARNING, logger='backend.database.health'):
        result = check(conn)
    assert result.reason == 'database_unavailable'
    assert SECRET not in caplog.text and 'denied' not in caplog.text
    assert 'MySQL error 1142' in caplog.text


def test_a_failed_connect_function_is_unavailable():
    def refused():
        raise BackendDatabaseUnavailable('Could not connect to the backend database at '
                                         '127.0.0.1:3307/netcommand_test (MySQL error 2003).')
    result = health.check_database(settings(), connect=refused)
    assert result.public() == {'status': 'not_ready', 'reason': 'database_unavailable'}


@pytest.mark.parametrize('rows', [[], [{'ok': 0}], [{'ok': '1'}], [{'other': 1}]])
def test_unexpected_select_1_result_is_unavailable(rows):
    conn = Conn(select_one=rows)
    result = check(conn)
    assert result == health.Readiness(False, 'database_unavailable')
    assert conn.sent == ['SELECT 1 AS ok']          # stopped before the schema checks
    assert conn.closed and conn.commits == 0


class RollbackFails(Conn):
    def rollback(self):
        self.rollbacks += 1
        raise pymysql.err.OperationalError(2013, 'Lost connection to MySQL server')


@pytest.mark.parametrize('change, reason', [
    ({}, 'ready'),
    ({'applied': []}, 'schema_not_ready'),
    ({'fail_on': 'information_schema',
      'error': pymysql.err.OperationalError(2013, 'Lost connection')}, 'database_unavailable'),
])
def test_connection_is_closed_even_when_rollback_raises(change, reason):
    conn = RollbackFails(**change)
    result = check(conn)                             # does not raise
    assert result.reason == reason
    assert conn.rollbacks == 1 and conn.closed


def test_uppercase_table_names_from_mysql_are_recognised():
    """information_schema may report names in upper case (lower_case_table_names=0 with
    tables created that way, or some platforms)."""
    conn = Conn(tables={t.upper() for t in set(ALL_TABLES) | {TRACKING_TABLE}})
    assert check(conn) == health.Readiness(True, 'ready')


def test_the_checker_never_writes_or_migrates():
    source = (ROOT / 'backend' / 'database' / 'health.py').read_text(encoding='utf-8')
    sql_lines = [l for l in source.splitlines() if 'cur.execute(' in l]
    assert sql_lines and all("cur.execute('SELECT" in l for l in sql_lines)
    for word in ('INSERT', 'UPDATE ', 'DELETE', 'CREATE', 'DROP', 'ALTER', 'commit(',
                 'MigrationRunner', '.up('):
        assert word not in source.replace('rollback()', '')


# ---------------------------------------------------------------- GET /ready
def client(monkeypatch, conn=None, failure=None, enabled=True):
    def connect(_settings):
        if failure:
            raise failure
        return conn
    monkeypatch.setattr(health, 'connect_runtime', connect)
    return TestClient(create_app(settings(enabled)))


def test_ready_endpoint_200(monkeypatch):
    r = client(monkeypatch, conn=Conn()).get('/ready')
    assert r.status_code == 200 and r.json() == {'status': 'ready'}
    assert r.headers['cache-control'] == 'no-store'


@pytest.mark.parametrize('conn, failure, reason', [
    (None, BackendDatabaseUnavailable(f'Could not connect to 127.0.0.1:3307 {SECRET}'),
     'database_unavailable'),
    (Conn(applied=[]), None, 'schema_not_ready'),
])
def test_ready_endpoint_503_with_a_generic_body(monkeypatch, conn, failure, reason):
    r = client(monkeypatch, conn=conn, failure=failure).get('/ready')
    assert r.status_code == 503 and r.json() == {'status': 'not_ready', 'reason': reason}
    for leak in (SECRET, '127.0.0.1', '3307', 'netcommand'):
        assert leak not in r.text


def test_ready_endpoint_without_database_settings_is_503(monkeypatch):
    r = client(monkeypatch, conn=Conn(), enabled=False).get('/ready')
    assert r.status_code == 503 and r.json()['reason'] == 'database_not_configured'


def test_app_factory_serves_ready(monkeypatch, tmp_path):
    """app_factory() (used by `uvicorn --factory`) loads settings from the environment and
    /ready works through it. Process-wide logging setup is recorded, not applied, so the
    rest of the test session keeps its own logging."""
    from backend import app as app_module
    for name in list(os.environ):
        if name.startswith('BACKEND_'):
            monkeypatch.delenv(name)
    monkeypatch.setenv('NETCOMMAND_BACKEND_ENV_FILE', str(tmp_path / 'no-such.env'))
    for name, value in {'BACKEND_DB_ENABLED': 'true', 'BACKEND_DB_HOST': '127.0.0.1',
                        'BACKEND_DB_PORT': '3307', 'BACKEND_DB_USER': 'netcommand_api',
                        'BACKEND_DB_PASSWORD': SECRET, 'BACKEND_DB_NAME': 'netcommand_test',
                        'BACKEND_MIGRATE_USER': 'netcommand_migrator'}.items():
        monkeypatch.setenv(name, value)
    logging_setup, used = [], []
    monkeypatch.setattr(app_module, 'configure_logging', logging_setup.append)
    monkeypatch.setattr(health, 'connect_runtime', lambda s: used.append(s) or Conn())

    app = app_module.app_factory()
    assert [s.database.user for s in logging_setup] == ['netcommand_api']
    assert used == []                                # building the app connects to nothing
    r = TestClient(app).get('/ready')
    assert r.status_code == 200 and r.json() == {'status': 'ready'}
    assert [(s.database.user, s.database.name) for s in used] == [('netcommand_api',
                                                                   'netcommand_test')]


def test_a_1045_refusal_leaks_nothing_into_logs_or_response(monkeypatch, caplog):
    """Through the real connect path (connection.connect -> translate) and GET /ready:
    neither the log nor the response names the host, port, account, database, password or
    the driver's message; the log keeps only the reason, error class and MySQL code."""
    driver_message = ("Access denied for user 'netcommand_api'@'127.0.0.1' "
                      "(using password: YES)")
    monkeypatch.setattr(pymysql, 'connect', lambda *a, **k: (_ for _ in ()).throw(
        pymysql.err.OperationalError(1045, driver_message)))
    with caplog.at_level(logging.DEBUG):             # every logger, every level
        r = TestClient(create_app(settings())).get('/ready')
    assert r.status_code == 503
    assert r.json() == {'status': 'not_ready', 'reason': 'database_unavailable'}
    logged = caplog.text + ''.join(str(rec.exc_info) for rec in caplog.records)
    for leak in (SECRET, '127.0.0.1', '3307', 'netcommand_api', 'netcommand_test',
                 driver_message, 'Access denied', 'using password', 'refused the account'):
        assert leak not in logged and leak not in r.text
    assert any(rec.name == 'backend.database.health' and 'MySQL error 1045' in rec.getMessage()
               for rec in caplog.records)


def test_creating_the_app_does_not_connect_until_ready_is_requested(monkeypatch):
    calls = []

    def counting_connect(*a, **k):
        calls.append(1)
        raise pymysql.err.OperationalError(2003, "Can't connect to MySQL server")
    monkeypatch.setattr(pymysql, 'connect', counting_connect)

    app = create_app(settings())                     # database support enabled
    with TestClient(app) as c:                       # runs startup/lifespan as well
        assert calls == []
        assert c.get('/health').status_code == 200
        assert c.get('/docs').status_code == 200
        assert calls == []                           # nothing but /ready connects
        assert c.get('/ready').status_code == 503
        assert len(calls) == 1
    assert len(calls) == 1                           # nor does shutdown


def test_health_stays_liveness_only_even_with_a_database_configured():
    """In a fresh interpreter with database settings enabled: create the app and call
    /health; no database module and no PyMySQL are ever loaded."""
    code = ('import json, sys\n'
            'from fastapi.testclient import TestClient\n'
            'from backend.app import create_app\n'
            'from backend.settings import parse_settings\n'
            's = parse_settings({"BACKEND_DB_ENABLED": "true", "BACKEND_DB_HOST": "127.0.0.1",'
            ' "BACKEND_DB_PORT": "3307", "BACKEND_DB_USER": "u", "BACKEND_DB_PASSWORD": "p",'
            ' "BACKEND_DB_NAME": "netcommand_test"})\n'
            'r = TestClient(create_app(s)).get("/health")\n'
            'print(json.dumps({"status": r.status_code, "body": r.json(), "loaded": sorted('
            'm for m in sys.modules if m.startswith("backend.database") or m == "pymysql")}))\n')
    env = {k: v for k, v in os.environ.items() if not k.startswith('BACKEND_')}
    env['NETCOMMAND_BACKEND_ENV_FILE'] = str(ROOT / 'tests' / 'backend' / 'no-such.env')
    out = subprocess.run([sys.executable, '-c', code], cwd=ROOT, env=env, capture_output=True,
                         text=True, timeout=120)
    assert out.returncode == 0, out.stderr
    assert json.loads(out.stdout.strip().splitlines()[-1]) == {
        'status': 200, 'body': {'status': 'ok'}, 'loaded': []}


# ---------------------------------------------------------------- the CLI command
def run_cli(args, s):
    out = []
    code = migrate.main(args, settings=s, out=out.append)
    return code, '\n'.join(out)


def test_cli_ready(monkeypatch):
    monkeypatch.setattr(health, 'connect_runtime', lambda s: Conn())
    code, text = run_cli(['check-runtime-connection'], settings())
    assert code == 0 and 'Runtime account netcommand_api on netcommand_test: READY' in text
    assert SECRET not in text


def test_cli_not_ready_exit_6(monkeypatch):
    monkeypatch.setattr(health, 'connect_runtime', lambda s: Conn(applied=[]))
    code, text = run_cli(['check-runtime-connection'], settings())
    assert code == 6 and 'NOT READY (schema_not_ready)' in text and 'nothing was changed' in text


def test_cli_refuses_unapproved_databases_before_connecting(monkeypatch):
    monkeypatch.setattr(health, 'connect_runtime', lambda s: pytest.fail('connected'))
    for name in ('netcommand', 'production'):
        code, text = run_cli(['check-runtime-connection'], settings(name=name))
        assert code == 2 and 'Migration refused' in text


def test_cli_uses_the_runtime_account(monkeypatch):
    seen = []
    from backend.database import connection
    monkeypatch.setattr(connection, 'connect', lambda *a: seen.append(a) or Conn())
    code, _ = run_cli(['check-runtime-connection'], settings())
    assert code == 0
    assert seen == [('127.0.0.1', 3307, 'netcommand_api', SECRET, 'netcommand_test')]
