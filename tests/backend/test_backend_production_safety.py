"""Production database safety (backend/database/production.py) in the operator tools.

Fully offline: pymysql.connect fails the test, every connection is a fake that records
what it is sent, and settings are built in memory. Every value is test-only; the server
UUIDs are made up."""
from types import SimpleNamespace

import pymysql
import pytest

from backend.database import migrate, production
from backend.database.errors import MigrationError
from backend.settings import DatabaseSettings, Secret, Settings, classify_database, \
    valid_server_uuid

DB_SECRET = 'Test-only-db-password-555'
MIGRATE_SECRET = 'Test-only-migrate-password-556'
UUID = '3e11fa47-71ca-11e1-9e33-c80aa9429562'
OTHER_UUID = '00000000-1111-2222-3333-444444444444'
PROD = 'netcommand_backend'
FULL = ['--production', '--authorize-database', PROD, '--confirm-database', PROD]


@pytest.fixture(autouse=True)
def no_real_mysql(monkeypatch):
    monkeypatch.setattr(pymysql, 'connect',
                        lambda *a, **k: pytest.fail('tried to open a real MySQL connection'))


def make_settings(name=PROD, environment='production', server_uuid=UUID):
    return Settings(environment=environment,
                    database=DatabaseSettings(host='127.0.0.1', port=3307, user='netcommand_api',
                                              password=Secret(DB_SECRET), name=name,
                                              server_uuid=server_uuid),
                    migrate_user='netcommand_migrator',
                    migrate_password=Secret(MIGRATE_SECRET))


class Cursor:
    def __init__(self, conn):
        self.conn, self._row = conn, None

    def __enter__(self):
        return self

    def __exit__(self, *e):
        return False

    def execute(self, sql, params=()):
        self.conn.sent.append(sql)
        if sql == production.IDENTITY_SQL:
            self._row = {'db': self.conn.db, 'server_uuid': self.conn.uuid}

    def fetchone(self):
        return self._row


class Conn:
    def __init__(self, db=PROD, uuid=UUID):
        self.db, self.uuid, self.sent, self.closed = db, uuid, [], False

    def cursor(self):
        return Cursor(self)

    def close(self):
        self.closed = True


class Schema:
    """Stands in for MySQLSchema: the identity query goes through .conn; anything else
    the tool might do is recorded so tests can prove it never happened."""

    def __init__(self, conn):
        self.conn, self.calls = conn, []

    def grants(self):
        self.calls.append('grants')
        return []


class Runner:
    """Stands in for MigrationRunner; records what it was asked to do."""
    calls = []

    def __init__(self, schema, log=None):
        Runner.calls.append(('created', len(schema.conn.sent)))

    def status(self):
        Runner.calls.append('status')
        return SimpleNamespace(applied=[], pending=[], problems=[],
                               audit=SimpleNamespace(state='protected', details=[]))

    def up(self, to, dry_run=False):
        Runner.calls.append(('up', dry_run))
        return []

    def down(self, to, **kw):
        Runner.calls.append(('down', kw.get('dry_run')))
        return []

    def down_partial(self, version, dry_run=False):
        Runner.calls.append(('down_partial', dry_run))
        return []


@pytest.fixture
def runner(monkeypatch):
    Runner.calls = []
    monkeypatch.setattr(migrate, 'MigrationRunner', Runner)
    monkeypatch.setattr(migrate, 'open_schema', lambda *a: pytest.fail('opened a connection'))
    monkeypatch.setattr(migrate, 'open_runtime_schema',
                        lambda *a: pytest.fail('opened a connection'))
    return Runner


def cli(args, settings, schema=None):
    out = []
    code = migrate.main(args, settings=settings, schema=schema, out=out.append)
    return code, '\n'.join(out)


# ================================================================ classification
@pytest.mark.parametrize('name, kind', [
    ('netcommand_backend', 'production'), ('NetCommand_Backend', 'production'),
    ('netcommand_test', 'test'), ('nc_rehearsal_test', 'test'), ('_test', 'other'),
    ('netcommand', 'legacy_main'), ('NETCOMMAND', 'legacy_main'),
    ('netcommand_backend_test', 'test'), ('netcommand_backend2', 'other'), ('', 'other'),
])
def test_database_classes(name, kind):
    assert classify_database(name) == kind


@pytest.mark.parametrize('value, ok', [(UUID, True), (UUID.upper(), True), ('', False),
                                       ('3e11fa47-71ca-11e1-9e33', False), ('not-a-uuid', False),
                                       (UUID + 'x', False), (None, False)])
def test_server_uuid_format(value, ok):
    assert valid_server_uuid(value) is ok


# ================================================================ target rules (no connection)
def test_production_needs_every_piece():
    assert production.check_target(PROD, 'production', production_flag=True, authorized=PROD,
                                    confirmed=PROD) == 'production'
    cases = [
        (dict(environment='development'), 'BACKEND_ENV=production'),
        (dict(production_flag=False), '--production'),
        (dict(authorized=None), f'--authorize-database {PROD}'),
        (dict(authorized='netcommand_test'), f'--authorize-database {PROD}'),
        (dict(confirmed=None), f'--confirm-database {PROD}'),
        (dict(confirmed='NETCOMMAND_BACKEND'), f'--confirm-database {PROD}'),
    ]
    for change, missing in cases:
        args = dict(environment='production', production_flag=True, authorized=PROD,
                    confirmed=PROD)
        args.update(change)
        env = args.pop('environment')
        with pytest.raises(MigrationError) as err:
            production.check_target(PROD, env, **args)
        assert missing in str(err.value) and 'PRODUCTION database' in str(err.value)
        assert 'Nothing was run' in str(err.value)


@pytest.mark.parametrize('name', ['netcommand_test', 'netcommand', 'other_db'])
def test_production_flag_and_environment_never_point_elsewhere(name):
    with pytest.raises(MigrationError, match='--production was given'):
        production.check_target(name, 'development', production_flag=True)
    with pytest.raises(MigrationError, match='BACKEND_ENV is production'):
        production.check_target(name, 'production')
    assert production.check_target(name, 'development') == classify_database(name)


@pytest.mark.parametrize('command, dry_run, refused', [
    ('down', False, True), ('down', True, False), ('up', False, False),
    ('status', False, False)])
def test_rollback_rule(command, dry_run, refused):
    if refused:
        with pytest.raises(MigrationError, match='restoring a verified backup'):
            production.check_rollback('production', command, dry_run)
    else:
        production.check_rollback('production', command, dry_run)
    for kind in ('test', 'legacy_main', 'other'):
        production.check_rollback(kind, 'down', False)          # unchanged elsewhere


# ================================================================ identity rules
def test_identity_matches():
    production.verify_identity({'db': PROD, 'server_uuid': UUID.upper()}, PROD, UUID,
                               'production')


@pytest.mark.parametrize('row, expected_uuid, message', [
    ({'db': 'netcommand_test', 'server_uuid': UUID}, UUID, "Connected to database"),
    ({'db': None, 'server_uuid': UUID}, UUID, 'Connected to database'),
    ({'db': 'NETCOMMAND_BACKEND', 'server_uuid': UUID}, UUID, 'Connected to database'),
    ({'db': PROD, 'server_uuid': OTHER_UUID}, UUID, 'server UUID'),
    ({'db': PROD, 'server_uuid': None}, UUID, 'server UUID'),
    (None, UUID, 'Connected to database'),
    ({'db': PROD, 'server_uuid': UUID}, '', 'BACKEND_DB_SERVER_UUID must be set'),
])
def test_identity_mismatches(row, expected_uuid, message):
    with pytest.raises(MigrationError) as err:
        production.verify_identity(row, PROD, expected_uuid, 'production')
    assert message in str(err.value) and 'not proof of identity' in str(err.value)


def test_identity_is_optional_elsewhere_but_checked_when_a_uuid_is_configured():
    assert not production.identity_required('test', '')
    assert production.identity_required('test', UUID)
    assert production.identity_required('production', '')
    with pytest.raises(MigrationError):
        production.verify_identity({'db': 'netcommand_test', 'server_uuid': OTHER_UUID},
                                   'netcommand_test', UUID, 'test')


# ================================================================ through migrate.main
COMMANDS = [['status'], ['up'], ['up', '--dry-run'], ['down', '--to', '0', '--dry-run'],
            ['check-runtime-grants'], ['check-runtime-connection'], ['audit-triggers-sql'],
            ['recommended-grants'], ['audit-purge-sql']]


@pytest.mark.parametrize('command', COMMANDS, ids=lambda c: ' '.join(c))
@pytest.mark.parametrize('drop', ['--production', '--authorize-database',
                                  '--confirm-database'])
def test_every_command_on_production_needs_every_flag(runner, monkeypatch, command, drop):
    monkeypatch.setattr('backend.database.connection.connect_runtime',
                        lambda s: pytest.fail('connected'))
    args = list(FULL)
    i = args.index(drop)
    del args[i:i + (1 if drop == '--production' else 2)]
    code, text = cli(command + args, make_settings())
    assert code == 2 and 'PRODUCTION database' in text and runner.calls == []


@pytest.mark.parametrize('command', COMMANDS, ids=lambda c: ' '.join(c))
def test_every_command_on_production_needs_the_production_environment(runner, command):
    code, text = cli(command + FULL, make_settings(environment='development'))
    assert code == 2 and 'BACKEND_ENV=production' in text and runner.calls == []


def test_plan_is_unchanged_and_never_connects(runner):
    code, text = cli(['plan'], make_settings())
    assert code == 0 and 'CREATE TABLE users' in text


def test_sql_printing_commands_work_with_the_full_set(runner):
    for command in (['audit-triggers-sql'], ['recommended-grants'], ['audit-purge-sql']):
        code, text = cli(command + FULL, make_settings())
        assert code == 0 and PROD in text and runner.calls == []


@pytest.mark.parametrize('command', [['status'], ['up', '--dry-run'], ['up'],
                                     ['down', '--to', '0', '--dry-run']],
                         ids=lambda c: ' '.join(c))
def test_identity_is_the_first_statement_and_then_the_command_runs(runner, command):
    conn = Conn()
    code, text = cli(command + FULL, make_settings(), Schema(conn))
    assert code == 0, text
    assert conn.sent == [production.IDENTITY_SQL]                   # the only statement sent
    assert runner.calls[0] == ('created', 1)                         # runner after the check
    assert 'Identity checked: database netcommand_backend' in text


@pytest.mark.parametrize('make_conn', [lambda: Conn(db='netcommand_test'),
                                       lambda: Conn(uuid=OTHER_UUID)],
                         ids=['wrong-database', 'wrong-server'])
@pytest.mark.parametrize('command', [['status'], ['up'], ['check-runtime-grants']],
                         ids=lambda c: ' '.join(c))
def test_a_wrong_server_or_database_stops_after_the_identity_query(runner, make_conn, command):
    conn = make_conn()
    schema = Schema(conn)
    code, text = cli(command + FULL, make_settings(), schema)
    assert code == 2 and 'not proof of identity' in text
    assert conn.sent == [production.IDENTITY_SQL] and runner.calls == []
    assert schema.calls == []                                        # no SHOW GRANTS either


@pytest.mark.parametrize('down', [['down', '--to', '0'], ['down', '--to', '0',
                                                          '--allow-data-loss'],
                                  ['down', '--to', '0', '--allow-data-loss',
                                   '--allow-audit-history-loss'], ['down', '--partial', '1']],
                         ids=lambda c: ' '.join(c))
def test_rollback_is_refused_on_production_before_connecting(runner, down):
    conn = Conn()
    code, text = cli(down + FULL, make_settings(), Schema(conn))
    assert code == 2 and 'restoring a verified backup' in text
    assert conn.sent == [] and runner.calls == []


def test_runtime_grants_check_runs_identity_first(runner):
    conn = Conn()
    schema = Schema(conn)
    code, text = cli(['check-runtime-grants'] + FULL, make_settings(), schema)
    assert conn.sent == [production.IDENTITY_SQL] and schema.calls == ['grants']


def test_runtime_connection_check_runs_identity_on_its_own_connection(runner, monkeypatch):
    conn, order = Conn(), []
    monkeypatch.setattr('backend.database.connection.connect_runtime',
                        lambda s: order.append('identity') or conn)
    from backend.database import health
    monkeypatch.setattr(health, 'check_database',
                        lambda s: order.append('readiness') or health.Readiness(True, 'ready'))
    code, text = cli(['check-runtime-connection'] + FULL, make_settings())
    assert code == 0 and order == ['identity', 'readiness'] and conn.closed
    assert conn.sent == [production.IDENTITY_SQL]
    bad = Conn(uuid=OTHER_UUID)
    monkeypatch.setattr('backend.database.connection.connect_runtime', lambda s: bad)
    monkeypatch.setattr(health, 'check_database', lambda s: pytest.fail('ran the readiness'))
    code, text = cli(['check-runtime-connection'] + FULL, make_settings())
    assert code == 2 and bad.closed


def test_a_configured_uuid_is_also_checked_for_test_databases(runner):
    settings = make_settings(name='netcommand_test', environment='development')
    good = Conn(db='netcommand_test')
    code, _ = cli(['status'], settings, Schema(good))
    assert code == 0 and good.sent == [production.IDENTITY_SQL]
    bad = Conn(db='netcommand_test', uuid=OTHER_UUID)
    code, text = cli(['status'], settings, Schema(bad))
    assert code == 2 and 'server UUID' in text


def test_test_databases_without_a_uuid_behave_as_before(runner):
    conn = Conn(db='netcommand_test')
    code, _ = cli(['status'], make_settings(name='netcommand_test', environment='development',
                                            server_uuid=''), Schema(conn))
    assert code == 0 and conn.sent == []                             # no extra query


def test_messages_never_contain_passwords(runner):
    outputs = []
    for args, schema in ((['status'], None), (['status'] + FULL, Schema(Conn(uuid=OTHER_UUID))),
                         (['down', '--to', '0'] + FULL, None)):
        outputs.append(cli(args, make_settings(), schema)[1])
    text = '\n'.join(outputs)
    assert DB_SECRET not in text and MIGRATE_SECRET not in text


def test_driver_errors_during_the_identity_check_are_translated(runner):
    class Failing(Conn):
        def cursor(self):
            raise pymysql.err.OperationalError(2013, f'Lost connection {DB_SECRET}')
    code, text = cli(['status'] + FULL, make_settings(), Schema(Failing()))
    assert code == 2 and 'MySQL error 2013' in text and DB_SECRET not in text
