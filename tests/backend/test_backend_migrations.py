"""Phase 4C (+ hardening): migrations for the authentication tables. No MySQL: the runner
works on a FakeSchema that simulates tables, columns, triggers, grants, table locks, row
counts and failures; MySQLSchema's SQL is checked with a stand-in connection."""
import json
import os
import re
import subprocess
import sys
from pathlib import Path

import pymysql
import pytest

from backend.database import audit_triggers as AT
from backend.database import m0001_auth_tables as M1
from backend.database import migrate
from backend.database.errors import (BackendDatabaseError, BackendDatabaseUnavailable,
                                     MigrationError)
from backend.database.migrations import (APP_TABLES, MIGRATIONS, TRACKING_COLUMNS,
                                         TRACKING_TABLE, Migration, MigrationRunner, MySQLSchema,
                                         check_database_name, check_definitions)
from backend.settings import parse_settings

ROOT = Path(__file__).resolve().parents[2]
MIGRATE_SECRET = 'Migrate-Account-Secret-6612'
EXPECTED = MIGRATIONS[0].expected_columns()


def trigger_rows(**override):
    rows = []
    for t in AT.TRIGGERS:
        row = {'TRIGGER_NAME': t.name, 'EVENT_OBJECT_TABLE': 'audit_log',
               'ACTION_TIMING': t.timing, 'EVENT_MANIPULATION': t.event,
               'ACTION_STATEMENT': t.body}
        row.update(override.get(t.name, {}))
        rows.append(row)
    return rows


class FakeSchema:
    """A database as the runner sees it."""

    def __init__(self, tables=APP_TABLES, fail_at=None, lock_free=True, triggers_visible=True):
        self.tables_ = set(tables)
        self.records, self.rows, self.events = {}, {}, []
        self.executed, self.fail_at, self.lock_free = [], fail_at, lock_free
        self.fail_error = RuntimeError('simulated failure')
        self.triggers_visible, self.installed_triggers = triggers_visible, []
        self.column_override, self.tracking_columns = {}, dict(TRACKING_COLUMNS)
        self.forget_error, self.on_lock_tables = None, None
        self.locked, self.locked_tables = False, None
        self.database = 'netcommand_test'
        # As the generated grants: the migration account has no DROP on audit_log.
        self.drop_denied = {'audit_log'}

    def admin_drop(self, table):
        """An ADMINISTRATOR drops a table by hand (outside the migration tool)."""
        self.events.append(('admin_drop', table))
        self.tables_.discard(table)
        if table == 'audit_log':
            self.installed_triggers = []

    # read
    def tables(self):
        return sorted(self.tables_)

    def columns(self, table):
        if table == TRACKING_TABLE:
            return dict(self.tracking_columns)
        names = self.column_override.get(table, EXPECTED.get(table, set()))
        return {n: 'x' for n in names}

    def applied(self):
        return [dict(r) for _, r in sorted(self.records.items())]

    def triggers(self):
        if not self.triggers_visible:
            return False, []
        return True, [r for r in self.installed_triggers if 'audit_log' in self.tables_]

    def row_count(self, table):
        self.events.append(('count', table))
        return self.rows.get(table, 0)

    # write
    def execute(self, sql):
        self.executed.append(sql)
        if self.fail_at is not None and len(self.executed) == self.fail_at:
            raise self.fail_error
        m = re.match(r'(?is)\s*CREATE\s+TABLE\s+(IF\s+NOT\s+EXISTS\s+)?(\w+)', sql)
        if m:
            if m.group(2) in self.tables_ and not m.group(1):
                raise RuntimeError(f'Table {m.group(2)} already exists')
            self.tables_.add(m.group(2))
            return
        m = re.match(r'(?is)\s*DROP\s+TABLE\s+IF\s+EXISTS\s+(\w+)', sql)
        if m:
            if m.group(1) in self.drop_denied:
                # As MySQL (error 1142) for an account without DROP on that table.
                raise RuntimeError(f"DROP command denied to user 'netcommand_migrator'@"
                                   f"'127.0.0.1' for table '{m.group(1)}'")
            if self.locked_tables is not None and m.group(1) not in self.locked_tables:
                # As MySQL under LOCK TABLES (error 1100): every table named must be locked.
                raise RuntimeError(f"Table '{m.group(1)}' was not locked with LOCK TABLES")
            self.events.append(('drop', m.group(1)))
            self.tables_.discard(m.group(1))
            if m.group(1) == 'audit_log':
                self.installed_triggers = []        # dropping a table drops its triggers
            return
        raise AssertionError(f'unexpected statement: {sql[:60]}')

    def record(self, version, name, checksum):
        self.records[version] = {'version': version, 'name': name, 'checksum': checksum,
                                 'applied_at': '2026-11-18 00:00:00', 'applied_by': 'mig@x'}

    def forget(self, version):
        if self.forget_error:
            raise self.forget_error
        self.events.append(('forget', version))
        self.records.pop(version)

    def lock(self):
        schema = self

        class Lock:
            def __enter__(self):
                if not schema.lock_free:
                    raise MigrationError('Another migration is running on this database.')
                schema.locked = True

            def __exit__(self, *e):
                schema.locked = False
        return Lock()

    def lock_tables(self, tables):
        schema = self

        class TableLock:
            def __enter__(self):
                if schema.on_lock_tables:
                    schema.on_lock_tables()          # e.g. a backend write just before the lock
                schema.events.append(('lock', tuple(tables)))
                schema.locked_tables = set(tables)

            def __exit__(self, *e):
                schema.events.append(('unlock',))
                schema.locked_tables = None
        return TableLock()


def runner(schema, migrations=MIGRATIONS):
    lines = []
    return MigrationRunner(schema, migrations, log=lines.append), lines


def applied_schema(**kw):
    schema = FakeSchema(**kw)
    runner(schema)[0].up()
    schema.executed.clear()
    schema.events.clear()
    return schema


def app_statements(schema):
    return [s for s in schema.executed if any(re.search(rf'\b{t}\b', s) for t in APP_TABLES)]


# ================================================================ definitions
def test_migration_definitions_are_valid_and_ordered():
    check_definitions()
    assert [m.version for m in MIGRATIONS] == [1]
    assert MIGRATIONS[0].tables == ('users', 'email_challenges', 'sessions', 'audit_log')


@pytest.mark.parametrize('bad, message', [
    (Migration(1, 'x', ('CREATE TABLE devices (\n  id INT)',), ('DROP TABLE IF EXISTS devices',),
               ('devices',)), 'names application tables'),
    (Migration(1, 'x', ('ALTER TABLE config_logs ADD COLUMN u INT',), (), ()),
     'names application tables'),
    (Migration(1, 'x', ('RENAME TABLE t1 TO devices',), (), ()), 'names application tables'),
    (Migration(1, 'x', ('CREATE TABLE t1 LIKE links',), ('DROP TABLE IF EXISTS t1',), ('t1',)),
     'names application tables'),
    (Migration(1, 'x', ('CREATE TABLE IF NOT EXISTS t1 (\n  id INT)',),
               ('DROP TABLE IF EXISTS t1',), ('t1',)), 'IF NOT EXISTS'),
    (Migration(1, 'x', ('CREATE TABLE t1 (\n  id INT)',), ('DROP TABLE IF EXISTS other',), ('t1',)),
     'may only drop its own'),
    (Migration(1, 'x', ('DROP TABLE t9',), (), ()), 'destructive or administrator-only'),
    (Migration(1, 'x', ('RENAME TABLE t1 TO t2',), (), ()), 'destructive or administrator-only'),
    (Migration(1, 'x', ('CREATE TRIGGER tr BEFORE UPDATE ON t1 FOR EACH ROW SET @a = 1',), (), ()),
     'destructive or administrator-only'),
    (Migration(1, 'x', ('CREATE DEFINER=root@localhost PROCEDURE p() SELECT 1',), (), ()),
     'destructive or administrator-only'),
    (Migration(2, 'x', ('CREATE TABLE t1 (\n  id INT)',), ('DROP TABLE IF EXISTS t1',), ('t1',)),
     'without gaps'),
    (Migration(1, 'x', ('CREATE TABLE t1 (\n  id INT)',), ('DROP TABLE IF EXISTS t2',),
               ('t1', 't2')), 'lists tables it does not create'),
])
def test_unsafe_definitions_are_refused_before_anything_runs(bad, message):
    with pytest.raises(MigrationError) as err:
        MigrationRunner(FakeSchema(), (bad,))
    assert message in str(err.value)


def test_checksum_covers_up_down_tables_and_name():
    m = MIGRATIONS[0]
    variants = [Migration(m.version, m.name + 'x', m.up, m.down, m.tables),
                Migration(m.version, m.name, m.up + ('SELECT 1',), m.down, m.tables),
                Migration(m.version, m.name, m.up, m.down[:-1], m.tables),
                Migration(m.version, m.name, m.up, m.down, m.tables[:-1])]
    assert len({m.checksum} | {v.checksum for v in variants}) == 5


def test_migration_0001_tables_are_safe_by_design():
    sql = '\n'.join(M1.UP)
    assert sql.count('ENGINE=InnoDB') == 4 and sql.count('DEFAULT CHARSET=utf8mb4') == 4
    assert 'IF NOT EXISTS' not in sql and 'TRIGGER' not in sql.upper()   # tables only
    assert "password_hash     VARCHAR(255) CHARACTER SET utf8mb4 COLLATE utf8mb4_bin" in sql
    assert "CHECK (password_hash LIKE '$argon2id$%')" in sql               # case-sensitive (bin)
    assert 'CHECK (CHAR_LENGTH(code_hmac) = 64)' in sql and 'CHECK (CHAR_LENGTH(token_hash) = 64)' in sql
    columns = set().union(*EXPECTED.values())
    assert {'password_hash', 'code_hmac', 'token_hash'} <= columns
    assert not {'password', 'otp', 'otp_code', 'code', 'token', 'session_token'} & columns
    assert "ENUM('admin','operator','viewer')" in sql
    assert ("ENUM('pending_verification','pending_approval','active','rejected','disabled')" in sql)
    assert 'UNIQUE KEY uq_users_email (email_normalized)' in sql
    assert 'KEY ix_users_role_status (role, status)' in sql
    assert sql.count('FOREIGN KEY') == 3                                    # audit_log has none
    assert 'TIMESTAMP ' not in sql.replace('UTC_TIMESTAMP', '')
    assert not set(re.findall(r'\b(\w+)\b', sql)) & set(APP_TABLES)
    assert M1.DOWN == ['DROP TABLE IF EXISTS audit_log', 'DROP TABLE IF EXISTS sessions',
                       'DROP TABLE IF EXISTS email_challenges', 'DROP TABLE IF EXISTS users']


# ================================================================ audit triggers (admin step)
def test_admin_sql_creates_both_triggers_for_the_named_database_only():
    text = AT.admin_sql('netcommand_test')
    assert 'USE `netcommand_test`;' in text and text.count('CREATE TRIGGER') == 2
    assert 'DELIMITER $$' in text and 'DELIMITER ;' in text
    assert 'BEFORE UPDATE ON audit_log' in text and 'BEFORE DELETE ON audit_log' in text
    assert 'INTERVAL 1 YEAR' in text and 'netcommand`' not in text.replace('netcommand_test`', '')
    with pytest.raises(ValueError):
        AT.admin_sql('bad; DROP DATABASE x')


def test_trigger_verification():
    assert AT.verify(trigger_rows()) == []
    assert AT.verify([]) == ['trigger audit_log_no_update is missing',
                             'trigger audit_log_no_recent_delete is missing']
    problems = AT.verify(trigger_rows(audit_log_no_update={'ACTION_TIMING': 'AFTER'},
                                      audit_log_no_recent_delete={
                                          'ACTION_STATEMENT': "SIGNAL SQLSTATE '45000'"}))
    assert any('is not BEFORE UPDATE' in p for p in problems)
    assert any('INTERVAL 1 YEAR' in p for p in problems)            # retention rule removed
    # MySQL may store the body with different spacing / capitals: still recognised
    spaced = trigger_rows(audit_log_no_update={'ACTION_STATEMENT':
                                               "signal   sqlstate '45000'\n set message_text='x'"})
    assert AT.verify(spaced) == []


# ================================================================ applying
def test_up_creates_tables_only_and_says_audit_is_not_yet_protected():
    schema = FakeSchema()
    r, log = runner(schema)
    assert r.up() == [1]
    assert {'users', 'email_challenges', 'sessions', 'audit_log', TRACKING_TABLE} <= schema.tables_
    assert set(APP_TABLES) <= schema.tables_ and app_statements(schema) == []
    assert not any('TRIGGER' in s.upper() for s in schema.executed)
    assert schema.records[1]['checksum'] == MIGRATIONS[0].checksum
    assert any('audit_log is NOT yet protected' in line for line in log)
    st = r.status()
    assert st.problems == [] and st.audit.state == 'not_protected' and not st.audit.protected


def test_status_reports_protected_only_when_both_triggers_are_verified():
    schema = applied_schema()
    r, _ = runner(schema)
    schema.installed_triggers = trigger_rows()[:1]
    assert r.status().audit.state == 'not_protected'
    schema.installed_triggers = trigger_rows()
    assert r.status().audit.state == 'protected'
    schema.triggers_visible = False
    st = r.status()
    assert st.audit.state == 'unknown' and not st.audit.protected
    assert FakeSchema().triggers()[1] == [] and runner(FakeSchema())[0].status().audit.state == \
        'no_audit_table'


def test_up_twice_does_nothing_the_second_time_and_dry_run_changes_nothing():
    schema = FakeSchema()
    r, log = runner(schema)
    assert r.up(dry_run=True) == [1] and schema.executed == []
    r.up()
    count = len(schema.executed)
    assert r.up() == [] and len(schema.executed) == count


def test_existing_unrecorded_table_is_never_recreated():
    schema = FakeSchema(tables=APP_TABLES + ('users',))
    r, _ = runner(schema)
    assert [p.kind for p in r.status().problems] == ['partial_apply']
    with pytest.raises(MigrationError) as err:
        r.up()
    assert 'inconsistent' in str(err.value) and schema.executed == []


@pytest.mark.parametrize('record, kind', [
    ({'version': 7, 'name': 'future', 'checksum': 'x' * 64}, 'unknown_version'),
    ({'version': 1, 'name': 'auth_tables', 'checksum': '0' * 64}, 'checksum'),
    ({'version': 1, 'name': 'renamed', 'checksum': MIGRATIONS[0].checksum}, 'name'),
])
def test_unknown_or_changed_migrations_are_refused(record, kind):
    schema = FakeSchema(tables=APP_TABLES + (TRACKING_TABLE,) + M1.TABLES)
    schema.records[record['version']] = dict(record, applied_at='x', applied_by='y')
    r, _ = runner(schema)
    assert kind in [p.kind for p in r.status().problems]
    with pytest.raises(MigrationError):
        r.up()
    with pytest.raises(MigrationError):
        r.down(0)
    assert schema.executed == []


def test_foreign_tracking_table_is_refused():
    schema = FakeSchema(tables=APP_TABLES + (TRACKING_TABLE,))
    schema.tracking_columns = {'id': 'int', 'version': 'varchar(20)'}
    r, _ = runner(schema)
    assert [p.kind for p in r.status().problems] == ['tracking_structure']
    with pytest.raises(MigrationError):
        r.up()
    assert schema.executed == []


def test_changed_table_columns_are_reported():
    schema = applied_schema()
    schema.column_override['sessions'] = EXPECTED['sessions'] - {'revoked_reason'}
    r, _ = runner(schema)
    assert [p.kind for p in r.status().problems] == ['columns']


def test_a_failure_part_way_is_reported_honestly_and_can_be_repaired():
    schema = FakeSchema(fail_at=4)          # tracking, users, email_challenges, then fail
    r, _ = runner(schema)
    with pytest.raises(MigrationError) as err:
        r.up()
    text = str(err.value)
    assert 'Statement 3 of 4 failed and was not applied' in text
    assert 'Statements 1 to 2 had already run and were committed' in text
    assert 'down --partial 1' in text
    assert {'users', 'email_challenges'} <= schema.tables_ and 1 not in schema.records
    schema.fail_at = None
    assert r.down_partial(1) == [1]
    assert not (set(M1.TABLES) & schema.tables_) and set(APP_TABLES) <= schema.tables_
    assert ('lock', ('users', 'email_challenges')) in schema.events      # locked while dropped
    assert r.up() == [1] and r.status().problems == []


def test_lost_connection_is_reported_as_uncertain():
    schema = FakeSchema(fail_at=3)
    schema.fail_error = BackendDatabaseUnavailable('The connection to the backend database at '
                                                   'x was lost (MySQL error 2013).')
    r, _ = runner(schema)
    with pytest.raises(MigrationError) as err:
        r.up()
    text = str(err.value)
    assert 'The connection was lost during statement 2 of 4' in text
    assert 'may or may not have completed it' in text and 'Run `status`' in text
    assert 'failed and was not applied' not in text


def test_recording_failure_after_a_complete_run_is_explained():
    schema = FakeSchema()
    schema.record = lambda *a: (_ for _ in ()).throw(BackendDatabaseUnavailable('lost'))
    r, _ = runner(schema)
    with pytest.raises(MigrationError) as err:
        r.up()
    assert 'ran completely, but recording it failed' in str(err.value)
    assert [p.kind for p in r.status().problems] == ['partial_apply']


def test_partial_repair_refuses_tables_with_data():
    schema = FakeSchema(fail_at=4)
    r, _ = runner(schema)
    with pytest.raises(MigrationError):
        r.up()
    schema.fail_at, schema.rows['users'] = None, 2
    with pytest.raises(MigrationError) as err:
        r.down_partial(1)
    assert 'holds 2 rows' in str(err.value) and 'users' in schema.tables_


def test_lock_is_required_and_unknown_target_refused():
    with pytest.raises(MigrationError) as err:
        runner(FakeSchema(lock_free=False))[0].up()
    assert 'Another migration is running' in str(err.value)
    with pytest.raises(MigrationError):
        runner(FakeSchema())[0].up(5)


# ================================================================ rolling back
# The migration account has no DROP on audit_log (FakeSchema.drop_denied, as the generated
# grants): a rollback stops before dropping anything while audit_log exists; an
# administrator removes it (FakeSchema.admin_drop), then the same command finishes.
REMAINING_DROPS = ['DROP TABLE IF EXISTS sessions', 'DROP TABLE IF EXISTS email_challenges',
                   'DROP TABLE IF EXISTS users']


def test_rollback_stops_before_anything_while_audit_log_exists():
    schema = applied_schema()
    r, _ = runner(schema)
    for call in (lambda: r.down(0), lambda: r.down(0, dry_run=True),
                 lambda: r.down(0, allow_data_loss=True, allow_audit_history_loss=True)):
        with pytest.raises(MigrationError) as err:
            call()
        text = str(err.value)
        assert 'Rollback stopped before dropping anything: audit_log still exists' in text
        assert 'deliberately has no DROP privilege on audit_log' in text
        assert 'It is empty, but only an administrator may drop it.' in text
        assert 'DROP TABLE `netcommand_test`.audit_log;' in text
        assert 'run `down --to 0` again' in text and 'No table was changed.' in text
    assert schema.executed == []                                   # no DROP sent at all
    assert not any(e[0] in ('lock', 'drop', 'forget') for e in schema.events)
    assert set(M1.TABLES) <= schema.tables_ and 1 in schema.records
    assert r.status().problems == []                               # still consistent


def test_rollback_message_asks_to_archive_existing_audit_records():
    schema = applied_schema()
    schema.rows['audit_log'] = 5
    with pytest.raises(MigrationError) as err:
        runner(schema)[0].down(0)
    text = str(err.value)
    assert 'It holds 5 audit records: an administrator must archive them first' in text
    assert schema.executed == []


def test_migration_account_cannot_drop_audit_log():
    """Even if the runner's guard were bypassed, the account's grants refuse the DROP."""
    schema = applied_schema()
    with pytest.raises(RuntimeError) as err:
        schema.execute('DROP TABLE IF EXISTS audit_log')
    assert 'DROP command denied' in str(err.value) and 'audit_log' in schema.tables_
    from backend.database.privileges import (ADMINISTRATOR_ONLY, MIGRATION_ACCOUNT,
                                             MIGRATION_GRANTS, effective_privileges,
                                             grant_statements, parse_grants)
    grants, _ = parse_grants(grant_statements(MIGRATION_GRANTS, 'netcommand_test',
                                              MIGRATION_ACCOUNT))
    assert 'DROP' not in effective_privileges(grants, 'netcommand_test', 'audit_log')
    for table in ('users', 'email_challenges', 'sessions'):
        assert 'DROP' in effective_privileges(grants, 'netcommand_test', table)
    assert ('DROP', 'audit_log') in ADMINISTRATOR_ONLY


def test_full_rollback_continues_after_the_administrator_removes_audit_log():
    schema = applied_schema()
    r, _ = runner(schema)
    with pytest.raises(MigrationError):
        r.down(0)
    schema.admin_drop('audit_log')
    assert [p.kind for p in r.status().problems] == ['interrupted_rollback']
    assert r.down(0) == [1]
    assert schema.executed == REMAINING_DROPS
    assert ('lock', ('users', 'email_challenges', 'sessions', TRACKING_TABLE)) in schema.events
    kinds = [e[0] for e in schema.events]
    assert kinds.index('admin_drop') < kinds.index('lock')       # administrator first
    assert kinds.index('count') < kinds.index('drop') and kinds[-2:] == ['forget', 'unlock']
    assert not (set(M1.TABLES) & schema.tables_) and set(APP_TABLES) <= schema.tables_
    assert app_statements(schema) == [] and schema.records == {} and r.down(0) == []
    assert r.status().problems == []


def test_a_write_just_before_the_lock_is_seen_and_stops_the_drop():
    """The emptiness check happens UNDER the table lock: a row written by a running backend
    after `status` but before the lock is counted, and nothing is dropped."""
    schema = applied_schema()
    schema.admin_drop('audit_log')
    schema.on_lock_tables = lambda: schema.rows.update(sessions=1)
    r, _ = runner(schema)
    with pytest.raises(MigrationError) as err:
        r.down(0)
    assert 'sessions: it holds 1 rows' in str(err.value)
    assert not any(e[0] == 'drop' for e in schema.events) and ('unlock',) in schema.events


def test_down_refuses_to_lose_data():
    schema = applied_schema()
    schema.admin_drop('audit_log')
    r, _ = runner(schema)
    schema.rows['users'] = 3
    with pytest.raises(MigrationError) as err:
        r.down(0)
    assert 'users: it holds 3 rows' in str(err.value) and schema.executed == []
    with pytest.raises(MigrationError):
        r.down(0, dry_run=True)                                    # dry run checks the same
    assert r.down(0, dry_run=True, allow_data_loss=True) == [1] and schema.executed == []


def test_audit_history_is_never_dropped_by_the_tool_even_with_both_flags():
    schema = applied_schema()
    schema.rows['audit_log'] = 7
    with pytest.raises(MigrationError):
        runner(schema)[0].down(0, allow_data_loss=True, allow_audit_history_loss=True)
    assert 'audit_log' in schema.tables_ and schema.executed == []


def test_failed_bookkeeping_after_drops_is_finished_by_running_down_again():
    schema = applied_schema()
    schema.admin_drop('audit_log')
    schema.forget_error = BackendDatabaseUnavailable('lost')
    r, _ = runner(schema)
    with pytest.raises(MigrationError) as err:
        r.down(0)
    assert 'Run the same `down` command again' in str(err.value)
    assert not (set(M1.TABLES) & schema.tables_) and 1 in schema.records
    assert [p.kind for p in r.status().problems] == ['interrupted_rollback']
    with pytest.raises(MigrationError):
        r.up()                                                     # never re-applied over it
    schema.forget_error = None
    schema.executed.clear()
    assert r.down(0) == [1] and schema.executed == []              # every table already gone
    assert schema.records == {} and r.status().problems == []
    assert ('lock', (TRACKING_TABLE,)) in schema.events


def test_rollback_interrupted_mid_drop_is_finished_by_running_it_again():
    schema = applied_schema()
    schema.admin_drop('audit_log')
    schema.fail_at = 2                                             # email_challenges drop fails
    r, _ = runner(schema)
    with pytest.raises(MigrationError) as err:
        r.down(0)
    assert 'Running the same command again finishes it' in str(err.value)
    assert [p.kind for p in r.status().problems] == ['interrupted_rollback']
    schema.fail_at = None
    schema.executed.clear()
    assert r.down(0) == [1] and not (set(M1.TABLES) & schema.tables_)
    assert schema.executed == REMAINING_DROPS[1:]                  # only what was still there


def test_partial_repair_before_audit_log_existed_needs_no_administrator():
    schema = FakeSchema(fail_at=3)                  # tracking table and users only
    r, _ = runner(schema)
    with pytest.raises(MigrationError):
        r.up()
    schema.fail_at = None
    schema.executed.clear()
    assert r.down_partial(1) == [1]
    assert schema.executed == ['DROP TABLE IF EXISTS users']
    assert ('lock', ('users',)) in schema.events


def test_partial_repair_after_audit_log_was_created_needs_the_administrator():
    schema = FakeSchema()
    schema.record = lambda *a: (_ for _ in ()).throw(BackendDatabaseUnavailable('lost'))
    r, _ = runner(schema)
    with pytest.raises(MigrationError):
        r.up()                                      # all four tables created, not recorded
    schema.executed.clear()
    with pytest.raises(MigrationError) as err:
        r.down_partial(1)
    text = str(err.value)
    assert 'Rollback stopped before dropping anything: audit_log still exists' in text
    assert 'run `down --partial 1` again' in text
    assert schema.executed == [] and set(M1.TABLES) <= schema.tables_
    schema.admin_drop('audit_log')
    assert r.down_partial(1) == [1]
    assert schema.executed == REMAINING_DROPS
    assert not (set(M1.TABLES) & schema.tables_) and r.status().problems == []
    del schema.record                                # the instance override; the class method returns
    assert r.up() == [1]


def test_cli_rollback_explains_the_administrator_step():
    schema = applied_schema()
    code, text = run_cli(['down', '--to', '0', '--confirm-database', 'netcommand_test'],
                         settings_for(), schema)
    assert code == 2 and 'Migration refused: Rollback stopped before dropping anything' in text
    assert 'administrator' in text and schema.executed == []


# ================================================================ database names
@pytest.mark.parametrize('name', ['netcommand_test', 'lab_test', 'NetCommand_TEST'])
def test_test_databases_are_allowed_by_default(name):
    check_database_name(name)


@pytest.mark.parametrize('name', ['', '_test', 'netcommand_prod', 'production', 'test'])
def test_other_databases_need_explicit_authorization(name):
    with pytest.raises(MigrationError):
        check_database_name(name)
    if name not in ('', '_test'):
        check_database_name(name, authorized=name)              # explicitly authorized
        with pytest.raises(MigrationError):
            check_database_name(name, authorized='something_else')


def test_main_database_needs_both_flags():
    for authorized, allow in ((None, False), ('netcommand', False), (None, True)):
        with pytest.raises(MigrationError):
            check_database_name('netcommand', authorized, allow)
    check_database_name('netcommand', 'netcommand', True)


# ================================================================ command line
def settings_for(name='netcommand_test', password=MIGRATE_SECRET):
    raw = {'BACKEND_DB_ENABLED': 'true', 'BACKEND_DB_HOST': '127.0.0.1', 'BACKEND_DB_PORT': '3307',
           'BACKEND_DB_USER': 'netcommand_api', 'BACKEND_DB_PASSWORD': 'runtime-secret-1',
           'BACKEND_DB_NAME': name, 'BACKEND_MIGRATE_USER': 'migrator'}
    if password:
        raw['BACKEND_MIGRATE_PASSWORD'] = password
    return parse_settings(raw)


def run_cli(args, settings, schema=None):
    out = []
    code = migrate.main(args, settings=settings, schema=schema, out=out.append)
    return code, '\n'.join(out)


def no_connection(monkeypatch):
    monkeypatch.setattr(migrate, 'open_schema', lambda *a: pytest.fail('connected'))
    monkeypatch.setattr(migrate, 'open_runtime_schema', lambda *a: pytest.fail('connected'))


def test_plan_and_trigger_sql_need_no_connection(monkeypatch):
    no_connection(monkeypatch)
    code, text = run_cli(['plan'], settings=None)
    assert code == 0 and 'CREATE TABLE users' in text and 'audit-triggers-sql' in text
    code, text = run_cli(['audit-triggers-sql'], settings_for())
    assert code == 0 and text.count('CREATE TRIGGER') == 2 and 'USE `netcommand_test`;' in text


@pytest.mark.parametrize('name, args, message', [
    ('netcommand', ['status'], "Refusing to migrate 'netcommand'"),
    ('netcommand', ['up', '--confirm-database', 'netcommand', '--authorize-database',
                    'netcommand'], "Refusing to migrate 'netcommand'"),
    ('netcommand_prod', ['up', '--dry-run'], "does not end in '_test'"),
    ('netcommand_prod', ['audit-triggers-sql'], "does not end in '_test'"),
])
def test_unapproved_databases_are_refused_before_connecting(monkeypatch, name, args, message):
    no_connection(monkeypatch)
    code, text = run_cli(args, settings_for(name))
    assert code == 2 and message in text


def test_authorized_non_test_database_still_needs_confirmation(monkeypatch):
    no_connection(monkeypatch)
    code, text = run_cli(['up', '--authorize-database', 'netcommand_prod'],
                         settings_for('netcommand_prod'))
    assert code == 2 and '--confirm-database netcommand_prod' in text


def test_cli_status_exit_codes_follow_audit_protection():
    schema = FakeSchema()
    code, text = run_cli(['status'], settings_for(), schema)
    assert code == 0 and 'pending  1 auth_tables' in text and 'not applicable' in text
    code, text = run_cli(['up', '--confirm-database', 'netcommand_test'], settings_for(), schema)
    assert code == 0 and 'NOT yet protected' in text
    code, text = run_cli(['status'], settings_for(), schema)
    assert code == 3 and 'audit_log protection: NOT PROTECTED' in text
    assert 'trigger audit_log_no_update is missing' in text
    schema.installed_triggers = trigger_rows()
    code, text = run_cli(['status'], settings_for(), schema)
    assert code == 0 and 'PROTECTED (both triggers verified)' in text
    schema.triggers_visible = False
    code, text = run_cli(['status'], settings_for(), schema)
    assert code == 3 and 'UNKNOWN' in text
    assert MIGRATE_SECRET not in text and 'runtime-secret-1' not in text


def test_cli_inconsistent_state_exit_code_1():
    code, text = run_cli(['status'], settings_for(), FakeSchema(tables=APP_TABLES + ('users',)))
    assert code == 1 and 'PROBLEM' in text


def test_cli_translates_connection_failures_and_interrupts():
    class Broken(FakeSchema):
        def tables(self):
            raise BackendDatabaseUnavailable('The connection to the backend database at '
                                              'netcommand_test was lost (MySQL error 2013).')
    code, text = run_cli(['status'], settings_for(), Broken())
    assert code == 2 and 'Migration refused' in text and 'was lost' in text

    class Interrupted(FakeSchema):
        def tables(self):
            raise KeyboardInterrupt
    code, text = run_cli(['status'], settings_for(), Interrupted())
    assert code == 130 and 'Run `status`' in text


def test_cli_runtime_grant_check(monkeypatch):
    class Grants:
        def __init__(self, lines):
            self.lines = lines

        def grants(self):
            return self.lines
    from backend.database.privileges import RUNTIME_ACCOUNT, RUNTIME_GRANTS, grant_statements
    safe = ["GRANT USAGE ON *.* TO `netcommand_api`@`127.0.0.1`"] + \
        grant_statements(RUNTIME_GRANTS, 'netcommand_test', RUNTIME_ACCOUNT)
    code, text = run_cli(['check-runtime-grants'], settings_for(), Grants(safe))
    assert code == 0 and 'ok: least privilege' in text
    assert 'against audit_log it can: only SELECT and INSERT' in text
    partial = safe[:2] + safe[4:]                         # email_challenges/sessions missing
    code, text = run_cli(['check-runtime-grants'], settings_for(), Grants(partial))
    assert code == 5 and 'MISSING  SELECT on netcommand_test.email_challenges' in text
    unsafe = safe + ["GRANT SELECT, INSERT, UPDATE, DELETE ON `netcommand_test`.* TO `x`@`h`"]
    code, text = run_cli(['check-runtime-grants'], settings_for(), Grants(unsafe))
    assert code == 4 and 'UNSAFE   DELETE, UPDATE on netcommand_test.*' in text
    assert 'against audit_log it can: update_rows, delete_rows' in text


def test_print_only_commands_need_no_connection(monkeypatch):
    no_connection(monkeypatch)
    code, text = run_cli(['recommended-grants'], settings_for())
    assert code == 0 and 'CREATE USER' in text and "TO 'netcommand_api'@'127.0.0.1';" in text
    code, text = run_cli(['audit-purge-sql'], settings_for())
    assert code == 0 and 'DELETE FROM `netcommand_test`.audit_log' in text
    code, text = run_cli(['recommended-grants'], settings_for('netcommand'))
    assert code == 2                                        # main database still refused


def test_migration_and_runtime_accounts_must_differ(monkeypatch):
    """Refused twice: by the settings themselves (so no part of the backend can start with
    one account for both), and again by the migration command before connecting."""
    import dataclasses
    from backend.database import connection
    from backend.settings import SettingsError
    monkeypatch.setattr(connection, 'connect', lambda *a: pytest.fail('connected'))
    raw = {'BACKEND_DB_ENABLED': 'true', 'BACKEND_DB_HOST': '127.0.0.1',
           'BACKEND_DB_PORT': '3307', 'BACKEND_DB_USER': 'netcommand_api',
           'BACKEND_DB_PASSWORD': 'p', 'BACKEND_DB_NAME': 'netcommand_test',
           'BACKEND_MIGRATE_USER': 'NetCommand_API'}
    with pytest.raises(SettingsError) as err:
        parse_settings(raw)
    assert 'must be a different account from BACKEND_DB_USER' in str(err.value)
    same = dataclasses.replace(settings_for(), migrate_user='NETCOMMAND_API')  # built directly
    with pytest.raises(MigrationError) as err:
        migrate.open_schema(same, password_source=lambda p: 'x')
    assert 'must be different accounts' in str(err.value)


def test_open_schema_uses_the_right_account_and_asks_for_a_missing_password(monkeypatch):
    calls = []
    from backend.database import connection
    monkeypatch.setattr(connection, 'connect', lambda *a: calls.append(a) or 'conn')
    migrate.open_schema(settings_for(password=None), password_source=lambda p: 'typed')
    migrate.open_runtime_schema(settings_for())
    assert calls == [('127.0.0.1', 3307, 'migrator', 'typed', 'netcommand_test'),
                     ('127.0.0.1', 3307, 'netcommand_api', 'runtime-secret-1', 'netcommand_test')]


# ================================================================ MySQLSchema's SQL
class Cur:
    def __init__(self, conn):
        self.conn, self._rows = conn, []

    def __enter__(self):
        return self

    def __exit__(self, *e):
        return False

    def execute(self, sql, params=()):
        self.conn.sent.append((sql, params))
        if self.conn.error is not None and self.conn.fail_on in sql:
            raise self.conn.error
        self._rows = self.conn.answer(sql)

    def fetchall(self):
        return self._rows


class Conn:
    def __init__(self, answer=lambda sql: [], error=None, fail_on=''):
        self.answer, self.error, self.fail_on = answer, error, fail_on
        self.sent, self.commits = [], 0

    def cursor(self):
        return Cur(self)

    def commit(self):
        self.commits += 1


def test_mysql_schema_reads_are_parameterised_and_locks_are_per_database():
    conn = Conn(lambda sql: [{'name': 'users'}] if 'TABLES WHERE' in sql else
                [{'n': 0}] if 'COUNT' in sql else [{'got': 1}] if 'GET_LOCK' in sql else
                [{'name': 'id', 'type': 'bigint unsigned'}] if 'COLUMNS' in sql else [])
    s = MySQLSchema(conn, 'netcommand_test')
    assert s.tables() == ['users'] and s.columns('users') == {'id': 'bigint unsigned'}
    assert conn.sent[0][1] == ('netcommand_test',) and conn.sent[1][1] == ('netcommand_test', 'users')
    assert s.row_count('users') == 0
    for app_table in APP_TABLES:
        with pytest.raises(MigrationError):
            s.row_count(app_table)
    with s.lock():
        pass
    lock_sql = [p for q, p in conn.sent if 'GET_LOCK' in q][0]
    assert lock_sql == ('netcommand_migrations:netcommand_test',)


def test_mysql_schema_table_lock_sql():
    conn = Conn()
    s = MySQLSchema(conn, 'netcommand_test')
    with s.lock_tables(['users', 'audit_log', TRACKING_TABLE]):
        pass
    sql = [q for q, _ in conn.sent]
    assert sql == ['LOCK TABLES `users` WRITE, `audit_log` WRITE, `schema_migrations` WRITE',
                   'UNLOCK TABLES']
    with pytest.raises(MigrationError):
        with s.lock_tables(['users', 'devices']):
            pass


def test_mysql_schema_hides_triggers_it_cannot_see():
    no_trigger = Conn(lambda sql: [{'Grants for x': 'GRANT SELECT ON `netcommand_test`.* TO `m`@`h`'}]
                      if sql == 'SHOW GRANTS' else [])
    assert MySQLSchema(no_trigger, 'netcommand_test').triggers() == (False, [])
    assert not any('information_schema.TRIGGERS' in q for q, _ in no_trigger.sent)
    rows = trigger_rows()
    with_trigger = Conn(lambda sql: [{'Grants for x': 'GRANT SELECT, TRIGGER ON '
                                                       '`netcommand_test`.`audit_log` TO `m`@`h`'}]
                        if sql == 'SHOW GRANTS' else rows)
    visible, got = MySQLSchema(with_trigger, 'netcommand_test').triggers()
    assert visible and got == rows
    assert with_trigger.sent[-1][1] == ('netcommand_test', 'audit_log')


@pytest.mark.parametrize('error, expected', [
    (pymysql.err.OperationalError(2013, 'Lost connection'), BackendDatabaseUnavailable),
    (pymysql.err.ProgrammingError(1146, "Table 'x' doesn't exist"), BackendDatabaseError),
])
def test_mysql_schema_translates_driver_errors(error, expected):
    s = MySQLSchema(Conn(error=error, fail_on='SELECT'), 'netcommand_test')
    for call in (s.tables, s.applied, lambda: s.columns('users')):
        with pytest.raises(expected) as err:
            call()
        assert "doesn't exist" not in str(err.value) and 'Lost connection' not in str(err.value)


def test_connect_errors_are_explained_without_secrets(monkeypatch):
    from backend.database import connection
    monkeypatch.setattr(pymysql, 'connect', lambda **kw: (_ for _ in ()).throw(
        pymysql.err.OperationalError(1045, f"Access denied for user 'm' (using password: YES) "
                                           f"{MIGRATE_SECRET}")))
    with pytest.raises(BackendDatabaseUnavailable) as err:
        connection.connect('127.0.0.1', 3307, 'm', MIGRATE_SECRET, 'netcommand_test')
    assert 'refused the account name or password' in str(err.value)
    assert MIGRATE_SECRET not in str(err.value) and 'Access denied' not in str(err.value)
    monkeypatch.setattr(pymysql, 'connect', lambda **kw: (_ for _ in ()).throw(TypeError('bug')))
    with pytest.raises(TypeError):                                 # a bug is not hidden
        connection.connect('127.0.0.1', 3307, 'm', 'p', 'netcommand_test')


# ================================================================ never on startup
def test_the_web_app_never_loads_the_migrations():
    code = ('import json, sys\n'
            'from fastapi.testclient import TestClient\n'
            'from backend.app import create_app\n'
            'from backend.settings import parse_settings\n'
            'TestClient(create_app(parse_settings({}))).get("/health")\n'
            'print(json.dumps(sorted(m for m in sys.modules if m.startswith("backend.database")'
            ' or m == "pymysql")))\n')
    env = {k: v for k, v in os.environ.items() if not k.startswith('BACKEND_')}
    env['NETCOMMAND_BACKEND_ENV_FILE'] = str(ROOT / 'tests' / 'backend' / 'no-such.env')
    out = subprocess.run([sys.executable, '-c', code], cwd=ROOT, env=env, capture_output=True,
                         text=True, timeout=120)
    assert out.returncode == 0, out.stderr
    assert json.loads(out.stdout.strip().splitlines()[-1]) == []


# ---------------------------------------------------------------- production flag (Phase 1)
@pytest.mark.parametrize('name', ['netcommand_test', 'netcommand_prod'])
def test_production_flag_is_refused_for_non_production_databases(monkeypatch, name):
    no_connection(monkeypatch)
    code, text = run_cli(['status', '--production', '--authorize-database', name],
                         settings_for(name))
    assert code == 2 and '--production was given' in text


def test_test_database_commands_are_unchanged_by_the_new_options():
    schema = FakeSchema()
    code, text = run_cli(['up', '--confirm-database', 'netcommand_test'], settings_for(), schema)
    assert code == 0 and 'Identity checked' not in text
    code, text = run_cli(['down', '--to', '0', '--confirm-database', 'netcommand_test'],
                         settings_for(), schema)
    assert 'restoring a verified backup' not in text   # the production rule does not apply
    assert 'administrator' in text                      # the existing audit_log rule does
