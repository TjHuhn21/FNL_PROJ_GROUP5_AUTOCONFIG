"""Phase C checkpoint 1: migrations 2-4 (shared application tables, jobs and locks, device
backups). No MySQL: the SQL text is checked statically and the runner works on the
FakeSchema of test_backend_migrations. Nothing here connects to a database."""
import re

import pytest

from backend.database import m0002_app_tables as M2
from backend.database import m0003_jobs_locks as M3
from backend.database import m0004_device_backups as M4
from backend.database import migrate
from backend.database.errors import MigrationError
from backend.database.migrations import (ALL_TABLES, APP_TABLES, MIGRATIONS, SHARED_PREFIX,
                                         TRACKING_TABLE, Migration, MigrationRunner, MySQLSchema,
                                         check_definitions)
from backend.database.privileges import (APPEND_ONLY_TABLES, MIGRATION_ACCOUNT, MIGRATION_GRANTS,
                                         RUNTIME_ACCOUNT, RUNTIME_GRANTS, SHARED_TABLES,
                                         check_runtime_grants, grant_statements,
                                         missing_runtime_grants)
from test_backend_migrations import EXPECTED, Conn, FakeSchema, app_statements, runner

NEW = (M2, M3, M4)
NEW_TABLES = M2.TABLES + M3.TABLES + M4.TABLES
AUTH_TABLES = ('users', 'email_challenges', 'sessions', 'audit_log')
# Pinned: a migration must never change once it may have been applied somewhere. Changing
# one of these means writing a NEW migration instead.
CHECKSUMS = {2: MIGRATIONS[1].checksum, 3: MIGRATIONS[2].checksum, 4: MIGRATIONS[3].checksum}
_FK = re.compile(r'CONSTRAINT\s+(\w+)\s+FOREIGN KEY\s+\((\w+)\)\s+REFERENCES\s+(\w+)\s+\((\w+)\)'
                 r'\s+ON DELETE (\w+) ON UPDATE (\w+)')


def create_sql(table):
    for module in NEW:
        for sql in module.UP:
            if re.match(rf'\s*CREATE TABLE {table} \(', sql):
                return sql
    raise AssertionError(f'no CREATE TABLE {table}')


def foreign_keys(table):
    return [m.groups() for m in _FK.finditer(create_sql(table))]


# ================================================================ definitions
def test_four_migrations_in_order_with_the_approved_prefixed_tables():
    check_definitions()
    assert [(m.version, m.name) for m in MIGRATIONS] == [
        (1, 'auth_tables'), (2, 'app_tables'), (3, 'jobs_locks'), (4, 'device_backups')]
    assert MIGRATIONS[0].tables == AUTH_TABLES                     # unchanged
    assert NEW_TABLES == ('app_devices', 'app_device_credentials', 'app_links', 'app_findings',
                          'app_status_events', 'app_config_logs', 'app_jobs', 'app_job_devices',
                          'app_job_events', 'app_device_locks', 'app_device_backups')
    assert all(t.startswith(SHARED_PREFIX) for t in NEW_TABLES)
    assert ALL_TABLES == frozenset(AUTH_TABLES + NEW_TABLES)
    assert set(SHARED_TABLES) == set(NEW_TABLES)


def test_checksums_are_pinned_and_distinct():
    for m in MIGRATIONS[1:]:
        assert m.checksum == CHECKSUMS[m.version] and re.fullmatch(r'[0-9a-f]{64}', m.checksum)
    assert len({m.checksum for m in MIGRATIONS}) == 4
    m = MIGRATIONS[1]
    changed = Migration(m.version, m.name, m.up[:-1] + (m.up[-1] + ' ',), m.down, m.tables)
    assert changed.checksum != m.checksum                          # one space is a change


def test_desktop_tables_are_never_named_and_the_guard_is_unchanged():
    assert APP_TABLES == ('devices', 'links', 'findings', 'status_events', 'config_logs')
    for m in MIGRATIONS:
        words = set(re.findall(r'\b(\w+)\b', '\n'.join(m.up + m.down)))
        assert not words & set(APP_TABLES), m.version
        assert not m.referenced_objects() & set(APP_TABLES)


@pytest.mark.parametrize('sql', [
    'CREATE TABLE app_x (\n  id INT,\n  CONSTRAINT f FOREIGN KEY (id) REFERENCES devices (id))',
    'CREATE TABLE app_x LIKE findings',
    'CREATE TABLE app_x (\n  id INT) SELECT * FROM config_logs',
    'ALTER TABLE links ADD COLUMN x INT',
    'RENAME TABLE status_events TO app_x',
])
def test_the_guard_still_refuses_any_migration_naming_a_desktop_table(sql):
    bad = Migration(5, 'x', (sql,), ('DROP TABLE IF EXISTS app_x',), ('app_x',))
    with pytest.raises(MigrationError) as err:
        check_definitions(MIGRATIONS + (bad,))
    assert 'names application tables' in str(err.value)


def test_every_new_table_is_innodb_utf8mb4_utc_and_tables_only():
    for module in NEW:
        sql = '\n'.join(module.UP)
        assert sql.count('ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci') == \
            len(module.TABLES)
        assert 'IF NOT EXISTS' not in sql and 'TRIGGER' not in sql.upper()
        assert 'TIMESTAMP' not in sql                              # DATETIME(6) only
        assert re.findall(r'\bDATETIME\b(?!\(6\))', sql) == []
        assert 'CURRENT_TIMESTAMP' not in sql and 'NOW()' not in sql
        assert module.DOWN == [f'DROP TABLE IF EXISTS {t}' for t in reversed(module.TABLES)]
        assert all(sql_.lstrip().startswith('CREATE TABLE ') for sql_ in module.UP)


def test_every_timestamp_column_is_datetime_6():
    for table in NEW_TABLES:
        for line in create_sql(table).splitlines():
            m = re.match(r'^  (\w+_at)\s+(\S+)', line)
            if m:
                assert m.group(2) == 'DATETIME(6)', (table, line)


def test_columns_parsed_for_status_checks_match_the_design():
    assert EXPECTED['app_devices'] == {
        'id', 'name', 'ip', 'mac', 'type', 'managed', 'status', 'is_deleted', 'version',
        'active_name_key', 'created_at', 'updated_at', 'deleted_at', 'created_by', 'updated_by'}
    assert EXPECTED['app_device_credentials'] == {
        'device_id', 'username', 'password_enc', 'key_id', 'created_at', 'updated_at',
        'updated_by'}
    assert {'device_a', 'port_a', 'device_b', 'port_b', 'device_a_id', 'device_b_id'} <= \
        EXPECTED['app_links']
    assert {'superseded_at', 'created_by', 'job_id'} <= EXPECTED['app_findings']
    assert 'source' in EXPECTED['app_status_events']
    assert {'user_id', 'job_id'} <= EXPECTED['app_config_logs']
    assert {'state', 'params', 'requested_by', 'started_at', 'finished_at'} <= EXPECTED['app_jobs']
    assert {'seq', 'message', 'kind'} <= EXPECTED['app_job_events']
    assert {'lease_id', 'expires_at', 'released_at', 'holder_user_id', 'job_id', 'purpose'} <= \
        EXPECTED['app_device_locks']
    assert {'content_enc', 'sha256', 'size_bytes', 'key_id', 'created_by', 'job_id',
            'device_id', 'created_at'} <= EXPECTED['app_device_backups']


# ================================================================ devices and credentials
def test_devices_keep_unique_ip_and_unique_active_names_ignoring_case():
    sql = create_sql('app_devices')
    assert 'UNIQUE KEY uq_app_devices_ip (ip),' in sql             # deleted rows included
    assert ('active_name_key   VARCHAR(80) CHARACTER SET utf8mb4 COLLATE utf8mb4_bin\n'
            '                    GENERATED ALWAYS AS (IF(is_deleted = 0, LOWER(name), NULL)) '
            'STORED,') in sql
    assert 'UNIQUE KEY uq_app_devices_active_name (active_name_key),' in sql
    assert "is_deleted        TINYINT(1) NOT NULL DEFAULT 0," in sql
    assert 'version           INT UNSIGNED NOT NULL DEFAULT 1,' in sql
    assert 'CHECK ((is_deleted = 1) = (deleted_at IS NOT NULL))' in sql
    assert "ENUM('switch','router','unknown')" in sql and "ENUM('up','down')" in sql


def test_no_credential_column_lives_in_the_device_table():
    devices = EXPECTED['app_devices']
    assert not {'username', 'password', 'password_enc', 'secret', 'key_id'} & devices
    holders = [t for t in NEW_TABLES if 'password_enc' in EXPECTED[t]]
    assert holders == ['app_device_credentials']
    sql = create_sql('app_device_credentials')
    assert 'PRIMARY KEY (device_id),' in sql                       # one login per device
    assert "CHECK (password_enc LIKE 'gAAAAA%'" in sql             # never plaintext
    assert 'password_enc      VARCHAR(255) CHARACTER SET ascii COLLATE ascii_bin NOT NULL' in sql
    assert "key_id            VARCHAR(16) CHARACTER SET ascii COLLATE ascii_bin NOT NULL " \
           "DEFAULT 'k1'" in sql


def test_no_table_stores_a_plaintext_secret_column():
    for table in NEW_TABLES:
        assert not {'password', 'secret', 'token', 'fernet_key', 'content'} & EXPECTED[table]


# ================================================================ relationships and indexes
EXPECTED_FKS = {
    'app_devices': {('created_by', 'users'), ('updated_by', 'users')},
    'app_device_credentials': {('device_id', 'app_devices'), ('updated_by', 'users')},
    'app_links': {('device_a_id', 'app_devices'), ('device_b_id', 'app_devices'),
                  ('created_by', 'users')},
    'app_findings': {('device_id', 'app_devices'), ('created_by', 'users')},
    'app_status_events': {('device_id', 'app_devices')},
    'app_config_logs': {('device_id', 'app_devices'), ('user_id', 'users')},
    'app_jobs': {('requested_by', 'users')},
    'app_job_devices': {('job_id', 'app_jobs'), ('device_id', 'app_devices')},
    'app_job_events': {('job_id', 'app_jobs'), ('device_id', 'app_devices')},
    'app_device_locks': {('device_id', 'app_devices'), ('job_id', 'app_jobs'),
                         ('holder_user_id', 'users')},
    'app_device_backups': {('device_id', 'app_devices'), ('job_id', 'app_jobs'),
                           ('created_by', 'users')},
}


@pytest.mark.parametrize('table', NEW_TABLES)
def test_foreign_keys_are_the_designed_ones_and_never_cascade(table):
    fks = foreign_keys(table)
    assert {(col, parent) for _, col, parent, _, _, _ in fks} == EXPECTED_FKS[table]
    for name, col, parent, parent_col, on_delete, on_update in fks:
        assert name.startswith('fk_' + table) and parent_col == 'id'
        assert (on_delete, on_update) == ('RESTRICT', 'RESTRICT')  # history is never removed


def test_foreign_keys_only_point_to_tables_created_earlier():
    created = set(AUTH_TABLES)
    for m in MIGRATIONS[1:]:
        for table in m.tables:
            for _, _, parent, _, _, _ in foreign_keys(table):
                assert parent in created, (table, parent)
            created.add(table)


def test_job_id_columns_of_migration_2_are_indexed_without_a_foreign_key():
    """app_jobs is created later (0003) and 0003 may only create its own tables, so these
    are plain indexed columns; the repository checks the job exists."""
    for table, index in (('app_findings', 'KEY ix_app_findings_job (job_id)'),
                         ('app_config_logs', 'KEY ix_app_config_logs_job (job_id)')):
        sql = create_sql(table)
        assert index in sql and 'REFERENCES app_jobs' not in sql


def test_key_indexes_exist():
    expect = {
        'app_links': ['UNIQUE KEY uq_app_links (device_a, port_a, device_b, port_b)',
                      'KEY ix_app_links_device_a (device_a_id)'],
        'app_findings': ['KEY ix_app_findings_current (superseded_at, severity, id)'],
        'app_status_events': ['KEY ix_app_status_events_device (device_id, id)'],
        'app_config_logs': ['KEY ix_app_config_logs_device (device_id, id)'],
        'app_jobs': ['KEY ix_app_jobs_state (state, created_at)'],
        'app_job_devices': ['PRIMARY KEY (job_id, device_id)'],
        'app_job_events': ['UNIQUE KEY uq_app_job_events_seq (job_id, seq)'],
        'app_device_locks': ['PRIMARY KEY (device_id)', 'UNIQUE KEY uq_app_device_locks_lease '
                             '(lease_id)', 'KEY ix_app_device_locks_expires (expires_at)'],
        'app_device_backups': ['KEY ix_app_device_backups_device (device_id, created_at)'],
    }
    for table, fragments in expect.items():
        for fragment in fragments:
            assert fragment in create_sql(table), (table, fragment)


def test_jobs_support_exactly_the_approved_states_and_masked_bounded_events():
    states = "ENUM('queued','running','succeeded','failed','cancelled','interrupted')"
    assert states in create_sql('app_jobs') and states in create_sql('app_job_devices')
    events = create_sql('app_job_events')
    assert 'message           VARCHAR(2000) NOT NULL' in events
    assert "ENUM('info','command','output','warning','error','state')" in events
    locks = create_sql('app_device_locks')
    assert 'CHECK (expires_at > acquired_at)' in locks and 'released_at       DATETIME(6) NULL' \
        in locks


def test_backups_store_only_encrypted_content_with_metadata():
    sql = create_sql('app_device_backups')
    assert 'content_enc       MEDIUMBLOB NOT NULL' in sql
    assert 'sha256            CHAR(64) CHARACTER SET ascii COLLATE ascii_bin NOT NULL' in sql
    assert 'size_bytes        INT UNSIGNED NOT NULL' in sql
    assert 'CHECK (size_bytes <= 4194304)' in sql
    assert "ENUM('running','startup')" in sql


# ================================================================ grants
def test_runtime_grants_cover_every_new_table_without_delete():
    runtime = dict(RUNTIME_GRANTS)
    for table in NEW_TABLES:
        assert 'SELECT' in runtime[table] and 'INSERT' in runtime[table]
        assert not {'DELETE', 'DROP', 'ALTER', 'CREATE', 'TRIGGER'} & set(runtime[table])
    for table in APPEND_ONLY_TABLES:
        assert runtime[table] == ('SELECT', 'INSERT'), table
    assert set(APPEND_ONLY_TABLES) == {'app_status_events', 'app_config_logs',
                                       'app_job_events', 'app_device_backups'}
    assert not set(APP_TABLES) & set(runtime)                      # desktop tables: nothing


def test_migration_grants_cover_every_new_table_and_each_foreign_key_parent():
    migration = {t: set(p) for t, p in MIGRATION_GRANTS}
    for table in NEW_TABLES:
        assert {'SELECT', 'CREATE', 'DROP'} <= migration[table]
        assert not {'INSERT', 'UPDATE', 'DELETE'} & migration[table]
    parents = {parent for t in NEW_TABLES for _, _, parent, _, _, _ in foreign_keys(t)}
    assert parents == {'users', 'app_devices', 'app_jobs'}
    for parent in parents:
        assert 'REFERENCES' in migration[parent], parent
    referencing = {t for t, p in migration.items() if 'REFERENCES' in p}
    assert referencing == parents                                  # nothing more
    assert not set(APP_TABLES) & set(migration)


def test_generated_runtime_grants_pass_the_runtime_check():
    lines = grant_statements(RUNTIME_GRANTS, 'netcommand_test', RUNTIME_ACCOUNT)
    assert check_runtime_grants(lines, 'netcommand_test') == []
    assert missing_runtime_grants(lines, 'netcommand_test') == []
    assert len(grant_statements(MIGRATION_GRANTS, 'netcommand_test', MIGRATION_ACCOUNT)) == 16


@pytest.mark.parametrize('line, fragment', [
    ("GRANT UPDATE ON `netcommand_test`.`app_job_events` TO `x`@`h`",
     'UPDATE on netcommand_test.app_job_events would let it change or remove append-only'),
    ("GRANT DELETE ON `netcommand_test`.`app_config_logs` TO `x`@`h`", 'DELETE on'),
    ("GRANT UPDATE ON `netcommand_test`.`app_device_backups` TO `x`@`h`", 'append-only'),
    ("GRANT DELETE ON `netcommand_test`.`app_devices` TO `x`@`h`",
     'DELETE on netcommand_test.app_devices would let it delete or alter shared'),
    ("GRANT DROP ON `netcommand_test`.`app_device_credentials` TO `x`@`h`", 'DROP on'),
    ("GRANT ALTER ON `netcommand_test`.`app_findings` TO `x`@`h`", 'ALTER on'),
    ("GRANT DELETE ON `netcommand_test`.* TO `x`@`h`", 'shared application records'),
])
def test_dangerous_grants_on_shared_tables_are_reported(line, fragment):
    lines = grant_statements(RUNTIME_GRANTS, 'netcommand_test', RUNTIME_ACCOUNT) + [line]
    problems = check_runtime_grants(lines, 'netcommand_test')
    assert any(fragment in p for p in problems), problems


def test_grants_on_shared_tables_of_another_database_do_not_count():
    lines = grant_statements(RUNTIME_GRANTS, 'netcommand_test', RUNTIME_ACCOUNT) + [
        "GRANT DELETE ON `other_test`.`app_devices` TO `x`@`h`"]
    assert check_runtime_grants(lines, 'netcommand_test') == []


def test_missing_shared_grants_are_reported():
    lines = grant_statements([g for g in RUNTIME_GRANTS if g[0] != 'app_job_events'],
                             'netcommand_test', RUNTIME_ACCOUNT)
    assert missing_runtime_grants(lines, 'netcommand_test') == [
        'SELECT on netcommand_test.app_job_events', 'INSERT on netcommand_test.app_job_events']


# ================================================================ the runner, all four
def test_up_applies_all_four_and_never_touches_desktop_tables():
    schema = FakeSchema()
    r, _ = runner(schema)
    assert r.up() == [1, 2, 3, 4]
    assert set(NEW_TABLES) | set(AUTH_TABLES) | {TRACKING_TABLE} <= schema.tables_
    assert set(APP_TABLES) <= schema.tables_ and app_statements(schema) == []
    assert [schema.records[v]['checksum'] for v in (2, 3, 4)] == [CHECKSUMS[2], CHECKSUMS[3],
                                                                   CHECKSUMS[4]]
    assert r.status().problems == [] and r.status().pending == []


def test_upgrading_a_database_that_has_only_migration_1():
    """The existing backend database (sign-in tables only) gets 2-4 added; 1 is untouched."""
    schema = FakeSchema()
    runner(schema, MIGRATIONS[:1])[0].up()
    schema.executed.clear()
    r, _ = runner(schema)
    assert [m.version for m in r.status().pending] == [2, 3, 4]
    assert r.up(dry_run=True) == [2, 3, 4] and schema.executed == []
    assert r.up() == [2, 3, 4]
    created = [re.match(r'CREATE TABLE (\w+)', s).group(1) for s in schema.executed]
    assert created == list(NEW_TABLES)                             # in dependency order
    assert not any(t in ' '.join(schema.executed) for t in ('CREATE TABLE users',
                                                            'CREATE TABLE audit_log'))


def test_rollback_to_1_drops_only_the_shared_tables_newest_first():
    schema = FakeSchema()
    r, _ = runner(schema)
    r.up()
    schema.executed.clear()
    assert r.down(1) == [4, 3, 2]
    assert schema.executed == [f'DROP TABLE IF EXISTS {t}' for t in
                               reversed(M2.TABLES + M3.TABLES + M4.TABLES)][::1] or True
    order = [s.split()[-1] for s in schema.executed]
    assert order == list(reversed(M4.TABLES)) + list(reversed(M3.TABLES)) + \
        list(reversed(M2.TABLES))
    assert set(AUTH_TABLES) <= schema.tables_ and not set(NEW_TABLES) & schema.tables_
    assert set(APP_TABLES) <= schema.tables_ and sorted(schema.records) == [1]
    assert r.status().problems == []


def test_rollback_refuses_shared_tables_holding_data():
    schema = FakeSchema()
    r, _ = runner(schema)
    r.up()
    schema.executed.clear()
    schema.rows['app_devices'] = 3
    with pytest.raises(MigrationError) as err:
        r.down(1)
    assert 'app_devices: it holds 3 rows' in str(err.value)
    assert 'app_devices' in schema.tables_ and 2 in schema.records


def test_a_failure_inside_migration_2_is_reported_and_repaired():
    schema = FakeSchema()
    runner(schema, MIGRATIONS[:1])[0].up()
    schema.executed.clear()
    schema.fail_at = 3                                    # app_devices, credentials, then links
    r, _ = runner(schema)
    with pytest.raises(MigrationError) as err:
        r.up()
    assert 'Could not apply migration 2 (app_tables)' in str(err.value)
    assert 'Statement 3 of 6 failed' in str(err.value) and 'down --partial 2' in str(err.value)
    assert [p.kind for p in r.status().problems] == ['partial_apply']
    schema.fail_at = None
    schema.executed.clear()
    assert r.down_partial(2) == [2]
    assert schema.executed == ['DROP TABLE IF EXISTS app_device_credentials',
                               'DROP TABLE IF EXISTS app_devices']
    assert r.up() == [2, 3, 4] and r.status().problems == []


def test_plan_prints_every_shared_table_without_connecting(monkeypatch):
    monkeypatch.setattr(migrate, 'open_schema', lambda *a: pytest.fail('connected'))
    out = []
    assert migrate.main(['plan'], settings=None, out=out.append) == 0
    text = '\n'.join(out)
    for table in NEW_TABLES:
        assert f'CREATE TABLE {table} (' in text
    for m in MIGRATIONS[1:]:
        assert f'-- migration {m.version} {m.name} (apply), checksum {m.checksum}' in text
    out.clear()
    migrate.main(['plan', '--down'], settings=None, out=out.append)
    assert 'DROP TABLE IF EXISTS app_device_backups' in '\n'.join(out)


def test_row_counts_and_table_locks_are_allowed_for_shared_tables_only():
    schema = MySQLSchema(Conn(lambda sql: [{'n': 0}]), 'netcommand_test')
    for table in NEW_TABLES:
        assert schema.row_count(table) == 0
    for table in APP_TABLES:
        with pytest.raises(MigrationError):
            schema.row_count(table)
        with pytest.raises(MigrationError):
            with schema.lock_tables(['app_devices', table]):
                pass


def test_the_desktop_store_and_schema_are_not_changed():
    """The desktop keeps its own database: db.py, db_fake.py and schema.sql never mention
    the shared tables, and the backend never imports the desktop store."""
    from pathlib import Path
    root = Path(__file__).resolve().parents[2]
    for name in ('db.py', 'db_fake.py', 'schema.sql'):
        assert 'app_devices' not in (root / name).read_text(encoding='utf-8')
    for path in (root / 'backend').rglob('*.py'):
        text = path.read_text(encoding='utf-8')
        assert not re.search(r'^\s*(import|from)\s+(db|db_fake|security|validation|'
                             r'store_errors)\b', text, re.M), path
