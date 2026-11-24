"""Versioned migrations for the backend's own tables.

Rules enforced here (each refusal raises MigrationError before anything is changed):
  * migrations are applied in version order, each exactly once, and recorded in
    schema_migrations (version, name, checksum, applied_at UTC, applied_by). The checksum
    covers the name, the up AND down SQL and the table list;
  * the recorded state must match the code: no unknown versions, no gaps, no changed
    checksums, schema_migrations itself must have the expected columns, and the tables of
    an applied migration must have the expected columns;
  * a migration's tables must not exist before it runs unless it is recorded as applied
    (an unrecorded table is a partial or foreign state: refused, never recreated);
  * no migration may name one of the five DESKTOP application tables (devices, links,
    findings, status_events, config_logs: the desktop database's own tables), nor create
    triggers, routines or events (those need administrator privilege: see
    audit_triggers.py). The shared application data of Phase C uses NEW tables with the
    app_ prefix (app_devices, ...), so this guard is unchanged;
  * MySQL commits every CREATE/DROP immediately, so a migration is NOT one transaction.
    A failed statement is reported with what is known about it: if the connection was
    lost, MySQL may or may not have completed it (`status` shows the real state);
  * down locks the tables it will drop (LOCK TABLES ... WRITE) before checking that they
    are empty, so no write can slip in between the check and the DROP. It still refuses
    tables holding data unless allow_data_loss, and audit history unless
    allow_audit_history_loss as well;
  * an interrupted rollback (tables already dropped, bookkeeping row still there) is
    finished by running the same `down` again;
  * a database lock (GET_LOCK, one per database) keeps two runners apart.

The runner talks to the database through a Schema object (MySQLSchema below, or a fake
in the tests), so all of these rules are tested without MySQL.
"""
import hashlib
import json
import re
from contextlib import contextmanager
from dataclasses import dataclass, field

from backend.database import (audit_triggers, m0001_auth_tables, m0002_app_tables,
                              m0003_jobs_locks, m0004_device_backups,
                              m0005_device_login_security)
from backend.database.connection import is_connection_lost, is_driver_error, translate
from backend.database.errors import MigrationError
from backend.database.privileges import can_see_triggers

# The desktop database's own tables (schema.sql). Never named by any migration.
APP_TABLES = ('devices', 'links', 'findings', 'status_events', 'config_logs')
DESKTOP_TABLES = APP_TABLES
# Every shared application table created by the backend starts with this prefix.
SHARED_PREFIX = 'app_'
MAIN_DATABASE = 'netcommand'
TEST_SUFFIX = '_test'
TRACKING_TABLE = 'schema_migrations'
LOCK_PREFIX = 'netcommand_migrations:'

TRACKING_DDL = """CREATE TABLE IF NOT EXISTS schema_migrations (
  version    INT UNSIGNED NOT NULL,
  name       VARCHAR(100) NOT NULL,
  checksum   CHAR(64) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
  applied_at DATETIME(6) NOT NULL,
  applied_by VARCHAR(100) NOT NULL,
  PRIMARY KEY (version)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci"""
# information_schema.COLUMNS.COLUMN_TYPE values the tracking table must have.
TRACKING_COLUMNS = {'version': 'int unsigned', 'name': 'varchar(100)', 'checksum': 'char(64)',
                    'applied_at': 'datetime(6)', 'applied_by': 'varchar(100)'}

# Object names after these keywords are checked against the application tables.
_OBJECT = re.compile(r'(?i)\b(?:TABLE|TABLES|INTO|UPDATE|FROM|JOIN|ON|REFERENCES|TRUNCATE|'
                     r'TO|LIKE|VIEW)\s+(?:IF\s+(?:NOT\s+)?EXISTS\s+)?`?([A-Za-z_][A-Za-z0-9_]*)`?')
_NOT_IN_UP = re.compile(r'(?i)^\s*(DROP|TRUNCATE|DELETE|RENAME)\b|'
                        r'\bCREATE\s+(?:DEFINER\s*=\s*\S+\s+)?(TRIGGER|PROCEDURE|FUNCTION|EVENT)\b')
_COLUMN = re.compile(r'^\s{2}([a-z_][a-z0-9_]*)\s+[A-Z]', re.M)
_CREATE = re.compile(r'(?is)^\s*CREATE\s+TABLE\s+`?(\w+)`?\s*\((.*)\)')


@dataclass(frozen=True)
class Migration:
    version: int
    name: str
    up: tuple
    down: tuple
    tables: tuple

    @property
    def checksum(self):
        payload = json.dumps({'name': self.name, 'up': list(self.up), 'down': list(self.down),
                              'tables': list(self.tables)}, sort_keys=True)
        return hashlib.sha256(payload.encode('utf-8')).hexdigest()

    def referenced_objects(self):
        return {m.group(1).lower() for sql in self.up + self.down for m in _OBJECT.finditer(sql)}

    def expected_columns(self):
        """{table: {column names}} from this migration's CREATE TABLE statements."""
        found = {}
        for sql in self.up:
            m = _CREATE.match(sql)
            if m:
                found[m.group(1).lower()] = set(_COLUMN.findall(m.group(2)))
        return found


def _from_module(module):
    return Migration(module.VERSION, module.NAME, tuple(module.UP), tuple(module.DOWN),
                     tuple(module.TABLES))


MIGRATIONS = tuple(_from_module(m) for m in (m0001_auth_tables, m0002_app_tables,
                                             m0003_jobs_locks, m0004_device_backups,
                                             m0005_device_login_security))
ALL_TABLES = frozenset(t for m in MIGRATIONS for t in m.tables)


def check_definitions(migrations=MIGRATIONS):
    """Static checks of the migration code itself (run before any connection)."""
    problems = []
    versions = [m.version for m in migrations]
    if versions != sorted(versions) or len(set(versions)) != len(versions):
        problems.append('Migration versions must be unique and in increasing order.')
    if versions and versions != list(range(1, len(versions) + 1)):
        problems.append('Migration versions must be 1, 2, 3, ... without gaps.')
    owners = {}
    for m in migrations:
        protected = sorted(m.referenced_objects() & set(APP_TABLES))
        if protected:
            problems.append(f'Migration {m.version} names application tables: '
                            f'{", ".join(protected)}.')
        if TRACKING_TABLE in m.tables:
            problems.append(f'Migration {m.version} may not create {TRACKING_TABLE}.')
        for t in m.tables:
            if t in owners:
                problems.append(f'Table {t} is created by migrations {owners[t]} and {m.version}.')
            owners[t] = m.version
        for sql in m.up:
            if re.search(r'(?i)\bIF\s+NOT\s+EXISTS\b', sql):
                problems.append(f'Migration {m.version} uses IF NOT EXISTS (would hide an '
                                f'existing table).')
            if _NOT_IN_UP.search(sql):
                problems.append(f'Migration {m.version} has a destructive or administrator-only '
                                f'statement in up (DROP/TRUNCATE/DELETE/RENAME, or CREATE '
                                f'TRIGGER/PROCEDURE/FUNCTION/EVENT).')
        for sql in m.down:
            match = re.match(r'(?i)^\s*DROP\s+TABLE\s+IF\s+EXISTS\s+(\w+)\s*$', sql)
            if not match or match.group(1) not in m.tables:
                problems.append(f'Migration {m.version} down may only drop its own tables: '
                                f'{sql.splitlines()[0][:60]}')
        missing = set(m.tables) - set(m.expected_columns())
        if missing:
            problems.append(f'Migration {m.version} lists tables it does not create: '
                            f'{", ".join(sorted(missing))}.')
    if problems:
        raise MigrationError('Invalid migration definitions: ' + ' '.join(problems))


def check_database_name(name, authorized=None, allow_main_database=False, action='migrate'):
    """Allowed by default: names ending in _test. Any other name must be repeated with
    --authorize-database NAME; the main database also needs --allow-main-database.
    action: the verb used in the messages (the bootstrap command passes its own)."""
    if not name:
        raise MigrationError('No database name is configured (BACKEND_DB_NAME).')
    lower = name.lower()
    if lower == MAIN_DATABASE:
        if not (allow_main_database and authorized == name):
            raise MigrationError(f"Refusing to {action} '{name}', the main NetCommand database. "
                                 f"It needs a backup and explicit approval first, then both "
                                 f"--authorize-database {name} and --allow-main-database.")
        return
    if lower.endswith(TEST_SUFFIX) and len(lower) > len(TEST_SUFFIX):
        return
    if authorized != name:
        raise MigrationError(f"'{name}' does not end in '{TEST_SUFFIX}', so it is not a test "
                             f"database. To {action} it anyway, add --authorize-database {name}.")


# ---------------------------------------------------------------- state
@dataclass(frozen=True)
class Problem:
    kind: str          # tracking_structure, unknown_version, checksum, name, order,
    message: str       # partial_apply, interrupted_rollback, columns
    version: int = None


@dataclass
class AuditProtection:
    state: str                         # protected | not_protected | unknown | no_audit_table
    details: list = field(default_factory=list)

    @property
    def protected(self):
        return self.state == 'protected'


@dataclass
class Status:
    applied: list
    pending: list
    problems: list
    tracking_table: bool
    audit: AuditProtection

    def messages(self, kinds=None):
        return [p.message for p in self.problems if kinds is None or p.kind in kinds]


class MigrationRunner:
    """Plans and applies migrations through a Schema (see MySQLSchema)."""

    def __init__(self, schema, migrations=MIGRATIONS, log=print):
        check_definitions(migrations)
        self.schema, self.migrations, self.log = schema, tuple(migrations), log

    # ------------------------------------------------------------ inspection (read-only)
    def status(self):
        tables = {t.lower() for t in self.schema.tables()}
        tracking = TRACKING_TABLE in tables
        problems, applied = [], []
        if tracking:
            columns = {k.lower(): v.lower() for k, v in self.schema.columns(TRACKING_TABLE).items()}
            if columns != TRACKING_COLUMNS:
                problems.append(Problem('tracking_structure', f'{TRACKING_TABLE} exists but does '
                                        f'not have the expected columns; it was not created by '
                                        f'this tool and is not used.'))
            else:
                applied = self.schema.applied()
        known = {m.version: m for m in self.migrations}
        for a in applied:
            m = known.get(a['version'])
            if m is None:
                problems.append(Problem('unknown_version', f"Version {a['version']} "
                                        f"({a['name']}) is recorded as applied but is not known "
                                        f"to this code.", a['version']))
            elif a['name'] != m.name:
                problems.append(Problem('name', f'Version {m.version} is recorded under another '
                                        f'name.', m.version))
            elif a['checksum'] != m.checksum:
                problems.append(Problem('checksum', f'Version {m.version} ({m.name}) was changed '
                                        f'after it was applied (checksum differs).', m.version))
        versions = [a['version'] for a in applied]
        if versions != list(range(1, len(versions) + 1)):
            problems.append(Problem('order', 'The applied versions are not 1, 2, 3, ... in order.'))
        done = set(versions)
        for m in self.migrations:
            present = [t for t in m.tables if t in tables]
            if m.version in done:
                missing = [t for t in m.tables if t not in tables]
                if missing:
                    problems.append(Problem('interrupted_rollback', f'Version {m.version} is '
                                            f'recorded as applied but its tables are missing '
                                            f'({", ".join(missing)}): a rollback was interrupted. '
                                            f'Run the same `down` again to finish it.', m.version))
                else:
                    for t, expected in m.expected_columns().items():
                        actual = {c.lower() for c in self.schema.columns(t)}
                        if actual != expected:
                            problems.append(Problem('columns', f'Table {t} does not have the '
                                                    f'columns migration {m.version} created.',
                                                    m.version))
            elif present:
                problems.append(Problem('partial_apply', f'Version {m.version} ({m.name}) is not '
                                        f'recorded, but its tables already exist: '
                                        f'{", ".join(present)}. They are never recreated; see '
                                        f'`down --partial {m.version}`.', m.version))
        pending = [m for m in self.migrations if m.version not in done]
        return Status(applied, pending, problems, tracking, self._audit(tables))

    def _audit(self, tables):
        if audit_triggers.TABLE not in tables:
            return AuditProtection('no_audit_table')
        visible, rows = self.schema.triggers()
        if not visible:
            return AuditProtection('unknown', ['this account cannot see triggers (grant it '
                                               'TRIGGER on audit_log, or check as an '
                                               'administrator)'])
        details = audit_triggers.verify(rows)
        return AuditProtection('not_protected' if details else 'protected', details)

    def plan_up(self, target=None):
        st = self._consistent(st=self.status())
        target = self._target(target)
        return [m for m in st.pending if m.version <= target]

    def plan_down(self, target):
        if target < 0:
            raise MigrationError('The target version cannot be negative.')
        st = self._consistent(st=self.status(), allow=('interrupted_rollback',))
        applied = {a['version'] for a in st.applied}
        return [m for m in reversed(self.migrations) if m.version in applied and m.version > target]

    # ------------------------------------------------------------ changes
    def up(self, target=None, dry_run=False):
        """Apply pending migrations up to target (default: all). Returns the versions."""
        with self.schema.lock():
            plan = self.plan_up(target)
            if dry_run:
                for m in plan:
                    self.log(f'[dry run] would apply {m.version} {m.name}: '
                             f'{len(m.up)} statements, creates {", ".join(m.tables)}')
                return [m.version for m in plan]
            if plan and not self.status().tracking_table:
                self._execute(TRACKING_DDL, f'create {TRACKING_TABLE}')
                self.log(f'Created {TRACKING_TABLE}.')
            for m in plan:
                self._apply(m)
            if plan and audit_triggers.TABLE in {t for m in plan for t in m.tables}:
                self.log('NOTE: audit_log is NOT yet protected by its triggers. An administrator '
                         'must install them: `python -m backend.database.migrate '
                         'audit-triggers-sql` prints the SQL. `status` shows when it is done.')
            return [m.version for m in plan]

    def down(self, target, dry_run=False, allow_data_loss=False, allow_audit_history_loss=False):
        """Roll back applied migrations above target, newest first. audit_log is never dropped
        by this account: while it exists the rollback stops before dropping anything (an
        administrator removes it first; see _require_audit_log_removed)."""
        with self.schema.lock():
            plan = self.plan_down(target)
            for m in plan:
                self._require_audit_log_removed(m, self._existing(m), f'down --to {target}')
            if dry_run:
                for m in plan:
                    existing = self._existing(m)
                    self._check_can_drop(existing, allow_data_loss, allow_audit_history_loss)
                    self.log(f'[dry run] would roll back {m.version} {m.name}: drops '
                             f'{", ".join(reversed(existing)) or "nothing (already dropped)"}')
                return [m.version for m in plan]
            for m in plan:
                existing = self._existing(m)
                with self.schema.lock_tables(existing + [TRACKING_TABLE]):
                    # Under the write lock: nobody can add rows between this check and DROP.
                    self._check_can_drop(existing, allow_data_loss, allow_audit_history_loss)
                    self._run(m, self._drops(m, existing), 'roll back')
                    try:
                        self.schema.forget(m.version)
                    except Exception as err:
                        raise MigrationError(
                            f'The tables of migration {m.version} were removed, but its '
                            f'bookkeeping row could not be deleted ({self._describe(err)}). Run '
                            f'the same `down` command again: it finishes the rollback.') from None
                self.log(f'Rolled back {m.version} {m.name}.')
            return [m.version for m in plan]

    def down_partial(self, version, dry_run=False):
        """Repair a migration that failed half-way (NOT recorded): drop only its own tables,
        and only if every one of them is empty."""
        with self.schema.lock():
            m = next((x for x in self.migrations if x.version == version), None)
            if m is None:
                raise MigrationError(f'Unknown migration version {version}.')
            st = self.status()
            if any(a['version'] == version for a in st.applied):
                raise MigrationError(f'Version {version} is recorded as applied: use down, '
                                     f'not --partial.')
            other = [p for p in st.problems
                     if not (p.kind == 'partial_apply' and p.version == version)]
            if other:
                raise MigrationError('The migration state has other problems; nothing was run. '
                                     + ' '.join(p.message for p in other))
            existing = self._existing(m)
            self._require_audit_log_removed(m, existing, f'down --partial {version}')
            if dry_run:
                self._check_can_drop(existing, False, False)
                self.log(f'[dry run] would remove the partial objects of {m.version} {m.name}: '
                         f'{", ".join(reversed(existing)) or "nothing"}')
                return [version]
            with self.schema.lock_tables(existing):
                self._check_can_drop(existing, False, False)
                self._run(m, self._drops(m, existing), 'repair')
            self.log(f'Removed the partial objects of {m.version} {m.name}.')
            return [version]

    # ------------------------------------------------------------ internals
    def _require_audit_log_removed(self, m, existing, command):
        """The migration account deliberately has no DROP on audit_log, so it can never
        destroy audit history. While audit_log still exists, stop BEFORE dropping anything
        (no table is touched) and say what the administrator must do. Once an administrator
        has removed audit_log, the same command finishes the rest (an interrupted-rollback
        state for `down`; fewer tables for `down --partial`)."""
        table = audit_triggers.TABLE
        if table not in m.tables or table not in existing:
            return
        rows = self.schema.row_count(table)
        held = (f'It holds {rows} audit record{"" if rows == 1 else "s"}: an administrator must '
                f'archive them first if they must be kept, then drop the table.' if rows else
                'It is empty, but only an administrator may drop it.')
        raise MigrationError(
            f'Rollback stopped before dropping anything: {table} still exists. The migration '
            f'account deliberately has no DROP privilege on {table}, so removing audit history '
            f'is an administrator step. {held} Administrator: DROP TABLE '
            f'`{self.schema_database()}`.{table}; (this also removes its triggers). Then run '
            f'`{command}` again: it removes the remaining tables. No table was changed.')

    def schema_database(self):
        return getattr(self.schema, 'database', '<database>')

    def _consistent(self, st, allow=()):
        blocking = [p for p in st.problems if p.kind not in allow]
        if blocking:
            raise MigrationError('The migration state is inconsistent; nothing was run. '
                                 + ' '.join(p.message for p in blocking))
        return st

    def _target(self, target):
        last = self.migrations[-1].version if self.migrations else 0
        if target is None:
            return last
        if target < 0 or target > last:
            raise MigrationError(f'Unknown target version {target} (known: 0 to {last}).')
        return target

    def _existing(self, m):
        tables = {t.lower() for t in self.schema.tables()}
        return [t for t in m.tables if t in tables]

    @staticmethod
    def _drops(m, existing):
        """m.down limited to tables that still exist. Only those are write-locked, and under
        LOCK TABLES MySQL refuses a statement that names a table that is not locked (which
        may include DROP TABLE IF EXISTS of an already-dropped table), so an interrupted
        rollback or a partial repair must not mention the tables already gone."""
        keep = []
        for sql in m.down:
            match = re.match(r'(?i)^\s*DROP\s+TABLE\s+IF\s+EXISTS\s+(\w+)\s*$', sql)
            if match and match.group(1) in existing:
                keep.append(sql)
        return keep

    def _apply(self, m):
        clash = self._existing(m)
        if clash:                                      # checked again just before running
            raise MigrationError(f'Tables already exist, nothing was run for {m.version}: '
                                 f'{", ".join(clash)}.')
        self._run(m, m.up, 'apply')
        try:
            self.schema.record(m.version, m.name, m.checksum)
        except Exception as err:
            raise MigrationError(
                f'Migration {m.version} ran completely, but recording it failed '
                f'({self._describe(err)}). Its tables exist but are not recorded: run `status`, '
                f'then `down --partial {m.version}` and `up` again.') from None
        self.log(f'Applied {m.version} {m.name}.')

    @staticmethod
    def _describe(err):
        return f'{type(err).__name__}: {err}'

    def _execute(self, sql, what):
        try:
            self.schema.execute(sql)
        except Exception as err:
            raise MigrationError(f'Could not {what} ({self._describe(err)}).') from None

    def _run(self, m, statements, verb):
        for i, sql in enumerate(statements, 1):
            try:
                self.schema.execute(sql)
            except Exception as err:
                done = (f'Statements 1 to {i - 1} had already run and were committed by MySQL '
                        f'(DDL cannot be rolled back).' if i > 1 else 'No earlier statement ran.')
                if is_connection_lost(err):
                    fate = (f'The connection was lost during statement {i} of {len(statements)}: '
                            f'MySQL may or may not have completed it (each CREATE/DROP TABLE either '
                            f'happens completely or not at all).')
                else:
                    fate = (f'Statement {i} of {len(statements)} failed and was not applied '
                            f'({self._describe(err)}).')
                after = (f'Run `status` to see the real state, then `down --partial {m.version}` '
                         f'to remove what was created.' if verb == 'apply' else
                         'Running the same command again finishes it (it only drops what still '
                         'exists).')
                raise MigrationError(f'Could not {verb} migration {m.version} ({m.name}). '
                                     f'{fate} {done} {after}') from None

    def _check_can_drop(self, existing, allow_data_loss, allow_audit_history_loss):
        for t in existing:
            rows = self.schema.row_count(t)
            if not rows:
                continue
            if t == audit_triggers.TABLE and not allow_audit_history_loss:
                raise MigrationError(f'Refusing to remove audit_log: it holds {rows} audit '
                                     f'records. Audit history is never removed by accident.')
            if not allow_data_loss:
                raise MigrationError(f'Refusing to remove {t}: it holds {rows} rows. Nothing '
                                     f'was changed.')


# ---------------------------------------------------------------- MySQL access
def _db_errors(method):
    """Driver errors from a MySQLSchema method become BackendDatabaseUnavailable /
    BackendDatabaseError (messages without SQL values)."""
    def wrapper(self, *args, **kwargs):
        try:
            return method(self, *args, **kwargs)
        except Exception as err:
            if is_driver_error(err):
                raise translate(err, where=self.database) from None
            raise
    wrapper.__name__, wrapper.__doc__ = method.__name__, method.__doc__
    return wrapper


class MySQLSchema:
    """The runner's view of a real MySQL database (one connection, autocommit off).
    It only reads information_schema / schema_migrations / SHOW GRANTS, runs the migration
    statements, locks and counts the migration's own tables, and writes schema_migrations."""

    def __init__(self, conn, database):
        self.conn, self.database = conn, database

    def _query(self, sql, params=()):
        with self.conn.cursor() as cur:
            cur.execute(sql, params)
            return list(cur.fetchall())

    @_db_errors
    def tables(self):
        rows = self._query('SELECT TABLE_NAME AS name FROM information_schema.TABLES '
                           'WHERE TABLE_SCHEMA = %s', (self.database,))
        return [r['name'] for r in rows]

    @_db_errors
    def columns(self, table):
        rows = self._query('SELECT COLUMN_NAME AS name, COLUMN_TYPE AS type FROM '
                           'information_schema.COLUMNS WHERE TABLE_SCHEMA = %s AND '
                           'TABLE_NAME = %s', (self.database, table))
        return {r['name']: r['type'] for r in rows}

    @_db_errors
    def applied(self):
        return self._query('SELECT version, name, checksum, applied_at, applied_by '
                           'FROM schema_migrations ORDER BY version')

    @_db_errors
    def grants(self):
        return [next(iter(r.values())) for r in self._query('SHOW GRANTS')]

    @_db_errors
    def triggers(self):
        """(visible, rows): visible is False when this account cannot see audit_log's
        triggers (MySQL then returns no rows, which would look like 'missing')."""
        if not can_see_triggers(self.grants(), self.database):
            return False, []
        return True, self._query('SELECT TRIGGER_NAME, EVENT_OBJECT_TABLE, ACTION_TIMING, '
                                 'EVENT_MANIPULATION, ACTION_STATEMENT FROM '
                                 'information_schema.TRIGGERS WHERE TRIGGER_SCHEMA = %s '
                                 'AND EVENT_OBJECT_TABLE = %s',
                                 (self.database, audit_triggers.TABLE))

    @_db_errors
    def row_count(self, table):
        if table not in ALL_TABLES:
            raise MigrationError(f'row_count is only allowed for migration tables, not {table}.')
        return self._query(f'SELECT COUNT(*) AS n FROM `{table}`')[0]['n']

    @_db_errors
    def execute(self, sql):
        with self.conn.cursor() as cur:
            cur.execute(sql)              # no parameters: the SQL is fixed in this package
        self.conn.commit()

    @_db_errors
    def record(self, version, name, checksum):
        with self.conn.cursor() as cur:
            cur.execute('INSERT INTO schema_migrations (version, name, checksum, applied_at, '
                        'applied_by) VALUES (%s, %s, %s, UTC_TIMESTAMP(6), CURRENT_USER())',
                        (version, name, checksum))
        self.conn.commit()

    @_db_errors
    def forget(self, version):
        with self.conn.cursor() as cur:
            cur.execute('DELETE FROM schema_migrations WHERE version = %s', (version,))
        self.conn.commit()

    @contextmanager
    def lock_tables(self, tables):
        """LOCK TABLES ... WRITE on these (migration or tracking tables only) for the block:
        other sessions can neither read nor write them until UNLOCK TABLES. DROP TABLE is
        allowed on a write-locked table and does not release the other locks."""
        allowed = ALL_TABLES | {TRACKING_TABLE}
        names = [t for t in dict.fromkeys(tables) if t in allowed]
        if len(names) != len(set(tables)):
            raise MigrationError('lock_tables is only allowed for migration tables.')
        if not names:
            yield
            return
        self._locked(f'LOCK TABLES {", ".join(f"`{t}` WRITE" for t in names)}')
        try:
            yield
        finally:
            try:
                self._query('UNLOCK TABLES')
            except Exception:
                pass                       # connection gone: the server releases the locks

    @_db_errors
    def _locked(self, sql):
        self._query(sql)

    def lock(self):
        return _Lock(self)


class _Lock:
    def __init__(self, schema):
        self.schema = schema
        self.name = (LOCK_PREFIX + schema.database)[:64]      # one lock per database

    @property
    def database(self):                 # used by _db_errors in messages
        return self.schema.database

    def __enter__(self):
        if self._get() != 1:            # 0 = timed out, None = error
            raise MigrationError('Another migration is running on this database (lock not '
                                 'available).')
        return self

    @_db_errors
    def _get(self):
        return self.schema._query('SELECT GET_LOCK(%s, 10) AS got', (self.name,))[0]['got']

    def __exit__(self, *exc):
        try:
            self.schema._query('SELECT RELEASE_LOCK(%s) AS released', (self.name,))
        except Exception:
            pass                         # connection gone: the server releases the lock
        return False
