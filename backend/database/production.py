"""Production database safety for the operator tools (python -m backend.database.migrate,
python -m backend.auth.bootstrap_admin).

Adds to the existing name rules (migrations.check_database_name: *_test allowed, any
other name needs --authorize-database, 'netcommand' also --allow-main-database), never
replaces or relaxes them.

  * The production database (settings.PRODUCTION_DATABASES: netcommand_backend) is used
    only when ALL of these are given, for EVERY command (read-only ones included, except
    `migrate plan`, which never connects and names no database):
        BACKEND_ENV=production, --production, --authorize-database <name>,
        --confirm-database <name>
    --production with any other database, or BACKEND_ENV=production with any other
    database, is refused too, so a production setting can never be aimed elsewhere by
    mistake.
  * Identity check, right after connecting and before any other statement: ONE read-only
    SELECT DATABASE(), @@server_uuid. The database must be the configured name and, when
    BACKEND_DB_SERVER_UUID is set (required for production), the server UUID must match.
    This catches a wrong server, port, tunnel or database. It is NOT authentication and
    NOT cryptographic proof of identity: anyone who administers a server can give it any
    UUID.
  * No rollback on production: every `migrate down` that would change something is
    refused; production rollback means restoring a verified backup. `down --dry-run`
    stays allowed (it changes nothing).

Messages name databases, flags, settings and UUIDs, never a password.
"""
from backend.database.errors import MigrationError
from backend.settings import PRODUCTION_DATABASES, classify_database

IDENTITY_SQL = 'SELECT DATABASE() AS db, @@server_uuid AS server_uuid'
SAFEGUARD_NOTE = ('(a safeguard against connecting to the wrong server, port, tunnel or '
                  'database, not proof of identity)')


def check_target(name, environment, *, production_flag=False, authorized=None,
                 confirmed=None):
    """The database class of `name` if this command may target it; MigrationError
    (nothing was run) otherwise. Call BEFORE connecting."""
    kind = classify_database(name)
    if kind == 'production':
        missing = []
        if environment != 'production':
            missing.append('BACKEND_ENV=production')
        if not production_flag:
            missing.append('--production')
        if authorized != name:
            missing.append(f'--authorize-database {name}')
        if confirmed != name:
            missing.append(f'--confirm-database {name}')
        if missing:
            raise MigrationError(f"'{name}' is the PRODUCTION database. Every command against "
                                 f"it needs: {', '.join(missing)}. Nothing was run.")
        return kind
    if production_flag:
        raise MigrationError(f"--production was given, but '{name}' is not the production "
                             f"database ({', '.join(PRODUCTION_DATABASES)}). Nothing was run.")
    if environment == 'production':
        raise MigrationError(f"BACKEND_ENV is production, but '{name}' is not the production "
                             f"database ({', '.join(PRODUCTION_DATABASES)}). Nothing was run.")
    return kind


def check_rollback(kind, command, dry_run):
    """Refuse every rollback that would change the production database."""
    if kind == 'production' and command == 'down' and not dry_run:
        raise MigrationError('Rollback is refused on the production database: production '
                             'rollback means restoring a verified backup. Nothing was run. '
                             '(`down --dry-run` is allowed; it changes nothing.)')


def identity_required(kind, server_uuid):
    return kind == 'production' or bool(server_uuid)


def verify_identity(row, expected_name, expected_uuid, kind):
    """Compare the answer of IDENTITY_SQL with the configuration. MigrationError on any
    difference (nothing else is run)."""
    if kind == 'production' and not expected_uuid:
        raise MigrationError('BACKEND_DB_SERVER_UUID must be set for the production database '
                             f'{SAFEGUARD_NOTE}. Nothing was run.')
    row = row or {}
    actual_db, actual_uuid = row.get('db'), row.get('server_uuid')
    if actual_db != expected_name:
        raise MigrationError(f"Connected to database {actual_db!r}, but the settings name "
                             f"'{expected_name}' {SAFEGUARD_NOTE}. Nothing was run.")
    if expected_uuid and str(actual_uuid or '').lower() != expected_uuid.lower():
        raise MigrationError(f'The MySQL server UUID is {actual_uuid!r}, but '
                             f'BACKEND_DB_SERVER_UUID is {expected_uuid!r} {SAFEGUARD_NOTE}. '
                             f'Nothing was run.')


def _read_identity(cursor_owner):
    """Run IDENTITY_SQL on a DB-API connection (driver errors translated)."""
    from backend.database.connection import is_driver_error, translate
    try:
        with cursor_owner.cursor() as cur:
            cur.execute(IDENTITY_SQL, ())
            return cur.fetchone()
    except Exception as err:
        if not is_driver_error(err):
            raise
        raise translate(err) from None


def check_schema_identity(schema, settings, kind):
    """For an open MySQLSchema (migration or runtime account): the identity check as its
    FIRST statement, when required. True if it ran."""
    db = settings.database
    if not identity_required(kind, db.server_uuid):
        return False
    verify_identity(_read_identity(schema.conn), db.name, db.server_uuid, kind)
    return True


def check_runtime_identity(settings, kind, connect=None):
    """The identity check on a short connection with the RUNTIME account (for commands
    that open their own connections later). True if it ran."""
    db = settings.database
    if not identity_required(kind, db.server_uuid):
        return False
    from backend.database.connection import close_quietly, connect_runtime
    conn = (connect or connect_runtime)(settings)
    try:
        verify_identity(_read_identity(conn), db.name, db.server_uuid, kind)
    finally:
        close_quietly(conn)
    return True
