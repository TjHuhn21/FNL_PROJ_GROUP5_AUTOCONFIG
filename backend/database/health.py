"""Runtime database readiness: can the backend use its database right now?

check_database(settings) connects with the RUNTIME account (BACKEND_DB_USER) and, with
SELECT statements only:
  1. runs SELECT 1;
  2. lists the tables it can see in the configured database;
  3. reads schema_migrations and checks that every migration this code knows is applied,
     in order, under the same name and with the same checksum (and nothing unknown);
  4. checks that the four authentication tables exist.
It never writes, never changes the schema and never runs migrations; the read-only
transaction is ended with a rollback and the connection is closed.

The result is deliberately generic: Readiness(ready, reason) where reason is one of
REASONS. No password, host, port, database name, SQL or driver message is ever part of it.
The server log gets the reason plus, for a connection problem, only the error class and
the MySQL error number.
"""
import logging
from dataclasses import dataclass

from backend.database.connection import close_quietly, connect_runtime, driver_error_code
from backend.database.migrations import ALL_TABLES, MIGRATIONS, TRACKING_TABLE

log = logging.getLogger('backend.database.health')

READY = 'ready'
NOT_CONFIGURED = 'database_not_configured'
UNAVAILABLE = 'database_unavailable'
SCHEMA_NOT_READY = 'schema_not_ready'
REASONS = (READY, NOT_CONFIGURED, UNAVAILABLE, SCHEMA_NOT_READY)


@dataclass(frozen=True)
class Readiness:
    ready: bool
    reason: str

    def public(self):
        """The body for clients: generic codes only."""
        if self.ready:
            return {'status': 'ready'}
        return {'status': 'not_ready', 'reason': self.reason}


class _SchemaNotReady(Exception):
    """Internal: the database answered, but the schema is not what this code expects."""


def check_database(settings, connect=None):
    """Readiness of the configured database for the RUNTIME account. Never raises for a
    database problem: returns Readiness(False, reason) instead."""
    if settings is None or settings.database is None:
        return Readiness(False, NOT_CONFIGURED)
    connect = connect or (lambda: connect_runtime(settings))
    try:
        conn = connect()
    except Exception as err:
        _log_unavailable('connect', err)
        return Readiness(False, UNAVAILABLE)
    try:
        with conn.cursor() as cur:
            _check(cur)
        return Readiness(True, READY)
    except _SchemaNotReady as err:
        log.warning('Database not ready: %s (%s)', SCHEMA_NOT_READY, err)
        return Readiness(False, SCHEMA_NOT_READY)
    except Exception as err:
        _log_unavailable('query', err)
        return Readiness(False, UNAVAILABLE)
    finally:
        try:
            conn.rollback()            # end the read-only transaction; nothing was written
        except Exception:
            pass
        close_quietly(conn)


def _check(cur):
    cur.execute('SELECT 1 AS ok', ())
    row = cur.fetchone()
    if not row or row.get('ok') != 1:
        raise RuntimeError('SELECT 1 did not return 1')

    cur.execute('SELECT TABLE_NAME AS name FROM information_schema.TABLES '
                'WHERE TABLE_SCHEMA = DATABASE()', ())
    tables = {r['name'].lower() for r in cur.fetchall()}
    if TRACKING_TABLE not in tables:
        raise _SchemaNotReady(f'{TRACKING_TABLE} is missing (no migration applied)')

    cur.execute('SELECT version, name, checksum FROM schema_migrations ORDER BY version', ())
    applied = {r['version']: r for r in cur.fetchall()}
    known = {m.version for m in MIGRATIONS}
    unknown = sorted(set(applied) - known)
    if unknown:
        raise _SchemaNotReady(f'unknown migration version(s) applied: {unknown}')
    for m in MIGRATIONS:
        row = applied.get(m.version)
        if row is None:
            raise _SchemaNotReady(f'migration {m.version} ({m.name}) is not applied')
        if row['name'] != m.name or row['checksum'] != m.checksum:
            raise _SchemaNotReady(f'migration {m.version} does not match this code '
                                  f'(name or checksum differs)')

    missing = sorted(ALL_TABLES - tables)
    if missing:
        raise _SchemaNotReady(f'tables missing: {", ".join(missing)}')


def _log_unavailable(stage, err):
    code = driver_error_code(err) or getattr(err, 'code', None)
    log.warning('Database not ready: %s (%s failed: %s%s)', UNAVAILABLE, stage,
                type(err).__name__, f', MySQL error {code}' if code else '')
