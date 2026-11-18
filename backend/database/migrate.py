"""python -m backend.database.migrate : manage the backend's own tables (operator only).

Never run automatically: the backend does not migrate on startup.

  plan [--down]               print the migration SQL; NO connection
  audit-triggers-sql          print the administrator SQL for the audit_log triggers;
                              NO connection (an administrator runs it, not this tool)
  status                      read-only: applied / pending / problems / audit protection
  up   [--to N] [--dry-run]   apply pending migrations
  down --to N   [--dry-run]   roll back to version N (0 = remove all auth tables)
  down --partial N            repair a migration that failed half-way
  check-runtime-grants        read-only: SHOW GRANTS of the RUNTIME account; reports
                              grants that could change or remove audit records, and
                              required grants that are missing
  check-runtime-connection    read-only: connect with the RUNTIME account and check that
                              the schema is ready (the same checks as GET /ready)
  recommended-grants          print the least-privilege GRANT script for both accounts;
                              NO connection (a DBA reviews and runs it, never this tool)
  audit-purge-sql             print the administrator's audit retention purge (keeps at
                              least one year); NO connection, never run by the backend

Connection: BACKEND_DB_HOST / BACKEND_DB_PORT / BACKEND_DB_NAME with the MIGRATION
account BACKEND_MIGRATE_USER (password from BACKEND_MIGRATE_PASSWORD or asked for without
echo). check-runtime-grants uses the runtime account BACKEND_DB_USER instead.

Target database: names ending in _test are allowed. Any other name needs
--authorize-database NAME; the main database 'netcommand' also needs
--allow-main-database (not approved yet). up/down (not --dry-run) also need
--confirm-database NAME. Stop the backend before `down`: the tables are write-locked
while they are checked and dropped, so a running backend would wait or fail.

The migration and runtime accounts must be different accounts (refused otherwise).

Exit codes: 0 ok; 1 inconsistent state; 2 refused or failed; 3 status ok but audit_log not
confirmed protected; 4 runtime grants unsafe; 5 runtime grants missing; 6 runtime
connection not ready; 130 interrupted.
"""
import argparse
import getpass
import sys

from backend.database import audit_triggers
from backend.database.errors import MigrationError, RepositoryError
from backend.database.migrations import (MIGRATIONS, TRACKING_DDL, MigrationRunner,
                                         MySQLSchema, check_database_name, check_definitions)
from backend.database.privileges import (audit_capabilities, check_runtime_grants,
                                         missing_runtime_grants, recommended_grants_sql)


def parse_args(argv):
    p = argparse.ArgumentParser(prog='python -m backend.database.migrate')
    sub = p.add_subparsers(dest='command', required=True)
    plan = sub.add_parser('plan', help='print the migration SQL (no connection)')
    plan.add_argument('--down', action='store_true', help='print the rollback SQL instead')
    triggers = sub.add_parser('audit-triggers-sql', help='print the administrator SQL for the '
                              'audit_log triggers (no connection)')
    status = sub.add_parser('status', help='show the migration state (read-only)')
    grants = sub.add_parser('check-runtime-grants', help="check the runtime account's grants")
    connection = sub.add_parser('check-runtime-connection', help='read-only readiness check '
                                'with the runtime account')
    recommended = sub.add_parser('recommended-grants', help='print the least-privilege grants '
                                 '(no connection)')
    purge = sub.add_parser('audit-purge-sql', help='print the administrator retention purge '
                           '(no connection)')
    up = sub.add_parser('up', help='apply pending migrations')
    up.add_argument('--to', type=int, default=None)
    down = sub.add_parser('down', help='roll back migrations')
    group = down.add_mutually_exclusive_group(required=True)
    group.add_argument('--to', type=int)
    group.add_argument('--partial', type=int, metavar='VERSION')
    down.add_argument('--allow-data-loss', action='store_true')
    down.add_argument('--allow-audit-history-loss', action='store_true')
    for cmd in (up, down):
        cmd.add_argument('--dry-run', action='store_true')
        cmd.add_argument('--confirm-database', metavar='NAME')
    for cmd in (up, down, status, grants, connection, triggers, recommended, purge):
        cmd.add_argument('--authorize-database', metavar='NAME',
                         help='allow a database whose name does not end in _test')
        cmd.add_argument('--allow-main-database', action='store_true')
    return p.parse_args(argv)


def print_plan(down=False, out=print):
    check_definitions()
    if not down:
        out('-- bookkeeping table (created only if missing)')
        out(TRACKING_DDL + ';')
    for m in (reversed(MIGRATIONS) if down else MIGRATIONS):
        out(f'\n-- migration {m.version} {m.name} ({"rollback" if down else "apply"}), '
            f'checksum {m.checksum}')
        for sql in (m.down if down else m.up):
            out(sql + ';')
    if not down:
        out('\n-- audit_log triggers: an ADMINISTRATOR step, see `audit-triggers-sql`')


def _password(secret, user, password_source):
    if secret:
        return secret.reveal()
    return (password_source or getpass.getpass)(f'Password for {user}: ')


def open_schema(settings, password_source=None):
    """A MySQLSchema on the configured database with the MIGRATION account."""
    from backend.database.connection import connect
    db = settings.database
    if db is None:
        raise MigrationError('BACKEND_DB_ENABLED must be true, with BACKEND_DB_HOST, '
                             'BACKEND_DB_PORT and BACKEND_DB_NAME set.')
    user = settings.migrate_user
    if not user:
        raise MigrationError('BACKEND_MIGRATE_USER (the account allowed to create tables) is '
                             'not set.')
    if user.lower() == db.user.lower():
        raise MigrationError('BACKEND_MIGRATE_USER and BACKEND_DB_USER must be different '
                             'accounts: the runtime account must not be able to create or drop '
                             'tables.')
    password = _password(settings.migrate_password, user, password_source)
    return MySQLSchema(connect(db.host, db.port, user, password, db.name), db.name)


def open_runtime_schema(settings, password_source=None):
    """A MySQLSchema with the RUNTIME account (only SHOW GRANTS is used)."""
    from backend.database.connection import connect
    db = settings.database
    if db is None:
        raise MigrationError('BACKEND_DB_ENABLED must be true with the BACKEND_DB_* settings.')
    password = _password(db.password, db.user, password_source)
    return MySQLSchema(connect(db.host, db.port, db.user, password, db.name), db.name)


def print_status(st, name, out):
    out(f'Database: {name}')
    for a in st.applied:
        out(f"  applied  {a['version']} {a['name']}  at {a['applied_at']} by {a['applied_by']}")
    for m in st.pending:
        out(f'  pending  {m.version} {m.name}')
    for p in st.problems:
        out(f'  PROBLEM  {p.message}')
    labels = {'protected': 'PROTECTED (both triggers verified)',
              'not_protected': 'NOT PROTECTED',
              'unknown': 'UNKNOWN (not verified)',
              'no_audit_table': 'not applicable (audit_log does not exist)'}
    out(f'  audit_log protection: {labels[st.audit.state]}')
    for d in st.audit.details:
        out(f'    - {d}')
    if st.audit.state in ('not_protected', 'unknown'):
        out('    An administrator installs the triggers with the SQL from '
            '`migrate audit-triggers-sql`.')


def main(argv=None, settings=None, schema=None, out=print, password_source=None):
    args = parse_args(sys.argv[1:] if argv is None else argv)
    try:
        if args.command == 'plan':
            print_plan(args.down, out)
            return 0
        if settings is None:
            from backend.settings import load_settings
            settings = load_settings()
        name = settings.database.name if settings.database else ''
        check_database_name(name, args.authorize_database, args.allow_main_database)
        if args.command == 'audit-triggers-sql':
            out(audit_triggers.admin_sql(name))
            return 0
        if args.command == 'recommended-grants':
            out(recommended_grants_sql(name))
            return 0
        if args.command == 'audit-purge-sql':
            out(audit_triggers.purge_sql(name))
            return 0
        changes = args.command in ('up', 'down') and not args.dry_run
        if changes and args.confirm_database != name:
            raise MigrationError(f'Add --confirm-database {name} to change that database '
                                 f'(nothing was run).')
        if args.command == 'check-runtime-connection':
            from backend.database.health import check_database
            result = check_database(settings)
            who = f'Runtime account {settings.database.user} on {name}'
            if result.ready:
                out(f'{who}: READY (connected; SELECT 1; migrations and tables as expected)')
                return 0
            out(f'{who}: NOT READY ({result.reason}). Details, without secrets, are in the '
                f'log; nothing was changed.')
            return 6
        if args.command == 'check-runtime-grants':
            if schema is None:
                schema = open_runtime_schema(settings, password_source)
            lines = schema.grants()
            problems, missing = check_runtime_grants(lines, name), missing_runtime_grants(lines, name)
            out(f'Runtime account {settings.database.user} on {name}:')
            for p in problems:
                out(f'  UNSAFE   {p}')
            for m in missing:
                out(f'  MISSING  {m}')
            caps = audit_capabilities(lines, name)
            out('  against audit_log it can: ' + (', '.join(k for k, v in caps.items() if v)
                                                   or 'only SELECT and INSERT'))
            if not problems and not missing:
                out('  ok: least privilege; cannot update, delete or drop audit records, nor '
                    'create/drop tables')
            return 4 if problems else 5 if missing else 0
        if schema is None:
            schema = open_schema(settings, password_source)
        runner = MigrationRunner(schema, log=out)
        if args.command == 'status':
            st = runner.status()
            print_status(st, name, out)
            if st.problems:
                return 1
            return 3 if st.audit.state in ('not_protected', 'unknown') else 0
        if args.command == 'up':
            done = runner.up(args.to, dry_run=args.dry_run)
        elif args.partial is not None:
            done = runner.down_partial(args.partial, dry_run=args.dry_run)
        else:
            done = runner.down(args.to, dry_run=args.dry_run,
                               allow_data_loss=args.allow_data_loss,
                               allow_audit_history_loss=args.allow_audit_history_loss)
        out(('[dry run] ' if args.dry_run else '') +
            (f'{len(done)} migration(s): {done}' if done else 'Nothing to do.'))
        return 0
    except (MigrationError, RepositoryError) as err:
        out(f'Migration refused: {err}')
        return 2
    except KeyboardInterrupt:
        out('Interrupted. Run `status` to see the current state.')
        return 130
    finally:
        conn = getattr(schema, 'conn', None)
        if conn is not None:
            from backend.database.connection import close_quietly
            close_quietly(conn)


if __name__ == '__main__':
    sys.exit(main())
