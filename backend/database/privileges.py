"""Reading MySQL grants (from SHOW GRANTS) without changing them.

check_runtime_grants(): problems if the RUNTIME account could change or remove audit
history (UPDATE, DELETE, DROP, ALTER, TRIGGER, or ALL on audit_log, its database or every
database), change or remove the append-only shared records (app_status_events,
app_config_logs, app_job_events, app_device_backups: the same privileges), delete, drop or
alter any other shared application table (app_*: soft delete and snapshot replacement
need no DELETE), or create/drop tables. can_see_triggers(): whether an account may read
information_schema.TRIGGERS rows for audit_log (MySQL hides them without TRIGGER).

Roles granted to an account are reported but not expanded (their privileges are unknown
here), so a role always produces a "cannot confirm" problem rather than a pass.
"""
import re

_GRANT = re.compile(r'^GRANT\s+(?P<privs>.+?)\s+ON\s+(?P<scope>\S+)\s+TO\s+', re.I | re.S)
_ROLE_GRANT = re.compile(r'^GRANT\s+(?!.+\s+ON\s+)(?P<roles>.+?)\s+TO\s+', re.I | re.S)
AUDIT_DANGEROUS = ('ALL', 'ALL PRIVILEGES', 'UPDATE', 'DELETE', 'DROP', 'ALTER', 'TRIGGER')
SCHEMA_DANGEROUS = ('CREATE', 'DROP', 'ALTER')
# Shared application tables (Phase C, migrations 2-4). Append-only ones: like audit_log,
# the runtime account may only read and add rows. The others: no DELETE/DROP/ALTER (devices
# are soft-deleted, findings superseded, locks released by UPDATE).
APPEND_ONLY_TABLES = ('app_status_events', 'app_config_logs', 'app_job_events',
                      'app_device_backups', 'security_lockouts')
SHARED_TABLES = ('app_devices', 'app_device_credentials', 'app_links', 'app_findings',
                 'app_status_events', 'app_config_logs', 'app_jobs', 'app_job_devices',
                 'app_job_events', 'app_device_locks', 'app_device_backups',
                 'security_device_login_state', 'security_lockouts')
SHARED_DANGEROUS = ('ALL', 'ALL PRIVILEGES', 'DELETE', 'DROP', 'ALTER', 'TRIGGER')


def _name(part):
    return part.strip().strip('`').strip('"').strip("'").replace('``', '`')


def parse_grants(lines):
    """[(privileges set, database or '*', table or '*')] plus a list of granted roles."""
    grants, roles = [], []
    for line in lines:
        text = line.strip().rstrip(';')
        m = _GRANT.match(text)
        if m:
            # Column privileges such as SELECT (`id`, `name`) contain commas: drop the
            # column lists first, then split.
            plain = re.sub(r'\([^)]*\)', '', m.group('privs'))
            privs = {p.strip().upper() for p in plain.split(',') if p.strip()}
            db_part, _, table_part = m.group('scope').partition('.')
            grants.append((privs, _name(db_part), _name(table_part)))
            continue
        m = _ROLE_GRANT.match(text)
        if m and not text.upper().startswith('GRANT PROXY'):
            roles += [_name(r) for r in m.group('roles').split(',')]
    return grants, roles


def _db_matches(pattern, database):
    """MySQL database grants may use % and _ wildcards (\\% and \\_ are literal). An
    unescaped _ matches any character, so this errs towards reporting a grant."""
    if pattern == '*':
        return True
    regex, i = '', 0
    while i < len(pattern):
        c = pattern[i]
        if c == '\\' and i + 1 < len(pattern):
            regex += re.escape(pattern[i + 1])
            i += 2
            continue
        regex += '.*' if c == '%' else '.' if c == '_' else re.escape(c)
        i += 1
    return re.fullmatch(regex, database, re.I) is not None


def _applies(db, table, database, target_table=None):
    if not _db_matches(db, database):
        return False
    return table == '*' or target_table is None or table.lower() == target_table


def check_runtime_grants(lines, database):
    """Problems (strings) with the runtime account's grants; empty = acceptable."""
    grants, roles = parse_grants(lines)
    problems = []
    for privs, db, table in grants:
        if _applies(db, table, database, 'audit_log'):
            bad = sorted(p for p in privs if p in AUDIT_DANGEROUS)
            if bad:
                where = '*.*' if db == '*' else f'{db}.{table}'
                problems.append(f'{", ".join(bad)} on {where} would let it change or remove '
                                f'audit records')
        if _applies(db, table, database) and table == '*':
            bad = sorted(p for p in privs if p in SCHEMA_DANGEROUS)
            if bad:
                problems.append(f'{", ".join(bad)} on {"*.*" if db == "*" else db + ".*"} '
                                f'lets it create or drop tables')
            bad = sorted(p for p in privs if p in SHARED_DANGEROUS)
            if bad:
                problems.append(f'{", ".join(bad)} on {"*.*" if db == "*" else db + ".*"} '
                                f'would let it delete or alter shared application records')
        elif _applies(db, table, database) and table.lower() in SHARED_TABLES:
            name = table.lower()
            dangerous = AUDIT_DANGEROUS if name in APPEND_ONLY_TABLES else SHARED_DANGEROUS
            bad = sorted(p for p in privs if p in dangerous)
            if bad:
                kind = ('change or remove append-only records' if name in APPEND_ONLY_TABLES
                        else 'delete or alter shared application records')
                problems.append(f'{", ".join(bad)} on {db}.{table} would let it {kind}')
    if roles:
        problems.append('roles are granted (' + ', '.join(roles) + '); their privileges cannot '
                        'be confirmed here')
    return problems


def can_see_triggers(lines, database):
    grants, _ = parse_grants(lines)
    return any(('TRIGGER' in privs or 'ALL' in privs or 'ALL PRIVILEGES' in privs)
               and _applies(db, table, database, 'audit_log') for privs, db, table in grants)


# ---------------------------------------------------------------- the least-privilege model
# The ONLY privileges each account needs. The README, `migrate recommended-grants` and the
# runtime check all come from these tuples, so they cannot drift apart.
RUNTIME_ACCOUNT = "'netcommand_api'@'127.0.0.1'"
MIGRATION_ACCOUNT = "'netcommand_migrator'@'127.0.0.1'"
RUNTIME_GRANTS = (
    ('users', ('SELECT', 'INSERT', 'UPDATE')),
    ('email_challenges', ('SELECT', 'INSERT', 'UPDATE')),
    ('sessions', ('SELECT', 'INSERT', 'UPDATE')),
    ('audit_log', ('SELECT', 'INSERT')),                 # append-only: no UPDATE, no DELETE
    ('schema_migrations', ('SELECT',)),
    # Shared application data (migrations 2-4). Still no DELETE anywhere: devices are
    # soft-deleted, findings superseded, locks released and jobs finished by UPDATE.
    ('app_devices', ('SELECT', 'INSERT', 'UPDATE')),
    ('app_device_credentials', ('SELECT', 'INSERT', 'UPDATE')),
    ('app_links', ('SELECT', 'INSERT', 'UPDATE')),       # UPDATE: names follow a rename
    ('app_findings', ('SELECT', 'INSERT', 'UPDATE')),    # UPDATE: superseded_at only
    ('app_status_events', ('SELECT', 'INSERT')),         # append-only
    ('app_config_logs', ('SELECT', 'INSERT')),           # append-only
    ('app_jobs', ('SELECT', 'INSERT', 'UPDATE')),
    ('app_job_devices', ('SELECT', 'INSERT', 'UPDATE')),
    ('app_job_events', ('SELECT', 'INSERT')),            # append-only
    ('app_device_locks', ('SELECT', 'INSERT', 'UPDATE')),
    ('app_device_backups', ('SELECT', 'INSERT')),        # append-only
    # Failed device logins and lockouts (migration 5): the state is updated in place;
    # lockouts are history (append-only).
    ('security_device_login_state', ('SELECT', 'INSERT', 'UPDATE')),
    ('security_lockouts', ('SELECT', 'INSERT')),         # append-only
)
MIGRATION_GRANTS = (
    ('schema_migrations', ('SELECT', 'INSERT', 'DELETE', 'CREATE')),
    ('users', ('SELECT', 'CREATE', 'DROP', 'REFERENCES')),
    ('email_challenges', ('SELECT', 'CREATE', 'DROP')),
    ('sessions', ('SELECT', 'CREATE', 'DROP')),
    ('audit_log', ('SELECT', 'CREATE')),                 # deliberately NO DROP (see below)
    # Shared application tables. REFERENCES only on the tables other tables point to
    # (MySQL needs it on the PARENT table to create a foreign key).
    ('app_devices', ('SELECT', 'CREATE', 'DROP', 'REFERENCES')),
    ('app_device_credentials', ('SELECT', 'CREATE', 'DROP')),
    ('app_links', ('SELECT', 'CREATE', 'DROP')),
    ('app_findings', ('SELECT', 'CREATE', 'DROP')),
    ('app_status_events', ('SELECT', 'CREATE', 'DROP')),
    ('app_config_logs', ('SELECT', 'CREATE', 'DROP')),
    ('app_jobs', ('SELECT', 'CREATE', 'DROP', 'REFERENCES')),
    ('app_job_devices', ('SELECT', 'CREATE', 'DROP')),
    ('app_job_events', ('SELECT', 'CREATE', 'DROP')),
    ('app_device_locks', ('SELECT', 'CREATE', 'DROP')),
    ('app_device_backups', ('SELECT', 'CREATE', 'DROP')),
    ('security_device_login_state', ('SELECT', 'CREATE', 'DROP')),
    ('security_lockouts', ('SELECT', 'CREATE', 'DROP')),
)
# Never granted to the migration or runtime account: done by an administrator only.
# Dropping audit_log destroys audit history (DROP and TRUNCATE bypass the triggers), so a
# rollback that reaches audit_log stops until an administrator has archived and dropped it.
ADMINISTRATOR_ONLY = (
    ('DROP', 'audit_log'),
    ('TRIGGER', 'audit_log'),          # CREATE/DROP TRIGGER (SUPER-level with binary logging)
    ('DELETE', 'audit_log'),           # the retention purge
)
MIGRATION_DATABASE_GRANTS = ('LOCK TABLES',)            # database level only in MySQL
_ALL = {'ALL', 'ALL PRIVILEGES'}


def grant_statements(grants, database, account):
    if not re.fullmatch(r'[A-Za-z0-9_]{1,64}', database or ''):
        raise ValueError('A valid database name is required.')
    width = max(len(', '.join(p)) for _, p in grants)
    return [f"GRANT {', '.join(privs):<{width}} ON `{database}`.`{table}` TO {account};"
            for table, privs in grants]


def escape_database_pattern(database):
    """A database name for a DATABASE-level grant (`db`.*). There MySQL treats _ and % as
    wildcards (unless partial_revokes is ON), so `netcommand_test`.* would also match
    netcommandXtest; escaped as netcommand\\_test it matches only that database. Table-level
    grants (`db`.`table`) use names literally and are not escaped."""
    return database.replace('\\', '\\\\').replace('_', '\\_').replace('%', '\\%')


def recommended_grants_sql(database):
    """The DBA script for both accounts (printed only; this project never runs it)."""
    lines = ['-- NetCommand backend accounts: least privilege. Review, then run as a MySQL',
             '-- administrator. NOT executed by NetCommand. Choose the passwords yourself.',
             '', '-- 1) MIGRATION account: creates/drops ONLY the backend tables (python -m',
             '--    backend.database.migrate). Never used by the running backend.',
             f"CREATE USER {MIGRATION_ACCOUNT} IDENTIFIED BY '<chosen by the DBA>';"]
    lines += grant_statements(MIGRATION_GRANTS, database, MIGRATION_ACCOUNT)
    lines += [f"GRANT {', '.join(MIGRATION_DATABASE_GRANTS)} ON `{escape_database_pattern(database)}`.* TO "
              f"{MIGRATION_ACCOUNT};  -- only works on tables it can SELECT",
              '-- Optional: lets `migrate status` VERIFY the audit triggers. It also lets this',
              '-- account drop them; leave it out to verify as an administrator instead.',
              f"-- GRANT TRIGGER ON `{database}`.`audit_log` TO {MIGRATION_ACCOUNT};",
              '', '-- 2) RUNTIME account: what the backend uses. Run AFTER `migrate up` (table',
              '--    grants need the tables). No DELETE anywhere; audit_log and the app_ event,',
              '--    log and backup tables are append-only.',
              f"CREATE USER {RUNTIME_ACCOUNT} IDENTIFIED BY '<chosen by the DBA>';"]
    lines += grant_statements(RUNTIME_GRANTS, database, RUNTIME_ACCOUNT)
    return '\n'.join(lines)


def effective_privileges(grants, database, table):
    """Every privilege that reaches database.table through global, database or table
    grants ('ALL' expands to everything)."""
    found = set()
    for privs, db, tbl in grants:
        if _applies(db, tbl, database, table) and (tbl == '*' or tbl.lower() == table):
            found |= privs
    return found


def audit_capabilities(lines, database):
    """What these grants allow against audit history (True = possible). Triggers stop
    only UPDATE and recent DELETE; DROP/TRUNCATE/ALTER are stopped only by privileges.
    REPLACE needs DELETE, and INSERT ... ON DUPLICATE KEY UPDATE needs UPDATE."""
    grants, _ = parse_grants(lines)
    p = effective_privileges(grants, database, 'audit_log')
    every = bool(p & _ALL)
    return {'update_rows': every or 'UPDATE' in p,
            'delete_rows': every or 'DELETE' in p,
            'drop_or_truncate': every or 'DROP' in p,
            'alter_table': every or 'ALTER' in p,
            'drop_or_create_triggers': every or 'TRIGGER' in p}


def missing_runtime_grants(lines, database):
    """Required runtime privileges that are NOT granted (the backend would fail)."""
    grants, _ = parse_grants(lines)
    missing = []
    for table, privs in RUNTIME_GRANTS:
        have = effective_privileges(grants, database, table)
        if have & _ALL:
            continue
        missing += [f'{p} on {database}.{table}' for p in privs if p not in have]
    return missing
