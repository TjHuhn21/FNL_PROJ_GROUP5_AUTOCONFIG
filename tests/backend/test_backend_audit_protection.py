"""Section 4: audit and privilege protections, checked without MySQL.

* The documented runtime grants are exactly the least-privilege set, and with them the
  account can neither change, delete, drop/truncate nor alter audit_log, nor manage its
  triggers.
* Every statement the repository sends needs only those grants (no DELETE anywhere; on
  audit_log only SELECT/INSERT): recorded from every repository method on a stand-in
  connection.
* The trigger rules (modelled in Python) refuse every UPDATE and every DELETE of a row
  younger than a year; the administrator purge removes exactly the complement.
* The README documents all of this, and never claims triggers stop DROP/TRUNCATE.

What MySQL itself does with the triggers is NOT verified here (no server is used).
"""
import re
from datetime import datetime, timedelta
from pathlib import Path

import pytest

from backend.database import audit_triggers as AT
from backend.database.auth_repository import AuthRepository
from backend.database.privileges import (MIGRATION_ACCOUNT, MIGRATION_GRANTS, RUNTIME_ACCOUNT,
                                         RUNTIME_GRANTS, audit_capabilities, check_runtime_grants,
                                         grant_statements, missing_runtime_grants,
                                         recommended_grants_sql)

ROOT = Path(__file__).resolve().parents[2]
README = (ROOT / 'backend' / 'README.md').read_text(encoding='utf-8')
DB = 'netcommand_test'
HASH = '$argon2id$v=19$m=65536,t=3,p=4$' + 'c2FsdHNhbHRzYWx0' + '$' + 'h' * 43
RUNTIME_LINES = grant_statements(RUNTIME_GRANTS, DB, RUNTIME_ACCOUNT)


# ---------------------------------------------------------------- the runtime account
def test_runtime_grants_are_exactly_the_required_least_privilege_set():
    assert dict(RUNTIME_GRANTS) == {
        'users': ('SELECT', 'INSERT', 'UPDATE'),
        'email_challenges': ('SELECT', 'INSERT', 'UPDATE'),
        'sessions': ('SELECT', 'INSERT', 'UPDATE'),
        'audit_log': ('SELECT', 'INSERT'),
        'schema_migrations': ('SELECT',)}
    granted = {p for _, privs in RUNTIME_GRANTS for p in privs}
    assert granted == {'SELECT', 'INSERT', 'UPDATE'}             # no DELETE / DDL at all
    assert check_runtime_grants(RUNTIME_LINES, DB) == []
    assert missing_runtime_grants(RUNTIME_LINES, DB) == []


def test_runtime_account_cannot_bypass_the_audit_protections():
    assert audit_capabilities(RUNTIME_LINES, DB) == {
        'update_rows': False, 'delete_rows': False, 'drop_or_truncate': False,
        'alter_table': False, 'drop_or_create_triggers': False}


@pytest.mark.parametrize('extra, capability', [
    ('GRANT UPDATE ON `netcommand_test`.`audit_log` TO `x`@`h`', 'update_rows'),
    ('GRANT DELETE ON `netcommand_test`.* TO `x`@`h`', 'delete_rows'),
    ('GRANT DROP ON *.* TO `x`@`h`', 'drop_or_truncate'),            # TRUNCATE needs DROP
    ('GRANT ALTER ON `netcommand_test`.`audit_log` TO `x`@`h`', 'alter_table'),
    ('GRANT TRIGGER ON `netcommand_test`.* TO `x`@`h`', 'drop_or_create_triggers'),
    ('GRANT ALL PRIVILEGES ON `netcommand_test`.* TO `x`@`h`', 'delete_rows'),
])
def test_any_bypassing_grant_is_detected(extra, capability):
    lines = RUNTIME_LINES + [extra]
    assert audit_capabilities(lines, DB)[capability] is True
    assert check_runtime_grants(lines, DB) != []


class RecordingConn:
    """Answers every query with a plausible row; records each statement sent."""

    def __init__(self, sent):
        self.sent = sent

    def cursor(self):
        conn = self

        class Cur:
            rowcount, lastrowid = 1, 1

            def __enter__(self):
                return self

            def __exit__(self, *e):
                return False

            def execute(self, sql, params=()):
                conn.sent.append(sql)

            def fetchone(self):
                return {'id': 1, 'role': 'admin', 'status': 'active', 'attempts': 1,
                        'invalidated_at': None, 'password_hash': HASH, 'expired': 0}

            def fetchall(self):
                return [{'id': 1}, {'id': 2}]
        return Cur()

    def commit(self):
        pass

    def rollback(self):
        pass

    def close(self):
        pass


def every_repository_statement():
    sent = []
    repo = AuthRepository(lambda: RecordingConn(sent))
    cid = 'A' * 43
    calls = [
        lambda: repo.create_user('a@example.com', 'A', HASH),
        lambda: repo.get_user(1), lambda: repo.find_user_by_email('a@example.com'),
        lambda: repo.get_password_hash(1),
        lambda: repo.set_status(3, 'disabled', actor_user_id=1),
        lambda: repo.set_role(3, 'viewer', actor_user_id=1),
        lambda: repo.mark_email_verified(1), lambda: repo.approve_user(3, 1),
        lambda: repo.create_challenge(1, 'login', 'a' * 64, 300),
        lambda: repo.get_challenge(cid), lambda: repo.record_failed_attempt(cid),
        lambda: repo.consume_challenge(cid, 'login', 1), lambda: repo.invalidate_challenge(cid),
        lambda: repo.invalidate_user_challenges(1, 'login'),
        lambda: repo.create_session(1, 'c' * 64, 3600),
        lambda: repo.get_active_session('c' * 64, 1800), lambda: repo.touch_session(1, 1800),
        lambda: repo.revoke_session(1), lambda: repo.revoke_user_sessions(1, 'logout'),
        lambda: repo.list_sessions(1), lambda: repo.write_audit('auth.login', 'success'),
        lambda: repo.list_audit()]
    for call in calls:
        call()
    return sent


def needed_privileges(sql):
    """(privilege, table) pairs a statement needs on MySQL 8.4."""
    text = ' '.join(sql.split())
    verb = text.split()[0].upper()
    tables = set(re.findall(r'\b(?:FROM|JOIN|INTO|UPDATE)\s+(\w+)', text, re.I))
    if verb == 'SELECT':
        need = {('SELECT', t) for t in tables}
        if text.endswith('FOR UPDATE'):                 # locking read: SELECT + UPDATE
            need |= {('UPDATE', t) for t in tables}
        return need
    if verb == 'INSERT':
        return {('INSERT', re.search(r'INTO\s+(\w+)', text).group(1))}
    if verb == 'UPDATE':
        table = re.match(r'UPDATE\s+(\w+)', text).group(1)
        return {('UPDATE', table), ('SELECT', table)}   # WHERE clauses read the table
    return {(verb, t) for t in tables} or {(verb, '?')}


def test_the_repository_needs_only_the_documented_runtime_grants():
    allowed = {(p, t) for t, privs in RUNTIME_GRANTS for p in privs}
    sent = every_repository_statement()
    assert len(sent) > 25
    needed = set().union(*(needed_privileges(s) for s in sent))
    assert needed <= allowed, sorted(needed - allowed)
    assert not any(s.lstrip().upper().startswith(('DELETE', 'DROP', 'TRUNCATE', 'ALTER',
                                                  'CREATE', 'REPLACE')) for s in sent)
    assert {p for p, t in needed if t == 'audit_log'} == {'SELECT', 'INSERT'}


def test_migration_and_runtime_accounts_have_separate_responsibilities():
    migration = {t: set(p) for t, p in MIGRATION_GRANTS}
    runtime = {t: set(p) for t, p in RUNTIME_GRANTS}
    assert MIGRATION_ACCOUNT != RUNTIME_ACCOUNT
    assert all(not ({'CREATE', 'DROP', 'ALTER', 'TRIGGER', 'DELETE'} & p) for p in runtime.values())
    assert all({'CREATE'} & p for p in migration.values())             # schema work only
    assert not any('UPDATE' in p for p in migration.values())          # never edits user data
    assert 'INSERT' not in migration['audit_log'] and 'TRIGGER' not in migration['audit_log']
    assert migration['audit_log'] == {'SELECT', 'CREATE'}               # no DROP: admin only
    assert all('DROP' in migration[t] for t in ('users', 'email_challenges', 'sessions'))


# ---------------------------------------------------------------- triggers and retention
def trigger_refuses_update(row):
    return True                                         # audit_log_no_update: unconditional


def trigger_refuses_delete(row, now):
    return row['created_at'] > now - timedelta(days=365)   # OLD.created_at > NOW - 1 YEAR


def purge_selects(row, now):
    return row['created_at'] <= now - timedelta(days=365)  # RETENTION_CONDITION


def test_trigger_rules_and_purge_are_exact_complements():
    no_update, no_delete = AT.TRIGGERS
    assert no_update.body.startswith('SIGNAL') and 'IF ' not in no_update.body   # every UPDATE
    assert 'IF OLD.created_at > UTC_TIMESTAMP(6) - INTERVAL 1 YEAR THEN' in no_delete.body
    assert AT.RETENTION_CONDITION == 'created_at <= UTC_TIMESTAMP(6) - INTERVAL 1 YEAR'
    now = datetime(2026, 11, 18, 12, 0, 0)
    for age in (0, 1, 364, 365, 366, 900):
        row = {'created_at': now - timedelta(days=age)}
        assert trigger_refuses_update(row)
        assert trigger_refuses_delete(row, now) != purge_selects(row, now)   # never both
    assert trigger_refuses_delete({'created_at': now - timedelta(days=364)}, now)
    assert purge_selects({'created_at': now - timedelta(days=365)}, now)


def test_purge_sql_is_admin_only_and_scoped():
    text = AT.purge_sql(DB)
    assert 'ADMINISTRATOR ONLY' in text and 'runtime account never has it' in text
    assert text.count('DELETE FROM') == 1
    assert f'DELETE FROM `{DB}`.audit_log WHERE {AT.RETENTION_CONDITION};' in text
    with pytest.raises(ValueError):
        AT.purge_sql('x; DROP DATABASE y')


# ---------------------------------------------------------------- documentation
def test_readme_shows_exactly_the_generated_least_privilege_grants():
    for line in grant_statements(RUNTIME_GRANTS, DB, RUNTIME_ACCOUNT) + \
            grant_statements(MIGRATION_GRANTS, DB, MIGRATION_ACCOUNT):
        assert line in README, line
    for line in recommended_grants_sql(DB).splitlines():
        if line.startswith('GRANT '):
            assert line in README, line


def test_readme_describes_the_protection_layers_honestly():
    text = ' '.join(README.split())
    assert 'Triggers do not stop DROP TABLE, TRUNCATE or ALTER TABLE' in text
    assert 'must not have' in text and 'DELETE' in text
    assert 'retention purge' in text.lower() and 'audit-purge-sql' in text
    assert 'the backend never runs it' in text.lower()
    assert 'check-runtime-grants' in text and 'recommended-grants' in text
    assert not re.search(r'triggers? (alone )?(prevent|stop|block)s? (drop|truncate)', text, re.I)


def test_readme_documents_what_the_trigger_definer_must_keep():
    text = ' '.join(README.split())
    assert 'Trigger definer' in text and 'error 1449' in text
    assert 'keep the `TRIGGER` privilege on `audit_log`' in text
    assert ('keep the `SELECT` privilege on `audit_log`, because the delete trigger reads '
            '`OLD.created_at`') in text
    assert 'not be dropped (or renamed)' in text


def test_definer_account_locking_is_not_claimed_to_be_safe():
    text = ' '.join(README.split())
    assert 'is NOT verified yet' in text and 'ACCOUNT LOCK' in text
    assert not re.search(r'lock\w*[^.]*does not affect the triggers', text, re.I)
    script = ' '.join(AT.admin_sql(DB).split())
    assert 'must keep TRIGGER and SELECT on audit_log' in script
    assert 'must not be dropped' in script and 'Locking it is not verified as safe' in script


# ---------------------------------------------------------------- database-level wildcards
def test_database_level_grant_escapes_the_underscore():
    from backend.database.privileges import escape_database_pattern
    lock_line = [l for l in recommended_grants_sql(DB).splitlines() if 'LOCK TABLES' in l]
    assert lock_line == ["GRANT LOCK TABLES ON `netcommand\\_test`.* TO "
                         "'netcommand_migrator'@'127.0.0.1';  -- only works on tables it can SELECT"]
    assert escape_database_pattern('netcommand_test') == 'netcommand\\_test'
    assert escape_database_pattern('a%b_c') == 'a\\%b\\_c'


def test_no_database_level_grant_is_left_as_a_wildcard():
    for line in recommended_grants_sql(DB).splitlines():
        scope = re.search(r'\bON\s+`([^`]*)`\.\*', line)
        if scope:                                       # database-level grant
            assert re.search(r'(?<!\\)[_%]', scope.group(1)) is None, line


def test_table_level_grants_keep_the_literal_name():
    for line in grant_statements(RUNTIME_GRANTS, DB, RUNTIME_ACCOUNT) + \
            grant_statements(MIGRATION_GRANTS, DB, MIGRATION_ACCOUNT):
        assert '`netcommand_test`.`' in line and '\\_' not in line


def test_escaped_grant_matches_only_the_test_database():
    from backend.database.privileges import _db_matches
    assert _db_matches('netcommand\\_test', 'netcommand_test')
    assert not _db_matches('netcommand\\_test', 'netcommandXtest')
    assert _db_matches('netcommand_test', 'netcommandXtest')      # what the unescaped form did
    assert not _db_matches('netcommand\\_test', 'netcommand')


def test_readme_shows_the_escaped_lock_tables_grant():
    assert ("GRANT LOCK TABLES ON `netcommand\\_test`.* TO 'netcommand_migrator'@'127.0.0.1';"
            in README)
    assert "GRANT LOCK TABLES ON `netcommand_test`.*" not in README


def test_readme_documents_the_administrator_audit_log_removal():
    text = ' '.join(README.split())
    assert 'deliberately has **no `DROP` privilege on `audit_log`**' in text
    assert 'stop **before dropping anything**' in text
    assert '`--allow-audit-history-loss` does not override this' in text
    assert 'if `audit_log` holds records, archive them first' in text
    assert '**Full rollback** (`down --to 0`)' in text
    assert '**Partial migration recovery** (`down --partial 1`' in text
    assert 'before** `audit_log` was created' in text and 'no administrator is needed' in text
    assert 'It deliberately has no `DROP` on `audit_log`' in text
