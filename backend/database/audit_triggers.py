"""audit_log protection triggers: a separate ADMINISTRATOR step, never run by the backend.

Why separate: MySQL 8.4 logs to the binary log by default, and with
log_bin_trust_function_creators=OFF (the default) CREATE TRIGGER requires SUPER-level
privilege. The migration account is not given that, and the server setting is not changed
without approval. So:
  * migration 0001 creates the tables only;
  * an administrator installs these two triggers once (admin_sql() prints the exact SQL);
  * `migrate status` checks information_schema.TRIGGERS and never reports the audit log as
    protected unless both triggers are found with the expected table, timing, event and body.

The triggers are a second layer. The first is the runtime account's grants: no UPDATE and
no DELETE on audit_log (privileges.check_runtime_grants() reports violations). Triggers
never stop DROP TABLE or TRUNCATE; only privileges do.
"""
import re
from dataclasses import dataclass

TABLE = 'audit_log'


@dataclass(frozen=True)
class Trigger:
    name: str
    timing: str
    event: str
    body: str          # the statement after FOR EACH ROW
    markers: tuple     # text the stored body must contain (whitespace-insensitive)


TRIGGERS = (
    Trigger('audit_log_no_update', 'BEFORE', 'UPDATE',
            "SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT = 'audit_log rows cannot be changed'",
            ("SIGNAL SQLSTATE '45000'",)),
    Trigger('audit_log_no_recent_delete', 'BEFORE', 'DELETE',
            "BEGIN\n"
            "  IF OLD.created_at > UTC_TIMESTAMP(6) - INTERVAL 1 YEAR THEN\n"
            "    SIGNAL SQLSTATE '45000'\n"
            "      SET MESSAGE_TEXT = 'audit_log rows younger than one year cannot be deleted';\n"
            "  END IF;\n"
            "END",
            ("SIGNAL SQLSTATE '45000'", 'OLD.created_at > UTC_TIMESTAMP(6) - INTERVAL 1 YEAR')),
)
NAMES = tuple(t.name for t in TRIGGERS)


def create_statement(trigger):
    return (f'CREATE TRIGGER {trigger.name} {trigger.timing} {trigger.event} ON {TABLE} '
            f'FOR EACH ROW\n{trigger.body}')


def admin_sql(database):
    """The script an administrator runs ONCE with the mysql client, after migration 0001
    (DELIMITER is needed because the second body contains semicolons)."""
    if not re.fullmatch(r'[A-Za-z0-9_]{1,64}', database or ''):
        raise ValueError('A valid database name is required.')
    lines = [f'-- NetCommand: audit_log protection triggers for `{database}`',
             '-- Run as a MySQL administrator (an account allowed to create triggers while',
             '-- binary logging is on), after `python -m backend.database.migrate up`.',
             '-- The trigger DEFINER will be that administrator account. While the triggers',
             '-- exist it must keep TRIGGER and SELECT on audit_log (the delete trigger reads',
             '-- OLD.created_at) and must not be dropped. Locking it is not verified as safe.',
             f'USE `{database}`;', 'DELIMITER $$']
    for t in TRIGGERS:
        lines += [create_statement(t) + '$$']
    lines += ['DELIMITER ;', '-- Check (expect 2 rows):',
              f"SELECT TRIGGER_NAME, ACTION_TIMING, EVENT_MANIPULATION FROM "
              f"information_schema.TRIGGERS WHERE TRIGGER_SCHEMA = '{database}' "
              f"AND EVENT_OBJECT_TABLE = '{TABLE}';"]
    return '\n'.join(lines)


def _squash(text):
    return re.sub(r'\s+', ' ', text or '').strip().upper()


def verify(rows):
    """rows: information_schema.TRIGGERS rows for audit_log (dicts with TRIGGER_NAME,
    EVENT_OBJECT_TABLE, ACTION_TIMING, EVENT_MANIPULATION, ACTION_STATEMENT).
    Returns a list of problems; empty means both triggers are correct."""
    by_name = {r['TRIGGER_NAME']: r for r in rows}
    problems = []
    for t in TRIGGERS:
        r = by_name.get(t.name)
        if r is None:
            problems.append(f'trigger {t.name} is missing')
            continue
        if r.get('EVENT_OBJECT_TABLE', '').lower() != TABLE:
            problems.append(f'trigger {t.name} is on table {r.get("EVENT_OBJECT_TABLE")}')
        if (r.get('ACTION_TIMING', '').upper(), r.get('EVENT_MANIPULATION', '').upper()) \
                != (t.timing, t.event):
            problems.append(f'trigger {t.name} is not {t.timing} {t.event}')
        body = _squash(r.get('ACTION_STATEMENT'))
        for marker in t.markers:
            if _squash(marker) not in body:
                problems.append(f'trigger {t.name} does not contain: {marker}')
    return problems


# ---------------------------------------------------------------- retention (administrator)
RETENTION_CONDITION = 'created_at <= UTC_TIMESTAMP(6) - INTERVAL 1 YEAR'


def purge_sql(database):
    """The administrator's retention purge: removes only audit records at least one year
    old, the exact complement of the delete trigger's condition, so it is never refused
    and can never reach a younger row. The backend never runs it: the runtime account has
    no DELETE on audit_log. Run it with a separate administrator account, after exporting
    the rows if they must be archived."""
    if not re.fullmatch(r'[A-Za-z0-9_]{1,64}', database or ''):
        raise ValueError('A valid database name is required.')
    return '\n'.join([
        f'-- NetCommand: audit_log retention purge for `{database}` (ADMINISTRATOR ONLY).',
        '-- Policy: keep at least one year. Run with an administrator account that has',
        '-- DELETE on audit_log; the backend runtime account never has it.',
        '-- 1) Optional archive first, for example:',
        f'--    mysqldump --single-transaction --where="{RETENTION_CONDITION}" {database} audit_log',
        '-- 2) Count, then purge:',
        f'SELECT COUNT(*) AS rows_to_purge FROM `{database}`.audit_log WHERE {RETENTION_CONDITION};',
        f'DELETE FROM `{database}`.audit_log WHERE {RETENTION_CONDITION};'])
