"""Reading SHOW GRANTS output (no MySQL): the runtime-account audit check and trigger
visibility."""
import pytest

from backend.database.privileges import can_see_triggers, check_runtime_grants, parse_grants

DB = 'netcommand_test'
RECOMMENDED = [
    "GRANT USAGE ON *.* TO `netcommand_api`@`127.0.0.1`",
    "GRANT SELECT, INSERT, UPDATE ON `netcommand_test`.`users` TO `netcommand_api`@`127.0.0.1`",
    "GRANT SELECT, INSERT, UPDATE ON `netcommand_test`.`email_challenges` TO `netcommand_api`@`127.0.0.1`",
    "GRANT SELECT, INSERT, UPDATE ON `netcommand_test`.`sessions` TO `netcommand_api`@`127.0.0.1`",
    "GRANT SELECT, INSERT ON `netcommand_test`.`audit_log` TO `netcommand_api`@`127.0.0.1`",
    "GRANT SELECT ON `netcommand_test`.`schema_migrations` TO `netcommand_api`@`127.0.0.1`",
]


def test_recommended_runtime_grants_pass():
    assert check_runtime_grants(RECOMMENDED, DB) == []


@pytest.mark.parametrize('line, fragment', [
    ("GRANT SELECT, INSERT, UPDATE, DELETE ON `netcommand_test`.* TO `x`@`h`", 'DELETE, UPDATE'),
    ("GRANT UPDATE ON `netcommand_test`.`audit_log` TO `x`@`h`", 'UPDATE on netcommand_test.audit_log'),
    ("GRANT DELETE ON *.* TO `x`@`h`", 'DELETE on *.*'),
    ("GRANT ALL PRIVILEGES ON `netcommand_test`.* TO `x`@`h`", 'ALL PRIVILEGES'),
    ("GRANT TRIGGER ON `netcommand_test`.`audit_log` TO `x`@`h`", 'TRIGGER'),
    ("GRANT DROP ON `netcommand\\_%`.* TO `x`@`h`", 'DROP'),          # wildcard database grant
    ("GRANT CREATE ON `netcommand_test`.* TO `x`@`h`", 'create or drop tables'),
    ("GRANT `dba_role`@`%` TO `x`@`h`", 'roles are granted'),
])
def test_dangerous_runtime_grants_are_reported(line, fragment):
    problems = check_runtime_grants(RECOMMENDED + [line], DB)
    assert problems and any(fragment in p for p in problems), problems


def test_grants_on_other_databases_or_tables_do_not_count():
    lines = RECOMMENDED + ["GRANT SELECT, INSERT, UPDATE, DELETE ON `netcommand`.* TO `x`@`h`",
                           "GRANT DELETE ON `netcommand_test`.`sessions` TO `x`@`h`"]
    assert check_runtime_grants(lines, DB) == []


def test_trigger_visibility():
    assert not can_see_triggers(RECOMMENDED, DB)
    assert can_see_triggers(["GRANT SELECT, TRIGGER ON `netcommand_test`.`audit_log` TO `m`@`h`"], DB)
    assert can_see_triggers(["GRANT ALL PRIVILEGES ON *.* TO `root`@`localhost`"], DB)
    assert not can_see_triggers(["GRANT TRIGGER ON `other_test`.* TO `m`@`h`"], DB)


def test_parse_grants_handles_column_privileges():
    grants, roles = parse_grants(["GRANT SELECT (`id`, `name`), UPDATE (`name`) ON "
                                  "`netcommand_test`.`users` TO `x`@`h`"])
    assert grants == [({'SELECT', 'UPDATE'}, 'netcommand_test', 'users')] and roles == []
