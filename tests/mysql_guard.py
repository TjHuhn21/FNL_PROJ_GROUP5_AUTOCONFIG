"""Safety guard for the tests that run against REAL MySQL (NETCOMMAND_TEST_DB=1).

Those tests DELETE every row of the NetCommand tables, so they may only ever run on a
separate test database. require_test_database() must be called before any connection
is opened. It refuses unless DB_NAME was set in the shell that started pytest to a name
ending in '_test' (for example netcommand_test), and it always refuses 'netcommand'.

Why the value is recorded early: db.py calls load_dotenv() when it is imported, which
copies any setting missing from the environment out of .env (for DB_NAME that is the
main database). tests/conftest.py imports this module before any test module imports
db, so PROCESS_DB_NAME is what the shell really set, never a value filled in from .env
or db.py's default. A DB_NAME that is missing there is refused, not looked up.
"""
import os

MAIN_DATABASE = 'netcommand'
SUFFIX = '_test'

# DB_NAME as set in the shell that started pytest (None if it was not set).
PROCESS_DB_NAME = os.environ.get('DB_NAME')

HOW_TO = ('The MySQL tests delete every row of the NetCommand tables, so they need a '
          'separate test database. In the same shell, set DB_NAME to a database whose '
          "name ends in '_test' (for example: $env:DB_NAME = 'netcommand_test'), plus the "
          'test account in DB_USER / DB_PASSWORD. No connection was opened and nothing '
          'was deleted.')


class UnsafeTestDatabase(Exception):
    """The configured database is not a separate test database."""


def problem_with(name):
    """Why this DB_NAME may not be used by the MySQL tests, or None if it may."""
    if name is None or name == '':
        return 'DB_NAME is not set in this shell (.env and the built-in default are not used).'
    if name != name.strip() or any(c.isspace() for c in name):
        return f'DB_NAME {name!r} contains spaces.'
    if name.lower() == MAIN_DATABASE:
        return f"DB_NAME is '{name}', the main NetCommand database. It is never used for tests."
    if not name.lower().endswith(SUFFIX) or len(name) == len(SUFFIX):
        return f"DB_NAME '{name}' does not end in '{SUFFIX}', so it is not a test database."
    return None


def require_test_database():
    """Return the test database name, or raise UnsafeTestDatabase before anything
    connects. Checks the name the shell set AND the one the connection will use now
    (they must be the same: nothing may have changed it since pytest started)."""
    problem = problem_with(PROCESS_DB_NAME)
    if problem is None and os.environ.get('DB_NAME') != PROCESS_DB_NAME:
        problem = 'DB_NAME was changed after the tests started.'
    if problem:
        raise UnsafeTestDatabase(f'{problem} {HOW_TO}')
    return PROCESS_DB_NAME


def fail_unless_test_database():
    """For the MySQL tests: require_test_database(), reported as a plain test failure
    with the explanation (no traceback). Call it before db.get_conn()."""
    import pytest
    try:
        return require_test_database()
    except UnsafeTestDatabase as err:
        pytest.fail(str(err), pytrace=False)
