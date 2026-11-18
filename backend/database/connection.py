"""Opening backend MySQL connections and translating driver errors.

PyMySQL is imported inside the functions, not at module import. Every connection:
  * uses utf8mb4, autocommit OFF (explicit transactions), finite timeouts;
  * sets the session time zone to UTC, so any NOW()/CURRENT_TIMESTAMP is UTC too
    (the repository writes UTC_TIMESTAMP(6) itself anyway);
  * PyMySQL never enables multi-statement queries, so stacked SQL cannot be injected.

Messages are written here, never copied from the driver (which may quote SQL values).
"""
from backend.database.errors import BackendDatabaseError, BackendDatabaseUnavailable

CONNECT_TIMEOUT = 5
IO_TIMEOUT = 15

# Connection-time server errors with a specific, safe explanation.
_CONNECT_ADVICE = {
    1044: 'the account has no access to this database',
    1045: 'the server refused the account name or password',
    1049: 'the database does not exist',
    1130: 'the server does not accept connections from this host for the account',
}


def connect(host, port, user, password, database):
    """A new PyMySQL connection (DictCursor). password: plain str (reveal() of a Secret).
    Raises BackendDatabaseUnavailable on any connection problem (a bug is re-raised)."""
    import pymysql
    try:
        return pymysql.connect(host=host, port=port, user=user, password=password,
                               database=database, charset='utf8mb4', autocommit=False,
                               connect_timeout=CONNECT_TIMEOUT, read_timeout=IO_TIMEOUT,
                               write_timeout=IO_TIMEOUT, init_command="SET time_zone = '+00:00'",
                               cursorclass=pymysql.cursors.DictCursor)
    except Exception as err:
        if not is_driver_error(err):
            raise
        raise translate(err, connecting=True, where=f'{host}:{port}/{database}') from None


def connect_runtime(settings):
    """A connection with the runtime account (settings.database, BACKEND_DB_*)."""
    db = settings.database
    if db is None:
        raise BackendDatabaseUnavailable('The backend database is not configured '
                                         '(BACKEND_DB_ENABLED is not true).')
    return connect(db.host, db.port, db.user, db.password.reveal(), db.name)


def driver_error_code(err):
    return err.args[0] if getattr(err, 'args', None) and isinstance(err.args[0], int) else None


def is_driver_error(err):
    try:
        import pymysql
        driver = (pymysql.err.MySQLError,)
    except ImportError:                   # pragma: no cover
        driver = ()
    return isinstance(err, driver + (OSError,))


def is_connection_lost(err):
    """True for errors meaning the connection itself failed (the server's state for the
    statement in flight is then unknown)."""
    if isinstance(err, BackendDatabaseUnavailable):
        return True
    if isinstance(err, BackendDatabaseError):
        return False
    import pymysql
    code = driver_error_code(err)
    return (isinstance(err, (pymysql.err.InterfaceError, OSError))
            or (isinstance(err, pymysql.err.OperationalError)
                and (code is None or 2000 <= code < 3000)))


def translate(err, uncertain=False, connecting=False, where='the database'):
    """Driver error -> BackendDatabaseUnavailable (connection) or BackendDatabaseError."""
    if isinstance(err, (BackendDatabaseUnavailable, BackendDatabaseError)):
        return err
    code = driver_error_code(err)
    detail = f' (MySQL error {code})' if code else ''
    if connecting:
        advice = _CONNECT_ADVICE.get(code)
        reason = f': {advice}' if advice else ''
        return BackendDatabaseUnavailable(f'Could not connect to the backend database at '
                                          f'{where}{detail}{reason}.', code=code)
    if is_connection_lost(err):
        return BackendDatabaseUnavailable(f'The connection to the backend database at {where} '
                                          f'was lost{detail}.', code=code, uncertain=uncertain)
    return BackendDatabaseError(f'The backend database could not complete the request{detail}.',
                                code=code)


def close_quietly(conn):
    try:
        conn.close()
    except Exception:
        pass
