"""MySQL store. Same function names as db_fake.py, so the screens never change.

Rules: every value goes in through %s placeholders (never pasted into the SQL,
which blocks SQL injection). The only text put into SQL is the ORDER BY column,
and it comes from the fixed SORT_SQL dictionary below.
"""
import os
import threading
import time

import pymysql
from dotenv import load_dotenv

import device_types
import security
import validation
from store_errors import (DatabaseError, DatabaseUnavailable,  # noqa: F401  (raised here;
                          DeletedDeviceExists, DeviceNotDeleted,  # the screens import them)
                          DuplicateDeviceName)

load_dotenv()

# sort_by from the screen -> the SQL used (only these are ever allowed)
SORT_SQL = {'name': 'name', 'ip': 'INET_ATON(ip)', 'type': 'type',
            'status': 'status', 'created_at': 'created_at'}

CONNECT_TIMEOUT = 5          # seconds to wait for the server to answer a new connection
IO_TIMEOUT = 15              # seconds a running statement may wait for the server
RETRY_AFTER = 5.0            # after a connection failure, fail at once for this long

# ---------------------------------------------------------------- outage handling
# After the server could not be reached, every call fails at once (DatabaseUnavailable)
# for RETRY_AFTER seconds instead of each one waiting up to CONNECT_TIMEOUT again: the
# screens stay responsive during an outage. After that a call tries for real again;
# ping() always tries. Shared by every thread (GUI, monitor, health check).
_outage = {'last_failure': None}
_outage_lock = threading.Lock()

# MySQL client error numbers (2000-2999) mean the connection itself failed; for example
# 2003 can't connect, 2006 server has gone away, 2013 lost connection during a query.
_CONNECT_ADVICE = {
    1045: 'The database refused the application login. Check DB_USER and DB_PASSWORD in .env.',
    1049: 'The database named in DB_NAME does not exist on the server.',
}


def _mark_down():
    with _outage_lock:
        _outage['last_failure'] = time.monotonic()


def _mark_up():
    with _outage_lock:
        _outage['last_failure'] = None


def is_marked_down():
    """True while a recent connection failure makes calls fail at once."""
    with _outage_lock:
        last = _outage['last_failure']
    return last is not None and time.monotonic() - last < RETRY_AFTER


def _where():
    return f"{os.getenv('DB_HOST', 'localhost')}:{os.getenv('DB_PORT', '3306')}"


def _code(err):
    return err.args[0] if err.args and isinstance(err.args[0], int) else None


def _unavailable(code=None, uncertain=False, connecting=False):
    _mark_down()
    advice = _CONNECT_ADVICE.get(code) if connecting else None
    detail = f' (MySQL error {code})' if code else ''
    return DatabaseUnavailable(
        f'The database at {_where()} is not available{detail}. '
        + (advice or 'Check that the MySQL server is running, then click Retry now.'),
        code=code, uncertain=uncertain)


def _translate(err, uncertain=False):
    """A driver error -> DatabaseUnavailable (connection problem) or DatabaseError (the
    server refused this statement). Our own messages only: never the driver's text,
    which may quote SQL values."""
    if isinstance(err, (DatabaseUnavailable, DatabaseError)):
        return err
    code = _code(err)
    lost = (isinstance(err, (pymysql.err.InterfaceError, OSError))
            or (isinstance(err, pymysql.err.OperationalError)
                and (code is None or 2000 <= code < 3000)))
    if lost:
        return _unavailable(code, uncertain=uncertain)
    return DatabaseError(f'The database could not complete the request'
                         f'{f" (MySQL error {code})" if code else ""}.', code=code)


def _is_driver_error(err):
    return isinstance(err, (pymysql.err.MySQLError, OSError))


def get_conn(force=False):
    """A new connection. Raises DatabaseUnavailable when the server cannot be reached
    (immediately, without waiting, during RETRY_AFTER after a failure, unless force)."""
    if not force and is_marked_down():
        raise _unavailable()
    load_dotenv()
    try:
        conn = pymysql.connect(host=os.getenv('DB_HOST', 'localhost'),
                               port=int(os.getenv('DB_PORT', '3306')),
                               user=os.getenv('DB_USER', 'netcommand'),
                               password=os.getenv('DB_PASSWORD', ''),
                               database=os.getenv('DB_NAME', 'netcommand'),
                               charset='utf8mb4', connect_timeout=CONNECT_TIMEOUT,
                               read_timeout=IO_TIMEOUT, write_timeout=IO_TIMEOUT,
                               cursorclass=pymysql.cursors.DictCursor)
    except Exception as err:
        if not _is_driver_error(err):
            raise
        raise _unavailable(_code(err), connecting=True) from None
    _mark_up()
    return conn


def ping():
    """Check the database for real (ignores the fail-fast window). Returns True, or
    raises DatabaseUnavailable / DatabaseError. Used by the GUI's health check."""
    conn = get_conn(force=True)
    try:
        with conn.cursor() as cur:
            cur.execute('SELECT 1')
            cur.fetchone()
        return True
    except Exception as err:
        if not _is_driver_error(err):
            raise
        raise _translate(err) from None
    finally:
        _close(conn)


def _close(conn):
    try:
        conn.close()
    except Exception:
        pass                                  # already closed or broken: nothing to do


def _run(sql, params=(), fetch=None, many=False):
    """Run one statement on its own connection. fetch is 'one', 'all', or None.
    Driver errors become DatabaseUnavailable / DatabaseError (store_errors)."""
    conn = get_conn()
    committing = False
    try:
        with conn.cursor() as cur:
            if many:
                cur.executemany(sql, params)
            else:
                cur.execute(sql, params)
            result = (cur.fetchone() if fetch == 'one' else
                      list(cur.fetchall()) if fetch == 'all' else cur.lastrowid)
        committing = fetch is None             # a write whose outcome is unknown if lost now
        conn.commit()
        return result
    except Exception as err:
        if not _is_driver_error(err):
            raise
        raise _translate(err, uncertain=committing) from None
    finally:
        _close(conn)


def _fail_transaction(conn, err, committing):
    """Roll back (nothing of the transaction is kept) and return the error to raise."""
    try:
        conn.rollback()
    except Exception:
        pass                                  # connection gone: the server rolls it back itself
    if isinstance(err, Exception) and _is_driver_error(err):
        return _translate(err, uncertain=committing)
    return err


def _clean(row):
    if row:
        row.pop('password_enc', None)       # never hand the encrypted password to a screen
        row['managed'] = bool(row['managed'])
    return row


# ---------------------------------------------------------------- devices
SAMPLE_REFUSED = ('Sample (demo) devices cannot be saved to the real database. '
                  'Use sample mode (python main.py --demo) to try them out.')


def upsert_device(d):
    """Insert a device, or update the ACTIVE device that already has this IP. Returns the
    device id. The IP of a soft-deleted device raises DeletedDeviceExists (never restored
    here), and a name another active device uses raises DuplicateDeviceName.
    A device marked 'sample' (from demo mode) is refused before any SQL runs.
    The marker itself is never stored: only the columns listed below are.
    No screen calls it (they use save_device); kept for the store API and its tests. It is
    exactly save_device(None, d) without a login, so it runs in that ONE transaction: the
    deleted-IP check, the locked duplicate-name check and the insert are atomic, and any
    failure rolls everything back."""
    return save_device(None, d)


# Adding an existing ACTIVE IP updates that device. A row that is soft-deleted is left
# exactly as it is (every assignment keeps its old value), so this statement can never
# bring a deleted device back; restore_device is the only way to do that.
_UPSERT_SQL = ('INSERT INTO devices (name, ip, mac, type, managed, status) '
               'VALUES (%s, %s, %s, %s, %s, %s) '
               'ON DUPLICATE KEY UPDATE id = LAST_INSERT_ID(id), '
               'name = IF(is_deleted = 0, VALUES(name), name), '
               'type = IF(is_deleted = 0, VALUES(type), type), '
               'managed = IF(is_deleted = 0, VALUES(managed), managed), '
               'status = IF(is_deleted = 0, VALUES(status), status)')


def _upsert_params(d):
    return (d['name'], d['ip'], d.get('mac', ''), d.get('type', 'unknown'),
            int(bool(d.get('managed'))), d.get('status', 'up'))


# A scan's save (data with 'detected_type'): the same upsert, also recording what the scan
# detected. The type itself is worked out first (device_types.type_after_scan), so a type
# the user changed survives the rescan. Needs the detected_type column
# (schema_update_detected_type.sql); without it the plain upsert above is used.
_UPSERT_DETECTED_SQL = ('INSERT INTO devices (name, ip, mac, type, managed, status, '
                        'detected_type) VALUES (%s, %s, %s, %s, %s, %s, %s) '
                        'ON DUPLICATE KEY UPDATE id = LAST_INSERT_ID(id), '
                        'name = IF(is_deleted = 0, VALUES(name), name), '
                        'type = IF(is_deleted = 0, VALUES(type), type), '
                        'managed = IF(is_deleted = 0, VALUES(managed), managed), '
                        'status = IF(is_deleted = 0, VALUES(status), status), '
                        'detected_type = IF(is_deleted = 0, VALUES(detected_type), '
                        'detected_type)')
_ACTIVE_TYPES_SQL = ('SELECT type, detected_type FROM devices WHERE ip = %s AND is_deleted = 0 '
                     'FOR UPDATE')
NO_SUCH_COLUMN = 1054                    # MySQL: Unknown column (the update was not run yet)


def _scan_upsert(cur, data):
    """Run the upsert for a scan's device; True when detected_type was stored, False when
    the column does not exist yet (then the plain upsert ran and the scan's type is used,
    as before). Runs inside save_device's transaction (the row is locked)."""
    detected = device_types.clean(data.get('detected_type'))
    try:
        cur.execute(_ACTIVE_TYPES_SQL, (data['ip'],))
    except pymysql.err.OperationalError as err:
        if _code(err) != NO_SUCH_COLUMN:
            raise
        cur.execute(_UPSERT_SQL, _upsert_params(data))
        return False
    row = cur.fetchone()
    kind = detected
    if row and row.get('type'):
        kind = device_types.type_after_scan(row.get('type'), row.get('detected_type'), detected)
    cur.execute(_UPSERT_DETECTED_SQL, _upsert_params(dict(data, type=kind)) + (detected,))
    return True


def _check_name(name):
    """The same name rules as the screens (validation.check_name), checked before any
    database work. A name with spaces around it is refused, never trimmed silently."""
    problem = validation.check_name(name)
    if not problem and name != name.strip():
        problem = 'The name cannot start or end with a space.'
    if problem:
        raise ValueError(problem)


def _name_taken_query(name, exclude_id=None, exclude_ip=None, lock=False):
    """SQL + params finding an ACTIVE device (is_deleted = 0) that already uses this name,
    ignoring capital letters. Deleted devices never count.

    Comparison: LOWER() on both sides, then COLLATE utf8mb4_bin, so the result does not
    depend on the column's or the connection's collation (the default utf8mb4_0900_ai_ci
    would also treat accented letters as equal). Names are ASCII only (validation), where
    MySQL's LOWER() and Python's str.lower() agree, so db_fake compares the same way.

    exclude_id: the device being edited (its own name is no conflict). exclude_ip: adding
    an IP that an active device already has updates that device, so it is excluded.
    lock: FOR UPDATE, inside a transaction. The name has no index, so InnoDB scans the
    table and (at the default REPEATABLE READ) locks every row and the gaps between them
    until commit: another save that adds or renames a device waits, so two saves cannot
    both pass the check with the same name."""
    sql = ('SELECT id, name FROM devices WHERE is_deleted = 0 '
           'AND LOWER(name) COLLATE utf8mb4_bin = LOWER(%s) COLLATE utf8mb4_bin')
    params = [name]
    if exclude_id is not None:
        sql += ' AND id <> %s'
        params.append(exclude_id)
    if exclude_ip is not None:
        sql += ' AND ip <> %s'
        params.append(exclude_ip)
    sql += ' ORDER BY id LIMIT 1' + (' FOR UPDATE' if lock else '')
    return sql, tuple(params)


PASSWORD_ENC_MAX = 255          # devices.password_enc is VARCHAR(255)


def _encrypted_login(user, password):
    """Check a login and encrypt its password, before any database work.
    Returns the Fernet token (never logged or shown)."""
    problem = validation.check_login(user, password)
    if problem:
        raise ValueError(problem)
    token = security.encrypt(password)
    if len(token) > PASSWORD_ENC_MAX:
        raise ValueError('The login password is too long to store. Nothing was saved.')
    return token


_DELETED_BY_IP_SQL = ("SELECT id, name, ip, type, (username <> '' AND password_enc <> '') "
                      "AS has_login FROM devices WHERE ip = %s AND is_deleted = 1")
_DELETED_BY_ID_SQL = ("SELECT id, name, ip, type, (username <> '' AND password_enc <> '') "
                      "AS has_login FROM devices WHERE id = %s AND is_deleted = 1")


def get_deleted_device_by_ip(ip):
    """The soft-deleted device that owns this IP, or None. Only non-sensitive details:
    {'id', 'name', 'ip', 'type', 'has_login'} (has_login: whether a login is saved)."""
    row = _run(_DELETED_BY_IP_SQL, (ip,), 'one')
    if row:
        row['has_login'] = bool(row['has_login'])
    return row


def save_device(device_id, data, username=None, password=None):
    """Add (device_id None) or edit a device, and optionally save its login, as ONE
    transaction: both are saved or neither. Returns the device id.
    A blank login (username and password both empty) leaves the saved login unchanged.
    Adding an IP that belongs to an ACTIVE device updates that device (as upsert_device
    does). An IP that belongs to a soft-DELETED device raises DeletedDeviceExists: the
    deleted record is not restored or changed (restoring is restore_device's job).

    Everything that can be checked is checked before connecting: the sample marker,
    the login (validation.check_login), and the password is encrypted first, so a
    FERNET_KEY problem or a too-long token never leaves half a save behind."""
    if data.get('sample'):
        raise ValueError(SAMPLE_REFUSED)
    _check_name(data['name'])
    user = (username or '').strip()
    token = _encrypted_login(user, password) if (user or password) else None
    conn = get_conn()
    committing = False
    try:
        with conn.cursor() as cur:
            # Locks the row (if any) for the rest of this transaction.
            cur.execute(_DELETED_BY_IP_SQL + ' FOR UPDATE', (data['ip'],))
            deleted = cur.fetchone()
            if deleted and deleted['id'] != device_id:
                raise DeletedDeviceExists(deleted)
            # Same transaction, locked: another active device must not have this name.
            if device_id is None:
                sql, params = _name_taken_query(data['name'], exclude_ip=data['ip'], lock=True)
            else:
                sql, params = _name_taken_query(data['name'], exclude_id=device_id, lock=True)
            cur.execute(sql, params)
            taken = cur.fetchone()
            if taken:
                raise DuplicateDeviceName(data['name'], taken)
            if device_id is None:
                if 'detected_type' in data:          # a scan's device
                    _scan_upsert(cur, data)
                else:
                    cur.execute(_UPSERT_SQL, _upsert_params(data))
                did = cur.lastrowid
                # The upsert SQL never changes a deleted row. Should the row with this IP
                # be a deleted one after all, say so (and roll back) instead of reporting
                # it as saved.
                cur.execute(_DELETED_BY_ID_SQL, (did,))
                gone = cur.fetchone()
                if gone:
                    gone['has_login'] = bool(gone['has_login'])
                    raise DeletedDeviceExists(gone)
            else:
                cur.execute('SELECT name FROM devices WHERE id = %s', (device_id,))
                old = cur.fetchone()
                if old is None:
                    raise ValueError('This device no longer exists in the database.')
                # The status belongs to the monitor: without one in data it is kept.
                cur.execute('UPDATE devices SET name = %s, ip = %s, type = %s, '
                            'status = COALESCE(%s, status), managed = %s WHERE id = %s',
                            (data['name'], data['ip'], data['type'], data.get('status'),
                             int(bool(data['managed'])), device_id))
                if old['name'] != data['name']:      # keep the saved links pointing at the device
                    cur.execute('UPDATE links SET device_a = %s WHERE device_a = %s',
                                (data['name'], old['name']))
                    cur.execute('UPDATE links SET device_b = %s WHERE device_b = %s',
                                (data['name'], old['name']))
                did = device_id
            if token is not None:
                cur.execute('UPDATE devices SET username = %s, password_enc = %s WHERE id = %s',
                            (user, token, did))
        committing = True                     # lost from here on: outcome unknown
        conn.commit()
        return did
    except BaseException as err:
        problem = _fail_transaction(conn, err, committing)   # nothing of this save is kept
        if problem is err:
            raise
        raise problem from None
    finally:
        _close(conn)


def restore_device(device_id, data, *, credentials, username=None, password=None):
    """Explicitly restore the soft-deleted device with this id, as ONE transaction.

    data: the new name / type / status / managed; data['ip'] must be the deleted
    device's own IP (a device is identified by its id, never by a matching IP).
    credentials (required, no default): 'keep' leaves the saved username and encrypted
    password exactly as they are; 'replace' saves the new username + password (checked
    and encrypted before connecting). Raises DeviceNotDeleted if the device is not
    deleted (for example already restored). Any failure rolls everything back."""
    if credentials not in ('keep', 'replace'):
        raise ValueError("Choose 'keep' or 'replace' for the saved login.")
    if data.get('sample'):
        raise ValueError(SAMPLE_REFUSED)
    _check_name(data['name'])
    mac = (data.get('mac') or '').strip()     # empty: keep the stored MAC; never blank it out
    if mac:
        problem = validation.check_mac(mac)
        if problem:
            raise ValueError(problem + ' Nothing was changed.')
    user = (username or '').strip()
    token = None
    if credentials == 'replace':
        if not user or not password:                  # never replace a login with blanks
            raise ValueError('Enter the new login username and password, or keep the saved '
                             'login.')
        token = _encrypted_login(user, password)
    elif user or password:
        raise ValueError('A new login was entered but "keep the saved login" was chosen.')
    conn = get_conn()
    committing = False
    try:
        with conn.cursor() as cur:
            cur.execute('SELECT id, name, ip, is_deleted FROM devices WHERE id = %s FOR UPDATE',
                        (device_id,))
            row = cur.fetchone()
            if row is None:
                raise ValueError('This device no longer exists in the database.')
            if not row['is_deleted']:
                raise DeviceNotDeleted(f"{row['name']} ({row['ip']}) is not deleted "
                                       f"(it may already have been restored). Nothing was changed.")
            if data['ip'] != row['ip']:
                raise ValueError(f"Device {device_id} has IP {row['ip']}, not {data['ip']}. "
                                 f"Nothing was changed.")
            # The restored device becomes active: no other active device may have its name.
            sql, params = _name_taken_query(data['name'], exclude_id=device_id, lock=True)
            cur.execute(sql, params)
            taken = cur.fetchone()
            if taken:
                raise DuplicateDeviceName(data['name'], taken)
            set_mac = ', mac = %s' if mac else ''
            values = [data['name'], data.get('type', 'unknown'), data.get('status', 'up'),
                      int(bool(data.get('managed')))] + ([mac] if mac else []) + [device_id]
            cur.execute('UPDATE devices SET name = %s, type = %s, status = %s, managed = %s'
                        + set_mac + ', is_deleted = 0 WHERE id = %s AND is_deleted = 1',
                        tuple(values))
            if cur.rowcount != 1:
                raise DeviceNotDeleted('The device changed while it was being restored. '
                                       'Nothing was changed.')
            if row['name'] != data['name']:           # keep its saved links pointing at it
                cur.execute('UPDATE links SET device_a = %s WHERE device_a = %s',
                            (data['name'], row['name']))
                cur.execute('UPDATE links SET device_b = %s WHERE device_b = %s',
                            (data['name'], row['name']))
            if token is not None:
                cur.execute('UPDATE devices SET username = %s, password_enc = %s WHERE id = %s',
                            (user, token, device_id))
        committing = True                     # lost from here on: outcome unknown
        conn.commit()
        return device_id
    except BaseException as err:
        problem = _fail_transaction(conn, err, committing)   # nothing of this restore is kept
        if problem is err:
            raise
        raise problem from None
    finally:
        _close(conn)


def update_device(device_id, data):
    """Edit a device (name, ip, type, status, managed; the login is left alone).
    No screen calls it (they use save_device); kept for the store API and its tests. It is
    exactly save_device(device_id, data) without a login: one transaction with the locked
    duplicate-name check, the update and the link renames, all or nothing. A device id
    that does not exist raises ValueError (it used to do nothing)."""
    save_device(device_id, data)


def delete_device(device_id):                    # soft delete: the logs stay valid
    _run('UPDATE devices SET is_deleted = 1 WHERE id = %s', (device_id,))


def get_device(device_id):
    return _clean(_run('SELECT * FROM devices WHERE id = %s AND is_deleted = 0',
                       (device_id,), 'one'))


def get_device_by_ip(ip):
    return _clean(_run('SELECT * FROM devices WHERE ip = %s AND is_deleted = 0',
                       (ip,), 'one'))


def get_device_by_name(name):
    return _clean(_run('SELECT * FROM devices WHERE name = %s AND is_deleted = 0 '
                       'ORDER BY id LIMIT 1', (name,), 'one'))


def count_devices(search=''):
    like = f'%{search}%'
    row = _run('SELECT COUNT(*) AS n FROM devices WHERE is_deleted = 0 '
               'AND (name LIKE %s OR ip LIKE %s)', (like, like), 'one')
    return row['n']


def get_devices(search='', sort_by='name', page=1, per_page=15):
    order = SORT_SQL.get(sort_by, 'name')
    like = f'%{search}%'
    rows = _run(f'SELECT * FROM devices WHERE is_deleted = 0 '
                f'AND (name LIKE %s OR ip LIKE %s) ORDER BY {order}, id '
                f'LIMIT %s OFFSET %s',
                (like, like, per_page, (max(page, 1) - 1) * per_page), 'all')
    return [_clean(r) for r in rows]


def set_status(device_id, status):
    _run('UPDATE devices SET status = %s WHERE id = %s', (status, device_id))


# ---------------------------------------------------------------- logins
def save_credentials(device_id, username, password):
    _run('UPDATE devices SET username = %s, password_enc = %s WHERE id = %s',
         (username, security.encrypt(password), device_id))


def get_credentials(device_id):
    """Returns (username, password) decrypted, or ('', '') when none is saved."""
    row = _run('SELECT username, password_enc FROM devices WHERE id = %s',
               (device_id,), 'one')
    if not row or not row['username'] or not row['password_enc']:
        return '', ''
    return row['username'], security.decrypt(row['password_enc'])


# ---------------------------------------------------------------- links
def save_links(links):
    if links:
        _run('INSERT IGNORE INTO links (device_a, port_a, device_b, port_b) '
             'VALUES (%s, %s, %s, %s)', [tuple(l) for l in links], many=True)


def get_links():
    """Only links whose two devices are both still registered."""
    rows = _run('SELECT device_a, port_a, device_b, port_b FROM links '
                'WHERE device_a IN (SELECT name FROM devices WHERE is_deleted = 0) '
                'AND device_b IN (SELECT name FROM devices WHERE is_deleted = 0) '
                'ORDER BY id', (), 'all')
    return [(r['device_a'], r['port_a'], r['device_b'], r['port_b']) for r in rows]


# ---------------------------------------------------------------- logs
def add_log(device_id, action, status, details=''):
    return _run('INSERT INTO config_logs (device_id, action, status, details) '
                'VALUES (%s, %s, %s, %s)', (device_id, action, status, details))


def _log_filter(search, status, within_hours=None):
    like = f'%{search}%'
    sql = ('FROM config_logs l JOIN devices d ON d.id = l.device_id '
           'WHERE (d.name LIKE %s OR l.action LIKE %s OR l.details LIKE %s)')
    params = [like, like, like]
    if status:
        sql += ' AND l.status = %s'
        params.append(status)
    if within_hours is not None:
        # compared with the server's clock, the same clock that filled created_at
        sql += ' AND l.created_at >= NOW() - INTERVAL %s HOUR'
        params.append(int(within_hours))
    return sql, params


def count_logs(search='', status='', within_hours=None):
    """within_hours: only entries from the last N hours (None: all of them)."""
    sql, params = _log_filter(search, status, within_hours)
    return _run('SELECT COUNT(*) AS n ' + sql, params, 'one')['n']


def get_logs(search='', page=1, per_page=15, status='', within_hours=None):
    sql, params = _log_filter(search, status, within_hours)
    return _run('SELECT l.id, l.created_at, d.name AS device, l.action, l.status, '
                'l.details ' + sql + ' ORDER BY l.id DESC LIMIT %s OFFSET %s',
                params + [per_page, (max(page, 1) - 1) * per_page], 'all')


# ---------------------------------------------------------------- Console history
# Everything the Console shows (gui.event_log), saved. The console_log table is APPEND-ONLY:
# its triggers refuse every UPDATE and DELETE (schema_update_console_log.sql), so nobody,
# not even this app's own database account, can change or remove an entry. There is
# deliberately no function here that would try.
CONSOLE_COLUMNS = ('created_at', 'user_label', 'category', 'device', 'device_ip', 'message',
                   'result', 'level', 'tags', 'detail')
CONSOLE_LIMITS = {'user_label': 120, 'category': 20, 'device': 80, 'device_ip': 45,
                  'result': 500, 'tags': 100}


def _console_row(r):
    values = []
    for c in CONSOLE_COLUMNS:
        v = r.get(c)
        if isinstance(v, str) and c in CONSOLE_LIMITS:
            v = v[:CONSOLE_LIMITS[c]]
        values.append(v)
    return tuple(values)


def add_console_events(rows):
    """Save Console records (gui.event_log.row_of), all in one statement."""
    if not rows:
        return
    _run(f"INSERT INTO console_log ({', '.join(CONSOLE_COLUMNS)}) "
         f"VALUES ({', '.join(['%s'] * len(CONSOLE_COLUMNS))})",
         [_console_row(r) for r in rows], many=True)


def _console_filter(search='', tag='', user='', category='', device=''):
    sql, params = 'FROM console_log WHERE 1 = 1', []
    if search:
        like = f'%{search}%'
        sql += (' AND (message LIKE %s OR result LIKE %s OR device LIKE %s OR device_ip LIKE %s'
                ' OR user_label LIKE %s)')
        params += [like] * 5
    if tag:
        sql += ' AND FIND_IN_SET(%s, tags)'
        params.append(tag)
    for column, value in (('user_label', user), ('category', category), ('device', device)):
        if value:
            sql += f' AND {column} = %s'          # column names from this fixed list only
            params.append(value)
    return sql, params


def count_console_events(search='', tag='', user='', category='', device=''):
    sql, params = _console_filter(search, tag, user, category, device)
    return _run('SELECT COUNT(*) AS n ' + sql, params, 'one')['n']


def get_console_events(search='', page=1, per_page=15, tag='', user='', category='',
                       device=''):
    """Newest first."""
    sql, params = _console_filter(search, tag, user, category, device)
    return _run('SELECT id, ' + ', '.join(CONSOLE_COLUMNS) + ' ' + sql +
                ' ORDER BY id DESC LIMIT %s OFFSET %s',
                params + [per_page, (max(page, 1) - 1) * per_page], 'all')


def console_event_users():
    """Every user name in the saved history (for the Logs page's User filter)."""
    rows = _run('SELECT DISTINCT user_label FROM console_log ORDER BY user_label LIMIT 500',
                (), 'all')
    return [r['user_label'] for r in rows]


# ---------------------------------------------------------------- findings
def clear_findings():
    _run('DELETE FROM findings')


def add_finding(f):
    """f is a finding dictionary (device is the device NAME). Findings about a
    device that is not registered (for example sample data) are skipped."""
    dev = get_device_by_name(f['device'])
    if not dev:
        return None
    return _run('INSERT INTO findings (device_id, rule, severity, message, commands) '
                'VALUES (%s, %s, %s, %s, %s)',
                (dev['id'], f['rule'], f['severity'], f['message'],
                 '\n'.join(f['commands'])))


_FINDING_INSERT_SQL = ('INSERT INTO findings (device_id, rule, severity, message, commands) '
                       'VALUES (%s, %s, %s, %s, %s)')


def replace_findings(findings):
    """Replace the stored review (the findings snapshot) with these findings, as ONE
    transaction: the old rows are deleted and the new ones inserted together, or, on any
    failure, nothing changes and the previous snapshot stays exactly as it was.
    An empty list is a real result (a review that found no problems): it clears the
    snapshot. Findings about a device that is not an active registered device are not
    stored (as add_finding). Returns {'saved': n, 'skipped': [device names not stored]}."""
    names = sorted({f['device'] for f in findings})
    conn = get_conn()
    committing = False
    try:
        with conn.cursor() as cur:
            ids = {}
            for name in names:
                cur.execute('SELECT id FROM devices WHERE name = %s AND is_deleted = 0 '
                            'ORDER BY id LIMIT 1', (name,))
                row = cur.fetchone()
                if row:
                    ids[name] = row['id']
            rows = [(ids[f['device']], f['rule'], f['severity'], f['message'],
                     '\n'.join(f['commands'])) for f in findings if f['device'] in ids]
            cur.execute('DELETE FROM findings')
            if rows:
                cur.executemany(_FINDING_INSERT_SQL, rows)
        committing = True                     # lost from here on: outcome unknown
        conn.commit()
        return {'saved': len(rows), 'skipped': [n for n in names if n not in ids]}
    except BaseException as err:
        problem = _fail_transaction(conn, err, committing)   # the old snapshot is kept
        if problem is err:
            raise
        raise problem from None
    finally:
        _close(conn)


def get_findings_snapshot():
    """The stored review, read in one statement: {'findings': [...], 'saved_at': datetime
    or None}. Each finding also says whether its device has been deleted since
    ('device_deleted'). No findings: no review saved yet, or the last one found nothing."""
    rows = _run('SELECT f.id, d.name AS device, d.is_deleted AS device_deleted, f.rule, '
                'f.severity, f.message, f.commands, f.created_at '
                'FROM findings f JOIN devices d ON d.id = f.device_id '
                'ORDER BY f.severity, f.id', (), 'all')     # ENUM sorts high, medium, low
    for r in rows:
        r['commands'] = (r['commands'] or '').split('\n')
        r['device_deleted'] = bool(r['device_deleted'])
    saved = [r['created_at'] for r in rows if r.get('created_at')]
    return {'findings': rows, 'saved_at': max(saved) if saved else None}


def get_findings(search='', page=1, per_page=15):
    like = f'%{search}%'
    rows = _run('SELECT f.id, d.name AS device, f.rule, f.severity, f.message, '
                'f.commands, f.created_at FROM findings f JOIN devices d ON d.id = f.device_id '
                'WHERE d.name LIKE %s OR f.rule LIKE %s OR f.message LIKE %s '
                'ORDER BY f.severity, f.id '   # ENUM sorts high, medium, low
                'LIMIT %s OFFSET %s',
                (like, like, like, per_page, (max(page, 1) - 1) * per_page), 'all')
    for r in rows:
        r['commands'] = (r['commands'] or '').split('\n')
    return rows


# ---------------------------------------------------------------- status events
def add_event(device_id, kind, detail=''):
    return _run('INSERT INTO status_events (device_id, kind, detail) VALUES (%s, %s, %s)',
                (device_id, kind, detail))


# A device is either up or down, so the status before an event is the other one.
PREVIOUS_STATUS = {'up': 'down', 'down': 'up'}


def record_status_change(device_id, old, new, detail=''):
    """Change a device's status from old to new AND record the event, as ONE transaction:
    both or neither. Only an active device whose status is still old is changed; if it
    changed meanwhile (or was deleted), nothing is written and False is returned.
    Returns True when the change and its event were saved."""
    conn = get_conn()
    committing = False
    try:
        with conn.cursor() as cur:
            cur.execute('UPDATE devices SET status = %s '
                        'WHERE id = %s AND status = %s AND is_deleted = 0',
                        (new, device_id, old))
            if cur.rowcount != 1:
                conn.rollback()
                return False
            cur.execute('INSERT INTO status_events (device_id, kind, detail) '
                        'VALUES (%s, %s, %s)', (device_id, new, detail))
        committing = True
        conn.commit()
        return True
    except BaseException as err:
        problem = _fail_transaction(conn, err, committing)   # status and event: neither
        if problem is err:
            raise
        raise problem from None
    finally:
        _close(conn)


def get_events(limit=50):
    """The newest status events: id, created_at, device (name), kind (the new status),
    previous (the status before), detail. Events of deleted devices are kept (history)."""
    rows = _run('SELECT e.id, e.created_at, d.name AS device, e.kind, e.detail '
                'FROM status_events e JOIN devices d ON d.id = e.device_id '
                'ORDER BY e.id DESC LIMIT %s', (limit,), 'all')
    for r in rows:
        r['previous'] = PREVIOUS_STATUS.get(r['kind'])
    return rows
