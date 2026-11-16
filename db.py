"""MySQL store. Same function names as db_fake.py, so the screens never change.

Rules: every value goes in through %s placeholders (never pasted into the SQL,
which blocks SQL injection). The only text put into SQL is the ORDER BY column,
and it comes from the fixed SORT_SQL dictionary below.
"""
import os

import pymysql
from dotenv import load_dotenv

import security

load_dotenv()

# sort_by from the screen -> the SQL used (only these are ever allowed)
SORT_SQL = {'name': 'name', 'ip': 'INET_ATON(ip)', 'type': 'type',
            'status': 'status', 'created_at': 'created_at'}


def get_conn():
    load_dotenv()
    return pymysql.connect(host=os.getenv('DB_HOST', 'localhost'),
                           user=os.getenv('DB_USER', 'netcommand'),
                           password=os.getenv('DB_PASSWORD', ''),
                           database=os.getenv('DB_NAME', 'netcommand'),
                           charset='utf8mb4', connect_timeout=5,
                           cursorclass=pymysql.cursors.DictCursor)


def _run(sql, params=(), fetch=None, many=False):
    """Run one statement on its own connection. fetch is 'one', 'all', or None."""
    conn = get_conn()
    try:
        with conn.cursor() as cur:
            if many:
                cur.executemany(sql, params)
            else:
                cur.execute(sql, params)
            result = (cur.fetchone() if fetch == 'one' else
                      list(cur.fetchall()) if fetch == 'all' else cur.lastrowid)
        conn.commit()
        return result
    finally:
        conn.close()


def _clean(row):
    if row:
        row.pop('password_enc', None)       # never hand the encrypted password to a screen
        row['managed'] = bool(row['managed'])
    return row


# ---------------------------------------------------------------- devices
SAMPLE_REFUSED = ('Sample (demo) devices cannot be saved to the real database. '
                  'Use sample mode (python main.py --demo) to try them out.')


def upsert_device(d):
    """Insert a device, or update it when the IP is already known (this also
    brings back a soft-deleted device). Returns the device id.
    A device marked 'sample' (from demo mode) is refused before any SQL runs.
    The marker itself is never stored: only the columns listed below are."""
    if d.get('sample'):
        raise ValueError(SAMPLE_REFUSED)
    return _run(
        'INSERT INTO devices (name, ip, mac, type, managed, status) '
        'VALUES (%s, %s, %s, %s, %s, %s) '
        'ON DUPLICATE KEY UPDATE id = LAST_INSERT_ID(id), name = VALUES(name), '
        'type = VALUES(type), managed = VALUES(managed), status = VALUES(status), '
        'is_deleted = 0',
        (d['name'], d['ip'], d.get('mac', ''), d.get('type', 'unknown'),
         int(bool(d.get('managed'))), d.get('status', 'up')))


def update_device(device_id, data):
    old = get_device(device_id)
    _run('UPDATE devices SET name = %s, ip = %s, type = %s, status = %s, managed = %s '
         'WHERE id = %s',
         (data['name'], data['ip'], data['type'], data['status'],
          int(bool(data['managed'])), device_id))
    if old and old['name'] != data['name']:      # keep the saved links pointing at the device
        _run('UPDATE links SET device_a = %s WHERE device_a = %s', (data['name'], old['name']))
        _run('UPDATE links SET device_b = %s WHERE device_b = %s', (data['name'], old['name']))


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


def _log_filter(search, status):
    like = f'%{search}%'
    sql = ('FROM config_logs l JOIN devices d ON d.id = l.device_id '
           'WHERE (d.name LIKE %s OR l.action LIKE %s OR l.details LIKE %s)')
    params = [like, like, like]
    if status:
        sql += ' AND l.status = %s'
        params.append(status)
    return sql, params


def count_logs(search='', status=''):
    sql, params = _log_filter(search, status)
    return _run('SELECT COUNT(*) AS n ' + sql, params, 'one')['n']


def get_logs(search='', page=1, per_page=15, status=''):
    sql, params = _log_filter(search, status)
    return _run('SELECT l.id, l.created_at, d.name AS device, l.action, l.status, '
                'l.details ' + sql + ' ORDER BY l.id DESC LIMIT %s OFFSET %s',
                params + [per_page, (max(page, 1) - 1) * per_page], 'all')


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


def get_events(limit=50):
    return _run('SELECT e.id, e.created_at, d.name AS device, e.kind, e.detail '
                'FROM status_events e JOIN devices d ON d.id = e.device_id '
                'ORDER BY e.id DESC LIMIT %s', (limit,), 'all')
