"""Shared application data on MySQL (the app_* tables of migrations 2-4), for the
runtime account (SELECT/INSERT/UPDATE; no DELETE anywhere, see privileges.py).

Persistence only: no HTTP, no permission checks (the API layer decides who may call
what), no encryption (the backend encrypts a password before it reaches this layer and
decrypts it only for a server-side device job). Every method:
  * checks its values first (app_records): nothing is sent for an invalid value, and a
    plaintext password or backup where a Fernet token belongs is refused;
  * runs in ONE short transaction on its own connection: committed, or rolled back on any
    error. Driver errors become the same errors InMemoryAppRepository raises (NotFound,
    DuplicateDeviceName, DuplicateDeviceIp, ...) or BackendDatabaseUnavailable /
    BackendDatabaseError; messages never contain values;
  * passes every value as a %s parameter (the only SQL text chosen at run time is an
    ORDER BY expression from a fixed table, and placeholder lists);
  * takes times from the database (UTC_TIMESTAMP(6); the connection's time zone is UTC).

Rules kept from the desktop store (db.py): soft delete only; an IP stays unique even for
deleted devices and is never silently restored; active names are unique ignoring capital
letters (also enforced by the uq_app_devices_active_name index); renaming a device
renames its links; findings are replaced as one snapshot; a status change and its event
are saved together, only if the status is still the old one.

New here: optimistic locking (app_devices.version; pass expected_version), actor columns,
credentials in their own table (device rows never include the token: only has_login),
jobs, device locks and backup metadata. Device, credential and backup changes write their
audit_log record in the SAME transaction.
"""
import json
import secrets
from datetime import timedelta

from backend.database import app_records as R
from backend.database.app_memory_repository import (BACKUP_FIELDS, DEVICE_GONE, JOB_GONE,
                                                    LOCK_FIELDS, LOCK_GONE, PREVIOUS_STATUS,
                                                    USER_GONE)
from backend.database.connection import close_quietly, connect_runtime, driver_error_code, \
    is_driver_error, translate
from backend.database.errors import (DeletedDeviceExists, DeviceLockHeld, DeviceNotDeleted,
                                     DuplicateDeviceIp, DuplicateDeviceName, InvalidTransition,
                                     InvalidValue, NotFound, VersionConflict)

NOW = 'UTC_TIMESTAMP(6)'
_DEVICE_SELECT = ('SELECT d.id, d.name, d.ip, d.mac, d.type, d.managed, d.status, d.version, '
                  'd.created_at, d.updated_at, d.created_by, d.updated_by, '
                  '(c.device_id IS NOT NULL) AS has_login '
                  'FROM app_devices d LEFT JOIN app_device_credentials c ON c.device_id = d.id')
# Sort expressions: the same order as the in-memory repository (active_name_key is
# LOWER(name) in utf8mb4_bin, i.e. Python's order of name.lower()).
ORDER = {'name': 'd.active_name_key', 'ip': 'INET_ATON(d.ip)', 'type': 'CAST(d.type AS CHAR)',
         'status': 'CAST(d.status AS CHAR)', 'created_at': 'd.id'}
_JOB_COLUMNS = ('id, kind, state, requested_by, params, summary, created_at, updated_at, '
                'started_at, finished_at')
_LOCK_COLUMNS = ', '.join(LOCK_FIELDS)
_BACKUP_COLUMNS = ', '.join(BACKUP_FIELDS)
# Foreign keys -> what is missing (error 1452).
_FK_MISSING = (('user', USER_GONE), ('created_by', USER_GONE), ('updated_by', USER_GONE),
               ('requested_by', USER_GONE), ('holder', USER_GONE), ('job', JOB_GONE),
               ('device', DEVICE_GONE))


def _like(search):
    return '%' + R.escape_like(R.check_search(search).lower()) + '%'


def _device(row):
    if row:
        row['managed'], row['has_login'] = bool(row['managed']), bool(row['has_login'])
    return row


def _commands(value):
    return value.split('\n') if value else []


def _placeholders(values):
    return ', '.join(['%s'] * len(values))


class AppRepository:
    def __init__(self, connect):
        """connect(): a new DB-API connection (PyMySQL, DictCursor, autocommit off)."""
        self._connect = connect

    @classmethod
    def from_settings(cls, settings):
        return cls(lambda: connect_runtime(settings))

    # ------------------------------------------------------------ transactions
    def _tx(self, work, conflicts=None):
        """One transaction. conflicts: {unique key name: () -> error} for duplicate-key
        errors (1062) that only the database's unique index caught (a race)."""
        conn = self._connect()
        committing = False
        try:
            with conn.cursor() as cur:
                result = work(cur)
            committing = True
            conn.commit()
            return result
        except BaseException as err:
            try:
                conn.rollback()
            except Exception:
                pass
            if isinstance(err, Exception) and is_driver_error(err):
                raise self._translate(err, committing, conflicts or {}) from None
            raise
        finally:
            close_quietly(conn)

    @staticmethod
    def _translate(err, committing, conflicts):
        code, text = driver_error_code(err), str(err)
        if code == 1062:
            for key, make in conflicts.items():
                if key in text:
                    return make()
        if code == 1452:
            for fragment, message in _FK_MISSING:
                if f'_{fragment}' in text:
                    return NotFound(message)
            return NotFound('A referenced record does not exist.')
        return translate(err, uncertain=committing)

    def _read(self, sql, params=(), one=False):
        def work(cur):
            cur.execute(sql, params)
            return cur.fetchone() if one else list(cur.fetchall())
        return self._tx(work)

    # ------------------------------------------------------------ shared steps
    @staticmethod
    def _audit(cur, action, device_id, actor, detail=None):
        cur.execute('INSERT INTO audit_log (created_at, actor_user_id, action, target_type, '
                    "target_id, outcome, detail) VALUES (UTC_TIMESTAMP(6), %s, %s, 'device', "
                    "%s, 'success', %s)", (actor, action, str(device_id), detail))

    @staticmethod
    def _has_login(cur, device_id):
        cur.execute('SELECT device_id FROM app_device_credentials WHERE device_id = %s',
                    (device_id,))
        return cur.fetchone() is not None

    def _deleted_info(self, cur, row):
        return {'id': row['id'], 'name': row['name'], 'ip': row['ip'], 'type': row['type'],
                'has_login': self._has_login(cur, row['id'])}

    @staticmethod
    def _name_taken(cur, name, exclude_id=None):
        """The ACTIVE device using this name ignoring capital letters, locked (FOR UPDATE on
        the unique index: at REPEATABLE READ this also locks the gap, so a concurrent save
        of the same name waits for this transaction)."""
        cur.execute('SELECT id, name FROM app_devices WHERE active_name_key = %s FOR UPDATE',
                    (R.name_key(name),))
        row = cur.fetchone()
        if row and row['id'] != exclude_id:
            return {'id': row['id'], 'name': row['name']}
        return None

    @staticmethod
    def _lock_device(cur, device_id):
        cur.execute('SELECT id, name, ip, type, version, is_deleted FROM app_devices '
                    'WHERE id = %s FOR UPDATE', (device_id,))
        return cur.fetchone()

    def _active_device(self, cur, device_id):
        R.check_id(device_id, 'device_id')
        cur.execute('SELECT id FROM app_devices WHERE id = %s AND is_deleted = 0 FOR SHARE',
                    (device_id,))
        if cur.fetchone() is None:
            raise NotFound(DEVICE_GONE)

    @staticmethod
    def _any_device(cur, device_id):
        R.check_id(device_id, 'device_id')
        cur.execute('SELECT id FROM app_devices WHERE id = %s', (device_id,))
        if cur.fetchone() is None:
            raise NotFound(DEVICE_GONE)

    @staticmethod
    def _job_exists(cur, job_id):
        if job_id is None:
            return
        R.check_id(job_id, 'job_id')
        cur.execute('SELECT id FROM app_jobs WHERE id = %s', (job_id,))
        if cur.fetchone() is None:
            raise NotFound(JOB_GONE)

    @staticmethod
    def _check_version(row, expected_version):
        if expected_version is not None:
            R.check_id(expected_version, 'expected_version')
            if row['version'] != expected_version:
                raise VersionConflict(row['version'])

    @staticmethod
    def _rename_links(cur, device_id, old, new):
        if old == new:
            return
        for side in ('a', 'b'):
            cur.execute(f'UPDATE app_links SET device_{side} = %s, device_{side}_id = %s '
                        f'WHERE device_{side} = %s OR device_{side}_id = %s',
                        (new, device_id, old, device_id))

    def _write_credentials(self, cur, device_id, username, password_enc, key_id, actor):
        cur.execute('SELECT device_id FROM app_device_credentials WHERE device_id = %s '
                    'FOR UPDATE', (device_id,))
        if cur.fetchone():
            cur.execute('UPDATE app_device_credentials SET username = %s, password_enc = %s, '
                        'key_id = %s, updated_at = UTC_TIMESTAMP(6), updated_by = %s '
                        'WHERE device_id = %s', (username, password_enc, key_id, actor,
                                                 device_id))
            detail = 'login replaced'
        else:
            cur.execute('INSERT INTO app_device_credentials (device_id, username, password_enc, '
                        'key_id, created_at, updated_at, updated_by) VALUES (%s, %s, %s, %s, '
                        'UTC_TIMESTAMP(6), UTC_TIMESTAMP(6), %s)',
                        (device_id, username, password_enc, key_id, actor))
            detail = 'login saved'
        self._audit(cur, 'device.credentials_set', device_id, actor, detail)

    @staticmethod
    def _now(cur):
        cur.execute('SELECT UTC_TIMESTAMP(6) AS now', ())
        return cur.fetchone()['now']

    # ------------------------------------------------------------ devices: writes
    def upsert_device(self, data, *, actor_user_id=None):
        d = R.check_device(data)
        R.check_optional_id(actor_user_id, 'actor_user_id')

        def work(cur):
            cur.execute('SELECT id, name, ip, type, is_deleted FROM app_devices WHERE ip = %s '
                        'FOR UPDATE', (d['ip'],))
            existing = cur.fetchone()
            if existing and existing['is_deleted']:
                raise DeletedDeviceExists(self._deleted_info(cur, existing))
            taken = self._name_taken(cur, d['name'], existing['id'] if existing else None)
            if taken:
                raise DuplicateDeviceName(d['name'], taken)
            if existing:
                cur.execute('UPDATE app_devices SET name = %s, type = %s, managed = %s, '
                            'status = %s, version = version + 1, updated_at = UTC_TIMESTAMP(6), '
                            'updated_by = %s WHERE id = %s',
                            (d['name'], d['type'], int(d['managed']), d['status'], actor_user_id,
                             existing['id']))
                self._rename_links(cur, existing['id'], existing['name'], d['name'])
                self._audit(cur, 'device.update', existing['id'], actor_user_id)
                return existing['id']
            cur.execute('INSERT INTO app_devices (name, ip, mac, type, managed, status, '
                        'created_at, updated_at, created_by, updated_by) VALUES (%s, %s, %s, '
                        '%s, %s, %s, UTC_TIMESTAMP(6), UTC_TIMESTAMP(6), %s, %s)',
                        (d['name'], d['ip'], d['mac'], d['type'], int(d['managed']),
                         d['status'], actor_user_id, actor_user_id))
            device_id = cur.lastrowid
            self._audit(cur, 'device.create', device_id, actor_user_id)
            return device_id
        return self._tx(work, self._device_conflicts(d))

    @staticmethod
    def _device_conflicts(d):
        return {'uq_app_devices_active_name': lambda: DuplicateDeviceName(d['name']),
                'uq_app_devices_ip': lambda: DuplicateDeviceIp(d['ip'])}

    def update_device(self, device_id, data, *, expected_version=None, actor_user_id=None):
        R.check_id(device_id, 'device_id')
        d = R.check_device(data)
        R.check_optional_id(actor_user_id, 'actor_user_id')

        def work(cur):
            row = self._lock_device(cur, device_id)
            if row is None or row['is_deleted']:
                raise NotFound(DEVICE_GONE)
            self._check_version(row, expected_version)
            cur.execute('SELECT id, name, ip, type, is_deleted FROM app_devices WHERE ip = %s '
                        'AND id <> %s FOR UPDATE', (d['ip'], device_id))
            other = cur.fetchone()
            if other:
                if other['is_deleted']:
                    raise DeletedDeviceExists(self._deleted_info(cur, other))
                raise DuplicateDeviceIp(d['ip'], {'id': other['id'], 'name': other['name']})
            taken = self._name_taken(cur, d['name'], device_id)
            if taken:
                raise DuplicateDeviceName(d['name'], taken)
            cur.execute('UPDATE app_devices SET name = %s, ip = %s, type = %s, status = %s, '
                        'managed = %s, version = version + 1, updated_at = UTC_TIMESTAMP(6), '
                        'updated_by = %s WHERE id = %s',
                        (d['name'], d['ip'], d['type'], d['status'], int(d['managed']),
                         actor_user_id, device_id))
            self._rename_links(cur, device_id, row['name'], d['name'])
            self._audit(cur, 'device.update', device_id, actor_user_id)
            return row['version'] + 1
        return self._tx(work, self._device_conflicts(d))

    def set_status(self, device_id, status, *, actor_user_id=None):
        R.check_id(device_id, 'device_id')
        R.check_choice(status, R.DEVICE_STATUSES, 'status')
        R.check_optional_id(actor_user_id, 'actor_user_id')

        def work(cur):
            row = self._lock_device(cur, device_id)
            if row is None or row['is_deleted']:
                raise NotFound(DEVICE_GONE)
            cur.execute('UPDATE app_devices SET status = %s, version = version + 1, '
                        'updated_at = UTC_TIMESTAMP(6), updated_by = %s WHERE id = %s',
                        (status, actor_user_id, device_id))
            return row['version'] + 1
        return self._tx(work)

    def delete_device(self, device_id, *, expected_version=None, actor_user_id=None):
        R.check_id(device_id, 'device_id')
        R.check_optional_id(actor_user_id, 'actor_user_id')

        def work(cur):
            row = self._lock_device(cur, device_id)
            if row is None or row['is_deleted']:
                return False
            self._check_version(row, expected_version)
            cur.execute('UPDATE app_devices SET is_deleted = 1, deleted_at = UTC_TIMESTAMP(6), '
                        'version = version + 1, updated_at = UTC_TIMESTAMP(6), updated_by = %s '
                        'WHERE id = %s', (actor_user_id, device_id))
            self._audit(cur, 'device.delete', device_id, actor_user_id)
            return True
        return self._tx(work)

    def restore_device(self, device_id, data, *, credentials, username=None,
                       password_enc=None, key_id=R.DEFAULT_KEY_ID, expected_version=None,
                       actor_user_id=None):
        R.check_id(device_id, 'device_id')
        R.check_choice(credentials, R.CREDENTIAL_CHOICES, 'credentials')
        d = R.check_device(data)
        user = None
        if credentials == 'replace':
            user = R.check_login_username(username)
            R.check_password_token(password_enc)
            R.check_key_id(key_id)
        elif username or password_enc:
            raise InvalidValue('A new login was given but "keep the saved login" was chosen.')
        R.check_optional_id(actor_user_id, 'actor_user_id')

        def work(cur):
            row = self._lock_device(cur, device_id)
            if row is None:
                raise NotFound(DEVICE_GONE)
            if not row['is_deleted']:
                raise DeviceNotDeleted(f"{row['name']} ({row['ip']}) is not deleted (it may "
                                       f"already have been restored). Nothing was changed.")
            self._check_version(row, expected_version)
            if d['ip'] != row['ip']:
                raise InvalidValue(f"Device {device_id} has IP {row['ip']}, not {d['ip']}. "
                                   f"Nothing was changed.")
            taken = self._name_taken(cur, d['name'], device_id)
            if taken:
                raise DuplicateDeviceName(d['name'], taken)
            mac_sql, mac_params = (', mac = %s', (d['mac'],)) if d['mac'] else ('', ())
            cur.execute('UPDATE app_devices SET name = %s, type = %s, status = %s, managed = %s, '
                        f'is_deleted = 0, deleted_at = NULL{mac_sql}, version = version + 1, '
                        'updated_at = UTC_TIMESTAMP(6), updated_by = %s WHERE id = %s',
                        (d['name'], d['type'], d['status'], int(d['managed'])) + mac_params +
                        (actor_user_id, device_id))
            self._rename_links(cur, device_id, row['name'], d['name'])
            self._audit(cur, 'device.restore', device_id, actor_user_id,
                        'login replaced' if credentials == 'replace' else 'login kept')
            if credentials == 'replace':
                self._write_credentials(cur, device_id, user, password_enc, key_id,
                                        actor_user_id)
            return device_id
        return self._tx(work, self._device_conflicts(d))

    # ------------------------------------------------------------ devices: reads
    def get_device(self, device_id):
        R.check_id(device_id, 'device_id')
        return _device(self._read(_DEVICE_SELECT + ' WHERE d.id = %s AND d.is_deleted = 0',
                                  (device_id,), one=True))

    def get_device_by_ip(self, ip):
        R.check_ip(ip)
        return _device(self._read(_DEVICE_SELECT + ' WHERE d.ip = %s AND d.is_deleted = 0',
                                  (ip,), one=True))

    def get_device_by_name(self, name):
        R.check_name(name)
        return _device(self._read(_DEVICE_SELECT + ' WHERE d.active_name_key = %s',
                                  (R.name_key(name),), one=True))

    def get_deleted_device_by_ip(self, ip):
        R.check_ip(ip)

        def work(cur):
            cur.execute('SELECT id, name, ip, type FROM app_devices WHERE ip = %s AND '
                        'is_deleted = 1', (ip,))
            row = cur.fetchone()
            return self._deleted_info(cur, row) if row else None
        return self._tx(work)

    _MATCH = (' WHERE d.is_deleted = 0 AND (LOWER(d.name) COLLATE utf8mb4_bin LIKE %s '
              'OR d.ip LIKE %s)')

    def count_devices(self, search=''):
        like = _like(search)
        row = self._read('SELECT COUNT(*) AS n FROM app_devices d' + self._MATCH, (like, like),
                         one=True)
        return row['n']

    def get_devices(self, search='', sort_by='name', page=1, per_page=15):
        R.check_page(page, per_page)
        like = _like(search)
        order = ORDER.get(sort_by, ORDER['name'])
        rows = self._read(_DEVICE_SELECT + self._MATCH + f' ORDER BY {order}, d.id '
                          'LIMIT %s OFFSET %s', (like, like, per_page, (page - 1) * per_page))
        return [_device(r) for r in rows]

    # ------------------------------------------------------------ credentials
    def set_credentials(self, device_id, username, password_enc, *, key_id=R.DEFAULT_KEY_ID,
                        actor_user_id=None):
        user = R.check_login_username(username)
        R.check_password_token(password_enc)
        R.check_key_id(key_id)
        R.check_optional_id(actor_user_id, 'actor_user_id')

        def work(cur):
            row = self._lock_device(cur, R.check_id(device_id, 'device_id'))
            if row is None or row['is_deleted']:
                raise NotFound(DEVICE_GONE)
            self._write_credentials(cur, device_id, user, password_enc, key_id, actor_user_id)
        self._tx(work)

    def get_login_username(self, device_id):
        R.check_id(device_id, 'device_id')
        row = self._read('SELECT c.username FROM app_device_credentials c JOIN app_devices d '
                         'ON d.id = c.device_id WHERE c.device_id = %s AND d.is_deleted = 0',
                         (device_id,), one=True)
        return row['username'] if row else None

    def get_encrypted_credentials(self, device_id):
        """SERVER-SIDE ONLY: {'username', 'password_enc', 'key_id'} or None."""
        R.check_id(device_id, 'device_id')
        return self._read('SELECT c.username, c.password_enc, c.key_id FROM '
                          'app_device_credentials c JOIN app_devices d ON d.id = c.device_id '
                          'WHERE c.device_id = %s AND d.is_deleted = 0', (device_id,), one=True)

    # ------------------------------------------------------------ links
    def _active_id(self, cur, name):
        cur.execute('SELECT id FROM app_devices WHERE active_name_key = %s FOR SHARE',
                    (R.name_key(name),))
        row = cur.fetchone()
        return row['id'] if row else None

    def save_links(self, links, *, actor_user_id=None):
        cleaned = list(dict.fromkeys(R.check_link(l) for l in links))
        R.check_optional_id(actor_user_id, 'actor_user_id')

        def work(cur):
            added = 0
            for a, pa, b, pb in cleaned:
                # ON DUPLICATE KEY UPDATE id = id: an existing link is left exactly as it is
                # (unlike INSERT IGNORE, every other error is still reported).
                cur.execute('INSERT INTO app_links (device_a, port_a, device_b, port_b, '
                            'device_a_id, device_b_id, created_at, created_by) VALUES (%s, %s, '
                            '%s, %s, %s, %s, UTC_TIMESTAMP(6), %s) ON DUPLICATE KEY UPDATE '
                            'id = id', (a, pa, b, pb, self._active_id(cur, a),
                                        self._active_id(cur, b), actor_user_id))
                added += cur.rowcount == 1
            return added
        return self._tx(work)

    def get_links(self):
        rows = self._read(
            'SELECT l.device_a, l.port_a, l.device_b, l.port_b FROM app_links l '
            'WHERE EXISTS (SELECT 1 FROM app_devices a WHERE a.active_name_key = '
            'LOWER(l.device_a) COLLATE utf8mb4_bin) AND EXISTS (SELECT 1 FROM app_devices b '
            'WHERE b.active_name_key = LOWER(l.device_b) COLLATE utf8mb4_bin) ORDER BY l.id')
        return [(r['device_a'], r['port_a'], r['device_b'], r['port_b']) for r in rows]

    # ------------------------------------------------------------ config logs (append-only)
    def add_log(self, device_id, action, status, details='', *, user_id=None, job_id=None):
        action = R.check_line(action, 'The action', R.ACTION_MAX)
        R.check_choice(status, R.LOG_STATUSES, 'status')
        details = R.check_text(details, 'The details')
        R.check_optional_id(user_id, 'user_id')

        def work(cur):
            self._any_device(cur, device_id)
            self._job_exists(cur, job_id)
            cur.execute('INSERT INTO app_config_logs (device_id, action, status, details, '
                        'created_at, user_id, job_id) VALUES (%s, %s, %s, %s, UTC_TIMESTAMP(6), '
                        '%s, %s)', (device_id, action, status, details, user_id, job_id))
            return cur.lastrowid
        return self._tx(work)

    @staticmethod
    def _log_filter(search, status):
        like = _like(search)
        sql = ('FROM app_config_logs l JOIN app_devices d ON d.id = l.device_id '
               'WHERE (LOWER(d.name) COLLATE utf8mb4_bin LIKE %s OR LOWER(l.action) COLLATE '
               'utf8mb4_bin LIKE %s OR LOWER(l.details) COLLATE utf8mb4_bin LIKE %s)')
        params = [like, like, like]
        if status:
            R.check_choice(status, R.LOG_STATUSES, 'status')
            sql += ' AND l.status = %s'
            params.append(status)
        return sql, params

    def count_logs(self, search='', status=''):
        sql, params = self._log_filter(search, status)
        return self._read('SELECT COUNT(*) AS n ' + sql, tuple(params), one=True)['n']

    def get_logs(self, search='', page=1, per_page=15, status=''):
        R.check_page(page, per_page)
        sql, params = self._log_filter(search, status)
        return self._read('SELECT l.id, l.created_at, d.name AS device, l.action, l.status, '
                          'l.details, l.user_id, l.job_id ' + sql +
                          ' ORDER BY l.id DESC LIMIT %s OFFSET %s',
                          tuple(params) + (per_page, (page - 1) * per_page))

    # ------------------------------------------------------------ findings (snapshot)
    _FINDING_INSERT = ('INSERT INTO app_findings (device_id, rule, severity, message, commands, '
                       'created_at, created_by, job_id) VALUES (%s, %s, %s, %s, %s, %s, %s, %s)')

    def replace_findings(self, findings, *, actor_user_id=None, job_id=None):
        cleaned = [R.check_finding(f) for f in findings]
        R.check_optional_id(actor_user_id, 'actor_user_id')

        def work(cur):
            self._job_exists(cur, job_id)
            names = sorted({f['device'] for f in cleaned})
            ids = {}
            for name in names:
                found = self._active_id(cur, name)
                if found is not None:
                    ids[name] = found
            now = self._now(cur)
            cur.execute('UPDATE app_findings SET superseded_at = %s WHERE superseded_at IS NULL',
                        (now,))
            rows = [(ids[f['device']], f['rule'], f['severity'], f['message'],
                     '\n'.join(f['commands']) or None, now, actor_user_id, job_id)
                    for f in cleaned if f['device'] in ids]
            if rows:
                cur.executemany(self._FINDING_INSERT, rows)
            return {'saved': len(rows), 'skipped': [n for n in names if n not in ids]}
        return self._tx(work)

    def clear_findings(self, *, actor_user_id=None):
        self.replace_findings([], actor_user_id=actor_user_id)

    def add_finding(self, f, *, actor_user_id=None, job_id=None):
        f = R.check_finding(f)
        R.check_optional_id(actor_user_id, 'actor_user_id')

        def work(cur):
            self._job_exists(cur, job_id)
            device_id = self._active_id(cur, f['device'])
            if device_id is None:
                return None
            cur.execute(self._FINDING_INSERT, (device_id, f['rule'], f['severity'],
                                               f['message'], '\n'.join(f['commands']) or None,
                                               self._now(cur), actor_user_id, job_id))
            return cur.lastrowid
        return self._tx(work)

    _FINDING_SELECT = ('SELECT f.id, d.name AS device, d.is_deleted AS device_deleted, f.rule, '
                       'f.severity, f.message, f.commands, f.created_at, f.created_by, f.job_id '
                       'FROM app_findings f JOIN app_devices d ON d.id = f.device_id '
                       'WHERE f.superseded_at IS NULL')

    def get_findings_snapshot(self):
        rows = self._read(self._FINDING_SELECT + ' ORDER BY f.severity, f.id')
        for r in rows:          # ENUM order: high, medium, low
            r['commands'], r['device_deleted'] = _commands(r['commands']), bool(r['device_deleted'])
        saved = [r['created_at'] for r in rows]
        return {'findings': rows, 'saved_at': max(saved) if saved else None}

    def get_findings(self, search='', page=1, per_page=15):
        R.check_page(page, per_page)
        like = _like(search)
        rows = self._read(self._FINDING_SELECT + ' AND (LOWER(d.name) COLLATE utf8mb4_bin LIKE '
                          '%s OR LOWER(f.rule) COLLATE utf8mb4_bin LIKE %s OR LOWER(f.message) '
                          'COLLATE utf8mb4_bin LIKE %s) ORDER BY f.severity, f.id LIMIT %s '
                          'OFFSET %s', (like, like, like, per_page, (page - 1) * per_page))
        for r in rows:
            r['commands'] = _commands(r['commands'])
            del r['device_deleted']
        return rows

    # ------------------------------------------------------------ status events (append-only)
    _EVENT_INSERT = ('INSERT INTO app_status_events (device_id, kind, detail, source, '
                     'created_at) VALUES (%s, %s, %s, %s, UTC_TIMESTAMP(6))')

    def add_event(self, device_id, kind, detail='', *, source='monitor'):
        kind = R.check_line(kind, 'The event kind', R.EVENT_KIND_MAX)
        detail = R.check_text(detail, 'The event detail')
        R.check_choice(source, R.EVENT_SOURCES, 'source')

        def work(cur):
            self._any_device(cur, device_id)
            cur.execute(self._EVENT_INSERT, (device_id, kind, detail, source))
            return cur.lastrowid
        return self._tx(work)

    def record_status_change(self, device_id, old, new, detail='', *, source='monitor',
                             actor_user_id=None):
        R.check_id(device_id, 'device_id')
        R.check_choice(old, R.DEVICE_STATUSES, 'old')
        R.check_choice(new, R.DEVICE_STATUSES, 'new')
        if old == new:
            raise InvalidValue('The old and new status must differ.')
        detail = R.check_text(detail, 'The event detail')
        R.check_choice(source, R.EVENT_SOURCES, 'source')
        R.check_optional_id(actor_user_id, 'actor_user_id')

        def work(cur):
            cur.execute('UPDATE app_devices SET status = %s, version = version + 1, '
                        'updated_at = UTC_TIMESTAMP(6), updated_by = %s WHERE id = %s AND '
                        'status = %s AND is_deleted = 0', (new, actor_user_id, device_id, old))
            if cur.rowcount != 1:
                return False                      # nothing was changed: committing is harmless
            cur.execute(self._EVENT_INSERT, (device_id, new, detail, source))
            return True
        return self._tx(work)

    def get_events(self, limit=50):
        R.check_limit(limit)
        rows = self._read('SELECT e.id, e.created_at, d.name AS device, e.kind, e.detail, '
                          'e.source FROM app_status_events e JOIN app_devices d ON '
                          'd.id = e.device_id ORDER BY e.id DESC LIMIT %s', (limit,))
        for r in rows:
            r['previous'] = PREVIOUS_STATUS.get(r['kind'])
        return rows

    # ------------------------------------------------------------ jobs
    def create_job(self, kind, device_ids=(), *, requested_by=None, params=None):
        kind = R.check_identifier(kind, 'The job kind', R.JOB_KIND_MAX)
        ids = list(dict.fromkeys(R.check_id(d, 'device_id') for d in device_ids))
        text = R.check_params(params)
        R.check_optional_id(requested_by, 'requested_by')

        def work(cur):
            if ids:
                cur.execute(f'SELECT id FROM app_devices WHERE id IN ({_placeholders(ids)}) '
                            f'AND is_deleted = 0 FOR SHARE', tuple(ids))
                if len(cur.fetchall()) != len(ids):
                    raise NotFound(DEVICE_GONE)
            cur.execute("INSERT INTO app_jobs (kind, state, requested_by, params, created_at, "
                        "updated_at) VALUES (%s, 'queued', %s, %s, UTC_TIMESTAMP(6), "
                        "UTC_TIMESTAMP(6))", (kind, requested_by, text))
            job_id = cur.lastrowid
            if ids:
                cur.executemany("INSERT INTO app_job_devices (job_id, device_id, state, "
                                "updated_at) VALUES (%s, %s, 'queued', UTC_TIMESTAMP(6))",
                                [(job_id, did) for did in ids])
            return job_id
        return self._tx(work)

    @staticmethod
    def _job_row(row):
        if row and isinstance(row.get('params'), (str, bytes)):
            row['params'] = json.loads(row['params'])
        return row

    def get_job(self, job_id):
        R.check_id(job_id, 'job_id')

        def work(cur):
            cur.execute(f'SELECT {_JOB_COLUMNS} FROM app_jobs WHERE id = %s', (job_id,))
            row = self._job_row(cur.fetchone())
            if row:
                cur.execute('SELECT job_id, device_id, state, message, updated_at FROM '
                            'app_job_devices WHERE job_id = %s ORDER BY device_id', (job_id,))
                row['devices'] = list(cur.fetchall())
            return row
        return self._tx(work)

    def list_jobs(self, limit=50, state=None):
        R.check_limit(limit)
        if state is None:
            rows = self._read(f'SELECT {_JOB_COLUMNS} FROM app_jobs ORDER BY id DESC LIMIT %s',
                              (limit,))
        else:
            R.check_choice(state, R.JOB_STATES, 'state')
            rows = self._read(f'SELECT {_JOB_COLUMNS} FROM app_jobs WHERE state = %s '
                              f'ORDER BY id DESC LIMIT %s', (state, limit))
        return [self._job_row(r) for r in rows]

    @staticmethod
    def _lock_job(cur, job_id):
        R.check_id(job_id, 'job_id')
        cur.execute('SELECT id, state FROM app_jobs WHERE id = %s FOR UPDATE', (job_id,))
        row = cur.fetchone()
        if row is None:
            raise NotFound(JOB_GONE)
        return row

    @staticmethod
    def _append_job_event(cur, job_id, kind, text, device_id):
        """The job row is locked (FOR UPDATE) by the caller, so seq is assigned one at a
        time per job."""
        cur.execute('SELECT COALESCE(MAX(seq), 0) + 1 AS seq FROM app_job_events '
                    'WHERE job_id = %s', (job_id,))
        seq = cur.fetchone()['seq']
        cur.execute('INSERT INTO app_job_events (job_id, seq, device_id, kind, message, '
                    'created_at) VALUES (%s, %s, %s, %s, %s, UTC_TIMESTAMP(6))',
                    (job_id, seq, device_id, kind, text))
        return seq

    def _change_job_state(self, cur, job_id, current, state, summary):
        R.check_job_transition(current, state)
        sets, params = ['state = %s', 'updated_at = UTC_TIMESTAMP(6)'], [state]
        if state == 'running':
            sets.append('started_at = UTC_TIMESTAMP(6)')
        if state in R.FINISHED_STATES:
            sets.append('finished_at = UTC_TIMESTAMP(6)')
        if summary is not None:
            sets.append('summary = %s')
            params.append(summary)
        cur.execute(f'UPDATE app_jobs SET {", ".join(sets)} WHERE id = %s',
                    tuple(params) + (job_id,))
        self._append_job_event(cur, job_id, 'state', f'state: {state}', None)

    def set_job_state(self, job_id, state, *, summary=None):
        if summary is not None:
            summary = R.clean_job_text(summary, R.SUMMARY_MAX)

        def work(cur):
            row = self._lock_job(cur, job_id)
            self._change_job_state(cur, job_id, row['state'], state, summary)
        self._tx(work)

    def set_job_device_state(self, job_id, device_id, state, message=None):
        if message is not None:
            message = R.clean_job_text(message, R.JOB_MESSAGE_MAX)
        R.check_id(device_id, 'device_id')

        def work(cur):
            self._lock_job(cur, job_id)
            cur.execute('SELECT state FROM app_job_devices WHERE job_id = %s AND device_id = %s '
                        'FOR UPDATE', (job_id, device_id))
            row = cur.fetchone()
            if row is None:
                raise NotFound('This device is not part of the job.')
            R.check_job_transition(row['state'], state)
            cur.execute('UPDATE app_job_devices SET state = %s, message = %s, '
                        'updated_at = UTC_TIMESTAMP(6) WHERE job_id = %s AND device_id = %s',
                        (state, message, job_id, device_id))
        self._tx(work)

    def add_job_event(self, job_id, kind, message, *, device_id=None):
        R.check_choice(kind, R.JOB_EVENT_KINDS, 'kind')
        text = R.clean_job_text(message, R.JOB_EVENT_MAX)
        R.check_optional_id(device_id, 'device_id')

        def work(cur):
            row = self._lock_job(cur, job_id)
            if row['state'] in R.FINISHED_STATES:
                raise InvalidTransition('The job has finished; no more events can be added.')
            if device_id is not None:
                self._any_device(cur, device_id)
            return self._append_job_event(cur, job_id, kind, text, device_id)
        return self._tx(work)

    def get_job_events(self, job_id, after_seq=0, limit=200):
        R.check_id(job_id, 'job_id')
        R.check_limit(limit)
        if isinstance(after_seq, bool) or not isinstance(after_seq, int) or after_seq < 0:
            raise InvalidValue('after_seq must be 0 or more.')
        return self._read('SELECT id, job_id, seq, device_id, kind, message, created_at FROM '
                          'app_job_events WHERE job_id = %s AND seq > %s ORDER BY seq LIMIT %s',
                          (job_id, after_seq, limit))

    def interrupt_unfinished_jobs(self):
        def work(cur):
            cur.execute("SELECT id, state FROM app_jobs WHERE state IN ('queued', 'running') "
                        "ORDER BY id FOR UPDATE", ())
            rows = list(cur.fetchall())
            for row in rows:
                self._change_job_state(cur, row['id'], row['state'], 'interrupted', None)
                cur.execute("UPDATE app_job_devices SET state = 'interrupted', "
                            "updated_at = UTC_TIMESTAMP(6) WHERE job_id = %s AND state IN "
                            "('queued', 'running')", (row['id'],))
            return len(rows)
        return self._tx(work)

    # ------------------------------------------------------------ device locks
    @staticmethod
    def _lock_row(cur, device_id):
        cur.execute(f'SELECT {_LOCK_COLUMNS}, lease_id, released_at, (released_at IS NULL AND '
                    f'expires_at > UTC_TIMESTAMP(6)) AS held FROM app_device_locks '
                    f'WHERE device_id = %s FOR UPDATE', (device_id,))
        return cur.fetchone()

    def acquire_device_lock(self, device_id, *, purpose, seconds, job_id=None,
                            holder_user_id=None):
        R.check_identifier(purpose, 'The lock purpose', R.PURPOSE_MAX)
        R.check_lock_seconds(seconds)
        R.check_optional_id(holder_user_id, 'holder_user_id')

        def work(cur):
            self._active_device(cur, device_id)
            self._job_exists(cur, job_id)
            row = self._lock_row(cur, device_id)
            if row and row['held']:
                raise DeviceLockHeld(row)
            now = self._now(cur)
            lock = {'device_id': device_id, 'lease_id': secrets.token_hex(16),
                    'job_id': job_id, 'holder_user_id': holder_user_id, 'purpose': purpose,
                    'acquired_at': now, 'expires_at': now + timedelta(seconds=seconds)}
            values = (lock['lease_id'], job_id, holder_user_id, purpose, now, lock['expires_at'])
            if row:                               # expired or released: taken over
                cur.execute('UPDATE app_device_locks SET lease_id = %s, job_id = %s, '
                            'holder_user_id = %s, purpose = %s, acquired_at = %s, '
                            'expires_at = %s, released_at = NULL WHERE device_id = %s',
                            values + (device_id,))
            else:
                cur.execute('INSERT INTO app_device_locks (lease_id, job_id, holder_user_id, '
                            'purpose, acquired_at, expires_at, device_id) VALUES (%s, %s, %s, '
                            '%s, %s, %s, %s)', values + (device_id,))
            return lock
        return self._tx(work, {'app_device_locks.PRIMARY': lambda: DeviceLockHeld(
            {'device_id': device_id, 'purpose': 'another operation'})})

    def renew_device_lock(self, device_id, lease_id, seconds):
        R.check_id(device_id, 'device_id')
        R.check_lease(lease_id)
        R.check_lock_seconds(seconds)

        def work(cur):
            row = self._lock_row(cur, device_id)
            if not row or not row['held'] or row['lease_id'] != lease_id:
                raise NotFound(LOCK_GONE)
            expires = self._now(cur) + timedelta(seconds=seconds)
            cur.execute('UPDATE app_device_locks SET expires_at = %s WHERE device_id = %s',
                        (expires, device_id))
            return expires
        return self._tx(work)

    def release_device_lock(self, device_id, lease_id):
        R.check_id(device_id, 'device_id')
        R.check_lease(lease_id)

        def work(cur):
            row = self._lock_row(cur, device_id)
            if not row or not row['held'] or row['lease_id'] != lease_id:
                return False
            cur.execute('UPDATE app_device_locks SET released_at = UTC_TIMESTAMP(6) '
                        'WHERE device_id = %s', (device_id,))
            return True
        return self._tx(work)

    def get_device_lock(self, device_id):
        R.check_id(device_id, 'device_id')
        return self._read(f'SELECT {_LOCK_COLUMNS} FROM app_device_locks WHERE device_id = %s '
                          f'AND released_at IS NULL AND expires_at > UTC_TIMESTAMP(6)',
                          (device_id,), one=True)

    # ------------------------------------------------------------ backups (schema only)
    def add_backup(self, device_id, *, content_enc, sha256, size_bytes, kind='running',
                   key_id=R.DEFAULT_KEY_ID, job_id=None, created_by=None):
        content = R.check_backup_content(content_enc)
        R.check_sha256(sha256)
        R.check_backup_size(size_bytes)
        R.check_choice(kind, R.BACKUP_KINDS, 'kind')
        R.check_key_id(key_id)
        R.check_optional_id(created_by, 'created_by')

        def work(cur):
            self._any_device(cur, device_id)
            self._job_exists(cur, job_id)
            cur.execute('INSERT INTO app_device_backups (device_id, job_id, kind, sha256, '
                        'size_bytes, key_id, content_enc, created_at, created_by) VALUES (%s, '
                        '%s, %s, %s, %s, %s, %s, UTC_TIMESTAMP(6), %s)',
                        (device_id, job_id, kind, sha256, size_bytes, key_id, content,
                         created_by))
            backup_id = cur.lastrowid
            self._audit(cur, 'device.backup_saved', device_id, created_by, f'backup {backup_id}')
            return backup_id
        return self._tx(work)

    def list_backups(self, device_id, limit=50):
        R.check_id(device_id, 'device_id')
        R.check_limit(limit)
        return self._read(f'SELECT {_BACKUP_COLUMNS} FROM app_device_backups WHERE '
                          f'device_id = %s ORDER BY id DESC LIMIT %s', (device_id, limit))

    def get_backup_encrypted(self, backup_id):
        """SERVER-SIDE ONLY: metadata plus content_enc, or None."""
        R.check_id(backup_id, 'backup_id')
        row = self._read(f'SELECT {_BACKUP_COLUMNS}, content_enc FROM app_device_backups '
                         f'WHERE id = %s', (backup_id,), one=True)
        if row is not None:
            row['content_enc'] = bytes(row['content_enc'])
        return row
