"""In-memory shared application repository: the same methods, values, rules, results AND
error types as AppRepository (MySQL), for tests and later phases. Nothing is persisted.

Times come from clock() (UTC, naive datetime), injectable so tests can move time forward
(lock expiry). One lock makes every method one atomic step (the SQL version uses one
transaction), and a failing method changes nothing: every check (values, existence,
versions, names, IPs, locks) runs before the first change.

What only the database can check: whether a user id exists (users is the authentication
repository's table). Pass user_exists=callable to check actors here as well; by default
any positive id is accepted.
"""
import copy
import json
import secrets
import threading
from datetime import datetime, timedelta, timezone

from backend.database import app_records as R
from backend.database.errors import (DeletedDeviceExists, DeviceLockHeld, DeviceNotDeleted,
                                     DuplicateDeviceIp, DuplicateDeviceName, InvalidValue,
                                     NotFound, VersionConflict)

DEVICE_FIELDS = ('id', 'name', 'ip', 'mac', 'type', 'managed', 'status', 'version',
                 'created_at', 'updated_at', 'created_by', 'updated_by', 'has_login')
DELETED_FIELDS = ('id', 'name', 'ip', 'type', 'has_login')
LOCK_FIELDS = ('device_id', 'purpose', 'job_id', 'holder_user_id', 'acquired_at',
               'expires_at')
BACKUP_FIELDS = ('id', 'device_id', 'job_id', 'kind', 'sha256', 'size_bytes', 'key_id',
                 'created_at', 'created_by')
PREVIOUS_STATUS = {'up': 'down', 'down': 'up'}
_SEVERITY_ORDER = {s: i for i, s in enumerate(R.SEVERITIES)}

DEVICE_GONE = 'The device does not exist or has been deleted.'
JOB_GONE = 'The job does not exist.'
USER_GONE = 'The user does not exist.'
LOCK_GONE = 'This lock is no longer held (it was released, expired or taken over).'


def utc_now():
    return datetime.now(timezone.utc).replace(tzinfo=None)


def _ip_key(ip):
    return tuple(int(p) for p in ip.split('.'))


SORT = {'name': lambda d: d['name'].lower(), 'ip': lambda d: _ip_key(d['ip']),
        'type': lambda d: d['type'], 'status': lambda d: d['status'],
        'created_at': lambda d: d['id']}


class InMemoryAppRepository:
    def __init__(self, clock=utc_now, user_exists=None):
        self.clock = clock
        self._user_exists = user_exists or (lambda user_id: True)
        self._lock = threading.RLock()
        self._devices, self._creds, self._links = {}, {}, []
        self._findings, self._events, self._logs = [], [], []
        self._jobs, self._job_devices, self._job_events = {}, {}, []
        self._locks, self._backups, self.audit = {}, {}, []
        self._next = {k: 1 for k in ('device', 'link', 'finding', 'event', 'log', 'job',
                                     'job_event', 'backup', 'audit')}

    # ------------------------------------------------------------ helpers
    def _id(self, kind):
        value = self._next[kind]
        self._next[kind] += 1
        return value

    def _actor(self, user_id, what='actor_user_id'):
        R.check_optional_id(user_id, what)
        if user_id is not None and not self._user_exists(user_id):
            raise NotFound(USER_GONE)
        return user_id

    def _audit(self, action, device_id, actor, detail=None):
        self.audit.append({'id': self._id('audit'), 'created_at': self.clock(),
                           'actor_user_id': actor, 'action': action, 'target_type': 'device',
                           'target_id': str(device_id), 'outcome': 'success',
                           'detail': detail})

    def _public(self, d):
        if d is None:
            return None
        row = {k: copy.copy(d[k]) for k in DEVICE_FIELDS if k != 'has_login'}
        row['has_login'] = d['id'] in self._creds
        return row

    def _active(self):
        return [d for d in self._devices.values() if not d['is_deleted']]

    def _active_by_key(self, name):
        key = R.name_key(name)
        return next((d for d in self._active() if R.name_key(d['name']) == key), None)

    def _name_taken(self, name, exclude_id=None):
        d = self._active_by_key(name)
        if d is not None and d['id'] != exclude_id:
            return {'id': d['id'], 'name': d['name']}
        return None

    def _by_ip(self, ip):
        return next((d for d in self._devices.values() if d['ip'] == ip), None)

    def _deleted_info(self, d):
        return {'id': d['id'], 'name': d['name'], 'ip': d['ip'], 'type': d['type'],
                'has_login': d['id'] in self._creds}

    def _active_device(self, device_id):
        R.check_id(device_id, 'device_id')
        d = self._devices.get(device_id)
        if d is None or d['is_deleted']:
            raise NotFound(DEVICE_GONE)
        return d

    def _any_device(self, device_id):
        R.check_id(device_id, 'device_id')
        if device_id not in self._devices:
            raise NotFound(DEVICE_GONE)
        return self._devices[device_id]

    def _job(self, job_id):
        R.check_id(job_id, 'job_id')
        if job_id not in self._jobs:
            raise NotFound(JOB_GONE)
        return self._jobs[job_id]

    @staticmethod
    def _check_version(d, expected_version):
        if expected_version is not None:
            R.check_id(expected_version, 'expected_version')
            if d['version'] != expected_version:
                raise VersionConflict(d['version'])

    def _rename_links(self, device_id, old, new):
        if old == new:
            return
        for link in self._links:
            for side in ('a', 'b'):
                if link[f'device_{side}'] == old or link[f'device_{side}_id'] == device_id:
                    link[f'device_{side}'], link[f'device_{side}_id'] = new, device_id

    def _touch(self, d, actor):
        d['version'] += 1
        d['updated_at'], d['updated_by'] = self.clock(), actor

    def _set_credentials(self, device_id, username, password_enc, key_id, actor):
        now = self.clock()
        old = self._creds.get(device_id)
        self._creds[device_id] = {'username': username, 'password_enc': password_enc,
                                  'key_id': key_id,
                                  'created_at': old['created_at'] if old else now,
                                  'updated_at': now, 'updated_by': actor}
        self._audit('device.credentials_set', device_id, actor,
                    'login replaced' if old else 'login saved')

    # ------------------------------------------------------------ devices: writes
    def upsert_device(self, data, *, actor_user_id=None):
        """Add a device, or update the ACTIVE device that has this IP (desktop semantics).
        The IP of a deleted device raises DeletedDeviceExists; a name another active device
        uses raises DuplicateDeviceName. Returns the device id."""
        d = R.check_device(data)
        with self._lock:
            actor = self._actor(actor_user_id)
            existing = self._by_ip(d['ip'])
            if existing is not None and existing['is_deleted']:
                raise DeletedDeviceExists(self._deleted_info(existing))
            taken = self._name_taken(d['name'], existing['id'] if existing else None)
            if taken:
                raise DuplicateDeviceName(d['name'], taken)
            if existing is not None:
                old_name = existing['name']
                existing.update(name=d['name'], type=d['type'], managed=d['managed'],
                                status=d['status'])
                self._touch(existing, actor)
                self._rename_links(existing['id'], old_name, d['name'])
                self._audit('device.update', existing['id'], actor)
                return existing['id']
            now, did = self.clock(), self._id('device')
            self._devices[did] = {'id': did, **d, 'is_deleted': False, 'version': 1,
                                  'created_at': now, 'updated_at': now, 'deleted_at': None,
                                  'created_by': actor, 'updated_by': actor}
            self._audit('device.create', did, actor)
            return did

    def update_device(self, device_id, data, *, expected_version=None, actor_user_id=None):
        """Edit an active device's name, ip, type, status and managed flag (the login and
        the MAC are left alone). Returns the new version."""
        d = R.check_device(data)
        with self._lock:
            actor = self._actor(actor_user_id)
            row = self._active_device(device_id)
            self._check_version(row, expected_version)
            other = self._by_ip(d['ip'])
            if other is not None and other['id'] != device_id:
                if other['is_deleted']:
                    raise DeletedDeviceExists(self._deleted_info(other))
                raise DuplicateDeviceIp(d['ip'], {'id': other['id'], 'name': other['name']})
            taken = self._name_taken(d['name'], device_id)
            if taken:
                raise DuplicateDeviceName(d['name'], taken)
            old_name = row['name']
            row.update(name=d['name'], ip=d['ip'], type=d['type'], status=d['status'],
                       managed=d['managed'])
            self._touch(row, actor)
            self._rename_links(device_id, old_name, d['name'])
            self._audit('device.update', device_id, actor)
            return row['version']

    def set_status(self, device_id, status, *, actor_user_id=None):
        R.check_choice(status, R.DEVICE_STATUSES, 'status')
        with self._lock:
            actor = self._actor(actor_user_id)
            row = self._active_device(device_id)
            row['status'] = status
            self._touch(row, actor)
            return row['version']

    def delete_device(self, device_id, *, expected_version=None, actor_user_id=None):
        """Soft delete. True if the device was active and is now deleted; False if it did
        not exist or was already deleted (nothing changed)."""
        R.check_id(device_id, 'device_id')
        with self._lock:
            actor = self._actor(actor_user_id)
            row = self._devices.get(device_id)
            if row is None or row['is_deleted']:
                return False
            self._check_version(row, expected_version)
            row['is_deleted'], row['deleted_at'] = True, self.clock()
            self._touch(row, actor)
            self._audit('device.delete', device_id, actor)
            return True

    def restore_device(self, device_id, data, *, credentials, username=None,
                       password_enc=None, key_id=R.DEFAULT_KEY_ID, expected_version=None,
                       actor_user_id=None):
        """Restore this deleted device (by id and its own IP), keeping or replacing its
        saved login; all or nothing. Returns the device id."""
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
        with self._lock:
            actor = self._actor(actor_user_id)
            row = self._devices.get(device_id)
            if row is None:
                raise NotFound(DEVICE_GONE)
            if not row['is_deleted']:
                raise DeviceNotDeleted(f"{row['name']} ({row['ip']}) is not deleted (it may "
                                       f"already have been restored). Nothing was changed.")
            self._check_version(row, expected_version)
            if d['ip'] != row['ip']:
                raise InvalidValue(f"Device {device_id} has IP {row['ip']}, not {d['ip']}. "
                                   f"Nothing was changed.")
            taken = self._name_taken(d['name'], device_id)
            if taken:
                raise DuplicateDeviceName(d['name'], taken)
            old_name = row['name']
            row.update(name=d['name'], type=d['type'], status=d['status'],
                       managed=d['managed'], is_deleted=False, deleted_at=None)
            if d['mac']:                               # empty: keep the stored MAC
                row['mac'] = d['mac']
            self._touch(row, actor)
            self._rename_links(device_id, old_name, d['name'])
            self._audit('device.restore', device_id, actor,
                        'login replaced' if credentials == 'replace' else 'login kept')
            if credentials == 'replace':
                self._set_credentials(device_id, user, password_enc, key_id, actor)
            return device_id

    # ------------------------------------------------------------ devices: reads
    def get_device(self, device_id):
        R.check_id(device_id, 'device_id')
        with self._lock:
            d = self._devices.get(device_id)
            return self._public(d) if d and not d['is_deleted'] else None

    def get_device_by_ip(self, ip):
        R.check_ip(ip)
        with self._lock:
            d = self._by_ip(ip)
            return self._public(d) if d and not d['is_deleted'] else None

    def get_device_by_name(self, name):
        """The active device with this name, ignoring capital letters (names are unique
        that way, so there is at most one)."""
        R.check_name(name)
        with self._lock:
            return self._public(self._active_by_key(name))

    def get_deleted_device_by_ip(self, ip):
        R.check_ip(ip)
        with self._lock:
            d = self._by_ip(ip)
            return self._deleted_info(d) if d and d['is_deleted'] else None

    def _match(self, search):
        s = R.check_search(search).lower()
        return [d for d in self._active() if s in d['name'].lower() or s in d['ip']]

    def count_devices(self, search=''):
        with self._lock:
            return len(self._match(search))

    def get_devices(self, search='', sort_by='name', page=1, per_page=15):
        R.check_page(page, per_page)
        key = SORT.get(sort_by, SORT['name'])
        with self._lock:
            rows = sorted(self._match(search), key=lambda d: (key(d), d['id']))
            start = (page - 1) * per_page
            return [self._public(d) for d in rows[start:start + per_page]]

    # ------------------------------------------------------------ credentials
    def set_credentials(self, device_id, username, password_enc, *, key_id=R.DEFAULT_KEY_ID,
                        actor_user_id=None):
        """Save or replace an active device's login. password_enc must already be a Fernet
        token (the backend encrypts; this layer never sees the password)."""
        user = R.check_login_username(username)
        R.check_password_token(password_enc)
        R.check_key_id(key_id)
        with self._lock:
            actor = self._actor(actor_user_id)
            self._active_device(device_id)
            self._set_credentials(device_id, user, password_enc, key_id, actor)

    def get_login_username(self, device_id):
        """The saved login's USERNAME for an active device (shown to authorized users), or
        None. Never the password or its token."""
        R.check_id(device_id, 'device_id')
        with self._lock:
            d = self._devices.get(device_id)
            c = self._creds.get(device_id)
            return c['username'] if d and not d['is_deleted'] and c else None

    def get_encrypted_credentials(self, device_id):
        """SERVER-SIDE ONLY (a device job decrypts it on the backend): {'username',
        'password_enc', 'key_id'} of an active device, or None. Never sent to a client."""
        R.check_id(device_id, 'device_id')
        with self._lock:
            d = self._devices.get(device_id)
            c = self._creds.get(device_id)
            if not d or d['is_deleted'] or not c:
                return None
            return {'username': c['username'], 'password_enc': c['password_enc'],
                    'key_id': c['key_id']}

    # ------------------------------------------------------------ links
    def save_links(self, links, *, actor_user_id=None):
        """Add links that are not stored yet (the same four values = the same link).
        Device ids are filled when a name matches an active device. Returns how many were
        added."""
        cleaned = [R.check_link(l) for l in links]
        with self._lock:
            actor = self._actor(actor_user_id)
            stored = {(l['device_a'], l['port_a'], l['device_b'], l['port_b'])
                      for l in self._links}
            added = 0
            for a, pa, b, pb in cleaned:
                if (a, pa, b, pb) in stored:
                    continue
                da, db = self._active_by_key(a), self._active_by_key(b)
                self._links.append({'id': self._id('link'), 'device_a': a, 'port_a': pa,
                                    'device_b': b, 'port_b': pb,
                                    'device_a_id': da['id'] if da else None,
                                    'device_b_id': db['id'] if db else None,
                                    'created_at': self.clock(), 'created_by': actor})
                stored.add((a, pa, b, pb))
                added += 1
            return added

    def get_links(self):
        """Links whose two device names both belong to active devices (ignoring capital
        letters), oldest first, as (device_a, port_a, device_b, port_b)."""
        with self._lock:
            names = {R.name_key(d['name']) for d in self._active()}
            return [(l['device_a'], l['port_a'], l['device_b'], l['port_b'])
                    for l in sorted(self._links, key=lambda l: l['id'])
                    if R.name_key(l['device_a']) in names and R.name_key(l['device_b']) in names]

    # ------------------------------------------------------------ config logs (append-only)
    def add_log(self, device_id, action, status, details='', *, user_id=None, job_id=None):
        action = R.check_line(action, 'The action', R.ACTION_MAX)
        R.check_choice(status, R.LOG_STATUSES, 'status')
        details = R.check_text(details, 'The details')
        with self._lock:
            self._actor(user_id, 'user_id')
            self._any_device(device_id)
            if job_id is not None:
                self._job(job_id)
            lid = self._id('log')
            self._logs.append({'id': lid, 'device_id': device_id, 'action': action,
                               'status': status, 'details': details, 'created_at': self.clock(),
                               'user_id': user_id, 'job_id': job_id})
            return lid

    def _log_rows(self, search, status):
        s = R.check_search(search).lower()
        if status:
            R.check_choice(status, R.LOG_STATUSES, 'status')
        rows = []
        for l in self._logs:
            name = self._devices[l['device_id']]['name']
            if status and l['status'] != status:
                continue
            if s and not (s in name.lower() or s in l['action'].lower()
                          or s in l['details'].lower()):
                continue
            rows.append({'id': l['id'], 'created_at': l['created_at'], 'device': name,
                         'action': l['action'], 'status': l['status'], 'details': l['details'],
                         'user_id': l['user_id'], 'job_id': l['job_id']})
        return sorted(rows, key=lambda r: r['id'], reverse=True)

    def count_logs(self, search='', status=''):
        with self._lock:
            return len(self._log_rows(search, status))

    def get_logs(self, search='', page=1, per_page=15, status=''):
        R.check_page(page, per_page)
        with self._lock:
            start = (page - 1) * per_page
            return self._log_rows(search, status)[start:start + per_page]

    # ------------------------------------------------------------ findings (snapshot)
    def _resolve(self, names):
        ids = {}
        for name in names:
            d = self._active_by_key(name)
            if d is not None:
                ids[name] = d['id']
        return ids

    def replace_findings(self, findings, *, actor_user_id=None, job_id=None):
        """The new snapshot replaces the current one at once: the current rows are marked
        superseded (kept, never deleted) and the new ones added. Findings for a name that
        matches no active device are skipped. An empty list clears the snapshot.
        Returns {'saved': n, 'skipped': [names]}."""
        cleaned = [R.check_finding(f) for f in findings]
        with self._lock:
            actor = self._actor(actor_user_id)
            if job_id is not None:
                self._job(job_id)
            names = sorted({f['device'] for f in cleaned})
            ids, now = self._resolve(names), self.clock()
            for f in self._findings:
                if f['superseded_at'] is None:
                    f['superseded_at'] = now
            saved = 0
            for f in cleaned:
                if f['device'] in ids:
                    self._findings.append(self._new_finding(ids[f['device']], f, now, actor,
                                                            job_id))
                    saved += 1
            return {'saved': saved, 'skipped': [n for n in names if n not in ids]}

    def clear_findings(self, *, actor_user_id=None):
        self.replace_findings([], actor_user_id=actor_user_id)

    def add_finding(self, f, *, actor_user_id=None, job_id=None):
        """Add one finding to the CURRENT snapshot. None if its device is not active."""
        f = R.check_finding(f)
        with self._lock:
            actor = self._actor(actor_user_id)
            if job_id is not None:
                self._job(job_id)
            ids = self._resolve([f['device']])
            if not ids:
                return None
            row = self._new_finding(ids[f['device']], f, self.clock(), actor, job_id)
            self._findings.append(row)
            return row['id']

    def _new_finding(self, device_id, f, when, actor, job_id):
        return {'id': self._id('finding'), 'device_id': device_id, 'rule': f['rule'],
                'severity': f['severity'], 'message': f['message'],
                'commands': list(f['commands']), 'created_at': when, 'superseded_at': None,
                'created_by': actor, 'job_id': job_id}

    def _current_findings(self):
        rows = [f for f in self._findings if f['superseded_at'] is None]
        return sorted(rows, key=lambda f: (_SEVERITY_ORDER[f['severity']], f['id']))

    def _finding_row(self, f):
        d = self._devices[f['device_id']]
        return {'id': f['id'], 'device': d['name'], 'rule': f['rule'],
                'severity': f['severity'], 'message': f['message'],
                'commands': list(f['commands']), 'created_at': f['created_at'],
                'created_by': f['created_by'], 'job_id': f['job_id']}

    def get_findings_snapshot(self):
        """{'findings': [...current, with 'device_deleted'], 'saved_at': newest or None}."""
        with self._lock:
            rows = []
            for f in self._current_findings():
                row = self._finding_row(f)
                row['device_deleted'] = bool(self._devices[f['device_id']]['is_deleted'])
                rows.append(row)
            saved = [r['created_at'] for r in rows]
            return {'findings': rows, 'saved_at': max(saved) if saved else None}

    def get_findings(self, search='', page=1, per_page=15):
        R.check_page(page, per_page)
        s = R.check_search(search).lower()
        with self._lock:
            rows = [self._finding_row(f) for f in self._current_findings()]
            rows = [r for r in rows if s in r['device'].lower() or s in r['rule'].lower()
                    or s in r['message'].lower()]
            start = (page - 1) * per_page
            return rows[start:start + per_page]

    # ------------------------------------------------------------ status events (append-only)
    def add_event(self, device_id, kind, detail='', *, source='monitor'):
        kind = R.check_line(kind, 'The event kind', R.EVENT_KIND_MAX)
        detail = R.check_text(detail, 'The event detail')
        R.check_choice(source, R.EVENT_SOURCES, 'source')
        with self._lock:
            self._any_device(device_id)
            return self._add_event(device_id, kind, detail, source)

    def _add_event(self, device_id, kind, detail, source):
        eid = self._id('event')
        self._events.append({'id': eid, 'device_id': device_id, 'kind': kind,
                             'detail': detail, 'source': source, 'created_at': self.clock()})
        return eid

    def record_status_change(self, device_id, old, new, detail='', *, source='monitor',
                             actor_user_id=None):
        """Status and its event together, only if the ACTIVE device's status is still old.
        True if saved, False if it changed meanwhile (or the device is deleted/missing)."""
        R.check_id(device_id, 'device_id')
        R.check_choice(old, R.DEVICE_STATUSES, 'old')
        R.check_choice(new, R.DEVICE_STATUSES, 'new')
        if old == new:
            raise InvalidValue('The old and new status must differ.')
        detail = R.check_text(detail, 'The event detail')
        R.check_choice(source, R.EVENT_SOURCES, 'source')
        with self._lock:
            actor = self._actor(actor_user_id)
            d = self._devices.get(device_id)
            if d is None or d['is_deleted'] or d['status'] != old:
                return False
            d['status'] = new
            self._touch(d, actor)
            self._add_event(device_id, new, detail, source)
            return True

    def get_events(self, limit=50):
        R.check_limit(limit)
        with self._lock:
            out = []
            for e in sorted(self._events, key=lambda e: e['id'], reverse=True)[:limit]:
                out.append({'id': e['id'], 'created_at': e['created_at'],
                            'device': self._devices[e['device_id']]['name'], 'kind': e['kind'],
                            'previous': PREVIOUS_STATUS.get(e['kind']), 'detail': e['detail'],
                            'source': e['source']})
            return out

    # ------------------------------------------------------------ jobs
    def create_job(self, kind, device_ids=(), *, requested_by=None, params=None):
        """A queued job for these active devices. params: non-secret options only."""
        kind = R.check_identifier(kind, 'The job kind', R.JOB_KIND_MAX)
        ids = list(dict.fromkeys(R.check_id(d, 'device_id') for d in device_ids))
        text = R.check_params(params)
        with self._lock:
            actor = self._actor(requested_by, 'requested_by')
            for did in ids:
                self._active_device(did)
            now, jid = self.clock(), self._id('job')
            self._jobs[jid] = {'id': jid, 'kind': kind, 'state': 'queued',
                               'requested_by': actor, 'params': text, 'summary': None,
                               'created_at': now, 'updated_at': now, 'started_at': None,
                               'finished_at': None}
            for did in ids:
                self._job_devices[(jid, did)] = {'job_id': jid, 'device_id': did,
                                                 'state': 'queued', 'message': None,
                                                 'updated_at': now}
            return jid

    @staticmethod
    def _job_row(j):
        row = dict(j)
        row['params'] = json.loads(j['params']) if j['params'] is not None else None
        return row

    def _job_public(self, j):
        row = self._job_row(j)
        row['devices'] = [dict(v) for k, v in sorted(self._job_devices.items()) if k[0] == j['id']]
        return row

    def get_job(self, job_id):
        R.check_id(job_id, 'job_id')
        with self._lock:
            j = self._jobs.get(job_id)
            return self._job_public(j) if j else None

    def list_jobs(self, limit=50, state=None):
        R.check_limit(limit)
        if state is not None:
            R.check_choice(state, R.JOB_STATES, 'state')
        with self._lock:
            rows = [j for j in self._jobs.values() if state is None or j['state'] == state]
            rows.sort(key=lambda j: j['id'], reverse=True)
            return [self._job_row(j) for j in rows[:limit]]

    def set_job_state(self, job_id, state, *, summary=None):
        """queued -> running | cancelled | interrupted; running -> succeeded | failed |
        cancelled | interrupted. A finished job never changes (InvalidTransition). The
        change is also appended to the job's events."""
        if summary is not None:
            summary = R.clean_job_text(summary, R.SUMMARY_MAX)
        with self._lock:
            j = self._job(job_id)
            R.check_job_transition(j['state'], state)
            now = self.clock()
            j['state'], j['updated_at'] = state, now
            if state == 'running':
                j['started_at'] = now
            if state in R.FINISHED_STATES:
                j['finished_at'] = now
            if summary is not None:
                j['summary'] = summary
            self._append_job_event(job_id, 'state', f'state: {state}', None)

    def set_job_device_state(self, job_id, device_id, state, message=None):
        if message is not None:
            message = R.clean_job_text(message, R.JOB_MESSAGE_MAX)
        R.check_id(device_id, 'device_id')
        with self._lock:
            self._job(job_id)
            row = self._job_devices.get((job_id, device_id))
            if row is None:
                raise NotFound('This device is not part of the job.')
            R.check_job_transition(row['state'], state)
            row.update(state=state, message=message, updated_at=self.clock())

    def add_job_event(self, job_id, kind, message, *, device_id=None):
        """Append an event (masked, length-limited) to an unfinished job. Returns its seq."""
        R.check_choice(kind, R.JOB_EVENT_KINDS, 'kind')
        text = R.clean_job_text(message, R.JOB_EVENT_MAX)
        R.check_optional_id(device_id, 'device_id')
        with self._lock:
            j = self._job(job_id)
            if j['state'] in R.FINISHED_STATES:
                from backend.database.errors import InvalidTransition
                raise InvalidTransition('The job has finished; no more events can be added.')
            if device_id is not None:
                self._any_device(device_id)
            return self._append_job_event(job_id, kind, text, device_id)

    def _append_job_event(self, job_id, kind, text, device_id):
        seq = 1 + max((e['seq'] for e in self._job_events if e['job_id'] == job_id), default=0)
        self._job_events.append({'id': self._id('job_event'), 'job_id': job_id, 'seq': seq,
                                 'device_id': device_id, 'kind': kind, 'message': text,
                                 'created_at': self.clock()})
        return seq

    def get_job_events(self, job_id, after_seq=0, limit=200):
        R.check_id(job_id, 'job_id')
        R.check_limit(limit)
        if isinstance(after_seq, bool) or not isinstance(after_seq, int) or after_seq < 0:
            raise InvalidValue('after_seq must be 0 or more.')
        with self._lock:
            rows = sorted((e for e in self._job_events
                           if e['job_id'] == job_id and e['seq'] > after_seq),
                          key=lambda e: e['seq'])
            return [dict(e) for e in rows[:limit]]

    def interrupt_unfinished_jobs(self):
        """After a backend restart: every queued or running job (and its unfinished
        devices) becomes interrupted. Returns how many jobs changed."""
        with self._lock:
            changed = 0
            for j in self._jobs.values():
                if j['state'] in ('queued', 'running'):
                    self.set_job_state(j['id'], 'interrupted')
                    for (jid, _), row in self._job_devices.items():
                        if jid == j['id'] and row['state'] in ('queued', 'running'):
                            row.update(state='interrupted', updated_at=self.clock())
                    changed += 1
            return changed

    # ------------------------------------------------------------ device locks
    def _held(self, row, now):
        return row is not None and row['released_at'] is None and row['expires_at'] > now

    def acquire_device_lock(self, device_id, *, purpose, seconds, job_id=None,
                            holder_user_id=None):
        """One lock per active device. Held: DeviceLockHeld. Expired or released: taken
        over. Returns the lock with its lease_id (only the holder gets it)."""
        R.check_identifier(purpose, 'The lock purpose', R.PURPOSE_MAX)
        R.check_lock_seconds(seconds)
        with self._lock:
            holder = self._actor(holder_user_id, 'holder_user_id')
            self._active_device(device_id)
            if job_id is not None:
                self._job(job_id)
            now = self.clock()
            row = self._locks.get(device_id)
            if self._held(row, now):
                raise DeviceLockHeld(row)
            lock = {'device_id': device_id, 'lease_id': secrets.token_hex(16),
                    'job_id': job_id, 'holder_user_id': holder, 'purpose': purpose,
                    'acquired_at': now, 'expires_at': now + timedelta(seconds=seconds),
                    'released_at': None}
            self._locks[device_id] = lock
            return {k: lock[k] for k in LOCK_FIELDS + ('lease_id',)}

    def renew_device_lock(self, device_id, lease_id, seconds):
        """Extend a lock still held by this lease. Returns the new expires_at."""
        R.check_id(device_id, 'device_id')
        R.check_lease(lease_id)
        R.check_lock_seconds(seconds)
        with self._lock:
            row, now = self._locks.get(device_id), self.clock()
            if not self._held(row, now) or row['lease_id'] != lease_id:
                raise NotFound(LOCK_GONE)
            row['expires_at'] = now + timedelta(seconds=seconds)
            return row['expires_at']

    def release_device_lock(self, device_id, lease_id):
        """True if this lease held the lock and it is now released; False otherwise."""
        R.check_id(device_id, 'device_id')
        R.check_lease(lease_id)
        with self._lock:
            row, now = self._locks.get(device_id), self.clock()
            if not self._held(row, now) or row['lease_id'] != lease_id:
                return False
            row['released_at'] = now
            return True

    def get_device_lock(self, device_id):
        """The lock currently held on the device (without its lease id), or None."""
        R.check_id(device_id, 'device_id')
        with self._lock:
            row = self._locks.get(device_id)
            return {k: row[k] for k in LOCK_FIELDS} if self._held(row, self.clock()) else None

    # ------------------------------------------------------------ backups (schema only)
    def add_backup(self, device_id, *, content_enc, sha256, size_bytes, kind='running',
                   key_id=R.DEFAULT_KEY_ID, job_id=None, created_by=None):
        """Store an ENCRYPTED backup (content_enc: a Fernet token as bytes). The backup job
        that makes it is Phase G. Returns the backup id."""
        content = R.check_backup_content(content_enc)
        R.check_sha256(sha256)
        R.check_backup_size(size_bytes)
        R.check_choice(kind, R.BACKUP_KINDS, 'kind')
        R.check_key_id(key_id)
        with self._lock:
            actor = self._actor(created_by, 'created_by')
            self._any_device(device_id)
            if job_id is not None:
                self._job(job_id)
            bid = self._id('backup')
            self._backups[bid] = {'id': bid, 'device_id': device_id, 'job_id': job_id,
                                  'kind': kind, 'sha256': sha256, 'size_bytes': size_bytes,
                                  'key_id': key_id, 'content_enc': content,
                                  'created_at': self.clock(), 'created_by': actor}
            self._audit('device.backup_saved', device_id, actor, f'backup {bid}')
            return bid

    def list_backups(self, device_id, limit=50):
        """Backup metadata, newest first. Never the content."""
        R.check_id(device_id, 'device_id')
        R.check_limit(limit)
        with self._lock:
            rows = sorted((b for b in self._backups.values() if b['device_id'] == device_id),
                          key=lambda b: b['id'], reverse=True)
            return [{k: b[k] for k in BACKUP_FIELDS} for b in rows[:limit]]

    def get_backup_encrypted(self, backup_id):
        """SERVER-SIDE ONLY (decrypted on the backend in Phase G): the metadata plus
        content_enc, or None."""
        R.check_id(backup_id, 'backup_id')
        with self._lock:
            b = self._backups.get(backup_id)
            return dict(b) if b else None
