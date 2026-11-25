"""In-memory store used in SAMPLE MODE (no MySQL). Same function names and
behaviour as db.py, so the screens work with either. Data is lost on exit."""
import functools
import threading
from datetime import datetime, timedelta

import device_types
from store_errors import DeletedDeviceExists, DeviceNotDeleted, DuplicateDeviceName

SORT_KEYS = {
    'name': lambda d: d['name'].lower(),
    'ip': lambda d: tuple(int(p) if p.isdigit() else 0 for p in d['ip'].split('.')),
    'type': lambda d: d['type'],
    'status': lambda d: d['status'],
    'created_at': lambda d: d['id'],
}

_devices, _logins, _links, _logs, _findings, _events = {}, {}, [], [], [], []
_next = {'device': 1, 'log': 1, 'finding': 1, 'event': 1}


def reset():
    _devices.clear(); _logins.clear(); _links.clear()
    _logs.clear(); _findings.clear(); _events.clear()
    _console.clear()
    _user_settings.clear()
    for k in _next:
        _next[k] = 1


def ping():
    """Same as db.ping: the in-memory store is always available."""
    return True


def _live():
    return [d for d in _devices.values() if not d['is_deleted']]


def _public(d):
    if d is None:
        return None
    return {k: v for k, v in d.items() if k != 'is_deleted'}


# ---------------------------------------------------------------- devices
# Every write that can create or change a device name holds this lock from its checks to
# its last change, so the check and the write are one step (as a transaction in db.py).
# Re-entrant: save_device calls upsert_device / update_device while holding it.
_write_lock = threading.RLock()


def _atomic(func):
    @functools.wraps(func)
    def locked(*args, **kwargs):
        with _write_lock:
            return func(*args, **kwargs)
    return locked


def _check_name(name):
    """Same as db._check_name: validation.check_name, and no spaces around the name."""
    import validation
    problem = validation.check_name(name)
    if not problem and name != name.strip():
        problem = 'The name cannot start or end with a space.'
    if problem:
        raise ValueError(problem)


def _name_taken(name, exclude_id=None, exclude_ip=None):
    """Same as db._name_taken_query: the ACTIVE device (lowest id) that already uses this
    name, ignoring capital letters, or None. Deleted devices never count."""
    wanted = name.lower()
    for d in sorted(_live(), key=lambda x: x['id']):
        if d['name'].lower() != wanted:
            continue
        if exclude_id is not None and d['id'] == exclude_id:
            continue
        if exclude_ip is not None and d['ip'] == exclude_ip:
            continue
        return {'id': d['id'], 'name': d['name']}
    return None


@_atomic
def upsert_device(d):
    """Add a device, or update the ACTIVE device with this IP. An IP that belongs to a
    soft-deleted device raises DeletedDeviceExists and changes nothing (as db.py):
    restore_device is the only way to bring a deleted device back.
    A name another active device uses raises DuplicateDeviceName (as db.py)."""
    _check_name(d['name'])
    if get_deleted_device_by_ip(d['ip']):
        raise DeletedDeviceExists(get_deleted_device_by_ip(d['ip']))
    taken = _name_taken(d['name'], exclude_ip=d['ip'])
    if taken:
        raise DuplicateDeviceName(d['name'], taken)
    scanned = 'detected_type' in d                 # a scan's device (as db._scan_upsert)
    detected = device_types.clean(d.get('detected_type')) if scanned else None
    for existing in _devices.values():
        if existing['ip'] == d['ip']:
            if existing['is_deleted']:
                raise DeletedDeviceExists(get_deleted_device_by_ip(d['ip']))
            kind = d.get('type', 'unknown')
            if scanned:
                kind = device_types.type_after_scan(existing['type'],
                                                    existing.get('detected_type'), detected)
                existing['detected_type'] = detected
            existing.update(name=d['name'], type=kind,
                            managed=bool(d.get('managed')), status=d.get('status', 'up'))
            return existing['id']
    did = _next['device']; _next['device'] += 1
    _devices[did] = {'id': did, 'name': d['name'], 'ip': d['ip'], 'mac': d.get('mac', ''),
                     'type': detected if scanned else d.get('type', 'unknown'),
                     'detected_type': detected, 'managed': bool(d.get('managed')),
                     'status': d.get('status', 'up'), 'is_deleted': False,
                     'created_at': datetime.now()}
    return did


@_atomic
def update_device(device_id, data):
    if device_id not in _devices:                  # as db.update_device
        raise ValueError('This device no longer exists.')
    _check_name(data['name'])
    taken = _name_taken(data['name'], exclude_id=device_id)
    if taken:
        raise DuplicateDeviceName(data['name'], taken)
    d = _devices[device_id]
    old_name = d['name']
    d.update(name=data['name'], ip=data['ip'], type=data['type'],
             status=data.get('status') or d['status'],      # the monitor's, unless given
             managed=bool(data['managed']))
    if old_name != d['name']:
        for i, (a, pa, b, pb) in enumerate(_links):
            _links[i] = (d['name'] if a == old_name else a, pa,
                         d['name'] if b == old_name else b, pb)


@_atomic
def save_device(device_id, data, username=None, password=None):
    """Same contract as db.save_device: add (device_id None) or edit a device and optionally
    its login, all or nothing. The login is checked first (validation.check_login); if any
    step fails, every change made by this call is undone. The steps are the module's own
    upsert_device / update_device / save_credentials, so tests that replace one of them
    still exercise the failure path."""
    import validation
    _check_name(data['name'])
    user = (username or '').strip()
    if user or password:
        problem = validation.check_login(user, password)
        if problem:
            raise ValueError(problem)
    deleted = get_deleted_device_by_ip(data['ip'])
    if deleted and deleted['id'] != device_id:          # never restored silently
        raise DeletedDeviceExists(deleted)
    saved = _snapshot()
    try:
        if device_id is None:
            did = upsert_device(data)
        else:
            if device_id not in _devices:
                raise ValueError('This device no longer exists.')
            update_device(device_id, data)
            did = device_id
        if user:
            save_credentials(did, user, password)
        return did
    except BaseException:
        _restore(saved)                                   # roll back: nothing of this save is kept
        raise


def _snapshot():
    import copy
    return copy.deepcopy(_devices), dict(_logins), list(_links), dict(_next)


def _restore(saved):
    _devices.clear(); _devices.update(saved[0])
    _logins.clear(); _logins.update(saved[1])
    _links[:] = saved[2]
    _next.update(saved[3])


def get_deleted_device_by_ip(ip):
    """Same as db.get_deleted_device_by_ip: non-sensitive details of the deleted device
    that owns this IP, or None."""
    for d in _devices.values():
        if d['ip'] == ip and d['is_deleted']:
            user, pw = _logins.get(d['id'], ('', ''))
            return {'id': d['id'], 'name': d['name'], 'ip': d['ip'], 'type': d['type'],
                    'has_login': bool(user and pw)}
    return None


@_atomic
def restore_device(device_id, data, *, credentials, username=None, password=None):
    """Same contract as db.restore_device: restore this deleted device by its id, keeping
    or replacing its login; all or nothing."""
    import validation
    if credentials not in ('keep', 'replace'):
        raise ValueError("Choose 'keep' or 'replace' for the saved login.")
    _check_name(data['name'])
    user = (username or '').strip()
    if credentials == 'replace':
        if not user or not password:
            raise ValueError('Enter the new login username and password, or keep the saved '
                             'login.')
        problem = validation.check_login(user, password)
        if problem:
            raise ValueError(problem)
    elif user or password:
        raise ValueError('A new login was entered but "keep the saved login" was chosen.')
    mac = (data.get('mac') or '').strip()     # empty: keep the stored MAC; never blank it out
    if mac:
        problem = validation.check_mac(mac)
        if problem:
            raise ValueError(problem + ' Nothing was changed.')
    d = _devices.get(device_id)
    if d is None:
        raise ValueError('This device no longer exists.')
    if not d['is_deleted']:
        raise DeviceNotDeleted(f"{d['name']} ({d['ip']}) is not deleted (it may already have "
                               f"been restored). Nothing was changed.")
    if data['ip'] != d['ip']:
        raise ValueError(f"Device {device_id} has IP {d['ip']}, not {data['ip']}. "
                         f"Nothing was changed.")
    taken = _name_taken(data['name'], exclude_id=device_id)
    if taken:                             # it would become a second active device with the name
        raise DuplicateDeviceName(data['name'], taken)
    saved = _snapshot()
    try:
        old_name = d['name']
        d.update(name=data['name'], type=data.get('type', 'unknown'),
                 status=data.get('status', 'up'), managed=bool(data.get('managed')),
                 is_deleted=False)
        if mac:
            d['mac'] = mac
        if old_name != d['name']:
            for i, (a, pa, b, pb) in enumerate(_links):
                _links[i] = (d['name'] if a == old_name else a, pa,
                             d['name'] if b == old_name else b, pb)
        if credentials == 'replace':
            save_credentials(device_id, user, password)
        return device_id
    except BaseException:
        _restore(saved)
        raise


def delete_device(device_id):
    if device_id in _devices:
        _devices[device_id]['is_deleted'] = True


def get_device(device_id):
    d = _devices.get(device_id)
    return _public(d) if d and not d['is_deleted'] else None


def get_device_by_ip(ip):
    return next((_public(d) for d in _live() if d['ip'] == ip), None)


def get_device_by_name(name):
    return next((_public(d) for d in sorted(_live(), key=lambda x: x['id'])
                 if d['name'] == name), None)


def _match(search):
    s = search.lower()
    return [d for d in _live() if s in d['name'].lower() or s in d['ip']]


def count_devices(search=''):
    return len(_match(search))


def get_devices(search='', sort_by='name', page=1, per_page=15):
    key = SORT_KEYS.get(sort_by, SORT_KEYS['name'])
    rows = sorted(_match(search), key=lambda d: (key(d), d['id']))
    start = (max(page, 1) - 1) * per_page
    return [_public(d) for d in rows[start:start + per_page]]


def set_status(device_id, status):
    if device_id in _devices:
        _devices[device_id]['status'] = status


# ---------------------------------------------------------------- logins
def save_credentials(device_id, username, password):
    _logins[device_id] = (username, password)      # memory only in sample mode


def get_credentials(device_id):
    return _logins.get(device_id, ('', ''))


# ---------------------------------------------------------------- links
def save_links(links):
    for l in links:
        l = tuple(l)
        if l not in _links:
            _links.append(l)


def get_links():
    names = {d['name'] for d in _live()}
    return [l for l in _links if l[0] in names and l[2] in names]


# ---------------------------------------------------------------- Console history
# Same contract as db.py: append-only (there is no way to change or remove an entry).
_console = []
_user_settings = {}                 # (user_key, name) -> value (memory only)


def get_user_setting(user_key, name):
    return _user_settings.get((str(user_key), str(name)))


def set_user_setting(user_key, name, value):
    _user_settings[(str(user_key), str(name))] = str(value)


def add_console_events(rows):
    with _write_lock:
        for r in rows:
            _console.append(dict(r, id=len(_console) + 1))


def _console_rows(search='', tag='', user='', category='', device='', users=None):
    s = (search or '').lower()
    out = []
    for r in _console:
        if users is not None and r.get('user_label') not in set(users):
            continue
        text = ' '.join(str(r.get(k) or '') for k in
                        ('message', 'result', 'device', 'device_ip', 'user_label')).lower()
        if s and s not in text:
            continue
        if tag and tag not in (r.get('tags') or '').split(','):
            continue
        if (user and r.get('user_label') != user) or (category and r.get('category') != category) \
                or (device and r.get('device') != device):
            continue
        out.append(r)
    return out


def count_console_events(search='', tag='', user='', category='', device='', users=None):
    return len(_console_rows(search, tag, user, category, device, users))


def get_console_events(search='', page=1, per_page=15, tag='', user='', category='',
                       device='', users=None):
    rows = list(reversed(_console_rows(search, tag, user, category, device, users)))
    start = (max(page, 1) - 1) * per_page
    return [dict(r) for r in rows[start:start + per_page]]


def console_event_users():
    return sorted({r.get('user_label') for r in _console if r.get('user_label')})


# ---------------------------------------------------------------- logs
def add_log(device_id, action, status, details=''):
    lid = _next['log']; _next['log'] += 1
    _logs.append({'id': lid, 'device_id': device_id, 'created_at': datetime.now(),
                  'action': action, 'status': status, 'details': details})
    return lid


def _log_rows(search, status, within_hours=None):
    s = search.lower()
    since = None if within_hours is None else datetime.now() - timedelta(hours=within_hours)
    rows = []
    for l in _logs:
        d = _devices.get(l['device_id'])
        name = d['name'] if d else '?'
        if status and l['status'] != status:
            continue
        if since is not None and l['created_at'] < since:
            continue
        if s and not (s in name.lower() or s in l['action'].lower()
                      or s in (l['details'] or '').lower()):
            continue
        rows.append({'id': l['id'], 'created_at': l['created_at'], 'device': name,
                     'action': l['action'], 'status': l['status'], 'details': l['details']})
    return sorted(rows, key=lambda r: r['id'], reverse=True)


def count_logs(search='', status='', within_hours=None):
    """Same as db.count_logs (within_hours: only the last N hours)."""
    return len(_log_rows(search, status, within_hours))


def get_logs(search='', page=1, per_page=15, status='', within_hours=None):
    start = (max(page, 1) - 1) * per_page
    return _log_rows(search, status, within_hours)[start:start + per_page]


# ---------------------------------------------------------------- findings
def clear_findings():
    _findings.clear()


def _new_finding(device_id, f, when):
    fid = _next['finding']; _next['finding'] += 1
    return {'id': fid, 'device_id': device_id, 'rule': f['rule'], 'severity': f['severity'],
            'message': f['message'], 'commands': list(f['commands']), 'created_at': when}


def _finding_row(f):
    """As db.py's JOIN: the device's CURRENT name (findings are kept by device id)."""
    d = _devices.get(f['device_id'])
    return {'id': f['id'], 'device': d['name'] if d else '?', 'rule': f['rule'],
            'severity': f['severity'], 'message': f['message'],
            'commands': list(f['commands']), 'created_at': f['created_at']}


_SEVERITY_ORDER = {'high': 0, 'medium': 1, 'low': 2}


def add_finding(f):
    dev = get_device_by_name(f['device'])
    if not dev:
        return None
    row = _new_finding(dev['id'], f, datetime.now())
    _findings.append(row)
    return row['id']


@_atomic
def replace_findings(findings):
    """Same as db.replace_findings: the new snapshot is built first and swapped in at once,
    so a failure leaves the previous one exactly as it was. An empty list clears it."""
    names = sorted({f['device'] for f in findings})
    ids = {}
    for name in names:
        dev = get_device_by_name(name)
        if dev:
            ids[name] = dev['id']
    when, saved_next = datetime.now(), _next['finding']
    try:
        new = [_new_finding(ids[f['device']], f, when) for f in findings if f['device'] in ids]
    except BaseException:
        _next['finding'] = saved_next
        raise
    _findings[:] = new
    return {'saved': len(new), 'skipped': [n for n in names if n not in ids]}


def get_findings_snapshot():
    """Same as db.get_findings_snapshot."""
    rows = []
    for f in sorted(_findings, key=lambda f: (_SEVERITY_ORDER[f['severity']], f['id'])):
        row = _finding_row(f)
        d = _devices.get(f['device_id'])
        row['device_deleted'] = bool(d is None or d['is_deleted'])
        rows.append(row)
    saved = [r['created_at'] for r in rows]
    return {'findings': rows, 'saved_at': max(saved) if saved else None}


def get_findings(search='', page=1, per_page=15):
    s = search.lower()
    rows = [_finding_row(f) for f in _findings]
    rows = [r for r in rows if s in r['device'].lower() or s in r['rule'].lower()
            or s in r['message'].lower()]
    rows.sort(key=lambda r: (_SEVERITY_ORDER[r['severity']], r['id']))
    start = (max(page, 1) - 1) * per_page
    return rows[start:start + per_page]


# ---------------------------------------------------------------- status events
def add_event(device_id, kind, detail=''):
    eid = _next['event']; _next['event'] += 1
    _events.append({'id': eid, 'device_id': device_id, 'created_at': datetime.now(),
                    'kind': kind, 'detail': detail})
    return eid


PREVIOUS_STATUS = {'up': 'down', 'down': 'up'}      # as db.py


@_atomic
def record_status_change(device_id, old, new, detail=''):
    """Same as db.record_status_change: status and event together, only if the active
    device's status is still old. Returns True if saved, False if it changed meanwhile."""
    d = _devices.get(device_id)
    if d is None or d['is_deleted'] or d['status'] != old:
        return False
    d['status'] = new
    add_event(device_id, new, detail)
    return True


def get_events(limit=50):
    out = []
    for e in sorted(_events, key=lambda e: e['id'], reverse=True)[:limit]:
        d = _devices.get(e['device_id'])
        out.append({'id': e['id'], 'created_at': e['created_at'],
                    'device': d['name'] if d else '?', 'kind': e['kind'],
                    'previous': PREVIOUS_STATUS.get(e['kind']), 'detail': e['detail']})
    return out
