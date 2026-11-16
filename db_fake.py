"""In-memory store used in SAMPLE MODE (no MySQL). Same function names and
behaviour as db.py, so the screens work with either. Data is lost on exit."""
from datetime import datetime

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
    for k in _next:
        _next[k] = 1


def _live():
    return [d for d in _devices.values() if not d['is_deleted']]


def _public(d):
    if d is None:
        return None
    return {k: v for k, v in d.items() if k != 'is_deleted'}


# ---------------------------------------------------------------- devices
def upsert_device(d):
    for existing in _devices.values():
        if existing['ip'] == d['ip']:
            existing.update(name=d['name'], type=d.get('type', 'unknown'),
                            managed=bool(d.get('managed')), status=d.get('status', 'up'),
                            is_deleted=False)
            return existing['id']
    did = _next['device']; _next['device'] += 1
    _devices[did] = {'id': did, 'name': d['name'], 'ip': d['ip'], 'mac': d.get('mac', ''),
                     'type': d.get('type', 'unknown'), 'managed': bool(d.get('managed')),
                     'status': d.get('status', 'up'), 'is_deleted': False,
                     'created_at': datetime.now()}
    return did


def update_device(device_id, data):
    d = _devices[device_id]
    old_name = d['name']
    d.update(name=data['name'], ip=data['ip'], type=data['type'], status=data['status'],
             managed=bool(data['managed']))
    if old_name != d['name']:
        for i, (a, pa, b, pb) in enumerate(_links):
            _links[i] = (d['name'] if a == old_name else a, pa,
                         d['name'] if b == old_name else b, pb)


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


# ---------------------------------------------------------------- logs
def add_log(device_id, action, status, details=''):
    lid = _next['log']; _next['log'] += 1
    _logs.append({'id': lid, 'device_id': device_id, 'created_at': datetime.now(),
                  'action': action, 'status': status, 'details': details})
    return lid


def _log_rows(search, status):
    s = search.lower()
    rows = []
    for l in _logs:
        d = _devices.get(l['device_id'])
        name = d['name'] if d else '?'
        if status and l['status'] != status:
            continue
        if s and not (s in name.lower() or s in l['action'].lower()
                      or s in (l['details'] or '').lower()):
            continue
        rows.append({'id': l['id'], 'created_at': l['created_at'], 'device': name,
                     'action': l['action'], 'status': l['status'], 'details': l['details']})
    return sorted(rows, key=lambda r: r['id'], reverse=True)


def count_logs(search='', status=''):
    return len(_log_rows(search, status))


def get_logs(search='', page=1, per_page=15, status=''):
    start = (max(page, 1) - 1) * per_page
    return _log_rows(search, status)[start:start + per_page]


# ---------------------------------------------------------------- findings
def clear_findings():
    _findings.clear()


def add_finding(f):
    dev = get_device_by_name(f['device'])
    if not dev:
        return None
    fid = _next['finding']; _next['finding'] += 1
    _findings.append({'id': fid, 'device': f['device'], 'rule': f['rule'],
                      'severity': f['severity'], 'message': f['message'],
                      'commands': list(f['commands']), 'created_at': datetime.now()})
    return fid


def get_findings(search='', page=1, per_page=15):
    s = search.lower()
    order = {'high': 0, 'medium': 1, 'low': 2}
    rows = [f for f in _findings if s in f['device'].lower() or s in f['rule'].lower()
            or s in f['message'].lower()]
    rows.sort(key=lambda f: (order[f['severity']], f['id']))
    start = (max(page, 1) - 1) * per_page
    return rows[start:start + per_page]


# ---------------------------------------------------------------- status events
def add_event(device_id, kind, detail=''):
    eid = _next['event']; _next['event'] += 1
    _events.append({'id': eid, 'device_id': device_id, 'created_at': datetime.now(),
                    'kind': kind, 'detail': detail})
    return eid


def get_events(limit=50):
    out = []
    for e in sorted(_events, key=lambda e: e['id'], reverse=True)[:limit]:
        d = _devices.get(e['device_id'])
        out.append({'id': e['id'], 'created_at': e['created_at'],
                    'device': d['name'] if d else '?', 'kind': e['kind'],
                    'detail': e['detail']})
    return out
