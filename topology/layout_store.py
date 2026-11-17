"""Saved topology layouts: where the user placed each device on the interactive map.

One local JSON file, kept apart from MariaDB and from the in-memory sample store.
Default location:  %APPDATA%\\NetCommand\\topology_layout.json  (Windows)
                   ~/.netcommand/topology_layout.json         (elsewhere)
The NETCOMMAND_LAYOUT_FILE environment variable can point somewhere else.

The file holds one layout per "scope" (which network it belongs to), e.g.
    "database:netcommand@localhost"   the real database
    "sample"                          sample / demo data
Each device entry has only its position and, for readability, its name and IP:
    {"version": 1, "layouts": {"<scope>": {"saved_at": "...", "devices": {
        "id:12": {"x": -0.85, "y": 6.2, "name": "SW1", "ip": "192.168.1.3"}}}}}
Positions are in device-box units (x / box width, y / box height), so the same
arrangement comes back at any window size. No passwords or credentials are stored.

A missing, empty or damaged file never stops the app: loading then simply finds
no saved layout. Before a damaged file is overwritten by a save, it is kept next
to it as topology_layout.damaged-<date-time>.json.
"""
import json
import math
import os
from datetime import datetime

VERSION = 1
ENTRY_FIELDS = ('x', 'y', 'name', 'ip')     # everything a saved entry may contain


def default_path():
    custom = os.environ.get('NETCOMMAND_LAYOUT_FILE')
    if custom:
        return custom
    base = os.environ.get('APPDATA')
    folder = os.path.join(base, 'NetCommand') if base else \
        os.path.join(os.path.expanduser('~'), '.netcommand')
    return os.path.join(folder, 'topology_layout.json')


class LayoutStore:
    def __init__(self, path=None):
        self.path = path or default_path()
        self.problem = None            # why the file could not be read (None = fine or absent)
        self.unreadable = False        # True when the path exists but cannot be opened

    # ---------------------------------------------------------------- reading
    def _read(self):
        """(data, problem). data is always a valid structure; problem explains a bad file.
        self.unreadable is set when the file exists but cannot be opened at all."""
        empty = {'version': VERSION, 'layouts': {}}
        self.unreadable = False
        if not os.path.exists(self.path):
            return empty, None
        try:
            with open(self.path, encoding='utf-8') as f:
                text = f.read()
        except (OSError, UnicodeDecodeError) as err:
            self.unreadable = not isinstance(err, UnicodeDecodeError)
            reason = getattr(err, 'strerror', None) or err
            return empty, f'could not read the file ({reason})'
        if not text.strip():
            return empty, None                         # an empty file: nothing saved yet
        try:
            data = json.loads(text)
        except ValueError:
            return empty, 'the file is damaged (not valid JSON)'
        if not isinstance(data, dict) or not isinstance(data.get('layouts'), dict):
            return empty, 'the file has an unexpected structure'
        return data, None

    def load(self, scope):
        """{key: {'x', 'y', 'name', 'ip'}} saved for this scope ({} if none).
        Entries without two finite numbers for x and y are skipped."""
        data, self.problem = self._read()
        layout = data['layouts'].get(scope)
        devices = layout.get('devices') if isinstance(layout, dict) else None
        if not isinstance(devices, dict):
            return {}
        good = {}
        for key, entry in devices.items():
            if not isinstance(entry, dict):
                continue
            x, y = entry.get('x'), entry.get('y')
            if all(isinstance(v, (int, float)) and not isinstance(v, bool) and math.isfinite(v)
                   for v in (x, y)):
                good[str(key)] = {'x': float(x), 'y': float(y),
                                  'name': str(entry.get('name', '')), 'ip': str(entry.get('ip', ''))}
        return good

    def has(self, scope):
        return bool(self.load(scope))

    # ---------------------------------------------------------------- writing
    def save(self, scope, devices):
        """Replace this scope's layout with `devices` ({key: {'x','y','name','ip'}}).
        Other scopes are kept. Raises OSError if the file cannot be written."""
        data, problem = self._read()
        if self.unreadable:      # a folder, a locked file, no permission: never move it aside
            raise OSError(f'{self.path}: {problem}')
        if problem:              # readable but damaged content: keep a copy, then start fresh
            self._keep_damaged_copy()
        clean ={str(k): {f: v[f] for f in ENTRY_FIELDS if f in v} for k, v in devices.items()}
        data['version'] = VERSION
        data['layouts'][scope] = {'saved_at': datetime.now().isoformat(timespec='seconds'),
                                  'devices': clean}
        self._write(data)

    def delete(self, scope):
        """Remove this scope's saved layout (other scopes are kept). True if one existed."""
        data, problem = self._read()
        if self.unreadable:
            raise OSError(f'{self.path}: {problem}')
        if problem or scope not in data['layouts']:
            return False
        del data['layouts'][scope]
        self._write(data)
        return True

    def _write(self, data):
        folder = os.path.dirname(os.path.abspath(self.path))
        os.makedirs(folder, exist_ok=True)
        tmp = self.path + '.tmp'
        try:
            with open(tmp, 'w', encoding='utf-8') as f:
                json.dump(data, f, indent=1, sort_keys=True)
            os.replace(tmp, self.path)                 # all or nothing
        finally:
            if os.path.exists(tmp):
                os.remove(tmp)

    def _keep_damaged_copy(self):
        """Move a damaged (but readable) file aside. Only ever a regular file."""
        if not os.path.isfile(self.path):
            return
        stamp = datetime.now().strftime('%Y%m%d-%H%M%S')
        root, ext = os.path.splitext(self.path)
        os.replace(self.path, f'{root}.damaged-{stamp}{ext or ".json"}')
