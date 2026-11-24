"""The workbench window's size, position and maximized state, kept between starts.

    window_state.place(root)        # at start: the remembered place, or a good first size
    window_state.remember(root)     # keeps it up to date (debounced) and saves on close

First start: about 90 % of the screen, centered; maximized on small screens (a logical
width under SMALL_SCREEN, e.g. 1366 x 768 at 100 % or 1920 x 1080 at 150 %).
Minimum size MIN_SIZE (made smaller only when the screen itself is smaller).
A remembered place whose centre is no longer on any monitor (a monitor was unplugged or
changed) is not used: the window opens on the current screen instead.

Saved as JSON in %APPDATA%\\NetCommand\\window.json (NETCOMMAND_WINDOW_FILE overrides it;
the tests use a temporary file). Only sizes and positions are stored.
"""
import json
import os
import re
import sys

MIN_SIZE = (1024, 640)
FIRST_SHARE = 0.9
SMALL_SCREEN = 1500                 # logical pixels: below this, start maximized
_GEOMETRY = re.compile(r'^(\d+)x(\d+)([+-]-?\d+)([+-]-?\d+)$')


def state_file():
    override = os.environ.get('NETCOMMAND_WINDOW_FILE')
    if override:
        return override
    base = os.environ.get('APPDATA') or os.path.expanduser('~')
    return os.path.join(base, 'NetCommand', 'window.json')


def load():
    try:
        with open(state_file(), encoding='utf-8') as f:
            data = json.load(f)
        return data if isinstance(data, dict) else {}
    except (OSError, ValueError):
        return {}


def save(data):
    path = state_file()
    try:
        os.makedirs(os.path.dirname(path), exist_ok=True)
        tmp = path + '.tmp'
        with open(tmp, 'w', encoding='utf-8') as f:
            json.dump(data, f)
        os.replace(tmp, path)
        return True
    except OSError:
        return False


def parse_geometry(text):
    """'1200x700+40+30' -> (1200, 700, 40, 30), or None."""
    m = _GEOMETRY.match(str(text or ''))
    if not m:
        return None
    return int(m.group(1)), int(m.group(2)), int(m.group(3)), int(m.group(4))


def on_a_monitor(x, y):
    """True when the point (screen pixels) is on a connected monitor (Windows; elsewhere
    always True)."""
    if not sys.platform.startswith('win'):
        return True
    try:
        import ctypes
        from ctypes import wintypes
        point = wintypes.POINT(int(x), int(y))
        return bool(ctypes.windll.user32.MonitorFromPoint(point, 0))   # 0: NULL if none
    except Exception:
        return True


def first_geometry(screen_w, screen_h, scale=1.0):
    """((w, h, x, y), maximized) for a first start on this screen."""
    logical = screen_w / (scale or 1.0)
    w, h = int(screen_w * FIRST_SHARE), int(screen_h * FIRST_SHARE * 0.94)
    x, y = (screen_w - w) // 2, max(0, (screen_h - h) // 3)
    return (w, h, x, y), logical < SMALL_SCREEN


def minimum_size(screen_w, screen_h):
    return min(MIN_SIZE[0], screen_w), min(MIN_SIZE[1], int(screen_h * 0.85))


def place(root):
    """Size and position the window (before it is shown). Returns what was used:
    'remembered', 'first' or 'first-maximized'."""
    sw, sh = root.winfo_screenwidth(), root.winfo_screenheight()
    try:
        scale = float(root.winfo_fpixels('1i')) / 96.0
    except Exception:
        scale = 1.0
    root.minsize(*minimum_size(sw, sh))
    data = load()
    geo = parse_geometry(data.get('geometry'))
    if geo:
        w, h, x, y = geo
        w, h = max(w, minimum_size(sw, sh)[0]), max(h, minimum_size(sw, sh)[1])
        if on_a_monitor(x + w // 2, y + h // 2):
            root.geometry(f'{w}x{h}+{x}+{y}')
            if data.get('maximized'):
                _maximize(root)
            return 'remembered'
    (w, h, x, y), maximize = first_geometry(sw, sh, scale)
    root.geometry(f'{w}x{h}+{x}+{y}')
    if maximize:
        _maximize(root)
        return 'first-maximized'
    return 'first'


def _maximize(root):
    try:
        root.state('zoomed')                     # Windows
    except Exception:
        try:
            root.attributes('-zoomed', True)     # other systems
        except Exception:
            pass


def current(root):
    """{'geometry', 'maximized'}: the normal (not maximized) size and position, kept even
    while the window is maximized, so restoring un-maximizes to the right place."""
    try:
        maximized = root.state() == 'zoomed'
    except Exception:
        maximized = False
    return {'maximized': maximized}


_settings = {}                       # put_setting(): saved with the window's place


def get_setting(key, default=None):
    """A layout setting kept between starts (e.g. the bottom panel's height per page)."""
    if key in _settings:
        return _settings[key]
    return load().get('settings', {}).get(key, default)


def put_setting(key, value):
    """Keep a layout setting for the next start (saved now, and again on close)."""
    _settings[key] = value
    data = load()
    data.setdefault('settings', {})[key] = value
    save(data)


def remember(root, delay_ms=500):
    """Keep the window's place up to date while it is used, and save it on close."""
    data = load()
    job = {'id': None}

    def snapshot():
        job['id'] = None
        try:
            info = current(root)
            if not info['maximized'] and root.state() == 'normal':
                geo = root.geometry()
                if parse_geometry(geo):
                    data['geometry'] = geo
            data['maximized'] = info['maximized']
        except Exception:
            pass

    def changed(event):
        if event.widget is not root:
            return
        if job['id'] is not None:
            try:
                root.after_cancel(job['id'])
            except Exception:
                pass
        try:
            job['id'] = root.after(delay_ms, snapshot)
        except Exception:
            job['id'] = None

    def closing(event):
        if event.widget is root:
            snapshot()
            data.setdefault('settings', {}).update(load().get('settings', {}))
            data['settings'].update(_settings)
            save(data)
    root.bind('<Configure>', changed, add='+')
    root.bind('<Destroy>', closing, add='+')
    return data
