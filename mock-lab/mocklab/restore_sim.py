"""Simulated restore support (Phase 4D): flash, file transfer, archive and
`configure replace` with a timed rollback, plus failure injection.

Everything here is a SIMULATION for testing a future restore engine against the
Mock Lab. The command names follow Cisco IOS; the wording of the messages is
written for the lab (not copied from Cisco output), and none of it proves how real
hardware behaves. Mock Lab success says nothing about Cisco 1900 compatibility.

Pieces:
    SimClock          simulated time. Tests advance it; nothing ever sleeps.
    Flash             a per-device flash: file system with a size, images,
                      transferred files and archive copies (kept apart by kind).
    load_config_text  a configuration file -> a device state, through the
                      device's own CLI parser on a blank device (what
                      `configure replace` and a reload need).
    Rollback          a pending `configure replace ... time N`: the state to go
                      back to, the archive copy and the deadline.
    exec handlers     dir, delete, verify /md5, tclsh, archive config,
                      configure replace|confirm|revert, show archive.

Transfers: Tcl (`tclsh` + `puts [open "flash:x" w+] {...}`, the form Netmiko's
InLineTransfer sends) and, only when the device configuration already contains
`ip scp server enable`, an SCP sink in server.py. Both end in store_transfer().
The mock never connects anywhere: files only arrive over the lab's own SSH server.

By default a transfer REFUSES to overwrite an existing file, so a test catches any
engine that reuses a name. The `flash_overwrites` quirk gives real IOS behaviour
(Tcl "w+" and SCP overwrite silently) to test the engine's own existence check.
"""
import copy
import datetime
import difflib
import hashlib
import re
import secrets
import threading

BOOT_SECONDS = 180                      # simulated reload time (connections refused)
DEFAULT_ARCHIVE_MAXIMUM = 10
EPOCH = datetime.datetime(2026, 11, 18, 10, 15, 0)
NO_PENDING = '% No Rollback Confirmed Change pending'
# verify_mismatch: the line the device "adds" after a replacement (a real difference)
MISMATCH_LINE = 'ip domain-lookup source-interface Loopback99'
_NAME = re.compile(r'^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$')
_FLASH = re.compile(r'^flash:/?(.*)$', re.IGNORECASE)
_PUTS = re.compile(r'^puts\s+\[open\s+"([^"]+)"\s+w\+?\]\s*\{(.*)$')
# lines running_config() always prints: not commands to replay
_IMPLICIT = {'service timestamps debug datetime msec', 'service timestamps log datetime msec',
             'no service password-encryption', 'boot-start-marker', 'boot-end-marker',
             'spanning-tree mode pvst', 'spanning-tree extend system-id',
             'vtp mode transparent', 'ip forward-protocol nd'}
_HEADER = re.compile(r'^(Building configuration\.\.\.|Current configuration : \d+ bytes|'
                     r'version \S+|Using \d+ out of \d+ bytes)$')


# ---------------------------------------------------------------- clock
class SimClock:
    """Simulated seconds since the lab started. advance() is the only way time moves."""

    def __init__(self, start=0.0):
        self._now = float(start)
        self._lock = threading.Lock()

    def now(self):
        with self._lock:
            return self._now

    def advance(self, seconds):
        if seconds < 0:
            raise ValueError('the simulated clock cannot go backwards')
        with self._lock:
            self._now += float(seconds)
            return self._now

    def stamp(self, t=None):
        moment = EPOCH + datetime.timedelta(seconds=self.now() if t is None else t)
        return moment.strftime('%b %d %Y %H:%M:%S') + ' +00:00'


# ---------------------------------------------------------------- flash
class FlashError(Exception):
    """message: the line the device prints."""

    def __init__(self, message):
        super().__init__(message)
        self.message = message


class FlashFile:
    def __init__(self, name, data, kind, created, size=None):
        self.name = name
        self.data = data                    # bytes, or None for a simulated image
        self.kind = kind                    # 'image' | 'archive' | 'file'
        self.size = len(data) if data is not None else int(size)
        self.created = created

    def md5(self):
        body = self.data if self.data is not None else f'{self.name}:{self.size}'.encode()
        return hashlib.md5(body).hexdigest()


class Flash:
    ROUTER_BYTES = 255_744_000
    SWITCH_BYTES = 64_016_384

    def __init__(self, clock, total):
        self.clock = clock
        self.total = int(total)
        self.files = {}                     # name -> FlashFile, in creation order

    @classmethod
    def for_device(cls, dev, spec):
        total = spec.get('flash_bytes') or (cls.ROUTER_BYTES if dev.kind == 'router'
                                            else cls.SWITCH_BYTES)
        flash = cls(dev.clock, total)
        m = re.search(r'System image file is "(?:flash0?:|mock:)/?([^"]+)"', dev.show_version())
        image = m.group(1) if m else 'netcommand-lab.bin'
        size = min(75_000_000 if dev.kind == 'router' else 12_000_000, flash.total // 2)
        flash.files[image] = FlashFile(image, None, 'image', 0.0, size=size)
        return flash

    def used(self):
        return sum(f.size for f in self.files.values())

    def free(self):
        return self.total - self.used()

    def get(self, name):
        return self.files.get(name)

    def exists(self, name):
        return name in self.files

    def write(self, name, data, kind='file', overwrite=False):
        if not _NAME.match(name or ''):
            raise FlashError(f'%Error opening flash:/{name} (Invalid file name)')
        old = self.files.get(name)
        if old is not None:
            if not overwrite or old.kind != 'file':
                raise FlashError(f'%Error opening flash:/{name} (File exists)')
        freed = old.size if old is not None else 0
        if len(data) > self.free() + freed:
            raise FlashError(f'%Error writing flash:/{name} (No space left on device)')
        self.files.pop(name, None)
        self.files[name] = FlashFile(name, bytes(data), kind, self.clock.now())
        return self.files[name]

    def delete(self, name):
        if self.files.pop(name, None) is None:
            raise FlashError(f'%Error deleting flash:/{name} (File not found)')

    def temp_name(self, prefix='nc-restore-', suffix='.cfg'):
        """An unpredictable name that does not exist yet."""
        while True:
            name = f'{prefix}{secrets.token_hex(8)}{suffix}'
            if name not in self.files:
                return name

    def listing(self, only=None):
        files = [self.files[only]] if only else list(self.files.values())
        rows = [f'Directory of flash:/{only or ""}', '']
        for n, f in enumerate(self.files.values(), 1):
            if f in files:
                rows.append(f'{n:>5}  -rw-  {f.size:>10}  {self.clock.stamp(f.created)}  {f.name}')
        rows += ['', f'{self.total} bytes total ({self.free()} bytes free)']
        return '\n'.join(rows)


def flash_path(text):
    """'flash:x' / 'flash:/x' -> 'x'; 'flash:' -> ''. Other file systems are refused."""
    m = _FLASH.match(text or '')
    if not m:
        raise FlashError(f'%Error opening {text} (No such device)')
    name = m.group(1)
    if '/' in name:
        raise FlashError(f'%Error opening {text} (No such file or directory)')
    return name


# ---------------------------------------------------------------- configuration state
def load_config_text(dev, text, reject_last=False):
    """Replay a configuration file on a BLANK copy of dev, through the device's own CLI.

    Physical facts are kept (ports, cables, RSA keys, quirks, the enable secret
    when the file sets none); configuration starts empty. Returns (state, rejected):
    state for dev.set_config_state(), rejected = [(line, message)] for the lines the
    CLI refused. reject_last (replace_partial): the last command is refused too."""
    from .cli import INVALID, Session
    from .device import CONFIG_ATTRS, Interface
    scratch = copy.copy(dev)
    scratch.hostname = 'Router' if dev.kind == 'router' else 'Switch'
    scratch.vlans = {1: 'default'}
    scratch.interfaces = {}
    for name, intf in dev.interfaces.items():
        if intf.physical:
            fresh = Interface(name)
            fresh.connected = intf.connected
            scratch.interfaces[name] = fresh
    if dev.kind == 'switch':
        scratch.interfaces['Vlan1'] = Interface('Vlan1', physical=False)
    scratch.routes, scratch.default_gateway, scratch.dhcp_excluded = [], None, []
    scratch.pools, scratch.name_servers, scratch.ntp_servers = {}, [], []
    scratch.global_lines, scratch.lines, scratch.archive = [], {}, None
    scratch.quirks = set()
    session = Session(scratch, privilege=15)
    session.mode = 'config'
    commands = []
    for raw in text.replace('\r\n', '\n').replace('\r', '\n').split('\n'):
        line = raw.rstrip()
        bare = line.strip()
        if not bare or bare.startswith('!') or bare in _IMPLICIT or _HEADER.match(bare):
            continue
        if bare == 'end':
            break
        commands.append(line)
    rejected = []
    if reject_last and commands:
        rejected.append((commands.pop().strip(), INVALID))
    for line in commands:
        reply = session._handle(line)
        problem = _error_line(reply.output)
        if session.pending is not None:            # a question: never answered here
            session.pending = None
            problem = problem or 'unanswered question'
        if problem:
            rejected.append((line.strip(), problem))
        if session.mode in ('user', 'exec'):
            session.mode = 'config'
    state = {attr: getattr(scratch, attr) for attr in CONFIG_ATTRS}
    return copy.deepcopy(state), rejected


def _error_line(output):
    for line in (output or '').split('\n'):
        s = line.strip()
        if (s.startswith('%') and not s.startswith('% Access VLAN does not exist')) or \
                s.startswith(('Command rejected', 'Bad mask', 'Default VLAN')) or \
                s.endswith('is an invalid network.'):
            return s
    return None


class Rollback:
    """A pending `configure replace ... time N`."""

    def __init__(self, snapshot, archive_name, started, minutes):
        self.snapshot = snapshot            # dev.config_state() before the replacement
        self.archive_name = archive_name    # the archive copy the rollback reads
        self.started = started
        self.minutes = minutes
        self.deadline = started + minutes * 60

    def remaining(self, now):
        return max(0, int(self.deadline - now))


def tick(dev):
    """Expire a pending rollback whose deadline has passed (called on every command,
    every new connection and Lab.advance)."""
    rb = dev.rollback
    if rb is not None and dev.clock.now() >= rb.deadline:
        rollback(dev, 'timer expired')


def rollback(dev, reason):
    """Go back to the state before `configure replace`. False when it cannot."""
    rb, dev.rollback = dev.rollback, None
    if rb is None:
        return False
    if 'revert_fails' in dev.quirks:
        dev.event('rollback_failed', f'{reason} (revert_fails)')
        return False
    if rb.archive_name and not dev.flash.exists(rb.archive_name):
        dev.event('rollback_failed', f'{reason} (archive copy {rb.archive_name} is missing)')
        return False
    dev.set_config_state(rb.snapshot)
    dev.logins_refused = False
    dev.event('rollback', reason)
    return True


def reload(dev, reason):
    """A simulated reload: running = startup, the pending rollback is lost, every session
    is cut and connections are refused for BOOT_SECONDS. Flash survives."""
    state, _ = load_config_text(dev, dev.startup)
    dev.set_config_state(state)
    dev.rollback = None
    dev.logins_refused = False
    dev.boot_count += 1
    dev.booting_until = dev.clock.now() + BOOT_SECONDS
    dev.event('reload', reason)


def make_archive_copy(dev):
    """Save the running configuration as the next archive copy; the oldest copies go
    beyond "maximum". Archive copies never overwrite anything."""
    a = dev.archive or {}
    if not a.get('path'):
        raise FlashError('% Archive path is not configured: configure "archive" and "path" '
                         'first (SIMULATED)')
    base = flash_path(a['path'].replace('$h', dev.hostname))
    while dev.flash.exists(f'{base}-{dev.archive_next}'):
        dev.archive_next += 1
    name = f'{base}-{dev.archive_next}'
    dev.flash.write(name, dev.running_config().encode('utf-8'), kind='archive')
    dev.archive_next += 1
    dev.archive_copies.append(name)
    maximum = a.get('maximum') or DEFAULT_ARCHIVE_MAXIMUM
    while len(dev.archive_copies) > maximum:
        old = dev.archive_copies.pop(0)
        if dev.flash.exists(old):
            dev.flash.delete(old)
    dev.event('archive', name)
    return name


def store_transfer(dev, name, data):
    """A file arriving over Tcl or SCP. Returns None, or the error line."""
    if 'transfer_corrupt' in dev.quirks and len(data) >= 2:
        data = data[:-2] + bytes([data[-2] ^ 0x01]) + data[-1:]
    try:
        dev.flash.write(name, data, kind='file', overwrite='flash_overwrites' in dev.quirks)
    except FlashError as err:
        dev.event('transfer_failed', f'{name}: {err.message}')
        return err.message
    dev.event('transfer', name)
    return None


# ---------------------------------------------------------------- exec commands
def _reply(*args, **kw):
    from .cli import Reply
    return Reply(*args, **kw)


def dir_command(session, w):
    target = w.word(1) if w.has(1) else 'flash:'
    w.end(2)
    try:
        name = flash_path(target)
    except FlashError as err:
        return _reply(err.message)
    if name and not session.dev.flash.exists(name):
        return _reply(f'%Error opening flash:/{name} (File not found)')
    return _reply(session.dev.flash.listing(name or None))


def delete_command(session, w):
    from .cli import CLIError, INVALID
    i, force = 1, False
    while w.has(i) and w.word(i).startswith('/'):
        option = w.word(i).lower()
        if option == '/force':
            force = True
        elif option != '/recursive':
            raise CLIError(INVALID, w.pos(i))
        i += 1
    target = w.word(i)
    w.end(i + 1)
    try:
        name = flash_path(target)
    except FlashError as err:
        return _reply(err.message)
    if not name:
        return _reply('%Error deleting flash:/ (Is a directory)')
    if force:
        return _reply(_delete(session.dev, name))

    def confirm(answer):
        if answer.strip().lower() not in ('', 'y', 'yes'):
            return _reply()
        return _reply(_delete(session.dev, name))

    def filename(answer):
        if answer.strip() not in ('', name):
            return _reply()
        session.pending = confirm
        return _reply(f'Delete flash:/{name}? [confirm]', raw=True)

    session.pending = filename
    return _reply(f'Delete filename [{name}]? ', raw=True)


def _delete(dev, name):
    f = dev.flash.get(name)
    if f is None:
        return f'%Error deleting flash:/{name} (File not found)'
    if 'delete_fails' in dev.quirks and f.kind != 'image':
        dev.event('delete_failed', name)
        return f'%Error deleting flash:/{name} (Device or resource busy) (SIMULATED)'
    dev.flash.delete(name)
    if name in dev.archive_copies:
        dev.archive_copies.remove(name)
    dev.event('delete', name)
    return ''


def verify_command(session, w):
    from .cli import CLIError, INVALID
    if w.word(1).lower() != '/md5':
        raise CLIError(INVALID, w.pos(1))
    target = w.word(2)
    expected = w.word(3) if w.has(3) else None
    w.end(4)
    try:
        name = flash_path(target)
    except FlashError as err:
        return _reply(err.message)
    f = session.dev.flash.get(name) if name else None
    if f is None:
        return _reply(f'%Error opening flash:/{name} (File not found)')
    md5 = f.md5()
    if expected is None:
        dots = '.' * max(1, min(40, f.size // 65536))
        return _reply(f'{dots}Done!\nverify /md5 (flash:/{name}) = {md5}')
    if expected.lower() == md5:
        return _reply(f'Verified (flash:/{name}) = {md5}')
    return _reply(f'%Error verifying flash:/{name}\nComputed signature = {md5}\n'
                  f'Submitted signature = {expected}')


def tclsh_command(session, w):
    w.end(1)
    session.mode = 'tcl'
    return _reply()


def tcl_line(session, line):
    """One line typed in tclsh."""
    from .cli import Words
    text = line.strip()
    if not text:
        return _reply()
    if text.lower() in ('tclquit', 'tclq', 'exit'):
        session.mode = 'exec'
        return _reply()
    m = _PUTS.match(text)
    if not m:                                   # IOS hands other lines to the exec CLI
        return session.exec_command(Words(line))
    path, first = m.group(1), m.group(2)
    try:
        name = flash_path(path)
    except FlashError:
        return _reply(f'couldn\'t open "{path}": no such file or directory')
    if not name:
        return _reply(f'couldn\'t open "{path}": illegal operation on a directory')
    session.tcl_block = {'name': name, 'lines': []}
    return _tcl_collect(session, first)


def _tcl_collect(session, line):
    block = session.tcl_block
    if line.endswith('}'):
        block['lines'].append(line[:-1])
        return _tcl_write(session)
    block['lines'].append(line)
    session.pending = lambda nxt: _tcl_collect(session, nxt)
    return _reply()


def _tcl_write(session):
    dev, block = session.dev, session.tcl_block
    session.tcl_block = None
    data = ('\n'.join(block['lines']) + '\n').encode('utf-8')      # puts adds the newline
    if 'transfer_fails' in dev.quirks:          # the connection is cut half way
        try:
            dev.flash.write(block['name'], data[:len(data) // 2], kind='file',
                            overwrite='flash_overwrites' in dev.quirks)
        except FlashError:
            pass
        dev.event('transfer_failed', f"{block['name']}: connection lost (transfer_fails)")
        return _reply(drop=True)
    error = store_transfer(dev, block['name'], data)
    if error:
        return _reply(f'couldn\'t open "flash:{block["name"]}": {error}')
    return _reply()


def archive_exec(session, w):
    w.kw(1, ['config'])
    w.end(2)
    try:
        make_archive_copy(session.dev)
    except FlashError as err:
        return _reply(err.message)
    return _reply()


def show_archive(session, w):
    dev = session.dev
    if w.has(2):
        w.kw(2, ['config'])
        w.kw(3, ['rollback'])
        w.kw(4, ['timer'])
        w.end(5)
        rb = dev.rollback
        if rb is None:
            return NO_PENDING
        return (f'Time configured(or Reset) : {dev.clock.stamp(rb.started)}\n'
                f'Timer type                : rollback timer\n'
                f'Timer value               : {rb.minutes} min\n'
                f'Time remaining            : {rb.remaining(dev.clock.now())} secs\n'
                f'Archive file name         : flash:/{rb.archive_name or "none"}')
    a = dev.archive
    if not a or not a.get('path'):
        return 'Archive feature not enabled (SIMULATED: no "archive" "path" in the configuration)'
    maximum = a.get('maximum') or DEFAULT_ARCHIVE_MAXIMUM
    base = flash_path(a['path'].replace('$h', dev.hostname))
    rows = [f'The maximum archive configurations allowed is {maximum}.',
            f'The next archive file will be named flash:{base}-{dev.archive_next}',
            ' Archive #  Name']
    for n, name in enumerate(dev.archive_copies, 1):
        latest = ' <- Most Recent' if n == len(dev.archive_copies) else ''
        rows.append(f'   {n:<9}flash:{name}{latest}')
    return '\n'.join(rows)


def configure_replace(session, w):
    from .cli import CLIError, INVALID
    dev = session.dev
    try:
        name = flash_path(w.word(2))
    except FlashError as err:
        return _reply(err.message)
    options, minutes, i = set(), None, 3
    while w.has(i):
        word = w.kw(i, ['list', 'force', 'nolock', 'time'])
        if word == 'time':
            minutes = w.number(i + 1, 1, 120)
            i += 2
            continue
        options.add(word)
        i += 1
    if not name:
        return _reply('%Error opening flash:/ (Is a directory)')
    f = dev.flash.get(name)
    if f is None:
        return _reply(f'%Error opening flash:/{name} (File not found)')
    if f.data is None:
        raise CLIError(INVALID, w.pos(2))
    if dev.rollback is not None:
        return _reply('% A Rollback Confirmed Change is already pending: use "configure confirm" '
                      'or "configure revert" first (SIMULATED)')
    if minutes and not (dev.archive or {}).get('path'):
        return _reply('% Timed rollback needs the configuration archive: configure "archive" '
                      'and "path" first (SIMULATED)')
    if 'force' in options:
        return _do_replace(session, f, 'list' in options, minutes)

    def answer(typed):
        if typed.strip().lower() not in ('y', 'yes'):
            return _reply()
        return _do_replace(session, f, 'list' in options, minutes)

    session.pending = answer
    return _reply('This will apply all necessary additions and deletions\n'
                  'to replace the current running configuration with the\n'
                  'contents of the specified configuration file, which is\n'
                  'assumed to be a complete configuration, not a partial\n'
                  'configuration. Enter Y if you are sure you want to proceed. ? [no]: ',
                  raw=True)


def _do_replace(session, f, show_list, minutes):
    dev = session.dev
    before = dev.running_config()
    archive_name = None
    if (dev.archive or {}).get('path'):
        try:
            archive_name = make_archive_copy(dev)
        except FlashError as err:               # nothing has changed yet
            return _reply(err.message)
    snapshot = dev.config_state()
    if 'reboot_during_restore' in dev.quirks:
        reload(dev, 'reboot during configure replace (reboot_during_restore)')
        return _reply(drop=True)
    state, rejected = load_config_text(dev, f.data.decode('utf-8', 'replace'),
                                       reject_last='replace_partial' in dev.quirks)
    dev.set_config_state(state)                 # applied, even when only partly
    if 'verify_mismatch' in dev.quirks:
        dev.global_lines.append(MISMATCH_LINE)
    if 'reconnect_refused' in dev.quirks:
        dev.logins_refused = True
    if minutes:
        dev.rollback = Rollback(snapshot, archive_name, dev.clock.now(), minutes)
    dev.event('replace_partial' if rejected else 'replace', f.name)
    out = []
    if show_list:
        out += ['!Pass 1', '!List of Commands:'] + _changes(before, dev.running_config()) + ['end']
    if rejected:
        out.append('The following commands were rejected:')
        out += [f'{line}  ({message})' for line, message in rejected]
        out += ['Total number of passes: 5', 'Rollback aborted after 5 passes']
    else:
        out += ['Total number of passes: 1', 'Rollback Done']
    if minutes:
        out.append(f'Timed rollback: the configuration returns to flash:{archive_name} in '
                   f'{minutes} minutes unless "configure confirm" is entered (SIMULATED)')
    if 'drop_during_replace' in dev.quirks:
        dev.event('disconnect', 'during configure replace (drop_during_replace)')
        return _reply(drop=True)
    return _reply('\n'.join(out), delay_s=2.0)


def _changes(before, after):
    def body(text):
        return [l for l in text.split('\n')[3:] if l.strip() and l.strip() != '!']
    out = []
    for line in difflib.ndiff(body(before), body(after)):
        if line.startswith('- '):
            out.append('no ' + line[2:].strip())
        elif line.startswith('+ '):
            out.append(line[2:])
    return out


def configure_confirm(session, w):
    w.end(2)
    dev = session.dev
    if dev.rollback is None:
        return _reply(NO_PENDING)
    dev.rollback = None
    dev.event('confirm', '')
    return _reply()


def configure_revert(session, w):
    dev = session.dev
    sub = w.kw(2, ['now', 'timer'])
    if dev.rollback is None:
        return _reply(NO_PENDING)
    if sub == 'now':
        w.end(3)
        if rollback(dev, 'configure revert now'):
            return _reply('Rollback Done')
        return _reply('%Error: the rollback failed; the running configuration was not restored '
                      '(SIMULATED)')
    i = 3
    if w.has(i) and w.word(i).lower() == 'idle':
        i += 1
    minutes = w.number(i, 1, 120)
    w.end(i + 1)
    dev.rollback.minutes = minutes
    dev.rollback.deadline = dev.clock.now() + minutes * 60
    return _reply()


# ---------------------------------------------------------------- scenario specs
# Device specs for each restore scenario, for tests and the future restore engine.
RESTORE_SCENARIOS = {
    'success': {},
    'confirm_in_time': {},
    'timer_expires': {},
    'rollback_ok': {},
    'replace_unsupported': {'quirks': ['replace_unsupported']},
    'no_archive': {'archive': None},
    'no_transfer': {'quirks': ['no_tcl', 'no_scp']},
    'transfer_fails': {'quirks': ['transfer_fails']},
    'md5_mismatch': {'quirks': ['transfer_corrupt']},
    'partial_replace': {'quirks': ['replace_partial']},
    'rollback_fails': {'quirks': ['revert_fails']},
    'drop_during_replace': {'quirks': ['drop_during_replace']},
    'management_ip_change': {'management_ip': True},
    'reconnect_refused': {'quirks': ['reconnect_refused']},
    'verify_mismatch': {'quirks': ['verify_mismatch']},
    'cleanup_fails': {'quirks': ['delete_fails']},
    'reboot_during_restore': {'quirks': ['reboot_during_restore']},
    'scp': {'scp': True},
}


def restore_spec(spec, scenario):
    """A copy of a lab device spec prepared for one restore scenario: an archive with
    a path (unless the scenario is about its absence) and the scenario's quirks.
    management_ip: the first interface address in the spec."""
    if scenario not in RESTORE_SCENARIOS:
        raise ValueError(f'unknown restore scenario {scenario!r}')
    changes = RESTORE_SCENARIOS[scenario]
    out = copy.deepcopy(spec)
    out['archive'] = (None if 'archive' in changes and changes['archive'] is None
                      else {'path': 'flash:archive', 'maximum': 5})
    if out['archive'] is None:
        out.pop('archive')
    out['quirks'] = sorted(set(out.get('quirks') or []) | set(changes.get('quirks') or []))
    if changes.get('management_ip'):
        out['management_ip'] = next(s['ip'] for s in (spec.get('interfaces') or {}).values()
                                    if s.get('ip'))
    if changes.get('scp'):
        out['global_lines'] = list(out.get('global_lines') or []) + ['ip scp server enable']
    return out
