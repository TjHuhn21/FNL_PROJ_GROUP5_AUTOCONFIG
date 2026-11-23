"""Restore preflight (Phase 4E): everything that must be true BEFORE a restore, in two
separately authorised stages. Nothing here transfers a configuration, runs
`configure replace`, starts or answers a rollback timer, saves the configuration, enables
SCP or configures the archive.

Stage 1, run_checks(selection, creds): READ-ONLY.
    1. the selected backup is re-verified offline (the file still exists, is not a link,
       has the SHA-256 recorded at selection; AES-GCM tag, key id, decrypted SHA-256 and
       size; Apply's configuration check; key id / configuration SHA-256 / creation time
       still those of the selection). The decrypted configuration stays in memory: only
       facts derived from it (addresses, line settings) are kept, never the text.
    2. one SSH session through config.connect._open (strict ssh_options algorithms):
       SSH protocol 2 confirmed from the transport, privilege level 15 ("show privilege").
    3. live identity: show version, show inventory (when the device has it) and the
       running configuration. Strict serial rules (resolve_serial).
    4. matching: backup_catalogue.match (the Phase 4B rules), with the live serial and
       platform this time. A backup recorded for another IP address (a pending candidate
       of the catalogue) is BLOCKED unless the live serial AND platform both match it;
       create_safety_backup refuses such a result again on its own.
    5. restore capabilities, by show commands and two probes that change no configuration:
       pending rollback timer, archive path, `configure replace` support (the incomplete
       command "configure replace", which IOS cannot execute), Tcl (enter tclsh and leave
       it at once, as Netmiko's InLineTransfer does, writing nothing), SCP already enabled
       (read from the configuration; never enabled), free flash space and a free
       temporary file name.
    6. management access in the backup (offline): the management address, SSH on the
       VTY lines, local users / AAA.
    The session is closed before the result is returned: nothing is held open while the
    user reads it.

Stage 2, create_safety_backup(result, typed, creds): only after the user has read the
result and typed result.required_confirmation EXACTLY. It re-verifies the selected backup,
reconnects, re-checks privilege 15 and the hardware identity, and writes an ENCRYPTED
pre-restore backup of the current running configuration (config.connect._save_backup,
purpose "pre-restore"), then reads that file back and decrypts it in memory to verify it.
cancel(result) ends the workflow instead; the device has not been changed in any stage.

Statuses: PASS, WARNING (may proceed after the typed confirmation), BLOCKED (a safety rule
forbids the restore) and FAILED (something could not be done or checked). The result's
status is the most severe of its checks; BLOCKED and FAILED both stop the workflow.

Messages never contain the configuration, keys, passwords or user names.
"""
import hashlib
import hmac
import ipaddress
import os
import re
import secrets
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone

import backup_catalogue as B
import backup_crypto as C
import ssh_options
from config import connect

PASS, WARNING, BLOCKED, FAILED = 'PASS', 'WARNING', 'BLOCKED', 'FAILED'
_SEVERITY = {PASS: 0, WARNING: 1, FAILED: 2, BLOCKED: 3}

# stages
CHECKED = 'checked: waiting for the typed confirmation'
SAFETY_BACKUP_CREATED = 'safety backup created'
CANCELLED = 'cancelled'
STOPPED = 'stopped'
RESTORE_STARTED = 'restore started'       # set by restore_engine: a result is used once

# Sealing (Phase 4F): a stage-2 result carries an HMAC, keyed with a secret that exists only
# in this process, over everything the restore engine relies on. A result changed after the
# safety backup (or built by hand) does not verify. Not a defence against code running in
# the same process; it stops stale, reused or edited objects from being trusted.
_SEAL_KEY = secrets.token_bytes(32)

FRESH_SECONDS = 600               # the typed confirmation must follow the checks within this
PURPOSE = 'pre-restore'
FILE_SYSTEM = 'flash:'
TEMP_PREFIX, TEMP_SUFFIX = 'nc-restore-', '.cfg'
TEMP_NAME_TRIES = 5
FLASH_MARGIN_BYTES = 64 * 1024    # kept free on top of the file and the archive copy

SHOW_PRIVILEGE = connect.SHOW_PRIVILEGE
SHOW_VERSION = connect.SHOW_VERSION
SHOW_INVENTORY = 'show inventory'
SHOW_RUNNING = 'show running-config'
SHOW_ROLLBACK_TIMER = 'show archive config rollback timer'
SHOW_ARCHIVE = 'show archive'
REPLACE_PROBE = 'configure replace'           # incomplete on purpose: never executed
TCL_ENTER, TCL_EXIT = 'tclsh', 'tclquit'
SCP_LINE = 'ip scp server enable'
_NO_PENDING = 'no rollback confirmed change pending'
_INCOMPLETE = '% incomplete command'
_PROMPT_END = r'[>#]\s*$'
_FREE = re.compile(r'(\d+)\s+bytes\s+total\s+\((\d+)\s+bytes\s+free\)', re.IGNORECASE)
_NOT_FOUND = re.compile(r'file not found|no such file', re.IGNORECASE)


# ---------------------------------------------------------------- results
@dataclass(frozen=True)
class Check:
    name: str
    status: str
    text: str


@dataclass
class PreflightResult:
    device_ip: str
    selection: object
    checks: list = field(default_factory=list)
    identity: dict = field(default_factory=dict)       # live: hostname/platform/serial/ios
    backup: dict = field(default_factory=dict)         # the selected backup (no content)
    capabilities: dict = field(default_factory=dict)
    transfer_method: str = None                        # 'tcl' | 'scp' | None
    temp_name: str = None                              # a free flash name (checked)
    hardware_match: bool = False
    requires_legacy_confirmation: bool = True
    live_identity_verified: bool = False               # live serial AND platform both match
    required_confirmation: str = ''
    stage: str = STOPPED
    checked_utc: str = ''
    checked_at: float = None                           # monotonic time of the checks
    safety_backup_path: str = None
    safety_backup_sha256: str = None
    safety_backup_at: float = None                     # monotonic time it was verified
    confirmed_phrase: str = None                       # what the user typed (stage 2)
    seal: str = None                                   # see seal_of()
    report: object = field(default=None, repr=False, compare=False)

    @property
    def status(self):
        if not self.checks:
            return FAILED
        return max((c.status for c in self.checks), key=_SEVERITY.__getitem__)

    @property
    def can_proceed(self):
        """True when the safety backup may be created (after the typed confirmation)."""
        return self.stage == CHECKED and self.status in (PASS, WARNING)

    def add(self, name, status, text):
        self.checks.append(Check(name, status, text))
        if self.report:
            self.report({PASS: 'ok', WARNING: 'warn'}.get(status, 'error'),
                        f'{status}  {name}: {text}')
        return status

    def check(self, name):
        """The last check with this name, or None."""
        for c in reversed(self.checks):
            if c.name == name:
                return c
        return None

    def of(self, *statuses):
        return [c for c in self.checks if c.status in statuses]

    def lines(self):
        """The result as plain lines (for a console or a later window)."""
        out = [f'Restore preflight for {self.device_ip}: {self.status} ({self.stage})']
        out += [f'  {c.status:<7} {c.name}: {c.text}' for c in self.checks]
        if self.safety_backup_path:
            out.append(f'  Pre-restore safety backup: {self.safety_backup_path}')
        if self.can_proceed:
            out.append(f'  To continue, type exactly: {self.required_confirmation}')
        return out


class ConfirmationRefused(Exception):
    """The safety-backup stage was not started: no connection was opened, no file was
    written and the device was not changed."""


def seal_of(result):
    """The HMAC over the fields of a result the restore engine depends on."""
    import dataclasses
    import json
    selection = result.selection
    body = {
        'selection': dataclasses.asdict(selection) if dataclasses.is_dataclass(selection)
        else repr(selection),
        'checks': [dataclasses.astuple(c) for c in result.checks],
        **{name: getattr(result, name) for name in (
            'device_ip', 'identity', 'backup', 'capabilities', 'transfer_method', 'temp_name',
            'hardware_match', 'requires_legacy_confirmation', 'live_identity_verified',
            'required_confirmation', 'stage', 'checked_utc', 'checked_at',
            'safety_backup_path', 'safety_backup_sha256', 'safety_backup_at',
            'confirmed_phrase')}}
    text = json.dumps(body, sort_keys=True, default=str).encode('utf-8')
    return hmac.new(_SEAL_KEY, text, hashlib.sha256).hexdigest()


def seal_valid(result):
    return isinstance(result, PreflightResult) and isinstance(result.seal, str) and \
        hmac.compare_digest(result.seal, seal_of(result))


def confirmation_phrase(ip, legacy):
    """What the user must type to proceed. A backup whose hardware identity is not
    confirmed by serial needs the legacy wording (the Phase 4B rule)."""
    return f'RESTORE LEGACY {ip}' if legacy else f'RESTORE {ip}'


# ---------------------------------------------------------------- configuration facts
@dataclass
class ConfigFacts:
    """What the preflight needs from a configuration. User names are kept only to answer
    "is this account defined" and are never shown."""
    interfaces: dict = field(default_factory=dict)     # name -> {'ips': set, 'shutdown': bool}
    lines: dict = field(default_factory=dict)          # 'vty 0 4' -> [sub-lines]
    users: dict = field(default_factory=dict)          # name -> privilege (int or None)
    globals: set = field(default_factory=set)          # top-level lines, stripped
    archive_path: str = None

    @property
    def aaa(self):
        return 'aaa new-model' in self.globals

    @property
    def enable_secret(self):
        return any(g.startswith(('enable secret ', 'enable password ')) for g in self.globals)

    @property
    def scp_enabled(self):
        return SCP_LINE in self.globals

    def interfaces_with(self, ip):
        return [n for n, i in self.interfaces.items() if ip in i['ips']]

    def vty_lines(self):
        return {n: s for n, s in self.lines.items() if n.split()[0] == 'vty'}


_IP_ADDRESS = re.compile(r'^ip address (\S+) (\S+)(?: secondary)?$')
_USER = re.compile(r'^username (\S+)(?:.*\bprivilege (\d{1,2})\b)?')


def parse_config(text):
    """ConfigFacts of an IOS configuration (running-config or a backup), in memory."""
    facts, section, name = ConfigFacts(), None, None
    for raw in (text or '').replace('\r\n', '\n').replace('\r', '\n').split('\n'):
        line = raw.rstrip()
        bare = line.strip()
        if not bare or bare.startswith('!'):
            if bare.startswith('!'):
                section = None
            continue
        if not line[0].isspace():                       # a top-level line
            facts.globals.add(bare)
            section, name = None, None
            words = bare.split()
            if words[0] == 'interface' and len(words) > 1:
                section, name = 'interface', ' '.join(words[1:])
                facts.interfaces.setdefault(name, {'ips': set(), 'shutdown': False})
            elif words[0] == 'line' and len(words) > 1:
                section, name = 'line', ' '.join(words[1:])
                facts.lines.setdefault(name, [])
            elif bare == 'archive':
                section = 'archive'
            elif words[0] == 'username':
                m = _USER.match(bare)
                if m:
                    facts.users[m.group(1)] = int(m.group(2)) if m.group(2) else None
            continue
        if section == 'interface':
            m = _IP_ADDRESS.match(bare)
            if m:
                facts.interfaces[name]['ips'].add(m.group(1))
            elif bare == 'shutdown':
                facts.interfaces[name]['shutdown'] = True
            elif bare == 'no shutdown':
                facts.interfaces[name]['shutdown'] = False
        elif section == 'line':
            facts.lines[name].append(bare)
        elif section == 'archive' and bare.startswith('path '):
            facts.archive_path = bare.split(None, 1)[1]
    return facts


# ---------------------------------------------------------------- identity
_PROCESSOR_BOARD = re.compile(r'^[ \t]*Processor board ID\b[ \t]*(.*?)[ \t\r]*$', re.MULTILINE)
_INV_NAME = re.compile(r'^NAME:\s*"([^"]*)"\s*,\s*DESCR:\s*"([^"]*)"\s*$')
_INV_PID = re.compile(r'^PID:\s*(\S*)\s*,\s*VID:\s*(\S*)\s*,\s*SN:\s*(\S*)\s*$')
INVENTORY_UNAVAILABLE, INVENTORY_UNREADABLE, INVENTORY_OK = 'unavailable', 'unreadable', 'ok'


def _known(value):
    return B._known(value)


def parse_inventory(text):
    """(state, [(name, descr, pid, sn)]). unavailable: no output, or the device does not
    know the command; unreadable: output that is not entirely NAME/PID entries."""
    lines = [l.strip() for l in (text or '').splitlines() if l.strip()]
    if not lines or lines[0].startswith('%') or connect.rejection(text) or \
            'authorization failed' in lines[0].lower():
        return INVENTORY_UNAVAILABLE, []
    entries, i = [], 0
    while i < len(lines):
        m = _INV_NAME.match(lines[i])
        p = _INV_PID.match(lines[i + 1]) if m and i + 1 < len(lines) else None
        if not p:
            return INVENTORY_UNREADABLE, []
        entries.append((m.group(1), m.group(2), p.group(1), p.group(3)))
        i += 2
    return INVENTORY_OK, entries


def is_chassis(name, descr):
    """A chassis entry: "chassis" in its name or description, or a bare stack-member
    number ("1", "2") as Catalyst switches name theirs. Modules never count."""
    return 'chassis' in name.lower() or 'chassis' in descr.lower() or \
        bool(re.fullmatch(r'\d{1,2}', name.strip()))


def resolve_serial(show_version, show_inventory):
    """(serial, None) or (None, why it cannot be relied on). Strict:
    * every "Processor board ID" line of show version and every chassis serial of show
      inventory is read; module serials are ignored;
    * an unreadable value, two different values in either source, or a disagreement
      between the sources: no serial;
    * no value at all: no serial."""
    boards = [v for v in _PROCESSOR_BOARD.findall(show_version or '')]
    if any(not _known(v) for v in boards):
        return None, 'the "Processor board ID" in show version is not a plain serial number'
    boards = sorted(set(boards))
    if len(boards) > 1:
        return None, f'show version reports {len(boards)} different processor board IDs'
    state, entries = parse_inventory(show_inventory)
    if state == INVENTORY_UNREADABLE:
        return None, 'the show inventory output could not be read reliably'
    chassis = [sn for name, descr, _pid, sn in entries if is_chassis(name, descr)]
    if any(not _known(sn) for sn in chassis):
        return None, 'a chassis entry of show inventory has no usable serial number'
    chassis = sorted(set(chassis))
    if len(chassis) > 1:
        return None, f'show inventory lists {len(chassis)} different chassis serial numbers'
    if boards and chassis and boards[0] != chassis[0]:
        return None, (f'show version (processor board ID {boards[0]}) and show inventory '
                      f'(chassis {chassis[0]}) disagree')
    serial = (boards or chassis or [None])[0]
    if serial is None:
        return None, 'the device shows no chassis serial number'
    return serial, None


def resolve_platform(version_platform, show_inventory):
    """(platform or None, problem or None): show version's model, cross-checked with the
    chassis PID of show inventory when both are known."""
    _state, entries = parse_inventory(show_inventory)
    pids = sorted({pid for name, descr, pid, _sn in entries
                   if is_chassis(name, descr) and _known(pid)})
    if len(pids) > 1:
        return None, f'show inventory lists {len(pids)} different chassis models'
    if _known(version_platform) and pids and version_platform.casefold() != pids[0].casefold():
        return None, (f'show version ({version_platform}) and show inventory ({pids[0]}) '
                      f'name different models')
    return (version_platform if _known(version_platform) else (pids or [None])[0]), None


def live_identity(show_version, show_inventory, running_config):
    """(identity dict, [(status, text) problems])."""
    base = connect.parse_identity(show_version, running_config)
    serial, serial_problem = resolve_serial(show_version, show_inventory)
    platform, platform_problem = resolve_platform(base['platform'], show_inventory)
    identity = {'hostname': base['hostname'], 'platform': platform, 'serial': serial,
                'ios_version': base['ios_version']}
    problems = []
    if serial_problem:
        problems.append(('serial', f'The hardware serial number cannot be reliably '
                                   f'identified: {serial_problem}.'))
    if platform_problem:
        problems.append(('platform', f'The platform cannot be reliably identified: '
                                     f'{platform_problem}.'))
    return identity, problems


# ---------------------------------------------------------------- stage 1
def run_checks(selection, creds, management_ip=None, key_source=None, log=None,
               clock=time.monotonic):
    """The read-only preflight. Returns a PreflightResult; never raises for device,
    network or backup problems. creds = {'host', 'username', 'password'[, 'secret']}.
    management_ip: the address NetCommand reaches the device by, when it differs from
    creds['host'] (NAT, a lab); default creds['host']."""
    report = connect._Report(log)
    ip = (creds or {}).get('host')
    result = PreflightResult(device_ip=ip, selection=selection, report=report)
    result.checked_utc = datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')
    report('section', 'RESTORE PREFLIGHT (read-only: nothing is changed)')
    if not isinstance(selection, B.Selection):
        result.add('selection', BLOCKED, 'No verified backup selection was given.')
        return _finish(result, clock)
    result.backup = {'path': selection.path, 'file_sha256': selection.file_sha256,
                     'key_id': selection.key_id,
                     'plaintext_sha256': selection.plaintext_sha256,
                     'created_utc': selection.created_utc,
                     'selected_for': selection.device_ip}
    if not ip or ip != selection.device_ip:
        result.add('device', BLOCKED, f'The backup was selected for {selection.device_ip}, not '
                                      f'for {ip}: select a backup for this device.')
        return _finish(result, clock)
    mgmt = management_ip or ip
    try:
        mgmt = str(ipaddress.IPv4Address(mgmt))
    except (ipaddress.AddressValueError, ValueError):
        result.add('management-ip', BLOCKED, 'The management address is not an IPv4 address.')
        return _finish(result, clock)

    report('section', 'SELECTED BACKUP')
    header, text = _reverify(selection, result, key_source, 'backup')
    if header is None:
        return _finish(result, clock)
    try:
        target = parse_config(text)
    finally:
        del text                                      # the configuration is never kept
    result.backup.update({'host': header.get('host'), 'plaintext_size': header['plaintext_size'],
                          'identity': C.identity_of(header), 'purpose': header.get('purpose')})

    report('section', 'CONNECT')
    report('info', f'Connecting to {ip} through SSH...')
    try:
        conn = connect._open(creds)
    except Exception as err:
        _kind, text = ssh_options.describe_error(err, ip)
        result.add('connection', FAILED, f'The SSH connection could not be opened: {text}.')
        return _finish(result, clock)
    try:
        _session_checks(conn, result, header, target, mgmt, creds, report)
    except Exception as err:
        _kind, text = ssh_options.describe_error(err, ip)
        result.add('session', FAILED, f'The SSH session failed: {text}. The preflight stopped; '
                                      f'nothing was changed.')
    finally:
        _close(conn, report)
    return _finish(result, clock)


def _finish(result, clock):
    if result.status in (PASS, WARNING):
        result.stage, result.checked_at = CHECKED, clock()
        result.required_confirmation = confirmation_phrase(
            result.device_ip, result.requires_legacy_confirmation)
    else:
        result.stage = STOPPED
    if result.report:
        result.report('section', 'PREFLIGHT RESULT')
        kind = {PASS: 'ok', WARNING: 'warn'}.get(result.status, 'error')
        if result.can_proceed:
            result.report(kind, f'{result.status}: the device was not changed. Review the '
                                f'checks; to continue, type {result.required_confirmation}')
        else:
            result.report(kind, f'{result.status}: the restore cannot continue. The device '
                                f'was not changed.')
    return result


def _close(conn, report):
    try:
        conn.disconnect()
        report('info', 'SSH session closed.')
    except Exception:
        pass


def _send(conn, report, command, **kw):
    report('command', command)
    return conn.send_command(command, **kw) or ''


# ---------------------------------------------------------------- backup reverification
def _reverify(selection, result, key_source, name):
    """(authenticated header, configuration text) of exactly the selected file, or
    (None, None) with the reason added to result. Reads only; writes nothing."""
    def stop(status, text):
        result.add(name, status, text)
        return None, None

    path = selection.path
    if not os.path.lexists(path):
        return stop(BLOCKED, 'The selected backup file no longer exists: select a backup again.')
    if B._is_link(path):
        return stop(BLOCKED, 'The selected backup is now a link or junction; it is not followed.')
    if not os.path.isfile(path):
        return stop(BLOCKED, 'The selected backup is not a regular file.')
    try:
        data = B._read(path)
    except C.FormatError as err:
        return stop(BLOCKED, str(err))
    except OSError as err:
        return stop(FAILED, f'The selected backup cannot be read '
                            f'({err.strerror or type(err).__name__}).')
    if not selection.file_sha256 or not hmac.compare_digest(
            hashlib.sha256(data).hexdigest(), selection.file_sha256):
        return stop(BLOCKED, 'The backup file changed after it was selected (its SHA-256 '
                             'differs): verify and select it again.')
    try:
        key_for = connect.load_backup_key(key_source).key_for
    except connect.BackupKeyUnavailable as err:
        return stop(FAILED, str(err))
    try:
        plaintext, header = C.decrypt_backup(data, key_for)
    except C.UnknownKey:
        return stop(FAILED, 'The keyring does not hold the key this backup was encrypted with.')
    except C.AuthenticationFailed:
        return stop(BLOCKED, C.AUTH_FAILED)
    except (C.IntegrityError, C.FormatError) as err:
        return stop(BLOCKED, str(err))
    except C.BackupCryptoError as err:
        return stop(FAILED, f'The keyring could not be used ({str(err).rstrip(".")}).')
    except Exception as err:
        return stop(FAILED, f'The backup could not be checked ({type(err).__name__}).')
    try:
        for field_name, expected, label in (
                ('key_id', selection.key_id, 'key id'),
                ('plaintext_sha256', selection.plaintext_sha256, 'configuration SHA-256'),
                ('created_utc', selection.created_utc, 'creation time')):
            if header.get(field_name) != expected:
                return stop(BLOCKED, f'The backup\'s {label} is not the one recorded when it '
                                     f'was selected: select it again.')
        if len(plaintext) != header['plaintext_size']:
            return stop(BLOCKED, 'The decrypted size does not match the backup header.')
        try:
            text = plaintext.decode('utf-8')
        except UnicodeDecodeError:
            return stop(BLOCKED, 'The configuration in the backup is not valid text.')
    finally:
        del plaintext
    problem = connect.check_backup(text)
    if problem:
        del text
        return stop(BLOCKED, f'The configuration is not usable: {problem.split(" (")[0]}.')
    result.add(name, PASS, f'Re-verified in memory: AES-GCM authentic, key_id={header["key_id"]}, '
                           f'configuration SHA-256 {header["plaintext_sha256"]}, '
                           f'{header["plaintext_size"]} bytes, configuration check passed, '
                           f'unchanged since selection.')
    return header, text


# ---------------------------------------------------------------- the session (stage 1)
def _ssh_protocol(conn, result):
    """SSH protocol 2 is required. Paramiko speaks only SSH-2; the server's banner says
    whether it would also accept SSH-1 ("SSH-1.99")."""
    try:
        transport = conn.remote_conn.get_transport()
        banner, active = transport.remote_version, transport.is_active()
    except Exception:
        banner, active = None, False
    if not active or not isinstance(banner, str):
        return result.add('ssh', FAILED, 'The SSH protocol version could not be confirmed.')
    if banner.startswith('SSH-2.0-'):
        return result.add('ssh', PASS, 'SSH protocol version 2 session.')
    if banner.startswith('SSH-1.99-'):
        return result.add('ssh', WARNING, 'SSH protocol version 2 session; the device also '
                                          'accepts SSH version 1 ("ip ssh version 2" is '
                                          'recommended).')
    return result.add('ssh', BLOCKED, 'The device did not offer SSH protocol version 2.')


def _session_checks(conn, result, header, target, mgmt, creds, report):
    if _ssh_protocol(conn, result) in (BLOCKED, FAILED):
        return
    problem = connect.privilege_problem(_send(conn, report, SHOW_PRIVILEGE))
    if problem:
        result.add('privilege', BLOCKED, f'Privilege level {connect.REQUIRED_PRIVILEGE} is '
                                         f'required: {problem}.')
        return
    result.add('privilege', PASS, f'Privilege level {connect.REQUIRED_PRIVILEGE} confirmed.')

    report('section', 'DEVICE IDENTITY')
    version = _send(conn, report, SHOW_VERSION)
    inventory = _send(conn, report, SHOW_INVENTORY)
    running = _send(conn, report, SHOW_RUNNING)
    unusable = connect.check_backup(running)
    if unusable:
        result.add('running-config', FAILED, f'The current running configuration could not '
                                             f'be read completely: {unusable.split(" (")[0]}.')
        return
    if not _identity_and_match(result, header, version, inventory, running):
        return

    report('section', 'RESTORE CAPABILITIES (read-only)')
    current = parse_config(running)
    _capabilities(conn, result, report, header['plaintext_size'],
                  len(running.encode('utf-8', 'replace')), current, target)
    report('section', 'MANAGEMENT ACCESS AFTER THE RESTORE')
    management_checks(result, target, current, mgmt, creds.get('username'))


def needs_live_identity(result, header):
    """True when only a live serial AND platform match may let this restore go on: the
    backup's recorded IP differs from the device's, or the catalogue selected it as a
    pending candidate."""
    return (header or {}).get('host') != result.device_ip or \
        bool(getattr(result.selection, 'live_identity_required', False))


def _identity_and_match(result, header, version, inventory, running):
    identity, problems = live_identity(version, inventory, running)
    result.identity = identity
    for _field, text in problems:
        result.add('identity', BLOCKED, text)
    if problems:
        return False
    result.add('identity', PASS, f'Live identity: {connect.describe_identity(identity)}.')
    m = B.match(header, B.Device(ip=result.device_ip, hostname=identity['hostname'],
                                 platform=identity['platform'], serial=identity['serial'],
                                 device_id=getattr(result.selection, 'device_id', None)))
    blocked_by_field = False
    for name, outcome, text in m.checks:
        if outcome == 'match':
            status = PASS
        elif outcome == 'mismatch' and name in ('serial', 'platform'):
            status, blocked_by_field = BLOCKED, True
        else:
            status = WARNING
        result.add(f'match-{name}', status, text + '.')
    if m.blocked and not blocked_by_field:
        result.add('match', BLOCKED, m.block_reason + '.')
    if not m.identity_recorded:
        result.add('match', WARNING, 'The backup records no device identity (made before '
                                     'identity was recorded); it is never treated as a '
                                     'hardware match.')
    result.hardware_match = m.hardware_match and not m.blocked
    result.requires_legacy_confirmation = m.requires_legacy_confirmation
    outcomes = {name: outcome for name, outcome, _text in m.checks}
    result.live_identity_verified = (not m.blocked and outcomes.get('serial') == 'match'
                                     and outcomes.get('platform') == 'match')
    if needs_live_identity(result, header) and not m.blocked:
        # A changed-IP backup (a pending candidate from the catalogue): the live serial AND
        # platform are the only proof that this is the same hardware.
        if not result.live_identity_verified:
            result.add('live-identity', BLOCKED, f'The backup was recorded for '
                                                 f'{header.get("host") or "no address"}, not '
                                                 f'{result.device_ip}: the live serial number '
                                                 f'AND platform must both match the backup, '
                                                 f'and they do not both match.')
            return False
        result.add('live-identity', PASS, f'Changed IP address: the live serial number and '
                                          f'platform both match the backup recorded for '
                                          f'{header.get("host")}.')
    if not m.blocked and m.requires_legacy_confirmation:
        result.add('match', WARNING, 'The hardware identity is not confirmed by serial number: '
                                     'the legacy-backup confirmation is required.')
    return not m.blocked


def _capabilities(conn, result, report, target_size, running_size, current, target):
    caps = result.capabilities

    out = _send(conn, report, SHOW_ROLLBACK_TIMER)
    if _NO_PENDING in out.lower():
        caps['rollback_pending'] = False
        result.add('pending-rollback', PASS, 'No timed rollback is pending.')
    elif not out.strip() or connect.rejection(out):
        caps['rollback_pending'] = None
        result.add('pending-rollback', BLOCKED, 'Whether a timed rollback is pending cannot be '
                                                'read (show archive config rollback timer).')
    else:
        caps['rollback_pending'] = True
        result.add('pending-rollback', BLOCKED, 'A timed rollback is already pending on the '
                                                'device: another change is in progress.')

    out = _send(conn, report, SHOW_ARCHIVE)
    caps['archive_path'] = current.archive_path
    if not out.strip() or connect.rejection(out):
        caps['archive'] = False
        result.add('archive', BLOCKED, 'The device does not support the configuration archive '
                                       '(show archive).')
    elif not current.archive_path:
        caps['archive'] = False
        result.add('archive', BLOCKED, 'No archive path is configured, so a timed rollback is '
                                       'not possible. NetCommand does not configure it: add '
                                       '"archive" / "path" yourself, then run the preflight '
                                       'again.')
    else:
        caps['archive'] = True
        result.add('archive', PASS, f'Archive path configured ({current.archive_path}).')
        if not target.archive_path:
            result.add('archive', WARNING, 'The backup has no archive path: after the restore '
                                           'the archive configuration would be removed.')

    out = _send(conn, report, REPLACE_PROBE)
    if _INCOMPLETE in out.lower():
        caps['configure_replace'] = True
        result.add('rollback', PASS, '"configure replace" (with timed rollback) is supported.')
    elif connect.rejection(out):
        caps['configure_replace'] = False
        result.add('rollback', BLOCKED, '"configure replace" is not supported by this device.')
    else:
        caps['configure_replace'] = None
        result.add('rollback', BLOCKED, 'Support for "configure replace" could not be '
                                        'determined.')

    out = _send(conn, report, f'dir {FILE_SYSTEM}')
    found = _FREE.findall(out)
    needed = target_size + running_size + FLASH_MARGIN_BYTES
    caps['flash_needed'] = needed
    if len(found) != 1:
        caps['flash_free'] = None
        result.add('flash-space', BLOCKED, f'The free space of {FILE_SYSTEM} could not be read.')
    else:
        free = int(found[0][1])
        caps['flash_free'] = free
        if free < needed:
            result.add('flash-space', BLOCKED, f'Not enough free space on {FILE_SYSTEM}: {free} '
                                               f'bytes free, {needed} needed (the backup, an '
                                               f'archive copy and a margin).')
        else:
            result.add('flash-space', PASS, f'{free} bytes free on {FILE_SYSTEM} ({needed} '
                                            f'needed).')

    _temp_name(conn, result, report)

    caps['scp'] = current.scp_enabled
    caps['tcl'] = _tcl_probe(conn, result, report)
    if caps['tcl'] is None:
        return                                     # the session is in an unknown state
    if caps['tcl']:
        result.transfer_method = 'tcl'
        result.add('transfer', PASS, 'Tcl (tclsh) is available: the configuration can be '
                                     'transferred from memory.' +
                   (' SCP is also enabled.' if caps['scp'] else ''))
    elif caps['scp']:
        result.transfer_method = 'scp'
        text = 'Tcl is not available; SCP is already enabled ("ip scp server enable").'
        if not current.aaa:
            result.add('transfer', WARNING, text + ' IOS normally also needs AAA authorization '
                                                   'for SCP; the transfer may be refused.')
        else:
            result.add('transfer', PASS, text)
    else:
        result.add('transfer', BLOCKED, 'No safe transfer method: Tcl is not available and SCP '
                                        'is not enabled (NetCommand never enables SCP).')


def _temp_name(conn, result, report):
    for _ in range(TEMP_NAME_TRIES):
        name = f'{TEMP_PREFIX}{secrets.token_hex(8)}{TEMP_SUFFIX}'
        out = _send(conn, report, f'dir {FILE_SYSTEM}/{name}')
        if name in out and not _NOT_FOUND.search(out):
            continue                                       # taken: try another name
        if _NOT_FOUND.search(out):
            result.temp_name = name
            result.add('temp-file', PASS, f'Temporary file name {FILE_SYSTEM}{name} is free.')
            return
        result.add('temp-file', BLOCKED, 'Whether a temporary file name is free could not be '
                                         'read.')
        return
    result.add('temp-file', BLOCKED, 'No free temporary file name was found.')


def _tcl_probe(conn, result, report):
    """True / False, or None when tclsh was entered but could not be left. Enters tclsh
    and leaves it at once; nothing is written."""
    out = _send(conn, report, TCL_ENTER, expect_string=_PROMPT_END, strip_prompt=False)
    if '(tcl)' not in out and '(tcl)' not in conn.find_prompt():
        return False
    _send(conn, report, TCL_EXIT, expect_string=_PROMPT_END, strip_prompt=False)
    if '(tcl)' in conn.find_prompt():
        result.add('transfer', FAILED, 'tclsh could not be left; the preflight stopped.')
        return None
    return True


# ---------------------------------------------------------------- management access
def management_checks(result, target, current, mgmt, username):
    """Offline: will NetCommand still reach and log in to the device after the restore?"""
    now = current.interfaces_with(mgmt)
    after = target.interfaces_with(mgmt)
    up_after = [n for n in after if not target.interfaces[n]['shutdown']]
    if up_after:
        moved = bool(now) and not set(now) & set(up_after)
        result.add('management-ip', WARNING if moved else PASS,
                   f'The backup keeps the management address {mgmt} on {", ".join(up_after)}' +
                   (f' (now on {", ".join(now)}).' if moved else '.'))
    elif after:
        result.add('management-ip', BLOCKED, f'The backup has the management address {mgmt} only '
                                             f'on a shut-down interface ({", ".join(after)}).')
    elif now:
        result.add('management-ip', BLOCKED, f'The backup does not have the management address '
                                             f'{mgmt} (now on {", ".join(now)}): the restore '
                                             f'would cut NetCommand off.')
    else:
        result.add('management-ip', WARNING, f'{mgmt} is not configured on the device itself '
                                             f'(NAT, a lab or another path): whether the backup '
                                             f'keeps management access cannot be checked.')

    vtys = target.vty_lines()
    ssh_lines, unknown = [], []
    for name, subs in vtys.items():
        transport = [s for s in subs if s.startswith('transport input')]
        if not transport:
            unknown.append(name)
        elif {'ssh', 'all'} & set(transport[-1].split()[2:]):
            ssh_lines.append(name)
    if not vtys:
        result.add('ssh-vty', BLOCKED, 'The backup configures no VTY lines: SSH logins would not '
                                       'be possible after the restore.')
        return
    if ssh_lines:
        result.add('ssh-vty', PASS, f'The backup allows SSH on line {", ".join(ssh_lines)}.')
    elif unknown:
        result.add('ssh-vty', WARNING, f'Line {", ".join(unknown)} has no "transport input" '
                                       f'line: whether SSH is allowed depends on the IOS '
                                       f'version.')
    else:
        result.add('ssh-vty', BLOCKED, 'No VTY line in the backup allows SSH: the restore would '
                                       'cut off NetCommand\'s SSH access.')
        return
    usable = {n: vtys[n] for n in ssh_lines + unknown}
    for name, subs in usable.items():
        if any(s.startswith('access-class ') for s in subs):
            result.add('login', WARNING, f'Line {name} has an access-class in the backup: check '
                                         f'that it allows NetCommand\'s address.')
    if target.aaa:
        result.add('login', WARNING, 'The backup uses AAA (aaa new-model): logins depend on '
                                     'AAA method lists and servers, which cannot be checked '
                                     'here.')
        return
    if current.aaa:
        result.add('login', WARNING, 'The device uses AAA now but the backup does not: the way '
                                     'logins are checked would change.')
    local = [n for n, subs in usable.items() if 'login local' in subs]
    if len(local) != len(usable):
        result.add('login', WARNING, 'Not every SSH-capable VTY line uses "login local": the '
                                     'user-name login NetCommand uses may not work there.')
    if not local:
        return
    if not target.users:
        result.add('login', BLOCKED, 'The backup uses "login local" but defines no local user: '
                                     'nobody could log in over SSH after the restore.')
    elif username not in target.users:
        result.add('login', WARNING, 'The account used for this session is not defined in the '
                                     'backup: NetCommand may not be able to log in again.')
    else:
        privilege = target.users[username]
        if privilege != 15 and not target.enable_secret:
            result.add('login', WARNING, 'In the backup, the account used for this session is '
                                         'not privilege 15 and there is no enable secret: '
                                         'privilege 15 may not be reachable afterwards.')
        else:
            result.add('login', PASS, 'The account used for this session is defined in the '
                                      'backup (login local).')


# ---------------------------------------------------------------- stage 2
def cancel(result):
    """End the workflow at the user's request. Nothing is sent; the device stays as it
    is (it was never changed). A safety backup already made is kept (encrypted)."""
    result.stage = CANCELLED
    if result.report:
        result.report('warn', 'Restore cancelled by the user. The device was not changed.')
    return result


def create_safety_backup(result, typed, creds, backup_dir=None, key_source=None, log=None,
                         clock=time.monotonic):
    """Stage 2, only after the user has read the preflight and typed
    result.required_confirmation exactly. Raises ConfirmationRefused (nothing done) when
    the stage may not start; otherwise returns result with the safety backup recorded, or
    with a FAILED / BLOCKED check (stage STOPPED). Only reads from the device."""
    if not isinstance(result, PreflightResult):
        raise ConfirmationRefused('There is no preflight result. Nothing was done.')
    if result.stage == CANCELLED:
        raise ConfirmationRefused('The restore was cancelled; run the preflight again. Nothing '
                                  'was done.')
    if result.stage == SAFETY_BACKUP_CREATED:
        raise ConfirmationRefused('The safety backup was already created for this preflight. '
                                  'Nothing was done.')
    if not result.can_proceed:
        raise ConfirmationRefused(f'The preflight did not pass ({result.status}); the restore '
                                  f'cannot continue. Nothing was done.')
    if (creds or {}).get('host') != result.device_ip:
        raise ConfirmationRefused('These login details are for another device. Nothing was '
                                  'done.')
    if needs_live_identity(result, {'host': result.backup.get('host')}) and \
            not result.live_identity_verified:
        raise ConfirmationRefused('This backup was recorded for another IP address and the '
                                  'live serial number and platform were not both verified. '
                                  'Nothing was done.')
    if result.checked_at is None or clock() - result.checked_at > FRESH_SECONDS:
        raise ConfirmationRefused('The preflight is too old; run it again. Nothing was done.')
    expected = result.required_confirmation
    if not isinstance(typed, str) or not expected or \
            not hmac.compare_digest(typed.encode('utf-8'), expected.encode('utf-8')):
        raise ConfirmationRefused(f'The confirmation was not typed exactly ({expected}). '
                                  f'Nothing was done.')

    report = connect._Report(log) if log else result.report
    result.report = report
    ip = result.device_ip
    report('section', 'PRE-RESTORE SAFETY BACKUP')
    header, text = _reverify(result.selection, result, key_source, 'backup-recheck')
    if header is None:
        result.stage = STOPPED
        return result
    del text
    try:
        backup_key = connect.load_backup_key(key_source)
    except connect.BackupKeyUnavailable as err:
        result.add('safety-backup', FAILED, f'{err} No safety backup was made.')
        result.stage = STOPPED
        return result
    report('info', f'Connecting to {ip} through SSH...')
    try:
        conn = connect._open(creds)
    except Exception as err:
        _kind, text = ssh_options.describe_error(err, ip)
        result.add('safety-backup', FAILED, f'The SSH connection could not be opened: {text}. '
                                            f'No safety backup was made.')
        result.stage = STOPPED
        return result
    try:
        _safety_session(conn, result, report, backup_dir, backup_key)
    except Exception as err:
        _kind, text = ssh_options.describe_error(err, ip)
        result.add('safety-backup', FAILED, f'The SSH session failed: {text}. No verified '
                                            f'safety backup was made.')
    finally:
        _close(conn, report)
    if result.safety_backup_path and result.status in (PASS, WARNING):
        result.stage = SAFETY_BACKUP_CREATED
        result.safety_backup_at, result.confirmed_phrase = clock(), typed
        result.seal = seal_of(result)
        report('ok', f'Safety backup created and verified: {result.safety_backup_path}. '
                     f'The device was not changed.')
    else:
        result.stage = STOPPED
        report('error', 'The restore cannot continue without a verified safety backup. The '
                        'device was not changed.')
    return result


def _safety_session(conn, result, report, backup_dir, backup_key):
    if _ssh_protocol(conn, result) in (BLOCKED, FAILED):
        return
    problem = connect.privilege_problem(_send(conn, report, SHOW_PRIVILEGE))
    if problem:
        result.add('privilege', BLOCKED, f'Privilege level {connect.REQUIRED_PRIVILEGE} is '
                                         f'required: {problem}.')
        return
    version = _send(conn, report, SHOW_VERSION)
    inventory = _send(conn, report, SHOW_INVENTORY)
    running = _send(conn, report, SHOW_RUNNING)
    identity, problems = live_identity(version, inventory, running)
    for _field, text in problems:
        result.add('identity-recheck', BLOCKED, text)
    if problems:
        return
    before = result.identity
    if identity['serial'] != before.get('serial') or \
            (identity['platform'] or '').casefold() != (before.get('platform') or '').casefold():
        result.add('identity-recheck', BLOCKED, 'The device answering at this address is not '
                                                'the one checked by the preflight (serial or '
                                                'platform differs).')
        return
    result.add('identity-recheck', PASS, f'Same device as in the preflight (serial '
                                         f'{identity["serial"]}).')
    try:
        path, sha, key_id = connect._save_backup(result.device_ip, running, backup_dir,
                                                 backup_key, identity, purpose=PURPOSE)
    except connect.BackupError as err:
        result.add('safety-backup', FAILED, f'{str(err).rstrip(".")}. No safety backup was made.')
        return
    problem = verify_safety_backup(path, running, backup_key.key_for, result.device_ip, identity)
    if problem:
        result.add('safety-backup', FAILED, f'The safety backup could not be verified: {problem}. '
                                            f'Do not continue. File: {path}')
        return
    result.safety_backup_path, result.safety_backup_sha256 = path, sha
    result.add('safety-backup', PASS, f'Encrypted pre-restore backup written, read back and '
                                      f'decrypted in memory (key_id={key_id}, configuration '
                                      f'SHA-256 {sha}): {path}')


def verify_safety_backup(path, running, key_for, ip, identity):
    """None when the file at path decrypts (in memory) to exactly `running` with the
    pre-restore label, address and identity; otherwise why not."""
    try:
        data = B._read(path)
    except (OSError, C.FormatError):
        return 'the file cannot be read back'
    try:
        plaintext, header = C.decrypt_backup(data, key_for)
    except C.BackupCryptoError:
        return 'the file does not decrypt and authenticate'
    try:
        if not hmac.compare_digest(plaintext, running.encode('utf-8')):
            return 'the decrypted configuration differs from the device\'s'
    finally:
        del plaintext
    if header.get('purpose') != PURPOSE or header.get('host') != ip:
        return 'the backup is not labelled as this device\'s pre-restore backup'
    if any(header.get(name) != identity.get(name) for name in ('serial', 'platform')):
        return 'the recorded identity differs'
    return None
