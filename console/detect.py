"""Read-only identification of a device over an open console session, and whether it can
do SSH (Console-Based SSH Auto-Setup, phase 2).

    with ConsoleSession('COM4') as session:
        session.connect()
        result = detect_device(session)          # a DetectionResult
        result.ssh.status                        # SshCapability.SUPPORTED_DISABLED ...
        result.ssh.evidence                      # why
        print(result.summary())

detect_device only sends the `show` commands in DETECTION_COMMANDS, through
ConsoleSession.send_show (which itself refuses anything that is not a single `show ...`
line). With elevate=True it also sends `enable` (privileged EXEC; this changes no
configuration). It never changes the hostname, an IP address, a username, SSH, RSA keys,
the VTY lines, and never saves the configuration.

A failed command is recorded and detection goes on with the next one. Only when the
console session itself ends (a timeout closes it, the cable is pulled, cancel()) are the
remaining commands skipped; what was already read is kept.

Every value that could not be read is None (or SshCapability.UNKNOWN). Nothing is
guessed. Like ConsoleSession, this blocks on serial I/O: run it in a worker thread.
"""
import re
import uuid
from dataclasses import asdict, dataclass, field
from datetime import datetime
from enum import Enum

from config.connect import mask
from console.link import CANCELLED, NOT_CONNECTED, ConsoleError
from discovery.crawler import platform_type

# ---------------------------------------------------------------- the commands
SHOW_VERSION = 'show version'
SHOW_PRIVILEGE = 'show privilege'
SHOW_HOSTNAME = 'show running-config | include hostname'
SHOW_IP_SSH = 'show ip ssh'
SHOW_RSA = 'show crypto key mypubkey rsa'
SHOW_USERNAMES = 'show running-config | include username'
SHOW_VTY = 'show running-config | section line vty'
SHOW_LINE = 'show line'
SHOW_INTERFACES = 'show ip interface brief'
SHOW_DOMAIN = 'show running-config | include ip domain'
SHOW_SSH_CONFIG = 'show running-config | include ip ssh'
SHOW_AAA = 'show running-config | include aaa'
DETECTION_COMMANDS = (SHOW_VERSION, SHOW_PRIVILEGE, SHOW_HOSTNAME, SHOW_IP_SSH, SHOW_RSA,
                      SHOW_USERNAMES, SHOW_VTY, SHOW_LINE, SHOW_INTERFACES,
                      SHOW_DOMAIN, SHOW_SSH_CONFIG, SHOW_AAA)
CONFIG_COMMANDS = (SHOW_HOSTNAME, SHOW_USERNAMES, SHOW_VTY, SHOW_DOMAIN, SHOW_SSH_CONFIG,
                   SHOW_AAA)                                     # output is masked

ROUTER, SWITCH, UNKNOWN_TYPE = 'router', 'switch', 'unknown'
SIMULATION_WARNING = ('SIMULATION: this output came from the NetCommand mock lab, not from a '
                      'physical device.')


class SshCapability(str, Enum):
    SUPPORTED_ENABLED = 'supported_enabled'
    SUPPORTED_DISABLED = 'supported_disabled'
    UNSUPPORTED = 'unsupported'
    UNKNOWN = 'unknown'


# command statuses
OK, REJECTED, DENIED, FAILED, SKIPPED = 'ok', 'rejected', 'denied', 'failed', 'skipped'
# The answer did not look like an answer to the command (a boot-loader or login prompt, or
# lines a configuration search cannot produce). Its content is never used: whatever it was
# meant to show stays unknown.
UNEXPECTED = 'unexpected'

# Prompts that mean the device is no longer at the IOS command line: detection stops.
BOOT_LOADER = re.compile(r'(^|\n)\s*(rommon\s*\d*\s*>|switch:|loader>)', re.IGNORECASE)
LOGGED_OUT = re.compile(r'Press RETURN to get started|^\s*(Username|Password)\s*:\s*$',
                        re.IGNORECASE | re.MULTILINE)
# Asynchronous system log lines ("*Nov 21 10:15:42.123: %LINK-3-UPDOWN: ...") that the
# console prints between other output; they are not part of any command's answer.
LOG_LINE = re.compile(r'^\s*(?:\*?[A-Z][a-z]{2}\s+\d+\s+[\d:.]+(?:\s+[A-Z]{2,5})?:\s+)?'
                      r'%[A-Z0-9_]+-\d-[A-Z0-9_]+:.*$')

_REJECTED = re.compile(r'^\s*%\s*(Invalid (input|command)|Incomplete command|Ambiguous command|'
                       r'Unknown command|Unrecognized command)|^\s*Syntax error',
                       re.IGNORECASE | re.MULTILINE)
_DENIED = re.compile(r'Command authorization failed|%\s*Authorization failed|not authorized|'
                     r'Permission denied|%\s*Access denied', re.IGNORECASE)
_IP = r'\d{1,3}(?:\.\d{1,3}){3}'


# ---------------------------------------------------------------- the result
@dataclass
class CommandResult:
    command: str
    status: str                   # ok / rejected (not recognised) / denied / failed / skipped
    output: str = None            # what the device printed (configuration lines masked)
    error: str = None             # why it did not work

    @property
    def ok(self):
        return self.status == OK


@dataclass
class DeviceInfo:
    hostname: str = None
    hostname_source: str = None   # running-config / show version / prompt
    device_type: str = UNKNOWN_TYPE          # router / switch / unknown
    manufacturer: str = None
    model: str = None
    software: str = None          # IOS / IOS-XE / NX-OS / IOS-XR / ASA, None = not recognised
    version: str = None
    image: str = None             # the image file name (c1900-universalk9-mz.SPA.154-3.M2.bin)
    image_path: str = None        # as reported (flash0:c1900-...)
    feature_set: str = None       # C1900-UNIVERSALK9-M
    platform: str = None          # C1900, C2960, ISR ...
    crypto_image: bool = None     # K9 in the feature set / image name; None = not known


@dataclass
class AccessInfo:
    prompt: str = None
    privilege_level: int = None
    privileged_exec: bool = None  # '#' prompt; None = not tried (user mode, elevate=False)
    elevation_tried: bool = False
    config_readable: bool = None  # show running-config worked


@dataclass
class RsaKeyInfo:
    present: bool = None          # None = could not be read
    key_names: list = field(default_factory=list)
    modulus_bits: int = None      # only when the output states it
    usage: str = None


@dataclass
class SshInfo:
    status: SshCapability = SshCapability.UNKNOWN
    enabled: bool = None          # from show ip ssh
    version: str = None           # "2.0", "1.99"
    rsa: RsaKeyInfo = field(default_factory=RsaKeyInfo)
    config_present: bool = None   # any SSH-related setup seen (keys, vty ssh, local users)
    local_usernames: list = field(default_factory=list)   # names only, never secrets
    evidence: list = field(default_factory=list)


@dataclass
class VtyBlock:
    lines: str                    # "0 4"
    login: str = None             # local / authentication <list> / line password / none
    has_password: bool = False    # a 'password' line exists (its value is never kept)
    transport_input: list = None  # ['ssh'], ['telnet', 'ssh'], None = not shown


@dataclass
class VtyInfo:
    configured: bool = None
    blocks: list = field(default_factory=list)
    ranges: list = field(default_factory=list)            # ["0 4", "5 15"]
    available_lines: int = None   # VTY rows in show line
    ssh_transport: bool = None
    login_configured: bool = None


@dataclass
class LocalUser:
    name: str
    privilege: int = None         # None: no "privilege" word in the line (IOS default is 1)


@dataclass
class ConfigInfo:
    """Facts from the running configuration that a later SSH setup depends on. A value is
    only 'known' when its search ran at privilege level 15: there an empty answer means
    "not configured"; at lower levels IOS may hide lines, so it means "unknown"."""
    domain_name: str = None
    domain_known: bool = False
    ssh_lines: list = field(default_factory=list)          # 'ip ssh ...' lines
    ssh_lines_known: bool = False
    ssh_version_configured: str = None                     # '2' from 'ip ssh version 2'
    ssh_keypair_name: str = None                           # 'ip ssh rsa keypair-name X'
    ssh_other_lines: list = field(default_factory=list)    # 'ip ssh' lines not examined
    ssh_secsh_key: str = None      # key named by show ip ssh ("IOS Keys in SECSH format"):
                                   # a key name, 'NONE', or None when not shown
    ssh_timeout: int = None                                # seconds (show ip ssh)
    ssh_retries: int = None
    aaa_new_model: bool = None
    aaa_login_lists: dict = field(default_factory=dict)    # list name -> methods
    aaa_known: bool = False
    local_users: list = field(default_factory=list)        # LocalUser (never a secret)
    local_users_known: bool = False


@dataclass
class InterfaceInfo:
    name: str
    ip: str = None                # None = unassigned
    method: str = None
    status: str = None            # up / down / administratively down
    protocol: str = None

    @property
    def up(self):
        return self.status == 'up' and self.protocol == 'up'


@dataclass
class DetectionResult:
    device: DeviceInfo = field(default_factory=DeviceInfo)
    access: AccessInfo = field(default_factory=AccessInfo)
    ssh: SshInfo = field(default_factory=SshInfo)
    vty: VtyInfo = field(default_factory=VtyInfo)
    config: ConfigInfo = field(default_factory=ConfigInfo)
    interfaces: list = field(default_factory=list)
    management_interface: str = None
    management_reason: str = None
    commands: list = field(default_factory=list)
    warnings: list = field(default_factory=list)
    limitations: list = field(default_factory=list)
    simulated: bool = False
    complete: bool = True         # False: the session ended and some commands were skipped
    detected_at: object = None    # datetime when detection finished
    # a unique identifier of this detection (phase 5.1.6): two detections within one clock
    # tick (Windows: often ~1-16 ms) have equal timestamps but never the same id
    detection_id: str = None

    @property
    def succeeded(self):
        return [c.command for c in self.commands if c.ok]

    @property
    def failed(self):
        return [c for c in self.commands if not c.ok]

    def command(self, text):
        return next((c for c in self.commands if c.command == text), None)

    def to_dict(self):
        return asdict(self)

    def summary(self):
        d, a, s, v = self.device, self.access, self.ssh, self.vty
        unknown = 'unknown'
        lines = [
            f'{"SIMULATED " if self.simulated else ""}device: {d.hostname or unknown} '
            f'({d.device_type})',
            f'Model: {d.model or unknown}   Software: {d.software or unknown} '
            f'{d.version or ""}'.rstrip(),
            f'Image: {d.image or unknown}',
            f'Privilege level: {a.privilege_level if a.privilege_level is not None else unknown}',
            f'SSH: {s.status.value}' + (f' (version {s.version})' if s.version else ''),
            f'RSA keys: {_yes_no(s.rsa.present)}   VTY SSH transport: {_yes_no(v.ssh_transport)}',
            f'Management interface: {self.management_interface or "none found"}',
        ]
        lines += [f'  evidence: {e}' for e in s.evidence]
        lines += [f'  warning: {w}' for w in self.warnings]
        return '\n'.join(lines)


def _yes_no(value):
    return 'unknown' if value is None else ('yes' if value else 'no')


# ---------------------------------------------------------------- parsing (pure functions)
def is_simulated(version_text):
    return bool(re.search(r'NetCommand Mock Lab', version_text or ''))


def software_family(text, simulated=False):
    text = text or ''
    if re.search(r'IOS[ -]XE', text, re.IGNORECASE):
        return 'IOS-XE'
    if re.search(r'IOS[ -]XR', text, re.IGNORECASE):
        return 'IOS-XR'
    if re.search(r'NX-OS|Nexus Operating System', text, re.IGNORECASE):
        return 'NX-OS'
    if re.search(r'Adaptive Security Appliance', text, re.IGNORECASE):
        return 'ASA'
    if re.search(r'^\s*Cisco IOS Software|^\s*IOS \(tm\)|Cisco Internetwork Operating System',
                 text, re.MULTILINE):
        return 'IOS'
    if simulated and re.search(r'^Simulated IOS Software', text, re.MULTILINE):
        return 'IOS'
    return None


def parse_version(text):
    """DeviceInfo fields from `show version` (only what the text states)."""
    text = text or ''
    simulated = is_simulated(text)
    info = DeviceInfo()
    info.software = software_family(text, simulated)
    if info.software and not simulated:
        info.manufacturer = 'Cisco'
    m = re.search(r'NXOS:\s+version\s+(\S+)|system:\s+version\s+(\S+)', text, re.IGNORECASE) \
        or re.search(r'\bVersion\s+(\d[\w.()\-:]*)', text)
    if m:
        info.version = next(g for g in m.groups() if g).rstrip(',')
    m = re.search(r'System image file is "([^"]+)"', text) or \
        re.search(r'(?:NXOS|system) image file is:\s+(\S+)', text, re.IGNORECASE)
    if m:
        info.image_path = m.group(1)
        info.image = re.split(r'[:/]', info.image_path)[-1] or None
    m = re.search(r'(?:^|,)\s*([^,\n]+?)\s+Software\s+\(([^)]+)\)', text, re.MULTILINE)
    if m:
        info.platform = re.sub(r'^(Cisco IOS Software(\s*\[[^\]]*\])?|Simulated IOS Software)$'
                               r'|^IOS \(tm\)\s*', '', m.group(1).strip()) or None
        info.feature_set = m.group(2).strip()
    m = re.search(r'^\s*Model [Nn]umber\s*:\s*(\S+)', text, re.MULTILINE) or \
        re.search(r'^\s*(?:[Cc]isco|Simulated)\s+(\S+)\s+\([^)]*\)\s+(?:processor|with)',
                  text, re.MULTILINE) or \
        re.search(r'^\s*cisco\s+(.+?)\s+[Cc]hassis', text, re.MULTILINE)
    if m:
        info.model = m.group(1).strip()
    # K9 marks a crypto image. Its absence only means something on classic IOS: IOS-XE
    # names (CAT9K_IOSXE, packages.conf) and other systems do not follow that convention.
    if 'K9' in (info.feature_set or '').upper() or 'k9' in (info.image or '').lower():
        info.crypto_image = True
    elif info.software == 'IOS' and info.feature_set:
        info.crypto_image = False
    if simulated:
        m = re.search(r'NetCommand Mock Lab - simulated (router|switch)', text)
        info.device_type = m.group(1) if m else UNKNOWN_TYPE
    else:
        info.device_type = platform_type(text) or UNKNOWN_TYPE
    if info.device_type == UNKNOWN_TYPE and info.model:
        info.device_type = platform_type(info.model) or UNKNOWN_TYPE
    m = re.search(r'^(\S+)\s+uptime is', text, re.MULTILINE)
    if m:
        info.hostname, info.hostname_source = m.group(1), 'show version'
    return info


def parse_privilege(text):
    m = re.search(r'Current privilege level is\s+(\d+)', text or '')
    return int(m.group(1)) if m else None


def parse_hostname(text):
    m = re.search(r'^hostname\s+(\S+)', text or '', re.MULTILINE)
    return m.group(1) if m else None


def parse_ip_ssh(text):
    """(enabled True/False/None, version, keys_missing)."""
    text = text or ''
    m = re.search(r'SSH\s+(Enabled|Disabled)\s*-\s*version\s+(\d+(?:\.\d+)?)', text,
                  re.IGNORECASE)
    keys_missing = bool(re.search(r'create RSA keys', text, re.IGNORECASE) or
                        re.search(r'Keys in SECSH format[^:]*:\s*NONE', text, re.IGNORECASE))
    if not m:
        return None, None, keys_missing
    return m.group(1).lower() == 'enabled', m.group(2), keys_missing


def parse_rsa(text):
    """RsaKeyInfo from `show crypto key mypubkey rsa`; None when the output is not
    recognised. Empty output (the command worked) means no key pair."""
    text = text or ''
    if not text.strip():
        return RsaKeyInfo(present=False)
    names = re.findall(r'Key name:\s*(\S+)', text)
    if not names:
        return None
    info = RsaKeyInfo(present=True, key_names=names)
    m = re.search(r'(\d{3,4})[- ]bits?\b', text) or \
        re.search(r'[Mm]odulus(?: size)?\s*(?:\(bits\))?\s*:\s*(\d+)', text)
    if m:
        info.modulus_bits = int(m.group(1))
    m = re.search(r'Usage:\s*(.+)', text)
    if m:
        info.usage = m.group(1).strip()
    return info


def parse_usernames(text):
    """Local account names (and nothing else: the secret is never kept)."""
    return re.findall(r'^username\s+(\S+)', text or '', re.MULTILINE)


def parse_local_users(text):
    """LocalUser(name, privilege) per `username` line; the secret is never kept."""
    users = []
    for m in re.finditer(r'^username\s+(\S+)(.*)$', text or '', re.MULTILINE):
        level = re.search(r'\bprivilege\s+(\d+)', m.group(2))
        users.append(LocalUser(m.group(1), int(level.group(1)) if level else None))
    return users


def parse_domain(text):
    m = re.search(r'^ip domain[ -]name\s+(\S+)', text or '', re.MULTILINE)
    return m.group(1) if m else None


def parse_ssh_config(text):
    """('ip ssh ...' lines, configured version or None)."""
    lines = [l.strip() for l in (text or '').splitlines() if l.strip().startswith('ip ssh')]
    version = next((re.match(r'ip ssh version (\d)', l).group(1) for l in lines
                    if re.match(r'ip ssh version (\d)', l)), None)
    return lines, version


EXAMINED_SSH_LINES = re.compile(r'^ip ssh (version \d|time-out \d+|authentication-retries \d+|'
                                r'rsa keypair-name \S+)$')


def parse_ssh_keypair(lines):
    """(keypair name from 'ip ssh rsa keypair-name', the 'ip ssh' lines not examined)."""
    name = next((l.split()[-1] for l in lines if l.startswith('ip ssh rsa keypair-name ')), None)
    return name, [l for l in lines if not EXAMINED_SSH_LINES.match(l)]


def parse_secsh_key(text):
    """The key name show ip ssh prints after "IOS Keys in SECSH format(...):", 'NONE', or
    None when the line is not there."""
    m = re.search(r'IOS Keys in SECSH format\([^)]*\):\s*(\S+)', text or '')
    return m.group(1) if m else None


def parse_aaa(text):
    """(aaa new-model True/False, {login list: methods})."""
    lines = [l.strip() for l in (text or '').splitlines()]
    new_model = 'aaa new-model' in lines
    lists = {}
    for l in lines:
        m = re.match(r'aaa authentication login (\S+)\s+(.+)$', l)
        if m:
            lists[m.group(1)] = m.group(2).strip()
    return new_model, lists


def parse_ssh_timers(text):
    """(authentication timeout seconds, retries) from show ip ssh, or None each."""
    t = re.search(r'Authentication timeout:\s*(\d+)', text or '', re.IGNORECASE)
    r = re.search(r'Authentication retries:\s*(\d+)', text or '', re.IGNORECASE)
    return (int(t.group(1)) if t else None), (int(r.group(1)) if r else None)


def parse_vty(text):
    blocks = []
    current = None
    for raw in (text or '').splitlines():
        line = raw.rstrip()
        m = re.match(r'^line vty\s+(\d+(?:\s+\d+)?)\s*$', line)
        if m:
            current = VtyBlock(lines=' '.join(m.group(1).split()))
            blocks.append(current)
            continue
        if current is None or not line.startswith(' '):
            if not line.startswith(' '):
                current = None
            continue
        words = line.split()
        if words[:2] == ['login', 'local']:
            current.login = 'local'
        elif words[:2] == ['login', 'authentication']:
            current.login = 'authentication ' + (words[2] if len(words) > 2 else 'default')
        elif words == ['login']:
            current.login = 'line password'
        elif words[:2] == ['no', 'login']:
            current.login = 'none'
        elif words[:1] == ['password']:
            current.has_password = True
        elif words[:2] == ['transport', 'input']:
            current.transport_input = [w.lower() for w in words[2:]]
    return blocks


def summarise_vty(blocks, command_ok):
    info = VtyInfo(blocks=blocks, ranges=[b.lines for b in blocks])
    if not command_ok:
        return info
    info.configured = bool(blocks)
    if not blocks:
        info.ssh_transport = None
        info.login_configured = False
        return info
    allowed = [b.transport_input for b in blocks]
    if any(t and ('ssh' in t or 'all' in t) for t in allowed):
        info.ssh_transport = True
    elif all(t is not None for t in allowed):
        info.ssh_transport = False
    logins = []
    for b in blocks:
        if b.login == 'local' or (b.login or '').startswith('authentication'):
            logins.append(True)
        elif b.login == 'line password':
            logins.append(b.has_password)
        elif b.login == 'none':
            logins.append(False)
        else:
            logins.append(None)
    if any(x is True for x in logins):
        info.login_configured = True
    elif all(x is False for x in logins):
        info.login_configured = False
    return info


def parse_show_line(text):
    """The number of VTY lines in `show line`, or None when there is no table."""
    rows = re.findall(r'^\s*\*?\s*\d+\s+(?:\d+\s+)?(VTY|CTY|AUX|TTY)\b', text or '',
                      re.MULTILINE)
    return rows.count('VTY') if rows else None


def parse_interfaces(text):
    found = []
    for m in re.finditer(r'^(\S+)\s+(\S+)\s+(?:YES|NO)\s+(\S+)\s+(administratively down|up|down|'
                         r'deleted)\s+(up|down)\s*$', text or '', re.MULTILINE):
        name, ip, method, status, protocol = m.groups()
        if name == 'Interface':
            continue
        found.append(InterfaceInfo(name=name, ip=ip if re.fullmatch(_IP, ip) else None,
                                   method=method, status=status, protocol=protocol))
    return found


def management_candidate(interfaces):
    """(name, reason) of the most likely management interface, or (None, reason):
    an interface that has an IP address and is up/up; dedicated management ports first,
    then VLAN interfaces, then other ports, loopbacks last."""
    def rank(i):
        n = i.name.lower()
        if n.startswith(('mgmt', 'management')) or n in ('gigabitethernet0', 'fastethernet0'):
            return 0
        if n.startswith('vlan'):
            return 1
        if n.startswith('loopback'):
            return 3
        return 2
    usable = [i for i in interfaces if i.ip and i.up]
    if not usable:
        down = [i.name for i in interfaces if i.ip]
        if down:
            return None, f'interfaces with an IP address are not up: {", ".join(down)}'
        return None, 'no interface has an IP address'
    best = min(usable, key=rank)
    reason = {0: 'dedicated management port', 1: 'VLAN interface',
              2: 'routed port', 3: 'loopback'}[rank(best)]
    return best.name, f'{best.ip}, up/up ({reason})'


# ---------------------------------------------------------------- running the commands
def strip_log_lines(text):
    """(text without system log lines, how many were removed)."""
    lines = (text or '').split('\n')
    kept = [l for l in lines if not LOG_LINE.match(l)]
    return '\n'.join(kept), len(lines) - len(kept)


def unexpected_answer(command, text):
    """(kind, reason) when `text` cannot be a real answer to `command`, else None.
    kind 'stop': the device left the IOS command line (boot loader, logged out).
    kind 'invalid': a configuration search printed lines it cannot produce."""
    text = text or ''
    if BOOT_LOADER.search(text):
        return 'stop', 'the device answered with a boot-loader prompt (ROMMON / switch: / loader>)'
    if LOGGED_OUT.search(text):
        return 'stop', 'the device answered with a login prompt (the console session was logged out)'
    lines = [l for l in text.splitlines() if l.strip()]
    if '| include ' in command:
        pattern = command.split('| include ', 1)[1].strip()
        if any(pattern not in l for l in lines):
            return 'invalid', f'lines that do not contain "{pattern}"'
    if '| section line vty' in command:
        if any(not (l.startswith('line vty') or l[:1] in (' ', '\t')) for l in lines):
            return 'invalid', 'lines that are not part of a "line vty" section'
    return None


def _rejection(output):
    head = '\n'.join(l for l in (output or '').splitlines()
                     if l.strip() and l.strip() != '^')[:400]
    if _DENIED.search(head):
        return DENIED
    if _REJECTED.search(head):
        return REJECTED
    return None


class _Runner:
    def __init__(self, session, result, timeout, progress):
        self.session, self.result = session, result
        self.timeout, self.progress = timeout, progress
        self.lost = False
        self.logs_noted = False

    def say(self, text):
        try:
            self.progress(text)
        except Exception:
            pass

    def run(self, command):
        if self.lost:
            rec = CommandResult(command, SKIPPED, error='the console session had ended')
            self.result.commands.append(rec)
            return rec
        self.say(f'Reading: {command}')
        try:
            out = self.session.send_show(command, timeout=self.timeout) \
                if self.timeout else self.session.send_show(command)
        except ConsoleError as err:
            rec = CommandResult(command, FAILED, error=str(err))
            self.result.commands.append(rec)
            if err.kind in (NOT_CONNECTED, CANCELLED) or not self._active():
                self.lost = True
                self.result.complete = False
                self.result.warnings.append(
                    f'The console session ended during "{command}" ({err}). The results '
                    f'below are partial; the remaining commands were not run.')
            return rec
        out = str(out or '')
        if command in CONFIG_COMMANDS:
            out = mask(out)
        out, logs = strip_log_lines(out)
        if logs and not self.logs_noted:
            self.logs_noted = True
            self.result.warnings.append('System log messages appeared in the console output; '
                                        'they were ignored.')
        kind = _rejection(out)
        odd = None if kind else unexpected_answer(command, out)
        if kind:
            why = ('blocked by command authorization' if kind == DENIED
                   else 'not recognised at this privilege level / on this software')
            rec = CommandResult(command, kind, output=out, error=why)
        elif odd:
            rec = CommandResult(command, UNEXPECTED, output=out,
                                error=f'unexpected answer: {odd[1]}')
            if odd[0] == 'stop':
                # not at the IOS command line any more: nothing further can be trusted
                self.lost = True
                self.result.complete = False
                self.result.warnings.append(
                    f'Detection stopped at "{command}": {odd[1]}. The device is not at its '
                    f'normal command line, so the remaining commands were not run and the '
                    f'information they read is unknown. Check the device on the console.')
            else:
                self.result.warnings.append(
                    f'The answer to "{command}" contained {odd[1]}; it was not used, and what '
                    f'it reads is reported as unknown.')
        else:
            rec = CommandResult(command, OK, output=out)
        self.result.commands.append(rec)
        return rec

    def _active(self):
        try:
            return bool(self.session.is_active())
        except Exception:
            return False


# ---------------------------------------------------------------- detection
def detect_device(session, elevate=False, command_timeout=None, progress=None):
    """A DetectionResult for the device on an open ConsoleSession. Read-only.

    elevate: from user mode ('>'), try `enable` with the session's enable password first
    (privileged EXEC is not a configuration change). Default False: detection runs at
    whatever level the session already has.
    Raises ConsoleError(NOT_CONNECTED) when the session is not active."""
    try:
        active = session.is_active()
    except Exception:
        active = False
    if not active:
        raise ConsoleError(NOT_CONNECTED, 'Not connected. Connect to the console first.')
    result = DetectionResult()
    runner = _Runner(session, result, command_timeout, progress or (lambda text: None))

    # 1. where we are
    try:
        result.access.prompt = session.find_prompt()
    except ConsoleError as err:
        result.warnings.append(f'The prompt could not be read ({err}).')
    if result.access.prompt and result.access.prompt.endswith('>') and elevate:
        result.access.elevation_tried = True
        try:
            result.access.prompt = session.enable()
        except ConsoleError as err:
            result.warnings.append(f'Privileged EXEC (enable) was not available: {err}')
    if result.access.prompt:
        if result.access.prompt.endswith('#'):
            result.access.privileged_exec = True
        elif result.access.elevation_tried:
            result.access.privileged_exec = False

    # 2. identity
    version = runner.run(SHOW_VERSION)
    if version.ok:
        result.device = parse_version(version.output)
        result.simulated = is_simulated(version.output)
    if result.simulated:
        result.warnings.insert(0, SIMULATION_WARNING)

    privilege = runner.run(SHOW_PRIVILEGE)
    if privilege.ok:
        result.access.privilege_level = parse_privilege(privilege.output)

    hostname = runner.run(SHOW_HOSTNAME)
    result.access.config_readable = True if hostname.ok else (
        False if hostname.status in (REJECTED, DENIED) else None)
    name = parse_hostname(hostname.output) if hostname.ok else None
    if name:
        result.device.hostname, result.device.hostname_source = name, 'running-config'
    elif not result.device.hostname and result.access.prompt:
        result.device.hostname = result.access.prompt.rstrip('#>').strip() or None
        result.device.hostname_source = 'prompt' if result.device.hostname else None

    # 3. SSH
    ip_ssh = runner.run(SHOW_IP_SSH)
    if ip_ssh.ok:
        result.ssh.enabled, result.ssh.version, keys_missing = parse_ip_ssh(ip_ssh.output)
        if result.ssh.enabled is None and not keys_missing:
            result.warnings.append('The output of "show ip ssh" was not recognised.')
    else:
        keys_missing = False
    rsa = runner.run(SHOW_RSA)
    if rsa.ok:
        parsed = parse_rsa(rsa.output)
        if parsed is None:
            result.warnings.append('The output of "show crypto key mypubkey rsa" was not '
                                   'recognised; RSA key status unknown.')
        else:
            result.ssh.rsa = parsed
            if parsed.present and all(n.startswith('TP-self-signed') for n in parsed.key_names):
                result.warnings.append('The only RSA key is a TP-self-signed key (used for '
                                       'HTTPS); it may not be the key SSH uses.')
    users = runner.run(SHOW_USERNAMES)
    if users.ok:
        result.ssh.local_usernames = parse_usernames(users.output)

    # 4. VTY lines
    vty = runner.run(SHOW_VTY)
    result.vty = summarise_vty(parse_vty(vty.output) if vty.ok else [], vty.ok)
    line = runner.run(SHOW_LINE)
    if line.ok:
        result.vty.available_lines = parse_show_line(line.output)

    # 5. interfaces
    brief = runner.run(SHOW_INTERFACES)
    if brief.ok:
        result.interfaces = parse_interfaces(brief.output)
        if not result.interfaces and brief.output.strip():
            result.warnings.append('The output of "show ip interface brief" was not recognised.')
        result.management_interface, result.management_reason = \
            management_candidate(result.interfaces)

    # 6. configuration a later SSH setup depends on (searches of the running-config)
    _read_config(result, runner, users, ip_ssh)

    # 7. SSH classification
    result.ssh.status, result.ssh.evidence, extra = classify_ssh(result, ip_ssh, rsa,
                                                                 keys_missing)
    result.warnings += extra
    result.ssh.config_present = _ssh_config_present(result, users.ok)
    result.limitations += _limitations(result)
    result.detected_at = datetime.now()
    result.detection_id = uuid.uuid4().hex
    return result


def _read_config(result, runner, users, ip_ssh):
    cfg = result.config
    full = result.access.privilege_level == 15          # an empty search means "none"
    if ip_ssh.ok:
        cfg.ssh_timeout, cfg.ssh_retries = parse_ssh_timers(ip_ssh.output)
        cfg.ssh_secsh_key = parse_secsh_key(ip_ssh.output)
    if users.ok:
        cfg.local_users = parse_local_users(users.output)
        cfg.local_users_known = full
    domain = runner.run(SHOW_DOMAIN)
    if domain.ok:
        cfg.domain_name = parse_domain(domain.output)
        cfg.domain_known = full or cfg.domain_name is not None
    ssh_cfg = runner.run(SHOW_SSH_CONFIG)
    if ssh_cfg.ok:
        cfg.ssh_lines, cfg.ssh_version_configured = parse_ssh_config(ssh_cfg.output)
        cfg.ssh_keypair_name, cfg.ssh_other_lines = parse_ssh_keypair(cfg.ssh_lines)
        cfg.ssh_lines_known = full
    aaa = runner.run(SHOW_AAA)
    if aaa.ok:
        new_model, lists = parse_aaa(aaa.output)
        cfg.aaa_login_lists = lists
        cfg.aaa_known = full or new_model
        cfg.aaa_new_model = new_model if cfg.aaa_known else None
    if not full and any(c.ok for c in (users, domain, ssh_cfg, aaa)):
        result.limitations.append('The running configuration was read below privilege level '
                                  '15, where lines can be hidden: settings that were not found '
                                  'are reported as unknown, not as missing.')


def _ssh_config_present(result, users_ok):
    signs = [result.ssh.enabled, result.ssh.rsa.present, result.vty.ssh_transport,
             bool(result.ssh.local_usernames) if users_ok else None]
    if any(s is True for s in signs):
        return True
    if all(s is False for s in signs):
        return False
    return None


def _reason(rec):
    if rec is None:
        return 'not run'
    if rec.status == SKIPPED:
        return 'skipped (the console session had ended)'
    if rec.status == FAILED:
        return f'failed ({rec.error})'
    return rec.error or rec.status


def classify_ssh(result, ip_ssh, rsa, keys_missing):
    """(SshCapability, evidence, warnings). UNKNOWN whenever the evidence is not clear."""
    S = SshCapability
    d, a, ssh = result.device, result.access, result.ssh
    evidence, warnings = [], []
    if d.crypto_image:
        evidence.append(f'The software image includes crypto (K9): '
                        f'{d.feature_set or d.image}.')
    elif d.crypto_image is False:
        evidence.append(f'The software image name has no crypto (K9) marker: '
                        f'{d.feature_set or d.image}.')

    if ssh.enabled is True:
        evidence.insert(0, f'show ip ssh reports "SSH Enabled - version {ssh.version}".')
        if ssh.rsa.present is False:
            msg = ('Contradictory: show ip ssh reports SSH enabled, but show crypto key '
                   'mypubkey rsa lists no RSA key pair.')
            warnings.append(msg)
            return S.UNKNOWN, evidence + [msg], warnings
        if ssh.rsa.present:
            evidence.append(f'RSA key pair present: {", ".join(ssh.rsa.key_names)}.')
        return S.SUPPORTED_ENABLED, evidence, warnings

    if ssh.enabled is False or (ip_ssh.ok and keys_missing):
        text = (f'show ip ssh reports "SSH Disabled - version {ssh.version}"'
                if ssh.enabled is False else 'show ip ssh reports that SSH is not running')
        evidence.insert(0, text + '; the command exists, so this software supports SSH.')
        if keys_missing:
            evidence.append('The device says RSA keys must be created to enable SSH.')
        if ssh.rsa.present is False:
            evidence.append('show crypto key mypubkey rsa lists no RSA key pair.')
        return S.SUPPORTED_DISABLED, evidence, warnings

    if ip_ssh.ok:
        evidence.insert(0, 'show ip ssh ran, but its output was not recognised.')
        return S.UNKNOWN, evidence, warnings

    # show ip ssh did not work: on its own that proves nothing
    evidence.insert(0, f'show ip ssh: {_reason(ip_ssh)}. On its own this does not show that '
                       f'SSH is unsupported.')
    if rsa is not None and not rsa.ok:
        evidence.append(f'show crypto key mypubkey rsa: {_reason(rsa)}.')
    if (d.software == 'IOS' and a.privilege_level == 15 and ip_ssh.status == REJECTED
            and rsa is not None and rsa.status == REJECTED and d.crypto_image is False):
        evidence.append('Classic IOS at privilege level 15 does not recognise either SSH '
                        'command, and the image has no crypto feature set: this image cannot '
                        'run SSH (a K9 image would be needed).')
        return S.UNSUPPORTED, evidence, warnings
    if ssh.rsa.present is False and (d.crypto_image or d.software == 'IOS-XE'):
        evidence.append('No RSA key pair exists, and SSH cannot run without one; the software '
                        'is SSH-capable.')
        return S.SUPPORTED_DISABLED, evidence, warnings
    if ssh.rsa.present:
        evidence.append(f'RSA key pair present ({", ".join(ssh.rsa.key_names)}), but the SSH '
                        f'state itself could not be read.')
    if a.privilege_level is not None and a.privilege_level < 15:
        evidence.append(f'Privilege level {a.privilege_level}: some commands need level 15.')
    elif a.privilege_level is None and a.privileged_exec is not True:
        evidence.append('The privilege level is unknown.')
    if DENIED in (ip_ssh.status, getattr(rsa, 'status', None)):
        evidence.append('Command authorization (AAA) blocks the SSH commands.')
    if d.software is None:
        evidence.append('The operating system was not recognised.')
    elif d.software not in ('IOS', 'IOS-XE'):
        evidence.append(f'{d.software} uses different commands for SSH; the IOS commands '
                        f'used here do not apply.')
    return S.UNKNOWN, evidence, warnings


def _limitations(result):
    out = []
    if result.ssh.status == SshCapability.UNSUPPORTED:
        out.append('UNSUPPORTED is based on the image name and the missing commands; it has '
                   'not been confirmed against Cisco feature documentation for this release.')
    if result.vty.configured and any(b.transport_input is None for b in result.vty.blocks):
        out.append('Some VTY lines show no "transport input" line; their default differs '
                   'between IOS releases, so SSH transport for them is unknown.')
    if result.vty.configured and any(b.login is None for b in result.vty.blocks):
        out.append('Some VTY lines show no login line; with "aaa new-model" the default '
                   'login list applies, which is not read here.')
    if (result.access.prompt or '').endswith('>') and not result.access.elevation_tried:
        out.append('Detection ran in user EXEC mode without trying "enable"; commands that '
                   'need privileged mode were rejected.')
    if result.device.software not in (None, 'IOS', 'IOS-XE'):
        out.append(f'{result.device.software} is not covered by these IOS commands.')
    return out
