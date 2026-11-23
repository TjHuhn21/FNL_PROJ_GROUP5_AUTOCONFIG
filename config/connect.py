"""Talks to one device over SSH: read its config, or apply commands safely.

apply_config does, in this order:
    backup key -> connect -> privilege 15 -> encrypted backup -> send commands -> check -> save
and reports every step, with the real commands and the device's real replies,
through an optional log(kind, text) callback (the Configure page's SSH console):

    kind      meaning                                     example text
    'info'    progress                                    Connecting to 192.168.1.2 through SSH...
    'section' a stage starts                              BACKUP
    'command' a command, after the device's prompt        SW1(config)# vlan 10
    'output'  what the device answered                    % Invalid input detected at '^' marker.
    'ok' / 'warn' / 'error'   outcome lines

Passwords and secrets are never reported: commands and replies are masked
before they are logged (what is SENT is not changed).

Every failure comes back as (False, 'a clear message'). Nothing crashes the app.

The session must be at privilege level 15 ("show privilege", privilege_problem()) before the
backup is read: below it IOS may show only part of the configuration. Otherwise the Apply
stops there, with no backup and no command sent.
The backup must be USABLE before anything is sent: check_backup() refuses empty output,
an IOS error instead of the configuration, output without a hostname line, and output that
does not end with the line "end" (Cisco IOS always ends a running configuration with it,
so a missing "end" means the text was cut off).

Backups are ENCRYPTED (.ncbak, AES-256-GCM with the active key of the user's backup
keyring; see backup_crypto.py, backup_keys.py, docs/BACKUP_ENCRYPTION.md). Before any SSH
connection, apply_config loads that key (load_backup_key); without it nothing is opened
or sent. The configuration is encrypted in memory and only ciphertext is written: to a
temporary file in the backup folder, flushed to disk, read back, decrypted and compared
byte for byte with what the device sent, and only then renamed to its final name, never
replacing an existing backup (a same-second backup gets _2, _3, ...). There is no
plaintext fallback: if any of this fails, no configuration command is sent to that device.
Read a backup with:  python backup_tool.py export <file>.ncbak --to <new file>

Every connection uses ssh_options.connect_options(host): strict SSH algorithms, with the
old SHA-1 ones allowed only for the addresses in NETCOMMAND_LEGACY_SSH_HOSTS.
"""
import hmac
import os
import re
import tempfile
from collections import namedtuple
from datetime import datetime

from netmiko import ConnectHandler
from netmiko.exceptions import NetmikoAuthenticationException, NetmikoTimeoutException

import ssh_options

LOGIN_TIMEOUTS = {'conn_timeout': 8, 'auth_timeout': 10, 'banner_timeout': 10}
# <project>\backups, whatever folder NetCommand is started from. It used to be the relative
# path 'backups' (so the same folder when started from the project folder, as usual).
# Nothing was moved; the backup catalogue (backup_catalogue.py) also looks in the start
# folder's "backups", where older versions wrote when started elsewhere.
BACKUP_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                          'backups')
# What a Cisco device prints when it rejects a command (it does not raise an error)
REJECTED = ('% Invalid', '% Incomplete', '% Ambiguous', '% Unknown command',
            '% Unrecognized', '% Bad ', '% Error', '% Cannot', '% Command rejected')
SAVE_COMMAND = 'write mem'          # what Netmiko's save_config() sends to Cisco IOS
BACKUP_PREVIEW_LINES = 25           # the console shows the start; the file has everything
OUTPUT_PREVIEW_LINES = 40
_PROMPT = re.compile(r'^\S+(\([^)]*\))?[#>]\s*$')
# A password or secret can contain spaces on Cisco IOS ("password 0 two words"), so
# everything after the keyword (and its optional type number) up to the end of the line
# is hidden. Other keywords hide only the next word.
# Every rule stays on ONE line ([ \t], never \s): otherwise "key 1" at the end of one line
# would take the first word of the NEXT line as its value and leave the real secret shown.
# The same rules are in backend/database/app_records.py (a test keeps them identical).
MASKED = '********'
_SECRET_TO_EOL = re.compile(r'(\b(?:password|secret)[ \t]+(?:\d{1,2}[ \t]+)?)\S[^\r\n]*',
                            re.IGNORECASE)
# One pass, leftmost match first, so each value is masked exactly once and the keywords
# around it (local, address, md5, aes 128, ...) stay readable.
_SECRET_WORD_RULES = (
    r'\bauth[ \t]+(?:md5|sha\d*)[ \t]+',                        # SNMPv3 user: auth key
    r'\bpriv[ \t]+(?:3des|des\d*|aes(?:[ \t]+\d+)?)[ \t]+',     # SNMPv3 user: privacy key
    r'\b(?:message-digest-key|authentication-key)[ \t]+\d+[ \t]+md5[ \t]+(?:\d[ \t]+)?',
    r'\b(?:standby|vrrp|glbp)[ \t]+(?:\d+[ \t]+)?authentication[ \t]+(?:text[ \t]+)?'
    r'(?!md5\b)',                                               # md5: key-string below
    r'\bwpa-psk[ \t]+(?:ascii|hex)[ \t]+(?:\d[ \t]+)?',
    r'\bpre-shared-key[ \t]+(?:local|remote)[ \t]+(?:\d[ \t]+)?',
    r'\bpre-shared-key[ \t]+(?:address|hostname)[ \t]+(?:\S+[ \t]+){1,2}?key[ \t]+'
    r'(?:\d[ \t]+)?',
    # SNMP v1/v2c notification host: the community after the address (v3 has a user name
    # there, not a secret, so "version 3" lines are left alone).
    r'\bsnmp-server[ \t]+host[ \t]+\S+[ \t]+(?:(?:informs|traps)[ \t]+)?'
    r'(?:version[ \t]+(?:1|2c)[ \t]+)?(?!version\b)',
    r'\bkey[ \t]+config-key[ \t]+(?:password-encrypt|\d+)[ \t]+',  # type 6 master key
    # The original rule; never the word config-key itself (nor the "key" inside it).
    r'(?<!config-)\b(?:key-string|community|key)[ \t]+(?:\d[ \t]+)?(?!config-key\b)',
)
_SECRET = re.compile('(' + '|'.join(f'(?:{r})' for r in _SECRET_WORD_RULES) + r')(\S+)',
                     re.IGNORECASE)


def mask(text):
    """Hide values that follow password / secret (to the end of the line); key /
    key-string / community; SNMPv3 auth and priv keys; OSPF/NTP md5 keys; HSRP/VRRP/GLBP
    authentication; wpa-psk; and IKEv2 pre-shared-key local/remote/address/hostname (the
    next word)."""
    text = _SECRET_TO_EOL.sub(lambda m: m.group(1) + MASKED, text or '')
    return _SECRET.sub(lambda m: m.group(1) + MASKED, text)


class _Report:
    """Sends lines to log(kind, text), masked and never raising."""
    def __init__(self, log):
        self.log = log

    def __call__(self, kind, text):
        if self.log:
            try:
                self.log(kind, mask(text))
            except Exception:
                pass                     # the console must never break an SSH session

    def output(self, text, limit=OUTPUT_PREVIEW_LINES, note=''):
        lines = (text or '').rstrip().splitlines()
        if not lines:
            return
        shown = lines[:limit]
        self('output', '\n'.join(shown))
        if len(lines) > limit:
            self('info', f'... {len(lines) - limit} more lines{note}')


def _open(creds):
    conn = ConnectHandler(device_type='cisco_ios', host=creds['host'],
                          username=creds['username'], password=creds['password'],
                          secret=creds.get('secret') or creds['password'], **LOGIN_TIMEOUTS,
                          **ssh_options.connect_options(creds['host']))
    if conn.find_prompt().endswith('>'):
        try:
            conn.enable()
            conn.netcommand_enabled = True      # so the console can show the step
        except Exception:
            pass
    return conn


def get_config(creds):
    """The running-config text of a device. creds = {'host','username','password'}."""
    conn = _open(creds)
    try:
        return conn.send_command('show running-config')
    finally:
        conn.disconnect()


# ---------------------------------------------------------------- privilege
SHOW_PRIVILEGE = 'show privilege'
REQUIRED_PRIVILEGE = 15
# Cisco IOS answers "Current privilege level is N" (as console/detect.parse_privilege reads
# it). Here the answer must be exactly that one line: anything else is "not recognised".
_PRIVILEGE_LINE = re.compile(r'Current privilege level is[ \t]+(\d{1,2})')


def privilege_problem(output):
    """None when `show privilege` reports level 15, otherwise why the Apply must stop.
    Below 15, IOS may show only part of the running configuration (still with its
    hostname and end lines), so the backup could look complete without being complete."""
    body = [l.strip() for l in (output or '').splitlines() if l.strip()]
    m = _PRIVILEGE_LINE.fullmatch(body[0]) if len(body) == 1 else None
    if m is None:
        return 'the answer to "show privilege" was not recognised'
    level = int(m.group(1))
    if level != REQUIRED_PRIVILEGE:
        return f'the session is at privilege level {level}'
    return None


# ---------------------------------------------------------------- device identity
# Recorded in every new encrypted backup (Phase 4A) so a future restore can tell whether
# a backup belongs to the device. Read with the read-only "show version" and from the
# running configuration that is read anyway. Only what the device shows is recorded;
# anything not found (or not a plain value) is recorded as unavailable (None), never guessed.
SHOW_VERSION = 'show version'
_SERIAL = re.compile(r'^Processor board ID[ \t]+(\S+)[ \t\r]*$', re.MULTILINE)
# "Cisco CISCO1941/K9 (revision 1.0) with 491520K/32768K bytes of memory."
# "cisco WS-C2960-24TT-L (PowerPC405) processor (revision B0) with 65536K bytes of memory."
_PLATFORM = re.compile(r'^[Cc]isco[ \t]+(\S+)[ \t]+\([^)\n]*\)[ \t]+(?:processor[ \t]+)?'
                       r'(?:\(revision[^)\n]*\)[ \t]+)?with[ \t]+\d+K', re.MULTILINE)
_MODEL_NUMBER = re.compile(r'^Model [Nn]umber[ \t]*:[ \t]*(\S+)[ \t\r]*$', re.MULTILINE)
# "Cisco IOS Software, C1900 Software (C1900-UNIVERSALK9-M), Version 15.4(3)M2, RELEASE ..."
# "IOS (tm) C2950 Software (C2950-I6Q4L2-M), Version 12.1(22)EA14, RELEASE SOFTWARE"
_IOS_VERSION = re.compile(r'^[^\n]*\bIOS\b[^\n]*?\bVersion[ \t]+([0-9][^,\s]*)', re.MULTILINE)
_HOSTNAME = re.compile(r'^hostname[ \t]+(\S+)[ \t\r]*$', re.MULTILINE)


def parse_identity(show_version, running_config):
    """{'serial', 'platform', 'ios_version', 'hostname'}: each the value the device shows,
    or None when it is missing, the command failed, or the value is not a plain token."""
    import backup_crypto

    def first(regex, text):
        m = regex.search(text or '') if isinstance(text, str) else None
        value = m.group(1) if m else None
        return value if backup_crypto.valid_identity_value(value) else None
    return {'serial': first(_SERIAL, show_version),
            'platform': first(_PLATFORM, show_version) or first(_MODEL_NUMBER, show_version),
            'ios_version': first(_IOS_VERSION, show_version),
            'hostname': first(_HOSTNAME, running_config)}


def describe_identity(identity):
    return ', '.join(f"{label} {identity.get(name) or 'unavailable'}" for name, label in
                     (('hostname', 'hostname'), ('platform', 'platform'),
                      ('serial', 'serial'), ('ios_version', 'IOS version')))


# ---------------------------------------------------------------- backups
_HOSTNAME_LINE = re.compile(r'^hostname[ \t]+\S', re.MULTILINE)
# An IPv4 address or host name: no path separators, and no ':' (on Windows it would open
# an alternate data stream instead of a normal file).
_SAFE_HOST = re.compile(r'[A-Za-z0-9][A-Za-z0-9.-]{0,252}')
# A backup purpose label (e.g. "pre-restore"): also part of the file name.
_PURPOSE = re.compile(r'[a-z][a-z0-9-]{0,31}')
MAX_SAME_SECOND_BACKUPS = 1000


class BackupError(Exception):
    """The backup is not usable or could not be written. Its message never contains the
    configuration, a secret or the backup folder."""


def check_backup(text):
    """None if `text` is a usable running configuration, otherwise why it is not.
    Accepted: Cisco IOS `show running-config` output, with or without the "Building
    configuration..." / "Current configuration : N bytes" header, LF or CRLF line ends,
    and blank lines or spaces after the final "end"."""
    lines = [l.rstrip() for l in (text or '').splitlines()]
    body = [l for l in lines if l.strip()]
    if not body:
        return 'the device returned an empty configuration'
    first = body[0].strip()
    if first.startswith('%') or 'authorization failed' in first.lower():
        return (f'the device answered with an error instead of its configuration '
                f'({mask(first)[:80]})')
    if not _HOSTNAME_LINE.search('\n'.join(lines)):
        return 'the output does not look like a running configuration (it has no hostname line)'
    if body[-1].strip() != 'end':
        return 'the configuration looks incomplete (it does not end with the line "end")'
    return None


# ---------------------------------------------------------------- the backup key
BACKUP_SUFFIX = '.ncbak'
BackupKey = namedtuple('BackupKey', 'key_id key key_for')


class BackupKeyUnavailable(BackupError):
    """The backup encryption key cannot be used (no keyring, an invalid or unreadable
    keyring, DPAPI refused, ...). Apply stops before any SSH connection."""


class KeyringKeySource:
    """Where Apply gets the active backup key: the user's DPAPI-protected keyring
    (backup_keys.py; %LOCALAPPDATA%\\NetCommand\\keys\\backup-keyring.json by default)."""

    def __init__(self, keyring_path=None, protector_factory=None):
        self.keyring_path, self.protector_factory = keyring_path, protector_factory

    def active_key(self):
        import backup_keys
        ring = backup_keys.Keyring.load(self.keyring_path or backup_keys.default_keyring_path())
        protector = (self.protector_factory or backup_keys.DpapiProtector)()
        key_id, key = ring.active(protector)
        return BackupKey(key_id, key, ring.key_for(protector))


KEY_SOURCE = KeyringKeySource()       # tests replace it with a synthetic key


def load_backup_key(source=None):
    """The active BackupKey, or BackupKeyUnavailable with a message that never contains
    key material. Any failure counts: there is no plaintext fallback."""
    try:
        backup_key = (source or KEY_SOURCE).active_key()
        if len(backup_key.key) != 32:
            raise ValueError('the key has the wrong length')
        return backup_key
    except Exception as err:
        import backup_crypto
        if isinstance(err, backup_crypto.BackupCryptoError):
            reason = str(err)                         # fixed text, never key material
        elif isinstance(err, OSError):
            reason = f'{err.strerror or type(err).__name__}'
        else:
            reason = type(err).__name__
        # Wording note: console lines are masked, and mask() hides the word after "key"; so
        # these messages say "keyring" / "key_id=" instead.
        raise BackupKeyUnavailable(f'The backup keyring cannot be used: '
                                   f'{reason.rstrip(".")}.') from None


def backup_key_problem(source=None):
    """Preflight: None when the active backup key can be loaded, otherwise why not."""
    try:
        load_backup_key(source)
        return None
    except BackupKeyUnavailable as err:
        return str(err)


def _place(temp, final):
    """Give the finished temporary file its final name; FileExistsError if that name is
    taken (an existing backup is never replaced). On Windows os.rename never replaces an
    existing file and is atomic within one folder; elsewhere a hard link does the same."""
    if os.name == 'nt':
        os.rename(temp, final)
    else:
        os.link(temp, final)
        os.unlink(temp)


SOURCES = ('show running-config', 'show startup-config')


def _save_backup(host, text, backup_dir=None, backup_key=None, identity=None, purpose=None,
                 source='show running-config'):
    """Encrypt the configuration and write it as <host>_<YYYYMMDD_HHMMSS>[_N].ncbak
    (<host>_<purpose>_<YYYYMMDD_HHMMSS>[_N].ncbak when a purpose is given).
    Returns (path, SHA-256 of the configuration, key id).

    The configuration is encrypted IN MEMORY (backup_crypto, AES-256-GCM, the active
    backup key); only ciphertext is ever written. The temporary file is flushed to disk,
    read back, decrypted with the keyring and compared byte for byte with the original
    configuration before it gets its final name (never replacing an existing file).
    Raises BackupError (nothing is left behind) for an unusable configuration, an
    unavailable key, or any encryption, write or verification failure.

    identity: {'serial', 'platform', 'hostname', 'ios_version'} (parse_identity), stored in
    the authenticated header; a value that is not a plain token is stored as unavailable
    (None). Without it (None), no identity fields are recorded.

    purpose: an optional label stored in the authenticated header and the file name (the
    restore preflight uses "pre-restore"). Apply does not pass one.

    source: the command the text came from (one of SOURCES; the startup save of Phase 4H
    backs up "show startup-config"). Recorded in the authenticated header."""
    import backup_crypto
    if not _SAFE_HOST.fullmatch(str(host or '')):     # it becomes part of a file name
        raise BackupError('Backup refused: the device address cannot be used in a file name')
    if purpose is not None and not _PURPOSE.fullmatch(str(purpose)):
        raise BackupError('Backup refused: the backup purpose label is not valid')
    if source not in SOURCES:
        raise BackupError('Backup refused: the backup source is not valid')
    problem = check_backup(text)
    if problem:
        raise BackupError(f'Backup of {host} refused: {problem}')
    try:
        plaintext = text.encode('utf-8')
    except UnicodeError:
        raise BackupError(f'Backup of {host} refused: the configuration contains characters '
                          f'that cannot be stored') from None
    backup_key = backup_key or load_backup_key()        # BackupKeyUnavailable
    metadata = {'host': host, 'source': source, 'privilege': REQUIRED_PRIVILEGE}
    if purpose is not None:
        metadata['purpose'] = purpose
    if identity is not None:
        for name in backup_crypto.IDENTITY_FIELDS:
            value = identity.get(name)
            metadata[name] = value if backup_crypto.valid_identity_value(value) else None
    try:
        data = backup_crypto.encrypt_backup(plaintext, backup_key.key, backup_key.key_id,
                                            metadata)
    except backup_crypto.BackupCryptoError as err:
        raise BackupError(f'Backup of {host} failed: the configuration could not be '
                          f'encrypted ({str(err).rstrip(".")})') from None
    folder = backup_dir or BACKUP_DIR
    temp = None
    try:
        os.makedirs(folder, exist_ok=True)
        fd, temp = tempfile.mkstemp(prefix=f'.{host}_', suffix='.partial', dir=folder)
        with os.fdopen(fd, 'wb') as f:                      # ciphertext only
            f.write(data)
            f.flush()
            os.fsync(f.fileno())
        with open(temp, 'rb') as f:                         # read back: what is on disk
            on_disk = f.read(len(data) + 1)
        if on_disk != data:
            raise BackupError(f'Backup of {host} failed: the encrypted file on disk does not '
                              f'match what was written')
        try:
            recovered, header = backup_crypto.decrypt_backup(on_disk, backup_key.key_for)
        except backup_crypto.BackupCryptoError as err:
            raise BackupError(f'Backup of {host} failed: the encrypted backup could not be '
                              f'verified ({str(err).rstrip(".")})') from None
        if not hmac.compare_digest(recovered, plaintext) or \
                header['key_id'] != backup_key.key_id or \
                any(header.get(name) != value for name, value in metadata.items()):
            raise BackupError(f'Backup of {host} failed: the decrypted backup does not match '
                              f'the configuration the device sent')
        sha = header['plaintext_sha256']
        stamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        base = f'{host}_{purpose}_{stamp}' if purpose else f'{host}_{stamp}'
        for n in range(1, MAX_SAME_SECOND_BACKUPS + 1):
            path = os.path.join(folder, base + (f'_{n}' if n > 1 else '') + BACKUP_SUFFIX)
            try:
                _place(temp, path)
            except FileExistsError:
                continue
            temp = None                                    # it is the backup now
            return path, sha, backup_key.key_id
        raise BackupError(f'Backup of {host} failed: no free file name for this second')
    except OSError as err:
        reason = err.strerror or type(err).__name__        # never the path
        raise BackupError(f'Backup of {host} failed: the file could not be written '
                          f'({reason})') from None
    finally:
        if temp is not None:
            try:
                os.remove(temp)
            except OSError:
                pass


def rejection(output):
    """The device's error line if `output` contains a rejection, else None."""
    for line in (output or '').splitlines():
        if any(line.strip().startswith(bad.strip()) or bad in line for bad in REJECTED):
            return line.strip()
    return None


def split_reply(raw, command):
    """Netmiko's text for one config command is: the echoed command, the device's
    reply, then the next prompt. Returns (reply, next_prompt or None)."""
    lines = (raw or '').splitlines()
    if lines and lines[0].strip().endswith(command.strip()):
        lines = lines[1:]                               # the echo of what we typed
    prompt = None
    while lines and not lines[-1].strip():
        lines.pop()
    if lines and _PROMPT.match(lines[-1].strip()):
        prompt = lines.pop().strip()
    return '\n'.join(lines).strip(), prompt


def apply_config(creds, commands, checks=(), backup_dir=None, log=None):
    """Returns (True or False, message).
    checks is a list of (show command, text that must appear in its output).
    log(kind, text), if given, receives every step (see the module notes)."""
    host = creds['host']
    report = _Report(log)
    commands = [c for c in commands if c and c.strip() and not c.strip().startswith('#')]
    if not commands:
        return False, 'There are no commands to send.'
    # Preflight: without a usable backup encryption key no SSH session is even opened.
    try:
        backup_key = load_backup_key()
    except BackupKeyUnavailable as err:
        report('section', 'BACKUP KEYRING')
        report('error', f'BACKUP KEYRING NOT USABLE: {err}')
        report('error', f'FAILED: no SSH connection was opened to {host}; nothing was sent.')
        return False, (f'{err} No SSH connection was opened to {host} and no configuration '
                       f'command was sent; the device was not changed.')
    report('section', 'CONNECT')
    report('info', f'Connecting to {host} through SSH...')
    try:
        conn = _open(creds)
    except Exception as err:
        return _connect_failed(err, host, report)
    try:
        return _session(conn, host, commands, checks, backup_dir, report, backup_key)
    except NetmikoTimeoutException:
        report('error', 'The device stopped answering during the session.')
        return False, 'No answer (wrong IP, device off, or SSH not enabled).'
    except NetmikoAuthenticationException:
        report('error', 'The device refused the login (wrong username or password).')
        return False, 'Wrong username or password.'
    except Exception as err:
        detail = mask(str(err))
        report('error', f'The session failed: {type(err).__name__}: {detail}')
        return False, f'Error: {type(err).__name__}: {detail}'
    finally:
        try:
            conn.disconnect()
            report('info', 'SSH session closed.')
        except Exception:
            pass


def _connect_failed(err, host, report):
    """(False, message) for a connection that could not be opened. The message comes
    from ssh_options.describe_error: fixed text, never the exception's own text."""
    kind, text = ssh_options.describe_error(err, host)
    if kind == ssh_options.AUTH:
        report('error', 'The device refused the login (wrong username or password).')
        return False, 'Wrong username or password.'
    if kind == ssh_options.TIMEOUT:
        report('error', f'No answer from {host}: {text}.')
        return False, 'No answer (the connection timed out: wrong IP, device off, or not reachable).'
    if kind == ssh_options.REFUSED:
        report('error', f'{host}: {text}.')
        return False, 'Connection refused (SSH is not enabled on the device, or port 22 is blocked).'
    if kind == ssh_options.ALGORITHMS:
        report('error', f'Unsupported SSH algorithms: {text}.')
        return False, f'Unsupported SSH algorithms: {text}.'
    report('error', f'Could not connect: {text}.')
    return False, f'Error: {type(err).__name__} (the SSH connection could not be opened).'


def _session(conn, host, commands, checks, backup_dir, report, backup_key=None):
    prompt = conn.find_prompt().strip()
    report('ok', f'SSH connection established. Device prompt: {prompt}')
    if getattr(conn, 'netcommand_enabled', False):
        report('command', f'{prompt.rstrip("#")}> enable')
        report('info', 'Entered privileged mode (the enable secret is not shown).')

    # ---- 1. backup (only at privilege level 15: below it the copy may be incomplete)
    report('section', 'BACKUP')
    report('command', f'{prompt} {SHOW_PRIVILEGE}')
    try:
        level_output = conn.send_command(SHOW_PRIVILEGE)
        problem = privilege_problem(level_output)
        report.output(level_output)
    except (NetmikoTimeoutException, NetmikoAuthenticationException):
        raise                                 # apply_config's own clear messages ("No answer")
    except Exception as err:                  # the session itself is closed by apply_config
        problem = f'the "show privilege" command failed ({type(err).__name__})'
    if problem:
        report('error', f'PRIVILEGE CHECK FAILED: {problem}; privilege level '
                        f'{REQUIRED_PRIVILEGE} is required for a complete backup.')
        report('section', 'RESULT')
        report('error', 'FAILED: no backup was taken and no configuration command was sent; '
                        'the device was not changed.')
        return False, (f'Privilege check on {host} failed: {problem}. Privilege level '
                       f'{REQUIRED_PRIVILEGE} is required to take a complete backup before '
                       f'configuring. No configuration command was sent; the device was not '
                       f'changed.')
    report('ok', f'Privilege level {REQUIRED_PRIVILEGE} confirmed.')
    # Device identity for the backup (read-only). Supplementary: if it cannot be read, it
    # is recorded as unavailable and the Apply goes on with its usual safety checks.
    report('command', f'{prompt} {SHOW_VERSION}')
    try:
        version = conn.send_command(SHOW_VERSION)
    except (NetmikoTimeoutException, NetmikoAuthenticationException):
        raise                                 # the session is gone: apply_config reports it
    except Exception as err:
        version = None
        report('warn', f'"{SHOW_VERSION}" failed ({type(err).__name__}); the device identity '
                       f'is recorded as unavailable.')
    report('command', f'{prompt} show running-config')
    running = conn.send_command('show running-config')
    identity = parse_identity(version, running)
    report('info', f'Device identity recorded in the backup: {describe_identity(identity)}.')
    try:
        backup, sha, key_id = _save_backup(host, running, backup_dir, backup_key, identity)
    except BackupError as err:
        # Stop here: without a verified encrypted backup nothing is sent to this device.
        reason = str(err).rstrip('.')
        report('error', f'BACKUP FAILED: {reason}.')
        report('section', 'RESULT')
        report('error', 'FAILED: no configuration command was sent; the device was not changed.')
        return False, (f'{reason}. No configuration command was sent; the device was not '
                       f'changed.')
    report.output(running, BACKUP_PREVIEW_LINES, ' (the complete copy is in the encrypted backup)')
    report('ok', f'Encrypted backup saved and verified (key_id={key_id}, configuration '
                 f'SHA-256 {sha}): {backup}')
    # The SHA-256 goes BEFORE "Backup: <path>" / "Restore from the backup if needed:
    # <path>", which stay last in every message (config/multi.py reads the path from there).
    checksum = (f'Backup SHA-256: {sha} (encrypted, key_id={key_id}; read it with '
                f'backup_tool.py export).')

    # ---- 2. configuration
    report('section', 'CONFIGURATION')
    applied, rejected = _send(conn, prompt, commands, report)
    if rejected:
        cmd, error = rejected
        report('error', f'REJECTED: "{cmd}"  ->  {error}')
        if applied is None:
            report('warn', 'POSSIBLY PARTIALLY APPLIED: the commands were sent as one batch, so '
                           'some of them may be in the running configuration. Nothing was saved.')
            state = 'possibly partially applied'
        elif applied:
            not_sent = len(commands) - len(applied) - 1
            report('warn', f'PARTIALLY APPLIED: {len(applied)} command(s) before it are now in the '
                           f'running configuration; {not_sent} after it were not sent. '
                           f'Nothing was saved.')
            state = (f'partially applied: {len(applied)} of {len(commands)} commands were applied '
                     f'before it')
        else:
            report('warn', 'Nothing was applied: the first command was rejected. Nothing was saved.')
            state = 'nothing was applied'
        report('section', 'RESULT')
        report('error', f'FAILED ({state}). Restore from the backup if needed: {backup}')
        return False, (f'The device rejected a command: "{cmd}" ({error}). The change is '
                       f'{state}, and it was not saved. {checksum} Restore from the backup if '
                       f'needed: {backup}')

    # ---- 3. verification
    report('section', 'VERIFICATION')
    if not checks:
        report('info', 'No automatic check is defined for these commands.')
    for show_cmd, expected in checks:
        report('command', f'{prompt} {show_cmd}')
        out = conn.send_command(show_cmd)
        report.output(out)
        if expected not in out:
            report('error', f'CHECK FAILED: "{expected}" was not found in "{show_cmd}".')
            report('section', 'RESULT')
            report('error', f'FAILED: all {len(commands)} commands were applied but the result '
                            f'could not be verified, so the configuration was NOT saved. '
                            f'Backup: {backup}')
            return False, (f'Check failed: "{expected}" was not found in {show_cmd}. The commands '
                           f'were applied but not saved. {checksum} Backup: {backup}')
        report('ok', f'OK: "{expected}" found.')

    # ---- 4. save
    report('section', 'SAVE')
    report('command', f'{prompt} {SAVE_COMMAND}')
    saved = conn.save_config()
    report.output(saved if isinstance(saved, str) else '')
    report('section', 'RESULT')
    report('ok', f'SUCCESS: {len(commands)} command(s) applied, verified and saved. Backup: {backup}')
    return True, f'Applied and verified. {checksum} Backup: {backup}'


def _send(conn, prompt, commands, report):
    """Send the configuration commands. Returns (applied, rejected or None).
    Normally: one configuration session, one command at a time, so each reply
    belongs to its command and sending stops at the first rejected one. A
    connection object without config_mode() (a simple fake) gets them as one batch."""
    if not hasattr(conn, 'config_mode'):
        for cmd in commands:
            report('command', f'(config)# {cmd}')
        output = conn.send_config_set(commands)
        report.output(output)
        error = rejection(output)
        # all commands went in one batch: which of them took effect is unknown
        return (commands, None) if not error else (None, ('one of the commands', error))

    entered = conn.config_mode()
    reply, now = split_reply(entered, 'configure terminal')
    report('command', f'{prompt} configure terminal')
    report.output(reply)
    now = now or prompt
    applied = []
    try:
        for cmd in commands:
            raw = conn.send_config_set([cmd], enter_config_mode=False, exit_config_mode=False)
            reply, after = split_reply(raw, cmd)
            report('command', f'{now} {cmd}')
            report.output(reply)
            error = rejection(reply)
            if error:
                return applied, (cmd, error)
            applied.append(cmd)
            now = after or now
    finally:
        try:
            report('command', f'{now} end')
            conn.exit_config_mode()
        except Exception as err:
            report('warn', f'Could not leave configuration mode cleanly: {err}')
    return applied, None
