"""The backup catalogue (Phase 4B): find encrypted backups (.ncbak), show their safe
metadata, verify them, match them against a device, and record a selection for a FUTURE
restore. Nothing here restores, connects to a device or writes any file.

Where backups are looked for (approved_locations): a fixed list of folders, top level only
(no recursion), never following a symbolic link or junction:
  1. the folder Apply writes to now (config.connect.BACKUP_DIR: <project>\\backups, or the
     Mock Lab launcher's folder);
  2. <project>\\backups;
  3. <project>\\mock-lab\\backups;
  4. the "backups" folder of the directory NetCommand was started from (older versions
     wrote there when started elsewhere).
The same folder is listed once. A missing or unreadable folder is reported, never an error.
Files with the same name in different folders are both listed, each with its folder;
byte-identical copies are marked as duplicates of the first one found.

Trust: the readable header of a backup is AUTHENTICATED but NOT confidential, and it is
only trusted after verify(): the whole file is decrypted IN MEMORY (authentication tag,
SHA-256 and size), its key id resolved, and the configuration checked with the Cisco IOS
check used by Apply (config.connect.check_backup). The decrypted bytes are never written,
printed or kept. Messages never contain configuration content, keys or secrets.
"""
import hashlib
import os
import stat
from dataclasses import dataclass, field
from datetime import datetime, timezone

import backup_crypto as C

PROJECT_DIR = os.path.dirname(os.path.abspath(__file__))
SUFFIX = '.ncbak'
MAX_FILES_PER_LOCATION = 5000

NOT_VERIFIED = 'Not verified'
VERIFIED = 'Verified'
UNAVAILABLE = 'Verification unavailable'
FAILED = 'Verification failed'
INVALID = 'Invalid'
UNREADABLE = 'Unreadable'

OK, MISSING, INACCESSIBLE, LINK_REFUSED = 'ok', 'missing', 'inaccessible', 'link refused'


# ---------------------------------------------------------------- locations
@dataclass(frozen=True)
class Location:
    path: str
    label: str
    status: str = OK
    problem: str = ''


def _is_link(path):
    """A symbolic link or (Windows) junction / reparse point: never followed."""
    try:
        st = os.lstat(path)
    except OSError:
        return False
    if stat.S_ISLNK(st.st_mode):
        return True
    attributes = getattr(st, 'st_file_attributes', 0)
    return bool(attributes & getattr(stat, 'FILE_ATTRIBUTE_REPARSE_POINT', 0x400))


def candidate_folders(backup_dir=None, cwd=None):
    """[(path, label)] in search order (see the module notes), before any checks."""
    if backup_dir is None:
        from config import connect
        backup_dir = connect.BACKUP_DIR
    cwd = cwd or os.getcwd()
    return [(os.path.abspath(backup_dir), 'Backup folder (Apply writes here)'),
            (os.path.join(PROJECT_DIR, 'backups'), 'Project backups'),
            (os.path.join(PROJECT_DIR, 'mock-lab', 'backups'), 'Mock Lab backups'),
            (os.path.join(cwd, 'backups'), 'Start-folder backups')]


def approved_locations(backup_dir=None, cwd=None, candidates=None):
    """Each approved folder once, with its status (ok, missing, inaccessible, link refused)."""
    seen, out = set(), []
    for path, label in candidates or candidate_folders(backup_dir, cwd):
        key = os.path.normcase(os.path.abspath(path))
        if key in seen:
            continue
        seen.add(key)
        if not os.path.lexists(path):
            out.append(Location(path, label, MISSING, 'does not exist'))
        elif _is_link(path):
            out.append(Location(path, label, LINK_REFUSED, 'is a link or junction; not '
                                                           'followed'))
        elif not os.path.isdir(path):
            out.append(Location(path, label, INACCESSIBLE, 'is not a folder'))
        else:
            try:
                with os.scandir(path):
                    pass
                out.append(Location(path, label))
            except OSError as err:
                out.append(Location(path, label, INACCESSIBLE,
                                    f'cannot be read ({err.strerror or type(err).__name__})'))
    return out


# ---------------------------------------------------------------- entries
@dataclass
class Entry:
    path: str
    location: str
    size: int = 0
    file_sha256: str = ''
    header: dict = None
    status: str = NOT_VERIFIED
    problem: str = ''
    duplicate_of: str = None
    verified_header: dict = None       # set only by a successful verify()

    @property
    def filename(self):
        return os.path.basename(self.path)

    def field(self, name):
        return (self.header or {}).get(name)

    @property
    def identity(self):
        if self.header is None:
            return {name: C.NOT_RECORDED for name in C.IDENTITY_FIELDS}
        return C.identity_of(self.header)

    @property
    def trusted(self):
        """True only after verification: then the header has been authenticated."""
        return self.status == VERIFIED and self.verified_header is not None


def _read(path):
    size = os.path.getsize(path)
    if size > C.MAX_FILE_BYTES:
        raise C.FormatError('The backup is too large.')
    with open(path, 'rb') as f:
        return f.read(C.MAX_FILE_BYTES + 1)


def _entry_for(path, label):
    entry = Entry(path, label)
    try:
        data = _read(path)
    except C.FormatError as err:
        entry.status, entry.problem = INVALID, str(err)
        return entry
    except OSError as err:
        entry.status = UNREADABLE
        entry.problem = f'The file cannot be read ({err.strerror or type(err).__name__}).'
        return entry
    entry.size, entry.file_sha256 = len(data), hashlib.sha256(data).hexdigest()
    try:
        entry.header = C.read_backup_header(data)[0]      # structure only: NOT trusted yet
    except C.BackupCryptoError as err:
        entry.status, entry.problem = INVALID, str(err)
    return entry


def scan(locations):
    """(entries, notes): every .ncbak at the top level of each usable location, newest
    first. One bad file never stops the scan."""
    entries, notes, first_copy = [], [], {}
    for loc in locations:
        if loc.status != OK:
            notes.append(f'{loc.label}: {loc.path} {loc.problem}.')
            continue
        count = 0
        try:
            with os.scandir(loc.path) as found:
                items = sorted(found, key=lambda e: e.name)
        except OSError as err:
            notes.append(f'{loc.label}: {loc.path} cannot be read '
                         f'({err.strerror or type(err).__name__}).')
            continue
        for item in items:
            if not item.name.lower().endswith(SUFFIX) or item.name.startswith('.'):
                continue
            if _is_link(item.path):
                notes.append(f'{item.path} is a link or junction; not followed.')
                continue
            try:
                if not item.is_file(follow_symlinks=False):
                    continue
            except OSError:
                continue
            count += 1
            if count > MAX_FILES_PER_LOCATION:
                notes.append(f'{loc.label}: more than {MAX_FILES_PER_LOCATION} backups; the '
                             f'rest were not listed.')
                break
            entry = _entry_for(item.path, loc.label)
            if entry.file_sha256:
                if entry.file_sha256 in first_copy:
                    entry.duplicate_of = first_copy[entry.file_sha256]
                else:
                    first_copy[entry.file_sha256] = entry.path
            entries.append(entry)
    entries.sort(key=lambda e: (e.field('created_utc') or '', e.filename), reverse=True)
    return entries, notes


# ---------------------------------------------------------------- verification
@dataclass(frozen=True)
class Verification:
    status: str
    problem: str = ''
    header: dict = None
    file_sha256: str = ''


def keyring_lookup(source=None):
    """(key_for, problem): a key lookup from the user's backup keyring, or None and why
    not (then every verification is 'Verification unavailable')."""
    from config import connect
    try:
        return connect.load_backup_key(source).key_for, None
    except connect.BackupKeyUnavailable as err:
        return None, str(err)


def verify(entry, key_for, key_problem=None):
    """Decrypt in memory and check everything; updates and returns entry's verification.
    The decrypted configuration never leaves this function."""
    from config import connect
    result = _verify(entry, key_for, key_problem, connect.check_backup)
    entry.status, entry.problem = result.status, result.problem
    entry.verified_header = result.header if result.status == VERIFIED else None
    return result


def _verify(entry, key_for, key_problem, check_backup):
    if key_for is None:
        return Verification(UNAVAILABLE, key_problem or 'The backup keyring is not available.')
    try:
        data = _read(entry.path)
    except FileNotFoundError:
        return Verification(UNREADABLE, 'The file no longer exists; refresh the list.')
    except C.FormatError as err:
        return Verification(INVALID, str(err))
    except OSError as err:
        return Verification(UNREADABLE, f'The file cannot be read '
                                         f'({err.strerror or type(err).__name__}).')
    digest = hashlib.sha256(data).hexdigest()
    if entry.file_sha256 and digest != entry.file_sha256:
        return Verification(FAILED, 'The file changed after it was listed; refresh the list.')
    try:
        plaintext, header = C.decrypt_backup(data, key_for)
    except C.UnknownKey as err:
        return Verification(UNAVAILABLE, str(err))
    except (C.AuthenticationFailed, C.IntegrityError) as err:
        return Verification(FAILED, str(err))
    except C.FormatError as err:
        return Verification(INVALID, str(err))
    except C.BackupCryptoError as err:                 # the keyring (DPAPI, fingerprint)
        return Verification(UNAVAILABLE, str(err))
    except Exception as err:                           # never crash the catalogue
        return Verification(FAILED, f'The backup could not be checked ({type(err).__name__}).')
    try:
        problem = check_backup(plaintext.decode('utf-8'))
    except UnicodeDecodeError:
        problem = 'the configuration is not valid text'
    finally:
        del plaintext                                  # never kept
    if problem:
        # Only the reason, never the configuration excerpt check_backup may quote.
        return Verification(FAILED, f'The configuration is not usable: '
                                    f'{problem.split(" (")[0]}.')
    return Verification(VERIFIED, '', header, digest)


# ---------------------------------------------------------------- device matching
@dataclass(frozen=True)
class Device:
    """What NetCommand knows about the selected device. serial/platform are None unless
    they were read from the device (the device records do not store them)."""
    ip: str
    hostname: str = None
    platform: str = None
    serial: str = None
    device_id: int = None


@dataclass
class Match:
    checks: list = field(default_factory=list)       # (field, outcome, text)
    warnings: list = field(default_factory=list)
    blocked: bool = False
    block_reason: str = ''
    hardware_match: bool = False
    identity_recorded: bool = False
    requires_legacy_confirmation: bool = True

    @property
    def summary(self):
        if self.blocked:
            return self.block_reason
        if self.hardware_match:
            return 'Serial match'
        if not self.identity_recorded:
            return 'Identity not recorded'
        return 'Hardware identity not confirmed'


_PLACEHOLDERS = {'unavailable', 'unknown', 'n/a', 'na', 'none', 'null', '-'}


def _known(value):
    """A real identity value: a plain token, and not a placeholder word."""
    return C.valid_identity_value(value) and value.casefold() not in _PLACEHOLDERS


def match(header, device):
    """Conservative matching of a backup header against a device. Unknown, null, missing or
    malformed values never count as a match. Serial or platform mismatch blocks selection."""
    header = header or {}
    m = Match(identity_recorded=any(name in header for name in C.IDENTITY_FIELDS))

    def block(reason):
        if not m.blocked:
            m.blocked, m.block_reason = True, reason

    serial, dev_serial = header.get('serial'), device.serial
    if _known(serial) and _known(dev_serial):
        if serial == dev_serial:
            m.hardware_match = True
            m.checks.append(('serial', 'match', f'Serial match ({serial})'))
        else:
            m.checks.append(('serial', 'mismatch', f'Serial differs: backup {serial}, device '
                                                   f'{dev_serial}'))
            block(f'Identity mismatch: the backup is from serial {serial}, the device is '
                  f'{dev_serial}')
    else:
        m.checks.append(('serial', 'unknown', 'Serial not known on both sides: hardware '
                                              'identity cannot be confirmed'))

    platform, dev_platform = header.get('platform'), device.platform
    if _known(platform) and _known(dev_platform):
        if platform.casefold() == dev_platform.casefold():
            m.checks.append(('platform', 'match', f'Platform match ({platform})'))
        else:
            m.checks.append(('platform', 'mismatch', f'Platform differs: backup {platform}, '
                                                     f'device {dev_platform}'))
            block(f'Platform mismatch: the backup is from a {platform}, the device is a '
                  f'{dev_platform}')
    else:
        m.checks.append(('platform', 'unknown', 'Platform not known on both sides'))

    host = header.get('host')
    ip_differs = host != device.ip
    if ip_differs:
        text = (f'IP address differs: backup made for {host}, device is {device.ip}' if host
                else f'The backup records no address; the device is {device.ip}')
        m.checks.append(('ip', 'mismatch', text))
        m.warnings.append(text)
    else:
        m.checks.append(('ip', 'match', f'IP address matches ({host})'))

    hostname = header.get('hostname')
    if _known(hostname) and _known(device.hostname):
        if hostname.casefold() == device.hostname.casefold():
            m.checks.append(('hostname', 'match', f'Hostname matches ({hostname}); a hostname '
                                                  f'alone does not prove the hardware'))
        else:
            text = f'Hostname differs: backup {hostname}, device {device.hostname}'
            m.checks.append(('hostname', 'mismatch', text))
            m.warnings.append(text)
    else:
        m.checks.append(('hostname', 'unknown', 'Hostname not known on both sides'))

    if not m.identity_recorded:
        m.warnings.append('Identity not recorded (a backup made before identity was '
                          'recorded): a restore needs the legacy-backup confirmation')
    if m.hardware_match and not m.blocked:
        m.requires_legacy_confirmation = False
    elif ip_differs:
        # Approved rule: without a serial match, the IP address must match.
        block('The IP address differs and the hardware identity cannot be confirmed by '
              'serial number')
    return m


# ---------------------------------------------------------------- selection
class SelectionRefused(Exception):
    """The backup may not be selected for a future restore. Nothing was recorded."""


@dataclass(frozen=True)
class Selection:
    """A backup chosen for a FUTURE restore. Recording it sends nothing to any device."""
    path: str
    file_sha256: str
    key_id: str
    plaintext_sha256: str
    created_utc: str
    device_id: int
    device_ip: str
    device_name: str
    hardware_match: bool
    requires_legacy_confirmation: bool
    warnings: tuple
    selected_utc: str


def select(entry, verification, device, can_select):
    """A Selection, or SelectionRefused(reason). Requires the right permission, a
    successful verification of exactly this file, and no blocking identity mismatch."""
    if not can_select:
        raise SelectionRefused('Your role may not select backups for restore.')
    if verification is None or verification.status != VERIFIED:
        status = verification.status if verification else NOT_VERIFIED
        raise SelectionRefused(f'Only a verified backup can be selected (this one: {status}).')
    if not entry.file_sha256 or verification.file_sha256 != entry.file_sha256:
        raise SelectionRefused('The verification does not belong to this file; verify it '
                               'again.')
    m = match(verification.header, device)           # the AUTHENTICATED header
    if m.blocked:
        raise SelectionRefused(m.block_reason + '.')
    h = verification.header
    return Selection(entry.path, entry.file_sha256, h['key_id'], h['plaintext_sha256'],
                     h['created_utc'], device.device_id, device.ip, device.hostname or '',
                     m.hardware_match, m.requires_legacy_confirmation, tuple(m.warnings),
                     datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ'))
