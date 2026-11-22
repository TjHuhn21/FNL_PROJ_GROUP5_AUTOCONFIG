"""The backup encryption keys: a keyring protected by Windows DPAPI, offline recovery
files, and the commands that manage them.

    python backup_keys.py init            --recovery E:\\netcommand-b1.ncrecovery
    python backup_keys.py verify-recovery --recovery E:\\netcommand-b1.ncrecovery
    python backup_keys.py import-recovery --recovery E:\\netcommand-b1.ncrecovery [--activate]
    python backup_keys.py rotate          --recovery E:\\netcommand-b2.ncrecovery
    python backup_keys.py status

Separate from security.py / FERNET_KEY (saved device logins), which is not touched.

Keyring: %LOCALAPPDATA%\\NetCommand\\keys\\backup-keyring.json (outside the project; another
path with --keyring or NETCOMMAND_BACKUP_KEYRING). Each key is 32 random bytes, kept ONLY
as a DPAPI blob made for the current Windows account (user scope, never machine scope,
with a fixed non-secret entropy label), plus its id (b1, b2, ...) and fingerprint
(backup_crypto.fingerprint: identifies a key without revealing it). The keyring file is
validated strictly, written atomically, and never replaced by `init`; an unreadable
keyring is never silently replaced by a new key.

DPAPI alone is NOT a recovery plan: a reinstalled Windows, a lost profile, another
computer or an administrator's forced password reset makes the blobs unreadable. So every
key gets a recovery file when it is created, and the command succeeds only after that
file has been read back and decrypted with the passphrase:

    "NCRCV" | version | header length | header JSON | AES-256-GCM(key) + tag

with the key derived from the passphrase by scrypt (N=2**17, r=8, p=1, 16-byte random
salt; parameters stored in the authenticated header and range-checked before use) and a
random 12-byte nonce. The passphrase is never stored. There is no plaintext key export.

Messages and output show key ids, fingerprints and paths only: never a key, a DPAPI blob
or a passphrase.
"""
import argparse
import base64
import getpass
import hmac
import json
import os
import sys
import tempfile
import unicodedata

import backup_crypto as C

KEYRING_FORMAT = 'netcommand-backup-keyring'
KEYRING_VERSION = 1
KEYRING_VARIABLE = 'NETCOMMAND_BACKUP_KEYRING'
MAX_KEYRING_BYTES = 1024 * 1024
MAX_KEYS = 1000
RECOVERY_MAGIC = b'NCRCV'
RECOVERY_SUFFIX = '.ncrecovery'
MAX_RECOVERY_BYTES = 8192
SCRYPT_N, SCRYPT_R, SCRYPT_P = 2 ** 17, 8, 1       # about 128 MiB and well under a second
# What a recovery file may ask for: only what NetCommand writes (2**14 for tests, 2**17 by
# default), at most 2**18 (256 MiB), r = 8 and p = 1. Checked BEFORE scrypt runs, because
# scrypt must run before the passphrase can be checked.
SCRYPT_N_RANGE = (2 ** 14, 2 ** 18)
SALT_BYTES = 16
PASSPHRASE_MIN = 12
DPAPI_ENTROPY = b'NetCommand backup keyring v1'     # fixed and NOT secret: separates our blobs
DPAPI_DESCRIPTION = 'NetCommand backup key'
CRYPTPROTECT_UI_FORBIDDEN = 0x1                     # never CRYPTPROTECT_LOCAL_MACHINE (0x4)
_ENTRY_FIELDS = {'key_id', 'created_utc', 'fingerprint', 'protection', 'protected_key'}
_KEYRING_FIELDS = {'format', 'version', 'active_key_id', 'keys'}
_RECOVERY_FIELDS = {'format': str, 'alg': str, 'kdf': str, 'kdf_n': int, 'kdf_r': int,
                    'kdf_p': int, 'salt': str, 'nonce': str, 'key_id': str,
                    'fingerprint': str, 'created_utc': str}


# ---------------------------------------------------------------- errors
class KeyStoreError(C.BackupCryptoError):
    """The keyring or a key cannot be used. Nothing was changed."""


class KeyringMissing(KeyStoreError):
    """No keyring exists yet."""


class RecoveryError(C.BackupCryptoError):
    """A recovery file cannot be used (wrong passphrase, damaged, or not matching)."""


# ---------------------------------------------------------------- atomic files
def _place_new(temp, final):
    """Give the finished temp file its name; FileExistsError if the name is taken."""
    if os.name == 'nt':
        os.rename(temp, final)                     # never replaces an existing file
    else:
        os.link(temp, final)
        os.unlink(temp)


def write_new_file(path, data):
    """Create `path` with `data` atomically; never replaces an existing file
    (FileExistsError). A failure leaves no temporary file behind."""
    _write(path, data, replace_expected=None)


def replace_file(path, data, expected):
    """Atomically replace `path`, but only if it still holds `expected` (its bytes when
    it was read): a concurrent change is refused, never overwritten."""
    _write(path, data, replace_expected=expected)


def _write_temp(path, data):
    """A flushed, read-back temporary file next to `path` holding `data`; its name.
    Nothing is left behind if this fails."""
    folder = os.path.dirname(os.path.abspath(path))
    os.makedirs(folder, exist_ok=True)
    fd, temp = tempfile.mkstemp(prefix='.' + os.path.basename(path) + '.', suffix='.partial',
                                dir=folder)
    try:
        with os.fdopen(fd, 'wb') as f:
            f.write(data)
            f.flush()
            os.fsync(f.fileno())
        with open(temp, 'rb') as f:
            if f.read() != data:
                raise OSError('the file on disk does not match what was written')
        return temp
    except BaseException:
        _remove_quietly(temp)
        raise


def _write(path, data, replace_expected):
    temp = _write_temp(path, data)
    try:
        if replace_expected is None:
            _place_new(temp, path)
        else:
            with open(path, 'rb') as f:
                if f.read() != replace_expected:
                    raise KeyStoreError('The keyring was changed by something else while this '
                                        'command ran. Nothing was changed; run it again.')
            os.replace(temp, path)
        temp = None
    finally:
        if temp is not None:
            try:
                os.remove(temp)
            except OSError:
                pass


def _read_limited(path, limit, what):
    try:
        size = os.path.getsize(path)
        if size > limit:
            raise C.FormatError(f'The {what} is too large.')
        with open(path, 'rb') as f:
            return f.read(limit + 1)
    except FileNotFoundError:
        raise
    except OSError as err:
        raise KeyStoreError(f'The {what} could not be read ({err.strerror or type(err).__name__}).'
                            ) from None


# ---------------------------------------------------------------- DPAPI
class DpapiProtector:
    """Windows DPAPI in USER scope (CryptProtectData without CRYPTPROTECT_LOCAL_MACHINE):
    only the same Windows account can unprotect. Output buffers are released with
    LocalFree; input copies and decrypted output are zeroed before being released."""
    name = 'dpapi-user'

    def __init__(self):
        if os.name != 'nt':
            raise KeyStoreError('Backup keys are protected with Windows DPAPI, which is only '
                                'available on Windows.')
        import ctypes
        from ctypes import wintypes
        self._ct = ctypes

        class Blob(ctypes.Structure):
            _fields_ = [('cbData', wintypes.DWORD), ('pbData', ctypes.POINTER(ctypes.c_ubyte))]
        self._Blob = Blob
        self._crypt32 = ctypes.WinDLL('crypt32', use_last_error=True)
        self._kernel32 = ctypes.WinDLL('kernel32', use_last_error=True)
        args = [ctypes.POINTER(Blob), wintypes.LPCWSTR, ctypes.POINTER(Blob), ctypes.c_void_p,
                ctypes.c_void_p, wintypes.DWORD, ctypes.POINTER(Blob)]
        self._crypt32.CryptProtectData.argtypes = args
        self._crypt32.CryptProtectData.restype = wintypes.BOOL
        self._crypt32.CryptUnprotectData.argtypes = [ctypes.POINTER(Blob),
                                                     ctypes.POINTER(wintypes.LPWSTR)] + args[2:]
        self._crypt32.CryptUnprotectData.restype = wintypes.BOOL
        self._kernel32.LocalFree.argtypes = [ctypes.c_void_p]
        self._kernel32.LocalFree.restype = ctypes.c_void_p
        self.flags = CRYPTPROTECT_UI_FORBIDDEN

    def _blob(self, data):
        buf = self._ct.create_string_buffer(bytes(data), len(data))
        return self._Blob(len(data), self._ct.cast(buf, self._ct.POINTER(self._ct.c_ubyte))), buf

    def _call(self, protect, data):
        ct = self._ct
        source, source_buf = self._blob(data)
        entropy, entropy_buf = self._blob(DPAPI_ENTROPY)
        out = self._Blob()
        try:
            if protect:
                ok = self._crypt32.CryptProtectData(ct.byref(source), DPAPI_DESCRIPTION,
                                                    ct.byref(entropy), None, None, self.flags,
                                                    ct.byref(out))
            else:
                ok = self._crypt32.CryptUnprotectData(ct.byref(source), None, ct.byref(entropy),
                                                      None, None, self.flags, ct.byref(out))
            if not ok:
                code = ct.get_last_error()
                raise KeyStoreError(f'Windows DPAPI could not {"protect" if protect else "open"} '
                                    f'the backup key for this Windows account (error {code}).')
            return ct.string_at(out.pbData, out.cbData)
        finally:
            ct.memset(source_buf, 0, len(data))
            if out.pbData:
                if not protect:
                    ct.memset(out.pbData, 0, out.cbData)   # the decrypted key
                self._kernel32.LocalFree(ct.cast(out.pbData, ct.c_void_p))

    def protect(self, data):
        return self._call(True, data)

    def unprotect(self, blob):
        return self._call(False, blob)


# ---------------------------------------------------------------- the keyring
def default_keyring_path(environ=None):
    environ = os.environ if environ is None else environ
    if environ.get(KEYRING_VARIABLE):
        return environ[KEYRING_VARIABLE]
    base = environ.get('LOCALAPPDATA')
    if not base:
        raise KeyStoreError('LOCALAPPDATA is not set, so the keyring location is unknown. '
                            'Give it with --keyring.')
    return os.path.join(base, 'NetCommand', 'keys', 'backup-keyring.json')


def _dump(data):
    return (json.dumps(data, indent=2, sort_keys=True) + '\n').encode('ascii')


def _invalid(why):
    return KeyStoreError(f'The backup keyring is not valid ({why}). It was not changed; '
                         f'NetCommand never replaces it automatically.')


def validate_keyring(data):
    if not isinstance(data, dict) or set(data) != _KEYRING_FIELDS:
        raise _invalid('unexpected or missing fields')
    if data['format'] != KEYRING_FORMAT or data['version'] != KEYRING_VERSION:
        raise _invalid('unknown format or version')
    keys = data['keys']
    if not isinstance(keys, list) or not 1 <= len(keys) <= MAX_KEYS:
        raise _invalid('no keys')
    ids, prints = set(), set()
    for entry in keys:
        if not isinstance(entry, dict) or set(entry) != _ENTRY_FIELDS:
            raise _invalid('a key entry has unexpected or missing fields')
        try:
            C.check_key_id(entry['key_id'])
        except C.FormatError:
            raise _invalid('a key id is not valid') from None
        if not C.valid_fingerprint(entry['fingerprint']):
            raise _invalid('a fingerprint is not valid')
        if not all(isinstance(entry[k], str) and entry[k] for k in
                   ('created_utc', 'protection', 'protected_key')):
            raise _invalid('a key entry is incomplete')
        try:
            blob = base64.b64decode(entry['protected_key'].encode('ascii'), validate=True)
        except (ValueError, UnicodeError):
            raise _invalid('a protected key is not valid base64') from None
        if not 0 < len(blob) <= 8192:
            raise _invalid('a protected key has an invalid size')
        if entry['key_id'] in ids or entry['fingerprint'] in prints:
            raise _invalid('a key id or fingerprint appears twice')
        ids.add(entry['key_id'])
        prints.add(entry['fingerprint'])
    if data['active_key_id'] not in ids:
        raise _invalid('the active key is not in the keyring')
    return data


class Keyring:
    def __init__(self, path, data, raw):
        self.path, self.data, self.raw = path, data, raw

    @classmethod
    def load(cls, path):
        try:
            raw = _read_limited(path, MAX_KEYRING_BYTES, 'backup keyring')
        except FileNotFoundError:
            raise KeyringMissing('No backup keyring was found. Create one with: python '
                                 'backup_keys.py init --recovery <offline path>') from None
        except C.FormatError:
            raise _invalid('too large') from None
        try:
            data = json.loads(raw.decode('ascii'), object_pairs_hook=C._no_duplicates)
        except (C.FormatError, UnicodeError, ValueError, RecursionError, MemoryError):
            # RecursionError: deeply nested JSON; never an uncaught traceback.
            raise _invalid('not valid JSON') from None
        return cls(path, validate_keyring(data), raw)

    @property
    def active_key_id(self):
        return self.data['active_key_id']

    def entry(self, key_id):
        return next((e for e in self.data['keys'] if e['key_id'] == key_id), None)

    def key(self, key_id, protector):
        """The key bytes, after checking its fingerprint. UnknownKey if absent."""
        entry = self.entry(key_id)
        if entry is None:
            raise C.UnknownKey(f'Backup key {key_id} is not in this keyring (import its '
                               f'recovery file with: python backup_keys.py import-recovery).')
        if entry['protection'] != protector.name:
            raise KeyStoreError(f'Backup key {key_id} is protected another way '
                                f'({entry["protection"]}) and cannot be opened here.')
        key = protector.unprotect(base64.b64decode(entry['protected_key']))
        if len(key) != C.KEY_BYTES or not hmac.compare_digest(C.fingerprint(key),
                                                               entry['fingerprint']):
            raise KeyStoreError(f'Backup key {key_id} does not match its recorded fingerprint. '
                                f'Nothing was used; restore it with import-recovery.')
        return key

    def active(self, protector):
        return self.active_key_id, self.key(self.active_key_id, protector)

    def key_for(self, protector):
        return lambda key_id: self.key(key_id, protector)

    def summary(self):
        return [{k: e[k] for k in ('key_id', 'fingerprint', 'created_utc', 'protection')}
                for e in self.data['keys']]


def _entry(key_id, key, protector):
    blob = protector.protect(key)
    if not hmac.compare_digest(protector.unprotect(blob), key):
        raise KeyStoreError('The protected key could not be read back; nothing was saved.')
    return {'key_id': key_id, 'created_utc': C.utc_now_text(), 'fingerprint': C.fingerprint(key),
            'protection': protector.name, 'protected_key': base64.b64encode(blob).decode('ascii')}


# ---------------------------------------------------------------- recovery files
def check_passphrase(passphrase):
    if not isinstance(passphrase, str):
        raise RecoveryError('A recovery passphrase is required.')
    value = unicodedata.normalize('NFC', passphrase)
    if len(value) < PASSPHRASE_MIN or len(value) > 1024:
        raise RecoveryError(f'The recovery passphrase must be at least {PASSPHRASE_MIN} '
                            f'characters long.')
    return value.encode('utf-8')


def _derive(passphrase, salt, n, r, p):
    from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
    return Scrypt(salt=salt, length=C.KEY_BYTES, n=n, r=r, p=p).derive(check_passphrase(passphrase))


def make_recovery(key_id, key, passphrase, n=SCRYPT_N):
    """The bytes of a recovery file for this key (nothing is written)."""
    C.check_key_id(key_id)
    _check_kdf(n, SCRYPT_R, SCRYPT_P)
    salt = os.urandom(SALT_BYTES)
    header = {'format': 'ncrecovery', 'alg': C.ALGORITHM, 'kdf': 'scrypt', 'kdf_n': n,
              'kdf_r': SCRYPT_R, 'kdf_p': SCRYPT_P, 'salt': C._b64(salt),
              'nonce': C._b64(os.urandom(C.NONCE_BYTES)), 'key_id': key_id,
              'fingerprint': C.fingerprint(key), 'created_utc': C.utc_now_text()}
    return C.seal(RECOVERY_MAGIC, header, C.check_key(key),
                  _derive(passphrase, salt, n, SCRYPT_R, SCRYPT_P))


def _check_kdf(n, r, p):
    if not (SCRYPT_N_RANGE[0] <= n <= SCRYPT_N_RANGE[1] and n & (n - 1) == 0
            and r == SCRYPT_R and p == SCRYPT_P):
        raise C.FormatError('The recovery file asks for unsupported scrypt parameters.')


def open_recovery(data, passphrase):
    """(key_id, key, header) from recovery-file bytes; RecoveryError for a wrong passphrase,
    a changed or damaged file, or a key that does not match the recorded fingerprint."""
    header, aad, ciphertext = C.parse(data, RECOVERY_MAGIC, 'recovery file')
    C.check_fields(header, _RECOVERY_FIELDS, 'recovery file')
    if header['format'] != 'ncrecovery' or header['alg'] != C.ALGORITHM or \
            header['kdf'] != 'scrypt':
        raise C.FormatError('The recovery file uses an unsupported format or algorithm.')
    _check_kdf(header['kdf_n'], header['kdf_r'], header['kdf_p'])
    C.check_key_id(header['key_id'])
    if not C.valid_fingerprint(header['fingerprint']):
        raise C.FormatError('The recovery file has an invalid fingerprint.')
    if len(ciphertext) != C.KEY_BYTES + C.TAG_BYTES:
        raise C.FormatError('The recovery file is truncated or has extra data.')
    salt = C._unb64(header['salt'], SALT_BYTES, 'salt')
    nonce = C._unb64(header['nonce'], C.NONCE_BYTES, 'nonce')
    wrapping = _derive(passphrase, salt, header['kdf_n'], header['kdf_r'], header['kdf_p'])
    try:
        key = C.open_sealed(aad, ciphertext, wrapping, nonce)
    except C.AuthenticationFailed:
        raise RecoveryError('The recovery file could not be opened: the passphrase is wrong, '
                            'or the file was changed or damaged.') from None
    if not hmac.compare_digest(C.fingerprint(key), header['fingerprint']):
        raise RecoveryError('The key in the recovery file does not match its fingerprint.')
    return header['key_id'], key, header


def read_recovery(path, passphrase):
    try:
        data = _read_limited(path, MAX_RECOVERY_BYTES, 'recovery file')
    except FileNotFoundError:
        raise RecoveryError('The recovery file was not found.') from None
    return open_recovery(data, passphrase)


def recovery_identity(path):
    """(key_id, fingerprint, file bytes) of the recovery file at `path`, read from its
    header WITHOUT the passphrase, or None when there is no file. A file that is not a
    recognisable recovery file raises RecoveryError (it is never replaced)."""
    try:
        data = _read_limited(path, MAX_RECOVERY_BYTES, 'recovery file')
    except FileNotFoundError:
        return None
    except C.FormatError:
        data = None
    try:
        if data is None:
            raise C.FormatError('too large')
        header = C.parse(data, RECOVERY_MAGIC, 'recovery file')[0]
        C.check_fields(header, _RECOVERY_FIELDS, 'recovery file')
        C.check_key_id(header['key_id'])
        if not C.valid_fingerprint(header['fingerprint']):
            raise C.FormatError('fingerprint')
    except C.FormatError:
        raise RecoveryError('The file at the recovery path is not a recognisable NetCommand '
                            'recovery file. It was not replaced; choose another path.') from None
    return header['key_id'], header['fingerprint'], data


class _StagedRecovery:
    """A new, verified recovery file waiting under a temporary name next to its final
    path. It is put in place (commit) only after the keyring change succeeded; until
    then an existing file at that path is untouched."""

    def __init__(self, path, temp, previous):
        self.path, self.temp, self.previous = path, temp, previous

    def commit(self):
        if self.previous is None:
            _place_new(self.temp, self.path)           # FileExistsError if one appeared
        else:
            with open(self.path, 'rb') as f:           # closed before the replace (Windows)
                current = f.read()
            if current != self.previous:
                raise RecoveryError('The existing recovery file changed meanwhile; it was not '
                                    'replaced.')
            os.replace(self.temp, self.path)
        self.temp = None

    def discard(self):
        if self.temp is not None:
            _remove_quietly(self.temp)
            self.temp = None


def _stage_recovery(path, key_id, key, passphrase, overwrite, n, ring=None):
    """Check the target path, then make the recovery file, verify it in memory, write it
    under a temporary name and verify it again by decrypting it from disk.
    An existing file at `path` is replaced (later, by commit) only with overwrite=True
    (--confirm-overwrite-recovery), and never when it is the recovery file of a key that
    is still in `ring`: older backups need that key and its only recovery file."""
    previous = None
    if os.path.lexists(path):
        if not overwrite:
            raise RecoveryError('The recovery file already exists. Choose another path, or add '
                                '--confirm-overwrite-recovery to replace it.')
        old_id, old_fingerprint, previous = recovery_identity(path)
        entry = ring.entry(old_id) if ring is not None else None
        if entry is not None and entry['fingerprint'] == old_fingerprint:
            raise RecoveryError(f'The file at the recovery path is the recovery file of key '
                                f'{old_id}, which is still in the keyring (older backups need '
                                f'it). It was not replaced; choose another path for the new '
                                f'key.')
    data = make_recovery(key_id, key, passphrase, n)
    if not hmac.compare_digest(open_recovery(data, passphrase)[1], key):
        raise RecoveryError('The recovery file did not decrypt to the key; nothing was saved.')
    temp = _write_temp(path, data)
    try:
        kid, from_disk, _ = read_recovery(temp, passphrase)
        if kid != key_id or not hmac.compare_digest(from_disk, key):
            raise RecoveryError('The recovery file on disk does not match; nothing was saved.')
    except BaseException:
        _remove_quietly(temp)
        raise
    return _StagedRecovery(path, temp, previous)


def _remove_quietly(path):
    try:
        os.remove(path)
    except OSError:
        pass


# ---------------------------------------------------------------- commands
def init(keyring_path, recovery_path, passphrase, protector, overwrite_recovery=False,
         n=SCRYPT_N):
    """Create the first key (b1) with its verified recovery file and a new keyring. Never
    replaces an existing keyring, readable or not."""
    if os.path.lexists(keyring_path):
        raise KeyStoreError('A backup keyring already exists. init never replaces it: use '
                            'rotate for a new key, or import-recovery to restore one.')
    key, key_id = os.urandom(C.KEY_BYTES), 'b1'
    entry = _entry(key_id, key, protector)
    staged = _stage_recovery(recovery_path, key_id, key, passphrase, overwrite_recovery, n)
    written = False
    try:
        write_new_file(keyring_path, _dump({'format': KEYRING_FORMAT, 'version': KEYRING_VERSION,
                                            'active_key_id': key_id, 'keys': [entry]}))
        written = True
        Keyring.load(keyring_path).key(key_id, protector)       # it opens as written
        staged.commit()                         # only now is a recovery file put in place
    except BaseException as err:
        # Undo only what THIS call created. A keyring never stays without its verified
        # recovery file, and an existing recovery file is never lost.
        staged.discard()
        if written:
            _remove_quietly(keyring_path)
        if isinstance(err, FileExistsError):
            raise KeyStoreError('A keyring or recovery file appeared while init ran; nothing '
                                'was replaced and nothing was kept.') from None
        raise
    return {'key_id': key_id, 'fingerprint': entry['fingerprint']}


def rotate(keyring_path, recovery_path, passphrase, protector, overwrite_recovery=False,
           n=SCRYPT_N):
    """Add a new active key (b<N+1>) with its own verified recovery file. Every older key
    stays, so older backups remain readable."""
    ring = Keyring.load(keyring_path)
    ring.active(protector)                     # the keyring opens for this Windows account
    number = max(int(e['key_id'][1:]) for e in ring.data['keys']) + 1
    key, key_id = os.urandom(C.KEY_BYTES), f'b{number}'
    C.check_key_id(key_id)
    entry = _entry(key_id, key, protector)
    staged = _stage_recovery(recovery_path, key_id, key, passphrase, overwrite_recovery, n,
                             ring)
    data = dict(ring.data, keys=ring.data['keys'] + [entry], active_key_id=key_id)
    updated = _dump(validate_keyring(data))
    try:
        replace_file(keyring_path, updated, ring.raw)
    except BaseException:
        staged.discard()                        # keyring and any old recovery file unchanged
        raise
    try:
        staged.commit()
    except BaseException as err:
        reason = err.strerror if isinstance(err, OSError) and err.strerror else type(err).__name__
        try:
            replace_file(keyring_path, ring.raw, updated)       # put the keyring back
        except BaseException:
            raise RecoveryError(
                f'The keyring now has key {key_id}, but its recovery file could not be put in '
                f'place ({reason}) and the keyring could not be put back. The verified '
                f'recovery file is at {staged.temp}: move it somewhere safe (offline) now.'
            ) from None
        staged.discard()
        raise RecoveryError(f'The recovery file could not be put in place ({reason}). The '
                            f'keyring was put back as it was; nothing was changed.') from None
    return {'key_id': key_id, 'fingerprint': entry['fingerprint'],
            'previous_key_id': ring.active_key_id, 'keys': len(data['keys'])}


def import_recovery(keyring_path, recovery_path, passphrase, protector, activate=False):
    """Restore the key in a recovery file into this Windows account's DPAPI keyring:
    a new keyring (the key becomes active), a key the keyring lacks (added), or a key it
    has but this account can no longer open (re-protected, fingerprint must match)."""
    key_id, key, _ = read_recovery(recovery_path, passphrase)
    entry = _entry(key_id, key, protector)
    if not os.path.lexists(keyring_path):
        try:
            write_new_file(keyring_path, _dump({'format': KEYRING_FORMAT,
                                                'version': KEYRING_VERSION,
                                                'active_key_id': key_id, 'keys': [entry]}))
        except FileExistsError:
            raise KeyStoreError('A backup keyring appeared while this ran; run it again.'
                                ) from None
        return {'key_id': key_id, 'fingerprint': entry['fingerprint'], 'result': 'created',
                'active': True}
    ring = Keyring.load(keyring_path)           # an invalid keyring is refused, not replaced
    existing = ring.entry(key_id)
    keys = list(ring.data['keys'])
    if existing is not None:
        if existing['fingerprint'] != entry['fingerprint']:
            raise KeyStoreError(f'The keyring already has a different key named {key_id}. '
                                f'Nothing was changed.')
        try:
            ring.key(key_id, protector)
            result = 'already present'
        except KeyStoreError:
            keys = [entry if e['key_id'] == key_id else e for e in keys]
            result = 'repaired'
    else:
        if any(e['fingerprint'] == entry['fingerprint'] for e in keys):
            raise KeyStoreError('The keyring already has this key under another id. Nothing '
                                'was changed.')
        keys.append(entry)
        result = 'added'
    active = ring.active_key_id
    if activate:
        active = key_id
    data = dict(ring.data, keys=keys, active_key_id=active)
    if result == 'already present' and active == ring.active_key_id:
        return {'key_id': key_id, 'fingerprint': entry['fingerprint'], 'result': result,
                'active': active == key_id}
    replace_file(keyring_path, _dump(validate_keyring(data)), ring.raw)
    return {'key_id': key_id, 'fingerprint': entry['fingerprint'], 'result': result,
            'active': active == key_id}


def verify_recovery(keyring_path, recovery_path, passphrase, protector):
    """The recovery file decrypts with the passphrase AND holds exactly the key this
    keyring has under that id (compared in memory). Changes nothing."""
    key_id, key, header = read_recovery(recovery_path, passphrase)
    ring = Keyring.load(keyring_path)
    entry = ring.entry(key_id)
    if entry is None or entry['fingerprint'] != header['fingerprint']:
        raise RecoveryError(f'The recovery file is for key {key_id}, which this keyring does not '
                            f'have with that fingerprint.')
    if not hmac.compare_digest(ring.key(key_id, protector), key):
        raise RecoveryError('The recovery file does not hold the keyring\'s key.')
    return {'key_id': key_id, 'fingerprint': entry['fingerprint'],
            'active': key_id == ring.active_key_id}


def status(keyring_path):
    ring = Keyring.load(keyring_path)
    return {'active_key_id': ring.active_key_id, 'keys': ring.summary()}


# ---------------------------------------------------------------- command line
NOTICE = ('Keep the recovery file OFFLINE, in two separate places, and the passphrase '
          'somewhere else. Without them, encrypted backups cannot be read if this Windows '
          'account\'s keys are lost (Windows reinstalled, profile lost, new computer, '
          'forced password reset).')


def _ask_new_passphrase(ask):
    first = ask('New recovery passphrase (at least 12 characters, not shown): ')
    check_passphrase(first)
    if ask('Repeat the passphrase: ') != first:
        raise RecoveryError('The two passphrases are different. Nothing was changed.')
    return first


def main(argv=None, protector=None, ask=None, out=print):
    p = argparse.ArgumentParser(prog='python backup_keys.py', description=__doc__,
                                formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = p.add_subparsers(dest='command', required=True)
    for name in ('init', 'rotate', 'import-recovery', 'verify-recovery', 'status'):
        s = sub.add_parser(name)
        s.add_argument('--keyring', help='the keyring file (default: %%LOCALAPPDATA%%'
                                         '\\NetCommand\\keys\\backup-keyring.json)')
        if name != 'status':
            s.add_argument('--recovery', required=True, help='the recovery file (.ncrecovery)')
        if name in ('init', 'rotate'):
            s.add_argument('--confirm-overwrite-recovery', action='store_true',
                           help='replace an existing recovery file at that path')
        if name == 'import-recovery':
            s.add_argument('--activate', action='store_true',
                           help='make the imported key the one used for new backups')
    args = p.parse_args(argv)
    ask = ask or getpass.getpass
    try:
        keyring = args.keyring or default_keyring_path()
        if args.command == 'status':
            info = status(keyring)
            out(f'Keyring: {keyring}')
            for k in info['keys']:
                mark = 'active' if k['key_id'] == info['active_key_id'] else '      '
                out(f"  {k['key_id']:<6} {mark}  fingerprint {k['fingerprint']}  "
                    f"created {k['created_utc']}  ({k['protection']})")
            return 0
        protector = protector or DpapiProtector()
        if args.command in ('init', 'rotate'):
            phrase = _ask_new_passphrase(ask)
            action = init if args.command == 'init' else rotate
            info = action(keyring, args.recovery, phrase, protector,
                          overwrite_recovery=args.confirm_overwrite_recovery)
            out(f"Backup key {info['key_id']} created (fingerprint {info['fingerprint']}) and "
                f"protected for this Windows account in {keyring}.")
            if args.command == 'rotate':
                out(f"It is now the active key; {info['previous_key_id']} and every older key "
                    f"were kept for older backups ({info['keys']} keys in total).")
            out(f'Recovery file written and verified by decrypting it: {args.recovery}')
            out(NOTICE)
        elif args.command == 'import-recovery':
            info = import_recovery(keyring, args.recovery, ask('Recovery passphrase: '),
                                   protector, activate=args.activate)
            out(f"Backup key {info['key_id']} (fingerprint {info['fingerprint']}): "
                f"{info['result']}{'; active' if info['active'] else ''}. Keyring: {keyring}")
        else:
            info = verify_recovery(keyring, args.recovery, ask('Recovery passphrase: '), protector)
            out(f"OK: the recovery file holds backup key {info['key_id']} (fingerprint "
                f"{info['fingerprint']}){' (the active key)' if info['active'] else ''}.")
        return 0
    except (C.BackupCryptoError, OSError) as err:
        text = str(err) if isinstance(err, C.BackupCryptoError) else \
            f'{type(err).__name__}: {err.strerror or "file error"}'
        out(f'Refused: {text}')
        return 1
    except (KeyboardInterrupt, EOFError):
        out('Cancelled. Nothing was changed.')
        return 1


if __name__ == '__main__':
    sys.exit(main())
