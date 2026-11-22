"""Encrypted configuration backups (.ncbak): the format, encryption and checks.

Phase 3A: the engine only. Nothing here writes files, finds keys or talks to devices;
backup_keys.py manages the keys, backup_tool.py verifies and exports files, and the
Apply workflow (config/connect.py) is NOT changed yet.

File layout (all integers big-endian):

    "NCBAK"  version (1 byte)  header length (4 bytes)  header (JSON, UTF-8)  ciphertext+tag
    \_______________________ AAD: authenticated, never encrypted ______/

* Algorithm: AES-256-GCM (cryptography's AESGCM), 256-bit key, 96-bit nonce, 128-bit tag.
* The EXACT bytes of the magic, version, header length and header JSON, as written to
  (or read from) the file, are the GCM associated data. The header is parsed only to
  find the key and nonce; it is never re-serialised before authentication, so changing
  any byte of it (or of the ciphertext, nonce or tag) makes decryption fail.
* Nonce: 12 fresh bytes from os.urandom for EVERY encryption. With random 96-bit nonces
  one key must not be used for more than 2**32 encryptions (NIST SP 800-38D); NetCommand
  makes a few backups per change, so this is never approached. Rotating the key yearly,
  or after 1,000,000 backups, keeps a wide margin (see docs/BACKUP_ENCRYPTION.md).
* The header also records the SHA-256 and size of the plaintext; after decryption both
  are checked again (IntegrityError on any difference).
* Strict parsing: wrong magic, unknown version, oversized or malformed header, duplicate
  JSON keys, missing or ill-typed fields, unknown algorithm, wrong nonce length, oversized
  file and truncated data are all refused before any decryption is attempted.

The same sealed layout (different magic) is used by the recovery files (backup_keys.py).
Error messages are fixed text: never a key, a passphrase or configuration content.
"""
import base64
import binascii
import hashlib
import hmac
import json
import os
import re
import struct
from datetime import datetime, timezone

MAGIC = b'NCBAK'
VERSION = 1
ALGORITHM = 'AES-256-GCM'
KEY_BYTES = 32
NONCE_BYTES = 12
TAG_BYTES = 16
PREFIX_BYTES = len(MAGIC) + 1 + 4
MAX_HEADER_BYTES = 4096
MAX_PLAINTEXT_BYTES = 16 * 1024 * 1024
MAX_FILE_BYTES = PREFIX_BYTES + MAX_HEADER_BYTES + MAX_PLAINTEXT_BYTES + TAG_BYTES
FINGERPRINT_LABEL = b'NetCommand backup key fingerprint v1'

_KEY_ID = re.compile(r'^b[1-9][0-9]{0,5}$')          # b1, b2, ... (rotation adds one)
_HEX64 = re.compile(r'^[0-9a-f]{64}$')
_HEX32 = re.compile(r'^[0-9a-f]{32}$')
# Optional, non-secret descriptive metadata a caller may add to a backup header.
METADATA_FIELDS = {'host': str, 'source': str, 'privilege': int, 'app': str}
# Device identity (Phase 4A), read from the device when the backup is made. Three states,
# so an unknown value can never be mistaken for a real one:
#   field absent      not recorded (backups made before Phase 4A)
#   null (None)       looked for, but the device did not show it (unavailable)
#   a string          the value the device showed (conservative characters only)
IDENTITY_FIELDS = ('serial', 'platform', 'hostname', 'ios_version')
NOT_RECORDED, UNAVAILABLE = 'not recorded', 'unavailable'
_IDENTITY_VALUE = re.compile(r'^[A-Za-z0-9._()/+:-]{1,64}$')


def valid_identity_value(value):
    """True for a string NetCommand may store as an identity value (no spaces or control
    characters, at most 64 characters)."""
    return isinstance(value, str) and bool(_IDENTITY_VALUE.match(value))


def identity_of(header):
    """{field: value | UNAVAILABLE | NOT_RECORDED} of a backup header, for display."""
    out = {}
    for name in IDENTITY_FIELDS:
        if name not in header:
            out[name] = NOT_RECORDED
        else:
            out[name] = header[name] if header[name] is not None else UNAVAILABLE
    return out
_REQUIRED = {'format': str, 'alg': str, 'key_id': str, 'nonce': str, 'created_utc': str,
             'plaintext_sha256': str, 'plaintext_size': int}


# ---------------------------------------------------------------- errors
class BackupCryptoError(Exception):
    """Base class. Messages never contain keys, passphrases or configuration content."""


class FormatError(BackupCryptoError):
    """Not a valid file of this kind (magic, header, fields, sizes, truncation)."""


class UnsupportedVersion(FormatError):
    """A format version this program does not know."""


class UnknownKey(BackupCryptoError):
    """The key that encrypted the file is not available here."""


class AuthenticationFailed(BackupCryptoError):
    """AES-GCM authentication failed: the wrong key, or the file was changed."""


class IntegrityError(BackupCryptoError):
    """Decryption worked but the plaintext does not match the header's SHA-256/size."""


AUTH_FAILED = ('The file could not be authenticated: it was encrypted with a different '
               'key, or it has been changed or damaged.')


# ---------------------------------------------------------------- helpers
def check_key_id(key_id):
    if not isinstance(key_id, str) or not _KEY_ID.match(key_id):
        raise FormatError('The key id is not valid (expected b1, b2, ...).')
    return key_id


def check_key(key):
    if not isinstance(key, (bytes, bytearray)) or len(key) != KEY_BYTES:
        raise BackupCryptoError('A backup key must be exactly 32 random bytes.')
    return bytes(key)


def fingerprint(key):
    """A non-secret identifier of a key (HMAC-SHA256 of a fixed label, 128 bits shown):
    two keys can be compared without revealing either."""
    return hmac.new(check_key(key), FINGERPRINT_LABEL, hashlib.sha256).hexdigest()[:32]


def valid_fingerprint(value):
    return isinstance(value, str) and bool(_HEX32.match(value))


def utc_now_text():
    return datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%S.%fZ')


def _b64(data):
    return base64.b64encode(data).decode('ascii')


def _unb64(text, length, what):
    try:
        raw = base64.b64decode(text.encode('ascii'), validate=True)
    except (binascii.Error, ValueError, UnicodeError, AttributeError):
        raise FormatError(f'The {what} is not valid base64.') from None
    if length is not None and len(raw) != length:
        raise FormatError(f'The {what} has the wrong length.')
    return raw


def _no_duplicates(pairs):
    seen = {}
    for k, v in pairs:
        if k in seen:
            raise FormatError('The header repeats a field.')
        seen[k] = v
    return seen


# ---------------------------------------------------------------- the sealed layout
def seal(magic, header, plaintext, key):
    """magic | version | header length | header JSON | AES-256-GCM(plaintext), the first
    four authenticated as associated data. `header` must already contain 'nonce'."""
    header_bytes = json.dumps(header, sort_keys=True, separators=(',', ':'),
                              ensure_ascii=True).encode('ascii')
    if len(header_bytes) > MAX_HEADER_BYTES:
        raise FormatError('The header is too large.')
    aad = magic + bytes([VERSION]) + struct.pack('>I', len(header_bytes)) + header_bytes
    nonce = _unb64(header['nonce'], NONCE_BYTES, 'nonce')
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    return aad + AESGCM(check_key(key)).encrypt(nonce, plaintext, aad)


def parse(data, magic, what='backup'):
    """(header dict, aad bytes, ciphertext+tag) without decrypting. The aad returned is
    the exact byte range from the file."""
    if not isinstance(data, (bytes, bytearray)):
        raise FormatError(f'The {what} must be bytes.')
    data = bytes(data)
    if len(data) > MAX_FILE_BYTES:
        raise FormatError(f'The {what} is too large.')
    if len(data) < PREFIX_BYTES:
        raise FormatError(f'The {what} is truncated.')
    if data[:len(magic)] != magic:
        raise FormatError(f'This is not a NetCommand {what} (wrong file signature).')
    version = data[len(magic)]
    if version != VERSION:
        raise UnsupportedVersion(f'Unsupported {what} format version {version}.')
    (length,) = struct.unpack('>I', data[len(magic) + 1:PREFIX_BYTES])
    if not 0 < length <= MAX_HEADER_BYTES:
        raise FormatError(f'The {what} header length is not valid.')
    end = PREFIX_BYTES + length
    if len(data) < end + TAG_BYTES:
        raise FormatError(f'The {what} is truncated.')
    raw = data[PREFIX_BYTES:end]
    try:
        header = json.loads(raw.decode('ascii'), object_pairs_hook=_no_duplicates)
    except FormatError:
        raise
    except (UnicodeError, ValueError, RecursionError, MemoryError):
        # RecursionError: deeply nested JSON (a 4 KiB header can nest ~4000 levels).
        raise FormatError(f'The {what} header is not valid JSON.') from None
    if not isinstance(header, dict):
        raise FormatError(f'The {what} header is not valid.')
    return header, data[:end], data[end:]


def open_sealed(aad, ciphertext, key, nonce):
    from cryptography.exceptions import InvalidTag
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    try:
        return AESGCM(check_key(key)).decrypt(nonce, ciphertext, aad)
    except InvalidTag:
        raise AuthenticationFailed(AUTH_FAILED) from None


def check_fields(header, required, what):
    for name, kind in required.items():
        value = header.get(name)
        if isinstance(value, bool) or not isinstance(value, kind):
            raise FormatError(f'The {what} header is missing or has an invalid "{name}".')


# ---------------------------------------------------------------- .ncbak backups
def encrypt_backup(plaintext, key, key_id, metadata=None):
    """The .ncbak bytes for `plaintext` (bytes). metadata: optional non-secret fields
    (host, source, privilege, app, and the identity fields serial / platform / hostname /
    ios_version, each a valid string or None = unavailable). A fresh random nonce is used
    every time."""
    if not isinstance(plaintext, (bytes, bytearray)):
        raise BackupCryptoError('The backup plaintext must be bytes.')
    plaintext = bytes(plaintext)
    if len(plaintext) > MAX_PLAINTEXT_BYTES:
        raise BackupCryptoError('The configuration is too large to back up.')
    check_key_id(key_id)
    header = {'format': 'ncbak', 'alg': ALGORITHM, 'key_id': key_id,
              'nonce': _b64(os.urandom(NONCE_BYTES)), 'created_utc': utc_now_text(),
              'plaintext_sha256': hashlib.sha256(plaintext).hexdigest(),
              'plaintext_size': len(plaintext)}
    for name, value in (metadata or {}).items():
        if name in IDENTITY_FIELDS:
            if value is not None and not valid_identity_value(value):
                raise BackupCryptoError(f'The backup identity field "{name}" is not valid.')
            header[name] = value
            continue
        kind = METADATA_FIELDS.get(name)
        if kind is None or isinstance(value, bool) or not isinstance(value, kind):
            raise BackupCryptoError(f'Unsupported backup metadata field "{name}".')
        if isinstance(value, str) and (len(value) > 200 or not value.isprintable()):
            raise BackupCryptoError(f'The backup metadata field "{name}" is not valid.')
        header[name] = value
    return seal(MAGIC, header, plaintext, key)


def read_backup_header(data):
    """(header, aad, ciphertext) of a .ncbak after every structural check."""
    header, aad, ciphertext = parse(data, MAGIC)
    check_fields(header, _REQUIRED, 'backup')
    if header['format'] != 'ncbak':
        raise FormatError('The backup header names another format.')
    if header['alg'] != ALGORITHM:
        raise FormatError('The backup uses an unsupported algorithm.')
    check_key_id(header['key_id'])
    _unb64(header['nonce'], NONCE_BYTES, 'nonce')
    if not _HEX64.match(header['plaintext_sha256']):
        raise FormatError('The backup header has an invalid SHA-256.')
    if not 0 <= header['plaintext_size'] <= MAX_PLAINTEXT_BYTES:
        raise FormatError('The backup header has an invalid size.')
    if len(ciphertext) != header['plaintext_size'] + TAG_BYTES:
        raise FormatError('The backup is truncated or has extra data.')
    for name, kind in METADATA_FIELDS.items():
        if name in header and (isinstance(header[name], bool)
                               or not isinstance(header[name], kind)):
            raise FormatError(f'The backup header has an invalid "{name}".')
    for name in IDENTITY_FIELDS:                  # absent (older backups) is fine
        if name in header and header[name] is not None and \
                not valid_identity_value(header[name]):
            raise FormatError(f'The backup header has an invalid "{name}".')
    return header, aad, ciphertext


def decrypt_backup(data, key_for):
    """(plaintext bytes, header). key_for(key_id) returns that key or raises UnknownKey.
    Raises FormatError / UnsupportedVersion / UnknownKey / AuthenticationFailed /
    IntegrityError; never returns unauthenticated data."""
    header, aad, ciphertext = read_backup_header(data)
    key = key_for(header['key_id'])
    plaintext = open_sealed(aad, ciphertext, key, _unb64(header['nonce'], NONCE_BYTES, 'nonce'))
    if len(plaintext) != header['plaintext_size'] or \
            hashlib.sha256(plaintext).hexdigest() != header['plaintext_sha256']:
        raise IntegrityError('The decrypted backup does not match its recorded SHA-256 and '
                             'size.')
    return plaintext, header
