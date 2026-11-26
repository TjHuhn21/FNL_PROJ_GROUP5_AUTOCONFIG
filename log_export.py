"""Encrypted ("locked") export of the Logs page.

LOCKED WITH A PASSWORD (the Logs page uses this): the password typed when exporting is the
only way to open the file - it is not stored anywhere, so nobody else can unlock it
(NetCommand included), and a lost password cannot be recovered.

    data = export_bytes(log, entries, password, filters=..., exported_by=...)
    header, payload = open_export(data, password)

LOCKED WITH NETCOMMAND'S KEY (module support only; not offered on the Logs page):

    data = lock_bytes(log, entries, backup_key, filters=..., exported_by=...)  # bytes only
    write_export(path, data)            # a NEW file; an existing file is never replaced
    header, payload = unlock_bytes(data, key_for)      # key_for(key_id) -> the key

The file is encrypted with a key derived (HKDF-SHA256, a random salt per file) from the
backup encryption key in the Windows-protected keyring (backup_keys.py, DPAPI) - the same
key NetCommand's encrypted backups use. The header names the key (key_id and its
fingerprint, never the key). Who can unlock it: the same Windows account on this computer,
or another computer where that backup key was imported from its recovery file
(python backup_keys.py import-recovery). Nobody needs to remember a passphrase.

From a terminal (the password is asked for without echo, never on the command line):

    python -m log_export info FILE                     what the file says about itself
    python -m log_export unlock FILE --out OUT [--format csv|json]   (or: decrypt)
                                                       writes a NEW readable copy

The file (.nclog) uses the same sealed layout as the encrypted backups (backup_crypto):

    NCLOG | version | header length | header JSON | AES-256-GCM(payload)

The header (which log, how many entries, when, the key id or the scrypt parameters, the
salt, the nonce) is readable but authenticated: changing any byte of it, or of the
ciphertext, makes the file impossible to open. Older files derive their key from a
passphrase with scrypt (N=2**17, r=8, p=1, a 16-byte random salt per file). The payload
holds exactly the entries the Logs page showed to the person exporting (its filters and
its per-user limits), as the database holds them.
"""
import argparse
import csv
import getpass
import io
import json
import os
import sys
import unicodedata
from datetime import date, datetime

import backup_crypto as C
import backup_keys as K

MAGIC = b'NCLOG'
SUFFIX = '.nclog'
FORMAT = 'netcommand-log-export'
LOGS = ('Configuration log', 'Activity history')
PASSPHRASE_MIN = 8                   # the export password: at least 8 characters
PASSPHRASE_MAX = 1024
SCRYPT_N, SCRYPT_R, SCRYPT_P = K.SCRYPT_N, K.SCRYPT_R, K.SCRYPT_P
SALT_BYTES = K.SALT_BYTES
MAX_ENTRIES = 100000                 # one export; narrow the filter for more
_HEADER_FIELDS = {'format': str, 'alg': str, 'kdf': str, 'kdf_n': int, 'kdf_r': int,
                  'kdf_p': int, 'salt': str, 'nonce': str, 'created_utc': str, 'log': str,
                  'count': int}
# the columns of a readable copy, per log (any other field follows, sorted)
CSV_COLUMNS = {'Configuration log': ['created_at', 'device', 'action', 'status', 'details'],
               'Activity history': ['created_at', 'user_label', 'category', 'device',
                                    'device_ip', 'message', 'result', 'level', 'tags', 'detail']}


class LogExportError(C.BackupCryptoError):
    """A log export cannot be made or opened; the message is meant for the user."""


# ---------------------------------------------------------------- the passphrase
def check_passphrase(passphrase):
    """The passphrase as bytes (Unicode NFC), or LogExportError. Never in a message."""
    if not isinstance(passphrase, str):
        raise LogExportError('A password is required.')
    value = unicodedata.normalize('NFC', passphrase)
    if not PASSPHRASE_MIN <= len(value) <= PASSPHRASE_MAX:
        raise LogExportError(f'The password must be at least {PASSPHRASE_MIN} characters '
                             f'long.')
    return value.encode('utf-8')


def _derive(passphrase, salt, n, r, p):
    from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
    return Scrypt(salt=salt, length=C.KEY_BYTES, n=n, r=r, p=p).derive(
        check_passphrase(passphrase))


def _check_kdf(n, r, p):
    """Checked BEFORE scrypt runs: a changed header must not make it run for minutes."""
    if not (K.SCRYPT_N_RANGE[0] <= n <= K.SCRYPT_N_RANGE[1] and n & (n - 1) == 0
            and r == SCRYPT_R and p == SCRYPT_P):
        raise C.FormatError('The log export asks for unsupported scrypt parameters.')


# ---------------------------------------------------------------- making an export
def _jsonable(value):
    if isinstance(value, (datetime, date)):
        return value.isoformat()
    if isinstance(value, (bytes, bytearray)):
        return bytes(value).decode('utf-8', 'replace')
    return str(value)


def export_bytes(log, entries, passphrase, filters=None, exported_by=None, n=SCRYPT_N):
    """The bytes of an encrypted export of `entries` (a list of dicts, as the store
    returns them). Nothing is written. The passphrase is used once and not kept."""
    if log not in LOGS:
        raise LogExportError(f'Unknown log {log!r}.')
    entries = list(entries)
    if len(entries) > MAX_ENTRIES:
        raise LogExportError(f'This export would hold {len(entries)} entries; at most '
                             f'{MAX_ENTRIES} fit in one file. Narrow the search or the '
                             f'filters.')
    key_material = check_passphrase(passphrase)         # before any work: a clear error
    del key_material
    _check_kdf(n, SCRYPT_R, SCRYPT_P)
    created = C.utc_now_text()
    payload = json.dumps({'format': FORMAT, 'log': log, 'created_utc': created,
                          'exported_by': exported_by or '', 'filters': dict(filters or {}),
                          'count': len(entries), 'entries': entries},
                         ensure_ascii=False, sort_keys=True, default=_jsonable).encode('utf-8')
    if len(payload) > C.MAX_PLAINTEXT_BYTES:
        raise LogExportError('This export is too large for one file (more than 16 MiB). '
                             'Narrow the search or the filters.')
    salt = os.urandom(SALT_BYTES)
    header = {'format': FORMAT, 'alg': C.ALGORITHM, 'kdf': 'scrypt', 'kdf_n': n,
              'kdf_r': SCRYPT_R, 'kdf_p': SCRYPT_P, 'salt': C._b64(salt),
              'nonce': C._b64(os.urandom(C.NONCE_BYTES)), 'created_utc': created,
              'log': log, 'count': len(entries)}
    return C.seal(MAGIC, header, payload, _derive(passphrase, salt, n, SCRYPT_R, SCRYPT_P))


# ---------------------------------------------------------------- locked with NetCommand's key
KEY_PROTECTION = 'netcommand-key'
HKDF_INFO = b'NetCommand log export v1'
_KEY_HEADER_FIELDS = {'format': str, 'alg': str, 'protection': str, 'key_id': str,
                      'key_fingerprint': str, 'salt': str, 'nonce': str, 'created_utc': str,
                      'log': str, 'count': int}


def _file_key(backup_key, salt):
    """The per-file key: HKDF-SHA256 of the backup key (never used directly)."""
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.kdf.hkdf import HKDF
    return HKDF(algorithm=hashes.SHA256(), length=C.KEY_BYTES, salt=salt,
                info=HKDF_INFO).derive(C.check_key(backup_key))


def _payload(log, entries, filters, exported_by, created):
    payload = json.dumps({'format': FORMAT, 'log': log, 'created_utc': created,
                          'exported_by': exported_by or '', 'filters': dict(filters or {}),
                          'count': len(entries), 'entries': entries},
                         ensure_ascii=False, sort_keys=True, default=_jsonable).encode('utf-8')
    if len(payload) > C.MAX_PLAINTEXT_BYTES:
        raise LogExportError('This export is too large for one file (more than 16 MiB). '
                             'Narrow the search or the filters.')
    return payload


def lock_bytes(log, entries, backup_key, filters=None, exported_by=None):
    """The bytes of an export locked with NetCommand's backup key (backup_key: an object
    with .key_id and .key, as config.connect.load_backup_key returns). Nothing is written;
    no passphrase is asked."""
    if log not in LOGS:
        raise LogExportError(f'Unknown log {log!r}.')
    entries = list(entries)
    if len(entries) > MAX_ENTRIES:
        raise LogExportError(f'This export would hold {len(entries)} entries; at most '
                             f'{MAX_ENTRIES} fit in one file. Narrow the search or the '
                             f'filters.')
    created = C.utc_now_text()
    payload = _payload(log, entries, filters, exported_by, created)
    salt = os.urandom(SALT_BYTES)
    header = {'format': FORMAT, 'alg': C.ALGORITHM, 'protection': KEY_PROTECTION,
              'key_id': str(backup_key.key_id), 'key_fingerprint': C.fingerprint(backup_key.key),
              'salt': C._b64(salt), 'nonce': C._b64(os.urandom(C.NONCE_BYTES)),
              'created_utc': created, 'log': log, 'count': len(entries)}
    return C.seal(MAGIC, header, payload, _file_key(backup_key.key, salt))


def is_key_locked(header):
    return header.get('protection') == KEY_PROTECTION


def unlock_bytes(data, key_for):
    """(header, payload) of an export locked with NetCommand's key. key_for(key_id) returns
    that backup key (the keyring's key_for). LogExportError when this computer does not
    have the key, or when the file was changed or damaged."""
    header = read_header(data)
    if not is_key_locked(header):
        raise LogExportError('This export is locked with a password: unlock it with its '
                             'password (Logs page: Unlock export...).')
    _header, aad, ciphertext = C.parse(data, MAGIC, 'log export')
    try:
        key = key_for(header['key_id'])
    except C.UnknownKey:
        raise LogExportError(f'This export was locked with NetCommand key '
                             f'{header["key_id"]}, which this computer does not have. Import '
                             f'that key from its recovery file (python backup_keys.py '
                             f'import-recovery), then unlock again.') from None
    if C.fingerprint(key) != header['key_fingerprint']:
        raise LogExportError(f'This computer\'s key {header["key_id"]} is not the key the '
                             f'export was locked with, so it cannot be unlocked here.')
    salt = C._unb64(header['salt'], SALT_BYTES, 'salt')
    nonce = C._unb64(header['nonce'], C.NONCE_BYTES, 'nonce')
    try:
        plaintext = C.open_sealed(aad, ciphertext, _file_key(key, salt), nonce)
    except C.AuthenticationFailed:
        raise LogExportError('The log export could not be unlocked: the file was changed or '
                             'damaged.') from None
    return header, _check_payload(header, plaintext)


def _check_payload(header, plaintext):
    try:
        payload = json.loads(plaintext.decode('utf-8'))
    except (UnicodeError, ValueError, RecursionError):
        raise C.FormatError('The log export content is not valid.') from None
    if not isinstance(payload, dict) or payload.get('log') != header['log'] or \
            payload.get('count') != header['count'] or \
            not isinstance(payload.get('entries'), list) or \
            len(payload['entries']) != header['count']:
        raise C.FormatError('The log export content does not match its header.')
    return payload


def write_export(path, data):
    """Write a NEW file atomically (flushed and read back first). An existing file is
    never replaced: LogExportError."""
    try:
        K.write_new_file(path, data)
    except FileExistsError:
        raise LogExportError(f'{os.path.basename(path)} already exists. Choose a new file '
                             f'name: an export never replaces a file.') from None


# ---------------------------------------------------------------- opening an export
def read_header(data):
    """What the file says about itself (no passphrase needed; not proof until opened)."""
    header, _aad, _ciphertext = C.parse(data, MAGIC, 'log export')
    if is_key_locked(header):
        C.check_fields(header, _KEY_HEADER_FIELDS, 'log export')
        if header['format'] != FORMAT or header['alg'] != C.ALGORITHM or \
                not C.valid_fingerprint(header['key_fingerprint']):
            raise C.FormatError('The log export uses an unsupported format or algorithm.')
    else:
        C.check_fields(header, _HEADER_FIELDS, 'log export')
        if header['format'] != FORMAT or header['alg'] != C.ALGORITHM or \
                header['kdf'] != 'scrypt':
            raise C.FormatError('The log export uses an unsupported format or algorithm.')
    if header['log'] not in LOGS or header['count'] < 0:
        raise C.FormatError('The log export header is not valid.')
    return header


def open_export(data, passphrase):
    """(header, payload dict). LogExportError for a wrong passphrase or a changed or
    damaged file; FormatError for something that is not a NetCommand log export."""
    header = read_header(data)
    if is_key_locked(header):
        raise LogExportError('This export is locked with NetCommand\'s key, not a passphrase: '
                             'unlock it on the Logs page (Unlock export...).')
    _header, aad, ciphertext = C.parse(data, MAGIC, 'log export')
    _check_kdf(header['kdf_n'], header['kdf_r'], header['kdf_p'])
    salt = C._unb64(header['salt'], SALT_BYTES, 'salt')
    nonce = C._unb64(header['nonce'], C.NONCE_BYTES, 'nonce')
    key = _derive(passphrase, salt, header['kdf_n'], header['kdf_r'], header['kdf_p'])
    try:
        plaintext = C.open_sealed(aad, ciphertext, key, nonce)
    except C.AuthenticationFailed:
        raise LogExportError('Wrong password (or the file was changed or damaged). The export '
                             'stays locked.') from None
    try:
        payload = json.loads(plaintext.decode('utf-8'))
    except (UnicodeError, ValueError, RecursionError):
        raise C.FormatError('The log export content is not valid.') from None
    if not isinstance(payload, dict) or payload.get('log') != header['log'] or \
            payload.get('count') != header['count'] or \
            not isinstance(payload.get('entries'), list) or \
            len(payload['entries']) != header['count']:
        raise C.FormatError('The log export content does not match its header.')
    return header, payload


def to_csv(payload):
    """A readable CSV copy of an opened export (text)."""
    entries = payload['entries']
    columns = list(CSV_COLUMNS.get(payload['log'], []))
    extra = sorted({k for e in entries if isinstance(e, dict) for k in e} - set(columns)
                   - {'id'})
    out = io.StringIO()
    writer = csv.writer(out)
    writer.writerow(columns + extra)
    for e in entries:
        writer.writerow(['' if e.get(c) is None else e.get(c) for c in columns + extra])
    return out.getvalue()


# ---------------------------------------------------------------- the command line
def _read(path):
    try:
        with open(path, 'rb') as f:
            return f.read(C.MAX_FILE_BYTES + 1)
    except OSError as err:
        raise LogExportError(f'{path} could not be read ({err.strerror or type(err).__name__}).') \
            from None


def keyring_key_for():
    """key_for(key_id) from this Windows account's backup keyring (DPAPI)."""
    from config import connect
    return connect.load_backup_key().key_for


def unlock_readable(data, key_for, fmt='csv'):
    """(header, readable text) of an export locked with NetCommand's key."""
    header, payload = unlock_bytes(data, key_for)
    text = to_csv(payload) if fmt == 'csv' else \
        json.dumps(payload, ensure_ascii=False, indent=2, sort_keys=True)
    return header, text


def main(argv=None, ask=getpass.getpass, out=print, key_for=None):
    p = argparse.ArgumentParser(prog='python -m log_export',
                                description='Open (unlock) an encrypted NetCommand log export.')
    sub = p.add_subparsers(dest='command', required=True)
    info = sub.add_parser('info', help='show what the file says about itself')
    info.add_argument('file')
    for name in ('decrypt', 'unlock'):
        dec = sub.add_parser(name, help='write a NEW readable copy (a file locked with '
                                        'NetCommand\'s key needs nothing; an older file asks '
                                        'its passphrase)')
        dec.add_argument('file')
        dec.add_argument('--out', required=True, help='the new file to write (never replaced)')
        dec.add_argument('--format', choices=('csv', 'json'), default='csv')
    args = p.parse_args(argv)
    try:
        data = _read(args.file)
        if args.command == 'info':
            h = read_header(data)
            how = (f"locked with NetCommand key {h['key_id']}" if is_key_locked(h) else
                   'locked with a password')
            out(f"{h['log']}: {h['count']} entries, exported {h['created_utc']} "
                f"({h['alg']}, {how})")
            return 0
        if is_key_locked(read_header(data)):
            header, payload = unlock_bytes(data, key_for or keyring_key_for())
        else:
            header, payload = open_export(data, ask('Password: '))
        text = to_csv(payload) if args.format == 'csv' else \
            json.dumps(payload, ensure_ascii=False, indent=2, sort_keys=True)
        write_export(args.out, text.encode('utf-8'))
        out(f"Wrote {args.out}: {header['count']} entries of the {header['log']} "
            f"(READABLE, not encrypted: keep it safe and delete it when done).")
        return 0
    except C.BackupCryptoError as err:
        out(f'Refused: {err}')
        return 2
    except Exception as err:                       # e.g. the keyring is not set up here
        from config.connect import BackupKeyUnavailable
        if isinstance(err, BackupKeyUnavailable):
            out(f'Refused: {err}')
            return 2
        raise


if __name__ == '__main__':
    sys.exit(main())
