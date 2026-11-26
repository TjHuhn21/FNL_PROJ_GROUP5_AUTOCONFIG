"""Encrypted export of the Logs page, protected by a passphrase.

    data = export_bytes(log, entries, passphrase, filters=..., exported_by=...)  # bytes only
    write_export(path, data)            # a NEW file; an existing file is never replaced
    header, payload = open_export(data, passphrase)

From a terminal (the passphrase is asked for without echo, never on the command line):

    python -m log_export info FILE                     what the file says about itself
    python -m log_export decrypt FILE --out OUT [--format csv|json]
                                                       writes a NEW readable copy

The file (.nclog) uses the same sealed layout as the encrypted backups (backup_crypto):

    NCLOG | version | header length | header JSON | AES-256-GCM(payload)

The header (which log, how many entries, when, the scrypt salt and parameters, the nonce)
is readable without the passphrase but authenticated: changing any byte of it, or of the
ciphertext, makes the file impossible to open. The key is derived from the passphrase
with scrypt (N=2**17, r=8, p=1, a 16-byte random salt per file), the same parameters as
the backup recovery files; a passphrase of at least 12 characters is required.

The passphrase is not stored anywhere: without it the export cannot be opened, by anyone,
NetCommand included. The payload holds exactly the entries the Logs page showed to the
person exporting (its filters and its per-user limits), as the database holds them.
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
PASSPHRASE_MIN = 12
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
        raise LogExportError('A passphrase is required.')
    value = unicodedata.normalize('NFC', passphrase)
    if not PASSPHRASE_MIN <= len(value) <= PASSPHRASE_MAX:
        raise LogExportError(f'The passphrase must be at least {PASSPHRASE_MIN} characters '
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
    C.check_fields(header, _HEADER_FIELDS, 'log export')
    if header['format'] != FORMAT or header['alg'] != C.ALGORITHM or header['kdf'] != 'scrypt':
        raise C.FormatError('The log export uses an unsupported format or algorithm.')
    if header['log'] not in LOGS or header['count'] < 0:
        raise C.FormatError('The log export header is not valid.')
    return header


def open_export(data, passphrase):
    """(header, payload dict). LogExportError for a wrong passphrase or a changed or
    damaged file; FormatError for something that is not a NetCommand log export."""
    header = read_header(data)
    _header, aad, ciphertext = C.parse(data, MAGIC, 'log export')
    _check_kdf(header['kdf_n'], header['kdf_r'], header['kdf_p'])
    salt = C._unb64(header['salt'], SALT_BYTES, 'salt')
    nonce = C._unb64(header['nonce'], C.NONCE_BYTES, 'nonce')
    key = _derive(passphrase, salt, header['kdf_n'], header['kdf_r'], header['kdf_p'])
    try:
        plaintext = C.open_sealed(aad, ciphertext, key, nonce)
    except C.AuthenticationFailed:
        raise LogExportError('The log export could not be opened: the passphrase is wrong, '
                             'or the file was changed or damaged.') from None
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


def main(argv=None, ask=getpass.getpass, out=print):
    p = argparse.ArgumentParser(prog='python -m log_export',
                                description='Open an encrypted NetCommand log export.')
    sub = p.add_subparsers(dest='command', required=True)
    info = sub.add_parser('info', help='show what the file says about itself (no passphrase)')
    info.add_argument('file')
    dec = sub.add_parser('decrypt', help='write a NEW readable copy (asks the passphrase)')
    dec.add_argument('file')
    dec.add_argument('--out', required=True, help='the new file to write (never replaced)')
    dec.add_argument('--format', choices=('csv', 'json'), default='csv')
    args = p.parse_args(argv)
    try:
        data = _read(args.file)
        if args.command == 'info':
            h = read_header(data)
            out(f"{h['log']}: {h['count']} entries, exported {h['created_utc']} "
                f"(encrypted, {h['alg']}; the passphrase is needed to read it)")
            return 0
        header, payload = open_export(data, ask('Passphrase: '))
        text = to_csv(payload) if args.format == 'csv' else \
            json.dumps(payload, ensure_ascii=False, indent=2, sort_keys=True)
        write_export(args.out, text.encode('utf-8'))
        out(f"Wrote {args.out}: {header['count']} entries of the {header['log']} "
            f"(READABLE, not encrypted: keep it safe and delete it when done).")
        return 0
    except C.BackupCryptoError as err:
        out(f'Refused: {err}')
        return 2


if __name__ == '__main__':
    sys.exit(main())
