"""Check or export an encrypted configuration backup (.ncbak).

    python backup_tool.py verify FILE.ncbak
    python backup_tool.py export FILE.ncbak --to D:\\restore\\R1-config.txt

verify: checks the envelope, decrypts IN MEMORY with the keyring (backup_keys.py) and
        checks the recorded SHA-256 and size. Prints only the key id, device, time, size
        and SHA-256; never the configuration.
export: writes the decrypted configuration to the destination you name, after warning
        that it is PLAINTEXT and asking you to type EXPORT PLAINTEXT. The backup is
        decrypted and checked completely before anything is written; the file is written
        to a temporary name (.ncbak-export.*.partial in the destination folder), flushed
        and renamed, never over an existing file. A failed export removes that temporary
        file, or, if Windows will not let it be removed, prints its exact path so you can
        delete it. A crash or power loss DURING the write can leave it behind: delete any
        .ncbak-export.*.partial file you find. Delete the exported copy when done.

There is no migration of old .txt backups here yet (a later, separately approved step).
"""
import argparse
import os
import sys
import tempfile

import backup_crypto as C
import backup_keys as K

EXPORT_PHRASE = 'EXPORT PLAINTEXT'


def read_backup(path):
    try:
        size = os.path.getsize(path)
    except FileNotFoundError:
        raise C.FormatError('The backup file was not found.') from None
    if size > C.MAX_FILE_BYTES:
        raise C.FormatError('The backup is too large.')
    with open(path, 'rb') as f:
        return f.read(C.MAX_FILE_BYTES + 1)


def open_backup(path, keyring_path, protector):
    """(plaintext bytes, header), fully verified."""
    data = read_backup(path)
    C.read_backup_header(data)                    # structural checks before the keyring
    ring = K.Keyring.load(keyring_path)
    return C.decrypt_backup(data, ring.key_for(protector))


def describe(header):
    info = {k: header.get(k) for k in ('key_id', 'host', 'created_utc', 'plaintext_size',
                                       'plaintext_sha256')}
    info['identity'] = C.identity_of(header)       # value / 'unavailable' / 'not recorded'
    return info


def verify(path, keyring_path, protector):
    _plaintext, header = open_backup(path, keyring_path, protector)
    return describe(header)


def export(path, destination, keyring_path, protector, confirm):
    """confirm(): returns the typed confirmation text. Returns the description."""
    if not destination:
        raise C.BackupCryptoError('An explicit destination (--to) is required.')
    destination = os.path.abspath(destination)
    if os.path.lexists(destination):
        raise C.BackupCryptoError('The destination already exists; it is never overwritten. '
                                  'Choose a new file name.')
    folder = os.path.dirname(destination)
    if not os.path.isdir(folder):
        raise C.BackupCryptoError('The destination folder does not exist.')
    plaintext, header = open_backup(path, keyring_path, protector)    # verified first
    if confirm() != EXPORT_PHRASE:
        raise C.BackupCryptoError('Export cancelled: the confirmation was not typed exactly. '
                                  'Nothing was written.')
    # The plaintext goes to a temporary file in the destination folder and gets its final
    # name only once it is complete and flushed, never over an existing file.
    fd, temp = tempfile.mkstemp(prefix='.ncbak-export.', suffix='.partial', dir=folder)
    try:
        with os.fdopen(fd, 'wb') as f:
            f.write(plaintext)
            f.flush()
            os.fsync(f.fileno())
        K._place_new(temp, destination)
    except FileExistsError:
        _remove_partial(temp, 'The destination appeared meanwhile; it was not overwritten.')
    except OSError as err:
        _remove_partial(temp, f'The plaintext file could not be written '
                              f'({err.strerror or type(err).__name__}).')
    except BaseException:                         # interrupted (Ctrl+C) or any other error
        _remove_partial(temp, 'The export was interrupted.', reraise=True)
        raise
    return describe(header)


class ExportCleanupError(C.BackupCryptoError):
    """An export failed AND its temporary plaintext file could not be removed: the
    message names that file so the user can delete it."""


def _remove_partial(temp, reason, reraise=False):
    """Remove the temporary plaintext file of a failed export. If it cannot be removed,
    say exactly where it is (ExportCleanupError). Otherwise raise BackupCryptoError(reason),
    or return when reraise=True (the caller re-raises the original exception)."""
    try:
        os.remove(temp)
    except FileNotFoundError:
        pass
    except OSError:
        raise ExportCleanupError(
            f'{reason} A temporary file holding PART OF THE PLAINTEXT configuration could not '
            f'be removed: {temp}  Delete this file yourself now.') from None
    if not reraise:
        raise C.BackupCryptoError(f'{reason} Nothing was written.')


def _show(out, info):
    out(f"  key {info['key_id']}, device {info.get('host') or 'unknown'}, created "
        f"{info['created_utc']}, {info['plaintext_size']} bytes, SHA-256 "
        f"{info['plaintext_sha256']}")
    ident = info['identity']
    out(f"  identity: hostname {ident['hostname']}, platform {ident['platform']}, serial "
        f"{ident['serial']}, IOS version {ident['ios_version']}")


def main(argv=None, protector=None, ask=None, out=print):
    p = argparse.ArgumentParser(prog='python backup_tool.py', description=__doc__,
                                formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = p.add_subparsers(dest='command', required=True)
    for name in ('verify', 'export'):
        s = sub.add_parser(name)
        s.add_argument('file', help='the encrypted backup (.ncbak)')
        s.add_argument('--keyring', help='the keyring file (default: the usual location)')
        if name == 'export':
            s.add_argument('--to', required=True, help='where to write the PLAINTEXT copy')
    args = p.parse_args(argv)
    ask = ask or input
    try:
        keyring = args.keyring or K.default_keyring_path()
        protector = protector or K.DpapiProtector()
        if args.command == 'verify':
            info = verify(args.file, keyring, protector)
            out('OK: the backup is authentic, decrypts with the keyring, and matches its '
                'recorded SHA-256 and size.')
            _show(out, info)
            return 0

        def confirm():
            out('WARNING: the exported file is the device configuration in PLAINTEXT. It '
                'may contain password hashes, keys and community strings. Store it safely '
                'and delete it when you no longer need it.')
            return ask(f'Type {EXPORT_PHRASE} to write it to {os.path.abspath(args.to)}: ')
        info = export(args.file, args.to, keyring, protector, confirm)
        out(f'Exported (plaintext) to {os.path.abspath(args.to)}.')
        _show(out, info)
        return 0
    except (C.BackupCryptoError, OSError) as err:
        text = str(err) if isinstance(err, C.BackupCryptoError) else \
            f'{type(err).__name__}: {err.strerror or "file error"}'
        out(f'Refused: {text}')
        return 1
    except (KeyboardInterrupt, EOFError):
        out('Cancelled. Nothing was written.')
        return 1


if __name__ == '__main__':
    sys.exit(main())
