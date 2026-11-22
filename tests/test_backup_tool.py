"""Phase 3A: backup_tool.py verify / export. Synthetic configurations, throwaway keys, a
fake DPAPI provider and temporary folders only."""
import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import backup_crypto as C  # noqa: E402
import backup_keys as K  # noqa: E402
import backup_tool as T  # noqa: E402
from test_backup_keys import FakeProtector, N, PHRASE  # noqa: E402,F401  (private_locations)
from test_backup_keys import private_locations  # noqa: E402,F401

CONFIG = (b'Building configuration...\r\n!\r\nhostname SYNTH-R1\r\n'
          b'enable secret 9 SynthHash-Not-Real\r\n!\r\nend\r\n')


@pytest.fixture
def lab(tmp_path):
    ring = str(tmp_path / 'keys' / 'backup-keyring.json')
    K.init(ring, str(tmp_path / 'offline' / 'b1.ncrecovery'), PHRASE, FakeProtector(), n=N)
    key_id, key = K.Keyring.load(ring).active(FakeProtector())
    backup = tmp_path / 'backups' / '10.0.0.2_20261122_150000.ncbak'
    backup.parent.mkdir()
    backup.write_bytes(C.encrypt_backup(CONFIG, key, key_id, {'host': '10.0.0.2',
                                                              'source': 'show running-config',
                                                              'privilege': 15}))
    out = tmp_path / 'restore'
    out.mkdir()
    return {'ring': ring, 'backup': str(backup), 'out': out, 'dir': tmp_path}


def run(argv, lab, answers=(), protector=None):
    printed, answers = [], list(answers)
    code = T.main(argv + ['--keyring', lab['ring']], protector=protector or FakeProtector(),
                  ask=lambda prompt: (printed.append(prompt), answers.pop(0))[1],
                  out=printed.append)
    return code, '\n'.join(printed)


def leftovers(folder):
    return [p.name for p in folder.rglob('*.partial')]


# ---------------------------------------------------------------- verify
def test_verify_checks_everything_and_never_prints_the_configuration(lab):
    code, text = run(['verify', lab['backup']], lab)
    assert code == 0 and text.startswith('OK: the backup is authentic')
    assert 'key b1, device 10.0.0.2' in text and f'{len(CONFIG)} bytes' in text
    assert 'SYNTH-R1' not in text and 'SynthHash' not in text
    assert 'hostname SYNTH-R1' not in text              # no configuration line is printed
    assert 'identity: hostname not recorded' in text    # a pre-4A backup: no identity


@pytest.mark.parametrize('damage', ['flip', 'truncate', 'signature'])
def test_verify_refuses_damaged_backups(lab, damage):
    data = bytearray(open(lab['backup'], 'rb').read())
    if damage == 'flip':
        data[-5] ^= 1
    elif damage == 'truncate':
        data = data[:-3]
    else:
        data[:5] = b'XXXXX'
    open(lab['backup'], 'wb').write(bytes(data))
    code, text = run(['verify', lab['backup']], lab)
    assert code == 1 and text.startswith('Refused:') and 'SYNTH' not in text


def test_verify_with_another_account_or_without_a_keyring(lab, tmp_path):
    code, text = run(['verify', lab['backup']], lab, protector=FakeProtector(account='B'))
    assert code == 1 and 'DPAPI' in text
    os.remove(lab['ring'])
    code, text = run(['verify', lab['backup']], lab)
    assert code == 1 and 'No backup keyring was found' in text


def test_verify_refuses_a_backup_made_with_an_unknown_key(lab, tmp_path):
    other = tmp_path / 'other.ncbak'
    other.write_bytes(C.encrypt_backup(CONFIG, os.urandom(32), 'b9'))
    code, text = run(['verify', str(other)], lab)
    assert code == 1 and 'b9 is not in this keyring' in text


# ---------------------------------------------------------------- export
def test_export_warns_asks_and_writes_the_exact_plaintext(lab):
    dest = lab['out'] / 'r1-config.txt'
    code, text = run(['export', lab['backup'], '--to', str(dest)], lab, [T.EXPORT_PHRASE])
    assert code == 0 and dest.read_bytes() == CONFIG
    assert 'PLAINTEXT' in text and 'Type EXPORT PLAINTEXT' in text
    assert 'SYNTH-R1' not in text and 'SynthHash' not in text           # never printed
    assert leftovers(lab['dir']) == []


@pytest.mark.parametrize('answer', ['', 'yes', 'export plaintext', 'EXPORT PLAINTEXT '])
def test_export_needs_the_exact_confirmation(lab, answer):
    dest = lab['out'] / 'r1-config.txt'
    code, text = run(['export', lab['backup'], '--to', str(dest)], lab, [answer])
    assert code == 1 and 'cancelled' in text and not dest.exists()
    assert leftovers(lab['dir']) == []


def test_export_never_overwrites(lab):
    dest = lab['out'] / 'existing.txt'
    dest.write_bytes(b'something the user keeps')
    code, text = run(['export', lab['backup'], '--to', str(dest)], lab, [T.EXPORT_PHRASE])
    assert code == 1 and 'never overwritten' in text
    assert dest.read_bytes() == b'something the user keeps'


def test_export_requires_a_destination_and_an_existing_folder(lab):
    with pytest.raises(SystemExit):
        T.main(['export', lab['backup'], '--keyring', lab['ring']], protector=FakeProtector(),
               ask=lambda p: T.EXPORT_PHRASE, out=lambda *a: None)
    code, text = run(['export', lab['backup'], '--to', str(lab['out'] / 'missing' / 'x.txt')],
                     lab, [T.EXPORT_PHRASE])
    assert code == 1 and 'folder does not exist' in text


def test_a_damaged_backup_is_never_exported(lab):
    data = bytearray(open(lab['backup'], 'rb').read())
    data[-1] ^= 1
    open(lab['backup'], 'wb').write(bytes(data))
    dest = lab['out'] / 'r1-config.txt'
    code, text = run(['export', lab['backup'], '--to', str(dest)], lab, [T.EXPORT_PHRASE])
    assert code == 1 and not dest.exists() and 'Type EXPORT' not in text   # refused before asking


def test_a_failed_export_write_leaves_no_partial_plaintext(lab, monkeypatch):
    def broken_fsync(fd):
        raise OSError(28, 'No space left on device')
    monkeypatch.setattr(T.os, 'fsync', broken_fsync)
    dest = lab['out'] / 'r1-config.txt'
    code, text = run(['export', lab['backup'], '--to', str(dest)], lab, [T.EXPORT_PHRASE])
    assert code == 1 and not dest.exists() and list(lab['out'].iterdir()) == []


def test_an_export_destination_that_appears_meanwhile_is_not_overwritten(lab, monkeypatch):
    dest = lab['out'] / 'r1-config.txt'

    def someone_creates_it():
        dest.write_bytes(b'created by another program')
        return T.EXPORT_PHRASE
    with pytest.raises(C.BackupCryptoError):
        T.export(lab['backup'], str(dest), lab['ring'], FakeProtector(), someone_creates_it)
    assert dest.read_bytes() == b'created by another program'
    assert leftovers(lab['dir']) == []


# ---------------------------------------------------------------- review fix M4: cleanup
def partials(folder):
    return sorted(str(p) for p in folder.glob('.ncbak-export.*.partial'))


def test_a_temporary_file_that_cannot_be_removed_is_named_with_an_instruction(lab, monkeypatch):
    dest = lab['out'] / 'r1-config.txt'

    def no_space(fd):
        raise OSError(28, 'No space left on device')

    def locked(path):
        raise PermissionError(32, 'The process cannot access the file')
    monkeypatch.setattr(T.os, 'fsync', no_space)
    monkeypatch.setattr(T.os, 'remove', locked)
    code, text = run(['export', lab['backup'], '--to', str(dest)], lab, [T.EXPORT_PHRASE])
    monkeypatch.undo()
    left = partials(lab['out'])
    assert code == 1 and len(left) == 1 and not dest.exists()
    assert 'could not be written (No space left on device)' in text
    assert f'could not be removed: {left[0]}' in text and 'Delete this file yourself now' in text
    assert 'PART OF THE PLAINTEXT' in text and 'SYNTH-R1' not in text   # never the content
    os.remove(left[0])


def test_cleanup_failure_after_the_destination_appeared_is_reported(lab, monkeypatch):
    dest = lab['out'] / 'r1-config.txt'

    def someone_creates_it():
        dest.write_bytes(b'created by another program')
        return T.EXPORT_PHRASE

    def locked(path):
        raise PermissionError(32, 'The process cannot access the file')
    monkeypatch.setattr(T.os, 'remove', locked)
    with pytest.raises(T.ExportCleanupError) as err:
        T.export(lab['backup'], str(dest), lab['ring'], FakeProtector(), someone_creates_it)
    monkeypatch.undo()
    left = partials(lab['out'])
    assert len(left) == 1 and left[0] in str(err.value)
    assert dest.read_bytes() == b'created by another program'
    os.remove(left[0])


def test_an_interrupted_export_removes_its_temporary_file(lab, monkeypatch):
    dest = lab['out'] / 'r1-config.txt'

    def interrupted(fd):
        raise KeyboardInterrupt
    monkeypatch.setattr(T.os, 'fsync', interrupted)
    with pytest.raises(KeyboardInterrupt):
        T.export(lab['backup'], str(dest), lab['ring'], FakeProtector(), lambda: T.EXPORT_PHRASE)
    code, text = run(['export', lab['backup'], '--to', str(dest)], lab, [T.EXPORT_PHRASE])
    assert code == 1 and text.endswith('Cancelled. Nothing was written.')
    assert partials(lab['out']) == [] and not dest.exists()


def test_an_interrupted_export_whose_temporary_file_stays_is_named(lab, monkeypatch):
    dest = lab['out'] / 'r1-config.txt'

    def interrupted(fd):
        raise KeyboardInterrupt

    def locked(path):
        raise PermissionError(32, 'The process cannot access the file')
    monkeypatch.setattr(T.os, 'fsync', interrupted)
    monkeypatch.setattr(T.os, 'remove', locked)
    code, text = run(['export', lab['backup'], '--to', str(dest)], lab, [T.EXPORT_PHRASE])
    monkeypatch.undo()
    left = partials(lab['out'])
    assert code == 1 and len(left) == 1 and 'The export was interrupted.' in text
    assert left[0] in text and 'Delete this file yourself now' in text
    os.remove(left[0])


def test_a_successful_export_leaves_only_the_destination(lab):
    dest = lab['out'] / 'r1-config.txt'
    assert run(['export', lab['backup'], '--to', str(dest)], lab, [T.EXPORT_PHRASE])[0] == 0
    assert sorted(p.name for p in lab['out'].iterdir()) == ['r1-config.txt']


# ---------------------------------------------------------------- review fix M1 (command line)
def test_a_deeply_nested_backup_header_is_refused_without_a_traceback(lab, tmp_path):
    raw = b'[' * 4000
    bad = tmp_path / 'nested.ncbak'
    bad.write_bytes(C.MAGIC + bytes([1]) + len(raw).to_bytes(4, 'big') + raw + b'\x00' * 16)
    code, text = run(['verify', str(bad)], lab)
    assert code == 1 and text.startswith('Refused:') and 'not valid JSON' in text


def test_there_is_no_migration_command_yet(lab):
    with pytest.raises(SystemExit):
        T.main(['migrate', lab['backup']], protector=FakeProtector(), out=lambda *a: None)
