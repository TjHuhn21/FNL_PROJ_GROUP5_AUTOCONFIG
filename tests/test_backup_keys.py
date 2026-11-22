"""Phase 3A: backup keys (backup_keys.py): the DPAPI keyring, recovery files, init /
verify-recovery / import-recovery / rotate, and the command line.

Offline tests use a FAKE DPAPI provider. The real Windows DPAPI is exercised only on
Windows, with throwaway random keys in temporary folders. The real keyring location
(%LOCALAPPDATA%\\NetCommand) is never used: every test points it at a temporary folder."""
import base64
import json
import os
import re
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import backup_crypto as C  # noqa: E402
import backup_keys as K  # noqa: E402

N = 2 ** 14                                     # fast scrypt for tests (production: 2**17)
PHRASE = 'synthetic recovery phrase 1'
OTHER_PHRASE = 'synthetic recovery phrase 2'


class FakeProtector:
    """Stands in for DPAPI: a blob only `account` can open; failures on request."""

    def __init__(self, account='A', fail_protect=False, fail_unprotect=False, name='test-fake'):
        self.account, self.name = account, name
        self.fail_protect, self.fail_unprotect = fail_protect, fail_unprotect

    def protect(self, data):
        if self.fail_protect:
            raise K.KeyStoreError('Windows DPAPI could not protect the backup key (error 5).')
        return f'FAKE:{self.account}:'.encode() + bytes(b ^ 0xA5 for b in data)

    def unprotect(self, blob):
        prefix = f'FAKE:{self.account}:'.encode()
        if self.fail_unprotect or not blob.startswith(prefix):
            raise K.KeyStoreError('Windows DPAPI could not open the backup key for this '
                                  'Windows account (error 13).')
        return bytes(b ^ 0xA5 for b in blob[len(prefix):])


@pytest.fixture(autouse=True)
def private_locations(tmp_path, monkeypatch):
    """Nothing may ever reach the real %LOCALAPPDATA%\\NetCommand keyring."""
    monkeypatch.setenv('LOCALAPPDATA', str(tmp_path / 'localappdata'))
    monkeypatch.delenv(K.KEYRING_VARIABLE, raising=False)


@pytest.fixture
def paths(tmp_path):
    return {'ring': str(tmp_path / 'keys' / 'backup-keyring.json'),
            'rec1': str(tmp_path / 'offline' / 'b1.ncrecovery'),
            'rec2': str(tmp_path / 'offline' / 'b2.ncrecovery'),
            'dir': tmp_path}


def make(paths, protector=None):
    return K.init(paths['ring'], paths['rec1'], PHRASE, protector or FakeProtector(), n=N)


def ring_bytes(paths):
    with open(paths['ring'], 'rb') as f:
        return f.read()


def leftovers(folder):
    return [p.name for p in folder.rglob('*.partial')]


# ================================================================ init
def test_init_creates_a_keyring_and_a_verified_recovery_file(paths):
    info = make(paths)
    assert info['key_id'] == 'b1' and C.valid_fingerprint(info['fingerprint'])
    ring = K.Keyring.load(paths['ring'])
    assert ring.active_key_id == 'b1' and len(ring.data['keys']) == 1
    entry = ring.entry('b1')
    assert entry['fingerprint'] == info['fingerprint'] and entry['protection'] == 'test-fake'
    key = ring.key('b1', FakeProtector())
    assert C.fingerprint(key) == info['fingerprint']
    text = ring_bytes(paths).decode()
    assert key.hex() not in text and base64.b64encode(key).decode() not in text   # only the blob
    kid, recovered, _ = K.read_recovery(paths['rec1'], PHRASE)
    assert kid == 'b1' and recovered == key
    assert K.verify_recovery(paths['ring'], paths['rec1'], PHRASE, FakeProtector())['key_id'] == 'b1'
    assert leftovers(paths['dir']) == []


def test_init_never_replaces_an_existing_keyring(paths):
    make(paths)
    before = ring_bytes(paths)
    with pytest.raises(K.KeyStoreError) as err:
        K.init(paths['ring'], paths['rec2'], PHRASE, FakeProtector(), n=N)
    assert 'never replaces it' in str(err.value)
    assert ring_bytes(paths) == before and not os.path.exists(paths['rec2'])


@pytest.mark.parametrize('content', [b'', b'garbage', b'{"format": "x"}'])
def test_init_refuses_an_unreadable_keyring_instead_of_replacing_it(paths, content):
    os.makedirs(os.path.dirname(paths['ring']))
    with open(paths['ring'], 'wb') as f:
        f.write(content)
    with pytest.raises(K.KeyStoreError):
        make(paths)
    assert ring_bytes(paths) == content and not os.path.exists(paths['rec1'])


def test_init_never_overwrites_a_recovery_file_without_confirmation(paths):
    older = K.make_recovery('b1', os.urandom(32), PHRASE, n=N)      # a key no keyring has
    os.makedirs(os.path.dirname(paths['rec1']))
    with open(paths['rec1'], 'wb') as f:
        f.write(older)
    with pytest.raises(K.RecoveryError) as err:
        make(paths)
    assert '--confirm-overwrite-recovery' in str(err.value)
    assert not os.path.exists(paths['ring'])
    with open(paths['rec1'], 'rb') as f:
        assert f.read() == older
    info = K.init(paths['ring'], paths['rec1'], PHRASE, FakeProtector(), overwrite_recovery=True,
                  n=N)
    assert K.read_recovery(paths['rec1'], PHRASE)[1] == \
        K.Keyring.load(paths['ring']).key('b1', FakeProtector())
    assert info['key_id'] == 'b1' and leftovers(paths['dir']) == []


@pytest.mark.parametrize('content', [b'an older recovery file', b'', b'NCRCV\x01garbage'])
def test_a_file_that_is_not_a_recovery_file_is_never_replaced(paths, content):
    os.makedirs(os.path.dirname(paths['rec1']))
    with open(paths['rec1'], 'wb') as f:
        f.write(content)
    with pytest.raises(K.RecoveryError) as err:
        K.init(paths['ring'], paths['rec1'], PHRASE, FakeProtector(), overwrite_recovery=True,
               n=N)
    assert 'not a recognisable NetCommand recovery file' in str(err.value)
    assert open(paths['rec1'], 'rb').read() == content and not os.path.exists(paths['ring'])
    assert leftovers(paths['dir']) == []


def test_init_with_a_dpapi_failure_writes_nothing(paths):
    with pytest.raises(K.KeyStoreError):
        make(paths, FakeProtector(fail_protect=True))
    assert not os.path.exists(paths['ring']) and not os.path.exists(paths['rec1'])
    assert leftovers(paths['dir']) == []


def test_a_failed_keyring_write_removes_the_new_recovery_file(paths, monkeypatch):
    real = K.write_new_file

    def fail_for_keyring(path, data):
        if path == paths['ring']:
            raise OSError(28, 'No space left on device')
        return real(path, data)
    monkeypatch.setattr(K, 'write_new_file', fail_for_keyring)
    with pytest.raises(OSError):
        make(paths)
    assert not os.path.exists(paths['rec1']) and not os.path.exists(paths['ring'])


def test_a_keyring_that_does_not_open_after_writing_is_removed_with_its_recovery(paths,
                                                                                   monkeypatch):
    def broken_load(path):
        raise K.KeyStoreError('simulated')
    monkeypatch.setattr(K.Keyring, 'load', staticmethod(broken_load))
    with pytest.raises(K.KeyStoreError):
        make(paths)
    assert not os.path.exists(paths['ring']) and not os.path.exists(paths['rec1'])


# ================================================================ recovery files
def test_a_wrong_passphrase_is_refused(paths):
    make(paths)
    with pytest.raises(K.RecoveryError) as err:
        K.read_recovery(paths['rec1'], OTHER_PHRASE)
    assert 'passphrase is wrong' in str(err.value)


def test_recovery_files_use_fresh_salt_and_nonce_and_never_store_the_passphrase():
    key = os.urandom(32)
    a, b = K.make_recovery('b1', key, PHRASE, n=N), K.make_recovery('b1', key, PHRASE, n=N)
    ha, hb = C.parse(a, K.RECOVERY_MAGIC)[0], C.parse(b, K.RECOVERY_MAGIC)[0]
    assert ha['salt'] != hb['salt'] and ha['nonce'] != hb['nonce'] and a != b
    assert (ha['kdf'], ha['kdf_n'], ha['kdf_r'], ha['kdf_p']) == ('scrypt', N, 8, 1)
    assert len(C._unb64(ha['salt'], 16, 'salt')) == 16
    for data in (a, b):
        assert PHRASE.encode() not in data and key not in data and key.hex().encode() not in data
    assert K.open_recovery(a, PHRASE)[1] == key == K.open_recovery(b, PHRASE)[1]


def test_production_scrypt_parameters():
    assert (K.SCRYPT_N, K.SCRYPT_R, K.SCRYPT_P, K.SALT_BYTES) == (2 ** 17, 8, 1, 16)


def _reseal(data, change):
    """Change a recovery file's header, keeping everything else (the tag no longer fits)."""
    header, aad, body = C.parse(data, K.RECOVERY_MAGIC)
    change(header)
    raw = json.dumps(header, sort_keys=True, separators=(',', ':')).encode()
    return K.RECOVERY_MAGIC + bytes([1]) + len(raw).to_bytes(4, 'big') + raw + body


@pytest.mark.parametrize('change, error', [
    (lambda h: h.update(key_id='b2'), K.RecoveryError),                 # authenticated
    (lambda h: h.update(kdf_n=2 ** 15), K.RecoveryError),               # KDF params authenticated
    (lambda h: h.update(salt=C._b64(os.urandom(16))), K.RecoveryError),
    (lambda h: h.update(kdf_n=2 ** 21), C.FormatError),                 # refused before scrypt
    (lambda h: h.update(kdf_n=3000), C.FormatError),
    (lambda h: h.update(kdf_r=1), C.FormatError),
    (lambda h: h.update(kdf='pbkdf2'), C.FormatError),
    (lambda h: h.pop('salt'), C.FormatError),
])
def test_changed_recovery_headers_are_refused(change, error):
    data = K.make_recovery('b1', os.urandom(32), PHRASE, n=N)
    with pytest.raises(error):
        K.open_recovery(_reseal(data, change), PHRASE)


def test_a_recovery_file_whose_key_does_not_match_its_fingerprint_is_refused():
    key, salt = os.urandom(32), os.urandom(16)
    header = {'format': 'ncrecovery', 'alg': C.ALGORITHM, 'kdf': 'scrypt', 'kdf_n': N,
              'kdf_r': 8, 'kdf_p': 1, 'salt': C._b64(salt), 'nonce': C._b64(os.urandom(12)),
              'key_id': 'b1', 'fingerprint': C.fingerprint(os.urandom(32)),
              'created_utc': C.utc_now_text()}
    data = C.seal(K.RECOVERY_MAGIC, header, key, K._derive(PHRASE, salt, N, 8, 1))
    with pytest.raises(K.RecoveryError) as err:
        K.open_recovery(data, PHRASE)
    assert 'fingerprint' in str(err.value)


@pytest.mark.parametrize('phrase', ['', 'short', 'x' * 11, None, 12345678901234])
def test_weak_or_missing_passphrases_are_refused(phrase):
    with pytest.raises(K.RecoveryError):
        K.make_recovery('b1', os.urandom(32), phrase, n=N)


def test_the_passphrase_is_compared_after_unicode_normalisation():
    composed, decomposed = 'café synthetic phrase', 'café synthetic phrase'
    data = K.make_recovery('b1', os.urandom(32), composed, n=N)
    assert K.open_recovery(data, decomposed)[0] == 'b1'


def test_truncated_or_foreign_recovery_files_are_refused():
    data = K.make_recovery('b1', os.urandom(32), PHRASE, n=N)
    for bad in (data[:30], data[:-1], b'NCBAK' + data[5:], b'not a recovery file at all'):
        with pytest.raises(C.FormatError):
            K.open_recovery(bad, PHRASE)


def test_verify_recovery_refuses_a_file_for_another_key(paths, tmp_path):
    make(paths)
    other = str(tmp_path / 'other.ncrecovery')
    K.write_new_file(other, K.make_recovery('b1', os.urandom(32), PHRASE, n=N))
    with pytest.raises(K.RecoveryError):
        K.verify_recovery(paths['ring'], other, PHRASE, FakeProtector())


# ================================================================ keyring validation
def valid_ring(paths):
    make(paths)
    return json.loads(ring_bytes(paths))


@pytest.mark.parametrize('mutate', [
    lambda d: d.pop('format'), lambda d: d.update(extra=1), lambda d: d.update(version=2),
    lambda d: d.update(format='other'), lambda d: d.update(keys=[]),
    lambda d: d.update(active_key_id='b9'), lambda d: d['keys'].append(dict(d['keys'][0])),
    lambda d: d['keys'][0].update(fingerprint='zz'), lambda d: d['keys'][0].update(key_id='k1'),
    lambda d: d['keys'][0].pop('protected_key'), lambda d: d['keys'][0].update(extra='x'),
    lambda d: d['keys'][0].update(protected_key='not base64!'),
    lambda d: d['keys'][0].update(protected_key=''), lambda d: d['keys'][0].update(created_utc=5),
    lambda d: d.update(keys='b1'),
])
def test_malformed_keyrings_are_refused_and_left_unchanged(paths, mutate):
    data = valid_ring(paths)
    mutate(data)
    raw = json.dumps(data).encode()
    with open(paths['ring'], 'wb') as f:
        f.write(raw)
    with pytest.raises(K.KeyStoreError):
        K.Keyring.load(paths['ring'])
    with pytest.raises(K.KeyStoreError):
        K.rotate(paths['ring'], paths['rec2'], PHRASE, FakeProtector(), n=N)
    assert ring_bytes(paths) == raw and not os.path.exists(paths['rec2'])


@pytest.mark.parametrize('raw', [b'not json', b'[]', b'{"format":"a","format":"b"}', b'\xff'])
def test_unparseable_keyrings_are_refused(paths, raw):
    os.makedirs(os.path.dirname(paths['ring']))
    with open(paths['ring'], 'wb') as f:
        f.write(raw)
    with pytest.raises(K.KeyStoreError):
        K.Keyring.load(paths['ring'])


def test_a_missing_keyring_is_reported_never_created_silently(paths):
    with pytest.raises(K.KeyringMissing):
        K.Keyring.load(paths['ring'])
    with pytest.raises(K.KeyringMissing):
        K.rotate(paths['ring'], paths['rec2'], PHRASE, FakeProtector(), n=N)
    assert not os.path.exists(paths['ring'])


def test_a_key_that_does_not_match_its_fingerprint_is_refused(paths):
    data = valid_ring(paths)
    data['keys'][0]['fingerprint'] = C.fingerprint(os.urandom(32))
    with open(paths['ring'], 'w') as f:
        json.dump(data, f)
    with pytest.raises(K.KeyStoreError) as err:
        K.Keyring.load(paths['ring']).key('b1', FakeProtector())
    assert 'fingerprint' in str(err.value)


def test_another_windows_account_cannot_open_the_keyring(paths):
    make(paths)
    ring = K.Keyring.load(paths['ring'])
    with pytest.raises(K.KeyStoreError):
        ring.key('b1', FakeProtector(account='B'))
    with pytest.raises(K.KeyStoreError):
        ring.key('b1', FakeProtector(fail_unprotect=True))
    with pytest.raises(K.KeyStoreError):
        ring.key('b1', FakeProtector(name='dpapi-user'))       # protected another way
    with pytest.raises(C.UnknownKey):
        ring.key('b5', FakeProtector())


# ================================================================ rotation
def test_rotation_adds_a_key_and_keeps_old_backups_readable(paths):
    make(paths)
    ring = K.Keyring.load(paths['ring'])
    old_backup = C.encrypt_backup(b'hostname SYNTH-OLD\nend\n', ring.key('b1', FakeProtector()), 'b1')
    info = K.rotate(paths['ring'], paths['rec2'], OTHER_PHRASE, FakeProtector(), n=N)
    assert (info['key_id'], info['previous_key_id'], info['keys']) == ('b2', 'b1', 2)
    ring = K.Keyring.load(paths['ring'])
    assert ring.active_key_id == 'b2' and [k['key_id'] for k in ring.summary()] == ['b1', 'b2']
    plaintext, header = C.decrypt_backup(old_backup, ring.key_for(FakeProtector()))
    assert plaintext == b'hostname SYNTH-OLD\nend\n' and header['key_id'] == 'b1'
    key_id, key = ring.active(FakeProtector())
    new_backup = C.encrypt_backup(b'hostname SYNTH-NEW\nend\n', key, key_id)
    assert C.read_backup_header(new_backup)[0]['key_id'] == 'b2'
    assert C.decrypt_backup(new_backup, ring.key_for(FakeProtector()))[0].startswith(b'hostname SYNTH-NEW')
    # each key has its OWN verified recovery file
    assert K.verify_recovery(paths['ring'], paths['rec1'], PHRASE, FakeProtector())['key_id'] == 'b1'
    assert K.verify_recovery(paths['ring'], paths['rec2'], OTHER_PHRASE, FakeProtector())['active']
    assert K.rotate(paths['ring'], str(paths['dir'] / 'b3.ncrecovery'), PHRASE, FakeProtector(),
                    n=N)['key_id'] == 'b3'
    assert len(K.Keyring.load(paths['ring']).data['keys']) == 3          # none discarded


def test_rotation_refuses_when_the_current_keyring_cannot_be_opened(paths):
    make(paths)
    before = ring_bytes(paths)
    with pytest.raises(K.KeyStoreError):
        K.rotate(paths['ring'], paths['rec2'], PHRASE, FakeProtector(account='B'), n=N)
    assert ring_bytes(paths) == before and not os.path.exists(paths['rec2'])


def test_a_failed_rotation_leaves_the_keyring_and_removes_its_recovery_file(paths, monkeypatch):
    make(paths)
    before = ring_bytes(paths)

    def fail(path, data, expected):
        raise OSError(13, 'Access is denied')
    monkeypatch.setattr(K, 'replace_file', fail)
    with pytest.raises(OSError):
        K.rotate(paths['ring'], paths['rec2'], PHRASE, FakeProtector(), n=N)
    assert ring_bytes(paths) == before and not os.path.exists(paths['rec2'])


def test_a_keyring_changed_meanwhile_is_never_overwritten(paths):
    make(paths)
    before = ring_bytes(paths)
    with pytest.raises(K.KeyStoreError) as err:
        K.replace_file(paths['ring'], b'{}', expected=b'what it was before someone changed it')
    assert 'changed by something else' in str(err.value)
    assert ring_bytes(paths) == before and leftovers(paths['dir']) == []


# ================================================================ import-recovery
def test_import_restores_the_keys_after_windows_was_reinstalled(paths):
    """Windows reinstalled: the keyring is gone and DPAPI changed (account B)."""
    make(paths)
    K.rotate(paths['ring'], paths['rec2'], OTHER_PHRASE, FakeProtector(), n=N)
    old = K.Keyring.load(paths['ring'])
    backup = C.encrypt_backup(b'hostname SYNTH\nend\n', old.key('b1', FakeProtector()), 'b1')
    os.remove(paths['ring'])
    new = FakeProtector(account='B')
    first = K.import_recovery(paths['ring'], paths['rec2'], OTHER_PHRASE, new)
    assert (first['result'], first['active']) == ('created', True)
    second = K.import_recovery(paths['ring'], paths['rec1'], PHRASE, new)
    assert (second['result'], second['active']) == ('added', False)
    ring = K.Keyring.load(paths['ring'])
    assert ring.active_key_id == 'b2'
    assert C.decrypt_backup(backup, ring.key_for(new))[0] == b'hostname SYNTH\nend\n'


def test_import_repairs_a_key_this_account_can_no_longer_open(paths):
    make(paths)
    new = FakeProtector(account='B')
    with pytest.raises(K.KeyStoreError):
        K.Keyring.load(paths['ring']).key('b1', new)
    info = K.import_recovery(paths['ring'], paths['rec1'], PHRASE, new)
    assert info['result'] == 'repaired'
    assert C.valid_fingerprint(info['fingerprint'])
    K.Keyring.load(paths['ring']).key('b1', new)


def test_import_of_a_key_already_present_changes_nothing(paths):
    make(paths)
    before = ring_bytes(paths)
    info = K.import_recovery(paths['ring'], paths['rec1'], PHRASE, FakeProtector())
    assert info['result'] == 'already present' and ring_bytes(paths) == before


def test_import_refuses_a_different_key_with_the_same_id(paths, tmp_path):
    make(paths)
    before = ring_bytes(paths)
    other = str(tmp_path / 'other-b1.ncrecovery')
    K.write_new_file(other, K.make_recovery('b1', os.urandom(32), PHRASE, n=N))
    with pytest.raises(K.KeyStoreError):
        K.import_recovery(paths['ring'], other, PHRASE, FakeProtector())
    assert ring_bytes(paths) == before


def test_import_activate_makes_the_key_active(paths, tmp_path):
    make(paths)
    extra = str(tmp_path / 'b4.ncrecovery')
    K.write_new_file(extra, K.make_recovery('b4', os.urandom(32), PHRASE, n=N))
    assert K.import_recovery(paths['ring'], extra, PHRASE, FakeProtector(), activate=True)['active']
    assert K.Keyring.load(paths['ring']).active_key_id == 'b4'


def test_import_refuses_an_invalid_keyring_instead_of_replacing_it(paths):
    make(paths)
    with open(paths['ring'], 'wb') as f:
        f.write(b'{"damaged": true}')
    with pytest.raises(K.KeyStoreError):
        K.import_recovery(paths['ring'], paths['rec1'], PHRASE, FakeProtector())
    assert ring_bytes(paths) == b'{"damaged": true}'


def test_import_with_a_wrong_passphrase_changes_nothing(paths):
    make(paths)
    before = ring_bytes(paths)
    with pytest.raises(K.RecoveryError):
        K.import_recovery(paths['ring'], paths['rec1'], OTHER_PHRASE, FakeProtector('B'))
    assert ring_bytes(paths) == before


# ================================================================ atomic files
def test_write_new_file_never_overwrites_and_leaves_no_temporary(tmp_path):
    target = str(tmp_path / 'f.bin')
    K.write_new_file(target, b'first')
    with pytest.raises(FileExistsError):
        K.write_new_file(target, b'second')
    assert open(target, 'rb').read() == b'first' and leftovers(tmp_path) == []


def test_a_failed_write_leaves_neither_file_nor_temporary(tmp_path, monkeypatch):
    def broken_fsync(fd):
        raise OSError(28, 'No space left on device')
    monkeypatch.setattr(K.os, 'fsync', broken_fsync)
    with pytest.raises(OSError):
        K.write_new_file(str(tmp_path / 'f.bin'), b'data')
    assert list(tmp_path.iterdir()) == []


# ================================================================ default location
def test_the_keyring_lives_outside_the_project(monkeypatch, tmp_path):
    monkeypatch.setenv('LOCALAPPDATA', str(tmp_path / 'LocalAppData'))
    path = K.default_keyring_path()
    assert path == str(tmp_path / 'LocalAppData' / 'NetCommand' / 'keys' / 'backup-keyring.json')
    project = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    assert not os.path.abspath(path).startswith(project)
    monkeypatch.setenv(K.KEYRING_VARIABLE, str(tmp_path / 'elsewhere.json'))
    assert K.default_keyring_path() == str(tmp_path / 'elsewhere.json')
    with pytest.raises(K.KeyStoreError):
        K.default_keyring_path({})


# ================================================================ command line
def run_cli(argv, answers, protector=None):
    out, answers = [], list(answers)
    code = K.main(argv, protector=protector or FakeProtector(), ask=lambda prompt: answers.pop(0),
                  out=out.append)
    return code, '\n'.join(out)


def test_cli_init_status_verify_and_rotate_never_show_secrets(paths):
    ring = ['--keyring', paths['ring']]
    code, text = run_cli(['init', '--recovery', paths['rec1']] + ring, [PHRASE, PHRASE])
    assert code == 0 and 'Backup key b1 created' in text and 'verified by decrypting it' in text
    assert 'OFFLINE' in text
    code, status_text = run_cli(['status'] + ring, [])
    assert code == 0 and re.search(r'\bb1\s+active\s+fingerprint [0-9a-f]{32}', status_text)
    code, verify_text = run_cli(['verify-recovery', '--recovery', paths['rec1']] + ring, [PHRASE])
    assert code == 0 and verify_text.startswith('OK: the recovery file holds backup key b1')
    code, rotate_text = run_cli(['rotate', '--recovery', paths['rec2']] + ring,
                                [OTHER_PHRASE, OTHER_PHRASE])
    assert code == 0 and 'b2' in rotate_text and 'b1 and every older key were kept' in rotate_text
    key = K.Keyring.load(paths['ring']).key('b1', FakeProtector())
    everything = text + status_text + verify_text + rotate_text
    for secret in (PHRASE, OTHER_PHRASE, key.hex(), base64.b64encode(key).decode()):
        assert secret not in everything


def test_cli_refusals(paths):
    ring = ['--keyring', paths['ring']]
    code, text = run_cli(['init', '--recovery', paths['rec1']] + ring, [PHRASE, OTHER_PHRASE])
    assert code == 1 and 'different' in text and not os.path.exists(paths['ring'])
    code, text = run_cli(['init', '--recovery', paths['rec1']] + ring, ['short'])
    assert code == 1 and 'at least 12' in text
    code, text = run_cli(['status'] + ring, [])
    assert code == 1 and 'No backup keyring was found' in text
    run_cli(['init', '--recovery', paths['rec1']] + ring, [PHRASE, PHRASE])
    code, text = run_cli(['verify-recovery', '--recovery', paths['rec1']] + ring, [OTHER_PHRASE])
    assert code == 1 and 'passphrase is wrong' in text and OTHER_PHRASE not in text
    code, text = run_cli(['init', '--recovery', paths['rec2']] + ring, [PHRASE, PHRASE])
    assert code == 1 and 'never replaces it' in text


# ================================================================ real Windows DPAPI
windows = pytest.mark.skipif(os.name != 'nt', reason='Windows DPAPI is only on Windows')


@windows
def test_real_dpapi_round_trip_with_a_throwaway_key():
    protector = K.DpapiProtector()
    assert protector.flags == K.CRYPTPROTECT_UI_FORBIDDEN and not protector.flags & 0x4
    key = os.urandom(32)
    blob = protector.protect(key)
    assert blob != key and key not in blob
    assert protector.unprotect(blob) == key
    damaged = bytearray(blob)
    damaged[len(damaged) // 2] ^= 0xFF
    with pytest.raises(K.KeyStoreError) as err:
        protector.unprotect(bytes(damaged))
    assert 'DPAPI' in str(err.value) and key.hex() not in str(err.value)


@windows
def test_real_dpapi_keyring_init_rotate_and_backup(paths):
    protector = K.DpapiProtector()
    K.init(paths['ring'], paths['rec1'], PHRASE, protector, n=N)
    assert K.Keyring.load(paths['ring']).entry('b1')['protection'] == 'dpapi-user'
    K.rotate(paths['ring'], paths['rec2'], OTHER_PHRASE, protector, n=N)
    ring = K.Keyring.load(paths['ring'])
    key_id, key = ring.active(protector)
    data = C.encrypt_backup(b'hostname SYNTH-DPAPI\nend\n', key, key_id)
    assert C.decrypt_backup(data, ring.key_for(protector))[0] == b'hostname SYNTH-DPAPI\nend\n'
    assert K.verify_recovery(paths['ring'], paths['rec1'], PHRASE, protector)['key_id'] == 'b1'


# ================================================================ review fix M1: nested JSON
DEEP = [b'[' * 3000, b'{"a":' * 800 + b'1' + b'}' * 800, b'[' * 2000 + b']' * 2000]


@pytest.mark.parametrize('raw', DEEP, ids=['open-arrays', 'nested-objects', 'balanced-arrays'])
def test_deeply_nested_recovery_headers_are_refused_cleanly(raw):
    data = K.RECOVERY_MAGIC + bytes([1]) + len(raw).to_bytes(4, 'big') + raw + b'\x00' * 48
    with pytest.raises(C.FormatError):
        K.open_recovery(data, PHRASE)


@pytest.mark.parametrize('raw', [b'[' * 3000, b'{"a":' * 5000 + b'1' + b'}' * 5000,
                                 b'[' * 5000 + b']' * 5000, b'[' * 100000],
                         ids=['open', 'objects', 'balanced', 'huge'])
def test_deeply_nested_keyrings_are_refused_cleanly(paths, raw):
    os.makedirs(os.path.dirname(paths['ring']))
    with open(paths['ring'], 'wb') as f:
        f.write(raw)
    with pytest.raises(K.KeyStoreError) as err:
        K.Keyring.load(paths['ring'])
    assert 'not valid JSON' in str(err.value)
    code, text = run_cli(['status', '--keyring', paths['ring']], [])
    assert code == 1 and text.startswith('Refused:') and 'Traceback' not in text


def test_running_out_of_memory_while_parsing_is_a_clean_refusal(paths, monkeypatch):
    make(paths)

    def no_memory(*a, **k):
        raise MemoryError
    monkeypatch.setattr(K.json, 'loads', no_memory)
    with pytest.raises(K.KeyStoreError):
        K.Keyring.load(paths['ring'])
    monkeypatch.setattr(C.json, 'loads', no_memory)
    with pytest.raises(C.FormatError):
        K.read_recovery(paths['rec1'], PHRASE)


# ================================================================ review fix M2: scrypt limits
@pytest.mark.parametrize('n', [2 ** 14, 2 ** 15, 2 ** 16, 2 ** 17, 2 ** 18])
def test_supported_scrypt_cost_is_accepted(n):
    K._check_kdf(n, 8, 1)


@pytest.mark.parametrize('n, r, p', [
    (2 ** 13, 8, 1), (2 ** 19, 8, 1), (2 ** 20, 8, 1), (2 ** 30, 8, 1), (3 * 2 ** 14, 8, 1),
    (0, 8, 1), (2 ** 17, 4, 1), (2 ** 17, 16, 1), (2 ** 17, 8, 2), (2 ** 17, 8, 4), (2 ** 17, 8, 0),
])
def test_unsupported_scrypt_parameters_are_refused_before_scrypt_runs(monkeypatch, n, r, p):
    data = K.make_recovery('b1', os.urandom(32), PHRASE, n=N)
    forged = _reseal(data, lambda h: h.update(kdf_n=n, kdf_r=r, kdf_p=p))
    monkeypatch.setattr(K, '_derive', lambda *a: pytest.fail('scrypt ran'))
    with pytest.raises(C.FormatError) as err:
        K.open_recovery(forged, PHRASE)
    assert 'unsupported scrypt parameters' in str(err.value)


def test_recovery_files_are_never_written_with_unsupported_cost():
    for n in (2 ** 13, 2 ** 19):
        with pytest.raises(C.FormatError):
            K.make_recovery('b1', os.urandom(32), PHRASE, n=n)
    assert K.SCRYPT_N_RANGE == (2 ** 14, 2 ** 18) and K.SCRYPT_N == 2 ** 17


# ================================================================ review fix M3: overwrite safety
def snapshot(paths, *names):
    return {name: open(paths[name], 'rb').read() for name in names}


def test_rotate_cannot_overwrite_the_recovery_file_of_a_key_still_in_the_keyring(paths):
    """The b1/b2 mistake: rotating with b1's recovery path and the overwrite flag."""
    make(paths)
    before = snapshot(paths, 'ring', 'rec1')
    with pytest.raises(K.RecoveryError) as err:
        K.rotate(paths['ring'], paths['rec1'], OTHER_PHRASE, FakeProtector(),
                 overwrite_recovery=True, n=N)
    assert 'recovery file of key b1, which is still in the keyring' in str(err.value)
    assert snapshot(paths, 'ring', 'rec1') == before                # nothing changed
    assert K.verify_recovery(paths['ring'], paths['rec1'], PHRASE, FakeProtector())['key_id'] == 'b1'
    assert leftovers(paths['dir']) == []


def test_rotate_may_replace_an_orphaned_recovery_file_when_confirmed(paths):
    """A recovery file whose key is NOT in the keyring (for example left by an interrupted
    rotate) can be replaced with --confirm-overwrite-recovery."""
    make(paths)
    orphan = K.make_recovery('b2', os.urandom(32), PHRASE, n=N)
    K.write_new_file(paths['rec2'], orphan)
    with pytest.raises(K.RecoveryError):                            # still needs the flag
        K.rotate(paths['ring'], paths['rec2'], OTHER_PHRASE, FakeProtector(), n=N)
    info = K.rotate(paths['ring'], paths['rec2'], OTHER_PHRASE, FakeProtector(),
                    overwrite_recovery=True, n=N)
    assert info['key_id'] == 'b2'
    assert K.verify_recovery(paths['ring'], paths['rec2'], OTHER_PHRASE, FakeProtector())['active']
    assert leftovers(paths['dir']) == []


def test_a_failed_keyring_update_keeps_the_old_recovery_file_and_keyring(paths, monkeypatch):
    make(paths)
    orphan = K.make_recovery('b2', os.urandom(32), PHRASE, n=N)
    K.write_new_file(paths['rec2'], orphan)
    before = snapshot(paths, 'ring', 'rec1', 'rec2')

    def fail(path, data, expected):
        raise OSError(13, 'Access is denied')
    monkeypatch.setattr(K, 'replace_file', fail)
    with pytest.raises(OSError):
        K.rotate(paths['ring'], paths['rec2'], OTHER_PHRASE, FakeProtector(),
                 overwrite_recovery=True, n=N)
    assert snapshot(paths, 'ring', 'rec1', 'rec2') == before          # all three untouched
    assert leftovers(paths['dir']) == []


def test_the_recovery_file_is_placed_only_after_the_keyring_update(paths, monkeypatch):
    make(paths)
    order = []
    real_replace, real_commit = K.replace_file, K._StagedRecovery.commit

    def replace(path, data, expected):
        order.append('keyring updated')
        assert not os.path.exists(paths['rec2'])                  # not yet in place
        return real_replace(path, data, expected)

    def commit(self):
        order.append('recovery placed')
        return real_commit(self)
    monkeypatch.setattr(K, 'replace_file', replace)
    monkeypatch.setattr(K._StagedRecovery, 'commit', commit)
    K.rotate(paths['ring'], paths['rec2'], OTHER_PHRASE, FakeProtector(), n=N)
    assert order == ['keyring updated', 'recovery placed']


def test_a_failed_recovery_placement_puts_the_keyring_back(paths, monkeypatch):
    make(paths)
    orphan = K.make_recovery('b2', os.urandom(32), PHRASE, n=N)
    K.write_new_file(paths['rec2'], orphan)
    before = snapshot(paths, 'ring', 'rec2')

    def broken_commit(self):
        raise PermissionError(13, 'Access is denied')
    monkeypatch.setattr(K._StagedRecovery, 'commit', broken_commit)
    with pytest.raises(K.RecoveryError) as err:
        K.rotate(paths['ring'], paths['rec2'], OTHER_PHRASE, FakeProtector(),
                 overwrite_recovery=True, n=N)
    assert 'The keyring was put back as it was; nothing was changed' in str(err.value)
    assert snapshot(paths, 'ring', 'rec2') == before
    assert leftovers(paths['dir']) == []


def test_if_the_keyring_cannot_be_put_back_the_staged_recovery_file_is_kept_and_named(
        paths, monkeypatch):
    make(paths)
    real_replace = K.replace_file
    calls = []

    def replace(path, data, expected):
        calls.append(1)
        if len(calls) > 1:                                         # the rollback fails too
            raise OSError(13, 'Access is denied')
        return real_replace(path, data, expected)

    def broken_commit(self):
        raise PermissionError(13, 'Access is denied')
    monkeypatch.setattr(K, 'replace_file', replace)
    monkeypatch.setattr(K._StagedRecovery, 'commit', broken_commit)
    with pytest.raises(K.RecoveryError) as err:
        K.rotate(paths['ring'], paths['rec2'], OTHER_PHRASE, FakeProtector(), n=N)
    text = str(err.value)
    assert 'The verified recovery file is at ' in text and 'move it somewhere safe' in text
    staged = text.split('recovery file is at ')[1].split(': move')[0]
    assert os.path.exists(staged)                                  # kept, never deleted
    assert K.read_recovery(staged, OTHER_PHRASE)[0] == 'b2'
    assert K.Keyring.load(paths['ring']).active_key_id == 'b2'


def test_init_failure_after_staging_keeps_an_existing_recovery_file(paths, monkeypatch):
    orphan = K.make_recovery('b1', os.urandom(32), PHRASE, n=N)
    K.write_new_file(paths['rec1'], orphan)
    real = K.write_new_file

    def fail_for_keyring(path, data):
        if path == paths['ring']:
            raise OSError(28, 'No space left on device')
        return real(path, data)
    monkeypatch.setattr(K, 'write_new_file', fail_for_keyring)
    with pytest.raises(OSError):
        K.init(paths['ring'], paths['rec1'], PHRASE, FakeProtector(), overwrite_recovery=True,
               n=N)
    assert open(paths['rec1'], 'rb').read() == orphan and not os.path.exists(paths['ring'])
    assert leftovers(paths['dir']) == []


def test_recovery_identity_reads_the_header_without_the_passphrase(paths):
    make(paths)
    key_id, fp, _ = K.recovery_identity(paths['rec1'])
    assert key_id == 'b1' and fp == K.Keyring.load(paths['ring']).entry('b1')['fingerprint']
    assert K.recovery_identity(str(paths['dir'] / 'missing.ncrecovery')) is None
