"""Phase 3B: Apply writes ENCRYPTED backups (.ncbak) and fails closed.

Synthetic configurations, fake devices (FakeIOS) and throwaway keys only. Keyrings are
created in temporary folders with the fake DPAPI provider; the real keyring location and
the real Windows DPAPI are never used, and no device is contacted."""
import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import backup_crypto as C  # noqa: E402
import backup_keys as K  # noqa: E402
import backup_tool as T  # noqa: E402
from config import connect, multi  # noqa: E402
from test_backup_keys import FakeProtector, N, PHRASE  # noqa: E402
from test_backup_keys import private_locations  # noqa: E402,F401  (autouse: temp LOCALAPPDATA)
from test_backup_security import Recording  # noqa: E402

# Unique markers: if any of them is found in a file on disk, plaintext leaked.
MARK_HOST, MARK_SECRET = 'SYNTH-PLAIN-7Q2', 'SynthHash-Plain-Marker-91'


def config_for(name):
    return (f'Building configuration...\n\nCurrent configuration : 99 bytes\n!\nhostname '
            f'{name}\n!\nusername admin privilege 15 secret 9 {MARK_SECRET}\n!\nend\n')


RUNNING = config_for(MARK_HOST)


@pytest.fixture
def keyring(tmp_path, monkeypatch):
    """A real keyring (backup_keys) in a temporary folder, fake DPAPI; Apply uses it."""
    ring = str(tmp_path / 'keys' / 'backup-keyring.json')
    K.init(ring, str(tmp_path / 'offline' / 'b1.ncrecovery'), PHRASE, FakeProtector(), n=N)
    monkeypatch.setattr(connect, 'KEY_SOURCE',
                        connect.KeyringKeySource(ring, protector_factory=FakeProtector))
    return ring


@pytest.fixture
def backups(tmp_path):
    folder = tmp_path / 'backups'
    folder.mkdir()
    return folder


def apply(monkeypatch, backups, fake, host='10.0.0.2', commands=('vlan 10', 'name SALES')):
    log = []
    monkeypatch.setattr(connect, '_open', lambda creds: fake)
    ok, msg = connect.apply_config({'host': host, 'username': 'admin',
                                    'password': 'Synth-Login-9'}, list(commands), [],
                                   backup_dir=str(backups), log=lambda k, t: log.append((k, t)))
    return ok, msg, log


def no_ssh(monkeypatch):
    opened = []
    monkeypatch.setattr(connect, '_open', lambda creds: opened.append(creds['host']) or
                        pytest.fail('an SSH session was opened'))
    return opened


def assert_no_plaintext_written(data):
    """`data` (written bytes) never holds the configuration in plaintext. Since Phase 4A
    the readable, authenticated header records the device hostname (non-secret identity),
    so the hostname may appear there, but only as the header's "hostname" field; the
    encrypted part and everything else must not contain it, and no secret appears at all."""
    assert MARK_SECRET.encode() not in data
    if data.startswith(C.MAGIC):
        header, aad, body = C.read_backup_header(data)
        assert MARK_HOST.encode() not in body
        assert aad.count(MARK_HOST.encode()) == aad.count(b'"hostname":"') == \
            (1 if MARK_HOST in str(header.get('hostname')) else 0)
    else:
        assert MARK_HOST.encode() not in data


def assert_no_plaintext_on_disk(*folders):
    """No file anywhere under these folders holds the configuration in plaintext, and no
    .txt backup exists."""
    for folder in folders:
        for path in folder.rglob('*'):
            if path.is_file():
                assert_no_plaintext_written(path.read_bytes())
                assert path.suffix != '.txt', path


def files(folder):
    return sorted(p.name for p in folder.iterdir())


# ---------------------------------------------------------------- success
def test_apply_writes_a_verified_encrypted_backup(monkeypatch, backups, keyring, tmp_path):
    fake = Recording(running=RUNNING)
    ok, msg, log = apply(monkeypatch, backups, fake)
    assert ok and fake.sent == ['vlan 10', 'name SALES'] and fake.saved and fake.closed
    (name,) = files(backups)
    assert name.startswith('10.0.0.2_') and name.endswith('.ncbak')
    path = str(backups / name)
    assert multi.backup_path(msg) == path
    # independently verifiable with the tools and the keyring
    info = T.verify(path, keyring, FakeProtector())
    assert info['host'] == '10.0.0.2' and info['key_id'] == 'b1'
    assert f"Backup SHA-256: {info['plaintext_sha256']} (encrypted, key_id=b1;" in msg
    plaintext, header = C.decrypt_backup(open(path, 'rb').read(),
                                         K.Keyring.load(keyring).key_for(FakeProtector()))
    assert plaintext == RUNNING.encode() and header['privilege'] == 15
    assert header['source'] == 'show running-config'
    assert_no_plaintext_on_disk(backups)
    assert any(k == 'output' and 'hostname' in t for k, t in log)        # the masked preview
    assert not any(MARK_SECRET in t for _, t in log)                     # secret masked there


def test_export_still_recovers_the_exact_configuration(monkeypatch, backups, keyring, tmp_path):
    ok, msg, _ = apply(monkeypatch, backups, Recording(running=RUNNING))
    dest = tmp_path / 'restore.txt'
    T.export(multi.backup_path(msg), str(dest), keyring, FakeProtector(),
             lambda: T.EXPORT_PHRASE)
    assert dest.read_bytes() == RUNNING.encode()


def test_the_backup_is_encrypted_in_memory_never_written_as_plaintext(monkeypatch, backups,
                                                                       keyring):
    """Every byte written while making the backup is checked, not just the final file."""
    written = []
    real_fdopen = os.fdopen

    class Spy:
        def __init__(self, f):
            self.f = f

        def write(self, data):
            written.append(bytes(data))
            return self.f.write(data)

        def __getattr__(self, name):
            return getattr(self.f, name)

        def __enter__(self):
            self.f.__enter__()
            return self

        def __exit__(self, *exc):
            return self.f.__exit__(*exc)
    monkeypatch.setattr(connect.os, 'fdopen', lambda fd, mode='r', **k: Spy(real_fdopen(fd, mode, **k)))
    ok, _, _ = apply(monkeypatch, backups, Recording(running=RUNNING))
    monkeypatch.undo()
    assert ok and written
    assert all(w.startswith(b'NCBAK\x01') for w in written)
    for w in written:
        assert_no_plaintext_written(w)


# ---------------------------------------------------------------- the key: before any SSH
@pytest.mark.parametrize('state', ['missing', 'garbage', 'other-account', 'dpapi-fails'])
def test_an_unusable_keyring_stops_apply_before_ssh(monkeypatch, backups, tmp_path, state):
    ring = str(tmp_path / 'keys' / 'backup-keyring.json')
    protector = FakeProtector
    if state != 'missing':
        K.init(ring, str(tmp_path / 'offline' / 'b1.ncrecovery'), PHRASE, FakeProtector(), n=N)
    if state == 'garbage':
        with open(ring, 'wb') as f:
            f.write(b'{"damaged": true}')
    elif state == 'other-account':
        protector = lambda: FakeProtector(account='B')               # noqa: E731
    elif state == 'dpapi-fails':
        protector = lambda: FakeProtector(fail_unprotect=True)      # noqa: E731
    monkeypatch.setattr(connect, 'KEY_SOURCE', connect.KeyringKeySource(ring, protector))
    opened = no_ssh(monkeypatch)
    ok, msg = connect.apply_config({'host': '10.0.0.2', 'username': 'a', 'password': 'Synth-9'},
                                   ['vlan 10'], [], backup_dir=str(backups))
    assert ok is False and opened == []
    assert msg.startswith('The backup keyring cannot be used:')
    assert 'No SSH connection was opened to 10.0.0.2 and no configuration command was sent' in msg
    assert multi.classify(ok, msg) == multi.FAILED and multi.backup_path(msg) is None
    assert files(backups) == []
    if state == 'missing':
        assert 'python backup_keys.py init' in msg


def test_the_key_preflight_reports_problems_without_key_material(monkeypatch, tmp_path, keyring):
    assert connect.backup_key_problem() is None
    key = K.Keyring.load(keyring).key('b1', FakeProtector())
    monkeypatch.setattr(connect, 'KEY_SOURCE', connect.KeyringKeySource(
        str(tmp_path / 'nowhere.json'), FakeProtector))
    problem = connect.backup_key_problem()
    assert problem.startswith('The backup keyring cannot be used: No backup keyring was found')
    assert key.hex() not in problem


def test_any_unexpected_key_source_error_fails_closed(monkeypatch, backups):
    class Broken:
        def active_key(self):
            raise RuntimeError('synthetic bug')
    monkeypatch.setattr(connect, 'KEY_SOURCE', Broken())
    opened = no_ssh(monkeypatch)
    ok, msg = connect.apply_config({'host': '10.0.0.2', 'username': 'a', 'password': 'S-9'},
                                   ['vlan 10'], [], backup_dir=str(backups))
    assert ok is False and opened == [] and 'RuntimeError' in msg and files(backups) == []


def test_the_default_key_source_is_the_users_keyring_and_tests_never_use_it(
        synthetic_backup_key):
    assert isinstance(connect.KeyringKeySource(), connect.KeyringKeySource)
    assert connect.KeyringKeySource().keyring_path is None        # = %LOCALAPPDATA% default
    assert connect.KEY_SOURCE is synthetic_backup_key              # replaced in every test


# ---------------------------------------------------------------- failures after SSH
def run_failure(monkeypatch, backups, keyring):
    fake = Recording(running=RUNNING)
    ok, msg, log = apply(monkeypatch, backups, fake)
    assert ok is False
    assert fake.sent == [] and not fake.in_config and not fake.saved   # nothing sent
    assert fake.closed                                                  # session cleaned up
    assert 'No configuration command was sent; the device was not changed.' in msg
    assert multi.classify(ok, msg) == multi.FAILED and multi.backup_path(msg) is None
    assert any(k == 'error' and t.startswith('BACKUP FAILED') for k, t in log)
    assert not any('Encrypted backup saved' in t for _, t in log)
    assert files(backups) == []                                        # no .ncbak, no .partial
    assert_no_plaintext_on_disk(backups)
    return msg


def test_an_encryption_failure_stops_before_any_command(monkeypatch, backups, keyring):
    def fail(*a, **k):
        raise C.BackupCryptoError('synthetic encryption failure')
    monkeypatch.setattr(C, 'encrypt_backup', fail)
    assert 'could not be encrypted (synthetic encryption failure)' in \
        run_failure(monkeypatch, backups, keyring)


def test_a_write_failure_stops_before_any_command(monkeypatch, backups, keyring):
    def no_space(fd):
        raise OSError(28, 'No space left on device')
    monkeypatch.setattr(connect.os, 'fsync', no_space)
    assert 'could not be written (No space left on device)' in \
        run_failure(monkeypatch, backups, keyring)


def test_a_failed_rename_stops_before_any_command(monkeypatch, backups, keyring):
    def refuse(temp, final):
        raise PermissionError(13, 'Access is denied')
    monkeypatch.setattr(connect, '_place', refuse)
    assert 'Access is denied' in run_failure(monkeypatch, backups, keyring)


def test_a_read_back_mismatch_stops_before_any_command(monkeypatch, backups, keyring):
    import builtins
    real_open = builtins.open

    def damaged_read(path, mode='r', *a, **k):
        f = real_open(path, mode, *a, **k)
        if str(path).endswith('.partial') and 'rb' in mode:
            data = f.read()
            f.close()
            import io
            return io.BytesIO(data[:-1] + bytes([data[-1] ^ 1]))
        return f
    monkeypatch.setattr(connect, 'open', damaged_read, raising=False)
    assert 'the encrypted file on disk does not match' in run_failure(monkeypatch, backups, keyring)


def test_an_authentication_failure_on_read_back_stops_before_any_command(monkeypatch, backups):
    """The file decrypts only with the key that wrote it: a keyring giving another key for
    the read-back fails authentication."""
    real_key, other = os.urandom(32), os.urandom(32)

    class Mismatched:
        def active_key(self):
            return connect.BackupKey('b1', real_key, lambda key_id: other)
    monkeypatch.setattr(connect, 'KEY_SOURCE', Mismatched())
    msg = run_failure(monkeypatch, backups, None)
    assert 'could not be verified (The file could not be authenticated' in msg


def test_a_decrypted_backup_that_differs_stops_before_any_command(monkeypatch, backups, keyring):
    real = C.decrypt_backup

    def altered(data, key_for):
        plaintext, header = real(data, key_for)
        return plaintext + b'!', header
    monkeypatch.setattr(C, 'decrypt_backup', altered)
    assert 'does not match the configuration the device sent' in \
        run_failure(monkeypatch, backups, keyring)


def test_an_unusable_configuration_still_stops_before_encryption(monkeypatch, backups, keyring):
    monkeypatch.setattr(C, 'encrypt_backup', lambda *a, **k: pytest.fail('encrypted'))
    fake = Recording(running='% Invalid input detected at the marker.\n')
    ok, msg, _ = apply(monkeypatch, backups, fake)
    assert ok is False and fake.sent == [] and 'refused' in msg and files(backups) == []


def test_privilege_below_15_still_stops_apply(monkeypatch, backups, keyring):
    fake = Recording(running=RUNNING, privilege='Current privilege level is 1')
    ok, msg, _ = apply(monkeypatch, backups, fake)
    assert ok is False and 'privilege level 1' in msg and fake.asked == ['show privilege']
    assert fake.sent == [] and fake.closed and files(backups) == []


# ---------------------------------------------------------------- several devices
DEVICES = [('SW1', '10.0.0.11'), ('SW2', '10.0.0.12'), ('SW3', '10.0.0.13')]


def jobs():
    return [{'device': {'id': i, 'name': n, 'ip': ip, 'type': 'switch'}, 'commands': ['vlan 10'],
             'checks': [], 'creds': {'host': ip, 'username': 'u', 'password': 'Synth-9'}}
            for i, (n, ip) in enumerate(DEVICES, 1)]


def runner(backups):
    return lambda c, cm, ch, log=None: connect.apply_config(c, cm, ch, backup_dir=str(backups),
                                                            log=log)


def test_multi_device_preflight_happens_before_any_ssh(monkeypatch, backups, tmp_path):
    monkeypatch.setattr(connect, 'KEY_SOURCE', connect.KeyringKeySource(
        str(tmp_path / 'missing.json'), FakeProtector))
    opened = no_ssh(monkeypatch)
    called, posted = [], []
    results = multi.run_devices(jobs(), lambda *a, **k: called.append(a) or (True, ''),
                                post=lambda k, t, n=None: posted.append((k, t)),
                                preflight=connect.backup_key_problem)
    assert called == [] and opened == [] and files(backups) == []
    assert [r['status'] for r in results] == [multi.NOT_RUN] * 3
    assert all('No backup keyring was found' in r['message'] and
               'No device was contacted' in r['message'] for r in results)
    assert posted[0][0] == 'error' and posted[0][1].startswith('NOT STARTED:')


def test_a_failing_preflight_check_itself_never_lets_devices_run(backups):
    def broken():
        raise RuntimeError('synthetic')
    called = []
    results = multi.run_devices(jobs(), lambda *a, **k: called.append(a) or (True, ''),
                                preflight=broken)
    assert called == [] and {r['status'] for r in results} == {multi.NOT_RUN}


def test_every_device_gets_its_own_verified_encrypted_backup(monkeypatch, backups, keyring):
    fakes = {ip: Recording(running=config_for(f'{name}-{MARK_HOST}')) for name, ip in DEVICES}
    monkeypatch.setattr(connect, '_open', lambda creds: fakes[creds['host']])
    results = multi.run_devices(jobs(), runner(backups), preflight=connect.backup_key_problem)
    assert [r['status'] for r in results] == [multi.SUCCESS] * 3
    ring = K.Keyring.load(keyring)
    for (name, ip), r in zip(DEVICES, results):
        assert r['backup'].endswith('.ncbak') and os.path.basename(r['backup']).startswith(ip)
        plaintext, header = C.decrypt_backup(open(r['backup'], 'rb').read(),
                                             ring.key_for(FakeProtector()))
        assert plaintext == config_for(f'{name}-{MARK_HOST}').encode()   # its own config
        assert header['host'] == ip
        assert fakes[ip].sent == ['vlan 10'] and fakes[ip].closed
    assert len(files(backups)) == 3
    assert_no_plaintext_on_disk(backups)


def test_one_devices_backup_failure_blocks_only_that_device(monkeypatch, backups, keyring):
    fakes = {ip: Recording(running=config_for(name)) for name, ip in DEVICES}
    monkeypatch.setattr(connect, '_open', lambda creds: fakes[creds['host']])
    real = C.encrypt_backup

    def fail_for_sw2(plaintext, key, key_id, metadata=None):
        if metadata and metadata.get('host') == '10.0.0.12':
            raise C.BackupCryptoError('synthetic encryption failure')
        return real(plaintext, key, key_id, metadata)
    monkeypatch.setattr(C, 'encrypt_backup', fail_for_sw2)
    results = multi.run_devices(jobs(), runner(backups), preflight=connect.backup_key_problem)
    assert [r['status'] for r in results] == [multi.SUCCESS, multi.FAILED, multi.SUCCESS]
    assert fakes['10.0.0.12'].sent == [] and fakes['10.0.0.12'].closed
    assert fakes['10.0.0.11'].sent == ['vlan 10'] == fakes['10.0.0.13'].sent
    assert results[1]['backup'] is None and '10.0.0.12' in results[1]['message']
    assert [os.path.basename(r['backup']).split('_')[0] for r in (results[0], results[2])] == \
        ['10.0.0.11', '10.0.0.13']
    assert [f.split('_')[0] for f in files(backups)] == ['10.0.0.11', '10.0.0.13']
    summary = multi.summary_text(results)
    assert summary.count('.ncbak') == 2 and 'SW2' in summary


# ---------------------------------------------------------------- the Configure page
def test_configure_refuses_to_start_without_a_usable_keyring(monkeypatch, tmp_path):
    pytest.importorskip('tkinter')
    from test_configure_console import choose, page  # noqa: F401
    from gui_helpers import new_root
    from tkinter import messagebox
    from gui.configure_tab import ConfigureTab
    from test_configure_console import Store
    shown = []
    for name in ('showinfo', 'showerror', 'showwarning'):
        monkeypatch.setattr(messagebox, name, lambda t, m, _n=name, **k: shown.append((_n, t, m)))
    monkeypatch.setattr(messagebox, 'askyesno', lambda *a, **k: pytest.fail('asked to confirm'))
    monkeypatch.setattr('gui.components.login_dialog.ask_device_login',
                        lambda *a, **k: pytest.fail('asked for a login'))
    monkeypatch.setattr(connect, 'KEY_SOURCE', connect.KeyringKeySource(
        str(tmp_path / 'missing.json'), FakeProtector))
    root = new_root()
    try:
        store = Store()
        store.get_credentials = lambda device_id: pytest.fail('read a saved login')
        conf = ConfigureTab(root, store, log=lambda *a, **k: None)
        conf.pack()
        root.update()
        conf.apply_fn = lambda *a, **k: pytest.fail('apply ran')
        choose(conf, 'SW1')
        conf.vid.set('10'); conf.vname.set('STAFF'); conf.add_vlan()
        conf.make_preview()
        conf.apply()
        assert not conf.busy
        kind, title, text = shown[-1]
        assert (kind, title) == ('showerror', 'Backup encryption key not available')
        assert 'No backup keyring was found' in text and 'nothing was sent' in text
    finally:
        root.destroy()


def test_configure_passes_the_preflight_to_the_device_run(monkeypatch):
    pytest.importorskip('tkinter')
    from gui_helpers import new_root, pump
    from tkinter import messagebox
    from gui.configure_tab import ConfigureTab
    from test_configure_console import Store, choose
    for name in ('showinfo', 'showerror', 'showwarning'):
        monkeypatch.setattr(messagebox, name, lambda *a, **k: None)
    monkeypatch.setattr(messagebox, 'askyesno', lambda *a, **k: True)
    root = new_root()
    try:
        conf = ConfigureTab(root, Store(), log=lambda *a, **k: None)
        conf.pack()
        root.update()
        answers = iter([None, 'The backup keyring cannot be used: synthetic.'])
        conf.backup_preflight = lambda: next(answers)   # fine at Apply, broken in the run
        conf.apply_fn = lambda *a, **k: pytest.fail('a device was contacted')
        choose(conf, 'SW1')
        conf.vid.set('10'); conf.vname.set('STAFF'); conf.add_vlan()
        conf.make_preview()
        conf.apply()
        assert pump(root, lambda: not conf.busy)
        assert [r['status'] for r in conf.last_results] == [multi.NOT_RUN]
        assert 'No device was contacted' in conf.last_results[0]['message']
    finally:
        root.destroy()
