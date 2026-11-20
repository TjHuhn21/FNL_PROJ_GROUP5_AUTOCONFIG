"""Phase 3C-1: saved logins that cannot be decrypted.

security.decrypt raises CredentialError (a RuntimeError) with a message that never
contains the key, the stored value or the password; Configure explains it and lets
the user type the login; the Findings review skips only that device.
No database and no network: temporary keys, a temporary .env path, fake stores.
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))
sys.path.insert(0, os.path.dirname(__file__))

import pytest
from cryptography.fernet import Fernet

import security
from security import CredentialError

PASSWORD = 'Sw1tch-Secret-Pa55'


@pytest.fixture
def keyenv(monkeypatch, tmp_path):
    """A private, empty .env path, and a helper that sets the key used (env variable)."""
    monkeypatch.setattr(security, 'ENV_PATH', str(tmp_path / '.env'))
    monkeypatch.delenv('FERNET_KEY', raising=False)

    def use(key):
        monkeypatch.setenv('FERNET_KEY', key)
        return key
    return use


def secrets_absent(text, *secrets):
    return all(s and s not in text for s in secrets)


# ---------------------------------------------------------------- security.decrypt
def test_correct_key_decrypts(keyenv):
    keyenv(Fernet.generate_key().decode())
    token = security.encrypt(PASSWORD)
    assert token != PASSWORD and PASSWORD not in token
    assert security.decrypt(token) == PASSWORD


def test_wrong_key_raises_credential_error_without_secrets(keyenv):
    key_a = keyenv(Fernet.generate_key().decode())
    token = security.encrypt(PASSWORD)
    key_b = keyenv(Fernet.generate_key().decode())
    with pytest.raises(CredentialError) as err:
        security.decrypt(token)
    message = str(err.value)
    assert isinstance(err.value, RuntimeError)             # existing RuntimeError handlers still apply
    assert 'enter its login again' in message
    assert secrets_absent(message, PASSWORD, key_a, key_b, token)
    assert err.value.__cause__ is None and err.value.__suppress_context__  # no chained details


@pytest.mark.parametrize('stored', ['not-a-token', '', 'gAAAAABxxxx', 'gAAAAAB' + 'A' * 120, None, 12345])
def test_damaged_or_missing_stored_value_raises_credential_error(keyenv, stored):
    key = keyenv(Fernet.generate_key().decode())
    with pytest.raises(CredentialError) as err:
        security.decrypt(stored)
    assert secrets_absent(str(err.value), key)


def test_missing_or_invalid_key_raises_credential_error(keyenv, monkeypatch):
    token = Fernet(Fernet.generate_key()).encrypt(PASSWORD.encode()).decode()
    with pytest.raises(CredentialError) as err:            # no key at all
        security.decrypt(token)
    assert 'FERNET_KEY' in str(err.value)
    bad = Fernet.generate_key().decode()[:-1]              # truncated key
    monkeypatch.setenv('FERNET_KEY', bad)
    with pytest.raises(CredentialError) as err:
        security.decrypt(token)
    assert 'FERNET_KEY' in str(err.value) and bad not in str(err.value)
    assert secrets_absent(str(err.value), token, PASSWORD)


def test_db_get_credentials_passes_the_error_on(keyenv, monkeypatch):
    """The real db.py function, with its SQL replaced (no database connection)."""
    import db
    keyenv(Fernet.generate_key().decode())
    other = Fernet(Fernet.generate_key()).encrypt(PASSWORD.encode()).decode()
    monkeypatch.setattr(db, '_run', lambda *a, **k: {'username': 'admin', 'password_enc': other})
    with pytest.raises(CredentialError):
        db.get_credentials(1)
    monkeypatch.setattr(db, '_run', lambda *a, **k: {'username': '', 'password_enc': ''})
    assert db.get_credentials(1) == ('', '')               # no saved login: unchanged behaviour


# ---------------------------------------------------------------- Findings (services.fetch_configs)
class ReviewStore:
    """SW1's saved login is unreadable; SW2's and R1's are fine."""
    devices = [
        {'id': 1, 'name': 'SW1', 'ip': '10.9.0.1', 'type': 'switch', 'managed': True, 'status': 'up'},
        {'id': 2, 'name': 'SW2', 'ip': '10.9.0.2', 'type': 'switch', 'managed': True, 'status': 'up'},
        {'id': 3, 'name': 'R1', 'ip': '10.9.0.3', 'type': 'router', 'managed': True, 'status': 'up'},
    ]

    def __init__(self):
        self.saved = []

    def get_devices(self, *a):
        return list(self.devices)

    def get_links(self):
        return [('SW1', 'Gi0/1', 'SW2', 'Gi0/1')]

    def get_credentials(self, device_id):
        if device_id == 1:
            raise CredentialError(security.DECRYPT_FAILED)
        return 'admin', PASSWORD

    def clear_findings(self):
        self.saved.clear()

    def add_finding(self, f):
        self.saved.append(f)


@pytest.fixture
def fake_ssh(monkeypatch):
    from config import connect
    calls = []

    def get_config(creds):
        calls.append(creds['host'])
        return 'hostname X\nline vty 0 4\n transport input telnet\n'
    monkeypatch.setattr(connect, 'get_config', get_config)
    return calls


def test_findings_skips_only_the_unreadable_device(fake_ssh):
    import services
    configs, notes = services.fetch_configs(ReviewStore(), ReviewStore.devices)
    assert sorted(configs) == ['R1', 'SW2']                # the others were still read
    assert fake_ssh == ['10.9.0.2', '10.9.0.3']            # no SSH attempt for SW1
    assert len(notes) == 1 and notes[0].startswith('SW1: saved login could not be decrypted')
    assert secrets_absent(' '.join(notes), PASSWORD)


def test_findings_review_completes_in_the_window(fake_ssh, monkeypatch):
    tk = pytest.importorskip('tkinter')
    from tkinter import messagebox
    from gui_helpers import new_root, pump
    import services
    from gui.findings_tab import FindingsTab
    shown = []
    for name in ('showinfo', 'showerror', 'showwarning'):
        monkeypatch.setattr(messagebox, name, lambda *a, _n=name, **k: shown.append((_n,) + a))
    root = new_root()
    try:
        store = ReviewStore()
        tab = FindingsTab(root, store, lambda: services.collect_review_inputs(store, False),
                          lambda *a: None)
        tab.pack()
        tab.run()
        assert pump(root, lambda: not tab.busy, 10)
        assert not [s for s in shown if s[0] == 'showerror']      # no "Review failed"
        devices = {f['device'] for f in tab.findings}
        assert {'SW2', 'R1'} <= devices and 'SW1' not in {f['device'] for f in tab.findings
                                                            if f['rule'] == 'telnet_enabled'}
        note = tab.note.cget('text')
        assert 'SW1: saved login could not be decrypted' in note
        assert secrets_absent(note + str(shown), PASSWORD)
    finally:
        root.destroy()


# ---------------------------------------------------------------- Configure (Apply)
class ConfigureStore:
    devices = [
        {'id': 1, 'name': 'SW1', 'ip': '10.9.0.1', 'type': 'switch', 'managed': 1},
        {'id': 2, 'name': 'SW2', 'ip': '10.9.0.2', 'type': 'switch', 'managed': 1},
    ]

    def __init__(self):
        self.logs = []

    def get_devices(self, *a):
        return list(self.devices)

    def get_credentials(self, device_id):
        if device_id == 1:
            raise CredentialError(security.DECRYPT_FAILED)
        return 'admin', PASSWORD

    def add_log(self, *a):
        self.logs.append(a)


@pytest.fixture
def configure(monkeypatch):
    tk = pytest.importorskip('tkinter')
    from tkinter import messagebox, simpledialog
    from gui_helpers import new_root
    from gui import theme
    from gui.configure_tab import ConfigureTab
    root = new_root()
    theme.apply(root)
    shown, asked = [], []
    for name in ('showinfo', 'showerror', 'showwarning'):
        monkeypatch.setattr(messagebox, name, lambda t, m, _n=name, **k: shown.append((_n, t, m)))
    monkeypatch.setattr(messagebox, 'askyesno', lambda *a, **k: True)
    answers = {'Username': 'typed-user', 'Password': 'Typed-Pa55'}
    monkeypatch.setattr('gui.components.login_dialog.ask_device_login',
                        lambda parent, devices, reason='missing', replaces=(): asked.append(
                            ([d['name'] for d in devices], reason,
                             [d['name'] for d in replaces])) or
                        {'username': answers['Username'], 'password': answers['Password'],
                         'save': False})
    store = ConfigureStore()
    conf = ConfigureTab(root, store)
    conf.pack()
    root.update()
    yield root, conf, store, shown, asked, answers
    root.destroy()


def test_configure_explains_and_asks_for_the_unreadable_login(configure):
    root, conf, store, shown, asked, answers = configure
    creds = conf._collect_creds(store.devices)
    assert creds[1] == {'host': '10.9.0.1', 'username': 'typed-user', 'password': 'Typed-Pa55'}
    assert creds[2] == {'host': '10.9.0.2', 'username': 'admin', 'password': PASSWORD}
    # the login dialog itself explains the unreadable login (no separate warning box);
    # its saved (unreadable) login is the one a 'save' would replace
    assert asked == [(['SW1'], 'unreadable', ['SW1'])]
    from gui.components.login_dialog import explanation
    text = explanation([store.devices[0]], 'unreadable')
    assert 'SW1' in text and 'cannot be read' in text and 'SW2' not in text
    assert secrets_absent(str(shown), PASSWORD, answers['Password'])


def test_configure_cancel_after_the_warning_stops_the_apply(configure, monkeypatch):
    root, conf, store, shown, asked, answers = configure
    monkeypatch.setattr('gui.components.login_dialog.ask_device_login', lambda *a, **k: None)
    assert conf._collect_creds(store.devices) is None
    assert shown == []                                     # cancelled: nothing else happens


def test_configure_apply_runs_with_the_typed_login(configure):
    from gui_helpers import pump
    root, conf, store, shown, asked, answers = configure
    conf.picker.set_checked([1, 2])
    conf.vid.set('10'); conf.vname.set('STAFF'); conf.add_vlan()
    conf.make_preview()
    calls = []
    conf.apply_fn = lambda creds, cmds, checks, log=None: (
        calls.append(creds), (True, 'Applied and verified. Backup: snapshot #1'))[1]
    conf.apply()
    assert pump(root, lambda: not conf.busy, 10)
    assert [c['username'] for c in calls] == ['typed-user', 'admin']
    # the unreadable login is explained inside the login dialog (no separate warning box)
    assert [s[1] for s in shown if s[0] != 'showinfo'] == []
    visible = str(shown) + conf.session.content() + conf.status.cget('text') + str(store.logs)
    assert secrets_absent(visible, PASSWORD, answers['Password'])


def test_no_secret_reaches_the_terminal_or_logs(keyenv, capsys, caplog, fake_ssh):
    import services
    keyenv(Fernet.generate_key().decode())
    with caplog.at_level('DEBUG'):
        configs, notes = services.fetch_configs(ReviewStore(), ReviewStore.devices)
    out = capsys.readouterr()
    assert secrets_absent(out.out + out.err + caplog.text + ' '.join(notes), PASSWORD)
