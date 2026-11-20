"""Phase 3C-2: a device and its login are saved together, or not at all.

* validation.check_login: both-or-neither, username 1-50 characters on one line,
  password at most 127 UTF-8 bytes (derived from VARCHAR(255) and Fernet's format).
* db.save_device: checks and encrypts BEFORE connecting, then one connection and
  one transaction; any failure rolls everything back. Tested with a stand-in
  connection that only keeps statements on commit(): no MySQL is contacted.
* db_fake.save_device: the same contract, in memory.
* Devices dialog and Scan -> Approve use it and report exactly what happened.
No database, no network, no real .env (temporary keys and paths only).
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))
sys.path.insert(0, os.path.dirname(__file__))

import pytest
from cryptography.fernet import Fernet

import db
import db_fake
import security
import validation

PASSWORD = 'Sw1tch-Secret-Pa55'


@pytest.fixture
def keyenv(monkeypatch, tmp_path):
    """A temporary FERNET_KEY in the environment; the real .env is never read."""
    monkeypatch.setattr(security, 'ENV_PATH', str(tmp_path / '.env'))
    key = Fernet.generate_key().decode()
    monkeypatch.setenv('FERNET_KEY', key)
    return key


def dev(name='SW1', ip='10.9.0.1', managed=True):
    return {'name': name, 'ip': ip, 'mac': '', 'type': 'switch', 'managed': managed,
            'status': 'up'}


# ---------------------------------------------------------------- validation.check_login
def test_username_50_ok_51_refused():
    assert validation.check_login('u' * 50, PASSWORD) is None
    msg = validation.check_login('u' * 51, PASSWORD)
    assert '50 characters or fewer' in msg and '51' in msg and PASSWORD not in msg


def test_password_127_bytes_ok_128_refused():
    assert validation.check_login('admin', 'p' * 127) is None
    msg = validation.check_login('admin', 'p' * 128)
    assert '127' in msg and '128 bytes' in msg and 'p' * 20 not in msg


@pytest.mark.parametrize('ok, too_long, size', [
    ('é' * 63, 'é' * 64, 2),            # 2-byte letters: 64 characters are already 128 bytes
    ('€' * 42, '€' * 43, 3),            # 3-byte symbol: 43 characters = 129 bytes
    ('🔒' * 31, '🔒' * 32, 4),           # 4-byte symbol: 32 characters = 128 bytes
])
def test_non_ascii_passwords_are_measured_in_bytes(ok, too_long, size):
    assert len(ok.encode()) <= 127 and validation.check_login('admin', ok) is None
    msg = validation.check_login('admin', too_long)
    assert msg and 'bytes' in msg and too_long not in msg
    assert len(too_long) < 127                           # it is the BYTES that are too many


def test_empty_login_is_allowed_and_half_logins_are_not():
    assert validation.check_login('', '') is None
    assert validation.check_login(None, None) is None
    assert validation.check_login('   ', '') is None
    both = 'Enter both a login username and password, or neither.'
    assert validation.check_login('admin', '') == both
    assert validation.check_login('', PASSWORD) == both
    assert validation.check_login('   ', PASSWORD) == both


def test_username_line_breaks_refused():
    assert 'one line' in validation.check_login('ad\nmin', PASSWORD)
    assert 'one line' in validation.check_login('ad\rmin', PASSWORD)


def test_the_127_byte_limit_matches_the_real_fernet_token_size():
    """VARCHAR(255): every password up to 127 bytes fits, 128 bytes does not."""
    f = Fernet(Fernet.generate_key())
    assert max(len(f.encrypt(b'a' * n)) for n in range(0, 128)) == 248
    assert len(f.encrypt(b'a' * 128)) == 268 > db.PASSWORD_ENC_MAX
    assert len(f.encrypt('é'.encode() * 63)) <= 255     # 126 bytes


# ---------------------------------------------------------------- db.save_device with a stand-in connection
class FakeConnection:
    """Behaves like a transactional connection: statements are staged and only become
    'committed' on commit(); rollback() discards them. fail_on: SQL text that fails."""

    def __init__(self, fail_on=None, existing_name='OLD', lastrowid=7, deleted=None, row=None,
                 rowcount=1, taken=None):
        self.fail_on, self.existing_name, self.lastrowid = fail_on, existing_name, lastrowid
        self.taken = taken              # answer to the "active device with this name" query (3C-5)
        self.deleted = deleted          # answer to the "deleted device with this IP" query
        self.row = row                  # answer to restore_device's "SELECT ... WHERE id" query
        self.rowcount = rowcount
        self.pending, self.committed = [], []
        self.commits = self.rollbacks = self.closes = 0

    def cursor(self):
        return FakeCursor(self)

    def commit(self):
        self.committed += self.pending
        self.pending = []
        self.commits += 1

    def rollback(self):
        self.pending = []
        self.rollbacks += 1

    def close(self):
        self.closes += 1

    def writes(self, rows):
        return [sql.split()[0] + ' ' + sql.split()[1] for sql, _ in rows
                if not sql.startswith('SELECT')]

    def write_rows(self, rows):
        return [(sql, params) for sql, params in rows if not sql.startswith('SELECT')]


class FakeCursor:
    def __init__(self, conn):
        self.conn, self.lastrowid, self.rowcount, self.last_sql = conn, None, 0, ''

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False

    def execute(self, sql, params=()):
        if self.conn.fail_on and self.conn.fail_on in sql:
            import pymysql
            raise pymysql.err.DataError(1406, "Data too long for column 'username' at row 1")
        self.conn.pending.append((sql, params))
        self.last_sql = sql
        self.rowcount = self.conn.rowcount if sql.startswith('UPDATE') else 0
        if sql.startswith('INSERT'):
            self.lastrowid = self.conn.lastrowid

    def fetchone(self):
        if 'is_deleted = 1' in self.last_sql and self.last_sql.startswith('SELECT'):
            return self.conn.deleted
        if 'is_deleted FROM devices WHERE id' in self.last_sql:
            return self.conn.row
        if 'LOWER(name)' in self.last_sql:
            return self.conn.taken
        return {'name': self.conn.existing_name} if self.conn.existing_name else None


@pytest.fixture
def fakeconn(monkeypatch):
    made = []

    def connect(**kw):
        conn = FakeConnection(**kw)
        made.append(conn)
        return conn
    holder = {'kw': {}}
    monkeypatch.setattr(db, 'get_conn', lambda: connect(**holder['kw']))
    monkeypatch.setattr(db, '_run', lambda *a, **k: pytest.fail('unexpected _run call'))
    return made, holder


def no_connection(monkeypatch):
    monkeypatch.setattr(db, 'get_conn', lambda: pytest.fail('connected to the database'))


def test_db_new_device_and_login_in_one_transaction(keyenv, fakeconn):
    made, _ = fakeconn
    assert db.save_device(None, dev(), 'admin', PASSWORD) == 7
    (conn,) = made
    assert conn.writes(conn.committed) == ['INSERT INTO', 'UPDATE devices']
    assert (conn.commits, conn.rollbacks, conn.closes) == (1, 0, 1)
    sql, params = conn.write_rows(conn.committed)[1]
    user, token, did = params
    assert (user, did) == ('admin', 7) and PASSWORD not in str(conn.committed)
    assert security.decrypt(token) == PASSWORD          # stored encrypted, readable with the key


def test_db_device_insert_failure_rolls_back_and_skips_the_login(keyenv, fakeconn):
    made, holder = fakeconn
    holder['kw'] = {'fail_on': 'INSERT INTO devices'}
    with pytest.raises(Exception):
        db.save_device(None, dev(), 'admin', PASSWORD)
    (conn,) = made
    assert conn.committed == [] and conn.pending == []
    assert (conn.commits, conn.rollbacks, conn.closes) == (0, 1, 1)


def test_db_login_failure_rolls_back_the_device_too(keyenv, fakeconn):
    made, holder = fakeconn
    holder['kw'] = {'fail_on': 'SET username'}
    with pytest.raises(Exception) as err:
        db.save_device(None, dev(), 'admin', PASSWORD)
    (conn,) = made
    assert conn.committed == []                           # the staged INSERT was discarded
    assert (conn.commits, conn.rollbacks, conn.closes) == (0, 1, 1)
    assert PASSWORD not in str(err.value)


def test_db_edit_with_rename_keeps_the_id_and_moves_links_in_the_same_transaction(keyenv, fakeconn):
    made, _ = fakeconn
    assert db.save_device(42, dict(dev('NEW'), managed=False)) == 42
    (conn,) = made
    assert conn.writes(conn.committed) == ['UPDATE devices', 'UPDATE links', 'UPDATE links']
    assert conn.write_rows(conn.committed)[0][1][-1] == 42   # WHERE id = 42: the same device
    assert conn.commits == 1


def test_db_edit_failure_rolls_back_rename_and_links(keyenv, fakeconn):
    made, holder = fakeconn
    holder['kw'] = {'fail_on': 'SET username'}
    with pytest.raises(Exception):
        db.save_device(42, dev('NEW'), 'admin', PASSWORD)
    (conn,) = made
    assert conn.committed == [] and conn.rollbacks == 1


def test_db_edit_of_a_device_that_is_gone(keyenv, fakeconn):
    made, holder = fakeconn
    holder['kw'] = {'existing_name': None}
    with pytest.raises(ValueError, match='no longer exists'):
        db.save_device(99, dev())
    assert made[0].committed == [] and made[0].rollbacks == 1


def test_db_blank_login_keeps_the_saved_one(keyenv, fakeconn):
    made, _ = fakeconn
    db.save_device(None, dev())
    (conn,) = made
    assert conn.writes(conn.committed) == ['INSERT INTO']   # no login statement at all


def test_db_encryption_failure_happens_before_any_connection(monkeypatch, tmp_path):
    monkeypatch.setattr(security, 'ENV_PATH', str(tmp_path / '.env'))
    monkeypatch.delenv('FERNET_KEY', raising=False)      # no key at all
    no_connection(monkeypatch)
    with pytest.raises(RuntimeError) as err:
        db.save_device(None, dev(), 'admin', PASSWORD)
    assert 'FERNET_KEY' in str(err.value) and PASSWORD not in str(err.value)


def test_db_invalid_login_and_long_token_are_refused_before_connecting(keyenv, monkeypatch):
    no_connection(monkeypatch)
    with pytest.raises(ValueError, match='50 characters'):
        db.save_device(None, dev(), 'u' * 51, PASSWORD)
    with pytest.raises(ValueError, match='Enter both'):
        db.save_device(None, dev(), 'admin', '')
    monkeypatch.setattr(security, 'encrypt', lambda text: 'x' * 256)   # guard on the real length
    with pytest.raises(ValueError, match='too long to store'):
        db.save_device(None, dev(), 'admin', PASSWORD)
    with pytest.raises(ValueError, match='Sample'):
        db.save_device(None, dict(dev(), sample=True))


def test_upsert_device_inserts_through_the_save_transaction(fakeconn):
    """Follow-up to 3C-5: upsert_device is save_device(None, d), one transaction
    (fakeconn makes any _run call fail the test)."""
    made, holder = fakeconn
    assert db.upsert_device(dev()) == 7
    conn, = made
    inserts = [p for sql, p in conn.committed if sql == db._UPSERT_SQL]
    assert inserts == [db._upsert_params(dev())] and conn.commits == 1 and conn.rollbacks == 0


# ---------------------------------------------------------------- db_fake.save_device (same contract)
@pytest.fixture
def fake():
    db_fake.reset()
    yield db_fake
    db_fake.reset()


def test_fake_success_and_ids(fake):
    a = fake.save_device(None, dev('SW1', '10.9.0.1'), 'admin', PASSWORD)
    b = fake.save_device(None, dev('SW2', '10.9.0.2'))
    assert (a, b) == (1, 2)
    assert fake.get_credentials(a) == ('admin', PASSWORD) and fake.get_credentials(b) == ('', '')
    assert fake.save_device(a, dict(dev('SW1b', '10.9.0.1')), None, None) == a
    assert fake.get_device(a)['name'] == 'SW1b' and fake.get_credentials(a) == ('admin', PASSWORD)


def test_fake_login_failure_leaves_no_device(fake, monkeypatch):
    monkeypatch.setattr(fake, 'save_credentials', lambda *a: (_ for _ in ()).throw(RuntimeError('disk full')))
    with pytest.raises(RuntimeError):
        fake.save_device(None, dev(), 'admin', PASSWORD)
    assert fake.count_devices() == 0
    monkeypatch.undo()
    assert fake.save_device(None, dev()) == 1            # the id was not used up either


def test_fake_device_failure_and_validation_change_nothing(fake, monkeypatch):
    fake.save_device(None, dev('SW1', '10.9.0.1'), 'admin', PASSWORD)
    monkeypatch.setattr(fake, 'upsert_device', lambda d: (_ for _ in ()).throw(RuntimeError('boom')))
    with pytest.raises(RuntimeError):
        fake.save_device(None, dev('SW2', '10.9.0.2'))
    monkeypatch.undo()
    with pytest.raises(ValueError):
        fake.save_device(None, dev('SW3', '10.9.0.3'), 'u' * 51, PASSWORD)
    assert [d['name'] for d in fake.get_devices()] == ['SW1']


def test_fake_edit_failure_restores_name_links_and_login(fake, monkeypatch):
    a = fake.save_device(None, dev('A', '10.9.0.1'), 'admin', PASSWORD)
    fake.save_device(None, dev('B', '10.9.0.2'))
    fake.save_links([('A', 'Gi0/1', 'B', 'Gi0/1')])
    monkeypatch.setattr(fake, 'save_credentials', lambda *a: (_ for _ in ()).throw(RuntimeError('x')))
    with pytest.raises(RuntimeError):
        fake.save_device(a, dev('A-renamed', '10.9.0.1'), 'newuser', 'New-Pa55')
    assert fake.get_device(a)['name'] == 'A'
    assert fake.get_links() == [('A', 'Gi0/1', 'B', 'Gi0/1')]
    assert fake.get_credentials(a) == ('admin', PASSWORD)


# ---------------------------------------------------------------- GUI: Devices dialog
@pytest.fixture
def gui(monkeypatch):
    pytest.importorskip('tkinter')
    from tkinter import messagebox
    from gui_helpers import new_root
    from gui import theme
    root = new_root()
    theme.apply(root)
    shown = []
    for name in ('showinfo', 'showerror', 'showwarning'):
        monkeypatch.setattr(messagebox, name, lambda t, m, _n=name, **k: shown.append((_n, t, m)))
    db_fake.reset()
    yield root, shown
    root.destroy()
    db_fake.reset()


def open_dialog(root, device=None, **values):
    from gui.devices_tab import DeviceDialog
    saved = []
    d = DeviceDialog(root, db_fake, device, lambda: saved.append(1))
    base = {'name': 'SW1', 'ip': '10.9.0.1', 'username': '', 'password': ''}
    base.update(values)
    for k, v in base.items():
        d.vars[k].set(v)
    return d, saved


@pytest.mark.parametrize('values, words', [
    ({'username': 'u' * 51, 'password': PASSWORD}, '50 characters or fewer'),
    ({'username': 'admin', 'password': 'é' * 64}, '127 bytes'),
    ({'username': 'admin', 'password': ''}, 'Enter both'),
    ({'username': '', 'password': PASSWORD}, 'Enter both'),
])
def test_dialog_refuses_invalid_logins_and_saves_nothing(gui, values, words):
    root, shown = gui
    d, saved = open_dialog(root, **values)
    d.save()
    assert shown[-1][:2] == ('showerror', 'Cannot save') and words in shown[-1][2]
    assert db_fake.count_devices() == 0 and saved == []
    assert values['password'] == '' or values['password'] not in str(shown)


def test_dialog_saves_device_and_login_together(gui):
    root, shown = gui
    d, saved = open_dialog(root, username='admin', password=PASSWORD)
    d.save()
    assert shown == [] and saved == [1]
    did = db_fake.get_device_by_ip('10.9.0.1')['id']
    assert db_fake.get_credentials(did) == ('admin', PASSWORD)


def test_dialog_store_failure_saves_nothing_and_says_so(gui, monkeypatch):
    root, shown = gui
    monkeypatch.setattr(db_fake, 'save_credentials',
                        lambda *a: (_ for _ in ()).throw(RuntimeError('database went away')))
    d, saved = open_dialog(root, username='admin', password=PASSWORD)
    d.save()
    assert shown[-1][1] == 'Cannot save'
    assert shown[-1][2] == 'Nothing was saved. database went away'
    assert db_fake.count_devices() == 0 and saved == [] and PASSWORD not in str(shown)


def test_dialog_edit_failure_keeps_the_old_record(gui, monkeypatch):
    root, shown = gui
    did = db_fake.save_device(None, dev('SW1', '10.9.0.1'), 'admin', PASSWORD)
    monkeypatch.setattr(db_fake, 'save_credentials',
                        lambda *a: (_ for _ in ()).throw(RuntimeError('x')))
    d, saved = open_dialog(root, db_fake.get_device(did), name='SW1-new',
                           username='other', password='Other-Pa55')
    d.save()
    assert shown[-1][1] == 'Cannot save'
    assert db_fake.get_device(did)['name'] == 'SW1'
    assert db_fake.get_credentials(did) == ('admin', PASSWORD)


# ---------------------------------------------------------------- GUI: Scan -> Approve
def make_scan(root, monkeypatch, user='admin', password=PASSWORD):
    from gui.scan_tab import ScanTab
    scan = ScanTab(root, db_fake, lambda *a: None, sample_store=False)
    scan.pack()
    devices = [dev('CORE', '10.9.0.1'), dev('SW1', '10.9.0.2'), dev('SW2', '10.9.0.3'),
               dev('PRN', '10.9.0.9', managed=False)]
    scan.show_found(devices, [('CORE', 'Gi0/1', 'SW1', 'Gi0/1')])
    scan.user.set(user)
    scan.pw.set(password)
    scan.save_login.set(1)
    scan.select_all()
    return scan


def test_scan_validates_the_shared_login_once_before_saving(gui, monkeypatch):
    root, shown = gui
    scan = make_scan(root, monkeypatch, user='u' * 51)
    scan.approve()
    assert shown[-1][:2] == ('showerror', 'Cannot save') and 'Nothing was saved.' in shown[-1][2]
    assert db_fake.count_devices() == 0 and PASSWORD not in str(shown)


def test_scan_saves_each_device_with_its_login(gui, monkeypatch):
    root, shown = gui
    scan = make_scan(root, monkeypatch)
    scan.approve()
    assert shown[-1][:2] == ('showinfo', 'Approved')
    creds = {d['name']: db_fake.get_credentials(d['id']) for d in db_fake.get_devices()}
    assert creds == {'CORE': ('admin', PASSWORD), 'SW1': ('admin', PASSWORD),
                     'SW2': ('admin', PASSWORD), 'PRN': ('', '')}     # unmanaged: no login
    assert db_fake.get_links() == [('CORE', 'Gi0/1', 'SW1', 'Gi0/1')]


def test_scan_reports_exactly_which_devices_were_saved(gui, monkeypatch):
    root, shown = gui
    real, calls = db_fake.save_credentials, []

    def flaky(did, user, pw):
        calls.append(did)
        if len(calls) == 2:
            raise RuntimeError('lost connection')
        return real(did, user, pw)
    monkeypatch.setattr(db_fake, 'save_credentials', flaky)
    scan = make_scan(root, monkeypatch)
    scan.approve()
    kind, title, text = shown[-1]
    assert (kind, title) == ('showerror', 'Could not save')
    assert '1 of 4 devices were saved' in text
    assert 'Saved: CORE.' in text and 'Failed (not saved, nothing of it kept): SW1.' in text
    assert 'Not attempted: SW2, PRN.' in text and 'lost connection' in text
    assert [d['name'] for d in db_fake.get_devices()] == ['CORE']     # SW1 left no row behind
    assert db_fake.get_links() == []
    assert scan.last_result == {'ok': False, 'total': 4, 'saved': 1, 'error': 'lost connection'}
    assert PASSWORD not in text + scan.status.cget('text')
