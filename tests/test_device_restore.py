"""Phase 3C-3: soft-deleted devices are never restored silently.

* save_device with the IP of a deleted device raises DeletedDeviceExists and changes nothing.
* restore_device(device_id, data, credentials='keep' | 'replace') restores that exact
  record, in one transaction, keeping or replacing its login.
* The Devices dialog and Scan -> Approve ask explicitly; Cancel changes nothing.
db.py is tested with a stand-in connection, db_fake in memory: MySQL is never contacted.
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
from store_errors import DeletedDeviceExists, DeviceNotDeleted
from test_device_save import FakeConnection, PASSWORD

OLD_PASSWORD = 'Old-Saved-Pa55'
NEW_PASSWORD = 'New-Typed-Pa55'


@pytest.fixture
def keyenv(monkeypatch, tmp_path):
    monkeypatch.setattr(security, 'ENV_PATH', str(tmp_path / '.env'))
    key = Fernet.generate_key().decode()
    monkeypatch.setenv('FERNET_KEY', key)
    return key


def dev(name='SW1', ip='10.9.0.1', managed=True, kind='switch'):
    return {'name': name, 'ip': ip, 'mac': '', 'type': kind, 'managed': managed, 'status': 'up'}


@pytest.fixture
def fakeconn(monkeypatch):
    made, holder = [], {'kw': {}}

    def connect():
        conn = FakeConnection(**holder['kw'])
        made.append(conn)
        return conn
    monkeypatch.setattr(db, 'get_conn', connect)
    monkeypatch.setattr(db, '_run', lambda *a, **k: pytest.fail('unexpected _run call'))
    return made, holder


def no_connection(monkeypatch):
    monkeypatch.setattr(db, 'get_conn', lambda: pytest.fail('connected to the database'))


DELETED_ROW = {'id': 5, 'name': 'OLD-SW', 'ip': '10.9.0.1', 'type': 'switch', 'has_login': 1}


# ---------------------------------------------------------------- db.py: no silent restore
def test_db_adding_a_deleted_ip_raises_and_writes_nothing(keyenv, fakeconn):
    made, holder = fakeconn
    holder['kw'] = {'deleted': dict(DELETED_ROW)}
    with pytest.raises(DeletedDeviceExists) as err:
        db.save_device(None, dev('NEW-SW'), 'admin', PASSWORD)
    (conn,) = made
    assert conn.writes(conn.pending + conn.committed) == []      # no INSERT, no UPDATE
    assert (conn.commits, conn.rollbacks) == (0, 1)
    info = err.value.device
    assert info == {'id': 5, 'name': 'OLD-SW', 'ip': '10.9.0.1', 'type': 'switch', 'has_login': True}
    assert PASSWORD not in str(err.value) and 'password' not in str(info)
    assert isinstance(err.value, ValueError)


def test_db_lookup_is_inside_the_transaction_and_locks_the_row(keyenv, fakeconn):
    made, holder = fakeconn
    holder['kw'] = {'deleted': None}
    db.save_device(None, dev('NEW-SW', '10.9.0.7'))
    conn = made[0]
    first_sql = conn.committed[0][0]
    assert first_sql.startswith('SELECT') and 'is_deleted = 1' in first_sql and 'FOR UPDATE' in first_sql
    assert conn.writes(conn.committed) == ['INSERT INTO']         # active / new IP: as before


def test_db_editing_to_a_deleted_ip_is_refused(keyenv, fakeconn):
    made, holder = fakeconn
    holder['kw'] = {'deleted': dict(DELETED_ROW)}
    with pytest.raises(DeletedDeviceExists):
        db.save_device(9, dev('SW9', '10.9.0.1'))
    assert made[0].writes(made[0].pending + made[0].committed) == []


def test_db_get_deleted_device_by_ip_returns_no_secrets(monkeypatch):
    seen = []
    monkeypatch.setattr(db, '_run', lambda sql, params, fetch=None: seen.append(sql) or dict(DELETED_ROW))
    row = db.get_deleted_device_by_ip('10.9.0.1')
    assert row['has_login'] is True and set(row) == {'id', 'name', 'ip', 'type', 'has_login'}
    assert 'password_enc' not in seen[0].split('AS has_login')[1]          # not selected as a column
    assert 'is_deleted = 1' in seen[0]


# ---------------------------------------------------------------- db.py: explicit restore
def restore_row(**over):
    row = {'id': 5, 'name': 'OLD-SW', 'ip': '10.9.0.1', 'is_deleted': 1}
    row.update(over)
    return row


def test_db_restore_keep_leaves_the_login_untouched(keyenv, fakeconn):
    made, holder = fakeconn
    holder['kw'] = {'row': restore_row()}
    assert db.restore_device(5, dev('NEW-SW'), credentials='keep') == 5
    conn = made[0]
    rows = conn.write_rows(conn.committed)
    assert [r[0].split()[0] + ' ' + r[0].split()[1] for r in rows] == \
        ['UPDATE devices', 'UPDATE links', 'UPDATE links']
    assert 'is_deleted = 0' in rows[0][0] and 'WHERE id = %s AND is_deleted = 1' in rows[0][0]
    assert rows[0][1][-1] == 5                                    # exactly this device id
    assert not any('password_enc' in sql for sql, _ in rows)      # login columns not touched
    assert conn.commits == 1


def test_db_restore_replace_stores_the_new_encrypted_login(keyenv, fakeconn):
    made, holder = fakeconn
    holder['kw'] = {'row': restore_row(name='NEW-SW')}            # same name: no link updates
    db.restore_device(5, dev('NEW-SW'), credentials='replace', username='ops',
                      password=NEW_PASSWORD)
    rows = made[0].write_rows(made[0].committed)
    assert len(rows) == 2 and 'password_enc' in rows[1][0]
    user, token, did = rows[1][1]
    assert (user, did) == ('ops', 5) and security.decrypt(token) == NEW_PASSWORD
    assert NEW_PASSWORD not in str(made[0].committed)


@pytest.mark.parametrize('kwargs, words', [
    ({'credentials': 'replace', 'username': '', 'password': ''}, 'Enter the new login'),
    ({'credentials': 'replace', 'username': 'ops', 'password': ''}, 'Enter the new login'),
    ({'credentials': 'replace', 'username': 'u' * 51, 'password': NEW_PASSWORD}, '50 characters'),
    ({'credentials': 'replace', 'username': 'ops', 'password': 'é' * 64}, '127'),
    ({'credentials': 'keep', 'username': 'ops', 'password': NEW_PASSWORD}, 'keep the saved login'),
    ({'credentials': 'maybe'}, "Choose 'keep' or 'replace'"),
])
def test_db_invalid_restore_requests_never_connect(keyenv, monkeypatch, kwargs, words):
    no_connection(monkeypatch)
    with pytest.raises(ValueError) as err:
        db.restore_device(5, dev('NEW-SW'), **kwargs)
    assert words in str(err.value) and NEW_PASSWORD not in str(err.value)


def test_db_restore_requires_an_explicit_choice(keyenv, monkeypatch):
    no_connection(monkeypatch)
    with pytest.raises(TypeError):
        db.restore_device(5, dev('NEW-SW'))                       # no default for credentials


def test_db_restore_encryption_failure_rolls_back_before_connecting(monkeypatch, tmp_path):
    monkeypatch.setattr(security, 'ENV_PATH', str(tmp_path / '.env'))
    monkeypatch.delenv('FERNET_KEY', raising=False)
    no_connection(monkeypatch)
    with pytest.raises(RuntimeError) as err:
        db.restore_device(5, dev('NEW-SW'), credentials='replace', username='ops',
                          password=NEW_PASSWORD)
    assert 'FERNET_KEY' in str(err.value) and NEW_PASSWORD not in str(err.value)


def test_db_restore_update_failure_rolls_back_everything(keyenv, fakeconn):
    made, holder = fakeconn
    holder['kw'] = {'row': restore_row(), 'fail_on': 'SET username'}
    with pytest.raises(Exception):
        db.restore_device(5, dev('NEW-SW'), credentials='replace', username='ops',
                          password=NEW_PASSWORD)
    conn = made[0]
    assert conn.committed == [] and (conn.commits, conn.rollbacks, conn.closes) == (0, 1, 1)


def test_db_restore_refuses_an_active_device_and_a_wrong_ip(keyenv, fakeconn):
    made, holder = fakeconn
    holder['kw'] = {'row': restore_row(is_deleted=0)}             # already restored
    with pytest.raises(DeviceNotDeleted):
        db.restore_device(5, dev('NEW-SW'), credentials='keep')
    holder['kw'] = {'row': restore_row()}
    with pytest.raises(ValueError, match='has IP 10.9.0.1'):
        db.restore_device(5, dev('NEW-SW', '10.9.0.99'), credentials='keep')
    holder['kw'] = {'row': None}
    with pytest.raises(ValueError, match='no longer exists'):
        db.restore_device(5, dev('NEW-SW'), credentials='keep')
    holder['kw'] = {'row': restore_row(), 'rowcount': 0}         # changed between SELECT and UPDATE
    with pytest.raises(DeviceNotDeleted):
        db.restore_device(5, dev('NEW-SW'), credentials='keep')
    assert all(c.committed == [] and c.rollbacks == 1 for c in made)


# ---------------------------------------------------------------- db_fake: same behaviour
@pytest.fixture
def fake():
    db_fake.reset()
    old = db_fake.save_device(None, dev('OLD-SW', '10.9.0.1'), 'admin', OLD_PASSWORD)
    other = db_fake.save_device(None, dev('OTHER', '10.9.0.2'))
    db_fake.add_log(old, 'Configuration', 'success', 'Applied')
    db_fake.save_links([('OLD-SW', 'Gi0/1', 'OTHER', 'Gi0/1')])
    db_fake.delete_device(old)
    yield db_fake, old, other
    db_fake.reset()


def test_fake_adding_a_deleted_ip_raises_and_keeps_it_deleted(fake):
    store, old, other = fake
    with pytest.raises(DeletedDeviceExists) as err:
        store.save_device(None, dev('NEW-SW', '10.9.0.1'), 'x', NEW_PASSWORD)
    assert err.value.device == {'id': old, 'name': 'OLD-SW', 'ip': '10.9.0.1', 'type': 'switch',
                                'has_login': True}
    assert store.get_device(old) is None                           # still deleted
    assert store.get_credentials(old) == ('admin', OLD_PASSWORD)    # login untouched
    assert store.save_device(None, dev('OTHER-2', '10.9.0.2')) == other   # active IP: as before


def test_fake_restore_keep_and_history(fake):
    store, old, other = fake
    assert store.restore_device(old, dev('NEW-SW', '10.9.0.1'), credentials='keep') == old
    assert store.get_device(old)['name'] == 'NEW-SW'
    assert store.get_credentials(old) == ('admin', OLD_PASSWORD)
    assert store.count_logs() == 1                                  # history preserved
    assert store.get_links() == [('NEW-SW', 'Gi0/1', 'OTHER', 'Gi0/1')]
    assert store.get_device(other)['name'] == 'OTHER'               # the other device untouched
    with pytest.raises(DeviceNotDeleted):                           # cannot be restored twice
        store.restore_device(old, dev('AGAIN', '10.9.0.1'), credentials='keep')
    assert store.get_device(old)['name'] == 'NEW-SW'


def test_fake_restore_replace_and_rollback(fake, monkeypatch):
    store, old, _ = fake
    monkeypatch.setattr(store, 'save_credentials', lambda *a: (_ for _ in ()).throw(RuntimeError('x')))
    with pytest.raises(RuntimeError):
        store.restore_device(old, dev('NEW-SW', '10.9.0.1'), credentials='replace',
                             username='ops', password=NEW_PASSWORD)
    assert store.get_device(old) is None                            # still deleted
    assert store.get_links() == []                                  # (hidden: endpoint deleted)
    monkeypatch.undo()
    store.restore_device(old, dev('NEW-SW', '10.9.0.1'), credentials='replace',
                         username='ops', password=NEW_PASSWORD)
    assert store.get_credentials(old) == ('ops', NEW_PASSWORD)


def test_fake_invalid_replace_restores_nothing(fake):
    store, old, _ = fake
    for kwargs in ({'credentials': 'replace', 'username': '', 'password': ''},
                   {'credentials': 'replace', 'username': 'u' * 51, 'password': 'x'},
                   {'credentials': 'keep', 'username': 'ops', 'password': 'x'}):
        with pytest.raises(ValueError):
            store.restore_device(old, dev('NEW-SW', '10.9.0.1'), **kwargs)
    assert store.get_device(old) is None


# ---------------------------------------------------------------- GUI
@pytest.fixture
def gui(monkeypatch, fake):
    pytest.importorskip('tkinter')
    from tkinter import messagebox
    from gui_helpers import new_root
    from gui import theme
    root = new_root()
    theme.apply(root)
    shown, answers = [], {'yes': True}
    for name in ('showinfo', 'showerror', 'showwarning'):
        monkeypatch.setattr(messagebox, name, lambda t, m, _n=name, **k: shown.append((_n, t, m)))
    monkeypatch.setattr(messagebox, 'askyesno',
                        lambda t, m, **k: shown.append(('askyesno', t, m)) or answers['yes'])
    yield root, shown, answers
    root.destroy()


def add_dialog(root, name='NEW-SW', ip='10.9.0.1', username='', password=''):
    from gui.devices_tab import DeviceDialog
    saved = []
    d = DeviceDialog(root, db_fake, None, lambda: saved.append(1))
    for k, v in {'name': name, 'ip': ip, 'username': username, 'password': password}.items():
        d.vars[k].set(v)
    d.save()
    return d, saved


def test_dialog_offers_restore_instead_of_restoring(gui, fake):
    root, shown, _ = gui
    store, old, _ = fake
    d, saved = add_dialog(root)
    assert hasattr(d, 'restore_dialog') and saved == []
    assert store.get_device(old) is None                           # nothing restored yet
    text = ' '.join(str(w.cget('text')) for w in d.restore_dialog.winfo_children()
                    if 'text' in w.keys())
    assert 'OLD-SW' in text and '10.9.0.1' in text and 'switch' in text
    assert OLD_PASSWORD not in text and 'admin' not in text        # nothing of the old login
    assert d.restore_dialog.username.get() == '' and d.restore_dialog.password.get() == ''


def test_dialog_cancel_changes_nothing(gui, fake):
    root, shown, _ = gui
    store, old, _ = fake
    d, saved = add_dialog(root)
    d.restore_dialog.cancel()
    assert store.get_device(old) is None and saved == []
    assert store.get_credentials(old) == ('admin', OLD_PASSWORD)


def test_dialog_requires_a_login_choice_and_confirmation(gui, fake):
    root, shown, answers = gui
    store, old, _ = fake
    d, saved = add_dialog(root)
    r = d.restore_dialog
    r.confirm()                                                    # no choice made
    assert shown[-1][:2] == ('showerror', 'Choose an option') and store.get_device(old) is None
    r.choice.set('keep')
    answers['yes'] = False
    r.confirm()                                                    # "No" at the confirmation
    assert shown[-1][0] == 'askyesno' and store.get_device(old) is None
    answers['yes'] = True
    r.confirm()
    assert store.get_device(old)['name'] == 'NEW-SW' and saved == [1]
    assert store.get_credentials(old) == ('admin', OLD_PASSWORD)  # kept exactly


def test_dialog_replace_validates_then_restores_with_the_new_login(gui, fake):
    root, shown, _ = gui
    store, old, _ = fake
    d, saved = add_dialog(root)
    r = d.restore_dialog
    r.choice.set('replace')
    r.confirm()                                                    # blank replacement
    assert shown[-1][:2] == ('showerror', 'Cannot restore') and store.get_device(old) is None
    r.username.set('u' * 51); r.password.set(NEW_PASSWORD)
    r.confirm()
    assert '50 characters' in shown[-1][2] and store.get_device(old) is None
    r.username.set('ops')
    r.confirm()
    assert store.get_credentials(old) == ('ops', NEW_PASSWORD) and saved == [1]
    assert NEW_PASSWORD not in str(shown) and OLD_PASSWORD not in str(shown)


def test_dialog_restore_failure_says_nothing_changed(gui, fake, monkeypatch):
    root, shown, _ = gui
    store, old, _ = fake
    d, saved = add_dialog(root)
    monkeypatch.setattr(db_fake, 'save_credentials',
                        lambda *a: (_ for _ in ()).throw(RuntimeError('database went away')))
    r = d.restore_dialog
    r.choice.set('replace'); r.username.set('ops'); r.password.set(NEW_PASSWORD)
    r.confirm()
    assert shown[-1][:2] == ('showerror', 'Restore failed')
    assert shown[-1][2] == 'Nothing was changed. database went away'
    assert store.get_device(old) is None and saved == []


def test_dialog_edit_to_a_deleted_ip_is_refused_without_restore(gui, fake):
    root, shown, _ = gui
    store, old, other = fake
    from gui.devices_tab import DeviceDialog
    d = DeviceDialog(root, db_fake, store.get_device(other), lambda: None)
    d.vars['ip'].set('10.9.0.1')
    d.save()
    assert shown[-1][1] == 'Cannot save' and 'deleted device OLD-SW' in shown[-1][2]
    assert not hasattr(d, 'restore_dialog') and store.get_device(other)['ip'] == '10.9.0.2'


# ---------------------------------------------------------------- Scan -> Approve
def make_scan(root, devices, user='scanuser', password=NEW_PASSWORD):
    from gui.scan_tab import ScanTab
    scan = ScanTab(root, db_fake, lambda *a: None, sample_store=False)
    scan.pack()
    scan.show_found(devices, [])
    scan.user.set(user); scan.pw.set(password); scan.save_login.set(1)
    scan.select_all()
    return scan


def test_scan_never_restores_silently(gui, fake):
    root, shown, _ = gui
    store, old, _ = fake
    scan = make_scan(root, [dev('NEW-SW', '10.9.0.1'), dev('SW3', '10.9.0.3')])
    scan.approve()
    assert hasattr(scan, 'restore_dialog')                          # asked, nothing saved yet
    assert store.get_device(old) is None and store.count_devices() == 1   # only OTHER
    scan.restore_dialog.cancel()
    assert store.get_device(old) is None and store.count_devices() == 1
    assert 'cancelled' in scan.status.cget('text')


def test_scan_unticked_device_stays_deleted_and_is_reported(gui, fake):
    root, shown, _ = gui
    store, old, _ = fake
    scan = make_scan(root, [dev('NEW-SW', '10.9.0.1'), dev('SW3', '10.9.0.3')])
    scan.approve()
    scan.restore_dialog.confirm()                                   # nothing ticked
    assert store.get_device(old) is None
    assert shown[-1][:2] == ('showinfo', 'Approved')
    assert 'Not restored (still deleted): NEW-SW.' in shown[-1][2]
    assert scan.last_result['skipped'] == 1 and 'restored' not in scan.last_result


def test_scan_restore_keep_and_replace_per_device(gui, fake):
    root, shown, _ = gui
    store, old, other = fake
    second = store.save_device(None, dev('OLD-R', '10.9.0.5', kind='router'), 'radm', OLD_PASSWORD)
    store.delete_device(second)
    scan = make_scan(root, [dev('NEW-SW', '10.9.0.1'), dev('NEW-R', '10.9.0.5', kind='router'),
                            dev('SW3', '10.9.0.3')])
    scan.approve()
    rows = scan.restore_dialog.rows
    for row in rows:
        row['restore'].set(1)
    rows[0]['choice'].set('keep')
    scan.restore_dialog.confirm()                                   # second row has no choice
    assert shown[-1][:2] == ('showerror', 'Choose a login option')
    assert store.get_device(old) is None and store.get_device(second) is None
    rows[1]['choice'].set('replace')
    scan.restore_dialog.confirm()
    assert shown[-1][:2] == ('showinfo', 'Approved')
    assert 'Restored: NEW-SW, NEW-R.' in shown[-1][2]
    assert store.get_credentials(old) == ('admin', OLD_PASSWORD)            # kept
    assert store.get_credentials(second) == ('scanuser', NEW_PASSWORD)      # replaced
    assert store.get_device(old)['name'] == 'NEW-SW' and store.get_device(second)['name'] == 'NEW-R'
    assert scan.last_result['restored'] == 2
    assert NEW_PASSWORD not in str(shown) and OLD_PASSWORD not in str(shown)


def test_scan_reports_a_failed_restore_accurately(gui, fake, monkeypatch):
    root, shown, _ = gui
    store, old, _ = fake

    def broken(*a, **k):
        raise RuntimeError('restore failed in the database')
    scan = make_scan(root, [dev('SW3', '10.9.0.3'), dev('NEW-SW', '10.9.0.1'), dev('SW4', '10.9.0.4')])
    scan.approve()
    scan.restore_dialog.rows[0]['restore'].set(1)
    scan.restore_dialog.rows[0]['choice'].set('keep')
    monkeypatch.setattr(db_fake, 'restore_device', broken)
    scan.restore_dialog.confirm()
    kind, title, text = shown[-1]
    assert (kind, title) == ('showerror', 'Could not save')
    assert 'Saved: SW3.' in text and 'Failed (not saved, nothing of it kept): NEW-SW.' in text
    assert 'Not attempted: SW4.' in text and 'restored' not in text.split('Failed')[0]
    assert store.get_device(old) is None                            # not claimed, not restored
    assert scan.last_result == {'ok': False, 'total': 3, 'saved': 1,
                                'error': 'restore failed in the database'}


def test_scan_without_deleted_ips_works_as_before(gui, fake):
    root, shown, _ = gui
    store, old, other = fake
    scan = make_scan(root, [dev('SW3', '10.9.0.3'), dev('OTHER-NEW', '10.9.0.2')])
    scan.approve()
    assert not hasattr(scan, 'restore_dialog')
    assert shown[-1] == ('showinfo', 'Approved',
                         '2 devices registered (1 new, 1 already registered and updated).')
    assert scan.last_result == {'ok': True, 'total': 2, 'added': 1, 'updated': 1, 'links': 0}


# ---------------------------------------------------------------- follow-up: upsert_device is safe too
class SentConnection(FakeConnection):
    """FakeConnection that also remembers every statement SENT (kept or rolled back).
    gone: what the 'is the saved row a deleted device?' re-check finds."""

    def __init__(self, gone=None, **kw):
        super().__init__(**kw)
        self.gone, self.sent = gone, []

    def cursor(self):
        cur = super().cursor()
        execute, fetchone = cur.execute, cur.fetchone

        def logged(sql, params=()):
            self.sent.append((sql, params))
            return execute(sql, params)

        def answer():
            if cur.last_sql == db._DELETED_BY_ID_SQL:
                return dict(self.gone) if self.gone else None
            return fetchone()
        cur.execute, cur.fetchone = logged, answer
        return cur


def upsert_conn(monkeypatch, **kw):
    """upsert_device runs in save_device's transaction (3C-5 follow-up): one stand-in
    connection, and any one-statement _run call fails the test."""
    made = []
    monkeypatch.setattr(db, 'get_conn',
                        lambda *a, **k: made.append(SentConnection(**kw)) or made[-1])
    monkeypatch.setattr(db, '_run', lambda *a, **k: pytest.fail('unexpected _run call'))
    return made


def test_db_upsert_refuses_a_deleted_ip_without_writing(monkeypatch):
    made = upsert_conn(monkeypatch, deleted=DELETED_ROW)
    with pytest.raises(DeletedDeviceExists) as err:
        db.upsert_device(dev('NEW-SW', '10.9.0.1'))
    conn, = made
    assert err.value.device['id'] == 5
    assert [sql for sql, _ in conn.sent] == [db._DELETED_BY_IP_SQL + ' FOR UPDATE']  # no INSERT
    assert conn.rollbacks == 1 and conn.commits == 0


def test_db_upsert_new_and_active_ips_work_as_before(monkeypatch):
    made = upsert_conn(monkeypatch, lastrowid=5)
    assert db.upsert_device(dev('NEW-SW', '10.9.0.7')) == 5
    conn, = made
    name_sql, _ = db._name_taken_query('NEW-SW', exclude_ip='10.9.0.7', lock=True)
    assert [sql for sql, _ in conn.sent] == [db._DELETED_BY_IP_SQL + ' FOR UPDATE', name_sql,
                                             db._UPSERT_SQL, db._DELETED_BY_ID_SQL]
    assert conn.commits == 1 and conn.rollbacks == 0


def test_db_upsert_reports_a_device_deleted_meanwhile(monkeypatch):
    """The row with this IP turns out to be a deleted one after the insert: the guarded
    SQL left it untouched, the transaction is rolled back, and the caller is told instead
    of being told it was saved."""
    made = upsert_conn(monkeypatch, gone=DELETED_ROW, lastrowid=5)
    with pytest.raises(DeletedDeviceExists) as err:
        db.upsert_device(dev('NEW-SW', '10.9.0.1'))
    conn, = made
    assert err.value.device['id'] == 5
    assert conn.rollbacks == 1 and conn.commits == 0 and conn.committed == []


def test_db_save_device_add_reports_a_device_deleted_meanwhile(monkeypatch, keyenv):
    made = upsert_conn(monkeypatch, gone=DELETED_ROW, lastrowid=5)
    with pytest.raises(DeletedDeviceExists):
        db.save_device(None, dev('NEW-SW', '10.9.0.1'), 'admin', PASSWORD)
    conn, = made
    assert conn.rollbacks == 1 and conn.committed == []
    assert not any(sql.startswith('UPDATE devices SET username')       # stopped before the login
                   for sql, _ in conn.sent)


def test_upsert_sql_can_never_undelete_or_change_a_deleted_row():
    import re
    update_part = db._UPSERT_SQL.split('ON DUPLICATE KEY UPDATE', 1)[1]
    # is_deleted is never ASSIGNED (only read inside the IF() guards)
    assert not re.search(r'(^|,)\s*is_deleted\s*=', update_part)
    for column in ('name', 'type', 'managed', 'status'):
        assert f'{column} = IF(is_deleted = 0, VALUES({column}), {column})' in update_part
    assert update_part.count('is_deleted = 0') == 4                # only inside the four IF()s


def test_fake_upsert_refuses_a_deleted_ip_and_changes_nothing(fake):
    store, old, other = fake
    before = dict(store._devices[old])
    with pytest.raises(DeletedDeviceExists) as err:
        store.upsert_device(dev('NEW-SW', '10.9.0.1'))
    assert err.value.device['id'] == old
    assert store._devices[old] == before                            # name, flags, all unchanged
    assert store.get_credentials(old) == ('admin', OLD_PASSWORD)
    assert store.upsert_device(dev('OTHER-2', '10.9.0.2')) == other    # active IP: updated
    assert store.get_device(other)['name'] == 'OTHER-2'


# ---------------------------------------------------------------- follow-up: MAC address on restore
def test_check_mac_formats():
    import validation
    for ok in ('aa:bb:cc:dd:ee:ff', 'AA-BB-CC-DD-EE-01', 'aabb.ccdd.eeff'):
        assert validation.check_mac(ok) is None
    for bad in ('aa:bb:cc:dd:ee', 'aa:bb-cc:dd:ee:ff', 'zz:bb:cc:dd:ee:ff', 'hello', ''):
        assert validation.check_mac(bad)


def test_db_restore_updates_a_valid_mac(keyenv, fakeconn):
    made, holder = fakeconn
    holder['kw'] = {'row': restore_row(name='NEW-SW')}
    db.restore_device(5, dict(dev('NEW-SW'), mac='aa:bb:cc:dd:ee:ff'), credentials='keep')
    (sql, params), = made[0].write_rows(made[0].committed)
    assert 'mac = %s' in sql and params == ('NEW-SW', 'switch', 'up', 1, 'aa:bb:cc:dd:ee:ff', 5)


@pytest.mark.parametrize('mac', ['', '   ', None, 'missing'])
def test_db_restore_keeps_the_stored_mac_when_none_is_supplied(keyenv, fakeconn, mac):
    made, holder = fakeconn
    holder['kw'] = {'row': restore_row(name='NEW-SW')}
    data = dev('NEW-SW')
    if mac == 'missing':
        data.pop('mac')
    else:
        data['mac'] = mac
    db.restore_device(5, data, credentials='keep')
    (sql, params), = made[0].write_rows(made[0].committed)
    assert 'mac' not in sql and params == ('NEW-SW', 'switch', 'up', 1, 5)


def test_db_restore_refuses_an_invalid_mac_before_connecting(keyenv, monkeypatch):
    no_connection(monkeypatch)
    with pytest.raises(ValueError, match='not a MAC address'):
        db.restore_device(5, dict(dev('NEW-SW'), mac='not-a-mac'), credentials='keep')


@pytest.fixture
def fake_with_mac():
    db_fake.reset()
    old = db_fake.save_device(None, dict(dev('OLD-SW', '10.9.0.1'), mac='00:11:22:33:44:55'))
    db_fake.delete_device(old)
    yield db_fake, old
    db_fake.reset()


def test_fake_restore_mac_rules(fake_with_mac):
    store, old = fake_with_mac
    with pytest.raises(ValueError):                                  # invalid: refused, still deleted
        store.restore_device(old, dict(dev('NEW-SW', '10.9.0.1'), mac='bad'), credentials='keep')
    assert store.get_device(old) is None
    store.restore_device(old, dict(dev('NEW-SW', '10.9.0.1'), mac=''), credentials='keep')
    assert store.get_device(old)['mac'] == '00:11:22:33:44:55'       # empty never blanks it out
    store.delete_device(old)
    store.restore_device(old, dict(dev('NEW-SW', '10.9.0.1'), mac='66:77:88:99:aa:bb'),
                         credentials='keep')
    assert store.get_device(old)['mac'] == '66:77:88:99:aa:bb'       # a new valid MAC wins


def test_scan_restore_keeps_the_known_mac(gui, fake_with_mac):
    """Scan results carry mac='' today (discovery does not read MACs): the known MAC stays."""
    root, shown, _ = gui
    store, old = fake_with_mac
    scan = make_scan(root, [dev('NEW-SW', '10.9.0.1')])
    scan.approve()
    scan.restore_dialog.rows[0]['restore'].set(1)
    scan.restore_dialog.rows[0]['choice'].set('keep')
    scan.restore_dialog.confirm()
    assert store.get_device(old)['mac'] == '00:11:22:33:44:55'
