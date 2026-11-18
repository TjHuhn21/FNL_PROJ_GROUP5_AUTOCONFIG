"""Phase 3C-5: no two ACTIVE devices may share a name (capital letters ignored).

* db_fake: the rules in memory (also run against MySQL by test_store_contract when
  NETCOMMAND_TEST_DB=1; never here).
* db.py: the check runs inside the save/restore transaction (stand-in connection from
  test_device_save: statements are only kept on commit). No MySQL is contacted.
* Devices dialogs and Scan -> Approve report a taken name and save nothing.
"""
import os
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))
sys.path.insert(0, os.path.dirname(__file__))

import pytest
from cryptography.fernet import Fernet

import db
import db_fake
import security
from store_errors import DeletedDeviceExists, DuplicateDeviceName
from test_device_save import FakeConnection

PASSWORD = 'Sw1tch-Secret-Pa55'


def dev(name, ip, managed=True):
    return {'name': name, 'ip': ip, 'mac': '', 'type': 'switch', 'managed': managed,
            'status': 'up'}


@pytest.fixture(autouse=True)
def safe_env(monkeypatch, tmp_path):
    """A temporary key; the real .env is never read; a real connection fails the test."""
    monkeypatch.setattr(security, 'ENV_PATH', str(tmp_path / '.env'))
    monkeypatch.setenv('FERNET_KEY', Fernet.generate_key().decode())
    monkeypatch.setattr(db, 'get_conn', lambda *a, **k: pytest.fail('connected to MySQL'))
    monkeypatch.setattr(db, '_run', lambda *a, **k: pytest.fail('unexpected _run call'))
    db_fake.reset()


# ================================================================ db_fake
def test_fake_unique_name_is_added():
    a = db_fake.save_device(None, dev('CORE-SW', '10.0.0.1'))
    b = db_fake.save_device(None, dev('ACCESS-SW', '10.0.0.2'))
    assert a != b and db_fake.count_devices() == 2


@pytest.mark.parametrize('name', ['CORE-SW', 'core-sw', 'Core-Sw', 'cORE-sW'])
def test_fake_duplicate_name_any_capitalisation_is_refused(name):
    a = db_fake.save_device(None, dev('CORE-SW', '10.0.0.1'))
    with pytest.raises(DuplicateDeviceName) as err:
        db_fake.save_device(None, dev(name, '10.0.0.2'), 'admin', PASSWORD)
    assert err.value.existing == {'id': a, 'name': 'CORE-SW'}
    assert 'CORE-SW' in str(err.value) and PASSWORD not in str(err.value)
    assert db_fake.count_devices() == 1 and db_fake.get_device_by_ip('10.0.0.2') is None
    assert db_fake._logins == {}                                 # no login kept either


def test_fake_upsert_refuses_a_duplicate_too():
    db_fake.upsert_device(dev('CORE-SW', '10.0.0.1'))
    with pytest.raises(DuplicateDeviceName):
        db_fake.upsert_device(dev('core-sw', '10.0.0.2'))
    assert db_fake.count_devices() == 1


def test_fake_deleted_device_does_not_block_its_old_name():
    a = db_fake.save_device(None, dev('CORE-SW', '10.0.0.1'))
    db_fake.delete_device(a)
    b = db_fake.save_device(None, dev('core-sw', '10.0.0.2'))
    assert db_fake.get_device(b)['name'] == 'core-sw'


def test_fake_edit_keeps_its_own_name_and_may_change_its_capitals():
    a = db_fake.save_device(None, dev('CORE-SW', '10.0.0.1'))
    db_fake.save_device(a, dict(dev('CORE-SW', '10.0.0.1'), status='down'))
    assert db_fake.get_device(a)['status'] == 'down'
    db_fake.save_device(a, dev('core-sw', '10.0.0.1'))           # only its own name: allowed
    assert db_fake.get_device(a)['name'] == 'core-sw'


def test_fake_rename_to_another_active_name_rolls_everything_back():
    a = db_fake.save_device(None, dev('CORE-SW', '10.0.0.1'))
    b = db_fake.save_device(None, dev('ACCESS-SW', '10.0.0.2'), 'old', 'old-pass')
    db_fake.save_links([('ACCESS-SW', 'Gi0/1', 'CORE-SW', 'Gi0/2')])
    with pytest.raises(DuplicateDeviceName) as err:
        db_fake.save_device(b, dev('Core-SW', '10.0.0.2'), 'admin', PASSWORD)
    assert err.value.existing['id'] == a
    assert db_fake.get_device(b)['name'] == 'ACCESS-SW'
    assert db_fake.get_credentials(b) == ('old', 'old-pass')      # login unchanged
    assert db_fake.get_links() == [('ACCESS-SW', 'Gi0/1', 'CORE-SW', 'Gi0/2')]


def test_fake_same_ip_rescan_keeps_its_name_but_cannot_take_another():
    db_fake.save_device(None, dev('CORE-SW', '10.0.0.1'))
    b = db_fake.save_device(None, dev('ACCESS-SW', '10.0.0.2'))
    assert db_fake.save_device(None, dev('access-sw', '10.0.0.2')) == b   # its own device
    with pytest.raises(DuplicateDeviceName):
        db_fake.save_device(None, dev('core-sw', '10.0.0.2'))
    assert db_fake.get_device(b)['name'] == 'access-sw'


def test_fake_restore_with_a_taken_name_changes_nothing():
    a = db_fake.save_device(None, dev('CORE-SW', '10.0.0.1'), 'old', 'old-pass')
    db_fake.delete_device(a)
    b = db_fake.save_device(None, dev('core-sw', '10.0.0.2'))    # its name, reused meanwhile
    with pytest.raises(DuplicateDeviceName) as err:
        db_fake.restore_device(a, dev('CORE-SW', '10.0.0.1'), credentials='replace',
                               username='admin', password=PASSWORD)
    assert err.value.existing == {'id': b, 'name': 'core-sw'}
    assert db_fake.get_device(a) is None                          # still deleted
    assert db_fake.get_deleted_device_by_ip('10.0.0.1')['name'] == 'CORE-SW'
    assert db_fake._logins[a] == ('old', 'old-pass')


def test_fake_restore_with_a_unique_name_succeeds():
    a = db_fake.save_device(None, dev('CORE-SW', '10.0.0.1'))
    db_fake.delete_device(a)
    db_fake.save_device(None, dev('core-sw', '10.0.0.2'))
    assert db_fake.restore_device(a, dev('CORE-SW-OLD', '10.0.0.1'), credentials='keep') == a
    assert db_fake.get_device(a)['name'] == 'CORE-SW-OLD'


@pytest.mark.parametrize('name', ['', '   ', 'has space', 'bad/name', ' SW1', 'SW1 ', 'x' * 81])
def test_fake_invalid_names_write_nothing(name):
    with pytest.raises(ValueError) as err:
        db_fake.save_device(None, dev(name, '10.0.0.1'), 'admin', PASSWORD)
    assert not isinstance(err.value, DuplicateDeviceName)
    assert db_fake.count_devices() == 0 and db_fake._logins == {}


# ================================================================ db.py (stand-in connection)
@pytest.fixture
def conns(monkeypatch):
    made, kw = [], {}

    def connect(*a, **k):
        conn = FakeConnection(**kw)
        made.append(conn)
        return conn
    monkeypatch.setattr(db, 'get_conn', connect)
    return made, kw


def executed(conn):
    """Every statement this connection ran (kept or rolled back)."""
    return conn.log


@pytest.fixture(autouse=True)
def keep_log(monkeypatch):
    """FakeConnection drops statements on rollback; keep a log of everything executed."""
    from test_device_save import FakeCursor
    original = FakeCursor.execute

    def execute(self, sql, params=()):
        self.conn.__dict__.setdefault('log', []).append((sql, params))
        return original(self, sql, params)
    monkeypatch.setattr(FakeCursor, 'execute', execute)


def test_db_query_checks_active_devices_ignoring_case():
    sql, params = db._name_taken_query('Core-SW', exclude_ip='10.0.0.1', lock=True)
    assert 'is_deleted = 0' in sql
    assert 'LOWER(name) COLLATE utf8mb4_bin = LOWER(%s) COLLATE utf8mb4_bin' in sql
    assert sql.endswith('FOR UPDATE') and 'ip <> %s' in sql and 'id <> %s' not in sql
    assert params == ('Core-SW', '10.0.0.1')                      # a value, never pasted in
    sql, params = db._name_taken_query('SW1', exclude_id=4)
    assert 'id <> %s' in sql and 'FOR UPDATE' not in sql and params == ('SW1', 4)


def test_db_add_unique_name_is_checked_in_the_transaction_and_saved(conns):
    made, kw = conns
    assert db.save_device(None, dev('CORE-SW', '10.0.0.1'), 'admin', PASSWORD) == 7
    conn, = made
    sqls = [s for s, _ in executed(conn)]
    assert 'is_deleted = 1' in sqls[0]                            # deleted-IP check first
    assert 'LOWER(name)' in sqls[1] and sqls[1].endswith('FOR UPDATE')   # then the name, locked
    assert executed(conn)[1][1] == ('CORE-SW', '10.0.0.1')        # its own IP excluded
    assert sqls[2].startswith('INSERT') and conn.commits == 1 and conn.rollbacks == 0


def test_db_duplicate_name_rolls_back_device_and_login(conns):
    made, kw = conns
    kw['taken'] = {'id': 3, 'name': 'core-sw'}
    with pytest.raises(DuplicateDeviceName) as err:
        db.save_device(None, dev('CORE-SW', '10.0.0.1'), 'admin', PASSWORD)
    conn, = made
    assert err.value.existing == {'id': 3, 'name': 'core-sw'}
    assert conn.commits == 0 and conn.rollbacks == 1 and conn.closes == 1
    assert conn.committed == [] and conn.pending == []
    assert not [s for s, _ in executed(conn) if not s.startswith('SELECT')]   # no write ran
    assert PASSWORD not in str(err.value) and 'gAAAA' not in str(err.value)


def test_db_edit_excludes_its_own_id(conns):
    made, kw = conns
    db.save_device(4, dev('CORE-SW', '10.0.0.1'))
    conn, = made
    (sql, params), = [q for q in executed(conn) if 'LOWER(name)' in q[0]]
    assert 'id <> %s' in sql and 'ip <> %s' not in sql and params == ('CORE-SW', 4)
    assert conn.commits == 1


def test_db_rename_to_a_taken_name_writes_nothing(conns):
    made, kw = conns
    kw['taken'] = {'id': 3, 'name': 'CORE-SW'}
    with pytest.raises(DuplicateDeviceName):
        db.save_device(4, dev('core-sw', '10.0.0.4'), 'admin', PASSWORD)
    conn, = made
    assert conn.rollbacks == 1 and conn.committed == []
    assert not any(s.startswith('UPDATE') for s, _ in executed(conn))   # rename and login


def test_db_restore_with_a_taken_name_changes_nothing(conns):
    made, kw = conns
    kw['row'] = {'id': 5, 'name': 'CORE-SW', 'ip': '10.0.0.1', 'is_deleted': 1}
    kw['taken'] = {'id': 9, 'name': 'core-sw'}
    with pytest.raises(DuplicateDeviceName) as err:
        db.restore_device(5, dev('CORE-SW', '10.0.0.1'), credentials='replace',
                          username='admin', password=PASSWORD)
    conn, = made
    assert err.value.existing['id'] == 9
    assert conn.rollbacks == 1 and conn.commits == 0 and conn.committed == []
    assert not any(s.startswith('UPDATE') for s, _ in executed(conn))   # not undeleted
    (sql, params), = [q for q in executed(conn) if 'LOWER(name)' in q[0]]
    assert sql.endswith('FOR UPDATE') and params == ('CORE-SW', 5)


def test_db_restore_with_a_unique_name_succeeds(conns):
    made, kw = conns
    kw['row'] = {'id': 5, 'name': 'CORE-SW', 'ip': '10.0.0.1', 'is_deleted': 1}
    assert db.restore_device(5, dev('CORE-SW', '10.0.0.1'), credentials='keep') == 5
    conn, = made
    assert conn.commits == 1
    assert any('is_deleted = 0 WHERE id' in s for s, _ in conn.committed)


@pytest.mark.parametrize('name', ['', 'has space', 'bad/name', ' SW1', 'SW1 ', 'x' * 81])
def test_db_invalid_names_never_reach_the_database(name):
    # safe_env makes get_conn and _run fail the test if they are called at all
    for call in (lambda: db.save_device(None, dev(name, '10.0.0.1'), 'admin', PASSWORD),
                 lambda: db.save_device(3, dev(name, '10.0.0.1')),
                 lambda: db.restore_device(3, dev(name, '10.0.0.1'), credentials='keep'),
                 lambda: db.upsert_device(dev(name, '10.0.0.1')),
                 lambda: db.update_device(3, dev(name, '10.0.0.1'))):
        with pytest.raises(ValueError) as err:
            call()
        assert not isinstance(err.value, DuplicateDeviceName)


# ---------------------------------------------------------------- follow-up: upsert / update
# Both now run in save_device's transaction: the locked name check and the write are one
# atomic step (the safe_env fixture makes any one-statement _run call fail the test).
def test_db_upsert_and_update_refuse_a_taken_name_before_writing(conns):
    made, kw = conns
    kw['taken'] = {'id': 3, 'name': 'CORE-SW'}
    with pytest.raises(DuplicateDeviceName):
        db.upsert_device(dev('core-sw', '10.0.0.9'))
    with pytest.raises(DuplicateDeviceName):
        db.update_device(4, dev('core-sw', '10.0.0.9'))
    assert len(made) == 2                                         # one connection per call
    for conn in made:
        assert conn.rollbacks == 1 and conn.commits == 0 and conn.committed == []
        assert all(sql.startswith('SELECT') for sql, _ in executed(conn))   # nothing written
        assert any('LOWER(name)' in s and s.endswith('FOR UPDATE') for s, _ in executed(conn))


def test_db_upsert_unique_name_works_in_one_transaction(conns):
    made, kw = conns
    assert db.upsert_device(dev('CORE-SW', '10.0.0.9')) == 7
    conn, = made
    (sql, params), = [q for q in executed(conn) if 'LOWER(name)' in q[0]]
    assert params == ('CORE-SW', '10.0.0.9') and sql.endswith('FOR UPDATE')   # own IP excluded
    assert conn.commits == 1
    assert [s for s, _ in conn.committed if s.startswith('INSERT')] == [db._UPSERT_SQL]


def test_db_update_unique_name_renames_device_and_links_together(conns):
    made, kw = conns
    kw['existing_name'] = 'OLD-NAME'
    db.update_device(4, dev('NEW-NAME', '10.0.0.4'))
    conn, = made
    (sql, params), = [q for q in executed(conn) if 'LOWER(name)' in q[0]]
    assert params == ('NEW-NAME', 4) and sql.endswith('FOR UPDATE')        # own id excluded
    writes = [s.split(' SET ')[0] for s, _ in conn.committed if s.startswith('UPDATE')]
    assert writes == ['UPDATE devices', 'UPDATE links', 'UPDATE links']   # one commit, together
    assert conn.commits == 1
    assert not any(s.startswith('UPDATE devices SET username') for s, _ in executed(conn))


def test_db_update_link_failure_rolls_back_the_rename(conns):
    made, kw = conns
    kw.update(existing_name='OLD-NAME', fail_on='UPDATE links SET device_b')
    with pytest.raises(Exception):
        db.update_device(4, dev('NEW-NAME', '10.0.0.4'))
    conn, = made
    assert conn.rollbacks == 1 and conn.commits == 0 and conn.committed == []


def test_db_update_of_a_missing_device_changes_nothing(conns):
    made, kw = conns
    kw['existing_name'] = None                                    # no row with this id
    with pytest.raises(ValueError, match='no longer exists'):
        db.update_device(99, dev('NEW-NAME', '10.0.0.4'))
    conn, = made
    assert conn.rollbacks == 1 and conn.committed == []


# ---------------------------------------------------------------- follow-up: db_fake atomic
def test_fake_update_device_refuses_a_taken_name_and_a_missing_device():
    a = db_fake.upsert_device(dev('CORE-SW', '10.0.0.1'))
    b = db_fake.upsert_device(dev('ACCESS-SW', '10.0.0.2'))
    with pytest.raises(DuplicateDeviceName) as err:
        db_fake.update_device(b, dev('core-SW', '10.0.0.2'))
    assert err.value.existing['id'] == a and db_fake.get_device(b)['name'] == 'ACCESS-SW'
    with pytest.raises(ValueError, match='no longer exists'):
        db_fake.update_device(99, dev('NEW', '10.0.0.9'))


def test_fake_simultaneous_adds_of_one_name_save_exactly_one():
    import threading
    start, results = threading.Barrier(8), []

    def add(i):
        start.wait()
        try:
            results.append(('ok', db_fake.upsert_device(dev('SAME-NAME' if i % 2 else 'same-name',
                                                            f'10.5.0.{i + 1}'))))
        except DuplicateDeviceName:
            results.append(('dup', None))
    threads = [threading.Thread(target=add, args=(i,)) for i in range(8)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert sorted(r[0] for r in results) == ['dup'] * 7 + ['ok']
    assert db_fake.count_devices() == 1


def test_fake_name_changing_writes_share_one_lock():
    for name in ('upsert_device', 'update_device', 'save_device', 'restore_device'):
        assert getattr(db_fake, name).__wrapped__        # wrapped by _atomic
    with db_fake._write_lock:                            # re-entrant: save_device -> upsert_device
        assert db_fake.save_device(None, dev('CORE-SW', '10.0.0.1')) == 1


def test_db_deleted_ip_is_still_reported_first(conns):
    made, kw = conns
    kw['deleted'] = {'id': 2, 'name': 'OLD', 'ip': '10.0.0.1', 'type': 'switch', 'has_login': 0}
    kw['taken'] = {'id': 3, 'name': 'CORE-SW'}
    with pytest.raises(DeletedDeviceExists):                      # the restore offer comes first
        db.save_device(None, dev('CORE-SW', '10.0.0.1'))


# ================================================================ GUI
tk = pytest.importorskip('tkinter')


def pump(root, cond, timeout=10):
    end = time.time() + timeout
    while time.time() < end:
        root.update()
        if cond():
            return True
        time.sleep(0.02)
    return False


@pytest.fixture
def ui(monkeypatch):
    from tkinter import messagebox
    try:
        root = tk.Tk()
    except tk.TclError as err:
        pytest.skip(f'no display available ({err})')
    shown = []
    for name in ('showinfo', 'showerror', 'showwarning'):
        monkeypatch.setattr(messagebox, name,
                            lambda t, m, _n=name, **k: shown.append((_n, t, m)))
    monkeypatch.setattr(messagebox, 'askyesno', lambda *a, **k: True)
    db_fake.reset()
    db_fake.save_device(None, dev('CORE-SW', '10.0.0.1'))
    db_fake.save_device(None, dev('ACCESS-SW', '10.0.0.2'), 'old', 'old-pass')
    from gui.main_window import build_main_window
    refs = build_main_window(root, db_fake, demo_store=False)     # real-database mode
    refs['shown'] = shown
    yield root, refs
    root.destroy()


def test_gui_add_with_a_taken_name_keeps_the_dialog_open(ui):
    root, r = ui
    from gui.devices_tab import DeviceDialog
    saved = []
    dlg = DeviceDialog(r['devices'], db_fake, None, lambda: saved.append(1))
    dlg.vars['name'].set('core-sw'); dlg.vars['ip'].set('10.0.0.3')
    dlg.save()
    kind, title, msg = r['shown'][-1]
    assert (kind, title) == ('showerror', 'Name already used')
    assert msg.startswith('Nothing was saved.') and 'CORE-SW (ID 1)' in msg
    assert dlg.winfo_exists() and saved == []                    # open, nothing claimed
    assert db_fake.count_devices() == 2
    dlg.vars['name'].set('DIST-SW')                               # corrected: saves normally
    dlg.save()
    assert saved == [1] and db_fake.get_device_by_ip('10.0.0.3')['name'] == 'DIST-SW'


def test_gui_edit_to_another_devices_name_is_refused(ui):
    root, r = ui
    from gui.devices_tab import DeviceDialog
    dlg = DeviceDialog(r['devices'], db_fake, db_fake.get_device(2), lambda: None)
    dlg.vars['name'].set('Core-Sw')
    dlg.vars['username'].set('admin'); dlg.vars['password'].set(PASSWORD)
    dlg.save()
    assert r['shown'][-1][1] == 'Name already used' and dlg.winfo_exists()
    assert db_fake.get_device(2)['name'] == 'ACCESS-SW'
    assert db_fake.get_credentials(2) == ('old', 'old-pass')
    dlg.destroy()


def test_gui_restore_with_a_taken_name_explains_it(ui):
    root, r = ui
    from gui.devices_tab import DeviceDialog
    db_fake.delete_device(1)
    db_fake.save_device(None, dev('core-sw', '10.0.0.5'))         # reused while deleted
    dlg = DeviceDialog(r['devices'], db_fake, None, lambda: None)
    dlg.vars['name'].set('CORE-SW'); dlg.vars['ip'].set('10.0.0.1')
    dlg.save()                                                    # deleted IP: restore offer
    restore = dlg.restore_dialog
    restore.choice.set('keep')
    restore.confirm()
    kind, title, msg = r['shown'][-1]
    assert title == 'Name already used' and 'was not restored' in msg and 'Cancel' in msg
    assert db_fake.get_device(1) is None and restore.winfo_exists()
    restore.cancel()
    dlg.destroy()


def test_gui_scan_approval_reports_the_duplicate_exactly(ui):
    root, r = ui
    scan = r['scan']
    scan.show_found([dev('NEW-1', '10.1.0.1'), dev('access-sw', '10.1.0.2'),
                     dev('NEW-3', '10.1.0.3')], [], sample=False)
    scan.approve()
    msg = r['shown'][-1][2]
    assert 'Saved: NEW-1.' in msg
    assert ('Failed (not saved, nothing of it kept): access-sw: the name is already used '
            'by ACCESS-SW (ID 2).') in msg
    assert 'Not attempted: NEW-3.' in msg
    assert scan.last_result['ok'] is False and scan.last_result['saved'] == 1
    assert db_fake.get_device_by_ip('10.1.0.2') is None and db_fake.count_devices() == 3
    assert r['db_status'].available                               # a name problem is no outage
