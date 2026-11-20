"""Phase 3C-6: device status events.

* record_status_change saves the new status and its event together (one transaction in
  db.py, one locked step in db_fake), or neither; a status changed meanwhile records
  nothing. get_events also gives the previous status.
* The monitor uses it: a failed save is retried next round, never lost or doubled.
* The console's Status events tab shows them (time, device, previous -> new, detail),
  is refreshed after the monitor records a change, shows outages honestly, and never
  shows secrets. The monitor's callback holds no widget.
No MySQL: db.py runs against a stand-in connection; the window uses db_fake.
"""
import os
import sys
import threading
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

import pymysql
import pytest

import db
import db_fake
from monitor import monitor
from store_errors import DatabaseError, DatabaseUnavailable

SECRET = 'Ev3nt-Login-Secret-91'


def dev(name, ip, status='up'):
    return {'name': name, 'ip': ip, 'mac': '', 'type': 'switch', 'managed': True,
            'status': status}


@pytest.fixture(autouse=True)
def no_mysql(monkeypatch):
    monkeypatch.setattr(db, 'get_conn', lambda *a, **k: pytest.fail('connected to MySQL'))
    monkeypatch.setattr(db, '_run', lambda *a, **k: pytest.fail('unexpected _run call'))
    db._mark_up()
    db_fake.reset()


# ================================================================ db_fake
def test_fake_records_status_and_event_together():
    a = db_fake.save_device(None, dev('SW1', '10.0.0.1'))
    assert db_fake.record_status_change(a, 'up', 'down', 'SW1 (10.0.0.1) is now down (was up)')
    assert db_fake.get_device(a)['status'] == 'down'
    (e,) = db_fake.get_events()
    assert (e['device'], e['previous'], e['kind']) == ('SW1', 'up', 'down')
    assert 'was up' in e['detail']


@pytest.mark.parametrize('case', ['changed meanwhile', 'deleted', 'missing'])
def test_fake_records_nothing_when_the_status_is_no_longer_old(case):
    a = db_fake.save_device(None, dev('SW1', '10.0.0.1'))
    if case == 'changed meanwhile':
        db_fake.set_status(a, 'down')
    elif case == 'deleted':
        db_fake.delete_device(a)
    target = 99 if case == 'missing' else a
    assert db_fake.record_status_change(target, 'up', 'down', 'x') is False
    assert db_fake.get_events() == []


def test_previous_status_is_derived_for_existing_events():
    a = db_fake.save_device(None, dev('SW1', '10.0.0.1'))
    db_fake.add_event(a, 'down', 'old-style event')                 # recorded before 3C-6
    db_fake.add_event(a, 'note', 'something else')
    assert [(e['kind'], e['previous']) for e in db_fake.get_events()] == [('note', None),
                                                                         ('down', 'up')]


# ================================================================ db.py (stand-in connection)
class Cursor:
    def __init__(self, conn):
        self.conn, self.rowcount = conn, 0

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False

    def execute(self, sql, params=()):
        self.conn.sent.append((sql, params))
        if self.conn.fail_on and sql.startswith(self.conn.fail_on):
            raise self.conn.error
        self.rowcount = self.conn.matched if sql.startswith('UPDATE') else 1


class Conn:
    def __init__(self, matched=1, fail_on=None, error=None, commit_error=None):
        self.matched, self.fail_on, self.error = matched, fail_on, error
        self.commit_error = commit_error
        self.sent, self.commits, self.rollbacks, self.closed = [], 0, 0, False

    def cursor(self):
        return Cursor(self)

    def commit(self):
        if self.commit_error:
            raise self.commit_error
        self.commits += 1

    def rollback(self):
        self.rollbacks += 1

    def close(self):
        self.closed = True


def use(monkeypatch, conn):
    monkeypatch.setattr(db, 'get_conn', lambda *a, **k: conn)
    return conn


def test_db_status_and_event_in_one_transaction(monkeypatch):
    conn = use(monkeypatch, Conn())
    assert db.record_status_change(4, 'up', 'down', 'SW1 (10.0.0.1) is now down (was up)')
    (upd, p1), (ins, p2) = conn.sent
    assert upd.startswith('UPDATE devices SET status = %s')
    assert 'AND status = %s AND is_deleted = 0' in upd and p1 == ('down', 4, 'up')
    assert ins.startswith('INSERT INTO status_events') and p2[:2] == (4, 'down')
    assert conn.commits == 1 and conn.rollbacks == 0 and conn.closed


def test_db_changed_meanwhile_writes_nothing(monkeypatch):
    conn = use(monkeypatch, Conn(matched=0))
    assert db.record_status_change(4, 'up', 'down', 'x') is False
    assert [s.split()[0] for s, _ in conn.sent] == ['UPDATE']        # no event inserted
    assert conn.commits == 0 and conn.rollbacks == 1


@pytest.mark.parametrize('error, expected', [
    (pymysql.err.DataError(1406, 'Data too long'), DatabaseError),
    (pymysql.err.OperationalError(2013, 'Lost connection'), DatabaseUnavailable),
])
def test_db_failed_event_rolls_the_status_back(monkeypatch, error, expected):
    conn = use(monkeypatch, Conn(fail_on='INSERT', error=error))
    with pytest.raises(expected):
        db.record_status_change(4, 'up', 'down', 'x')
    assert conn.commits == 0 and conn.rollbacks == 1                  # neither is kept
    db._mark_up()


def test_db_lost_commit_is_uncertain(monkeypatch):
    use(monkeypatch, Conn(commit_error=pymysql.err.OperationalError(2013, 'Lost')))
    with pytest.raises(DatabaseUnavailable) as err:
        db.record_status_change(4, 'up', 'down', 'x')
    assert err.value.uncertain
    db._mark_up()


def test_db_events_have_the_previous_status(monkeypatch):
    monkeypatch.setattr(db, '_run', lambda *a, **k: [
        {'id': 2, 'created_at': None, 'device': 'SW1', 'kind': 'up', 'detail': ''},
        {'id': 1, 'created_at': None, 'device': 'SW1', 'kind': 'down', 'detail': ''}])
    assert [e['previous'] for e in db.get_events()] == ['down', 'up']


# ================================================================ the monitor
def test_monitor_records_through_one_call_with_the_previous_status():
    a = db_fake.save_device(None, dev('SW1', '10.0.0.1'))
    fails = {}
    monitor.check_all(db_fake, fails, check=lambda ip: False)          # 1st failure: no change
    assert db_fake.get_events() == []
    changed = monitor.check_all(db_fake, fails, check=lambda ip: False)
    assert [(d['name'], new) for d, new in changed] == [('SW1', 'down')]
    (e,) = db_fake.get_events()
    assert e['detail'] == 'SW1 (10.0.0.1) is now down (was up)' and e['previous'] == 'up'
    assert db_fake.get_device(a)['status'] == 'down'


def test_monitor_failed_save_is_retried_never_lost_or_doubled(monkeypatch):
    db_fake.save_device(None, dev('SW1', '10.0.0.1', status='down'))
    real = db_fake.record_status_change
    monkeypatch.setattr(db_fake, 'record_status_change', lambda *a: (_ for _ in ()).throw(
        DatabaseUnavailable('The database is down.')))
    fails = {}
    with pytest.raises(DatabaseUnavailable):
        monitor.check_all(db_fake, fails, check=lambda ip: True)
    assert db_fake.get_device(1)['status'] == 'down' and db_fake.get_events() == []
    monkeypatch.setattr(db_fake, 'record_status_change', real)        # database back
    assert len(monitor.check_all(db_fake, fails, check=lambda ip: True)) == 1
    assert len(monitor.check_all(db_fake, fails, check=lambda ip: True)) == 0
    assert [e['kind'] for e in db_fake.get_events()] == ['up']         # exactly one event


def test_monitor_skips_a_device_changed_meanwhile(monkeypatch):
    db_fake.save_device(None, dev('SW1', '10.0.0.1', status='down'))
    monkeypatch.setattr(db_fake, 'record_status_change', lambda *a: False)
    assert monitor.check_all(db_fake, {}, check=lambda ip: True) == []


def test_monitor_still_works_with_a_store_without_the_new_call():
    class OldStore:
        def __init__(self):
            self.calls = []

        def get_devices(self, *a):
            return [dict(dev('SW1', '10.0.0.1', status='down'), id=1)]

        def set_status(self, *a):
            self.calls.append(('set_status', a))

        def add_event(self, *a):
            self.calls.append(('add_event', a))
    store = OldStore()
    assert len(monitor.check_all(store, {}, check=lambda ip: True)) == 1
    assert [c[0] for c in store.calls] == ['set_status', 'add_event']


# ================================================================ the Status events tab
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
    for name in ('showinfo', 'showerror', 'showwarning'):
        monkeypatch.setattr(messagebox, name, lambda *a, **k: None)
    db_fake.reset()
    db_fake.save_device(None, dev('SW1', '10.0.0.1'), 'admin', SECRET)
    db_fake.save_device(None, dev('SW2', '10.0.0.2'))
    from gui.main_window import build_main_window
    refs = build_main_window(root, db_fake, demo_store=False)
    yield root, refs
    root.destroy()


def events_text(console):
    return console.events_text.get('1.0', 'end')


def test_tab_lists_recorded_changes_without_secrets(ui):
    root, r = ui
    console = r['console']
    db_fake.record_status_change(1, 'up', 'down', 'SW1 (10.0.0.1) is now down (was up)')
    db_fake.record_status_change(1, 'down', 'up', 'SW1 (10.0.0.1) is now up (was down)')
    console.tabs.select(2)
    root.update()
    text = events_text(console)
    lines = [l for l in text.splitlines() if l.strip()]
    assert 'down -> up' in lines[0] and 'up -> down' in lines[1]      # newest first
    assert 'SW1' in lines[0] and 'is now up (was down)' in lines[0]
    assert SECRET not in text and 'gAAAA' not in text


def test_tab_says_when_nothing_is_recorded(ui):
    root, r = ui
    assert r['console'].refresh_events() == []
    assert 'No status changes have been recorded yet' in events_text(r['console'])


def test_monitor_change_reaches_the_tab_through_the_main_thread(ui):
    root, r = ui
    console = r['console']
    console.tabs.select(2)
    root.update()
    stop = monitor.start_monitor(db_fake, interval=0.05, check=lambda ip: ip != '10.0.0.2',
                                 on_change=console.status_changed)
    try:
        assert pump(root, lambda: 'up -> down' in events_text(console))
    finally:
        stop.set()
    console.flush()
    assert any(src == 'monitor' and 'SW2 (10.0.0.2): up -> down (recorded)' in msg
               for _t, src, msg, _l in console.lines)


def test_monitor_callback_holds_no_widget(ui):
    root, r = ui
    callback = r['console'].status_changed
    assert not hasattr(callback, '__self__')
    cells = [c.cell_contents for c in (callback.__closure__ or ())]
    assert cells and not any(isinstance(c, tk.Misc) for c in cells)
    done = []
    t = threading.Thread(target=lambda: done.append(callback(dict(dev('SW9', '10.9.9.9'), id=9),
                                                             'down')))
    t.start(); t.join()                                  # safe from another thread
    assert done == [None]


def test_read_error_is_shown_and_reported(ui, monkeypatch):
    root, r = ui
    monkeypatch.setattr(db_fake, 'get_events', lambda limit=50: (_ for _ in ()).throw(
        DatabaseUnavailable('The database at x is not available (MySQL error 2003).')))
    assert r['console'].refresh_events() == []
    assert 'Could not read the status events' in events_text(r['console'])
    assert not r['db_status'].available


def test_outage_blanks_the_tab_and_recovery_reloads_it(ui, monkeypatch):
    root, r = ui
    console = r['console']
    db_fake.record_status_change(1, 'up', 'down', 'SW1 (10.0.0.1) is now down (was up)')
    console.tabs.select(2)
    root.update()
    assert 'up -> down' in events_text(console)
    r['db_status'].report(DatabaseUnavailable('The database is down.'))
    assert 'Database unavailable' in events_text(console)
    assert 'up -> down' not in events_text(console)              # no old rows as current
    assert 'Database unavailable' in console.config_text.get('1.0', 'end')
    r['db_status'].check_now()                                    # db_fake answers: back
    assert pump(root, lambda: r['db_status'].available)
    assert 'up -> down' in events_text(console)
