"""Phase 3C-6: the stored Findings review (snapshot).

* replace_findings replaces the whole snapshot in one transaction (db.py) or one swap
  (db_fake): all new findings, or, on any failure, the previous snapshot untouched. An
  empty review is a real result and clears it.
* get_findings_snapshot reads it back (with when it was saved and deleted devices marked).
* The Findings page loads the stored review when opened, labels stored vs new results,
  keeps results on screen (marked) during an outage, and never updates widgets from its
  worker threads.
No MySQL: db.py runs against a stand-in connection; the window uses db_fake.
"""
import os
import sys
import threading
import time
from datetime import datetime

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))
sys.path.insert(0, os.path.dirname(__file__))

import pymysql
import pytest

import db
import db_fake
from store_errors import DatabaseError, DatabaseUnavailable


def dev(name, ip):
    return {'name': name, 'ip': ip, 'mac': '', 'type': 'switch', 'managed': True,
            'status': 'up'}


def finding(device, rule='telnet_enabled', severity='high', message='Telnet is on'):
    return {'device': device, 'rule': rule, 'severity': severity, 'message': message,
            'commands': ['line vty 0 4', 'transport input ssh']}


@pytest.fixture(autouse=True)
def no_mysql(monkeypatch):
    monkeypatch.setattr(db, 'get_conn', lambda *a, **k: pytest.fail('connected to MySQL'))
    monkeypatch.setattr(db, '_run', lambda *a, **k: pytest.fail('unexpected _run call'))
    db._mark_up()
    db_fake.reset()


# ================================================================ db_fake
def test_fake_replace_and_read_back():
    a = db_fake.save_device(None, dev('SW1', '10.0.0.1'))
    db_fake.save_device(None, dev('SW2', '10.0.0.2'))
    result = db_fake.replace_findings([finding('SW2', severity='low'), finding('SW1'),
                                       finding('GHOST')])
    assert result == {'saved': 2, 'skipped': ['GHOST']}
    snap = db_fake.get_findings_snapshot()
    assert [(f['device'], f['severity']) for f in snap['findings']] == [('SW1', 'high'),
                                                                       ('SW2', 'low')]
    assert isinstance(snap['saved_at'], datetime)
    assert snap['findings'][0]['commands'] == ['line vty 0 4', 'transport input ssh']
    assert not any(f['device_deleted'] for f in snap['findings'])
    db_fake.replace_findings([finding('SW2', rule='other')])        # replaces, never appends
    assert [f['rule'] for f in db_fake.get_findings_snapshot()['findings']] == ['other']
    db_fake.save_device(a, dev('SW1-NEW', '10.0.0.1'))
    db_fake.replace_findings([finding('SW1-NEW')])
    db_fake.save_device(a, dev('SW1', '10.0.0.1'))                   # renamed after storing
    assert db_fake.get_findings_snapshot()['findings'][0]['device'] == 'SW1'   # read live


def test_fake_empty_review_clears_the_snapshot():
    db_fake.save_device(None, dev('SW1', '10.0.0.1'))
    db_fake.replace_findings([finding('SW1')])
    assert db_fake.replace_findings([]) == {'saved': 0, 'skipped': []}
    assert db_fake.get_findings_snapshot() == {'findings': [], 'saved_at': None}


def test_fake_failure_partway_keeps_the_previous_snapshot():
    db_fake.save_device(None, dev('SW1', '10.0.0.1'))
    db_fake.replace_findings([finding('SW1', message='old')])
    before = db_fake.get_findings_snapshot()
    broken = {'device': 'SW1', 'rule': 'x', 'severity': 'high', 'message': 'no commands'}
    with pytest.raises(KeyError):
        db_fake.replace_findings([finding('SW1', message='new'), broken])
    assert db_fake.get_findings_snapshot() == before


def test_fake_deleted_device_is_marked_and_renames_follow():
    a = db_fake.save_device(None, dev('SW1', '10.0.0.1'))
    b = db_fake.save_device(None, dev('SW2', '10.0.0.2'))
    db_fake.replace_findings([finding('SW1'), finding('SW2')])
    db_fake.delete_device(a)
    db_fake.save_device(b, dev('SW2-RENAMED', '10.0.0.2'))
    snap = {f['device']: f['device_deleted'] for f in db_fake.get_findings_snapshot()['findings']}
    assert snap == {'SW1': True, 'SW2-RENAMED': False}


# ================================================================ db.py (stand-in connection)
class Cursor:
    def __init__(self, conn):
        self.conn, self._row = conn, None

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False

    def _maybe_fail(self, sql):
        if self.conn.fail_on and self.conn.fail_on in sql:
            raise self.conn.error

    def execute(self, sql, params=()):
        self.conn.sent.append((sql, params))
        self._maybe_fail(sql)
        self._row = None
        if sql.startswith('SELECT id FROM devices WHERE name'):
            did = self.conn.ids.get(params[0])
            self._row = {'id': did} if did else None

    def executemany(self, sql, rows):
        self.conn.sent.append((sql, list(rows)))
        self._maybe_fail(sql)

    def fetchone(self):
        return self._row


class Conn:
    def __init__(self, ids=None, fail_on=None, error=None, commit_error=None):
        self.ids = ids or {}
        self.fail_on, self.error, self.commit_error = fail_on, error, commit_error
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


def test_db_replace_is_one_transaction(monkeypatch):
    conn = use(monkeypatch, Conn(ids={'SW1': 1, 'SW2': 2}))
    result = db.replace_findings([finding('SW2'), finding('SW1', severity='low'),
                                  finding('GHOST')])
    assert result == {'saved': 2, 'skipped': ['GHOST']}
    kinds = [sql.split()[0] for sql, _ in conn.sent]
    assert kinds == ['SELECT', 'SELECT', 'SELECT', 'DELETE', 'INSERT']   # lookups, then swap
    assert all('is_deleted = 0' in sql for sql, _ in conn.sent[:3])     # active devices only
    insert_sql, rows = conn.sent[-1]
    assert insert_sql == db._FINDING_INSERT_SQL
    assert rows == [(2, 'telnet_enabled', 'high', 'Telnet is on', 'line vty 0 4\ntransport input ssh'),
                    (1, 'telnet_enabled', 'low', 'Telnet is on', 'line vty 0 4\ntransport input ssh')]
    assert conn.commits == 1 and conn.rollbacks == 0 and conn.closed


def test_db_empty_review_clears_in_one_transaction(monkeypatch):
    conn = use(monkeypatch, Conn())
    assert db.replace_findings([]) == {'saved': 0, 'skipped': []}
    assert [sql for sql, _ in conn.sent] == ['DELETE FROM findings'] and conn.commits == 1


@pytest.mark.parametrize('fail_on, error, expected', [
    ('INSERT', pymysql.err.DataError(1406, 'Data too long'), DatabaseError),
    ('INSERT', pymysql.err.OperationalError(2013, 'Lost connection'), DatabaseUnavailable),
    ('DELETE', pymysql.err.OperationalError(2006, 'gone away'), DatabaseUnavailable),
    ('SELECT', pymysql.err.OperationalError(2013, 'Lost connection'), DatabaseUnavailable),
])
def test_db_failure_partway_rolls_back_and_keeps_the_old_snapshot(monkeypatch, fail_on, error,
                                                                  expected):
    conn = use(monkeypatch, Conn(ids={'SW1': 1}, fail_on=fail_on, error=error))
    with pytest.raises(expected) as err:
        db.replace_findings([finding('SW1')])
    assert conn.commits == 0 and conn.rollbacks == 1 and conn.closed   # nothing kept
    assert not getattr(err.value, 'uncertain', False)
    db._mark_up()


def test_db_lost_during_commit_is_uncertain(monkeypatch):
    use(monkeypatch, Conn(ids={'SW1': 1},
                          commit_error=pymysql.err.OperationalError(2013, 'Lost')))
    with pytest.raises(DatabaseUnavailable) as err:
        db.replace_findings([finding('SW1')])
    assert err.value.uncertain
    db._mark_up()


def test_db_snapshot_reads_everything_in_one_statement(monkeypatch):
    calls = []
    t1, t2 = datetime(2026, 11, 18, 14, 2, 0), datetime(2026, 11, 18, 14, 2, 1)

    def run(sql, params=(), fetch=None, many=False):
        calls.append(sql)
        return [{'id': 1, 'device': 'SW1', 'device_deleted': 0, 'rule': 'r', 'severity': 'high',
                 'message': 'm', 'commands': 'a\nb', 'created_at': t1},
                {'id': 2, 'device': 'OLD', 'device_deleted': 1, 'rule': 'r', 'severity': 'low',
                 'message': 'm', 'commands': None, 'created_at': t2}]
    monkeypatch.setattr(db, '_run', run)
    snap = db.get_findings_snapshot()
    assert len(calls) == 1 and 'LIMIT' not in calls[0] and 'is_deleted AS device_deleted' in calls[0]
    assert snap['saved_at'] == t2
    assert [f['device_deleted'] for f in snap['findings']] == [False, True]
    assert snap['findings'][0]['commands'] == ['a', 'b'] and snap['findings'][1]['commands'] == ['']


def test_db_empty_snapshot(monkeypatch):
    monkeypatch.setattr(db, '_run', lambda *a, **k: [])
    assert db.get_findings_snapshot() == {'findings': [], 'saved_at': None}


# ================================================================ the Findings page
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
    db_fake.reset()
    db_fake.save_device(None, dev('SW1', '10.0.0.1'))
    db_fake.save_device(None, dev('SW2', '10.0.0.2'))
    from gui.main_window import build_main_window
    refs = build_main_window(root, db_fake, demo_store=False)      # real-database mode
    refs['shown'] = shown
    yield root, refs
    root.destroy()


def fake_review(monkeypatch, tab, result, notes=()):
    """The review itself replaced: devices are the registered ones, findings given."""
    from gui import findings_tab
    tab.collect = lambda: (db_fake.get_devices('', 'name', 1, 100), [], {}, list(notes),
                           'Registered devices (2)')
    monkeypatch.setattr(findings_tab, 'review_network', lambda *a: result)


def test_opening_the_page_loads_the_stored_review(ui):
    root, r = ui
    db_fake.replace_findings([finding('SW1'), finding('SW2', severity='low')])
    r['show_page']('findings')
    f = r['findings']
    assert pump(root, lambda: not f.busy and f.view == 'stored')
    assert len(f.tree.get_children()) == 2
    assert 'STORED REVIEW' in f.score.cget('text') and '/ 100' in f.score.cget('text')
    assert f.score.cget('text').startswith(f'Health score: {100 - 15 - 3} / 100')
    note = f.note.cget('text')
    assert note.startswith('Stored review from ') and 'not a new check' in note


def test_no_stored_findings_message_is_explicit(ui):
    root, r = ui
    from gui.findings_tab import NO_STORED_MESSAGE
    r['show_page']('findings')
    f = r['findings']
    assert pump(root, lambda: not f.busy and f.view == 'stored')
    assert f.note.cget('text') == NO_STORED_MESSAGE
    assert 'no review has been saved yet' in NO_STORED_MESSAGE
    assert 'found no problems' in NO_STORED_MESSAGE


def test_new_review_replaces_the_snapshot_and_is_labelled_new(ui, monkeypatch):
    root, r = ui
    db_fake.replace_findings([finding('SW1', message='old')])
    f = r['findings']
    fake_review(monkeypatch, f, ([finding('SW2', message='new')], 85))
    f.run()
    assert pump(root, lambda: not f.busy)
    assert f.view == 'fresh'
    assert 'Review completed just now and stored (1 finding).' in f.note.cget('text')
    assert f.note.cget('text').startswith('Registered devices (2)')
    assert [x['message'] for x in db_fake.get_findings_snapshot()['findings']] == ['new']
    r['show_page']('findings')                      # opening the page keeps the new results
    root.update()
    assert not f.busy and f.view == 'fresh'


def test_empty_completed_review_clears_outdated_findings(ui, monkeypatch):
    root, r = ui
    db_fake.replace_findings([finding('SW1', message='outdated')])
    f = r['findings']
    fake_review(monkeypatch, f, ([], 100))
    f.run()
    assert pump(root, lambda: not f.busy)
    assert db_fake.get_findings_snapshot()['findings'] == []       # nothing outdated kept
    assert 'stored (0 findings)' in f.note.cget('text')
    assert f.score.cget('text').startswith('Health score: 100 / 100')


def test_failed_save_keeps_the_previous_snapshot_and_says_so(ui, monkeypatch):
    root, r = ui
    db_fake.replace_findings([finding('SW1', message='old')])
    f = r['findings']
    fake_review(monkeypatch, f, ([finding('SW2', message='new')], 85))
    monkeypatch.setattr(db_fake, 'replace_findings', lambda findings: (_ for _ in ()).throw(
        DatabaseError('The database could not complete the request (MySQL error 1213).')))
    f.run()
    assert pump(root, lambda: not f.busy)
    assert f.view == 'unsaved' and len(f.findings) == 1
    note = f.note.cget('text')
    assert 'NOT stored' in note and 'previously stored review was kept unchanged' in note
    assert [x['message'] for x in db_fake.get_findings_snapshot()['findings']] == ['old']


def test_lost_commit_is_not_called_not_stored(ui, monkeypatch):
    root, r = ui
    f = r['findings']
    fake_review(monkeypatch, f, ([finding('SW2')], 85))
    monkeypatch.setattr(db_fake, 'replace_findings', lambda findings: (_ for _ in ()).throw(
        DatabaseUnavailable('The database at x is not available.', uncertain=True)))
    f.run()
    assert pump(root, lambda: not f.busy)
    note = f.note.cget('text')
    assert 'may or may not have been saved' in note and 'NOT stored' not in note


def test_review_failure_keeps_the_stored_snapshot(ui, monkeypatch):
    root, r = ui
    db_fake.replace_findings([finding('SW1', message='old')])
    f = r['findings']
    f.collect = lambda: (_ for _ in ()).throw(DatabaseUnavailable('The database is down.'))
    f.run()
    assert pump(root, lambda: not f.busy)
    assert 'Nothing was stored' in f.note.cget('text')
    assert [x['message'] for x in db_fake.get_findings_snapshot()['findings']] == ['old']
    assert not r['db_status'].available


def test_load_failure_keeps_what_is_shown_and_reports_the_outage(ui, monkeypatch):
    root, r = ui
    db_fake.replace_findings([finding('SW1')])
    f = r['findings']
    r['show_page']('findings')
    assert pump(root, lambda: not f.busy and f.view == 'stored')
    monkeypatch.setattr(db_fake, 'get_findings_snapshot', lambda: (_ for _ in ()).throw(
        DatabaseUnavailable('The database at x is not available (MySQL error 2003).')))
    assert f.load_stored()
    assert pump(root, lambda: not f.busy)
    note = f.note.cget('text')
    assert 'Could not load the stored review' in note and 'MySQL error 2003' in note
    assert 'not refreshed' in note
    assert len(f.tree.get_children()) == 1                     # not cleared silently
    assert not r['db_status'].available


def test_outage_marks_results_and_recovery_reloads_them(ui, monkeypatch):
    root, r = ui
    db_fake.replace_findings([finding('SW1')])
    f = r['findings']
    r['show_page']('findings')
    assert pump(root, lambda: not f.busy and f.view == 'stored')
    f.on_db_down('down')
    assert 'could not be refreshed' in f.note.cget('text') and len(f.tree.get_children()) == 1
    db_fake.replace_findings([finding('SW1'), finding('SW2')])  # changed meanwhile
    f.on_db_up()
    assert pump(root, lambda: not f.busy and len(f.tree.get_children()) == 2)
    assert f.note.cget('text').startswith('Stored review from ')


def test_deleted_devices_are_marked_on_the_page(ui):
    root, r = ui
    db_fake.replace_findings([finding('SW1'), finding('SW2')])
    db_fake.delete_device(1)
    r['show_page']('findings')
    f = r['findings']
    assert pump(root, lambda: not f.busy and f.view == 'stored')
    devices = [f.tree.item(i)['values'][0] for i in f.tree.get_children()]
    assert 'SW1 (deleted)' in devices and 'Devices deleted since: SW1.' in f.note.cget('text')


def test_sample_review_is_never_stored(monkeypatch):
    try:
        root = tk.Tk()
    except tk.TclError as err:
        pytest.skip(f'no display available ({err})')
    try:
        db_fake.reset()
        from gui.main_window import build_main_window
        refs = build_main_window(root, db_fake, demo_store=True)
        f = refs['findings']
        calls = []
        monkeypatch.setattr(db_fake, 'replace_findings', lambda x: calls.append(x))
        f.run()
        assert pump(root, lambda: not f.busy)
        assert f.view == 'sample' and f.findings and calls == []
    finally:
        root.destroy()


def test_workers_get_no_widgets(ui, monkeypatch):
    root, r = ui
    from gui import findings_tab
    started = []

    class Spy:
        def __init__(self, target, args, daemon):
            started.append((target, args))

        def start(self):
            pass
    monkeypatch.setattr(findings_tab.threading, 'Thread', Spy)
    f = r['findings']
    f.run()
    f.busy = False
    f.load_stored()
    assert [t for t, _ in started] == [findings_tab._review_worker, findings_tab._snapshot_worker]
    for target, args in started:
        assert not hasattr(target, '__self__')                 # plain functions, not methods
        assert not any(isinstance(a, tk.Misc) for a in args)   # no widget handed over
