"""Phase 3C-4: the window when the database becomes unavailable while it runs.

The window is built in REAL database mode (demo_store=False) on OutageStore: db_fake
with a switch that makes every call raise DatabaseUnavailable, like a stopped MySQL.
No MySQL server is contacted. Message boxes are recorded, not shown.

Checked: the outage is visible (header, red bar, every list), the app never switches to
sample mode, no out-of-date data is shown as current, writes are blocked or reported
honestly, recovery refreshes the pages without repeating anything, background threads
never touch widgets, one health check at a time, and closing stops every timer.
"""
import gc
import os
import sys
import threading
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))
import pytest

tk = pytest.importorskip('tkinter')
from tkinter import messagebox, simpledialog

import db_fake
from gui import db_status
from gui.db_status import DatabaseStatus
from store_errors import DatabaseError, DatabaseUnavailable

REASON = 'The database at 127.0.0.1:3307 is not available (MySQL error 2003).'
WRITES = {'save_device', 'restore_device', 'delete_device', 'upsert_device', 'update_device',
          'save_credentials', 'save_links', 'add_log', 'clear_findings', 'add_finding',
          'set_status', 'add_event', 'replace_findings', 'record_status_change'}


class OutageStore:
    """db_fake behind a switch. down=True: every call (and ping) raises
    DatabaseUnavailable. fail[name] = (calls_that_work_first, error) makes one function
    fail on its own."""

    def __init__(self):
        self.down, self.fail, self.calls = False, {}, []
        self.ping_threads = []

    def ping(self):
        self.ping_threads.append(threading.current_thread())
        if self.down:
            raise DatabaseUnavailable(REASON, code=2003)
        return True

    def writes(self):
        return [c for c in self.calls if c in WRITES]

    def __getattr__(self, name):
        target = getattr(db_fake, name)
        if not callable(target):
            return target

        def call(*args, **kwargs):
            self.calls.append(name)
            if self.down:
                raise DatabaseUnavailable(REASON, code=2003)
            if name in self.fail:
                skip, err = self.fail[name]
                if self.calls.count(name) > skip:
                    raise err
            return target(*args, **kwargs)
        return call


def pump(root, cond, timeout=10):
    end = time.time() + timeout
    while time.time() < end:
        root.update()
        if cond():
            return True
        time.sleep(0.02)
    return False


def dev(name, ip, managed=True):
    return {'name': name, 'ip': ip, 'mac': '', 'type': 'switch', 'managed': managed,
            'status': 'up'}


@pytest.fixture
def ui(monkeypatch):
    try:
        root = tk.Tk()
    except tk.TclError as err:
        pytest.skip(f'no display available ({err})')
    shown = []
    for name in ('showinfo', 'showerror', 'showwarning'):
        monkeypatch.setattr(messagebox, name,
                            lambda t, m, _n=name, **k: shown.append((_n, t, m)))
    monkeypatch.setattr(messagebox, 'askyesno', lambda *a, **k: True)
    monkeypatch.setattr('gui.components.login_dialog.ask_device_login',
                        lambda *a, **k: {'username': 'admin', 'password': 'admin', 'save': False})
    db_fake.reset()
    db_fake.upsert_device(dev('SW1', '10.0.0.1'))
    db_fake.upsert_device(dev('SW2', '10.0.0.2'))
    db_fake.add_log(1, 'Configuration', 'success', 'Applied')
    store = OutageStore()
    from gui.main_window import build_main_window
    refs = build_main_window(root, store, demo_store=False)
    refs['shown'], refs['store'] = shown, store
    before = set(threading.enumerate())
    yield root, refs
    finish(root, before)
    del refs


def finish(root, before):
    """Let the worker threads this test started (review, health check) end BEFORE the
    window is destroyed, so the last reference to a Tk object is never dropped outside
    the main thread; then clean up here, on the main thread."""
    end = time.time() + 3
    while time.time() < end and any(t.is_alive() and t not in before
                                    for t in threading.enumerate()):
        try:
            root.update()
        except tk.TclError:
            break
        time.sleep(0.02)
    try:
        root.destroy()
    except tk.TclError:
        pass
    gc.collect()


def go_down(root, r):
    r['store'].down = True
    r['db_status'].check_now()
    assert pump(root, lambda: not r['db_status'].available)


def go_up(root, r):
    r['store'].down = False
    r['db_status'].check_now()
    assert pump(root, lambda: r['db_status'].available)


def tree_rows(tab):
    return tab.tree.get_children()


# ---------------------------------------------------------------- visible status
def test_connected_window_has_a_status_and_no_bar(ui):
    root, r = ui
    root.update()
    from gui.main_window import SOURCE_CONNECTED
    assert r['db_status'].available
    assert r['source_label'].cget('text') == SOURCE_CONNECTED
    assert not r['outage_bar'].winfo_manager()
    assert len(tree_rows(r['devices'])) == 2


def test_outage_is_shown_everywhere_and_old_data_is_hidden(ui):
    root, r = ui
    r['show_page']('topology')
    r['inspector'].show_device(1)
    root.update()
    assert len(tree_rows(r['devices'])) == 2 and len(tree_rows(r['logs'])) == 1
    assert len(r['configure'].devices) == 2

    go_down(root, r)
    from gui.main_window import SOURCE_UNAVAILABLE
    assert r['source_label'].cget('text') == SOURCE_UNAVAILABLE
    assert r['outage_bar'].winfo_manager() == 'pack'
    bar = r['outage_text'].cget('text')
    assert 'MySQL error 2003' in bar and 'Nothing can be saved' in bar
    # no stale rows anywhere, and each list says why
    assert tree_rows(r['devices']) == () and 'Database unavailable' in r['devices'].empty.cget('text')
    assert r['devices'].prev_btn.instate(['disabled']) and r['devices'].next_btn.instate(['disabled'])
    assert tree_rows(r['logs']) == () and 'Database unavailable' in r['logs'].empty.cget('text')
    assert r['configure'].devices == [] and r['configure'].picker.devices == []
    assert 'Database unavailable' in r['configure'].status.cget('text')
    assert r['topology'].interactive.devices == []
    assert 'Database unavailable' in r['topology'].source.cget('text')
    assert r['inspector'].device is None and r['inspector'].selection == ('device', 1)
    assert r['status_devices'].cget('text') == 'device count unavailable'
    r['console'].flush()
    assert any(src == 'database' and 'connection lost' in msg.lower()
               for _t, src, msg, _l in r['console'].lines)


def test_runtime_outage_never_switches_to_sample_mode(ui):
    root, r = ui
    go_down(root, r)
    assert r['store'] is r['devices'].store and r['scan'].store is r['store']
    assert r['scan'].sample_store is False
    assert 'sample' not in r['source_label'].cget('text').lower()
    assert r['topology'].interactive.sample is False      # no sample network drawn instead
    r['findings'].run()                                    # blocked, not run on sample data
    assert r['shown'][-1][1] == 'Database unavailable' and r['findings'].findings == []


def test_listing_during_an_outage_reports_it(ui):
    """A screen that hits the outage first (before any health check) reports it."""
    root, r = ui
    r['store'].down = True
    r['devices'].refresh()
    assert not r['db_status'].available
    assert tree_rows(r['devices']) == () and tree_rows(r['logs']) == ()   # all lists cleared


def test_unhandled_callback_error_shows_the_outage_not_a_traceback(ui, capsys):
    root, r = ui
    err = DatabaseUnavailable(REASON)
    root.report_callback_exception(DatabaseUnavailable, err, None)
    assert not r['db_status'].available
    assert 'Traceback' not in capsys.readouterr().err


def test_unhandled_sql_error_is_shown_but_is_not_an_outage(ui):
    root, r = ui
    err = DatabaseError('The database could not complete the request (MySQL error 1064).')
    root.report_callback_exception(DatabaseError, err, None)
    assert r['db_status'].available
    assert r['shown'][-1][:2] == ('showerror', 'Database error')


def test_other_callback_errors_still_use_the_default_handler(ui, capsys):
    root, r = ui
    try:
        raise RuntimeError('a real bug')
    except RuntimeError as err:
        root.report_callback_exception(RuntimeError, err, err.__traceback__)
    assert 'a real bug' in capsys.readouterr().err and r['db_status'].available


# ---------------------------------------------------------------- writes during an outage
def test_actions_are_blocked_while_down(ui):
    root, r = ui
    go_down(root, r)
    store, shown = r['store'], r['shown']
    before = list(store.calls)
    devices = r['devices']
    devices.add()
    assert shown[-1][1] == 'Database unavailable' and 'Nothing was changed' in shown[-1][2]
    devices.tree.insert('', 'end', iid='1', values=('SW1',))   # as if a row were selected
    devices.tree.selection_set('1')
    devices.delete()
    devices.edit()
    assert [s[1] for s in shown[-3:]] == ['Database unavailable'] * 3
    scan = r['scan']
    scan.show_found([dev('SW9', '10.0.0.9')], [], sample=False)
    scan.approve()
    assert 'Nothing was saved' in scan.status.cget('text')
    r['findings'].run()
    assert store.calls == before                    # nothing was even attempted
    assert db_fake.count_devices() == 2


def test_device_save_during_outage_says_nothing_was_saved(ui):
    root, r = ui
    from gui.devices_tab import DeviceDialog
    dlg = DeviceDialog(r['devices'], r['store'], None, lambda: None)
    dlg.vars['name'].set('SW3'); dlg.vars['ip'].set('10.0.0.3')
    r['store'].down = True                          # the outage starts while the dialog is open
    dlg.save()
    kind, title, msg = r['shown'][-1]
    assert (kind, title) == ('showerror', 'Cannot save') and msg.startswith('Nothing was saved.')
    assert not r['db_status'].available and db_fake.count_devices() == 2
    dlg.destroy()


def test_device_save_lost_during_commit_is_reported_as_uncertain(ui):
    root, r = ui
    from gui.devices_tab import DeviceDialog
    r['store'].fail['save_device'] = (0, DatabaseUnavailable(REASON, uncertain=True))
    dlg = DeviceDialog(r['devices'], r['store'], None, lambda: None)
    dlg.vars['name'].set('SW3'); dlg.vars['ip'].set('10.0.0.3')
    dlg.save()
    msg = r['shown'][-1][2]
    assert 'may or may not have been saved' in msg and 'Nothing was saved' not in msg
    dlg.destroy()


def test_delete_during_outage_deletes_nothing(ui):
    root, r = ui
    r['store'].fail['delete_device'] = (0, DatabaseUnavailable(REASON))
    devices = r['devices']
    devices.tree.selection_set('1')
    devices.delete()
    kind, title, msg = r['shown'][-1]
    assert title == 'Delete failed' and msg.startswith('Nothing was deleted.')
    assert db_fake.get_device(1) is not None and not r['db_status'].available


def test_restore_during_outage_changes_nothing(ui):
    root, r = ui
    from gui.devices_tab import RestoreDialog
    db_fake.delete_device(2)
    deleted = db_fake.get_deleted_device_by_ip('10.0.0.2')
    r['store'].fail['restore_device'] = (0, DatabaseUnavailable(REASON))
    dlg = RestoreDialog(r['devices'], r['store'], deleted, dev('SW2', '10.0.0.2'), lambda: None)
    dlg.choice.set('keep')
    dlg.confirm()
    kind, title, msg = r['shown'][-1]
    assert title == 'Restore failed' and msg.startswith('Nothing was changed.')
    assert db_fake.get_device(2) is None and not r['db_status'].available
    dlg.destroy()


def test_scan_approval_interrupted_by_an_outage_reports_exactly(ui):
    root, r = ui
    scan, store = r['scan'], r['store']
    store.fail['save_device'] = (1, DatabaseUnavailable(REASON))   # the 2nd device fails
    scan.show_found([dev('A1', '10.1.0.1'), dev('A2', '10.1.0.2'), dev('A3', '10.1.0.3')],
                    [('A1', 'Gi0/1', 'A2', 'Gi0/1')], sample=False)
    scan.approve()
    msg = r['shown'][-1][2]
    assert 'Saved: A1.' in msg and 'Failed (not saved, nothing of it kept): A2.' in msg
    assert 'Not attempted: A3.' in msg
    assert scan.last_result['ok'] is False and scan.last_result['saved'] == 1
    assert 'save_links' not in store.calls                    # links never attempted
    assert not r['db_status'].available


def test_scan_approval_uncertain_commit(ui):
    root, r = ui
    scan, store = r['scan'], r['store']
    store.fail['save_device'] = (0, DatabaseUnavailable(REASON, uncertain=True))
    scan.show_found([dev('A1', '10.1.0.1')], [], sample=False)
    scan.approve()
    msg = r['shown'][-1][2]
    assert 'may or may not have been saved' in msg and 'Nothing was saved' not in msg


# ---------------------------------------------------------------- findings and monitoring
def test_findings_review_fails_honestly_during_outage(ui):
    root, r = ui
    findings = r['findings']
    r['store'].down = True                  # not yet known to the status: the run starts
    findings.run()
    assert pump(root, lambda: not findings.busy)
    assert 'database could not be read' in findings.note.cget('text')
    assert r['shown'][-1][:2] == ('showerror', 'Review failed')
    assert REASON in r['shown'][-1][2]
    assert not r['db_status'].available and findings.findings == []


def test_findings_that_cannot_be_saved_are_not_hidden(ui):
    root, r = ui
    # 3C-6: the review's worker stores it with replace_findings (one transaction).
    findings = r['findings']
    old = {'device': 'SW1', 'rule': 'telnet_enabled', 'severity': 'high', 'message': 'Old',
           'commands': ['line vty 0 4']}
    db_fake.replace_findings([old])                          # the previously stored review
    f = {'device': 'SW1', 'rule': 'no_password_encryption', 'severity': 'medium',
         'message': 'New', 'commands': ['service password-encryption']}
    from gui import findings_tab
    findings.collect = lambda: ([db_fake.get_device(1)], [], {}, [], 'Registered devices (2)')
    original = findings_tab.review_network
    findings_tab.review_network = lambda *a: ([f], 92)
    try:
        r['store'].fail['replace_findings'] = (0, DatabaseError(
            'The database could not complete the request (MySQL error 1406).'))
        findings.run()
        assert pump(root, lambda: not findings.busy)
    finally:
        findings_tab.review_network = original
    note = findings.note.cget('text')
    assert 'NOT stored' in note and 'previously stored review was kept' in note
    assert len(findings.findings) == 1                      # the review itself is still shown
    assert [x['message'] for x in db_fake.get_findings_snapshot()['findings']] == ['Old']
    assert r['db_status'].available                          # an SQL error is not an outage


def test_monitor_failure_reaches_the_window_from_its_thread(ui):
    root, r = ui
    from monitor import monitor
    r['store'].down = True
    stop = monitor.start_monitor(r['store'], interval=0.05, check=lambda ip: True,
                                 on_error=r['db_status'].post)
    try:
        assert pump(root, lambda: not r['db_status'].available)
    finally:
        stop.set()
    r['console'].flush()
    assert any(src == 'database' and msg.startswith('monitor: paused')
               for _t, src, msg, _l in r['console'].lines)
    assert r['store'].writes() == []


# ---------------------------------------------------------------- recovery
def test_recovery_refreshes_everything_and_repeats_nothing(ui):
    root, r = ui
    r['inspector'].show_device(1)
    r['configure'].picker.set_checked([1, 2], notify=False)
    go_down(root, r)
    writes_before = r['store'].writes()
    go_up(root, r)
    from gui.main_window import SOURCE_CONNECTED
    assert r['source_label'].cget('text') == SOURCE_CONNECTED
    assert not r['outage_bar'].winfo_manager()
    assert len(tree_rows(r['devices'])) == 2 and len(tree_rows(r['logs'])) == 1
    assert len(r['configure'].devices) == 2 and r['configure'].picker.checked == {1, 2}
    assert r['inspector'].device['name'] == 'SW1'
    assert r['status_devices'].cget('text') == '2 registered devices'
    assert r['store'].writes() == writes_before              # no automatic retry of anything
    r['console'].flush()
    assert any('restored' in msg for _t, src, msg, _l in r['console'].lines if src == 'database')


def test_retry_button_starts_a_check(ui):
    root, r = ui
    go_down(root, r)
    r['store'].down = False
    r['retry_button'].invoke()
    assert pump(root, lambda: r['db_status'].available)


def test_failed_save_is_not_retried_after_recovery(ui):
    root, r = ui
    from gui.devices_tab import DeviceDialog
    dlg = DeviceDialog(r['devices'], r['store'], None, lambda: None)
    dlg.vars['name'].set('SW3'); dlg.vars['ip'].set('10.0.0.3')
    r['store'].down = True
    dlg.save()
    dlg.destroy()
    go_up(root, r)
    pump(root, lambda: False, timeout=0.3)
    assert db_fake.get_device_by_ip('10.0.0.3') is None
    assert 'save_device' not in r['store'].calls


# ---------------------------------------------------------------- the status object itself
class SlowStore:
    def __init__(self, ok=True, delay=0.2):
        self.ok, self.delay, self.threads = ok, delay, []

    def ping(self):
        self.threads.append(threading.current_thread())
        time.sleep(self.delay)
        if not self.ok:
            raise DatabaseUnavailable(REASON)
        return True


@pytest.fixture
def root():
    try:
        r = tk.Tk()
    except tk.TclError as err:
        pytest.skip(f'no display available ({err})')
    before = set(threading.enumerate())
    yield r
    finish(r, before)


def test_health_check_runs_off_the_main_thread_and_callbacks_on_it(root):
    store, seen = SlowStore(ok=False), []
    status = DatabaseStatus(root, store, on_down=lambda reason: seen.append(
        threading.current_thread()), check_up_ms=60000)
    started = time.time()
    assert status.check_now()
    assert time.time() - started < 0.15               # the GUI was not blocked by the ping
    assert pump(root, lambda: seen)
    assert store.threads[0] is not threading.main_thread()
    assert seen == [threading.main_thread()]


def test_only_one_health_check_at_a_time(root):
    store = SlowStore(delay=0.3)
    status = DatabaseStatus(root, store, check_up_ms=60000)
    assert status.check_now() is True
    assert status.check_now() is False and status.check_now() is False
    assert pump(root, lambda: not status.checking)
    assert status.checks_started == 1 and len(store.threads) == 1
    assert status.check_now() is True                # the next one may start afterwards


def test_periodic_checks_run_by_themselves(root):
    store = SlowStore(ok=False, delay=0)
    status = DatabaseStatus(root, store, check_up_ms=50, check_down_ms=50)
    assert pump(root, lambda: not status.available)
    store.ok = True
    assert pump(root, lambda: status.available)


def test_post_is_safe_from_any_thread(root):
    status = DatabaseStatus(root, SlowStore(), check_up_ms=60000)
    threads = [threading.Thread(target=status.post, args=(DatabaseUnavailable(REASON),))
               for _ in range(5)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert status.available                          # nothing changes until the main thread reads
    assert pump(root, lambda: not status.available)


def test_sql_error_does_not_mark_the_database_down(root):
    logged = []
    status = DatabaseStatus(root, SlowStore(), log=lambda *a: logged.append(a),
                            check_up_ms=60000)
    assert status.report(DatabaseError('refused')) is True
    assert status.available and logged[-1][2] == 'error'
    assert status.report(ValueError('typed wrong')) is False


def test_closing_the_window_stops_every_check():
    try:
        r = tk.Tk()
    except tk.TclError as err:
        pytest.skip(f'no display available ({err})')
    store = SlowStore(delay=0)
    status = DatabaseStatus(r, store, check_up_ms=30, check_down_ms=30, poll_ms=10)
    pump(r, lambda: store.threads)
    r.destroy()
    assert status.closed and status._timers == {}
    time.sleep(0.05)                                  # a check started just before may finish
    count = len(store.threads)
    time.sleep(0.2)
    assert len(store.threads) == count                # no more checks after closing
    assert status.check_now() is False


def test_report_error_without_a_status_is_harmless(root):
    assert db_status.report_error(root, DatabaseUnavailable('x')) is True
    assert db_status.report_error(root, ValueError('x')) is False
    assert db_status.database_ready(root) is True


# ---------------------------------------------------------------- startup modes
@pytest.mark.parametrize('problem', [None, REASON])
def test_sample_modes_are_labelled_and_have_no_database_status(problem, monkeypatch):
    try:
        root = tk.Tk()
    except tk.TclError as err:
        pytest.skip(f'no display available ({err})')
    try:
        db_fake.reset()
        from gui.main_window import SOURCE_FALLBACK, SOURCE_SAMPLE, build_main_window
        refs = build_main_window(root, db_fake, demo_store=True, startup_problem=problem)
        root.update()
        assert 'db_status' not in refs and getattr(root, 'db_status', None) is None
        if problem:
            assert refs['source_label'].cget('text') == SOURCE_FALLBACK
            banners = [w.cget('text') for w in refs['outage_bar'].master.winfo_children()
                       if w.winfo_class() == 'TLabel']
            assert any('could not be used at startup' in t and 'MySQL error 2003' in t
                       for t in banners)
        else:
            assert refs['source_label'].cget('text') == SOURCE_SAMPLE
    finally:
        root.destroy()
