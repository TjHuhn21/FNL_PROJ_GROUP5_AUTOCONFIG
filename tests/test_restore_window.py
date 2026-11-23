"""Phase 4G: the Restore Backup window (gui/restore_window.py).

Most tests replace restore_preflight.run_checks / create_safety_backup and
restore_engine.restore with controllable stand-ins (the window must only call them, never
re-implement them), and run the REAL worker threads (gui.background.run_async) and Tk event
loop. The end-to-end tests run the real preflight, safety backup and engine through the
window against the Mock Lab on 127.0.0.1. Synthetic data, logins and keys only.
"""
import os
import sys
import threading
import time
import types

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

pytest.importorskip('tkinter')

import backup_catalogue as B  # noqa: E402
import restore_engine as E  # noqa: E402
import restore_preflight as R  # noqa: E402
from config import connect  # noqa: E402
from gui import restore_window as W  # noqa: E402
from gui_helpers import new_root, pump  # noqa: E402

IP = '10.0.0.2'
SEL = B.Selection(os.path.join('C:\\', 'synthetic', 'R1_backup.ncbak'), 'a' * 64, 'b1',
                  'b' * 64, '2026-11-20T00:00:00Z', 7, IP, 'R1', False, False, (),
                  '2026-11-22T00:00:00Z')
DEVICE = B.Device(ip=IP, hostname='R1', device_id=7)
LOGIN = {'host': IP, 'username': 'synthetic-user', 'password': 'Synthetic-pass-1'}
SAFETY = os.path.join('C:\\', 'synthetic', f'{IP}_pre-restore_20261123_100000.ncbak')


# ---------------------------------------------------------------- fixtures and stand-ins
@pytest.fixture
def gui_base(monkeypatch):
    """A root window and recorded message boxes (askyesno answers from answers['yes'])."""
    shown = []
    from tkinter import messagebox
    for name in ('showinfo', 'showerror', 'showwarning'):
        monkeypatch.setattr(messagebox, name,
                            lambda t, m, _n=name, **k: shown.append((_n, t, m)))
    answers = {'yes': True}
    monkeypatch.setattr(messagebox, 'askyesno',
                        lambda t, m, **k: (shown.append(('askyesno', t, m)), answers['yes'])[1])
    root = new_root()
    yield types.SimpleNamespace(root=root, shown=shown, answers=answers)
    W._ACTIVE.clear()
    try:
        root.destroy()
    except Exception:
        pass
    # Collect this test's Tk objects now, on the Tk thread. Otherwise Python's cyclic GC may
    # collect them later while a worker thread of ANOTHER test runs, and tkinter's
    # Variable.__del__ complains ("main thread is not in main loop").
    import gc
    gc.collect()


@pytest.fixture
def gui(gui_base, monkeypatch):
    """gui_base, and any SSH connection fails the test (the stand-in tests)."""
    monkeypatch.setattr(connect, '_open', lambda creds: pytest.fail('the GUI connected'))
    return gui_base


def fake_pre(statuses=(R.PASS,), legacy=False, backup_host=IP, names=None):
    pre = R.PreflightResult(device_ip=IP, selection=SEL)
    names = names or ['backup', 'ssh', 'privilege', 'identity', 'match-serial', 'transfer']
    for n, status in enumerate(statuses):
        pre.checks.append(R.Check(names[n % len(names)], status, f'Explanation {n} ({status}).'))
    pre.identity = {'serial': 'FTX0000SYN1', 'platform': 'CISCO1941/K9', 'hostname': 'R1',
                    'ios_version': None}
    pre.backup = {'host': backup_host, 'plaintext_sha256': 'b' * 64}
    pre.transfer_method, pre.temp_name = 'tcl', 'nc-restore-0123456789abcdef.cfg'
    pre.requires_legacy_confirmation = legacy
    if pre.status in (R.PASS, R.WARNING):
        pre.stage, pre.checked_at = R.CHECKED, time.monotonic()
        pre.required_confirmation = R.confirmation_phrase(IP, legacy)
    return pre


class Calls:
    """Stand-ins that record calls; each can be made to wait on an event."""

    def __init__(self, monkeypatch, pre=None, safety_ok=True, result=E.SUCCESS):
        self.pre = pre if pre is not None else fake_pre()
        self.safety_ok, self.result = safety_ok, result
        self.checks = self.safeties = self.restores = 0
        self.hold_checks, self.hold_safety, self.hold_restore = (threading.Event(),
                                                                 threading.Event(),
                                                                 threading.Event())
        for e in (self.hold_checks, self.hold_safety, self.hold_restore):
            e.set()
        self.threads = []
        monkeypatch.setattr(R, 'run_checks', self.run_checks)
        monkeypatch.setattr(R, 'create_safety_backup', self.create_safety_backup)
        monkeypatch.setattr(E, 'restore', self.restore)

    def run_checks(self, selection, creds, key_source=None, log=None, **kw):
        assert selection is SEL and creds == LOGIN
        self.threads.append(threading.current_thread())
        self.checks += 1
        log('section', 'RESTORE PREFLIGHT (read-only: nothing is changed)')
        self.hold_checks.wait(10)
        if isinstance(self.pre, Exception):
            raise self.pre
        return self.pre

    def create_safety_backup(self, pre, typed, creds, backup_dir=None, key_source=None,
                             log=None):
        self.threads.append(threading.current_thread())
        self.safeties += 1
        assert typed == pre.required_confirmation
        self.hold_safety.wait(10)
        if isinstance(self.safety_ok, Exception):
            raise self.safety_ok
        if self.safety_ok:
            pre.stage, pre.safety_backup_path = R.SAFETY_BACKUP_CREATED, SAFETY
        else:
            pre.checks.append(R.Check('safety-backup', R.FAILED, 'Synthetic write failure.'))
            pre.stage = R.STOPPED
        return pre

    def restore(self, pre, creds, timer_minutes=5, key_source=None, log=None, **kw):
        self.threads.append(threading.current_thread())
        self.restores += 1
        self.minutes = timer_minutes
        assert pre.stage == R.SAFETY_BACKUP_CREATED
        log('section', 'CONFIGURE REPLACE')
        self.hold_restore.wait(10)
        if isinstance(self.result, Exception):
            raise self.result
        res = E.RestoreResult(status=self.result, device_ip=IP, backup_file=SEL.path,
                              safety_backup_file=SAFETY, identity=pre.identity,
                              timer_state='cancelled (verified)'
                              if self.result == E.SUCCESS else 'not pending')
        if self.result != E.SUCCESS:
            res.manual_actions.append('Synthetic manual action.')
        return res


def window(g, can_restore=True, get_creds=lambda: dict(LOGIN), **kw):
    win = W.RestoreWindow(g.root, SEL, DEVICE, can_restore, get_creds, **kw)
    g.root.update()
    return win


def checked(g, win):
    win.run_checks()
    assert pump(g.root, lambda: win.state == W.IDLE and win.pre is not None)
    return win


def disabled(button):
    return button.instate(['disabled'])


def tree_rows(win):
    return [win.tree.item(i, 'values') for i in win.tree.get_children()]


# ================================================================ opening, permissions
def test_opening_and_closing_touches_no_device(gui, monkeypatch):
    monkeypatch.setattr(R, 'run_checks', lambda *a, **k: pytest.fail('checks ran'))
    win = window(gui, get_creds=lambda: pytest.fail('the login was read'))
    assert IP in win.device_label.cget('text') and 'R1_backup.ncbak' in \
        win.backup_label.cget('text')
    assert 'verified when it was selected' in win.backup_label.cget('text')
    assert disabled(win.restore_btn) and not disabled(win.check_btn)
    assert disabled(win.typed_entry)
    win.close()
    assert not win.alive and not W.busy(IP)


def test_viewer_cannot_check_or_restore(gui, monkeypatch):
    calls = Calls(monkeypatch)
    win = window(gui, can_restore=False, get_creds=lambda: pytest.fail('login read'))
    assert disabled(win.check_btn) and disabled(win.restore_btn)
    assert 'may not restore' in win.note_label.cget('text')
    win.run_checks()
    win.pre = calls.pre
    win.typed.set(calls.pre.required_confirmation)
    win.start_restore()
    gui.root.update()
    assert calls.checks == calls.safeties == calls.restores == 0


def test_catalogue_offers_restore_only_after_selection_and_with_permission(gui, tmp_path):
    from gui.backup_catalogue_window import BackupCatalogueWindow
    opened = []
    win = BackupCatalogueWindow(gui.root, DEVICE, True, backup_dir=str(tmp_path),
                                on_restore=opened.append)
    assert disabled(win.restore_btn)
    win.open_restore()
    assert opened == []
    win.selection = SEL
    win.restore_btn.state(['!disabled'])
    win.open_restore()
    assert opened == [SEL]
    viewer = BackupCatalogueWindow(gui.root, DEVICE, False, backup_dir=str(tmp_path),
                                   on_restore=opened.append)
    viewer.selection = SEL
    viewer.open_restore()
    assert opened == [SEL] and disabled(viewer.restore_btn)


def test_devices_page_opens_restore_only_with_the_configure_permission(gui, monkeypatch):
    import db_fake
    from gui.devices_tab import DevicesTab
    db_fake.reset()
    tab = DevicesTab(gui.root, db_fake)
    tab.set_backups_allowed(False)
    tab.open_restore(SEL, {'id': 7, 'ip': IP, 'name': 'R1'})
    assert not hasattr(tab, 'restore_window')
    tab.set_backups_allowed(True)
    tab.open_restore(SEL, {'id': 7, 'ip': IP, 'name': 'R1'})
    assert isinstance(tab.restore_window, W.RestoreWindow) and tab.restore_window.can_restore
    from gui.components import login_dialog
    monkeypatch.setattr(login_dialog, 'ask_device_login',
                        lambda *a, **k: {'username': 'u', 'password': 'p', 'save': False})
    assert tab._restore_login({'id': 7, 'ip': IP, 'name': 'R1'}) == {
        'host': IP, 'username': 'u', 'password': 'p'}
    monkeypatch.setattr(login_dialog, 'ask_device_login', lambda *a, **k: None)
    assert tab._restore_login({'id': 7, 'ip': IP, 'name': 'R1'}) is None


# ================================================================ read-only checks
def test_run_checks_is_read_only_and_runs_on_a_worker(gui, monkeypatch):
    statuses = (R.PASS, R.WARNING, R.PASS, R.PASS, R.WARNING, R.PASS)
    calls = Calls(monkeypatch, fake_pre(statuses))
    win = checked(gui, window(gui))
    assert calls.checks == 1 and calls.safeties == calls.restores == 0
    assert calls.threads[0] is not threading.main_thread()
    rows = tree_rows(win)
    assert [r[0] for r in rows] == list(statuses)
    assert rows[0][1] == 'Selected backup' and rows[4][1] == 'Serial number'
    assert all(r[2].startswith('Explanation') for r in rows)
    summary = win.summary_label.cget('text')
    assert 'Overall: WARNING' in summary and 'read why before you confirm' in summary
    assert f'type exactly:   RESTORE {IP}' in win.phrase_label.cget('text')
    assert disabled(win.restore_btn) and not disabled(win.typed_entry)
    assert 'RESTORE PREFLIGHT' in win.log_text.get('1.0', 'end')
    assert not W.busy(IP)


@pytest.mark.parametrize('statuses, word', [
    ((R.PASS, R.BLOCKED, R.WARNING), 'BLOCKED'), ((R.PASS, R.FAILED), 'FAILED'),
    ((R.BLOCKED, R.FAILED, R.WARNING, R.PASS), 'BLOCKED')])
def test_blocked_or_failed_checks_prevent_safety_backup_and_restore(gui, monkeypatch,
                                                                    statuses, word):
    calls = Calls(monkeypatch, fake_pre(statuses))
    win = checked(gui, window(gui))
    assert [r[0] for r in tree_rows(win)] == list(statuses)
    assert f'Overall: {word}' in win.summary_label.cget('text')
    assert 'cannot continue' in win.phrase_label.cget('text')
    assert disabled(win.restore_btn) and disabled(win.typed_entry)
    win.typed.set(f'RESTORE {IP}')
    win.start_restore()
    gui.root.update()
    assert calls.safeties == calls.restores == 0


@pytest.mark.parametrize('typed', ['', 'RESTORE', f'RESTORE {IP[:-1]}', f'restore {IP}',
                                   f'RESTORE {IP} ', f' RESTORE {IP}', f'RESTORE LEGACY {IP}'])
def test_wrong_or_incomplete_confirmation(gui, monkeypatch, typed):
    calls = Calls(monkeypatch)
    win = checked(gui, window(gui))
    win.typed.set(typed)
    gui.root.update()
    assert disabled(win.restore_btn)
    win.start_restore()                                 # even if called directly
    gui.root.update()
    assert calls.safeties == calls.restores == 0
    assert gui.shown and gui.shown[-1][0] == 'showerror' and 'not typed exactly' in \
        gui.shown[-1][2]


def test_legacy_backup_needs_the_legacy_phrase(gui, monkeypatch):
    calls = Calls(monkeypatch, fake_pre((R.PASS, R.WARNING), legacy=True))
    win = checked(gui, window(gui))
    assert 'LEGACY BACKUP' in win.summary_label.cget('text')
    win.typed.set(f'RESTORE {IP}')
    gui.root.update()
    assert disabled(win.restore_btn)
    win.typed.set(f'RESTORE LEGACY {IP}')
    gui.root.update()
    assert not disabled(win.restore_btn)
    win.start_restore()
    assert pump(gui.root, lambda: win.state == W.DONE)
    assert calls.safeties == calls.restores == 1


def test_changed_ip_candidate_is_explained(gui, monkeypatch):
    import dataclasses
    candidate = dataclasses.replace(SEL, live_identity_required=True)
    calls = Calls(monkeypatch, fake_pre((R.PASS, R.WARNING), backup_host='10.0.0.99'))
    calls.pre.selection = candidate
    monkeypatch.setattr(calls, 'run_checks', lambda *a, **k: calls.pre)
    monkeypatch.setattr(R, 'run_checks', lambda *a, **k: calls.pre)
    win = W.RestoreWindow(gui.root, candidate, DEVICE, True, lambda: dict(LOGIN))
    assert 'PENDING CANDIDATE' in win.note_label.cget('text')
    checked(gui, win)
    assert 'CHANGED IP: the backup was recorded for 10.0.0.99' in win.summary_label.cget('text')
    assert win.pre.required_confirmation == f'RESTORE {IP}'


def test_no_login_means_no_checks(gui, monkeypatch):
    calls = Calls(monkeypatch)
    win = window(gui, get_creds=lambda: None)
    win.run_checks()
    gui.root.update()
    assert calls.checks == 0 and win.state == W.IDLE and not W.busy(IP)


# ================================================================ safety backup and restore
def confirm(g, win):
    win.typed.set(win.pre.required_confirmation)
    g.root.update()
    assert not disabled(win.restore_btn)
    win.start_restore()


def test_declining_the_final_question_changes_nothing(gui, monkeypatch):
    calls = Calls(monkeypatch)
    win = checked(gui, window(gui))
    gui.answers['yes'] = False
    confirm(gui, win)
    gui.root.update()
    assert calls.safeties == calls.restores == 0 and win.state == W.IDLE
    question = [m for k, _t, m in gui.shown if k == 'askyesno'][-1]
    assert IP in question and 'R1_backup.ncbak' in question and 'FTX0000SYN1' in question


@pytest.mark.parametrize('failure', [False, R.ConfirmationRefused('too old'),
                                     RuntimeError('worker crashed')])
def test_safety_backup_failure_prevents_restore(gui, monkeypatch, failure):
    calls = Calls(monkeypatch, safety_ok=failure)
    win = checked(gui, window(gui))
    confirm(gui, win)
    assert pump(gui.root, lambda: win.state == W.IDLE and calls.safeties == 1)
    gui.root.update()
    assert calls.restores == 0 and not W.busy(IP)
    assert 'not' in win.summary_label.cget('text')       # "not made" / "Restore not started"
    assert 'Safety backup: not created yet' == win.safety_label.cget('text')


@pytest.mark.parametrize('status', [E.SUCCESS, E.FAILED, E.PARTIAL, E.UNKNOWN])
def test_every_final_result_is_shown_accurately(gui, monkeypatch, status):
    finished = []
    calls = Calls(monkeypatch, result=status)
    win = checked(gui, window(gui, on_finished=finished.append))
    win.minutes.set('7')
    confirm(gui, win)
    assert pump(gui.root, lambda: win.state == W.DONE)
    assert calls.safeties == calls.restores == 1 and calls.minutes == 7
    assert all(t is not threading.main_thread() for t in calls.threads)
    assert win.result_label.cget('text') == f'Result: {status}'
    summary = win.summary_label.cget('text')
    assert W.RESULT_HELP[status] in summary
    assert SEL.path in summary and SAFETY in summary
    assert SAFETY in win.safety_label.cget('text')
    assert finished and finished[0].status == status and not W.busy(IP)
    if status == E.SUCCESS:
        assert 'cancelled (verified)' in win.timer_label.cget('text')
        assert not [s for s in gui.shown if s[0] == 'showwarning']
    else:
        warning = [s for s in gui.shown if s[0] == 'showwarning'][-1]
        assert status in warning[1] and 'ACTION REQUIRED: Synthetic manual action.' in warning[2]
    assert disabled(win.restore_btn) and disabled(win.cancel_btn)


def test_restore_worker_exception_is_unknown_with_instructions(gui, monkeypatch):
    calls = Calls(monkeypatch, result=RuntimeError('synthetic crash'))
    win = checked(gui, window(gui))
    confirm(gui, win)
    assert pump(gui.root, lambda: win.state == W.DONE)
    assert win.result.status == E.UNKNOWN and win.result_label.cget('text') == 'Result: UNKNOWN'
    assert any('RuntimeError' in a and SAFETY in a for a in win.result.manual_actions)
    assert 'synthetic crash' not in win.summary_label.cget('text')


def test_check_worker_exception(gui, monkeypatch):
    Calls(monkeypatch, pre=RuntimeError('synthetic'))
    win = window(gui)
    win.run_checks()
    assert pump(gui.root, lambda: win.state == W.IDLE and 'stopped unexpectedly' in
                win.summary_label.cget('text'))
    assert disabled(win.restore_btn) and not W.busy(IP)


def test_window_stays_responsive_while_workers_run(gui, monkeypatch):
    calls = Calls(monkeypatch)
    calls.hold_checks.clear()
    win = window(gui)
    ticks = []
    win.run_checks()
    for n in range(5):
        gui.root.after(20 * (n + 1), lambda: ticks.append(1))
    assert pump(gui.root, lambda: len(ticks) == 5, timeout=5)
    assert win.state == W.CHECKING                      # the worker is still waiting
    calls.hold_checks.set()
    assert pump(gui.root, lambda: win.state == W.IDLE and win.pre is not None)


# ================================================================ closing and duplicates
def test_closing_during_checks_releases_the_device(gui, monkeypatch):
    calls = Calls(monkeypatch)
    calls.hold_checks.clear()
    win = window(gui)
    win.run_checks()
    gui.root.update()
    win.close()
    assert not win.alive and W.busy(IP)
    calls.hold_checks.set()
    assert pump(gui.root, lambda: not W.busy(IP))
    assert calls.safeties == calls.restores == 0


def test_closing_before_replacement_cancels_the_restore(gui, monkeypatch):
    calls = Calls(monkeypatch)
    calls.hold_safety.clear()
    win = checked(gui, window(gui))
    confirm(gui, win)
    assert pump(gui.root, lambda: calls.safeties == 1)
    win.close()                                         # allowed: nothing replaced yet
    assert not win.alive
    calls.hold_safety.set()
    assert pump(gui.root, lambda: not W.busy(IP))
    gui.root.update()
    assert calls.restores == 0 and calls.pre.stage == R.CANCELLED


def test_cancel_button_before_replacement(gui, monkeypatch):
    calls = Calls(monkeypatch)
    calls.hold_safety.clear()
    win = checked(gui, window(gui))
    confirm(gui, win)
    assert pump(gui.root, lambda: calls.safeties == 1)
    win.cancel()
    assert win.alive and win.cancel_requested
    calls.hold_safety.set()
    assert pump(gui.root, lambda: not W.busy(IP))
    assert calls.restores == 0 and calls.pre.stage == R.CANCELLED
    assert 'Cancelled after the safety backup' in win.summary_label.cget('text')
    assert SAFETY in win.safety_label.cget('text')
    checked_again = fake_pre()
    calls.pre = checked_again
    win.cancel()                                        # idle: cancels the checks and closes
    assert not win.alive


def test_closing_after_replacement_began_never_interrupts(gui, monkeypatch):
    calls = Calls(monkeypatch)
    calls.hold_restore.clear()
    win = checked(gui, window(gui))
    confirm(gui, win)
    assert pump(gui.root, lambda: win.state == W.RESTORING and calls.restores == 1)
    assert pump(gui.root, lambda: 'CONFIGURE REPLACE' in win.stage_label.cget('text'))
    assert 'started (5 minutes)' in win.timer_label.cget('text')
    win.close()
    win.cancel()
    win.protocol('WM_DELETE_WINDOW')                    # the handler is still ours
    assert win.alive and win.winfo_exists() and win.state == W.RESTORING
    assert disabled(win.close_btn) and disabled(win.cancel_btn)
    refusals = [s for s in gui.shown if s[0] == 'showwarning' and 'cannot be' in s[2]]
    assert len(refusals) == 2 and W.busy(IP)
    calls.hold_restore.set()                            # the engine finishes on its own
    assert pump(gui.root, lambda: win.state == W.DONE)
    assert win.result_label.cget('text') == 'Result: SUCCESS' and not W.busy(IP)
    win.close()
    assert not win.alive


def test_closing_the_catalogue_does_not_close_a_running_restore(gui, monkeypatch, tmp_path):
    from gui.backup_catalogue_window import BackupCatalogueWindow
    calls = Calls(monkeypatch)
    calls.hold_restore.clear()
    catalogue = BackupCatalogueWindow(gui.root, DEVICE, True, backup_dir=str(tmp_path))
    win = W.RestoreWindow(catalogue, SEL, DEVICE, True, lambda: dict(LOGIN))
    checked(gui, win)
    confirm(gui, win)
    assert pump(gui.root, lambda: win.state == W.RESTORING)
    catalogue.destroy()
    gui.root.update()
    assert win.winfo_exists() and win.alive
    calls.hold_restore.set()
    assert pump(gui.root, lambda: win.state == W.DONE)


def test_only_one_operation_per_device(gui, monkeypatch):
    calls = Calls(monkeypatch)
    calls.hold_checks.clear()
    first = window(gui)
    second = window(gui, get_creds=lambda: pytest.fail('second window read the login'))
    first.run_checks()
    gui.root.update()
    second.run_checks()
    assert gui.shown[-1][0] == 'showerror' and 'already running' in gui.shown[-1][2]
    assert calls.checks == 1
    calls.hold_checks.set()
    assert pump(gui.root, lambda: not W.busy(IP))
    calls.hold_restore.clear()
    second = window(gui)
    checked(gui, second)
    calls.pre = fake_pre()                              # each window has its own result
    checked(gui, first)
    confirm(gui, first)
    assert pump(gui.root, lambda: first.state == W.RESTORING)
    second.typed.set(second.pre.required_confirmation)
    second.start_restore()
    assert gui.shown[-1][0] == 'showerror' and 'already running' in gui.shown[-1][2]
    assert calls.safeties == 1
    calls.hold_restore.set()
    assert pump(gui.root, lambda: first.state == W.DONE and not W.busy(IP))


def test_claims_are_exclusive_across_threads():
    W._ACTIVE.clear()
    wins = []
    barrier = threading.Barrier(8)

    def grab():
        barrier.wait()
        wins.append(W.claim('192.0.2.50'))
    threads = [threading.Thread(target=grab) for _ in range(8)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert wins.count(True) == 1
    W.release('192.0.2.50')
    assert not W.busy('192.0.2.50')


# ================================================================ end to end (Mock Lab)
from test_restore_preflight import (creds, key_path, lab_with, r1_spec,  # noqa: E402,F401
                                    setup, state)


@pytest.fixture
def fast_inline_transfer(monkeypatch):
    import time as real_time
    from netmiko.cisco import cisco_ios
    monkeypatch.setattr(cisco_ios, 'time', types.SimpleNamespace(
        sleep=lambda s: real_time.sleep(min(s, 0.05)), time=real_time.time,
        monotonic=real_time.monotonic))


@pytest.fixture
def lab_gui(gui_base, setup, fast_inline_transfer, tmp_path):
    """The real preflight, safety backup and engine, through the window, to the Mock Lab
    (the synthetic backup key of tests/conftest.py; never the user's keyring)."""
    pytest.importorskip('netmiko')
    gui = gui_base

    def make(spec=None, **kw):
        lab, dev, selection, spec = setup(spec=spec, **kw)
        device = B.Device(ip=spec['host'], hostname='MOCK-R1', device_id=1)
        win = W.RestoreWindow(gui.root, selection, device, True, lambda: creds(spec),
                              backup_dir=str(tmp_path / 'safety'))
        return types.SimpleNamespace(lab=lab, dev=dev, spec=spec, win=win,
                                     original=dev.running_config(), before=state(dev))
    return make


def run_gui_restore(gui, case):
    """Checks, typed confirmation, safety backup and restore, all through the window."""
    win = case.win
    win.run_checks()
    assert pump(gui.root, lambda: win.state == W.IDLE and win.pre is not None, timeout=60)
    assert win.pre.can_proceed, win.pre.lines()
    assert state(case.dev) == case.before                # checks changed nothing
    win.typed.set(win.pre.required_confirmation)
    gui.root.update()
    win.start_restore()
    assert pump(gui.root, lambda: win.state == W.RESTORING, timeout=60)
    win.close()                                         # refused while restoring
    assert win.alive
    assert pump(gui.root, lambda: win.state == W.DONE, timeout=120)
    return win.result


def test_end_to_end_success_through_the_window(gui_base, lab_gui, tmp_path):
    gui = gui_base
    case = lab_gui()
    result = run_gui_restore(gui, case)
    assert result.status == E.SUCCESS, result.lines()
    assert 'ntp server 192.0.2.77' in case.dev.running_config()
    assert case.dev.saves == 0 and case.dev.startup == case.before[1]   # startup untouched
    assert os.listdir(tmp_path / 'safety') == [os.path.basename(result.safety_backup_file)]
    assert result.safety_backup_file in case.win.summary_label.cget('text')
    assert case.win.result_label.cget('text') == 'Result: SUCCESS'
    log = case.win.log_text.get('1.0', 'end')
    assert 'SynthPreflightMarker' not in log and 'ntp server 192.0.2.77' not in log


def test_end_to_end_mismatch_is_rolled_back_through_the_window(gui_base, lab_gui):
    gui = gui_base
    case = lab_gui(spec=r1_spec(quirks=['verify_mismatch']))
    result = run_gui_restore(gui, case)
    assert result.status == E.FAILED and result.rollback_verified, result.lines()
    assert case.dev.running_config() == case.original and case.dev.saves == 0
    assert case.win.result_label.cget('text') == 'Result: FAILED'
    assert any(s[0] == 'showwarning' and 'FAILED' in s[1] for s in gui.shown)
