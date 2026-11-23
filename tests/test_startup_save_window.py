"""Phase 4H: the Save to Startup action of the Restore window and the Save to Startup window
(gui/startup_save_window.py).

Stand-ins replace startup_save.check / save (the window only calls them) with the REAL
worker threads, device claims and shutdown protection; the end-to-end test runs a real
restore and a real save against the Mock Lab. Synthetic data, logins and keys only.
"""
import dataclasses
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

import restore_engine as E  # noqa: E402
import startup_save as S  # noqa: E402
from gui import restore_window as W  # noqa: E402
from gui import startup_save_window as SW  # noqa: E402
from gui_helpers import pump  # noqa: E402
from test_restore_window import (DEVICE, IP, LOGIN, SEL, gui, gui_base,  # noqa: E402,F401
                                 window)

BACKUP = os.path.join('C:\\', 'synthetic', f'{IP}_pre-save-startup_20261123_120000.ncbak')


@pytest.fixture(autouse=True)
def clean_registry():
    for reg in (W._ACTIVE, W._PROTECTED, W._WINDOWS, S._SAVED):
        reg.clear()
    yield
    for reg in (W._ACTIVE, W._PROTECTED, W._WINDOWS, S._SAVED):
        reg.clear()


def restore_result(status=E.SUCCESS, ip=IP, sealed=True, digest='d' * 64):
    """A RestoreResult as the engine produces it (sealed with the engine's own function)."""
    res = E.RestoreResult(status=status, device_ip=ip, backup_file=SEL.path,
                          safety_backup_file='C:\\synthetic\\pre-restore.ncbak',
                          identity={'serial': 'FTX0000SYN1', 'platform': 'CISCO1941/K9',
                                    'hostname': 'R1', 'ios_version': None},
                          confirmed=status in (E.SUCCESS, E.PARTIAL),
                          timer_state='cancelled (verified)' if status in (E.SUCCESS, E.PARTIAL)
                          else 'not pending',
                          device_state=E.RESTORED if status in (E.SUCCESS, E.PARTIAL)
                          else E.ORIGINAL_VERIFIED,
                          restored_digest=digest if status == E.SUCCESS else None)
    if sealed:
        res.seal = E.result_seal_of(res)
    return res


def fake_plan(result, statuses=(S.PASS,)):
    plan = S.SavePlan(device_ip=IP, restore=result)
    plan.identity = dict(result.identity)
    names = ['eligibility', 'session', 'rollback-timer', 'running-config', 'startup-config']
    for n, status in enumerate(statuses):
        plan.checks.append(S.R.Check(names[n % len(names)], status, f'Explanation {n}.'))
    if plan.status in (S.PASS, S.WARNING):
        plan.stage, plan.checked_at = S.CHECKED, time.monotonic()
        plan.required_confirmation = S.confirmation_phrase(IP)
    return plan


class SaveCalls:
    def __init__(self, monkeypatch, statuses=(S.PASS,), outcome=S.SUCCESS):
        self.statuses, self.outcome = statuses, outcome
        self.checks = self.saves = 0
        self.hold_check, self.hold_save = threading.Event(), threading.Event()
        self.hold_check.set()
        self.hold_save.set()
        self.threads = []
        monkeypatch.setattr(S, 'check', self.check)
        monkeypatch.setattr(S, 'save', self.save)

    def check(self, result, creds, key_source=None, log=None, **kw):
        assert creds == LOGIN
        self.threads.append(threading.current_thread())
        self.checks += 1
        log('section', 'SAVE TO STARTUP: CHECKS (read-only: nothing is changed)')
        self.hold_check.wait(10)
        self.plan = fake_plan(result, self.statuses)
        return self.plan

    def save(self, plan, typed, creds, backup_dir=None, key_source=None, log=None, **kw):
        self.threads.append(threading.current_thread())
        self.saves += 1
        assert typed == plan.required_confirmation
        log('section', 'SAVE TO STARTUP')
        self.hold_save.wait(10)
        if isinstance(self.outcome, Exception):
            raise self.outcome
        res = S.SaveResult(status=self.outcome, device_ip=IP, restored_backup=SEL.path,
                           startup_backup=BACKUP, command_sent=True,
                           startup_state=S.SAVED if self.outcome == S.SUCCESS else S.UNCHANGED)
        if self.outcome != S.SUCCESS:
            res.manual_actions.append('Synthetic manual action.')
        return res


def save_window(g, result=None, can_save=True):
    win = SW.StartupSaveWindow(g.root, result or restore_result(), DEVICE, can_save,
                               dict(LOGIN))
    g.root.update()
    return win


def disabled(button):
    return button.instate(['disabled'])


def checked(g, win):
    win.run_checks()
    assert pump(g.root, lambda: win.state == SW.IDLE and win.plan is not None)
    return win


def confirm(g, win):
    win.typed.set(win.plan.required_confirmation)
    g.root.update()
    assert not disabled(win.save_btn)
    win.start_save()


# ================================================================ eligibility in the Restore window
@pytest.mark.parametrize('result, enabled', [
    (restore_result(E.SUCCESS), True),
    (restore_result(E.FAILED), False),
    (restore_result(E.PARTIAL), False),
    (restore_result(E.UNKNOWN), False),
    (restore_result(E.SUCCESS, sealed=False), False),          # not produced by the engine
    (restore_result(E.SUCCESS, ip='10.0.0.9'), False),         # another device
    (restore_result(E.SUCCESS, digest=None), False),           # restored config not recorded
    (None, False)])
def test_save_button_only_for_a_verified_success(gui, result, enabled):
    win = window(gui)
    win.result, win.state = result, W.DONE
    win._update()
    assert disabled(win.save_btn) is not enabled
    win.open_save()
    assert hasattr(win, 'save_window') is enabled


def test_save_button_needs_the_permission_and_a_finished_restore(gui):
    viewer = window(gui, can_restore=False)
    viewer.result, viewer.state = restore_result(), W.DONE
    viewer._update()
    assert disabled(viewer.save_btn)
    busy = window(gui)
    busy.result, busy.state = restore_result(), W.RESTORING
    busy._update()
    assert disabled(busy.save_btn)
    tampered = restore_result()
    tampered.status = E.SUCCESS
    tampered.timer_state = 'pending'                       # changed after sealing
    win = window(gui)
    win.result, win.state = tampered, W.DONE
    win._update()
    assert disabled(win.save_btn)


def test_restore_never_saves_by_itself(gui, monkeypatch):
    from test_restore_window import Calls, checked as restore_checked, confirm as restore_confirm
    monkeypatch.setattr(S, 'save', lambda *a, **k: pytest.fail('saved during the restore'))
    monkeypatch.setattr(S, 'check', lambda *a, **k: pytest.fail('save checks during restore'))
    Calls(monkeypatch)
    win = restore_checked(gui, window(gui))
    restore_confirm(gui, win)
    assert pump(gui.root, lambda: win.state == W.DONE)
    assert not hasattr(win, 'save_window')


# ================================================================ the Save to Startup window
def test_opening_touches_nothing_and_checks_are_read_only(gui, monkeypatch):
    calls = SaveCalls(monkeypatch, statuses=(S.PASS, S.WARNING, S.PASS))
    win = save_window(gui)
    assert calls.checks == calls.saves == 0 and disabled(win.save_btn)
    checked(gui, win)
    assert calls.checks == 1 and calls.saves == 0
    assert calls.threads[0] is not threading.main_thread()
    rows = [win.tree.item(i, 'values') for i in win.tree.get_children()]
    assert [r[0] for r in rows] == [S.PASS, S.WARNING, S.PASS]
    assert rows[0][1] == 'Verified restore' and rows[2][1] == 'No rollback timer'
    assert f'SAVE STARTUP {IP}' in win.phrase_label.cget('text')
    assert 'SAVE TO STARTUP: CHECKS' in win.log_text.get('1.0', 'end')
    assert not W.busy(IP) and W.active_restores() == []


@pytest.mark.parametrize('statuses', [(S.PASS, S.BLOCKED), (S.FAILED,), (S.BLOCKED, S.WARNING)])
def test_blocked_or_failed_checks_prevent_saving(gui, monkeypatch, statuses):
    calls = SaveCalls(monkeypatch, statuses=statuses)
    win = checked(gui, save_window(gui))
    assert disabled(win.save_btn) and disabled(win.typed_entry)
    assert 'not possible' in win.phrase_label.cget('text')
    win.typed.set(f'SAVE STARTUP {IP}')
    win.start_save()
    gui.root.update()
    assert calls.saves == 0


@pytest.mark.parametrize('typed', ['', 'SAVE STARTUP', f'save startup {IP}',
                                   f'SAVE STARTUP {IP} ', f'RESTORE {IP}',
                                   f'SAVE STARTUP 10.0.0.9'])
def test_wrong_confirmation_never_saves(gui, monkeypatch, typed):
    calls = SaveCalls(monkeypatch)
    win = checked(gui, save_window(gui))
    win.typed.set(typed)
    gui.root.update()
    assert disabled(win.save_btn)
    win.start_save()
    gui.root.update()
    assert calls.saves == 0 and gui.shown[-1][0] == 'showerror'


def test_declining_or_closing_before_the_save_changes_nothing(gui, monkeypatch):
    calls = SaveCalls(monkeypatch)
    win = checked(gui, save_window(gui))
    gui.answers['yes'] = False
    confirm(gui, win)
    gui.root.update()
    assert calls.saves == 0 and win.state == SW.IDLE
    question = [m for k, _t, m in gui.shown if k == 'askyesno'][-1]
    for words in (IP, 'R1', 'FTX0000SYN1', 'CISCO1941/K9', os.path.basename(SEL.path),
                  'pre-save-startup backup', 'OVERWRITTEN', 'after a reload'):
        assert words in question, words
    win.close()
    assert not win.alive and calls.saves == 0 and not W.busy(IP)


@pytest.mark.parametrize('outcome', [S.SUCCESS, S.FAILED, S.UNKNOWN,
                                     RuntimeError('synthetic worker crash')])
def test_every_save_result_is_shown_and_releases_everything(gui, monkeypatch, outcome):
    finished = []
    calls = SaveCalls(monkeypatch, outcome=outcome)
    calls.hold_save.clear()
    win = SW.StartupSaveWindow(gui.root, restore_result(), DEVICE, True, dict(LOGIN),
                               on_finished=finished.append)
    checked(gui, win)
    confirm(gui, win)
    assert pump(gui.root, lambda: calls.saves == 1)
    assert win.state == SW.SAVING and W.active_restores() == [IP] and W.busy(IP)
    assert W.block_shutdown(gui.root) is True                # NetCommand cannot close now
    win.close()
    assert win.alive                                         # nor this window
    calls.hold_save.set()
    assert pump(gui.root, lambda: win.state == SW.DONE)
    status = outcome if isinstance(outcome, str) else S.UNKNOWN
    assert win.result_label.cget('text') == f'Result: {status}'
    assert SW.RESULT_HELP[status] in win.summary_label.cget('text')
    assert finished and finished[0].status == status
    assert W.active_restores() == [] and not W.busy(IP)
    assert disabled(win.save_btn) and disabled(win.check_btn)
    if status == S.SUCCESS:
        assert BACKUP in win.backup_label.cget('text')
    else:
        box = [s for s in gui.shown if s[0] == 'showwarning' and s[1].startswith(SW.TITLE)][-1]
        assert status in box[1] and 'ACTION REQUIRED' in box[2]
    win.close()
    assert not win.alive


def test_refused_save_reports_and_saves_nothing(gui, monkeypatch):
    calls = SaveCalls(monkeypatch, outcome=S.SaveRefused('The checks are too old.'))
    win = checked(gui, save_window(gui))
    confirm(gui, win)
    assert pump(gui.root, lambda: win.state == SW.IDLE and calls.saves == 1)
    assert 'Not saved: The checks are too old.' in win.summary_label.cget('text')
    assert W.active_restores() == [] and not W.busy(IP)


def test_check_worker_exception(gui, monkeypatch):
    calls = SaveCalls(monkeypatch)
    monkeypatch.setattr(S, 'check', lambda *a, **k: (_ for _ in ()).throw(RuntimeError('x')))
    win = save_window(gui)
    win.run_checks()
    assert pump(gui.root, lambda: 'stopped unexpectedly' in win.summary_label.cget('text'))
    assert calls.saves == 0 and not W.busy(IP)


def test_window_stays_responsive_during_the_save(gui, monkeypatch):
    calls = SaveCalls(monkeypatch)
    calls.hold_save.clear()
    win = checked(gui, save_window(gui))
    confirm(gui, win)
    ticks = []
    for n in range(5):
        gui.root.after(20 * (n + 1), lambda: ticks.append(1))
    assert pump(gui.root, lambda: len(ticks) == 5, timeout=5)
    assert win.state == SW.SAVING
    calls.hold_save.set()
    assert pump(gui.root, lambda: win.state == SW.DONE)


def test_device_claim_prevents_overlap_with_a_restore_or_another_save(gui, monkeypatch):
    calls = SaveCalls(monkeypatch)
    assert W.claim(IP)                                       # e.g. a restore check running
    win = save_window(gui)
    win.run_checks()
    assert calls.checks == 0 and gui.shown[-1][0] == 'showerror'
    W.release(IP)
    checked(gui, win)
    other = checked(gui, save_window(gui))
    calls.hold_save.clear()
    confirm(gui, win)
    assert pump(gui.root, lambda: win.state == SW.SAVING)
    other.typed.set(other.plan.required_confirmation)
    other.start_save()
    assert calls.saves == 1 and gui.shown[-1][0] == 'showerror'
    calls.hold_save.set()
    assert pump(gui.root, lambda: win.state == SW.DONE and not W.busy(IP))


def test_an_ended_session_waits_for_the_save_and_its_result(gui, monkeypatch):
    calls = SaveCalls(monkeypatch)
    calls.hold_save.clear()
    win = checked(gui, save_window(gui))
    assert not W.restore_activity()                          # read-only checks: no hold
    confirm(gui, win)
    assert pump(gui.root, lambda: win.state == SW.SAVING)
    assert W.restore_activity()
    calls.hold_save.set()
    assert pump(gui.root, lambda: win.state == SW.DONE)
    assert W.restore_activity()                              # its result is still shown
    win.close()
    assert not W.restore_activity()


def test_ineligible_result_cannot_be_checked(gui, monkeypatch):
    calls = SaveCalls(monkeypatch)
    win = save_window(gui, result=restore_result(E.FAILED))
    assert disabled(win.check_btn)
    win.run_checks()
    assert calls.checks == 0
    viewer = save_window(gui, can_save=False)
    viewer.run_checks()
    assert calls.checks == 0 and disabled(viewer.check_btn)


# ================================================================ end to end (Mock Lab)
from test_restore_engine import (fast_inline_transfer, prepared,  # noqa: E402,F401
                                 restore as run_restore)
from test_restore_preflight import key_path, lab_with, setup  # noqa: E402,F401


def test_end_to_end_restore_then_save_through_the_window(gui_base, prepared, tmp_path):
    g = gui_base
    case = prepared()
    result = run_restore(case)
    assert result.status == E.SUCCESS
    saves = case.dev.saves
    device = types.SimpleNamespace(ip=case.spec['host'], hostname='MOCK-R1')
    win = SW.StartupSaveWindow(g.root, result, device, True, case.login,
                               backup_dir=str(tmp_path / 'startup'))
    win.run_checks()
    assert pump(g.root, lambda: win.state == SW.IDLE and win.plan is not None, timeout=60)
    assert win.plan.can_proceed, [c.text for c in win.plan.checks]
    assert case.dev.saves == saves                           # checks saved nothing
    win.typed.set(win.plan.required_confirmation)
    g.root.update()
    win.start_save()
    assert pump(g.root, lambda: win.state == SW.SAVING, timeout=10)
    assert W.block_shutdown(g.root) is True
    assert pump(g.root, lambda: win.state == SW.DONE, timeout=120)
    assert win.result.status == S.SUCCESS, win.result.lines()
    assert case.dev.saves == saves + 1
    assert E.compare_configs(case.dev.startup, case.dev.running_config())[0]
    assert os.listdir(tmp_path / 'startup') == [os.path.basename(win.result.startup_backup)]
    assert W.active_restores() == [] and not W.busy(case.spec['host'])
    assert not S.eligible(result)[0]                         # saved once only
    log = win.log_text.get('1.0', 'end')
    assert 'ntp server 192.0.2.77' not in log and 'SynthPreflightMarker' not in log


def test_a_plan_not_sealed_by_check_is_refused():
    """A hand-made or edited plan never reaches the device (the real save())."""
    plan = fake_plan(restore_result())
    for forged in (plan, dataclasses.replace(plan, seal='0' * 64)):
        with pytest.raises(S.SaveRefused, match='were not run'):
            S.save(forged, forged.required_confirmation, LOGIN)
