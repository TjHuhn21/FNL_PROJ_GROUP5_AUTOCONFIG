"""Phase 4G follow-up: the application must not close while a restore runs.

The real main.run_workbench is used (its event loop replaced by each test's action, as in
tests/test_gui_auth.py), in demo mode and signed in against the synthetic auth backend.
Window-level protection uses the Phase 4G stand-ins and, end to end, the Mock Lab.
Synthetic data only; no physical device, real login or production key.
"""
import os
import sys
import threading
import time
import tkinter as tk

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from tkinter import messagebox  # noqa: E402

import db_fake  # noqa: E402
import restore_engine as E  # noqa: E402
from auth_api_harness import Backend  # noqa: E402
from desktop_auth.session import Access, AuthSession  # noqa: E402
from gui import restore_window as W  # noqa: E402
from gui_helpers import new_root, pump  # noqa: E402
from test_restore_window import (IP, Calls, checked, confirm, fast_inline_transfer,  # noqa
                                 gui, gui_base, key_path, lab_gui, lab_with,
                                 run_gui_restore, setup, window)

SHUTDOWN = W.SHUTDOWN_TITLE


@pytest.fixture(autouse=True)
def clean_registry():
    W._ACTIVE.clear()
    W._PROTECTED.clear()
    W._WINDOWS.clear()
    yield
    W._ACTIVE.clear()
    W._PROTECTED.clear()
    W._WINDOWS.clear()


@pytest.fixture
def boxes(monkeypatch):
    shown = []
    for name in ('showinfo', 'showwarning', 'showerror'):
        monkeypatch.setattr(messagebox, name,
                            lambda t, m, _n=name, **k: shown.append((_n, t, m)))
    return shown


def exists(root):
    try:
        return bool(root.winfo_exists())
    except tk.TclError:
        return False


def signed_in_session(backend, role='operator'):
    email = f'{role}@example.com'
    backend.user(email, role=role)
    data = backend.sign_in_data(email)
    return AuthSession(token=data['token'], user_id=data['user_id'], role=data['role'],
                       email=email, idle_timeout_seconds=data['idle_timeout_seconds'],
                       expires_in_seconds=data['expires_in_seconds'])


def workbench(monkeypatch, action, signed_in=False):
    """main.run_workbench with `action(refs, root)` instead of the event loop. Returns
    (outcome, root, session)."""
    import main
    import gui.main_window as mw
    captured, roots = {}, []
    real_build = mw.build_main_window
    monkeypatch.setattr(mw, 'build_main_window',
                        lambda *a, **k: captured.setdefault('refs', real_build(*a, **k)))

    def make_root():
        root = new_root()
        root.mainloop = lambda n=0: action(captured['refs'], root)
        roots.append(root)
        return root
    db_fake.reset()
    session = None
    if signed_in:
        backend = Backend()
        session = signed_in_session(backend)
        kwargs = dict(access=session.access, client=backend.client, session=session)
    else:
        kwargs = dict(access=Access(None, demo=True))
    try:
        outcome = main.run_workbench(db_fake, True, None, make_root=make_root, **kwargs)
    finally:
        for root in roots:
            try:
                root.destroy()
            except tk.TclError:
                pass
    return outcome, roots[0], session


def press_x(refs, root):
    root.tk.call(refs['close_window'])          # exactly what the title-bar X runs


# ================================================================ the application window
def test_demo_mode_closes_normally_without_a_restore(monkeypatch, boxes):
    import main
    seen = {}

    def action(refs, root):
        press_x(refs, root)
        seen['open'] = exists(root)
    outcome, root, _ = workbench(monkeypatch, action)
    assert outcome == main.CLOSED and seen['open'] is False and boxes == []


def test_demo_mode_x_is_blocked_while_a_restore_runs(monkeypatch, boxes):
    seen = {}

    def action(refs, root):
        token = W._protect(IP)
        press_x(refs, root)
        seen['blocked'] = exists(root)
        W._unprotect(token)                     # the restore finished
        press_x(refs, root)
        seen['after'] = exists(root)
    workbench(monkeypatch, action)
    assert seen == {'blocked': True, 'after': False}
    assert len(boxes) == 1 and boxes[0][1] == SHUTDOWN and IP in boxes[0][2]
    assert 'must stay open' in boxes[0][2]


def test_signed_in_x_and_sign_out_are_blocked_while_a_restore_runs(monkeypatch, boxes):
    import main
    seen = {}

    def action(refs, root):
        token = W._protect(IP)
        session = refs['session_watcher'].session
        press_x(refs, root)
        refs['sign_out_button'].invoke()
        seen['open'], seen['active'] = exists(root), session.active   # nothing ended
        W._unprotect(token)
        refs['sign_out_button'].invoke()
        seen['after'] = exists(root)
    outcome, root, session = workbench(monkeypatch, action, signed_in=True)
    assert seen == {'open': True, 'active': True, 'after': False}
    assert outcome == main.SIGNED_OUT and not session.active
    assert [b[1] for b in boxes] == [SHUTDOWN, SHUTDOWN]


def test_signed_in_x_works_without_a_restore(monkeypatch, boxes):
    import main
    outcome, root, session = workbench(monkeypatch, press_x, signed_in=True)
    assert outcome == main.CLOSED and not exists(root) and not session.active
    assert boxes == []


def test_ended_session_waits_for_the_restore_and_its_window(monkeypatch, boxes):
    import main
    seen = {}

    class OpenResultWindow:                    # a Restore window still showing its result
        alive, state = True, W.DONE

        def keeps_open(self):
            return True

    def pump_until(root, cond, timeout=5):
        end = time.time() + timeout
        while time.time() < end and exists(root) and not cond():
            root.update()
            time.sleep(0.02)

    def action(refs, root):
        token = W._protect(IP)
        result_window = OpenResultWindow()
        W._WINDOWS.add(result_window)
        refs['session_watcher'].end('ended')   # e.g. the account was disabled
        seen['hidden'] = root.state() == 'withdrawn'
        pump_until(root, lambda: False, timeout=1.2)
        seen['still_open'] = exists(root)
        W._unprotect(token)                    # the restore finished...
        pump_until(root, lambda: False, timeout=1.2)
        seen['open_with_result'] = exists(root)
        result_window.alive = False            # ...and the user closed its window
        pump_until(root, lambda: not exists(root), timeout=3)
        seen['closed'] = not exists(root)
    outcome, root, session = workbench(monkeypatch, action, signed_in=True)
    assert seen == {'hidden': True, 'still_open': True, 'open_with_result': True,
                    'closed': True}
    assert outcome == main.SIGNED_OUT and not session.active
    assert boxes[0][1] == 'Signed out after the restore' and 'restore is still running' in \
        boxes[0][2]


def test_ended_session_without_a_restore_signs_out_at_once(monkeypatch, boxes):
    import main
    outcome, root, _ = workbench(
        monkeypatch, lambda refs, root: refs['session_watcher'].end('idle'), signed_in=True)
    assert outcome == main.SIGNED_OUT and not exists(root)
    assert boxes and boxes[0][1] == 'Signed out'


def test_workbench_closed_frees_unprotected_claims():
    assert W.claim('192.0.2.1') and W.claim('192.0.2.2')
    W._protect('192.0.2.2')
    W.workbench_closed()
    assert not W.busy('192.0.2.1') and W.busy('192.0.2.2')


# ================================================================ protection lifecycle
def test_read_only_checks_do_not_block_shutdown(gui, monkeypatch):
    calls = Calls(monkeypatch)
    calls.hold_checks.clear()
    win = window(gui)
    win.run_checks()
    gui.root.update()
    assert win.state == W.CHECKING and W.active_restores() == []
    assert W.block_shutdown(gui.root) is False
    calls.hold_checks.set()
    assert pump(gui.root, lambda: win.state == W.IDLE)


def test_safety_backup_blocks_shutdown_until_it_ends(gui, monkeypatch):
    calls = Calls(monkeypatch, safety_ok=False)
    calls.hold_safety.clear()
    win = checked(gui, window(gui))
    confirm(gui, win)
    assert pump(gui.root, lambda: calls.safeties == 1)
    assert W.active_restores() == [IP] and W.block_shutdown(gui.root) is True
    calls.hold_safety.set()
    assert pump(gui.root, lambda: win.state == W.IDLE)
    assert W.active_restores() == [] and W.block_shutdown(gui.root) is False


@pytest.mark.parametrize('result', [E.SUCCESS, E.FAILED, E.PARTIAL, E.UNKNOWN,
                                    RuntimeError('synthetic worker crash')])
def test_restore_blocks_shutdown_until_every_terminal_result(gui, monkeypatch, result):
    calls = Calls(monkeypatch, result=result)
    calls.hold_restore.clear()
    win = checked(gui, window(gui))
    confirm(gui, win)
    assert pump(gui.root, lambda: win.state == W.RESTORING and calls.restores == 1)
    for _ in range(3):
        assert W.block_shutdown(gui.root) is True
    calls.hold_restore.set()
    assert pump(gui.root, lambda: win.state == W.DONE)
    assert W.active_restores() == [] and not W.busy(IP)
    assert W.block_shutdown(gui.root) is False


@pytest.mark.parametrize('safety', [False, RuntimeError('synthetic'), 'cancel'])
def test_safety_stage_endings_release_the_protection(gui, monkeypatch, safety):
    calls = Calls(monkeypatch, safety_ok=True if safety == 'cancel' else safety)
    calls.hold_safety.clear()
    win = checked(gui, window(gui))
    confirm(gui, win)
    assert pump(gui.root, lambda: calls.safeties == 1)
    if safety == 'cancel':
        win.close()                                     # before replacement: allowed
    calls.hold_safety.set()
    assert pump(gui.root, lambda: not W.busy(IP))
    assert W.active_restores() == [] and calls.restores == 0


def test_an_error_in_the_result_handler_still_releases_everything(gui, monkeypatch):
    calls = Calls(monkeypatch)
    win = checked(gui, window(gui))
    errors = []
    gui.root.report_callback_exception = lambda *exc: errors.append(exc[1])

    def broken(result, error):
        raise RuntimeError('synthetic display failure')
    monkeypatch.setattr(win, '_restore_done', broken)
    confirm(gui, win)
    assert pump(gui.root, lambda: errors)
    assert calls.restores == 1 and W.active_restores() == [] and not W.busy(IP)


def test_shutdown_handler_never_touches_the_worker_or_its_ssh_session(gui, monkeypatch):
    from netmiko.base_connection import BaseConnection
    monkeypatch.setattr(E, '_hard_close', lambda conn: pytest.fail('a session was closed'))
    monkeypatch.setattr(BaseConnection, 'disconnect', lambda self: pytest.fail('disconnect'))
    calls = Calls(monkeypatch)
    calls.hold_restore.clear()
    win = checked(gui, window(gui))
    confirm(gui, win)
    assert pump(gui.root, lambda: win.state == W.RESTORING and calls.restores == 1)
    worker = calls.threads[-1]
    for _ in range(5):
        assert W.block_shutdown(gui.root)
        win.close()
    assert worker.is_alive() and win.state == W.RESTORING
    calls.hold_restore.set()
    assert pump(gui.root, lambda: win.state == W.DONE)
    assert win.result.status == E.SUCCESS


def test_end_to_end_restore_cannot_be_shut_down_and_completes(gui_base, lab_gui):
    """The real preflight, safety backup and engine against the Mock Lab: every shutdown
    attempt during the restore is refused, and the restore completes and is verified."""
    gui = gui_base
    case = lab_gui()
    attempts = []
    real_drain = case.win._drain

    def drain_and_try_to_quit():
        if case.win.state in (W.SAFETY, W.RESTORING):
            attempts.append(W.block_shutdown(gui.root))
        real_drain()
    case.win._drain = drain_and_try_to_quit
    result = run_gui_restore(gui, case)
    assert result.status == E.SUCCESS, result.lines()
    assert attempts and all(attempts)
    assert W.active_restores() == [] and W.block_shutdown(gui.root) is False


# ================================================================ release timing (deterministic)
class Gate:
    """Stand-in for gui.background.run_async: each worker really runs on its own thread
    and has FINISHED when run_async returns, but its result is held until deliver() hands
    it to the Tk thread. The interval in between is what these tests probe."""

    def __init__(self):
        self.pending = []

    def run_async(self, widget, fn, done, poll_ms=50):
        box = {}

        def work():
            try:
                box['result'] = fn()
            except Exception as err:
                box['error'] = err
        worker = threading.Thread(target=work)
        worker.start()
        worker.join(10)
        assert not worker.is_alive()
        self.pending.append((done, box))

    def deliver(self):
        done, box = self.pending.pop(0)
        done(box.get('result'), box.get('error'))


@pytest.fixture
def gate(monkeypatch):
    from gui import background
    g = Gate()
    monkeypatch.setattr(background, 'run_async', g.run_async)
    return g


def to_engine_result(g, win):
    """Checks, confirmation, safety backup: stops with the ENGINE worker finished and its
    result not yet handled."""
    win.run_checks()
    g.deliver()                                         # checks (never protected)
    win.typed.set(win.pre.required_confirmation)
    win.start_restore()                                 # the safety worker has finished
    g.deliver()                                         # its handler starts the engine
    assert len(g.pending) == 1 and win.state == W.RESTORING


def test_shutdown_is_blocked_until_the_result_has_been_handled(monkeypatch, boxes, gate):
    """The real workbench X, tried (1) after the safety worker finished but before its
    result was handled, (2) after the engine worker finished but before its result was
    handled, (3) while the result warning box is open, and (4) afterwards."""
    from test_restore_window import DEVICE, LOGIN, SEL
    Calls(monkeypatch, result=E.FAILED)
    monkeypatch.setattr(messagebox, 'askyesno', lambda *a, **k: True)
    seen = {}

    def action(refs, root):
        win = W.RestoreWindow(root, SEL, DEVICE, True, lambda: dict(LOGIN))
        win.run_checks()
        gate.deliver()
        win.typed.set(win.pre.required_confirmation)
        win.start_restore()
        press_x(refs, root)
        seen['safety worker done, result pending'] = exists(root)
        gate.deliver()
        press_x(refs, root)
        seen['engine worker done, result pending'] = exists(root)
        real_warning = messagebox.showwarning

        def warning(title, text, **kw):
            if title.startswith(W.TITLE + ': '):        # the result box of the restore
                press_x(refs, root)                     # a click on X inside its event loop
                seen['result box open'] = exists(root)
                seen['result recorded'] = (win.result is not None and win.result_label.cget(
                    'text') == 'Result: FAILED' and 'Synthetic manual action.' in text)
                seen['claim released'] = not W.busy(IP)
            return real_warning(title, text, **kw)
        monkeypatch.setattr(messagebox, 'showwarning', warning)
        gate.deliver()
        seen['protected after'] = W.active_restores()
        press_x(refs, root)
        seen['closed after'] = not exists(root)
    workbench(monkeypatch, action)
    assert seen == {'safety worker done, result pending': True,
                    'engine worker done, result pending': True,
                    'result box open': True, 'result recorded': True, 'claim released': True,
                    'protected after': [], 'closed after': True}
    assert sum(1 for b in boxes if b[1] == SHUTDOWN) == 3


@pytest.mark.parametrize('result', [E.SUCCESS, E.FAILED, E.PARTIAL, E.UNKNOWN,
                                    RuntimeError('synthetic worker crash')])
def test_restore_protection_is_released_only_after_its_result_is_handled(gui, monkeypatch,
                                                                        gate, result):
    Calls(monkeypatch, result=result)
    win = window(gui)
    to_engine_result(gate, win)
    assert W.active_restores() == [IP]                  # worker done, result not handled
    during_box = []
    monkeypatch.setattr(messagebox, 'showwarning',
                        lambda t, m, **k: during_box.append(W.active_restores()))
    gate.deliver()
    status = result if isinstance(result, str) else E.UNKNOWN
    assert win.result.status == status and win.state == W.DONE
    assert during_box == ([] if status == E.SUCCESS else [[IP]])   # still protected there
    assert W.active_restores() == [] and not W.busy(IP)
    assert W.block_shutdown(gui.root) is False


@pytest.mark.parametrize('ending', [False, RuntimeError('synthetic'), 'closed'])
def test_safety_protection_is_released_only_after_its_outcome_is_handled(gui, monkeypatch,
                                                                        gate, ending):
    calls = Calls(monkeypatch, safety_ok=True if ending == 'closed' else ending)
    win = window(gui)
    win.run_checks()
    gate.deliver()
    win.typed.set(win.pre.required_confirmation)
    win.start_restore()
    if ending == 'closed':
        win.close()                                     # cancel before replacement
    assert W.active_restores() == [IP]                  # worker done, outcome not handled
    gate.deliver()
    assert W.active_restores() == [] and not W.busy(IP) and calls.restores == 0
    if ending == 'closed':
        assert calls.pre.stage == 'cancelled'


@pytest.mark.parametrize('handler', ['_restore_done', '_safety_done'])
def test_a_failing_completion_handler_still_releases_protection(gui, monkeypatch, gate,
                                                                handler):
    Calls(monkeypatch)
    win = window(gui)
    win.run_checks()
    gate.deliver()
    win.typed.set(win.pre.required_confirmation)

    def broken(result, error):
        raise RuntimeError('synthetic handler failure')
    monkeypatch.setattr(win, handler, broken)
    win.start_restore()
    if handler == '_restore_done':
        gate.deliver()                                  # the real _safety_done runs
    assert W.active_restores() == [IP]
    with pytest.raises(RuntimeError, match='synthetic handler failure'):
        gate.deliver()
    assert W.active_restores() == [] and not W.busy(IP)


def test_the_next_stage_keeps_its_own_protection(gui, monkeypatch, gate):
    """Handing over from the safety backup to the engine never leaves a moment without
    protection, and releasing the safety stage does not drop the engine stage."""
    Calls(monkeypatch)
    win = window(gui)
    win.run_checks()
    gate.deliver()
    win.typed.set(win.pre.required_confirmation)
    win.start_restore()
    assert len(W._PROTECTED) == 1
    gate.deliver()                                      # safety handled, engine started
    assert len(W._PROTECTED) == 1 and W.active_restores() == [IP]
    gate.deliver()
    assert W._PROTECTED == {}
