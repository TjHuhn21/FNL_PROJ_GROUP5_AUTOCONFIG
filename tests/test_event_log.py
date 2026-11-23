"""The Console's shared logging (gui.event_log.log_event) and how the Console shows it:
labelled, colour-coded outcomes, 12-hour times, the full history, smart auto-scroll, and
error dialogs that are never silent."""
import os, sys, re
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))
sys.path.insert(0, os.path.dirname(__file__))
import pytest

tk = pytest.importorskip('tkinter')

import db_fake  # noqa: E402
from gui import event_log, theme  # noqa: E402
from gui.event_log import log_event, normalize  # noqa: E402

TIME = re.compile(r'^ ?\d{1,2}:\d{2}:\d{2} (AM|PM)$')


@pytest.mark.parametrize('message, level, shown', [
    ('R1: validation SUCCESSFUL.', 'ok', ('R1: validation SUCCESSFUL.', 'ok')),
    ('Approved 1 device', 'success', ('SUCCESSFUL: Approved 1 device', 'ok')),
    ('R1: apply FAILED. No answer', 'error', ('R1: apply FAILED. No answer', 'error')),
    ('No answer', 'failed', ('FAILED: No answer', 'error')),
    ('Sample mode', 'warning', ('WARNING: Sample mode', 'warn')),
    ('Scanning from seed 10.0.0.1...', 'info', ('Scanning from seed 10.0.0.1...', 'info')),
    ('two\n  lines', None, ('two lines', 'info'))])
def test_every_outcome_says_what_happened(message, level, shown):
    assert normalize(message, level) == shown


@pytest.fixture
def console():
    from gui_helpers import new_root
    from gui.components.console import OperationsConsole
    root = new_root()
    theme.apply(root)
    c = OperationsConsole(root, db_fake)
    c.pack(fill='both', expand=True)
    root.update()
    yield root, c
    root.destroy()


def test_log_event_reaches_the_console_coloured_with_12_hour_time(console):
    root, c = console
    log_event('configure', 'R1: validating configuration...')
    log_event('configure', 'R1: validation SUCCESSFUL.', 'ok')
    log_event('configure', 'R1: apply FAILED. No answer.', 'error')
    log_event('app', 'Sample mode', 'warn')
    c.flush()
    assert [(s, m, l) for _t, s, m, l in c.lines] == [
        ('configure', 'R1: validating configuration...', 'info'),
        ('configure', 'R1: validation SUCCESSFUL.', 'ok'),
        ('configure', 'R1: apply FAILED. No answer.', 'error'),
        ('app', 'WARNING: Sample mode', 'warn')]
    assert all(TIME.match(t) for t, *_ in c.lines)
    colours = {level: c.text.tag_cget(level, 'foreground') for level in ('ok', 'error', 'warn')}
    assert colours == {'ok': theme.SUCCESS, 'error': theme.DANGER, 'warn': theme.WARNING}


def test_the_full_history_is_kept_and_clear_only_clears_the_screen(console):
    root, c = console
    for i in range(3000):
        log_event('test', f'line {i}')
    c.flush()
    assert len(c.lines) == 3000 and int(c.text.index('end-1c').split('.')[0]) > 3000
    db_fake.reset()
    did = db_fake.save_device(None, {'name': 'R1', 'ip': '10.0.0.1', 'type': 'router'})
    db_fake.add_log(did, 'Configuration', 'failed', 'x')
    c.clear()
    assert c.lines == [] and db_fake.count_logs() == 1        # nothing deleted


def test_auto_scroll_follows_unless_scrolled_up(console):
    root, c = console
    for i in range(200):
        log_event('test', f'line {i}')
    c.flush(); root.update()
    assert c.text.yview()[1] == 1.0                           # at the newest line
    c.text.yview_moveto(0)                                    # the user scrolls up
    log_event('test', 'new line')
    c.flush(); root.update()
    assert c.text.yview()[0] == 0.0                           # left where the user is
    c.text.yview_moveto(1.0)                                  # back at the bottom
    log_event('test', 'another')
    c.flush(); root.update()
    assert c.text.yview()[1] == 1.0


def test_history_since_app_start_is_given_to_a_new_console(monkeypatch):
    from gui_helpers import new_root
    from gui.components.console import OperationsConsole
    monkeypatch.setattr(event_log, '_history', [])
    monkeypatch.setattr(event_log, '_keeping', [False])
    event_log.keep_history()
    log_event('app', 'NetCommand started.')
    log_event('sign-in', 'Checking your password: SUCCESSFUL.', 'ok')
    root = new_root()
    try:
        c = OperationsConsole(root, db_fake)         # e.g. the workbench after sign-in
        c.flush()
        assert [m for _t, _s, m, _l in c.lines][:2] == ['NetCommand started.',
                                                         'Checking your password: SUCCESSFUL.']
    finally:
        root.destroy()


def test_error_dialogs_are_logged_once(console, monkeypatch):
    from tkinter import messagebox
    root, c = console
    shown = []
    monkeypatch.setattr(messagebox, 'showerror', lambda *a, **k: shown.append(a))
    event_log.install_dialog_logging()
    messagebox.showerror('Scan failed', 'No answer from 10.0.0.1.')
    log_event('scan', 'Scan FAILED. Timed out.', 'error')
    messagebox.showerror('Scan failed', 'Timed out.')               # already logged: once
    c.flush()
    texts = [m for _t, _s, m, _l in c.lines]
    # 'Scan failed' already says FAILED, so no label is added in front
    assert texts == ['Scan failed: No answer from 10.0.0.1.', 'Scan FAILED. Timed out.']
    assert [l for *_x, l in c.lines] == ['error', 'error']
    assert len(shown) == 2                                           # the dialogs still show


def test_switching_pages_and_console_tabs_logs_nothing(monkeypatch):
    from tkinter import messagebox
    from gui_helpers import new_root
    from gui.main_window import build_main_window
    for name in ('showinfo', 'showerror', 'showwarning'):
        monkeypatch.setattr(messagebox, name, lambda *a, **k: None)
    db_fake.reset()
    root = new_root()
    try:
        r = build_main_window(root, db_fake, demo_store=True)
        console = r['console']
        console.flush()
        before = len(console.lines)
        for key in ('scan', 'devices', 'topology', 'configure', 'logs', 'dashboard'):
            r['show_page'](key)
        for tab in (1, 2, 0):
            console.tabs.select(tab)
            root.update()
        console.flush()
        assert console.lines[before:] == []
        assert not any('Opened the' in m for _t, _s, m, _l in console.lines)
        r['show_page']('findings')          # real work on opening: still logged
        root.update()
        console.flush()
        assert any('Loading the stored review' in m for _t, _s, m, _l in console.lines[before:])
    finally:
        root.destroy()


def test_monitor_changes_are_labelled(console):
    root, c = console
    c.status_changed({'name': 'R1', 'ip': '10.0.0.1', 'status': 'up'}, 'down')
    c.status_changed({'name': 'R1', 'ip': '10.0.0.1', 'status': 'down'}, 'up')
    c.flush()
    assert [(m, l) for _t, _s, m, l in c.lines] == [
        ('R1 (10.0.0.1): status check FAILED, the device is DOWN (was up). Recorded.', 'error'),
        ('R1 (10.0.0.1): status check SUCCESSFUL, the device is UP (was down). Recorded.', 'ok')]
