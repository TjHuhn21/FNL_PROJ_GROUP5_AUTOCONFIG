"""Settings for every test in this folder.

The saved topology layout normally lives in the user's own folder
(%APPDATA%\\NetCommand\\topology_layout.json). Tests must never read or change
that file, so each test gets its own empty layout file in a temporary folder.
(The project's root conftest.py is shared by the whole team and left unchanged.)

It also imports mysql_guard FIRST, so the guard records DB_NAME exactly as the shell
set it, before any test module imports db.py (which fills missing settings from .env).
"""
import os
import sys

sys.path.insert(0, os.path.dirname(__file__))
import mysql_guard  # noqa: E402,F401  (records the shell's DB_NAME now: see its docstring)

import pytest  # noqa: E402


class SyntheticBackupKey:
    """A random, in-memory backup key standing in for the user's DPAPI keyring, so no
    test ever reads %LOCALAPPDATA%\\NetCommand or calls Windows DPAPI through Apply."""

    def __init__(self, key_id='b1'):
        self.key_id, self.key = key_id, os.urandom(32)

    def key_for(self, key_id):
        import backup_crypto
        if key_id != self.key_id:
            raise backup_crypto.UnknownKey(f'Backup key {key_id} is not in this keyring.')
        return self.key

    def active_key(self):
        from config.connect import BackupKey
        return BackupKey(self.key_id, self.key, self.key_for)

    def decrypt(self, path):
        """(configuration bytes, header) of an .ncbak written with this key."""
        import backup_crypto
        with open(path, 'rb') as f:
            return backup_crypto.decrypt_backup(f.read(), self.key_for)


@pytest.fixture(autouse=True)
def synthetic_backup_key(monkeypatch):
    """Apply (config.connect) encrypts backups with this synthetic key in every test."""
    try:
        from config import connect
    except Exception:                       # tests that cannot import it do not need it
        return None
    source = SyntheticBackupKey()
    monkeypatch.setattr(connect, 'KEY_SOURCE', source)
    return source


@pytest.fixture(autouse=True)
def fresh_console_history(monkeypatch):
    """main.main() turns on the app-wide Console history (gui.event_log.keep_history);
    each test starts without it, so no Console replays another test's lines."""
    try:
        from gui import event_log
    except Exception:                       # tests that cannot import it do not need it
        return
    monkeypatch.setattr(event_log, '_history', [])
    monkeypatch.setattr(event_log, '_keeping', [False])
    # nobody signed in, and nothing saved, unless the test says so
    monkeypatch.setattr(event_log, '_user', [None])
    monkeypatch.setattr(event_log, '_store', [None])
    monkeypatch.setattr(event_log, '_pending', [])
    monkeypatch.setattr(event_log, '_saving', {'off': False, 'thread': None})


@pytest.fixture(autouse=True)
def private_layout_file(tmp_path, monkeypatch):
    path = tmp_path / 'topology_layout.json'
    monkeypatch.setenv('NETCOMMAND_LAYOUT_FILE', str(path))
    # the remembered window size and place (gui/window_state.py): never the user's own
    monkeypatch.setenv('NETCOMMAND_WINDOW_FILE', str(tmp_path / 'window.json'))
    monkeypatch.delenv('NETCOMMAND_UI_TEXT_SIZE', raising=False)
    try:                                    # layout settings kept between starts: none
        from gui import window_state
        monkeypatch.setattr(window_state, '_settings', {})
    except Exception:
        pass
    return path


@pytest.fixture(autouse=True)
def no_real_serial_ports(monkeypatch):
    """No test may see or open this computer's real COM ports (the Initial Setup page and
    console tests). The operating system's port list is empty, and opening a port fails
    the test. Tests that need ports install their own fakes on top of this."""
    try:
        import serial
        import serial.tools.list_ports as list_ports
    except Exception:                       # no pyserial: nothing could open a port
        return
    real = serial.Serial

    class NoRealPort(real):
        def __init__(self, *args, **kwargs):
            raise AssertionError('a test tried to open a real serial port')
    monkeypatch.setattr(serial, 'Serial', NoRealPort)
    monkeypatch.setattr(list_ports, 'comports', lambda *a, **k: [])


@pytest.fixture(autouse=True)
def collect_garbage_on_the_main_thread():
    """Window tests leave Tk objects (variables, fonts, images) in reference cycles. If
    Python's garbage collector later frees them from another thread (an SSH or monitor
    worker of a following test), Tcl aborts the whole test run. Collect them here, on
    the main thread, after every test."""
    yield
    import gc
    gc.collect()


@pytest.fixture(autouse=True)
def answered_confirmations(monkeypatch):
    """The shared confirmation dialog (gui/components/dialogs.confirm) never opens in a
    test. When the test replaced messagebox.askyesno (the older way tests answer
    questions), that answers; otherwise the answer is yes, as it was before the question
    existed. Every question is recorded in dialogs.ASKED (title, message, options).
    The welcome tour is not offered by itself (tests of the tour start it), and nothing
    is 'still running' from another test."""
    monkeypatch.setenv('NETCOMMAND_TOUR', 'off')
    try:
        from tkinter import messagebox
        from gui import activity
        from gui.components import dialogs
    except Exception:                       # no tkinter here: nothing can ask
        yield None
        return
    original = messagebox.askyesno
    asked = []

    def answer(title, message, **options):
        asked.append((title, message, options))
        if options.get('kind') != 'confirm':
            return None                     # a notice: nothing to answer
        if messagebox.askyesno is not original:
            return bool(messagebox.askyesno(title, message))
        return True
    monkeypatch.setattr(dialogs, '_runner', answer)
    monkeypatch.setattr(dialogs, 'ASKED', asked, raising=False)
    activity.reset()
    yield asked
    activity.reset()


@pytest.fixture(autouse=True)
def no_unanswered_login_dialog(monkeypatch):
    """The SSH login dialog is modal: opened in a test without an answer it would wait
    forever. Tests that reach it must replace login_dialog.ask_device_login themselves;
    any other test that opens it fails at once instead of hanging."""
    try:
        from gui.components import login_dialog
    except Exception:                       # no tkinter here: nothing can open it
        return

    def unanswered(*args, **kwargs):
        raise AssertionError('the SSH login dialog was opened, but this test does not answer '
                             'it (replace login_dialog.ask_device_login)')
    monkeypatch.setattr(login_dialog, 'ask_device_login', unanswered)
