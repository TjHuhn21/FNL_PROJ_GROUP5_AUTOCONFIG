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


@pytest.fixture(autouse=True)
def private_layout_file(tmp_path, monkeypatch):
    path = tmp_path / 'topology_layout.json'
    monkeypatch.setenv('NETCOMMAND_LAYOUT_FILE', str(path))
    return path


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
