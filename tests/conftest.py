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
