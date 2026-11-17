"""Settings for every test in this folder.

The saved topology layout normally lives in the user's own folder
(%APPDATA%\\NetCommand\\topology_layout.json). Tests must never read or change
that file, so each test gets its own empty layout file in a temporary folder.
(The project's root conftest.py is shared by the whole team and left unchanged.)
"""
import pytest


@pytest.fixture(autouse=True)
def private_layout_file(tmp_path, monkeypatch):
    path = tmp_path / 'topology_layout.json'
    monkeypatch.setenv('NETCOMMAND_LAYOUT_FILE', str(path))
    return path
