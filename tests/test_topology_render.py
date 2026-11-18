"""The static topology map's temporary PNG (TopologyTab._render).

Before: every render, in every NetCommand process, used ONE fixed file
(%TEMP%\\netcommand_topology.png); two processes drawing at once could read each other's
half-written file ("unexpected end of file"). Now each render creates its own unique file
(tempfile.mkstemp), reads it, and removes it, also when drawing fails; failures always
name the exception type, even when its message is empty.

Every test points tempfile at its own temporary folder, so nothing in the real temp
folder is touched.
"""
import json
import os
import subprocess
import sys
import tempfile
from pathlib import Path

import pytest

tk = pytest.importorskip('tkinter')
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))
sys.path.insert(0, os.path.dirname(__file__))

import sample_data
from gui import topology_tab
from gui.topology_tab import RENDER_PREFIX, TopologyTab, map_error_text, remove_render_file

ROOT = Path(__file__).resolve().parents[1]


@pytest.fixture
def private_temp(tmp_path, monkeypatch):
    folder = tmp_path / 'temp'
    folder.mkdir()
    monkeypatch.setattr(tempfile, 'tempdir', str(folder))
    return folder


@pytest.fixture
def tab(private_temp, tmp_path, monkeypatch):
    from gui_helpers import new_root
    shown = []
    monkeypatch.setattr(topology_tab.messagebox, 'showerror',
                        lambda title, message, **k: shown.append((title, message)))
    root = new_root()
    t = TopologyTab(root, lambda: (sample_data.DEVICES, sample_data.LINKS,
                                   'SAMPLE DATA (test)'), layout_file=str(tmp_path / 'layout.json'))
    t.pack()
    t.shown = shown
    yield t
    root.destroy()


def leftovers(folder):
    return sorted(p.name for p in Path(folder).glob(RENDER_PREFIX + '*'))


def test_each_render_uses_its_own_file_and_removes_it(tab, private_temp, monkeypatch):
    used = []
    real = topology_tab.draw_map

    def recording(devices, links, path, **kw):
        used.append(path)
        assert os.path.exists(path)                       # created exclusively, before drawing
        return real(devices, links, path, **kw)
    monkeypatch.setattr(topology_tab, 'draw_map', recording)
    for _ in range(4):
        tab.refresh()
    assert len(used) == 4 and len(set(used)) == 4          # unique per render
    for path in used:
        name = Path(path).name
        assert Path(path).parent == private_temp and name.startswith(RENDER_PREFIX)
        assert name.endswith('.png') and name != 'netcommand_topology.png'
    assert leftovers(private_temp) == []                   # cleaned up after success
    assert tab.img is not None and tab.shown == []


def test_failed_drawing_removes_the_file_and_keeps_the_old_map(tab, private_temp, monkeypatch):
    tab.refresh()
    old_image = tab.img

    def broken(devices, links, path, **kw):
        Path(path).write_bytes(b'half a png')
        raise RuntimeError('')                             # an exception with NO message
    monkeypatch.setattr(topology_tab, 'draw_map', broken)
    tab.refresh()
    assert tab.shown == [('Map failed', 'RuntimeError (no further details were given)')]
    assert leftovers(private_temp) == [] and tab.img is old_image


def test_unreadable_image_is_reported_with_its_type_and_cleaned_up(tab, private_temp,
                                                                   monkeypatch):
    monkeypatch.setattr(topology_tab, 'draw_map',
                        lambda devices, links, path, **kw: Path(path).write_bytes(b'not a png'))
    tab.refresh()
    (title, message), = tab.shown
    assert title == 'Map failed' and message.startswith('TclError: ')
    assert leftovers(private_temp) == []


def test_cleanup_never_touches_another_renders_file(tab, private_temp):
    other = private_temp / (RENDER_PREFIX + 'other-process.png')
    other.write_bytes(b'being used by another render')
    tab.refresh()
    tab.refresh()
    assert other.exists() and other.read_bytes() == b'being used by another render'
    assert leftovers(private_temp) == [other.name]


@pytest.mark.parametrize('err, text', [
    (RuntimeError(''), 'RuntimeError (no further details were given)'),
    (MemoryError(), 'MemoryError (no further details were given)'),
    (OSError('   '), 'OSError (no further details were given)'),
    (ValueError('bad size'), 'ValueError: bad size'),
])
def test_error_text_is_never_blank(err, text):
    assert map_error_text(err) == text


def test_remove_render_file_is_safe_when_the_file_is_gone(private_temp):
    remove_render_file(str(private_temp / 'missing.png'))      # no error


RENDERER = r'''
import json, os, sys, tempfile
sys.path.insert(0, sys.argv[1])
tempfile.tempdir = sys.argv[2]
import tkinter as tk
import sample_data
from gui import topology_tab
errors = []
topology_tab.messagebox.showerror = lambda title, message, **k: errors.append(message)
root = tk.Tk()
root.withdraw()
tab = topology_tab.TopologyTab(root, lambda: (sample_data.DEVICES, sample_data.LINKS, 'SAMPLE'),
                               layout_file=os.path.join(sys.argv[2], 'layout-%d.json' % os.getpid()))
for _ in range(int(sys.argv[3])):
    tab.refresh()
root.destroy()
print(json.dumps({'errors': errors}))
'''


def test_concurrent_renders_in_separate_processes_do_not_collide(tmp_path):
    """Three processes draw the map at the same time into ONE shared temp folder (with the
    old fixed file name this produced 'unexpected end of file' errors)."""
    folder = tmp_path / 'shared-temp'
    folder.mkdir()
    env = {k: v for k, v in os.environ.items() if not k.startswith('BACKEND_')}
    procs = [subprocess.Popen([sys.executable, '-c', RENDERER, str(ROOT), str(folder), '25'],
                              cwd=ROOT, env=env, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                              text=True) for _ in range(3)]
    results = []
    for p in procs:
        out, err = p.communicate(timeout=300)
        if p.returncode != 0 and ('init.tcl' in err or 'tk.tcl' in err):
            pytest.skip('a test process could not start Tk (known Windows start-up issue)')
        assert p.returncode == 0, err
        results.append(json.loads(out.strip().splitlines()[-1]))
    assert all(r['errors'] == [] for r in results), results
    assert leftovers(folder) == []                               # every render cleaned up
