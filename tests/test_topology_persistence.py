"""Saved topology layouts: the JSON store, and Save / Load / Reset through the window.
Every test has its own layout file (see tests/conftest.py); the user's file is never used."""
import json
import math
import os, sys
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))
sys.path.insert(0, os.path.dirname(__file__))
import pytest

from topology.layout_store import LayoutStore, default_path


# ================================================================ the JSON store (no window)
def test_no_file_means_no_saved_layout(tmp_path):
    store = LayoutStore(str(tmp_path / 'none.json'))
    assert store.load('sample') == {} and store.problem is None and not store.has('sample')


def test_an_empty_file_means_no_saved_layout(tmp_path):
    p = tmp_path / 'layout.json'
    p.write_text('   \n')
    store = LayoutStore(str(p))
    assert store.load('sample') == {} and store.problem is None


@pytest.mark.parametrize('content', ['{not json', '[1, 2, 3]', '{"layouts": [1]}', '"text"'])
def test_a_damaged_file_never_crashes_and_is_reported(tmp_path, content):
    p = tmp_path / 'layout.json'
    p.write_text(content)
    store = LayoutStore(str(p))
    assert store.load('sample') == {} and store.problem


def test_entries_without_usable_numbers_are_skipped(tmp_path):
    p = tmp_path / 'layout.json'
    p.write_text(json.dumps({'version': 1, 'layouts': {'sample': {'devices': {
        'ip:1': {'x': 1.5, 'y': -2, 'name': 'A', 'ip': '1'},
        'ip:2': {'x': 'left', 'y': 3},
        'ip:3': {'x': True, 'y': 3},
        'ip:4': {'y': 3},
        'ip:5': 'not an entry'}}}}).replace('"left"', '"left"') + '\n')
    text = p.read_text().replace('{"y": 3}', '{"x": NaN, "y": 3}')   # JSON allows NaN
    p.write_text(text)
    assert LayoutStore(str(p)).load('sample') == {'ip:1': {'x': 1.5, 'y': -2.0, 'name': 'A', 'ip': '1'}}


def test_save_load_round_trip_and_scopes_are_kept_apart(tmp_path):
    store = LayoutStore(str(tmp_path / 'sub' / 'layout.json'))     # the folder is created
    store.save('database:netcommand@localhost', {'id:7': {'x': 1, 'y': 2, 'name': 'SW1', 'ip': '10.0.0.1'}})
    store.save('sample', {'ip:192.168.1.2': {'x': 3, 'y': 4, 'name': 'CORE', 'ip': '192.168.1.2'}})
    assert store.load('database:netcommand@localhost') == {'id:7': {'x': 1.0, 'y': 2.0, 'name': 'SW1', 'ip': '10.0.0.1'}}
    assert list(store.load('sample')) == ['ip:192.168.1.2']
    assert store.delete('sample') and not store.has('sample')
    assert store.has('database:netcommand@localhost')                # the other scope is untouched
    assert not store.delete('sample')                                 # nothing left to delete


def test_only_positions_names_and_ips_are_written(tmp_path):
    store = LayoutStore(str(tmp_path / 'layout.json'))
    store.save('sample', {'ip:1': {'x': 1, 'y': 2, 'name': 'A', 'ip': '1',
                                   'password': 'secret', 'username': 'admin'}})
    text = (tmp_path / 'layout.json').read_text()
    assert 'secret' not in text and 'password' not in text and 'admin' not in text
    assert set(json.loads(text)['layouts']['sample']['devices']['ip:1']) == {'x', 'y', 'name', 'ip'}


def test_saving_over_a_damaged_file_keeps_a_copy_of_it(tmp_path):
    p = tmp_path / 'layout.json'
    p.write_text('{damaged')
    store = LayoutStore(str(p))
    store.save('sample', {'ip:1': {'x': 1, 'y': 1, 'name': 'A', 'ip': '1'}})
    assert store.load('sample') and store.problem is None
    copies = [f for f in os.listdir(tmp_path) if f.startswith('layout.damaged-')]
    assert len(copies) == 1 and (tmp_path / copies[0]).read_text() == '{damaged'
    assert not any(f.endswith('.tmp') for f in os.listdir(tmp_path))


def test_an_unreadable_path_is_never_moved_aside(tmp_path):
    folder = tmp_path / 'layout.json'
    folder.mkdir()                                   # the path is a folder, not a file
    store = LayoutStore(str(folder))
    assert store.load('sample') == {} and store.problem and store.unreadable
    with pytest.raises(OSError):
        store.save('sample', {'ip:1': {'x': 1, 'y': 1, 'name': 'A', 'ip': '1'}})
    with pytest.raises(OSError):
        store.delete('sample')
    assert folder.is_dir() and os.listdir(tmp_path) == ['layout.json']    # untouched


def test_default_location(monkeypatch, tmp_path):
    monkeypatch.setenv('NETCOMMAND_LAYOUT_FILE', str(tmp_path / 'x.json'))
    assert default_path() == str(tmp_path / 'x.json')
    monkeypatch.delenv('NETCOMMAND_LAYOUT_FILE')
    monkeypatch.setenv('APPDATA', str(tmp_path))
    assert default_path() == os.path.join(str(tmp_path), 'NetCommand', 'topology_layout.json')


# ================================================================ through the window
tk = pytest.importorskip('tkinter')
from tkinter import messagebox

import db_fake
from discovery import crawler
from fakes import fake_login_factory, lab
from gui_helpers import new_root, pump

BUTTON1 = 0x0100


@pytest.fixture
def dialogs(monkeypatch):
    shown, answers = [], {'askyesno': True}
    for name in ('showinfo', 'showerror', 'showwarning'):
        monkeypatch.setattr(messagebox, name, lambda t, m, _n=name, **k: shown.append((_n, t, m)))
    monkeypatch.setattr(messagebox, 'askyesno',
                        lambda t, m, **k: shown.append(('askyesno', t, m)) or answers['askyesno'])
    return shown, answers


def register_lab(monkeypatch):
    monkeypatch.setattr(crawler, '_login', fake_login_factory(lab()))
    devices, links = crawler.discover('admin', 'cisco123', '192.168.1.2', login_neighbours=True)
    for d in devices:
        db_fake.upsert_device(d)
    db_fake.save_links(links)


def open_app(demo_store=False):
    """Open the main window on the Topology page with the store's CURRENT contents
    (the store is not reset, so this is 'reopening' the application)."""
    root = new_root()
    root.geometry('1200x760')
    from gui.main_window import build_main_window
    refs = build_main_window(root, db_fake, demo_store=demo_store)
    refs['show_page']('topology')
    tc = refs['topology'].interactive
    root.update()
    assert pump(root, lambda: tc.canvas.winfo_width() > 100)
    settle(root, tc)
    refs['topology'].refresh()                      # as when the page is opened at full size
    root.update()
    return root, refs, tc


def settle(root, tc):
    """Wait until the new window has stopped resizing (the automatic layout follows
    the canvas size, so positions are only comparable at one settled size)."""
    import time
    last, stable_since = None, time.time()
    while time.time() - stable_since < 0.6:
        root.update()
        size = (tc.canvas.winfo_width(), tc.canvas.winfo_height())
        if size != last or tc._pending:
            last, stable_since = size, time.time()
        time.sleep(0.02)


def is_automatic(tc):
    """Are the devices where the automatic layout puts them at the current size?"""
    now = tc.positions()
    keep = (dict((n, dict(v)) for n, v in tc.nodes.items()), [dict(e) for e in tc.edges],
            tc.zoom, tc.off_x, tc.off_y, tc.moved, tc.fitted)
    tc.reset_layout()
    auto = tc.positions()
    tc.nodes, tc.edges, tc.zoom, tc.off_x, tc.off_y, tc.moved, tc.fitted = keep   # put back
    tc.render()
    return all(math.isclose(now[n][0], auto[n][0], abs_tol=1e-6) and
               math.isclose(now[n][1], auto[n][1], abs_tol=1e-6) for n in auto)


def drag(root, tc, name, dx, dy):
    x, y = tc.screen_center(name)
    c = tc.canvas
    c.event_generate('<ButtonPress-1>', x=int(x), y=int(y))
    for i in range(1, 7):
        c.event_generate('<Motion>', x=int(x + dx * i / 6), y=int(y + dy * i / 6), state=BUTTON1)
    c.event_generate('<ButtonRelease-1>', x=int(x + dx), y=int(y + dy), state=BUTTON1)
    root.update()


def saved_file(private_layout_file):
    return json.loads(private_layout_file.read_text())


def boxes_overlap(a, b):
    return abs(a['x'] - b['x']) < (a['w'] + b['w']) / 2 and abs(a['y'] - b['y']) < (a['h'] + b['h']) / 2


@pytest.fixture
def lab_store(monkeypatch):
    db_fake.reset()
    register_lab(monkeypatch)


def test_save_layout_writes_every_device_by_its_database_id(lab_store, dialogs, private_layout_file):
    shown, _ = dialogs
    root, r, tc = open_app()
    try:
        topo = r['topology']
        assert topo.layout_state.cget('text') == 'Layout: automatic'
        drag(root, tc, 'SW3', 140, -20)
        assert topo.layout_state.cget('text') == 'Layout: changed, not saved'
        topo.save_button.invoke()
        assert shown[-1][:2] == ('showinfo', 'Save layout') and '5 devices' in shown[-1][2]
        devices = saved_file(private_layout_file)['layouts'][topo.layout_scope]['devices']
        ids = {f"id:{db_fake.get_device_by_name(n)['id']}" for n in tc.nodes}
        assert set(devices) == ids                                     # stable database ids
        sw3 = devices[f"id:{db_fake.get_device_by_name('SW3')['id']}"]
        assert sw3['name'] == 'SW3' and sw3['ip'] == '192.168.1.5'
        ux, uy = tc.positions()['SW3']
        assert math.isclose(sw3['x'], ux, abs_tol=1e-4) and math.isclose(sw3['y'], uy, abs_tol=1e-4)
        assert topo.layout_state.cget('text') == 'Layout: saved (5 devices)'
        r['console'].flush()
        assert any(s == 'topology' and 'Saved the layout of 5' in m for _, s, m, _ in r['console'].lines)
    finally:
        root.destroy()


def test_the_saved_layout_comes_back_after_reopening(lab_store, dialogs):
    root, r, tc = open_app()
    drag(root, tc, 'SW3', 140, -20)
    drag(root, tc, 'R1', -160, 30)
    r['topology'].save_layout()
    saved = tc.positions()
    root.destroy()

    root, r, tc = open_app()                                          # "reopen the application"
    try:
        for name, (x, y) in saved.items():
            assert math.isclose(tc.positions()[name][0], x, abs_tol=1e-3), name
            assert math.isclose(tc.positions()[name][1], y, abs_tol=1e-3), name
        assert r['topology'].layout_state.cget('text') == 'Layout: saved (5 devices)'
        r['console'].flush()
        assert any('Restored the saved layout for 5' in m for _, _, m, _ in r['console'].lines)
        e = tc.edges[next(i for i, e in enumerate(tc.edges) if {e['a'], e['b']} == {'SW2', 'SW3'})]
        assert len(e['points']) == 2                                   # links follow restored devices
    finally:
        root.destroy()


def test_a_new_device_is_placed_automatically_and_a_removed_one_is_ignored(lab_store, dialogs):
    root, r, tc = open_app()
    drag(root, tc, 'SW1', -80, 60)
    r['topology'].save_layout()
    saved = tc.positions()
    root.destroy()

    new_id = db_fake.upsert_device({'name': 'SW9', 'ip': '192.168.1.9', 'type': 'switch',
                                    'managed': True})
    db_fake.save_links([('SW1', 'Gi0/5', 'SW9', 'Gi0/1')])
    db_fake.delete_device(db_fake.get_device_by_name('SW3')['id'])    # soft delete: removed
    root, r, tc = open_app()
    try:
        assert set(tc.nodes) == {'CORE', 'SW1', 'SW2', 'R1', 'SW9'}    # SW3 gone, SW9 new
        for name in ('CORE', 'SW1', 'SW2', 'R1'):
            assert math.isclose(tc.positions()[name][0], saved[name][0], abs_tol=1e-3), name
        new = tc.nodes['SW9']
        assert not any(boxes_overlap(new, tc.nodes[n]) for n in tc.nodes if n != 'SW9')
        assert r['topology'].layout_state.cget('text') == \
            'Layout: saved (4 devices, 1 new placed automatically)'
    finally:
        root.destroy()


def test_a_damaged_layout_file_opens_the_automatic_layout(lab_store, dialogs, private_layout_file):
    private_layout_file.write_text('{"layouts": {damaged')
    root, r, tc = open_app()
    try:
        assert is_automatic(tc)
        assert r['topology'].layout_state.cget('text') == 'Layout: automatic'
        r['console'].flush()
        assert any(lvl == 'warn' and 'could not be read' in m for _, _, m, lvl in r['console'].lines)
        assert r['topology'].save_layout()                             # saving still works
        assert any(f.startswith('topology_layout.damaged-') for f in os.listdir(private_layout_file.parent))
    finally:
        root.destroy()


def test_reset_asks_first_and_cancel_changes_nothing(lab_store, dialogs, private_layout_file):
    shown, answers = dialogs
    root, r, tc = open_app()
    try:
        drag(root, tc, 'SW3', 140, -20)
        r['topology'].save_layout()
        before = tc.positions()
        answers['askyesno'] = False
        tc.buttons['reset'].invoke()
        assert shown[-1][0] == 'askyesno' and 'saved layout will be deleted' in shown[-1][2]
        assert tc.positions() == before
        assert saved_file(private_layout_file)['layouts'][r['topology'].layout_scope]['devices']
    finally:
        root.destroy()


def test_confirmed_reset_restores_the_automatic_layout_and_forgets_the_saved_one(
        lab_store, dialogs, private_layout_file):
    shown, answers = dialogs
    root, r, tc = open_app()
    drag(root, tc, 'SW3', 140, -20)
    r['topology'].save_layout()
    assert not is_automatic(tc)
    answers['askyesno'] = True
    tc.buttons['reset'].invoke()
    try:
        assert is_automatic(tc) and not tc.moved
        assert r['topology'].layout_scope not in saved_file(private_layout_file)['layouts']
        assert r['topology'].layout_state.cget('text') == 'Layout: automatic'
    finally:
        root.destroy()
    root, r, tc = open_app()                                          # reopened: automatic
    try:
        assert is_automatic(tc)
        assert r['topology'].layout_state.cget('text') == 'Layout: automatic'
    finally:
        root.destroy()


def test_reset_without_a_saved_layout_does_not_ask(lab_store, dialogs):
    shown, _ = dialogs
    root, r, tc = open_app()
    try:
        drag(root, tc, 'CORE', 50, 50)
        assert not is_automatic(tc)
        tc.buttons['reset'].invoke()
        assert not any(s[0] == 'askyesno' for s in shown)
        assert is_automatic(tc)
    finally:
        root.destroy()


def test_a_failed_save_says_so(lab_store, dialogs, tmp_path, monkeypatch):
    shown, _ = dialogs
    blocked = tmp_path / 'is_a_folder'
    blocked.mkdir()
    monkeypatch.setenv('NETCOMMAND_LAYOUT_FILE', str(blocked))         # cannot write a file here
    root, r, tc = open_app()
    try:
        drag(root, tc, 'SW3', 100, 0)
        assert r['topology'].save_layout() is False
        assert shown[-1][:2] == ('showerror', 'Save layout')
        assert r['topology'].layout_state.cget('text') == 'Layout: changed, not saved'
        assert blocked.is_dir()                                        # left exactly where it was
    finally:
        root.destroy()


def test_sample_data_has_its_own_layout_keyed_by_ip(dialogs, private_layout_file):
    db_fake.reset()
    root, r, tc = open_app(demo_store=True)
    try:
        topo = r['topology']
        assert topo.layout_scope == 'sample'
        topo.save_layout()
        devices = saved_file(private_layout_file)['layouts']['sample']['devices']
        assert set(devices) == {f"ip:{tc.by_name[n]['ip']}" for n in tc.nodes}
        assert all(not k.startswith('id:') for k in devices)
    finally:
        root.destroy()


def test_refreshing_the_same_network_keeps_unsaved_moves(lab_store, dialogs):
    root, r, tc = open_app()
    try:
        drag(root, tc, 'SW2', 60, 40)
        moved = tc.positions()['SW2']
        r['topology'].refresh()
        assert tc.positions()['SW2'] == moved
        assert r['topology'].layout_state.cget('text') == 'Layout: changed, not saved'
    finally:
        root.destroy()
