"""Approving scanned devices: the whole workflow, through the real window.
db_fake stands in for the database (as the sample store, or acting as the real one)."""
import os, sys
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))
sys.path.insert(0, os.path.dirname(__file__))
import pytest

tk = pytest.importorskip('tkinter')
from tkinter import messagebox

import db_fake
from gui_helpers import new_root, pump


def make_app(monkeypatch, demo_store):
    root = new_root()
    root.geometry('1200x800')
    shown = []
    for name in ('showinfo', 'showerror', 'showwarning'):
        monkeypatch.setattr(messagebox, name, lambda t, m, _n=name, **k: shown.append((_n, t, m)))
    db_fake.reset()
    from gui.main_window import build_main_window
    refs = build_main_window(root, db_fake, demo_store=demo_store)
    root.update()
    return root, refs, shown


@pytest.fixture
def demo(monkeypatch):
    root, refs, shown = make_app(monkeypatch, demo_store=True)
    yield root, refs, shown
    root.destroy()


@pytest.fixture
def real(monkeypatch):
    root, refs, shown = make_app(monkeypatch, demo_store=False)
    yield root, refs, shown
    root.destroy()


def sample_scan(root, scan):
    scan.demo.set(1)
    scan.found = []
    scan.on_scan()
    assert pump(root, lambda: scan.found)


def select(scan, names):
    scan.tree.selection_set([str(i) for i, d in enumerate(scan.found) if d['name'] in names])


def console_lines(r):
    r['console'].flush()
    return r['console'].lines


# ---------------------------------------------------------------- sample mode: approval works
def test_approve_one_selected_device(demo):
    root, r, shown = demo
    scan = r['scan']
    sample_scan(root, scan)
    select(scan, {'CORE'})
    scan.approve()
    assert shown[-1] == ('showinfo', 'Approved', '1 device registered.')
    assert [d['name'] for d in db_fake.get_devices('', 'name', 1, 50)] == ['CORE']
    assert scan.last_result == {'ok': True, 'total': 1, 'added': 1, 'updated': 0, 'links': 0}
    assert any(s == 'scan' and 'Approved 1 device: 1 new' in m for _, s, m, _ in console_lines(r))


def test_approve_multiple_devices_saves_only_links_between_them(demo):
    root, r, shown = demo
    scan = r['scan']
    sample_scan(root, scan)
    select(scan, {'CORE', 'SW1', 'R1'})
    scan.approve()
    assert shown[-1] == ('showinfo', 'Approved', '3 devices registered.')
    assert db_fake.count_devices() == 3
    assert sorted(db_fake.get_links()) == [('CORE', 'Gi0/1', 'SW1', 'Gi0/1'),
                                           ('CORE', 'Gi0/3', 'R1', 'Gi0/0')]


def test_approve_with_nothing_selected_saves_nothing(demo):
    root, r, shown = demo
    scan = r['scan']
    sample_scan(root, scan)
    scan.tree.selection_set(())
    scan.approve()
    assert shown[-1][:2] == ('showinfo', 'Nothing selected')
    assert db_fake.count_devices() == 0 and scan.last_result is None


def test_approving_already_registered_devices_says_they_were_updated(demo):
    root, r, shown = demo
    scan = r['scan']
    sample_scan(root, scan)
    scan.approve()                                         # all 5 selected after a scan
    sample_scan(root, scan)
    scan.approve()
    assert shown[-1] == ('showinfo', 'Approved',
                         '5 devices registered (0 new, 5 already registered and updated).')
    assert db_fake.count_devices() == 5                     # no duplicates


def test_approved_devices_appear_in_devices_and_topology(demo):
    root, r, shown = demo
    scan = r['scan']
    sample_scan(root, scan)
    scan.approve()
    r['show_page']('devices')
    names = sorted(r['devices'].tree.item(i)['values'][0] for i in r['devices'].tree.get_children())
    assert names == ['AP-1', 'CORE', 'R1', 'SW1', 'SW2']
    r['show_page']('topology')
    topo = r['topology']
    assert 'Registered' in topo.source.cget('text') and 'SAMPLE' not in topo.source.cget('text')
    assert sorted(topo.shown_names) == ['AP-1', 'CORE', 'R1', 'SW1', 'SW2']


# ---------------------------------------------------------------- failures are never reported as success
def test_partial_failure_reports_exactly_what_was_saved(demo, monkeypatch):
    root, r, shown = demo
    scan = r['scan']
    sample_scan(root, scan)
    real_upsert, calls = db_fake.upsert_device, []

    def flaky(d):
        calls.append(d['name'])
        if len(calls) == 3:
            raise RuntimeError('connection lost')
        return real_upsert(d)
    monkeypatch.setattr(db_fake, 'upsert_device', flaky)
    scan.approve()
    kind, title, text = shown[-1]
    assert (kind, title) == ('showerror', 'Could not save')
    assert '2 of 5 devices were saved' in text and 'connection lost' in text
    assert not any(s[1] == 'Approved' for s in shown)
    assert db_fake.count_devices() == 2 and db_fake.get_links() == []
    assert scan.last_result == {'ok': False, 'total': 5, 'saved': 2, 'error': 'connection lost'}
    assert len(r['devices'].tree.get_children()) == 2        # the list was refreshed
    assert any(lvl == 'error' and '2 of 5' in m for _, _, m, lvl in console_lines(r))


def test_failure_before_anything_is_saved(demo, monkeypatch):
    root, r, shown = demo
    scan = r['scan']
    sample_scan(root, scan)
    monkeypatch.setattr(db_fake, 'upsert_device', lambda d: (_ for _ in ()).throw(RuntimeError('db down')))
    scan.approve()
    assert shown[-1][1] == 'Could not save' and 'Nothing was saved.' in shown[-1][2]
    assert db_fake.count_devices() == 0


# ---------------------------------------------------------------- real-database mode: blocked, but never silently
def test_blocked_sample_approval_is_visible_and_explained_on_click(real):
    root, r, shown = real
    scan = r['scan']
    r['show_page']('scan')
    sample_scan(root, scan)
    root.update()
    assert scan.approve_btn.instate(['disabled'])
    assert scan.block_note.winfo_ismapped()                 # the amber notice is on screen
    scan.approve_btn.event_generate('<Button-1>', x=5, y=5)  # a real click on the disabled button
    root.update()
    assert shown[-1][:2] == ('showinfo', 'Sample devices')
    assert db_fake.count_devices() == 0


def test_the_notice_disappears_for_a_normal_scan(real, monkeypatch):
    root, r, shown = real
    scan = r['scan']
    r['show_page']('scan')
    sample_scan(root, scan)
    from fakes import fake_login_factory, lab
    from discovery import crawler
    monkeypatch.setattr(crawler, '_login', fake_login_factory(lab()))
    scan.demo.set(0); scan.user.set('admin'); scan.pw.set('cisco123'); scan.seed.set('192.168.1.2')
    scan.found = []
    scan.on_scan()
    assert pump(root, lambda: scan.found)
    root.update()
    assert not scan.block_note.winfo_ismapped() and not scan.approve_btn.instate(['disabled'])
    scan.approve()
    # seed-only (the default): CORE plus its three CDP neighbours, which were not logged in to
    assert shown[-1] == ('showinfo', 'Approved', '4 devices registered.')
