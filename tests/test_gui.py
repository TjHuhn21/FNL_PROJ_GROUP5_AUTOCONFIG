"""Drives the real windows end to end (scan, approve, map, review, configure,
logs) with message boxes and SSH stubbed out. Skipped when there is no display
(on Linux run it with: xvfb-run python -m pytest tests/test_gui.py)."""
import os, sys, time
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))
import pytest

tk = pytest.importorskip('tkinter')
from tkinter import messagebox, simpledialog

import db_fake


def pump(root, cond, timeout=10):
    end = time.time() + timeout
    while time.time() < end:
        root.update()
        if cond():
            return True
        time.sleep(0.02)
    return False


@pytest.fixture
def app(monkeypatch):
    try:
        root = tk.Tk()
    except tk.TclError:
        pytest.skip('no display available')
    shown = []
    for name in ('showinfo', 'showerror', 'showwarning'):
        monkeypatch.setattr(messagebox, name, lambda t, m, _n=name, **k: shown.append((_n, t, m)))
    monkeypatch.setattr(messagebox, 'askyesno', lambda *a, **k: True)
    monkeypatch.setattr(simpledialog, 'askstring', lambda *a, **k: 'admin')
    db_fake.reset()
    from gui.main_window import build_main_window
    refs = build_main_window(root, db_fake, demo_store=True)
    refs['shown'] = shown
    yield root, refs
    root.destroy()


def test_full_path(app, tmp_path, monkeypatch):
    root, r = app
    devices, scan, topo, findings, conf, logs = (r[k] for k in
        ('devices', 'scan', 'topology', 'findings', 'configure', 'logs'))

    # empty state is friendly
    assert 'No devices yet' in devices.empty.cget('text')

    # review on sample data (nothing registered yet) shows the planted mistakes
    findings.run()
    assert pump(root, lambda: findings.findings)
    rules = {f['rule'] for f in findings.findings}
    assert {'telnet_enabled', 'no_password_encryption', 'single_point_of_failure'} <= rules
    assert 'SAMPLE' in findings.note.cget('text')

    # scan (demo) then approve
    scan.on_scan()
    assert pump(root, lambda: scan.found)
    assert len(scan.found) == 5 and len(scan.tree.get_children()) == 5
    assert scan.found_is_sample and all(d['sample'] for d in scan.found)     # B3 marker
    assert not scan.approve_btn.instate(['disabled'])     # sample mode: approving is allowed
    scan.approve()
    devices.refresh()
    assert len(devices.tree.get_children()) == 5
    assert db_fake.get_links()
    assert all('sample' not in d for d in db_fake.get_devices('', 'name', 1, 50))

    # search, sort and paging controls work on real data
    devices.search.set('SW'); devices.go_first()
    assert len(devices.tree.get_children()) == 2
    devices.search.set(''); devices.sort('ip')
    first = devices.tree.item(devices.tree.get_children()[0])['values'][1]
    assert first == '192.168.1.1'

    # map draws from registered devices and links
    topo.refresh()
    assert topo.img is not None and 'Registered' in topo.source.cget('text')

    # send a finding to Configure, then build VLANs and apply
    findings.run(); pump(root, lambda: not findings.busy)
    telnet = next(i for i, f in enumerate(findings.findings) if f['rule'] == 'telnet_enabled')
    findings.tree.selection_set(str(telnet)); findings.send_selected()
    assert conf.commands_from_preview() == ['line vty 0 4', 'transport input ssh']

    calls = []
    conf.apply_fn = lambda creds, cmds, checks: (calls.append((creds, cmds, checks)),
                                                 (True, 'Applied and verified. Backup: x'))[1]
    conf.device_box.current(0)
    for vid, name in [(10, 'SALES'), (20, 'HR'), (30, 'IT')]:
        conf.vid.set(str(vid)); conf.vname.set(name); conf.add_vlan()
    conf.make_preview()
    assert conf.commands_from_preview()[:2] == ['vlan 10', 'name SALES']
    conf.apply()
    assert pump(root, lambda: not conf.busy and calls)
    assert calls[0][2] == [('show vlan brief', 'SALES'), ('show vlan brief', 'HR'),
                           ('show vlan brief', 'IT')]
    logs.refresh()
    assert len(logs.tree.get_children()) == 1


def test_bad_input_shows_messages_not_crashes(app):
    root, r = app
    conf, shown = r['configure'], r['shown']
    conf.vid.set('abc'); conf.add_vlan()
    conf.vid.set('1'); conf.vname.set('X'); conf.add_vlan()
    conf.vid.set('10'); conf.vname.set('bad name'); conf.add_vlan()
    assert [s[0] for s in shown].count('showerror') == 3 and conf.vlans == []
    r['scan'].demo.set(0); r['scan'].on_scan()            # no login typed
    assert shown[-1][1] == 'Login needed'
    r['scan'].user.set('admin'); r['scan'].pw.set('x'); r['scan'].seed.set('999.1.1.1')
    r['scan'].on_scan()
    assert 'IPv4' in shown[-1][2]


def test_failed_scan_reports_clear_message(app, monkeypatch):
    root, r = app
    import services
    def boom(*a): raise RuntimeError('Could not log in to the starting device')
    r['scan'].discover = lambda u, p, s, d: boom()
    r['scan'].demo.set(0); r['scan'].user.set('a'); r['scan'].pw.set('b')
    r['scan'].seed.set('192.168.1.2'); r['scan'].on_scan()
    assert pump(root, lambda: not r['scan'].scanning)
    assert r['shown'][-1][0] == 'showerror' and 'starting device' in r['shown'][-1][2]


def test_add_edit_duplicate_and_delete(app):
    root, r = app
    from gui.devices_tab import DeviceDialog
    dt, shown = r['devices'], r['shown']
    d = DeviceDialog(dt, db_fake, None, dt._saved)
    d.vars['name'].set('SW9'); d.vars['ip'].set('10.0.0.9'); d.save()
    assert db_fake.count_devices() == 1
    d = DeviceDialog(dt, db_fake, None, dt._saved)
    d.vars['name'].set('DUP'); d.vars['ip'].set('10.0.0.9'); d.save()
    assert 'already exists' in shown[-1][2] and db_fake.count_devices() == 1
    d.destroy()
    d = DeviceDialog(dt, db_fake, None, dt._saved)
    d.vars['name'].set('X'); d.vars['ip'].set('not-an-ip'); d.save()
    assert 'IPv4' in shown[-1][2]
    d.destroy()
    dt.tree.selection_set(dt.tree.get_children()[0]); dt.delete()
    assert db_fake.count_devices() == 0 and 'No devices yet' in dt.empty.cget('text')


# ---------------------------------------------------------------- B3: sample devices vs the real database
@pytest.fixture
def real_app(monkeypatch):
    """The window in REAL database mode (demo_store=False). db_fake stands in for MySQL
    so no server is needed: the Scan tab treats it exactly as the real database."""
    try:
        root = tk.Tk()
    except tk.TclError:
        pytest.skip('no display available')
    shown = []
    for name in ('showinfo', 'showerror', 'showwarning'):
        monkeypatch.setattr(messagebox, name, lambda t, m, _n=name, **k: shown.append((_n, t, m)))
    monkeypatch.setattr(messagebox, 'askyesno', lambda *a, **k: True)
    db_fake.reset()
    from gui.main_window import build_main_window
    refs = build_main_window(root, db_fake, demo_store=False)
    refs['shown'] = shown
    yield root, refs
    root.destroy()


def demo_scan(root, scan):
    scan.demo.set(1)
    scan.found = []
    scan.on_scan()
    assert pump(root, lambda: scan.found)


def real_scan(root, scan, monkeypatch):
    """A real discovery run (services.run_discovery -> crawler.discover) on the fake lab."""
    sys.path.insert(0, os.path.dirname(__file__))
    from fakes import fake_login_factory, lab
    from discovery import crawler
    monkeypatch.setattr(crawler, '_login', fake_login_factory(lab()))
    scan.demo.set(0); scan.user.set('admin'); scan.pw.set('cisco123'); scan.seed.set('192.168.1.2')
    scan.found = []
    scan.on_scan()
    assert pump(root, lambda: scan.found)


def test_real_mode_demo_scan_cannot_be_approved(real_app):
    root, r = real_app
    scan, shown = r['scan'], r['shown']
    assert scan.demo.get() == 0                                   # off by default with a real DB
    demo_scan(root, scan)
    assert scan.found_is_sample and len(scan.found) == 5
    assert {scan.tree.item(i)['values'][4] for i in scan.tree.get_children()} == {'SAMPLE'}
    assert scan.approve_btn.instate(['disabled']) and 'sample mode' in scan.status.cget('text')
    scan.approve_btn.invoke()                                     # disabled button: does nothing
    scan.approve()                                                # called directly: refused
    assert shown[-1][:2] == ('showerror', 'Sample devices')
    assert db_fake.count_devices() == 0 and db_fake.get_links() == []


def test_real_mode_unticking_demo_after_the_scan_does_not_unlock_approval(real_app):
    root, r = real_app
    scan = r['scan']
    demo_scan(root, scan)
    scan.demo.set(0)                                              # untick AFTER the demo scan
    scan.approve()
    assert r['shown'][-1][1] == 'Sample devices'
    assert db_fake.count_devices() == 0 and db_fake.get_links() == []


def test_real_mode_real_discovery_is_still_approved(real_app, monkeypatch):
    root, r = real_app
    scan = r['scan']
    real_scan(root, scan, monkeypatch)
    assert not scan.found_is_sample and not any('sample' in d for d in scan.found)
    assert not scan.approve_btn.instate(['disabled'])
    scan.approve()
    assert r['shown'][-1] == ('showinfo', 'Approved', '5 devices registered.')
    assert db_fake.count_devices() == 5 and len(db_fake.get_links()) == 4
    core, sw3 = db_fake.get_device_by_ip('192.168.1.2'), db_fake.get_device_by_ip('192.168.1.5')
    assert db_fake.get_credentials(core['id']) == ('admin', 'cisco123')     # login saved
    assert db_fake.get_credentials(sw3['id']) == ('', '')                     # unmanaged: none
    assert all('sample' not in d for d in db_fake.get_devices('', 'name', 1, 50))
    r['configure'].refresh_devices()                              # and it can be configured
    assert 'CORE' in {d['name'] for d in r['configure'].devices}


def test_real_mode_demo_then_real_scan_enables_approval_again(real_app, monkeypatch):
    root, r = real_app
    scan = r['scan']
    demo_scan(root, scan)
    assert scan.approve_btn.instate(['disabled'])
    real_scan(root, scan, monkeypatch)
    assert not scan.found_is_sample and not scan.approve_btn.instate(['disabled'])
    scan.approve()
    assert db_fake.count_devices() == 5


def test_db_refuses_sample_devices_even_if_the_gui_check_is_bypassed(real_app, monkeypatch):
    """Defense in depth: the REAL db module, with SQL replaced by a recorder.
    Even if the Scan tab's own check were skipped, no SQL is ever sent."""
    import db, services
    from gui.scan_tab import ScanTab
    root, r = real_app
    sent = []
    monkeypatch.setattr(db, '_run', lambda *a, **k: sent.append(a))
    scan = ScanTab(root, db, services.run_discovery, sample_store=False)
    demo_scan(root, scan)
    scan.found_is_sample = False                                  # simulate a GUI bug
    scan.approve()
    assert r['shown'][-1][:2] == ('showerror', 'Could not save')
    assert 'Sample (demo) devices' in r['shown'][-1][2]
    assert sent == []                                             # nothing reached the database
