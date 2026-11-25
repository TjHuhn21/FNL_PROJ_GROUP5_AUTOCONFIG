"""The Configure page with several devices: the device picker, compatibility in
the preview, per-device sections, sequential Apply with individual results, the
summary, and the collapsible inspector. Fake apply functions only: no device,
no database."""
import threading
import time

import pytest

tk = pytest.importorskip('tkinter')
from tkinter import messagebox, simpledialog  # noqa: E402

from gui_helpers import new_root, pump, wide_window  # noqa: E402

PASSWORD = 'Top$ecret99'
DEVICES = [
    {'id': 1, 'name': 'CORE', 'ip': '10.0.0.2', 'type': 'switch', 'managed': 1},
    {'id': 2, 'name': 'R1', 'ip': '10.0.0.1', 'type': 'router', 'managed': 1},
    {'id': 3, 'name': 'R2', 'ip': '10.0.0.5', 'type': 'router', 'managed': 1},
    {'id': 4, 'name': 'SW1', 'ip': '10.0.0.3', 'type': 'switch', 'managed': 1},
    {'id': 5, 'name': 'SW2', 'ip': '10.0.0.4', 'type': 'switch', 'managed': 1},
    {'id': 6, 'name': 'AP-1', 'ip': '10.0.0.9', 'type': 'unknown', 'managed': 1},
    {'id': 7, 'name': 'PHONE', 'ip': '10.0.0.8', 'type': 'switch', 'managed': 0},
]


class Store:
    def __init__(self, logins=None):
        self.logs = []
        self.logins = logins if logins is not None else {i: ('admin', PASSWORD) for i in range(1, 8)}

    def get_devices(self, *a):
        return sorted(DEVICES, key=lambda d: d['name'])

    def get_credentials(self, device_id):
        return self.logins.get(device_id, (None, None))

    def add_log(self, device_id, action, status, message):
        self.logs.append((device_id, action, status, message))


@pytest.fixture
def env(monkeypatch):
    root = new_root()
    root.geometry('1200x700')
    from gui import theme
    theme.apply(root)
    shown, asked, confirms = [], [], []
    for name in ('showinfo', 'showerror', 'showwarning'):
        monkeypatch.setattr(messagebox, name, lambda t, m, _n=name, **k: shown.append((_n, t, m)))
    # yes to every question, except the offer to retry a refused login (the fakes refuse it again)
    monkeypatch.setattr(messagebox, 'askyesno',
                        lambda t, m, **k: confirms.append((t, m)) or t != 'SSH login refused')
    monkeypatch.setattr('gui.components.login_dialog.ask_device_login',
                        lambda parent, devices, reason='missing', replaces=(): asked.append(
                            ([d['name'] for d in devices], reason)) or
                        {'username': 'admin', 'password': 'pw', 'save': False})
    from gui.configure_tab import ConfigureTab
    store, summary = Store(), []
    conf = ConfigureTab(root, store, log=lambda *a, **k: summary.append(a))
    conf.pack(fill='both', expand=True)
    root.update()
    yield {'root': root, 'conf': conf, 'store': store, 'shown': shown, 'asked': asked,
           'confirms': confirms, 'summary': summary}
    root.destroy()


def ids(conf, *names):
    return [d['id'] for d in conf.devices if d['name'] in names]


def tick(conf, *names):
    conf.picker.set_checked(ids(conf, *names))


def vlan_form(conf):
    conf.vid.set('10'); conf.vname.set('STAFF'); conf.add_vlan()
    conf.port.set('Fa0/1-5'); conf.port_vlan.set('10'); conf.add_port()


def fake_apply(calls, fail=(), delay=0.0):
    def apply(creds, commands, checks, log=None):
        calls.append({'host': creds['host'], 'commands': commands, 'checks': checks,
                      'thread': threading.current_thread().name, 'creds': creds})
        log('section', 'CONNECT')
        log('command', f"(config)# {commands[0]}")
        time.sleep(delay)
        if creds['host'] in fail:
            log('error', 'The device refused the login (wrong username or password).')
            return False, 'Wrong username or password.'
        return True, f"Applied and verified. Backup: backups/{creds['host']}_x.txt"
    return apply


# ---------------------------------------------------------------- picker
def test_only_managed_devices_are_offered_and_the_first_is_preselected(env):
    conf = env['conf']
    assert [d['name'] for d in conf.devices] == ['AP-1', 'CORE', 'R1', 'R2', 'SW1', 'SW2']
    assert [d['name'] for d in conf.selected_devices()] == ['AP-1']       # one device, as before
    rows = [conf.picker.tree.item(i)['values'] for i in conf.picker.tree.get_children()]
    assert rows[1] == ['☐', 'CORE', '10.0.0.2', 'switch']


def test_select_all_clear_filter_and_count(env):
    conf = env['conf']
    conf.picker.clear_button.invoke()
    assert conf.selected_devices() == [] and conf.picker.count.cget('text').startswith('0 of 6')
    conf.picker.filter.set('Switches'); conf.picker.show()
    assert len(conf.picker.tree.get_children()) == 3            # CORE, SW1, SW2
    conf.picker.all_button.invoke()                              # only what the filter shows
    assert [d['name'] for d in conf.selected_devices()] == ['CORE', 'SW1', 'SW2']
    assert conf.picker.count.cget('text') == '3 of 6 selected  (3 switches)'
    conf.picker.filter.set('Routers'); conf.picker.show()
    conf.picker.all_button.invoke()
    assert len(conf.selected_devices()) == 5
    assert '3 hidden by the filter' in conf.picker.count.cget('text')
    conf.picker.filter.set('All types'); conf.picker.show()
    conf.picker.all_button.invoke()
    assert len(conf.selected_devices()) == 6
    conf.picker.clear_button.invoke()
    assert conf.selected_devices() == []


def test_clicking_a_row_ticks_and_unticks_it(env):
    root, conf = env['root'], env['conf']
    conf.picker.clear()
    root.update()
    tree = conf.picker.tree
    iid = str(ids(conf, 'SW1')[0])
    x, y, w, h = tree.bbox(iid, 'name')
    tree.event_generate('<ButtonRelease-1>', x=x + 5, y=y + h // 2)
    assert [d['name'] for d in conf.selected_devices()] == ['SW1']
    assert tree.item(iid)['values'][0] == '☑'
    tree.event_generate('<ButtonRelease-1>', x=x + 5, y=y + h // 2)
    assert conf.selected_devices() == []


def test_ticks_survive_a_refresh(env):
    conf = env['conf']
    tick(conf, 'SW1', 'R1')
    conf.refresh_devices()
    assert [d['name'] for d in conf.selected_devices()] == ['R1', 'SW1']


def test_single_device_api_still_works(env):
    conf = env['conf']
    conf.device_box.current(4)                                   # SW1
    assert conf.selected_device()['name'] == 'SW1' and conf.device_box.current() == 4
    assert conf.select_device('R2') and conf.selected_device()['name'] == 'R2'
    assert conf.config_kind() == 'router'                        # the forms follow the type
    assert not conf.select_device('PHONE')                       # not managed


def test_settings_follow_the_selection(env):
    conf = env['conf']
    tick(conf, 'SW1', 'SW2')
    assert conf.config_kind() == 'switch'
    tick(conf, 'R1', 'R2')
    assert conf.config_kind() == 'router'
    assert 'Router settings will go to 2 routers: R1, R2' in conf.target_note.cget('text')
    tick(conf, 'R1', 'SW1')                                     # mixed: the tab stays
    assert 'Skipped (not a router): SW1' in conf.target_note.cget('text')


# ---------------------------------------------------------------- preview
def test_preview_has_a_section_per_compatible_device_and_lists_the_skipped(env):
    conf = env['conf']
    tick(conf, 'CORE', 'SW1', 'R1', 'AP-1')
    conf.forms.select(0)
    vlan_form(conf)
    conf.make_preview()
    text = conf.preview.get('1.0', 'end')
    assert '# ===== CORE  10.0.0.2  switch  |  Switch settings =====' in text
    assert '# ===== SW1  10.0.0.3  switch  |  Switch settings =====' in text
    assert 'R1  10.0.0.1  router: switch settings cannot be sent to a router' in text
    assert '# SKIPPED  AP-1' in text and '=====  R1' not in text
    assert '#   check: show vlan brief  ->  STAFF' in text
    blocks, loose = conf.blocks_from_preview()
    assert loose == [] and [b['name'] for b in blocks] == ['CORE', 'SW1']
    assert blocks[0]['commands'] == ['vlan 10', 'name STAFF', 'interface range FastEthernet0/1 - 5',
                                     'switchport mode access', 'switchport access vlan 10']
    assert set(conf._built) == set(ids(conf, 'CORE', 'SW1'))
    assert conf.status.cget('text').startswith('5 commands for 2 devices, 2 skipped')


def test_no_compatible_device(env):
    conf = env['conf']
    tick(conf, 'R1')
    conf.forms.select(0)
    vlan_form(conf)
    conf.make_preview()
    assert env['shown'][-1][1] == 'No compatible device' and 'R1:' in env['shown'][-1][2]
    assert conf.commands_from_preview() == []


def test_unique_router_settings_are_refused_for_several_routers(env):
    conf, shown = env['conf'], env['shown']
    tick(conf, 'R1', 'R2')
    conf.hostname.set('EDGE')
    conf.make_preview()
    assert shown[-1][1] == 'Hostname' and '2 routers are selected' in shown[-1][2]
    conf.hostname.set('')
    ri = conf.router_if_editor
    ri.vars['name'].set('Gi0/0'); ri.vars['ip'].set('10.1.1.1'); ri.vars['mask'].set('255.255.255.0')
    ri.add()
    conf.make_preview()
    assert shown[-1][1] == 'Interfaces' and 'must be unique' in shown[-1][2]
    ri.items.clear(); ri.show()
    conf.ntp_server.set('10.0.0.50'); conf.dns_servers.set('8.8.8.8')
    conf.make_preview()
    assert [b['name'] for b in conf.blocks_from_preview()[0]] == ['R1', 'R2']
    conf.select_device('R1'); conf.hostname.set('EDGE')         # one router: fine
    conf.make_preview()
    assert conf.blocks_from_preview()[0][0]['commands'][0] == 'hostname EDGE'


# ---------------------------------------------------------------- apply
def test_apply_to_several_devices_one_after_the_other(env):
    root, conf, store = env['root'], env['conf'], env['store']
    tick(conf, 'CORE', 'SW1', 'SW2', 'R1')
    conf.forms.select(0)
    vlan_form(conf)
    conf.make_preview()
    calls = []
    conf.apply_fn = fake_apply(calls, fail={'10.0.0.3'}, delay=0.02)
    conf.apply()
    title, message = env['confirms'][-1]
    assert title == 'Apply to devices' and 'Apply configuration to 3 devices?' in message
    assert 'CORE (switch, 10.0.0.2): 5 commands' in message and \
        'R1: switch settings cannot' in message and 'A backup is saved first' in message
    assert conf.busy and not conf.stop_btn.instate(['disabled'])
    assert pump(root, lambda: not conf.busy)
    assert [c['host'] for c in calls] == ['10.0.0.2', '10.0.0.3', '10.0.0.4']
    assert all(c['thread'] != 'MainThread' for c in calls)
    assert all(c['checks'] for c in calls)                       # every device is checked
    assert all(set(c['creds']) == {'host', 'username', 'password'} for c in calls)
    assert [(i, s) for i, _, s, _ in store.logs] == [(1, 'success'), (4, 'failed'), (5, 'success')]
    text = env['conf'].session.content()
    for line in ('MULTI-DEVICE CONFIGURATION SUMMARY', 'CORE - 10.0.0.2', 'Status: SUCCESS',
                 'Backup: backups/10.0.0.2_x.txt', 'SW1 - 10.0.0.3', 'Status: FAILED',
                 'Reason: Wrong username or password.', 'Status: SKIPPED (nothing sent)',
                 'Completed: 2', 'Failed: 1', 'Total: 3', 'DEVICE 2 OF 3:  SW1  (10.0.0.3)'):
        assert line in text, line
    assert PASSWORD not in text and PASSWORD not in str(env['summary'])
    assert env['shown'][-1][1] == 'Some devices were not configured'
    assert conf.status.cget('text').startswith('2 of 3 devices configured, 1 failed')
    assert not conf.apply_btn.instate(['disabled']) and conf.stop_btn.instate(['disabled'])


def test_all_succeed_means_no_error_box(env):
    root, conf = env['root'], env['conf']
    tick(conf, 'SW1', 'SW2')
    vlan_form(conf)
    conf.make_preview()
    conf.apply_fn = fake_apply([])
    conf.apply()
    assert pump(root, lambda: not conf.busy)
    assert not [s for s in env['shown'] if s[0] == 'showerror']
    assert conf.status.cget('text').startswith('2 of 2 devices configured.')


def test_login_is_asked_once_for_devices_without_one(env):
    root, conf, store = env['root'], env['conf'], env['store']
    store.logins = {4: ('admin', PASSWORD)}                      # only SW1 has a saved login
    tick(conf, 'CORE', 'SW1', 'SW2')
    vlan_form(conf)
    conf.make_preview()
    calls = []
    conf.apply_fn = fake_apply(calls)
    conf.apply()
    assert pump(root, lambda: not conf.busy)
    assert env['asked'] == [(['CORE', 'SW2'], 'missing')]      # ONE dialog for both
    assert [c['creds']['password'] for c in calls] == ['pw', PASSWORD, 'pw']


def test_editing_one_section_changes_only_that_device(env):
    root, conf = env['root'], env['conf']
    tick(conf, 'SW1', 'SW2')
    vlan_form(conf)
    conf.make_preview()
    start = conf.preview.search('# ===== SW2', '1.0')
    conf.preview.insert(f'{start} lineend +1c', 'vlan 99\n')
    calls = []
    conf.apply_fn = fake_apply(calls)
    conf.apply()
    assert 'Edited by hand, so not checked automatically: SW2' in env['confirms'][-1][1]
    assert pump(root, lambda: not conf.busy)
    assert calls[0]['commands'][0] == 'vlan 10' and calls[0]['checks']
    assert calls[1]['commands'][0] == 'vlan 99' and calls[1]['checks'] == []


def test_preview_must_match_the_selection(env):
    conf, shown = env['conf'], env['shown']
    tick(conf, 'SW1', 'SW2')
    vlan_form(conf)
    conf.make_preview()
    tick(conf, 'SW1')                                            # SW2 unticked after the preview
    conf.apply()
    assert shown[-1][1] == 'Cannot apply' and 'SW2: in the preview but not selected' in shown[-1][2]
    conf.preview.delete('1.0', 'end')
    conf.preview.insert('1.0', 'vlan 10\n# ===== SW1  10.0.0.3  switch  |  Switch settings =====\n')
    conf.apply()
    assert 'above the first device section' in shown[-1][2]


def test_a_section_for_the_wrong_type_is_refused(env):
    conf, shown = env['conf'], env['shown']
    tick(conf, 'R1')
    conf.preview.insert('1.0', '# ===== R1  10.0.0.1  router  |  Switch settings =====\nvlan 10\n')
    conf.apply()
    assert shown[-1][1] == 'Cannot apply'
    assert 'switch settings cannot be sent to a router' in shown[-1][2]


def test_typed_commands_without_sections(env):
    root, conf, shown = env['root'], env['conf'], env['shown']
    tick(conf, 'SW1', 'SW2')
    conf.preview.insert('1.0', 'vlan 10\nname STAFF\n')
    conf.apply()
    assert shown[-1][1] == 'Cannot apply' and 'no device sections' in shown[-1][2]
    tick(conf, 'R2')                                             # one device: sent as typed
    calls = []
    conf.apply_fn = fake_apply(calls)
    conf.apply()
    assert pump(root, lambda: not conf.busy)
    assert calls[0]['host'] == '10.0.0.5' and calls[0]['commands'] == ['vlan 10', 'name STAFF']


def test_findings_suggestion_gets_its_own_section(env):
    conf = env['conf']
    conf.load_commands(['line vty 0 4', 'transport input ssh'], 'R1')
    assert conf.commands_from_preview() == ['line vty 0 4', 'transport input ssh']
    assert [d['name'] for d in conf.selected_devices()] == ['R1']
    blocks, _ = conf.blocks_from_preview()
    assert blocks[0]['name'] == 'R1' and blocks[0]['label'] == 'Findings suggestion'


def test_stop_button_and_responsiveness(env):
    root, conf = env['root'], env['conf']
    tick(conf, 'CORE', 'SW1', 'SW2')
    vlan_form(conf)
    conf.make_preview()
    gate = threading.Event()
    calls = []

    def slow(creds, commands, checks, log=None):
        calls.append(creds['host'])
        log('info', 'waiting for the device...')
        gate.wait(5)
        return True, 'Applied and verified. Backup: b.txt'
    conf.apply_fn = slow
    conf.apply()
    ticks = []
    root.after(30, lambda: ticks.append(1))
    assert pump(root, lambda: ticks and calls, 3)                # the window keeps running
    conf.stop_btn.invoke()
    assert 'Stopping after the current device' in conf.status.cget('text')
    gate.set()
    assert pump(root, lambda: not conf.busy)
    assert calls == ['10.0.0.2']
    assert [r['status'] for r in conf.last_results] == ['SUCCESS', 'NOT RUN', 'NOT RUN']
    assert 'Not run: 2' in conf.session.content()


# ---------------------------------------------------------------- workbench layout
@pytest.fixture
def app(monkeypatch):
    import db_fake
    root = new_root()
    root.geometry('1200x700')
    for name in ('showinfo', 'showerror', 'showwarning'):
        monkeypatch.setattr(messagebox, name, lambda *a, **k: None)
    db_fake.reset()
    from gui.main_window import build_main_window
    refs = build_main_window(root, db_fake, demo_store=True)
    root.update()
    yield root, refs, db_fake
    root.destroy()


def test_inspector_is_hidden_on_configure_and_can_be_toggled(app):
    root, r, store = app
    wide_window(root, r)                  # a narrow window hides the inspector by itself
    assert r['inspector_shown']()
    r['show_page']('configure'); root.update()
    assert not r['inspector_shown']() and len(r['panels']['upper'].panes()) == 1
    assert r['inspector_toggle'].cget('text') == 'Show inspector'
    r['inspector_toggle'].invoke()                               # the user wants it here
    assert r['inspector_shown']()
    r['show_page']('devices'); r['show_page']('configure')
    assert r['inspector_shown']()                                # remembered for this page
    r['inspector'].hide_button.invoke()
    assert not r['inspector_shown']()
    r['show_page']('topology')
    assert r['inspector_shown']()                                # other pages keep theirs


def test_finding_a_device_brings_the_inspector_back(app):
    root, r, store = app
    did = store.upsert_device({'name': 'SW1', 'ip': '10.0.0.1', 'type': 'switch',
                               'managed': True, 'status': 'up'})
    r['show_page']('configure')
    assert not r['inspector_shown']()
    r['command'].set_text('SW1')
    items = r['command'].update_suggestions()
    r['command'].run([i for i, (k, _, _) in enumerate(items) if k == 'device'][0])
    assert r['inspector_shown']() and r['inspector'].device['id'] == did


def test_configure_page_layout_fits(app):
    root, r, store = app
    for i in range(3):
        store.upsert_device({'name': f'SW{i}', 'ip': f'10.0.0.{i + 1}', 'type': 'switch',
                             'managed': True, 'status': 'up'})
    r['show_page']('configure')
    root.update()
    conf = r['configure']
    assert pump(root, lambda: conf._placed, 3)
    widths = [conf.columns.sashpos(0), conf.columns.sashpos(1) - conf.columns.sashpos(0)]
    assert all(w > 150 for w in widths)                          # devices and settings get room
    # the settings content gets exactly the visible width (nothing cut off on the right)
    s = conf.settings
    assert abs(s.inner.winfo_width() - s.canvas.winfo_width()) <= 1
    assert conf.session.winfo_height() > 120                     # a usable SSH console
    assert conf.preview.winfo_height() > 60
