"""What happens after an Apply (physical-test issues 1 and 2):

1. a hostname the router accepted renames the SAME device record (no duplicate; links,
   findings and history stay with it) and the Devices page shows the new name;
2. only form sections that were successfully applied are cleared, so a later Preview
   contains only the pending change; failed, partial, unverified or hand-edited
   results keep their inputs.

The real main window with db_fake (in memory) and a fake apply function: no device,
no database server."""
import os, sys
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))
sys.path.insert(0, os.path.dirname(__file__))
import pytest

tk = pytest.importorskip('tkinter')
from tkinter import messagebox, simpledialog  # noqa: E402

import db_fake  # noqa: E402
from gui_helpers import new_root, pump  # noqa: E402

PASSWORD = 'Rtr-Pa55word!'
OK = 'Applied and verified. Backup: backups/x.txt'


@pytest.fixture
def app(monkeypatch):
    root = new_root()
    shown = []
    for name in ('showinfo', 'showerror', 'showwarning'):
        monkeypatch.setattr(messagebox, name, lambda t, m, _n=name, **k: shown.append((_n, t, m)))
    # yes to every question, except the offer to retry a refused login (the fakes refuse it again)
    monkeypatch.setattr(messagebox, 'askyesno', lambda t, *a, **k: t != 'SSH login refused')
    monkeypatch.setattr('gui.components.login_dialog.ask_device_login',
                        lambda *a, **k: {'username': 'admin', 'password': 'admin', 'save': False})
    db_fake.reset()
    r1 = db_fake.save_device(None, {'name': 'R1', 'ip': '10.0.0.1', 'type': 'router',
                                    'managed': True, 'status': 'up'}, 'admin', PASSWORD)
    r2 = db_fake.save_device(None, {'name': 'R2', 'ip': '10.0.0.3', 'type': 'router',
                                    'managed': True, 'status': 'up'}, 'admin', PASSWORD)
    sw = db_fake.save_device(None, {'name': 'SW1', 'ip': '10.0.0.2', 'type': 'switch',
                                    'managed': True, 'status': 'up'}, 'admin', PASSWORD)
    db_fake.save_links([('R1', 'Gi0/1', 'SW1', 'Gi0/1')])
    db_fake.add_finding({'device': 'R1', 'rule': 'no_password_encryption', 'severity': 'medium',
                         'message': 'm', 'commands': ['service password-encryption']})
    db_fake.add_log(r1, 'Configuration', 'success', 'earlier change')
    from gui.main_window import build_main_window
    refs = build_main_window(root, db_fake, demo_store=True)
    root.update()
    yield root, refs, shown, {'R1': r1, 'R2': r2, 'SW1': sw}
    root.destroy()


def pick(conf, *names):
    conf.refresh_devices()
    conf.picker.set_checked([d['id'] for d in conf.devices if d['name'] in names])
    conf._show_forms_for_device()


def run_apply(root, conf, results):
    """Apply with a fake apply function; results: {device ip: (ok, message)}."""
    sent = []

    def fake(creds, commands, checks):
        sent.append((creds['host'], list(commands)))
        return results.get(creds['host'], (True, OK))
    conf.apply_fn = fake
    conf.apply()
    assert pump(root, lambda: not conf.busy)
    return sent


def fill_dhcp(conf):
    for key, value in {'pool': 'LAN', 'network': '192.168.50.0', 'mask': '255.255.255.0',
                       'gateway': '192.168.50.1', 'dns': '8.8.8.8'}.items():
        conf.dhcp[key].set(value)


def device_rows(r):
    devices = r['devices']
    devices.refresh()
    return [devices.tree.item(i)['values'][0] for i in devices.tree.get_children()]


# ---------------------------------------------------------------- issue 1: hostname
def test_successful_hostname_change_renames_the_same_record(app):
    root, r, shown, ids = app
    conf = r['configure']
    pick(conf, 'R1')
    conf.hostname.set('BRANCH-RTR')
    conf.make_preview()
    run_apply(root, conf, {})
    assert db_fake.count_devices() == 3                               # no duplicate record
    renamed = db_fake.get_device(ids['R1'])
    assert renamed['name'] == 'BRANCH-RTR' and renamed['ip'] == '10.0.0.1'
    assert db_fake.get_device_by_name('R1') is None
    assert db_fake.get_credentials(ids['R1']) == ('admin', PASSWORD)  # login kept
    assert db_fake.get_links() == [('BRANCH-RTR', 'Gi0/1', 'SW1', 'Gi0/1')]   # link follows
    assert db_fake.get_findings()[0]['device'] == 'BRANCH-RTR'        # findings by id
    logs = db_fake.get_logs()                       # rows show the device's CURRENT name (by id)
    assert len(logs) == 2 and {l['device'] for l in logs} == {'BRANCH-RTR'}   # old entry kept


def test_devices_page_shows_the_new_name_after_the_apply(app):
    root, r, shown, ids = app
    assert 'R1' in device_rows(r)
    conf = r['configure']
    pick(conf, 'R1')
    conf.hostname.set('BRANCH-RTR')
    conf.make_preview()
    run_apply(root, conf, {})
    tree = r['devices'].tree                                  # refreshed by the Apply itself
    shown_names = [tree.item(i)['values'][0] for i in tree.get_children()]
    assert 'BRANCH-RTR' in shown_names and 'R1' not in shown_names
    assert 'BRANCH-RTR' in {d['name'] for d in conf.devices}  # and Configure's own list
    assert device_rows(r).count('BRANCH-RTR') == 1            # a manual refresh agrees


def test_failed_hostname_change_does_not_rename(app):
    root, r, shown, ids = app
    conf = r['configure']
    pick(conf, 'R1')
    conf.hostname.set('BRANCH-RTR')
    conf.make_preview()
    run_apply(root, conf, {'10.0.0.1': (False, 'Wrong username or password.')})
    assert db_fake.get_device(ids['R1'])['name'] == 'R1'
    assert conf.hostname.get() == 'BRANCH-RTR'                       # kept for a retry


def test_unverified_hostname_change_does_not_rename(app):
    root, r, shown, ids = app
    conf = r['configure']
    pick(conf, 'R1')
    conf.hostname.set('BRANCH-RTR')
    conf.make_preview()
    run_apply(root, conf, {'10.0.0.1': (False, 'Check failed: "hostname BRANCH-RTR" was not '
                                                'found in show running-config. The commands were '
                                                'applied but not saved. Backup: b.txt')})
    assert db_fake.get_device(ids['R1'])['name'] == 'R1'
    assert conf.hostname.get() == 'BRANCH-RTR'


def test_hostname_already_used_by_another_device_is_reported_not_duplicated(app):
    root, r, shown, ids = app
    conf = r['configure']
    pick(conf, 'R1')
    conf.hostname.set('SW1')
    conf.make_preview()
    run_apply(root, conf, {})
    assert db_fake.get_device(ids['R1'])['name'] == 'R1'
    assert [d['name'] for d in db_fake.get_devices('', 'name', 1, 50)].count('SW1') == 1
    r['console'].flush()
    assert any('already uses that name' in line for line in map(str, r['console'].lines))


def test_hostname_typed_into_the_preview_by_hand_also_renames(app):
    root, r, shown, ids = app
    conf = r['configure']
    pick(conf, 'R1')
    conf._set_preview(['hostname EDGE1'])                    # no sections: one device ticked
    conf._built = {}
    run_apply(root, conf, {})
    assert db_fake.get_device(ids['R1'])['name'] == 'EDGE1'


# ---------------------------------------------------------------- issue 2: clearing the forms
def test_successful_dhcp_clears_only_the_dhcp_fields(app):
    root, r, shown, ids = app
    conf = r['configure']
    pick(conf, 'R1')
    fill_dhcp(conf)
    conf.vid.set('30'); conf.vname.set('VOICE'); conf.add_vlan()      # switch form: unrelated
    conf.make_preview()
    assert 'ip dhcp pool LAN' in conf.commands_from_preview()
    conf.ntp_server.set('10.0.0.123')                 # typed after the Preview: not applied
    sent = run_apply(root, conf, {})
    assert any('ip dhcp pool LAN' in c for c in sent[0][1])
    assert all(v.get() == '' for v in conf.dhcp.values())             # applied: cleared
    assert conf.ntp_server.get() == '10.0.0.123'                      # pending: kept
    assert conf.vlans == [(30, 'VOICE')]                              # other form: kept
    assert conf.commands_from_preview() == []                         # nothing left pending


def test_next_preview_contains_only_the_new_change(app):
    root, r, shown, ids = app
    conf = r['configure']
    pick(conf, 'R1')
    fill_dhcp(conf)
    conf.make_preview()
    run_apply(root, conf, {})
    conf.hostname.set('BRANCH-RTR')                  # the next, different change
    conf.make_preview()
    commands = conf.commands_from_preview()
    assert commands == ['hostname BRANCH-RTR']
    assert not any('dhcp' in c for c in commands)


def test_failed_apply_keeps_the_inputs_and_the_preview(app):
    root, r, shown, ids = app
    conf = r['configure']
    pick(conf, 'R1')
    fill_dhcp(conf)
    conf.make_preview()
    before = conf.commands_from_preview()
    run_apply(root, conf, {'10.0.0.1': (False, 'No answer (the connection timed out: wrong IP, '
                                                'device off, or not reachable).')})
    assert conf.dhcp['pool'].get() == 'LAN' and conf.dhcp['network'].get() == '192.168.50.0'
    assert conf.commands_from_preview() == before                     # ready to retry


def test_partially_applied_keeps_the_inputs(app):
    root, r, shown, ids = app
    conf = r['configure']
    pick(conf, 'R1')
    fill_dhcp(conf)
    conf.make_preview()
    run_apply(root, conf, {'10.0.0.1': (False, 'The device rejected a command: "network ..." '
                                                '(% Invalid input). The change is partially '
                                                'applied: 1 of 4 commands were applied before '
                                                'it, and it was not saved. Restore from the '
                                                'backup if needed: b.txt')})
    assert conf.dhcp['pool'].get() == 'LAN'
    assert 'ip dhcp pool LAN' in conf.commands_from_preview()


def test_one_router_failing_of_two_keeps_the_inputs_and_its_section(app):
    root, r, shown, ids = app
    conf = r['configure']
    pick(conf, 'R1', 'R2')
    fill_dhcp(conf)
    conf.make_preview()
    run_apply(root, conf, {'10.0.0.3': (False, 'Wrong username or password.')})
    assert conf.dhcp['pool'].get() == 'LAN'                           # R2 still needs them
    blocks, _ = conf.blocks_from_preview()
    assert [b['name'] for b in blocks] == ['R2']                      # R1 (done) left the preview
    assert 'ip dhcp pool LAN' in blocks[0]['commands']


def test_both_routers_succeeding_clears_the_dhcp_fields(app):
    root, r, shown, ids = app
    conf = r['configure']
    pick(conf, 'R1', 'R2')
    fill_dhcp(conf)
    conf.make_preview()
    run_apply(root, conf, {})
    assert all(v.get() == '' for v in conf.dhcp.values())
    assert conf.blocks_from_preview() == ([], [])


def test_hand_edited_preview_does_not_clear_the_form(app):
    root, r, shown, ids = app
    conf = r['configure']
    pick(conf, 'R1')
    fill_dhcp(conf)
    conf.make_preview()
    text = conf.preview.get('1.0', 'end').replace('default-router 192.168.50.1',
                                                  'default-router 192.168.50.254')
    conf.preview.delete('1.0', 'end'); conf.preview.insert('1.0', text)
    run_apply(root, conf, {})
    assert conf.dhcp['gateway'].get() == '192.168.50.1'      # the form no longer matches what ran


def test_switch_sections_are_cleared_after_success_and_router_forms_kept(app):
    root, r, shown, ids = app
    conf = r['configure']
    conf.hostname.set('KEEP-ME')                             # router form, not applied
    pick(conf, 'SW1')
    conf.vid.set('40'); conf.vname.set('LAB'); conf.add_vlan()
    conf.port.set('Fa0/5'); conf.port_vlan.set('40'); conf.add_port()
    conf.make_preview()
    run_apply(root, conf, {})
    assert conf.vlans == [] and conf.ports == []
    assert conf.hostname.get() == 'KEEP-ME'
    assert db_fake.get_device(ids['R1'])['name'] == 'R1'     # nothing renamed by a switch apply
