"""The Configure page: the live SSH session console, port ranges and the new
switch / router forms. Uses a small in-memory store and a fake apply function:
no device, no database."""
import threading
import time

import pytest

tk = pytest.importorskip('tkinter')
from tkinter import messagebox, simpledialog  # noqa: E402

from gui_helpers import new_root, pump  # noqa: E402

PASSWORD = 'Top$ecret99'


class Store:
    def __init__(self):
        self.logs = []
        self.devices = [
            {'id': 1, 'name': 'SW1', 'ip': '10.0.0.2', 'type': 'switch', 'managed': 1},
            {'id': 2, 'name': 'R1', 'ip': '10.0.0.1', 'type': 'router', 'managed': 1},
        ]

    def get_devices(self, *a):
        return list(self.devices)

    def get_credentials(self, device_id):
        return 'admin', PASSWORD

    def add_log(self, device_id, action, status, message):
        self.logs.append((device_id, action, status, message))


@pytest.fixture
def page(monkeypatch):
    root = new_root()
    from gui import theme
    theme.apply(root)
    shown = []
    for name in ('showinfo', 'showerror', 'showwarning'):
        monkeypatch.setattr(messagebox, name, lambda t, m, _n=name, **k: shown.append((_n, t, m)))
    monkeypatch.setattr(messagebox, 'askyesno', lambda *a, **k: True)
    monkeypatch.setattr('gui.components.login_dialog.ask_device_login',
                        lambda *a, **k: {'username': 'admin', 'password': 'admin', 'save': False})
    from gui.configure_tab import ConfigureTab
    store, summary = Store(), []
    conf = ConfigureTab(root, store, log=lambda *a, **k: summary.append(a))
    conf.pack(fill='both', expand=True)
    root.update()
    yield root, conf, store, shown, summary
    root.destroy()


def choose(conf, name):
    conf.device_box.current([d['name'] for d in conf.devices].index(name))
    conf._show_forms_for_device()


def session_text(conf):
    conf.session.flush()
    return conf.session.content()


# ---------------------------------------------------------------- the SSH console
def test_live_session_is_shown_and_password_never_is(page):
    root, conf, store, shown, summary = page
    choose(conf, 'SW1')
    seen_threads = []

    def fake_apply(creds, commands, checks, log=None):
        assert creds == {'host': '10.0.0.2', 'username': 'admin', 'password': PASSWORD}
        seen_threads.append(threading.current_thread() is threading.main_thread())
        log('section', 'CONNECT')
        log('info', 'Connecting to 10.0.0.2 through SSH...')
        log('section', 'CONFIGURATION')
        for c in commands:
            log('command', f'SW1(config)# {c}')
            time.sleep(0.01)
        log('output', "% Invalid input detected at '^' marker.")
        log('section', 'RESULT')
        log('error', 'FAILED (partially applied)')
        return False, 'The device rejected a command: "x". The change is partially applied'

    conf.apply_fn = fake_apply
    conf.port.set('Fa0/1-5'); conf.port_vlan.set('10'); conf.add_port()
    conf.make_preview()
    conf.apply()
    assert conf.busy and conf.apply_btn.instate(['disabled'])
    assert pump(root, lambda: not conf.busy)
    text = session_text(conf)
    assert seen_threads == [False]                        # SSH work ran off the window thread
    assert 'SW1 (10.0.0.2)  3 commands' in text
    assert '[CONFIGURATION]' in text and 'SW1(config)# interface range FastEthernet0/1 - 5' in text
    assert '% Invalid input' in text and '[SW1] FAILED (partially applied)' in text
    assert PASSWORD not in text
    assert store.logs[-1][2] == 'failed' and shown[-1][:2] == ('showerror', 'Apply failed')
    assert summary and 'PARTIALLY APPLIED' in summary[-1][1] and PASSWORD not in str(summary)
    assert not conf.apply_btn.instate(['disabled'])


def test_previous_output_is_kept_until_clear(page):
    root, conf, store, shown, summary = page
    choose(conf, 'SW1')
    conf.apply_fn = lambda creds, cmds, checks: (True, 'Applied and verified. Backup: b.txt')
    for vid in ('10', '20'):          # a successful Apply clears the applied preview and form,
        conf.vid.set(vid); conf.vname.set('STAFF'); conf.add_vlan()   # so preview each change
        conf.make_preview()
        conf.apply()
        assert pump(root, lambda: not conf.busy)
    text = session_text(conf)
    assert text.count('SW1 (10.0.0.2)  2 commands =====') == 2
    assert text.count('[SW1] Applied and verified') == 2     # 3-argument fakes still get a line
    conf.session.clear_button.invoke()
    assert session_text(conf).strip() == '' and conf.session.lines == []


def test_window_stays_responsive_while_applying(page):
    root, conf, store, shown, summary = page
    choose(conf, 'SW1')
    release = threading.Event()

    def slow_apply(creds, commands, checks, log=None):
        log('info', 'waiting for the device...')
        release.wait(5)
        return True, 'Applied and verified. Backup: b.txt'

    conf.apply_fn = slow_apply
    conf.vid.set('10'); conf.vname.set('STAFF'); conf.add_vlan()
    conf.make_preview(); conf.apply()
    ticks = []
    root.after(50, lambda: ticks.append(1))
    assert pump(root, lambda: ticks and 'waiting for the device' in conf.session.content(), 3)
    assert conf.busy
    conf.apply()                                       # a second click does nothing while busy
    release.set()
    assert pump(root, lambda: not conf.busy)
    assert store.logs[-1][2] == 'success'


def test_posting_from_many_threads(page):
    root, conf, *_ = page
    workers = [threading.Thread(target=lambda n=n: [conf.session.post('output', f'{n}-{i}')
                                                    for i in range(50)]) for n in range(4)]
    for w in workers:
        w.start()
    for w in workers:
        w.join()
    assert pump(root, lambda: len(conf.session.lines) == 200, 3)


def test_crashing_apply_function_is_reported(page):
    root, conf, store, shown, summary = page
    choose(conf, 'SW1')

    def boom(creds, commands, checks, log=None):
        raise RuntimeError('socket closed')
    conf.apply_fn = boom
    conf.vid.set('10'); conf.vname.set('STAFF'); conf.add_vlan()
    conf.make_preview(); conf.apply()
    assert pump(root, lambda: not conf.busy)
    assert 'RuntimeError: socket closed' in session_text(conf)
    assert store.logs[-1][2] == 'failed'


# ---------------------------------------------------------------- forms
def test_access_port_range_form(page):
    root, conf, store, shown, summary = page
    choose(conf, 'SW1')
    conf.vid.set('10'); conf.vname.set('STAFF'); conf.add_vlan()
    conf.port.set('Fa0/1-Fa0/5'); conf.port_vlan.set('10'); conf.add_port()
    conf.port.set('Fa0/5-1'); conf.port_vlan.set('10'); conf.add_port()        # reversed
    conf.port.set('Fa0/3'); conf.port_vlan.set('10'); conf.add_port()          # already listed
    assert [s[1] for s in shown] == ['Cannot add ports', 'Cannot add ports']
    assert 'reversed' in shown[0][2] and 'already in the list' in shown[1][2]
    assert conf.ports == [('Fa0/1-Fa0/5', 10)]
    assert '(5 ports)' in str(conf.port_tree.item(conf.port_tree.get_children()[0])['values'])
    conf.make_preview()
    assert conf.commands_from_preview() == ['vlan 10', 'name STAFF',
                                            'interface range FastEthernet0/1 - 5',
                                            'switchport mode access', 'switchport access vlan 10']


def test_trunk_security_and_interface_editors(page):
    root, conf, store, shown, summary = page
    choose(conf, 'SW1')
    t = conf.trunk_editor
    t.vars['ports'].set('Gi0/1-2'); t.vars['allowed'].set('30-32, 10,20'); t.vars['native'].set('99')
    t.add()
    t.vars['ports'].set('Gi0/2'); t.add()                                     # overlaps
    s = conf.security_editor
    s.vars['ports'].set('Fa0/1-4'); s.vars['maximum'].set('0'); s.add()       # bad maximum
    s.vars['maximum'].set('3'); s.add()
    i = conf.switch_if_editor
    i.vars['ports'].set('Fa0/24'); i.vars['description'].set('Uplink'); i.vars['state'].set('shutdown')
    i.add()
    assert [m[1] for m in shown] == ['Cannot add (trunk)', 'Cannot add (port security)']
    assert t.items[0]['allowed'] == '10,20,30-32' and t.items[0]['native'] == 99
    conf.make_preview()
    cmds = conf.commands_from_preview()
    assert 'switchport trunk allowed vlan 10,20,30-32' in cmds
    assert 'switchport port-security maximum 3' in cmds
    assert cmds[-3:] == ['interface Fa0/24', 'description Uplink', 'shutdown']
    assert ('show running-config interface GigabitEthernet0/1', 'switchport mode trunk') \
        in conf._built[1][1]                                  # device id 1 = SW1


def test_router_forms(page):
    root, conf, store, shown, summary = page
    choose(conf, 'R1')
    assert conf.forms.index(conf.forms.select()) == 1
    conf.hostname.set('EDGE-1'); conf.dns_servers.set('8.8.8.8, 1.1.1.1')
    conf.ntp_server.set('10.0.0.50'); conf.default_route.set('10.0.0.254')
    ri = conf.router_if_editor
    ri.vars['name'].set('Gi0/0-1'); ri.vars['ip'].set('10.0.0.1'); ri.vars['mask'].set('255.255.255.0')
    ri.add()                                                                  # a range: refused
    ri.vars['name'].set('Gi0/0'); ri.vars['ip'].set('10.0.0.0'); ri.add()     # network address
    ri.vars['ip'].set('10.0.0.1'); ri.add()
    routes = conf.route_editor
    routes.vars['network'].set('172.16.1.0'); routes.vars['mask'].set('255.255.0.0')
    routes.vars['next_hop'].set('10.0.0.254'); routes.add()                   # not a network address
    routes.vars['network'].set('172.16.0.0'); routes.vars['mask'].set('255.255.0.0')
    routes.vars['next_hop'].set('10.0.0.254'); routes.add()
    assert [m[1] for m in shown] == ['Cannot add (router interface)'] * 2 + \
        ['Cannot add (static route)']
    assert shown[-1][2] == 'Use the network address: 172.16.0.0'
    conf.make_preview()
    assert conf.commands_from_preview() == [
        'hostname EDGE-1', 'interface Gi0/0', 'ip address 10.0.0.1 255.255.255.0', 'no shutdown',
        'ip route 0.0.0.0 0.0.0.0 10.0.0.254', 'ip route 172.16.0.0 255.255.0.0 10.0.0.254',
        'ip name-server 8.8.8.8 1.1.1.1', 'ntp server 10.0.0.50']


def test_router_dhcp_checks(page):
    root, conf, store, shown, summary = page
    choose(conf, 'R1')
    for k, v in {'pool': 'LAN', 'network': '192.168.1.0', 'mask': '255.255.255.0',
                 'gateway': '192.168.2.1', 'dns': '8.8.8.8'}.items():
        conf.dhcp[k].set(v)
    conf.make_preview()
    # Preview is blocked by the form check, which lists the field and the reason
    assert shown[-1][1] == 'Cannot preview: fix these fields first'
    assert 'DHCP > DHCP gateway: The gateway 192.168.2.1 is not inside' in shown[-1][2]
    conf.dhcp['gateway'].set('192.168.1.1')
    conf.dhcp['ex_start'].set('192.168.1.20'); conf.dhcp['ex_end'].set('192.168.1.1')
    conf.make_preview()
    assert '"Exclude from" must not be after "Exclude to"' in shown[-1][2]
    conf.dhcp['ex_start'].set('192.168.1.1'); conf.dhcp['ex_end'].set('192.168.1.20')
    conf.hostname.set('bad name')
    conf.make_preview()
    assert 'Basics > Hostname: No spaces allowed in a hostname.' in shown[-1][2]
    conf.hostname.set('')
    conf.make_preview()
    assert conf.commands_from_preview()[0] == 'ip dhcp excluded-address 192.168.1.1 192.168.1.20'
