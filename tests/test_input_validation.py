"""Input validation on the Configure page (Switch and Router settings).

* validators.py: the one set of rules (IPv4, masks, VLANs, VLAN lists, ports, interfaces,
  hostnames, names, descriptions, numbers, DHCP, static routes, blocked characters).
* The screen: characters refused while typing, a red border and message under an invalid
  field, Add disabled until the section's required fields are valid, Preview / Apply
  blocked with a list of what is wrong.
* The backend: the command builders and apply_config check again (nothing is trusted).
No device, no database.
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))
sys.path.insert(0, os.path.dirname(__file__))

import pytest

import validators as V
from config import commands_router, commands_switch, connect


# ---------------------------------------------------------------- the user's examples
def test_the_examples():
    assert not V.typing_ok('ipv4', 'asdasd') and not V.typing_ok('ipv4', '1a')
    assert V.typing_ok('ipv4', '192.168.') is True
    assert 'must be 0-255' in V.check_ipv4('300.1.1.1')
    assert 'contiguous' in V.check_mask('255.0.255.0')
    assert V.check_vlan_id('5000') == 'Enter a VLAN ID from 1 to 4094.'
    assert '"40-30" is reversed' in V.check_vlan_list('10,20,40-30')
    assert V.check_port_list('Fa0/1-5, Gi0/1') is None
    assert V.check_hostname('R1 main') == 'No spaces allowed in a hostname.'
    assert V.check_description('test; reload') == \
        'The character ";" is not allowed (values are sent as device commands).'
    assert ('gateway', 'The gateway 10.0.0.1 is not inside the network 192.168.10.0/24.') in \
        V.check_dhcp({'pool': 'LAN', 'network': '192.168.10.0', 'mask': '255.255.255.0',
                      'gateway': '10.0.0.1'})
    assert V.check_static_route('10.10.0.0', '255.255.0.0', '192.168.1.254') is None
    assert V.check_static_route('10.10.5.1', '255.255.0.0', '192.168.1.254') == \
        ('network', 'Use the network address: 10.10.0.0')
    assert V.check_static_route('0.0.0.0', '0.0.0.0', '192.168.1.254') == \
        ('network', 'Use Basics > Default route for the default route.')


# ---------------------------------------------------------------- rules
@pytest.mark.parametrize('ip, ok', [('192.168.1.1', True), ('0.0.0.0', True),
                                    ('255.255.255.255', True), ('192.168.01.1', False),
                                    ('1.2.3', False), ('1.2.3.4.5', False), (' 10.0.0.1 ', True),
                                    ('1.2.3.256', False), ('', False)])
def test_ipv4(ip, ok):
    assert V.is_valid_ipv4(ip) is ok


def test_masks_and_slash_notation():
    assert V.parse_mask('/24') == '255.255.255.0' and V.parse_mask('255.255.0.0') == '255.255.0.0'
    assert V.parse_mask('/0') == '0.0.0.0' and V.parse_mask('/32') == '255.255.255.255'
    for bad in ('/33', '255.255.255.1', '24', '255.255.0.255'):
        assert not V.is_valid_mask(bad)


def test_vlans():
    assert V.is_valid_vlan_id('1') and V.is_valid_vlan_id('4094') and not V.is_valid_vlan_id('0')
    assert not V.is_valid_vlan_id('12a') and not V.is_valid_vlan_id('-5')
    assert 'default VLAN' in V.vlan_id_warning('1') and 'reserved' in V.vlan_id_warning('1003')
    assert V.vlan_id_warning('10') is None
    assert V.parse_vlan_list('10,20,30-32') == [10, 20, 30, 31, 32]
    assert 'listed twice' in V.check_vlan_list('10,5-15')
    assert 'outside' in V.check_vlan_list('10,4095') and 'empty entry' in V.check_vlan_list('10,,20')
    assert V.check_vlan_list('10;20') and not V.typing_ok('vlan_list', '10a')


def test_ports_and_interfaces():
    for ok in ('Fa0/1', 'fa0/1-5', 'Fa0/1-Fa0/5', 'GigabitEthernet0/1', 'Te1/0/1', 'Eth0/1'):
        assert V.check_port_list(ok) is None, ok
    assert 'reversed' in V.check_port_list('Fa0/5-1')
    for ok in ('Gi0/0', 'GigabitEthernet0/0', 'Fa0/1', 'Se0/0/0', 'Lo0', 'Gi0/0.10', 'Vlan10'):
        assert V.is_valid_interface_name(ok), ok
    for bad in ('Gi0', 'Xy0/1', 'Gi0/0;', 'Gi 0/0 0', ''):
        assert not V.is_valid_interface_name(bad), bad
    assert V.interface_key('gi0/0') == V.interface_key('GigabitEthernet0/0')


def test_names_hostnames_descriptions_numbers():
    assert V.is_valid_hostname('R1-core') and not V.is_valid_hostname('1R')
    assert 'end with a hyphen' in V.check_hostname('R1-')
    assert 'at most 63' in V.check_hostname('R' * 64)
    assert V.check_name('STAFF_10', 'The VLAN name') is None
    assert 'No spaces' in V.check_name('A B', 'The VLAN name')
    assert 'at most 32' in V.check_name('A' * 33, 'The VLAN name')
    assert 'can only use' in V.check_name('A.B', 'The VLAN name')
    assert V.check_description('Uplink to SW1') is None
    assert 'at most 240' in V.check_description('x' * 241)
    assert V.check_number('8192', 1, 8192) is None and V.check_number('8193', 1, 8192)
    assert V.check_number('2.5', 1, 10) and not V.typing_ok('number', '2.5')


@pytest.mark.parametrize('bad', ['a\nb', 'a;b', 'a|b', 'a`b', 'a$b', 'a\x07b'])
def test_blocked_characters_everywhere(bad):
    for check in (V.check_description, V.check_hostname, V.check_port_list,
                  V.check_interface_name, V.check_cli_line,
                  lambda t: V.check_name(t, 'The name')):
        assert check(bad), (check, bad)


def test_dhcp_rules():
    base = {'pool': 'LAN', 'network': '192.168.10.0', 'mask': '255.255.255.0'}
    assert V.check_dhcp({}) == []
    assert V.check_dhcp(base) == []
    fields = {f for f, _ in V.check_dhcp({'gateway': '192.168.10.1'})}
    assert {'pool', 'network', 'mask'} <= fields
    assert V.check_dhcp(dict(base, network='192.168.10.5')) == \
        [('network', 'Use the network address: 192.168.10.0')]
    assert 'broadcast' in V.check_dhcp(dict(base, gateway='192.168.10.255'))[0][1]
    assert V.check_dhcp(dict(base, ex_start='192.168.10.1'))[0][0] == 'ex_end'
    assert V.check_dhcp(dict(base, ex_start='192.168.10.9', ex_end='192.168.10.2'))[0][0] == \
        'ex_start'
    assert 'not inside' in V.check_dhcp(dict(base, ex_start='10.0.0.1',
                                            ex_end='192.168.10.2'))[0][1]
    assert V.check_dhcp(dict(base, mask='/24')) == []


def test_static_route_rules():
    assert V.check_static_route('10.10.0.0', '/16', 'Gi0/0') is None
    assert V.check_static_route('10.10.0.0', '255.255.0.0', '0.0.0.0')[0] == 'next_hop'
    assert 'inside the destination' in V.check_static_route('10.10.0.0', '255.255.0.0',
                                                            '10.10.3.4')[1]
    assert V.check_static_route('10.10.0.0', '255.255.0.0', '300.1.1.1')[0] == 'next_hop'
    assert V.check_static_route('', '255.255.0.0', '1.1.1.1') == ('network', 'Required.')


def test_interface_address_rules():
    assert V.check_interface_address('', '') is None
    assert V.check_interface_address('192.168.1.1', '')[0] == 'mask'
    assert 'network address' in V.check_interface_address('192.168.1.0', '255.255.255.0')[1]
    assert V.check_interface_address('192.168.1.1', '/24') is None


# ---------------------------------------------------------------- the backend
def test_the_builders_check_again():
    with pytest.raises(commands_switch.PlanError):
        commands_switch.build_commands({'vlans': [(5000, 'X')]}, ['VLANs'])
    with pytest.raises(commands_switch.PlanError):
        commands_switch.build_commands({'interfaces': [{'ports': 'Fa0/1',
                                                        'description': 'x; reload'}]},
                                       ['Interface settings'])
    with pytest.raises(commands_router.PlanError):
        commands_router.build_commands({'static_routes': [('10.10.5.1', '255.255.0.0',
                                                           '192.168.1.254')]},
                                       ['Static routes'])
    with pytest.raises(commands_router.PlanError):
        commands_router.build_commands({'hostname': 'R1 main'}, ['Hostname'])
    cmds, _ = commands_switch.build_commands({'vlans': [(10, '')]}, ['VLANs'])
    assert cmds == ['vlan 10']                               # the name is optional


def test_apply_refuses_a_blocked_command_before_connecting(monkeypatch, tmp_path):
    monkeypatch.setattr(connect, '_open', lambda creds: pytest.fail('connected'))
    ok, msg = connect.apply_config({'host': '10.0.0.2', 'username': 'a', 'password': 'b'},
                                   ['interface Gi0/1', 'description x; reload'],
                                   backup_dir=str(tmp_path))
    assert not ok and 'refused before connecting' in msg and 'nothing was sent' in msg


# ---------------------------------------------------------------- the screen
@pytest.fixture
def page(monkeypatch):
    from tkinter import messagebox
    import db_fake
    from gui import theme
    from gui.configure_tab import ConfigureTab
    from gui_helpers import new_root
    root = new_root()
    theme.apply(root)
    shown = []
    for name in ('showerror', 'showinfo', 'showwarning'):
        monkeypatch.setattr(messagebox, name, lambda t, m, _n=name, **k: shown.append((_n, t, m)))
    db_fake.reset()
    conf = ConfigureTab(root, db_fake, log=lambda *a, **k: None)
    conf.pack()
    root.update()
    yield root, conf, shown
    root.destroy()
    db_fake.reset()


def type_into(entry, text):
    """Type key by key, as the user would (refused keys do not arrive)."""
    w = entry.entry
    w.delete(0, 'end')
    for ch in text:
        w.insert('end', ch)


def test_letters_cannot_be_typed_into_an_ip_field(page):
    root, conf, _ = page
    entry = conf.basic_entries['NTP server']
    type_into(entry, 'asdasd')
    assert entry.var.get() == ''
    type_into(entry, '1a0.0.0.1')
    assert entry.var.get() == '10.0.0.1'


def test_an_invalid_field_turns_red_with_a_message(page):
    root, conf, _ = page
    entry = conf.basic_entries['NTP server']
    entry.var.set('300.1.1.1')
    root.update()
    assert entry.entry.cget('style') == 'Invalid.TEntry'
    assert 'must be 0-255' in entry.shown_message and entry.message.winfo_manager()
    entry.var.set('10.0.0.1')
    assert entry.entry.cget('style') == 'TEntry' and entry.shown_message == ''


def test_add_stays_disabled_until_the_required_fields_are_valid(page):
    root, conf, _ = page
    ed = conf.route_editor
    assert ed.add_btn.instate(['disabled'])
    ed.vars['network'].set('10.10.0.0'); ed.vars['mask'].set('255.255.0.0')
    assert ed.add_btn.instate(['disabled'])
    ed.vars['next_hop'].set('192.168.1.254')
    assert not ed.add_btn.instate(['disabled'])
    assert conf.add_vlan_btn.instate(['disabled'])
    conf.vid.set('5000')
    assert conf.add_vlan_btn.instate(['disabled'])
    conf.vid.set('10')
    assert not conf.add_vlan_btn.instate(['disabled'])


def test_route_examples_on_the_page(page):
    root, conf, shown = page
    ed = conf.route_editor
    for network, ok in (('10.10.0.0', True), ('10.10.5.1', False), ('0.0.0.0', False)):
        ed.vars['network'].set(network)
        ed.vars['mask'].set('0.0.0.0' if network == '0.0.0.0' else '255.255.0.0')
        ed.vars['next_hop'].set('192.168.1.254')
        assert (ed.add() is not None) is ok
    assert ed.items == [{'network': '10.10.0.0', 'mask': '255.255.0.0',
                         'next_hop': '192.168.1.254'}]
    assert ed.entries['network'].shown_message == \
        'Use Basics > Default route for the default route.'
    assert shown[-2][2] == 'Use the network address: 10.10.0.0'


def test_dhcp_gateway_outside_the_network_is_marked(page):
    root, conf, _ = page
    for key, value in (('pool', 'LAN'), ('network', '192.168.10.0'),
                       ('mask', '255.255.255.0'), ('gateway', '10.0.0.1')):
        conf.dhcp[key].set(value)
    assert 'not inside' in conf.dhcp_entries['gateway'].shown_message
    conf.dhcp['gateway'].set('192.168.10.1')
    assert conf.dhcp_entries['gateway'].shown_message == ''


def test_preview_is_blocked_with_a_list_of_problems(page, monkeypatch):
    root, conf, shown = page
    monkeypatch.setattr(conf, 'selected_devices', lambda: [{'id': 1, 'name': 'R1',
                                                            'ip': '10.0.0.1', 'type': 'router'}])
    monkeypatch.setattr(conf, 'config_kind', lambda: 'router')
    conf.hostname.set('R1 main')
    conf.dhcp['gateway'].set('10.0.0.1')
    conf.make_preview()
    title, text = shown[-1][1:]
    assert title.startswith('Cannot preview')
    assert 'Basics > Hostname: No spaces allowed in a hostname.' in text
    assert 'DHCP > DHCP pool name: Required when any DHCP field is filled in.' in text
    assert conf.preview.get('1.0', 'end').strip() == ''


def test_switch_fields(page):
    root, conf, _ = page
    conf.trunk_editor.vars['ports'].set('Fa0/1-5, Gi0/1')
    conf.trunk_editor.vars['allowed'].set('10,20,40-30')
    assert 'reversed' in conf.trunk_editor.entries['allowed'].shown_message
    assert conf.trunk_editor.entries['ports'].shown_message == ''
    conf.switch_if_editor.vars['description'].set('test; reload')
    assert 'not allowed' in conf.switch_if_editor.entries['description'].shown_message
    conf.vid.set('1')
    assert 'default VLAN' in conf.vid_entry.shown_message          # a warning, not a block
    assert not conf.add_vlan_btn.instate(['disabled'])
    conf.add_vlan()
    conf.vid.set('1')
    assert 'already in the list' in conf.vid_entry.shown_message
    conf.port.set('Fa0/1'); conf.port_vlan.set('30')
    assert 'must already exist on the device' in conf.port_vlan_entry.shown_message
