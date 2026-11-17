"""Port ranges, the switch and router command builders, and the new input checks."""
import pytest

import validation
from config import commands_router, commands_switch
from config.interfaces import PortError, first_port, interface_lines, parse_ports, port_count


# ---------------------------------------------------------------- port ranges
@pytest.mark.parametrize('typed, expected', [
    ('Fa0/1-Fa0/5', ['interface range FastEthernet0/1 - 5']),
    ('Fa0/1-5', ['interface range FastEthernet0/1 - 5']),
    ('fa0/1 - 5', ['interface range FastEthernet0/1 - 5']),
    ('FastEthernet0/1-FastEthernet0/5', ['interface range FastEthernet0/1 - 5']),
    ('Gi0/1-2', ['interface range GigabitEthernet0/1 - 2']),
    ('GigabitEthernet1/0/1-24', ['interface range GigabitEthernet1/0/1 - 24']),
    ('Fa0/1-5, Fa0/10-12', ['interface range FastEthernet0/1 - 5 , FastEthernet0/10 - 12']),
    ('Fa0/1-5,Gi0/1', ['interface range FastEthernet0/1 - 5 , GigabitEthernet0/1']),
    ('Fa0/1, Fa0/3', ['interface range FastEthernet0/1 , FastEthernet0/3']),
    ('Fa0/1', ['interface Fa0/1']),                       # one port: as typed
    ('GigabitEthernet0/2', ['interface GigabitEthernet0/2']),
])
def test_interface_lines(typed, expected):
    assert interface_lines(typed) == expected


def test_more_than_five_pieces_are_split():
    lines = interface_lines('Fa0/1, Fa0/3, Fa0/5, Fa0/7, Fa0/9, Fa0/11, Fa0/13')
    assert lines == ['interface range FastEthernet0/1 , FastEthernet0/3 , FastEthernet0/5 , '
                     'FastEthernet0/7 , FastEthernet0/9',
                     'interface range FastEthernet0/11 , FastEthernet0/13']


@pytest.mark.parametrize('typed, words', [
    ('Fa0/5-1', 'reversed'),
    ('Fa0/5-Fa0/1', 'reversed'),
    ('Fa0/3-3', 'same port'),
    ('Fa0/1-Gi0/5', 'one interface type'),
    ('Fa0/1-Fa1/5', 'one slot'),
    ('Fa0/1-5, Fa0/3', 'more than once'),
    ('Fa0/1,,Fa0/2', 'empty item'),
    ('', 'Enter a port'),
    ('Xy0/1', 'not a known interface type'),
    ('Fa1', 'slot and a port'),
    ('Fa0/1-abc', 'not a port name'),
    ('hello world', 'not a port name'),
])
def test_bad_ranges_are_refused(typed, words):
    with pytest.raises(PortError) as err:
        parse_ports(typed)
    assert words in str(err.value)
    assert validation.check_port_list(typed) == str(err.value)


def test_parse_details():
    assert parse_ports('Gi1/0/1-24') == [{'type': 'GigabitEthernet', 'prefix': '1/0/',
                                          'start': 1, 'end': 24}]
    assert port_count('Fa0/1-5, Gi0/1') == 6
    assert first_port('Fa0/3-8') == 'FastEthernet0/3'
    assert validation.check_port_list('Fa0/1-5') is None
    assert validation.check_single_interface('Gi0/0') is None
    assert 'one interface' in validation.check_single_interface('Gi0/0-1')


# ---------------------------------------------------------------- switch commands
def test_access_range_matches_the_requested_output():
    cmds, checks = commands_switch.build_commands({'access_ports': [('Fa0/1-Fa0/5', 10)]},
                                                  ['Access ports'])
    assert cmds == ['interface range FastEthernet0/1 - 5', 'switchport mode access',
                    'switchport access vlan 10']
    assert checks == [('show running-config interface FastEthernet0/1',
                       'switchport access vlan 10')]


def test_access_body_repeats_for_each_range_command():
    spec = 'Fa0/1, Fa0/3, Fa0/5, Fa0/7, Fa0/9, Fa0/11'
    cmds, _ = commands_switch.access_port_commands({'access_ports': [(spec, 20)]})
    assert cmds.count('switchport access vlan 20') == 2
    assert cmds[3].startswith('interface range FastEthernet0/11')


def test_single_access_port_still_works():
    cmds, _ = commands_switch.access_port_commands({'access_ports': [('Fa0/1', 10)]})
    assert cmds == ['interface Fa0/1', 'switchport mode access', 'switchport access vlan 10']


def test_trunk_commands():
    plan = {'trunks': [{'ports': 'Gi0/1-2', 'allowed': '10,20,30-32', 'native': 99,
                        'encapsulation': True}]}
    cmds, checks = commands_switch.build_commands(plan, ['Trunk ports'])
    assert cmds == ['interface range GigabitEthernet0/1 - 2',
                    'switchport trunk encapsulation dot1q', 'switchport mode trunk',
                    'switchport trunk native vlan 99', 'switchport trunk allowed vlan 10,20,30-32']
    show = 'show running-config interface GigabitEthernet0/1'
    assert (show, 'switchport mode trunk') in checks
    assert (show, 'switchport trunk allowed vlan 10,20,30-32') in checks
    assert (show, 'switchport trunk native vlan 99') in checks


def test_trunk_without_options():
    cmds, checks = commands_switch.trunk_commands(
        {'trunks': [{'ports': 'Gi0/1', 'allowed': '', 'native': None, 'encapsulation': False}]})
    assert cmds == ['interface Gi0/1', 'switchport mode trunk']
    assert len(checks) == 1


def test_port_security_and_interface_settings():
    plan = {'port_security': [{'ports': 'Fa0/1-4', 'maximum': 2, 'violation': 'restrict',
                               'sticky': True}],
            'interfaces': [{'ports': 'Fa0/24', 'description': 'Uplink to R1',
                            'state': 'shutdown'}]}
    cmds, checks = commands_switch.build_commands(plan, ['Interface settings', 'Port security'])
    assert cmds[:6] == ['interface range FastEthernet0/1 - 4', 'switchport mode access',
                        'switchport port-security', 'switchport port-security maximum 2',
                        'switchport port-security violation restrict',
                        'switchport port-security mac-address sticky']
    assert cmds[6:] == ['interface Fa0/24', 'description Uplink to R1', 'shutdown']
    assert ('show running-config interface FastEthernet0/24', '\n shutdown') in checks


def test_vlans_come_before_ports():
    plan = {'vlans': [(10, 'STAFF')], 'access_ports': [('Fa0/1-2', 10)]}
    cmds, _ = commands_switch.build_commands(plan, ['Access ports', 'VLANs'])
    assert cmds[:2] == ['vlan 10', 'name STAFF']


# ---------------------------------------------------------------- router commands
def test_router_commands():
    plan = {'hostname': 'R1',
            'interfaces': [{'name': 'Gi0/0', 'ip': '192.168.1.1', 'mask': '255.255.255.0',
                            'description': 'LAN', 'state': 'no shutdown'}],
            'static_routes': [('10.10.0.0', '255.255.0.0', '192.168.1.254')],
            'default_route': '192.168.1.254',
            'dns_servers': ['8.8.8.8', '1.1.1.1'], 'ntp_server': '192.168.1.10',
            'dhcp': {'pool': 'LAN', 'network': '192.168.1.0', 'mask': '255.255.255.0',
                     'gateway': '192.168.1.1', 'dns': '8.8.8.8',
                     'excluded': ('192.168.1.1', '192.168.1.20')}}
    cmds, checks = commands_router.build_commands(plan, list(commands_router.ROUTER_FEATURES))
    assert cmds == ['hostname R1',
                    'interface Gi0/0', 'description LAN', 'ip address 192.168.1.1 255.255.255.0',
                    'no shutdown',
                    'ip dhcp excluded-address 192.168.1.1 192.168.1.20', 'ip dhcp pool LAN',
                    'network 192.168.1.0 255.255.255.0', 'default-router 192.168.1.1',
                    'dns-server 8.8.8.8',
                    'ip route 0.0.0.0 0.0.0.0 192.168.1.254',
                    'ip route 10.10.0.0 255.255.0.0 192.168.1.254',
                    'ip name-server 8.8.8.8 1.1.1.1', 'ntp server 192.168.1.10']
    assert ('show ip interface brief', '192.168.1.1') in checks
    assert ('show running-config | include ip route',
            'ip route 10.10.0.0 255.255.0.0 192.168.1.254') in checks
    assert ('show running-config | include ntp server', 'ntp server 192.168.1.10') in checks


def test_router_interface_state_only():
    cmds, checks = commands_router.interface_commands(
        {'interfaces': [{'name': 'Gi0/1', 'ip': '', 'mask': '', 'description': '',
                         'state': 'shutdown'}]})
    assert cmds == ['interface Gi0/1', 'shutdown'] and checks == []


# ---------------------------------------------------------------- input checks
def test_vlan_lists():
    assert validation.vlan_list('10, 20,30-32') == [10, 20, 30, 31, 32]
    assert validation.compress_vlans([30, 10, 31, 32, 20]) == '10,20,30-32'
    assert 'reversed' in validation.check_vlan_list('40-30')
    assert 'outside' in validation.check_vlan_list('5000')
    assert validation.check_vlan_list('10,,20') is not None
    assert validation.check_vlan_number('1') is None
    assert validation.check_vlan_number('1', allow_1=False) is not None


@pytest.mark.parametrize('fn, args, ok', [
    (validation.check_hostname, ('R1',), True),
    (validation.check_hostname, ('1R',), False),
    (validation.check_hostname, ('core router',), False),
    (validation.check_hostname, ('edge-',), False),
    (validation.check_description, ('Uplink to R1',), True),
    (validation.check_description, ('what?',), False),
    (validation.check_description, ('x' * 201,), False),
    (validation.check_network, ('10.10.0.0', '255.255.0.0'), True),
    (validation.check_network, ('10.10.1.0', '255.255.0.0'), False),
    (validation.check_network, ('10.10.0.0', '255.0.255.0'), False),
    (validation.check_host_address, ('192.168.1.1', '255.255.255.0'), True),
    (validation.check_host_address, ('192.168.1.0', '255.255.255.0'), False),
    (validation.check_host_address, ('192.168.1.255', '255.255.255.0'), False),
    (validation.check_ip_in_network, ('192.168.1.1', '192.168.1.0', '255.255.255.0'), True),
    (validation.check_ip_in_network, ('192.168.2.1', '192.168.1.0', '255.255.255.0'), False),
    (validation.check_ip_order, ('192.168.1.1', '192.168.1.20'), True),
    (validation.check_ip_order, ('192.168.1.20', '192.168.1.1'), False),
])
def test_checks(fn, args, ok):
    assert (fn(*args) is None) == ok


def test_network_check_suggests_the_right_address():
    assert 'Did you mean 10.10.0.0' in validation.check_network('10.10.1.0', '255.255.0.0')
