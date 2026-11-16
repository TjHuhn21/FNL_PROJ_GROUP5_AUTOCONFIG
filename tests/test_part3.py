import os, sys
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))
import sample_data
from review.rules import (rule_telnet, rule_password_encryption, rule_port_security,
                          rule_trunk_all_vlans, review_network, interface_blocks, global_lines)
from topology.graph import find_single_points, draw_map
from config.commands_switch import build_commands
from config import commands_router

CLEAN = """hostname SW1
service password-encryption
line vty 0 4
 transport input ssh
!
interface FastEthernet0/1
 switchport mode access
 switchport port-security
!
interface GigabitEthernet0/1
 switchport mode trunk
 switchport trunk allowed vlan 10,20
!
"""

def test_telnet():
    assert rule_telnet('SW1', 'line vty 0 4\n transport input all\n')[0]['rule'] == 'telnet_enabled'
    assert rule_telnet('SW1', CLEAN) == []

def test_password_encryption():
    assert rule_password_encryption('SW1', 'hostname SW1\n')[0]['severity'] == 'medium'
    assert rule_password_encryption('SW1', CLEAN) == []

def test_port_security():
    cfg = 'interface FastEthernet0/2\n switchport mode access\n!\n'
    f = rule_port_security('SW1', cfg)
    assert len(f) == 1 and 'FastEthernet0/2' in f[0]['message']
    assert rule_port_security('SW1', CLEAN) == []

def test_trunk():
    cfg = 'interface GigabitEthernet0/2\n switchport mode trunk\n!\n'
    assert len(rule_trunk_all_vlans('SW1', cfg)) == 1
    assert rule_trunk_all_vlans('SW1', CLEAN) == []

def test_blocks():
    assert 'FastEthernet0/1' in interface_blocks(CLEAN)

def test_single_points_and_score():
    findings, score = review_network(sample_data.DEVICES, sample_data.LINKS,
                                     {'SW1': 'hostname SW1\nline vty 0 4\n transport input all\n'})
    rules = {f['rule'] for f in findings}
    assert {'telnet_enabled', 'no_password_encryption', 'single_point_of_failure'} <= rules
    assert 0 <= score < 100
    assert 'CORE' in find_single_points(sample_data.DEVICES, sample_data.LINKS)

def test_clean_network_scores_100():
    devs = [{'name': n, 'ip': '', 'mac': '', 'type': 'switch', 'managed': True, 'status': 'up'} for n in 'ABC']
    links = [('A', 'g1', 'B', 'g1'), ('B', 'g2', 'C', 'g1'), ('C', 'g2', 'A', 'g2')]  # ring
    assert review_network(devs, links, {'A': CLEAN}) == ([], 100)

def test_draw_map(tmp_path):
    p = draw_map(sample_data.DEVICES, sample_data.LINKS, str(tmp_path / 'm.png'))
    assert os.path.getsize(p) > 0

def test_three_vlans_and_order():
    plan = {'vlans': [(10, 'SALES'), (20, 'HR'), (30, 'IT')], 'access_ports': [('Fa0/1', 10)]}
    cmds, checks = build_commands(plan, ['Access ports', 'VLANs'])  # wrong order on purpose
    assert cmds[:6] == ['vlan 10', 'name SALES', 'vlan 20', 'name HR', 'vlan 30', 'name IT']
    assert cmds.index('vlan 10') < cmds.index('interface Fa0/1')
    assert ('show vlan brief', 'HR') in checks

def test_router():
    plan = {'default_route': '192.168.1.1',
            'dhcp': {'pool': 'LAN', 'network': '192.168.1.0', 'mask': '255.255.255.0',
                     'gateway': '192.168.1.1', 'dns': '8.8.8.8',
                     'excluded': ('192.168.1.1', '192.168.1.20')}}
    cmds, checks = commands_router.build_commands(plan, ['Default route', 'DHCP'])
    assert cmds[0] == 'ip dhcp excluded-address 192.168.1.1 192.168.1.20'
    assert cmds[-1] == 'ip route 0.0.0.0 0.0.0.0 192.168.1.1'


# ---------------------------------------------------------------- B2: password-encryption rule
# What a real switch prints for "show running-config" (encryption OFF, the IOS default).
REAL_IOS = """Building configuration...

Current configuration : 1520 bytes
!
version 15.2
service timestamps debug datetime msec
service timestamps log datetime msec
no service password-encryption
!
hostname SW1
!
username admin privilege 15 secret 9 $9$abc$def
!
banner motd ^C
 Authorized access only.
 service password-encryption is planned for next week.
^C
!
interface FastEthernet0/1
 description reminder: service password-encryption
 switchport access vlan 10
 switchport mode access
 switchport port-security
!
interface GigabitEthernet0/1
 switchport trunk allowed vlan 10,20
 switchport mode trunk
!
line vty 0 4
 login local
 transport input ssh
!
end
"""
REAL_IOS_ON = REAL_IOS.replace('no service password-encryption', 'service password-encryption')


def pw_finding(config):
    """True when the rule reports password encryption as off."""
    return bool(rule_password_encryption('SW1', config))


def test_pw_no_form_is_a_finding():                                   # the B2 regression
    assert pw_finding('hostname SW1\nno service password-encryption\n')
    assert pw_finding(REAL_IOS)


def test_pw_enabled_is_clean():
    assert not pw_finding('hostname SW1\nservice password-encryption\n')
    assert not pw_finding(REAL_IOS_ON)


def test_pw_missing_line_is_a_finding():                               # IOS default is off
    assert pw_finding('hostname SW1\n') and pw_finding('')


def test_pw_last_line_wins():
    assert pw_finding('service password-encryption\nno service password-encryption\n')
    assert not pw_finding('no service password-encryption\nservice password-encryption\n')


def test_pw_comments_do_not_count():
    assert pw_finding('! service password-encryption\n!service password-encryption\n')


def test_pw_indented_text_does_not_count():
    assert pw_finding('interface Fa0/1\n description service password-encryption\n'
                      ' service password-encryption\n!\n')


def test_pw_multiline_banner_does_not_count():
    cfg = ('banner motd ^C\nservice password-encryption\nno service password-encryption\n^C\n'
           'hostname SW1\n')
    assert pw_finding(cfg)
    # a command AFTER the banner is still read
    assert not pw_finding(cfg + 'service password-encryption\n')


def test_pw_single_line_banner_does_not_count():
    assert pw_finding('banner motd ^Cservice password-encryption^C\nhostname SW1\n')
    assert pw_finding('banner login #service password-encryption#\n')
    assert not pw_finding('banner motd ^CHello^C\nservice password-encryption\n')
    assert not pw_finding('banner exec #Hello#\nservice password-encryption\n')


def test_pw_line_endings_and_spaces():
    assert not pw_finding('hostname SW1\r\nservice password-encryption   \r\n')
    assert not pw_finding('service  password-encryption\n')
    assert pw_finding('hostname SW1\r\nno service password-encryption \r\n')


def test_pw_look_alike_lines_do_not_count():
    assert pw_finding('service password-encryption-x\n')
    assert pw_finding('xservice password-encryption\n')
    assert not pw_finding('service password-encryption\nno service password-encryption extra\n')


def test_pw_finding_text():
    (f,) = rule_password_encryption('SW1', REAL_IOS)
    assert (f['rule'], f['severity'], f['commands']) == \
        ('no_password_encryption', 'medium', ['service password-encryption'])
    assert f['message'] == ('Password protection is disabled. Passwords may appear in clear '
                            'text in the configuration.')


def test_global_lines_keeps_only_global_commands():
    assert list(global_lines(REAL_IOS)) == [
        'Building configuration...', 'Current configuration : 1520 bytes', 'version 15.2',
        'service timestamps debug datetime msec', 'service timestamps log datetime msec',
        'no service password-encryption', 'hostname SW1',
        'username admin privilege 15 secret 9 $9$abc$def',
        'interface FastEthernet0/1', 'interface GigabitEthernet0/1', 'line vty 0 4', 'end']


def test_real_config_review_only_password_rule_changes():
    """On a full real config the other rules give the same results either way."""
    devs = [{'name': n, 'ip': '', 'mac': '', 'type': 'switch', 'managed': True, 'status': 'up'}
            for n in 'AB']
    links = [('A', 'g1', 'B', 'g1')]
    off, _ = review_network(devs, links, {'A': REAL_IOS})
    on, score_on = review_network(devs, links, {'A': REAL_IOS_ON})
    assert [f['rule'] for f in off] == ['no_password_encryption']
    assert on == [] and score_on == 100


def test_sample_configs_keep_their_findings():
    assert pw_finding(sample_data.CONFIGS['SW1'])          # SW1 has no encryption line
    assert not pw_finding(sample_data.CONFIGS['SW2'])      # SW2 has "service password-encryption"
    findings, _ = review_network(sample_data.DEVICES, sample_data.LINKS, sample_data.CONFIGS)
    got = sorted((f['device'], f['rule']) for f in findings)
    assert got == sorted([('SW1', 'telnet_enabled'), ('SW1', 'no_password_encryption'),
                          ('SW1', 'no_port_security'), ('SW2', 'no_port_security'),
                          ('SW2', 'trunk_all_vlans'), ('CORE', 'single_point_of_failure'),
                          ('SW2', 'single_point_of_failure')])
