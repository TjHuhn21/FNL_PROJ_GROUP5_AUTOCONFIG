import os, sys
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))
sys.path.insert(0, os.path.dirname(__file__))
import pytest

from discovery import crawler
from fakes import FakeConn, cdp_text, fake_login_factory, lab

CORE = '192.168.1.2'


def by_name(devices):
    return {d['name']: d for d in devices}


def test_parse_cdp_reads_ports_ips_and_types():
    text = cdp_text([('SW2.lab.local', '192.168.1.4', 'Switch IGMP', 'GigabitEthernet0/2', 'FastEthernet0/1'),
                     ('R1', '192.168.1.1', 'Router Source-Route-Bridge', 'GigabitEthernet0/3', 'GigabitEthernet0/0')])
    sw2, r1 = crawler.parse_cdp(text)
    assert sw2 == {'name': 'SW2', 'ip': '192.168.1.4', 'local_port': 'Gi0/2', 'remote_port': 'Fa0/1',
                   'platform': 'cisco IOSv', 'type': 'switch'}
    assert r1['type'] == 'router' and r1['name'] == 'R1'
    assert crawler.parse_cdp('') == [] and crawler.parse_cdp('% CDP is not enabled') == []


def test_parse_lldp():
    text = """------------------------------------------------
Local Intf: Gi0/1
Chassis id: 5254.0012.3456
Port id: Gi0/2
Port Description: uplink
System Name: SW9.lab.local

System Capabilities: B,R
Enabled Capabilities: B
Management Addresses:
    IP: 192.168.1.9
"""
    (n,) = crawler.parse_lldp(text)
    assert (n['name'], n['ip'], n['local_port'], n['remote_port'], n['type']) == \
           ('SW9', '192.168.1.9', 'Gi0/1', 'Gi0/2', 'switch')


def test_helpers():
    assert crawler.short_port('TenGigabitEthernet1/0/1') == 'Te1/0/1'
    assert crawler.short_name('SW1(FOC1234ABCD)') == 'SW1' and crawler.short_name('10.0.0.9') == '10.0.0.9'
    assert crawler.guess_type('Router Switch IGMP') == 'switch' and crawler.guess_type('Host Phone') == 'unknown'


def test_crawl_finds_the_whole_lab(monkeypatch):
    visited = []
    monkeypatch.setattr(crawler, '_login', fake_login_factory(lab(), visited=visited))
    devices, links = crawler.discover('admin', 'cisco123', CORE, login_neighbours=True)
    d = by_name(devices)
    assert set(d) == {'CORE', 'SW1', 'SW2', 'SW3', 'R1'}
    assert d['R1']['type'] == 'router' and d['CORE']['type'] == 'switch'
    assert d['SW3']['managed'] is False                        # T3: different password -> gray
    assert all(d[n]['managed'] for n in ('CORE', 'SW1', 'SW2', 'R1'))
    assert len(links) == 4 and ('CORE', 'Gi0/1', 'SW1', 'Gi0/1') in links
    assert ('SW2', 'Gi0/2', 'SW3', 'Gi0/1') in links
    assert len(visited) == len(set(visited))                   # nobody visited twice


@pytest.mark.parametrize('start', ['192.168.1.3', '192.168.1.4', '192.168.1.1'])
def test_same_map_from_any_plug_in_point(monkeypatch, start):   # T2
    monkeypatch.setattr(crawler, '_login', fake_login_factory(lab()))
    devices, links = crawler.discover('admin', 'cisco123', start, login_neighbours=True)
    assert {x['name'] for x in devices} == {'CORE', 'SW1', 'SW2', 'SW3', 'R1'} and len(links) == 4


def test_progress_messages(monkeypatch):
    monkeypatch.setattr(crawler, '_login', fake_login_factory(lab()))
    messages = []
    crawler.discover('admin', 'cisco123', CORE, progress=messages.append, login_neighbours=True)
    assert any('CORE' in m for m in messages) and any('unmanaged' in m for m in messages)


def test_wrong_login_on_the_starting_device_gives_a_clear_error(monkeypatch):
    monkeypatch.setattr(crawler, '_login', fake_login_factory(lab()))
    with pytest.raises(RuntimeError) as err:
        crawler.discover('admin', 'wrong', CORE)
    assert 'starting device' in str(err.value) and 'username or password' in str(err.value)


def test_unreachable_start_says_no_answer(monkeypatch):
    monkeypatch.setattr(crawler, '_login', fake_login_factory(lab()))
    with pytest.raises(RuntimeError) as err:
        crawler.discover('admin', 'cisco123', '10.9.9.9')
    assert 'no answer' in str(err.value)


def test_safety_limit(monkeypatch):
    chain = {f'10.0.0.{i}': dict(name=f'S{i}', kind='switch', nbrs=[
        (f'S{i+1}', f'10.0.0.{i+1}', 'Switch', 'GigabitEthernet0/1', 'GigabitEthernet0/2')])
        for i in range(1, 20)}
    monkeypatch.setattr(crawler, '_login', fake_login_factory(chain))
    messages = []
    devices, _ = crawler.discover('admin', 'cisco123', '10.0.0.1', progress=messages.append, max_devices=5,
                                  login_neighbours=True)
    assert sum(d['managed'] for d in devices) == 5 and any('safety limit' in m for m in messages)


def test_two_switches_with_the_same_hostname_get_unique_names(monkeypatch):
    net = {'10.0.0.1': dict(name='Switch', kind='switch', nbrs=[
               ('Switch', '10.0.0.2', 'Switch', 'GigabitEthernet0/1', 'GigabitEthernet0/1')]),
           '10.0.0.2': dict(name='Switch', kind='switch', nbrs=[
               ('Switch', '10.0.0.1', 'Switch', 'GigabitEthernet0/1', 'GigabitEthernet0/1')])}
    monkeypatch.setattr(crawler, '_login', fake_login_factory(net))
    devices, links = crawler.discover('admin', 'cisco123', '10.0.0.1')
    assert sorted(d['name'] for d in devices) == ['Switch', 'Switch-2'] and len(links) == 1


def test_neighbor_without_ip_is_skipped_and_lldp_is_the_fallback(monkeypatch):
    class LldpOnly(FakeConn):
        def send_command(self, cmd, **kw):
            if cmd == 'show cdp neighbors detail':
                return '% CDP is not enabled'
            if cmd == 'show lldp neighbors detail':
                if self.info['name'] != 'A':
                    return ''                      # only A has LLDP neighbors
                return ("------------------------------------------------\nLocal Intf: Gi0/1\nPort id: Gi0/1\n"
                        "System Name: PEER\nEnabled Capabilities: B\nManagement Addresses:\n    IP: 10.0.0.2\n"
                        "------------------------------------------------\nLocal Intf: Gi0/2\nPort id: Gi0/1\n"
                        "System Name: NOIP\nEnabled Capabilities: B\n")
            return super().send_command(cmd, **kw)
    infos = {'10.0.0.1': dict(name='A', kind='switch', nbrs=[]), '10.0.0.2': dict(name='PEER', kind='switch', nbrs=[])}
    def login(ip, u, p):
        if ip not in infos: raise Exception('x')
        return LldpOnly(infos[ip])
    monkeypatch.setattr(crawler, '_login', login)
    messages = []
    devices, links = crawler.discover('u', 'p', '10.0.0.1', progress=messages.append)
    assert {d['name'] for d in devices} == {'A', 'PEER'} and len(links) == 1
    assert any('NOIP' in m and 'skipped' in m for m in messages)


def test_demo_mode_returns_copies():
    devices, links = crawler.discover_demo()
    devices[0]['name'] = 'CHANGED'
    assert crawler.discover_demo()[0][0]['name'] == 'CORE' and len(links) == 4


# ---------------------------------------------------------------- seed-only scanning (Phase 2)
@pytest.fixture
def no_network(monkeypatch):
    """Any attempt to run a program (arp, route, ping) or open a socket fails the test."""
    import socket, subprocess
    def forbidden(*a, **k):
        raise AssertionError('the scan tried to reach something other than the seed')
    monkeypatch.setattr(subprocess, 'run', forbidden)
    monkeypatch.setattr(socket, 'create_connection', forbidden)


def test_default_scan_logs_in_to_the_seed_only(monkeypatch, no_network):
    visited, messages = [], []
    monkeypatch.setattr(crawler, '_login', fake_login_factory(lab(), visited=visited))
    devices, links = crawler.discover('admin', 'cisco123', CORE, progress=messages.append)
    assert visited == [CORE]                                     # the login went to the seed only
    d = by_name(devices)
    assert set(d) == {'CORE', 'SW1', 'SW2', 'R1'}                # its CDP neighbours are listed
    assert d['CORE']['managed'] is True
    assert not any(d[n]['managed'] for n in ('SW1', 'SW2', 'R1'))
    assert d['R1']['type'] == 'router' and d['SW1']['type'] == 'switch'   # from CDP capabilities
    assert set(links) == {('CORE', 'Gi0/1', 'SW1', 'Gi0/1'), ('CORE', 'Gi0/2', 'SW2', 'Gi0/1'),
                          ('CORE', 'Gi0/3', 'R1', 'Gi0/0')}      # the seed's links are kept
    assert any('not logged in' in m for m in messages)


def test_lldp_neighbours_are_not_logged_in_by_default(monkeypatch, no_network):
    class LldpOnly(FakeConn):
        def send_command(self, cmd, **kw):
            if cmd == 'show cdp neighbors detail':
                return '% CDP is not enabled'
            if cmd == 'show lldp neighbors detail':
                return ("------------------------------------------------\nLocal Intf: Gi0/1\n"
                        "Port id: Gi0/2\nSystem Name: PEER\nEnabled Capabilities: B\n"
                        "Management Addresses:\n    IP: 10.0.0.2\n")
            return super().send_command(cmd, **kw)
    visited = []
    def login(ip, u, p):
        visited.append(ip)
        return LldpOnly(dict(name='A', kind='switch', nbrs=[]))
    monkeypatch.setattr(crawler, '_login', login)
    devices, links = crawler.discover('u', 'p', '10.0.0.1')
    assert visited == ['10.0.0.1']
    assert {(d['name'], d['managed']) for d in devices} == {('A', True), ('PEER', False)}
    assert links == [('A', 'Gi0/1', 'PEER', 'Gi0/2')]


def test_failed_seed_login_never_contacts_any_other_device(monkeypatch, no_network):
    visited = []
    monkeypatch.setattr(crawler, '_login', fake_login_factory(lab(), visited=visited))
    for password in ('wrong', 'cisco123'):
        visited.clear()
        seed = CORE if password == 'wrong' else '192.168.1.254'       # wrong login / no answer
        with pytest.raises(RuntimeError) as err:
            crawler.discover('admin', password, seed, login_neighbours=True)
        assert visited == [seed] and 'starting device' in str(err.value)
    assert not hasattr(crawler, 'arp_candidates') and not hasattr(crawler, 'port_open')
    assert not hasattr(crawler, 'default_gateway')


@pytest.mark.parametrize('seed', ['', '   ', None])
def test_a_real_scan_needs_an_explicit_seed_ip(monkeypatch, no_network, seed):
    visited = []
    monkeypatch.setattr(crawler, '_login', fake_login_factory(lab(), visited=visited))
    with pytest.raises(ValueError) as err:
        crawler.discover('admin', 'cisco123', seed)
    assert 'seed IP is required' in str(err.value) and visited == []


def test_an_invalid_seed_ip_is_refused_before_any_login(monkeypatch, no_network):
    visited = []
    monkeypatch.setattr(crawler, '_login', fake_login_factory(lab(), visited=visited))
    with pytest.raises(ValueError) as err:
        crawler.discover('admin', 'cisco123', '999.1.1.1')
    assert 'IPv4' in str(err.value) and visited == []


def test_neighbour_login_failure_is_reported_without_secrets(monkeypatch):
    messages = []
    monkeypatch.setattr(crawler, '_login', fake_login_factory(lab()))
    crawler.discover('admin', 'cisco123', CORE, progress=messages.append, login_neighbours=True)
    sw3 = [m for m in messages if m.startswith('192.168.1.5')]
    assert sw3 and 'rejected the username or password' in sw3[0] and 'cisco123' not in sw3[0]


def test_services_run_discovery_is_seed_only_unless_asked(monkeypatch):
    import services
    visited = []
    monkeypatch.setattr(crawler, '_login', fake_login_factory(lab(), visited=visited))
    services.run_discovery('admin', 'cisco123', CORE, False)
    assert visited == [CORE]
    visited.clear()
    services.run_discovery('admin', 'cisco123', CORE, False, True)
    assert set(visited) == {'192.168.1.1', '192.168.1.2', '192.168.1.3', '192.168.1.4', '192.168.1.5'}


# ---------------------------------------------------------------- device type (physical-test issue 3)
C1941_VERSION = """Cisco IOS Software, C1900 Software (C1900-UNIVERSALK9-M), Version 15.4(3)M2, RELEASE SOFTWARE (fc2)
Technical Support: http://www.cisco.com/techsupport
ROM: System Bootstrap, Version 15.0(1r)M15, RELEASE SOFTWARE (fc1)
BRANCH uptime is 2 hours, 5 minutes
System image file is "flash0:c1900-universalk9-mz.SPA.154-3.M2.bin"
Cisco CISCO1941/K9 (revision 1.0) with 491520K/32768K bytes of memory.
2 Gigabit Ethernet interfaces
Configuration register is 0x2102
"""
C2960_VERSION = """Cisco IOS Software, C2960 Software (C2960-LANBASEK9-M), Version 15.0(2)SE11, RELEASE SOFTWARE (fc3)
cisco WS-C2960-24TT-L (PowerPC405) processor (revision B0) with 65536K bytes of memory.
Model number                    : WS-C2960-24TT-L
"""
VLAN_TABLE = """VLAN Name                             Status    Ports
---- -------------------------------- --------- -------------------------------
1    default                          active    Fa0/1, Fa0/2
"""


class ShowConn:
    """A logged-in device that answers show commands from a dict (an Exception = fails)."""
    def __init__(self, name, answers):
        self.name, self.answers, self.sent = name, answers, []

    def find_prompt(self):
        return self.name + '#'

    def send_command(self, cmd, **kw):
        self.sent.append(cmd)
        answer = self.answers.get(cmd, '')
        if isinstance(answer, Exception):
            raise answer
        return answer


@pytest.mark.parametrize('vlan_answer', [
    '% Ambiguous command:  "show vlan"',                # what an ISR router can print
    '% Invalid input detected at \'^\' marker.',
    VLAN_TABLE,                                        # even a VLAN-looking answer: the model wins
    TimeoutError('read timed out'),
])
def test_cisco_1900_router_is_classified_as_a_router(vlan_answer):
    conn = ShowConn('BRANCH', {'show version': C1941_VERSION, 'show vlan brief': vlan_answer})
    name, kind, _ = crawler._read_device(conn)
    assert (name, kind) == ('BRANCH', 'router')


def test_router_is_found_through_a_real_scan(monkeypatch):
    conn = ShowConn('BRANCH', {'show version': C1941_VERSION,
                               'show vlan brief': '% Ambiguous command:  "show vlan"'})
    monkeypatch.setattr(crawler, '_login', lambda ip, u, p: conn)
    devices, _ = crawler.discover('netadmin', 'x', '192.168.10.1')
    assert [(d['name'], d['type'], d['managed']) for d in devices] == [('BRANCH', 'router', True)]


def test_cisco_switch_classification_still_works():
    by_model = ShowConn('SW1', {'show version': C2960_VERSION, 'show vlan brief': VLAN_TABLE})
    assert crawler._read_device(by_model)[1] == 'switch'
    no_model = ShowConn('SW2', {'show version': 'Cisco IOS Software, unknown build',
                                'show vlan brief': VLAN_TABLE})
    assert crawler._read_device(no_model)[1] == 'switch'           # the VLAN table decides


def test_unidentifiable_device_is_unknown_not_switch():
    nothing = ShowConn('X1', {'show version': TimeoutError('t'), 'show vlan brief': TimeoutError('t')})
    assert crawler._read_device(nothing)[1] == 'unknown'
    odd = ShowConn('X2', {'show version': 'Some other OS', 'show vlan brief': 'nothing useful'})
    assert crawler._read_device(odd)[1] == 'unknown'


@pytest.mark.parametrize('text, kind', [
    ('Cisco CISCO1941/K9 (revision 1.0)', 'router'), ('cisco CISCO1921/K9', 'router'),
    ('Cisco CISCO1941W-E/K9', 'router'), ('C1900 Software (C1900-UNIVERSALK9-M)', 'router'),
    ('cisco CISCO2911/K9', 'router'), ('cisco ISR4331/K9 (1RU) processor', 'router'),
    ('Cisco C891F-K9', 'router'), ('IOSv Software (VIOS-ADVENTERPRISEK9-M)', 'router'),
    ('cisco WS-C2960-24TT-L', 'switch'), ('C2960 Software (C2960-LANBASEK9-M)', 'switch'),
    ('cisco WS-C3560-24PS-S', 'switch'), ('cisco WS-C3850-24T', 'switch'),
    ('cisco C9300-24T', 'switch'), ('vios_l2 Software (vios_l2-ADVENTERPRISEK9-M)', 'switch'),
    ('cisco IOSv', None), ('', None)])
def test_platform_families(text, kind):
    assert crawler.platform_type(text) == kind


def test_cdp_neighbour_router_that_also_reports_switch_is_a_router():
    text = cdp_text([('BRANCH', '192.168.10.1', 'Router Switch IGMP', 'GigabitEthernet0/1',
                      'GigabitEthernet0/0')]).replace('cisco IOSv', 'Cisco CISCO1941/K9')
    (n,) = crawler.parse_cdp(text)
    assert n['type'] == 'router' and n['platform'] == 'Cisco CISCO1941/K9'
    switch = cdp_text([('SW9', '10.0.0.9', 'Router Switch IGMP', 'GigabitEthernet0/1',
                        'GigabitEthernet0/2')]).replace('cisco IOSv', 'cisco WS-C3560-24PS')
    assert crawler.parse_cdp(switch)[0]['type'] == 'switch'


def test_lldp_neighbour_uses_its_system_description():
    text = ("------------------------------------------------\nLocal Intf: Gi0/1\nPort id: Gi0/0\n"
            "System Name: BRANCH\n\nSystem Description: \nCisco IOS Software, C1900 Software "
            "(C1900-UNIVERSALK9-M), Version 15.4(3)M2\n\nEnabled Capabilities: B,R\n"
            "Management Addresses:\n    IP: 192.168.10.1\n")
    assert crawler.parse_lldp(text)[0]['type'] == 'router'
