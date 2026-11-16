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
    devices, links = crawler.discover('admin', 'cisco123', CORE)
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
    devices, links = crawler.discover('admin', 'cisco123', start)
    assert {x['name'] for x in devices} == {'CORE', 'SW1', 'SW2', 'SW3', 'R1'} and len(links) == 4


def test_progress_messages(monkeypatch):
    monkeypatch.setattr(crawler, '_login', fake_login_factory(lab()))
    messages = []
    crawler.discover('admin', 'cisco123', CORE, progress=messages.append)
    assert any('CORE' in m for m in messages) and any('unmanaged' in m for m in messages)


def test_wrong_login_on_the_starting_device_gives_a_clear_error(monkeypatch):
    monkeypatch.setattr(crawler, '_login', fake_login_factory(lab()))
    monkeypatch.setattr(crawler, 'arp_candidates', lambda: [])
    with pytest.raises(RuntimeError) as err:
        crawler.discover('admin', 'wrong', CORE)
    assert 'starting device' in str(err.value) and 'username or password' in str(err.value)


def test_unreachable_start_says_no_answer(monkeypatch):
    monkeypatch.setattr(crawler, '_login', fake_login_factory(lab()))
    monkeypatch.setattr(crawler, 'arp_candidates', lambda: [])
    with pytest.raises(RuntimeError) as err:
        crawler.discover('admin', 'cisco123', '10.9.9.9')
    assert 'no answer' in str(err.value)


def test_gateway_without_ssh_falls_back_to_another_local_ssh_host(monkeypatch):
    monkeypatch.setattr(crawler, '_login', fake_login_factory(lab()))
    monkeypatch.setattr(crawler, 'arp_candidates', lambda: ['192.168.1.100', CORE])
    monkeypatch.setattr(crawler, 'port_open', lambda ip, port=22, timeout=1.0: ip == CORE)
    devices, links = crawler.discover('admin', 'cisco123', '192.168.1.254')   # the ISP modem: no SSH
    assert {x['name'] for x in devices} >= {'CORE', 'SW1', 'SW2', 'R1'}


def test_safety_limit(monkeypatch):
    chain = {f'10.0.0.{i}': dict(name=f'S{i}', kind='switch', nbrs=[
        (f'S{i+1}', f'10.0.0.{i+1}', 'Switch', 'GigabitEthernet0/1', 'GigabitEthernet0/2')])
        for i in range(1, 20)}
    monkeypatch.setattr(crawler, '_login', fake_login_factory(chain))
    messages = []
    devices, _ = crawler.discover('admin', 'cisco123', '10.0.0.1', progress=messages.append, max_devices=5)
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


def test_arp_candidates_reads_windows_and_linux_formats(monkeypatch):
    import subprocess
    windows = "  Interface: 192.168.1.10\n  192.168.1.1           aa-bb-cc-dd-ee-ff     dynamic\n  192.168.1.255         ff-ff-ff-ff-ff-ff     static\n  224.0.0.22            01-00-5e-00-00-16     static\n"
    linux = "? (192.168.1.2) at 52:54:00:12:34:56 [ether] on eth0\n? (192.168.1.255) at ff:ff:ff:ff:ff:ff [ether] on eth0\n"
    for text, expected in ((windows, ['192.168.1.1']), (linux, ['192.168.1.2'])):
        monkeypatch.setattr(subprocess, 'run', lambda *a, _t=text, **k: type('R', (), {'stdout': _t})())
        assert crawler.arp_candidates() == expected
