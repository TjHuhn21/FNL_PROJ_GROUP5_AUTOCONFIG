"""The Mock Cisco SSH Lab (mock-lab/): the simulated CLI, the SSH protocol with
the REAL Netmiko ConnectHandler, failure modes, and NetCommand's own unmodified
apply_config / run_devices / discovery against it.

The lab listens on free ports of 127.0.0.1 here (not 127.0.0.11-13:22), so these
tests never clash with a lab you have running. NetCommand always connects to
port 22, so for the NetCommand tests ConnectHandler is wrapped to add the test
port: the real Netmiko ConnectHandler still does all the work.
"""
import os
import sys
import time

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, 'mock-lab'))

netmiko = pytest.importorskip('netmiko')
from netmiko import ConnectHandler  # noqa: E402
from netmiko.exceptions import (NetmikoAuthenticationException,  # noqa: E402
                                NetmikoTimeoutException, ReadTimeout)

from mocklab.cli import Session  # noqa: E402
from mocklab.device import Device  # noqa: E402
from mocklab.lab import Lab, LabError, check_config, load_config  # noqa: E402
from mocklab.server import _loggable  # noqa: E402

CONFIG = load_config()
SPEC = {d['name']: d for d in CONFIG['devices']}
LOCAL = {name: ('127.0.0.1', 0) for name in SPEC}


@pytest.fixture(scope='module')
def key_path(tmp_path_factory):
    return str(tmp_path_factory.mktemp('mocklab-key') / 'host_rsa.key')


@pytest.fixture
def lab(key_path):
    lab = Lab(CONFIG, key_path=key_path, overrides=LOCAL).start()
    yield lab
    lab.stop()


def connect_to(lab, name, user=None, password=None, **extra):
    host, port = lab.address(name)
    spec = SPEC[name]
    kw = dict(device_type='cisco_ios', host=host, port=port,
              username=user or spec['username'], password=password or spec['password'],
              secret=password or spec['password'], conn_timeout=5, auth_timeout=5,
              banner_timeout=5)
    kw.update(extra)
    return ConnectHandler(**kw)


def cli(name):
    """A device and a session, without SSH."""
    dev = Device(SPEC[name], lab_hosts={n: (s['host'], s['type']) for n, s in SPEC.items()})
    return dev, Session(dev)


def run(session, *lines):
    return [session.handle(l).output for l in lines]


# ---------------------------------------------------------------- the simulated CLI (no SSH)
def test_prompts_and_modes():
    dev, s = cli('R1')
    assert s.prompt() == 'R1>'
    assert s.handle('enable').output == 'Password: '
    assert s.handle('wrong').output == '% Access denied' and s.prompt() == 'R1>'
    s.handle('en'); s.handle(SPEC['R1']['password'])
    assert s.prompt() == 'R1#'
    assert 'Enter configuration commands' in s.handle('conf t').output
    assert s.prompt() == 'R1(config)#'
    s.handle('int gi0/2'); assert s.prompt() == 'R1(config-if)#'
    s.handle('ip dhcp pool LAN'); assert s.prompt() == 'R1(dhcp-config)#'     # global from a sub-mode
    s.handle('exit'); assert s.prompt() == 'R1(config)#'
    s.handle('end'); assert s.prompt() == 'R1#'
    sw, t = cli('SW1')
    assert t.prompt() == 'SW1#'                                   # starts privileged
    t.handle('configure terminal'); t.handle('interface range fa0/1 - 3')
    assert t.prompt() == 'SW1(config-if-range)#'
    t.handle('vlan 30'); assert t.prompt() == 'SW1(config-vlan)#'


def test_error_messages_look_like_ios():
    dev, s = cli('SW1')
    out = s.handle('show vlna brief').output
    assert out == ' ' * len('SW1#show ') + "^\n% Invalid input detected at '^' marker."
    assert s.handle('show').output == '% Incomplete command.'
    assert s.handle('sh i').output.startswith('% Ambiguous command')        # interfaces / ip
    assert 'Unknown command' in s.handle('frobnicate').output
    s.handle('conf t')
    assert '% Invalid input' in s.handle('ip route 10.0.0.0 255.0.0.0 1.1.1.1').output   # L2 switch
    assert '% Invalid input' in s.handle('interface FastEthernet0/99').output
    _, r = cli('R1')
    r.handle('enable'); r.handle(SPEC['R1']['password'])
    assert '% Invalid input' in r.handle('show vlan brief').output        # routers have no VLANs


def test_vlans_ranges_access_and_port_security():
    dev, s = cli('SW1')
    run(s, 'conf t', 'vlan 20', 'name SALES', 'interface range FastEthernet0/3 - 5 , Gi0/1',
        'switchport mode access', 'switchport access vlan 20', 'switchport port-security maximum 2',
        'switchport port-security violation restrict', 'switchport port-security mac-address sticky',
        'switchport port-security', 'end')
    brief = s.handle('show vlan brief').output
    assert 'SALES' in brief and 'Fa0/3, Fa0/4, Fa0/5, Gi0/1' in brief
    cfg = s.handle('show running-config interface FastEthernet0/4').output
    for line in ('switchport access vlan 20', 'switchport mode access',
                 'switchport port-security maximum 2', 'switchport port-security violation restrict',
                 'switchport port-security mac-address sticky', '\n switchport port-security\n'):
        assert line in cfg
    s.handle('conf t'); s.handle('int fa0/10')
    assert s.handle('switchport port-security').output == \
        'Command rejected: FastEthernet0/10 is a dynamic port.'
    assert s.handle('switchport access vlan 77').output == \
        '% Access VLAN does not exist. Creating vlan 77'
    s.handle('shutdown'); s.handle('end')
    assert '\n shutdown\n' in s.handle('show running-config interface Fa0/10').output


def test_trunks_differ_per_switch_model():
    dev, s = cli('SW1')                                           # encapsulation required
    run(s, 'conf t', 'int fa0/20')
    assert 'trunk encapsulation is "Auto"' in s.handle('switchport mode trunk').output
    run(s, 'switchport trunk encapsulation dot1q', 'switchport mode trunk',
        'switchport trunk native vlan 99', 'switchport trunk allowed vlan 10,20,30-32', 'end')
    cfg = s.handle('show running-config interface FastEthernet0/20').output
    assert 'switchport trunk allowed vlan 10,20,30-32' in cfg and 'switchport mode trunk' in cfg
    assert 'switchport trunk native vlan 99' in cfg
    assert 'Fa0/20' in s.handle('show interfaces trunk').output
    _, t = cli('SW2')                                             # 802.1Q only
    run(t, 'conf t', 'int gi0/2')
    assert '% Invalid input' in t.handle('switchport trunk encapsulation dot1q').output
    assert t.handle('switchport mode trunk').output == ''


def test_router_interfaces_routes_dhcp_dns_ntp():
    dev, s = cli('R1')
    dev.interfaces['GigabitEthernet0/2'].connected = True        # plug a cable into Gi0/2
    run(s, 'enable', SPEC['R1']['password'], 'conf t', 'interface Gi0/2',
        'ip address 172.16.5.1 255.255.255.0', 'description Branch', 'no shutdown', 'exit',
        'ip route 10.10.0.0 255.255.0.0 172.16.5.254', 'ip route 10.20.0.0 255.255.0.0 9.9.9.9',
        'ip dhcp excluded-address 172.16.5.1 172.16.5.20', 'ip dhcp pool BRANCH',
        'network 172.16.5.0 255.255.255.0', 'default-router 172.16.5.1', 'dns-server 8.8.8.8',
        'exit', 'ip name-server 8.8.8.8 1.1.1.1', 'ntp server 192.168.10.5', 'end')
    brief = s.handle('show ip interface brief').output
    assert 'GigabitEthernet0/2     172.16.5.1      YES manual up' in brief
    route = s.handle('show ip route').output
    assert 'S        10.10.0.0/16 [1/0] via 172.16.5.254' in route
    assert '10.20.0.0' not in route                               # next hop not reachable
    run_cfg = s.handle('show running-config').output
    for line in ('ip route 10.20.0.0 255.255.0.0 9.9.9.9', 'ip name-server 8.8.8.8 1.1.1.1',
                 'ntp server 192.168.10.5', 'ip dhcp excluded-address 172.16.5.1 172.16.5.20',
                 ' default-router 172.16.5.1'):
        assert line in run_cfg
    assert 'Pool BRANCH' in s.handle('show ip dhcp pool').output
    assert s.handle('show running-config | include ip route').output.count('ip route') == 3
    s.handle('conf t'); s.handle('int gi0/2')
    assert 'overlaps with GigabitEthernet0/0' in s.handle('ip address 192.168.10.9 255.255.255.0').output
    assert s.handle('ip route 10.0.0.1 255.0.0.0 1.1.1.1').output == '%Inconsistent address and mask'


def test_an_interface_without_a_cable_stays_down():
    dev, s = cli('R1')                                            # Gi0/2 has no simulated cable
    run(s, 'enable', SPEC['R1']['password'], 'conf t', 'interface Gi0/2',
        'ip address 172.16.5.1 255.255.255.0', 'no shutdown', 'exit',
        'ip route 10.10.0.0 255.255.0.0 172.16.5.254', 'end')
    assert 'GigabitEthernet0/2     172.16.5.1      YES manual down                  down' in \
        s.handle('show ip interface brief').output
    assert '10.10.0.0' not in s.handle('show ip route').output    # next hop not reachable
    assert 'ip route 10.10.0.0 255.255.0.0 172.16.5.254' in s.handle('show running-config').output


def test_hostname_and_write_mem():
    dev, s = cli('SW2')
    run(s, 'conf t', 'hostname CORE-SW')
    assert s.prompt() == 'CORE-SW(config)#'
    assert 'illegal characters' in s.handle('hostname bad!name').output
    assert '% Invalid input' in s.handle('hostname two words').output        # one word only
    s.handle('end')
    assert dev.saves == 0 and 'hostname SW2' in dev.startup
    assert s.handle('write mem').output == 'Building configuration...\n[OK]'
    assert dev.saves == 1 and 'hostname CORE-SW' in dev.startup
    assert s.handle('show running-config | include ^hostname').output == 'hostname CORE-SW'


def test_passwords_are_never_logged():
    assert _loggable('username ops secret 5 Hidden', True) == 'username ops secret 5 ********'
    assert _loggable('enable secret TopSecret', True) == 'enable secret ********'
    assert _loggable('anything at all', False) == '<password hidden>'


def test_config_file_checks():
    bad = {'devices': [dict(SPEC['R1'], host='192.168.1.1')]}
    with pytest.raises(LabError, match='not a loopback'):
        check_config(bad)
    dup = {'devices': [SPEC['R1'], dict(SPEC['SW1'], host=SPEC['R1']['host'])]}
    with pytest.raises(LabError, match='used twice'):
        check_config(dup)
    for d in CONFIG['devices']:                                   # the shipped file is sane
        assert d['host'].startswith('127.0.0.1') and int(d['port']) == 22


# ---------------------------------------------------------------- SSH with the real Netmiko
def test_real_netmiko_workflow(lab):
    conn = connect_to(lab, 'R1')
    assert conn.find_prompt() == 'R1>' and conn.base_prompt == 'R1'
    conn.enable()
    assert conn.find_prompt() == 'R1#'
    running = conn.send_command('show running-config')
    assert 'hostname R1' in running and running.rstrip().endswith('end')
    assert '[OK]' not in running
    conn.config_mode()
    assert conn.check_config_mode()
    out = conn.send_config_set(['ip route 10.10.0.0 255.255.0.0 192.168.10.254',
                                'ntp server 192.168.10.5'])
    assert '% Invalid' not in out
    conn.exit_config_mode()
    assert not conn.check_config_mode()
    assert 'ip route 10.10.0.0 255.255.0.0 192.168.10.254' in \
        conn.send_command('show running-config | include ip route')
    assert '[OK]' in conn.save_config()
    conn.disconnect()
    assert lab.devices['R1'].saves == 1 and 'ntp server 192.168.10.5' in lab.devices['R1'].startup


def test_invalid_command_comes_back_through_netmiko(lab):
    conn = connect_to(lab, 'SW1')
    assert conn.find_prompt() == 'SW1#'
    out = conn.send_config_set(['interface Gi0/1', 'switchport mode trunk'])
    assert 'Command rejected' in out
    assert "% Invalid input detected at '^' marker." in conn.send_command('show vlna brief')
    conn.disconnect()


def test_hostname_change_then_save_reproduces_the_stale_prompt_issue(lab):
    """KNOWN ISSUE (left unchanged on purpose): after `hostname X`, Netmiko keeps the old
    base prompt; send_command() still works (it looks up the prompt itself), but
    save_config() calls enable() -> check_enable_mode(), which waits for the OLD prompt."""
    conn = connect_to(lab, 'SW2')
    conn.send_config_set(['hostname EDGE'])
    assert conn.base_prompt == 'SW2'
    assert 'hostname EDGE' in conn.send_command('show running-config | include ^hostname')
    conn.read_timeout_override = 2
    with pytest.raises(ReadTimeout):
        conn.save_config()
    assert lab.devices['SW2'].saves == 0                          # write mem was never sent
    conn.read_timeout_override = None
    conn.clear_buffer()
    conn.set_base_prompt()                                        # the workaround
    assert '[OK]' in conn.save_config() and lab.devices['SW2'].saves == 1
    conn.disconnect()


def test_privilege_15_scan_account_lands_in_enable_mode(lab):
    shared = CONFIG['shared_scan_account']
    conn = connect_to(lab, 'R1', user=shared['username'], password=shared['password'])
    assert conn.find_prompt() == 'R1#'
    conn.disconnect()


# ---------------------------------------------------------------- failures
def test_wrong_password_and_auth_fail_mode(lab):
    with pytest.raises(NetmikoAuthenticationException):
        connect_to(lab, 'SW1', password='not-the-password')
    lab.set_failure('SW1', 'auth_fail')
    with pytest.raises(NetmikoAuthenticationException):
        connect_to(lab, 'SW1')
    lab.set_failure('SW1', 'none')
    connect_to(lab, 'SW1').disconnect()


def test_start_refuses_an_address_that_is_taken(key_path):
    import socket
    other = socket.socket()                                       # "another SSH server"
    other.bind(('127.0.0.1', 0)); other.listen(1)
    port = other.getsockname()[1]
    try:
        lab = Lab(CONFIG, key_path=key_path,
                  overrides={'R1': ('127.0.0.1', 0), 'SW1': ('127.0.0.1', port),
                             'SW2': ('127.0.0.1', 0)})
        with pytest.raises(LabError, match='already in use'):
            lab.start()
        assert all(ep.sock is None for ep in lab.endpoints.values())   # nothing was started
    finally:
        other.close()


def test_offline_device_refuses_connections(key_path):
    import socket
    s = socket.socket(); s.bind(('127.0.0.1', 0)); port = s.getsockname()[1]; s.close()
    config = {'devices': [dict(SPEC['SW1'], failure='offline')]}
    with Lab(config, key_path=key_path, overrides={'SW1': ('127.0.0.1', port)}) as lab:
        start = time.time()
        with pytest.raises(NetmikoTimeoutException):
            connect_to(lab, 'SW1')
        assert time.time() - start < 5                            # refused at once


def test_offline_while_running_and_hang(lab):
    lab.set_failure('SW1', 'offline')
    with pytest.raises(Exception) as err:
        connect_to(lab, 'SW1')
    assert not isinstance(err.value, NetmikoAuthenticationException)
    lab.set_failure('SW2', 'hang')
    start = time.time()
    with pytest.raises(Exception) as err:
        connect_to(lab, 'SW2', banner_timeout=2, conn_timeout=2, auth_timeout=2)
    assert time.time() - start < 15
    assert 'banner' in str(err.value).lower() or isinstance(err.value, NetmikoTimeoutException)


def test_slow_device_still_works(lab):
    lab.set_failure('SW1', 'slow', delay_ms=300)
    conn = connect_to(lab, 'SW1')
    start = time.time()
    assert 'SW1' in conn.send_command('show running-config | include ^hostname')
    assert time.time() - start >= 0.3
    conn.disconnect()


# ---------------------------------------------------------------- NetCommand against the lab
@pytest.fixture
def route(monkeypatch, lab):
    """NetCommand connects to <lab host>:22; send it to the test port instead,
    through the REAL Netmiko ConnectHandler."""
    from config import connect
    from discovery import crawler
    ports = {SPEC[n]['host']: lab.address(n) for n in SPEC}

    def real_connect(**kw):
        host, port = ports[kw['host']]
        return ConnectHandler(**dict(kw, host=host, port=port))
    monkeypatch.setattr(connect, 'ConnectHandler', real_connect)
    monkeypatch.setattr(crawler, 'ConnectHandler', real_connect)
    return lab


def creds(name, password=None):
    return {'host': SPEC[name]['host'], 'username': SPEC[name]['username'],
            'password': password or SPEC[name]['password']}


def test_apply_config_backup_verify_save(route, tmp_path):
    from config import commands_switch, connect
    lab = route
    plan = {'vlans': [(30, 'GUEST')], 'access_ports': [('Fa0/5-8', 30)],
            'interfaces': [{'ports': 'Fa0/24', 'description': 'Spare', 'state': 'shutdown'}]}
    cmds, checks = commands_switch.build_commands(plan, ['VLANs', 'Access ports', 'Interface settings'])
    before = lab.devices['SW1'].running_config()
    log = []
    ok, msg = connect.apply_config(creds('SW1'), cmds, checks, backup_dir=str(tmp_path),
                                   log=lambda k, t: log.append((k, t)))
    assert ok, msg
    (backup,) = tmp_path.iterdir()
    assert backup.name.startswith('127.0.0.12_')
    assert backup.read_text(encoding='utf-8').strip() == before.strip()        # the OLD config
    dev = lab.devices['SW1']
    assert dev.saves == 1 and dev.vlans[30] == 'GUEST'
    assert all(dev.interfaces[f'FastEthernet0/{n}'].access_vlan == 30 for n in range(5, 9))
    commands = [t for k, t in log if k == 'command']
    # each command is shown after the prompt the device showed before it (still VLAN mode)
    assert 'SW1(config-vlan)# interface range FastEthernet0/5 - 8' in commands
    assert 'SW1(config-if-range)# switchport access vlan 30' in commands
    assert any(k == 'ok' and 'OK: "switchport access vlan 30" found' in t for k, t in log)
    assert SPEC['SW1']['password'] not in str(log)


def test_rejected_command_is_partial_and_not_saved(route, tmp_path):
    from config import commands_switch, connect
    lab = route
    plan = {'trunks': [{'ports': 'Gi0/2', 'allowed': '10,20', 'native': 99, 'encapsulation': True}]}
    cmds, checks = commands_switch.build_commands(plan, ['Trunk ports'])
    ok, msg = connect.apply_config(creds('SW2'), cmds, checks, backup_dir=str(tmp_path))
    assert not ok and 'rejected' in msg and 'switchport trunk encapsulation dot1q' in msg
    assert 'partially applied: 1 of' in msg                    # the interface line went in
    assert lab.devices['SW2'].saves == 0


def test_router_settings_through_netcommand(route, tmp_path):
    from config import commands_router, connect
    lab = route
    plan = {'interfaces': [{'name': 'Gi0/2', 'ip': '172.16.9.1', 'mask': '255.255.255.0',
                            'description': 'Branch', 'state': 'no shutdown'}],
            'static_routes': [('10.50.0.0', '255.255.0.0', '172.16.9.254')],
            'dhcp': {'pool': 'BRANCH', 'network': '172.16.9.0', 'mask': '255.255.255.0',
                     'gateway': '172.16.9.1', 'dns': '8.8.8.8',
                     'excluded': ('172.16.9.1', '172.16.9.10')},
            'dns_servers': ['8.8.8.8'], 'ntp_server': '192.168.10.5'}
    cmds, checks = commands_router.build_commands(
        plan, ['Interfaces', 'Static routes', 'DHCP', 'DNS servers', 'NTP'])
    lab.devices['R1'].interfaces['GigabitEthernet0/2'].connected = True     # cable plugged in
    ok, msg = connect.apply_config(creds('R1'), cmds, checks, backup_dir=str(tmp_path))
    assert ok, msg
    dev = lab.devices['R1']
    assert dev.saves == 1 and 'BRANCH' in dev.pools and dev.interfaces['GigabitEthernet0/2'].is_up()
    assert ('10.50.0.0', '255.255.0.0', '172.16.9.254') in dev.routes


def test_dropped_connection_mid_change(route, tmp_path):
    from config import connect
    lab = route
    lab.set_failure('SW1', 'drop', drop_after=2)
    ok, msg = connect.apply_config(creds('SW1'), ['vlan 40', 'name LAB', 'vlan 41'], [],
                                   backup_dir=str(tmp_path))
    assert not ok and lab.devices['SW1'].saves == 0
    assert 40 in lab.devices['SW1'].vlans and 41 not in lab.devices['SW1'].vlans   # partly done
    assert len(list(tmp_path.iterdir())) == 1                  # the backup was still taken


def test_multi_device_run_with_one_failure(route, tmp_path):
    from config import commands_switch, connect, multi
    lab = route
    lab.set_failure('SW2', 'auth_fail')
    cmds, checks = commands_switch.build_commands({'vlans': [(50, 'VOICE')]}, ['VLANs'])
    jobs = [{'device': {'id': i, 'name': n, 'ip': SPEC[n]['host'], 'type': 'switch'},
             'creds': creds(n), 'commands': cmds, 'checks': checks}
            for i, n in enumerate(('SW1', 'SW2'))]
    posted = []
    results = multi.run_devices(
        jobs, lambda c, cm, ch, log=None: connect.apply_config(c, cm, ch, backup_dir=str(tmp_path),
                                                               log=log),
        post=lambda k, t, n=None: posted.append((k, t, n)))
    assert [r['status'] for r in results] == ['SUCCESS', 'FAILED']
    assert 'Wrong username or password' in results[1]['message']
    assert lab.devices['SW1'].saves == 1 and lab.devices['SW2'].saves == 0
    assert [p.name.split('_')[0] for p in tmp_path.iterdir()] == ['127.0.0.12']
    summary = multi.summary_text(results)
    assert 'SW1 - 127.0.0.12\nStatus: SUCCESS' in summary and 'Completed: 1' in summary
    assert SPEC['SW1']['password'] not in str(posted)


def test_hostname_change_through_netcommand_is_reported_not_saved(route, tmp_path):
    """Reproduces the documented issue end to end: NetCommand's verification passes, then
    write mem times out (about 10 s) on the stale prompt, so nothing is saved and NetCommand
    reports the error instead of claiming success."""
    from config import commands_router, connect
    lab = route
    cmds, checks = commands_router.build_commands({'hostname': 'BRANCH-RTR'}, ['Hostname'])
    log = []
    ok, msg = connect.apply_config(creds('R1'), cmds, checks, backup_dir=str(tmp_path),
                                   log=lambda k, t: log.append((k, t)))
    assert not ok and 'ReadTimeout' in msg
    assert any(k == 'ok' and 'hostname BRANCH-RTR' in t for k, t in log)   # the check passed
    assert lab.devices['R1'].hostname == 'BRANCH-RTR' and lab.devices['R1'].saves == 0


def test_discovery_finds_the_lab(route):
    from discovery import crawler
    shared = CONFIG['shared_scan_account']
    devices, links = crawler.discover(shared['username'], shared['password'], '127.0.0.11')
    assert {(d['name'], d['ip'], d['type'], d['managed']) for d in devices} == {
        ('R1', '127.0.0.11', 'router', True), ('SW1', '127.0.0.12', 'switch', True),
        ('SW2', '127.0.0.13', 'switch', True)}
    assert set(links) == {('R1', 'Gi0/1', 'SW1', 'Gi0/1'), ('SW1', 'Gi0/2', 'SW2', 'Gi0/1')}
