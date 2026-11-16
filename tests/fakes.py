"""A fake lab: pretend switches that answer the same commands as the real GNS3 lab."""
import os, sys
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))
from netmiko.exceptions import NetmikoAuthenticationException, NetmikoTimeoutException

REAL_PORT = {'Gi': 'GigabitEthernet', 'Fa': 'FastEthernet'}


def cdp_text(neighbors):
    """neighbors = [(device_id, ip, caps, local_port, remote_port)] in Cisco's format."""
    out = []
    for dev_id, ip, caps, local, remote in neighbors:
        out.append(f"""-------------------------
Device ID: {dev_id}
Entry address(es):
  IP address: {ip}
Platform: cisco IOSv,  Capabilities: {caps}
Interface: {local},  Port ID (outgoing port): {remote}
Holdtime : 150 sec

Version :
Cisco IOS Software

advertisement version: 2
Management address(es):
  IP address: {ip}
""")
    return ''.join(out) + '\n' if out else ''


def lab():
    """CORE connects to SW1, SW2, R1. SW3 connects to SW2 only (and has a different password)."""
    G = 'GigabitEthernet'
    return {
        '192.168.1.2': dict(name='CORE', kind='switch', nbrs=[
            ('SW1.lab.local', '192.168.1.3', 'Switch IGMP', f'{G}0/1', f'{G}0/1'),
            ('SW2.lab.local', '192.168.1.4', 'Switch IGMP', f'{G}0/2', f'{G}0/1'),
            ('R1.lab.local', '192.168.1.1', 'Router Source-Route-Bridge', f'{G}0/3', f'{G}0/0')]),
        '192.168.1.3': dict(name='SW1', kind='switch', nbrs=[
            ('CORE.lab.local', '192.168.1.2', 'Switch IGMP', f'{G}0/1', f'{G}0/1')]),
        '192.168.1.4': dict(name='SW2', kind='switch', nbrs=[
            ('CORE.lab.local', '192.168.1.2', 'Switch IGMP', f'{G}0/1', f'{G}0/2'),
            ('SW3.lab.local', '192.168.1.5', 'Switch IGMP', f'{G}0/2', f'{G}0/1')]),
        '192.168.1.5': dict(name='SW3', kind='switch', password='DIFFERENT', nbrs=[
            ('SW2.lab.local', '192.168.1.4', 'Switch IGMP', f'{G}0/1', f'{G}0/2')]),
        '192.168.1.1': dict(name='R1', kind='router', nbrs=[
            ('CORE.lab.local', '192.168.1.2', 'Switch IGMP', f'{G}0/0', f'{G}0/3')]),
    }


class FakeConn:
    def __init__(self, info):
        self.info, self.closed = info, False

    def find_prompt(self):
        return self.info['name'] + '#'

    def enable(self):
        pass

    def send_command(self, cmd, **kw):
        if cmd == 'show vlan brief':
            return ('VLAN Name Status\n1 default active' if self.info['kind'] == 'switch'
                    else '% Invalid input detected at "^" marker.')
        if cmd == 'show cdp neighbors detail':
            return cdp_text(self.info['nbrs'])
        if cmd == 'show lldp neighbors detail':
            return ''
        if cmd == 'show running-config':
            return f"hostname {self.info['name']}\n"
        return ''

    def disconnect(self):
        self.closed = True


def fake_login_factory(devices, good_password='cisco123', visited=None):
    """Replacement for crawler._login: logs in to a device from the fake lab."""
    def fake_login(ip, username, password):
        if visited is not None:
            visited.append(ip)
        info = devices.get(ip)
        if info is None:
            raise NetmikoTimeoutException(f'no answer from {ip}')
        if password != info.get('password', good_password):
            raise NetmikoAuthenticationException('bad login')
        return FakeConn(info)
    return fake_login
