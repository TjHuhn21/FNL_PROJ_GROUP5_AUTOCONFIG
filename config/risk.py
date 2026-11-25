"""Commands that can cut NetCommand off from a device (read before Apply asks).

    disconnect_risks(['interface Gi0/0', 'shutdown'], '192.168.1.1')
    -> ['Gi0/0 is shut down. If NetCommand reaches the device through it, the SSH
         session and every later check are lost.']

Nothing here talks to a device: it only reads the command lines. A warning means "this
MAY disconnect NetCommand"; the user decides. Checked:
  * an interface shut down
  * a new address on an interface in the same network as the address NetCommand uses
    (most likely the interface it connects through), or 'no ip address'
  * the default route or default gateway changed or removed
  * port security 'violation shutdown' on an uplink (a Gigabit/Ten-Gigabit port, or a
    port made a trunk by the same commands)
  * remote-access settings: line vty, transport input, SSH, access-class, usernames
"""
import ipaddress
import re

# lines that leave interface configuration mode (a new top-level command)
_TOP_LEVEL = ('hostname', 'vlan', 'ip route', 'ip dhcp', 'ip name-server', 'ip domain',
              'ntp', 'line', 'router', 'username', 'ip default-gateway', 'no ip route',
              'ip ssh', 'no ip ssh', 'crypto', 'end', 'exit', 'spanning-tree', 'access-list')
_UPLINK = re.compile(r'^(gi|gigabitethernet|te|tengigabitethernet|tw|fo|hu)', re.I)
_REMOTE = ('line vty', 'transport input', 'no ip ssh', 'ip ssh version', 'access-class',
           'no username', 'crypto key zeroize', 'no ip http', 'login local', 'no login')


def _interfaces(line):
    """The interface names of 'interface X' / 'interface range A , B'."""
    rest = line.split(None, 1)[1] if ' ' in line else ''
    if rest.lower().startswith('range '):
        rest = rest[6:]
    return [p.strip() for p in rest.split(',') if p.strip()]


def _same_network(address, mask, device_ip):
    try:
        net = ipaddress.ip_network(f'{address}/{mask}', strict=False)
        return ipaddress.ip_address(device_ip) in net
    except ValueError:
        return False


def disconnect_risks(commands, device_ip):
    """The warnings for these command lines (an empty list when none apply)."""
    risks, current, trunks, secured = [], [], set(), []
    for raw in commands:
        line = ' '.join(str(raw).split())
        low = line.lower()
        if not low or low.startswith('#') or low.startswith('!'):
            continue
        if low.startswith('interface '):
            current = _interfaces(line)
            continue
        if low.startswith(_TOP_LEVEL):
            current = []
        where = ', '.join(current) or 'An interface'
        if current and low == 'shutdown':
            risks.append(f'{where} is shut down. If NetCommand reaches the device through it, '
                         f'the SSH session and every later check are lost.')
        elif current and low.startswith('ip address '):
            parts = line.split()
            if len(parts) >= 4 and parts[2] != device_ip and \
                    _same_network(parts[2], parts[3], device_ip):
                risks.append(f'{where} gets the address {parts[2]}, in the same network as '
                             f'{device_ip} (the address NetCommand uses). If that is the '
                             f'interface NetCommand connects through, the connection is lost.')
        elif current and low == 'no ip address':
            risks.append(f'{where} loses its IP address. If NetCommand connects through it, '
                         f'the connection is lost.')
        elif current and low == 'switchport mode trunk':
            trunks.update(n.lower() for n in current)
        elif current and low == 'switchport port-security violation shutdown':
            secured.append(list(current))
        if low.startswith(('ip route 0.0.0.0 0.0.0.0', 'no ip route 0.0.0.0 0.0.0.0',
                           'ip default-gateway', 'no ip default-gateway')):
            risks.append('The default route changes. If NetCommand is on another network, the '
                         'device may no longer find the way back to it.')
        elif low.startswith(_REMOTE):
            risks.append(f'"{line}" changes how the device accepts remote logins (SSH / VTY). '
                         f'A mistake here can lock NetCommand out.')
    for names in secured:
        uplinks = [n for n in names if _UPLINK.match(n) or n.lower() in trunks]
        if uplinks:
            risks.append(f'Port security "violation shutdown" on {", ".join(uplinks)}, which '
                         f'looks like an uplink: an unexpected MAC address there shuts the '
                         f'port and can disconnect NetCommand.')
    out = []
    for r in risks:                                     # the same warning once
        if r not in out:
            out.append(r)
    return out
