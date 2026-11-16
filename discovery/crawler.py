"""Finds the network by crawling outward over SSH.

Start at one device (the default gateway, or the IP the admin types). Log in,
read its CDP (or LLDP) neighbor table, and put every neighbor that has a
management IP in a queue. Visit them the same way, until the queue is empty.

This is a breadth-first search: a queue of devices still to visit, and a SET of
devices already seen, so a device is never visited twice.

Uses only the login the admin typed, one attempt per device. It never tries
guessed passwords.
"""
import ipaddress
import os
import re
import socket
import subprocess
import sys

from netmiko import ConnectHandler

import sample_data

MAX_DEVICES = 64            # safety limit so a scan can never run away
LOGIN_TIMEOUTS = {'conn_timeout': 6, 'auth_timeout': 10, 'banner_timeout': 10}

_IP = r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})'
_PORT_PREFIX = [('TenGigabitEthernet', 'Te'), ('GigabitEthernet', 'Gi'),
                ('FastEthernet', 'Fa'), ('Port-channel', 'Po'), ('Ethernet', 'Eth')]


# ---------------------------------------------------------------- small helpers
def short_port(port):
    """GigabitEthernet0/1 -> Gi0/1 (short names keep the map readable)."""
    port = (port or '').strip()
    for long, short in _PORT_PREFIX:
        if port.startswith(long):
            return short + port[len(long):]
    return port


def short_name(device_id):
    """SW2.lab.local -> SW2, SW1(FOC1234) -> SW1. An IP address is kept whole."""
    name = (device_id or '').strip()
    if re.fullmatch(_IP, name):
        return name
    return name.split('(')[0].split('.')[0]


def guess_type(capabilities):
    """Cisco CDP capabilities such as 'Router Switch IGMP' -> switch or router."""
    caps = (capabilities or '').lower()
    if 'switch' in caps:
        return 'switch'
    if 'router' in caps:
        return 'router'
    return 'unknown'


def default_gateway():
    """The default gateway of this computer, or None when it cannot be found."""
    try:
        if os.name == 'nt':
            out = subprocess.run(['route', 'print', '-4', '0.0.0.0'],
                                 capture_output=True, text=True, timeout=10).stdout
            m = re.search(r'0\.0\.0\.0\s+0\.0\.0\.0\s+' + _IP, out)
        elif sys.platform == 'darwin':
            out = subprocess.run(['route', '-n', 'get', 'default'],
                                 capture_output=True, text=True, timeout=10).stdout
            m = re.search(r'gateway:\s*' + _IP, out)
        else:
            out = subprocess.run(['ip', 'route', 'show', 'default'],
                                 capture_output=True, text=True, timeout=10).stdout
            m = re.search(r'default via ' + _IP, out)
        return m.group(1) if m else None
    except Exception:
        return None


# ---------------------------------------------------------------- parsing
def _blocks(text):
    return [b for b in re.split(r'-{5,}', text or '') if b.strip()]


def parse_cdp(text):
    """Parse `show cdp neighbors detail` into a list of neighbor dictionaries:
    {'name', 'ip', 'local_port', 'remote_port', 'platform', 'type'}.
    A neighbor with no management IP gets ip = ''."""
    found = []
    for block in _blocks(text):
        dev = re.search(r'Device ID:\s*(\S+)', block)
        ports = re.search(r'Interface:\s*([^,\n]+),\s*Port ID \(outgoing port\):\s*(\S+)', block)
        if not dev or not ports:
            continue
        mgmt = re.search(r'Management address\(es\):\s*\n\s*IP(?:v4)? address:\s*' + _IP, block)
        any_ip = re.search(r'IP(?:v4)? address:\s*' + _IP, block)
        ip = (mgmt or any_ip).group(1) if (mgmt or any_ip) else ''
        plat = re.search(r'Platform:\s*([^,\n]+)', block)
        caps = re.search(r'Capabilities:\s*(.+)', block)
        found.append({'name': short_name(dev.group(1)), 'ip': ip,
                      'local_port': short_port(ports.group(1)),
                      'remote_port': short_port(ports.group(2)),
                      'platform': plat.group(1).strip() if plat else '',
                      'type': guess_type(caps.group(1) if caps else '')})
    return found


def parse_lldp(text):
    """Parse `show lldp neighbors detail`. Same output shape as parse_cdp."""
    found = []
    for block in _blocks(text):
        local = re.search(r'Local Intf:\s*(\S+)', block)
        remote = re.search(r'Port id:\s*(\S+)', block)
        name = re.search(r'System Name:\s*(\S+)', block)
        if not (local and remote and name):
            continue
        ip = re.search(r'Management Addresses?:\s*\n?\s*IP:\s*' + _IP, block) \
            or re.search(r'\bIP:\s*' + _IP, block)
        caps = re.search(r'Enabled Capabilities:\s*(\S+)', block)
        enabled = (caps.group(1) if caps else '').upper().split(',')
        kind = 'router' if 'R' in enabled else 'switch' if 'B' in enabled else 'unknown'
        found.append({'name': short_name(name.group(1)), 'ip': ip.group(1) if ip else '',
                      'local_port': short_port(local.group(1)),
                      'remote_port': short_port(remote.group(1)),
                      'platform': '', 'type': kind})
    return found


# ---------------------------------------------------------------- talking to one device
def _login(ip, username, password):
    conn = ConnectHandler(device_type='cisco_ios', host=ip, username=username,
                          password=password, secret=password, **LOGIN_TIMEOUTS)
    if conn.find_prompt().endswith('>'):          # user mode: step up to privileged mode
        try:
            conn.enable()
        except Exception:
            pass
    return conn


def _read_device(conn):
    """(hostname, 'switch' or 'router', neighbors) for the device we are logged in to."""
    name = conn.find_prompt().rstrip('#>').strip()
    try:
        is_switch = 'Invalid' not in conn.send_command('show vlan brief')
    except Exception:
        is_switch = True
    neighbors = []
    try:
        neighbors = parse_cdp(conn.send_command('show cdp neighbors detail'))
    except Exception:
        pass
    if not neighbors:                              # CDP off or empty: try LLDP
        try:
            neighbors = parse_lldp(conn.send_command('show lldp neighbors detail'))
        except Exception:
            pass
    return name, ('switch' if is_switch else 'router'), neighbors


# ---------------------------------------------------------------- entry point when the gateway has no SSH
def port_open(ip, port=22, timeout=1.0):
    try:
        with socket.create_connection((ip, port), timeout=timeout):
            return True
    except OSError:
        return False


def arp_candidates():
    """IPs of other hosts this computer has recently talked to (from its ARP table)."""
    try:
        out = subprocess.run(['arp', '-a'], capture_output=True, text=True, timeout=10).stdout
    except Exception:
        return []
    ips = re.findall(r'\(' + _IP + r'\) at [0-9a-f:]{11,17}', out, re.I)       # Linux, macOS
    ips += re.findall(r'^\s*' + _IP + r'\s+[0-9a-f-]{17}', out, re.I | re.M)    # Windows
    keep = []
    for ip in ips:
        first = int(ip.split('.')[0])
        if ip.endswith('.255') or 224 <= first <= 239 or ip in keep:
            continue
        keep.append(ip)
    return keep


def _find_entry(username, password, seed_ip, notify):
    """Log in to the seed. If that fails, try other SSH hosts the laptop already knows.
    One login attempt per host. Returns (ip, connection)."""
    first_error = None
    try:
        notify(f'Logging in to the starting device {seed_ip}...')
        return seed_ip, _login(seed_ip, username, password)
    except Exception as err:
        first_error = err
    tried = {seed_ip}
    for ip in arp_candidates()[:12]:
        if ip in tried or not port_open(ip):
            continue
        tried.add(ip)
        notify(f'Trying another device on the local network: {ip}...')
        try:
            return ip, _login(ip, username, password)
        except Exception:
            continue
    reason = type(first_error).__name__
    hint = ('wrong username or password' if 'Authentication' in reason
            else 'no answer (is the IP right, is SSH on, is it reachable?)')
    raise RuntimeError(f'Could not log in to the starting device {seed_ip}: {hint}. '
                       f'Check the login, or type the IP of your core switch as the seed IP.')


# ---------------------------------------------------------------- the crawl
def discover(username, password, seed_ip, progress=None, max_devices=MAX_DEVICES):
    """Crawl from seed_ip. Returns (devices, links) in the shapes the app uses:
    device = {'name','ip','mac','type','managed','status'}
    link   = (name_a, port_a, name_b, port_b)"""
    notify = progress or (lambda message: None)
    managed = {}        # ip -> {'name', 'type'}   devices we logged in to
    unmanaged = {}      # ip -> {'name', 'type'}   seen in CDP/LLDP but could not log in
    raw_links = []      # (ip_a, port_a, ip_b, port_b)
    seen, queue = set(), [seed_ip]
    first = True

    while queue and len(seen) < max_devices:
        ip = queue.pop(0)
        if ip in seen:
            continue
        seen.add(ip)
        try:
            if first:
                ip, conn = _find_entry(username, password, ip, notify)
                seen.add(ip)
                first = False
            else:
                notify(f'Logging in to {ip}...')
                conn = _login(ip, username, password)
        except RuntimeError:
            raise
        except Exception:
            notify(f'{ip}: could not log in, listed as unmanaged')
            continue
        try:
            name, kind, neighbors = _read_device(conn)
        finally:
            try:
                conn.disconnect()
            except Exception:
                pass
        managed[ip] = {'name': name, 'type': kind}
        unmanaged.pop(ip, None)
        notify(f'{name} ({ip}): {len(neighbors)} neighbors')
        for n in neighbors:
            if not n['ip']:
                notify(f"{n['name']}: no management IP, skipped")
                continue
            raw_links.append((ip, n['local_port'], n['ip'], n['remote_port']))
            if n['ip'] not in managed:
                unmanaged.setdefault(n['ip'], {'name': n['name'], 'type': n['type']})
            if n['ip'] not in seen:
                queue.append(n['ip'])
    if queue and len(seen) >= max_devices:
        notify(f'Stopped at the safety limit of {max_devices} devices.')

    # give every device a unique name (two switches may both be called "Switch")
    names, used = {}, set()
    for ip, info in list(managed.items()) + list(unmanaged.items()):
        name = info['name'] or ip
        if name in used:
            name = f"{name}-{ip.split('.')[-1]}"
        used.add(name)
        names[ip] = name

    devices = [{'name': names[ip], 'ip': ip, 'mac': '', 'type': i['type'],
                'managed': True, 'status': 'up'} for ip, i in managed.items()]
    devices += [{'name': names[ip], 'ip': ip, 'mac': '', 'type': i['type'],
                 'managed': False, 'status': 'up'} for ip, i in unmanaged.items()]
    links = set()
    for ia, pa, ib, pb in raw_links:
        if ia in names and ib in names:
            a, b = sorted([(names[ia], pa), (names[ib], pb)])
            links.add((a[0], a[1], b[0], b[1]))        # sorted: A-B and B-A are one link
    return devices, sorted(links)


def discover_demo():
    """Sample data for demo mode (no network). Returns copies, so callers can change them.
    Each copy carries 'sample': True, an in-app safety marker only (never a database
    column): the Scan tab and db.py use it to keep sample devices out of the real database.
    It is a marker, not a name/IP check, because the real lab uses the same names and IPs."""
    return [dict(d, sample=True) for d in sample_data.DEVICES], list(sample_data.LINKS)
