"""Finds the network over SSH, starting at the seed device the admin names.

Seed-only by default: log in to the seed IP (and nothing else), read its CDP (or LLDP)
neighbor table, and list every neighbor as an UNMANAGED device, with its link to the
seed. The login is never sent to the neighbors.

Only when the admin explicitly asks for it (login_neighbours=True) is every neighbor
with a management IP also logged in to, with the same login, breadth-first: a queue of
devices still to visit and a SET of devices already seen, so none is visited twice.

There is no fallback: if the seed login fails, the scan stops with the reason. Nothing
else (other hosts from the ARP table, the default gateway) is ever tried. One login
attempt per device; it never tries guessed passwords.

Every connection uses ssh_options.connect_options(ip) (strict SSH algorithms, old ones
only for the addresses in NETCOMMAND_LEGACY_SSH_HOSTS).
"""
import re

from netmiko import ConnectHandler

import sample_data
import ssh_options
import validation

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


# Model and software-image families, as they appear in `show version`, in a CDP
# "Platform:" line or in an LLDP "System Description". Switch families are checked first:
# their numbers would otherwise overlap router families (C2960 vs C2900, C3850 vs C3800).
_SWITCH_FAMILIES = re.compile(
    r'\bWS-C\d'                                         # WS-C2960-24TT-L, WS-C3560...
    r'|\bC(?:2918|2940|2948|2950|2955|2960|2970|2975|3550|3560|3650|3750|3850|4500|6500|6800'
    r'|9200|9300|9400|9500|9600)'                       # C2960 Software, C9300-24T
    r'|\bC1000-'                                        # Catalyst 1000 (C1000-24T-4G-L)
    r'|\bCAT[39]K'                                      # CAT9K_IOSXE, CAT3K_CAA
    r'|\bvios_l2'                                       # GNS3 virtual IOS switch
    r'|\bIE-?[2-5]\d{3}',                               # Industrial Ethernet switches
    re.IGNORECASE)
_ROUTER_FAMILIES = re.compile(
    r'\b(?:CISCO|C)(?:18|19|28|29|38|39)\d\d(?!\d)'     # ISR G1/G2: C1900, CISCO1941/K9,
                                                        # CISCO1941W-E/K9, C2911
    r'|\bISR\s?\d{3,4}'                                 # ISR4331, ISR 4451
    r'|\bC11\d\d(?!\d)'                                 # ISR 1100 (C1111-8P)
    r'|\bC8\d\d(?!\d)'                                  # C880, C891F-K9
    r'|\bC(?:7200|7600)(?!\d)'
    r'|\bASR\s?\d{3,4}|\bCSR1000V\b|\bISRv\b'
    r'|\bVIOS-',                                        # GNS3 virtual IOS router image
    re.IGNORECASE)


def platform_type(text):
    """'switch' or 'router' when the model/image text names a known family, else None."""
    text = text or ''
    if _SWITCH_FAMILIES.search(text):
        return 'switch'
    if _ROUTER_FAMILIES.search(text):
        return 'router'
    return None


_REJECTED = ('% Invalid', '% Ambiguous', '% Unknown command', '% Incomplete')


def _vlan_table(text):
    """True when `show vlan brief` printed a real VLAN table (only switches have one)."""
    text = text or ''
    return bool(re.search(r'^\s*1\s+default\s+active', text, re.MULTILINE)) or \
        ('VLAN' in text and 'Name' in text and 'Status' in text and 'Ports' in text)


def classify(version_text, vlan_text):
    """'router', 'switch' or 'unknown' from `show version` and `show vlan brief` output
    (either may be None when the command failed). In order of reliability:
      1. the model / software image in show version;
      2. a real VLAN table -> switch;  show vlan brief rejected by the device -> router
         (a Cisco switch always has the command; a router does not have a VLAN table);
      3. otherwise 'unknown' - never a guessed switch."""
    kind = platform_type(version_text)
    if kind:
        return kind
    if vlan_text is not None:
        if _vlan_table(vlan_text):
            return 'switch'
        if any(r in vlan_text for r in _REJECTED):
            return 'router'
    return 'unknown'


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
        platform = plat.group(1).strip() if plat else ''
        found.append({'name': short_name(dev.group(1)), 'ip': ip,
                      'local_port': short_port(ports.group(1)),
                      'remote_port': short_port(ports.group(2)),
                      'platform': platform,
                      # the platform (model) first: routers often also report "Switch"
                      'type': platform_type(platform) or guess_type(caps.group(1) if caps else '')})
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
        description = re.search(r'System Description:\s*\n?(.+)', block)
        kind = platform_type(description.group(1) if description else '') or \
            ('router' if 'R' in enabled else 'switch' if 'B' in enabled else 'unknown')
        found.append({'name': short_name(name.group(1)), 'ip': ip.group(1) if ip else '',
                      'local_port': short_port(local.group(1)),
                      'remote_port': short_port(remote.group(1)),
                      'platform': '', 'type': kind})
    return found


# ---------------------------------------------------------------- talking to one device
def _login(ip, username, password):
    conn = ConnectHandler(device_type='cisco_ios', host=ip, username=username,
                          password=password, secret=password, **LOGIN_TIMEOUTS,
                          **ssh_options.connect_options(ip))
    if conn.find_prompt().endswith('>'):          # user mode: step up to privileged mode
        try:
            conn.enable()
        except Exception:
            pass
    return conn


def _show(conn, command):
    """The command's output, or None when it could not be run (never guessed)."""
    try:
        return conn.send_command(command)
    except Exception:
        return None


def _read_device(conn):
    """(hostname, 'switch' / 'router' / 'unknown', neighbors) for the device we are
    logged in to. The type comes from classify(): show version first."""
    name = conn.find_prompt().rstrip('#>').strip()
    version = _show(conn, 'show version')
    kind = platform_type(version)
    vlan = None if kind else _show(conn, 'show vlan brief')   # only needed without a model
    kind = classify(version, vlan)
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
    return name, kind, neighbors


# ---------------------------------------------------------------- the seed
def _login_to_seed(username, password, seed_ip, notify):
    """Log in to the seed device and nothing else. Raises RuntimeError with the reason
    (from ssh_options.describe_error: never the exception's own text)."""
    notify(f'Logging in to the starting device {seed_ip}...')
    try:
        return _login(seed_ip, username, password)
    except Exception as err:
        _, reason = ssh_options.describe_error(err, seed_ip)
        raise RuntimeError(f'Could not log in to the starting device {seed_ip}: {reason}.') \
            from None


def check_seed(seed_ip):
    """The seed IP, stripped, or ValueError: a real scan needs an explicit seed IP."""
    seed = (seed_ip or '').strip()
    if not seed:
        raise ValueError('A seed IP is required: type the management IP of the switch or '
                         'router to log in to.')
    problem = validation.check_ip(seed)
    if problem:
        raise ValueError(f'Seed IP: {problem}')
    return seed


# ---------------------------------------------------------------- the scan
def discover(username, password, seed_ip, progress=None, max_devices=MAX_DEVICES,
             login_neighbours=False):
    """Scan from seed_ip. Returns (devices, links) in the shapes the app uses:
    device = {'name','ip','mac','type','managed','status'}
    link   = (name_a, port_a, name_b, port_b)
    login_neighbours=False (default): only the seed is logged in to; its CDP/LLDP
    neighbors are listed as unmanaged. True: the neighbors are logged in to as well."""
    seed_ip = check_seed(seed_ip)
    notify = progress or (lambda message: None)
    managed = {}        # ip -> {'name', 'type'}   devices we logged in to
    unmanaged = {}      # ip -> {'name', 'type'}   seen in CDP/LLDP only (or the login failed)
    raw_links = []      # (ip_a, port_a, ip_b, port_b)
    seen, queue = set(), [seed_ip]
    first = True

    while queue and len(seen) < max_devices:
        ip = queue.pop(0)
        if ip in seen:
            continue
        seen.add(ip)
        if first:
            conn = _login_to_seed(username, password, ip, notify)
            first = False
        else:
            notify(f'Logging in to {ip}...')
            try:
                conn = _login(ip, username, password)
            except Exception as err:
                _, reason = ssh_options.describe_error(err, ip)
                notify(f'{ip}: could not log in ({reason}), listed as unmanaged')
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
            if not login_neighbours:
                if n['ip'] not in managed:
                    notify(f"{n['name']} ({n['ip']}): neighbor listed from CDP/LLDP, "
                           f"not logged in")
            elif n['ip'] not in seen:
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
