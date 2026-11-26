"""The input rules of the Configure page, in ONE place, for the screen and the backend.

The screen (gui/components/field_check.py, gui/configure_tab.py) uses them to block wrong
characters while typing, to mark a field red with a short message, to keep Add disabled,
and to block Preview / Apply. The backend uses the SAME functions again before anything is
sent: config/commands_switch.py and config/commands_router.py check the whole plan
(check_switch_plan / check_router_plan) and config/connect.apply_config checks every command
line (check_cli_line). Nothing typed is trusted just because the screen accepted it.

Every check_* function returns an error message, or None when the value is fine. The
is_valid_* / parse_* functions are the same rules in boolean / parsing form. Values are
trimmed first; an empty optional value is fine (the caller decides what is required).

No value may contain a line break, a control character, or one of  ; | ` $  : the values
become CLI commands on the device (command injection).
"""
import ipaddress
import re

BLOCKED_CHARACTERS = ';|`$'
IP_EXAMPLE = '(e.g. 192.168.1.1)'
MASK_EXAMPLE = '(e.g. 255.255.255.0 or /24)'
VLAN_MIN, VLAN_MAX = 1, 4094
RESERVED_VLANS = range(1002, 1006)
HOSTNAME_MAX, NAME_MAX, DESCRIPTION_MAX = 63, 32, 240
PORT_SECURITY_MAX = 8192
VIOLATIONS = ('protect', 'restrict', 'shutdown')
STATES = ('', 'shutdown', 'no shutdown')

# What may be TYPED into a field (checked on every key press, a paste included). Fields
# not listed here (names, ports, descriptions) accept any key and are checked as a whole.
TYPING = {
    'ipv4': re.compile(r'[0-9.]*'),
    'mask': re.compile(r'[0-9./]*'),
    'number': re.compile(r'[0-9]*'),
    'vlan_list': re.compile(r'[0-9,\- ]*'),
    'ipv4_list': re.compile(r'[0-9., ]*'),
}


def typing_ok(kind, text):
    """True when `text` (the whole field after the key press) may be typed into a field
    of this kind."""
    rule = TYPING.get(kind)
    return True if rule is None else bool(rule.fullmatch(text or ''))


def clean(text):
    return str(text if text is not None else '').strip()


# ---------------------------------------------------------------- characters
def check_characters(text, what='This value'):
    """No line break, control character or ; | ` $ (they would end or chain a CLI command)."""
    for c in str(text or ''):
        if c in '\r\n':
            return f'{what} must be on one line.'
        if ord(c) < 32 or ord(c) == 127:
            return f'{what} contains a control character, which is not allowed.'
        if c in BLOCKED_CHARACTERS:
            return f'The character "{c}" is not allowed (values are sent as device commands).'
    return None


# `username X ... secret|password VALUE` / `enable secret VALUE` with a VALUE typed in plain
# text (no type number in front): IOS hashes it itself. A stored hash pasted there ("$1$...")
# would be taken as the PLAINTEXT password (and refused as too long by IOS 15.4), so it is
# refused here; plaintext account secrets are 1-25 characters on IOS 15.4.
_SECRET_VALUE = re.compile(r'^\s*(username\s+\S+.*?|enable)\s+(secret|password)\s+(?!\d\s)(\S+)\s*$',
                           re.IGNORECASE)
SECRET_MAX = 25


def check_cli_line(line):
    """The backend's last check on one command line before it is sent (apply_config)."""
    problem = check_characters(line, 'A command')
    if problem:
        return problem
    m = _SECRET_VALUE.match(line or '')
    if m:
        value = m.group(3)
        if re.match(r'^\$\d+\$', value):
            return ('Type a real password, not an encrypted secret: "' + m.group(2) + ' $..." '
                    'would be taken as the plaintext password. Nothing was sent.')
        if m.group(2).lower() == 'secret' and len(value) > SECRET_MAX:
            return (f'The password is longer than {SECRET_MAX} characters; Cisco IOS refuses it '
                    f'("% Invalid Password length"). Nothing was sent.')
    return None


# ---------------------------------------------------------------- IPv4 addresses and masks
_IPV4 = re.compile(r'\d{1,3}(\.\d{1,3}){3}')


def check_ipv4(text, what='IP address'):
    """Digits and dots only, exactly 4 numbers, each 0-255, no leading zeros."""
    text = clean(text)
    problem = check_characters(text)
    if problem:
        return problem
    if not _IPV4.fullmatch(text):
        return f'Enter a valid {what} {IP_EXAMPLE}.'
    parts = text.split('.')
    if any(len(p) > 1 and p.startswith('0') for p in parts):
        return f'No leading zeros in an {what} {IP_EXAMPLE}.'
    if any(int(p) > 255 for p in parts):
        return f'Each number in an {what} must be 0-255 {IP_EXAMPLE}.'
    return None


def is_valid_ipv4(text):
    return check_ipv4(text) is None


def parse_mask(text):
    """'255.255.255.0' or '/24' -> '255.255.255.0'. ValueError with the reason."""
    text = clean(text)
    if text.startswith('/'):
        bits = text[1:]
        if not bits.isdigit() or not 0 <= int(bits) <= 32:
            raise ValueError(f'Enter a valid subnet mask {MASK_EXAMPLE}.')
        return str(ipaddress.IPv4Network(f'0.0.0.0/{int(bits)}').netmask)
    if check_ipv4(text) is not None:
        raise ValueError(f'Enter a valid subnet mask {MASK_EXAMPLE}.')
    value = int(ipaddress.IPv4Address(text))
    inverted = ~value & 0xFFFFFFFF
    if inverted & (inverted + 1):              # the 1s are not contiguous
        raise ValueError(f'Not a valid subnet mask: the 1s must be contiguous '
                         f'{MASK_EXAMPLE}.')
    return text


def check_mask(text):
    try:
        parse_mask(text)
        return None
    except ValueError as err:
        return str(err)


def is_valid_mask(text):
    return check_mask(text) is None


def _net(ip, mask):
    return ipaddress.IPv4Network(f'{clean(ip)}/{parse_mask(mask)}', strict=False)


def network_address(ip, mask):
    return str(_net(ip, mask).network_address)


def check_network_address(ip, mask):
    """ip must be the NETWORK address for mask ('Use the network address: 10.10.0.0')."""
    problem = check_ipv4(ip) or check_mask(mask)
    if problem:
        return problem
    real = network_address(ip, mask)
    if real != clean(ip):
        return f'Use the network address: {real}'
    return None


def check_host_address(ip, mask, what='The address'):
    """A usable host address: not the network or the broadcast address for the mask."""
    problem = check_ipv4(ip) or check_mask(mask)
    if problem:
        return problem
    net = _net(ip, mask)
    addr = ipaddress.IPv4Address(clean(ip))
    if net.prefixlen < 31 and addr == net.network_address:
        return f'{what} {addr} is the network address of {net}; use a host address.'
    if net.prefixlen < 31 and addr == net.broadcast_address:
        return f'{what} {addr} is the broadcast address of {net}; use a host address.'
    return None


def check_inside(ip, network, mask, what='The address'):
    """ip is a host address inside network/mask (not its network or broadcast address)."""
    problem = check_ipv4(ip)
    if problem:
        return problem
    net = _net(network, mask)
    if ipaddress.IPv4Address(clean(ip)) not in net:
        return f'{what} {clean(ip)} is not inside the network {net}.'
    return check_host_address(ip, mask, what)


def parse_ipv4_list(text):
    """'8.8.8.8, 1.1.1.1' -> ['8.8.8.8', '1.1.1.1']. ValueError naming the bad entry."""
    items = [clean(p) for p in clean(text).split(',')]
    if not any(items):
        raise ValueError(f'Enter one or more IP addresses separated by commas {IP_EXAMPLE}.')
    out = []
    for item in items:
        if not item:
            raise ValueError('There is an empty entry between two commas.')
        problem = check_ipv4(item)
        if problem:
            raise ValueError(f'"{item}": {problem}')
        if item in out:
            raise ValueError(f'{item} is listed twice.')
        out.append(item)
    return out


def check_ipv4_list(text):
    try:
        parse_ipv4_list(text)
        return None
    except ValueError as err:
        return str(err)


# ---------------------------------------------------------------- numbers and VLANs
def check_number(text, low, high, what='The number'):
    """Digits only, a whole number from low to high."""
    text = clean(text)
    if not text.isdigit() or not text.isascii():
        return f'{what} must be a whole number from {low} to {high}.'
    if not low <= int(text) <= high:
        return f'{what} must be from {low} to {high}.'
    return None


def check_vlan_id(text, what='VLAN ID'):
    return check_number(text, VLAN_MIN, VLAN_MAX, what) and \
        f'Enter a {what} from {VLAN_MIN} to {VLAN_MAX}.'


def is_valid_vlan_id(text):
    return check_vlan_id(text) is None


def vlan_id_warning(text):
    """A warning (never a block) for the default and reserved VLANs."""
    if check_vlan_id(text):
        return None
    n = int(clean(text))
    if n == 1:
        return 'VLAN 1 is the default VLAN (devices may refuse to change it).'
    if n in RESERVED_VLANS:
        return f'VLAN {n} is reserved (1002-1005; devices may refuse to change it).'
    return None


def parse_vlan_list(text):
    """'10,20,30-40' -> [10, 20, 30, ..., 40]. Digits, commas and hyphens only; every
    number 1-4094; a range goes from low to high; nothing listed twice. ValueError."""
    text = clean(text)
    problem = check_characters(text)
    if problem:
        raise ValueError(problem)
    if not re.fullmatch(r'[0-9,\- ]+', text):
        raise ValueError('Use only digits, commas and hyphens, e.g. 10,20,30-40.')
    numbers = []
    for part in (p.strip() for p in text.split(',')):
        if not part:
            raise ValueError('There is an empty entry between two commas.')
        m = re.fullmatch(r'(\d+)\s*-\s*(\d+)|(\d+)', part)
        if not m:
            raise ValueError(f'"{part}" is not a VLAN or a range like 30-40.')
        a, b = (int(m.group(1)), int(m.group(2))) if m.group(1) else (int(m.group(3)),) * 2
        if a > b:
            raise ValueError(f'"{part}" is reversed: write {b}-{a}.')
        for n in (a, b):
            if not VLAN_MIN <= n <= VLAN_MAX:
                raise ValueError(f'VLAN {n} is outside {VLAN_MIN}-{VLAN_MAX}.')
        for n in range(a, b + 1):
            if n in numbers:
                raise ValueError(f'VLAN {n} is listed twice.')
            numbers.append(n)
    return sorted(numbers)


def check_vlan_list(text):
    try:
        parse_vlan_list(text)
        return None
    except ValueError as err:
        return str(err)


# ---------------------------------------------------------------- ports and interfaces
def parse_port_list(text):
    """One port, a range, or a comma list: Fa0/1, Fa0/1-5, Fa0/1-Fa0/5, Fa0/1-5, Gi0/1.
    Short and long names (Fa/FastEthernet, Gi/GigabitEthernet, Te, Eth), any case; ranges
    low to high. Returns config.interfaces segments; ValueError (PortError) otherwise."""
    from config.interfaces import parse_ports
    problem = check_characters(text)
    if problem:
        raise ValueError(problem)
    return parse_ports(clean(text))


def check_port_list(text):
    try:
        parse_port_list(text)
        return None
    except ValueError as err:
        return str(err)


# Router interface types: short and long spellings -> the name IOS uses.
INTERFACE_TYPES = {
    'fa': 'FastEthernet', 'fastethernet': 'FastEthernet',
    'gi': 'GigabitEthernet', 'gigabitethernet': 'GigabitEthernet',
    'te': 'TenGigabitEthernet', 'tengigabitethernet': 'TenGigabitEthernet',
    'e': 'Ethernet', 'eth': 'Ethernet', 'ethernet': 'Ethernet',
    'se': 'Serial', 'serial': 'Serial',
    'lo': 'Loopback', 'loopback': 'Loopback',
    'vl': 'Vlan', 'vlan': 'Vlan',
    'tu': 'Tunnel', 'tunnel': 'Tunnel',
    'po': 'Port-channel', 'port-channel': 'Port-channel',
}
_INTERFACE = re.compile(r'([A-Za-z]+(?:-[A-Za-z]+)?)\s*(\d+(?:/\d+){0,3})(?:\.(\d{1,10}))?')
_NEEDS_SLOT = {'FastEthernet', 'GigabitEthernet', 'TenGigabitEthernet', 'Serial'}


def parse_interface_name(text):
    """'Gi0/0', 'GigabitEthernet0/0', 'Fa0/1', 'Se0/0/0', 'Lo0', 'Gi0/0.10' ->
    (full type, numbers, subinterface or None). ValueError otherwise."""
    text = clean(text)
    problem = check_characters(text)
    if problem:
        raise ValueError(problem)
    m = _INTERFACE.fullmatch(text)
    if not m:
        raise ValueError(f'"{text}" is not an interface name (e.g. Gi0/0, Se0/0/0, Lo0, '
                         f'Gi0/0.10).')
    kind = INTERFACE_TYPES.get(m.group(1).lower())
    if kind is None:
        raise ValueError(f'"{m.group(1)}" is not a known interface type (Gi, Fa, Te, Eth, Se, '
                         f'Lo, Vlan, Tu, Po).')
    if kind in _NEEDS_SLOT and '/' not in m.group(2):
        raise ValueError(f'"{text}" needs a slot and a port, e.g. Gi0/0.')
    sub = m.group(3)
    if sub is not None and not 1 <= int(sub) <= 4294967295:
        raise ValueError(f'"{text}": the subinterface number must be 1 or more.')
    return kind, m.group(2), (int(sub) if sub is not None else None)


def check_interface_name(text):
    try:
        parse_interface_name(text)
        return None
    except ValueError as err:
        return str(err)


def is_valid_interface_name(text):
    return check_interface_name(text) is None


def interface_key(text):
    """The same interface typed differently ('gi0/0' / 'GigabitEthernet0/0') -> one key."""
    kind, numbers, sub = parse_interface_name(text)
    return f'{kind}{numbers}' + (f'.{sub}' if sub is not None else '')


# ---------------------------------------------------------------- names and text
_HOSTNAME = re.compile(r'[A-Za-z]([A-Za-z0-9-]*[A-Za-z0-9])?')
_NAME = re.compile(r'[A-Za-z0-9_-]+')


def check_hostname(text):
    """Letters, digits and hyphens; starts with a letter; does not end with a hyphen;
    at most 63 characters; no spaces."""
    text = clean(text)
    problem = check_characters(text, 'The hostname')
    if problem:
        return problem
    if not text:
        return 'Enter a hostname.'
    if ' ' in text or '\t' in text:
        return 'No spaces allowed in a hostname.'
    if len(text) > HOSTNAME_MAX:
        return f'A hostname can have at most {HOSTNAME_MAX} characters.'
    if not text[0].isalpha() or not text[0].isascii():
        return 'A hostname must start with a letter.'
    if text.endswith('-'):
        return 'A hostname cannot end with a hyphen.'
    if not _HOSTNAME.fullmatch(text):
        return 'A hostname can only use letters, digits and hyphens.'
    return None


def is_valid_hostname(text):
    return check_hostname(text) is None


def check_name(text, what='The name'):
    """A VLAN or DHCP pool name: letters, digits, hyphen, underscore; no spaces; <= 32."""
    text = clean(text)
    problem = check_characters(text, what)
    if problem:
        return problem
    if not text:
        return f'{what} is required.'
    if ' ' in text:
        return f'No spaces allowed in {what.lower()}.'
    if len(text) > NAME_MAX:
        return f'{what} can have at most {NAME_MAX} characters.'
    if not _NAME.fullmatch(text):
        return f'{what} can only use letters, digits, "-" and "_".'
    return None


def check_description(text):
    """Printable text on one line, at most 240 characters, none of the blocked characters
    (and no "?", which makes IOS print its help instead)."""
    text = clean(text)
    problem = check_characters(text, 'The description')
    if problem:
        return problem
    if len(text) > DESCRIPTION_MAX:
        return f'The description can have at most {DESCRIPTION_MAX} characters.'
    if '?' in text:
        return 'A description cannot contain "?" (the device would show its help instead).'
    if not text.isprintable():
        return 'The description must be plain printable text.'
    return None


# ---------------------------------------------------------------- combined rules
def check_static_route(network, mask, next_hop):
    """(field, message) or None. Field: 'network', 'mask' or 'next_hop'."""
    for field, value, check in (('network', network, check_ipv4), ('mask', mask, check_mask)):
        if not clean(value):
            return field, 'Required.'
        problem = check(value)
        if problem:
            return field, problem
    if not clean(next_hop):
        return 'next_hop', 'Required.'
    if clean(network) == '0.0.0.0' and parse_mask(mask) == '0.0.0.0':
        return 'network', 'Use Basics > Default route for the default route.'
    problem = check_network_address(network, mask)
    if problem:
        return 'network', problem
    hop = clean(next_hop)
    if check_ipv4(hop) is None:
        if hop == '0.0.0.0':
            return 'next_hop', 'The next hop cannot be 0.0.0.0.'
        if hop == '255.255.255.255':
            return 'next_hop', 'The next hop cannot be a broadcast address.'
        if ipaddress.IPv4Address(hop) in _net(network, mask):
            return 'next_hop', f'The next hop {hop} is inside the destination network.'
        return None
    if re.fullmatch(r'[0-9.]+', hop):                 # meant as an address, but not valid
        return 'next_hop', check_ipv4(hop, 'next hop')
    if check_interface_name(hop) is None:
        return None
    return 'next_hop', f'Enter the next hop as an IP address {IP_EXAMPLE} or an interface ' \
                       f'(e.g. Gi0/0).'


def check_interface_address(ip, mask):
    """(field, message) or None for a router interface's IP address and mask."""
    ip, mask = clean(ip), clean(mask)
    if not ip and not mask:
        return None
    if not ip:
        return 'ip', 'Enter the IP address for this mask (or clear the mask).'
    problem = check_ipv4(ip)
    if problem:
        return 'ip', problem
    if not mask:
        return 'mask', 'A subnet mask is required with an IP address.'
    problem = check_mask(mask)
    if problem:
        return 'mask', problem
    problem = check_host_address(ip, mask, 'The IP address')
    return ('ip', problem) if problem else None


DHCP_FIELDS = ('pool', 'network', 'mask', 'gateway', 'dns', 'ex_start', 'ex_end')


def check_dhcp(d):
    """[(field, message)] for the DHCP form d (keys DHCP_FIELDS). Empty when it is fine,
    or when nothing at all is filled in (then there is no DHCP pool to make)."""
    d = {k: clean(d.get(k)) for k in DHCP_FIELDS}
    if not any(d.values()):
        return []
    problems = []
    single = {'pool': lambda v: check_name(v, 'The pool name'), 'network': check_ipv4,
              'mask': check_mask, 'gateway': check_ipv4, 'dns': check_ipv4,
              'ex_start': check_ipv4, 'ex_end': check_ipv4}
    for field in ('pool', 'network', 'mask'):
        if not d[field]:
            problems.append((field, 'Required when any DHCP field is filled in.'))
    for field, check in single.items():
        if d[field]:
            problem = check(d[field])
            if problem:
                problems.append((field, problem))
    bad = {f for f, _ in problems}
    if {'network', 'mask'} & bad:
        return problems
    problem = check_network_address(d['network'], d['mask'])
    if problem:
        return problems + [('network', problem)]
    if d['gateway'] and 'gateway' not in bad:
        problem = check_inside(d['gateway'], d['network'], d['mask'], 'The gateway')
        if problem:
            problems.append(('gateway', problem))
    if bool(d['ex_start']) != bool(d['ex_end']):
        missing = 'ex_end' if d['ex_start'] else 'ex_start'
        problems.append((missing, 'Fill in both Exclude from and Exclude to (or neither).'))
    elif d['ex_start'] and not {'ex_start', 'ex_end'} & bad:
        for field in ('ex_start', 'ex_end'):
            if ipaddress.IPv4Address(d[field]) not in _net(d['network'], d['mask']):
                problems.append((field, f'{d[field]} is not inside the DHCP network.'))
        if ipaddress.IPv4Address(d['ex_start']) > ipaddress.IPv4Address(d['ex_end']):
            problems.append(('ex_start', '"Exclude from" must not be after "Exclude to".'))
    return problems


# ---------------------------------------------------------------- the backend's plan checks
def check_switch_plan(plan):
    """Every problem in a switch plan (commands_switch), as messages. Empty: fine."""
    problems = []

    def add(where, problem):
        if problem:
            problems.append(f'{where}: {problem}')
    seen = set()
    for vid, name in plan.get('vlans', []):
        add(f'VLAN {vid}', check_vlan_id(str(vid)))
        if name:
            add(f'VLAN {vid} name', check_name(name, 'The VLAN name'))
        if vid in seen:
            add(f'VLAN {vid}', 'listed twice.')
        seen.add(vid)
    for spec, vid in plan.get('access_ports', []):
        add('Access ports', check_port_list(spec))
        add('Access ports VLAN', check_vlan_id(str(vid)))
    for t in plan.get('trunks', []):
        add('Trunk ports', check_port_list(t.get('ports')))
        if t.get('allowed'):
            add('Allowed VLANs', check_vlan_list(t['allowed']))
        if t.get('native') not in (None, ''):
            add('Native VLAN', check_vlan_id(str(t['native'])))
    for p in plan.get('port_security', []):
        add('Port security ports', check_port_list(p.get('ports')))
        add('Max MAC addresses', check_number(str(p.get('maximum', '')), 1, PORT_SECURITY_MAX,
                                              'Max MAC addresses'))
        if p.get('violation') not in VIOLATIONS:
            add('On violation', 'choose protect, restrict or shutdown.')
    for i in plan.get('interfaces', []):
        add('Interface ports', check_port_list(i.get('ports')))
        if i.get('description'):
            add('Description', check_description(i['description']))
        if i.get('state', '') not in STATES:
            add('State', 'choose shutdown or no shutdown.')
    return problems


def check_router_plan(plan):
    """Every problem in a router plan (commands_router), as messages. Empty: fine."""
    problems = []

    def add(where, problem):
        if problem:
            problems.append(f'{where}: {problem}')
    if plan.get('hostname'):
        add('Hostname', check_hostname(plan['hostname']))
    if plan.get('default_route'):
        add('Default route', check_ipv4(plan['default_route']))
    for server in plan.get('dns_servers') or []:
        add('DNS servers', check_ipv4(server))
    if plan.get('ntp_server'):
        add('NTP server', check_ipv4(plan['ntp_server']))
    d = plan.get('dhcp')
    if d:
        flat = dict(d, ex_start=(d.get('excluded') or ('', ''))[0],
                    ex_end=(d.get('excluded') or ('', ''))[1])
        for field, problem in check_dhcp(flat):
            add(f'DHCP {field}', problem)
    for i in plan.get('interfaces', []):
        add('Interface', check_interface_name(i.get('name')))
        found = check_interface_address(i.get('ip'), i.get('mask'))
        if found:
            add(f"Interface {i.get('name')}", found[1])
        if i.get('description'):
            add('Interface description', check_description(i['description']))
        if i.get('state', '') not in STATES:
            add('Interface state', 'choose shutdown or no shutdown.')
    seen = set()
    for network, mask, hop in plan.get('static_routes', []):
        found = check_static_route(network, mask, hop)
        if found:
            add(f'Static route {network}', found[1])
        key = (clean(network), clean(mask))
        if key in seen:
            add(f'Static route {network}', 'listed twice.')
        seen.add(key)
    return problems
