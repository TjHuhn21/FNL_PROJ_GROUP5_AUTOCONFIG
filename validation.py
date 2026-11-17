"""Input checks. Every function returns an error message, or None when the
input is fine, so the screens can show the message in a message box."""
import ipaddress
import re

_NAME = re.compile(r'^[A-Za-z0-9._-]+$')
_VLAN_NAME = re.compile(r'^[A-Za-z0-9._-]+$')
_PORT = re.compile(r'^[A-Za-z]+\s?\d+(/\d+)*(\.\d+)?$')


def check_ip(text):
    try:
        ipaddress.IPv4Address(str(text).strip())
        return None
    except ValueError:
        return 'Enter a valid IPv4 address, like 192.168.1.10'


def check_name(name):
    name = (name or '').strip()
    if not name:
        return 'The name is required.'
    if len(name) > 80:
        return 'The name must be 80 characters or fewer.'
    if not _NAME.match(name):
        return 'The name can only use letters, numbers, dots, dashes, and underscores.'
    return None


def check_vlan(vlan_id, existing_ids=()):
    try:
        vlan_id = int(vlan_id)
    except (TypeError, ValueError):
        return 'The VLAN ID must be a number.'
    if vlan_id < 2 or vlan_id > 4094:
        return 'VLAN ID must be from 2 to 4094.'
    if 1002 <= vlan_id <= 1005:
        return 'VLANs 1002 to 1005 are reserved by Cisco. Pick another ID.'
    if vlan_id in existing_ids:
        return f'VLAN {vlan_id} is already in the list.'
    return None


def check_vlan_name(name):
    name = (name or '').strip()
    if not name:
        return 'The VLAN name is required.'
    if len(name) > 32:
        return 'The VLAN name must be 32 characters or fewer.'
    if not _VLAN_NAME.match(name):
        return 'The VLAN name cannot have spaces. Use letters, numbers, dots, dashes, or underscores.'
    return None


def check_port(text):
    text = (text or '').strip()
    if not text:
        return 'The port is required, for example Fa0/1.'
    if not _PORT.match(text):
        return 'Enter a port like Fa0/1 or Gi1/0/2.'
    return None


def check_mask(text):
    try:
        ipaddress.IPv4Network(f'0.0.0.0/{str(text).strip()}')
        return None
    except ValueError:
        return 'Enter a valid subnet mask, like 255.255.255.0'


# ---------------------------------------------------------------- ports and port ranges
def check_port_list(text):
    """One port, a range or a list: Fa0/1 | Fa0/1-5 | Fa0/1-Fa0/5 | Fa0/1-5, Gi0/1."""
    from config.interfaces import PortError, parse_ports
    try:
        parse_ports(text)
        return None
    except PortError as err:
        return str(err)


def check_single_interface(text):
    """Exactly one interface (a router interface, for example Gi0/0)."""
    from config.interfaces import PortError, is_single, parse_ports
    try:
        if not is_single(parse_ports(text)):
            return 'Enter one interface here, for example Gi0/0 (not a range or a list).'
        return None
    except PortError as err:
        return str(err)


# ---------------------------------------------------------------- VLAN lists (trunks)
def vlan_list(text):
    """'10, 20,30-32' -> [10, 20, 30, 31, 32]. Raises ValueError with a clear message."""
    numbers = set()
    for part in (text or '').replace(' ', '').split(','):
        if not part:
            raise ValueError('There is an empty item in the VLAN list.')
        if '-' in part:
            a, _, b = part.partition('-')
            if not (a.isdigit() and b.isdigit()):
                raise ValueError(f'"{part}" is not a VLAN range like 30-40.')
            a, b = int(a), int(b)
            if b < a:
                raise ValueError(f'"{part}" is reversed: write {b}-{a}.')
            span = range(a, b + 1)
        elif part.isdigit():
            span = [int(part)]
        else:
            raise ValueError(f'"{part}" is not a VLAN number.')
        for n in span:
            if not 1 <= n <= 4094:
                raise ValueError(f'VLAN {n} is outside 1 to 4094.')
            numbers.add(n)
    if not numbers:
        raise ValueError('Enter at least one VLAN, for example 10,20,30-40.')
    return sorted(numbers)


def compress_vlans(numbers):
    """[10, 20, 30, 31, 32] -> '10,20,30-32' (the way IOS prints a trunk's VLAN list)."""
    out, start, prev = [], None, None
    for n in sorted(numbers):
        if start is None:
            start = prev = n
        elif n == prev + 1:
            prev = n
        else:
            out.append(f'{start}-{prev}' if prev > start else str(start))
            start = prev = n
    if start is not None:
        out.append(f'{start}-{prev}' if prev > start else str(start))
    return ','.join(out)


def check_vlan_list(text):
    try:
        vlan_list(text)
        return None
    except ValueError as err:
        return str(err)


def check_vlan_number(text, allow_1=True):
    """A VLAN number for a native VLAN (1 is allowed there) or a port assignment."""
    try:
        n = int(str(text).strip())
    except ValueError:
        return 'The VLAN must be a number.'
    low = 1 if allow_1 else 2
    if not low <= n <= 4094:
        return f'The VLAN must be from {low} to 4094.'
    return None


# ---------------------------------------------------------------- names and text
_HOSTNAME = re.compile(r'^[A-Za-z]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?$')


def check_hostname(name):
    name = (name or '').strip()
    if not name:
        return 'The hostname is required.'
    if not _HOSTNAME.match(name):
        return ('A hostname must start with a letter, use only letters, numbers and dashes, '
                'not end with a dash, and be at most 63 characters.')
    return None


def check_description(text):
    text = (text or '').strip()
    if not text:
        return 'The description is empty.'
    if len(text) > 200:
        return 'The description must be 200 characters or fewer.'
    if '?' in text:
        return 'A description cannot contain "?" (the device would show its help text instead).'
    if any(ord(c) < 32 for c in text):
        return 'The description must be one line of plain text.'
    return None


# ---------------------------------------------------------------- networks
def check_network(address, mask):
    """address must be the network address for mask (for routes and DHCP pools)."""
    problem = check_ip(address) or check_mask(mask)
    if problem:
        return problem
    try:
        ipaddress.IPv4Network(f'{address.strip()}/{mask.strip()}', strict=True)
        return None
    except ValueError:
        real = ipaddress.IPv4Network(f'{address.strip()}/{mask.strip()}', strict=False)
        return (f'{address.strip()} is not a network address for mask {mask.strip()}. '
                f'Did you mean {real.network_address}?')


def check_ip_in_network(address, network, mask, what='The address'):
    problem = check_ip(address)
    if problem:
        return problem
    net = ipaddress.IPv4Network(f'{network.strip()}/{mask.strip()}', strict=False)
    if ipaddress.IPv4Address(address.strip()) not in net:
        return f'{what} {address.strip()} is not inside {net}.'
    return None


def check_host_address(address, mask):
    """An interface address: valid, and not the network or broadcast address."""
    problem = check_ip(address) or check_mask(mask)
    if problem:
        return problem
    net = ipaddress.IPv4Network(f'{address.strip()}/{mask.strip()}', strict=False)
    ip = ipaddress.IPv4Address(address.strip())
    if net.prefixlen < 31 and ip in (net.network_address, net.broadcast_address):
        return f'{ip} is the network or broadcast address of {net}; use a host address.'
    return None


def check_ip_order(first, last):
    problem = check_ip(first) or check_ip(last)
    if problem:
        return problem
    if ipaddress.IPv4Address(first.strip()) > ipaddress.IPv4Address(last.strip()):
        return f'The range is reversed: {first.strip()} comes after {last.strip()}.'
    return None
