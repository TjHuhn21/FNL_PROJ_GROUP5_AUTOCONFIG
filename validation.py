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
