"""Cisco interface names and ranges, typed by the user.

Accepted (letters are not case-sensitive, spaces around '-' and ',' are fine):
    Fa0/1                    a single port          (FastEthernet0/1 works too)
    Fa0/1-5   Fa0/1 - 5      ports 1 to 5 in slot 0/
    Fa0/1-Fa0/5              the same, written in full
    Gi1/0/1-24               three-part numbers (stack/module/port)
    Fa0/1-5, Gi0/1-2         several pieces, separated by commas

parse_ports() turns that into "segments"; interface_lines() turns segments into
the IOS commands that select them:
    interface FastEthernet0/1
    interface range FastEthernet0/1 - 5 , GigabitEthernet0/1 - 2
"""
import re

# short and long spellings -> the name IOS prints in its configuration
TYPES = {
    'fa': 'FastEthernet', 'fastethernet': 'FastEthernet',
    'gi': 'GigabitEthernet', 'gigabitethernet': 'GigabitEthernet',
    'te': 'TenGigabitEthernet', 'tengigabitethernet': 'TenGigabitEthernet',
    'eth': 'Ethernet', 'ethernet': 'Ethernet', 'e': 'Ethernet',
}
SHORT = {'FastEthernet': 'Fa', 'GigabitEthernet': 'Gi', 'TenGigabitEthernet': 'Te',
         'Ethernet': 'Eth'}
MAX_RANGES_PER_COMMAND = 5           # IOS accepts at most 5 pieces in one "interface range"
MAX_PORT = 1000                      # far above any real switch; catches typing mistakes

_PORT = re.compile(r'^([A-Za-z]+)\s*(\d+(?:/\d+)*)$')


class PortError(ValueError):
    """A port or range the user typed is not valid (the message says why)."""


def parse_port(text):
    """'Fa0/1' -> ('FastEthernet', '0/', 1). The last number is the port; the
    numbers before it (with their slashes) are the slot prefix."""
    m = _PORT.match((text or '').strip())
    if not m:
        raise PortError(f'"{text.strip()}" is not a port name. Use for example Fa0/1 or Gi1/0/2.')
    kind = TYPES.get(m.group(1).lower())
    if kind is None:
        raise PortError(f'"{m.group(1)}" is not a known interface type. '
                        f'Use Fa / FastEthernet, Gi / GigabitEthernet or Te.')
    numbers = m.group(2)
    if '/' not in numbers:
        raise PortError(f'"{text.strip()}" needs a slot and a port, like Fa0/1.')
    prefix, port = numbers.rsplit('/', 1)
    port = int(port)
    if port > MAX_PORT:
        raise PortError(f'Port number {port} is too large.')
    return kind, prefix + '/', port


def parse_ports(text):
    """'Fa0/1-5, Gi0/1' -> [{'type','prefix','start','end'}, ...]. Raises PortError."""
    pieces = [p.strip() for p in (text or '').split(',')]
    if not any(pieces):
        raise PortError('Enter a port, a range or a list, for example Fa0/1-5.')
    segments = []
    for piece in pieces:
        if not piece:
            raise PortError('There is an empty item between two commas.')
        if '-' in piece:
            left, right = (s.strip() for s in piece.split('-', 1))
            kind, prefix, start = parse_port(left)
            if right.isdigit():
                end = int(right)
            else:
                kind2, prefix2, end = parse_port(right)
                if kind2 != kind:
                    raise PortError(f'"{piece}": a range must use one interface type '
                                    f'({kind} and {kind2} are different).')
                if prefix2 != prefix:
                    raise PortError(f'"{piece}": a range must stay in one slot '
                                    f'({SHORT[kind]}{prefix}... and {SHORT[kind2]}{prefix2}...).')
            if end < start:
                raise PortError(f'"{piece}" is reversed: the first port must be the lower one '
                                f'(write {SHORT[kind]}{prefix}{end}-{start}).')
            if end == start:
                raise PortError(f'"{piece}" starts and ends on the same port: write it as one port.')
        else:
            kind, prefix, start = parse_port(piece)
            end = start
        segments.append({'type': kind, 'prefix': prefix, 'start': start, 'end': end})
    _no_overlap(segments)
    return segments


def _no_overlap(segments):
    seen = {}
    for s in segments:
        for p in range(s['start'], s['end'] + 1):
            key = (s['type'], s['prefix'], p)
            if key in seen:
                raise PortError(f"{SHORT[s['type']]}{s['prefix']}{p} is listed more than once.")
            seen[key] = True


def segment_text(s):
    """IOS spelling of one segment: 'FastEthernet0/1' or 'FastEthernet0/1 - 5'."""
    first = f"{s['type']}{s['prefix']}{s['start']}"
    return first if s['start'] == s['end'] else f"{first} - {s['end']}"


def is_single(segments):
    return len(segments) == 1 and segments[0]['start'] == segments[0]['end']


def interface_lines(text):
    """The command(s) that select the typed ports. One port keeps the spelling the
    user typed (interface Fa0/1); anything else becomes 'interface range ...',
    split into several commands when there are more than 5 pieces."""
    segments = parse_ports(text)
    if is_single(segments):
        return [f'interface {text.strip()}']
    lines = []
    for i in range(0, len(segments), MAX_RANGES_PER_COMMAND):
        chunk = segments[i:i + MAX_RANGES_PER_COMMAND]
        lines.append('interface range ' + ' , '.join(segment_text(s) for s in chunk))
    return lines


def first_port(text):
    """The full name of the first port typed (used for verification commands)."""
    s = parse_ports(text)[0]
    return f"{s['type']}{s['prefix']}{s['start']}"


def port_count(text):
    return sum(s['end'] - s['start'] + 1 for s in parse_ports(text))
