from topology.graph import find_single_points


def interface_blocks(config):
    """Split a running-config into {'Fa0/1': ['switchport mode access', ...]}."""
    blocks, current = {}, None
    for line in config.splitlines():
        if line.startswith('interface '):
            current = line.split(' ', 1)[1].strip()
            blocks[current] = []
        elif current and line.startswith(' '):
            blocks[current].append(line.strip())
        else:
            current = None  # a line such as ! ends the block
    return blocks


def global_lines(config):
    """The top-level (global) commands of a running-config, one per item, with extra
    spaces removed. Comments (!), indented block lines (interface, line, ...) and
    banner text are left out, so their words can never be mistaken for commands.

    Banners: IOS shows them as  banner motd ^C  ...text...  ^C  (the text can span
    many lines), or on one line as  banner motd ^CHello^C.  Everything from the
    opening delimiter to the closing one is skipped."""
    in_banner, delim = False, ''
    for raw in config.splitlines():
        if in_banner:
            if delim in raw:                    # the closing delimiter ends the banner
                in_banner = False
            continue
        if not raw.strip() or raw[0] in ' \t!':
            continue
        line = ' '.join(raw.split())
        if line.startswith('banner '):
            body = line.split(' ', 2)[2] if line.count(' ') >= 2 else ''
            delim = '^C' if body.startswith('^C') else body[:1]
            in_banner = bool(delim) and delim not in body[len(delim):]   # one-line banner?
            continue
        yield line


def finding(device, rule, severity, message, commands):
    return {'device': device, 'rule': rule, 'severity': severity,
            'message': message, 'commands': commands}


def rule_telnet(name, config):
    lines = [l.strip() for l in config.splitlines()]
    if 'transport input all' in lines or 'transport input telnet' in lines:
        return [finding(name, 'telnet_enabled', 'high',
                        'Telnet is allowed on the remote login lines',
                        ['line vty 0 4', 'transport input ssh'])]
    return []


def rule_password_encryption(name, config):
    """Only the exact global command counts. A plain text search was wrong: the IOS
    default line  no service password-encryption  contains the same words."""
    enabled = False                             # IOS default: off
    for line in global_lines(config):
        if line == 'service password-encryption':
            enabled = True
        elif line == 'no service password-encryption':
            enabled = False                     # the last one wins, as on the device
    if not enabled:
        return [finding(name, 'no_password_encryption', 'medium',
                        'Password protection is disabled. Passwords may appear in clear '
                        'text in the configuration.',
                        ['service password-encryption'])]
    return []


def rule_port_security(name, config):
    found = []
    for iface, lines in interface_blocks(config).items():
        has_security = any(l.startswith('switchport port-security') for l in lines)
        if 'switchport mode access' in lines and not has_security:
            found.append(finding(
                name, 'no_port_security', 'medium',
                f'{iface} is an access port without port security',
                [f'interface {iface}',
                 'switchport port-security',
                 'switchport port-security maximum 2',
                 'switchport port-security violation shutdown']))
    return found


def rule_trunk_all_vlans(name, config):
    found = []
    for iface, lines in interface_blocks(config).items():
        allowed = any(l.startswith('switchport trunk allowed vlan') for l in lines)
        if 'switchport mode trunk' in lines and not allowed:
            found.append(finding(
                name, 'trunk_all_vlans', 'medium',
                f'{iface} is a trunk that allows every VLAN',
                [f'interface {iface}',
                 'switchport trunk allowed vlan 10,20,30']))  # edit VLAN list to match your network
    return found


def rule_single_points(devices, links):
    return [finding(n, 'single_point_of_failure', 'medium',
                    f'If {n} fails, part of the network is cut off',
                    ['Add a second uplink to this part of the network'])
            for n in find_single_points(devices, links)]


POINTS = {'high': 15, 'medium': 8, 'low': 3}
RULES = [rule_telnet, rule_password_encryption,
         rule_port_security, rule_trunk_all_vlans]


def review_network(devices, links, configs):
    """configs = {'SW1': 'text'}; returns (findings, score 0-100)."""
    findings = []
    for name, config in configs.items():
        for rule in RULES:
            findings += rule(name, config)
    findings += rule_single_points(devices, links)
    score = max(0, 100 - sum(POINTS[f['severity']] for f in findings))
    return findings, score
