"""Switch commands, built from the Configure page's forms (the "plan").

plan keys used here (each is optional):
  'vlans':          [(10, 'STAFF'), ...]
  'access_ports':   [('Fa0/1-5', 10), ...]               ports, ranges or lists
  'trunks':         [{'ports': 'Gi0/1', 'allowed': '10,20', 'native': 99,
                      'encapsulation': True}, ...]
  'port_security':  [{'ports': 'Fa0/1-5', 'maximum': 2, 'violation': 'shutdown',
                      'sticky': True}, ...]
  'interfaces':     [{'ports': 'Fa0/6', 'description': 'Printer', 'state': 'shutdown'}, ...]

Every builder returns (commands, checks). A check is (show command, text that
must appear in its output); apply_config runs them after the change and saves
only when all of them pass.
"""
from config.interfaces import first_port, interface_lines


def _on_ports(spec, body):
    """Select the ports, then send `body`. With more than 5 ranges IOS needs
    several 'interface range' commands, so the body is repeated after each."""
    cmds = []
    for line in interface_lines(spec):
        cmds += [line] + list(body)
    return cmds


def _show_interface(spec):
    return f'show running-config interface {first_port(spec)}'


def vlan_commands(plan):
    cmds, checks = [], []
    for vlan_id, name in plan.get('vlans', []):
        cmds += [f'vlan {vlan_id}', f'name {name}']
        checks.append(('show vlan brief', name))
    return cmds, checks


def access_port_commands(plan):
    cmds, checks = [], []
    for spec, vlan_id in plan.get('access_ports', []):
        cmds += _on_ports(spec, ['switchport mode access', f'switchport access vlan {vlan_id}'])
        checks.append((_show_interface(spec), f'switchport access vlan {vlan_id}'))
    return cmds, checks


def trunk_commands(plan):
    cmds, checks = [], []
    for t in plan.get('trunks', []):
        body = ['switchport trunk encapsulation dot1q'] if t.get('encapsulation') else []
        body.append('switchport mode trunk')
        if t.get('native'):
            body.append(f"switchport trunk native vlan {t['native']}")
        if t.get('allowed'):
            body.append(f"switchport trunk allowed vlan {t['allowed']}")
        cmds += _on_ports(t['ports'], body)
        show = _show_interface(t['ports'])
        checks.append((show, 'switchport mode trunk'))
        if t.get('allowed'):
            checks.append((show, f"switchport trunk allowed vlan {t['allowed']}"))
        if t.get('native') and int(t['native']) != 1:       # VLAN 1 is the default: not shown
            checks.append((show, f"switchport trunk native vlan {t['native']}"))
    return cmds, checks


def port_security_commands(plan):
    cmds, checks = [], []
    for p in plan.get('port_security', []):
        body = ['switchport mode access', 'switchport port-security',
                f"switchport port-security maximum {p.get('maximum', 1)}",
                f"switchport port-security violation {p.get('violation', 'shutdown')}"]
        if p.get('sticky'):
            body.append('switchport port-security mac-address sticky')
        cmds += _on_ports(p['ports'], body)
        checks.append((_show_interface(p['ports']), 'switchport port-security'))
    return cmds, checks


def interface_settings_commands(plan):
    cmds, checks = [], []
    for i in plan.get('interfaces', []):
        body = []
        if i.get('description'):
            body.append(f"description {i['description']}")
        if i.get('state') in ('shutdown', 'no shutdown'):
            body.append(i['state'])
        if not body:
            continue
        cmds += _on_ports(i['ports'], body)
        show = _show_interface(i['ports'])
        if i.get('description'):
            checks.append((show, f"description {i['description']}"))
        if i.get('state') == 'shutdown':           # 'no shutdown' is the default: not shown
            checks.append((show, '\n shutdown'))      # its own line, not "...violation shutdown"
    return cmds, checks


SWITCH_FEATURES = {'VLANs': vlan_commands, 'Access ports': access_port_commands,
                   'Trunk ports': trunk_commands, 'Port security': port_security_commands,
                   'Interface settings': interface_settings_commands}
# VLANs must exist before ports are assigned to them; risky changes go last.
FEATURE_ORDER = ['VLANs', 'Access ports', 'Trunk ports', 'Port security', 'Interface settings']


def build_commands(plan, selected):
    all_cmds, all_checks = [], []
    for name in sorted(selected, key=lambda n: FEATURE_ORDER.index(n)
                       if n in FEATURE_ORDER else len(FEATURE_ORDER)):
        if name in SWITCH_FEATURES:
            cmds, checks = SWITCH_FEATURES[name](plan)
            all_cmds += cmds
            all_checks += checks
    return all_cmds, all_checks
