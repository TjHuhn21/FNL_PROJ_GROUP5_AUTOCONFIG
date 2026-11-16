def vlan_commands(plan):
    cmds, checks = [], []
    for vlan_id, name in plan.get('vlans', []):
        cmds += [f'vlan {vlan_id}', f'name {name}']
        checks.append(('show vlan brief', name))
    return cmds, checks


def access_port_commands(plan):
    cmds = []
    for port, vlan_id in plan.get('access_ports', []):
        cmds += [f'interface {port}',
                 'switchport mode access',
                 f'switchport access vlan {vlan_id}']
    return cmds, []


SWITCH_FEATURES = {'VLANs': vlan_commands, 'Access ports': access_port_commands}
# VLANs must exist before ports are assigned to them; risky changes go last.
FEATURE_ORDER = ['VLANs', 'Access ports']


def build_commands(plan, selected):
    all_cmds, all_checks = [], []
    for name in sorted(selected, key=lambda n: FEATURE_ORDER.index(n)
                       if n in FEATURE_ORDER else len(FEATURE_ORDER)):
        if name in SWITCH_FEATURES:
            cmds, checks = SWITCH_FEATURES[name](plan)
            all_cmds += cmds
            all_checks += checks
    return all_cmds, all_checks
