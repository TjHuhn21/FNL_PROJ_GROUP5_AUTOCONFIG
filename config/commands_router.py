# plan keys used here:
#   'default_route': '192.168.1.1'
#   'dhcp': {'pool': 'LAN', 'network': '192.168.1.0', 'mask': '255.255.255.0',
#            'gateway': '192.168.1.1', 'dns': '8.8.8.8',
#            'excluded': ('192.168.1.1', '192.168.1.20')}
def default_route_commands(plan):
    nxt = plan.get('default_route')
    if not nxt:
        return [], []
    return [f'ip route 0.0.0.0 0.0.0.0 {nxt}'], [('show ip route', nxt)]


def dhcp_commands(plan):
    d = plan.get('dhcp')
    if not d:
        return [], []
    cmds = []
    if d.get('excluded'):
        start, end = d['excluded']
        cmds.append(f'ip dhcp excluded-address {start} {end}')
    cmds += [f"ip dhcp pool {d['pool']}",
             f"network {d['network']} {d['mask']}",
             f"default-router {d['gateway']}",
             f"dns-server {d['dns']}"]
    return cmds, [('show ip dhcp pool', d['pool'])]


ROUTER_FEATURES = {'Default route': default_route_commands,
                   'DHCP': dhcp_commands}
FEATURE_ORDER = ['DHCP', 'Default route']


def build_commands(plan, selected):
    all_cmds, all_checks = [], []
    for name in sorted(selected, key=lambda n: FEATURE_ORDER.index(n)
                       if n in FEATURE_ORDER else len(FEATURE_ORDER)):
        if name in ROUTER_FEATURES:
            cmds, checks = ROUTER_FEATURES[name](plan)
            all_cmds += cmds
            all_checks += checks
    return all_cmds, all_checks
