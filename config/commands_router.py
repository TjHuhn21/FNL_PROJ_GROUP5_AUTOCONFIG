"""Router commands, built from the Configure page's forms (the "plan").

plan keys used here (each is optional):
  'hostname':      'R1'
  'interfaces':    [{'name': 'Gi0/0', 'ip': '192.168.1.1', 'mask': '255.255.255.0',
                     'description': 'LAN', 'state': 'no shutdown'}, ...]
  'dhcp':          {'pool': 'LAN', 'network': '192.168.1.0', 'mask': '255.255.255.0',
                    'gateway': '192.168.1.1', 'dns': '8.8.8.8',
                    'excluded': ('192.168.1.1', '192.168.1.20')}
  'default_route': '192.168.1.1'
  'static_routes': [('10.10.0.0', '255.255.0.0', '192.168.1.254'), ...]
  'dns_servers':   ['8.8.8.8', '1.1.1.1']          the router's own name servers
  'ntp_server':    '192.168.1.10'

Every builder returns (commands, checks), as in commands_switch.
"""


def hostname_commands(plan):
    name = plan.get('hostname')
    if not name:
        return [], []
    return [f'hostname {name}'], [('show running-config | include ^hostname', f'hostname {name}')]


def interface_commands(plan):
    cmds, checks = [], []
    for i in plan.get('interfaces', []):
        body = []
        if i.get('description'):
            body.append(f"description {i['description']}")
        if i.get('ip'):
            body.append(f"ip address {i['ip']} {i['mask']}")
        if i.get('state') in ('shutdown', 'no shutdown'):
            body.append(i['state'])
        if not body:
            continue
        cmds += [f"interface {i['name']}"] + body
        if i.get('ip'):
            checks.append(('show ip interface brief', i['ip']))
        if i.get('description'):
            checks.append((f"show running-config interface {i['name']}",
                           f"description {i['description']}"))
    return cmds, checks


def default_route_commands(plan):
    nxt = plan.get('default_route')
    if not nxt:
        return [], []
    return [f'ip route 0.0.0.0 0.0.0.0 {nxt}'], [('show ip route', nxt)]


def static_route_commands(plan):
    cmds, checks = [], []
    for network, mask, next_hop in plan.get('static_routes', []):
        line = f'ip route {network} {mask} {next_hop}'
        cmds.append(line)
        # the configuration line is checked (a route only enters the routing table
        # once its next hop is reachable, which is a network fact, not a config error)
        checks.append(('show running-config | include ip route', line))
    return cmds, checks


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


def dns_commands(plan):
    servers = plan.get('dns_servers') or []
    if not servers:
        return [], []
    return ([f"ip name-server {' '.join(servers)}"],
            [('show running-config | include name-server', servers[0])])


def ntp_commands(plan):
    server = plan.get('ntp_server')
    if not server:
        return [], []
    return [f'ntp server {server}'], [('show running-config | include ntp server',
                                       f'ntp server {server}')]


ROUTER_FEATURES = {'Hostname': hostname_commands, 'Interfaces': interface_commands,
                   'DHCP': dhcp_commands, 'Default route': default_route_commands,
                   'Static routes': static_route_commands, 'DNS servers': dns_commands,
                   'NTP': ntp_commands}
# Interfaces first (routes and DHCP need their networks), routes after DHCP.
FEATURE_ORDER = ['Hostname', 'Interfaces', 'DHCP', 'Default route', 'Static routes',
                 'DNS servers', 'NTP']


def build_commands(plan, selected):
    all_cmds, all_checks = [], []
    for name in sorted(selected, key=lambda n: FEATURE_ORDER.index(n)
                       if n in FEATURE_ORDER else len(FEATURE_ORDER)):
        if name in ROUTER_FEATURES:
            cmds, checks = ROUTER_FEATURES[name](plan)
            all_cmds += cmds
            all_checks += checks
    return all_cmds, all_checks
