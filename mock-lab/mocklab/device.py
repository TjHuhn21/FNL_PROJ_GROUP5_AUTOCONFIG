"""The simulated configuration of one mock device, and the text of its show
commands. The formats imitate Cisco IOS output closely enough for NetCommand's
parsers and checks; they are not copied from Cisco software.

One Device is shared by every SSH session to it (guarded by a lock); it is
built fresh from lab_config.json each time the lab starts.
"""
import ipaddress
import re
import threading

INTERFACE_TYPES = ['FastEthernet', 'GigabitEthernet', 'TenGigabitEthernet', 'Vlan', 'Loopback',
                   'Port-channel']
SHORT = {'FastEthernet': 'Fa', 'GigabitEthernet': 'Gi', 'TenGigabitEthernet': 'Te',
         'Vlan': 'Vl', 'Loopback': 'Lo', 'Port-channel': 'Po'}
RESERVED_VLANS = {1002: 'fddi-default', 1003: 'token-ring-default', 1004: 'fddinet-default',
                  1005: 'trnet-default'}


def short_name(name):
    for full, short in SHORT.items():
        if name.startswith(full):
            return short + name[len(full):]
    return name


def compress(numbers):
    """[10, 20, 30, 31, 32] -> '10,20,30-32'."""
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


class Interface:
    def __init__(self, name, physical=True):
        self.name, self.physical = name, physical
        self.description = ''
        self.shutdown = False
        self.ip = self.mask = None
        self.mode = None                  # None (dynamic), 'access' or 'trunk'
        self.access_vlan = 1
        self.encapsulation = None         # 'dot1q' once set
        self.native = 1
        self.allowed = None               # None = all VLANs, else a set
        self.ps_enabled, self.ps_max, self.ps_violation, self.ps_sticky = False, 1, 'shutdown', False
        self.connected = False            # a cable is plugged in (status up/up when not shut)
        self.extra = []                   # other accepted lines (duplex, spanning-tree portfast...)

    def network(self):
        if not self.ip:
            return None
        return ipaddress.IPv4Interface(f'{self.ip}/{self.mask}').network

    def is_up(self):
        return not self.shutdown and (self.connected or not self.physical)


class Device:
    """spec: one entry of lab_config.json's "devices" (already checked by lab.py)."""

    def __init__(self, spec, lab_hosts=None):
        self.lock = threading.RLock()
        self.spec = spec
        self.name = spec['name']
        self.kind = spec['type']                         # 'router' or 'switch'
        self.host = spec['host']
        self.hostname = spec.get('hostname', spec['name'])
        self.model = spec.get('model', f'NetCommand mock {self.kind}')
        self.enable_secret = spec.get('enable_secret') or spec['password']
        self.start_privileged = bool(spec.get('start_privileged', self.kind == 'switch'))
        self.trunk_encapsulation = spec.get('trunk_encapsulation', 'required' if self.kind == 'switch'
                                            else 'unsupported')   # required | unsupported
        self.vlans = {1: 'default'}
        for vid, name in (spec.get('vlans') or {}).items():
            self.vlans[int(vid)] = name
        self.interfaces = {}
        for kind, count in (spec.get('ports') or {}).items():
            first = 0 if kind == 'GigabitEthernet' and self.kind == 'router' else 1
            for n in range(first, first + int(count)):
                name = f'{kind}0/{n}'
                self.interfaces[name] = Interface(name)
                if self.kind == 'router':
                    self.interfaces[name].shutdown = True     # router ports start shut down
        if self.kind == 'switch':
            self.interfaces['Vlan1'] = Interface('Vlan1', physical=False)
        for name, s in (spec.get('interfaces') or {}).items():
            intf = self.interfaces.get(name) or self._create(name)
            intf.description = s.get('description', '')
            intf.shutdown = bool(s.get('shutdown', intf.shutdown))
            intf.connected = bool(s.get('connected', False))
            if s.get('ip'):
                intf.ip, intf.mask = s['ip'], s['mask']
            if s.get('mode'):
                intf.mode = s['mode']
            if s.get('access_vlan'):
                intf.access_vlan = int(s['access_vlan'])
            if s.get('encapsulation'):
                intf.encapsulation = s['encapsulation']
        self.routes = [tuple(r) for r in spec.get('static_routes') or []]
        self.default_gateway = spec.get('default_gateway')
        self.dhcp_excluded = [tuple(e) for e in spec.get('dhcp_excluded') or []]
        self.pools = {p['name']: {'network': p.get('network'), 'mask': p.get('mask'),
                                  'default_router': p.get('default_router'),
                                  'dns': list(p.get('dns') or [])}
                      for p in spec.get('dhcp_pools') or []}
        self.name_servers = list(spec.get('name_servers') or [])
        self.ntp_servers = list(spec.get('ntp_servers') or [])
        self.global_lines = list(spec.get('global_lines') or [])
        self.lines = {k: list(v) for k, v in (spec.get('line_config') or
                                              {'con 0': [], 'vty 0 4': ['login local',
                                                                        'transport input ssh']}).items()}
        self.cdp = [dict(n) for n in spec.get('cdp_neighbors') or []]
        self.lab_hosts = lab_hosts or {}                 # neighbour name -> (host, type)
        self.startup = self.running_config()             # as if saved before the lab started
        self.saves = 0

    # ---------------------------------------------------------------- interfaces
    def _create(self, name):
        intf = Interface(name, physical=not name.startswith(('Vlan', 'Loopback')))
        self.interfaces[name] = intf
        return intf

    def ordered_interfaces(self):
        def key(name):
            kind = re.match(r'[A-Za-z-]+', name).group()
            nums = [int(n) for n in re.findall(r'\d+', name[len(kind):])]
            return (INTERFACE_TYPES.index(kind) if kind in INTERFACE_TYPES else 99, nums)
        return [self.interfaces[n] for n in sorted(self.interfaces, key=key)]

    # ---------------------------------------------------------------- running-config
    def running_config(self):
        L = ['!', 'version 15.2', 'service timestamps debug datetime msec',
             'service timestamps log datetime msec']
        if not any(g.endswith('service password-encryption') for g in self.global_lines):
            L.append('no service password-encryption')
        L += [g for g in self.global_lines if g.endswith('service password-encryption')]
        L += ['!', f'hostname {self.hostname}', '!', 'boot-start-marker', 'boot-end-marker', '!']
        L += [g for g in self.global_lines if not g.endswith('service password-encryption')]
        if self.global_lines:
            L.append('!')
        if self.kind == 'router':
            for start, end in self.dhcp_excluded:
                L.append(f'ip dhcp excluded-address {start}' + (f' {end}' if end else ''))
            if self.dhcp_excluded:
                L.append('!')
            for name, p in self.pools.items():
                L.append(f'ip dhcp pool {name}')
                if p['network']:
                    L.append(f" network {p['network']} {p['mask']}")
                if p['default_router']:
                    L.append(f" default-router {p['default_router']}")
                if p['dns']:
                    L.append(f" dns-server {' '.join(p['dns'])}")
                L.append('!')
        if self.name_servers:
            L += [f"ip name-server {' '.join(self.name_servers)}", '!']
        if self.kind == 'switch':
            L += ['spanning-tree mode pvst', 'spanning-tree extend system-id', '!',
                  'vtp mode transparent', '!']
            for vid in sorted(self.vlans):
                if vid != 1 and vid not in RESERVED_VLANS:
                    L.append(f'vlan {vid}')
                    if self.vlans[vid] != default_vlan_name(vid):
                        L.append(f' name {self.vlans[vid]}')
                    L.append('!')
        for intf in self.ordered_interfaces():
            L.append(f'interface {intf.name}')
            L += [' ' + line for line in self.interface_lines(intf)]
            L.append('!')
        if self.kind == 'router':
            L += ['ip forward-protocol nd', '!']
        if self.default_gateway:
            L += [f'ip default-gateway {self.default_gateway}', '!']
        for net, mask, nh in self.routes:
            L.append(f'ip route {net} {mask} {nh}')
        if self.routes:
            L.append('!')
        for server in self.ntp_servers:
            L.append(f'ntp server {server}')
        if self.ntp_servers:
            L.append('!')
        for name, sub in self.lines.items():
            L.append(f'line {name}')
            L += [' ' + s for s in sub]
        L += ['!', 'end']
        body = '\n'.join(L)
        return f'Building configuration...\n\nCurrent configuration : {len(body)} bytes\n{body}'

    def interface_lines(self, i):
        L = []
        if i.description:
            L.append(f'description {i.description}')
        if self.kind == 'switch' and i.physical:
            if i.encapsulation:
                L.append(f'switchport trunk encapsulation {i.encapsulation}')
            if i.native != 1:
                L.append(f'switchport trunk native vlan {i.native}')
            if i.allowed is not None:
                L.append('switchport trunk allowed vlan ' + (compress(i.allowed) if i.allowed
                                                              else 'none'))
            if i.access_vlan != 1:
                L.append(f'switchport access vlan {i.access_vlan}')
            if i.mode:
                L.append(f'switchport mode {i.mode}')
            if i.ps_max != 1:
                L.append(f'switchport port-security maximum {i.ps_max}')
            if i.ps_violation != 'shutdown':
                L.append(f'switchport port-security violation {i.ps_violation}')
            if i.ps_sticky:
                L.append('switchport port-security mac-address sticky')
            if i.ps_enabled:
                L.append('switchport port-security')
        if not (self.kind == 'switch' and i.physical):
            L.append(f'ip address {i.ip} {i.mask}' if i.ip else 'no ip address')
        L += i.extra
        if i.shutdown:
            L.append('shutdown')
        if self.kind == 'router' and i.physical:
            L += ['duplex auto', 'speed auto']
        return L

    def interface_config(self, name):
        i = self.interfaces[name]
        body = '\n'.join(['!', f'interface {i.name}'] + [' ' + l for l in self.interface_lines(i)]
                         + ['end'])
        return f'Building configuration...\n\nCurrent configuration : {len(body)} bytes\n{body}'

    def save(self):
        self.startup = self.running_config()
        self.saves += 1

    # ---------------------------------------------------------------- show commands
    def show_version(self):
        return (f'NetCommand Mock Lab - simulated {self.kind} (not Cisco software)\n'
                f'Mock software, Version 15.2(mock), RELEASE SOFTWARE\n\n'
                f'{self.hostname} uptime is 1 hour, 2 minutes\n'
                f'System image file is "mock:netcommand-lab.bin"\n\n'
                f'{self.model} with 262144K bytes of memory.\n'
                f'Configuration register is 0x2102')

    def show_ip_interface_brief(self):
        out = [f"{'Interface':<23}{'IP-Address':<16}OK? Method {'Status':<22}Protocol"]
        for i in self.ordered_interfaces():
            ip = i.ip or 'unassigned'
            method = 'manual' if i.ip else 'unset'
            if i.shutdown:
                status, proto = 'administratively down', 'down'
            elif i.is_up():
                status, proto = 'up', 'up'
            else:
                status, proto = 'down', 'down'
            out.append(f'{i.name:<23}{ip:<16}YES {method:<7}{status:<22}{proto}')
        return '\n'.join(out)

    def show_vlan_brief(self):
        out = [f"{'VLAN':<5}{'Name':<33}{'Status':<10}Ports",
               f"{'-' * 4} {'-' * 32} {'-' * 9} {'-' * 31}"]
        for vid in sorted(set(self.vlans) | set(RESERVED_VLANS)):
            name = self.vlans.get(vid) or RESERVED_VLANS[vid]
            status = 'act/unsup' if vid in RESERVED_VLANS else 'active'
            ports = [short_name(i.name) for i in self.ordered_interfaces()
                     if i.physical and i.mode != 'trunk' and i.access_vlan == vid]
            rows, cur = [], ''
            for p in ports:
                piece = p if not cur else f'{cur}, {p}'
                if len(piece) > 31:
                    rows.append(cur + ',')
                    cur = p
                else:
                    cur = piece
            rows.append(cur)
            out.append(f'{vid:<5}{name:<33}{status:<10}{rows[0]}'.rstrip())
            out += [' ' * 48 + r for r in rows[1:]]
        return '\n'.join(out)

    def show_interfaces_trunk(self):
        trunks = [i for i in self.ordered_interfaces() if i.mode == 'trunk']
        if not trunks:
            return ''
        out = [f"{'Port':<12}{'Mode':<13}{'Encapsulation':<16}{'Status':<14}Native vlan"]
        for i in trunks:
            out.append(f"{short_name(i.name):<12}{'on':<13}{(i.encapsulation and '802.1q') or '802.1q':<16}"
                       f"{'trunking' if i.is_up() else 'not-trunking':<14}{i.native}")
        out += ['', f"{'Port':<12}Vlans allowed on trunk"]
        for i in trunks:
            out.append(f"{short_name(i.name):<12}"
                       f"{'1-4094' if i.allowed is None else (compress(i.allowed) or 'none')}")
        return '\n'.join(out)

    def connected_networks(self):
        return [(i.network(), i) for i in self.ordered_interfaces() if i.ip and i.is_up()]

    def route_usable(self, next_hop):
        nh = ipaddress.IPv4Address(next_hop)
        return any(nh in net for net, _ in self.connected_networks())

    def show_ip_route(self):
        if self.kind == 'switch':
            gw = self.default_gateway or 'not set'
            return (f'Default gateway is {gw}\n\n'
                    f'Host               Gateway           Last Use    Total Uses  Interface\n'
                    f'ICMP redirect cache is empty')
        out = ['Codes: L - local, C - connected, S - static, R - RIP, M - mobile, B - BGP',
               '       D - EIGRP, EX - EIGRP external, O - OSPF, IA - OSPF inter area',
               '       * - candidate default, U - per-user static route, o - ODR', '']
        usable = [r for r in self.routes if self.route_usable(r[2])]
        default = next((r for r in usable if r[0] == '0.0.0.0' and r[1] == '0.0.0.0'), None)
        out.append(f'Gateway of last resort is {default[2]} to network 0.0.0.0' if default
                   else 'Gateway of last resort is not set')
        out.append('')
        entries = []
        for net, i in self.connected_networks():
            entries.append((net, f'C        {net} is directly connected, {i.name}'))
            entries.append((ipaddress.IPv4Network(f'{i.ip}/32'),
                            f'L        {i.ip}/32 is directly connected, {i.name}'))
        for net, mask, nh in usable:
            n = ipaddress.IPv4Network(f'{net}/{mask}')
            code = 'S*' if n.prefixlen == 0 else 'S '
            entries.append((n, f'{code}       {n} [1/0] via {nh}'))
        entries.sort(key=lambda e: (int(e[0].network_address), e[0].prefixlen))
        out += [e[1] for e in entries]
        return '\n'.join(out)

    def show_dhcp_pool(self):
        out = []
        for name, p in self.pools.items():
            out += [f'', f'Pool {name} :',
                    ' Utilization mark (high/low)    : 100 / 0',
                    ' Subnet size (first/next)       : 0 / 0 ']
            if p['network']:
                net = ipaddress.IPv4Network(f"{p['network']}/{p['mask']}", strict=False)
                hosts = max(net.num_addresses - 2, 0)
                first = net.network_address + 1
                last = net.broadcast_address - 1
                out += [f' Total addresses                : {hosts}',
                        ' Leased addresses               : 0',
                        ' Pending event                  : none',
                        ' 1 subnet is currently in the pool :',
                        ' Current index        IP address range                    Leased addresses',
                        f' {str(first):<21}{str(first):<17}- {str(last):<18}0']
            else:
                out += [' Total addresses                : 0', ' Leased addresses               : 0',
                        ' Pending event                  : none',
                        ' 0 subnet is currently in the pool :']
        return '\n'.join(out).lstrip('\n')

    def show_cdp_neighbors_detail(self):
        blocks = []
        for n in self.cdp:
            host, kind = self.lab_hosts.get(n['device'], ('', 'switch'))
            caps = 'Router Source-Route-Bridge' if kind == 'router' else 'Switch IGMP'
            platform = f'NetCommand mock {kind}'
            blocks.append('\n'.join([
                '-------------------------',
                f"Device ID: {n['device']}.lab.local",
                'Entry address(es): ',
                f'  IP address: {host}',
                f'Platform: {platform},  Capabilities: {caps} ',
                f"Interface: {n['local']},  Port ID (outgoing port): {n['remote']}",
                'Holdtime : 155 sec', '',
                'Version :', 'Mock software, Version 15.2(mock)', '',
                'advertisement version: 2',
                'Management address(es): ',
                f'  IP address: {host}', '']))
        return '\n'.join(blocks)

    def show_cdp_neighbors(self):
        out = ['Capability Codes: R - Router, T - Trans Bridge, B - Source Route Bridge',
               '                  S - Switch, H - Host, I - IGMP, r - Repeater', '',
               'Device ID        Local Intrfce     Holdtme    Capability  Platform  Port ID']
        for n in self.cdp:
            kind = self.lab_hosts.get(n['device'], ('', 'switch'))[1]
            out.append(f"{n['device'] + '.lab.local':<17}{short_name(n['local']):<18}155"
                       f"{'R B' if kind == 'router' else 'S I':>14}       Mock      "
                       f"{short_name(n['remote'])}")
        return '\n'.join(out)


def default_vlan_name(vid):
    return f'VLAN{vid:04d}'
