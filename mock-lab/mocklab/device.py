"""The simulated configuration of one mock device, and the text of its show
commands. The formats imitate Cisco IOS output closely enough for NetCommand's
parsers and checks; they are not copied from Cisco software.

One Device is shared by every SSH session to it (guarded by a lock); it is
built fresh from lab_config.json each time the lab starts.
"""
import copy
import ipaddress
import re
import threading

from . import restore_sim

INTERFACE_TYPES = ['FastEthernet', 'GigabitEthernet', 'TenGigabitEthernet', 'Vlan', 'Loopback',
                   'Port-channel']
SHORT = {'FastEthernet': 'Fa', 'GigabitEthernet': 'Gi', 'TenGigabitEthernet': 'Te',
         'Vlan': 'Vl', 'Loopback': 'Lo', 'Port-channel': 'Po'}
RESERVED_VLANS = {1002: 'fddi-default', 1003: 'token-ring-default', 1004: 'fddinet-default',
                  1005: 'trnet-default'}

# Simulated SSH conditions (lab_config.json "ssh_condition"; for console detection tests).
# They only change what the show commands REPORT. The lab's own SSH server still accepts
# connections whatever the condition.
#   enabled      SSH on, RSA keys present (the default)
#   disabled     crypto image, but no RSA keys yet: "SSH Disabled"
#   unsupported  classic IOS image without crypto (no K9): the ssh/crypto commands do not exist
#   unknown      unrecognised software, and the ssh/crypto commands are blocked by authorization
SSH_CONDITIONS = ('enabled', 'disabled', 'unsupported', 'unknown')
# Edge-case behaviours a device can be given ("quirks" in lab_config / scenario specs).
# All are SIMULATIONS of situations NetCommand must handle safely; the wording of the
# simulated messages marked (SIMULATED) is not copied from real Cisco output, and none of
# them proves how real hardware behaves.
QUIRKS = {
    'rsa_slow': 'key generation reports a long simulated delay (Reply.delay_s, no real sleep)',
    'rsa_fails': 'key generation prints a failure and creates no key',
    'rsa_ask_modulus': '"crypto key generate rsa" without a size asks "How many bits in the '
                       'modulus [512]:"',
    'rsa_partial': 'key generation output stops before "[OK]"; the key list is unreadable '
                   'afterwards',
    'prompt_lag': 'after "hostname X" the next prompt still shows the old name once',
    'prompt_garbled': 'after "hostname X" the next prompt is cut off (no # or >) once',
    'domain_rejected': '"ip domain-name" is rejected',
    'ssh_v2_ignored': '"ip ssh version 2" is accepted, but show ip ssh keeps reporting 1.99',
    'ssh_v2_rejected': '"ip ssh version 2" is rejected',
    'syslog': 'system log lines are interleaved into command output',
    'legacy_ssh_only': 'the SSH server offers only SHA-1 key exchange / ssh-rsa / hmac-sha1',
    # restore simulation (restore_sim.py)
    'replace_unsupported': '"configure replace", "configure confirm" and "configure revert" '
                           'do not exist',
    'no_tcl': '"tclsh" does not exist',
    'no_scp': 'the SCP server refuses transfers even with "ip scp server enable"',
    'flash_overwrites': 'a transfer to an existing file name overwrites it silently (as IOS '
                        'does); by default the mock refuses',
    'transfer_fails': 'the connection is cut half way through a file transfer; a partial '
                      'file is left on flash',
    'transfer_corrupt': 'a transferred file is stored with one byte changed (MD5 mismatch)',
    'replace_partial': 'configure replace rejects the last command of the file and reports '
                       '"Rollback aborted"; the rest is applied',
    'revert_fails': 'the rollback (configure revert, or the timer) fails and leaves the '
                    'running configuration as it is',
    'drop_during_replace': 'configure replace is applied, then the connection is cut before '
                           'its output arrives',
    'reconnect_refused': 'after configure replace every new login is refused until a rollback',
    'verify_mismatch': 'after configure replace the device adds a line, so the running '
                       'configuration no longer matches the file',
    'delete_fails': '"delete" of a flash file fails (cleanup failure)',
    'reboot_during_restore': 'the device reloads during configure replace: running = startup, '
                             'the pending rollback is lost, sessions are cut',
    # restore engine (Phase 4F)
    'replace_prompts': 'configure replace asks a question even with "force" (an unexpected '
                       'prompt); only "y" would go on',
    'confirm_ignored': 'configure confirm answers nothing but the rollback timer stays '
                       'pending (a confirmation failure)',
    # saving to startup (Phase 4H)
    'save_fails': '"write memory" prints an NVRAM error and saves nothing',
    'save_prompts': '"write memory" asks "Overwrite the previous NVRAM configuration?'
                    '[confirm]" (as IOS does after an image change); Enter or y saves',
    'drop_during_save': '"write memory" saves, then the connection is cut before its output',
    'startup_mismatch': 'after "write memory" the startup configuration has one extra line, '
                        'so it no longer matches the running configuration',
}
# Device attributes that make up the running configuration (configure replace, rollback
# and reload swap these; ports, cables, keys, quirks and flash are physical and stay).
CONFIG_ATTRS = ('hostname', 'enable_secret', 'enable_configured','vlans', 'interfaces', 'routes', 'default_gateway',
                'dhcp_excluded', 'pools', 'name_servers', 'ntp_servers', 'global_lines', 'lines',
                'archive')
SYSLOG_LINES = ('*Nov 21 10:15:42.123: %LINK-3-UPDOWN: Interface GigabitEthernet0/1, changed '
                'state to up',
                '*Nov 21 10:15:43.456: %LINEPROTO-5-UPDOWN: Line protocol on Interface '
                'GigabitEthernet0/1, changed state to up')
AUTHORIZATION_FAILED = '% Command authorization failed.'
# show version lines per (type, condition), used only when "ssh_condition" is set in the
# spec. Every output still starts with the "NetCommand Mock Lab - simulated" line.
_PROFILES = {
    'router': {
        'crypto': ('Simulated IOS Software, C1900 Software (C1900-UNIVERSALK9-M), '
                   'Version 15.4(3)M2, RELEASE SOFTWARE (fc2)',
                   'flash0:c1900-universalk9-mz.SPA.154-3.M2.bin',
                   'Simulated CISCO1941/K9 (revision 1.0) with 491520K/32768K bytes of memory.'),
        'plain': ('Simulated IOS Software, C1900 Software (C1900-IPBASE-M), Version 15.1(4)M4, '
                  'RELEASE SOFTWARE (fc1)',
                  'flash0:c1900-ipbase-mz.SPA.151-4.M4.bin',
                  'Simulated CISCO1941/K9 (revision 1.0) with 491520K/32768K bytes of memory.'),
    },
    'switch': {
        'crypto': ('Simulated IOS Software, C2960 Software (C2960-LANBASEK9-M), '
                   'Version 15.0(2)SE11, RELEASE SOFTWARE (fc3)',
                   'flash:c2960-lanbasek9-mz.150-2.SE11.bin',
                   'Simulated WS-C2960-24TT-L (PowerPC405) processor (revision B0) with '
                   '65536K bytes of memory.\nModel number                    : WS-C2960-24TT-L'),
        'plain': ('Simulated IOS Software, C2960 Software (C2960-LANBASE-M), '
                  'Version 12.2(55)SE12, RELEASE SOFTWARE (fc2)',
                  'flash:c2960-lanbase-mz.122-55.SE12.bin',
                  'Simulated WS-C2960-24TT-L (PowerPC405) processor (revision B0) with '
                  '65536K bytes of memory.\nModel number                    : WS-C2960-24TT-L'),
    },
}


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

    def __init__(self, spec, lab_hosts=None, clock=None):
        self.lock = threading.RLock()
        self.clock = clock or restore_sim.SimClock()     # simulated time (never real sleeps)
        self.spec = spec
        self.name = spec['name']
        self.kind = spec['type']                         # 'router' or 'switch'
        self.host = spec['host']
        self.hostname = spec.get('hostname', spec['name'])
        self.model = spec.get('model', f'NetCommand mock {self.kind}')
        # Two separate facts (phase 5.1.3, M3):
        #   enable_configured  False ONLY for a factory device (spec "no_enable_secret"):
        #                      `enable` on its console needs no password
        #   enable_secret      the password `enable` accepts; None = not known (for example
        #                      a replayed hash that cannot be reversed): `enable` is refused
        self.enable_configured = not spec.get('no_enable_secret')
        self.enable_secret = (spec.get('enable_secret') or spec['password']) \
            if self.enable_configured else None
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
        # simulated SSH condition: None keeps the original show version text
        self.ssh_profile = spec.get('ssh_condition')
        self.ssh_condition = self.ssh_profile or 'enabled'
        self.rsa_keys = self.ssh_condition == 'enabled'      # the key SSH uses (hostname.domain)
        # other key pairs that exist besides SSH's, e.g. "TP-self-signed-1234" (HTTPS)
        self.extra_rsa_keys = list(spec.get('extra_rsa_keys') or [])
        # VTY lines the device has (show line), when more than the configured ranges
        self.vty_count = spec.get('vty_count')
        self.quirks = set(spec.get('quirks') or [])
        unknown = self.quirks - set(QUIRKS)
        if unknown:
            raise ValueError(f'unknown quirk(s): {", ".join(sorted(unknown))}')
        # the label of SSH's key: fixed when the key is made (a later rename keeps it)
        self.rsa_label = f'{self.hostname}.{self.domain_name() or "lab.local"}'
        self.rsa_bits = 2048
        self.rsa_listing_broken = False      # rsa_partial: the key list cannot be read
        self.lab_hosts = lab_hosts or {}                 # neighbour name -> (host, type)
        # restore simulation (restore_sim.py). None of it is in the default lab config, so
        # the default devices' running configurations are unchanged.
        archive = spec.get('archive')
        self.archive = None if archive is None else {
            'path': archive.get('path'), 'maximum': archive.get('maximum'),
            'write_memory': bool(archive.get('write_memory')),
            'time_period': archive.get('time_period')}
        self.management_ip = spec.get('management_ip')  # SIMULATED address NetCommand uses
        # restore preflight (Phase 4E), both optional and absent from the default lab:
        # "serial": a synthetic chassis serial (or a list, to simulate an ambiguous device),
        # shown as "Processor board ID" in show version; "inventory": the entries of
        # "show inventory" (the command exists only when this key is given).
        serial = spec.get('serial')
        self.serials = [] if serial is None else ([serial] if isinstance(serial, str)
                                                  else list(serial))
        self.inventory = None if spec.get('inventory') is None else \
            [dict(item) for item in spec['inventory']]
        self.flash = restore_sim.Flash.for_device(self, spec)
        self.archive_copies = []                         # flash names, oldest first
        self.archive_next = 1
        self.rollback = None                             # a pending restore_sim.Rollback
        self.logins_refused = False                      # reconnect_refused
        self.boot_count = 0
        self.booting_until = None
        self.events = []                                 # (simulated time, kind, detail)
        self.startup = self.running_config()             # as if saved before the lab started
        self.saves = 0

    # ---------------------------------------------------------------- restore simulation
    def config_state(self):
        return copy.deepcopy({attr: getattr(self, attr) for attr in CONFIG_ATTRS})

    def set_config_state(self, state):
        for attr in CONFIG_ATTRS:
            setattr(self, attr, copy.deepcopy(state[attr]))

    def event(self, kind, detail=''):
        self.events.append((self.clock.now(), kind, detail))

    def tick(self):
        with self.lock:
            restore_sim.tick(self)

    def booting(self):
        return self.booting_until is not None and self.clock.now() < self.booting_until

    def reachable(self):
        """Can NetCommand reach the device? Not while it reloads, and (when management_ip
        is set) not once no up interface has that address any more."""
        with self.lock:
            restore_sim.tick(self)
            if self.booting():
                return False
            if self.management_ip is None:
                return True
            return any(i.ip == self.management_ip and i.is_up()
                       for i in self.interfaces.values())

    def scp_enabled(self):
        return (self.ssh_commands_exist() and 'no_scp' not in self.quirks
                and 'ip scp server enable' in self.global_lines)

    def reload(self, reason='reload'):
        with self.lock:
            restore_sim.reload(self, reason)

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
        if self.archive is not None:
            L.append('archive')
            if self.archive.get('path'):
                L.append(f" path {self.archive['path']}")
            if self.archive.get('maximum'):
                L.append(f" maximum {self.archive['maximum']}")
            if self.archive.get('write_memory'):
                L.append(' write-memory')
            if self.archive.get('time_period'):
                L.append(f" time-period {self.archive['time_period']}")
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
        serials = ''.join(f'Processor board ID {s}\n' for s in self.serials)
        if self.ssh_profile in ('enabled', 'disabled', 'unsupported'):
            software, image, hardware = _PROFILES[self.kind][
                'plain' if self.ssh_profile == 'unsupported' else 'crypto']
            return (f'NetCommand Mock Lab - simulated {self.kind} (not Cisco software)\n'
                    f'{software}\n\n'
                    f'{self.hostname} uptime is 1 hour, 2 minutes\n'
                    f'System image file is "{image}"\n\n'
                    f'{hardware}\n{serials}'
                    f'Configuration register is 0x2102')
        return (f'NetCommand Mock Lab - simulated {self.kind} (not Cisco software)\n'
                f'Mock software, Version 15.2(mock), RELEASE SOFTWARE\n\n'
                f'{self.hostname} uptime is 1 hour, 2 minutes\n'
                f'System image file is "mock:netcommand-lab.bin"\n\n'
                f'{self.model} with 262144K bytes of memory.\n{serials}'
                f'Configuration register is 0x2102')

    def show_inventory(self):
        """IOS-style "show inventory" from the spec's synthetic "inventory" entries."""
        rows = []
        for item in self.inventory or []:
            rows += [f'NAME: "{item.get("name", "")}", DESCR: "{item.get("descr", "")}"',
                     f'PID: {item.get("pid", ""):<18}, VID: {item.get("vid", "V01")} , '
                     f'SN: {item.get("sn", "")}', '']
        return '\n'.join(rows).rstrip('\n')

    # ---------------------------------------------------------------- SSH-related shows
    def domain_name(self):
        for line in self.global_lines:
            m = re.match(r'ip domain[ -]name (\S+)$', line)
            if m:
                return m.group(1)
        return None

    def ssh_commands_exist(self):
        """False on the simulated image without crypto: the commands are not in its CLI."""
        return self.ssh_condition != 'unsupported'

    def show_ip_ssh(self):
        if self.ssh_condition == 'unknown':
            return AUTHORIZATION_FAILED
        version = '2.0' if ('ip ssh version 2' in self.global_lines
                            and 'ssh_v2_ignored' not in self.quirks) else '1.99'
        timeout, retries = 120, 3
        for line in self.global_lines:
            m = re.fullmatch(r'ip ssh time-out (\d+)', line)
            timeout = int(m.group(1)) if m else timeout
            m = re.fullmatch(r'ip ssh authentication-retries (\d+)', line)
            retries = int(m.group(1)) if m else retries
        if self.rsa_keys:
            return (f'SSH Enabled - version {version}\n'
                    'Authentication methods:publickey,keyboard-interactive,password\n'
                    f'Authentication timeout: {timeout} secs; Authentication retries: {retries}\n'
                    'Minimum expected Diffie Hellman key size : 2048 bits\n'
                    'IOS Keys in SECSH format(ssh-rsa, base64 encoded): '
                    f'{self.rsa_label}\n'
                    'AAAAB3NzaC1yc2EAAAADAQABAAABAQ-SIMULATED-KEY')
        return ('SSH Disabled - version 1.99\n'
                '%Please create RSA keys to enable SSH (and of atleast 768 bits for SSH v2).\n'
                'Authentication methods:publickey,keyboard-interactive,password\n'
                'Authentication timeout: 120 secs; Authentication retries: 3\n'
                'Minimum expected Diffie Hellman key size : 1024 bits\n'
                'IOS Keys in SECSH format(ssh-rsa, base64 encoded): NONE')

    def show_crypto_key(self):
        if self.ssh_condition == 'unknown':
            return AUTHORIZATION_FAILED
        names = ([self.rsa_label] if self.rsa_keys else []) + self.extra_rsa_keys
        if self.rsa_listing_broken:               # rsa_partial: generation never finished
            return ('% Key pair was generated at: 10:15:00 UTC Nov 18 2026\n'
                    ' Key Data:\n  30820122 300D0609 (SIMULATED: listing incomplete)')
        return '\n'.join(
            f'% Key pair was generated at: 10:15:00 UTC Nov 18 2026\n'
            f'Key name: {name}\n'
            f'Key type: RSA KEYS\n'
            f' Storage Device: not specified\n'
            f' Usage: General Purpose Key\n'
            f' Key is not exportable.\n'
            f' Key Data:\n'
            f'  30820122 300D0609 2A864886 F70D0101 01050003 82010F00 3082010A 02820101\n'
            f'  00SIMULA TEDKEY00 00000000 00000000 00000000 00000000 00000000 00000000'
            for name in names)

    def vty_numbers(self):
        numbers = set(range(max(5, int(self.vty_count or 0))))
        for name in self.lines:
            m = re.fullmatch(r'vty (\d+)(?: (\d+))?', name)
            if m:
                numbers.update(range(int(m.group(1)), int(m.group(2) or m.group(1)) + 1))
        return sorted(numbers)

    def show_line(self):
        out = ['   Tty Line Typ     Tx/Rx    A Modem  Roty AccO AccI  Uses  Noise Overruns  Int',
               '*     0    0 CTY              -    -      -    -    -     0      0    0/0      -']
        first = 1
        if self.kind == 'router':
            out.append('      1    1 AUX   9600/9600  -    -      -    -    -     0      0    0/0'
                       '      -')
            first = 2
        for n, _ in enumerate(self.vty_numbers()):
            tty = first + n
            out.append(f'{tty:>7}{tty:>5} VTY              -    -      -    -    -     0      0'
                       f'    0/0      -')
        return '\n'.join(out)

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
