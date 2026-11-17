"""The command line of one SSH session to a mock device.

    session = Session(device)
    session.prompt()                 -> 'R1>'
    session.handle('enable')         -> Reply(output='Password: ', echo_next=False, ...)

Modes and prompts (as on Cisco IOS):
    user        R1>                     privileged  R1#
    config      R1(config)#             config-if   R1(config-if)#
    config-if-range  SW1(config-if-range)#          config-vlan  SW1(config-vlan)#
    dhcp-config R1(dhcp-config)#        config-line R1(config-line)#

Commands are matched by unique prefix (sh run, conf t, int range...). Anything
not simulated is answered like IOS answers an unknown command, so it can never
be mistaken for success.
"""
import ipaddress
import re

from .device import compress, default_vlan_name

INVALID = "% Invalid input detected at '^' marker."
INCOMPLETE = '% Incomplete command.'
SUFFIX = {'user': '>', 'exec': '#', 'config': '(config)#', 'config-if': '(config-if)#',
          'config-if-range': '(config-if-range)#', 'config-vlan': '(config-vlan)#',
          'dhcp-config': '(dhcp-config)#', 'config-line': '(config-line)#'}
_HOSTNAME = re.compile(r'^[A-Za-z]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?$')


class CLIError(Exception):
    """pos: where the caret goes (an index into the typed line), or None for a plain message."""
    def __init__(self, message=INVALID, pos=None):
        super().__init__(message)
        self.message, self.pos = message, pos


class Reply:
    def __init__(self, output='', close=False, echo_next=True, raw=False):
        self.output = output            # text after the command (no prompt)
        self.close = close              # end the session
        self.echo_next = echo_next      # False while a password is being typed
        self.raw = raw                  # True: no newline / prompt after the output


class Words:
    def __init__(self, line):
        self.line = line
        self.items = [(m.group(), m.start()) for m in re.finditer(r'\S+', line)]

    def __len__(self):
        return len(self.items)

    def pos(self, i):
        return self.items[i][1] if i < len(self.items) else len(self.line.rstrip()) + 1

    def word(self, i):
        if i >= len(self.items):
            raise CLIError(INCOMPLETE)
        return self.items[i][0]

    def kw(self, i, options):
        """The keyword at i, completed from a unique prefix."""
        text = self.word(i).lower()
        exact = [o for o in options if o.lower() == text]
        if exact:
            return exact[0]
        found = [o for o in options if o.lower().startswith(text)]
        if len(found) == 1:
            return found[0]
        if not found:
            raise CLIError(INVALID, self.pos(i))
        raise CLIError(f'% Ambiguous command:  "{self.line.strip()}"')

    def has(self, i):
        return i < len(self.items)

    def rest(self, i):
        return self.line[self.items[i][1]:].strip() if i < len(self.items) else ''

    def end(self, i):
        if i < len(self.items):
            raise CLIError(INVALID, self.pos(i))

    def number(self, i, low, high):
        w = self.word(i)
        if not w.isdigit() or not low <= int(w) <= high:
            raise CLIError(INVALID, self.pos(i))
        return int(w)

    def ip(self, i):
        try:
            return str(ipaddress.IPv4Address(self.word(i)))
        except ValueError:
            raise CLIError(INVALID, self.pos(i))

    def mask(self, i):
        try:
            ipaddress.IPv4Network(f'0.0.0.0/{self.word(i)}')
            return self.word(i)
        except ValueError:
            raise CLIError(INVALID, self.pos(i))


def vlan_numbers(text, pos):
    """'10,20,30-32' -> {10, 20, 30, 31, 32}."""
    found = set()
    for part in text.split(','):
        m = re.fullmatch(r'(\d+)(?:-(\d+))?', part.strip())
        if not m:
            raise CLIError(INVALID, pos)
        a, b = int(m.group(1)), int(m.group(2) or m.group(1))
        if not (1 <= a <= b <= 4094):
            raise CLIError(INVALID, pos)
        found.update(range(a, b + 1))
    return found


class Session:
    def __init__(self, device, privilege=None):
        """privilege: the logged-in account's level (15 = straight to #); None = device default."""
        self.dev = device
        privileged = device.start_privileged if privilege is None else privilege >= 15
        self.mode = 'exec' if privileged else 'user'
        self.targets = []               # interface names (config-if / config-if-range)
        self.vlan_ids = []              # config-vlan
        self.pool = None                # dhcp-config
        self.line_name = None           # config-line
        self.pending = None             # a question waiting for an answer (enable password...)

    def prompt(self):
        return self.dev.hostname + SUFFIX[self.mode]

    # ---------------------------------------------------------------- entry point
    def handle(self, line):
        """One line typed by the user (without the newline)."""
        with self.dev.lock:
            if self.pending:
                handler, self.pending = self.pending, None
                return handler(line)
            if not line.strip():
                return Reply()
            prompt_len = len(self.prompt())
            try:
                return self._dispatch(line)
            except CLIError as err:
                if err.pos is None:
                    return Reply(err.message)
                return Reply(' ' * (prompt_len + err.pos) + '^\n' + err.message)

    def control_z(self):
        if self.mode not in ('user', 'exec'):
            self.mode = 'exec'
        return Reply()

    def _dispatch(self, line):
        w = Words(line)
        if self.mode in ('user', 'exec'):
            return self.exec_command(w)
        if w.word(0).lower() == 'do':
            return self.exec_command(Words(line[w.pos(1):] if w.has(1) else ''), from_config=True,
                                     offset=w.pos(1))
        if self.mode == 'config':
            return self.global_command(w)
        sub = {'config-if': self.interface_command, 'config-if-range': self.interface_command,
               'config-vlan': self.vlan_command, 'dhcp-config': self.dhcp_command,
               'config-line': self.line_command}[self.mode]
        try:
            return sub(w)
        except CLIError as sub_err:
            # IOS also accepts global commands in a sub-mode (and leaves the sub-mode)
            if sub_err.pos is None:
                raise
            saved = (self.mode, self.targets, self.vlan_ids, self.pool, self.line_name)
            try:
                self.mode = 'config'
                return self.global_command(w)
            except CLIError as glob_err:
                self.mode, self.targets, self.vlan_ids, self.pool, self.line_name = saved
                if glob_err.pos is not None and glob_err.pos > sub_err.pos:
                    raise glob_err
                raise sub_err

    # ---------------------------------------------------------------- exec modes
    def exec_command(self, w, from_config=False, offset=0):
        if not len(w):
            raise CLIError(INCOMPLETE)
        privileged = self.mode != 'user'
        words = ['enable', 'disable', 'exit', 'logout', 'quit', 'show', 'terminal']
        if privileged:
            words += ['configure', 'write', 'copy']
        try:
            cmd = w.kw(0, words)
        except CLIError as err:
            if err.pos == w.pos(0) and not from_config:
                raise CLIError('% Unknown command or computer name, or unable to find computer '
                               'address')
            raise CLIError(err.message, None if err.pos is None else err.pos + offset)
        try:
            return self._exec(cmd, w, privileged, from_config)
        except CLIError as err:
            raise CLIError(err.message, None if err.pos is None else err.pos + offset)

    def _exec(self, cmd, w, privileged, from_config):
        if cmd == 'enable':
            w.end(1)
            if privileged:
                return Reply()
            self.pending = self._enable_password
            return Reply('Password: ', echo_next=False, raw=True)
        if cmd == 'disable':
            w.end(1)
            self.mode = 'user'
            return Reply()
        if cmd in ('exit', 'logout', 'quit'):
            return Reply(close=True)
        if cmd == 'terminal':
            sub = w.kw(1, ['length', 'width', 'monitor', 'no'])
            if sub in ('length', 'width'):
                w.number(2, 0, 512)
            return Reply()
        if cmd == 'configure':
            if w.has(1):
                w.kw(1, ['terminal'])
                w.end(2)
            self.mode = 'config'
            return Reply('Enter configuration commands, one per line.  End with CNTL/Z.')
        if cmd == 'write':
            if w.has(1):
                w.kw(1, ['memory'])
                w.end(2)
            self.dev.save()
            return Reply('Building configuration...\n[OK]')
        if cmd == 'copy':
            src = w.kw(1, ['running-config', 'startup-config'])
            dst = w.kw(2, ['running-config', 'startup-config'])
            if src != 'running-config' or dst != 'startup-config':
                raise CLIError(INVALID, w.pos(1))
            self.pending = self._copy_confirm
            return Reply('Destination filename [startup-config]? ', raw=True)
        return self.show_command(w, privileged)

    def _enable_password(self, typed):
        if typed == self.dev.enable_secret:
            self.mode = 'exec'
            return Reply()
        return Reply('% Access denied')

    def _copy_confirm(self, typed):
        if typed.strip() not in ('', 'startup-config'):
            return Reply('%Error opening ' + typed.strip() + ' (Invalid argument)')
        self.dev.save()
        return Reply('Building configuration...\n[OK]')

    # ---------------------------------------------------------------- show
    def show_command(self, w, privileged):
        line, pipe = w.line, None
        if '|' in line:
            line, pipe = line.split('|', 1)
        w = Words(line)
        options = ['version', 'privilege', 'clock']
        if privileged:
            options += ['running-config', 'startup-config', 'ip', 'interfaces', 'cdp', 'lldp',
                        'history']
            if self.dev.kind == 'switch':
                options += ['vlan']
        what = w.kw(1, options)
        d = self.dev
        if what == 'version':
            out = d.show_version()
        elif what == 'privilege':
            out = f"Current privilege level is {15 if privileged else 1}"
        elif what == 'clock':
            out = '*10:15:00.000 UTC Wed Nov 18 2026'
        elif what == 'history':
            out = ''
        elif what == 'running-config':
            if w.has(2):
                w.kw(2, ['interface'])
                name = self.resolve_interface(w.rest(3) if w.has(3) else '', w.pos(3))
                out = d.interface_config(name)
            else:
                out = d.running_config()
        elif what == 'startup-config':
            w.end(2)
            out = f'Using {len(d.startup)} out of 262144 bytes\n' + \
                d.startup.split('\n', 3)[-1]
        elif what == 'vlan':
            if w.has(2):
                w.kw(2, ['brief'])
            out = d.show_vlan_brief()
        elif what == 'ip':
            sub = w.kw(2, ['interface', 'route', 'dhcp'])
            if sub == 'interface':
                w.kw(3, ['brief'])
                out = d.show_ip_interface_brief()
            elif sub == 'route':
                w.end(3)
                out = d.show_ip_route()
            else:
                if d.kind != 'router':
                    raise CLIError(INVALID, w.pos(2))
                w.kw(3, ['pool'])
                out = d.show_dhcp_pool()
        elif what == 'interfaces':
            sub = w.kw(2, ['trunk', 'status'])
            if sub == 'status' or d.kind != 'switch':
                raise CLIError(INVALID, w.pos(2))
            out = d.show_interfaces_trunk()
        elif what == 'cdp':
            sub = w.kw(2, ['neighbors'])
            if w.has(3):
                w.kw(3, ['detail'])
                out = d.show_cdp_neighbors_detail()
            else:
                out = d.show_cdp_neighbors()
        else:                                            # lldp
            out = '% LLDP is not enabled'
        if pipe is not None:
            out = self._pipe(out, pipe)
        return Reply(out)

    @staticmethod
    def _pipe(text, pipe):
        m = re.match(r'\s*(\S+)\s+(.*)$', pipe)
        if not m:
            raise CLIError(INCOMPLETE)
        verb = m.group(1).lower()
        try:
            pattern = re.compile(m.group(2).strip())
        except re.error:
            raise CLIError('% Invalid regular expression')
        lines = text.split('\n')
        if 'include'.startswith(verb):
            return '\n'.join(l for l in lines if pattern.search(l))
        if 'exclude'.startswith(verb):
            return '\n'.join(l for l in lines if not pattern.search(l))
        if 'begin'.startswith(verb):
            for n, l in enumerate(lines):
                if pattern.search(l):
                    return '\n'.join(lines[n:])
            return ''
        if 'section'.startswith(verb):
            out, keep = [], False
            for l in lines:
                if not l.startswith(' '):
                    keep = bool(pattern.search(l))
                if keep:
                    out.append(l)
            return '\n'.join(out)
        raise CLIError(INVALID)

    # ---------------------------------------------------------------- global configuration
    def global_command(self, w):
        d = self.dev
        words = ['hostname', 'interface', 'ip', 'no', 'ntp', 'service', 'enable', 'username',
                 'line', 'end', 'exit', 'cdp', 'crypto', 'spanning-tree', 'default']
        if d.kind == 'switch':
            words += ['vlan', 'vtp']
        cmd = w.kw(0, words)
        if cmd == 'end':
            self.mode = 'exec'
            return Reply()
        if cmd == 'exit':
            self.mode = 'exec'
            return Reply()
        if cmd == 'no':
            return self.no_global(w)
        if cmd == 'hostname':
            name = w.word(1)
            w.end(2)
            if not _HOSTNAME.match(name):
                return Reply('% Hostname contains one or more illegal characters.')
            d.hostname = name
            return Reply()
        if cmd == 'vlan':
            ids = vlan_numbers(w.word(1), w.pos(1))
            w.end(2)
            for vid in ids:
                if vid in (1002, 1003, 1004, 1005):
                    raise CLIError(f'Default VLAN {vid} may not have its name changed.')
                d.vlans.setdefault(vid, default_vlan_name(vid))
            self.mode, self.vlan_ids = 'config-vlan', sorted(ids)
            return Reply()
        if cmd == 'interface':
            if w.has(1) and 'range'.startswith(w.word(1).lower()) and len(w.word(1)) >= 2:
                self.targets = self.resolve_range(w.rest(2), w.pos(2))
                self.mode = 'config-if-range'
            else:
                self.targets = [self.resolve_interface(w.rest(1), w.pos(1), create=True)]
                self.mode = 'config-if'
            return Reply()
        if cmd == 'ip':
            return self.global_ip(w)
        if cmd == 'ntp':
            w.kw(1, ['server'])
            server = w.ip(2)
            w.end(3)
            if server not in d.ntp_servers:
                d.ntp_servers.append(server)
            return Reply()
        if cmd == 'line':
            kind = w.kw(1, ['console', 'vty'])
            if kind == 'console':
                w.number(2, 0, 0)
                name = 'con 0'
            else:
                a = w.number(2, 0, 15)
                b = w.number(3, a, 15) if w.has(3) else a
                name = f'vty {a} {b}' if b != a else f'vty {a}'
                if name not in d.lines:
                    name = 'vty 0 4' if (a, b) == (0, 4) else name
            d.lines.setdefault(name, [])
            self.mode, self.line_name = 'config-line', name
            return Reply()
        if cmd == 'crypto':
            w.kw(1, ['key'])
            w.kw(2, ['generate'])
            w.kw(3, ['rsa'])
            return Reply(f'The name for the keys will be: {d.hostname}.lab.local\n'
                         f'% The key modulus size is 2048 bits\n'
                         f'% Generating 2048 bit RSA keys, keys will be non-exportable...\n'
                         f'[OK] (elapsed time was 1 seconds)')
        if cmd in ('cdp', 'spanning-tree', 'vtp', 'default'):
            return Reply()                                # accepted, not modelled
        # service / enable / username: stored as configuration lines
        line = ' '.join(x for x, _ in w.items)
        if cmd == 'service':
            w.word(1)
            self._set_global(line, ' '.join(line.split()[:2]))
        elif cmd == 'enable':
            kind = w.kw(1, ['secret', 'password'])
            secret = w.rest(2)
            if not secret:
                raise CLIError(INCOMPLETE)
            secret = secret.split()[-1]
            d.enable_secret = secret
            self._set_global(f'enable {kind} 5 $1$mock${_scramble(secret)}', f'enable {kind}')
        else:                                             # username NAME [privilege N] secret X
            name = w.word(1)
            if not w.has(2):
                raise CLIError(INCOMPLETE)
            kind = 'secret' if 'secret' in line.split() else 'password'
            secret = line.split()[-1]
            prefix = line.split(kind)[0].strip()
            self._set_global(f'{prefix} {kind} {5 if kind == "secret" else 0} '
                             f'{"$1$mock$" + _scramble(secret) if kind == "secret" else secret}',
                             f'username {name}')
        return Reply()

    def _set_global(self, line, key):
        lines = self.dev.global_lines
        for n, existing in enumerate(lines):
            bare = existing[3:] if existing.startswith('no ') else existing
            if bare.startswith(key) or existing.startswith(key):
                lines[n] = line
                return
        lines.append(line)

    def global_ip(self, w):
        d = self.dev
        options = ['domain-name', 'name-server', 'http', 'ssh', 'dhcp', 'default-gateway']
        if d.kind == 'router':
            options += ['route', 'routing']
        sub = w.kw(1, options)
        if sub == 'route':
            net, mask, nh = w.ip(2), w.mask(3), w.ip(4)
            w.end(5)
            n = ipaddress.IPv4Network(f'{net}/{mask}', strict=False)
            if str(n.network_address) != net:
                return Reply('%Inconsistent address and mask')
            if (net, mask, nh) not in d.routes:
                d.routes.append((net, mask, nh))
            return Reply()
        if sub == 'name-server':
            servers = [w.ip(i) for i in range(2, max(len(w), 3))]
            for s in servers:
                if s not in d.name_servers:
                    d.name_servers.append(s)
            return Reply()
        if sub == 'default-gateway':
            d.default_gateway = w.ip(2)
            w.end(3)
            return Reply()
        if sub == 'dhcp':
            what = w.kw(2, ['pool', 'excluded-address'])
            if what == 'pool':
                name = w.word(3)
                w.end(4)
                d.pools.setdefault(name, {'network': None, 'mask': None, 'default_router': None,
                                          'dns': []})
                self.mode, self.pool = 'dhcp-config', name
                return Reply()
            start = w.ip(3)
            end = w.ip(4) if w.has(4) else None
            w.end(5)
            if end and ipaddress.IPv4Address(end) < ipaddress.IPv4Address(start):
                raise CLIError(INVALID, w.pos(4))
            if (start, end) not in d.dhcp_excluded:
                d.dhcp_excluded.append((start, end))
            return Reply()
        if sub == 'routing':
            return Reply()
        self._set_global(' '.join(x for x, _ in w.items), ' '.join(x for x, _ in w.items[:2]))
        return Reply()

    def no_global(self, w):
        d = self.dev
        options = ['ip', 'ntp', 'service', 'username', 'cdp', 'hostname', 'interface']
        if d.kind == 'switch':
            options.append('vlan')
        cmd = w.kw(1, options)
        if cmd == 'vlan':
            for vid in vlan_numbers(w.word(2), w.pos(2)):
                if vid == 1 or vid in (1002, 1003, 1004, 1005):
                    return Reply(f'%Default VLAN {vid} may not be deleted.')
                d.vlans.pop(vid, None)
            return Reply()
        if cmd == 'hostname':
            d.hostname = 'Router' if d.kind == 'router' else 'Switch'
            return Reply()
        if cmd == 'ntp':
            w.kw(2, ['server'])
            server = w.ip(3)
            if server in d.ntp_servers:
                d.ntp_servers.remove(server)
            return Reply()
        if cmd == 'interface':
            name = self.resolve_interface(w.rest(2), w.pos(2))
            if d.interfaces[name].physical:
                return Reply('% Removal of physical interfaces is not permitted')
            del d.interfaces[name]
            return Reply()
        if cmd == 'ip':
            sub = w.kw(2, ['route', 'name-server', 'dhcp', 'domain-name', 'http', 'ssh',
                           'default-gateway'])
            if sub == 'route':
                net, mask, nh = w.ip(3), w.mask(4), w.ip(5)
                if (net, mask, nh) in d.routes:
                    d.routes.remove((net, mask, nh))
                else:
                    return Reply('%No matching route to delete')
                return Reply()
            if sub == 'name-server':
                for i in range(3, len(w)):
                    if w.ip(i) in d.name_servers:
                        d.name_servers.remove(w.ip(i))
                if len(w) == 3:
                    d.name_servers.clear()
                return Reply()
            if sub == 'dhcp':
                what = w.kw(3, ['pool', 'excluded-address'])
                if what == 'pool':
                    d.pools.pop(w.word(4), None)
                else:
                    start = w.ip(4)
                    end = w.ip(5) if w.has(5) else None
                    if (start, end) in d.dhcp_excluded:
                        d.dhcp_excluded.remove((start, end))
                return Reply()
            if sub == 'default-gateway':
                d.default_gateway = None
                return Reply()
        line = ' '.join(x for x, _ in w.items[1:])
        key = ' '.join(line.split()[:2])
        if cmd == 'service':
            self._set_global('no ' + line, key)
        else:
            d.global_lines[:] = [g for g in d.global_lines if not g.startswith(key)]
        return Reply()

    # ---------------------------------------------------------------- interfaces
    def resolve_interface(self, text, pos, create=False):
        m = re.fullmatch(r'([A-Za-z-]+)\s*(\d+(?:/\d+)*(?:\.\d+)?)', text.strip())
        if not m:
            raise CLIError(INCOMPLETE if not text.strip() else INVALID,
                           None if not text.strip() else pos)
        kind = _interface_type(m.group(1), pos)
        name = kind + m.group(2)
        if name in self.dev.interfaces:
            return name
        if create:
            if (kind == 'Vlan' and self.dev.kind == 'switch' and m.group(2).isdigit()) or \
                    (kind == 'Loopback' and m.group(2).isdigit()):
                self.dev._create(name)
                return name
        raise CLIError(INVALID, pos)

    def resolve_range(self, text, pos):
        pieces = [p for p in text.split(',')]
        if not text.strip():
            raise CLIError(INCOMPLETE)
        if len(pieces) > 5:
            raise CLIError(INVALID, pos)
        names, offset = [], pos
        for piece in pieces:
            m = re.fullmatch(r'\s*([A-Za-z-]+)\s*((?:\d+/)*)(\d+)\s*(?:-\s*(\d+))?\s*', piece)
            if not m:
                raise CLIError(INVALID, offset)
            kind = _interface_type(m.group(1), offset)
            start, end = int(m.group(3)), int(m.group(4) or m.group(3))
            if end < start:
                raise CLIError(INVALID, offset)
            for n in range(start, end + 1):
                name = f'{kind}{m.group(2)}{n}'
                if name not in self.dev.interfaces:
                    raise CLIError(INVALID, offset)
                if name not in names:
                    names.append(name)
            offset += len(piece) + 1
        return names

    def interface_command(self, w):
        d = self.dev
        words = ['description', 'shutdown', 'no', 'ip', 'duplex', 'speed', 'exit', 'end',
                 'spanning-tree', 'cdp', 'negotiation']
        if d.kind == 'switch':
            words.append('switchport')
        cmd = w.kw(0, words)
        intfs = [d.interfaces[n] for n in self.targets]
        if cmd == 'exit':
            self.mode = 'config'
            return Reply()
        if cmd == 'end':
            self.mode = 'exec'
            return Reply()
        if cmd == 'description':
            text = w.rest(1)
            if not text:
                raise CLIError(INCOMPLETE)
            for i in intfs:
                i.description = text[:240]
            return Reply()
        if cmd == 'shutdown':
            w.end(1)
            for i in intfs:
                i.shutdown = True
            return Reply()
        if cmd in ('duplex', 'speed', 'cdp', 'negotiation'):
            w.word(1)
            return Reply()
        if cmd == 'spanning-tree':
            w.kw(1, ['portfast', 'bpduguard'])
            line = ' '.join(x for x, _ in w.items)
            for i in intfs:
                if line not in i.extra:
                    i.extra.append(line)
            return Reply()
        if cmd == 'ip':
            w.kw(1, ['address'])
            ip, mask = w.ip(2), w.mask(3)
            w.end(4)
            out = []
            for i in intfs:
                if d.kind == 'switch' and i.physical:
                    return Reply('% IP addresses may not be configured on L2 links.')
                try:
                    net = ipaddress.IPv4Interface(f'{ip}/{mask}')
                except ValueError:
                    return Reply('% Bad mask /' + mask)
                if ip in (str(net.network.network_address), str(net.network.broadcast_address)) \
                        and net.network.prefixlen < 31:
                    return Reply('Bad mask /%d for address %s' % (net.network.prefixlen, ip))
                for other in d.interfaces.values():
                    if other is not i and other.ip and other.network().overlaps(net.network):
                        return Reply(f'% {net.network.network_address} overlaps with {other.name}')
                i.ip, i.mask = ip, mask
            return Reply('\n'.join(out))
        if cmd == 'switchport':
            return self.switchport(w, intfs, negate=False, base=1)
        # no ...
        what = w.kw(1, [x for x in words if x not in ('no', 'exit', 'end')])
        if what == 'shutdown':
            for i in intfs:
                i.shutdown = False
            return Reply()
        if what == 'description':
            for i in intfs:
                i.description = ''
            return Reply()
        if what == 'ip':
            w.kw(2, ['address'])
            for i in intfs:
                i.ip = i.mask = None
            return Reply()
        if what == 'switchport':
            return self.switchport(w, intfs, negate=True, base=2)
        if what == 'spanning-tree':
            line = ' '.join(x for x, _ in w.items[1:])
            for i in intfs:
                i.extra = [e for e in i.extra if e != line]
            return Reply()
        raise CLIError(INVALID, w.pos(1))

    def switchport(self, w, intfs, negate, base):
        d = self.dev
        if any(not i.physical for i in intfs):
            raise CLIError(INVALID, w.pos(base - 1))
        sub = w.kw(base, ['mode', 'access', 'trunk', 'port-security', 'nonegotiate'])
        out = []
        if sub == 'nonegotiate':
            return Reply()
        if sub == 'mode':
            if negate:
                for i in intfs:
                    i.mode = None
                return Reply()
            mode = w.kw(base + 1, ['access', 'trunk', 'dynamic'])
            for i in intfs:
                if mode == 'trunk' and d.trunk_encapsulation == 'required' and not i.encapsulation:
                    out.append('Command rejected: An interface whose trunk encapsulation is '
                               '"Auto" can not be configured to "trunk" mode.')
                    continue
                if mode == 'trunk' and i.ps_enabled:
                    out.append(f'Command rejected: {i.name} is a port-security enabled port.')
                    continue
                i.mode = None if mode == 'dynamic' else mode
            return Reply('\n'.join(dict.fromkeys(out)))
        if sub == 'access':
            w.kw(base + 1, ['vlan'])
            if negate:
                for i in intfs:
                    i.access_vlan = 1
                return Reply()
            vid = w.number(base + 2, 1, 4094)
            if vid not in d.vlans:
                d.vlans[vid] = default_vlan_name(vid)
                out.append(f'% Access VLAN does not exist. Creating vlan {vid}')
            for i in intfs:
                i.access_vlan = vid
            return Reply('\n'.join(out))
        if sub == 'trunk':
            what = w.kw(base + 1, ['encapsulation', 'native', 'allowed'])
            if what == 'encapsulation':
                if d.trunk_encapsulation == 'unsupported':
                    raise CLIError(INVALID, w.pos(base + 1))
                if negate:
                    for i in intfs:
                        i.encapsulation = None
                    return Reply()
                enc = w.kw(base + 2, ['dot1q', 'isl', 'negotiate'])
                for i in intfs:
                    i.encapsulation = None if enc == 'negotiate' else enc
                return Reply()
            if what == 'native':
                w.kw(base + 2, ['vlan'])
                vid = 1 if negate else w.number(base + 3, 1, 4094)
                for i in intfs:
                    i.native = vid
                return Reply()
            w.kw(base + 2, ['vlan'])
            if negate:
                for i in intfs:
                    i.allowed = None
                return Reply()
            spec = w.word(base + 3)
            pos = w.pos(base + 3)
            for i in intfs:
                if spec == 'all':
                    i.allowed = None
                elif spec == 'none':
                    i.allowed = set()
                elif spec in ('add', 'remove', 'except'):
                    numbers = vlan_numbers(w.word(base + 4), w.pos(base + 4))
                    current = set(range(1, 4095)) if i.allowed is None else set(i.allowed)
                    i.allowed = (current | numbers if spec == 'add' else current - numbers
                                 if spec == 'remove' else set(range(1, 4095)) - numbers)
                else:
                    i.allowed = vlan_numbers(spec, pos)
            return Reply()
        # port-security
        if not w.has(base + 1):
            if negate:
                for i in intfs:
                    i.ps_enabled = False
                return Reply()
            for i in intfs:
                if i.mode is None:
                    out.append(f'Command rejected: {i.name} is a dynamic port.')
                elif i.mode == 'trunk' and d.kind == 'switch':
                    out.append(f'Command rejected: {i.name} is a trunk port.')
                else:
                    i.ps_enabled = True
            return Reply('\n'.join(out))
        what = w.kw(base + 1, ['maximum', 'violation', 'mac-address'])
        for i in intfs:
            if what == 'maximum':
                i.ps_max = 1 if negate else w.number(base + 2, 1, 132)
            elif what == 'violation':
                i.ps_violation = 'shutdown' if negate else \
                    w.kw(base + 2, ['protect', 'restrict', 'shutdown'])
            else:
                w.kw(base + 2, ['sticky'])
                i.ps_sticky = not negate
        return Reply()

    # ---------------------------------------------------------------- other sub-modes
    def vlan_command(self, w):
        cmd = w.kw(0, ['name', 'exit', 'end', 'no', 'state'])
        if cmd == 'exit':
            self.mode = 'config'
            return Reply()
        if cmd == 'end':
            self.mode = 'exec'
            return Reply()
        if cmd == 'state':
            w.kw(1, ['active', 'suspend'])
            return Reply()
        if cmd == 'no':
            w.kw(1, ['name'])
            for vid in self.vlan_ids:
                self.dev.vlans[vid] = default_vlan_name(vid)
            return Reply()
        name = w.word(1)
        w.end(2)
        if len(name) > 32:
            raise CLIError(INVALID, w.pos(1))
        for vid in self.vlan_ids:
            if vid == 1:
                return Reply('Default VLAN 1 may not have its name changed.')
            self.dev.vlans[vid] = name
        return Reply()

    def dhcp_command(self, w):
        p = self.dev.pools[self.pool]
        cmd = w.kw(0, ['network', 'default-router', 'dns-server', 'domain-name', 'lease', 'exit',
                       'end'])
        if cmd == 'exit':
            self.mode = 'config'
            return Reply()
        if cmd == 'end':
            self.mode = 'exec'
            return Reply()
        if cmd == 'network':
            net, mask = w.ip(1), w.mask(2)
            w.end(3)
            n = ipaddress.IPv4Network(f'{net}/{mask}', strict=False)
            if str(n.network_address) != net:
                return Reply(f'{net} / {mask} is an invalid network.')
            p['network'], p['mask'] = net, mask
            return Reply()
        if cmd == 'default-router':
            p['default_router'] = w.ip(1)
            return Reply()
        if cmd == 'dns-server':
            p['dns'] = [w.ip(i) for i in range(1, max(len(w), 2))]
            return Reply()
        w.word(1)
        return Reply()

    def line_command(self, w):
        cmd = w.kw(0, ['transport', 'login', 'password', 'exec-timeout', 'logging', 'exit',
                       'end', 'no'])
        if cmd == 'exit':
            self.mode = 'config'
            return Reply()
        if cmd == 'end':
            self.mode = 'exec'
            return Reply()
        sub = self.dev.lines[self.line_name]
        if cmd == 'transport':
            w.kw(1, ['input'])
            protocols = [w.kw(i, ['ssh', 'telnet', 'none', 'all']) for i in range(2, max(len(w), 3))]
            sub[:] = [s for s in sub if not s.startswith('transport input')]
            sub.append('transport input ' + ' '.join(protocols))
            return Reply()
        line = ' '.join(x for x, _ in w.items)
        if cmd == 'no':
            sub[:] = [s for s in sub if not s.startswith(' '.join(line.split()[1:2]))]
            return Reply()
        if cmd == 'login':
            if w.has(1):
                w.kw(1, ['local'])
        else:
            w.word(1)
        key = line.split()[0]
        sub[:] = [s for s in sub if s.split()[0] != key]
        sub.append(line)
        return Reply()


def _interface_type(text, pos):
    from .device import INTERFACE_TYPES
    t = text.lower()
    found = [k for k in INTERFACE_TYPES if k.lower().startswith(t)]
    if t in ('fa', 'f'):
        found = ['FastEthernet']
    if t in ('gi', 'g', 'gig'):
        found = ['GigabitEthernet']
    if t in ('te', 't'):
        found = ['TenGigabitEthernet']
    if t in ('vl', 'v'):
        found = ['Vlan']
    if t in ('lo', 'l'):
        found = ['Loopback']
    if t in ('po',):
        found = ['Port-channel']
    if len(found) != 1:
        raise CLIError(INVALID, pos)
    return found[0]


def _scramble(secret):
    """A fake hash: never the real text, never a real IOS hash."""
    import hashlib
    return hashlib.sha256(secret.encode()).hexdigest()[:22]
