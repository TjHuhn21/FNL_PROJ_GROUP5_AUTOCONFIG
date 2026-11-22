"""The SSH side of the mock lab: one listening socket per device (Paramiko's
server mode), an interactive shell with echo, and simulated failures.

Failure modes (per device, from lab_config.json, the command line, or
`python -m mocklab fail`):
    none       normal
    auth_fail  every login is refused                (Netmiko: authentication error)
    offline    nothing listens / the connection is closed at once (Netmiko: TCP failure)
    hang       TCP connects but SSH never answers    (Netmiko: banner timeout)
    drop       the connection is cut right after the Nth configuration command
               (drop_after, default 1): that command IS applied, nothing more
    slow       every reply waits delay_ms (default 2000)

Restore simulation (restore_sim.py), decided by the device rather than a mode:
    a command can cut the connection (Reply.drop); a device that is reloading,
    or whose management_ip no longer exists, refuses connections and cuts the
    sessions it has; reconnect_refused refuses logins; and when the device
    configuration contains `ip scp server enable` an SCP sink ("scp -t") writes
    files to the simulated flash. The lab only accepts connections: it never
    connects anywhere.

Passwords are never logged.
"""
import logging
import re
import socket
import sys
import threading
import time

import paramiko

from . import restore_sim
from .cli import Session

FAILURES = ('none', 'auth_fail', 'offline', 'hang', 'drop', 'slow')
log = logging.getLogger('mocklab')
# Paramiko logs "Socket exception ... (10053)" on the server side whenever a client simply
# disconnects; that is normal here, so only real errors are shown.
logging.getLogger('paramiko').setLevel(logging.CRITICAL)


class LabError(Exception):
    """A problem starting the lab, with a message meant for the user."""


def load_host_key(path):
    """The lab's SSH host key (generated once, kept out of Git)."""
    import os
    if os.path.exists(path):
        return paramiko.RSAKey(filename=path)
    os.makedirs(os.path.dirname(path), exist_ok=True)
    key = paramiko.RSAKey.generate(2048)
    key.write_private_key_file(path)
    return key


def address_in_use(host, port, timeout=0.5):
    """Is something already answering on host:port?"""
    s = socket.socket()
    s.settimeout(timeout)
    try:
        return s.connect_ex((host, port)) == 0
    except OSError:
        return False
    finally:
        s.close()


class _Auth(paramiko.ServerInterface):
    def __init__(self, endpoint):
        self.ep = endpoint
        self.shell = threading.Event()
        self.ready = threading.Event()          # a shell or an SCP exec was requested
        self.exec_command = None
        self.user = None

    def get_allowed_auths(self, username):
        return 'password'

    def check_auth_password(self, username, password):
        if self.ep.failure == 'auth_fail':
            log.info('[%s] login refused for %r (auth_fail mode)', self.ep.name, username)
            return paramiko.AUTH_FAILED
        if getattr(self.ep.device, 'logins_refused', False):
            log.info('[%s] login refused for %r (reconnect_refused)', self.ep.name, username)
            return paramiko.AUTH_FAILED
        if username in self.ep.accounts and self.ep.accounts[username][0] == password:
            self.user = username
            log.info('[%s] login ok: %s', self.ep.name, username)
            return paramiko.AUTH_SUCCESSFUL
        log.info('[%s] wrong username or password for %r', self.ep.name, username)
        return paramiko.AUTH_FAILED

    def check_channel_request(self, kind, chanid):
        if kind == 'session':
            return paramiko.OPEN_SUCCEEDED
        return paramiko.OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED

    def check_channel_pty_request(self, *args):
        return True

    def check_channel_window_change_request(self, *args):
        return True

    def check_channel_shell_request(self, channel):
        self.shell.set()
        self.ready.set()
        return True

    def check_channel_exec_request(self, channel, command):
        """Only "scp -t <path>", and only when the device configuration already has
        `ip scp server enable` (nothing ever turns it on). Netmiko uses a shell."""
        text = command.decode('utf-8', 'replace') if isinstance(command, bytes) else command
        if text.startswith('scp ') and self.ep.device.scp_enabled():
            if self.ready.is_set():
                # a later channel of a connection that is already served (the scp package
                # opens one next to the shell): serve it on its own thread
                threading.Thread(target=self.ep._scp_channel,
                                 args=(channel, text, self.ep.accounts[self.user][1]),
                                 daemon=True).start()
                return True
            self.exec_command = text
            self.ready.set()
            return True
        log.info('[%s] exec request refused: %s', self.ep.name, text.split()[:1])
        return False


class Endpoint:
    """One mock device on one address."""

    def __init__(self, device, host, port, accounts, host_key, failure='none', delay_ms=0,
                 drop_after=1, control=None):
        self.device, self.name = device, device.name
        self.host, self.port = host, port
        self.accounts = dict(accounts)       # username -> (password, privilege or None)
        self.host_key = host_key
        self._failure, self.delay_ms, self.drop_after = failure, delay_ms, drop_after
        self.control = control              # callable -> {name: {...}} live overrides, or None
        self.sock = None
        self.stopping = threading.Event()
        self.threads = []
        self.connections = 0

    # live settings (the control file can change them while the lab runs)
    def _live(self):
        if self.control:
            try:
                return self.control().get(self.name) or {}
            except Exception:
                return {}
        return {}

    @property
    def failure(self):
        return self._live().get('failure', self._failure)

    def set_failure(self, failure, delay_ms=None, drop_after=None):
        if failure not in FAILURES:
            raise LabError(f'Unknown failure mode {failure!r}. Use one of: {", ".join(FAILURES)}')
        self._failure = failure
        if delay_ms is not None:
            self.delay_ms = delay_ms
        if drop_after is not None:
            self.drop_after = drop_after

    def check_free(self):
        if self.failure == 'offline':
            return
        if address_in_use(self.host, self.port):
            raise LabError(f'{self.host}:{self.port} ({self.name}) is already in use: another SSH '
                           f'server or a mock lab that is already running. Stop it, or change '
                           f'"host"/"port" for {self.name} in lab_config.json.')

    def start(self):
        if self.failure == 'offline':                 # nothing listens: connection refused
            log.info('[%s] offline: not listening on %s:%s', self.name, self.host, self.port)
            return
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        if sys.platform == 'win32':                   # refuse to share the address
            s.setsockopt(socket.SOL_SOCKET, socket.SO_EXCLUSIVEADDRUSE, 1)
        try:
            s.bind((self.host, self.port))
        except OSError as err:
            s.close()
            raise LabError(f'Cannot use {self.host}:{self.port} for {self.name}: {err.strerror}. '
                           f'Another program may be using it, or the address is not available '
                           f'on this computer.')
        s.listen(16)
        s.settimeout(0.3)
        self.sock = s
        self.port = s.getsockname()[1]               # the real port when 0 was asked for
        t = threading.Thread(target=self._accept_loop, name=f'mocklab-{self.name}', daemon=True)
        t.start()
        self.threads.append(t)
        log.info('[%s] listening on %s:%s', self.name, self.host, self.port)

    def stop(self):
        self.stopping.set()
        if self.sock:
            try:
                self.sock.close()
            except OSError:
                pass
        for t in self.threads:
            t.join(timeout=2)

    # ---------------------------------------------------------------- connections
    def _accept_loop(self):
        while not self.stopping.is_set():
            try:
                conn, peer = self.sock.accept()
            except socket.timeout:
                continue
            except OSError:
                break
            self.connections += 1
            t = threading.Thread(target=self._serve, args=(conn,), daemon=True)
            t.start()

    def _serve(self, conn):
        failure = self.failure
        if failure == 'offline':
            log.info('[%s] offline: connection closed at once', self.name)
            conn.close()
            return
        if failure == 'hang':
            log.info('[%s] hang: connection accepted, SSH will never answer', self.name)
            self.stopping.wait(120)
            conn.close()
            return
        if not self.device.reachable():               # reloading, or its address is gone
            log.info('[%s] unreachable (simulated): connection closed at once', self.name)
            conn.close()
            return
        transport = paramiko.Transport(conn)
        if 'legacy_ssh_only' in getattr(self.device, 'quirks', ()):
            # like an older IOS image: only SHA-1 key exchange, ssh-rsa host key, hmac-sha1
            options = transport.get_security_options()
            options.kex = ('diffie-hellman-group14-sha1',)
            options.key_types = ('ssh-rsa',)
            options.digests = ('hmac-sha1',)
        transport.add_server_key(self.host_key)
        auth = _Auth(self)
        try:
            transport.start_server(server=auth)
            chan = transport.accept(20)
            if chan is None or not auth.ready.wait(10):
                return
            if auth.exec_command is not None:
                self._scp(chan, transport, auth.exec_command, self.accounts[auth.user][1])
                return
            self._shell(chan, transport, failure, self.accounts[auth.user][1])
        except Exception as err:                      # a client that went away
            log.debug('[%s] session ended: %s', self.name, err)
        finally:
            try:
                transport.close()
            except Exception:
                pass

    def _shell(self, chan, transport, failure, privilege=None):
        session = Session(self.device, privilege)
        boot = self.device.boot_count
        chan.settimeout(0.3)
        chan.sendall(f'\r\n{session.prompt()}'.encode())
        buf, echo, last_cr, config_lines = '', True, False, 0
        while not self.stopping.is_set() and not chan.closed:
            if self._cut_off(boot):
                log.info('[%s] session cut (simulated reload or management address gone)',
                         self.name)
                transport.close()
                return
            try:
                data = chan.recv(4096)
            except socket.timeout:
                continue
            if not data:
                break
            out = []
            for ch in data.decode('utf-8', 'replace'):
                if ch == '\n' and last_cr:
                    last_cr = False
                    continue
                last_cr = ch == '\r'
                if ch in '\r\n':
                    in_config = session.mode not in ('user', 'exec') and session.pending is None
                    reply = session.handle(buf)
                    log.info('[%s] %s', self.name, _loggable(buf, echo))
                    buf = ''
                    if reply.drop or self._cut_off(boot):
                        log.info('[%s] connection cut by the device (simulated)', self.name)
                        if out:                            # what was echoed, not the reply
                            chan.sendall(''.join(out).encode())
                        transport.close()
                        return
                    if failure == 'drop' and in_config:
                        config_lines += 1
                        if config_lines >= self.drop_after:
                            log.info('[%s] drop: cutting the connection now', self.name)
                            if out:
                                chan.sendall(''.join(out).encode())
                            transport.close()
                            return
                    out.append('\r\n')
                    if reply.close:
                        chan.sendall(''.join(out).encode())
                        return
                    text = reply.output.replace('\n', '\r\n')
                    if reply.raw:
                        out.append(text)
                    else:
                        if text:
                            out.append(text + '\r\n')
                            if reply.output.lstrip().startswith('%') or '\n%' in reply.output:
                                out.append('\r\n')
                        out.append(session.prompt())
                    echo = reply.echo_next
                elif ch == '\x1a':                         # Ctrl+Z
                    session.control_z()
                    buf = ''
                    out.append(f'^Z\r\n{session.prompt()}')
                elif ch in '\x08\x7f':
                    if buf:
                        buf = buf[:-1]
                        if echo:
                            out.append('\b \b')
                elif ch == '\x03':
                    continue
                else:
                    buf += ch
                    if echo:
                        out.append(ch)
            if out:
                if failure == 'slow' and any('\r\n' in o for o in out):
                    time.sleep((self.delay_ms or 2000) / 1000)
                chan.sendall(''.join(out).encode())

    def _cut_off(self, boot):
        return self.device.boot_count != boot or not self.device.reachable()

    # ---------------------------------------------------------------- SCP sink (simulated)
    def _scp_channel(self, chan, command, privilege):
        try:
            self._scp(chan, chan.get_transport(), command, privilege)
        except Exception as err:                      # a client that went away
            log.debug('[%s] scp ended: %s', self.name, err)

    def _scp(self, chan, transport, command, privilege):
        """The receiving side of "scp -t <path>": files go to the simulated flash through
        restore_sim.store_transfer. Only for a privilege-15 login, as IOS requires.
        transfer_fails cuts the whole connection half way through."""
        dev = self.device
        chan.settimeout(10)
        try:
            m = re.match(r'scp\s+(?:-[a-zA-Z]+\s+)*-t\s+(?:-[a-zA-Z]+\s+)*(\S+)\s*$', command)
            privileged = (privilege or 0) >= 15 or (privilege is None and dev.start_privileged)
            if not m or '-r' in command.split() or '-f' in command.split():
                return self._scp_error(chan, 'only "scp -t <file>" is simulated')
            if not privileged:
                return self._scp_error(chan, 'Privilege denied (SIMULATED: SCP needs a privilege '
                                             '15 login)')
            try:
                target = restore_sim.flash_path(m.group(1).strip('\'"'))
            except restore_sim.FlashError as err:
                return self._scp_error(chan, err.message)
            chan.sendall(b'\0')
            while True:
                line = _read_line(chan)
                if not line:
                    break
                if line[:1] in (b'T', b'E'):
                    chan.sendall(b'\0')
                    continue
                if line[:1] != b'C':
                    return self._scp_error(chan, 'only single files are simulated')
                parts = line[1:].decode('utf-8', 'replace').rstrip('\n').split(' ', 2)
                if len(parts) != 3 or not parts[1].isdigit():
                    return self._scp_error(chan, 'bad SCP header')
                size, name = int(parts[1]), target or parts[2]
                chan.sendall(b'\0')
                if 'transfer_fails' in dev.quirks:          # cut half way: a partial file
                    data = _read_exact(chan, size // 2)
                    with dev.lock:
                        try:
                            dev.flash.write(name, data, overwrite='flash_overwrites' in dev.quirks)
                        except restore_sim.FlashError:
                            pass
                        dev.event('transfer_failed', f'{name}: connection lost (transfer_fails)')
                    transport.close()                       # the whole connection drops
                    return
                data = _read_exact(chan, size)
                _read_exact(chan, 1)
                with dev.lock:
                    error = restore_sim.store_transfer(dev, name, data)
                if error:
                    return self._scp_error(chan, error)
                log.info('[%s] scp: %s (%d bytes)', self.name, name, size)
                chan.sendall(b'\0')
            chan.send_exit_status(0)
        finally:
            chan.close()

    @staticmethod
    def _scp_error(chan, message):
        chan.sendall(b'\x01' + message.encode('utf-8', 'replace') + b'\n')
        chan.send_exit_status(1)
        # let the client read the refusal before the channel closes (closing at once can
        # overtake the reply to its exec request, and it would only see "Channel closed")
        chan.settimeout(2)
        try:
            chan.recv(1)
        except Exception:
            pass


def _read_line(chan):
    out = b''
    while not out.endswith(b'\n'):
        piece = chan.recv(1)
        if not piece:
            break
        out += piece
    return out


def _read_exact(chan, size):
    out = b''
    while len(out) < size:
        piece = chan.recv(min(65536, size - len(out)))
        if not piece:
            raise EOFError('the SCP client went away')
        out += piece
    return out


def _loggable(line, echo):
    """What was typed, for the lab log: never a password."""
    if not echo:
        return '<password hidden>'
    words = line.split()
    for i, w in enumerate(words[:-1]):
        if w.lower() in ('password', 'secret', 'key-string', 'community'):
            if len(words) > i + 2 and words[i + 1] in ('0', '5', '7', '8', '9'):
                words[i + 2] = '********'          # 'secret 5 <hash>': keep the type number
            else:
                words[i + 1] = '********'
    return ' '.join(words) or '<enter>'
