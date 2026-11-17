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

Passwords are never logged.
"""
import logging
import socket
import sys
import threading
import time

import paramiko

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
        self.user = None

    def get_allowed_auths(self, username):
        return 'password'

    def check_auth_password(self, username, password):
        if self.ep.failure == 'auth_fail':
            log.info('[%s] login refused for %r (auth_fail mode)', self.ep.name, username)
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
        return True

    def check_channel_exec_request(self, channel, command):
        return False                       # Netmiko uses an interactive shell


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
        transport = paramiko.Transport(conn)
        transport.add_server_key(self.host_key)
        auth = _Auth(self)
        try:
            transport.start_server(server=auth)
            chan = transport.accept(20)
            if chan is None or not auth.shell.wait(10):
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
        chan.settimeout(0.3)
        chan.sendall(f'\r\n{session.prompt()}'.encode())
        buf, echo, last_cr, config_lines = '', True, False, 0
        while not self.stopping.is_set() and not chan.closed:
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
