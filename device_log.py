"""What NetCommand sends to devices, for the Console (and its saved history).

No window code here: the GUI registers where the lines go (gui.event_log sets the sink);
without a sink (tests of the device code, command-line tools) nothing is logged.

Every SSH session of the app is opened through open_logged() (config.connect._open for
Configure, restore, startup save and the Findings review; discovery.crawler._login for
Scan). It logs the connection steps and returns a LoggedConnection, which logs each
command with a short result and keeps the full (masked) output for the Console's popup:

    ssh      Connecting to 127.0.0.11:22 as labscan...
    ssh      Connected to MOCK-R1 (127.0.0.11).
    scan     MOCK-R1 > show cdp neighbors detail          OK
    config   MOCK-R1 > interface Gi0/1                    OK
    config   MOCK-R1 > vlan 4095                          FAILED  % Invalid input detected...
    ssh      Disconnected from MOCK-R1.

Commands and output are MASKED (config.connect.mask: passwords, secrets, keys, SNMP
communities, pre-shared keys) before anything is logged. Logging never changes what is
sent and never breaks a session.
"""
import threading
from contextlib import contextmanager

SSH, SCAN, CONFIG, FINDINGS = 'ssh', 'scan', 'config', 'findings'
OK, FAILED, TIMED_OUT = 'OK', 'FAILED', 'timed out'
MAX_DETAIL = 200_000                 # characters of output kept for the popup

_sink = [None]                       # fn(category, message, level, **fields)
_local = threading.local()


def set_sink(fn):
    _sink[0] = fn


def emit(category, message, level='info', **fields):
    """One line to the sink (if any). Never raises."""
    sink = _sink[0]
    if sink is None:
        return
    try:
        sink(category, message, level, **fields)
    except Exception:
        pass


@contextmanager
def activity(category):
    """Commands sent on this thread inside the block are logged under `category`."""
    stack = getattr(_local, 'stack', None)
    if stack is None:
        stack = _local.stack = []
    stack.append(category)
    try:
        yield
    finally:
        stack.pop()


def current_activity(default):
    stack = getattr(_local, 'stack', None)
    return stack[-1] if stack else default


def _mask(text):
    from config.connect import mask
    return mask(text or '')


def _rejection(output):
    from config.connect import rejection
    return rejection(output)


def _is_timeout(err):
    try:
        from netmiko.exceptions import NetmikoTimeoutException, ReadTimeout
        timeouts = (NetmikoTimeoutException, ReadTimeout, TimeoutError)
    except Exception:
        timeouts = (TimeoutError,)
    return isinstance(err, timeouts) or 'timed out' in str(err).lower()


def open_logged(factory, ip, username='', category=None):
    """Open a session with factory() and return it wrapped in a LoggedConnection.
    Logs 'Connecting...' first; a failure is logged (with a fixed reason, never the
    exception's own text) and raised again unchanged."""
    import ssh_options
    who = f' as {username}' if username else ''
    emit(SSH, f'Connecting to {ip}:22{who}...', device=ip, ip=ip)
    try:
        conn = factory()
    except Exception as err:
        _kind, reason = ssh_options.describe_error(err, ip)
        emit(SSH, f'Connection to {ip} FAILED: {reason}.', 'error', device=ip, ip=ip)
        raise
    return LoggedConnection(conn, ip, category)


class LoggedConnection:
    """Behaves like the Netmiko connection it wraps; the calls that send something to the
    device are logged. Anything else is passed through unchanged."""

    _OWN = ('_conn', '_ip', '_name', '_category', '_connected')

    def __init__(self, conn, ip, category=None):
        object.__setattr__(self, '_conn', conn)
        object.__setattr__(self, '_ip', ip)
        object.__setattr__(self, '_name', None)
        object.__setattr__(self, '_category', category)
        object.__setattr__(self, '_connected', False)

    # ---- pass-through
    def __getattr__(self, name):
        return getattr(self._conn, name)

    def __setattr__(self, name, value):
        if name in self._OWN:
            object.__setattr__(self, name, value)
        else:
            setattr(self._conn, name, value)

    @property
    def device_name(self):
        return self._name or self._ip

    def _cat(self):
        return self._category or current_activity(CONFIG)

    def _fields(self):
        return {'device': self.device_name, 'ip': self._ip}

    # ---- logging helpers
    def _log_command(self, command, output=None, error=None):
        """One command line with its result: OK, FAILED with the device's error, or timed
        out. The full output is kept (masked) for the popup, never put on the line."""
        shown = _mask(command)
        detail = _mask(output)[:MAX_DETAIL] if output else ''
        if error is not None:
            if _is_timeout(error):
                result, level = TIMED_OUT, 'warn'
            else:
                result, level = f'{FAILED} ({type(error).__name__})', 'error'
        else:
            problem = _rejection(output)
            result, level = (f'{FAILED}  {_mask(problem)}', 'error') if problem else (OK, 'ok')
        emit(self._cat(), f'{self.device_name} > {shown}', level, command=True, result=result,
             detail=detail, **self._fields())

    def _call(self, command, fn, *args, **kwargs):
        try:
            out = fn(*args, **kwargs)
        except Exception as err:
            self._log_command(command, error=err)
            raise
        self._log_command(command, out if isinstance(out, str) else '')
        return out

    # ---- the logged calls
    def find_prompt(self, *args, **kwargs):
        prompt = self._conn.find_prompt(*args, **kwargs)
        name = (prompt or '').strip().rstrip('#>').split('(')[0].strip()
        if name:
            object.__setattr__(self, '_name', name)
        if not self._connected:
            object.__setattr__(self, '_connected', True)
            emit(SSH, f'Connected to {self.device_name} ({self._ip}).', 'ok', **self._fields())
        return prompt

    def enable(self, *args, **kwargs):
        return self._call('enable', self._conn.enable, *args, **kwargs)

    def send_command(self, command, *args, **kwargs):
        return self._call(command, self._conn.send_command, command, *args, **kwargs)

    def send_command_timing(self, command, *args, **kwargs):
        return self._call(command, self._conn.send_command_timing, command, *args, **kwargs)

    def config_mode(self, *args, **kwargs):
        return self._call('configure terminal', self._conn.config_mode, *args, **kwargs)

    def exit_config_mode(self, *args, **kwargs):
        return self._call('end', self._conn.exit_config_mode, *args, **kwargs)

    def save_config(self, *args, **kwargs):
        return self._call('write memory', self._conn.save_config, *args, **kwargs)

    def send_config_set(self, config_commands=None, *args, **kwargs):
        commands = [config_commands] if isinstance(config_commands, str) else \
            list(config_commands or [])
        label = commands[0] if len(commands) == 1 else f'({len(commands)} configuration lines)'
        out = self._call(label, self._conn.send_config_set, config_commands, *args, **kwargs)
        if len(commands) > 1:                 # one batch: list what was in it
            for c in commands:
                emit(self._cat(), f'{self.device_name} > {_mask(c)}', 'info', command=True,
                     result='sent in the batch above', **self._fields())
        return out

    def disconnect(self, *args, **kwargs):
        try:
            return self._conn.disconnect(*args, **kwargs)
        finally:
            emit(SSH, f'Disconnected from {self.device_name}.', 'info', **self._fields())
