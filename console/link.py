"""One console session to a Cisco device over a serial (COM) port. Read-only in this phase.

    session = ConsoleSession('COM4', baudrate=9600, username='', password='', enable_password='')
    result = session.connect()          # ConnectResult: prompt, privileged, notices
    session.find_prompt()               # 'R1#'
    session.send_show('show version')   # only 'show ...' commands are accepted
    session.enable()                    # '>' -> '#' with the enable password (not a config change)
    session.is_active()
    session.disconnect()                # always safe; also after errors
    session.cancel()                    # from ANOTHER thread: closes the port, the call stops

It uses Netmiko's `cisco_ios_serial` driver (8 data bits, no parity, 1 stop bit, default
9600 baud). EVERY method here blocks on serial I/O: call them from a worker thread
(gui.background.run_async), never from the Tk main thread. Each one is bounded by a
timeout; when it expires the port is closed so the waiting call returns.

Safety (phase 1):
  * Only `show ...` commands can be sent (send_show refuses anything else), plus what
    Netmiko itself sends to log in and prepare the session: the username and password if
    the console asks, `terminal width 511` and `terminal length 0` (session settings, not
    configuration), `enable` (only when you call enable()), and `exit` when disconnecting.
  * NetCommand never answers a device prompt with "yes". NETMIKO_SETUP_DIALOG_NOTICE: if
    an unconfigured device asks "Would you like to enter the initial configuration
    dialog? [yes/no]", Netmiko answers "no" by itself; that only skips the setup wizard
    and changes no configuration. The ConnectResult says when this happened.
  * Passwords are never logged or put in a message. What the device prints is captured
    in memory only (to explain a failed login) with Netmiko masking the passwords, and it
    is never written to a file.
  * Errors are ConsoleError with a fixed, readable message (never the driver's own text).
"""
import io
import re
import threading

from console.ports import check_port_name

DEFAULT_BAUD = 9600
BAUD_RATES = (1200, 2400, 4800, 9600, 14400, 19200, 38400, 57600, 115200)
DEFAULT_TIMEOUT = 45          # seconds for connecting (logging in at 9600 baud can be slow)
COMMAND_TIMEOUT = 30          # seconds for one show command
NETMIKO_SETUP_DIALOG_NOTICE = (
    'If an unconfigured device asks "Would you like to enter the initial configuration '
    'dialog? [yes/no]", Netmiko answers "no" automatically. This only skips the setup wizard; '
    'it does not change the configuration. NetCommand never answers "yes".')
SETUP_DIALOG_ANSWERED = ('The device asked to start its initial configuration dialog; Netmiko '
                         'answered "no" (setup wizard skipped, configuration unchanged).')

# ConsoleError kinds
PORT_UNAVAILABLE, PORT_BUSY, UNREADABLE = 'port_unavailable', 'port_busy', 'unreadable'
AUTH, UNEXPECTED_PROMPT, TIMEOUT = 'auth', 'unexpected_prompt', 'timeout'
NOT_CONNECTED, REFUSED, CANCELLED, OTHER = 'not_connected', 'refused', 'cancelled', 'other'

_SHOW = re.compile(r'^show\s+[\x20-\x7e]+$', re.IGNORECASE)        # one printable line
_WRITES_FILE = re.compile(r'\|\s*(redirect|tee|append)\b', re.IGNORECASE)
_BOOT_LOADER = re.compile(r'(^|\n)\s*(rommon\s*\d*\s*>|switch:|loader>)', re.IGNORECASE)
_PASSWORD_PROMPT = re.compile(r'assword\s*:', re.IGNORECASE)
_LOGIN_REFUSED = re.compile(r'% ?(Bad passwords|Login invalid|Authentication failed|Access denied)'
                            r'|Login incorrect', re.IGNORECASE)
_PROMPT = re.compile(r'^[\w.\-/()]+[>#]\s*$')


class ConsoleError(Exception):
    """A console problem: .kind (one of the constants above) and a fixed message."""

    def __init__(self, kind, message):
        super().__init__(message)
        self.kind = kind


class ConnectResult:
    def __init__(self, port, baudrate, prompt, notices):
        self.port, self.baudrate, self.prompt = port, baudrate, prompt
        self.privileged = prompt.endswith('#')
        self.notices = list(notices)

    def __repr__(self):
        return (f'ConnectResult(port={self.port!r}, baudrate={self.baudrate}, '
                f'prompt={self.prompt!r}, privileged={self.privileged})')


def check_baudrate(value):
    try:
        rate = int(value)
    except (TypeError, ValueError):
        raise ValueError('The speed must be a number, for example 9600.') from None
    if rate not in BAUD_RATES:
        raise ValueError(f'Choose one of the usual console speeds: '
                         f'{", ".join(map(str, BAUD_RATES))} (most Cisco devices: 9600).')
    return rate


def check_show_command(command):
    """The command if it is a single 'show ...' line, else ConsoleError(REFUSED)."""
    text = (command or '').strip()
    if not _SHOW.match(text) or '\r' in (command or '') or '\n' in (command or ''):
        raise ConsoleError(REFUSED, 'Only single-line "show ..." commands can be sent in this '
                                    'version; nothing was sent.')
    if _WRITES_FILE.search(text):
        raise ConsoleError(REFUSED, '"| redirect", "| tee" and "| append" write a file on the '
                                    'device, so they are not allowed; nothing was sent.')
    return text


def unreadable(text):
    """True when the device's output looks like a wrong speed (mostly unprintable or
    non-ASCII characters; Cisco IOS prints plain ASCII)."""
    if not text:
        return False
    bad = sum(1 for ch in text
              if ord(ch) > 126 or (ord(ch) < 32 and ch not in '\r\n\t\x08'))
    return bad >= 4 and bad / len(text) > 0.2


TRANSCRIPT_LIMIT = 16 * 1024      # bytes of device output kept while logging in


class _Transcript(io.BytesIO):
    """In-memory copy of what the device printed while LOGGING IN, used only to explain a
    failed login (wrong speed, boot loader, password prompt) and to see whether Netmiko
    answered the setup dialog. Never written anywhere.

    * It keeps at most `limit` bytes (the newest).
    * stop() empties it and makes it ignore everything after a successful login, so the
      output of later commands (for example running-config lines) is not kept.
    * Netmiko closes its session log when it disconnects; close() is ignored so the text
      can still explain a failure, and wipe() empties it instead."""

    def __init__(self, limit=TRANSCRIPT_LIMIT):
        super().__init__()
        self.limit = limit
        self.recording = True

    def write(self, data):
        if not self.recording:
            return len(data)                        # accepted, not kept
        written = super().write(data)
        if self.tell() > self.limit:
            tail = self.getvalue()[-self.limit:]
            self.seek(0)
            self.truncate(0)
            super().write(tail)
        return written

    def stop(self):
        self.recording = False
        self.wipe()

    def wipe(self):
        self.seek(0)
        self.truncate(0)

    def close(self):
        pass


def _chain(err):
    out, seen = [], set()
    while err is not None and id(err) not in seen and len(out) < 10:
        seen.add(id(err))
        out.append(err)
        err = err.__cause__ or err.__context__
    return out


def _is(err, name):
    return any(c.__name__ == name for c in type(err).__mro__)


class ConsoleSession:
    def __init__(self, port, baudrate=DEFAULT_BAUD, username='', password='',
                 enable_password='', timeout=DEFAULT_TIMEOUT, command_timeout=COMMAND_TIMEOUT,
                 log=None, connect_handler=None):
        """log(kind, text): optional progress lines ('info', 'command', 'ok', 'warn',
        'error'), never containing a password. connect_handler: tests only (default
        netmiko.ConnectHandler)."""
        self.port = check_port_name(port)
        self.baudrate = check_baudrate(baudrate)
        self._username = username or ''
        self._password = password or ''
        self._enable_password = enable_password or ''
        self.timeout, self.command_timeout = timeout, command_timeout
        self._log = log or (lambda kind, text: None)
        self._handler = connect_handler
        self._conn = None
        self._transcript = None
        self._lock = threading.Lock()                      # one call at a time
        self._cancelled = threading.Event()

    def __repr__(self):                                    # never shows the passwords
        state = 'connected' if self._conn is not None else 'closed'
        return f'ConsoleSession(port={self.port!r}, baudrate={self.baudrate}, {state})'

    # ------------------------------------------------------------ logging without secrets
    def _say(self, kind, text):
        for secret in (self._password, self._enable_password):
            if secret:
                text = text.replace(secret, '********')
        try:
            self._log(kind, text)
        except Exception:
            pass

    # ------------------------------------------------------------ connecting
    def connect(self):
        """Open the port and log in. Returns a ConnectResult, or raises ConsoleError
        (the port is closed again in every failure case)."""
        with self._lock:
            if self._conn is not None:
                raise ConsoleError(OTHER, f'{self.port} is already connected.')
            self._cancelled.clear()
            self._transcript = _Transcript()
            self._say('info', f'Opening {self.port} at {self.baudrate} baud (8 data bits, no '
                              f'parity, 1 stop bit)...')
            try:
                conn = self._create()
            except Exception as err:
                problem = self._translate(err, phase='open')
                self._transcript.wipe()
                raise problem from None
            error = self._run_with_deadline(
                lambda: (conn.establish_connection(), conn._try_session_preparation()),
                self.timeout, conn)
            if error is not None:
                self._close(conn)
                problem = self._translate(error, phase='login')
                self._transcript.wipe()                   # explained: no longer needed
                raise problem from None
            self._conn = conn
            try:
                prompt = self._prompt_now()
            except ConsoleError:
                self._release()
                self._transcript.wipe()
                raise
            notices = [NETMIKO_SETUP_DIALOG_NOTICE]
            if 'initial configuration dialog' in self._device_output().lower():
                notices.insert(0, SETUP_DIALOG_ANSWERED)
                self._say('warn', SETUP_DIALOG_ANSWERED)
            self._transcript.stop()          # logged in: later command output is not kept
            self._say('ok', f'Connected on {self.port}. Device prompt: {prompt}')
            return ConnectResult(self.port, self.baudrate, prompt, notices)

    def _create(self):
        handler = self._handler
        if handler is None:
            from netmiko import ConnectHandler
            handler = ConnectHandler
        return handler(device_type='cisco_ios_serial',
                       serial_settings={'port': self.port, 'baudrate': self.baudrate,
                                        'bytesize': 8, 'parity': 'N', 'stopbits': 1},
                       username=self._username, password=self._password,
                       secret=self._enable_password, session_log=self._transcript,
                       auto_connect=False, read_timeout_override=self.command_timeout)

    def _run_with_deadline(self, work, seconds, conn):
        """Run work() in a helper thread. On timeout or cancel, close the port so the
        blocked read ends. Returns the exception raised (or a TIMEOUT/CANCELLED marker),
        or None on success."""
        outcome = {}

        def target():
            try:
                work()
            except BaseException as err:                    # reported, never re-raised here
                outcome['error'] = err
        helper = threading.Thread(target=target, daemon=True)
        helper.start()
        step = 0.05
        waited = 0.0
        while helper.is_alive() and waited < seconds and not self._cancelled.is_set():
            helper.join(step)
            waited += step
        if helper.is_alive():
            self._close(conn)                                # unblocks the read
            helper.join(2)
            return ConsoleError(CANCELLED, 'Cancelled. The serial port was closed.') \
                if self._cancelled.is_set() else _Timeout()
        if self._cancelled.is_set():
            return ConsoleError(CANCELLED, 'Cancelled. The serial port was closed.')
        return outcome.get('error')

    # ------------------------------------------------------------ errors
    def _device_output(self):
        """What the device printed so far (passwords masked by Netmiko). Memory only."""
        conn = self._conn
        try:
            log = getattr(conn, 'session_log', None) if conn is not None else None
            if log is not None and hasattr(log, 'flush'):
                log.flush()
        except Exception:
            pass
        raw = self._transcript.getvalue() if self._transcript is not None else b''
        return raw.decode('utf-8', errors='replace')

    def _translate(self, err, phase):
        """A fixed, readable ConsoleError for any failure (never the driver's text)."""
        if isinstance(err, ConsoleError):
            return err
        port = self.port
        if isinstance(err, _Timeout):
            seen = self._device_output()
            if unreadable(seen):
                return ConsoleError(UNREADABLE, self._unreadable_text())
            return ConsoleError(TIMEOUT, f'No usable answer on {port} within {self.timeout} '
                                         f'seconds. Check the cable, that the device is on, and '
                                         f'the speed ({self.baudrate} baud).')
        chain = _chain(err)
        text = ' '.join(f'{type(e).__name__} {e}' for e in chain).lower()
        serial_error = any(_is(e, 'SerialException') or _is(e, 'OSError') for e in chain)
        # The port itself is opened by Netmiko's establish_connection (pyserial:
        # "could not open port 'COM4': PermissionError(13, 'Access is denied.')"), and the
        # name is checked against the port list when the connection object is created
        # (ValueError "device COM4 not found").
        if phase == 'open' or serial_error:
            if 'access is denied' in text or 'permissionerror' in text or 'busy' in text \
                    or 'errno 13' in text or 'errno 16' in text:
                return ConsoleError(PORT_BUSY, f'{port} is in use by another program (for example '
                                               f'PuTTY or Tera Term). Close it, then try again.')
            if 'not found' in text or 'filenotfounderror' in text or 'cannot find' in text \
                    or 'could not open port' in text or 'no such file' in text:
                return ConsoleError(PORT_UNAVAILABLE, f'{port} is not available. Check that the '
                                                      f'cable is plugged in and its driver is '
                                                      f'installed, then refresh the port list.')
            if phase == 'open':
                return ConsoleError(OTHER, f'{port} could not be opened ({type(err).__name__}).')
            if any(_is(e, 'SerialException') for e in chain):
                return ConsoleError(PORT_UNAVAILABLE, f'{port} stopped working (was the cable '
                                                      f'unplugged?).')
        seen = self._device_output()
        if unreadable(seen):
            return ConsoleError(UNREADABLE, self._unreadable_text())
        if _BOOT_LOADER.search(seen):
            return ConsoleError(UNEXPECTED_PROMPT, 'The device is in its boot loader (ROMMON / '
                                                   'switch:), not running IOS. Stop and ask the '
                                                   'instructor; do not type commands there.')
        if any(_is(e, 'NetmikoAuthenticationException') for e in chain):
            if 'password required, but none set' in text:
                return ConsoleError(AUTH, 'The console asks for a password, but the device has '
                                          'none set, so nobody can log in on this line.')
            if _LOGIN_REFUSED.search(seen) or (_PASSWORD_PROMPT.search(seen)
                                              and (self._username or self._password)):
                return ConsoleError(AUTH, 'The device refused the console login (wrong username '
                                          'or password).')
            if _PASSWORD_PROMPT.search(seen):
                return ConsoleError(AUTH, 'The console asks for a password. Enter the console '
                                          'login and try again.')
            if not seen.strip():
                return ConsoleError(TIMEOUT, f'No answer on {port}. Check the cable, that the '
                                             f'device is on, and the speed ({self.baudrate} '
                                             f'baud).')
            return ConsoleError(UNEXPECTED_PROMPT, 'The device answered, but not with a Cisco IOS '
                                                   'prompt (">" or "#"). It may not be a Cisco IOS '
                                                   'device, or it is in an unusual state.')
        if any(_is(e, n) for e in chain for n in ('ReadTimeout', 'NetmikoTimeoutException',
                                                   'SerialTimeoutException', 'TimeoutError')):
            return ConsoleError(TIMEOUT, f'The device on {port} stopped answering in time.')
        if isinstance(err, ValueError) and 'prompt' in text:
            return ConsoleError(UNEXPECTED_PROMPT, 'The device answered, but not with a Cisco IOS '
                                                   'prompt (">" or "#").')
        return ConsoleError(OTHER, f'The console session failed ({type(err).__name__}).')

    def _unreadable_text(self):
        return (f'The output on {self.port} is unreadable at {self.baudrate} baud. Most Cisco '
                f'devices use 9600; check the speed in the device documentation.')

    # ------------------------------------------------------------ using the session
    def _require(self):
        if self._conn is None:
            raise ConsoleError(NOT_CONNECTED, 'Not connected. Connect to the console first.')
        if self._cancelled.is_set():
            raise ConsoleError(CANCELLED, 'Cancelled. The serial port was closed.')
        return self._conn

    def _call(self, work, seconds):
        conn = self._require()
        holder = {}
        error = self._run_with_deadline(lambda: holder.__setitem__('value', work(conn)),
                                        seconds, conn)
        if error is not None:
            problem = self._translate(error, phase='command')    # before the output is wiped
            self._release()
            raise problem from None
        return holder.get('value')

    def _prompt_now(self):
        prompt = (self._call(lambda c: c.find_prompt(), self.command_timeout) or '').strip()
        if not _PROMPT.match(prompt):
            self._release()
            raise ConsoleError(UNEXPECTED_PROMPT, 'The device answered, but not with a Cisco IOS '
                                                  'prompt (">" or "#").')
        return prompt

    def find_prompt(self):
        with self._lock:
            return self._prompt_now()

    def send_show(self, command, timeout=None):
        """Send ONE read-only 'show ...' command and return the device's answer."""
        text = check_show_command(command)
        with self._lock:
            self._say('command', text)
            out = self._call(lambda c: c.send_command(text, read_timeout=timeout or
                                                      self.command_timeout),
                             (timeout or self.command_timeout) + 5)
            self._say('info', f'{len(str(out).splitlines())} line(s) received.')
            return out

    def enable(self):
        """'>' -> '#' with the enable password. 'enable' changes no configuration."""
        with self._lock:
            prompt = self._prompt_now()
            if prompt.endswith('#'):
                return prompt
            if not self._enable_password:
                raise ConsoleError(AUTH, 'Privileged mode needs the enable password.')
            self._say('command', 'enable')
            try:
                self._call(lambda c: c.enable(), self.command_timeout)
            except ConsoleError as err:
                if err.kind in (OTHER, UNEXPECTED_PROMPT, TIMEOUT):
                    raise ConsoleError(AUTH, 'The device refused the enable password.') from None
                raise
            prompt = self._prompt_now()
            if not prompt.endswith('#'):
                raise ConsoleError(AUTH, 'The device refused the enable password.')
            return prompt

    def is_active(self):
        """True while the session is logged in and the port is open. Sends nothing
        (Netmiko's is_alive() is not used: for serial it takes its SSH branch and fails)."""
        conn = self._conn
        if conn is None or self._cancelled.is_set():
            return False
        try:
            remote = getattr(conn, 'remote_conn', None)
            return remote is not None and bool(getattr(remote, 'is_open', False))
        except Exception:
            return False

    # ------------------------------------------------------------ closing
    def cancel(self):
        """From any thread: stop the current call and close the port."""
        self._cancelled.set()
        conn = self._conn
        if conn is not None:
            self._close(conn)

    def disconnect(self):
        """Close the session (sends 'exit' to log out of the console line, then closes
        the port). Safe to call at any time, also twice or after an error."""
        conn, self._conn = self._conn, None
        if conn is None:
            return
        self._close(conn, graceful=not self._cancelled.is_set())
        if self._transcript is not None:
            self._transcript.wipe()
        self._say('info', f'Disconnected from {self.port}.')

    def _release(self):
        conn, self._conn = self._conn, None
        if conn is not None:
            self._close(conn)
        if self._transcript is not None:
            self._transcript.wipe()

    @staticmethod
    def _close(conn, graceful=False):
        try:
            if graceful:
                conn.disconnect()
                return
        except Exception:
            pass
        try:
            remote = getattr(conn, 'remote_conn', None)
            if remote is not None:
                remote.close()
        except Exception:
            pass

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.disconnect()
        return False


class _Timeout(Exception):
    """Internal marker: a call did not finish within its time limit."""
