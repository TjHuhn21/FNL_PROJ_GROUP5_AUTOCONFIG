"""One console session to a Cisco device over a serial (COM) port.

    session = ConsoleSession('COM4', baudrate=9600, username='', password='', enable_password='')
    check = session.listen()            # Preflight: the port is opened and only READ
    result = session.connect(confirm_idle=False, startup_action=None)
                                        # ConnectResult: prompt, privileged, notices, how verified

Connecting safely (phase 5.1.6, N1). NetCommand opens the port ITSELF and first only
listens (listen(): nothing is written, not even Enter). What the device printed decides:

    normal ">" / "#" prompt     verified by NetCommand: connect() goes on
    nothing (an idle console)   connect(confirm_idle=True) only: the operator confirms, in
                                a terminal, that the device is at a normal prompt (this is
                                the operator's check, not NetCommand's)
    "Press RETURN to get started"            connect(startup_action=PRESS_RETURN_ACTION)
    "...initial configuration dialog? [yes/no]:"
                                connect(startup_action=DECLINE_SETUP_ACTION): answers "no"
                                (and the "Press RETURN" that follows), never "yes"
    anything else (a question, [confirm], a password or login prompt, a boot loader,
    configuration mode, unreadable or unknown output)        refused: the port is closed
                                                              without writing a byte

The SAME open port is then handed to Netmiko (never reopened, so the decision applies to
the connection that writes the first byte), NetCommand logs in itself (_login: never
Netmiko's serial_login, which writes Enter before reading) and prepares the session with
the unread-output check (N2) before every write.
    session.find_prompt()               # 'R1#'
    session.send_show('show version')   # only 'show ...' commands are accepted
    session.enable()                    # '>' -> '#' with the enable password (not a config change)
    session.is_active()
    session.disconnect()                # always safe; also after errors
    session.cancel()                    # from ANOTHER thread: closes the port, the call stops

Configuration (phase 5.1.2, used only by console.apply for an approved SSH setup plan):

    session.allow_config(plan_lines)    # the ONLY configuration lines that may be sent
    session.enter_config()              # 'configure terminal'           -> ConfigReply
    session.send_config_line(line, secrets={PLACEHOLDER: value})        -> ConfigReply
    session.refresh_prompt()            # an empty line, to re-read a prompt
    session.end_config()                # 'end'                           -> ConfigReply

Each configuration line is checked by check_config_line (one printable line, not a
dangerous command, and listed by allow_config) before anything is written. A reply that
ends in a question, a password prompt or a boot-loader prompt is never answered: the
port is closed at once without sending anything more, and the reply says so. Secret
values are substituted only when the line is written and are masked in every reply,
message and log line. These exchanges read and write the port directly (Netmiko's
serial channel), so a password never reaches Netmiko's debug logging or session log.

Unread output (phase 5.1.5, N2): before ANY write - a configuration line, `enable`, and
every Netmiko call that writes an Enter (find_prompt, send_command, enable,
set_base_prompt, the graceful logout) - what arrived unread is inspected
(classify_pending). Only nothing, log lines, or a recognised prompt are safe; a question,
confirmation, password or boot-loader prompt or unknown text raises
ConsoleError(UNSAFE_OUTPUT) and the port is closed without writing a byte.

It uses Netmiko's `cisco_ios_serial` driver (8 data bits, no parity, 1 stop bit, default
9600 baud). EVERY method here blocks on serial I/O: call them from a worker thread
(gui.background.run_async), never from the Tk main thread. Each one is bounded by a
timeout; when it expires the port is closed so the waiting call returns.

Safety (phase 1):
  * Only `show ...` commands can be sent (send_show refuses anything else), plus what it
    takes to log in and prepare the session: Enter (only after the decision above), the
    username and password if the console asks, `terminal width 511` and `terminal length
    0` (session settings, not configuration), `enable` (only when you call enable()), and
    `exit` when disconnecting.
  * NetCommand never answers a device prompt with "yes". SETUP_DIALOG_NOTICE: if an
    unconfigured device asks "Would you like to enter the initial configuration dialog?
    [yes/no]", NetCommand answers "no" only when the operator approved it (phase 5.1.6;
    before, Netmiko answered "no" by itself); that only skips the setup wizard and changes
    no configuration. The ConnectResult says when this happened.
  * Passwords are never logged or put in a message. What the device prints is captured
    in memory only (to explain a failed login) with Netmiko masking the passwords, and it
    is never written to a file.
  * Errors are ConsoleError with a fixed, readable message (never the driver's own text).
"""
import io
import re
import threading
import time

from console.ports import check_port_name

DEFAULT_BAUD = 9600
BAUD_RATES = (1200, 2400, 4800, 9600, 14400, 19200, 38400, 57600, 115200)
DEFAULT_TIMEOUT = 45          # seconds for connecting (logging in at 9600 baud can be slow)
COMMAND_TIMEOUT = 30          # seconds for one show command
SETUP_DIALOG_NOTICE = (
    'If an unconfigured device asks "Would you like to enter the initial configuration '
    'dialog? [yes/no]", NetCommand answers "no" only after you approve it. This only skips '
    'the setup wizard; it does not change the configuration. NetCommand never answers "yes".')
NETMIKO_SETUP_DIALOG_NOTICE = SETUP_DIALOG_NOTICE           # the name used before phase 5.1.6
SETUP_DIALOG_ANSWERED = ('The device asked to start its initial configuration dialog; with '
                         'your approval NetCommand answered "no" (setup wizard skipped, '
                         'configuration unchanged).')
IDLE_CONFIRMATION = ('I checked the console in a terminal and confirmed that the device is '
                     'at a normal IOS ">" or "#" prompt.')

# ConsoleError kinds
PORT_UNAVAILABLE, PORT_BUSY, UNREADABLE = 'port_unavailable', 'port_busy', 'unreadable'
AUTH, UNEXPECTED_PROMPT, TIMEOUT = 'auth', 'unexpected_prompt', 'timeout'
NOT_CONNECTED, REFUSED, CANCELLED, OTHER = 'not_connected', 'refused', 'cancelled', 'other'
# phase 5.1.6: the port is open, nothing was written, and the operator must decide
CONFIRMATION_REQUIRED, APPROVAL_REQUIRED = 'confirmation_required', 'approval_required'

# listening before the first byte (seconds): at least LISTEN_SECONDS, then until the
# device has been quiet for LISTEN_QUIET (startup output can keep coming), never longer
# than LISTEN_MAX
LISTEN_SECONDS, LISTEN_QUIET, LISTEN_MAX = 2.0, 1.0, 20.0
LISTEN_LIMIT = 16 * 1024          # characters of listened output kept (the newest); memory only

_SHOW = re.compile(r'^show\s+[\x20-\x7e]+$', re.IGNORECASE)        # one printable line
_WRITES_FILE = re.compile(r'\|\s*(redirect|tee|append)\b', re.IGNORECASE)
_BOOT_LOADER = re.compile(r'(^|\n)\s*(rommon\s*\d*\s*>|switch:|loader>)', re.IGNORECASE)
_PASSWORD_PROMPT = re.compile(r'assword\s*:', re.IGNORECASE)
_LOGIN_REFUSED = re.compile(r'% ?(Bad passwords|Login invalid|Authentication failed|Access denied)'
                            r'|Login incorrect', re.IGNORECASE)
_PROMPT = re.compile(r'^[\w.\-/()]+[>#]\s*$')

# ---------------------------------------------------------------- configuration exchanges
MASK = '********'
CONFIG_TIMEOUT = 30           # seconds for one configuration line (RSA keys: the step says)
SETTLE = 0.3                  # seconds of silence after a question-like ending before trusting it
# reply states (ConfigReply.state)
PROMPT, QUESTION, PASSWORD_PROMPT, BOOT_LOADER = 'prompt', 'question', 'password', 'boot_loader'
# a recognised IOS prompt: name, optional (config...) mode, > or #
_IOS_PROMPT = re.compile(r'^([A-Za-z][\w.\-]*)(?:\((config[\w\-]*)\))?([>#])$')
_ENABLE_PASSWORD = re.compile(r'^\s*password\s*:\s*$', re.IGNORECASE)
_BOOT_LINE = re.compile(r'^\s*(rommon\s*\d*\s*>|switch:|loader>)\s*$', re.IGNORECASE)
_QUESTION_END = re.compile(r'(\[yes/no\]\s*:?|\[confirm\]|\[[^\]\n]*\]\s*[:?]|\?|:)\s*$',
                           re.IGNORECASE)
# never sent as configuration, whatever a plan says (the plan allow-list is the main gate)
DANGEROUS_WORDS = ('write', 'copy', 'reload', 'erase', 'delete', 'format', 'boot', 'do',
                   'configure', 'exit', 'end', 'archive', 'tclsh', 'squeeze', 'fsck', 'license',
                   'debug', 'undebug', 'test', 'verify', 'clear', 'rename', 'mkdir', 'rmdir',
                   'upgrade', 'send', 'more', 'dir', 'event', 'kron', 'alias', 'macro', 'default',
                   'aaa', 'enable', 'disable', 'shutdown', 'no')
_PLACEHOLDER = re.compile(r'<[A-Z_]+>')
# Exact lines allowed although their first word is in DANGEROUS_WORDS: bringing up the
# management interface the operator chose (interface mode only; the plan decides where).
SAFE_EXCEPTIONS = ('no shutdown',)
# The ONLY non-configuration command the console session can send besides `show` and
# `enable`: saving, as the very last step of an approved plan that asked for it
# (ConsoleSession.allow_save / save_config). Never through send_config_line.
SAVE_COMMAND = 'write memory'
SAVE_TIMEOUT = 120               # seconds: writing NVRAM can be slow on old devices


def check_config_line(line, allowed=None):
    """The line if it may be sent as configuration, else ConsoleError(REFUSED). It must be
    ONE printable line, contain no redirection, not start with a dangerous command (the
    exact lines in SAFE_EXCEPTIONS excepted), and (when `allowed` is given) be one of the
    allowed lines. <PLACEHOLDER> tokens are allowed: their values are substituted only
    when the line is written."""
    text = line if isinstance(line, str) else ''
    bare = text.strip()
    if not bare or '\r' in text or '\n' in text or any(not 32 <= ord(c) <= 126 for c in text):
        raise ConsoleError(REFUSED, 'Only one printable configuration line can be sent at a '
                                    'time; nothing was sent.')
    without = _PLACEHOLDER.sub('', bare)
    if any(c in without for c in '|<>?') or 'redirect' in without.lower():
        raise ConsoleError(REFUSED, f'"{bare}" contains "|", "<", ">" or "?" (redirection or '
                                    f'help); nothing was sent.')
    first = bare.split()[0].lower()
    if bare in SAFE_EXCEPTIONS:
        first = ''
    if first in DANGEROUS_WORDS or bare.lower().startswith('crypto key zeroize'):
        raise ConsoleError(REFUSED, f'"{first}" is never sent as configuration by NetCommand; '
                                    f'nothing was sent.')
    if allowed is not None and bare not in allowed:
        raise ConsoleError(REFUSED, f'"{bare}" is not part of the approved plan; nothing was '
                                    f'sent.')
    return bare


def check_secret(value):
    """A secret substituted into a configuration line: printable, no whitespace (IOS
    would read "5 x" / "7 x" as a hash type, or cut the value at a space), no "?", and
    not shaped like a stored hash ("$1$..."), and at most SECRET_MAX characters (IOS
    refuses longer account secrets)."""
    if not isinstance(value, str) or not value or '?' in value or \
            any(not 33 <= ord(c) <= 126 for c in value) or re.match(r'^\$\d+\$', value) or \
            len(value) > SECRET_MAX:
        raise ConsoleError(REFUSED, f'The password cannot be sent (empty, longer than '
                                    f'{SECRET_MAX} characters, whitespace, "?", an unprintable '
                                    f'character, or shaped like a stored hash); nothing was '
                                    f'sent.')
    return value


# Cisco IOS limit for `username ... secret` (IOS 15.4 on a CISCO1941: "% Invalid Password
# length - must contain 1 to 25 characters"); console.plan.PASSWORD_MAX is the same
SECRET_MAX = 25


def mask_text(text, secrets):
    """text with every secret value replaced by ********."""
    for value in secrets or ():
        if value:
            text = text.replace(value, MASK)
    return text


def classify_reply(text):
    """(state, prompt) for what the device printed after a line, judged on its last line:
    BOOT_LOADER, PASSWORD_PROMPT, PROMPT (with the prompt text), QUESTION, or (None, None)
    when the reply has not ended yet (or ended in something unrecognised)."""
    tail = (text or '').replace('\r', '').rstrip(' \t')
    last = tail.split('\n')[-1].strip() if tail.strip() else ''
    if not last:
        return None, None
    if _BOOT_LINE.match(last):
        return BOOT_LOADER, None
    if _ENABLE_PASSWORD.match(last):
        return PASSWORD_PROMPT, None
    if _IOS_PROMPT.match(last):
        return PROMPT, last
    if _QUESTION_END.search(last):
        return QUESTION, None
    return None, None


UNSAFE_OUTPUT = 'unsafe_output'          # ConsoleError kind: unread output was not safe


def classify_pending(text):
    """(safe, what) for output that arrived while NetCommand was NOT waiting for a reply
    (phase 5.1.5, N2). Safe only when it is empty, only blank or system log lines
    (`%LINK-3-UPDOWN`, `%SYS-5-CONFIG_I` ...), or ends in a recognised IOS prompt. A
    question, confirmation, password prompt, boot-loader prompt or anything else is not
    safe: the next byte written could become its answer."""
    from console.detect import strip_log_lines              # (detect imports this module)
    body, _logs = strip_log_lines((text or '').replace('\r', ''))
    if not body.strip():
        return True, None
    state, _prompt = classify_reply(body)
    if state == PROMPT:
        return True, None
    return False, {QUESTION: 'a question or confirmation prompt',
                   PASSWORD_PROMPT: 'a password prompt',
                   BOOT_LOADER: 'a boot-loader prompt'}.get(state, 'output NetCommand does not '
                                                                   'recognise')


def unread_output(conn):
    """Everything the device sent that nobody has read yet: Netmiko's own read buffer and
    the serial port's input. Reading sends nothing. (A connection without a serial
    channel - only test doubles - has nothing to read.)"""
    pieces = []
    buffered = getattr(conn, '_read_buffer', '')
    if buffered:
        pieces.append(buffered)
        conn._read_buffer = ''
    channel = getattr(conn, 'channel', None)
    if channel is not None:
        pieces.append(channel.read_channel())
    return ''.join(pieces)


# ---------------------------------------------------------------- the console before connecting
CONSOLE_SILENT, CONSOLE_PROMPT, CONSOLE_CONFIG_PROMPT = 'silent', 'prompt', 'config_prompt'
CONSOLE_PRESS_RETURN, CONSOLE_SETUP_DIALOG = 'press_return', 'setup_dialog'
CONSOLE_USERNAME, CONSOLE_PASSWORD, CONSOLE_QUESTION = 'username', 'password', 'question'
CONSOLE_BOOT_LOADER, CONSOLE_UNREADABLE, CONSOLE_UNKNOWN = 'boot_loader', 'unreadable', 'unknown'
# the only startup prompts recognised (documented in docs/INITIAL_SETUP.md, tested)
_PRESS_RETURN = re.compile(r'^press return to get started\s*[.!]?$', re.IGNORECASE)
_SETUP_DIALOG = re.compile(r'would you like to enter the initial configuration dialog\?\s*'
                           r'\[yes/no\]\s*:?$', re.IGNORECASE)
_LOGIN_NAME = re.compile(r'^(username|user name|login)\s*:$', re.IGNORECASE)
# how the first byte was allowed (ConnectResult.verification)
VERIFIED, OPERATOR_CONFIRMED, STARTUP_ACTION = 'verified', 'operator_confirmed', 'startup_action'
PRESS_RETURN_ACTION, DECLINE_SETUP_ACTION = 'press_return', 'decline_setup'


def console_state(text):
    """(state, prompt) of a console from what it printed, judged on its last meaningful
    line (system log lines are ignored): CONSOLE_SILENT (nothing), CONSOLE_PROMPT ("R1>" /
    "R1#"), CONSOLE_CONFIG_PROMPT, the two startup prompts, CONSOLE_USERNAME /
    CONSOLE_PASSWORD, CONSOLE_QUESTION, CONSOLE_BOOT_LOADER, CONSOLE_UNREADABLE or
    CONSOLE_UNKNOWN. Only whole, recognised lines count; nothing is guessed."""
    raw = text or ''
    if unreadable(raw):
        return CONSOLE_UNREADABLE, None
    from console.detect import strip_log_lines              # (detect imports this module)
    body, _logs = strip_log_lines(raw.replace('\r', ''))
    lines = [l.strip() for l in body.split('\n') if l.strip()]
    if not lines:
        return CONSOLE_SILENT, None
    last = lines[-1]
    if _BOOT_LINE.match(last):
        return CONSOLE_BOOT_LOADER, None
    if _SETUP_DIALOG.search(last):
        return CONSOLE_SETUP_DIALOG, None
    if _PRESS_RETURN.match(last):
        return CONSOLE_PRESS_RETURN, None
    if _LOGIN_NAME.match(last):
        return CONSOLE_USERNAME, None
    if _ENABLE_PASSWORD.match(last):
        return CONSOLE_PASSWORD, None
    m = _IOS_PROMPT.match(last)
    if m:
        return (CONSOLE_CONFIG_PROMPT if m.group(2) else CONSOLE_PROMPT), last
    if _QUESTION_END.search(last):
        return CONSOLE_QUESTION, None
    return CONSOLE_UNKNOWN, None


_PREFLIGHT_TEXT = {
    CONSOLE_PROMPT: 'Normal prompt detected by NetCommand ({prompt}).',
    CONSOLE_SILENT: ('The console is silent: NetCommand cannot see whether the device is at '
                     'a normal prompt or waiting for an answer. Manual confirmation required.'),
    CONSOLE_PRESS_RETURN: 'Known startup prompt detected: "Press RETURN to get started".',
    CONSOLE_SETUP_DIALOG: ('Known startup question detected: the device asks whether to enter '
                           'its initial configuration dialog.'),
}
# refused states: (ConsoleError kind, message)
_REFUSED = {
    CONSOLE_QUESTION: (UNSAFE_OUTPUT, 'The device is waiting for an answer to a question or '
                                      'confirmation.'),
    CONSOLE_PASSWORD: (UNSAFE_OUTPUT, 'The device is waiting at a password prompt.'),
    CONSOLE_USERNAME: (UNSAFE_OUTPUT, 'The device is waiting at a login prompt.'),
    CONSOLE_BOOT_LOADER: (UNEXPECTED_PROMPT, 'The device is in its boot loader (ROMMON / '
                                             'switch:), not running IOS. Stop and ask the '
                                             'instructor; do not type commands there.'),
    CONSOLE_CONFIG_PROMPT: (UNEXPECTED_PROMPT, 'The device is in configuration mode (left there '
                                               'by someone).'),
    CONSOLE_UNREADABLE: (UNREADABLE, 'The output is unreadable (probably the wrong speed).'),
    CONSOLE_UNKNOWN: (UNEXPECTED_PROMPT, 'The device printed something NetCommand does not '
                                         'recognise, not with a Cisco IOS prompt (">" or "#").'),
}
REFUSAL_ADVICE = (' Nothing was sent and the console port was closed. Look at the console in a '
                  'terminal program and resolve it yourself, then connect again.')


class Preflight:
    """What the console showed before NetCommand wrote anything. The listened text itself
    is never kept: only its state and, for a normal prompt, the prompt."""

    def __init__(self, state, prompt=None):
        self.state, self.prompt = state, prompt

    @property
    def refused(self):
        return self.state in _REFUSED

    @property
    def needs(self):
        """What the operator must give before the first byte: 'confirm_idle', a startup
        action, or None (a verified prompt, or refused)."""
        return {CONSOLE_SILENT: 'confirm_idle', CONSOLE_PRESS_RETURN: PRESS_RETURN_ACTION,
                CONSOLE_SETUP_DIALOG: DECLINE_SETUP_ACTION}.get(self.state)

    @property
    def message(self):
        if self.state in _REFUSED:
            return 'Unsafe or unknown console state; connection refused. ' + \
                _REFUSED[self.state][1] + REFUSAL_ADVICE
        return _PREFLIGHT_TEXT[self.state].format(prompt=self.prompt)

    def __repr__(self):
        return f'Preflight(state={self.state!r}, prompt={self.prompt!r})'


def gate(preflight, confirm_idle=False, startup_action=None):
    """None when the first byte may be written for this preflight, else the ConsoleError
    saying why not. confirm_idle must be exactly True (a ticked checkbox); startup_action
    must name the startup prompt that was actually detected."""
    state = preflight.state
    if state in _REFUSED:
        kind, text = _REFUSED[state]
        return ConsoleError(kind, preflight.message)
    if state == CONSOLE_SILENT and confirm_idle is not True:
        return ConsoleError(CONFIRMATION_REQUIRED, _PREFLIGHT_TEXT[state] + ' Tick "' +
                            IDLE_CONFIRMATION + '" only after checking it yourself.')
    if state == CONSOLE_PRESS_RETURN and startup_action != PRESS_RETURN_ACTION:
        return ConsoleError(APPROVAL_REQUIRED, _PREFLIGHT_TEXT[state] + ' Approve pressing '
                                               'Enter to start the console session.')
    if state == CONSOLE_SETUP_DIALOG and startup_action != DECLINE_SETUP_ACTION:
        return ConsoleError(APPROVAL_REQUIRED, _PREFLIGHT_TEXT[state] + ' Approve answering '
                                               '"no" (skip the wizard) to continue.')
    return None


def prompt_parts(prompt):
    """'R1(config-line)#' -> ('R1', 'config-line', '#'); None when not an IOS prompt."""
    m = _IOS_PROMPT.match(prompt or '')
    return (m.group(1), m.group(2), m.group(3)) if m else None


class ConfigReply:
    """What the device answered to one configuration exchange. text: the whole reply
    (echo included) with every secret masked. state: PROMPT / QUESTION / PASSWORD_PROMPT /
    BOOT_LOADER. prompt: the prompt it ended with (PROMPT only). A reply in any state but
    PROMPT has closed the session: nothing was answered."""

    def __init__(self, text, state, prompt=None):
        self.text, self.state, self.prompt = text, state, prompt

    @property
    def last_line(self):
        lines = [l.strip() for l in self.text.replace('\r', '').split('\n') if l.strip()]
        return lines[-1] if lines else ''

    def __repr__(self):
        return f'ConfigReply(state={self.state!r}, prompt={self.prompt!r})'


class ConsoleError(Exception):
    """A console problem: .kind (one of the constants above) and a fixed message."""

    def __init__(self, kind, message):
        super().__init__(message)
        self.kind = kind


class ConnectResult:
    """verification: how the first byte was allowed - VERIFIED (NetCommand saw a normal
    prompt), OPERATOR_CONFIRMED (silent console, the operator's own check) or
    STARTUP_ACTION (an approved startup prompt). preflight: the Preflight state."""

    def __init__(self, port, baudrate, prompt, notices, verification=VERIFIED,
                 preflight=CONSOLE_PROMPT):
        self.port, self.baudrate, self.prompt = port, baudrate, prompt
        self.privileged = prompt.endswith('#')
        self.notices = list(notices)
        self.verification, self.preflight = verification, preflight

    def __repr__(self):
        return (f'ConnectResult(port={self.port!r}, baudrate={self.baudrate}, '
                f'prompt={self.prompt!r}, privileged={self.privileged}, '
                f'verification={self.verification!r})')


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
                 log=None, connect_handler=None, enable_without_password=False,
                 listen_seconds=LISTEN_SECONDS, listen_quiet=LISTEN_QUIET,
                 listen_max=LISTEN_MAX):
        """log(kind, text): optional progress lines ('info', 'command', 'ok', 'warn',
        'error'), never containing a password. connect_handler: tests only (default
        netmiko.ConnectHandler). enable_without_password: enable() may send a bare
        `enable` when no enable password was given (a factory device has none); if the
        device asks for a password it is never answered."""
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
        self._enable_without_password = bool(enable_without_password)
        self._allowed = frozenset()                        # allow_config(): plan lines only
        self._save_allowed = False                         # allow_save(): the plan saves
        self._in_config = False
        self._secrets = ()                                 # values masked in config replies
        self.listen_seconds, self.listen_quiet = listen_seconds, listen_quiet
        self.listen_max = listen_max
        self._serial = None          # the port NetCommand opened (listen); handed to Netmiko
        self._preflight = None       # what it showed before anything was written

    def __repr__(self):                                    # never shows the passwords
        state = 'connected' if self._conn is not None else 'closed'
        return f'ConsoleSession(port={self.port!r}, baudrate={self.baudrate}, {state})'

    # ------------------------------------------------------------ logging without secrets
    def _say(self, kind, text):
        for secret in (self._password, self._enable_password) + tuple(self._secrets):
            if secret:
                text = text.replace(secret, '********')
        try:
            self._log(kind, text)
        except Exception:
            pass

    # ------------------------------------------------------------ connecting (phase 5.1.6)
    def listen(self):
        """Open the port and only READ for a bounded time: nothing is written, not even
        Enter. Returns a Preflight. A refused state closes the port again; otherwise the
        port stays open (still nothing written) for connect()."""
        with self._lock:
            return self._listen_locked()

    def _listen_locked(self):
        if self._conn is not None:
            raise ConsoleError(OTHER, f'{self.port} is already connected.')
        if self._serial is not None and self._preflight is not None:
            return self._preflight                       # already listening on this port
        self._cancelled.clear()
        self._transcript = _Transcript()
        self._say('info', f'Opening {self.port} at {self.baudrate} baud (8 data bits, no '
                          f'parity, 1 stop bit) and listening only: nothing is sent yet...')
        try:
            self._serial = self._open_port()
        except ConsoleError:
            raise
        except Exception as err:
            raise self._translate(err, phase='open') from None
        holder = {}
        error = self._run_with_deadline(lambda: holder.__setitem__('text', self._listen_port()),
                                        min(self.timeout, self.listen_max + 5),
                                        _PortOnly(self._serial))
        if error is not None:
            self._close_port()
            raise self._translate(error, phase='listen') from None
        state, prompt = console_state(holder.pop('text', ''))
        preflight = Preflight(state, prompt)
        if preflight.refused:
            self._close_port()                           # nothing was written
            self._say('error', preflight.message)
        else:
            self._preflight = preflight                  # the port stays open, nothing written
            self._say('info', preflight.message)
        return preflight

    def _open_port(self):
        """Open the serial port (once; Netmiko never reopens it). Only a port the system
        lists is opened. pyserial clears both buffers when it opens the port and raises
        DTR/RTS as any terminal program does; nothing toggles them afterwards."""
        import serial
        import serial.tools.list_ports as list_ports
        names = {p.device.upper() for p in list_ports.comports()}
        if self.port.upper() not in names:
            raise ConsoleError(PORT_UNAVAILABLE, f'{self.port} is not available. Check that the '
                                                 f'cable is plugged in and its driver is '
                                                 f'installed, then refresh the port list.')
        return serial.Serial(port=self.port, baudrate=self.baudrate, bytesize=8, parity='N',
                             stopbits=1, timeout=0)

    def _listen_port(self):
        """Read what the device prints, without writing: at least listen_seconds, then
        until it has been quiet for listen_quiet, at most listen_max. Memory only."""
        port = self._serial
        text, start = '', time.monotonic()
        last = start
        while True:
            if self._cancelled.is_set():
                raise ConsoleError(CANCELLED, 'Cancelled. The serial port was closed.')
            waiting = port.in_waiting
            now = time.monotonic()
            if waiting:
                text = (text + port.read(waiting).decode('utf-8', 'replace'))[-LISTEN_LIMIT:]
                last = now
                continue
            if now - start >= self.listen_max:
                return text
            if now - start >= self.listen_seconds and now - last >= self.listen_quiet:
                return text
            time.sleep(0.02)

    def connect(self, confirm_idle=False, startup_action=None):
        """Log in on the port listen() opened (listen() first when it has not run). The
        first byte is written only when gate() allows it for what the device showed:
        a normal prompt; a silent console with confirm_idle=True (the operator's own
        check); or the approved action for a recognised startup prompt. Otherwise raises
        ConsoleError: refused states close the port; CONFIRMATION_REQUIRED and
        APPROVAL_REQUIRED leave it open with nothing written, for another connect()."""
        with self._lock:
            preflight = self._listen_locked()
            problem = gate(preflight, confirm_idle, startup_action)
            if problem is not None:
                if preflight.refused:
                    self._close_port()
                raise problem
            try:
                conn = self._create()
            except Exception as err:
                self._close_port()
                raise self._translate(err, phase='open') from None
            self._hand_over(conn)
            self._conn = conn
            notices = [SETUP_DIALOG_NOTICE]
            try:
                self._login(preflight, notices)
                self._prepare_session()
                prompt = self._prompt_now()
            except ConsoleError as err:
                if err.kind == APPROVAL_REQUIRED and self._serial is not None:
                    self._conn = None                    # the port stays open, nothing answered
                    raise
                self._release()
                raise
            verification = {CONSOLE_PROMPT: VERIFIED, CONSOLE_SILENT: OPERATOR_CONFIRMED}.get(
                preflight.state, STARTUP_ACTION)
            self._transcript.stop()          # logged in: later command output is not kept
            how = {VERIFIED: 'NetCommand verified the prompt before writing anything',
                   OPERATOR_CONFIRMED: 'the first Enter relied on your confirmation that the '
                                       'console was at a normal prompt',
                   STARTUP_ACTION: 'after the approved startup action'}[verification]
            self._say('ok', f'Connected on {self.port} ({how}). Device prompt: {prompt}')
            return ConnectResult(self.port, self.baudrate, prompt, notices, verification,
                                 preflight.state)

    def _hand_over(self, conn):
        """Give Netmiko the port NetCommand opened and listened on (it never opens its
        own: establish_connection and its serial_login, which writes Enter before
        reading, are not used)."""
        from netmiko.channel import SerialChannel
        conn.remote_conn = self._serial
        conn.channel = SerialChannel(conn=self._serial,
                                     encoding=getattr(conn, 'encoding', 'utf-8'))

    def _login(self, preflight, notices):
        """The controlled login. Writes only what the decision allowed, then answers ONLY
        the console's own login prompts (username / password, when given) and, after an
        approved "no" to the setup dialog, the one "Press RETURN" that follows. Any other
        state stops: a recognised startup prompt that was not approved leaves the port open
        (APPROVAL_REQUIRED); everything else closes it."""
        if preflight.state == CONSOLE_PROMPT:
            return preflight.prompt                     # nothing to write: already logged in
        press_return_allowed = False
        if preflight.state == CONSOLE_SETUP_DIALOG:
            self._say('warn', 'Answering "no" to the initial configuration dialog (approved).')
            reply = self._login_exchange('no')
            notices.insert(0, SETUP_DIALOG_ANSWERED)
            press_return_allowed = True
        else:                                           # silent (confirmed) / Press RETURN
            reply = self._login_exchange('')
        sent_user = sent_password = False
        for _round in range(8):
            state, prompt = console_state(reply)
            low = reply.lower()
            if 'password required, but none set' in low:
                raise ConsoleError(AUTH, 'The console asks for a password, but the device has '
                                         'none set, so nobody can log in on this line.')
            if (sent_user or sent_password) and _LOGIN_REFUSED.search(reply):
                raise ConsoleError(AUTH, 'The device refused the console login (wrong username '
                                         'or password).')
            if state == CONSOLE_PROMPT:
                return prompt
            if state == CONSOLE_PRESS_RETURN and press_return_allowed:
                press_return_allowed = False
                reply = self._login_exchange('')
                continue
            if state == CONSOLE_USERNAME and self._username and not sent_user:
                sent_user = True
                reply = self._login_exchange(self._username)
                continue
            if state == CONSOLE_PASSWORD and self._password and not sent_password:
                sent_password = True
                reply = self._login_exchange(self._password, secrets=(self._password,))
                continue
            if state in (CONSOLE_USERNAME, CONSOLE_PASSWORD):
                raise ConsoleError(AUTH, 'The console asks for a password. Enter the console '
                                         'login and try again.' if not (sent_user or
                                                                        sent_password) else
                                   'The device refused the console login (wrong username or '
                                   'password).')
            if state in (CONSOLE_SETUP_DIALOG, CONSOLE_PRESS_RETURN):
                self._preflight = Preflight(state)         # ask the operator; port stays open
                raise gate(self._preflight)
            if state in _REFUSED:
                raise ConsoleError(_REFUSED[state][0], 'Unsafe or unknown console state after '
                                                       'logging in. ' + _REFUSED[state][1] +
                                   REFUSAL_ADVICE)
            break
        raise ConsoleError(UNEXPECTED_PROMPT, 'The device answered, but not with a Cisco IOS '
                                              'prompt (">" or "#").')

    def _login_exchange(self, text, secrets=()):
        """One login line: unread output checked first (N2), then the line, then read
        until the console shows a recognised state. Never anything else."""
        def work(conn):
            self._check_unread(conn)
            channel = conn.channel
            channel.write_channel(text + conn.RETURN)
            buffer, deadline = '', time.monotonic() + min(self.timeout, 30)
            while True:
                if self._cancelled.is_set():
                    raise ConsoleError(CANCELLED, 'Cancelled. The serial port was closed.')
                piece = channel.read_buffer()
                if piece:
                    buffer = (buffer + piece)[-LISTEN_LIMIT:]
                    continue
                state, _prompt = console_state(buffer)
                if state not in (CONSOLE_SILENT, CONSOLE_UNKNOWN, CONSOLE_UNREADABLE):
                    time.sleep(SETTLE)
                    more = channel.read_buffer()
                    if not more:
                        return buffer
                    buffer += more
                    continue
                if time.monotonic() > deadline:
                    if unreadable(buffer):
                        raise ConsoleError(UNREADABLE, self._unreadable_text())
                    if not buffer.strip():
                        raise ConsoleError(TIMEOUT, f'No answer on {self.port}. Check the '
                                                    f'cable, that the device is on, and the '
                                                    f'speed ({self.baudrate} baud).')
                    raise ConsoleError(UNEXPECTED_PROMPT, 'The device answered, but not with a '
                                                          'Cisco IOS prompt (">" or "#").')
                time.sleep(0.02)
        return mask_text(self._call(work, min(self.timeout, 30) + 10), secrets)

    def _prepare_session(self):
        """Netmiko's IOS session preparation, one call at a time, each after the
        unread-output check (its own blind Enter, force_data, is not used)."""
        for work in (lambda c: c.set_terminal_width(command='terminal width 511',
                                                     pattern='terminal width 511'),
                     lambda c: c.disable_paging(),
                     lambda c: c.set_base_prompt()):
            self._call(self._guarded(work), self.timeout)

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

    def _check_unread(self, conn):
        """N2: before ANY write (ours, or Netmiko's own Enter in find_prompt, send_command,
        set_base_prompt, enable), look at what arrived unread. Anything unsafe raises
        ConsoleError(UNSAFE_OUTPUT); the caller's _call then closes the port without
        writing a byte. The unread text itself is never kept or shown."""
        safe, what = classify_pending(unread_output(conn))
        if not safe:
            raise ConsoleError(UNSAFE_OUTPUT, f'The device printed {what} while NetCommand was '
                                              f'not waiting for anything. Nothing was sent: the '
                                              f'console port was closed so that nothing can '
                                              f'answer it. Resolve it at the console, then '
                                              f'connect again.')

    def _guarded(self, work):
        """work(conn), after _check_unread(conn): for Netmiko calls that write."""
        def run(conn):
            self._check_unread(conn)
            return work(conn)
        return run

    def _prompt_now(self):
        prompt = (self._call(self._guarded(lambda c: c.find_prompt()),
                             self.command_timeout) or '').strip()
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
            out = self._call(self._guarded(lambda c: c.send_command(
                text, read_timeout=timeout or self.command_timeout)),
                (timeout or self.command_timeout) + 5)
            self._say('info', f'{len(str(out).splitlines())} line(s) received.')
            return out

    def enable(self):
        """'>' -> '#' with the enable password. 'enable' changes no configuration.
        Without an enable password (and enable_without_password): only `enable` is sent;
        the '#' prompt is accepted, and a password prompt is never answered."""
        with self._lock:
            prompt = self._prompt_now()
            if prompt.endswith('#'):
                return prompt
            if not self._enable_password:
                if self._enable_without_password:
                    return self._enable_bare()
                raise ConsoleError(AUTH, 'Privileged mode needs the enable password.')
            self._say('command', 'enable')
            try:
                self._call(self._guarded(lambda c: c.enable()), self.command_timeout)
            except ConsoleError as err:
                if err.kind in (OTHER, UNEXPECTED_PROMPT, TIMEOUT):
                    raise ConsoleError(AUTH, 'The device refused the enable password.') from None
                raise
            prompt = self._prompt_now()
            if not prompt.endswith('#'):
                raise ConsoleError(AUTH, 'The device refused the enable password.')
            return prompt

    def _enable_bare(self):
        """`enable` with no password: '#' is accepted; a password prompt is NOT answered
        (the port is closed at once, leaving the device at its prompt)."""
        self._say('command', 'enable')
        reply = self._exchange('enable', self.command_timeout)
        if reply.state == PASSWORD_PROMPT:
            raise ConsoleError(AUTH, 'The device asks for an enable password. NetCommand did not '
                                     'answer it and closed the console port; the device is left '
                                     'at its "Password:" prompt. Connect again with the enable '
                                     'password, or ask whoever manages the device.')
        if reply.state != PROMPT:
            raise ConsoleError(UNEXPECTED_PROMPT, 'The device did not answer "enable" with a '
                                                  'prompt; the console port was closed and nothing '
                                                  'was answered.')
        if not reply.prompt.endswith('#'):
            raise ConsoleError(AUTH, 'The device did not enter privileged mode.')
        return reply.prompt

    # ------------------------------------------------------------ configuration (phase 5.1.2)
    def allow_config(self, lines):
        """The configuration lines that may be sent in this session (the approved plan's
        lines, with <PLACEHOLDERS>). Every one must pass check_config_line."""
        allowed = frozenset(check_config_line(l) for l in lines)
        with self._lock:
            self._allowed = allowed

    def enter_config(self, timeout=None):
        """'configure terminal'. ConfigReply; the caller checks the prompt it ended with."""
        with self._lock:
            if self._in_config:
                raise ConsoleError(REFUSED, 'Already in configuration mode; nothing was sent.')
            self._say('command', 'configure terminal')
            reply = self._exchange('configure terminal', timeout or self.command_timeout)
            self._in_config = reply.state == PROMPT and '(config' in (reply.prompt or '')
            return reply

    def send_config_line(self, line, expect=None, timeout=None, secrets=None):
        """ONE line of the approved plan, in configuration mode. secrets: {placeholder:
        value}, substituted only when the line is written and masked in the reply.
        expect: informational (the caller compares ConfigReply.prompt with it)."""
        template = check_config_line(line, self._allowed)
        values = dict(secrets or {})
        text = template
        for placeholder, value in values.items():
            if placeholder in text:
                text = text.replace(placeholder, check_secret(value))
        if _PLACEHOLDER.search(text):
            raise ConsoleError(REFUSED, 'A value the line needs was not given; nothing was sent.')
        with self._lock:
            if not self._in_config:
                raise ConsoleError(REFUSED, 'Not in configuration mode; nothing was sent.')
            self._secrets = tuple(v for v in values.values() if v)
            try:
                self._say('command', template)
                return self._exchange(text, timeout or CONFIG_TIMEOUT)
            finally:
                self._secrets = ()

    def refresh_prompt(self, timeout=None):
        """An empty line, to read the prompt again (after a stale prompt). Only when the
        last reply ended in a prompt, never to answer a question."""
        with self._lock:
            return self._exchange('', timeout or self.command_timeout)

    def allow_save(self, allowed):
        """Whether save_config() may run in this session (only for an approved plan whose
        last step is saving)."""
        with self._lock:
            self._save_allowed = bool(allowed)

    def save_config(self, timeout=None):
        """`write memory`, at the privileged prompt, only after allow_save(True). A question
        or any other prompt is never answered (the session closes, as for every exchange).
        ConfigReply; the caller verifies the startup configuration with show commands."""
        with self._lock:
            if not getattr(self, '_save_allowed', False):
                raise ConsoleError(REFUSED, 'Saving was not part of the approved plan; nothing '
                                            'was sent.')
            if self._in_config:
                raise ConsoleError(REFUSED, 'Still in configuration mode; nothing was sent.')
            self._say('command', SAVE_COMMAND)
            return self._exchange(SAVE_COMMAND, timeout or SAVE_TIMEOUT)

    def end_config(self, timeout=None):
        """'end', then Netmiko learns the (possibly renamed) prompt again."""
        with self._lock:
            if not self._in_config:
                raise ConsoleError(REFUSED, 'Not in configuration mode; nothing was sent.')
            self._say('command', 'end')
            reply = self._exchange('end', timeout or self.command_timeout)
            if reply.state == PROMPT and '(config' not in reply.prompt:
                self._in_config = False
                self._call(self._guarded(lambda c: c.set_base_prompt()), self.command_timeout)
            return reply

    def _exchange(self, text, seconds):
        """Write one line and read until the reply ends (a prompt, a question, a password
        or boot-loader prompt). Reads and writes the port directly. A reply that is not a
        prompt closes the session at once: nothing is ever answered. Secret values are
        masked before the text leaves this method. Caller holds self._lock."""
        secrets = self._secrets

        def work(conn):
            channel = conn.channel
            # N2: what arrived meanwhile is INSPECTED, not thrown away: if it is a question
            # (or anything unsafe), nothing is written and the port is closed
            self._check_unread(conn)
            channel.write_channel(text + conn.RETURN)
            buffer, deadline = '', time.monotonic() + seconds
            while True:
                if self._cancelled.is_set():
                    raise ConsoleError(CANCELLED, 'Cancelled. The serial port was closed.')
                piece = channel.read_buffer()
                if piece:
                    buffer += piece
                    continue
                state, _prompt = classify_reply(buffer)
                if state is not None:
                    time.sleep(SETTLE)                     # a line may still be arriving
                    more = channel.read_buffer()
                    if not more:
                        return buffer
                    buffer += more
                    continue
                if time.monotonic() > deadline:
                    raise ConsoleError(TIMEOUT, f'The device did not finish answering within '
                                                f'{int(seconds)} seconds; the console port was '
                                                f'closed. Whether the line took effect is not '
                                                f'known.')
                time.sleep(0.02)

        raw = self._call(work, seconds + 10)
        masked = mask_text(raw, secrets)
        state, prompt = classify_reply(masked)
        if state != PROMPT:
            self._release()                                # never answered: port closed
            self._say('warn', f'The device ended with "{masked.strip().splitlines()[-1] if masked.strip() else ""}"; '
                              f'nothing was answered and the console port was closed.')
        return ConfigReply(masked, state, prompt)

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
        port = self._serial
        if port is not None:                         # listening / waiting for a decision
            self._close(_PortOnly(port))

    def _close_port(self):
        """Close the port NetCommand opened, before Netmiko had it: nothing is written."""
        port, self._serial, self._preflight = self._serial, None, None
        if port is not None:
            self._close(_PortOnly(port))
        if self._transcript is not None:
            self._transcript.wipe()

    def disconnect(self):
        """Close the session (sends 'exit' to log out of the console line, then closes
        the port). Safe to call at any time, also twice or after an error. A port that was
        only listened on (nothing written yet) is just closed."""
        conn, self._conn = self._conn, None
        self._allowed, self._in_config, self._save_allowed = frozenset(), False, False
        if conn is None:
            if self._serial is not None:
                self._close_port()
                self._say('info', f'Closed {self.port} (nothing was sent).')
            return
        self._serial, self._preflight = None, None   # Netmiko closes it below
        graceful = not self._cancelled.is_set()
        if graceful:
            # N2: Netmiko's graceful logout writes Enter, maybe "end", then "exit": only
            # when nothing unsafe is waiting unread; otherwise the port is just closed
            try:
                graceful = classify_pending(unread_output(conn))[0]
            except Exception:
                graceful = False
        self._close(conn, graceful=graceful)
        if self._transcript is not None:
            self._transcript.wipe()
        self._say('info', f'Disconnected from {self.port}.')

    def _release(self):
        self._in_config = False
        conn, self._conn = self._conn, None
        if conn is not None:
            self._close(conn)
        port, self._serial, self._preflight = self._serial, None, None
        if port is not None and (conn is None or getattr(conn, 'remote_conn', None) is not port):
            self._close(_PortOnly(port))
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


class _PortOnly:
    """Lets _run_with_deadline / _close close a bare serial port (before Netmiko has it)."""

    def __init__(self, port):
        self.remote_conn = port


class _Timeout(Exception):
    """Internal marker: a call did not finish within its time limit."""
