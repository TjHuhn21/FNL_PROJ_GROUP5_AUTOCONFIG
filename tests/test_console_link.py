"""console.link: one console session. Offline.

Phase 5.1.6 (N1): the session opens the port itself and LISTENS before writing anything.
An idle fake device (like real IOS) prints nothing until it receives a line, so these
tests connect with confirm_idle=True: the operator's confirmation that the console is at
a normal prompt. FakeSerial.on_open is output that is already there when the port opens
(what listening can see). Login is NetCommand's own (never Netmiko's serial_login).

Two kinds of fake:
  * FakeSerial replaces serial.Serial, so the REAL Netmiko cisco_ios_serial driver runs
    against a tiny emulated IOS console (no port is opened).
  * FakeConn replaces netmiko.ConnectHandler, for failures whose real login loop takes
    20+ seconds (wrong password, wrong speed, boot loader, ...).
"""
import threading
import time
from types import SimpleNamespace

import pytest
import serial
import serial.tools.list_ports as list_ports

from console import link
from console.link import ConsoleError, ConsoleSession

LOGIN_PW = 'S3cret-Console!'
ENABLE_PW = 'En4ble-Secret!'
VERSION = ('Cisco IOS Software, C1900 Software (C1900-UNIVERSALK9-M), Version 15.4(3)M2\r\n'
           'R1 uptime is 1 hour\r\n')


class Device:
    """A minimal Cisco IOS console: what it prints for each line it receives."""

    def __init__(self, login_password=None, enable_password=ENABLE_PW, setup_dialog=False,
                 echo_secrets=False, privileged=False, mute=False, no_password_set=False):
        self.login_password = login_password
        self.enable_password = enable_password
        self.setup_dialog = setup_dialog
        self.echo_secrets = echo_secrets
        self.privileged = privileged
        self.mute, self.no_password_set = mute, no_password_set   # never answers / no password
        self.state = 'setup' if setup_dialog else ('login' if login_password else 'exec')
        self.greeted = False
        self.lines = []                         # every line NetCommand/Netmiko sent

    @property
    def prompt(self):
        return 'R1#' if self.privileged else 'R1>'

    def line(self, text):
        self.lines.append(text)
        if self.mute:
            return ''
        if self.no_password_set:
            return ('\r\nPassword required, but none set\r\n\r\nR1 con0 is now available\r\n'
                    '\r\nPress RETURN to get started.\r\n')
        if self.state == 'setup':
            if not self.greeted:
                self.greeted = True
                return ('\r\n         --- System Configuration Dialog ---\r\n\r\n'
                        'Would you like to enter the initial configuration dialog? [yes/no]: ')
            if text == 'no':
                self.state = 'exec'
                return 'no\r\n\r\nPress RETURN to get started!\r\n\r\n'
            if text == 'yes':                     # would start the wizard: must never happen
                self.state = 'wizard'
                return 'yes\r\n'
            return ("\r\n% Please answer 'yes' or 'no'.\r\n"
                    'Would you like to enter the initial configuration dialog? [yes/no]: ')
        if self.state == 'login':
            if not self.greeted:
                self.greeted = True
                return '\r\n\r\nUser Access Verification\r\n\r\nPassword: '
            echo = text if self.echo_secrets else ''
            if text == self.login_password:
                self.state = 'exec'
                return f'{echo}\r\n{self.prompt}'
            return f'{echo}\r\n% Bad passwords\r\n\r\nPassword: '
        if self.state == 'enable':
            self.state = 'exec'
            echo = text if self.echo_secrets else ''
            if text == self.enable_password:
                self.privileged = True
                return f'{echo}\r\n{self.prompt}'
            return f'{echo}\r\n% Access denied\r\n\r\n{self.prompt}'
        if self.state == 'logged_out':
            return ''
        # exec mode
        out = text + '\r\n'
        if text in ('', 'terminal width 511', 'terminal length 0'):
            return out + self.prompt
        if text == 'show version':
            return out + VERSION + self.prompt
        if text == 'enable':
            self.state = 'enable'
            return out + 'Password: '
        if text == 'exit':
            self.state = 'logged_out'
            return out + '\r\nR1 con0 is now available\r\n\r\nPress RETURN to get started.\r\n'
        return out + "% Invalid input detected at '^' marker.\r\n\r\n" + self.prompt


class FakeSerial(serial.Serial):
    """Stands in for a real port: nothing is opened. isinstance(x, serial.Serial) holds,
    as Netmiko's disconnect() checks."""
    device = None                 # the Device answering, set by the fixture
    instances = []
    open_error = None             # an exception to raise when "opening" the port
    block = False                 # True: the device never answers and reads hang
    on_open = ''                  # output already there when the port opens (listen sees it)

    def __init__(self, **settings):                       # no super(): never touch the OS
        if FakeSerial.open_error is not None:
            raise FakeSerial.open_error
        self.settings = settings
        self.is_open = True
        self._out = bytearray(FakeSerial.on_open.encode('latin-1'))
        self._buffer = ''
        self._closed = threading.Event()
        self.close_calls = 0
        FakeSerial.instances.append(self)

    @property
    def in_waiting(self):
        if FakeSerial.block:
            self._closed.wait(10)                          # hangs until the port is closed
        if not self.is_open:
            raise serial.SerialException('port is closed')
        return len(self._out)

    def read(self, size=1):
        data, self._out = bytes(self._out[:size]), self._out[size:]
        return data

    def write(self, data):
        if not self.is_open:
            raise serial.SerialException('port is closed')
        self._buffer += data.decode('utf-8', 'replace')
        while True:
            cut = [i for i in (self._buffer.find('\r'), self._buffer.find('\n')) if i >= 0]
            if not cut:
                break
            i = min(cut)
            text, self._buffer = self._buffer[:i], self._buffer[i + 1:].lstrip('\n')
            if not FakeSerial.block:
                self._out += self.device.line(text).encode()
        return len(data)

    def flush(self):
        pass

    def close(self):
        self.close_calls += 1
        self.is_open = False
        self._closed.set()

    def __del__(self):
        pass


@pytest.fixture
def port(monkeypatch):
    """COM4 exists in the port list and serial.Serial is the fake."""
    FakeSerial.instances = []
    FakeSerial.open_error = None
    FakeSerial.block = False
    FakeSerial.on_open = ''
    FakeSerial.device = Device()
    monkeypatch.setattr(serial, 'Serial', FakeSerial)
    monkeypatch.setattr(list_ports, 'comports',
                        lambda: [SimpleNamespace(device='COM4', description='USB Serial Port',
                                                 hwid='USB VID:PID=067B:2303')])
    monkeypatch.setattr('sys.platform', 'win32')
    return FakeSerial


def session(**kwargs):
    lines = []
    kwargs.setdefault('timeout', 15)
    kwargs.setdefault('listen_seconds', 0.1)
    kwargs.setdefault('listen_quiet', 0.05)
    s = ConsoleSession('COM4', log=lambda kind, text: lines.append((kind, text)), **kwargs)
    s.lines = lines
    return s


def everything_shown(s, *extra):
    return ' '.join([repr(s)] + [t for _, t in s.lines] + [str(x) for x in extra])


ALLOWED_LINES = {'', 'terminal width 511', 'terminal length 0', 'show version', 'enable', 'exit',
                 'no', LOGIN_PW, ENABLE_PW}


def assert_only_safe_lines(device):
    sent = set(device.lines)
    assert sent <= ALLOWED_LINES, sent - ALLOWED_LINES
    assert 'yes' not in sent
    assert not any(l.startswith(('conf', 'write', 'copy', 'ip ', 'hostname', 'crypto'))
                   for l in sent)


# ------------------------------------------------------------------ real Netmiko, fake port
def test_connect_show_disconnect(port):
    s = session()
    result = s.connect(confirm_idle=True)
    assert result.prompt == 'R1>' and not result.privileged
    assert result.verification == link.OPERATOR_CONFIRMED
    assert result.port == 'COM4' and result.baudrate == 9600
    assert link.SETUP_DIALOG_NOTICE in result.notices
    assert link.SETUP_DIALOG_ANSWERED not in result.notices
    settings = port.instances[0].settings
    assert settings['port'] == 'COM4' and settings['baudrate'] == 9600
    assert (settings['bytesize'], settings['parity'], settings['stopbits']) == (8, 'N', 1)
    assert s.is_active()
    assert s.find_prompt() == 'R1>'
    out = s.send_show('show version')
    assert 'Version 15.4(3)M2' in out
    s.disconnect()
    assert not s.is_active()
    assert port.instances[0].is_open is False
    assert port.device.lines[-1] == 'exit'                 # logged out of the console line
    assert ('command', 'show version') in s.lines
    assert_only_safe_lines(port.device)


def test_configurable_baud_rate(port):
    s = session(baudrate=115200)
    s.connect(confirm_idle=True)
    assert port.instances[0].settings['baudrate'] == 115200
    s.disconnect()


def test_bad_baud_rate_is_refused_before_anything_opens(port):
    with pytest.raises(ValueError):
        session(baudrate=9601)
    with pytest.raises(ValueError):
        session(baudrate='fast')
    assert port.instances == []


def test_console_password_and_enable(port):
    port.device = Device(login_password=LOGIN_PW)
    s = session(password=LOGIN_PW, enable_password=ENABLE_PW)
    assert s.connect(confirm_idle=True).prompt == 'R1>'
    assert s.enable() == 'R1#'
    assert s.find_prompt() == 'R1#'
    s.disconnect()
    assert_only_safe_lines(port.device)


def test_enable_without_password_sends_nothing(port):
    s = session()
    s.connect(confirm_idle=True)
    sent = len(port.device.lines)
    with pytest.raises(ConsoleError) as err:
        s.enable()
    assert err.value.kind == link.AUTH
    assert 'enable' not in port.device.lines[sent:]
    s.disconnect()


def test_enable_already_privileged(port):
    port.device = Device(privileged=True)
    s = session()
    assert s.connect(confirm_idle=True).privileged
    assert s.enable() == 'R1#'
    assert 'enable' not in port.device.lines
    s.disconnect()


def test_setup_dialog_is_answered_no_only_after_approval(port):
    # phase 5.1.6 (updated deliberately): Netmiko used to answer "no" by itself. Now the
    # dialog stops the login with the port open and nothing answered; "no" is sent only
    # with the approved startup action (and then one Enter at "Press RETURN").
    port.device = Device(setup_dialog=True)
    s = session()
    with pytest.raises(ConsoleError) as err:
        s.connect(confirm_idle=True)
    assert err.value.kind == link.APPROVAL_REQUIRED
    assert port.device.lines == [''] and port.instances[0].is_open    # nothing answered
    result = s.connect(startup_action=link.DECLINE_SETUP_ACTION)
    assert result.prompt == 'R1>' and result.verification == link.STARTUP_ACTION
    assert result.notices[0] == link.SETUP_DIALOG_ANSWERED
    assert port.device.lines[:3] == ['', 'no', '']
    assert 'yes' not in port.device.lines and len(port.instances) == 1   # never reopened
    s.disconnect()
    assert_only_safe_lines(port.device)


def test_passwords_never_shown_even_if_the_device_echoes_them(port):
    port.device = Device(login_password=LOGIN_PW, echo_secrets=True)
    s = session(username='admin', password=LOGIN_PW, enable_password=ENABLE_PW)
    result = s.connect(confirm_idle=True)
    s.enable()
    s.send_show('show version')
    transcript = s._device_output()
    assert LOGIN_PW not in transcript and ENABLE_PW not in transcript
    shown = everything_shown(s, result, result.notices)
    assert LOGIN_PW not in shown and ENABLE_PW not in shown
    s.disconnect()


def test_unknown_port(port):
    s = ConsoleSession('COM9')
    with pytest.raises(ConsoleError) as err:
        s.connect(confirm_idle=True)
    assert err.value.kind == link.PORT_UNAVAILABLE
    assert 'COM9' in str(err.value) and 'available devices' not in str(err.value)
    assert port.instances == []


def test_port_in_use_by_another_program(port):
    port.open_error = serial.SerialException(
        "could not open port 'COM4': PermissionError(13, 'Access is denied.', None, 5)")
    s = session()
    with pytest.raises(ConsoleError) as err:
        s.connect()
    assert err.value.kind == link.PORT_BUSY
    assert 'in use by another program' in str(err.value)
    assert not s.is_active()


def test_port_vanished_before_opening(port):
    port.open_error = serial.SerialException(
        "could not open port 'COM4': FileNotFoundError(2, 'The system cannot find the file "
        "specified.', None, 2)")
    with pytest.raises(ConsoleError) as err:
        session().connect()
    assert err.value.kind == link.PORT_UNAVAILABLE


def test_connection_timeout_closes_the_port(port):
    port.block = True
    s = session(timeout=1)
    started = time.monotonic()
    with pytest.raises(ConsoleError) as err:
        s.connect(confirm_idle=True)
    assert time.monotonic() - started < 6
    assert err.value.kind == link.TIMEOUT
    assert port.instances[0].is_open is False
    assert not s.is_active()


def test_cancel_from_another_thread(port):
    port.block = True
    s = session(timeout=30)
    threading.Timer(0.3, s.cancel).start()
    started = time.monotonic()
    with pytest.raises(ConsoleError) as err:
        s.connect(confirm_idle=True)
    assert err.value.kind == link.CANCELLED
    assert time.monotonic() - started < 6
    assert port.instances[0].is_open is False


def test_connect_twice_is_refused(port):
    s = session()
    s.connect(confirm_idle=True)
    with pytest.raises(ConsoleError):
        s.connect()
    s.disconnect()


def test_disconnect_is_idempotent_and_context_manager_closes(port):
    with session() as s:
        s.connect(confirm_idle=True)
    assert port.instances[0].is_open is False
    s.disconnect()
    s.disconnect()
    session().disconnect()                                   # never connected


def test_use_after_disconnect(port):
    s = session()
    s.connect(confirm_idle=True)
    s.disconnect()
    for call in (s.find_prompt, lambda: s.send_show('show clock'), s.enable):
        with pytest.raises(ConsoleError) as err:
            call()
        assert err.value.kind == link.NOT_CONNECTED


# ------------------------------------------------------------------ read-only commands
@pytest.mark.parametrize('command', [
    'configure terminal', 'conf t', 'write memory', 'copy running-config startup-config',
    'reload', 'enable', 'ip ssh version 2', 'hostname R2', 'show', 'show run\nconf t',
    'show run\rwrite', 'show version\x03', 'show running-config | redirect flash:x.txt',
    'show run | tee flash:a', 'show run | append flash:a', '', None, 'crypto key generate rsa',
])
def test_only_single_show_commands_are_sent(port, command):
    s = session()
    s.connect(confirm_idle=True)
    sent = len(port.device.lines)
    with pytest.raises(ConsoleError) as err:
        s.send_show(command)
    assert err.value.kind == link.REFUSED
    assert port.device.lines[sent:] == []                    # nothing reached the device
    assert s.is_active()                                     # the session is still usable
    s.disconnect()


def test_show_command_accepted_forms():
    assert link.check_show_command('  show ip interface brief ') == 'show ip interface brief'
    assert link.check_show_command('SHOW version') == 'SHOW version'
    assert link.check_show_command('show run | include hostname') == 'show run | include hostname'


# ------------------------------------------------------------------ failures
class FakeConn:
    """A Netmiko connection stand-in, for what happens AFTER NetCommand's own login
    (session preparation, prompts, commands, disconnect). It gets the fake port handed
    over like the real driver. error: raised by the session preparation."""
    made = []
    encoding, RETURN = 'utf-8', '\n'

    def __init__(self, transcript='', error=None, prompt='R1>', command_error=None, **kwargs):
        self.kwargs = kwargs
        self.session_log = kwargs['session_log']
        self.error, self.prompt = error, prompt
        self.command_error = command_error
        self.remote_conn = None
        self.disconnected = 0
        FakeConn.made.append(self)

    def _prepare(self, *a, **k):
        if self.error is not None:
            raise self.error

    set_terminal_width = disable_paging = set_base_prompt = _prepare

    def establish_connection(self):                     # must never be used any more
        raise AssertionError('Netmiko establish_connection / serial_login was called')

    def find_prompt(self):
        return self.prompt

    def send_command(self, command, read_timeout=None):
        if self.command_error is not None:
            raise self.command_error
        return 'output'

    def disconnect(self):
        self.disconnected += 1
        if self.remote_conn is not None:
            self.remote_conn.close()


def fake_session(error=None, prompt='R1>', command_error=None, **kwargs):
    FakeConn.made = []

    def handler(**params):
        return FakeConn('', error, prompt, command_error, **params)
    kwargs.setdefault('timeout', 5)
    kwargs.setdefault('listen_seconds', 0.1)
    kwargs.setdefault('listen_quiet', 0.05)
    lines = []
    s = ConsoleSession('COM4', connect_handler=handler,
                       log=lambda kind, text: lines.append((kind, text)), **kwargs)
    s.lines = lines
    return s


def failure(port, s=None, **connect):
    s = s or session()
    with pytest.raises(ConsoleError) as err:
        s.connect(**(connect or {'confirm_idle': True}))
    assert all(not p.is_open for p in port.instances)          # the port was closed
    assert not s.is_active()
    return err.value, s


def test_handler_gets_serial_settings_and_no_auto_connect(port):
    s = fake_session(password=LOGIN_PW, enable_password=ENABLE_PW, baudrate=19200)
    s.connect(confirm_idle=True)
    params = FakeConn.made[0].kwargs
    assert params['device_type'] == 'cisco_ios_serial' and params['auto_connect'] is False
    assert params['serial_settings'] == {'port': 'COM4', 'baudrate': 19200, 'bytesize': 8,
                                         'parity': 'N', 'stopbits': 1}
    assert params['password'] == LOGIN_PW and params['secret'] == ENABLE_PW
    # the port NetCommand opened and listened on is the one Netmiko got: never reopened
    assert len(port.instances) == 1 and FakeConn.made[0].remote_conn is port.instances[0]
    assert port.instances[0].settings['baudrate'] == 19200
    s.disconnect()
    assert FakeConn.made[0].disconnected == 1


def test_wrong_password(port):
    port.device = Device(login_password=LOGIN_PW)
    err, s = failure(port, session(password='Wr0ng-Password'))
    assert err.kind == link.AUTH and 'refused the console login' in str(err)
    assert LOGIN_PW not in everything_shown(s, err) and 'Wr0ng-Password' not in str(err)


def test_password_asked_but_none_given(port):
    port.device = Device(login_password=LOGIN_PW)
    err, _ = failure(port)
    assert err.kind == link.AUTH and 'Enter the console login' in str(err)


def test_password_required_but_none_set(port):
    port.device = Device(no_password_set=True)
    err, _ = failure(port)
    assert err.kind == link.AUTH and 'has none set' in str(err)


def test_wrong_speed_gives_unreadable_output(port):
    port.on_open = '\x00\x1e\x86\xf8\x80\x00\xfe\x98\x1e\x00\xe6\x86' * 3
    err, _ = failure(port)
    assert err.kind == link.UNREADABLE and 'wrong speed' in str(err)
    assert port.device.lines == []                              # nothing was written


def test_silent_device(port):
    port.device = Device(mute=True)
    err, _ = failure(port, session(timeout=2))
    assert err.kind == link.TIMEOUT and 'No answer on COM4' in str(err)


@pytest.mark.parametrize('transcript', ['\r\nrommon 1 > ', '\r\nswitch: ', '\r\nloader> '])
def test_boot_loader(port, transcript):
    port.on_open = transcript
    err, _ = failure(port)
    assert err.kind == link.UNEXPECTED_PROMPT and 'boot loader' in str(err)
    assert port.device.lines == []


def test_not_a_cisco_prompt_during_login(port):
    port.on_open = '\r\nWelcome to ExampleOS\r\n$ '
    err, _ = failure(port)
    assert err.kind == link.UNEXPECTED_PROMPT and port.device.lines == []


def test_not_a_cisco_prompt_after_login(port):
    err, _ = failure(port, fake_session(prompt='root@box:~$'))
    assert err.kind == link.UNEXPECTED_PROMPT


def test_netmiko_timeout_during_session_preparation(port):
    from netmiko.exceptions import ReadTimeout
    err, _ = failure(port, fake_session(error=ReadTimeout('Pattern not detected: secret')))
    assert err.kind == link.TIMEOUT and 'secret' not in str(err)


def test_cable_unplugged_during_session_preparation(port):
    err, _ = failure(port, fake_session(error=serial.SerialException('ClearCommError failed')))
    assert err.kind == link.PORT_UNAVAILABLE


def test_unknown_error_does_not_leak_its_text(port):
    s = fake_session(error=RuntimeError(f'boom {LOGIN_PW}'), password=LOGIN_PW)
    err, s = failure(port, s)
    assert err.kind == link.OTHER and 'RuntimeError' in str(err)
    assert LOGIN_PW not in everything_shown(s, err)


def test_command_timeout_closes_the_session(port):
    from netmiko.exceptions import ReadTimeout
    s = fake_session(command_error=ReadTimeout('Pattern not detected'))
    s.connect(confirm_idle=True)
    with pytest.raises(ConsoleError) as err:
        s.send_show('show version')
    assert err.value.kind == link.TIMEOUT
    assert not port.instances[0].is_open and not s.is_active()


def test_log_callback_errors_are_ignored(port):
    def bad_log(kind, text):
        raise RuntimeError('log broke')
    s = ConsoleSession('COM4', connect_handler=lambda **p: FakeConn(**p), log=bad_log,
                       timeout=5, listen_seconds=0.1, listen_quiet=0.05)
    s.connect(confirm_idle=True)
    s.disconnect()


def test_repr_hides_passwords():
    s = fake_session(username='admin', password=LOGIN_PW, enable_password=ENABLE_PW)
    assert LOGIN_PW not in repr(s) and ENABLE_PW not in repr(s)
    assert 'COM4' in repr(s)


def test_log_lines_mask_passwords():
    s = fake_session(password=LOGIN_PW)
    s._say('info', f'something with {LOGIN_PW} in it')
    assert LOGIN_PW not in everything_shown(s) and '********' in s.lines[-1][1]


@pytest.mark.parametrize('name', ['COM0', 'LPT1', '', 'COM4; show'])
def test_bad_port_name(name, monkeypatch):
    monkeypatch.setattr('sys.platform', 'win32')
    with pytest.raises(ValueError):
        ConsoleSession(name)


def test_setup_dialog_policy_is_documented():
    # phase 5.1.6 (updated deliberately): "no" only after the operator approves it
    assert '"no" only after you approve it' in link.SETUP_DIALOG_NOTICE
    assert 'never answers "yes"' in link.SETUP_DIALOG_NOTICE
    assert link.NETMIKO_SETUP_DIALOG_NOTICE == link.SETUP_DIALOG_NOTICE
    assert 'answers "no" only when the operator approved it' in link.__doc__
