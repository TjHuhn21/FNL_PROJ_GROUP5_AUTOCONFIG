"""The Initial Setup page (gui/setup_tab.py). Offline: no real COM port is listed or opened
(tests/conftest.py blocks both). The page's background work runs on real worker threads
(gui.background.run_async); the tests pump the Tk loop until it is done.

Backends used here:
  * FakeBackend / FakeSession: scripted ports and sessions (errors, timing, threads)
  * RealConsoleBackend with fake pyserial port listings (port discovery)
  * mocklab.console.MockConsoleBackend: the simulated mock-lab devices (--mock-console)
"""
import os
import sys
import threading
import time
from types import SimpleNamespace

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
sys.path.insert(0, os.path.join(ROOT, 'mock-lab'))
sys.path.insert(0, os.path.dirname(__file__))

tk = pytest.importorskip('tkinter')

import db_fake  # noqa: E402
from console import link  # noqa: E402
from console.detect import DETECTION_COMMANDS, SshCapability  # noqa: E402
from console.link import ConsoleError, ConnectResult, check_show_command  # noqa: E402
from console.ports import ComPort, PortScan  # noqa: E402
from desktop_auth.session import Access  # noqa: E402
from gui import setup_tab, theme  # noqa: E402
from gui.setup_tab import (CONNECTED, DETECTED, DETECTING, DISCONNECTED, ERROR,  # noqa: E402
                           SIMULATED_BANNER, RealConsoleBackend, SetupTab)
from gui_helpers import new_root, pump  # noqa: E402
from mocklab.console import MockConsoleBackend, SCENARIOS  # noqa: E402

PASSWORD, ENABLE = 'Console-Pa55!', 'En4ble-Pa55!'
INVALID = "% Invalid input detected at '^' marker."
VERSION = ('Cisco IOS Software, C1900 Software (C1900-UNIVERSALK9-M), Version 15.4(3)M2\n'
           'R1 uptime is 1 hour\nSystem image file is "flash0:c1900-universalk9-mz.SPA.154-3.M2'
           '.bin"\nCisco CISCO1941/K9 (revision 1.0) with 491520K/32768K bytes of memory.\n')
ANSWERS = {
    'show version': VERSION,
    'show privilege': 'Current privilege level is 15',
    'show running-config | include hostname': 'hostname R1',
    'show ip ssh': 'SSH Enabled - version 2.0',
    'show crypto key mypubkey rsa': 'Key name: R1.lab.local\n Usage: General Purpose Key',
    'show running-config | include username': 'username admin privilege 15 secret 9 $9$x$y',
    'show running-config | section line vty': 'line vty 0 4\n login local\n transport input ssh',
    'show line': '*     0    0 CTY  -\n      2    2 VTY  -\n      3    3 VTY  -',
    'show ip interface brief': (
        'Interface              IP-Address      OK? Method Status                Protocol\n'
        'GigabitEthernet0/0     192.168.10.1    YES manual up                    up\n'
        'GigabitEthernet0/1     unassigned      YES unset  administratively down down'),
}


# ------------------------------------------------------------------ fakes
class FakeSession:
    """Scripted console session. Records which thread ran each serial call."""

    def __init__(self, port, baudrate, username='', password='', enable_password='',
                 connect_error=None, answers=None, prompt='R1#', hold=None,
                 disconnect_error=None):
        self.port, self.baudrate = port, baudrate
        self.username, self.password, self.enable_password = username, password, enable_password
        self.connect_error, self.answers = connect_error, dict(answers or ANSWERS)
        self.prompt, self.hold = prompt, hold               # hold: an Event the calls wait for
        self.disconnect_error = disconnect_error
        self.connected, self.cancelled = False, False
        self.calls, self.sent = [], []
        self.disconnects = 0

    def _record(self, name):
        self.calls.append((name, threading.current_thread() is threading.main_thread()))
        if self.hold is not None:
            self.hold.wait(10)
        if self.cancelled and name not in ('disconnect',):
            raise ConsoleError(link.CANCELLED, 'Cancelled. The serial port was closed.')

    def listen(self):
        """Phase 5.1.6: what the console showed before anything was sent. This fake
        shows its prompt (a normal, verified state) unless a test sets self.preflight."""
        self._record('listen')
        return getattr(self, 'preflight', None) or link.Preflight(link.CONSOLE_PROMPT,
                                                                   self.prompt)

    def connect(self, confirm_idle=False, startup_action=None):
        self._record('connect')
        if self.connect_error is not None:
            raise self.connect_error
        self.connected = True
        return ConnectResult(self.port, self.baudrate, self.prompt,
                             [link.SETUP_DIALOG_NOTICE])

    def is_active(self):
        return self.connected and not self.cancelled

    def find_prompt(self):
        self._record('find_prompt')
        return self.prompt

    def enable(self):
        self._record('enable')
        self.sent.append('enable')
        self.prompt = self.prompt[:-1] + '#'
        return self.prompt

    def send_show(self, command, timeout=None):
        check_show_command(command)
        self._record('send_show')
        if not self.connected:
            raise ConsoleError(link.NOT_CONNECTED, 'Not connected.')
        self.sent.append(command)
        answer = self.answers.get(command, INVALID)
        if isinstance(answer, Exception):
            self.connected = False
            raise answer
        return answer

    def cancel(self):
        self.cancelled = True
        if self.hold is not None:
            self.hold.set()

    def disconnect(self):
        self._record('disconnect')
        self.disconnects += 1
        self.connected = False
        if self.disconnect_error is not None:
            raise self.disconnect_error


class FakeBackend:
    simulated, mode_note = False, None

    def __init__(self, ports=('COM4',), scan_error=None, **session_options):
        self.ports = [ComPort(p, 'USB Serial Port', 'USB VID:PID=067B:2303', confidence='possible',
                              reason='Prolific USB-to-serial adapter; often a console cable, '
                                     'but it could be another serial device') for p in ports]
        self.scan_error, self.options = scan_error, session_options
        self.sessions, self.scans = [], 0
        self.scan_threads = []

    def discover_ports(self):
        self.scans += 1
        self.scan_threads.append(threading.current_thread() is threading.main_thread())
        if self.scan_error:
            raise self.scan_error
        return PortScan(ports=tuple(self.ports))

    def open_session(self, port, baudrate, username, password, enable_password, log=None,
                     **extra):
        s = FakeSession(port, baudrate, username, password, enable_password, **self.options)
        s.open_extra = extra                       # e.g. enable_without_password (B1)
        self.sessions.append(s)
        return s


@pytest.fixture
def root():
    r = new_root()
    r.geometry('1200x900')
    errors = []
    r.report_callback_exception = lambda *exc: errors.append(exc)
    r.errors = errors
    from gui import theme as th
    th.apply(r)
    yield r
    try:
        r.destroy()
    except tk.TclError:
        pass
    assert not errors, errors


def make(root, backend=None, **options):
    lines = []
    tab = SetupTab(root, log=lambda source, text, level='info': lines.append((source, text, level)),
                   backend=backend or FakeBackend(**options))
    tab.pack(fill='both', expand=True)
    tab.logged = lines
    root.update()
    return tab


def settle(root, tab, phase=None):
    """Pump until the page is idle (or in `phase`)."""
    ok = pump(root, (lambda: tab.phase == phase) if phase else (lambda: not tab.busy), 10)
    root.update()
    assert ok, f'still {tab.phase}'


def ports_ready(root, tab):
    tab.refresh_ports()
    settle(root, tab)


def connected(root, tab, port_index=0):
    ports_ready(root, tab)
    tab.port_var.set(tab.ports[port_index].label())
    tab._show_port_hint()
    tab.connect()
    settle(root, tab)
    return tab


def detected(root, tab, **kw):
    connected(root, tab, **kw)
    tab.detect()
    settle(root, tab)
    return tab


def disabled(widget):
    return widget.instate(['disabled'])


def texts(widget):
    """All label texts under a widget."""
    out = []
    for child in widget.winfo_children():
        try:
            out.append(str(child.cget('text')))
        except tk.TclError:
            pass
        out += texts(child)
    return out


def shown(tab):
    return '\n'.join(texts(tab.results))


# ------------------------------------------------------------------ navigation and roles
def build(root, access=None, backend=None):
    db_fake.reset()
    from gui.main_window import build_main_window
    refs = build_main_window(root, db_fake, demo_store=True, access=access,
                             console_backend=backend or FakeBackend())
    root.update()
    return refs


def test_setup_page_is_on_the_rail_and_opens(root):
    refs = build(root)
    assert refs['nav'].items['setup'].label_text == 'Setup'
    refs['show_page']('setup')
    root.update()
    assert refs['current_page']() == 'setup' and refs['setup'].winfo_ismapped()
    assert 'Initial Setup' in texts(refs['setup'].page)
    settle(root, refs['setup'])
    assert refs['setup'].ports and refs['setup'].backend.scans == 1   # listed when first shown
    refs['show_page']('devices')
    assert refs['current_page']() == 'devices'                       # other pages still work


@pytest.mark.parametrize('role, allowed', [('viewer', False), ('operator', True),
                                           ('admin', True)])
def test_setup_page_permissions(root, role, allowed):
    refs = build(root, access=Access(role))
    assert ('setup' in refs['pages']) is allowed
    assert ('setup' in refs) is allowed                               # not even built for viewers
    refs['show_page']('setup')
    assert (refs['current_page']() == 'setup') is allowed
    if not allowed:
        assert 'configure' not in refs['pages'] and 'scan' not in refs['pages']


def test_demo_access_can_use_setup(root):
    refs = build(root, access=Access(None, demo=True))
    assert 'setup' in refs['pages']


def test_real_backend_is_the_default(root):
    tab = SetupTab(root)
    assert isinstance(tab.backend, RealConsoleBackend) and tab.mode_banner is None


# ------------------------------------------------------------------ port discovery
def fake_listing(monkeypatch, *entries, error=None):
    import serial.tools.list_ports as lp

    def listing():
        if error:
            raise error
        return [SimpleNamespace(device=d, description=desc, hwid=hwid, vid=vid, pid=None,
                                manufacturer=None) for d, desc, hwid, vid in entries]
    monkeypatch.setattr(lp, 'comports', listing)


def test_ports_appear_sorted_with_hints(root, monkeypatch):
    fake_listing(monkeypatch, ('COM10', 'USB Serial Port', 'USB VID:PID=067B:2303', 0x067B),
                 ('COM3', 'Cisco Serial', 'USB VID:PID=05A6:0001', 0x05A6),
                 ('COM2', 'Communications Port', 'ACPI\\PNP0501\\1', None))
    tab = make(root, backend=RealConsoleBackend())
    ports_ready(root, tab)
    assert [p.device for p in tab.ports] == ['COM2', 'COM3', 'COM10']
    assert list(tab.port_box.cget('values'))[2].startswith('COM10 - USB Serial Port')
    assert tab._selected_port().device == 'COM3'                   # the one likely console port
    assert 'Looks like a console port' in tab.port_hint.cget('text')
    tab.port_var.set(tab.ports[2].label())
    tab._show_port_hint()
    hint = tab.port_hint.cget('text')
    assert 'could be another serial device' in hint and 'Possibly a console cable' in hint
    assert 'USB VID:PID=067B:2303' in hint
    assert '3 serial ports found' in tab.message.cget('text')


def test_refresh_updates_the_list_and_never_opens_a_port(root, monkeypatch):
    fake_listing(monkeypatch, ('COM4', 'USB Serial Port', 'x', 0x067B))
    tab = make(root, backend=RealConsoleBackend())
    ports_ready(root, tab)
    fake_listing(monkeypatch, ('COM4', 'USB Serial Port', 'x', 0x067B),
                 ('COM7', 'USB Serial Port', 'y', 0x0403))
    ports_ready(root, tab)
    assert [p.device for p in tab.ports] == ['COM4', 'COM7']
    # conftest's NoRealPort would have failed the test if anything had opened a port


def test_no_ports(root):
    tab = make(root, ports=())
    ports_ready(root, tab)
    assert tab.ports == [] and setup_tab.NO_PORTS == tab.message.cget('text')
    assert disabled(tab.connect_btn)


def test_enumeration_error_from_the_operating_system(root, monkeypatch):
    fake_listing(monkeypatch, error=OSError('SetupDiGetClassDevs failed'))
    tab = make(root, backend=RealConsoleBackend())
    ports_ready(root, tab)
    assert 'could not be read' in tab.message.cget('text')
    assert 'SetupDi' not in tab.message.cget('text')


def test_enumeration_error_from_the_backend(root):
    tab = make(root, scan_error=RuntimeError('raw driver text'))
    ports_ready(root, tab)
    assert 'could not be read' in tab.message.cget('text')
    assert 'raw driver text' not in tab.message.cget('text')


def test_selected_port_disappears(root):
    backend = FakeBackend(ports=('COM4', 'COM5'))
    tab = make(root, backend=backend)
    ports_ready(root, tab)
    tab.port_var.set(tab.ports[1].label())
    backend.ports = backend.ports[:1]
    ports_ready(root, tab)
    assert 'COM5 is no longer listed' in tab.message.cget('text')


def test_port_discovery_runs_off_the_main_thread(root):
    tab = make(root)
    ports_ready(root, tab)
    assert tab.backend.scan_threads == [False]


# ------------------------------------------------------------------ connection
def test_controls_follow_the_state(root):
    tab = make(root)
    assert tab.phase == DISCONNECTED
    assert disabled(tab.detect_btn) and disabled(tab.disconnect_btn) and disabled(tab.connect_btn)
    ports_ready(root, tab)
    assert not disabled(tab.connect_btn)
    connected(root, tab)
    assert tab.phase == CONNECTED
    assert disabled(tab.connect_btn) and disabled(tab.refresh_btn) and disabled(tab.port_box)
    assert not disabled(tab.detect_btn) and not disabled(tab.disconnect_btn)
    assert 'Connected: R1# (privileged mode)' in tab.status_label.cget('text')
    assert 'COM4, 9600 baud' in tab.status_label.cget('text')


def test_successful_connection_uses_the_chosen_speed(root):
    tab = make(root)
    ports_ready(root, tab)
    tab.baud_var.set('19200')
    tab.connect()
    settle(root, tab)
    session = tab.backend.sessions[0]
    assert (session.port, session.baudrate) == ('COM4', 19200)
    assert 'on COM4 at 19200 baud' in tab.message.cget('text')
    # phase 5.1.6: listen (nothing written) comes first, then connect; both off the Tk thread
    assert session.calls[:2] == [('listen', False), ('connect', False)]


@pytest.mark.parametrize('kind, text', [
    (link.PORT_BUSY, 'COM4 is in use by another program (for example PuTTY or Tera Term).'),
    (link.PORT_UNAVAILABLE, 'COM4 is not available. Check that the cable is plugged in.'),
    (link.AUTH, 'The device refused the console login (wrong username or password).'),
    (link.UNREADABLE, 'The output on COM4 is unreadable at 9600 baud.'),
    (link.TIMEOUT, 'No usable answer on COM4 within 45 seconds.'),
    (link.UNEXPECTED_PROMPT, 'The device is in its boot loader (ROMMON / switch:).'),
])
def test_connection_failures_are_explained(root, kind, text):
    tab = make(root, connect_error=ConsoleError(kind, text))
    connected(root, tab)
    assert tab.phase == ERROR and tab.session is None
    assert tab.message.cget('text') == text
    assert not disabled(tab.connect_btn) and disabled(tab.detect_btn)
    assert any(level == 'error' and text in m for _s, m, level in tab.logged)


def test_raw_driver_exceptions_are_not_shown(root):
    tab = make(root, connect_error=RuntimeError('Traceback: driver internals 0xC0000022'))
    connected(root, tab)
    assert 'driver internals' not in tab.message.cget('text')
    assert 'RuntimeError' in tab.message.cget('text')


def test_busy_port_through_the_real_console_session(root, monkeypatch):
    import serial
    fake_listing(monkeypatch, ('COM4', 'USB Serial Port', 'x', 0x067B))

    class Busy(serial.Serial.__mro__[1]):                 # the real class under conftest's guard
        def __init__(self, **settings):
            raise serial.SerialException("could not open port 'COM4': PermissionError(13, "
                                         "'Access is denied.', None, 5)")
    monkeypatch.setattr(serial, 'Serial', Busy)
    tab = make(root, backend=RealConsoleBackend())
    connected(root, tab)
    assert tab.phase == ERROR and 'in use by another program' in tab.message.cget('text')


def test_duplicate_connection_attempts_are_ignored(root):
    hold = threading.Event()
    tab = make(root, hold=hold)
    ports_ready(root, tab)
    tab.connect()
    tab.connect()
    tab.connect()
    hold.set()
    settle(root, tab)
    assert len(tab.backend.sessions) == 1 and tab.phase == CONNECTED
    tab.connect()                                                  # already connected
    root.update()
    assert len(tab.backend.sessions) == 1


def test_cancel_while_connecting(root):
    hold = threading.Event()
    tab = make(root, hold=hold)
    ports_ready(root, tab)
    tab.connect()
    root.update()
    assert tab.disconnect_btn.cget('text') == 'Cancel' and not disabled(tab.disconnect_btn)
    pump(root, lambda: tab._pending is not None, 5)
    tab.disconnect()
    settle(root, tab)
    assert tab.phase == ERROR and 'Cancelled' in tab.message.cget('text')
    assert tab.session is None


def test_disconnect(root):
    tab = connected(root, make(root))
    session = tab.session
    tab.disconnect()
    settle(root, tab)
    assert tab.phase == DISCONNECTED and tab.session is None
    assert session.disconnects == 1 and ('disconnect', False) in session.calls
    assert 'port is free again' in tab.message.cget('text')
    assert disabled(tab.detect_btn) and not disabled(tab.connect_btn)


def test_disconnect_failure_still_closes_the_port(root):
    tab = connected(root, make(root, disconnect_error=RuntimeError('raw')))
    session = tab.session
    tab.disconnect()
    settle(root, tab)
    assert tab.phase == DISCONNECTED and session.cancelled
    assert 'reported a problem' in tab.message.cget('text') and 'raw' not in \
        tab.message.cget('text')


# ------------------------------------------------------------------ detection
def test_detect_is_disabled_until_connected(root):
    tab = make(root)
    ports_ready(root, tab)
    assert disabled(tab.detect_btn)
    tab.detect()                                                   # e.g. a stray call
    root.update()
    assert tab.phase == DISCONNECTED and tab.result is None


def test_detection_shows_device_information(root):
    tab = detected(root, make(root))
    assert tab.phase == DETECTED
    device = {k: v.cget('text') for k, v in tab.result_widgets['device'].items()}
    assert device == {'Hostname': 'R1', 'Device type': 'Router', 'Manufacturer': 'Cisco',
                      'Model': 'CISCO1941/K9', 'Software': 'IOS',
                      'Software version': '15.4(3)M2',
                      'Image file': 'c1900-universalk9-mz.SPA.154-3.M2.bin',
                      'Platform': 'C1900', 'Privilege level': '15'}
    ssh = {k: v.cget('text') for k, v in tab.result_widgets['ssh'].items()}
    assert ssh['SSH version'] == '2.0' and ssh['RSA keys'] == 'Present: R1.lab.local'
    assert ssh['VTY lines configured'] == 'vty 0 4' and ssh['SSH allowed on VTY lines'] == 'Yes'
    assert ssh['Login required on VTY lines'] == 'Yes' and ssh['VTY lines on the device'] == '2'
    assert ssh['Local accounts'] == 'admin'
    tree = tab.result_widgets['interfaces']
    rows = [tree.item(i, 'values') for i in tree.get_children()]
    assert rows[0] == ('GigabitEthernet0/0', '192.168.10.1', 'up', 'up',
                       'likely management interface')
    assert rows[1][:4] == ('GigabitEthernet0/1', 'none', 'administratively down', 'down')
    assert 'Likely management interface: GigabitEthernet0/0' in \
        tab.result_widgets['management'].cget('text')
    assert 'simulated' not in tab.result_widgets
    assert 'Live result' in tab.result_widgets['live'].cget('text')


def test_missing_values_say_unknown(root):
    answers = {c: INVALID for c in DETECTION_COMMANDS}
    tab = detected(root, make(root, answers=answers))
    device = {k: v.cget('text') for k, v in tab.result_widgets['device'].items()}
    assert set(device.values()) == {'Unknown', 'R1'}             # the prompt gives the name only
    assert tab.result_widgets['interfaces'] is None
    assert 'Unknown' in tab.result_widgets['ssh_badge'].cget('text')


def test_detection_runs_off_the_main_thread_and_the_gui_stays_responsive(root):
    hold = threading.Event()
    tab = connected(root, make(root))
    session = tab.session
    session.hold = hold
    tab.detect()
    ticks = []
    for _ in range(5):                                           # the Tk loop keeps running
        root.after_idle(lambda: ticks.append(1))
        root.update()
        time.sleep(0.02)
    assert tab.phase == DETECTING and len(ticks) == 5
    assert disabled(tab.detect_btn) and disabled(tab.connect_btn)
    assert tab.disconnect_btn.cget('text') == 'Cancel'
    assert tab.progress_bar.winfo_manager()
    hold.set()
    settle(root, tab)
    assert tab.phase == DETECTED
    assert session.calls and not any(on_main for _n, on_main in session.calls)


def test_duplicate_detection_is_prevented(root):
    hold = threading.Event()
    tab = connected(root, make(root))
    tab.session.hold = hold
    tab.detect()
    tab.detect()
    tab.detect()
    hold.set()
    settle(root, tab)
    assert tab.session.sent.count('show version') == 1


def test_detect_again_replaces_the_result(root):
    tab = detected(root, make(root))
    first = tab.result
    assert not disabled(tab.detect_btn)
    tab.detect()
    settle(root, tab)
    assert tab.result is not first and tab.phase == DETECTED


def test_cancel_during_detection_disconnects(root):
    hold = threading.Event()
    tab = connected(root, make(root))
    session = tab.session
    session.hold = hold
    tab.detect()
    root.update()
    tab.disconnect()                                             # "Cancel"
    settle(root, tab)
    assert tab.phase == DISCONNECTED and tab.session is None and session.cancelled
    assert 'EARLIER RESULT' in tab.result_widgets['live'].cget('text')


def test_device_disconnect_during_detection(root):
    answers = dict(ANSWERS)
    answers['show running-config | section line vty'] = ConsoleError(
        link.PORT_UNAVAILABLE, 'COM4 stopped working (was the cable unplugged?).')
    tab = detected(root, make(root, answers=answers))
    assert tab.phase == ERROR and tab.session is None
    assert 'ended during detection' in tab.message.cget('text')
    assert 'INCOMPLETE' in tab.result_widgets['incomplete'].cget('text')
    assert 'EARLIER RESULT' in tab.result_widgets['live'].cget('text')
    assert tab.result_widgets['device']['Model'].cget('text') == 'CISCO1941/K9'   # kept
    assert not disabled(tab.connect_btn) and disabled(tab.detect_btn)


def test_command_timeout_marks_results_incomplete(root):
    answers = dict(ANSWERS)
    answers['show line'] = ConsoleError(link.TIMEOUT, 'The device on COM4 stopped answering.')
    tab = detected(root, make(root, answers=answers))
    assert 'incomplete' in tab.result_widgets and tab.phase == ERROR


def test_results_after_disconnect_are_marked_historical(root):
    tab = detected(root, make(root))
    tab.disconnect()
    settle(root, tab)
    assert 'not live' in tab.result_widgets['live'].cget('text')
    assert 'Not connected' in tab.status_label.cget('text')
    assert 'COM4' not in tab.status_label.cget('text')


def test_user_mode_detection_explains_missing_privilege(root):
    answers = dict(ANSWERS)
    answers['show privilege'] = 'Current privilege level is 1'
    for c in ('show ip ssh', 'show crypto key mypubkey rsa',
              'show running-config | include hostname', 'show running-config | include username',
              'show running-config | section line vty'):
        answers[c] = INVALID
    tab = detected(root, make(root, answers=answers, prompt='R1>'))
    assert 'enable' not in tab.backend.sessions[0].sent           # elevate=False by default
    assert 'Privilege level 1' in tab.result_widgets['warnings'].cget('text')


def test_privileged_mode_only_when_asked(root):
    tab = make(root, prompt='R1>')
    tab.use_enable.set(1)
    tab._apply_state()
    tab.enable_var.set(ENABLE)
    detected(root, tab)
    session = tab.backend.sessions[0]
    assert session.enable_password == ENABLE and session.sent[0] == 'enable'


def test_privileged_mode_without_an_enable_password_is_a_bare_enable(root):
    # Phase 5.1.2, decision B1 (approved; this test replaced "needs the enable password"):
    # privileged mode with an empty enable password asks the session for a bare `enable`,
    # which never answers a password prompt. With a password typed, nothing changes.
    tab = make(root)
    ports_ready(root, tab)
    assert disabled(tab.enable_entry)                             # only when ticked
    tab.use_enable.set(1)
    tab._apply_state()
    assert not disabled(tab.enable_entry)
    tab.connect()
    pump(root, lambda: tab.backend.sessions)
    session = tab.backend.sessions[0]
    assert session.open_extra == {'enable_without_password': True}
    assert session.enable_password == ''


def test_technical_details_are_separate(root):
    tab = detected(root, make(root))
    body = tab.result_widgets['details']
    assert not body.winfo_manager()                               # hidden until asked
    tab.result_widgets['details_toggle'].invoke()
    assert body.winfo_manager()
    text = body.cget('text')
    assert 'Why this SSH status:' in text and 'show ip ssh: worked' in text


def test_detection_sends_only_read_only_commands(root):
    tab = detected(root, make(root))
    assert set(tab.backend.sessions[0].sent) <= set(DETECTION_COMMANDS)


# ------------------------------------------------------------------ the four SSH states (mock lab)
@pytest.mark.parametrize('port, status, title', [
    ('SIM1', SshCapability.SUPPORTED_ENABLED, 'Supported and enabled'),
    ('SIM2', SshCapability.SUPPORTED_DISABLED, 'Supported, not enabled'),
    ('SIM3', SshCapability.UNSUPPORTED, 'Not supported'),
    ('SIM4', SshCapability.UNKNOWN, 'Unknown'),
])
def test_mock_lab_ssh_states(root, port, status, title):
    backend = MockConsoleBackend(delay=0)
    tab = make(root, backend=backend)
    ports_ready(root, tab)
    tab.port_var.set(next(p.label() for p in tab.ports if p.device == port))
    tab._show_port_hint()
    tab.connect()
    settle(root, tab)
    tab.detect()
    settle(root, tab)
    assert tab.result.ssh.status == status
    badge = tab.result_widgets['ssh_badge'].cget('text')
    assert badge.startswith(title) and status.name in badge
    assert tab.result_widgets['ssh_sentence'].cget('text') == setup_tab.SSH_TEXT[status][3]
    assert tab.result_widgets['simulated'].cget('text') == SIMULATED_BANNER
    assert tab.result_widgets['device']['Manufacturer'].cget('text') == 'None (simulated device)'
    assert 'SIMULATED' in tab.port_hint.cget('text')
    tab.disconnect()
    settle(root, tab)
    assert tab.phase == DISCONNECTED


def test_mock_mode_is_announced_on_the_page(root):
    tab = make(root, backend=MockConsoleBackend(delay=0))
    assert tab.mode_banner is not None and 'MOCK CONSOLE MODE' in tab.mode_banner.cget('text')
    ports_ready(root, tab)
    assert all('SIMULATED' in p.label() for p in tab.ports)
    assert [p.device for p in tab.ports] == list(SCENARIOS)


@pytest.mark.parametrize('port, words', [('SIM5', 'refused the console login'),
                                         ('SIM6', 'No usable answer')])
def test_mock_lab_connection_failures(root, port, words):
    tab = make(root, backend=MockConsoleBackend(delay=0, timeout=0.2))
    ports_ready(root, tab)
    tab.port_var.set(next(p.label() for p in tab.ports if p.device == port))
    tab._show_port_hint()
    tab.connect()
    settle(root, tab)
    if port == 'SIM6':
        # a device that never answers is a SILENT console: Enter is sent (logged), and with
        # no reply the page says what to check
        assert tab.phase == ERROR and 'No response on SIM6' in tab.message.cget('text')
        assert 'CONSOLE port' in tab.message.cget('text')
        return
    assert tab.phase == ERROR and words in tab.message.cget('text')


def test_mock_lab_cable_pulled_during_detection(root):
    tab = make(root, backend=MockConsoleBackend(delay=0))
    ports_ready(root, tab)
    tab.port_var.set(next(p.label() for p in tab.ports if p.device == 'SIM7'))
    tab._show_port_hint()
    tab.connect()
    settle(root, tab)
    tab.detect()
    settle(root, tab)
    assert tab.phase == ERROR and not tab.result.complete
    assert 'simulated' in tab.result_widgets and 'incomplete' in tab.result_widgets


def test_mock_mode_is_only_used_when_asked():
    import main
    assert main.console_backend(['main.py']) is None
    assert main.console_backend(['main.py', '--demo']) is None
    assert isinstance(main.console_backend(['main.py', '--mock-console']), MockConsoleBackend)


# ------------------------------------------------------------------ closing safely
def test_closing_the_page_while_connecting_releases_the_port(root):
    hold = threading.Event()
    backend = FakeBackend(hold=hold)
    tab = make(root, backend=backend)
    ports_ready(root, tab)
    tab.connect()
    pump(root, lambda: backend.sessions, 5)
    tab.destroy()
    root.update()
    hold.set()
    session = backend.sessions[0]
    assert pump(root, lambda: session.cancelled and session.disconnects >= 1, 5)
    for _ in range(10):                                          # late results touch nothing
        root.update()
        time.sleep(0.02)


def test_closing_the_page_while_detecting(root):
    hold = threading.Event()
    tab = connected(root, make(root))
    session = tab.session
    session.hold = hold
    tab.detect()
    root.update()
    tab.destroy()
    hold.set()
    assert pump(root, lambda: session.cancelled and session.disconnects >= 1, 5)
    for _ in range(10):
        root.update()
        time.sleep(0.02)


def test_closing_the_window_closes_the_session(root):
    tab = connected(root, make(root))
    session = tab.session
    root.destroy()
    deadline = time.time() + 5
    while time.time() < deadline and not session.disconnects:
        time.sleep(0.02)
    assert session.cancelled and session.disconnects >= 1


# ------------------------------------------------------------------ credential safety
def test_password_fields_are_masked(root):
    tab = make(root)
    assert tab.entries['Password'].cget('show') == '*'
    assert tab.entries['Enable password'].cget('show') == '*'
    assert tab.entries['Username'].cget('show') == ''


def test_passwords_are_not_kept_logged_or_shown(root):
    tab = make(root, connect_error=ConsoleError(link.AUTH, f'refused {PASSWORD}'))
    ports_ready(root, tab)
    tab.user_var.set('admin')
    tab.password_var.set(PASSWORD)
    tab.use_enable.set(1)
    tab._apply_state()
    tab.enable_var.set(ENABLE)
    tab.connect()
    assert tab.password_var.get() == '' and tab.enable_var.get() == ''   # emptied at once
    settle(root, tab)
    assert tab.backend.sessions[0].password == PASSWORD               # handed to the session only
    message = tab.message.cget('text')
    assert PASSWORD not in message and '********' in message
    everything = repr(tab.logged) + '\n'.join(texts(tab))
    assert PASSWORD not in everything and ENABLE not in everything
    assert not any(PASSWORD in str(v) or ENABLE in str(v) for v in vars(tab).values())


def test_credentials_are_never_saved(root, monkeypatch):
    tab = connected(root, make(root))
    tab.password_var.set(PASSWORD)
    import db_fake as store
    # the page saves a device only in step 7, after a successful SSH test AND the
    # operator's confirmation; here it was given no store at all
    assert tab.store is None
    for name in ('save_login', 'set_device_login', 'upsert_device'):
        if hasattr(store, name):
            monkeypatch.setattr(store, name, lambda *a, **k: pytest.fail('saved something'))
    tab.detect()
    settle(root, tab)
    tab.disconnect()
    settle(root, tab)


def test_describe_error_never_shows_secrets():
    err = ConsoleError(link.OTHER, 'x secret-1 y')
    assert setup_tab.describe_error(err, ('secret-1',)) == 'x ******** y'
    assert setup_tab.describe_error(KeyError('secret-1')) == \
        'The console operation failed (KeyError).'
