"""Phase 5.1.6 (N1): connecting without a blind Enter.

NetCommand opens the port itself and only LISTENS first. A normal prompt is verified by
NetCommand; a silent console needs the operator's confirmation; "Press RETURN" and the
setup dialog need an explicitly approved startup action; everything else is refused with
the port closed. The same open port is then handed to Netmiko (never reopened), and the
login is NetCommand's own: Netmiko's establish_connection / serial_login (which write
Enter before reading) are never used.

The REAL ConsoleSession and Netmiko cisco_ios_serial driver run against a fake port that
counts every byte written, records any DTR/RTS change or buffer reset, and refuses to be
opened twice. Offline: no COM port is opened, no device is contacted.
"""
import os
import sys
import threading
import time

import pytest
import serial

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path[:0] = [ROOT, os.path.join(ROOT, 'mock-lab'), os.path.dirname(__file__)]

from console import link  # noqa: E402
from console.detect import detect_device  # noqa: E402
from console.link import (APPROVAL_REQUIRED, CONFIRMATION_REQUIRED, DECLINE_SETUP_ACTION,  # noqa
                          PRESS_RETURN_ACTION, UNEXPECTED_PROMPT, UNREADABLE, UNSAFE_OUTPUT,
                          ConsoleError, ConsoleSession, Preflight, console_state, gate)
from console.plan import build_plan, plan_is_stale  # noqa: E402
from test_console_link import Device, FakeSerial, port  # noqa: E402,F401

BOOT = ('\r\nSystem Bootstrap, Version 15.0(1r)M15, RELEASE SOFTWARE (fc1)\r\n'
        'Readonly ROMMON initialized\r\n\r\nCisco IOS Software, C1900 Software ...\r\n'
        '*Nov 23 10:00:01.000: %SYS-5-RESTART: System restarted --\r\n')
PRESS_RETURN = '\r\nPress RETURN to get started!\r\n'
SETUP = ('\r\n         --- System Configuration Dialog ---\r\n\r\n'
         'Would you like to enter the initial configuration dialog? [yes/no]: ')
REFUSED_STATES = {
    'confirm': ('\r\nProceed with reload? [confirm]', UNSAFE_OUTPUT),
    'yes/no question': ('\r\n% Do you really want to replace them? [yes/no]: ', UNSAFE_OUTPUT),
    'password prompt': ('\r\nPassword: ', UNSAFE_OUTPUT),
    'login prompt': ('\r\nUser Access Verification\r\n\r\nUsername: ', UNSAFE_OUTPUT),
    'unknown question': ('\r\nDo you want to continue? (y/n)', UNEXPECTED_PROMPT),
    'boot loader': ('\r\nrommon 1 > ', UNEXPECTED_PROMPT),
    'switch boot loader': ('\r\nswitch: ', UNEXPECTED_PROMPT),
    'configuration mode': ('\r\nR1(config)#', UNEXPECTED_PROMPT),
    'unknown output': ('\r\nWelcome to ExampleOS\r\n$ ', UNEXPECTED_PROMPT),
    'unreadable': ('\x00\x1e\x86\xf8\x80\x00\xfe\x98\x1e\x00\xe6\x86' * 3, UNREADABLE),
    'boot still printing': (BOOT + 'Decompressing the image : ######', UNEXPECTED_PROMPT),
}


class WatchedSerial(FakeSerial):
    """A fake port that records how it is used. schedule: [(seconds after opening,
    text)], plus VANISH to make it disappear then."""
    schedule = []
    VANISH = object()

    def __init__(self, **settings):
        if any(p.is_open for p in FakeSerial.instances):
            raise AssertionError('the port was opened a second time while still open')
        self.__dict__['signals'] = []                    # dtr / rts / buffer resets
        super().__init__(**settings)
        self.bytes_written = 0
        self.opened_at = time.monotonic()
        self._pending = list(WatchedSerial.schedule)

    def __setattr__(self, name, value):
        if name in ('dtr', 'rts', 'dsrdtr', 'rtscts', 'break_condition'):
            self.signals.append((name, value))
        super().__setattr__(name, value)

    def reset_input_buffer(self):
        self.signals.append(('reset_input_buffer', None))

    def reset_output_buffer(self):
        self.signals.append(('reset_output_buffer', None))

    def write(self, data):
        if self.is_open:
            self.bytes_written += len(data)
        return super().write(data)

    @property
    def in_waiting(self):
        now = time.monotonic() - self.opened_at
        due = [x for x in self._pending if x[0] <= now]
        self._pending = [x for x in self._pending if x[0] > now]
        for _at, text in due:
            if text is WatchedSerial.VANISH:
                self.is_open = False
                raise serial.SerialException('ClearCommError failed (the device was removed)')
            self._out += text.encode('latin-1')
        if not self.is_open:
            raise serial.SerialException('port is closed')
        return len(self._out)


@pytest.fixture
def wire(port, monkeypatch):
    """The watched port, and Netmiko's own blind login made impossible."""
    WatchedSerial.schedule = []
    monkeypatch.setattr(serial, 'Serial', WatchedSerial)
    import netmiko.base_connection as base

    def forbidden(*a, **k):
        raise AssertionError('Netmiko opened the port or logged in by itself')
    monkeypatch.setattr(base.BaseConnection, 'establish_connection', forbidden)
    monkeypatch.setattr(base.BaseConnection, 'serial_login', forbidden)
    monkeypatch.setattr(base.BaseConnection, 'telnet_login', forbidden)
    return port


def session(**kw):
    kw.setdefault('timeout', 10)
    kw.setdefault('listen_seconds', 0.15)
    kw.setdefault('listen_quiet', 0.1)
    return ConsoleSession('COM4', **kw)


def the_port():
    [p] = FakeSerial.instances
    return p


def nothing_written(p):
    assert p.bytes_written == 0
    assert FakeSerial.device.lines == []


# ================================================================ classification
@pytest.mark.parametrize('text, state', [
    ('', link.CONSOLE_SILENT), ('\r\n\r\n', link.CONSOLE_SILENT),
    ('\r\n%LINK-3-UPDOWN: Interface Gi0/1, changed state to up\r\n', link.CONSOLE_SILENT),
    ('\r\nRouter>', link.CONSOLE_PROMPT), ('Router#', link.CONSOLE_PROMPT),
    (BOOT + PRESS_RETURN, link.CONSOLE_PRESS_RETURN),
    ('\r\nR1 con0 is now available\r\n\r\nPress RETURN to get started.\r\n',
     link.CONSOLE_PRESS_RETURN),
    (BOOT + SETUP, link.CONSOLE_SETUP_DIALOG),
    ('\r\nProceed with reload? [confirm]', link.CONSOLE_QUESTION),
    ('\r\nPassword: ', link.CONSOLE_PASSWORD), ('\r\nUsername: ', link.CONSOLE_USERNAME),
    ('\r\nrommon 2 > ', link.CONSOLE_BOOT_LOADER), ('R1(config-if)#', link.CONSOLE_CONFIG_PROMPT),
    ('\r\nsomething else', link.CONSOLE_UNKNOWN)])
def test_console_states(text, state):
    assert console_state(text)[0] == state


def test_only_the_detected_startup_prompt_can_be_approved():
    for state, needs in ((link.CONSOLE_PRESS_RETURN, PRESS_RETURN_ACTION),
                         (link.CONSOLE_SETUP_DIALOG, DECLINE_SETUP_ACTION)):
        pf = Preflight(state)
        assert pf.needs == needs and gate(pf, startup_action=needs) is None
        assert gate(pf, confirm_idle=True).kind == APPROVAL_REQUIRED      # not a substitute
        wrong = DECLINE_SETUP_ACTION if needs == PRESS_RETURN_ACTION else PRESS_RETURN_ACTION
        assert gate(pf, startup_action=wrong).kind == APPROVAL_REQUIRED
    silent = Preflight(link.CONSOLE_SILENT)
    for not_a_tick in (False, None, 1, 'yes', 'True'):
        assert gate(silent, confirm_idle=not_a_tick).kind == CONFIRMATION_REQUIRED
    assert gate(silent, confirm_idle=True) is None
    assert gate(Preflight(link.CONSOLE_PROMPT, 'R1#')) is None


# ================================================================ existing router (Option B)
@pytest.mark.parametrize('privileged, shown', [(False, 'R1>'), (True, 'R1#')])
def test_a_visible_prompt_is_verified_and_no_blind_enter_follows(wire, privileged, shown):
    wire.device = Device(privileged=privileged)
    wire.on_open = f'\r\n{shown}'
    s = session()
    pf = s.listen()
    assert pf.state == link.CONSOLE_PROMPT and pf.prompt == shown and pf.needs is None
    nothing_written(the_port())
    result = s.connect()
    assert result.verification == link.VERIFIED and result.prompt == shown
    # the first thing written after the handover is a session setting, NOT a blind Enter
    assert wire.device.lines[0] == 'terminal width 511'
    assert 'Normal prompt detected by NetCommand' in pf.message
    s.disconnect()


def test_a_silent_console_needs_the_operator_confirmation(wire):
    s = session()
    pf = s.listen()
    assert pf.state == link.CONSOLE_SILENT and pf.needs == 'confirm_idle'
    with pytest.raises(ConsoleError) as err:
        s.connect()                                       # not ticked
    assert err.value.kind == CONFIRMATION_REQUIRED
    assert link.IDLE_CONFIRMATION in str(err.value)
    p = the_port()
    nothing_written(p)
    assert p.is_open and not s.is_active()                # open, waiting, nothing sent
    s.disconnect()                                        # the operator cancels
    assert not p.is_open and p.bytes_written == 0


def test_a_silent_console_with_the_confirmation_sends_exactly_one_enter_first(wire):
    s = session()
    s.listen()
    result = s.connect(confirm_idle=True)
    assert result.verification == link.OPERATOR_CONFIRMED
    assert wire.device.lines[0] == ''                     # the one, confirmed Enter
    assert wire.device.lines[1] == 'terminal width 511'
    s.disconnect()


@pytest.mark.parametrize('name', list(REFUSED_STATES))
def test_unsafe_or_unknown_states_are_refused_without_a_byte(wire, name):
    text, kind = REFUSED_STATES[name]
    wire.on_open = text
    s = session()
    pf = s.listen()
    assert pf.refused and pf.needs is None and 'connection refused' in pf.message
    p = the_port()
    nothing_written(p)
    assert not p.is_open                                  # closed at once
    for kwargs in ({}, {'confirm_idle': True}, {'startup_action': PRESS_RETURN_ACTION},
                   {'startup_action': DECLINE_SETUP_ACTION}):
        FakeSerial.on_open = text
        with pytest.raises(ConsoleError) as err:
            s.connect(**kwargs)
        assert err.value.kind == kind
    assert all(q.bytes_written == 0 for q in FakeSerial.instances)
    assert wire.device.lines == []


def test_output_arriving_while_the_operator_decides_is_checked_before_the_first_byte(wire):
    s = session()
    assert s.listen().state == link.CONSOLE_SILENT
    p = the_port()
    p._out += b'\r\nProceed with reload? [confirm]'          # appears meanwhile, unread
    with pytest.raises(ConsoleError) as err:
        s.connect(confirm_idle=True)
    assert err.value.kind == UNSAFE_OUTPUT
    nothing_written(p)
    assert not p.is_open


def test_a_question_after_a_verified_prompt_is_caught_before_session_setup(wire):
    wire.on_open = '\r\nR1#'
    s = session()
    s.listen()
    p = the_port()
    p._out += b'\r\n% Do you really want to replace them? [yes/no]: '
    with pytest.raises(ConsoleError) as err:
        s.connect()
    assert err.value.kind == UNSAFE_OUTPUT
    nothing_written(p)


def test_serial_disconnect_during_the_preflight(wire):
    WatchedSerial.schedule = [(0.05, '\r\nSystem Boot'), (0.1, WatchedSerial.VANISH)]
    s = session(listen_seconds=1)
    with pytest.raises(ConsoleError) as err:
        s.listen()
    assert err.value.kind == link.PORT_UNAVAILABLE
    p = the_port()
    nothing_written(p)
    assert not p.is_open and not s.is_active()


# ================================================================ fresh boot (Option C)
def test_press_return_needs_the_approved_startup_action(wire):
    wire.on_open = BOOT + PRESS_RETURN
    s = session()
    pf = s.listen()
    assert pf.state == link.CONSOLE_PRESS_RETURN and pf.needs == PRESS_RETURN_ACTION
    for kwargs in ({}, {'confirm_idle': True}, {'startup_action': DECLINE_SETUP_ACTION}):
        with pytest.raises(ConsoleError) as err:
            s.connect(**kwargs)
        assert err.value.kind == APPROVAL_REQUIRED
    nothing_written(the_port())
    result = s.connect(startup_action=PRESS_RETURN_ACTION)
    assert result.verification == link.STARTUP_ACTION and result.prompt == 'R1>'
    assert wire.device.lines[0] == ''                     # the approved Enter, once
    assert len(FakeSerial.instances) == 1                 # never reopened
    s.disconnect()


def test_setup_dialog_is_declined_only_with_approval(wire):
    wire.device = Device(setup_dialog=True)
    wire.device.greeted = True                            # the dialog was printed at boot
    wire.on_open = BOOT + SETUP
    s = session()
    pf = s.listen()
    assert pf.state == link.CONSOLE_SETUP_DIALOG and pf.needs == DECLINE_SETUP_ACTION
    for kwargs in ({}, {'confirm_idle': True}, {'startup_action': PRESS_RETURN_ACTION}):
        with pytest.raises(ConsoleError) as err:
            s.connect(**kwargs)
        assert err.value.kind == APPROVAL_REQUIRED
    nothing_written(the_port())
    result = s.connect(startup_action=DECLINE_SETUP_ACTION)
    assert result.verification == link.STARTUP_ACTION
    assert result.notices[0] == link.SETUP_DIALOG_ANSWERED
    # exactly "no", then the one Enter at the "Press RETURN" that follows; never "yes"
    assert wire.device.lines[:2] == ['no', ''] and 'yes' not in wire.device.lines
    s.disconnect()


def test_delayed_startup_output_is_waited_for(wire):
    WatchedSerial.schedule = [(0.05, BOOT[:60]), (0.25, BOOT[60:]), (0.45, PRESS_RETURN)]
    s = session(listen_seconds=0.1, listen_quiet=0.3, listen_max=5)
    pf = s.listen()
    assert pf.state == link.CONSOLE_PRESS_RETURN           # not "silent", not cut short
    nothing_written(the_port())
    s.disconnect()


def test_output_still_streaming_at_the_limit_is_refused(wire):
    WatchedSerial.schedule = [(0.05 * n, f'loading part {n}\r\n') for n in range(1, 40)]
    s = session(listen_seconds=0.1, listen_quiet=0.3, listen_max=0.6)
    pf = s.listen()
    assert pf.refused and pf.state == link.CONSOLE_UNKNOWN
    nothing_written(the_port())


# ================================================================ serial ownership
def test_one_port_one_owner_no_dtr_rts_changes_no_buffer_reset(wire):
    wire.on_open = '\r\nR1>'
    s = session()
    s.listen()
    s.connect()
    p = the_port()
    assert len(FakeSerial.instances) == 1                 # opened exactly once
    assert s._conn.remote_conn is p                       # Netmiko got the same port
    assert p.settings == {'port': 'COM4', 'baudrate': 9600, 'bytesize': 8, 'parity': 'N',
                          'stopbits': 1, 'timeout': 0}    # no dsrdtr / rtscts handshaking
    assert p.signals == []                                # DTR/RTS and buffers untouched
    s.disconnect()
    assert not p.is_open


def test_an_unlisted_port_is_never_opened(wire):
    s = ConsoleSession('COM9', listen_seconds=0.1)
    with pytest.raises(ConsoleError) as err:
        s.listen()
    assert err.value.kind == link.PORT_UNAVAILABLE and FakeSerial.instances == []


def test_cancel_while_listening_closes_without_writing(wire):
    s = session(listen_seconds=5, listen_max=5)
    threading.Timer(0.2, s.cancel).start()
    with pytest.raises(ConsoleError) as err:
        s.listen()
    assert err.value.kind == link.CANCELLED
    p = the_port()
    nothing_written(p)
    assert not p.is_open


# ================================================================ the plan's detection identity
def test_detections_in_the_same_clock_tick_are_still_different():
    from mocklab.console import MockConsoleBackend
    s = MockConsoleBackend(delay=0).open_session('SIM8', 9600, '', '', '', None)
    s.connect()
    first, second = detect_device(s), detect_device(s)
    second.detected_at = first.detected_at               # same Windows clock tick
    assert first.detection_id and first.detection_id != second.detection_id
    plan = build_plan(first)
    assert plan.detection_id == first.detection_id
    assert plan_is_stale(plan, first, True) is None
    assert plan_is_stale(plan, second, True) == ('The device was detected again after this '
                                                 'preview was made.')
    second.detection_id = first.detection_id             # (the timestamp still counts too)
    second.detected_at = None
    assert plan_is_stale(plan, second, True) is not None
