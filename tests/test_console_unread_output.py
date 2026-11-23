"""Phase 5.1.5, N2: output that arrives while NetCommand is not waiting for a reply is
INSPECTED before anything else is written - by NetCommand's own configuration exchange
and before every Netmiko call that writes an Enter (find_prompt, send_command, enable,
set_base_prompt, the graceful logout). A question, confirmation, password prompt,
boot-loader prompt or unrecognised text stops everything: not one byte is written and
the port is closed.

The REAL ConsoleSession and Netmiko cisco_ios_serial driver run against a fake port
(no COM port is opened) with the mock lab CLI behind it; the fake port counts every byte
written. Offline; synthetic password.
"""
import os
import sys

import pytest
import serial

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path[:0] = [ROOT, os.path.join(ROOT, 'mock-lab'), os.path.dirname(__file__)]

from console import apply as A  # noqa: E402
from console.apply import approvals_needed, apply_plan, confirmation_phrase  # noqa: E402
from console.detect import detect_device  # noqa: E402
from console.link import (UNSAFE_OUTPUT, ConsoleError, ConsoleSession,  # noqa: E402
                          classify_pending)
from console.plan import build_plan, validate_request  # noqa: E402
from console.steps import UNCERTAIN, VERIFIED  # noqa: E402
from mocklab.console import scenario_port  # noqa: E402
from test_console_apply_fixes import PW, CliConsole, TimedSerial  # noqa: E402
from test_console_link import port  # noqa: E402,F401

QUESTION = '\r\nProceed with reload? [confirm]'
UNSAFE = {
    'confirm': '\r\nProceed with reload? [confirm]',
    'yes/no': '\r\n% Do you really want to replace them? [yes/no]: ',
    'question': '\r\nHow many bits in the modulus [512]: ',
    'password': '\r\nPassword: ',
    'boot loader': '\r\nrommon 1 > ',
    'unknown': '\r\nsomething unexpected',
    'logged out': '\r\nR1 con0 is now available\r\n\r\nPress RETURN to get started.\r\n',
}


class CountingSerial(TimedSerial):
    """TimedSerial that counts every write (a rejected case must write nothing)."""
    device = None

    def __init__(self, **settings):
        super().__init__(**settings)
        self.bytes_written = 0

    def write(self, data):
        self.bytes_written += len(data)
        return super().write(data)

    def inject(self, text):
        """Output that 'arrives' now, unread."""
        self._out += text.encode()


@pytest.fixture
def wire(port, monkeypatch):
    monkeypatch.setattr(serial, 'Serial', CountingSerial)
    return CountingSerial


def connect(wire, sim='SIM8', **kw):
    wire.device = CliConsole(sim)
    s = ConsoleSession('COM4', timeout=20, listen_seconds=0.1, listen_quiet=0.05, **kw)
    s.connect(confirm_idle=True)          # an idle fake device: operator-confirmed path
    return s, wire.device, wire.instances[-1]


def refused(err, ser, before):
    assert err.value.kind == UNSAFE_OUTPUT and 'Nothing was sent' in str(err.value)
    assert ser.bytes_written == before                     # not one byte
    assert not ser.is_open or ser.close_calls >= 1


# ================================================================ the classification
@pytest.mark.parametrize('text', [
    '', '\r\n', '   \r\n\r\n',
    '\r\n*Nov 23 10:15:42.123: %LINK-3-UPDOWN: Interface Gi0/1, changed state to up\r\n',
    '\r\n%SYS-5-CONFIG_I: Configured from console by console\r\n',
    'R1#', '\r\nR1>', '[OK]\r\nR1(config)#',
    '\r\n%SSH-5-ENABLED: SSH 2.0 has been enabled\r\nEdge-R1#'])
def test_safe_unread_output(text):
    assert classify_pending(text) == (True, None)


@pytest.mark.parametrize('name', list(UNSAFE))
def test_unsafe_unread_output(name):
    safe, what = classify_pending(UNSAFE[name])
    assert safe is False and what


def test_a_question_hidden_among_log_lines_is_still_unsafe():
    text = ('\r\n*Nov 23 10:15:42.123: %LINK-3-UPDOWN: Interface Gi0/1, changed state to up'
            '\r\nProceed with reload? [confirm]')
    assert classify_pending(text)[0] is False


# ================================================================ before each Netmiko write
@pytest.mark.parametrize('name', list(UNSAFE))
def test_unsafe_output_before_a_show_command_writes_nothing(wire, name):
    s, dev, ser = connect(wire)
    ser.inject(UNSAFE[name])
    before = ser.bytes_written
    with pytest.raises(ConsoleError) as err:
        s.send_show('show version')
    refused(err, ser, before)
    assert not s.is_active()


def test_question_before_find_prompt_writes_nothing(wire):
    s, dev, ser = connect(wire)
    ser.inject(QUESTION)
    before = ser.bytes_written
    with pytest.raises(ConsoleError) as err:
        s.find_prompt()
    refused(err, ser, before)


def test_question_before_enable_writes_nothing(wire):
    s, dev, ser = connect(wire, scenario_port('enable-no-password'),
                          enable_without_password=True)
    ser.inject(UNSAFE['yes/no'])
    before, lines = ser.bytes_written, len(dev.lines)
    with pytest.raises(ConsoleError) as err:
        s.enable()
    refused(err, ser, before)
    assert dev.lines[lines:] == [] and 'enable' not in dev.lines


def test_question_before_end_writes_nothing(wire):
    s, dev, ser = connect(wire)
    s.allow_config(['ip domain-name lab.local'])
    assert s.enter_config().prompt == 'Router(config)#'
    s.send_config_line('ip domain-name lab.local')
    ser.inject(QUESTION)
    before = ser.bytes_written
    with pytest.raises(ConsoleError) as err:
        s.end_config()
    refused(err, ser, before)
    assert dev.lines[-1] == 'ip domain-name lab.local'     # "end" was never written


def test_question_before_set_base_prompt_writes_nothing(wire, monkeypatch):
    s, dev, ser = connect(wire)
    s.allow_config(['ip domain-name lab.local'])
    s.enter_config()
    s.send_config_line('ip domain-name lab.local')
    real = ConsoleSession._exchange

    def exchange_then_question(self, text, seconds):
        reply = real(self, text, seconds)
        if text == 'end':
            ser.inject(QUESTION)                           # after "end", before Netmiko's Enter
        return reply
    monkeypatch.setattr(ConsoleSession, '_exchange', exchange_then_question)
    with pytest.raises(ConsoleError) as err:
        s.end_config()
    after_end = ser.bytes_written
    assert err.value.kind == UNSAFE_OUTPUT
    assert dev.lines[-1] == 'end'                          # set_base_prompt wrote nothing
    assert ser.bytes_written == after_end and not s.is_active()


def test_question_before_a_configuration_line_writes_nothing(wire):
    s, dev, ser = connect(wire)
    s.allow_config(['ip domain-name lab.local'])
    s.enter_config()
    ser.inject(UNSAFE['question'])
    before = ser.bytes_written
    with pytest.raises(ConsoleError) as err:
        s.send_config_line('ip domain-name lab.local')
    refused(err, ser, before)


def test_safe_unread_output_changes_nothing(wire):
    s, dev, ser = connect(wire)
    ser.inject('\r\n*Nov 23 10:15:42.123: %LINK-3-UPDOWN: Interface Gi0/1, changed state to up'
               '\r\nRouter#')
    assert 'NetCommand Mock Lab' in s.send_show('show version')
    assert s.is_active()
    s.disconnect()


# ================================================================ the graceful logout
def test_graceful_disconnect_is_skipped_when_a_question_waits(wire):
    s, dev, ser = connect(wire)
    ser.inject(QUESTION)
    before = ser.bytes_written
    s.disconnect()
    assert ser.bytes_written == before and 'exit' not in dev.lines
    assert not s.is_active()


def test_graceful_disconnect_still_logs_out_normally(wire):
    s, dev, ser = connect(wire)
    s.disconnect()
    assert 'exit' in dev.lines                              # unchanged when nothing waits


# ================================================================ during an Apply
def prepared(wire, hostname='Edge-R1', domain='lab.local'):
    s, dev, ser = connect(wire)
    r = detect_device(s)
    req, errors = validate_request(hostname, domain, 'netadmin', PW, PW, 2048, r)
    assert not errors
    return s, dev, ser, r, req, build_plan(r, req)


def run(s, r, req, plan, **kw):
    return apply_plan(s, plan, r, req, password=PW, confirm=PW,
                      confirmation=confirmation_phrase(plan),
                      approvals={x.step_id for x in approvals_needed(plan)}, **kw)


def test_log_lines_arriving_between_steps_are_harmless(wire):
    s, dev, ser, r, req, plan = prepared(wire)

    def progress(step_id, status, text):
        if status == 'running' and step_id in ('domain', 'rsa'):
            ser.inject('\r\n%SYS-5-CONFIG_I: Configured from console by console\r\n')
    res = run(s, r, req, plan, progress=progress)
    assert res.outcome == A.SUCCESS, [(x.step_id, x.reasons) for x in res.steps]
    s.disconnect()


def test_a_question_arriving_between_steps_stops_before_any_byte(wire):
    s, dev, ser, r, req, plan = prepared(wire)
    seen = {}

    def progress(step_id, status, text):
        if (step_id, status) == ('rsa', 'running'):
            ser.inject(UNSAFE['yes/no'])
            seen['bytes'], seen['lines'] = ser.bytes_written, len(dev.lines)
    res = run(s, r, req, plan, progress=progress)
    st = {x.step_id: x.status for x in res.steps}
    assert st['rsa'] == UNCERTAIN and st['domain'] == VERIFIED
    assert ser.bytes_written == seen['bytes'] and len(dev.lines) == seen['lines']
    assert st['ssh_version'] == A.BLOCKED and st['ssh_ready'] == A.BLOCKED
    assert any('question or another prompt' in x for x in res.recovery)
    assert not s.is_active() and res.final_detection is None


def test_a_question_arriving_just_before_end_stops_before_end(wire, monkeypatch):
    s, dev, ser, r, req, plan = prepared(wire)
    real_end = ConsoleSession.end_config

    def end_with_question_first(self, timeout=None):
        if dev.lines and dev.lines[-1] == 'ip domain-name lab.local':
            ser.inject(QUESTION)                            # delayed output, just before end
        return real_end(self, timeout)
    monkeypatch.setattr(ConsoleSession, 'end_config', end_with_question_first)
    res = run(s, r, req, plan)
    rec = res.step('domain')
    assert rec.status == UNCERTAIN and rec.status != VERIFIED
    assert dev.lines[-1] == 'ip domain-name lab.local'     # "end" never written
    assert not s.is_active()


def test_unread_output_never_shows_up_in_the_result(wire):
    s, dev, ser, r, req, plan = prepared(wire)

    def progress(step_id, status, text):
        if (step_id, status) == ('domain', 'running'):
            ser.inject('\r\nSECRET-LOOKING-MARKER and then? [confirm]')
    res = run(s, r, req, plan, progress=progress)
    text = repr(res) + ' '.join(res.recovery)
    assert 'SECRET-LOOKING-MARKER' not in text and PW not in text
