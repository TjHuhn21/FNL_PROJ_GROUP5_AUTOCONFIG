"""Phase 5.1.2 with the REAL Netmiko cisco_ios_serial driver: FakeSerial (from
test_console_link) stands in for the COM port, and behind it the mock lab's simulated
IOS CLI answers. Nothing opens a real port or contacts a device. Synthetic password.

Checks the parts only the real ConsoleSession has: its direct serial exchanges, the
password masking before anything leaves them, Netmiko learning the new prompt after a
rename, enable without a password (B1), and questions / password prompts never answered
(D1) - the port is closed with nothing more written.
"""
import logging
import os
import sys

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path[:0] = [ROOT, os.path.join(ROOT, 'mock-lab'), os.path.dirname(__file__)]

from console import apply as A  # noqa: E402
from console.apply import approvals_needed, apply_plan, confirmation_phrase  # noqa: E402
from console.detect import detect_device  # noqa: E402
from console.link import AUTH, ConsoleError, ConsoleSession, mask_text  # noqa: E402
from console.plan import build_plan, validate_request  # noqa: E402
from console.steps import UNCERTAIN, VERIFIED  # noqa: E402
from mocklab.cli import Session, _scramble  # noqa: E402
from mocklab.console import device_spec, scenario_port  # noqa: E402
from mocklab.device import Device  # noqa: E402
from test_console_link import FakeSerial, port  # noqa: E402,F401

PW = 'Synth3tic-Pass!'


class CliConsole:
    """What FakeSerial's device answers: the mock lab CLI, with IOS-like echo (none while
    a password is typed). Its record of received lines is masked (never the password)."""

    def __init__(self, sim_port):
        self.device = Device(device_spec(sim_port))
        self.cli = Session(self.device)
        self.echo = True
        self.lines = []

    def line(self, text):
        self.lines.append(mask_text(text, [PW]))
        if self.cli is None:
            return ''
        reply = self.cli.handle(text)
        echo = text if self.echo else ''
        self.echo = reply.echo_next
        if reply.close:
            self.cli = None
            return echo + '\r\n'
        out = echo + '\r\n'
        if reply.raw:
            return out + reply.output
        if reply.output:
            out += reply.output.replace('\n', '\r\n') + '\r\n'
        return out + self.cli.prompt()


def console(port, sim_port, **kw):
    port.device = CliConsole(sim_port)
    logs = []
    # phase 5.1.6: an idle fake device is silent: the operator-confirmed path
    s = ConsoleSession('COM4', timeout=20, log=lambda kind, text: logs.append((kind, text)),
                       listen_seconds=0.1, listen_quiet=0.05,
                       **kw)
    s.logs = logs
    return s, port.device


def planned(s, hostname='', domain=''):
    r = detect_device(s)
    req, errors = validate_request(hostname, domain, 'netadmin', PW, PW, 2048, r)
    assert not errors
    plan = build_plan(r, req)
    assert plan.available and plan.steps
    return r, req, plan


def go(s, r, req, plan, **kw):
    return apply_plan(s, plan, r, req, password=PW, confirm=PW,
                      confirmation=confirmation_phrase(plan),
                      approvals={x.step_id for x in approvals_needed(plan)}, **kw)


def test_real_driver_applies_and_verifies_a_factory_setup(port, caplog):
    s, dev = console(port, 'SIM8')
    s.connect(confirm_idle=True)
    r, req, plan = planned(s, hostname='Edge-R1', domain='lab.local')
    caplog.set_level(logging.DEBUG)                      # Netmiko's own debug logging too
    res = go(s, r, req, plan)
    assert res.outcome == A.SUCCESS, (res.message, [(x.step_id, x.reasons) for x in res.steps])
    assert {x.status for x in res.steps} == {VERIFIED}
    # Netmiko learnt the new prompt: show commands after the rename worked
    assert res.final_detection.device.hostname == 'Edge-R1'
    assert s.find_prompt() == 'Edge-R1#'
    # the device received the real password; nothing recorded it
    assert f'secret 5 $1$mock${_scramble(PW)}' in ' '.join(dev.device.global_lines)
    assert PW not in caplog.text
    assert PW not in str(s.logs) and PW not in repr(res)
    assert all(PW not in x.reply for x in res.steps)
    assert PW not in s._device_output()
    # nothing saved, no save command ever written
    assert dev.device.saves == 0
    assert not any(l.startswith(('write', 'copy', 'reload')) for l in dev.lines)
    s.disconnect()


def test_real_driver_enable_without_a_password(port):
    s, dev = console(port, scenario_port('enable-no-password'), enable_without_password=True)
    assert s.connect(confirm_idle=True).prompt == 'Router>'
    before = len(dev.lines)
    assert s.enable() == 'Router#'
    assert [l for l in dev.lines[before:] if l] == ['enable']
    s.disconnect()


def test_real_driver_enable_password_prompt_is_never_answered(port):
    s, dev = console(port, scenario_port('enable-password-prompt'), enable_without_password=True)
    s.connect(confirm_idle=True)
    before = len(dev.lines)
    cli = dev.cli
    with pytest.raises(ConsoleError) as err:
        s.enable()
    assert err.value.kind == AUTH and 'did not answer' in str(err.value)
    after = dev.lines[before:]
    assert [l for l in after if l] == ['enable']             # only "enable" ...
    assert after[-1] == 'enable'                             # ... and nothing after the prompt
    assert cli.pending is not None and not s.is_active()
    assert port.instances[-1].close_calls >= 1


def test_real_driver_never_answers_a_question(port):
    s, dev = console(port, 'SIM20')
    s.connect(confirm_idle=True)
    dev.device.rsa_keys = False                              # keys appear after detection
    r, req, plan = planned(s)
    rsa = 'crypto key generate rsa modulus 2048'

    def progress(step_id, status, text):
        if (step_id, status) == ('rsa', 'running'):
            dev.device.rsa_keys = True
    res = go(s, r, req, plan, progress=progress)
    assert res.step('rsa').status == UNCERTAIN
    assert any('replace them' in x and 'NOT answered' in x for x in res.step('rsa').reasons)
    assert dev.lines[-1] == rsa                              # the last line written
    assert dev.cli.pending is not None and not s.is_active()
    assert port.instances[-1].close_calls >= 1
