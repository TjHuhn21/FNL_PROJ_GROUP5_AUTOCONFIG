"""Phase 5.1.3: fixes for the Phase 5.1.2 review findings.

  H1  NetCommand cannot close (X, demo close, Sign out, ended session) during an SSH Apply;
      the current step finishes, no further step starts, the console closes, then it closes.
  M1  clear IOS rejections are FAILED (checked before the prompt); a console not back at a
      verified '#' is closed at once without typing anything; the page cannot Detect then.
  M2  SSH passwords with whitespace or shaped like a stored hash are refused.
  M3  Mock Lab: "no enable password configured" and "unknown enable hash" are separate.
  M4  the REAL ConsoleSession / Netmiko serial driver against a timed fake port: chunks,
      pauses around the 0.3 s settle time, a silent line, a vanishing port, partial output.

Offline only: Mock Lab consoles, FakeSerial (no port is opened), synthetic passwords.
"""
import os
import sys
import threading
import time

import pytest
import serial

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path[:0] = [ROOT, os.path.join(ROOT, 'mock-lab'), os.path.dirname(__file__)]

from console import apply as A  # noqa: E402
from console.apply import approvals_needed, apply_plan, confirmation_phrase  # noqa: E402
from console.detect import detect_device  # noqa: E402
from console.link import (SETTLE, ConsoleError, ConsoleSession, check_secret,  # noqa: E402
                          mask_text)
from console.plan import build_plan, check_password, validate_request  # noqa: E402
from console.steps import FAILED, UNCERTAIN, VERIFIED  # noqa: E402
from gui import apply_guard  # noqa: E402
from mocklab import restore_sim  # noqa: E402
from mocklab.cli import Session, _scramble  # noqa: E402
from mocklab.console import MockConsoleBackend, device_spec, scenario_port  # noqa: E402
from mocklab.device import Device  # noqa: E402
from mocklab.lab import load_config  # noqa: E402
from test_console_link import FakeSerial, port  # noqa: E402,F401

PW = 'Synth3tic-Pass!'
USER_LINE = 'username netadmin privilege 15 secret <SSH_PASSWORD>'
RSA_LINE = 'crypto key generate rsa modulus 2048'


@pytest.fixture(autouse=True)
def clean_apply_guard():
    apply_guard._RUNS.clear()
    yield
    apply_guard._RUNS.clear()


# ================================================================ helpers (Mock Lab)
def mock_prepared(sim='SIM8', hostname='Edge-R1', domain='lab.local', **open_kw):
    s = MockConsoleBackend(delay=0, edge_cases=True).open_session(sim, 9600, '', '', '', None,
                                                                  **open_kw)
    s.connect()
    r = detect_device(s)
    req, errors = validate_request(hostname, domain, 'netadmin', PW, PW, 2048, r)
    assert not errors
    plan = build_plan(r, req)
    assert plan.available and plan.steps
    return s, r, req, plan


def go(s, r, req, plan, **kw):
    args = dict(password=PW, confirm=PW, confirmation=confirmation_phrase(plan),
                approvals={x.step_id for x in approvals_needed(plan)})
    args.update(kw)
    return apply_plan(s, plan, r, req, **args)


def statuses(res):
    return {x.step_id: x.status for x in res.steps}


def shown(res):
    parts = [repr(res), res.message] + res.recovery + res.commands_sent
    for rec in res.steps + res.invariants:
        parts += [rec.reply] + rec.reasons + list(rec.checks.values())
    return '\n'.join(parts)


# ================================================================ M1 (Mock Lab)
def test_m1_rejected_hostname_is_failed_and_leaves_config_cleanly():
    s, r, req, plan = mock_prepared()
    s.console = {'reject_on': 'hostname Edge-R1'}
    res = go(s, r, req, plan)
    st = statuses(res)
    assert st['hostname'] == FAILED                         # not UNCERTAIN
    assert any('rejected the command' in x and 'Invalid input' in x
               for x in res.step('hostname').reasons)
    assert res.step('hostname').commands == ['configure terminal', 'hostname Edge-R1', 'end']
    assert '<Enter>' not in s.config_sent                   # no prompt re-read was needed
    assert s.device.hostname == 'Router' and s.is_active()  # at its verified '#'
    assert not res.console_released
    assert st['domain'] == A.NOT_RUN and st['rsa'] == A.BLOCKED
    assert [i.status for i in res.invariants] == [VERIFIED]  # final checks still ran
    assert res.final_detection is not None and res.outcome == A.FAILURE


def test_m1_rejected_line_vty_is_failed():
    s, r, req, plan = mock_prepared()
    s.console = {'reject_on': 'line vty 0 4'}
    res = go(s, r, req, plan)
    st = statuses(res)
    first_vty = next(x.step_id for x in plan.steps if x.step_id.startswith('vty_login'))
    assert st[first_vty] == FAILED
    assert res.step(first_vty).commands == ['configure terminal', 'line vty 0 4', 'end']
    assert s.is_active() and not res.console_released
    assert all(v == A.BLOCKED for k, v in st.items() if k.startswith('vty_transport'))


def test_m1_rejection_at_an_unexpected_prompt_closes_the_port_without_typing():
    s, r, req, plan = mock_prepared()
    s.console = {'reject_on': 'ip domain-name lab.local'}
    real_send = s.send_config_line

    def send(line, **kw):                               # refused, AND somewhere else now
        if line == 'ip domain-name lab.local':
            s.forced_prompt = 'Edge-R1(config-if)#'
        return real_send(line, **kw)
    s.send_config_line = send
    res = go(s, r, req, plan)
    assert statuses(res)['domain'] == FAILED
    assert 'not where it should be' in ' '.join(res.step('domain').reasons)
    assert s.config_sent[-1] == 'ip domain-name lab.local'  # no end, no Enter after it
    assert res.console_released and not s.is_active() and s.graceful_disconnects == 0
    assert res.recovery[0].startswith('The console was not back at the privileged "#" prompt')
    assert res.final_detection is None and res.invariants == []


def test_m1_unexpected_prompt_is_uncertain_and_closed_without_typing():
    s, r, req, plan = mock_prepared()
    s.console = {'wrong_prompt_on': 'ip domain-name lab.local'}
    res = go(s, r, req, plan)
    assert statuses(res)['domain'] == UNCERTAIN
    assert 'expected "Edge-R1(config)#"' in ' '.join(res.step('domain').reasons)
    # exactly one empty line to re-read the prompt, then nothing at all
    assert s.config_sent[-2:] == ['ip domain-name lab.local', '<Enter>']
    assert res.console_released and not s.is_active() and s.graceful_disconnects == 0
    assert 'end' not in res.step('domain').commands
    assert statuses(res)['rsa'] == A.BLOCKED


def test_m1_a_question_still_closes_without_an_answer():
    s, r, req, plan = mock_prepared('SIM21', hostname='', domain='')
    s.console = {'modulus_question_on': RSA_LINE}
    cli = s.cli
    res = go(s, r, req, plan)
    assert statuses(res)['rsa'] == UNCERTAIN and cli.pending is not None
    assert not s.is_active() and s.graceful_disconnects == 0


def test_m1_success_leaves_the_session_open_at_its_prompt():
    s, r, req, plan = mock_prepared()
    res = go(s, r, req, plan)
    assert res.outcome == A.SUCCESS and s.is_active() and not res.console_released
    assert s.find_prompt() == 'Edge-R1#'


def test_m1_a_programming_error_closes_the_console_too(monkeypatch):
    s, r, req, plan = mock_prepared()
    monkeypatch.setattr(A._Runner, '_one', lambda *a: 1 / 0)
    with pytest.raises(ZeroDivisionError):
        go(s, r, req, plan)
    assert not s.is_active() and s.graceful_disconnects == 0


# ---------------------------------------------------------------- M1 on the page
tk = pytest.importorskip('tkinter')


def page(root, port='SIM8', backend=None):
    from test_setup_preview import fill, ready
    tab = ready(root, port, backend=backend or MockConsoleBackend(delay=0))
    fill(tab, password=PW)
    tab.preview()
    tab.apply_vars['password'].set(PW)
    tab.apply_vars['confirm'].set(PW)
    tab.apply_vars['phrase'].set(confirmation_phrase(tab.plan))
    return tab


def test_m1_page_cannot_detect_after_the_console_was_released(root):
    from test_setup_tab import settle
    from gui.setup_tab import ERROR
    tab = page(root)
    session = tab.session
    session.console = {'wrong_prompt_on': 'ip domain-name lab.local'}
    tab.apply_btn.invoke()
    settle(root, tab)
    assert tab.phase == ERROR and tab.session is None
    assert tab.detect_btn.instate(['disabled']) and tab.redetect_btn.instate(['disabled'])
    assert 'closed without typing anything' in tab.message.cget('text')
    assert not session.is_active() and session.graceful_disconnects == 0
    assert 'resolve it yourself' in tab.apply_recovery.cget('text')


def test_m1_page_closes_the_console_after_an_unexpected_error(root, monkeypatch):
    from test_setup_tab import settle
    from gui.setup_tab import ERROR
    tab = page(root)
    session = tab.session

    def broken(*a, **k):
        raise RuntimeError('simulated bug')
    monkeypatch.setattr(A, 'apply_plan', broken)
    tab.apply_btn.invoke()
    settle(root, tab)
    assert tab.phase == ERROR and not session.is_active()
    assert session.graceful_disconnects == 0
    assert 'stopped unexpectedly' in tab.apply_summary.cget('text')


@pytest.fixture
def root():
    from gui_helpers import new_root
    r = new_root()
    r.geometry('1200x900')
    yield r
    try:
        r.destroy()
    except tk.TclError:
        pass


# ================================================================ M2
@pytest.mark.parametrize('password', [
    'has space1', ' leading1', 'trailing1 ', 'tab\there1', 'line\nbreak1', 'cr\rbreak1',
    'vtab\x0bhere1', 'nbsp\xa0here1', '5 $1$abcdefgh', '7 0822455D0A16', '0 plainpass',
    '9 $9$abcdefghij', '$1$abcdefgh', '$9$abcdefghij', '$14$abcdefgh', '$8$abcdefghij'])
def test_m2_whitespace_and_hash_like_passwords_are_refused(password):
    problem = check_password(password, password)
    assert problem and password not in problem
    with pytest.raises(ConsoleError) as err:
        check_secret(password)
    assert password not in str(err.value)
    _req, errors = validate_request('', '', 'netadmin', password, password, 2048, None)
    assert 'password' in errors and password not in errors['password']


@pytest.mark.parametrize('password', ['Synth3tic-Pass!', '5$1$abcdefgh', 'pass$1$word',
                                      '7x0822455D0A16', 'a' * 25, 'Ab3!Ab3!'])
def test_m2_ordinary_passwords_still_pass(password):
    assert check_password(password, password) is None
    assert check_secret(password) == password


# ---------------------------------------------------------------- the IOS 25-character limit
# Seen on the lab router (CISCO1941, IOS 15.4) during the first physical Apply: a longer
# account secret is refused with exactly this message, and the account step FAILED.
IOS_TOO_LONG = ('% Invalid Password length - must contain 1 to 25 characters. Password '
                'configuration failed')


def test_passwords_over_25_characters_are_refused_before_anything_is_sent():
    assert check_password('a' * 25, 'a' * 25) is None
    problem = check_password('a' * 26, 'a' * 26)
    assert problem and '25' in problem and 'a' * 26 not in problem
    with pytest.raises(ConsoleError):
        check_secret('a' * 26)
    s, r, req, plan = mock_prepared()
    long_pw = 'Synth3tic-Pass!-0123456789'                 # 26 characters
    res = go(s, r, req, plan, password=long_pw, confirm=long_pw)
    assert res.outcome == A.REFUSED and s.config_sent == []
    assert '25' in res.message and long_pw not in shown(res)


def test_the_real_ios_length_message_is_a_rejection():
    s, r, req, plan = mock_prepared()
    user = plan.step('user')
    reply = f'username netadmin privilege 15 secret ********\n{IOS_TOO_LONG}\nEdge-R1(config)#'
    assert any(m in reply for m in user.failure_replies)    # "% Invalid" -> FAILED
    assert user.evaluate({}, reply=reply)[0] == FAILED


def test_m2_a_whitespace_password_sends_nothing():
    s, r, req, plan = mock_prepared()
    before = s.device.running_config()
    bad = 'two words1'
    res = go(s, r, req, plan, password=bad, confirm=bad)
    assert res.outcome == A.REFUSED and s.config_sent == []
    assert s.device.running_config() == before
    assert bad not in shown(res)


# ================================================================ M3
def lab_router():
    spec = {d['name']: d for d in load_config()['devices']}['MOCK-R1']
    return spec, Device(spec)


def test_m3_unknown_enable_hash_refuses_enable_after_a_replay():
    spec, dev = lab_router()
    text = dev.running_config().replace(
        '\nhostname MOCK-R1', '\nenable secret 5 $1$mock$unknownhash\nhostname MOCK-R1')
    state, rejected = restore_sim.load_config_text(dev, text)
    assert rejected == []
    dev.set_config_state(state)
    assert dev.enable_configured and dev.enable_secret is None
    cli = Session(dev)
    assert cli.handle('enable').output == 'Password: '        # still asked
    assert cli.handle(spec['password']).output == '% Access denied'
    assert cli.prompt() == 'MOCK-R1>'


def test_m3_a_known_hash_still_works_after_a_replay():
    spec, dev = lab_router()
    cli = Session(dev)
    cli.handle('enable'); cli.handle(spec['password'])
    cli.handle('configure terminal'); cli.handle('enable secret Synth-Enable-9'); cli.handle('end')
    state, _ = restore_sim.load_config_text(dev, dev.running_config())
    dev.set_config_state(state)
    again = Session(dev)
    again.handle('enable')
    again.handle('Synth-Enable-9')
    assert again.prompt() == 'MOCK-R1#'


def test_m3_only_a_device_with_no_enable_password_goes_straight_in():
    factory = Device(device_spec(scenario_port('enable-no-password')))
    assert not factory.enable_configured
    cli = Session(factory)
    assert cli.handle('enable').output == '' and cli.prompt() == 'Router#'
    cli.handle('configure terminal'); cli.handle('enable secret Synth-Enable-9'); cli.handle('end')
    cli.handle('disable')
    assert factory.enable_configured
    assert cli.handle('enable').output == 'Password: '        # now one is needed


def test_m3_enable_state_survives_rollback():
    _spec, dev = lab_router()
    snap = dev.config_state()
    assert 'enable_configured' in snap
    dev.enable_configured = False
    dev.set_config_state(snap)
    assert dev.enable_configured is True


# ================================================================ M4: real driver, timed port
VANISH, SILENCE = object(), object()


class CliConsole:
    """The mock lab CLI behind the fake port, with IOS-like echo. script[line] may replace
    a reply: fn(line, normal_reply) -> [(delay_s, text | VANISH | SILENCE), ...]. The record
    of received lines is masked."""

    def __init__(self, sim_port):
        self.device = Device(device_spec(sim_port))
        self.cli = Session(self.device)
        self.echo, self.lines, self.script, self.forced_prompt = True, [], {}, None

    def prompt(self):
        return self.forced_prompt or self.cli.prompt()

    def line(self, text):
        self.lines.append(mask_text(text, [PW]))
        if self.cli is None:
            return ''
        key = mask_text(text, [PW]).replace('********', '<SSH_PASSWORD>')
        if key in self.script and self.script[key][0] == 'reject':
            return text + '\r\n% Invalid input detected at \'^\' marker.\r\n\r\n' + self.prompt()
        reply = self.cli.handle(text)
        echo = text if self.echo else ''
        self.echo = reply.echo_next
        if reply.close:
            self.cli = None
            return echo + '\r\n'
        out = echo + '\r\n'
        if reply.raw:
            out += reply.output
        else:
            if reply.output:
                out += reply.output.replace('\n', '\r\n') + '\r\n'
            out += self.prompt()
        if key in self.script:
            return self.script[key][1](out)
        return out


class TimedSerial(FakeSerial):
    """FakeSerial whose replies arrive on a schedule (chunks with delays), can stop for
    good (SILENCE) or make the port vanish (VANISH)."""
    device = None

    def __init__(self, **settings):
        super().__init__(**settings)
        self._schedule, self._vanish_at = [], None

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
            self._enqueue(self.device.line(text))
        return len(data)

    def _enqueue(self, reply):
        when = time.monotonic()
        for delay, piece in ([(0, reply)] if isinstance(reply, str) else reply):
            when += delay
            if piece is VANISH:
                self._vanish_at = when
            elif piece is not SILENCE:
                self._schedule.append((when, piece.encode()))

    @property
    def in_waiting(self):
        now = time.monotonic()
        if self._vanish_at is not None and now >= self._vanish_at:
            self.is_open = False
            raise serial.SerialException('ClearCommError failed (the device was removed)')
        if not self.is_open:
            raise serial.SerialException('port is closed')
        due = [x for x in self._schedule if x[0] <= now]
        self._schedule = [x for x in self._schedule if x[0] > now]
        for _when, data in due:
            self._out += data
        return len(self._out)


@pytest.fixture
def timed(port, monkeypatch):
    monkeypatch.setattr(serial, 'Serial', TimedSerial)
    return TimedSerial


def real(timed, sim='SIM8', hostname='Edge-R1', domain='lab.local'):
    timed.device = CliConsole(sim)
    s = ConsoleSession('COM4', timeout=20, listen_seconds=0.1, listen_quiet=0.05)
    s.connect(confirm_idle=True)          # an idle fake device: operator-confirmed path
    r = detect_device(s)
    req, errors = validate_request(hostname, domain, 'netadmin', PW, PW, 2048, r)
    assert not errors
    plan = build_plan(r, req)
    return s, r, req, plan, timed.device


def chunks(*pieces):
    return lambda normal: list(pieces)


def after(dev, line):
    """Lines the device received after `line` (the last time it was sent)."""
    idx = len(dev.lines) - 1 - dev.lines[::-1].index(line)
    return dev.lines[idx + 1:]


def test_m4_replies_in_delayed_chunks_are_read_whole(timed):
    s, r, req, plan, dev = real(timed)
    dev.script['ip domain-name lab.local'] = ('chunks', lambda normal: [
        (0, normal[:5]), (0.1, normal[5:12]), (0.1, normal[12:-3]), (0.1, normal[-3:])])
    dev.script['configure terminal'] = ('chunks', lambda normal: [
        (0, 'configure terminal\r\nEnter configuration commands, one per line.'),
        (0.15, '  End with CNTL/Z.\r\n'), (0.15, normal.split('\r\n')[-1])])
    res = go(s, r, req, plan)
    assert res.outcome == A.SUCCESS, [(x.step_id, x.reasons) for x in res.steps]
    assert statuses(res)['domain'] == VERIFIED
    s.disconnect()


def test_m4_a_question_like_pause_shorter_than_the_settle_time_continues(timed):
    s, r, req, plan, dev = real(timed)
    assert SETTLE == 0.3
    dev.script[RSA_LINE] = ('pause', lambda normal: [
        (0, normal.split('will be:')[0] + 'will be:'), (0.1, normal.split('will be:')[1])])
    res = go(s, r, req, plan)
    assert statuses(res)['rsa'] == VERIFIED and res.outcome == A.SUCCESS
    s.disconnect()


def test_m4_a_pause_longer_than_the_settle_time_stops_safely(timed):
    s, r, req, plan, dev = real(timed)
    dev.script[RSA_LINE] = ('pause', lambda normal: [
        (0, normal.split('will be:')[0] + 'will be:'), (1.0, normal.split('will be:')[1])])
    res = go(s, r, req, plan)
    st = statuses(res)
    assert st['rsa'] == UNCERTAIN                            # read as a question: not answered
    assert any('NOT answered' in x for x in res.step('rsa').reasons)
    assert after(dev, RSA_LINE) == []                        # nothing typed after it
    assert st['ssh_version'] == A.BLOCKED and st['ssh_ready'] == A.BLOCKED
    assert not s.is_active() and timed.instances[-1].close_calls >= 1


def test_m4_a_silent_configuration_line_times_out(timed, monkeypatch):
    monkeypatch.setattr(A, 'CONFIG_TIMEOUT', 1)
    s, r, req, plan, dev = real(timed)
    dev.script['ip ssh version 2'] = ('silent', lambda normal: [(0, 'ip ssh version 2\r\n'),
                                                                (0, SILENCE)])
    started = time.monotonic()
    res = go(s, r, req, plan)
    assert time.monotonic() - started < 60
    st = statuses(res)
    assert st['ssh_version'] == UNCERTAIN and st['ssh_ready'] == A.BLOCKED
    assert any('did not finish answering' in x for x in res.step('ssh_version').reasons)
    assert after(dev, 'ip ssh version 2') == []
    assert not s.is_active() and timed.instances[-1].close_calls >= 1
    assert res.final_detection is None


def test_m4_the_port_vanishing_mid_read_is_uncertain_and_released(timed):
    s, r, req, plan, dev = real(timed)
    dev.script['ip domain-name lab.local'] = ('vanish', lambda normal: [
        (0, normal[:10] + 'PARTIAL-MARKER'), (0.2, VANISH)])
    res = go(s, r, req, plan)
    st = statuses(res)
    assert st['domain'] == UNCERTAIN and st['rsa'] == A.BLOCKED
    assert any('unplugged' in x or 'stopped working' in x for x in res.step('domain').reasons)
    assert 'PARTIAL-MARKER' not in shown(res)                # partial output never used
    assert not s.is_active()


def test_m4_partial_output_then_a_timeout_is_never_verified(timed, monkeypatch):
    monkeypatch.setattr(A, 'CONFIG_TIMEOUT', 1)
    s, r, req, plan, dev = real(timed)
    dev.script[USER_LINE] = ('partial', lambda normal: [
        (0, normal[:len(normal) // 2] + ' PARTIAL-MARKER'), (0, SILENCE)])
    res = go(s, r, req, plan)
    rec = res.step('user')
    assert rec.status == UNCERTAIN and rec.status != VERIFIED
    assert 'PARTIAL-MARKER' not in shown(res) and PW not in shown(res)
    assert not s.is_active()
    assert all(statuses(res)[x] in (A.BLOCKED, A.NOT_RUN)
               for x in statuses(res) if x.startswith('vty'))


def test_m4_real_driver_hostname_rejection_is_failed_then_end(timed):
    s, r, req, plan, dev = real(timed)
    dev.script['hostname Edge-R1'] = ('reject', None)
    res = go(s, r, req, plan)
    assert statuses(res)['hostname'] == FAILED
    assert after(dev, 'hostname Edge-R1') [:1] == ['end']    # left config mode normally
    assert s.is_active() and s.find_prompt() == 'Router#' and not res.console_released
    assert statuses(res)['rsa'] == A.BLOCKED
    s.disconnect()


def test_m4_real_driver_line_vty_rejection_is_failed(timed):
    s, r, req, plan, dev = real(timed)
    dev.script['line vty 0 4'] = ('reject', None)
    res = go(s, r, req, plan)
    vty = next(x.step_id for x in plan.steps if x.step_id.startswith('vty_login'))
    assert statuses(res)[vty] == FAILED and s.is_active()
    s.disconnect()


def test_m4_real_driver_unexpected_prompt_closes_without_typing(timed):
    s, r, req, plan, dev = real(timed)

    def odd(normal):
        dev.forced_prompt = 'Edge-R1(config-if)#'
        return [(0, normal.rsplit('\r\n', 1)[0] + '\r\nEdge-R1(config-if)#')]
    dev.script['ip domain-name lab.local'] = ('odd', odd)
    res = go(s, r, req, plan)
    assert statuses(res)['domain'] == UNCERTAIN and res.console_released
    # one empty line to re-read the prompt, then NOTHING: no end, no exit, no Enter
    assert after(dev, 'ip domain-name lab.local') == ['']
    assert not s.is_active() and timed.instances[-1].close_calls >= 1


# ================================================================ H1: application shutdown
from tkinter import messagebox  # noqa: E402

from test_restore_shutdown import exists, press_x, workbench  # noqa: E402
from gui import restore_window as W  # noqa: E402


@pytest.fixture
def boxes(monkeypatch):
    seen = []
    for name in ('showinfo', 'showwarning', 'showerror'):
        monkeypatch.setattr(messagebox, name,
                            lambda t, m, _n=name, **k: seen.append((_n, t, m)))
    return seen


@pytest.fixture(autouse=True)
def clean_restore_registry():
    W._ACTIVE.clear(); W._PROTECTED.clear(); W._WINDOWS.clear()
    yield
    W._ACTIVE.clear(); W._PROTECTED.clear(); W._WINDOWS.clear()


def pump_until(root, cond, timeout=5):
    end = time.time() + timeout
    while time.time() < end and exists(root) and not cond():
        root.update()
        time.sleep(0.02)


def finish_later(token, seconds=0.5):
    threading.Timer(seconds, apply_guard.end, args=(token,)).start()


def test_h1_demo_x_waits_for_the_current_step_then_closes(monkeypatch, boxes):
    import main
    seen = {}

    def action(refs, root):
        cancel = threading.Event()
        token = apply_guard.begin('SIM8', cancel)
        press_x(refs, root)
        seen['open'] = exists(root)
        seen['stop_requested'] = cancel.is_set() and apply_guard.shutdown_requested(token)
        seen['fast'] = apply_guard.finish_fast_event(token).is_set()
        pump_until(root, lambda: False, timeout=0.6)
        seen['still_open'] = exists(root)                  # the step is still running
        apply_guard.end(token)                             # the worker closed the console
        pump_until(root, lambda: not exists(root), timeout=3)
        seen['closed'] = not exists(root)
    outcome, _root, _ = workbench(monkeypatch, action)
    assert seen == {'open': True, 'stop_requested': True, 'fast': True, 'still_open': True,
                    'closed': True}
    assert outcome == main.CLOSED
    assert boxes[0][1] == apply_guard.SHUTDOWN_TITLE and 'never cut off' in boxes[0][2]


@pytest.mark.parametrize('how, expected', [('x', 'CLOSED'), ('sign_out', 'SIGNED_OUT')])
def test_h1_signed_in_x_and_sign_out_wait_for_the_step(monkeypatch, boxes, how, expected):
    import main
    seen = {}

    def action(refs, root):
        token = apply_guard.begin('COM4', threading.Event())
        session = refs['session_watcher'].session
        if how == 'x':
            press_x(refs, root)
        else:
            refs['sign_out_button'].invoke()
        seen['open'], seen['active'] = exists(root), session.active
        finish_later(token, 0.4)
        pump_until(root, lambda: not exists(root), timeout=5)
        seen['closed'] = not exists(root)
    outcome, _root, session = workbench(monkeypatch, action, signed_in=True)
    assert seen == {'open': True, 'active': True, 'closed': True}
    assert outcome == getattr(main, expected) and not session.active
    assert 'sign out' in boxes[0][2] if how == 'sign_out' else 'then will close' in boxes[0][2]


def test_h1_ended_session_signs_out_after_the_step(monkeypatch, boxes):
    import main
    seen = {}

    def action(refs, root):
        cancel = threading.Event()
        token = apply_guard.begin('COM4', cancel)
        refs['session_watcher'].end('ended')
        seen['open'], seen['stop'] = exists(root), cancel.is_set()
        pump_until(root, lambda: False, timeout=0.7)
        seen['still_open'] = exists(root)
        apply_guard.end(token)
        pump_until(root, lambda: not exists(root), timeout=3)
        seen['closed'] = not exists(root)
    outcome, _root, _ = workbench(monkeypatch, action, signed_in=True)
    assert seen == {'open': True, 'stop': True, 'still_open': True, 'closed': True}
    assert outcome == main.SIGNED_OUT
    assert boxes[0][1] == 'Signed out after the current SSH step'


def test_h1_repeated_requests_close_once_and_the_latest_wins(monkeypatch, boxes):
    import main
    seen = {'runs': 0}

    def action(refs, root):
        token = apply_guard.begin('COM4', threading.Event())
        press_x(refs, root)
        press_x(refs, root)                                # twice: one wait, not two
        refs['sign_out_button'].invoke()                   # then Sign out: this one wins
        apply_guard.end(token)
        pump_until(root, lambda: not exists(root), timeout=3)
        seen['closed'] = not exists(root)
    outcome, _root, _ = workbench(monkeypatch, action, signed_in=True)
    assert seen['closed'] and outcome == main.SIGNED_OUT and len(boxes) == 3


def test_h1_restore_protection_is_unchanged_and_checked_first(monkeypatch, boxes):
    seen = {}

    def action(refs, root):
        restore = W._protect('192.0.2.10')
        cancel = threading.Event()
        token = apply_guard.begin('COM4', cancel)
        press_x(refs, root)
        seen['restore_box'] = boxes[-1][1] == W.SHUTDOWN_TITLE
        seen['apply_untouched'] = not cancel.is_set()      # the restore message came first
        W._unprotect(restore)
        press_x(refs, root)
        seen['apply_box'] = boxes[-1][1] == apply_guard.SHUTDOWN_TITLE and cancel.is_set()
        apply_guard.end(token)
        pump_until(root, lambda: not exists(root), timeout=3)
        seen['closed'] = not exists(root)
    workbench(monkeypatch, action)
    assert seen == {'restore_box': True, 'apply_untouched': True, 'apply_box': True,
                    'closed': True}


def test_h1_ended_session_waits_for_both_restore_and_apply(monkeypatch, boxes):
    import main
    seen = {}

    def action(refs, root):
        restore = W._protect('192.0.2.10')
        cancel = threading.Event()
        token = apply_guard.begin('COM4', cancel)
        refs['session_watcher'].end('ended')
        seen['stop'] = cancel.is_set()
        W._unprotect(restore)
        pump_until(root, lambda: False, timeout=0.8)
        seen['open_for_apply'] = exists(root)
        apply_guard.end(token)
        pump_until(root, lambda: not exists(root), timeout=3)
        seen['closed'] = not exists(root)
    outcome, _root, _ = workbench(monkeypatch, action, signed_in=True)
    assert seen == {'stop': True, 'open_for_apply': True, 'closed': True}
    assert outcome == main.SIGNED_OUT


def test_h1_without_an_apply_nothing_changes(monkeypatch, boxes):
    import main
    outcome, root, _ = workbench(monkeypatch, press_x)
    assert outcome == main.CLOSED and not exists(root) and boxes == []
    assert apply_guard.block_shutdown(None) is False


def test_h1_end_to_end_the_step_finishes_then_the_console_closes(monkeypatch, boxes):
    """The real Setup page in the real workbench, a slow simulated console: X during a
    step lets that step finish (configure terminal ... end), starts no other step, closes
    the console without typing, and then NetCommand closes."""
    import main
    from test_setup_preview import fill
    backend = MockConsoleBackend(delay=0.03)
    monkeypatch.setattr(main, 'console_backend', lambda: backend)
    seen = {}

    def action(refs, root):
        tab = refs['setup']
        tab.refresh_ports()
        pump_until(root, lambda: tab.ports, 5)
        tab.port_var.set(next(p.label() for p in tab.ports if p.device == 'SIM8'))
        tab._show_port_hint()
        tab.connect()
        pump_until(root, lambda: tab.session is not None and not tab.busy, 5)
        tab.detect()
        pump_until(root, lambda: not tab.busy, 10)
        fill(tab, password=PW)
        tab.preview()
        tab.apply_vars['password'].set(PW)
        tab.apply_vars['confirm'].set(PW)
        tab.apply_vars['phrase'].set(confirmation_phrase(tab.plan))
        session = tab.session
        tab.apply_btn.invoke()
        pump_until(root, lambda: session.config_sent.count('configure terminal') == 2, 10)
        seen['steps_started'] = session.config_sent.count('configure terminal')
        press_x(refs, root)                                # in the middle of step 2
        seen['open_during_step'] = exists(root)
        seen['not_cut'] = not session._cancelled.is_set()
        pump_until(root, lambda: not exists(root), timeout=15)
        seen['closed'] = not exists(root)
        seen['session'] = session
    outcome, _root, _ = workbench(monkeypatch, action)
    s = seen.pop('session')
    assert seen == {'steps_started': 2, 'open_during_step': True, 'not_cut': True,
                    'closed': True}
    assert outcome == main.CLOSED
    sent = s.config_sent
    assert sent.count('configure terminal') == sent.count('end') == 2   # step 2 finished
    assert not s.is_active() and s.graceful_disconnects == 0           # closed, nothing typed
    assert apply_guard.active() == []
    assert PW not in str(sent)
