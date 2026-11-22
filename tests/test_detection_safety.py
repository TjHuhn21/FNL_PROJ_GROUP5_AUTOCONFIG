"""Phase 5.1.2: unexpected prompts or invalid answers are never read as confirmed empty
configuration, and both "% Error" and "%Error" replies are failures. Offline: mock-lab
consoles and scripted sessions; show commands only; nothing is executed."""
import os
import sys

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path[:0] = [ROOT, os.path.join(ROOT, 'mock-lab'), os.path.dirname(__file__)]

from console import detect  # noqa: E402
from console.detect import (UNEXPECTED, SshCapability, detect_device,  # noqa: E402
                            strip_log_lines, unexpected_answer)
from console.plan import build_plan, validate_request  # noqa: E402
from console.steps import COMMON_FAILURE_REPLIES, FAILED, UNCERTAIN  # noqa: E402
from mocklab.console import MockConsoleBackend, scenario_port  # noqa: E402
from test_console_detect import ScriptedSession, healthy  # noqa: E402

PASSWORD = 'Str0ng-Pass!'
ROMMON = '\nrommon 7 > '


def mock_detect(command):
    """Mock router whose console falls into the boot loader at `command`."""
    s = MockConsoleBackend(delay=0, edge_cases=True).open_session(
        scenario_port('console-unexpected-prompt'), 9600, '', '', '', None)
    s.console = {'unexpected_prompt_on': command}
    s.connect()
    return detect_device(s), s


def with_new_account(result, **values):
    req, errors = validate_request(username='netadmin', password=PASSWORD, confirm=PASSWORD,
                                   key_size=2048, result=result, **values)
    assert not errors, list(errors)
    return build_plan(result, req)


# ================================================================== recognising answers
@pytest.mark.parametrize('text', ['rommon 1 >', '\nrommon 12 > ', 'switch: ', 'loader> '])
def test_boot_loader_prompts_stop_detection(text):
    assert unexpected_answer('show version', text)[0] == 'stop'


@pytest.mark.parametrize('text', ['Press RETURN to get started!', '\r\nUsername: ',
                                  'User Access Verification\n\nPassword: '])
def test_logged_out_prompts_stop_detection(text):
    assert unexpected_answer(detect.SHOW_USERNAMES, text)[0] == 'stop'


@pytest.mark.parametrize('command, text, valid', [
    (detect.SHOW_USERNAMES, 'username a privilege 15 secret 9 ********', True),
    (detect.SHOW_USERNAMES, '', True),                               # a real empty search
    (detect.SHOW_USERNAMES, 'R1#', False),
    (detect.SHOW_DOMAIN, 'ip domain-name lab.local\nno ip domain lookup', True),
    (detect.SHOW_DOMAIN, 'Building configuration...', False),
    (detect.SHOW_AAA, 'aaa new-model\naaa authentication login default local', True),
    (detect.SHOW_AAA, 'garbled ~#$ output', False),
    (detect.SHOW_VTY, 'line vty 0 4\n login local\n transport input ssh', True),
    (detect.SHOW_VTY, 'line vty 0 4\n login local\ninterface Gi0/0', False),
])
def test_configuration_search_answers_are_checked(command, text, valid):
    assert (unexpected_answer(command, text) is None) is valid


def test_log_lines_are_removed_but_nothing_else():
    text = ('hostname R1\n*Nov 21 10:15:42.123: %LINK-3-UPDOWN: Interface Gi0/1, changed '
            'state to up\n%SYS-5-CONFIG_I: Configured from console by console\nhostname-x')
    assert strip_log_lines(text) == ('hostname R1\nhostname-x', 2)
    assert strip_log_lines('% Invalid input detected')[1] == 0       # rejections are kept


# ================================================================== boot loader (mock lab)
def test_boot_loader_during_domain_detection():
    r, s = mock_detect(detect.SHOW_DOMAIN)
    c = r.config
    assert not r.complete and r.command(detect.SHOW_DOMAIN).status == UNEXPECTED
    assert c.domain_name is None and not c.domain_known                 # unknown, not "none"
    assert not c.aaa_known and c.aaa_new_model is None                  # skipped afterwards
    assert not c.ssh_lines_known
    # earlier, valid information is kept
    assert c.local_users_known and [u.name for u in c.local_users] == ['labadmin']
    assert r.vty.configured is True and r.ssh.status == SshCapability.SUPPORTED_ENABLED
    assert any('Detection stopped at "show running-config | include ip domain"' in w
               and 'boot-loader' in w for w in r.warnings)
    assert all(cmd.status == detect.SKIPPED for cmd in r.commands
               if cmd.command in (detect.SHOW_SSH_CONFIG, detect.SHOW_AAA))
    plan = with_new_account(r)
    assert not plan.available and plan.commands == [] and plan.steps == []


def test_boot_loader_during_username_detection():
    r, s = mock_detect(detect.SHOW_USERNAMES)
    c = r.config
    assert not c.local_users_known and c.local_users == [] and r.ssh.local_usernames == []
    assert not c.domain_known and not c.aaa_known
    assert r.vty.configured is None and r.vty.ssh_transport is None     # never "no VTY lines"
    assert r.ssh.status == SshCapability.SUPPORTED_ENABLED              # read before
    assert r.device.model and r.access.privilege_level == 15
    plan = with_new_account(r)
    assert not plan.available and 'did not finish' in plan.reason
    assert s.find_prompt() == 'rommon 1 >'


# ================================================================== invalid answers (scripted)
def test_unexpected_output_during_aaa_detection():
    answers = healthy(**{detect.SHOW_AAA: 'line con 0\n exec-timeout 0 0'})
    answers[detect.SHOW_VTY] = 'line vty 0 4\n password 7 ********\n login\n transport input ssh'
    r = detect_device(ScriptedSession(answers))
    assert r.complete                                         # not a boot loader: detection went on
    assert r.command(detect.SHOW_AAA).status == UNEXPECTED
    assert not r.config.aaa_known and r.config.aaa_new_model is None
    assert any('include aaa' in w and 'not used' in w for w in r.warnings)
    plan = with_new_account(r)
    assert plan.available
    assert plan.item('aaa').status == 'unknown' and plan.item('vty_login').status == 'unknown'
    assert 'login local' not in [c.text for c in plan.commands]          # depends on AAA
    assert any('treated as unknown' in w for w in plan.warnings)
    [aaa] = plan.invariants
    assert aaa.evaluate({detect.SHOW_AAA: ''})[0] == UNCERTAIN


def test_unexpected_output_during_vty_detection():
    answers = healthy(**{detect.SHOW_VTY: 'line vty 0 4\n login local\ninterface Gi0/0\n '
                                          'transport input telnet'})
    r = detect_device(ScriptedSession(answers))
    assert r.command(detect.SHOW_VTY).status == UNEXPECTED
    assert r.vty.configured is None and r.vty.blocks == [] and r.vty.ssh_transport is None
    plan = with_new_account(r)
    assert plan.item('vty_login').status == 'unknown'
    assert plan.item('vty_transport').status == 'unknown'
    assert not any(c.mode for c in plan.commands)                         # no VTY change
    assert [s.step_id for s in plan.steps if s.step_id.startswith('vty')] == []


def test_logged_out_console_stops_detection():
    answers = healthy(**{detect.SHOW_USERNAMES: '\r\nR1 con0 is now available\r\n\r\nPress '
                                                'RETURN to get started.\r\n'})
    r = detect_device(ScriptedSession(answers))
    assert not r.complete and not r.config.local_users_known
    assert any('login prompt' in w for w in r.warnings)
    assert not build_plan(r).available


def test_valid_empty_searches_still_mean_not_configured():
    answers = healthy(**{detect.SHOW_DOMAIN: '', detect.SHOW_AAA: ''})
    r = detect_device(ScriptedSession(answers))
    assert r.config.domain_known and r.config.domain_name is None
    assert r.config.aaa_known and r.config.aaa_new_model is False
    assert r.complete and not any(c.status == UNEXPECTED for c in r.commands)


# ================================================================== verification checks
@pytest.mark.parametrize('step_id, command', [
    ('domain', detect.SHOW_DOMAIN), ('user', detect.SHOW_USERNAMES),
    ('vty_login[0 4]', detect.SHOW_VTY), ('hostname', detect.SHOW_HOSTNAME)])
def test_checks_never_read_a_boot_loader_as_missing(step_id, command):
    s = MockConsoleBackend(delay=0).open_session('SIM8', 9600, '', '', '', None)
    s.connect()
    r = detect_device(s)
    plan = with_new_account(r, hostname='Edge-R1', domain_name='lab.local')
    outcome, reasons = plan.step(step_id).evaluate({command: ROMMON})
    assert outcome == UNCERTAIN and any('boot-loader' in x for x in reasons)


def test_checks_ignore_log_lines():
    s = MockConsoleBackend(delay=0).open_session('SIM8', 9600, '', '', '', None)
    s.connect()
    plan = with_new_account(detect_device(s), hostname='Edge-R1', domain_name='lab.local')
    text = ('*Nov 21 10:15:42.123: %LINK-3-UPDOWN: Interface Gi0/1, changed state to up\n'
            'hostname Edge-R1')
    assert plan.step('hostname').evaluate({detect.SHOW_HOSTNAME: text})[0] == 'verified'


# ================================================================== % Error / %Error
def test_both_error_spellings_are_failure_replies():
    assert '% Error' in COMMON_FAILURE_REPLIES and '%Error' in COMMON_FAILURE_REPLIES


@pytest.mark.parametrize('reply', ['%Error: RSA key generation failed (SIMULATED)',
                                   '% Error in generating keys: no available resources',
                                   '%Error opening flash:x (No such file)'])
def test_error_replies_fail_the_step(reply):
    s = MockConsoleBackend(delay=0, edge_cases=True).open_session(
        scenario_port('rsa-fails'), 9600, '', '', '', None)
    s.connect()
    rsa = build_plan(detect_device(s)).step('rsa')
    assert rsa.evaluate({}, reply=reply)[0] == FAILED                   # from the reply alone


def test_simulated_rsa_failure_is_caught_from_the_reply():
    from mocklab.cli import Session
    from mocklab.console import device_spec
    from mocklab.device import Device
    port = scenario_port('rsa-fails')
    s = MockConsoleBackend(delay=0, edge_cases=True).open_session(port, 9600, '', '', '', None)
    s.connect()
    rsa = build_plan(detect_device(s)).step('rsa')
    cli = Session(Device(device_spec(port)))
    cli.handle('configure terminal')
    reply = cli.handle(rsa.command.text).output
    outcome, reasons = rsa.evaluate({}, reply=reply)
    assert outcome == FAILED and reasons == ['the device rejected the command']
