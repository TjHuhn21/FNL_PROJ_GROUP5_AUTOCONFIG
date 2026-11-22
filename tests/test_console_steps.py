"""console.steps: dependency and verification DEFINITIONS for preview commands (phase 5.1).
Offline: mock-lab devices, the real detection and planner, and pure evaluators fed with
text. Nothing is executed; there is no runner."""
import os
import sys
from dataclasses import asdict

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path[:0] = [ROOT, os.path.join(ROOT, 'mock-lab'), os.path.dirname(__file__)]

from console import detect, steps as S  # noqa: E402
from console.detect import DETECTION_COMMANDS, detect_device  # noqa: E402
from console.link import ConsoleSession, check_show_command  # noqa: E402
from console.plan import build_plan, validate_request  # noqa: E402
from console.steps import FAILED, UNCERTAIN, VERIFIED, readiness  # noqa: E402
from mocklab.console import MockConsoleBackend  # noqa: E402
from test_setup_tab import root  # noqa: E402,F401

PASSWORD = 'Str0ng-Pass!'
SHOW_IP_SSH, SHOW_RSA, SHOW_VTY = detect.SHOW_IP_SSH, detect.SHOW_RSA, detect.SHOW_VTY


def detected(port):
    session = MockConsoleBackend(delay=0).open_session(port, 9600, '', '', '', None)
    session.connect()
    return detect_device(session)


def plan_for(port, username='', **values):
    r = detected(port)
    pw = PASSWORD if username else ''
    req, errors = validate_request(username=username, password=pw, confirm=pw, key_size=2048,
                                   result=r, **values)
    assert not errors, list(errors)
    return build_plan(r, req)


def full_plan():
    return plan_for('SIM8', username='netadmin', hostname='Edge-R1', domain_name='lab.local')


def outcome(step, outputs, reply=None):
    return step.evaluate(outputs, reply=reply)[0]


# ------------------------------------------------------------------ structure and order
def test_every_command_has_a_step_in_command_order():
    plan = full_plan()
    ids = [s.step_id for s in plan.steps]
    assert ids == ['hostname', 'domain', 'user', 'rsa', 'ssh_version', 'ssh_ready',
                   'vty_login[0 4]', 'vty_transport[0 4]']
    sent = [s.command.text for s in plan.steps if s.command is not None]
    assert sent == [l.strip() for l in plan.lines() if l not in
                    ('configure terminal', 'end', 'line vty 0 4')]
    assert all(c.step_id for c in plan.commands)
    assert plan.step('ssh_ready').kind == S.CHECK and plan.step('ssh_ready').command is None


def test_dependencies_point_backwards():
    plan = full_plan()
    seen = set()
    for step in plan.steps:
        assert set(step.requires) <= seen, step.step_id
        seen.add(step.step_id)
    assert plan.step('rsa').requires == ('hostname', 'domain')
    assert plan.step('ssh_version').requires == ('rsa',)
    assert plan.step('ssh_ready').requires == ('rsa', 'ssh_version')
    assert plan.step('vty_login[0 4]').requires == ('user',)
    assert plan.step('vty_transport[0 4]').requires == ('ssh_ready', 'vty_login[0 4]')


def test_every_check_is_a_read_only_detection_command():
    plan = full_plan()
    for step in plan.steps + plan.invariants:
        assert step.verifications, step.step_id
        for v in step.verifications:
            assert check_show_command(v.command) == v.command
            assert v.command in DETECTION_COMMANDS
            assert v.verified and v.failed and v.uncertain


def test_steps_hold_no_password_and_no_save():
    plan = full_plan()
    dump = repr(asdict(plan))
    assert PASSWORD not in dump and '<SSH_PASSWORD>' in dump
    for step in plan.steps:
        text = step.command.text if step.command else ''
        assert not text.startswith(('write', 'copy', 'reload'))


# ------------------------------------------------------------------ readiness
def test_only_steps_without_prerequisites_start_ready():
    ready = readiness(full_plan().steps, {})
    assert [k for k, (ok, _w) in ready.items() if ok] == ['hostname', 'domain', 'user']
    assert ready['rsa'][1] == 'blocked: hostname is not verified yet; domain is not verified yet'


def test_failed_prerequisite_blocks_dependents():
    plan = full_plan()
    ready = readiness(plan.steps, {'hostname': VERIFIED, 'domain': FAILED})
    assert ready['rsa'] == (False, 'blocked: domain is failed')
    ready = readiness(plan.steps, {'hostname': VERIFIED, 'domain': VERIFIED})
    assert ready['rsa'] == (True, 'ready')


def test_uncertain_prerequisite_blocks_dependents_transitively():
    plan = full_plan()
    done = {'hostname': VERIFIED, 'domain': VERIFIED, 'user': VERIFIED, 'rsa': UNCERTAIN}
    ready = readiness(plan.steps, done)
    assert not ready['ssh_version'][0] and 'rsa is uncertain' in ready['ssh_version'][1]
    assert not ready['ssh_ready'][0]
    assert ready['vty_login[0 4]'][0]                            # only needs the account
    assert not ready['vty_transport[0 4]'][0]                    # ssh_ready never verified


# ------------------------------------------------------------------ prompts
def test_hostname_prompt_change_is_described():
    plan = full_plan()
    prompt = plan.step('hostname').prompt
    assert prompt.hostname_changes_to == 'Edge-R1' and prompt.prompt_after == 'Edge-R1(config)#'
    assert 'set_base_prompt' in prompt.note
    assert plan.step('vty_login[0 4]').prompt.prompt_after == 'Edge-R1(config-line)#'
    assert plan.step('user').prompt.prompt_after == 'Edge-R1(config)#'


def test_prompt_keeps_the_current_name_without_a_rename():
    plan = plan_for('SIM2')
    assert plan.step('rsa').prompt.prompt_after == 'R2(config)#'
    assert plan.step('rsa').prompt.hostname_changes_to is None


# ------------------------------------------------------------------ hostname / domain / user
def test_hostname_and_domain_verification():
    plan = full_plan()
    h, d = plan.step('hostname'), plan.step('domain')
    assert outcome(h, {detect.SHOW_HOSTNAME: 'hostname Edge-R1'}) == VERIFIED
    assert outcome(h, {detect.SHOW_HOSTNAME: 'hostname Router'}) == FAILED
    assert outcome(h, {detect.SHOW_HOSTNAME: ''}) == UNCERTAIN
    assert outcome(h, {}) == UNCERTAIN                          # the check did not run
    assert outcome(d, {detect.SHOW_DOMAIN: 'ip domain-name lab.local'}) == VERIFIED
    assert outcome(d, {detect.SHOW_DOMAIN: 'ip domain name lab.local'}) == VERIFIED
    assert outcome(d, {detect.SHOW_DOMAIN: ''}) == FAILED
    assert outcome(d, {detect.SHOW_DOMAIN: "% Invalid input detected at '^' marker."}) == \
        UNCERTAIN


def test_new_account_verification():
    user = full_plan().step('user')
    q = detect.SHOW_USERNAMES
    assert outcome(user, {q: 'username netadmin privilege 15 secret 9 ********'}) == VERIFIED
    assert outcome(user, {q: 'username netadmin secret 9 ********'}) == FAILED   # privilege 1
    assert outcome(user, {q: 'username other privilege 15 secret 9 ********'}) == FAILED
    assert outcome(user, {q: 'username netadmin privilege 15 password 0 ********'}) == UNCERTAIN
    assert outcome(user, {q: 'username netadminx privilege 15 secret 9 ********'}) == FAILED
    assert any('cannot prove the password' in l for l in user.limitations)


def test_a_rejected_reply_fails_and_a_prompt_alone_proves_nothing():
    h = full_plan().step('hostname')
    assert outcome(h, {}, reply="% Invalid input detected at '^' marker.") == FAILED
    assert outcome(h, {}, reply='Edge-R1(config)#') == UNCERTAIN  # accepted, not yet verified


# ------------------------------------------------------------------ RSA keys
KEY = ('Key name: Edge-R1.lab.local\n Usage: General Purpose Key\n Key Data:\n  3082')


def test_rsa_key_identity_verification_and_its_limits():
    rsa = full_plan().step('rsa')
    assert outcome(rsa, {SHOW_RSA: KEY, SHOW_IP_SSH: 'IOS Keys in SECSH format(ssh-rsa, base64 '
                                                     'encoded): Edge-R1.lab.local'}) == VERIFIED
    out, reasons = rsa.evaluate({SHOW_RSA: KEY})                # size not printed, no ip ssh
    assert out == VERIFIED and any('not confirmed' in r for r in reasons)
    assert outcome(rsa, {SHOW_RSA: KEY.replace('Edge-R1', 'Old')}) == UNCERTAIN   # other name
    assert outcome(rsa, {SHOW_RSA: ''}) == FAILED                                  # no keys
    assert outcome(rsa, {SHOW_RSA: KEY + '\n Modulus size (bits): 1024'}) == FAILED  # 2048 asked
    assert outcome(rsa, {SHOW_RSA: KEY, SHOW_IP_SSH: 'IOS Keys in SECSH format(ssh-rsa, '
                                                     'base64 encoded): NONE'}) == FAILED
    assert outcome(rsa, {SHOW_RSA: 'something odd'}) == UNCERTAIN
    assert any('cannot prove the key is newly generated' in l for l in rsa.limitations)
    assert any('size' in l.lower() for l in rsa.limitations)


def test_rsa_replies_and_questions():
    rsa = full_plan().step('rsa')
    assert outcome(rsa, {SHOW_RSA: KEY},
                   reply='% Please define a domain-name first.') == FAILED
    assert outcome(rsa, {SHOW_RSA: KEY}, reply='% You already have RSA keys defined named '
                   'Edge-R1.lab.local.\n% Do you really want to replace them? [yes/no]: ') == \
        UNCERTAIN
    assert 'Do you really want to replace them' in rsa.questions


# ------------------------------------------------------------------ SSH after the keys
def test_ssh_version_2_is_not_verified_by_acceptance():
    v2 = full_plan().step('ssh_version')
    assert outcome(v2, {}, reply='Edge-R1(config)#') == UNCERTAIN
    assert outcome(v2, {SHOW_IP_SSH: 'SSH Enabled - version 1.99'}) == FAILED
    assert outcome(v2, {SHOW_IP_SSH: 'SSH Disabled - version 1.99'}) == FAILED
    assert outcome(v2, {SHOW_IP_SSH: 'SSH Enabled - version 2.0'}) == VERIFIED
    assert outcome(v2, {SHOW_IP_SSH: 'garbled'}) == UNCERTAIN


def test_ssh_ready_check_after_key_generation():
    ready = full_plan().step('ssh_ready')
    assert outcome(ready, {SHOW_IP_SSH: 'SSH Enabled - version 1.99'}) == VERIFIED
    assert outcome(ready, {SHOW_IP_SSH: 'SSH Disabled - version 1.99'}) == FAILED
    assert outcome(ready, {}) == UNCERTAIN


# ------------------------------------------------------------------ VTY
def test_transport_depends_on_verified_ssh_even_when_ssh_already_runs():
    plan = plan_for('SIM10')                         # SSH enabled; only the transport changes
    assert [s.step_id for s in plan.steps] == ['ssh_ready', 'vty_transport[0 4]']
    assert plan.step('ssh_ready').requires == ()
    t = plan.step('vty_transport[0 4]')
    assert t.requires == ('ssh_ready',)
    assert not readiness(plan.steps, {'ssh_ready': UNCERTAIN})['vty_transport[0 4]'][0]
    assert readiness(plan.steps, {'ssh_ready': VERIFIED})['vty_transport[0 4]'][0]
    vty_ok = 'line vty 0 4\n login local\n transport input ssh'
    assert outcome(t, {SHOW_VTY: vty_ok}) == VERIFIED
    assert outcome(t, {SHOW_VTY: vty_ok.replace('input ssh', 'input telnet ssh')}) == FAILED
    assert outcome(t, {SHOW_VTY: 'line vty 0 4\n login local'}) == UNCERTAIN
    assert outcome(t, {SHOW_VTY: 'line vty 5 15\n transport input ssh'}) == UNCERTAIN
    assert t.approval_required and t.disruptive


def test_login_local_depends_on_the_new_verified_account():
    plan = plan_for('SIM16', username='netadmin')
    login = plan.step('vty_login[5 15]')
    assert login.requires == ('user',)
    assert 'NEW account netadmin is VERIFIED' in login.preconditions[0]
    assert 'an existing account is not enough' in login.preconditions[0]
    assert plan.step('vty_transport[5 15]').requires == ('ssh_ready', 'vty_login[5 15]')
    assert not readiness(plan.steps, {'user': UNCERTAIN})['vty_login[5 15]'][0]
    assert not readiness(plan.steps, {'user': FAILED})['vty_login[5 15]'][0]
    assert readiness(plan.steps, {'user': VERIFIED})['vty_login[5 15]'][0]
    vty = 'line vty 5 15\n password 7 ********\n login local\n transport input ssh'
    assert outcome(login, {SHOW_VTY: vty}) == VERIFIED
    assert outcome(login, {SHOW_VTY: vty.replace('login local', 'login')}) == FAILED


def test_no_login_step_without_a_new_account():
    plan = plan_for('SIM16')                         # existing admin labadmin only
    assert not any(s.step_id.startswith('vty_login') for s in plan.steps)
    assert plan.step('vty_transport[5 15]').requires == ('ssh_ready',)


# ------------------------------------------------------------------ AAA invariant
def test_aaa_is_an_invariant_that_must_not_change():
    plan = plan_for('SIM9', username='netadmin')
    [aaa] = plan.invariants
    assert aaa.step_id == 'aaa_unchanged' and aaa.command is None
    assert not any(s.command and s.command.text.startswith('aaa') for s in plan.steps)
    same = 'aaa new-model\naaa authentication login default local'
    assert outcome(aaa, {detect.SHOW_AAA: same}) == VERIFIED
    assert outcome(aaa, {detect.SHOW_AAA: same + '\naaa authentication login VTY local'}) == FAILED
    assert outcome(aaa, {detect.SHOW_AAA: ''}) == FAILED


def test_aaa_not_known_at_detection_can_only_be_uncertain():
    r = detected('SIM8')
    r.config.aaa_known, r.config.aaa_new_model = False, None
    req, _e = validate_request('Edge-R1', 'lab.local', 'netadmin', PASSWORD, PASSWORD, 2048, r)
    [aaa] = build_plan(r, req).invariants
    assert outcome(aaa, {detect.SHOW_AAA: ''}) == UNCERTAIN


# ------------------------------------------------------------------ renames while SSH runs
def test_rename_while_ssh_runs_needs_separate_approval():
    plan = plan_for('SIM1', hostname='R1-new', domain_name='corp.local')
    for step_id in ('hostname', 'domain'):
        step = plan.step(step_id)
        assert step.disruptive and step.approval_required
        assert 'SSH is running' in step.approval_reason
    assert 'SSH is running now' in plan.item('hostname').explanation
    assert 'SSH is running now' in plan.item('domain').explanation


def test_rename_without_running_ssh_needs_no_extra_approval():
    plan = full_plan()                               # SIM8: SSH not enabled
    assert not plan.step('hostname').approval_required
    assert not plan.step('hostname').command.disruptive


# ------------------------------------------------------------------ backward compatibility
def test_existing_preview_is_unchanged():
    plan = full_plan()
    assert plan.lines() == [
        'configure terminal', 'hostname Edge-R1', 'ip domain-name lab.local',
        'username netadmin privilege 15 secret <SSH_PASSWORD>',
        'crypto key generate rsa modulus 2048', 'ip ssh version 2', 'line vty 0 4',
        ' login local', ' transport input ssh', 'end']


@pytest.mark.parametrize('port', ['SIM1', 'SIM3', 'SIM4'])
def test_no_steps_without_commands(port):
    plan = plan_for(port)
    assert plan.steps == [] and plan.invariants == []


# ------------------------------------------------------------------ still no execution
def test_console_session_has_no_way_to_configure():
    public = {n for n in dir(ConsoleSession) if not n.startswith('_')}
    assert public == {'connect', 'find_prompt', 'send_show', 'enable', 'is_active', 'cancel',
                      'disconnect'}


def test_steps_module_has_no_session_or_device_access():
    source = open(S.__file__, encoding='utf-8').read()
    for word in ('ConsoleSession', 'netmiko', 'send_show', 'send_config', 'serial', 'connect('):
        assert word not in source, word


def test_gui_shows_steps_as_definitions_only(root):
    from gui.setup_tab import STEPS_NOTE
    from test_setup_tab import make, settle
    tab = make(root, backend=MockConsoleBackend(delay=0))
    tab.refresh_ports()
    settle(root, tab)
    tab.port_var.set(next(p.label() for p in tab.ports if p.device == 'SIM1'))
    tab._show_port_hint()
    tab.connect()
    settle(root, tab)
    tab.detect()
    settle(root, tab)
    tab.want['hostname'].set('R1-new')
    tab.want['domain_name'].set('corp.local')
    tab.preview()
    body = tab.preview_widgets['steps']
    assert not body.winfo_manager()
    tab.preview_widgets['steps_toggle'].invoke()
    text = body.cget('text')
    assert text.startswith(STEPS_NOTE) and 'nothing is run or sent' in text
    assert 'SEPARATE APPROVAL NEEDED' in text and '[aaa_unchanged]' in text
    assert 'prompt:   changes to R1-new(config)#' in text
    assert tab.session.sent and set(tab.session.sent) <= set(DETECTION_COMMANDS)
