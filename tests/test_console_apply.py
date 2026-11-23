"""Phase 5.1.2: applying an approved SSH setup plan through the console (console.apply)
against the mock lab's simulated consoles. Offline: no COM port, no physical device, no
network SSH. The password used here is synthetic.

Covered: the configuration guards, enable without a password (B1), unexpected questions
never answered (D1), no management IP / no network SSH (D2), nothing saved (D3), every
refusal sending nothing, step-by-step verification, BLOCKED dependents, the AAA invariant,
cancellation between steps only, the edge-case scenarios SIM8 and SIM18-SIM37, and the
password never appearing anywhere.
"""
import os
import sys
import threading

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path[:0] = [ROOT, os.path.join(ROOT, 'mock-lab')]

from console import apply as A  # noqa: E402
from console import detect  # noqa: E402
from console.apply import (BLOCKED, NOT_RUN, approvals_needed, apply_plan,  # noqa: E402
                           confirmation_phrase)
from console.detect import detect_device  # noqa: E402
from console.link import (AUTH, BOOT_LOADER, PASSWORD_PROMPT, PROMPT, QUESTION,  # noqa: E402
                          REFUSED, ConsoleError, check_config_line, check_secret,
                          classify_reply, mask_text)
from console.plan import PASSWORD_PLACEHOLDER, build_plan, validate_request  # noqa: E402
from console.steps import FAILED, UNCERTAIN, VERIFIED  # noqa: E402
from mocklab.cli import _scramble  # noqa: E402
from mocklab.console import MockConsoleBackend, scenario_port  # noqa: E402

PW = 'Synth3tic-Pass!'                 # never a real credential
USER_LINE = f'username netadmin privilege 15 secret {PASSWORD_PLACEHOLDER}'
SAVE_WORDS = ('write', 'copy', 'reload', 'erase', 'delete', 'format', 'boot ')


# ---------------------------------------------------------------- helpers
def open_mock(port, **kw):
    s = MockConsoleBackend(delay=0, edge_cases=True).open_session(port, 9600, '', '', '', None,
                                                                  **kw)
    s.connect()
    return s


def prepare(port, hostname='', domain='', username='netadmin', before_detect=None):
    s = open_mock(port)
    if before_detect:
        before_detect(s)
    r = detect_device(s)
    req, errors = validate_request(hostname, domain, username, PW, PW, 2048, r)
    assert not errors, errors
    plan = build_plan(r, req)
    assert plan.available and plan.steps, plan.reason
    return s, r, req, plan


def run(s, r, req, plan, events=None, on=None, **kw):
    """apply_plan with every requirement met unless kw overrides one. on: {(step, status):
    fn(session)} called from the progress callback (between or during steps)."""
    seen = events if events is not None else []

    def progress(step_id, status, text):
        seen.append((step_id, status, text))
        for (sid, st), fn in (on or {}).items():
            if (sid, st) == (step_id, status):
                fn(s)
    args = dict(password=PW, confirm=PW, confirmation=confirmation_phrase(plan),
                approvals={x.step_id for x in approvals_needed(plan)}, progress=progress)
    args.update(kw)
    return apply_plan(s, plan, r, req, **args)


def statuses(res):
    return {x.step_id: x.status for x in res.steps}


def everything(res, session=None, events=()):
    """All text a result (and the session's records) could show anyone."""
    parts = [repr(res), res.message] + res.problems + res.recovery + res.commands_sent
    for rec in res.steps + res.invariants:
        parts += [rec.reply, repr(rec)] + rec.reasons + rec.commands + list(rec.checks.values())
    parts += [str(e) for e in events]
    if session is not None:
        parts += [repr(session), str(session.config_sent), str(session.sent),
                  str(session.partial_output)]
    return '\n'.join(str(p) for p in parts)


def nothing_sent(s, before):
    assert s.config_sent == []
    assert s.device.running_config() == before


# ---------------------------------------------------------------- guards (pure)
@pytest.mark.parametrize('line', [
    'write memory', 'write', 'copy running-config startup-config', 'reload', 'erase nvram:',
    'delete flash:x', 'format flash:', 'boot system flash:x', 'do write memory',
    'configure terminal', 'exit', 'end', 'no username netadmin', 'crypto key zeroize rsa',
    'aaa new-model', 'enable secret x', 'default interface Gi0/0',
    'hostname R1\nwrite memory', 'hostname R1\rwrite', 'hostname R1 | redirect flash:x',
    'hostname R1 > flash:x', 'hostname ?', '', '   ', 'hostname R\x03'])
def test_dangerous_or_malformed_lines_are_refused(line):
    with pytest.raises(ConsoleError) as err:
        check_config_line(line)
    assert err.value.kind == REFUSED and 'nothing was sent' in str(err.value)


def test_plan_lines_pass_and_only_allowed_lines_are_accepted():
    for line in ('hostname Edge-R1', 'ip domain-name lab.local', USER_LINE,
                 'crypto key generate rsa modulus 2048', 'ip ssh version 2', 'line vty 0 4',
                 'login local', 'transport input ssh'):
        assert check_config_line(line) == line
    with pytest.raises(ConsoleError, match='not part of the approved plan'):
        check_config_line('hostname Other', allowed={'hostname Edge-R1'})


def test_write_is_refused_even_if_a_plan_listed_it():
    s = open_mock('SIM8')
    with pytest.raises(ConsoleError):
        s.allow_config(['hostname Edge-R1', 'write memory'])
    s.allow_config(['hostname Edge-R1'])
    s.enter_config()
    for line in ('write memory', 'copy running-config startup-config', 'reload', 'hostname X'):
        with pytest.raises(ConsoleError) as err:
            s.send_config_line(line)
        assert err.value.kind == REFUSED
    assert s.config_sent == ['configure terminal']


def test_secret_values_are_checked_and_masked():
    for bad in ('', 'has?mark', 'line\nbreak', 'tab\there', None):
        with pytest.raises(ConsoleError):
            check_secret(bad)
    assert mask_text(f'username a secret {PW}', [PW]) == 'username a secret ********'


@pytest.mark.parametrize('text, state', [
    ('hostname X\nX(config)#', PROMPT), ('end\nR1#', PROMPT), ('x\nR1(config-line)#', PROMPT),
    ('enable\nRouter>', PROMPT),
    ('% Do you really want to replace them? [yes/no]: ', QUESTION),
    ('How many bits in the modulus [512]: ', QUESTION),
    ('Destination filename [startup-config]? ', QUESTION),
    ('Proceed with reload? [confirm]', QUESTION),
    ('enable\nPassword: ', PASSWORD_PROMPT), ('x\nrommon 2 > ', BOOT_LOADER),
    ('x\nswitch: ', BOOT_LOADER), ('hostname X\nEdg', None), ('', None),
    ('The name for the keys will be: R1.lab.local\n', None)])
def test_reply_classification(text, state):
    assert classify_reply(text)[0] == state


# ---------------------------------------------------------------- SIM8: the normal case
def test_factory_router_full_setup_is_verified_step_by_step():
    s, r, req, plan = prepare('SIM8', hostname='Edge-R1', domain='lab.local')
    startup, saves = s.device.startup, s.device.saves
    events = []
    res = run(s, r, req, plan, events=events)
    assert res.outcome == A.SUCCESS and not res.problems
    assert set(statuses(res).values()) == {VERIFIED}
    assert [i.status for i in res.invariants] == [VERIFIED]          # AAA unchanged
    fd = res.final_detection
    assert fd is not None and fd.complete and fd.device.hostname == 'Edge-R1'
    assert fd.ssh.status == detect.SshCapability.SUPPORTED_ENABLED
    # one configuration session per step, each closed with end, in plan order
    config_steps = [x for x in plan.steps if x.command is not None]
    assert s.config_sent.count('configure terminal') == len(config_steps)
    assert s.config_sent.count('end') == len(config_steps)
    assert s.config_sent == res.commands_sent
    assert USER_LINE in s.config_sent                    # the template, never the value
    # D3: nothing saved; D2: no IP address, no interface
    assert s.device.startup == startup and s.device.saves == saves
    assert not any(c.startswith(SAVE_WORDS) for c in s.config_sent + s.sent)
    assert not any(c.startswith(('interface', 'ip address')) for c in s.config_sent)
    assert res.saved is False and 'Nothing was saved' in res.message
    # the device got the REAL password (its stored hash), the record never did
    assert f'username netadmin privilege 15 secret 5 $1$mock${_scramble(PW)}' in \
        s.device.global_lines
    assert PW not in everything(res, s, events)
    # each step was verified only by its own show commands
    assert res.step('rsa').checks and all(c.startswith('show ') for c in res.checks_run)


def test_each_step_is_verified_before_the_next_starts():
    s, r, req, plan = prepare('SIM8', hostname='Edge-R1', domain='lab.local')
    events = []
    run(s, r, req, plan, events=events)
    order = [(sid, st) for sid, st, _ in events if sid in {x.step_id for x in plan.steps}]
    for a, b in zip(plan.steps, plan.steps[1:]):
        assert order.index((a.step_id, VERIFIED)) < order.index((b.step_id, 'running'))


# ---------------------------------------------------------------- refusals send nothing
def test_stale_plan_sends_nothing():
    s, r, req, plan = prepare('SIM8', hostname='Edge-R1', domain='lab.local')
    before = s.device.running_config()
    res = run(s, r, req, plan, stale_reason='The values entered were changed.')
    assert res.outcome == A.REFUSED and 'out of date' in res.message
    nothing_sent(s, before)
    r2 = detect_device(s)                                   # a newer detection exists
    res = run(s, r2, req, plan)
    assert res.outcome == A.REFUSED and 'detected again' in res.message
    nothing_sent(s, before)


@pytest.mark.parametrize('confirmation', ['', 'APPLY SSH', 'apply ssh Router',
                                          'APPLY SSH Edge-R1', 'APPLY SSH Router!'])
def test_missing_or_wrong_typed_confirmation_sends_nothing(confirmation):
    s, r, req, plan = prepare('SIM8', hostname='Edge-R1', domain='lab.local')
    before = s.device.running_config()
    res = run(s, r, req, plan, confirmation=confirmation)
    assert res.outcome == A.REFUSED and 'APPLY SSH Router' in res.message
    nothing_sent(s, before)


def test_missing_disruptive_approval_sends_nothing():
    s, r, req, plan = prepare('SIM10')                     # Telnet+SSH -> SSH only: disruptive
    needed = [x.step_id for x in approvals_needed(plan)]
    assert needed == ['vty_transport[0 4]']
    before = s.device.running_config()
    res = run(s, r, req, plan, approvals=set())
    assert res.outcome == A.REFUSED and 'cut off current users' in res.message
    nothing_sent(s, before)
    res = run(s, r, req, plan)                             # approved: it runs
    assert res.outcome == A.SUCCESS


@pytest.mark.parametrize('password, confirm', [('', ''), (PW, 'Different-Pass1'),
                                               ('short', 'short'), ('bad?pass1', 'bad?pass1')])
def test_password_must_be_typed_again_correctly(password, confirm):
    s, r, req, plan = prepare('SIM8', hostname='Edge-R1', domain='lab.local')
    before = s.device.running_config()
    res = run(s, r, req, plan, password=password, confirm=confirm)
    assert res.outcome == A.REFUSED and 'password' in res.message.lower()
    nothing_sent(s, before)
    for secret in (password, confirm):
        if len(secret) >= 6:
            assert secret not in everything(res, s)


def test_closed_session_sends_nothing():
    s, r, req, plan = prepare('SIM8', hostname='Edge-R1', domain='lab.local')
    s.disconnect()
    res = run(s, r, req, plan)
    assert res.outcome == A.REFUSED and s.config_sent == []


def test_privilege_below_15_sends_nothing():
    s, r, req, plan = prepare('SIM8', hostname='Edge-R1', domain='lab.local')
    real = s.send_show
    s.send_show = lambda c, timeout=None: ('Current privilege level is 1'
                                           if c == detect.SHOW_PRIVILEGE else real(c, timeout))
    before = s.device.running_config()
    res = run(s, r, req, plan)
    assert res.outcome == A.REFUSED and 'privilege level 1' in res.message
    nothing_sent(s, before)


def test_device_changed_after_the_preview_sends_nothing():
    s, r, req, plan = prepare('SIM8', hostname='Edge-R1', domain='lab.local')
    s.device.global_lines.append('ip domain-name other.local')     # someone else changed it
    before = s.device.running_config()
    res = run(s, r, req, plan)
    assert res.outcome == A.REFUSED and 'changed since the preview' in res.message
    nothing_sent(s, before)


def test_aaa_changed_after_the_preview_sends_nothing():
    s, r, req, plan = prepare('SIM8', hostname='Edge-R1', domain='lab.local')
    s.device.global_lines.append('aaa new-model')
    before = s.device.running_config()
    res = run(s, r, req, plan)
    assert res.outcome == A.REFUSED
    nothing_sent(s, before)


def test_a_refused_apply_only_reads():
    s, r, req, plan = prepare('SIM8', hostname='Edge-R1', domain='lab.local')
    sent = len(s.sent)
    run(s, r, req, plan, confirmation='nope')
    assert s.sent[sent:] == []                             # not even a show command
    s.device.global_lines.append('ip domain-name other.local')
    run(s, r, req, plan)
    assert all(c.startswith('show ') for c in s.sent[sent:])


# ---------------------------------------------------------------- B1: enable without a password
def test_enable_without_password_on_a_factory_router():
    s = open_mock(scenario_port('enable-no-password'), enable_without_password=True)
    assert s.find_prompt() == 'Router>'
    assert s.enable() == 'Router#'
    assert s.sent == ['enable']
    r = detect_device(s)
    assert r.access.privilege_level == 15


def test_enable_without_password_needs_the_option():
    s = open_mock(scenario_port('enable-no-password'))
    with pytest.raises(ConsoleError) as err:
        s.enable()
    assert err.value.kind == AUTH and s.sent == []


def test_enable_password_prompt_is_never_answered():
    s = open_mock(scenario_port('enable-password-prompt'), enable_without_password=True)
    cli = s.cli
    with pytest.raises(ConsoleError) as err:
        s.enable()
    assert err.value.kind == AUTH and 'did not answer' in str(err.value)
    assert s.sent == ['enable'] and not s.is_active()
    assert cli.pending is not None                          # still waiting at "Password:"
    assert cli.prompt() == 'R39>'


def test_detection_with_bare_enable_reports_the_password_prompt():
    s = open_mock(scenario_port('enable-password-prompt'), enable_without_password=True)
    r = detect_device(s, elevate=True)
    assert any('did not answer' in w for w in r.warnings)
    assert not r.complete or r.access.privilege_level != 15
    assert not build_plan(r).available


# ---------------------------------------------------------------- D1: questions never answered
def test_rsa_replace_question_stops_without_an_answer():
    def hide_keys(s):                                       # SIM20 keys appear after detection
        s.device.rsa_keys = False
    s, r, req, plan = prepare('SIM20', before_detect=hide_keys)
    rsa = 'crypto key generate rsa modulus 2048'
    assert rsa in [x.command.text for x in plan.steps if x.command]
    s.console = {'keys_appear_on': rsa}
    cli = s.cli
    res = run(s, r, req, plan)
    st = statuses(res)
    assert st['rsa'] == UNCERTAIN and res.outcome == A.INCOMPLETE
    assert any('Do you really want to replace them' in x and 'NOT answered' in x
               for x in res.step('rsa').reasons)
    assert cli.pending is not None                          # the device is still asking
    assert s.config_sent[-1] == rsa and not s.is_active()   # nothing after the question
    assert 'ssh_version' not in st                         # SIM20 already has version 2
    assert st['ssh_ready'] == BLOCKED
    assert any('NetCommand never answers device questions' in x for x in res.recovery)
    assert res.final_detection is None and res.invariants == []


def test_modulus_question_stops_without_an_answer():
    s, r, req, plan = prepare('SIM21')
    rsa = 'crypto key generate rsa modulus 2048'
    s.console = {'modulus_question_on': rsa}
    cli = s.cli
    res = run(s, r, req, plan)
    assert statuses(res)['rsa'] == UNCERTAIN
    assert any('How many bits in the modulus' in x for x in res.step('rsa').reasons)
    assert cli.pending is not None and not s.is_active()
    assert not cli.dev.rsa_keys                            # nothing was generated


def test_sim21_with_the_planned_size_asks_nothing():
    s, r, req, plan = prepare('SIM21')
    res = run(s, r, req, plan)
    assert res.outcome == A.SUCCESS and statuses(res)['rsa'] == VERIFIED


# ---------------------------------------------------------------- edge-case scenarios
def test_sim18_slow_key_generation_is_waited_for():
    s, r, req, plan = prepare('SIM18')
    res = run(s, r, req, plan)
    assert res.outcome == A.SUCCESS and statuses(res)['rsa'] == VERIFIED


def test_sim19_rsa_failure_blocks_its_dependents():
    s, r, req, plan = prepare('SIM19')
    res = run(s, r, req, plan)
    st = statuses(res)
    assert st['user'] == VERIFIED and st['rsa'] == FAILED
    assert 'RSA key generation failed' in ' '.join(res.step('rsa').reasons)
    assert st['ssh_version'] == BLOCKED and st['ssh_ready'] == BLOCKED
    assert res.outcome == A.FAILURE and res.blocked == ['ssh_version', 'ssh_ready']
    assert [i.status for i in res.invariants] == [VERIFIED]  # still checked: console is fine
    assert res.final_detection is not None


def test_sim24_incomplete_key_output_is_uncertain():
    s, r, req, plan = prepare('SIM24')
    res = run(s, r, req, plan)
    assert statuses(res)['rsa'] == UNCERTAIN and res.outcome == A.INCOMPLETE


def test_sim25_stale_prompt_after_rename_is_read_again():
    s, r, req, plan = prepare('SIM25', hostname='R25-new')
    res = run(s, r, req, plan)
    assert res.outcome == A.SUCCESS
    assert A.REFRESH in res.step('hostname').commands
    assert any('showed "R25(config)#" once' in x for x in res.step('hostname').reasons)
    assert res.final_detection.device.hostname == 'R25-new'


def test_sim26_cut_off_prompt_stops_as_uncertain():
    s, r, req, plan = prepare('SIM26', hostname='R26-new')
    res = run(s, r, req, plan)
    st = statuses(res)
    assert st['hostname'] == UNCERTAIN and not s.is_active()
    assert all(v in (BLOCKED, NOT_RUN) for k, v in st.items() if k != 'hostname')
    assert 'end' not in res.step('hostname').commands     # never left config blindly
    assert any('detect again' in x for x in res.recovery)


def test_sim27_rejected_domain_fails_and_blocks_keys():
    s, r, req, plan = prepare('SIM27', domain='lab.local')
    res = run(s, r, req, plan)
    st = statuses(res)
    assert st['domain'] == FAILED and st['rsa'] == BLOCKED
    assert 'Invalid input' in ' '.join(res.step('domain').reasons)
    assert s.is_active()                                    # left config mode normally
    assert res.step('domain').commands[-1] == 'end'


def test_sim28_ssh_v2_accepted_but_not_effective_fails():
    s, r, req, plan = prepare('SIM28')
    res = run(s, r, req, plan)
    st = statuses(res)
    assert st['ssh_version'] == FAILED and st['ssh_ready'] == BLOCKED
    assert 'not 2.0' in ' '.join(res.step('ssh_version').reasons)


def test_sim29_ssh_v2_rejected_fails():
    s, r, req, plan = prepare('SIM29')
    res = run(s, r, req, plan)
    assert statuses(res)['ssh_version'] == FAILED
    assert 'rejected' in ' '.join(res.step('ssh_version').reasons)


def test_sim33_log_messages_do_not_change_conclusions():
    s, r, req, plan = prepare('SIM33', hostname='R33-new')
    res = run(s, r, req, plan)
    assert res.outcome == A.SUCCESS
    assert any('%LINK' in x.reply or '%LINEPROTO' in x.reply for x in res.steps)


def _quiet(s):
    s.console = {}                                          # no event during detection


@pytest.mark.parametrize('event', ['timeout_on', 'partial_timeout_on'])
def test_sim34_35_timeout_on_a_configuration_line(event):
    s, r, req, plan = prepare(scenario_port('console-timeout' if event == 'timeout_on'
                                            else 'console-partial-timeout'), before_detect=_quiet)
    s.console = {event: USER_LINE}
    res = run(s, r, req, plan)
    assert statuses(res)['user'] == UNCERTAIN and not s.is_active()
    assert res.final_detection is None and res.invariants == []
    assert any('whether the last line took effect is not known' in x.lower()
               for x in res.recovery)
    assert PW not in everything(res, s)


def test_sim35_partial_output_of_a_check_is_never_used():
    s, r, req, plan = prepare(scenario_port('console-partial-timeout'), before_detect=_quiet)
    res = run(s, r, req, plan, on={('user', 'running'): lambda m: m.console.update(
        {'partial_timeout_on': detect.SHOW_USERNAMES})})
    assert statuses(res)['user'] == UNCERTAIN
    assert s.partial_output and res.step('user').checks == {}
    assert PW not in everything(res, s)


def test_sim36_boot_loader_on_a_configuration_line():
    s, r, req, plan = prepare(scenario_port('console-unexpected-prompt'), before_detect=_quiet)
    s.console = {'unexpected_prompt_on': USER_LINE}
    res = run(s, r, req, plan)
    assert statuses(res)['user'] == UNCERTAIN
    assert any('boot-loader' in x for x in res.step('user').reasons)
    assert any('boot loader' in x for x in res.recovery)
    assert not s.is_active() and s.config_sent[-1] == USER_LINE


def test_sim37_cable_pulled_on_a_configuration_line():
    s, r, req, plan = prepare(scenario_port('console-interrupted'), before_detect=_quiet)
    s.console = {'unplug_on': USER_LINE}
    res = run(s, r, req, plan)
    assert statuses(res)['user'] == UNCERTAIN and not s.is_active()
    assert any('unplugged' in x for x in res.step('user').reasons)


def test_sim34_timeout_during_a_verification_check():
    s, r, req, plan = prepare(scenario_port('console-timeout'), before_detect=_quiet)
    res = run(s, r, req, plan, on={('user', 'running'): lambda m: m.console.update(
        {'timeout_on': detect.SHOW_USERNAMES})})
    rec = res.step('user')
    assert rec.status == UNCERTAIN and any('did not run' in x for x in rec.reasons)


# ---------------------------------------------------------------- AAA, cancel, blocking
def test_aaa_invariant_failure_is_reported():
    s, r, req, plan = prepare('SIM8', hostname='Edge-R1', domain='lab.local')
    last = plan.steps[-1].step_id
    res = run(s, r, req, plan, on={(last, VERIFIED): lambda m: m.device.global_lines.append(
        'aaa new-model')})
    assert set(statuses(res).values()) == {VERIFIED}
    assert [i.status for i in res.invariants] == [FAILED]
    assert res.outcome == A.FAILURE and res.recovery[0].startswith('AAA IS NOT AS IT WAS')


def test_cancel_takes_effect_only_between_steps():
    s, r, req, plan = prepare('SIM8', hostname='Edge-R1', domain='lab.local')
    cancel = threading.Event()
    res = run(s, r, req, plan, cancel=cancel,
              on={('domain', 'running'): lambda m: cancel.set()})   # asked DURING a step
    st = statuses(res)
    assert st['hostname'] == VERIFIED and st['domain'] == VERIFIED    # that step finished
    assert res.step('domain').commands[-1] == 'end'
    assert all(st[x.step_id] == NOT_RUN for x in plan.steps[2:])
    assert all('cancelled' in res.step(x.step_id).reasons[0] for x in plan.steps[2:])
    assert res.outcome == A.CANCELLED and res.cancelled
    assert [i.status for i in res.invariants] == [VERIFIED]           # still checked


def test_verification_failure_blocks_dependents_transitively():
    # the command is accepted, but its read-only check shows another hostname: FAILED,
    # and everything that needs it (directly or through other steps) is BLOCKED
    s2, r2, req2, plan2 = prepare('SIM8', hostname='Edge-R1', domain='lab.local')
    real = s2.send_show

    def show(c, timeout=None):
        if c == detect.SHOW_HOSTNAME and s2.config_sent.count('end') == 1:
            return 'hostname Other'
        return real(c, timeout)
    s2.send_show = show
    res = run(s2, r2, req2, plan2)
    st = statuses(res)
    assert st['hostname'] == FAILED
    for step in plan2.steps[1:]:
        expected = BLOCKED if step.step_id in ('rsa', 'ssh_version', 'ssh_ready',
                                               'vty_transport[0 4]') else NOT_RUN
        assert st[step.step_id] == expected, step.step_id


def test_steps_already_verified_stay_in_effect_and_are_listed():
    s, r, req, plan = prepare('SIM19')
    res = run(s, r, req, plan)
    assert 'Verified: user' in res.message
    assert any('VERIFIED are in effect in the running configuration' in x for x in res.recovery)


# ---------------------------------------------------------------- secrets
def test_password_never_appears_even_when_the_device_echoes_it():
    s, r, req, plan = prepare('SIM8', hostname='Edge-R1', domain='lab.local')
    logs = []
    s._log = lambda kind, text: logs.append((kind, text))
    events = []
    res = run(s, r, req, plan, events=events)
    rec = res.step('user')
    assert 'secret ********' in rec.reply                  # the echo, masked
    assert PW not in everything(res, s, events) and PW not in str(logs)
    assert PW not in repr(res.final_detection.to_dict())


def test_password_never_appears_in_errors():
    s, r, req, plan = prepare(scenario_port('console-interrupted'), before_detect=_quiet)
    s.console = {'unplug_on': USER_LINE}
    res = run(s, r, req, plan)
    assert PW not in everything(res, s)


def test_apply_module_has_no_network_access_and_never_saves():
    source = open(A.__file__, encoding='utf-8').read()
    for word in ('ConnectHandler', 'paramiko', 'socket', 'save_config', "'write memory'",
                 'copy running-config', 'ip address'):
        assert word not in source, word
