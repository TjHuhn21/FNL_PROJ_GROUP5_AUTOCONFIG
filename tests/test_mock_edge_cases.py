"""Mock-lab edge cases for future console configuration work (phase 5.1.1).

Everything here is SIMULATED and offline. Detection runs through MockConsoleSession (show
commands only). Where a configuration reply is needed, the TEST types into the mock
lab's own simulated CLI (mocklab.cli.Session) - not through any NetCommand path - and
feeds the text to the pure step evaluators (console.steps). Nothing in NetCommand sends
a configuration command; no real port or device is used; no delay really sleeps.
"""
import os
import sys
import time
from dataclasses import asdict

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path[:0] = [ROOT, os.path.join(ROOT, 'mock-lab'), os.path.dirname(__file__)]

from console import detect, link  # noqa: E402
from console.detect import SshCapability, detect_device  # noqa: E402
from console.plan import build_plan, validate_request  # noqa: E402
from console.steps import FAILED, UNCERTAIN, VERIFIED, readiness  # noqa: E402
from mocklab.cli import Session  # noqa: E402
from mocklab.console import (ALL_SCENARIOS, EDGE_SCENARIOS, SCENARIOS,  # noqa: E402
                             SCENARIO_IDS, MockConsoleBackend, device_spec, scenario_port)
from mocklab.device import QUIRKS, SYSLOG_LINES, Device  # noqa: E402
from mocklab.lab import Lab, LabError, check_config  # noqa: E402

PASSWORD = 'Str0ng-Pass!'
SHOW_RSA, SHOW_IP_SSH = detect.SHOW_RSA, detect.SHOW_IP_SSH


def session_for(identifier_or_port, quirks=None):
    port = SCENARIO_IDS.get(identifier_or_port, identifier_or_port)
    s = MockConsoleBackend(delay=0, edge_cases=True).open_session(port, 9600, '', '', '', None)
    if quirks is not None:
        s.device.quirks = set(quirks)
    s.connect()
    return s


def detected(identifier, quirks=None):
    s = session_for(identifier, quirks)
    before = s.device.running_config()
    result = detect_device(s)
    if s.cli is not None:
        assert s.device.running_config() == before                # detection changed nothing
    assert set(s.sent) <= set(detect.DETECTION_COMMANDS)
    return result, s


def plan_for(identifier, username='', **values):
    r, _ = detected(identifier)
    pw = PASSWORD if username else ''
    req, errors = validate_request(username=username, password=pw, confirm=pw, key_size=2048,
                                   result=r, **values)
    assert not errors, list(errors)
    return build_plan(r, req)


def simulated_cli(identifier):
    """The mock device's own CLI in configuration mode (test-only simulation)."""
    dev = Device(device_spec(scenario_port(identifier) if identifier in SCENARIO_IDS
                             else identifier))
    cli = Session(dev)
    cli.handle('configure terminal')
    return dev, cli


def shows(cli, *commands):
    """Read-only checks, from privileged EXEC mode (leaves configuration mode first)."""
    if cli.mode not in ('user', 'exec'):
        cli.handle('end')
    return {c: cli.handle(c).output for c in commands}


# ================================================================== catalogue
def test_every_edge_scenario_has_a_unique_identifier():
    ids = [s['id'] for s in EDGE_SCENARIOS.values()]
    assert len(ids) == len(set(ids)) and all(ids)
    for identifier, port in SCENARIO_IDS.items():
        assert port in ALL_SCENARIOS and scenario_port(identifier) == port


def test_default_port_list_is_unchanged_and_edge_cases_are_opt_in():
    assert [p.device for p in MockConsoleBackend().discover_ports().ports] == list(SCENARIOS)
    assert len(SCENARIOS) == 19              # SIM47 / SIM48: brand-new switch and router
    edge = [p.device for p in MockConsoleBackend(edge_cases=True).discover_ports().ports]
    assert edge == list(SCENARIOS) + list(EDGE_SCENARIOS)
    with pytest.raises(ValueError):
        MockConsoleBackend().open_session('SIM18', 9600, '', '', '', None)


def test_unknown_quirks_are_refused():
    with pytest.raises(ValueError):
        Device(dict(device_spec('SIM2'), quirks=['made_up']))
    with pytest.raises(LabError):
        check_config({'devices': [dict(device_spec('SIM2'), quirks=['made_up'])]})
    assert set(QUIRKS) >= {'rsa_slow', 'syslog', 'legacy_ssh_only'}


# phase 5.1.6: SIM40-SIM46 describe the console BEFORE connecting (silent, startup prompts,
# unsafe states); they are covered by tests/test_console_preflight.py, not by detection
@pytest.mark.parametrize('port', [p for p, s in EDGE_SCENARIOS.items()
                                  if s['preflight'] == 'prompt'])
def test_every_edge_scenario_is_simulated_deterministic_and_fast(port):
    started = time.monotonic()
    r, _ = detected(port)
    assert time.monotonic() - started < 3                         # no real delays
    assert r.simulated and r.warnings[0] == detect.SIMULATION_WARNING
    again, _ = detected(port)
    assert (again.ssh.status, again.complete) == (r.ssh.status, r.complete)


# ================================================================== RSA key generation
def test_slow_key_generation_is_simulated_not_slept():
    plan = plan_for('rsa-slow')
    rsa = plan.step('rsa')
    dev, cli = simulated_cli('rsa-slow')
    started = time.monotonic()
    reply = cli.handle(rsa.command.text)
    assert time.monotonic() - started < 0.5
    assert reply.delay_s == 45.0 and cli.simulated_seconds == 45.0
    assert 'up to a minute' in rsa.prompt.note
    assert rsa.evaluate(shows(cli, SHOW_RSA, SHOW_IP_SSH), reply=reply.output)[0] == VERIFIED


def test_failed_key_generation_is_failed():
    rsa = plan_for('rsa-fails').step('rsa')
    dev, cli = simulated_cli('rsa-fails')
    reply = cli.handle(rsa.command.text)
    assert 'failed (SIMULATED)' in reply.output and not dev.rsa_keys
    assert rsa.evaluate(shows(cli, SHOW_RSA, SHOW_IP_SSH), reply=reply.output)[0] == FAILED


def test_existing_key_asks_to_replace_and_is_never_answered():
    plan = plan_for('rsa-replace-question')
    assert not any('crypto' in c.text for c in plan.commands)     # never proposed: keys exist
    rsa_step = plan_for('rsa-slow').step('rsa')
    dev, cli = simulated_cli('rsa-replace-question')
    label = dev.rsa_label
    reply = cli.handle('crypto key generate rsa modulus 2048')
    assert reply.raw and 'Do you really want to replace them? [yes/no]' in reply.output
    assert cli.pending is not None                                # waiting: the mock never answers
    assert rsa_step.evaluate({}, reply=reply.output)[0] == UNCERTAIN
    # whatever is typed next is taken as the answer: a later command must never be sent
    cli.handle('end')
    assert dev.rsa_keys and dev.rsa_label == label                # "end" was not "yes": kept


def test_key_size_question_appears_only_without_a_size():
    plan = plan_for('rsa-modulus-question')
    assert 'crypto key generate rsa modulus 2048' in plan.text()  # the plan always gives a size
    dev, cli = simulated_cli('rsa-modulus-question')
    reply = cli.handle('crypto key generate rsa')
    assert reply.raw and reply.output.rstrip().endswith('How many bits in the modulus [512]:')
    assert plan.step('rsa').evaluate({}, reply=reply.output)[0] == UNCERTAIN
    dev2, cli2 = simulated_cli('rsa-modulus-question')
    assert '[OK]' in cli2.handle('crypto key generate rsa modulus 2048').output


@pytest.mark.parametrize('identifier, message, blocker', [
    ('rsa-missing-hostname', '% Please define a hostname other than Router.', 'hostname'),
    ('rsa-missing-domain', '% Please define a domain-name first.', 'domain name'),
])
def test_prerequisite_errors(identifier, message, blocker):
    plan = plan_for(identifier)
    assert plan.item('rsa').status == 'needs_attention' and blocker in plan.item('rsa').explanation
    assert not any('crypto' in c.text for c in plan.commands)
    dev, cli = simulated_cli(identifier)
    reply = cli.handle('crypto key generate rsa modulus 2048')
    assert reply.output == message and not dev.rsa_keys
    rsa_step = plan_for('rsa-slow').step('rsa')
    assert rsa_step.evaluate({}, reply=reply.output)[0] == FAILED


def test_prerequisites_ordered_before_keys_once_supplied():
    plan = plan_for('rsa-missing-hostname', hostname='Edge-R22')
    assert [s.step_id for s in plan.steps][:2] == ['hostname', 'rsa']
    assert plan.step('rsa').requires == ('hostname',)


def test_incomplete_key_generation_output_is_uncertain():
    plan = plan_for('rsa-partial')
    rsa = plan.step('rsa')
    dev, cli = simulated_cli('rsa-partial')
    reply = cli.handle(rsa.command.text)
    assert '[OK]' not in reply.output
    outputs = shows(cli, SHOW_RSA, SHOW_IP_SSH)
    assert detect.parse_rsa(outputs[SHOW_RSA]) is None              # listing unreadable
    assert rsa.evaluate(outputs, reply=reply.output)[0] == UNCERTAIN
    ready = readiness(plan.steps, {'rsa': UNCERTAIN})
    assert not ready['ssh_version'][0] and not ready['ssh_ready'][0]


# ================================================================== hostname and domain
def test_prompt_changes_after_a_rename():
    dev, cli = simulated_cli('SIM2')
    cli.handle('hostname Edge-R2')
    assert cli.prompt() == 'Edge-R2(config)#'


def test_old_prompt_is_shown_once_after_a_rename():
    plan = plan_for('prompt-lag', hostname='Edge-R25')
    step = plan.step('hostname')
    dev, cli = simulated_cli('prompt-lag')
    cli.handle(step.command.text)
    first, second = cli.prompt(), cli.prompt()
    assert first == 'R25(config)#' != step.prompt.prompt_after        # the stale prompt
    assert second == step.prompt.prompt_after == 'Edge-R25(config)#'
    assert step.evaluate(shows(cli, detect.SHOW_HOSTNAME))[0] == VERIFIED


def test_cut_off_prompt_is_not_a_valid_prompt():
    dev, cli = simulated_cli('prompt-garbled')
    cli.handle('hostname Edge-R26')
    garbled = cli.prompt()
    assert garbled == 'Edg' and not link._PROMPT.match(garbled)     # prompt detection fails
    assert link._PROMPT.match(cli.prompt())                         # then normal again


def test_rejected_domain_name():
    plan = plan_for('domain-rejected', domain_name='lab.local')
    step = plan.step('domain')
    dev, cli = simulated_cli('domain-rejected')
    reply = cli.handle(step.command.text)
    assert '% Invalid input' in reply.output
    assert step.evaluate(shows(cli, detect.SHOW_DOMAIN), reply=reply.output)[0] == FAILED
    assert step.evaluate(shows(cli, detect.SHOW_DOMAIN))[0] == FAILED  # also without the reply


# ================================================================== SSH
def test_ssh_v2_accepted_but_still_1_99():
    plan = plan_for('ssh-v2-ignored')
    step = plan.step('ssh_version')
    dev, cli = simulated_cli('ssh-v2-ignored')
    reply = cli.handle('ip ssh version 2')
    assert reply.output == ''                                       # accepted
    out = shows(cli, SHOW_IP_SSH, detect.SHOW_SSH_CONFIG)
    assert 'ip ssh version 2' in out[detect.SHOW_SSH_CONFIG]       # in the configuration...
    assert 'version 1.99' in out[SHOW_IP_SSH]                       # ...but not in effect
    assert step.evaluate(out, reply=reply.output)[0] == FAILED


def test_ssh_v2_rejected():
    plan = plan_for('ssh-v2-rejected')
    dev, cli = simulated_cli('ssh-v2-rejected')
    cli.handle(plan.step('rsa').command.text)
    reply = cli.handle('ip ssh version 2')
    assert 'SIMULATED rejection' in reply.output
    assert 'ip ssh version 2' not in dev.global_lines
    assert plan.step('ssh_version').evaluate(shows(cli, SHOW_IP_SSH), reply=reply.output)[0] \
        == FAILED


def test_keys_exist_but_ssh_disabled():
    plan = plan_for('ssh-keys-but-disabled')
    assert plan.item('rsa').status == 'needs_attention'
    assert not any('crypto' in c.text for c in plan.commands)


@pytest.fixture
def key_path(tmp_path):
    return str(tmp_path / 'host_rsa.key')


def lab_for(port, key_path):
    spec = dict(device_spec(port), host='127.0.0.1')
    return Lab({'devices': [spec]}, key_path=key_path,
               overrides={spec['name']: ('127.0.0.1', 0)}).start()


def connect(lab, name, **options):
    from netmiko import ConnectHandler
    host, port = lab.address(name)
    return ConnectHandler(device_type='cisco_ios', host=host, port=port, username='sim',
                          password='sim', conn_timeout=3, auth_timeout=3, banner_timeout=3,
                          **options)


def test_ssh_enabled_but_not_reachable_over_ethernet(key_path):
    import ssh_options
    r, _ = detected('ssh-ethernet-unavailable')
    assert r.ssh.status == SshCapability.SUPPORTED_ENABLED          # the console says SSH is on
    lab = lab_for(scenario_port('ssh-ethernet-unavailable'), key_path)
    try:
        with pytest.raises(Exception) as err:
            connect(lab, 'R30', **ssh_options.connect_options('127.0.0.1'))
    finally:
        lab.stop()
    kind, message = ssh_options.describe_error(err.value, '127.0.0.1')
    assert kind != ssh_options.AUTH and 'sim' not in message


def test_legacy_only_ssh_server_needs_the_legacy_setting(key_path, monkeypatch):
    import ssh_options
    monkeypatch.setenv(ssh_options.SETTING, '')
    lab = lab_for(scenario_port('ssh-legacy-algorithms'), key_path)
    try:
        with pytest.raises(Exception) as err:
            connect(lab, 'R31', **ssh_options.connect_options('127.0.0.1'))
        kind, message = ssh_options.describe_error(err.value, '127.0.0.1')
        assert kind == ssh_options.ALGORITHMS and ssh_options.SETTING in message
        monkeypatch.setenv(ssh_options.SETTING, '127.0.0.1')
        conn = connect(lab, 'R31', **ssh_options.connect_options('127.0.0.1'))
        try:
            assert conn.find_prompt() == 'R31#'
        finally:
            conn.disconnect()
    finally:
        lab.stop()


# ================================================================== VTY
def test_ssh_only_transport_waits_for_verified_ssh():
    plan = plan_for('vty-ssh-not-verified')
    t = plan.step('vty_transport[0 4]')
    assert t.requires == ('ssh_ready',)
    dev, cli = simulated_cli('vty-ssh-not-verified')               # nothing generated yet
    outcome = plan.step('ssh_ready').evaluate(shows(cli, SHOW_IP_SSH))[0]
    assert outcome == FAILED
    assert not readiness(plan.steps, {'ssh_ready': outcome})['vty_transport[0 4]'][0]


def test_vty_aliases_cover_the_required_cases():
    r, _ = detected('vty-multiple-ranges')
    assert [(b.lines, b.login, b.transport_input, b.has_password) for b in r.vty.blocks] == [
        ('0 4', 'local', ['ssh'], False), ('5 15', 'line password', ['telnet'], True)]
    r, _ = detected('vty-uncovered-lines')
    assert r.vty.available_lines == 16 and r.vty.ranges == ['0 4']
    r, _ = detected('vty-login-local')
    assert r.vty.blocks[0].login == 'local'
    plan = plan_for('vty-different-settings', username='netadmin')
    assert [s.step_id for s in plan.steps if s.step_id.startswith('vty')] == [
        'vty_login[5 15]', 'vty_transport[5 15]']                   # vty 0 4 left alone


# ================================================================== console behaviour
IMPORTANT = lambda r: {                                            # noqa: E731
    'hostname': r.device.hostname, 'model': r.device.model, 'version': r.device.version,
    'image': r.device.image, 'privilege': r.access.privilege_level,
    'ssh_enabled': r.ssh.enabled, 'ssh_version': r.ssh.version, 'rsa': r.ssh.rsa.present,
    'keys': tuple(r.ssh.rsa.key_names) or None, 'domain': r.config.domain_name,
    'users': tuple(u.name for u in r.config.local_users) or None,
    'vty_ssh': r.vty.ssh_transport, 'vty_login': r.vty.login_configured,
    'management': r.management_interface}


def test_interleaved_log_lines_never_change_a_conclusion():
    noisy, s = detected('console-syslog')
    clean, _ = detected('console-syslog', quirks=[])
    # the log lines were really in the device's answers, and were removed before parsing
    assert s.device.quirks == {'syslog'}
    assert any('System log messages appeared' in w for w in noisy.warnings)
    assert not any(SYSLOG_LINES[0] in (c.output or '') for c in noisy.commands)
    assert IMPORTANT(noisy) == IMPORTANT(clean)                     # every conclusion the same
    assert noisy.ssh.status == clean.ssh.status == SshCapability.SUPPORTED_ENABLED
    assert noisy.vty.ssh_transport is True and noisy.complete


def test_interleaved_log_lines_do_not_fool_the_checks():
    _dev, cli = simulated_cli('console-syslog')
    out = shows(cli, SHOW_IP_SSH)[SHOW_IP_SSH]
    assert any(line in out for line in SYSLOG_LINES)                # a log line inside the output
    ready = plan_for('vty-ssh-not-verified').step('ssh_ready')
    assert ready.evaluate({SHOW_IP_SSH: out})[0] == VERIFIED


def test_command_timeout_keeps_earlier_results_only():
    r, s = detected('console-timeout')
    assert not r.complete and r.command(SHOW_IP_SSH).status == detect.FAILED
    assert r.ssh.status == SshCapability.UNKNOWN and r.device.model is not None
    assert all(c.status == detect.SKIPPED for c in r.commands[4:])
    assert not build_plan(r).available


def test_partial_output_before_a_timeout_is_never_used():
    r, s = detected('console-partial-timeout')
    assert s.partial_output and 'line vty' in s.partial_output
    vty = r.command(detect.SHOW_VTY)
    assert vty.status == detect.FAILED and vty.output is None
    assert r.vty.configured is None and not r.complete
    assert s.partial_output not in repr(asdict(r))


def test_unexpected_boot_loader_prompt_withholds_every_command():
    r, s = detected('console-unexpected-prompt')
    assert r.ssh.status == SshCapability.UNKNOWN
    assert any('show ip ssh' in w for w in r.warnings)
    plan = build_plan(r)
    assert not plan.available and plan.commands == [] and plan.steps == []
    assert s.find_prompt() == 'rommon 1 >' and not link._PROMPT.match(s.find_prompt())


def test_boot_loader_output_must_not_count_as_known_configuration():
    """Found by the phase 5.1.1 mock, fixed in 5.1.2: a boot-loader prompt answering a
    running-config search was read as an EMPTY search ("no accounts", ...)."""
    s = MockConsoleBackend(delay=0, edge_cases=True).open_session('SIM36', 9600, '', '', '', None)
    s.console = {'unexpected_prompt_on': 'show running-config | include username'}
    s.connect()
    r = detect_device(s)
    assert r.ssh.status == SshCapability.SUPPORTED_ENABLED       # read before the prompt
    assert not r.config.local_users_known
    assert not r.config.domain_known and not r.config.aaa_known
    assert r.vty.configured is None


def test_connection_lost_during_a_show_command():
    r, s = detected('console-interrupted')
    assert not r.complete and r.command(SHOW_RSA).status == detect.FAILED
    assert any('ended' in w for w in r.warnings)
    assert not s.is_active() and not build_plan(r).available


# ================================================================== secrets
def test_secrets_never_appear_in_simulated_output_or_results():
    dev, cli = simulated_cli('console-syslog')
    cli.handle('username ops privilege 15 secret Zq7-Secret-Value')
    out = cli.handle('show running-config | include username').output
    assert 'Zq7-Secret-Value' not in out                            # the mock stores a fake hash
    r, s = detected('console-syslog')
    dump = repr(asdict(r)) + repr(s.sent)
    assert '$1$mock$hidden' not in dump
    from config.connect import mask
    for port in EDGE_SCENARIOS:
        for line in device_spec(port)['global_lines']:
            if ' secret ' in line:
                assert mask(line).endswith('secret 5 ********')


# ================================================================== existing scenarios
@pytest.mark.parametrize('port', list(SCENARIOS))
def test_existing_scenarios_still_behave_the_same(port):
    s = MockConsoleBackend(delay=0).open_session(port, 9600, '', '', '', None)
    if SCENARIOS[port]['behaviour'] in ('refuse_login', 'no_answer'):
        return
    s.connect()
    r = detect_device(s)
    assert r.simulated and s.device.quirks == set()
