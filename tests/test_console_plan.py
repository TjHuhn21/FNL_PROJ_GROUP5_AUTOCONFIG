"""console.plan (SSH configuration PREVIEW) and the configuration facts detection reads for
it. Offline: devices are the mock lab's simulated consoles (mocklab.console) or scripted
detection results; nothing is executed and no port is opened."""
import copy
import os
import sys
from dataclasses import asdict

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path[:0] = [ROOT, os.path.join(ROOT, 'mock-lab')]

from console import detect, plan as P  # noqa: E402
from console.detect import (DETECTION_COMMANDS, LocalUser, SshCapability,  # noqa: E402
                            detect_device, parse_aaa, parse_domain, parse_local_users,
                            parse_ssh_config, parse_ssh_timers)
from console.plan import (ADD, ATTENTION, CONFIGURED, CONFLICT, MISSING, MODIFY,  # noqa: E402
                          PASSWORD_PLACEHOLDER, PREVIEW_NOTICE, UNKNOWN, UNSUPPORTED,
                          SetupRequest, build_plan, plan_is_stale, validate_request)
from mocklab.console import SCENARIOS, MockConsoleBackend  # noqa: E402

PASSWORD = 'Str0ng-Pass!'
CONFIG_WORDS = ('configure', 'hostname', 'username', 'crypto', 'ip ssh version', 'line vty',
                'login', 'transport', 'write', 'copy', 'ip domain')


def detected(port):
    """Detection of a simulated device; also returns the session (to see what was sent)."""
    session = MockConsoleBackend(delay=0).open_session(port, 9600, '', '', '', None)
    session.connect()
    before = session.device.running_config()
    result = detect_device(session)
    assert session.device.running_config() == before          # detection changed nothing
    return result, session


def request(result=None, **values):
    values.setdefault('key_size', 2048)
    req, errors = validate_request(result=result, **values)
    assert not errors, errors
    return req


def new_user(result, name='netadmin', **more):
    return request(result, username=name, password=PASSWORD, confirm=PASSWORD, **more)


def texts(plan):
    return [c.text for c in plan.commands]


# ------------------------------------------------------------------ detection: config facts
def test_parsers():
    users = parse_local_users('username admin privilege 15 secret 9 $9$x\n'
                              'username guest password 7 0822455D0A16\n')
    assert users == [LocalUser('admin', 15), LocalUser('guest', None)]
    assert parse_domain('ip domain-name lab.local') == 'lab.local'
    assert parse_domain('ip domain name corp.example\nip domain lookup') == 'corp.example'
    assert parse_domain('') is None
    assert parse_ssh_config('ip ssh version 2\nip ssh time-out 60') == (
        ['ip ssh version 2', 'ip ssh time-out 60'], '2')
    assert parse_aaa('aaa new-model\naaa authentication login default group tacacs+ local') == (
        True, {'default': 'group tacacs+ local'})
    assert parse_aaa('') == (False, {})
    assert parse_ssh_timers('Authentication timeout: 90 secs; Authentication retries: 2') == (90, 2)


def test_new_commands_are_read_only_show_commands():
    from console.link import check_show_command
    for command in (detect.SHOW_DOMAIN, detect.SHOW_SSH_CONFIG, detect.SHOW_AAA):
        assert command in DETECTION_COMMANDS and command in detect.CONFIG_COMMANDS
        assert check_show_command(command) == command


def test_detection_reads_the_ssh_related_configuration():
    r, session = detected('SIM9')
    c = r.config
    assert c.domain_name == 'lab.local' and c.domain_known
    assert c.ssh_version_configured == '2' and c.ssh_lines_known
    assert c.aaa_new_model is True and c.aaa_login_lists == {'default': 'local'}
    assert c.local_users == [LocalUser('labadmin', 15)] and c.local_users_known
    assert (c.ssh_timeout, c.ssh_retries) == (120, 3)
    assert r.detected_at is not None
    assert set(session.sent) <= set(DETECTION_COMMANDS)


def test_detection_never_keeps_secrets():
    r, _ = detected('SIM1')
    dump = repr(asdict(r))
    assert '$1$mock$hidden' not in dump
    out = r.command(detect.SHOW_USERNAMES).output
    assert '********' in out


def test_below_privilege_15_missing_lines_are_unknown():
    r, _ = detected('SIM2')
    r = copy.deepcopy(r)
    from console.detect import _read_config, _Runner
    answers = {detect.SHOW_DOMAIN: '', detect.SHOW_SSH_CONFIG: '', detect.SHOW_AAA: ''}

    class Session:
        def send_show(self, command, timeout=None):
            return answers[command]

        def is_active(self):
            return True
    r.access.privilege_level = 7
    r.config = detect.ConfigInfo()
    runner = _Runner(Session(), r, None, lambda t: None)
    users = detect.CommandResult(detect.SHOW_USERNAMES, detect.OK, output='')
    _read_config(r, runner, users, detect.CommandResult(detect.SHOW_IP_SSH, detect.FAILED))
    c = r.config
    assert not c.domain_known and not c.ssh_lines_known and not c.aaa_known
    assert c.aaa_new_model is None and not c.local_users_known
    assert any('below privilege level 15' in l for l in r.limitations)


# ------------------------------------------------------------------ the four SSH states
def test_ssh_enabled_and_complete_needs_nothing():
    r, _ = detected('SIM1')
    plan = build_plan(r, request(r))
    assert plan.available and plan.commands == [] and plan.lines() == []
    assert all(i.status == CONFIGURED for i in plan.items)
    assert plan.notice == PREVIEW_NOTICE


def test_ssh_supported_disabled_adds_keys_and_version():
    r, _ = detected('SIM2')
    plan = build_plan(r, request(r))
    assert plan.lines() == ['configure terminal', 'crypto key generate rsa modulus 2048',
                            'ip ssh version 2', 'end']
    assert all(c.kind == ADD for c in plan.commands)
    assert plan.item('rsa').status == MISSING


def test_unsupported_device_gets_no_commands():
    r, _ = detected('SIM3')
    plan = build_plan(r, new_user(r, hostname='SW-new'))
    assert not plan.available and plan.commands == [] and plan.lines() == []
    assert 'not to support SSH' in plan.reason
    assert plan.item('rsa').status == UNSUPPORTED and plan.item('ssh_version').status == UNSUPPORTED


def test_unknown_device_gets_no_commands():
    r, _ = detected('SIM4')
    plan = build_plan(r, new_user(r))
    assert not plan.available and plan.commands == []
    assert 'could not determine' in plan.reason
    assert all(i.commands == [] for i in plan.items)


def test_incomplete_detection_gets_no_commands():
    r, _ = detected('SIM2')
    r.complete = False
    plan = build_plan(r, request(r))
    assert not plan.available and 'did not finish' in plan.reason and plan.commands == []


def test_privilege_below_15_gets_no_commands():
    r, _ = detected('SIM2')
    r.access.privilege_level = 1
    plan = build_plan(r, request(r))
    assert not plan.available and 'privilege level 1;' in plan.reason
    assert 'only level 15 shows all of it' in plan.reason and plan.commands == []


def test_other_software_gets_no_commands():
    r, _ = detected('SIM2')
    r.device.software = 'NX-OS'
    assert not build_plan(r, request()).available


# ------------------------------------------------------------------ the factory-fresh device
def test_unconfigured_device_full_plan_in_order():
    r, _ = detected('SIM8')
    plan = build_plan(r, new_user(r, hostname='Edge-R1', domain_name='lab.local'))
    assert plan.lines() == [
        'configure terminal',
        'hostname Edge-R1',
        'ip domain-name lab.local',
        f'username netadmin privilege 15 secret {PASSWORD_PLACEHOLDER}',
        'crypto key generate rsa modulus 2048',
        'ip ssh version 2',
        'line vty 0 4',
        ' login local',
        ' transport input ssh',
        'end']
    assert 'write' not in plan.text() and 'copy' not in plan.text()
    login = next(c for c in plan.commands if c.text == 'login local')
    # replaces "login" with no line password set: nobody can log in there now, so nobody is cut off
    assert login.kind == MODIFY and not login.disruptive
    assert 'nobody can log in there now' in plan.item('vty_login').explanation
    assert plan.item('vty_transport').status == UNKNOWN             # no transport line shown


def test_nothing_is_invented():
    r, _ = detected('SIM8')
    plan = build_plan(r, request(r))
    # no name, domain, account or key made up (only "transport input ssh", which needs no value)
    assert texts(plan) == ['transport input ssh']
    assert plan.item('ssh_version').status == ATTENTION and 'its key is created' in \
        plan.item('ssh_version').explanation
    assert plan.item('hostname').status == ATTENTION
    assert plan.item('domain').status == ATTENTION and 'never invents' in \
        plan.item('domain').explanation
    assert plan.item('rsa').status == ATTENTION and 'hostname other than' in \
        plan.item('rsa').explanation
    assert plan.item('vty_login').status == ATTENTION and 'lock everybody out' in \
        plan.item('vty_login').explanation


def test_management_ip_is_never_invented():
    r, _ = detected('SIM2')
    r.management_interface, r.management_reason = None, 'no interface has an IP address'
    plan = build_plan(r, request(r))
    item = plan.item('management')
    assert item.status == ATTENTION and item.commands == [] and 'never invents' in item.explanation
    assert not any('ip address' in t for t in texts(plan))


def test_ios_xe_uses_its_domain_syntax_and_key_sizes():
    r, _ = detected('SIM8')
    r.device.software = 'IOS-XE'
    assert P.key_sizes(r) == (2048, 4096)
    plan = build_plan(r, new_user(r, hostname='Edge-R1', domain_name='lab.local', key_size=4096))
    assert 'ip domain name lab.local' in texts(plan)
    assert 'crypto key generate rsa modulus 4096' in texts(plan)


# ------------------------------------------------------------------ accounts
def test_existing_username_is_never_replaced():
    r, _ = detected('SIM2')
    plan = build_plan(r, new_user(r, name='labadmin'))
    item = plan.item('user')
    assert item.status == CONFLICT and item.commands == []
    assert not any(t.startswith('username') for t in texts(plan))
    assert 'labadmin (privilege 15)' in item.current


def test_existing_admin_is_reported():
    r, _ = detected('SIM2')
    item = build_plan(r, request(r)).item('user')
    assert item.status == CONFIGURED and 'labadmin' in item.explanation


def test_accounts_without_privilege_15_need_attention():
    r, _ = detected('SIM2')
    r.config.local_users = [LocalUser('guest', None), LocalUser('ops', 5)]
    plan = build_plan(r, request(r))
    assert plan.item('user').status == ATTENTION
    assert 'guest (privilege 1, default)' in plan.item('user').current


def test_new_account_needs_known_accounts():
    r, _ = detected('SIM2')
    r.config.local_users_known = False
    plan = build_plan(r, new_user(r))
    assert plan.item('user').status == UNKNOWN and not any(
        t.startswith('username') for t in texts(plan))


# ------------------------------------------------------------------ RSA keys
def test_existing_keys_are_never_regenerated():
    r, _ = detected('SIM1')
    plan = build_plan(r, request(r, key_size=1024))
    assert not any('crypto' in t for t in texts(plan))
    assert 'never regenerated' in plan.item('rsa').explanation


def test_unknown_keys_are_not_generated():
    r, _ = detected('SIM2')
    r.ssh.rsa = detect.RsaKeyInfo(present=None)
    plan = build_plan(r, request(r))
    assert plan.item('rsa').status == UNKNOWN and not any('crypto' in t for t in texts(plan))


def test_too_small_key_is_a_conflict():
    r, _ = detected('SIM1')
    r.config.ssh_version_configured = None
    r.ssh.rsa = detect.RsaKeyInfo(present=True, key_names=['R1.lab.local'], modulus_bits=512)
    plan = build_plan(r, request(r))
    assert plan.item('rsa').status == CONFLICT and plan.item('ssh_version').status == CONFLICT
    assert not any('crypto' in t or 'ip ssh version' in t for t in texts(plan))


# ------------------------------------------------------------------ AAA and VTY lines
def test_aaa_is_left_alone():
    r, _ = detected('SIM9')
    plan = build_plan(r, new_user(r))
    assert plan.item('aaa').status == ATTENTION and 'does not change AAA' in \
        plan.item('aaa').explanation
    assert plan.item('vty_login').commands == [] and plan.item('vty_login').status == CONFIGURED
    assert not any(t.startswith('aaa') for t in texts(plan))


def test_unknown_aaa_leaves_the_vty_login_alone():
    r, _ = detected('SIM8')
    r.config.aaa_known, r.config.aaa_new_model = False, None
    plan = build_plan(r, new_user(r, hostname='Edge-R1', domain_name='lab.local'))
    assert plan.item('vty_login').status == UNKNOWN and plan.item('vty_login').commands == []


def test_telnet_and_ssh_is_flagged_as_disruptive_change():
    r, _ = detected('SIM10')
    plan = build_plan(r, request(r))
    item = plan.item('vty_transport')
    assert item.status == ATTENTION and 'Telnet' in item.explanation
    [command] = item.commands
    assert (command.text, command.kind, command.disruptive, command.mode) == (
        'transport input ssh', MODIFY, True, 'line vty 0 4')
    assert plan.modifications == [command] and plan.additions == []


def test_telnet_only_is_a_conflict():
    r, _ = detected('SIM12')
    plan = build_plan(r, request(r))
    assert plan.item('vty_transport').status == CONFLICT
    assert plan.item('vty_login').status == CONFLICT        # login local, but no account at all
    assert 'nobody can log in' in plan.item('vty_login').explanation
    assert len(plan.conflicts) == 2


def test_new_account_resolves_the_missing_account():
    r, _ = detected('SIM12')
    plan = build_plan(r, new_user(r))
    assert plan.item('vty_login').status == ATTENTION
    assert f'username netadmin privilege 15 secret {PASSWORD_PLACEHOLDER}' in texts(plan)


def test_missing_vty_login_line():
    r, _ = detected('SIM11')
    plan = build_plan(r, new_user(r))
    item = plan.item('vty_login')
    assert item.status == UNKNOWN and [c.text for c in item.commands] == ['login local']
    assert item.commands[0].kind == ADD and not item.commands[0].disruptive


def test_login_local_is_never_proposed_without_an_account():
    r, _ = detected('SIM11')
    r.config.local_users = []
    plan = build_plan(r, request(r))
    assert plan.item('vty_login').commands == [] and 'lock everybody out' in \
        plan.item('vty_login').explanation


def test_aaa_login_list_without_aaa_is_a_conflict():
    r, _ = detected('SIM2')
    r.vty.blocks[0].login = 'authentication VTY'
    plan = build_plan(r, request(r))
    assert plan.item('vty_login').status == CONFLICT and plan.item('vty_login').commands == []


def test_no_vty_lines_at_all():
    r, _ = detected('SIM2')
    r.vty.configured, r.vty.blocks, r.vty.ranges, r.vty.available_lines = False, [], [], 16
    plan = build_plan(r, new_user(r))
    assert 'line vty 0 15' in plan.lines()                # every line show line reports
    assert plan.item('vty_login').status == MISSING


def test_unknown_vty_configuration():
    r, _ = detected('SIM2')
    r.vty = detect.VtyInfo()
    plan = build_plan(r, request(r))
    assert plan.item('vty_login').status == UNKNOWN and plan.item('vty_transport').status == UNKNOWN
    assert not any(c.mode for c in plan.commands)


@pytest.mark.parametrize('port', [p for p, s in SCENARIOS.items() if s['behaviour'] is None])
def test_every_mock_scenario_plans_without_errors(port):
    r, session = detected(port)
    plan = build_plan(r, new_user(r, hostname='NewName', domain_name='lab.local'))
    assert plan.simulated and plan.warnings[0].startswith('SIMULATED')
    assert set(session.sent) <= set(DETECTION_COMMANDS)
    for c in plan.commands:
        assert not c.text.startswith(('write', 'copy', 'reload', 'no aaa', 'aaa'))


# ------------------------------------------------------------------ input validation
@pytest.mark.parametrize('values, field', [
    ({'hostname': '1bad'}, 'hostname'),
    ({'hostname': 'Router'}, 'hostname'),
    ({'hostname': 'a' * 70}, 'hostname'),
    ({'domain_name': 'bad domain'}, 'domain_name'),
    ({'domain_name': '-x.local'}, 'domain_name'),
    ({'username': '9user', 'password': PASSWORD, 'confirm': PASSWORD}, 'username'),
    ({'username': 'admin user', 'password': PASSWORD, 'confirm': PASSWORD}, 'username'),
    ({'username': 'admin'}, 'password'),
    ({'username': 'admin', 'password': PASSWORD, 'confirm': 'other'}, 'password'),
    ({'username': 'admin', 'password': 'short', 'confirm': 'short'}, 'password'),
    ({'username': 'admin', 'password': 'has?mark1', 'confirm': 'has?mark1'}, 'password'),
    ({'username': 'admin', 'password': ' leading1', 'confirm': ' leading1'}, 'password'),
    ({'username': 'admin', 'password': 'pässwörd1', 'confirm': 'pässwörd1'}, 'password'),
    ({'password': PASSWORD, 'confirm': PASSWORD}, 'username'),
])
def test_invalid_input(values, field):
    _req, errors = validate_request(**values)
    assert field in errors
    for message in errors.values():
        assert PASSWORD not in message and 'has?mark1' not in message and 'pässwörd1' not in message


def test_key_size_must_suit_the_device():
    r, _ = detected('SIM2')
    assert P.key_sizes(r) == (1024, 2048)
    _req, errors = validate_request(key_size=4096, result=r)
    assert 'key_size' in errors
    _req, errors = validate_request(key_size='big', result=r)
    assert 'key_size' in errors


# ------------------------------------------------------------------ passwords
def test_no_password_anywhere_in_the_plan():
    r, _ = detected('SIM8')
    req = new_user(r, hostname='Edge-R1', domain_name='lab.local')
    assert not hasattr(req, 'password') and req.password_set
    assert PASSWORD not in repr(req)
    plan = build_plan(r, req)
    everything = repr(plan) + plan.text() + repr(asdict(plan))
    assert PASSWORD not in everything and PASSWORD_PLACEHOLDER in plan.text()


def test_request_never_holds_a_password():
    fields = set(SetupRequest.__dataclass_fields__)
    assert fields == {'hostname', 'domain_name', 'username', 'password_set', 'key_size',
                      # the management address and saving (added on request): no secrets
                      'mgmt_interface', 'mgmt_ip', 'mgmt_mask', 'gateway', 'save'}


# ------------------------------------------------------------------ staleness
def test_plan_staleness():
    r, _ = detected('SIM2')
    plan = build_plan(r, request(r))
    assert plan_is_stale(plan, r, live=True) is None
    assert 'ended' in plan_is_stale(plan, r, live=False)
    newer = copy.copy(r)
    from datetime import timedelta
    newer.detected_at = r.detected_at + timedelta(seconds=5)
    assert 'detected again' in plan_is_stale(plan, newer, live=True)
    assert plan_is_stale(None, r, True) is None


def test_planning_sends_nothing():
    """The planner gets only a result: it has no session to send anything with."""
    r, session = detected('SIM8')
    sent_before = list(session.sent)
    build_plan(r, new_user(r, hostname='Edge-R1', domain_name='lab.local'))
    assert session.sent == sent_before
    assert not any(s.startswith(CONFIG_WORDS) for s in session.sent if not s.startswith('show'))
