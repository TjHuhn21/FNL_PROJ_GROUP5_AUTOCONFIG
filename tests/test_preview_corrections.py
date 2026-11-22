"""Phase 4.1: regression tests for the corrections from the Phase 4 review (H1, M1-M5,
L1-L8). Offline: the mock lab's simulated consoles, the real detection and planner, and the
real Initial Setup page. No real port is listed or opened; nothing is executed."""
import copy
import os
import sys
from dataclasses import asdict

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path[:0] = [ROOT, os.path.join(ROOT, 'mock-lab'), os.path.dirname(__file__)]

from config.connect import mask  # noqa: E402
from console import detect, link  # noqa: E402
from console.detect import detect_device, parse_secsh_key, parse_ssh_keypair  # noqa: E402
from console.plan import (ATTENTION, CONFIGURED, MISSING, UNKNOWN, build_plan,  # noqa: E402
                          validate_request)
from mocklab.console import MockConsoleBackend  # noqa: E402
from test_console_detect import MockLabSession, mock_spec  # noqa: E402
from test_setup_tab import root  # noqa: E402,F401  (the Tk window fixture)

PASSWORD = 'Str0ng-Pass!'


def assert_hidden(secrets, text, where):
    """Fails without printing the secrets or the text: the result is computed first, so
    pytest's assertion message only shows `assert not True`."""
    found = any(word in text for secret in secrets for word in secret.split())
    assert not found, f'a secret value is visible in {where}'


def detected(port):
    session = MockConsoleBackend(delay=0).open_session(port, 9600, '', '', '', None)
    session.connect()
    before = session.device.running_config()
    result = detect_device(session)
    assert session.device.running_config() == before
    return result, session


def plan_for(result, username='', **values):
    password = PASSWORD if username else ''
    req, errors = validate_request(username=username, password=password, confirm=password,
                                   key_size=2048, result=result, **values)
    assert not errors, list(errors)
    return build_plan(result, req)


def texts(plan):
    return [c.text for c in plan.commands]


# ================================================================== H1: which key is SSH's
def test_ssh_off_with_its_normal_key_is_not_called_ready():
    r, _ = detected('SIM15')                       # SSH disabled, key R15.lab.local exists
    assert r.ssh.status.name == 'SUPPORTED_DISABLED' and r.ssh.rsa.key_names == ['R15.lab.local']
    plan = plan_for(r)
    item = plan.item('rsa')
    assert item.status == ATTENTION and 'not report SSH as enabled' in item.explanation
    assert not any('crypto' in t for t in texts(plan))          # never regenerated
    assert any('not proof that SSH is ready' in w for w in plan.warnings)


def test_only_an_https_self_signed_key_is_not_an_ssh_key():
    r, _ = detected('SIM13')                       # SSH disabled, only TP-self-signed-4001
    plan = plan_for(r)
    item = plan.item('rsa')
    assert item.status == MISSING and 'HTTPS self-signed' in item.explanation
    assert 'crypto key generate rsa modulus 2048' in texts(plan)
    assert 'ip ssh version 2' in texts(plan)
    assert any('not proof that SSH is ready' in w for w in plan.warnings)


def test_a_key_of_unknown_purpose_is_unknown():
    r, _ = detected('SIM14')                       # SSH disabled, key LEGACY-KEY
    plan = plan_for(r)
    item = plan.item('rsa')
    assert item.status == UNKNOWN and 'does not show whether SSH uses' in item.explanation
    assert not any('crypto' in t or t == 'ip ssh version 2' for t in texts(plan))


def test_running_ssh_keeps_its_key():
    r, _ = detected('SIM1')
    item = plan_for(r).item('rsa')
    assert item.status == CONFIGURED and 'SSH is running' in item.explanation
    assert r.config.ssh_secsh_key == 'R1.lab.local'


def test_keypair_name_pointing_at_a_missing_key():
    spec = mock_spec('router', 'disabled', global_lines=[
        'ip domain-name lab.local', 'username labadmin privilege 15 secret 5 $1$mock$hidden',
        'ip ssh rsa keypair-name SSHKEY'])
    r = detect_device(MockLabSession(spec))
    assert r.config.ssh_keypair_name == 'SSHKEY'
    plan = plan_for(r)
    assert plan.item('rsa').status == UNKNOWN and 'SSHKEY' in plan.item('rsa').explanation
    assert not any('crypto' in t for t in texts(plan))


def test_unreadable_keys_are_never_generated():
    r, _ = detected('SIM2')
    r.ssh.rsa = detect.RsaKeyInfo(present=None)
    assert not any('crypto' in t for t in texts(plan_for(r)))


def test_show_ip_ssh_key_line_parsing():
    assert parse_secsh_key('IOS Keys in SECSH format(ssh-rsa, base64 encoded): R1.lab.local\n'
                           'AAAAB3') == 'R1.lab.local'
    assert parse_secsh_key('IOS Keys in SECSH format(ssh-rsa, base64 encoded): NONE') == 'NONE'
    assert parse_secsh_key('SSH Enabled - version 2.0') is None
    assert parse_ssh_keypair(['ip ssh version 2', 'ip ssh rsa keypair-name K1',
                              'ip ssh source-interface Gi0/0']) == (
        'K1', ['ip ssh source-interface Gi0/0'])


# ================================================================== M1: masking
@pytest.mark.parametrize('line, kept, secret', [
    ('password 0 line pass words', 'password 0 ', 'line pass words'),
    (' password 7 0822455D0A16', ' password 7 ', '0822455D0A16'),
    ('username admin privilege 15 secret 0 two words', 'username admin privilege 15 secret 0 ',
     'two words'),
    ('enable password 0 example words', 'enable password 0 ', 'example words'),
    ('enable secret 5 $1$abc$def', 'enable secret 5 ', '$1$abc$def'),
    ('username a algorithm-type scrypt secret 9 $9$x$y', 'username a algorithm-type scrypt secret 9 ',
     '$9$x$y'),
    ('username bob privilege 15 password 0 my secret phrase',
     'username bob privilege 15 password 0 ', 'my secret phrase'),
    ('ppp chap password 0 a b c', 'ppp chap password 0 ', 'a b c'),
])
def test_passwords_are_masked_to_the_end_of_the_line(line, kept, secret):
    out = mask(line)
    assert_hidden([secret], out[len(kept):], 'the masked line')
    assert out == kept + '********'


def test_masking_keeps_everything_else():
    assert mask('service password-encryption') == 'service password-encryption'
    assert mask('username x nopassword') == 'username x nopassword'
    assert mask('security passwords min-length 8') == 'security passwords min-length 8'
    assert mask('snmp-server community public RO') == 'snmp-server community ******** RO'
    assert mask('line vty 0 4\n password 0 a b\n login\nhostname R1') == \
        'line vty 0 4\n password 0 ********\n login\nhostname R1'


# distinctive words, so a match can only come from the secret itself
SECRETS = ('Zq7alpha Wq9bravo Xq3charlie', 'Lp4delta Kp8echo Mp2foxtrot', 'Plain-Admin-Qz1')


def multi_word_spec():
    return mock_spec('router', 'enabled', global_lines=[
        'ip domain-name lab.local', f'username ops privilege 15 password 0 {SECRETS[0]}',
        f'username admin privilege 15 password 0 {SECRETS[2]}'],
        line_config={'con 0': [], 'vty 0 4': [f'password 0 {SECRETS[1]}', 'login',
                                                'transport input ssh']})


def test_detection_results_never_hold_multi_word_secrets():
    r = detect_device(MockLabSession(multi_word_spec()))
    everything = repr(asdict(r)) + repr(r.to_dict()) + r.summary()
    assert_hidden(SECRETS, everything, 'the detection result')
    assert [u.name for u in r.config.local_users] == ['ops', 'admin']
    assert r.vty.blocks[0].has_password and r.vty.blocks[0].login == 'line password'


def test_gui_never_shows_multi_word_secrets(root):
    from test_setup_tab import make, settle, texts as widget_texts

    class Backend(MockConsoleBackend):
        def open_session(self, port, baudrate, username, password, enable_password, log=None):
            from mocklab.console import MockConsoleSession
            from mocklab.device import Device
            s = MockConsoleSession('SIM1', baudrate, enable_password, None, delay=0, log=log)
            s.device = Device(multi_word_spec())
            return s
    tab = make(root, backend=Backend(delay=0))
    tab.refresh_ports()
    settle(root, tab)
    tab.port_var.set(tab.ports[0].label())
    tab._show_port_hint()
    tab.connect()
    settle(root, tab)
    tab.detect()
    settle(root, tab)
    tab.result_widgets['details_toggle'].invoke()
    tab.preview()
    shown = '\n'.join(widget_texts(tab)) + repr(tab.logged)
    assert_hidden(SECRETS, shown, 'the window or the log')


# ================================================================== M2: transcript
def test_transcript_keeps_only_a_bounded_tail():
    t = link._Transcript(limit=1000)
    for n in range(100):
        t.write(f'line {n:04d} '.encode() * 10)
    data = t.getvalue()
    assert len(data) == 1000 and data.endswith(b'line 0099 ')


def test_transcript_stops_and_wipes():
    t = link._Transcript()
    t.write(b'User Access Verification')
    t.stop()
    assert t.getvalue() == b'' and t.write(b'password 0 x') == 12 and t.getvalue() == b''
    t.close()                                       # Netmiko's close is harmless
    assert t.getvalue() == b''


def test_command_output_is_not_kept_after_login(monkeypatch):
    from test_console_link import Device, FakeSerial
    import serial
    import serial.tools.list_ports as list_ports
    from types import SimpleNamespace
    FakeSerial.instances, FakeSerial.open_error, FakeSerial.block = [], None, False
    FakeSerial.device = Device()
    monkeypatch.setattr(serial, 'Serial', FakeSerial)
    monkeypatch.setattr(list_ports, 'comports',
                        lambda: [SimpleNamespace(device='COM4', description='x', hwid='y')])
    monkeypatch.setattr('sys.platform', 'win32')
    s = link.ConsoleSession('COM4', timeout=15)
    s.connect()
    assert s._transcript.getvalue() == b'' and not s._transcript.recording
    out = s.send_show('show version')                # normal command handling still works
    assert 'Version 15.4(3)M2' in out
    assert s._transcript.getvalue() == b''
    s.disconnect()
    assert s._transcript.getvalue() == b''


def test_failed_login_is_still_explained_and_then_wiped():
    from netmiko.exceptions import NetmikoAuthenticationException
    from test_console_link import FakeConn

    def handler(**params):
        return FakeConn('\r\nUser Access Verification\r\n\r\nPassword: \r\n% Bad passwords\r\n',
                        NetmikoAuthenticationException('Login failed: serial'), **params)
    s = link.ConsoleSession('COM4', password='x-pass', connect_handler=handler, timeout=5)
    with pytest.raises(link.ConsoleError) as err:
        s.connect()
    assert err.value.kind == link.AUTH                      # classified from the transcript
    assert s._transcript.getvalue() == b''                  # then emptied


# ================================================================== M3 / M5: VTY coverage
def test_sixteen_lines_with_only_vty_0_4_configured():
    r, _ = detected('SIM17')
    assert r.vty.available_lines == 16 and r.vty.ranges == ['0 4']
    plan = plan_for(r)
    for key in ('vty_login', 'vty_transport'):
        item = plan.item(key)
        assert item.status == ATTENTION
        assert 'vty 5-15 are not in the configuration' in item.explanation
        assert 'NOT changed' in item.explanation
    assert not any(c.mode and c.mode != 'line vty 0 4' for c in plan.commands)


def test_separate_ranges_keep_their_own_settings():
    r, _ = detected('SIM16')
    assert [(b.lines, b.login, b.transport_input) for b in r.vty.blocks] == [
        ('0 4', 'local', ['ssh']), ('5 15', 'line password', ['telnet'])]
    plan = plan_for(r, username='netadmin')
    assert plan.lines()[-4:] == ['line vty 5 15', ' login local', ' transport input ssh', 'end']
    assert 'line vty 0 4' not in plan.lines()                  # already SSH + local: untouched
    login = next(c for c in plan.commands if c.text == 'login local')
    transport = next(c for c in plan.commands if c.text == 'transport input ssh')
    assert login.disruptive and transport.disruptive           # line password / Telnet users
    assert 'vty 5 15 uses the line password' in plan.item('vty_login').explanation
    assert 'Telnet will stop working' in plan.item('vty_transport').explanation


def test_separate_ranges_without_a_new_account():
    r, _ = detected('SIM16')
    plan = plan_for(r)
    assert texts(plan) == ['transport input ssh']               # login not changed (M4)
    assert plan.item('vty_login').status == ATTENTION


def test_unknown_vty_capacity_is_reported_and_nothing_is_invented():
    r, _ = detected('SIM2')
    r.vty.available_lines = None
    plan = plan_for(r, username='netadmin')
    assert plan.item('vty_transport').status == UNKNOWN
    assert 'number of VTY lines could not be read' in plan.item('vty_login').explanation
    r.vty = detect.VtyInfo(configured=False, available_lines=None)
    plan = plan_for(r, username='netadmin')
    assert not any(c.mode for c in plan.commands)               # no range invented
    assert 'number is unknown' in plan.item('vty_login').explanation


# ================================================================== M4: no lockout
def test_existing_admin_alone_does_not_allow_login_local():
    r, _ = detected('SIM2')
    r.vty.blocks[0].login, r.vty.blocks[0].has_password = 'line password', True
    plan = plan_for(r)
    assert 'login local' not in texts(plan)
    explanation = plan.item('vty_login').explanation
    assert 'labadmin' in explanation and 'cannot tell whether you know their passwords' in \
        explanation
    assert 'proposes changing the VTY login only together with a new account' in \
        plan.item('user').explanation


def test_a_new_account_allows_login_local():
    r, _ = detected('SIM2')
    r.vty.blocks[0].login, r.vty.blocks[0].has_password = 'line password', True
    plan = plan_for(r, username='netadmin')
    assert texts(plan)[:1] == [f'username netadmin privilege 15 secret <SSH_PASSWORD>']
    assert 'login local' in texts(plan)


def test_aaa_stays_untouched_even_with_a_new_account():
    r, _ = detected('SIM9')
    plan = plan_for(r, username='netadmin')
    assert 'login local' not in texts(plan) and not any(t.startswith('aaa') for t in texts(plan))


# ================================================================== L1, L4, L8
def test_login_without_any_password_is_not_disruptive():
    r, _ = detected('SIM8')
    plan = plan_for(r, username='netadmin', hostname='Edge-R1', domain_name='lab.local')
    login = next(c for c in plan.commands if c.text == 'login local')
    assert not login.disruptive and 'nobody can log in there now' in \
        plan.item('vty_login').explanation


def test_unknown_privilege_explains_why_nothing_is_proposed():
    r, _ = detected('SIM2')
    r = copy.deepcopy(r)
    r.access.privilege_level = None
    plan = plan_for(r)
    assert not plan.available and plan.commands == []
    assert '"show privilege" did not work' in plan.reason and 'might only be hidden' in plan.reason


def test_unexamined_ssh_settings_are_marked_outside_scope():
    spec = mock_spec('router', 'enabled', global_lines=[
        'ip domain-name lab.local', 'username labadmin privilege 15 secret 5 $1$mock$hidden',
        'ip ssh version 2', 'ip ssh source-interface GigabitEthernet0/0'])
    r = detect_device(MockLabSession(spec))
    item = plan_for(r).item('ssh_other')
    assert item.status == UNKNOWN and 'source-interface' in item.current
    assert 'outside what this preview examines' in item.explanation
    item = plan_for(detected('SIM1')[0]).item('ssh_other')
    assert item.status == CONFIGURED and item.current == 'none'


# ================================================================== L2, L3 (GUI)
def ready(root, port):
    from test_setup_tab import make, settle
    tab = make(root, backend=MockConsoleBackend(delay=0))
    tab.refresh_ports()
    settle(root, tab)
    tab.port_var.set(next(p.label() for p in tab.ports if p.device == port))
    tab._show_port_hint()
    tab.connect()
    settle(root, tab)
    return tab


@pytest.mark.parametrize('field, value', [('hostname', 'Other-R'), ('domain_name', 'x.local'),
                                          ('username', 'someone')])
def test_changing_any_input_makes_the_preview_out_of_date(root, field, value):
    from test_setup_tab import settle
    tab = ready(root, 'SIM2')
    tab.detect()
    settle(root, tab)
    tab.preview()
    assert not tab.preview_widgets['stale'].winfo_manager()
    tab.want[field].set(value)
    root.update()
    stale = tab.preview_widgets['stale']
    assert stale.winfo_manager() and 'values entered below were changed' in stale.cget('text')
    if field == 'username':                             # a new account needs its password
        tab.want['password'].set(PASSWORD)
        tab.want['confirm'].set(PASSWORD)
    tab.preview()                                       # a new preview is current again
    assert not tab.preview_widgets['stale'].winfo_manager()


def test_changing_the_key_size_makes_the_preview_out_of_date(root):
    from test_setup_tab import settle
    tab = ready(root, 'SIM2')
    tab.detect()
    settle(root, tab)
    tab.preview()
    tab.key_var.set('1024')
    assert 'values entered below were changed' in tab.preview_widgets['stale'].cget('text')


def test_failed_detect_again_explains_why_no_preview_was_made(root):
    from test_setup_tab import settle
    from gui.setup_tab import NO_NEW_PREVIEW
    tab = ready(root, 'SIM7')                      # the cable is "pulled" during detection
    tab.redetect_btn.invoke()
    settle(root, tab)
    assert tab.plan is None and tab.preview_error.cget('text') == NO_NEW_PREVIEW


# ================================================================== the port guard
def test_the_suite_still_blocks_real_serial_ports():
    import serial
    import serial.tools.list_ports as list_ports
    assert list_ports.comports() == []
    with pytest.raises(AssertionError):
        serial.Serial(port='COM1')
