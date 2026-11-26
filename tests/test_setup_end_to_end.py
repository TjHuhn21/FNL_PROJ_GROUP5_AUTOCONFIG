"""The Initial Setup page end to end on the MOCK console (no COM port, no real device):

    SIM49  the real CISCO1941 "R1" as it was after the first hardware test: an admin account
           with a type-5 secret, no domain, no RSA keys, VTY "login / transport input none",
           Gi0/0 and Gi0/1 without an address and shut down
    SIM50  a factory-new Catalyst 2960 (hostname Switch, nothing configured)

Connect -> Detect (checklist) -> Preview (only what is missing) -> Apply (one step at a
time, each verified) -> final summary -> Test SSH login -> register in Devices. The SSH
test itself is replaced (there is no network); the password used is synthetic.
"""
import os
import sys

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path[:0] = [ROOT, os.path.join(ROOT, 'mock-lab'), os.path.dirname(__file__)]
tk = pytest.importorskip('tkinter')

import db_fake  # noqa: E402
from console import plan as P  # noqa: E402
from console import ssh_test  # noqa: E402
from console.apply import percent_error  # noqa: E402
from console.link import (MODULUS_QUESTION, REPLACE_KEYS_QUESTION, answer_for,  # noqa: E402
                          masked_reply)
from gui import setup_tab  # noqa: E402
from gui.components import dialogs  # noqa: E402
from gui.setup_tab import (APPLY_STATUS_TEXT, DETECTED, SetupTab, final_summary,  # noqa: E402
                           short_interface)
from mocklab.console import MockConsoleBackend  # noqa: E402
from test_setup_tab import root, settle  # noqa: E402,F401
from gui_helpers import pump  # noqa: E402

PW = 'Lab-Pass1234'                       # synthetic, 12 characters


@pytest.fixture
def asked(monkeypatch):
    """Every shared confirmation is answered from `answers` (default yes), and recorded."""
    class Seen(list):
        pass
    seen, answers = Seen(), []

    def runner(title, message, **options):
        seen.append((title, message, options))
        if options.get('kind') != 'confirm':
            return None
        return answers.pop(0) if answers else True
    monkeypatch.setattr(dialogs, '_runner', runner)
    seen.answers = answers
    return seen


def page(root, port, store=None):
    lines = []
    tab = SetupTab(root, log=lambda source, text, level='info', **extra:
                   lines.append((text, level, extra)),
                   backend=MockConsoleBackend(delay=0), store=store)
    tab.pack(fill='both', expand=True)
    tab.logged = lines
    root.update()
    tab.refresh_ports()
    settle(root, tab)
    tab.port_var.set(next(p.label() for p in tab.ports if p.device == port))
    tab._show_port_hint()
    tab.connect()
    settle(root, tab)
    tab.detect()
    settle(root, tab)
    assert tab.phase == DETECTED
    return tab


def preview(root, tab, **values):
    for key, value in values.items():
        tab.want[key].set(value)
    tab.preview()
    root.update()
    assert tab.plan is not None, tab.preview_error.cget('text')
    return tab.plan


def apply(root, tab, password=''):
    tab.apply_vars['password'].set(password)
    tab.apply_vars['confirm'].set(password)
    tab.apply_vars['phrase'].set(tab.phrase_label.cget('text').split('  ')[1])
    for var in tab.approval_vars.values():
        var.set(1)
    tab.apply_ssh()
    assert pump(root, lambda: tab.apply_result is not None or tab.apply_error.cget('text'), 30)
    settle(root, tab)
    return tab.apply_result


def rows(tab):
    return {tab.apply_tree.item(i, 'values')[0]: tab.apply_tree.item(i, 'values')[1]
            for i in tab.apply_tree.get_children()}


# ---------------------------------------------------------------- the real R1, as found
def test_r1_checklist_preview_and_apply(root, asked):
    tab = page(root, 'SIM49')
    checklist = tab.result_widgets['checklist']
    assert checklist == {'Hostname not "Router"/"Switch"': 'OK', 'Domain name': 'MISSING',
                         'Local user with privilege 15': 'OK', 'RSA key 2048+': 'MISSING',
                         'SSH version 2': 'MISSING',
                         'VTY: login local + transport ssh': 'MISSING',
                         'Management IP on an "up" interface': 'MISSING',
                         'Default gateway': 'MISSING'}
    # the dropdown: the router's physical ports, with their address and status
    values = list(tab.mgmt_box.cget('values'))
    assert 'GigabitEthernet0/0  (no IP, administratively down)' in values
    assert not any('Embedded' in v for v in values)
    assert 'Existing user(s): admin' in tab.users_note.cget('text')
    assert '(required)' in tab.preview_labels['domain_name'].cget('text')
    assert '(optional)' in tab.preview_labels['hostname'].cget('text')
    assert tab.save_var.get() is True                         # ticked by default
    plan = preview(root, tab, domain_name='lab.local',
                   mgmt_interface='GigabitEthernet0/0  (no IP, administratively down)',
                   mgmt_ip='192.168.1.1', mgmt_mask='255.255.255.0')
    assert plan.lines() == ['configure terminal', 'ip domain-name lab.local',
                            'crypto key generate rsa modulus 2048', 'ip ssh version 2',
                            'line vty 0 4', ' login local', ' transport input ssh',
                            'interface GigabitEthernet0/0', ' ip address 192.168.1.1 255.255.255.0',
                            ' no shutdown', 'end']
    assert not any('username' in l or '$1$' in l for l in plan.lines())   # never a hash
    res = apply(root, tab)
    assert asked[-1][0] == 'Apply SSH configuration'            # the final question
    assert asked[-1][1].startswith('Apply 9 steps to R1 through the console?')
    assert res.outcome == 'success', [(s.step_id, s.reasons) for s in res.steps]
    shown = rows(tab)
    assert shown['Set the domain name'] == 'OK' and shown['Hostname'] == 'SKIPPED'
    assert shown['Local SSH account'] == 'SKIPPED'
    text = tab.apply_summary.cget('text')
    assert text.startswith('SSH setup complete on R1. SSH: enabled (v2). Login: admin. '
                           'Management IP: 192.168.1.1 on Gi0/0 (up). Saved to startup-config.')
    assert tab.ssh_test_box.winfo_manager()                     # step 6 offered
    assert tab.ssh_test_user.get() == 'admin'
    # transparency: every command sent is in the log
    sent = [extra.get('command') for _t, _l, extra in tab.logged if extra.get('command')]
    assert 'crypto key generate rsa modulus 2048' in sent and 'write memory' in sent


def test_an_existing_username_asks_change_or_keep(root, asked):
    tab = page(root, 'SIM49')
    asked.answers[:] = [False]                                   # "Keep existing"
    plan = preview(root, tab, domain_name='lab.local', username='admin', password=PW,
                   confirm=PW)
    assert asked[-1][0] == setup_tab.CHANGE_PASSWORD_TITLE
    assert asked[-1][2]['confirm_text'] == 'Change password'
    assert asked[-1][2]['cancel_text'] == 'Keep existing'
    assert not any(l.startswith('username') for l in plan.lines())
    asked.answers[:] = [True]                                    # "Change password"
    plan = preview(root, tab, domain_name='lab.local', username='admin', password=PW,
                   confirm=PW)
    assert f'username admin privilege 15 secret {P.PASSWORD_PLACEHOLDER}' in plan.lines()


def test_a_hash_is_refused_as_the_password(root, asked):
    tab = page(root, 'SIM49')
    tab.want['domain_name'].set('lab.local')
    tab.want['username'].set('netadmin')
    tab.want['password'].set('$1$B3rU$k.snkyAbcdefgh')
    tab.want['confirm'].set('$1$B3rU$k.snkyAbcdefgh')
    tab.preview()
    assert 'Type a real password, not an encrypted secret' in tab.preview_error.cget('text')


# ---------------------------------------------------------------- a factory-new 2960
def test_2960_required_fields_then_full_setup(root, asked):
    tab = page(root, 'SIM50')
    tab.preview()
    errors = tab.preview_error.cget('text')
    assert 'Required' in errors and 'Switch' in errors          # hostname, domain, account
    assert tab.want['mgmt_interface'].get().startswith('Vlan1')  # Vlan1 by default
    plan = preview(root, tab, hostname='SW1', domain_name='lab.local', username='netadmin',
                   password=PW, confirm=PW, mgmt_ip='192.168.1.2', mgmt_mask='/24',
                   gateway='192.168.1.1')
    assert 'line vty 5 15' in plan.lines() and 'ip default-gateway 192.168.1.1' in plan.lines()
    res = apply(root, tab, PW)
    assert res.outcome == 'success', res.problems
    assert set(rows(tab).values()) <= {'OK', 'SKIPPED'}
    assert 'SSH setup complete on SW1' in tab.apply_summary.cget('text')
    assert PW not in str(tab.logged)                             # masked everywhere


def test_no_management_ip_warns(root, asked):
    tab = page(root, 'SIM49')
    preview(root, tab, domain_name='lab.local')
    assert "can't reach this device over the network" in tab.mgmt_note.cget('text')


# ---------------------------------------------------------------- 6 / 7
def test_ssh_test_then_register_the_device(root, asked, monkeypatch):
    db_fake.reset()
    tab = page(root, 'SIM49', store=db_fake)
    preview(root, tab, domain_name='lab.local',
            mgmt_interface='GigabitEthernet0/0  (no IP, administratively down)',
            mgmt_ip='192.168.1.1', mgmt_mask='255.255.255.0')
    apply(root, tab)
    tries = []
    monkeypatch.setattr(ssh_test, 'test_ssh_login', lambda ip, user, pw: tries.append(
        (ip, user)) or (True, f'SSH login OK: {user}@{ip}, prompt R1#'))
    tab.ssh_test_pw.set(PW)
    tab.test_ssh()
    assert pump(root, lambda: 'SSH login OK' in tab.ssh_test_result.cget('text'), 10)
    root.update()
    assert tries == [('192.168.1.1', 'admin')] and tab.ssh_test_pw.get() == ''
    assert asked[-1][0] == 'Add to Devices'
    assert asked[-1][1] == ('Add R1 (192.168.1.1, router) to Devices as managed, and save '
                            'this login (encrypted)?')
    d = db_fake.get_device_by_ip('192.168.1.1')
    assert d['name'] == 'R1' and d['managed'] and d['type'] == 'router'
    assert db_fake.get_credentials(d['id']) == ('admin', PW)
    assert tab.offer_registration('192.168.1.1', 'admin', PW) is False   # no duplicate
    assert asked[-1][1].startswith('192.168.1.1 is already in Devices as R1')


def test_ssh_test_messages():
    class Timeout(Exception):
        pass
    import socket

    def refuse(**kw):
        raise socket.timeout('timed out')
    ok, text = ssh_test.test_ssh_login('192.168.1.1', 'admin', PW, connect=refuse)
    assert not ok and 'timed out' in text and 'network' in text and PW not in text

    from netmiko.exceptions import NetmikoAuthenticationException

    def bad_login(**kw):
        raise NetmikoAuthenticationException(f'Authentication failed for {PW}')
    ok, text = ssh_test.test_ssh_login('192.168.1.1', 'admin', PW, connect=bad_login)
    assert not ok and 'check the username and password' in text and PW not in text


# ---------------------------------------------------------------- the pieces
def test_percent_lines_fail_a_step_except_informational_ones():
    assert percent_error('username admin secret x\n% Invalid Password length - must contain 1 '
                         'to 25 characters. Password configuration failed\nR1(config)#') == \
        ('% Invalid Password length - must contain 1 to 25 characters. Password configuration '
         'failed')
    assert percent_error("ip address 1.1.1.1 255.0.0.0\n% 1.0.0.0 overlaps with "
                         "GigabitEthernet0/1\nR1(config-if)#").startswith('% 1.0.0.0 overlaps')
    assert percent_error('% The key modulus size is 2048 bits\n% Generating 2048 bit RSA keys, '
                         'keys will be non-exportable...\n[OK]\nR1(config)#') is None


def test_the_mock_answers_like_the_1941_for_a_too_long_password():
    from mocklab.cli import Session
    from mocklab.console import device_spec
    from mocklab.device import Device
    cli = Session(Device(device_spec('SIM49')))
    cli.handle('enable')
    cli.handle('configure terminal')
    out = cli.handle('username admin privilege 15 secret $1$B3rU$k.snkyMockHashNotReal0').output
    assert out.startswith('% Invalid Password length - must contain 1 to 25 characters')


def test_no_page_can_send_a_hash_or_a_too_long_secret():
    from validators import check_cli_line
    from console.link import ConsoleError, check_secret
    assert check_cli_line('username admin privilege 15 secret $1$B3rU$k.snkyAbc')
    assert check_cli_line('username admin secret ' + 'x' * 26).startswith('The password is longer')
    assert check_cli_line('username admin privilege 15 secret Good-Pass123') is None
    for bad in ('$1$B3rU$k.snkyAbc', 'x' * 26):
        with pytest.raises(ConsoleError):
            check_secret(bad)                       # the console link's own last check


def test_known_questions_and_masked_replies():
    answers = ((MODULUS_QUESTION, '2048'), (REPLACE_KEYS_QUESTION, 'yes'))
    assert answer_for('How many bits in the modulus [512]:', answers) == '2048'
    assert answer_for('% Do you really want to replace them? [yes/no]:', answers) == 'yes'
    assert answer_for('Proceed with reload? [confirm]', answers) is None
    assert '********' in masked_reply('username admin privilege 15 secret 5 $1$abc$def')
    assert '$1$abc$def' not in masked_reply('username admin privilege 15 secret 5 $1$abc$def')


def test_summary_and_interface_names():
    assert short_interface('GigabitEthernet0/0') == 'Gi0/0'
    assert short_interface('Vlan1') == 'Vlan1'
    assert APPLY_STATUS_TEXT['verified'] == 'OK' and APPLY_STATUS_TEXT['blocked'] == 'NOT RUN'
    assert final_summary(None, None, None, None) == ''


def test_leaving_the_page_while_connected_asks_and_disconnects(root, asked):
    tab = page(root, 'SIM1')
    asked.answers[:] = [False]
    assert tab.confirm_leave() is False and tab.session is not None
    assert asked[-1][2]['confirm_text'] == 'Disconnect and leave'
    assert tab.confirm_leave() is True
    settle(root, tab)
    assert tab.session is None
