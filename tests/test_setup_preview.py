"""The SSH Configuration Preview on the Initial Setup page (phase 4). Offline: simulated
mock-lab consoles and scripted sessions; no real port; nothing is ever executed."""
import os
import sys
import threading

import pytest

sys.path.insert(0, os.path.dirname(__file__))
tk = pytest.importorskip('tkinter')

from test_setup_tab import (FakeBackend, make, pump, root, settle, texts)  # noqa: E402,F401
from console.detect import DETECTION_COMMANDS  # noqa: E402
from console.plan import PASSWORD_PLACEHOLDER, PREVIEW_NOTICE  # noqa: E402
from gui.setup_tab import DETECTED, DISCONNECTED  # noqa: E402
from mocklab.console import MockConsoleBackend  # noqa: E402

PASSWORD = 'Str0ng-Pass!'
FORBIDDEN_BUTTONS = ('apply', 'execute', 'send', 'save', 'write', 'run commands', 'configure')


def ready(root, port='SIM8', backend=None):
    """Connected to a simulated device and detected."""
    tab = make(root, backend=backend or MockConsoleBackend(delay=0))
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


def fill(tab, hostname='Edge-R1', domain='lab.local', username='netadmin', password=PASSWORD,
         confirm=None):
    tab.want['hostname'].set(hostname)
    tab.want['domain_name'].set(domain)
    tab.want['username'].set(username)
    tab.want['password'].set(password)
    tab.want['confirm'].set(password if confirm is None else confirm)


def buttons(widget):
    out = []
    for child in widget.winfo_children():
        if child.winfo_class() in ('TButton', 'Button'):
            out.append(str(child.cget('text')))
        out += buttons(child)
    return out


def disabled(widget):
    return widget.instate(['disabled'])


# ------------------------------------------------------------------ availability
def test_preview_needs_a_detection(root):
    tab = make(root, backend=MockConsoleBackend(delay=0))
    assert disabled(tab.preview_btn) and disabled(tab.redetect_btn)
    tab.preview()
    assert tab.plan is None and 'detect the device first' in tab.preview_error.cget('text')
    assert PREVIEW_NOTICE == tab.preview_notice.cget('text')


def test_preview_is_enabled_after_detection_and_offers_device_key_sizes(root):
    tab = ready(root)
    assert not disabled(tab.preview_btn) and not disabled(tab.redetect_btn)
    assert list(tab.key_box.cget('values')) == ['1024', '2048'] and tab.key_var.get() == '2048'


def test_there_is_no_way_to_execute_the_plan(root):
    tab = ready(root)
    fill(tab)
    tab.preview()
    names = [b.lower() for b in buttons(tab)]
    assert not any(word in name for name in names for word in FORBIDDEN_BUTTONS), names
    assert tab.preview_widgets['commands'].cget('state') == 'disabled'       # read-only text


# ------------------------------------------------------------------ the preview
def test_preview_shows_status_commands_and_explanations(root):
    tab = ready(root)
    sent_before = list(tab.session.sent)
    config_before = tab.session.device.running_config()
    fill(tab)
    tab.preview()
    w = tab.preview_widgets
    assert tab.plan.available
    rows = {w['items'].item(i, 'values')[0]: w['items'].item(i, 'values')[1]
            for i in w['items'].get_children()}
    assert rows['Hostname'] == 'Missing' and rows['VTY login'] == 'Needs attention'
    assert rows['VTY protocols (SSH/Telnet)'] == 'Unknown'
    commands = w['commands'].get('1.0', 'end').strip().splitlines()
    assert commands[0] == 'configure terminal' and commands[-1] == 'end'
    assert f'username netadmin privilege 15 secret {PASSWORD_PLACEHOLDER}' in commands
    assert 'Creates the account used to log in over SSH' in w['additions'].cget('text')
    # SIM8's VTY "login" has no line password: nobody can log in there now, nobody is cut off
    assert 'MAY CUT OFF CURRENT USERS' not in w['modifications'].cget('text')
    assert 'hostname Edge-R1' in w['modifications'].cget('text')
    assert PREVIEW_NOTICE in '\n'.join(texts(tab.preview_box))
    assert w['simulated'].cget('text').startswith('SIMULATED DEVICE')
    # nothing was sent: only the detection's show commands, the device is unchanged
    assert tab.session.sent == sent_before
    assert set(tab.session.sent) <= set(DETECTION_COMMANDS)
    assert tab.session.device.running_config() == config_before
    assert any('Nothing was sent' in m for _s, m, _l in tab.logged)


def test_conflicts_and_unknowns_are_listed(root):
    tab = ready(root, 'SIM12')
    tab.preview()
    text = tab.preview_widgets['attention'].cget('text')
    assert 'Conflict detected - VTY protocols' in text and 'Conflict detected - VTY login' in text


def test_selecting_a_row_shows_its_full_explanation(root):
    tab = ready(root, 'SIM10')
    tab.preview()
    tree = tab.preview_widgets['items']
    tree.selection_set('vty_transport')
    root.update()
    assert 'Telnet' in tab.preview_widgets['item_text'].cget('text')


@pytest.mark.parametrize('port, words', [('SIM3', 'not to support SSH'),
                                         ('SIM4', 'could not determine')])
def test_unsupported_and_unknown_devices_get_no_commands(root, port, words):
    tab = ready(root, port)
    tab.preview()
    assert not tab.plan.available and words in tab.preview_widgets['reason'].cget('text')
    assert tab.preview_widgets['commands'] is None


def test_fully_configured_device(root):
    tab = ready(root, 'SIM1')
    tab.preview()
    assert tab.plan.commands == [] and tab.preview_widgets['commands'] is None


# ------------------------------------------------------------------ input and passwords
def test_invalid_input_makes_no_plan(root):
    tab = ready(root)
    fill(tab, hostname='9bad', username='netadmin', password=PASSWORD, confirm='different')
    tab.preview()
    error = tab.preview_error.cget('text')
    assert tab.plan is None and 'hostname' in error and 'do not match' in error
    assert PASSWORD not in error


def test_passwords_are_masked_emptied_and_never_shown(root):
    tab = ready(root)
    assert tab.preview_entries['password'].cget('show') == '*'
    assert tab.preview_entries['confirm'].cget('show') == '*'
    fill(tab)
    tab.preview()
    assert tab.want['password'].get() == '' and tab.want['confirm'].get() == ''
    assert tab.plan.item('user').commands                       # the account is still planned
    everything = (repr(tab.logged) + '\n'.join(texts(tab)) + repr(tab.plan)
                  + tab.preview_widgets['commands'].get('1.0', 'end'))
    assert PASSWORD not in everything
    assert not any(PASSWORD in str(v) for v in vars(tab).values())


# ------------------------------------------------------------------ staleness and refresh
def test_disconnect_makes_the_preview_out_of_date(root):
    tab = ready(root)
    tab.preview()
    tab.disconnect()
    settle(root, tab)
    assert tab.phase == DISCONNECTED
    stale = tab.preview_widgets['stale']
    assert stale.winfo_manager() and 'OUT OF DATE' in stale.cget('text')
    assert 'session that this preview is based on has ended' in stale.cget('text')
    assert disabled(tab.preview_btn)
    tab.preview()                                               # refused
    assert 'detect the device first' in tab.preview_error.cget('text')


def test_a_new_detection_makes_the_old_preview_out_of_date(root):
    tab = ready(root)
    tab.preview()
    tab.detect()
    settle(root, tab)
    assert 'detected again' in tab.preview_widgets['stale'].cget('text')


def test_detect_again_and_preview_uses_fresh_information(root):
    tab = ready(root, 'SIM2')
    tab.preview()
    old = tab.plan
    reads = tab.session.sent.count('show version')
    # the device changes behind NetCommand's back (someone typed on another console)
    tab.session.device.rsa_keys = True
    tab.redetect_btn.invoke()
    settle(root, tab)
    assert tab.session.sent.count('show version') == reads + 1
    assert tab.plan is not old and tab.plan.detected_at == tab.result.detected_at
    assert not tab.preview_widgets['stale'].winfo_manager()
    assert not any('crypto' in c.text for c in tab.plan.commands)     # keys exist now


def test_detect_again_keeps_the_new_account_without_the_password(root):
    tab = ready(root)
    fill(tab)
    tab.redetect_btn.invoke()
    assert tab.want['password'].get() == ''
    settle(root, tab)
    assert any(c.text.startswith('username netadmin') for c in tab.plan.commands)


def test_detect_again_is_refused_with_invalid_input(root):
    tab = ready(root)
    reads = tab.session.sent.count('show version')
    fill(tab, domain='not a domain')
    tab.redetect_btn.invoke()
    root.update()
    assert tab.session.sent.count('show version') == reads and tab.plan is None


def test_preview_with_a_scripted_real_ios_router(root):
    """A non-simulated device: no simulation banner in the preview."""
    tab = make(root)                                            # FakeBackend (scripted IOS)
    tab.refresh_ports()
    settle(root, tab)
    tab.connect()
    settle(root, tab)
    tab.detect()
    settle(root, tab)
    tab.preview()
    assert 'simulated' not in tab.preview_widgets and not tab.plan.simulated
    assert set(tab.backend.sessions[0].sent) <= set(DETECTION_COMMANDS)
