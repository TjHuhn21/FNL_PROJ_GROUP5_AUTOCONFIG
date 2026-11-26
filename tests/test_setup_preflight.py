"""Phase 5.1.6: the Initial Setup page shows what the console showed before anything was
sent, and asks the operator to decide when NetCommand could not verify a prompt.
Simulated mock-lab consoles only (SIM40-SIM46 and the normal ports); no real port."""
import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(__file__))
tk = pytest.importorskip('tkinter')

from test_setup_tab import make, root, settle  # noqa: E402,F401
from console import link  # noqa: E402
from gui import setup_tab  # noqa: E402
from gui.setup_tab import AWAITING, CONNECTED, DISCONNECTED, ERROR  # noqa: E402
from mocklab.console import MockConsoleBackend, scenario_port  # noqa: E402


def open_page(root, port, auto=False):
    """The page with the operator deciding each startup prompt (auto_startup False: the
    phase 5.1.6 flow tested here); auto=True: the default, automatic handling."""
    tab = make(root, backend=MockConsoleBackend(delay=0, edge_cases=True))
    tab.auto_startup = auto
    tab.refresh_ports()
    settle(root, tab)
    tab.port_var.set(next(p.label() for p in tab.ports if p.device == port))
    tab._show_port_hint()
    tab.connect()
    settle(root, tab)                    # idle again: connected, waiting for a decision, or error
    return tab


def visible(widget):
    return bool(widget.winfo_manager())


def test_a_normal_prompt_is_shown_as_verified_by_netcommand(root):
    tab = open_page(root, 'SIM1')
    assert tab.phase == CONNECTED
    assert tab.preflight_label.cget('text').startswith(
        'Normal prompt detected (verified by NetCommand)')
    assert not visible(tab.decision)
    assert tab.connection_verification == link.VERIFIED
    assert 'NetCommand saw the normal prompt' in tab.message.cget('text')


def test_a_silent_console_needs_the_unticked_confirmation(root):
    tab = open_page(root, scenario_port('console-silent'))
    session = tab._awaiting[0]
    assert tab.phase == AWAITING and visible(tab.decision) and visible(tab.idle_box)
    assert tab.preflight_label.cget('text').startswith('Console silent; manual confirmation '
                                                       'required')
    assert tab.idle_box.cget('text') == link.IDLE_CONFIRMATION
    assert tab.idle_confirm.get() == 0                         # never preselected
    assert tab.continue_btn.instate(['disabled'])              # cannot go on unticked
    assert 'your responsibility' in tab.idle_note.cget('text')
    assert 'NOTHING has been sent' in tab.message.cget('text')
    assert session.cli is None                                 # nothing written yet
    tab.continue_connect()                                     # even if called anyway
    assert tab.phase == AWAITING and session.cli is None
    tab.idle_confirm.set(1)
    tab._apply_state()
    assert not tab.continue_btn.instate(['disabled'])
    tab.continue_btn.invoke()
    settle(root, tab)
    assert tab.phase == CONNECTED
    assert tab.connection_verification == link.OPERATOR_CONFIRMED
    assert 'relied on YOUR confirmation' in tab.message.cget('text')


def test_cancelling_a_decision_closes_the_port_with_nothing_sent(root):
    tab = open_page(root, scenario_port('console-silent'))
    session = tab._awaiting[0]
    tab.abort_btn.invoke()
    root.update()
    assert tab.phase == DISCONNECTED and tab._awaiting is None
    assert 'Nothing was sent' in tab.message.cget('text')
    assert session.cli is None and not session.listened


def test_the_checkbox_is_reset_every_time(root):
    tab = open_page(root, scenario_port('console-silent'))
    tab.idle_confirm.set(1)
    tab.abort_btn.invoke()
    root.update()
    tab.connect()
    settle(root, tab)
    assert tab.phase == AWAITING and tab.idle_confirm.get() == 0


def test_press_return_is_a_separate_approved_startup_action(root):
    tab = open_page(root, scenario_port('startup-press-return'))
    assert tab.phase == AWAITING and not visible(tab.idle_box)
    assert tab.preflight_label.cget('text').startswith('Known startup prompt detected')
    assert tab.continue_btn.cget('text') == 'Press Enter to start the console session'
    assert 'Press RETURN to get started' in tab.decision_text.cget('text')
    tab.continue_btn.invoke()
    settle(root, tab)
    assert tab.phase == CONNECTED
    assert tab.connection_verification == link.STARTUP_ACTION


def test_the_setup_dialog_policy_is_shown_and_needs_approval(root):
    tab = open_page(root, scenario_port('startup-setup-dialog'))
    assert tab.phase == AWAITING
    assert tab.continue_btn.cget('text') == 'Answer "no" and continue'
    text = tab.decision_text.cget('text')
    assert 'only with your approval' in text and 'never answers' in text
    tab.continue_btn.invoke()
    settle(root, tab)
    assert tab.phase == CONNECTED and 'answered "no"' in tab.message.cget('text')


@pytest.mark.parametrize('identifier', ['console-silent', 'startup-press-return',
                                        'startup-setup-dialog'])
def test_known_startup_prompts_are_handled_automatically_by_default(root, identifier):
    tab = open_page(root, scenario_port(identifier), auto=True)
    assert tab.phase == CONNECTED and tab._awaiting is None
    assert 'Connected:' in tab.message.cget('text')


def test_a_pending_console_password_needs_the_console_login(root):
    tab = open_page(root, scenario_port('console-pending-password'), auto=True)
    assert tab.phase == ERROR and tab.session is None
    assert 'Console login' in tab.message.cget('text') and \
        'Nothing was sent' in tab.message.cget('text')


@pytest.mark.parametrize('identifier', ['console-pending-confirm', 'console-boot-loader',
                                        'console-unknown'])
def test_unsafe_states_are_refused(root, identifier):
    tab = open_page(root, scenario_port(identifier))
    assert tab.phase == ERROR and tab.session is None and tab._awaiting is None
    assert tab.preflight_label.cget('text').startswith(setup_tab.REFUSED_TITLE)
    assert 'Nothing was sent' in tab.message.cget('text')
    assert not visible(tab.decision)


def test_closing_the_page_while_waiting_closes_the_port(root):
    tab = open_page(root, scenario_port('console-silent'))
    session = tab._awaiting[0]
    tab.destroy()
    import time
    end = time.time() + 3
    while time.time() < end and session.listened:
        root.update()
        time.sleep(0.02)
    assert not session.listened and session.cli is None
