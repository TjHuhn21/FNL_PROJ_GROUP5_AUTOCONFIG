"""Phase 5.1.2: the Apply section of the Initial Setup page, against simulated mock-lab
consoles. Offline; no real port; synthetic password."""
import os
import sys
import threading

import pytest

sys.path.insert(0, os.path.dirname(__file__))
tk = pytest.importorskip('tkinter')

from test_setup_preview import buttons, disabled, fill, ready  # noqa: E402
from test_setup_tab import pump, root, settle, texts  # noqa: E402,F401
from console import apply as A  # noqa: E402
from gui.setup_tab import APPLYING, DETECTED, ERROR  # noqa: E402
from mocklab.console import MockConsoleBackend  # noqa: E402

PW = 'Synth3tic-Pass!'


def previewed(root, port='SIM8', backend=None, **values):
    tab = ready(root, port, backend=backend)
    fill(tab, password=PW, **values)
    tab.preview()
    assert tab.plan.available and tab.plan.steps
    return tab


def type_apply(tab, phrase=None, password=PW, confirm=PW):
    tab.apply_vars['password'].set(password)
    tab.apply_vars['confirm'].set(confirm)
    tab.apply_vars['phrase'].set(A.confirmation_phrase(tab.plan) if phrase is None else phrase)


def all_text(widget):
    """Every text the page shows: labels, entries, text boxes and tree rows."""
    out = []
    for child in widget.winfo_children():
        cls = child.winfo_class()
        try:
            if cls in ('TEntry', 'Entry'):
                out.append(child.get())
            elif cls == 'Text':
                out.append(child.get('1.0', 'end'))
            elif cls == 'Treeview':
                out += [' '.join(map(str, child.item(i, 'values')))
                        for i in child.get_children()]
            else:
                out.append(str(child.cget('text')))
        except tk.TclError:
            pass
        out += all_text(child)
    return '\n'.join(out)


def test_apply_runs_step_by_step_and_shows_every_status(root):
    tab = previewed(root)
    assert not disabled(tab.apply_btn) and disabled(tab.stop_btn)
    assert 'APPLY SSH Router' in tab.phrase_label.cget('text')
    type_apply(tab)
    tab.apply_btn.invoke()
    # the password fields are emptied at once
    assert tab.apply_vars['password'].get() == '' and tab.apply_vars['confirm'].get() == ''
    assert tab.phase == APPLYING and disabled(tab.disconnect_btn) and disabled(tab.apply_btn)
    settle(root, tab)
    assert tab.phase == DETECTED
    res = tab.apply_result
    assert res.outcome == A.SUCCESS
    rows = {i: tab.apply_tree.item(i, 'values')[1] for i in tab.apply_tree.get_children()}
    assert set(rows.values()) <= {'OK', 'SKIPPED'} and rows['aaa_unchanged'] == 'OK'
    summary = tab.apply_summary.cget('text')
    assert summary.startswith('SSH setup complete on Edge-R1. SSH: enabled (v2). '
                              'Login: netadmin.')
    assert 'Not saved: the settings are lost when the device restarts.' in summary
    assert 'username netadmin privilege 15 secret <SSH_PASSWORD>' in \
        tab.apply_commands.cget('text')
    # the page now shows the re-detected device, and the preview is out of date
    assert tab.result is res.final_detection and tab.result.device.hostname == 'Edge-R1'
    assert 'OUT OF DATE' in tab.preview_widgets['stale'].cget('text')
    assert disabled(tab.apply_btn)                            # once per preview
    assert tab.session.device.saves == 0
    assert any('SSH apply: success' in m for _s, m, _l in tab.logged)


def test_password_never_shown_logged_or_kept(root):
    tab = previewed(root)
    type_apply(tab)
    tab.apply_btn.invoke()
    settle(root, tab)
    assert PW not in all_text(tab)
    assert PW not in str(tab.logged) and PW not in repr(tab.apply_result)
    for steps in tab.apply_result.steps:
        assert PW not in steps.reply


def test_apply_without_confirmation_or_with_a_changed_preview_sends_nothing(root):
    tab = previewed(root)
    before = tab.session.device.running_config()
    type_apply(tab, phrase='APPLY SSH')
    tab.apply_btn.invoke()
    root.update()
    assert tab.phase == DETECTED and tab.session.config_sent == []
    assert 'Nothing was sent' in tab.apply_error.cget('text')
    tab.want['domain_name'].set('changed.local')               # the preview is now stale
    type_apply(tab)
    tab.apply_btn.invoke()
    root.update()
    assert 'out of date' in tab.apply_error.cget('text') and tab.session.config_sent == []
    assert tab.session.device.running_config() == before
    assert any('refused before sending anything' in m for _s, m, _l in tab.logged)


def test_disruptive_steps_need_their_own_tick(root):
    tab = previewed(root, 'SIM10', hostname='', domain='')
    assert [s.step_id for s in A.approvals_needed(tab.plan)] == ['vty_transport[0 4]']
    assert len(tab.approval_boxes) == 1
    assert 'I approve "Allow only SSH on vty 0 4"' in tab.approval_boxes[0].cget('text')
    type_apply(tab)
    tab.apply_btn.invoke()
    root.update()
    assert tab.session.config_sent == [] and 'cut off' in tab.apply_error.cget('text')
    tab.approval_vars['vty_transport[0 4]'].set(1)
    type_apply(tab)
    tab.apply_btn.invoke()
    settle(root, tab)
    assert tab.apply_result.outcome == A.SUCCESS


def test_apply_runs_off_the_tk_thread(root):
    tab = previewed(root)
    session, threads = tab.session, []
    real = session.send_config_line

    def spy(*a, **kw):
        threads.append(threading.current_thread() is threading.main_thread())
        return real(*a, **kw)
    session.send_config_line = spy
    type_apply(tab)
    tab.apply_btn.invoke()
    settle(root, tab)
    assert threads and not any(threads)


def test_stop_takes_effect_between_steps_only(root):
    tab = previewed(root, backend=MockConsoleBackend(delay=0.02))
    session = tab.session
    type_apply(tab)
    tab.apply_btn.invoke()
    assert not disabled(tab.stop_btn)
    pump(root, lambda: 'end' in session.config_sent, 10)       # the first step has finished
    tab.stop_btn.invoke()
    assert disabled(tab.stop_btn)
    settle(root, tab)
    res = tab.apply_result
    assert res.outcome == A.CANCELLED and res.cancelled
    assert session.config_sent[-1] == 'end'                     # never cut in the middle
    assert not session._cancelled.is_set() and session.is_active()
    rows = {i: tab.apply_tree.item(i, 'values')[1] for i in tab.apply_tree.get_children()}
    assert 'NOT RUN' in rows.values() and rows['hostname'] == 'OK'


def test_closing_the_page_during_apply_never_cuts_an_exchange(root):
    tab = previewed(root, backend=MockConsoleBackend(delay=0.02))
    session = tab.session
    type_apply(tab)
    tab.apply_btn.invoke()
    pump(root, lambda: 'configure terminal' in session.config_sent, 10)
    tab.destroy()
    assert not session._cancelled.is_set()                    # not cut mid-exchange
    assert pump(root, lambda: not session.is_active(), 20)     # closed once the step ended
    sent = session.config_sent
    assert sent.count('configure terminal') == sent.count('end')


def test_the_known_key_size_question_is_answered(root):
    tab = previewed(root, 'SIM21', hostname='', domain='',
                    backend=MockConsoleBackend(delay=0, edge_cases=True))
    tab.session.console = {'modulus_question_on': 'crypto key generate rsa modulus 2048'}
    type_apply(tab)
    tab.apply_btn.invoke()
    settle(root, tab)
    assert tab.phase == DETECTED and tab.apply_tree.item('rsa', 'values')[1] == 'OK'


def test_an_unexpected_question_is_shown_with_recovery(root):
    tab = previewed(root, 'SIM21', hostname='', domain='',
                    backend=MockConsoleBackend(delay=0, edge_cases=True))
    tab.session.console = {'modulus_question_on': 'crypto key generate rsa modulus 2048'}
    next(s for s in tab.plan.steps if s.step_id == 'rsa').answers = ()   # not expected
    type_apply(tab)
    tab.apply_btn.invoke()
    settle(root, tab)
    assert tab.phase == ERROR and tab.session is None            # the console was closed
    assert tab.apply_tree.item('rsa', 'values')[1] == 'NOT VERIFIED'
    assert 'How many bits in the modulus' in tab.apply_tree.item('rsa', 'values')[2]
    assert 'never answers device questions' in tab.apply_recovery.cget('text')


def test_only_apply_and_stop_were_added(root):
    tab = previewed(root)
    names = {b.lower() for b in buttons(tab)}
    assert {'apply ssh configuration', 'stop after the current step'} <= names
    assert not any(w in n for n in names for w in ('save', 'write', 'reload'))


def test_a_failed_step_and_its_reason_go_to_the_config_log(root):
    # the first physical run: the reason was only in the table and was lost with the page
    tab = previewed(root)
    tab.session.console = {'reject_on': 'username netadmin privilege 15 secret <SSH_PASSWORD>'}
    type_apply(tab)
    tab.apply_btn.invoke()
    settle(root, tab)
    lines = [m for _s, m, _l in tab.logged if m.startswith('SSH apply step')]
    assert lines and 'Create the new administrator account' in lines[0]
    assert 'FAILED' in lines[0] and 'rejected the command' in lines[0]
    assert PW not in str(tab.logged)
