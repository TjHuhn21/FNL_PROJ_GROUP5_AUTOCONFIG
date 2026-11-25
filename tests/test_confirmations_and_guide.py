"""Confirmations for important or risky actions (gui/components/dialogs.confirm and where
it is used) and the new-user guide (gui/guide.py, gui/guide_content.py). No device, no
database (the in-memory sample store)."""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))
sys.path.insert(0, os.path.dirname(__file__))

import pytest

tk = pytest.importorskip('tkinter')
from tkinter import messagebox, ttk  # noqa: E402

import db_fake  # noqa: E402
from config.risk import disconnect_risks  # noqa: E402
from gui import activity, guide, guide_content, theme  # noqa: E402
from gui.components import dialogs  # noqa: E402
from gui_helpers import new_root, pump  # noqa: E402

PASSWORD = 'Rtr-Pa55word!'


@pytest.fixture
def root():
    r = new_root()
    theme.apply(r)
    yield r
    try:
        r.destroy()
    except tk.TclError:
        pass


@pytest.fixture
def answers(monkeypatch):
    """Answer the shared confirmations from a list (True / False), recording each one."""
    asked, queue = [], []

    def runner(title, message, **options):
        asked.append((title, message, options))
        if options.get('kind') != 'confirm':
            return None
        return queue.pop(0) if queue else True
    monkeypatch.setattr(dialogs, '_runner', runner)
    return asked, queue


@pytest.fixture
def app(monkeypatch):
    for name in ('showinfo', 'showerror', 'showwarning'):
        monkeypatch.setattr(messagebox, name, lambda *a, **k: None)
    db_fake.reset()
    r = new_root()
    from gui.main_window import build_main_window
    refs = build_main_window(r, db_fake, demo_store=True)
    r.update()
    yield r, refs
    try:
        r.destroy()
    except tk.TclError:
        pass


def add_devices():
    ids = {}
    for name, ip, kind in (('R1', '10.0.0.1', 'router'), ('SW1', '10.0.0.2', 'switch'),
                           ('SW2', '10.0.0.3', 'switch')):
        ids[name] = db_fake.save_device(None, {'name': name, 'ip': ip, 'type': kind,
                                               'managed': True, 'status': 'up'}, 'admin',
                                        PASSWORD)
    return ids


# ---------------------------------------------------------------- the shared dialog
def test_a_dangerous_confirmation_has_a_red_button_and_cancel_has_the_focus(root):
    dialog = dialogs.ConfirmDialog(root, 'Delete device', 'Delete R1?', 'Delete device',
                                   danger=True)
    root.update()
    assert dialog.confirm_button.cget('text') == 'Delete device'       # says what it does
    assert dialog.confirm_button.cget('style') == 'Danger.TButton'
    assert dialog.focus_get() in (dialog.cancel_button, None)          # None: not in front
    dialog.cancel_button.focus_force()
    root.update()
    dialog._enter()                                                    # Enter = Cancel
    assert dialog.result is False


def test_a_normal_confirmation_is_green_and_escape_cancels(root):
    dialog = dialogs.ConfirmDialog(root, 'Sign out', 'Sign out of NetCommand?', 'Sign out')
    root.update()
    assert dialog.confirm_button.cget('style') == 'Accent.TButton'
    assert dialog.focus_get() in (dialog.confirm_button, None)   # None: window not in front
    dialog.confirm_button.focus_force()
    root.update()
    dialog.confirm_button.event_generate('<Escape>')             # Esc: Cancel, whatever has focus
    root.update()
    assert dialog.result is False and not dialog.winfo_exists()


def test_view_commands_shows_the_details(root):
    dialog = dialogs.ConfirmDialog(root, 'Apply', 'Apply?', 'Apply to R1',
                                   details='! R1\n  vlan 10', danger=True)
    root.update()
    assert not dialog.details_holder.winfo_manager()
    dialog.toggle_details()
    assert dialog.details_holder.winfo_manager() and \
        'vlan 10' in dialog.details_box.get('1.0', 'end')


def test_confirm_logs_the_answer(answers, monkeypatch):
    lines = []
    monkeypatch.setattr('gui.event_log.log_event', lambda c, m, *a, **k: lines.append(m))
    asked, queue = answers
    queue[:] = [False, True]
    assert dialogs.confirm('Sign out', 'Sign out?', 'Sign out', log=('app', 'Sign out')) is False
    assert dialogs.confirm('Sign out', 'Sign out?', 'Sign out', log=('app', 'Sign out')) is True
    assert lines == ['Sign out cancelled.', 'Sign out confirmed.']


# ---------------------------------------------------------------- commands that can cut access
def test_disconnect_risks():
    assert disconnect_risks(['interface Gi0/0', 'shutdown'], '10.0.0.1')
    assert not disconnect_risks(['interface Gi0/0', 'no shutdown'], '10.0.0.1')
    same_net = disconnect_risks(['interface Gi0/0', 'ip address 10.0.0.9 255.255.255.0'],
                                '10.0.0.1')
    assert same_net and '10.0.0.9' in same_net[0]
    assert not disconnect_risks(['interface Gi0/1', 'ip address 192.168.5.1 255.255.255.0'],
                                '10.0.0.1')                           # another network: fine
    assert disconnect_risks(['ip route 0.0.0.0 0.0.0.0 10.0.0.254'], '10.0.0.1')
    uplink = disconnect_risks(['interface Gi0/1', 'switchport port-security violation shutdown'],
                              '10.0.0.2')
    assert uplink and 'uplink' in uplink[0]
    assert not disconnect_risks(['interface Fa0/5', 'switchport port-security violation shutdown'],
                                '10.0.0.2')
    assert not disconnect_risks(['vlan 10', 'name STAFF'], '10.0.0.2')


# ---------------------------------------------------------------- Configure
def test_apply_is_blocked_when_the_settings_changed_after_the_preview(app, answers):
    root, refs = app
    add_devices()
    conf = refs['configure']
    conf.refresh_devices()
    conf.picker.set_checked([d['id'] for d in conf.devices if d['name'] == 'R1'])
    conf.hostname.set('EDGE1')
    conf.make_preview()
    assert not conf.preview_outdated()
    conf.hostname.set('EDGE2')
    assert conf.preview_outdated()
    sent = []
    conf.apply_fn = lambda creds, commands, checks: sent.append(commands) or (True, 'ok')
    conf.apply()
    assert sent == [] and 'Click Preview again' in conf.status.cget('text')
    assert answers[0][-1][2]['kind'] == 'warning'                     # told, not asked


def test_apply_summary_names_every_device_and_offers_the_commands(app, answers):
    root, refs = app
    add_devices()
    conf = refs['configure']
    conf.refresh_devices()
    conf.picker.set_checked([d['id'] for d in conf.devices if d['type'] == 'switch'])
    conf.forms.select(0)
    conf.vid.set('10'); conf.vname.set('STAFF'); conf.add_vlan()
    conf.make_preview()
    asked, queue = answers
    queue[:] = [False]                                                 # cancel
    conf.apply()
    title, message, options = asked[-1]
    assert options['confirm_text'] == 'Apply to 2 devices' and options['danger']
    assert 'SW1 (switch, 10.0.0.2): ' in message and 'A backup is saved first' in message
    assert 'vlan 10' in options['details'] and not conf.busy           # nothing sent


def test_commands_that_may_disconnect_ask_again(app, answers):
    root, refs = app
    add_devices()
    conf = refs['configure']
    conf.refresh_devices()
    conf.picker.set_checked([d['id'] for d in conf.devices if d['name'] == 'R1'])
    conf.default_route.set('10.0.0.254')
    conf.make_preview()
    asked, queue = answers
    queue[:] = [True, False]                    # yes to the summary, no to the risk warning
    conf.apply()
    assert asked[-1][0] == 'May disconnect NetCommand' and 'R1' in asked[-1][1]
    assert not conf.busy


def test_unsaved_settings_and_clear_form(app, answers):
    root, refs = app
    conf = refs['configure']
    assert not conf.has_unsaved()
    conf.ntp_server.set('10.0.0.123')
    assert conf.has_unsaved()
    asked, queue = answers
    queue[:] = [False]
    assert conf.clear_form() is False and conf.ntp_server.get() == '10.0.0.123'
    assert conf.clear_form() is True and not conf.has_unsaved()
    assert asked[-1][2]['danger']


def test_removing_several_rows_asks_first(app, answers):
    root, refs = app
    conf = refs['configure']
    conf.vlans = [(10, 'A'), (20, 'B')]
    conf._show_lists()
    conf.vlan_tree.selection_set(conf.vlan_tree.get_children())
    asked, queue = answers
    queue[:] = [False]
    conf.remove_vlan()
    assert len(conf.vlans) == 2 and asked[-1][2]['confirm_text'] == 'Remove 2 VLANs'
    conf.vlan_tree.selection_set(conf.vlan_tree.get_children()[:1])
    before = len(asked)
    conf.remove_vlan()                                                 # one row: no question
    assert len(conf.vlans) == 1 and len(asked) == before


# ---------------------------------------------------------------- Scan
def test_approve_lists_new_and_registered_devices_and_needs_a_selection(app, answers):
    root, refs = app
    scan = refs['scan']
    db_fake.save_device(None, {'name': 'R1', 'ip': '10.0.0.1', 'type': 'router',
                               'managed': True, 'status': 'up'})
    found = [{'name': 'R1', 'ip': '10.0.0.1', 'type': 'router', 'managed': True},
             {'name': 'SW9', 'ip': '10.0.0.9', 'type': 'switch', 'managed': True}]
    scan.show_found(found, [])
    root.update()
    scan.tree.selection_set(())
    root.update()
    assert scan.approve_btn.instate(['disabled'])                      # 0 selected: off
    scan.select_all()
    root.update()
    assert not scan.approve_btn.instate(['disabled'])
    asked, queue = answers
    queue[:] = [False]
    scan.approve()
    message = asked[-1][1]
    assert message.startswith('Save 2 devices to the database?')
    assert 'New (1): SW9' in message and 'Already registered' in message and 'R1' in message
    assert db_fake.get_device_by_ip('10.0.0.9') is None                # cancelled


def test_a_new_scan_asks_before_discarding_unapproved_results(app, answers):
    root, refs = app
    scan = refs['scan']
    scan.show_found([{'name': 'SW9', 'ip': '10.0.0.9', 'type': 'switch', 'managed': True}], [])
    scan.demo.set(1)
    asked, queue = answers
    queue[:] = [False]
    scan.on_scan()
    assert asked[-1][0] == 'Discard scan results' and not scan.scanning


# ---------------------------------------------------------------- Devices
def test_delete_explains_what_happens_and_several_can_be_deleted(app, answers):
    root, refs = app
    ids = add_devices()
    devices = refs['devices']
    devices.refresh()
    devices.tree.selection_set([str(ids['SW1']), str(ids['SW2'])])
    asked, queue = answers
    queue[:] = [True]
    devices.delete()
    title, message, options = asked[-1]
    assert options['confirm_text'] == 'Delete 2 devices' and options['danger']
    assert 'SW1 (10.0.0.2)' in message and 'history' in message
    assert db_fake.get_device(ids['SW1']) is None and db_fake.get_device(ids['SW2']) is None


def test_an_ip_change_asks_first(app, answers):
    root, refs = app
    ids = add_devices()
    from gui.devices_tab import DeviceDialog
    saved = []
    dialog = DeviceDialog(root, db_fake, db_fake.get_device(ids['R1']), lambda: saved.append(1))
    dialog.vars['ip'].set('10.0.0.20')
    asked, queue = answers
    queue[:] = [False]
    dialog.save()
    assert asked[-1][0] == 'Change IP address' and '10.0.0.1 to 10.0.0.20' in asked[-1][1]
    assert db_fake.get_device(ids['R1'])['ip'] == '10.0.0.1' and not saved
    queue[:] = [False]                                       # Cancel: discard? -> Stay
    assert dialog.close() is False and dialog.winfo_exists()
    queue[:] = [True]
    assert dialog.close() is True


def test_devices_empty_state_offers_the_scan_page(app):
    root, refs = app
    devices = refs['devices']
    devices.refresh()
    assert devices.empty.cget('text') == guide_content.EMPTY['devices']
    assert devices.go_scan_btn.winfo_manager()
    devices.go_scan_btn.invoke()
    assert refs['current_page']() == 'scan'


# ---------------------------------------------------------------- leaving the app
def test_close_warns_about_running_work_then_unsaved_settings(app, answers):
    from main import confirm_leaving
    root, refs = app
    asked, queue = answers
    activity.start('configure', 'A configuration is still being applied to MOCK-R1.')
    queue[:] = [False]
    assert confirm_leaving(root, refs, 'close') is False
    title, message, options = asked[-1]
    assert 'MOCK-R1' in message and options['confirm_text'] == 'Close anyway' and \
        options['cancel_text'] == 'Wait'
    activity.finish('configure')
    refs['configure'].ntp_server.set('10.0.0.1')
    queue[:] = [True]
    assert confirm_leaving(root, refs, 'sign out') is True
    assert asked[-1][2]['confirm_text'] == 'Discard' and asked[-1][2]['cancel_text'] == 'Stay'
    refs['configure'].ntp_server.set('')
    confirm_leaving(root, refs, 'sign out')
    assert asked[-1][0] == 'Sign out of NetCommand?' and asked[-1][2]['confirm_text'] == 'Sign out'


def test_closing_the_sign_in_window_asks_first():
    from types import SimpleNamespace
    from main import close_sign_in_question

    class Var:
        def __init__(self, value=''):
            self.value = value

        def get(self):
            return self.value
    plain = SimpleNamespace(busy=False, current='login', vars={'email': Var('a@b.c')})
    assert close_sign_in_question(plain) == ('Close NetCommand?', 'Close', False)
    busy = SimpleNamespace(busy=True, current='login', vars={})
    assert close_sign_in_question(busy)[1:] == ('Close anyway', True)
    code = SimpleNamespace(busy=False, current='login_code', vars={})
    assert 'verification code' in close_sign_in_question(code)[0]
    form = SimpleNamespace(busy=False, current='register', vars={'reg_name': Var('Jo')})
    assert close_sign_in_question(form)[1] == 'Discard and close'
    empty = SimpleNamespace(busy=False, current='register', vars={'reg_name': Var('')})
    assert close_sign_in_question(empty)[1] == 'Close'


def test_clearing_the_console_asks_and_says_nothing_is_deleted(app, answers):
    root, refs = app
    asked, queue = answers
    queue[:] = [False]
    assert refs['console'].clear() is False
    assert 'Saved logs are not deleted' in asked[-1][1]


# ---------------------------------------------------------------- the guide
def test_tour_steps_follow_the_role():
    viewer = [s['key'] for s in guide.steps_for(['dashboard', 'devices', 'topology',
                                                 'findings', 'logs'])]
    assert 'configure' not in viewer and 'accounts' not in viewer and 'scan' not in viewer
    assert viewer[0] == 'sidebar' and 'command' in viewer
    admin = [s['key'] for s in guide.steps_for(['dashboard', 'scan', 'devices', 'topology',
                                                'findings', 'configure', 'setup', 'logs',
                                                'accounts'])]
    assert 'accounts' in admin and len(admin) == len(guide_content.TOUR_STEPS)


def test_every_page_has_help_and_every_step_a_known_target():
    from gui.main_window import PAGES
    for key, _label in PAGES + [('accounts', 'Accounts')]:
        title, intro, sections = guide.page_help_sections(key)
        assert intro and sections[0][1]
    for step in guide_content.TOUR_STEPS:
        assert step['target'] in ('rail', 'page', 'command', 'inspector', 'console', 'help')
        assert step['title'] and step['text']


def test_the_tour_flag_is_saved_per_user(monkeypatch):
    db_fake.reset()
    assert not guide.get_flag(db_fake, '7', guide.TOUR_DONE)
    guide.set_flag(db_fake, '7', guide.TOUR_DONE)
    assert guide.get_flag(db_fake, '7', guide.TOUR_DONE)
    assert not guide.get_flag(db_fake, '8', guide.TOUR_DONE)           # another user

    class NoTable:                                   # schema_update_user_settings.sql not run
        def get_user_setting(self, *a):
            raise RuntimeError('no table')

        def set_user_setting(self, *a):
            raise RuntimeError('no table')
    assert guide.set_flag(NoTable(), '9', guide.TOUR_DONE) is False
    assert guide.get_flag(NoTable(), '9', guide.TOUR_DONE)            # kept locally instead


def test_welcome_skip_is_remembered_and_the_tour_walks_the_steps(app, monkeypatch):
    root, refs = app
    monkeypatch.delenv('NETCOMMAND_TOUR', raising=False)
    g = refs['guide']
    assert g.maybe_welcome() is True and g.welcome.winfo_exists()
    g.welcome_skip.invoke()
    assert g.tour_done() and g.maybe_welcome() is False               # never again
    tour = g.start_tour()                                              # ? Help: restart
    root.update()
    assert tour.counter.cget('text') == f'Step 1 of {len(tour.steps)}'
    assert tour.back_btn.instate(['disabled'])
    tour.next()
    assert refs['current_page']() == 'dashboard' and tour.popup.winfo_ismapped()
    tour.next()
    assert refs['current_page']() == 'scan'
    tour.back()
    assert tour.index == 1
    while not tour.ended:
        tour.next()
    assert not tour.popup.winfo_exists()


def test_help_for_this_page_and_shortcuts(app):
    root, refs = app
    g = refs['guide']
    refs['show_page']('scan')
    g.page_help()
    text = g.help_window.text.get('1.0', 'end')
    assert 'Help: Scan' in text and '5 failed device logins' in text
    g.shortcuts()
    assert 'Ctrl+K' in g.help_window.text.get('1.0', 'end')


def test_getting_started_checklist_ticks_real_progress(app):
    root, refs = app
    overview = refs['dashboard']
    overview.refresh(force=True)
    root.update()
    assert overview.checklist.winfo_manager()                          # a new installation
    assert overview.checklist_done == {'scan': False, 'approve': False, 'topology': False,
                                       'review': False}
    add_devices()
    refs['show_page']('topology')
    refs['show_page']('dashboard')
    overview.refresh(force=True)
    assert overview.checklist_done['approve'] and overview.checklist_done['topology']
    overview.hide_checklist()
    overview.refresh(force=True)
    assert not overview.checklist.winfo_manager()


def test_tooltips_are_attached(app):
    root, refs = app
    assert refs['scan'].entries['Seed IP'].nc_tip.text == guide_content.TOOLTIPS['seed_ip']
    assert refs['help_button'].nc_tip is not None
    labels = [w for w in _all(refs['configure'].trunk_editor) if hasattr(w, 'nc_tip')]
    assert {str(w.cget('text')) for w in labels} >= {'Native VLAN', 'encapsulation dot1q'}


def _all(widget):
    out, stack = [], [widget]
    while stack:
        w = stack.pop()
        stack.extend(w.winfo_children())
        out.append(w)
    return out
