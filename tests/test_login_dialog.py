"""The SSH login dialog (gui.components.login_dialog) and how Configure uses it:
saved logins, missing logins, saving only after the device accepted the login,
refused logins with a retry, and cancelling. db_fake and a fake apply function:
no device, no database server. The password must never appear anywhere visible."""
import os, sys
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))
sys.path.insert(0, os.path.dirname(__file__))
import pytest

tk = pytest.importorskip('tkinter')
from tkinter import messagebox  # noqa: E402

import db_fake  # noqa: E402
from gui import theme  # noqa: E402
from gui.components import login_dialog  # noqa: E402
from gui.components.login_dialog import DeviceLoginDialog, explanation  # noqa: E402
from gui_helpers import new_root, pump  # noqa: E402

RIGHT, WRONG, SAVED = 'Right-Pa55word', 'Wrong-Pa55word', 'Saved-Pa55word'
R1 = {'id': 1, 'name': 'R1', 'ip': '10.0.0.1', 'type': 'router'}


@pytest.fixture
def root():
    r = new_root()
    theme.apply(r)
    r.geometry('900x600+120+80')
    r.update()
    yield r
    r.destroy()


# ---------------------------------------------------------------- the dialog itself
def test_dialog_is_a_modal_child_of_the_main_window_and_centered(root):
    dlg = DeviceLoginDialog(root, [R1])
    dlg.update()
    assert dlg.title() == 'SSH login needed'
    assert str(dlg.master) == str(root) and str(dlg.transient()) == str(root)
    assert dlg.password_entry.cget('show') == '*'                       # masked
    x, y = dlg.winfo_rootx(), dlg.winfo_rooty()
    assert root.winfo_rootx() <= x <= root.winfo_rootx() + root.winfo_width()
    assert root.winfo_rooty() <= y <= root.winfo_rooty() + root.winfo_height()
    assert 'no saved SSH login for R1 (10.0.0.1)' in dlg.info.cget('text')
    dlg.cancel()


def test_explanations_say_why_the_login_is_needed():
    two = [R1, {'id': 2, 'name': 'R2', 'ip': '10.0.0.2'}]
    assert 'no saved SSH login for 2 devices' in explanation(two, 'missing')
    assert 'used for all of them' in explanation(two, 'missing')
    assert 'cannot be read' in explanation([R1], 'unreadable')
    assert 'refused the SSH login' in explanation([R1], 'refused')


def test_ok_needs_both_fields_and_returns_the_answer(root):
    dlg = DeviceLoginDialog(root, [R1])
    dlg.ok()
    assert dlg.winfo_exists() and 'both' in dlg.error.cget('text') and dlg.result is None
    dlg.username.set(' netadmin ')
    dlg.password.set(RIGHT)
    dlg.ok()
    assert dlg.result == {'username': 'netadmin', 'password': RIGHT, 'save': False}


def test_cancel_and_escape_give_none(root):
    dlg = DeviceLoginDialog(root, [R1])
    dlg.username.set('netadmin')
    dlg.cancel()
    assert dlg.result is None
    dlg = DeviceLoginDialog(root, [R1])
    dlg.event_generate('<Escape>')
    root.update()
    assert dlg.result is None


def test_saving_is_off_by_default_and_explained(root):
    dlg = DeviceLoginDialog(root, [R1])
    assert dlg.save.get() == 0 and 'this Apply only' in dlg.save_note.cget('text')
    dlg.save_box.invoke()
    assert 'Saved only after the device accepts it' in dlg.save_note.cget('text')
    dlg.cancel()


def test_replacing_a_saved_login_needs_confirmation(root, monkeypatch):
    answers = []
    monkeypatch.setattr(messagebox, 'askyesno', lambda t, m, **k: answers.append(t) or False)
    dlg = DeviceLoginDialog(root, [R1], reason='refused', replaces=[R1])
    assert 'Replace the saved login' in dlg.save_box.cget('text')
    dlg.username.set('netadmin'); dlg.password.set(RIGHT); dlg.save.set(1)
    dlg.ok()
    assert answers == ['Replace the saved login?'] and dlg.result is None and dlg.winfo_exists()
    monkeypatch.setattr(messagebox, 'askyesno', lambda *a, **k: True)
    dlg.ok()
    assert dlg.result == {'username': 'netadmin', 'password': RIGHT, 'save': True}


def test_password_is_dropped_from_the_dialog_when_closed(root):
    dlg = DeviceLoginDialog(root, [R1])
    dlg.username.set('netadmin'); dlg.password.set(RIGHT)
    var = dlg.password
    dlg.ok()
    assert var.get() == ''


# ---------------------------------------------------------------- Configure + the dialog
@pytest.fixture
def conf(root, monkeypatch):
    shown, questions = [], []
    for name in ('showinfo', 'showerror', 'showwarning'):
        monkeypatch.setattr(messagebox, name, lambda t, m, _n=name, **k: shown.append((_n, t, m)))
    db_fake.reset()
    ids = {
        'R1': db_fake.save_device(None, {'name': 'R1', 'ip': '10.0.0.1', 'type': 'router',
                                         'managed': True, 'status': 'up'}),          # no login
        'R2': db_fake.save_device(None, {'name': 'R2', 'ip': '10.0.0.2', 'type': 'router',
                                         'managed': True, 'status': 'up'}, 'netadmin', SAVED),
    }
    from gui.configure_tab import ConfigureTab
    console = []
    c = ConfigureTab(root, db_fake, log=lambda *a, **k: console.append(' '.join(map(str, a))))
    c.pack(fill='both', expand=True)
    root.update()
    asked, sent = [], []
    state = {'answers': [], 'retry': True}

    def ask(parent, devices, reason='missing', replaces=()):
        asked.append(([d['name'] for d in devices], reason, [d['name'] for d in replaces]))
        return state['answers'].pop(0) if state['answers'] else None

    def askyesno(title, message, **k):
        questions.append(title)
        return state['retry'] if title == 'SSH login refused' else True
    monkeypatch.setattr(login_dialog, 'ask_device_login', ask)
    monkeypatch.setattr(messagebox, 'askyesno', askyesno)

    def apply_fn(creds, commands, checks):
        sent.append((creds['host'], creds['username'], creds['password']))
        if creds['password'] not in (RIGHT, SAVED):
            return False, 'Wrong username or password.'
        return True, 'Applied and verified. Backup: backups/x.txt'
    c.apply_fn = apply_fn
    return {'conf': c, 'root': root, 'ids': ids, 'asked': asked, 'sent': sent, 'state': state,
            'shown': shown, 'questions': questions, 'console': console}


def run(env, *names):
    c, root = env['conf'], env['root']
    c.refresh_devices()
    c.picker.set_checked([env['ids'][n] for n in names])
    c._show_forms_for_device()
    c.ntp_server.set('10.0.0.123')
    c.make_preview()
    c.apply()
    assert pump(root, lambda: not c.busy)


def nothing_secret(env, *secrets):
    c = env['conf']
    visible = ' '.join(env['console']) + str(env['shown']) + c.session.content() + \
        c.status.cget('text') + str(db_fake.get_logs())
    return not any(s in visible for s in secrets)


def answer(user='netadmin', password=RIGHT, save=False):
    return {'username': user, 'password': password, 'save': save}


def test_saved_login_is_used_without_asking(conf):
    run(conf, 'R2')
    assert conf['asked'] == [] and conf['sent'] == [('10.0.0.2', 'netadmin', SAVED)]


def test_missing_login_is_asked_once_and_not_saved_by_default(conf):
    conf['state']['answers'] = [answer()]
    run(conf, 'R1')
    assert conf['asked'] == [(['R1'], 'missing', [])]
    assert conf['sent'] == [('10.0.0.1', 'netadmin', RIGHT)]
    assert db_fake.get_credentials(conf['ids']['R1']) == ('', '')       # used for this Apply only
    assert nothing_secret(conf, RIGHT)


def test_login_is_saved_after_the_device_accepted_it(conf):
    conf['state']['answers'] = [answer(save=True)]
    run(conf, 'R1')
    assert db_fake.get_credentials(conf['ids']['R1']) == ('netadmin', RIGHT)
    assert any('SSH login saved (encrypted)' in line for line in conf['console'])
    assert nothing_secret(conf, RIGHT)


def test_refused_login_is_not_saved_and_can_be_retried(conf):
    conf['state']['answers'] = [answer(password=WRONG, save=True), answer(save=True)]
    run(conf, 'R1')
    assert conf['questions'].count('SSH login refused') == 1
    assert conf['asked'] == [(['R1'], 'missing', []), (['R1'], 'refused', [])]
    assert [s[2] for s in conf['sent']] == [WRONG, RIGHT]               # retried once, R1 only
    assert db_fake.get_credentials(conf['ids']['R1']) == ('netadmin', RIGHT)   # only the good one
    assert conf['conf'].ntp_server.get() == ''                          # applied in the retry
    assert nothing_secret(conf, RIGHT, WRONG)


def test_refused_saved_login_offers_to_replace_it(conf):
    db_fake.save_credentials(conf['ids']['R2'], 'netadmin', WRONG)      # an outdated saved login
    conf['state']['answers'] = [answer(save=True)]
    run(conf, 'R2')
    assert conf['asked'] == [(['R2'], 'refused', ['R2'])]               # it would be replaced
    assert db_fake.get_credentials(conf['ids']['R2']) == ('netadmin', RIGHT)


def test_declining_the_retry_changes_nothing(conf):
    conf['state']['answers'] = [answer(password=WRONG, save=True)]
    conf['state']['retry'] = False
    run(conf, 'R1')
    assert len(conf['sent']) == 1 and db_fake.get_credentials(conf['ids']['R1']) == ('', '')
    assert conf['conf'].ntp_server.get() == '10.0.0.123'                # kept for a later retry
    assert any('not retried' in line for line in conf['console'])


def test_cancelling_the_dialog_cancels_the_apply(conf):
    conf['state']['answers'] = [None]
    run(conf, 'R1')
    assert conf['sent'] == [] and 'Apply cancelled' in conf['conf'].status.cget('text')
    assert db_fake.get_logs() == []                                     # nothing happened
