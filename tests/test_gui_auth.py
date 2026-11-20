"""Desktop sign-in GUI: the sign-in window, role-based workbench, Accounts page, session
watcher and main.py's start-up flow. The real desktop client talks to the real backend
API in-process (no network, no database, no real email). Background calls are made
synchronous so the tests are deterministic. Skipped when no window can be opened."""
import logging
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))
import pytest

tk = pytest.importorskip('tkinter')
from tkinter import messagebox  # noqa: E402

import db_fake  # noqa: E402
from auth_api_harness import PASSWORD, Backend  # noqa: E402
from desktop_auth.api_client import UNREACHABLE, ApiConfigError, AuthApiClient  # noqa: E402
from desktop_auth.session import Access, AuthSession  # noqa: E402
from gui import background  # noqa: E402
from gui.auth_window import APPROVAL_NEEDED, SignInWindow  # noqa: E402
from gui.session_watch import SessionWatcher, SignedInContext  # noqa: E402
from gui_helpers import new_root  # noqa: E402


@pytest.fixture(autouse=True)
def synchronous(monkeypatch):
    monkeypatch.setattr(background, 'run_async', background.run_now)


@pytest.fixture
def backend():
    return Backend()


@pytest.fixture
def root():
    r = new_root()
    yield r
    try:
        r.destroy()
    except tk.TclError:
        pass


def sign_in_window(root, backend):
    signed = []
    win = SignInWindow(root, backend.client, signed.append)
    win.pack()
    return win, signed


# ================================================================ sign-in window
def test_login_needs_the_code_before_a_session_exists(root, backend):
    uid = backend.user()
    win, signed = sign_in_window(root, backend)
    win.vars['email'].set('user@example.com')
    win.vars['password'].set(PASSWORD)
    win.submit_login()
    assert win.current == 'login_code' and signed == []
    assert win.vars['password'].get() == ''                       # cleared once sent
    assert backend.repo.list_sessions(uid) == []                   # password alone: nothing
    code = backend.mailer.last_code()
    win.vars['code'].set(code)
    win.submit_login_code()
    (session,) = signed
    assert isinstance(session, AuthSession) and session.role == 'viewer'
    assert session.email == 'user@example.com' and win.vars['code'].get() == ''
    assert backend.client.get_session(session.token())['user_id'] == uid
    assert code not in win.message.cget('text')


def test_wrong_password_and_unknown_account_show_the_same_message(root, backend):
    backend.user()
    win, signed = sign_in_window(root, backend)
    texts = []
    for email, password in [('user@example.com', 'Test-only wrong password'),
                            ('nobody@example.com', PASSWORD)]:
        win.vars['email'].set(email)
        win.vars['password'].set(password)
        win.submit_login()
        texts.append(win.message.cget('text'))
        assert win.current == 'login' and win.vars['password'].get() == ''
    assert texts[0] == texts[1] and 'incorrect' in texts[0] and signed == []
    assert 'Test-only wrong password' not in texts[0]


def test_wrong_code_keeps_asking(root, backend):
    backend.user()
    win, signed = sign_in_window(root, backend)
    win.vars['email'].set('user@example.com')
    win.vars['password'].set(PASSWORD)
    win.submit_login()
    right = backend.mailer.last_code()
    win.vars['code'].set('000000' if right != '000000' else '111111')
    win.submit_login_code()
    assert signed == [] and win.current == 'login_code'
    assert 'wrong' in win.message.cget('text')
    win.vars['code'].set(right)
    win.submit_login_code()
    assert len(signed) == 1


def test_inactive_account_gets_the_servers_message(root, backend):
    backend.user(status='pending_approval')
    win, signed = sign_in_window(root, backend)
    win.vars['email'].set('user@example.com')
    win.vars['password'].set(PASSWORD)
    win.submit_login()
    assert win.current == 'login' and 'approval' in win.message.cget('text') and signed == []


def test_registration_and_verification(root, backend):
    win, _ = sign_in_window(root, backend)
    win.show('register')
    win.vars['reg_email'].set('new@example.com')
    win.vars['reg_name'].set('New Person')
    win.vars['reg_password'].set(PASSWORD)
    win.vars['reg_confirm'].set(PASSWORD + 'x')
    win.submit_register()
    assert 'not the same' in win.message.cget('text') and backend.mailer.sent == []
    assert win.vars['reg_password'].get() == '' == win.vars['reg_confirm'].get()
    win.vars['reg_password'].set(PASSWORD)
    win.vars['reg_confirm'].set(PASSWORD)
    win.submit_register()
    assert win.current == 'register_code'
    assert 'If this email address can be registered' in win.message.cget('text')
    win.vars['reg_code'].set(backend.mailer.last_code())
    win.submit_register_code()
    assert win.current == 'login' and win.message.cget('text') == APPROVAL_NEEDED
    assert win.vars['email'].get() == 'new@example.com'
    assert backend.repo.find_user_by_email('new@example.com')['status'] == 'pending_approval'


def test_taken_address_registers_without_revealing_it(root, backend):
    backend.user('taken@example.com')
    win, _ = sign_in_window(root, backend)
    win.show('register')
    for name, value in [('reg_email', 'taken@example.com'), ('reg_name', 'T'),
                        ('reg_password', PASSWORD), ('reg_confirm', PASSWORD)]:
        win.vars[name].set(value)
    win.submit_register()
    assert win.current == 'register_code' and backend.mailer.sent == []


def test_verifying_an_account_created_earlier(root, backend):
    backend.client.register('later@example.com', 'Later', PASSWORD)
    backend.clock.advance(61)
    win, _ = sign_in_window(root, backend)
    win.show('register_resend')
    win.vars['resend_email'].set('later@example.com')
    win.submit_register_resend()
    assert win.current == 'register_code'
    win.vars['reg_code'].set(backend.mailer.last_code())
    win.submit_register_code()
    assert win.message.cget('text') == APPROVAL_NEEDED


def test_resend_login_code(root, backend):
    backend.user()
    win, signed = sign_in_window(root, backend)
    win.vars['email'].set('user@example.com')
    win.vars['password'].set(PASSWORD)
    win.submit_login()
    old = backend.mailer.last_code()
    win.resend_code()
    assert 'Try again in' in win.message.cget('text')            # cooldown
    backend.clock.advance(61)
    win.resend_code()
    new = backend.mailer.last_code()
    assert len(backend.mailer.sent) == 2
    win.vars['code'].set(old)
    win.submit_login_code()
    assert signed == []
    win.vars['code'].set(new)
    win.submit_login_code()
    assert len(signed) == 1


def test_server_unreachable(root):
    def down(request, timeout=None):
        raise OSError('connection refused')
    win = SignInWindow(root, AuthApiClient('http://127.0.0.1:8000', opener=down), lambda s: None)
    win.vars['email'].set('user@example.com')
    win.vars['password'].set(PASSWORD)
    win.submit_login()
    assert win.message.cget('text') == UNREACHABLE and win.current == 'login'


def test_the_token_stays_in_memory_only(root, backend, monkeypatch, tmp_path, caplog):
    monkeypatch.chdir(tmp_path)
    backend.user()
    with caplog.at_level(logging.DEBUG):
        win, signed = sign_in_window(root, backend)
        win.vars['email'].set('user@example.com')
        win.vars['password'].set(PASSWORD)
        win.submit_login()
        win.vars['code'].set(backend.mailer.last_code())
        win.submit_login_code()
    token = signed[0].token()
    assert token not in caplog.text and PASSWORD not in caplog.text
    assert token not in str(dict(os.environ))
    assert list(tmp_path.iterdir()) == []                         # nothing written
    assert all(token not in v.get() for v in win.vars.values())
    assert token not in repr(signed[0]) and token not in win.message.cget('text')


# ================================================================ role-based workbench
def signed_in(backend, role, email=None):
    email = email or f'{role}@example.com'
    backend.user(email, role=role)
    data = backend.sign_in_data(email)
    return AuthSession(token=data['token'], user_id=data['user_id'], role=data['role'],
                       email=email, idle_timeout_seconds=data['idle_timeout_seconds'],
                       expires_in_seconds=data['expires_in_seconds'])


def workbench(root, backend, role, monkeypatch, ended=None):
    for name in ('showinfo', 'showerror', 'showwarning'):
        monkeypatch.setattr(messagebox, name, lambda *a, **k: None)
    db_fake.reset()
    session = signed_in(backend, role)
    signed_out = []
    account = SignedInContext(backend.client, session, lambda: signed_out.append(True),
                              (ended if ended is not None else []).append)
    from gui.main_window import build_main_window
    refs = build_main_window(root, db_fake, demo_store=True, access=session.access,
                             account=account)
    return refs, session, signed_out


def test_viewer_is_read_only(root, backend, monkeypatch):
    refs, session, _ = workbench(root, backend, 'viewer', monkeypatch)
    assert 'scan' not in refs['pages'] and 'configure' not in refs['pages']
    assert 'accounts' not in refs['pages'] and 'accounts' not in refs
    assert set(refs['nav'].items) == set(refs['pages'])
    refs['show_page']('scan')
    refs['show_page']('configure')
    assert refs['current_page']() == 'dashboard'
    refs['inspector'].on_configure('SW1')                           # inspector's Configure
    assert refs['current_page']() == 'dashboard'
    assert refs['devices'].add_btn.instate(['disabled'])
    assert refs['devices'].edit_btn.instate(['disabled'])
    assert refs['devices'].delete_btn.instate(['disabled'])
    import gui.devices_tab as devices_module
    monkeypatch.setattr(devices_module, 'DeviceDialog',
                        lambda *a, **k: pytest.fail('a device dialog was opened'))
    refs['devices'].add()                                           # e.g. a keyboard shortcut
    refs['devices'].edit()
    refs['devices'].delete()
    assert refs['findings'].run_btn.instate(['disabled'])
    assert refs['findings'].send_btn.instate(['disabled'])
    refs['findings'].run()
    assert not refs['findings'].busy
    refs['show_page']('devices')
    assert refs['current_page']() == 'devices'                      # viewing is allowed
    assert 'Viewer' in refs['user_label'].cget('text')


def test_operator_can_scan_and_configure_but_not_manage_accounts(root, backend, monkeypatch):
    refs, _, _ = workbench(root, backend, 'operator', monkeypatch)
    assert {'scan', 'configure', 'devices', 'findings'} <= set(refs['pages'])
    assert 'accounts' not in refs['pages']
    assert not refs['devices'].add_btn.instate(['disabled'])
    assert not refs['findings'].run_btn.instate(['disabled'])
    refs['show_page']('configure')
    assert refs['current_page']() == 'configure'
    refs['show_page']('accounts')
    assert refs['current_page']() == 'configure'


def test_admin_has_everything_plus_accounts(root, backend, monkeypatch):
    refs, _, signed_out = workbench(root, backend, 'admin', monkeypatch)
    assert refs['pages'][-1] == 'accounts' and 'scan' in refs['pages']
    refs['show_page']('accounts')
    assert refs['current_page']() == 'accounts'
    refs['sign_out_button'].invoke()
    assert signed_out == [True]


def test_accounts_page_actions(root, backend, monkeypatch):
    refs, session, _ = workbench(root, backend, 'admin', monkeypatch)
    monkeypatch.setattr(messagebox, 'askyesno', lambda *a, **k: True)
    a = backend.user('a@example.com', status='pending_approval')
    b = backend.user('b@example.com', status='pending_approval')
    page = refs['accounts']
    page.refresh()
    assert list(page.tree.get_children()) == [str(a), str(b)]
    page.tree.selection_set(str(a))
    page.role.set('operator')
    page.approve()
    assert backend.repo.get_user(a)['status'] == 'active'
    assert backend.repo.get_user(a)['role'] == 'operator'
    page.tree.selection_set(str(b))
    page.reject()
    assert backend.repo.get_user(b)['status'] == 'rejected'
    page.filter.set('all')
    page.refresh()
    page.tree.selection_set(str(a))
    page.disable()
    assert backend.repo.get_user(a)['status'] == 'disabled'
    page.tree.selection_set(str(a))
    page.disable()                                                # already disabled: 409
    assert 'already disabled' in page.status.cget('text')
    page.tree.selection_remove(page.tree.selection())
    page.approve()
    assert 'Select an account' in page.status.cget('text')


def test_accounts_page_signs_out_when_the_session_has_ended(root, backend, monkeypatch):
    ended = []
    refs, session, _ = workbench(root, backend, 'admin', monkeypatch, ended=ended)
    backend.repo.revoke_session(backend.client.get_session(session.token())['session_id'],
                                'logout')
    refs['accounts'].refresh()
    assert ended == ['ended']


def test_demo_mode_is_labelled_and_has_no_accounts(root, monkeypatch):
    db_fake.reset()
    from gui.main_window import build_main_window
    refs = build_main_window(root, db_fake, demo_store=True, access=Access(None, demo=True))
    assert refs['demo_label'].cget('text').startswith('DEMO MODE')
    assert 'accounts' not in refs['pages'] and 'scan' in refs['pages']
    assert 'sign_out_button' not in refs


def test_without_access_everything_is_as_before(root):
    db_fake.reset()
    from gui.main_window import PAGES, build_main_window
    refs = build_main_window(root, db_fake, demo_store=True)
    assert refs['pages'] == [k for k, _ in PAGES]
    assert 'demo_label' not in refs and 'user_label' not in refs


# ================================================================ session watcher
class Ticker:
    def __init__(self):
        self.now = 1000.0

    def __call__(self):
        return self.now


def watcher_for(root, backend, role='viewer', client=None):
    clock = Ticker()
    backend.user(f'{role}@example.com', role=role)
    data = backend.sign_in_data(f'{role}@example.com')
    session = AuthSession(token=data['token'], user_id=data['user_id'], role=role,
                          email='x', idle_timeout_seconds=1800, expires_in_seconds=8 * 3600,
                          clock=clock)
    ended = []
    w = SessionWatcher(root, client or backend.client, session, ended.append, clock=clock,
                       start=False)
    return w, session, clock, ended


def test_idle_session_ends_locally(root, backend):
    w, session, clock, ended = watcher_for(root, backend)
    clock.now += 1799
    w.tick()
    assert ended == []
    clock.now += 1
    w.tick()
    assert ended == ['idle'] and session.token() is None


def test_absolute_lifetime(root, backend):
    w, session, clock, ended = watcher_for(root, backend)
    for _ in range(int(8 * 3600 / 600)):
        clock.now += 600
        w._activity()
        w.tick()
    assert ended == ['expired'] and not session.active


def test_server_check_only_after_activity(root, backend):
    w, session, clock, ended = watcher_for(root, backend)
    calls = len(backend.opener.requests)
    clock.now += 120
    w.tick()                                                        # idle: no server call
    assert len(backend.opener.requests) == calls
    w._activity()
    clock.now += 1
    w.tick()
    assert len(backend.opener.requests) == calls + 1 and ended == []


def test_revoked_or_disabled_sessions_end(root, backend):
    w, session, clock, ended = watcher_for(root, backend)
    backend.repo.set_status(session.user_id, 'disabled', actor_user_id=None)
    clock.now += 61
    w._activity()
    clock.now += 1
    w.tick()
    assert ended == ['ended'] and session.token() is None


def test_role_change_ends_the_session(root, backend):
    w, session, clock, ended = watcher_for(root, backend, role='operator')
    backend.user('boss@example.com', role='admin')
    backend.repo.set_role(session.user_id, 'viewer', actor_user_id=None)
    clock.now += 61
    w._activity()
    clock.now += 1
    w.tick()
    assert ended == ['role_changed']


def test_unreachable_server_does_not_end_the_session(root, backend):
    def down(request, timeout=None):
        raise OSError('down')
    w, session, clock, ended = watcher_for(
        root, backend, client=AuthApiClient('http://127.0.0.1:8000', opener=down))
    clock.now += 61
    w._activity()
    clock.now += 1
    w.tick()
    assert ended == [] and session.active and w.unreachable


# ================================================================ main.py start-up
def test_demo_starts_without_sign_in_and_is_marked(monkeypatch):
    import main
    seen = {}
    monkeypatch.setattr(sys, 'argv', ['main.py', '--demo'])
    monkeypatch.setattr(main, 'choose_store', lambda force: (db_fake, True, None))
    monkeypatch.setattr(main, 'run_workbench', lambda *a, **k: seen.update(k) or main.CLOSED)
    monkeypatch.setattr(main, 'sign_in', lambda client: pytest.fail('sign-in in demo mode'))
    monkeypatch.setattr('desktop_auth.api_client.AuthApiClient',
                        lambda *a, **k: pytest.fail('API client in demo mode'))
    main.main()
    assert seen['access'].demo


def test_a_bad_api_address_stops_and_never_falls_back_to_demo(monkeypatch):
    import main
    shown = []
    monkeypatch.setattr(sys, 'argv', ['main.py'])
    monkeypatch.setenv('NETCOMMAND_API_URL', 'http://10.0.0.5:8000')     # http, not local
    monkeypatch.setattr(messagebox, 'showerror', lambda *a, **k: shown.append(a))
    monkeypatch.setattr(main, 'choose_store', lambda force: pytest.fail('opened the database'))
    monkeypatch.setattr(main, 'run_workbench', lambda *a, **k: pytest.fail('opened the workbench'))
    main.main()
    assert shown and 'https://' in shown[0][1]


def test_closing_the_sign_in_window_exits_without_demo(monkeypatch):
    import main
    monkeypatch.setattr(sys, 'argv', ['main.py'])
    monkeypatch.setenv('NETCOMMAND_API_URL', 'http://127.0.0.1:8000')
    monkeypatch.setattr(main, 'sign_in', lambda client: None)
    monkeypatch.setattr(main, 'choose_store', lambda force: pytest.fail('opened the database'))
    monkeypatch.setattr(main, 'run_workbench', lambda *a, **k: pytest.fail('opened the workbench'))
    main.main()


def test_sign_out_returns_to_the_sign_in_window(monkeypatch):
    import main
    monkeypatch.setattr(sys, 'argv', ['main.py'])
    monkeypatch.setenv('NETCOMMAND_API_URL', 'http://127.0.0.1:8000')
    sessions = [AuthSession('A' * 43, 1, 'operator', 'op@example.com'), None]
    stores, runs = [], []
    monkeypatch.setattr(main, 'sign_in', lambda client: sessions.pop(0))
    monkeypatch.setattr(main, 'choose_store',
                        lambda force: stores.append(force) or (db_fake, False, None))
    monkeypatch.setattr(main, 'run_workbench',
                        lambda *a, **k: runs.append(k['access']) or main.SIGNED_OUT)
    main.main()
    assert stores == [False] and len(runs) == 1 and not runs[0].demo


def test_end_server_session_clears_first_then_logs_out():
    import main
    seen = []

    class Client:
        def logout(self, token):
            seen.append((token, session.token()))
    session = AuthSession('B' * 43, 1, 'viewer', 'v@example.com')
    main.end_server_session(Client(), session)
    assert seen == [('B' * 43, None)] and not session.active


def run_workbench_and(monkeypatch, backend, action):
    """main.run_workbench with a real signed-in session; `action(refs)` runs instead of
    the event loop."""
    import main
    import gui.main_window as mw
    captured, roots = {}, []
    real_build = mw.build_main_window
    monkeypatch.setattr(mw, 'build_main_window',
                        lambda *a, **k: captured.setdefault('refs', real_build(*a, **k)))

    def make_root():
        """A plain Tk window whose event loop runs `action` instead. (A real ctk.CTk()
        would switch the whole test process to high-DPI mode on Windows, changing the
        window sizes later tests see.)"""
        root = new_root()
        root.mainloop = lambda n=0: action(captured['refs'])
        roots.append(root)
        return root
    shown = []
    monkeypatch.setattr(messagebox, 'showinfo', lambda *a, **k: shown.append(a))
    db_fake.reset()
    session = signed_in(backend, 'operator')
    try:
        outcome = main.run_workbench(db_fake, True, None, access=session.access,
                                     client=backend.client, session=session,
                                     make_root=make_root)
    finally:
        for root in roots:                                # never leave a window behind
            try:
                root.destroy()
            except tk.TclError:
                pass
    return outcome, session, shown


def test_sign_out_button_ends_the_session_on_the_server(monkeypatch, backend):
    import main
    token_holder = {}

    def press_sign_out(refs):
        token_holder['token'] = refs['session_watcher'].session.token()
        refs['sign_out_button'].invoke()
    outcome, session, shown = run_workbench_and(monkeypatch, backend, press_sign_out)
    assert outcome == main.SIGNED_OUT and not session.active and shown == []
    with pytest.raises(Exception):
        backend.client.get_session(token_holder['token'])


def test_an_ended_session_signs_out_with_a_message(monkeypatch, backend):
    import main
    outcome, session, shown = run_workbench_and(
        monkeypatch, backend, lambda refs: refs['session_watcher'].end('ended'))
    assert outcome == main.SIGNED_OUT and not session.active
    assert shown and 'Sign in again' in shown[0][1]
