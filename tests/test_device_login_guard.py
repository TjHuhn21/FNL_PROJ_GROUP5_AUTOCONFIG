"""Failed device logins on the Scan and Configure pages: reported to the real backend API
(in-process: in-memory repository, fake mailer, no network), with the warnings in the
popup and the Console, the sign-out on a lock, the Accounts page's lock column and Unlock,
and nothing counted in demo mode. No device, database or real email."""
import os, sys
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))
sys.path.insert(0, os.path.dirname(__file__))
import pytest

tk = pytest.importorskip('tkinter')

import db_fake  # noqa: E402
from auth_api_harness import Backend  # noqa: E402
from backend.auth import device_lockout as DL  # noqa: E402
from desktop_auth.session import AuthSession  # noqa: E402
from gui import background, event_log, theme  # noqa: E402
from gui.device_login_guard import (AUTH_FAILED, SUCCESS, UNREACHABLE,  # noqa: E402
                                    DeviceLoginGuard, outcome_of_apply, outcome_of_scan_error,
                                    warning_text)
from gui.session_watch import SignedInContext  # noqa: E402
from gui_helpers import new_root  # noqa: E402

AUTH_ERROR = ('Could not log in to the starting device 127.0.0.11: the device rejected the '
              'username or password.')
TIMEOUT_ERROR = ('Could not log in to the starting device 10.9.9.9: no answer (the connection '
                 'timed out: is the IP right, is the device on, is it reachable?).')


@pytest.fixture(autouse=True)
def synchronous(monkeypatch):
    monkeypatch.setattr(background, 'run_async', background.run_now)


@pytest.fixture
def dialogs(monkeypatch):
    from tkinter import messagebox
    shown = []
    for name in ('showerror', 'showwarning', 'showinfo'):
        monkeypatch.setattr(messagebox, name,
                            lambda title, text, _n=name, **k: shown.append((_n, title, text)))
    monkeypatch.setattr(messagebox, 'askyesno', lambda *a, **k: True)
    return shown


class Signed:
    """A signed-in desktop account against the in-process backend."""

    def __init__(self, backend, email='user@example.com', role='operator'):
        backend.user(email, role=role)
        data = backend.sign_in_data(email)
        self.session = AuthSession(token=data['token'], user_id=data['user_id'],
                                   role=data['role'], email=email,
                                   session_id=data.get('session_id'),
                                   idle_timeout_seconds=data['idle_timeout_seconds'],
                                   expires_in_seconds=data['expires_in_seconds'])
        self.ended = []
        self.context = SignedInContext(backend.client, self.session, lambda: None,
                                       lambda reason, message=None:
                                       self.ended.append((reason, message)))


@pytest.fixture
def scan_page(dialogs):
    from gui.components.console import OperationsConsole
    from gui.scan_tab import ScanTab
    root = new_root()
    theme.apply(root)
    console = OperationsConsole(root, db_fake)
    db_fake.reset()
    answers = {'next': AUTH_ERROR}

    def discover(user, password, seed, demo, *rest):
        if demo:
            import sample_data
            return sample_data.DEVICES, sample_data.LINKS
        if answers['next'] == 'ok':
            return [{'name': 'R1', 'ip': seed, 'type': 'router', 'managed': True,
                     'status': 'up'}], []
        raise RuntimeError(answers['next'])
    page = ScanTab(root, db_fake, discover)
    page.pack()
    yield root, page, console, answers, dialogs
    root.destroy()


def scan(root, page, seed='127.0.0.11', demo=False):
    page.demo.set(demo)
    page.user.set('labscan'); page.pw.set('wrong'); page.seed.set(seed)
    page.on_scan()
    for _ in range(100):
        root.update()
        if not page.scanning:
            break
        root.after(20); page.check_queue()


# ---------------------------------------------------------------- classification
def test_only_rejected_logins_and_timeouts_count():
    assert outcome_of_scan_error(AUTH_ERROR) == AUTH_FAILED
    assert outcome_of_scan_error(TIMEOUT_ERROR) == UNREACHABLE
    assert outcome_of_scan_error('Seed IP: Enter a valid IPv4 address') is None
    assert outcome_of_scan_error('the connection to port 22 was refused') is None
    from config import multi
    assert outcome_of_apply({'status': multi.FAILED, 'message': 'Wrong username or password.'}) \
        == AUTH_FAILED
    assert outcome_of_apply({'status': multi.FAILED, 'message': 'No answer (the connection '
                             'timed out: wrong IP, device off, or not reachable).'}) == UNREACHABLE
    assert outcome_of_apply({'status': multi.SUCCESS, 'message': 'ok'}) == SUCCESS
    assert outcome_of_apply({'status': multi.NOT_RUN, 'message': 'Not run'}) is None


def test_warning_texts():
    assert warning_text({'event': 'failed', 'remaining': 4, 'locked': None}) == \
        '4 attempts left before your account is locked.'
    assert warning_text({'event': 'failed', 'remaining': 1, 'locked': None}) == \
        '1 attempt left. One more failed login will lock your account and sign you out.'
    assert warning_text({'event': 'reset', 'remaining': 5, 'locked': None}) == ''
    assert warning_text(None) == ''


# ---------------------------------------------------------------- the Scan page
def test_failed_scans_warn_then_lock_and_sign_out(scan_page):
    root, page, console, answers, shown = scan_page
    backend = Backend()
    me = Signed(backend)
    page.device_guard = DeviceLoginGuard(me.context)
    # a successful scan first: its results must not survive a failed one
    answers['next'] = 'ok'
    scan(root, page)
    assert page.tree.get_children()
    answers['next'] = AUTH_ERROR
    for left in (4, 3, 2):
        scan(root, page)
        assert shown[-1][0] == 'showerror' and shown[-1][1] == 'Scan failed'
        assert f'{left} attempts left before your account is locked.' in shown[-1][2]
    assert page.tree.get_children() == () and page.found == []       # old results cleared
    scan(root, page)
    assert 'One more failed login will lock your account and sign you out.' in shown[-1][2]
    console.flush()
    lines = [m for _t, s, m, _l in console.lines if s == 'security']
    assert 'u*****@example.com: login to 127.0.0.11 FAILED (wrong username or password). '\
           '4 attempts left before your account is locked.' in lines
    assert me.ended == []
    scan(root, page)                                                 # the 5th: locked
    assert me.ended and me.ended[0][0] == 'security_lock'
    assert 'locked for 15 minutes' in me.ended[0][1] and 'after 3 lockouts' in me.ended[0][1]
    console.flush()
    assert any('Account LOCKED for 15 minutes' in m for _t, _s, m, _l in console.lines)
    assert any('signed out by the server' in m for _t, _s, m, _l in console.lines)
    with pytest.raises(Exception):                                   # the session is gone
        backend.client.get_session(me.session.token())


def test_a_timeout_counts_and_a_successful_scan_resets(scan_page):
    root, page, console, answers, shown = scan_page
    backend = Backend()
    me = Signed(backend)
    page.device_guard = DeviceLoginGuard(me.context)
    answers['next'] = TIMEOUT_ERROR
    scan(root, page, seed='10.9.9.9')
    scan(root, page, seed='10.9.9.9')
    assert '3 attempts left' in shown[-1][2]
    answers['next'] = 'ok'
    scan(root, page)
    answers['next'] = AUTH_ERROR
    scan(root, page)
    assert '4 attempts left' in shown[-1][2]                         # counting restarted


def test_demo_mode_never_counts(scan_page):
    root, page, console, answers, shown = scan_page
    backend = Backend()
    me = Signed(backend)
    page.device_guard = DeviceLoginGuard(me.context)
    for _ in range(7):
        scan(root, page, demo=True)
    state, _now, _n = backend.repo.device_login_state(me.session.user_id)
    assert state['failed_count'] == 0 and me.ended == []


def test_without_an_account_nothing_is_reported(scan_page):
    root, page, console, answers, shown = scan_page
    page.device_guard = DeviceLoginGuard(None)                      # the --demo start
    scan(root, page)
    assert shown[-1][1] == 'Scan failed' and 'attempts left' not in shown[-1][2]


# ---------------------------------------------------------------- the Configure page
def test_configure_failures_count_with_a_warning(dialogs):
    from config import multi
    from gui.configure_tab import ConfigureTab
    root = new_root()
    try:
        backend = Backend()
        me = Signed(backend)
        conf = ConfigureTab(root, db_fake)
        conf.device_guard = DeviceLoginGuard(me.context)
        dev = {'id': 1, 'name': 'R1', 'ip': '192.168.1.1'}
        conf._jobs, conf._skipped, conf._pending_saves = {}, [], {}
        conf._after_apply = conf._save_confirmed_logins = lambda results: None
        for left in (4, 3):
            conf._finish([{'device': dev, 'status': multi.FAILED, 'ok': False,
                           'message': 'No answer (the connection timed out: wrong IP, device '
                                      'off, or not reachable).'}])
            assert dialogs[-1][1] == 'Apply failed'
            assert f'{left} attempts left before your account is locked.' in dialogs[-1][2]
    finally:
        root.destroy()


# ---------------------------------------------------------------- the Accounts page
def test_accounts_page_shows_locks_and_unlocks(dialogs):
    from gui.accounts_page import AccountsPage, lock_text
    backend = Backend()
    victim = Signed(backend, 'victim@example.com')
    for _ in range(DL.MAX_FAILED_DEVICE_LOGINS):
        backend.client.report_device_login(victim.session.token(), '127.0.0.11', 'auth_failed')
    boss = Signed(backend, 'boss@example.com', role='admin')
    root = new_root()
    try:
        page = AccountsPage(root, boss.context)
        page.filter.set('all')
        page.refresh()
        row = page.tree.item(str(victim.session.user_id))['values']
        assert str(row[-1]).startswith('Temporarily locked until ') and row[-1].endswith(('AM', 'PM'))
        assert lock_text({'security_lock': 'permanent'}) == 'Locked: admin unlock required'
        page.tree.selection_set(str(boss.session.user_id))
        page.unlock()
        assert 'cannot unlock your own account' in page.status.cget('text')
        page.tree.selection_set(str(victim.session.user_id))
        page.unlock()
        assert page.tree.item(str(victim.session.user_id))['values'][-1] in ('', None)
        audit = backend.repo.list_audit(action='security.unlocked')
        assert audit and audit[0]['actor_user_id'] == boss.session.user_id
    finally:
        root.destroy()


# ---------------------------------------------------------------- TESTING MODE (dev reset)
def test_app_start_resets_locks_and_says_so(monkeypatch):
    import main
    backend = Backend()
    victim = Signed(backend)
    for _ in range(DL.MAX_FAILED_DEVICE_LOGINS):
        backend.client.report_device_login(victim.session.token(), '127.0.0.11', 'auth_failed')
    lines = []
    monkeypatch.setattr(main, 'log_event', lambda *a: lines.append(a))
    assert main.dev_reset_locks(backend.client) is True
    assert lines == [('dev', '[DEV] Lockout attempts and locks reset (testing mode).', 'warn')]
    state, now, _ = backend.repo.device_login_state(victim.session.user_id)
    assert DL.is_locked(state, now) is None


def test_app_start_does_nothing_when_testing_mode_is_off(monkeypatch):
    import main
    monkeypatch.setattr(DL, 'DEV_RESET_LOCKS_ON_RESTART', False)
    backend = Backend()                                   # the endpoint is not registered
    lines = []
    monkeypatch.setattr(main, 'log_event', lambda *a: lines.append(a))
    assert main.dev_reset_locks(backend.client) is False and lines == []


def test_the_header_shows_the_testing_mode_label(dialogs):
    from gui.main_window import DEV_LOCK_RESET_TEXT, build_main_window
    for flag in (True, False):
        root = new_root()
        try:
            refs = build_main_window(root, db_fake, demo_store=True, dev_lock_reset=flag)
            assert ('dev_label' in refs) is flag
            if flag:
                assert refs['dev_label'].cget('text') == DEV_LOCK_RESET_TEXT
        finally:
            root.destroy()
