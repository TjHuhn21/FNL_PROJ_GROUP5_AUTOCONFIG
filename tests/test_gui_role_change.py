"""Accounts page: the approval flow and role changes, against the real backend API
in-process (in-memory repository, fake mailer; no network, no MySQL, no real email).
Background calls are synchronous. Skipped when no window can be opened.

One role dropdown ("Approve as:" for a pending account, "Role:" with the current role for
an active / disabled one), only the actions that make sense for the selected account, a
role description, confirmations (admin access, reject, ...), and before -> after logging.
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))
import pytest

tk = pytest.importorskip('tkinter')
from tkinter import messagebox  # noqa: E402

from auth_api_harness import Backend  # noqa: E402
from desktop_auth.api_client import ApiError  # noqa: E402
from desktop_auth.session import AuthSession  # noqa: E402
from gui import background, event_log  # noqa: E402
from gui.session_watch import SignedInContext  # noqa: E402
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


def admin_page(root, backend, ended=None):
    backend.user('admin@example.com', role='admin')
    data = backend.sign_in_data('admin@example.com')
    session = AuthSession(token=data['token'], user_id=data['user_id'], role='admin',
                          email='admin@example.com')
    account = SignedInContext(backend.client, session, lambda: None,
                              (ended if ended is not None else []).append)
    from gui.accounts_page import AccountsPage
    page = AccountsPage(root, account)
    page.filter.set('all')
    page.refresh()
    return page, session


def select(page, uid):
    page.tree.selection_set(str(uid))
    page.update_actions()


def shown_buttons(page):
    return [k for k, b in page.buttons.items() if b.winfo_manager()]


def enabled(page):
    return [k for k in shown_buttons(page) if not page.buttons[k].instate(['disabled'])]


def requests_made(backend):
    return len(backend.opener.requests)


def account_in(backend, email, status, role='viewer'):
    """An account that reached `status` the real way (verified first, then changed)."""
    start = 'pending_approval' if status == 'rejected' else 'active'
    uid = backend.user(email, role=role, status=start)
    backend.repo.set_status(uid, status, actor_user_id=None)
    return uid


# ---------------------------------------------------------------- the approval flow
def test_a_pending_account_shows_no_role_and_only_approve_and_reject(root, backend):
    pending = backend.user('justine@example.com', role='admin', status='pending_approval')
    page, _ = admin_page(root, backend)
    assert page.tree.set(str(pending), 'role') == '—'        # an old stored role is hidden
    select(page, pending)
    assert shown_buttons(page) == ['approve', 'reject'] == enabled(page)
    assert page.role_label.cget('text') == 'Approve as:' and page.role.get() == 'viewer'
    assert 'cannot change anything' in page.role_note.cget('text')
    assert page.hint.cget('text') == 'Selected: justine@example.com (pending approval)'


def test_approving_sets_the_chosen_role_and_admin_asks_first(root, backend, monkeypatch):
    pending = backend.user('justine@example.com', role='admin', status='pending_approval')
    page, _ = admin_page(root, backend)
    asked, lines = [], []
    monkeypatch.setattr(messagebox, 'askyesno', lambda t, text, **k: asked.append(text) or False)
    monkeypatch.setattr('gui.accounts_page.log_event', lambda *a, **k: lines.append(a[1]))
    select(page, pending)
    page.role.set('admin')
    assert 'full access' in page.role_note.cget('text')
    page.approve()
    assert asked == ['Give justine@example.com full admin access? Admins can approve, '
                     'disable, and change roles of other accounts.']
    assert backend.repo.get_user(pending)['status'] == 'pending_approval'    # declined
    page.role.set('operator')                                # no question for operator
    page.approve()
    user = backend.repo.get_user(pending)
    assert (user['status'], user['role']) == ('active', 'operator')
    assert any('role — -> operator; status pending_approval -> active' in l for l in lines)
    assert not any('justine@example.com' in l for l in lines)            # masked in the Console
    assert 'justine@example.com' in page.status.cget('text')            # full e-mail here
    assert page.tree.set(str(pending), 'role') == 'operator'


def test_reject_asks_first(root, backend, monkeypatch):
    pending = backend.user('p@example.com', status='pending_approval')
    page, _ = admin_page(root, backend)
    monkeypatch.setattr(messagebox, 'askyesno', lambda *a, **k: False)
    select(page, pending)
    page.reject()
    assert backend.repo.get_user(pending)['status'] == 'pending_approval'
    monkeypatch.setattr(messagebox, 'askyesno', lambda *a, **k: True)
    page.reject()
    assert backend.repo.get_user(pending)['status'] == 'rejected'


def test_actions_follow_the_status(root, backend):
    active = backend.user('a@example.com', role='operator')
    disabled = account_in(backend, 'd@example.com', 'disabled')
    rejected = account_in(backend, 'r@example.com', 'rejected')
    page, session = admin_page(root, backend)
    select(page, active)
    assert shown_buttons(page) == ['change_role', 'disable']     # Unlock only when locked
    assert page.role_label.cget('text') == 'Role:' and page.role.get() == 'operator'
    assert enabled(page) == ['disable']                          # same role: not yet
    page.role.set('viewer')
    assert enabled(page) == ['change_role', 'disable']
    select(page, disabled)
    assert shown_buttons(page) == ['change_role', 'enable'] and page.role.get() == 'viewer'
    select(page, rejected)
    assert shown_buttons(page) == ['reopen'] == enabled(page)
    assert str(page.role_box.cget('state')) == 'disabled'
    select(page, session.user_id)                                # own account: nothing
    assert enabled(page) == [] and 'your own account' in page.hint.cget('text')
    page.tree.selection_remove(page.tree.selection())
    page.update_actions()
    assert enabled(page) == [] and str(page.role_box.cget('state')) == 'disabled'


def test_enable_and_reopen(root, backend, monkeypatch):
    disabled = account_in(backend, 'd@example.com', 'disabled', role='operator')
    rejected = account_in(backend, 'r@example.com', 'rejected')
    page, _ = admin_page(root, backend)
    monkeypatch.setattr(messagebox, 'askyesno', lambda *a, **k: True)
    select(page, disabled)
    page.enable()
    assert backend.repo.get_user(disabled)['status'] == 'active'
    select(page, rejected)
    page.reopen()
    assert backend.repo.get_user(rejected)['status'] == 'pending_approval'
    assert page.tree.set(str(rejected), 'role') == '—'


def test_selecting_another_account_clears_the_old_message(root, backend, monkeypatch):
    a = backend.user('a@example.com')
    b = backend.user('b@example.com')
    page, _ = admin_page(root, backend)
    monkeypatch.setattr(messagebox, 'askyesno', lambda *a, **k: True)
    select(page, a)
    page.role.set('operator')
    page.change_role()
    assert 'Change role a@example.com' in page.status.cget('text')
    select(page, b)
    assert page.status.cget('text') == ''


# ---------------------------------------------------------------- role changes
def test_change_role_after_confirmation(root, backend, monkeypatch):
    target = backend.user('target@example.com')
    page, _ = admin_page(root, backend)
    asked = []
    monkeypatch.setattr(messagebox, 'askyesno', lambda title, text, **k: asked.append(text) or True)
    select(page, target)
    page.role.set('operator')
    page.change_role()
    assert backend.repo.get_user(target)['role'] == 'operator'
    assert 'from viewer to operator' in asked[0] and 'signed out everywhere' in asked[0]
    assert 'role viewer -> operator' in page.status.cget('text')
    assert page.tree.set(str(target), 'role') == 'operator'          # list refreshed


def test_promoting_to_admin_asks_the_full_access_question(root, backend, monkeypatch):
    target = backend.user('target@example.com')
    page, _ = admin_page(root, backend)
    asked = []
    monkeypatch.setattr(messagebox, 'askyesno', lambda t, text, **k: asked.append(text) or False)
    select(page, target)
    page.role.set('admin')
    before = requests_made(backend)
    page.change_role()
    assert asked[0].startswith('Give target@example.com full admin access?')
    assert requests_made(backend) == before and 'Nothing was changed' in page.status.cget('text')
    assert backend.repo.get_user(target)['role'] == 'viewer'


def test_own_account_same_role_and_no_selection_are_refused_locally(root, backend, monkeypatch):
    target = backend.user('target@example.com')
    page, session = admin_page(root, backend)
    monkeypatch.setattr(messagebox, 'askyesno', lambda *a, **k: pytest.fail('asked to confirm'))
    before = requests_made(backend)
    select(page, session.user_id)
    page.change_role()
    assert 'your own role' in page.status.cget('text')
    select(page, target)
    page.role.set('viewer')
    page.change_role()
    assert 'already has the role viewer' in page.status.cget('text')
    page.tree.selection_remove(page.tree.selection())
    page.change_role()
    assert 'Select an account' in page.status.cget('text')
    assert requests_made(backend) == before


def test_one_selector_with_the_three_roles(root, backend):
    page, _ = admin_page(root, backend)
    combos = [w for frame in page.winfo_children() for w in frame.winfo_children()
              if w.winfo_class() == 'TCombobox']
    assert combos[1:] == [page.role_box]           # the first is the "Show:" filter
    assert tuple(page.role_box.cget('values')) == ('viewer', 'operator', 'admin')
    assert not hasattr(page, 'new_role')


def test_server_refusals_are_shown(root, backend, monkeypatch):
    """The GUI's own checks are only a convenience: the server refuses too."""
    page, session = admin_page(root, backend)
    monkeypatch.setattr(messagebox, 'askyesno', lambda *a, **k: True)
    with pytest.raises(ApiError) as err:
        backend.client.change_role(session.token(), session.user_id, 'viewer')
    assert err.value.status == 400 and 'your own role' in str(err.value)
    for call in (backend.client.disable_user, backend.client.reject_user):
        with pytest.raises(ApiError) as err:
            call(session.token(), session.user_id)
        assert err.value.status == 400 and 'your own account' in str(err.value)
    pending = backend.user('p@example.com', status='pending_approval')
    with pytest.raises(ApiError) as err:                       # a role only when approved
        backend.client.change_role(session.token(), pending, 'admin')
    assert err.value.status == 400 and 'no role yet' in str(err.value)
    target = backend.user('target@example.com')
    page.refresh()
    select(page, target)
    page.rows[str(target)]['role'] = 'admin'                       # stale list on screen
    page.role.set('viewer')
    page.change_role()
    assert 'already has this role' in page.status.cget('text')


def test_an_ended_admin_session_signs_out(root, backend, monkeypatch):
    ended = []
    target = backend.user('target@example.com')
    page, session = admin_page(root, backend, ended=ended)
    monkeypatch.setattr(messagebox, 'askyesno', lambda *a, **k: True)
    backend.repo.revoke_user_sessions(session.user_id, 'logout')
    select(page, target)
    page.role.set('operator')
    page.change_role()
    assert ended == ['ended'] and backend.repo.get_user(target)['role'] == 'viewer'


def test_client_refuses_unknown_roles_before_sending(backend):
    before = requests_made(backend)
    with pytest.raises(ValueError):
        backend.client.change_role('x' * 43, 1, 'superuser')
    assert requests_made(backend) == before
