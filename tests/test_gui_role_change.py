"""Accounts page: changing another account's role (selector + confirmation), against the
real backend API in-process (in-memory repository, fake mailer; no network, no MySQL,
no real email). Background calls are synchronous. Skipped when no window can be opened."""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))
import pytest

tk = pytest.importorskip('tkinter')
from tkinter import messagebox  # noqa: E402

from auth_api_harness import Backend  # noqa: E402
from desktop_auth.api_client import ApiError  # noqa: E402
from desktop_auth.session import AuthSession  # noqa: E402
from gui import background  # noqa: E402
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


def requests_made(backend):
    return len(backend.opener.requests)


def test_change_role_after_confirmation(root, backend, monkeypatch):
    target = backend.user('target@example.com')
    page, _ = admin_page(root, backend)
    asked = []
    monkeypatch.setattr(messagebox, 'askyesno', lambda title, text, **k: asked.append(text) or True)
    page.tree.selection_set(str(target))
    page.new_role.set('operator')
    page.change_role()
    assert backend.repo.get_user(target)['role'] == 'operator'
    assert 'from viewer to operator' in asked[0] and 'signed out everywhere' in asked[0]
    assert 'is now operator (was viewer)' in page.status.cget('text')
    assert page.tree.set(str(target), 'role') == 'operator'          # list refreshed


def test_declining_the_confirmation_changes_nothing(root, backend, monkeypatch):
    target = backend.user('target@example.com')
    page, _ = admin_page(root, backend)
    monkeypatch.setattr(messagebox, 'askyesno', lambda *a, **k: False)
    page.tree.selection_set(str(target))
    page.new_role.set('admin')
    before = requests_made(backend)
    page.change_role()
    assert requests_made(backend) == before and 'not changed' in page.status.cget('text')
    assert backend.repo.get_user(target)['role'] == 'viewer'


def test_own_account_same_role_and_no_selection_are_refused_locally(root, backend, monkeypatch):
    target = backend.user('target@example.com')
    page, session = admin_page(root, backend)
    monkeypatch.setattr(messagebox, 'askyesno', lambda *a, **k: pytest.fail('asked to confirm'))
    before = requests_made(backend)
    page.tree.selection_set(str(session.user_id))
    page.new_role.set('viewer')
    page.change_role()
    assert 'your own role' in page.status.cget('text')
    page.tree.selection_set(str(target))
    page.new_role.set('viewer')
    page.change_role()
    assert 'already has the role viewer' in page.status.cget('text')
    page.tree.selection_remove(page.tree.selection())
    page.change_role()
    assert 'Select an account' in page.status.cget('text')
    assert requests_made(backend) == before


def test_the_selector_offers_only_the_three_roles(root, backend):
    page, _ = admin_page(root, backend)
    combo = [w for w in page.winfo_children()[-2].winfo_children()
             if w.winfo_class() == 'TCombobox'][0]
    assert tuple(combo.cget('values')) == ('viewer', 'operator', 'admin')
    assert str(combo.cget('state')) == 'readonly'


def test_server_refusals_are_shown(root, backend, monkeypatch):
    """The GUI's own checks are only a convenience: the server refuses too (here the
    local check is bypassed to show the server's answer)."""
    page, session = admin_page(root, backend)
    monkeypatch.setattr(messagebox, 'askyesno', lambda *a, **k: True)
    with pytest.raises(ApiError) as err:
        backend.client.change_role(session.token(), session.user_id, 'viewer')
    assert err.value.status == 400 and 'your own role' in str(err.value)
    target = backend.user('target@example.com')
    page.refresh()
    backend.repo._users[target]['role'] = 'viewer'
    page.tree.selection_set(str(target))
    page.rows[str(target)]['role'] = 'admin'                       # stale list on screen
    page.new_role.set('viewer')
    page.change_role()
    assert 'already has this role' in page.status.cget('text')


def test_an_ended_admin_session_signs_out(root, backend, monkeypatch):
    ended = []
    target = backend.user('target@example.com')
    page, session = admin_page(root, backend, ended=ended)
    monkeypatch.setattr(messagebox, 'askyesno', lambda *a, **k: True)
    backend.repo.revoke_user_sessions(session.user_id, 'logout')
    page.tree.selection_set(str(target))
    page.new_role.set('operator')
    page.change_role()
    assert ended == ['ended'] and backend.repo.get_user(target)['role'] == 'viewer'


def test_client_refuses_unknown_roles_before_sending(backend):
    before = requests_made(backend)
    with pytest.raises(ValueError):
        backend.client.change_role('x' * 43, 1, 'superuser')
    assert requests_made(backend) == before
