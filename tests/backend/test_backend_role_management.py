"""Admin role management: AuthService.change_role and POST /admin/users/{id}/role, on the
existing set_role (one transaction with its audit record and the last-admin lock).
In-memory repository and a fake mailer: no MySQL, no real email; test-only secrets."""
import re
import threading
from datetime import datetime, timedelta

import pymysql
import pytest
from fastapi.testclient import TestClient

from backend.app import create_app
from backend.auth import passwords
from backend.auth.errors import InvalidRequest, NotAuthenticated, NotPermitted
from backend.auth.rate_limit import Limit
from backend.auth.service import AuthService, RateLimits
from backend.database.memory_repository import InMemoryAuthRepository
from backend.settings import Secret, parse_settings

PASSWORD = 'Test-only role password 8'
PEPPER = Secret('test-only-role-pepper-' + 'k' * 32)
ROLES = ('viewer', 'operator', 'admin')
NO_LIMITS = RateLimits(**{name: Limit(100000, 60) for name in RateLimits.__dataclass_fields__})


@pytest.fixture(autouse=True)
def no_real_mysql(monkeypatch):
    monkeypatch.setattr(pymysql, 'connect',
                        lambda *a, **k: pytest.fail('tried to open a real MySQL connection'))


@pytest.fixture(scope='module')
def hashed():
    return passwords.hash_password(PASSWORD)


class FakeMailer:
    def __init__(self):
        self.sent = []

    def send(self, outgoing):
        self.sent.append(outgoing)

    def code_for(self, email):
        m = next(m for m in reversed(self.sent) if m.to == email)
        return re.search(r'^ {4}([0-9]{6})$', m.text, re.M).group(1)


class Clock:
    def __init__(self):
        self.now = datetime(2026, 11, 19, 9, 0, 0)

    def __call__(self):
        return self.now

    def advance(self, seconds):
        self.now += timedelta(seconds=seconds)


class World:
    def __init__(self, hashed):
        self.clock = Clock()
        self.repo = InMemoryAuthRepository(clock=self.clock)
        self.mailer, self.hashed = FakeMailer(), hashed
        self.svc = AuthService(self.repo, self.mailer, PEPPER, limits=NO_LIMITS)

    def user(self, email, role='viewer', status='active'):
        return self.repo.create_user(email, 'User', self.hashed, role=role, status=status,
                                     email_verified=status in ('active', 'pending_approval'))

    def token(self, email):
        sent = self.svc.login(email, PASSWORD)
        return self.svc.verify_login(sent.challenge_id, self.mailer.code_for(email)).token


@pytest.fixture
def world(hashed):
    return World(hashed)


def admin_and_target(world, target_role='viewer'):
    world.user('admin@example.com', role='admin')
    target = world.user('target@example.com', role=target_role)
    return world.token('admin@example.com'), target


# ================================================================ the change itself
@pytest.mark.parametrize('old, new', [(a, b) for a in ROLES for b in ROLES if a != b])
def test_admin_changes_any_role_to_any_other(world, old, new):
    token, target = admin_and_target(world, old)
    if old == 'admin':
        world.user('third.admin@example.com', role='admin')     # not the only other admin
    result = world.svc.change_role(token, target, new, client_ip='10.0.0.4',
                                   workstation_label='LAB-PC-1')
    assert result == {'user_id': target, 'previous_role': old, 'role': new,
                      'sessions_ended': 0}
    assert world.repo.get_user(target)['role'] == new


def test_everything_else_about_the_account_is_kept(world):
    token, target = admin_and_target(world)
    before = dict(world.repo._users[target])
    world.svc.change_role(token, target, 'operator')
    after = world.repo._users[target]
    for key in ('id', 'email', 'email_normalized', 'full_name', 'password_hash', 'status',
                'email_verified_at', 'approved_by', 'approved_at', 'created_at',
                'failed_logins', 'locked_until'):
        assert after[key] == before[key], key
    assert after['role'] == 'operator'


def test_the_change_is_audited_without_secrets(world):
    token, target = admin_and_target(world)
    admin_id = world.repo.find_user_by_email('admin@example.com')['id']
    world.svc.change_role(token, target, 'operator', client_ip='10.0.0.4')
    (row,) = world.repo.list_audit(action='user.role_changed')
    assert (row['outcome'], row['actor_user_id'], row['target_type'], row['target_id'],
            row['detail'], row['client_ip']) == (
        'success', admin_id, 'user', str(target), 'role viewer -> operator', '10.0.0.4')
    assert row['created_at'] is not None
    text = str(world.repo.list_audit(limit=1000))
    for secret in (token, PASSWORD, world.hashed, PEPPER.reveal()):
        assert secret not in text


def test_same_role_is_no_change(world):
    token, target = admin_and_target(world)
    assert world.svc.change_role(token, target, 'viewer') is None
    assert world.repo.list_audit(action='user.role_changed') == []


def test_a_pending_account_gets_its_role_only_when_approved(world):
    """Changed deliberately: a role on a pending account skipped the approval step."""
    token, _ = admin_and_target(world)
    pending = world.user('pending@example.com', role='admin', status='pending_approval')
    with pytest.raises(InvalidRequest, match='no role yet'):
        world.svc.change_role(token, pending, 'operator')
    denied = world.repo.list_audit(action='user.role_changed')[0]
    assert denied['outcome'] == 'denied'
    listed = {u['id']: u for u in world.svc.list_accounts(token)}
    assert listed[pending]['role'] is None                  # an old stored role is not shown
    assert world.svc.approve_account(token, pending) is True       # default: viewer
    assert world.repo.get_user(pending)['role'] == 'viewer'        # the stale admin is gone
    approved = world.repo.list_audit(action='user.approved')[0]
    assert approved['detail'] == 'role — -> viewer; status pending_approval -> active'


def test_enable_and_reopen_follow_the_status_rules(world):
    token, target = admin_and_target(world)
    world.svc.disable_account(token, target)
    assert world.svc.enable_account(token, target) is True
    assert world.repo.get_user(target)['status'] == 'active'
    assert world.svc.enable_account(token, target) is False        # not disabled any more
    rejected = world.user('r@example.com', status='pending_approval')
    world.svc.reject_account(token, rejected)
    assert world.svc.reopen_account(token, rejected) is True
    assert world.repo.get_user(rejected)['status'] == 'pending_approval'
    assert {u['id']: u for u in world.svc.list_accounts(token)}[rejected]['role'] is None


# ================================================================ sessions
def test_the_account_is_signed_out_and_signs_in_with_the_new_role(world):
    token, target = admin_and_target(world)
    world.user('bystander@example.com')
    target_token = world.token('target@example.com')
    bystander = world.token('bystander@example.com')
    assert world.svc.validate_session(target_token).role == 'viewer'
    result = world.svc.change_role(token, target, 'operator')
    assert result['sessions_ended'] == 1
    with pytest.raises(NotAuthenticated):
        world.svc.validate_session(target_token)
    assert world.svc.validate_session(token).role == 'admin'           # the admin keeps theirs
    assert world.svc.validate_session(bystander).role == 'viewer'      # others unaffected
    world.clock.advance(61)                                            # code cooldown
    assert world.svc.validate_session(world.token('target@example.com')).role == 'operator'
    revoked = world.repo.list_audit(action='auth.sessions_revoked')[0]
    assert '1 session(s) ended' in revoked['detail']
    reasons = [s['revoked_reason'] for s in sorted(world.repo._sessions.values(),
                                                   key=lambda s: s['id'])
               if s['user_id'] == target]
    assert reasons == ['role_changed', None]          # the old one ended, the new one is live


def test_a_demoted_admin_loses_admin_rights_at_once(world):
    token, other_admin = admin_and_target(world, 'admin')
    other_token = world.token('target@example.com')
    world.svc.change_role(token, other_admin, 'viewer')
    with pytest.raises(NotAuthenticated):
        world.svc.list_accounts(other_token)


# ================================================================ who may do it
@pytest.mark.parametrize('role', ['viewer', 'operator'])
def test_viewers_and_operators_are_refused(world, role):
    world.user('admin@example.com', role='admin')
    caller = world.user(f'{role}@example.com', role=role)
    target = world.user('target@example.com')
    token = world.token(f'{role}@example.com')
    for victim in (target, caller):                                    # incl. their own
        with pytest.raises(NotPermitted):
            world.svc.change_role(token, victim, 'admin')
    assert world.repo.get_user(caller)['role'] == role
    assert world.repo.get_user(target)['role'] == 'viewer'
    denied = world.repo.list_audit(action='user.role_changed')
    assert len(denied) == 2 and all(d['outcome'] == 'denied' for d in denied)


def test_signed_out_callers_are_refused(world):
    _, target = admin_and_target(world)
    for token in ('x' * 43, '', None):
        with pytest.raises(NotAuthenticated):
            world.svc.change_role(token, target, 'admin')


@pytest.mark.parametrize('role', ['superuser', 'Admin', '', None, 'root'])
def test_invalid_roles_are_refused(world, role):
    token, target = admin_and_target(world)
    with pytest.raises(InvalidRequest):
        world.svc.change_role(token, target, role)
    assert world.repo.get_user(target)['role'] == 'viewer'


@pytest.mark.parametrize('user_id', [0, -1, 'abc', True])
def test_invalid_or_missing_accounts(world, user_id):
    token, _ = admin_and_target(world)
    with pytest.raises(InvalidRequest):
        world.svc.change_role(token, user_id, 'operator')
    with pytest.raises(InvalidRequest, match='does not exist'):
        world.svc.change_role(token, 9999, 'operator')


def test_an_admin_cannot_change_their_own_role(world):
    token, _ = admin_and_target(world)
    admin_id = world.repo.find_user_by_email('admin@example.com')['id']
    world.user('second.admin@example.com', role='admin')         # even with another admin
    for role in ('viewer', 'operator'):
        with pytest.raises(InvalidRequest, match='your own role'):
            world.svc.change_role(token, admin_id, role)
    assert world.repo.get_user(admin_id)['role'] == 'admin'
    assert world.repo.list_audit(action='user.role_changed')[0]['outcome'] == 'denied'


def test_the_last_active_admin_cannot_be_demoted(world):
    """A and B are admins; while A is demoting B, B demotes A first. A's change would then
    leave no active admin: refused inside the transaction, audited, nothing changed."""
    world.user('a@example.com', role='admin')
    b = world.user('b@example.com', role='admin')
    a_token = world.token('a@example.com')
    a_id = world.repo.find_user_by_email('a@example.com')['id']
    real_get_user = world.repo.get_user

    def get_user_while_b_acts(user_id):
        world.repo.set_role(a_id, 'viewer', actor_user_id=b)         # B was quicker
        world.repo.get_user = real_get_user
        return real_get_user(user_id)
    world.repo.get_user = get_user_while_b_acts
    with pytest.raises(InvalidRequest, match='There must be at least one active admin'):
        world.svc.change_role(a_token, b, 'viewer')
    assert world.repo.get_user(b)['role'] == 'admin'                     # B is still admin
    denied = world.repo.list_audit(action='user.role_changed')[0]
    assert denied['outcome'] == 'denied' and 'no active admin' in denied['detail']


def test_two_admins_demoting_each_other_at_once_leave_one_admin(world):
    world.user('a@example.com', role='admin')
    world.user('b@example.com', role='admin')
    ids = {e: world.repo.find_user_by_email(e)['id'] for e in ('a@example.com', 'b@example.com')}
    tokens = {e: world.token(e) for e in ids}
    barrier, outcomes = threading.Barrier(2), []

    def demote(actor, victim):
        barrier.wait()
        try:
            world.svc.change_role(tokens[actor], ids[victim], 'viewer')
            outcomes.append('changed')
        except (InvalidRequest, NotAuthenticated, NotPermitted) as err:
            outcomes.append(type(err).__name__)
    threads = [threading.Thread(target=demote, args=('a@example.com', 'b@example.com')),
               threading.Thread(target=demote, args=('b@example.com', 'a@example.com'))]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert outcomes.count('changed') == 1
    admins = [u for u in world.repo.list_users(status='active') if u['role'] == 'admin']
    assert len(admins) == 1


# ================================================================ the API
@pytest.fixture
def api(world):
    client = TestClient(create_app(parse_settings({}), auth_service=world.svc))
    return client


def post_role(client, user_id, body, token=None):
    headers = {'Authorization': f'Bearer {token}'} if token else {}
    return client.post(f'/admin/users/{user_id}/role', json=body, headers=headers)


def test_api_changes_the_role(world, api):
    token, target = admin_and_target(world)
    r = post_role(api, target, {'role': 'operator'}, token)
    assert r.status_code == 200 and r.headers['cache-control'] == 'no-store'
    assert r.json() == {'user_id': target, 'previous_role': 'viewer', 'role': 'operator',
                        'sessions_ended': 0}
    assert token not in r.text and 'password' not in r.text


def test_api_refusals(world, api):
    token, target = admin_and_target(world)
    admin_id = world.repo.find_user_by_email('admin@example.com')['id']
    world.user('op@example.com', role='operator')
    op_token = world.token('op@example.com')
    assert post_role(api, target, {'role': 'admin'}).status_code == 401
    assert post_role(api, target, {'role': 'admin'}, op_token).json()['error'] == 'not_permitted'
    assert post_role(api, target, {'role': 'viewer'}, token).status_code == 409
    self_change = post_role(api, admin_id, {'role': 'viewer'}, token)
    assert self_change.status_code == 400 and 'your own role' in self_change.json()['detail']
    assert post_role(api, 9999, {'role': 'operator'}, token).status_code == 400
    for body in ({'role': 'superuser'}, {'role': None}, {}, {'role': 'admin', 'extra': 1},
                 {'role': 'ADMIN'}):
        assert post_role(api, target, body, token).status_code == 422
    for bad_id in ('0', 'abc', '-3'):
        assert api.post(f'/admin/users/{bad_id}/role', json={'role': 'operator'},
                        headers={'Authorization': f'Bearer {token}'}).status_code == 422
    assert world.repo.get_user(target)['role'] == 'viewer'


def test_api_role_change_signs_the_account_out(world, api):
    token, target = admin_and_target(world)
    target_token = world.token('target@example.com')
    assert api.get('/auth/session', headers={'Authorization': f'Bearer {target_token}'}
                   ).status_code == 200
    post_role(api, target, {'role': 'operator'}, token)
    assert api.get('/auth/session', headers={'Authorization': f'Bearer {target_token}'}
                   ).status_code == 401
