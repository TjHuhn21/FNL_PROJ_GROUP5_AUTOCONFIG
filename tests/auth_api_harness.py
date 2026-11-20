"""Test harness: the real backend API (Phase 5) with the in-memory repository and a fake
mailer, reachable by the desktop AuthApiClient through an in-process opener (urllib
requests are handed to FastAPI's TestClient). No socket, database or email is used."""
import io
import re
import urllib.error
import urllib.parse
from datetime import datetime, timedelta

from fastapi.testclient import TestClient

from backend.app import create_app
from backend.auth import passwords
from backend.auth.rate_limit import SlidingWindowLimiter
from backend.auth.service import AuthService
from backend.database.memory_repository import InMemoryAuthRepository
from backend.settings import Secret, parse_settings
from desktop_auth.api_client import AuthApiClient

PEPPER = Secret('test-only-desktop-pepper-' + 'z' * 32)
PASSWORD = 'Test-only desktop password 5'
T0 = datetime(2026, 11, 19, 10, 0, 0)
_HASH = {}


def password_hash():
    if 'value' not in _HASH:
        _HASH['value'] = passwords.hash_password(PASSWORD)
    return _HASH['value']


class Clock:
    def __init__(self):
        self.now = T0

    def __call__(self):
        return self.now

    def seconds(self):
        return (self.now - T0).total_seconds()

    def advance(self, seconds):
        self.now += timedelta(seconds=seconds)


class FakeMailer:
    def __init__(self):
        self.sent, self.fail = [], None

    def send(self, outgoing):
        if self.fail:
            raise self.fail
        self.sent.append(outgoing)

    def last_code(self):
        return re.search(r'^ {4}([0-9]{6})$', self.sent[-1].text, re.M).group(1)


class FakeResponse:
    def __init__(self, status, body):
        self.status, self._body = status, body

    def read(self, n=-1):
        return self._body if n is None or n < 0 else self._body[:n]

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False


class InProcessOpener:
    """Stands in for urllib's opener: records every request (method, full URL, headers)."""

    def __init__(self, test_client):
        self.client, self.requests = test_client, []

    def __call__(self, request, timeout=None):
        parts = urllib.parse.urlsplit(request.full_url)
        path = parts.path + ('?' + parts.query if parts.query else '')
        headers = dict(request.header_items())
        self.requests.append((request.get_method(), request.full_url, headers))
        r = self.client.request(request.get_method(), path, content=request.data,
                                headers=headers)
        if r.status_code >= 400:
            raise urllib.error.HTTPError(request.full_url, r.status_code, 'error', r.headers,
                                         io.BytesIO(r.content))
        return FakeResponse(r.status_code, r.content)


class Backend:
    def __init__(self):
        self.clock = Clock()
        self.repo = InMemoryAuthRepository(clock=self.clock)
        self.mailer = FakeMailer()
        self.service = AuthService(self.repo, self.mailer, PEPPER,
                                   limiter=SlidingWindowLimiter(clock=self.clock.seconds))
        self.app = create_app(parse_settings({}), auth_service=self.service)
        self.opener = InProcessOpener(TestClient(self.app))
        self.client = AuthApiClient('http://127.0.0.1:8000', opener=self.opener)

    def user(self, email='user@example.com', status='active', role='viewer'):
        return self.repo.create_user(email, 'Desk User', password_hash(), role=role,
                                     status=status,
                                     email_verified=status in ('active', 'pending_approval'))

    def sign_in_data(self, email='user@example.com'):
        challenge = self.client.login(email, PASSWORD)
        return self.client.verify_login(challenge['challenge_id'], self.mailer.last_code())
