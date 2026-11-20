"""HTTP client for the backend's sign-in and account API (urllib; no extra dependency).

Where the API is (NETCOMMAND_API_URL, not a secret):
  1. the NETCOMMAND_API_URL environment variable, when set;
  2. otherwise the NETCOMMAND_API_URL line of the project's .env (only that line is used);
  3. otherwise http://127.0.0.1:8000 (the backend's default address).
Plain http is accepted only for this computer (127.0.0.1, localhost, ::1): anywhere else
the token would cross the network unencrypted, so https is required.

Safety rules kept here:
  * the token travels only in the Authorization: Bearer header, never in a URL;
  * redirects are refused (a redirect could carry the Authorization header elsewhere) and
    no proxy is used;
  * nothing is logged; errors carry the server's fixed message (short, one line) or a
    fixed message of our own, never a password, code, token or response body.
"""
import ipaddress
import json
import os
import socket
import urllib.error
import urllib.parse
import urllib.request

DEFAULT_API_URL = 'http://127.0.0.1:8000'
API_URL_VARIABLE = 'NETCOMMAND_API_URL'
ENV_PATH = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), '.env')
TIMEOUT = 15                       # seconds per request (a login sends an email)
MAX_RESPONSE_BYTES = 256 * 1024
ROLES = ('viewer', 'operator', 'admin')
_LOOPBACK_NAMES = ('localhost',)


class ApiConfigError(ValueError):
    """NETCOMMAND_API_URL is not usable. The message names the problem, not secrets."""


class ApiError(Exception):
    """The server refused the request. .status (HTTP), .code (the server's short error
    code), .retry_after (seconds, for 429). str() is safe to show."""

    def __init__(self, message, status=None, code=None, retry_after=None):
        self.status, self.code, self.retry_after = status, code, retry_after
        super().__init__(message)

    @property
    def session_ended(self):
        return self.status == 401 and self.code in (None, 'not_authenticated')


class ApiUnavailable(ApiError):
    """The server could not be reached, or did not answer in time."""


class BadResponse(ApiError):
    """The server answered something this client does not understand."""


UNREACHABLE = 'The NetCommand server could not be reached. Check that it is running.'
UNEXPECTED = 'The NetCommand server sent an unexpected answer.'


def _is_loopback(host):
    if host.lower() in _LOOPBACK_NAMES:
        return True
    try:
        return ipaddress.ip_address(host.strip('[]')).is_loopback
    except ValueError:
        return False


def check_api_url(url):
    """The base URL without a trailing slash; ApiConfigError if it is not acceptable."""
    if not isinstance(url, str) or not url.strip():
        raise ApiConfigError(f'{API_URL_VARIABLE} is empty.')
    parts = urllib.parse.urlsplit(url.strip())
    if parts.scheme not in ('http', 'https') or not parts.hostname:
        raise ApiConfigError(f'{API_URL_VARIABLE} must be an http:// or https:// address.')
    if parts.username or parts.password:
        raise ApiConfigError(f'{API_URL_VARIABLE} must not contain a user name or password.')
    if parts.query or parts.fragment:
        raise ApiConfigError(f'{API_URL_VARIABLE} must not contain ? or #.')
    if parts.scheme == 'http' and not _is_loopback(parts.hostname):
        raise ApiConfigError(f'{API_URL_VARIABLE} must use https:// for a server on another '
                             f'computer (http:// is allowed only for this computer).')
    return urllib.parse.urlunsplit((parts.scheme, parts.netloc, parts.path.rstrip('/'), '', ''))


def api_url_from_environment(env_path=None):
    """The configured API address (see the module notes), checked."""
    url = os.environ.get(API_URL_VARIABLE, '').strip()
    if not url:
        path = env_path or ENV_PATH
        if os.path.exists(path):
            from dotenv import dotenv_values
            url = (dotenv_values(path).get(API_URL_VARIABLE) or '').strip()
    return check_api_url(url or DEFAULT_API_URL)


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None                                   # the 3xx is then reported as an error


def _default_opener():
    return urllib.request.build_opener(urllib.request.ProxyHandler({}), _NoRedirect()).open


def _safe_text(value, limit=300):
    if not isinstance(value, str):
        return None
    text = ' '.join(value.split())
    return text[:limit] if text else None


class AuthApiClient:
    def __init__(self, base_url, timeout=TIMEOUT, opener=None):
        self.base_url = check_api_url(base_url)
        self.timeout = timeout
        self._open = opener or _default_opener()

    def __repr__(self):
        return f'AuthApiClient({self.base_url})'

    # ------------------------------------------------------------ transport
    def _request(self, method, path, body=None, token=None, query=None):
        url = self.base_url + path
        if query:
            url += '?' + urllib.parse.urlencode({k: v for k, v in query.items() if v is not None})
        headers = {'Accept': 'application/json'}
        data = None
        if body is not None:
            data = json.dumps(body).encode('utf-8')
            headers['Content-Type'] = 'application/json'
        if token is not None:
            headers['Authorization'] = f'Bearer {token}'
        request = urllib.request.Request(url, data=data, headers=headers, method=method)
        try:
            with self._open(request, timeout=self.timeout) as response:
                status, raw = response.status, response.read(MAX_RESPONSE_BYTES + 1)
                retry = None
        except urllib.error.HTTPError as err:
            status, retry = err.code, err.headers.get('Retry-After') if err.headers else None
            try:
                raw = err.read(MAX_RESPONSE_BYTES + 1)
            except Exception:
                raw = b''
            finally:
                err.close()
        except (urllib.error.URLError, socket.timeout, TimeoutError, ConnectionError, OSError):
            raise ApiUnavailable(UNREACHABLE) from None
        if len(raw) > MAX_RESPONSE_BYTES:
            raise BadResponse(UNEXPECTED, status=status) from None
        payload = None
        if raw:
            try:
                payload = json.loads(raw.decode('utf-8'))
            except (UnicodeDecodeError, ValueError):
                raise BadResponse(UNEXPECTED, status=status) from None
        if 300 <= status < 400:
            raise BadResponse(UNEXPECTED, status=status)
        if status >= 400:
            info = payload if isinstance(payload, dict) else {}
            message = _safe_text(info.get('detail')) or f'The request failed (HTTP {status}).'
            if status >= 500 and status != 503:
                message = 'The NetCommand server reported an error. Try again later.'
            try:
                retry_after = int(retry) if retry is not None else None
            except ValueError:
                retry_after = None
            error = ApiUnavailable if status == 503 else ApiError
            raise error(message, status=status, code=_safe_text(info.get('error'), 40),
                        retry_after=retry_after)
        return status, payload

    @staticmethod
    def _dict(payload, *required):
        if not isinstance(payload, dict) or any(k not in payload for k in required):
            raise BadResponse(UNEXPECTED)
        return payload

    def _challenge(self, payload):
        p = self._dict(payload, 'challenge_id', 'expires_in_seconds')
        if not isinstance(p['challenge_id'], str) or not isinstance(p['expires_in_seconds'], int):
            raise BadResponse(UNEXPECTED)
        return {'challenge_id': p['challenge_id'], 'expires_in_seconds': p['expires_in_seconds'],
                'message': _safe_text(p.get('message')) or ''}

    # ------------------------------------------------------------ registration
    def register(self, email, full_name, password):
        _, p = self._request('POST', '/auth/register',
                             {'email': email, 'full_name': full_name, 'password': password})
        return self._challenge(p)

    def verify_registration(self, challenge_id, code):
        _, p = self._request('POST', '/auth/register/verify',
                             {'challenge_id': challenge_id, 'code': code})
        status = self._dict(p, 'status')['status']
        if status != 'pending_approval':
            raise BadResponse(UNEXPECTED)
        return status

    def resend_registration(self, email):
        _, p = self._request('POST', '/auth/register/resend', {'email': email})
        return self._challenge(p)

    # ------------------------------------------------------------ login
    def login(self, email, password):
        _, p = self._request('POST', '/auth/login', {'email': email, 'password': password})
        return self._challenge(p)

    def verify_login(self, challenge_id, code):
        """The session (a dict; 'token' is the raw token, to be kept in memory only)."""
        _, p = self._request('POST', '/auth/login/verify',
                             {'challenge_id': challenge_id, 'code': code})
        p = self._dict(p, 'token', 'user_id', 'role', 'session_id', 'expires_in_seconds',
                       'idle_timeout_seconds')
        if (not isinstance(p['token'], str) or not 20 <= len(p['token']) <= 128
                or p['role'] not in ROLES or not isinstance(p['user_id'], int)
                or not isinstance(p['idle_timeout_seconds'], int)
                or not isinstance(p['expires_in_seconds'], int)):
            raise BadResponse(UNEXPECTED)
        return p

    def resend_login(self, challenge_id):
        _, p = self._request('POST', '/auth/login/resend', {'challenge_id': challenge_id})
        return self._challenge(p)

    # ------------------------------------------------------------ session
    def get_session(self, token):
        _, p = self._request('GET', '/auth/session', token=token)
        p = self._dict(p, 'user_id', 'role')
        if p['role'] not in ROLES:
            raise BadResponse(UNEXPECTED)
        return {'user_id': p['user_id'], 'role': p['role'], 'session_id': p.get('session_id')}

    def logout(self, token):
        self._request('POST', '/auth/logout', token=token)

    # ------------------------------------------------------------ admin
    def list_users(self, token, status=None, limit=200):
        _, p = self._request('GET', '/admin/users', token=token,
                             query={'status': status, 'limit': limit})
        users = self._dict(p, 'users')['users']
        if not isinstance(users, list) or not all(
                isinstance(u, dict) and isinstance(u.get('id'), int) for u in users):
            raise BadResponse(UNEXPECTED)
        return users

    def approve_user(self, token, user_id, role=None):
        _, p = self._request('POST', f'/admin/users/{int(user_id)}/approve',
                             {'role': role} if role else None, token=token)
        return self._dict(p, 'status')

    def reject_user(self, token, user_id):
        _, p = self._request('POST', f'/admin/users/{int(user_id)}/reject', token=token)
        return self._dict(p, 'status')

    def change_role(self, token, user_id, role):
        if role not in ROLES:
            raise ValueError('Unknown role.')
        _, p = self._request('POST', f'/admin/users/{int(user_id)}/role', {'role': role},
                             token=token)
        p = self._dict(p, 'role', 'previous_role')
        if p['role'] not in ROLES or p['previous_role'] not in ROLES:
            raise BadResponse(UNEXPECTED)
        return p

    def disable_user(self, token, user_id):
        _, p = self._request('POST', f'/admin/users/{int(user_id)}/disable', token=token)
        return self._dict(p, 'status')
