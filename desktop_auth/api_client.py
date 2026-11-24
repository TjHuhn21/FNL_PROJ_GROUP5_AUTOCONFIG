"""HTTP client for the backend's sign-in and account API (urllib; no extra dependency).

Settings (none is a secret). Each is read from the environment variable, otherwise from
that line of the project's .env (only that line is used):
  NETCOMMAND_API_URL      where the API is; default http://127.0.0.1:8000.
  NETCOMMAND_API_CA_FILE  for https:// only, and then REQUIRED: the server's certificate
                          (server.crt from python -m backend.tls_cert). It is the ONLY
                          certificate trusted for the connection (not the Windows store):
                          the server's certificate is pinned. A relative path is relative
                          to the project folder.
  NETCOMMAND_API_ADDRESS  optional, https:// only: the IP address to connect to for the
                          server name in the URL (for a phone hotspot whose addresses
                          change, without editing the hosts file). The certificate is still
                          checked against the NAME in the URL; nothing is relaxed.
Plain http is accepted only for this computer (127.0.0.1, localhost, ::1): anywhere else
the token would cross the network unencrypted, so https is required. An https:// URL is
never retried over http.

Safety rules kept here:
  * the token travels only in the Authorization: Bearer header, never in a URL;
  * redirects are refused (a redirect could carry the Authorization header elsewhere) and
    no proxy is used;
  * certificate and host-name verification are always on, with TLS 1.2 or newer;
  * nothing is logged; errors carry the server's fixed message (short, one line) or a
    fixed message of our own, never a password, code, token, path or response body.
"""
import http.client
import ipaddress
import json
import os
import socket
import ssl
import urllib.error
import urllib.parse
import urllib.request

DEFAULT_API_URL = 'http://127.0.0.1:8000'
API_URL_VARIABLE = 'NETCOMMAND_API_URL'
CA_FILE_VARIABLE = 'NETCOMMAND_API_CA_FILE'
ADDRESS_VARIABLE = 'NETCOMMAND_API_ADDRESS'
PROJECT_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
ENV_PATH = os.path.join(PROJECT_DIR, '.env')
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


class ApiTlsError(ApiUnavailable):
    """The secure connection was refused because the server's certificate is not the
    trusted one, or not valid for the server name. Nothing was sent."""


UNREACHABLE = 'The NetCommand server could not be reached. Check that it is running.'
UNEXPECTED = 'The NetCommand server sent an unexpected answer.'
REFUSED = ('The NetCommand server refused the connection: it is not running on that address '
           'and port, or the server laptop\'s firewall blocks it.')
TIMED_OUT = ('The NetCommand server did not answer in time. Check the network connection and '
             'that both laptops are on the same network.')
NAME_UNKNOWN = ('The NetCommand server name could not be found on this network. Set '
                f'{ADDRESS_VARIABLE} to the server\'s current IP address, or add the name to the '
                'hosts file (see docs/LAN_DEPLOYMENT.md).')
UNTRUSTED = ('The NetCommand server\'s certificate is not the trusted one in '
             f'{CA_FILE_VARIABLE}. Nothing was sent. Copy the current server.crt from the server '
             'laptop (and compare its fingerprint) if the certificate was replaced.')
MISMATCH = ('The NetCommand server\'s certificate is not valid for the server name in '
            f'{API_URL_VARIABLE}. Nothing was sent. Use the name the certificate was made for '
            '(not an IP address).')
TLS_FAILED = ('A secure (HTTPS) connection to the NetCommand server could not be set up. Check '
              'that the server runs with HTTPS on that port. Nothing was sent.')
CERT_NOT_CONFIGURED = (f'{API_URL_VARIABLE} uses https://, so {CA_FILE_VARIABLE} must name the '
                       'server\'s certificate file (server.crt from the server laptop).')
CERT_MISSING = f'The certificate file named by {CA_FILE_VARIABLE} was not found.'
CERT_INVALID = (f'The file named by {CA_FILE_VARIABLE} is not a valid certificate (PEM). Copy '
                'server.crt again from the server laptop.')
CERT_HAS_KEY = (f'The file named by {CA_FILE_VARIABLE} contains a PRIVATE KEY. A client needs '
                'only server.crt; delete this copy of the server\'s private key from this '
                'computer.')


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


def _setting(name, env_path=None):
    """The environment variable, else that line of the .env file, else ''."""
    value = os.environ.get(name, '').strip()
    if not value:
        path = env_path or ENV_PATH
        if os.path.exists(path):
            from dotenv import dotenv_values
            value = (dotenv_values(path).get(name) or '').strip()
    return value


def api_url_from_environment(env_path=None):
    """The configured API address (see the module notes), checked."""
    return check_api_url(_setting(API_URL_VARIABLE, env_path) or DEFAULT_API_URL)


def check_address(address, base_url):
    """NETCOMMAND_API_ADDRESS: an IP address, used only with an https:// URL that names
    the server (the certificate is checked against that name)."""
    text = (address or '').strip()
    try:
        ip = ipaddress.ip_address(text.strip('[]'))
    except ValueError:
        raise ApiConfigError(f'{ADDRESS_VARIABLE} must be an IP address (for example '
                             f'10.0.0.5).') from None
    parts = urllib.parse.urlsplit(base_url)
    if parts.scheme != 'https':
        raise ApiConfigError(f'{ADDRESS_VARIABLE} can only be used with an https:// '
                             f'{API_URL_VARIABLE}.')
    if _is_ip(parts.hostname):
        raise ApiConfigError(f'With {ADDRESS_VARIABLE}, {API_URL_VARIABLE} must use the '
                             f'server NAME (the one in its certificate), not an IP address.')
    return str(ip)


def _is_ip(host):
    try:
        ipaddress.ip_address((host or '').strip('[]'))
        return True
    except ValueError:
        return False


def tls_context(ca_file):
    """An SSL context that trusts ONLY the certificate(s) in ca_file (the pinned server
    certificate), with certificate and host-name verification on and TLS 1.2 or newer.
    Never the system store; never unverified."""
    if not ca_file:
        raise ApiConfigError(CERT_NOT_CONFIGURED)
    if not os.path.isfile(ca_file):
        raise ApiConfigError(CERT_MISSING)
    try:
        with open(ca_file, 'rb') as f:
            content = f.read(1024 * 1024)
    except OSError:
        raise ApiConfigError(CERT_MISSING) from None
    if b'PRIVATE KEY' in content:                      # the server's key must never be here
        raise ApiConfigError(CERT_HAS_KEY)
    if b'-----BEGIN CERTIFICATE-----' not in content:
        raise ApiConfigError(CERT_INVALID)
    try:
        context = ssl.create_default_context(ssl.Purpose.SERVER_AUTH, cafile=ca_file)
    except (ssl.SSLError, ValueError, OSError):
        raise ApiConfigError(CERT_INVALID) from None
    if not context.cert_store_stats().get('x509'):     # nothing usable was loaded
        raise ApiConfigError(CERT_INVALID)
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    context.check_hostname = True
    context.verify_mode = ssl.CERT_REQUIRED
    return context


class _PinnedHTTPSConnection(http.client.HTTPSConnection):
    """HTTPS to the URL's host name, optionally connecting to a given IP address instead
    of resolving the name. TLS (SNI and host-name verification) always uses the NAME."""

    def __init__(self, host, address=None, **kwargs):
        super().__init__(host, **kwargs)
        self._address = address

    def connect(self):
        if not self._address:
            return super().connect()
        sock = socket.create_connection((self._address, self.port), self.timeout,
                                        self.source_address)
        try:
            self.sock = self._context.wrap_socket(sock, server_hostname=self.host)
        except BaseException:
            sock.close()
            raise


class _PinnedHTTPSHandler(urllib.request.HTTPSHandler):
    def __init__(self, context, address=None):
        super().__init__(context=context)
        self._pinned_context, self._address = context, address

    def https_open(self, req):
        address = self._address

        def connection(host, **kwargs):
            return _PinnedHTTPSConnection(host, address=address, **kwargs)
        return self.do_open(connection, req, context=self._pinned_context)


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None                                   # the 3xx is then reported as an error


def _default_opener():
    return urllib.request.build_opener(urllib.request.ProxyHandler({}), _NoRedirect()).open


def _https_opener(context, address=None):
    """Only the pinned HTTPS handler (it replaces urllib's default one), no proxy, no
    redirects."""
    return urllib.request.build_opener(urllib.request.ProxyHandler({}), _NoRedirect(),
                                       _PinnedHTTPSHandler(context, address)).open


def _connection_error(err):
    """A fixed, safe ApiUnavailable / ApiTlsError for a failed connection."""
    reason = err.reason if isinstance(err, urllib.error.URLError) else err
    if isinstance(reason, ssl.SSLCertVerificationError):
        text = f'{getattr(reason, "verify_message", "")} {reason}'.lower()
        if getattr(reason, 'verify_code', None) == 62 or 'mismatch' in text:
            return ApiTlsError(MISMATCH)
        return ApiTlsError(UNTRUSTED)
    if isinstance(reason, ssl.SSLError):
        return ApiTlsError(TLS_FAILED)
    if isinstance(reason, (socket.timeout, TimeoutError)):
        return ApiUnavailable(TIMED_OUT)
    if isinstance(reason, socket.gaierror):
        return ApiUnavailable(NAME_UNKNOWN)
    if isinstance(reason, ConnectionRefusedError):
        return ApiUnavailable(REFUSED)
    return ApiUnavailable(UNREACHABLE)


def client_from_environment(env_path=None, timeout=None):
    """The AuthApiClient for this computer's settings (see the module notes). Raises
    ApiConfigError with a fixed message naming the setting at fault."""
    url = api_url_from_environment(env_path)
    ca_file = _setting(CA_FILE_VARIABLE, env_path)
    if ca_file and not os.path.isabs(ca_file):
        ca_file = os.path.join(PROJECT_DIR, ca_file)
    address = _setting(ADDRESS_VARIABLE, env_path)
    return AuthApiClient(url, timeout=timeout or TIMEOUT, ca_file=ca_file or None,
                         address=address or None)


def _safe_text(value, limit=300):
    if not isinstance(value, str):
        return None
    text = ' '.join(value.split())
    return text[:limit] if text else None


class AuthApiClient:
    def __init__(self, base_url, timeout=TIMEOUT, opener=None, ca_file=None, address=None):
        """https:// needs ca_file (the pinned server certificate); address (optional, https
        only) is the IP address to connect to for the URL's server name. opener: tests."""
        self.base_url = check_api_url(base_url)
        self.timeout = timeout
        https = self.base_url.startswith('https://')
        if address is not None:
            address = check_address(address, self.base_url)
        if opener is not None:
            self._open = opener
        elif https:
            self._open = _https_opener(tls_context(ca_file), address)
        else:
            self._open = _default_opener()                # http://: this computer only

    def __repr__(self):
        return f'AuthApiClient({self.base_url})'

    def health(self):
        """GET /health: True when the server answers (a connection test; no sign-in)."""
        _, p = self._request('GET', '/health')
        return isinstance(p, dict) and p.get('status') == 'ok'

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
        except (urllib.error.URLError, socket.timeout, TimeoutError, ConnectionError,
                ssl.SSLError, OSError) as err:
            raise _connection_error(err) from None
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

    def unlock_user(self, token, user_id):
        """Clear another account's failed-device-login lock (admins only, checked by the
        server). {'user_id', 'cleared': 'temporary' | 'permanent' | None}."""
        _, p = self._request('POST', f'/admin/users/{int(user_id)}/unlock', token=token)
        return self._dict(p, 'user_id', 'cleared')

    def dev_reset_locks(self):
        """TESTING MODE: ask the backend to reset every account's failed device logins and
        locks. {'testing_mode': True, 'reset_users': n}; ApiError (403/404) when the
        backend's testing mode is off."""
        _, p = self._request('POST', '/dev/reset-locks')
        return self._dict(p, 'testing_mode', 'reset_users')

    # ------------------------------------------------------------ device logins
    def report_device_login(self, token, device_ip, outcome):
        """Report one login to a network device (Scan, Configure). The server counts the
        failures and may lock the account; the answer describes the state."""
        if outcome not in ('success', 'auth_failed', 'unreachable'):
            raise ValueError('Unknown outcome.')
        _, p = self._request('POST', '/security/device-login',
                             {'device_ip': device_ip, 'outcome': outcome}, token=token)
        p = self._dict(p, 'event', 'failed_count', 'remaining', 'locked', 'lockouts_left')
        if p['locked'] not in (None, 'temporary', 'permanent'):
            raise BadResponse(UNEXPECTED)
        return p
