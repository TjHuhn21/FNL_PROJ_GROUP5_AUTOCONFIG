"""Phase B: the desktop client's HTTPS with a pinned self-signed certificate, against a
REAL backend (uvicorn) started on 127.0.0.1 with test certificates. Loopback only; the
certificates and keys are made in a temporary folder and thrown away."""
import os
import socket
import ssl
import sys
import threading
import time
import urllib.error

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from backend import __main__ as backend_main  # noqa: E402
from backend import tls_cert  # noqa: E402
from backend.app import create_app  # noqa: E402
from backend.settings import Settings  # noqa: E402
from desktop_auth import api_client  # noqa: E402
from desktop_auth.api_client import (ApiConfigError, ApiTlsError, ApiUnavailable,  # noqa: E402
                                     AuthApiClient, client_from_environment)

TOKEN = 'tok_' + 'A' * 40


def free_port():
    with socket.socket() as s:
        s.bind(('127.0.0.1', 0))
        return s.getsockname()[1]


class Backend:
    """The real backend app under uvicorn, in a thread, on 127.0.0.1."""

    def __init__(self, cert=None, key=None):
        import uvicorn
        self.port = free_port()
        settings = Settings(port=self.port, tls_cert_file=str(cert or ''),
                            tls_key_file=str(key or ''))
        self.server = uvicorn.Server(backend_main.server_config(create_app(settings), settings))
        self.thread = threading.Thread(target=self.server.run, daemon=True)

    def __enter__(self):
        self.thread.start()
        end = time.time() + 10
        while not self.server.started and time.time() < end:
            time.sleep(0.02)
        assert self.server.started, 'the test backend did not start'
        return self

    def __exit__(self, *exc):
        self.server.should_exit = True
        self.thread.join(5)


@pytest.fixture(scope='module')
def certs(tmp_path_factory):
    good = tmp_path_factory.mktemp('good')
    other = tmp_path_factory.mktemp('other')
    tls_cert.write(good, ['netcommand-server'])
    tls_cert.write(other, ['netcommand-server'])         # same name, a different key
    return {'crt': str(good / 'server.crt'), 'key': str(good / 'server.key'),
            'other_crt': str(other / 'server.crt')}


@pytest.fixture(scope='module')
def https_backend(certs):
    with Backend(certs['crt'], certs['key']) as b:
        yield b


# ------------------------------------------------------------------ trusted certificate
def test_https_backend_starts_and_the_pinned_certificate_is_accepted(https_backend, certs):
    client = AuthApiClient(f'https://localhost:{https_backend.port}', ca_file=certs['crt'])
    assert client.health() is True


def test_server_name_with_an_explicit_address(https_backend, certs):
    """The hotspot case: connect to an IP address, verify the certificate for the NAME."""
    client = AuthApiClient(f'https://netcommand-server:{https_backend.port}',
                           ca_file=certs['crt'], address='127.0.0.1')
    assert client.health() is True


def test_negotiated_tls_is_1_2_or_newer(https_backend, certs):
    context = api_client.tls_context(certs['crt'])
    with socket.create_connection(('127.0.0.1', https_backend.port), 5) as raw:
        with context.wrap_socket(raw, server_hostname='localhost') as tls:
            assert tls.version() in ('TLSv1.2', 'TLSv1.3')


# ------------------------------------------------------------------ rejected certificates
def test_untrusted_certificate_is_rejected(https_backend, certs):
    client = AuthApiClient(f'https://localhost:{https_backend.port}', ca_file=certs['other_crt'])
    with pytest.raises(ApiTlsError) as err:
        client.get_session(TOKEN)
    assert str(err.value) == api_client.UNTRUSTED and TOKEN not in str(err.value)


def test_mismatched_host_name_is_rejected(https_backend, certs):
    client = AuthApiClient(f'https://some-other-server:{https_backend.port}',
                           ca_file=certs['crt'], address='127.0.0.1')
    with pytest.raises(ApiTlsError) as err:
        client.login('a@example.com', 'Pa55word-not-shown')
    assert str(err.value) == api_client.MISMATCH
    assert 'Pa55word' not in str(err.value)


def test_system_trust_store_is_not_used(certs):
    """Only the pinned file is trusted: the context holds exactly that certificate."""
    context = api_client.tls_context(certs['crt'])
    assert context.cert_store_stats()['x509'] == 1             # this certificate, nothing else
    assert context.check_hostname and context.verify_mode == ssl.CERT_REQUIRED
    assert context.minimum_version == ssl.TLSVersion.TLSv1_2


# ------------------------------------------------------------------ no downgrade to HTTP
def test_https_never_falls_back_to_plain_http(certs):
    """A plain-HTTP listener on the https:// port: the client fails at the TLS step and
    never sends an HTTP request in clear text."""
    received, ready = [], threading.Event()
    port = free_port()

    def listener():
        with socket.socket() as srv:
            srv.bind(('127.0.0.1', port))
            srv.listen(1)
            ready.set()
            srv.settimeout(10)
            conn, _ = srv.accept()
            with conn:
                conn.settimeout(2)
                try:
                    received.append(conn.recv(65536))
                    conn.sendall(b'HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\n\r\n')
                except OSError:
                    pass
    thread = threading.Thread(target=listener, daemon=True)
    thread.start()
    ready.wait(5)
    client = AuthApiClient(f'https://localhost:{port}', ca_file=certs['crt'])
    with pytest.raises(ApiTlsError) as err:
        client.get_session(TOKEN)
    thread.join(5)
    assert str(err.value) == api_client.TLS_FAILED
    data = b''.join(received)
    assert data[:1] == b'\x16'                          # a TLS handshake record, nothing else
    assert b'GET ' not in data and TOKEN.encode() not in data


def test_redirects_are_still_refused_over_https(https_backend, certs):
    client = AuthApiClient(f'https://localhost:{https_backend.port}', ca_file=certs['crt'])
    handlers = [type(h).__name__ for h in client._open.__self__.handlers]
    assert '_NoRedirect' in handlers and '_PinnedHTTPSHandler' in handlers
    assert 'HTTPSHandler' not in handlers                     # urllib's default is replaced


# ------------------------------------------------------------------ unreachable server
def test_backend_not_running(certs):
    client = AuthApiClient(f'https://localhost:{free_port()}', ca_file=certs['crt'])
    with pytest.raises(ApiUnavailable) as err:
        client.health()
    assert str(err.value) == api_client.REFUSED


@pytest.mark.parametrize('error, message', [
    (socket.gaierror(11001, 'getaddrinfo failed'), api_client.NAME_UNKNOWN),
    (socket.timeout('timed out'), api_client.TIMED_OUT),
    (ConnectionRefusedError(), api_client.REFUSED),
    (ssl.SSLCertVerificationError(1, 'certificate verify failed'), api_client.UNTRUSTED),
    (ssl.SSLError(1, 'wrong version number'), api_client.TLS_FAILED),
    (OSError('anything else'), api_client.UNREACHABLE),
])
def test_connection_errors_have_clear_messages(error, message):
    result = api_client._connection_error(urllib.error.URLError(error))
    assert str(result) == message and isinstance(result, ApiUnavailable)


# ------------------------------------------------------------------ configuration errors
def test_https_needs_a_certificate_file():
    with pytest.raises(ApiConfigError) as err:
        AuthApiClient('https://netcommand-server:8443')
    assert str(err.value) == api_client.CERT_NOT_CONFIGURED


def test_missing_certificate_file(tmp_path):
    with pytest.raises(ApiConfigError) as err:
        AuthApiClient('https://netcommand-server:8443', ca_file=str(tmp_path / 'server.crt'))
    assert str(err.value) == api_client.CERT_MISSING
    assert str(tmp_path) not in str(err.value)


@pytest.mark.parametrize('content', ['', 'not a certificate',
                                     '-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----\n'])
def test_invalid_certificate_file(tmp_path, content):
    path = tmp_path / 'server.crt'
    path.write_text(content)
    with pytest.raises(ApiConfigError) as err:
        AuthApiClient('https://netcommand-server:8443', ca_file=str(path))
    assert str(err.value) == api_client.CERT_INVALID


@pytest.mark.parametrize('which', ['key', 'both'])
def test_a_private_key_is_never_accepted_as_the_trust_file(tmp_path, certs, which):
    path = tmp_path / 'server.crt'
    key = open(certs['key'], 'rb').read()
    path.write_bytes(key if which == 'key' else open(certs['crt'], 'rb').read() + key)
    with pytest.raises(ApiConfigError) as err:
        AuthApiClient('https://netcommand-server:8443', ca_file=str(path))
    assert str(err.value) == api_client.CERT_HAS_KEY


@pytest.mark.parametrize('url, address, fragment', [
    ('http://127.0.0.1:8000', '127.0.0.1', 'only be used with an https://'),
    ('https://10.0.0.5:8443', '10.0.0.5', 'must use the server NAME'),
    ('https://netcommand-server:8443', 'netcommand-server', 'must be an IP address'),
])
def test_address_setting_is_checked(url, address, fragment, certs):
    with pytest.raises(ApiConfigError) as err:
        AuthApiClient(url, ca_file=certs['crt'], address=address)
    assert fragment in str(err.value)


def test_plain_http_to_another_computer_is_still_refused():
    with pytest.raises(ApiConfigError):
        AuthApiClient('http://10.167.221.171:8443')


def test_client_from_environment(monkeypatch, tmp_path, certs):
    env = tmp_path / '.env'
    env.write_text('')
    monkeypatch.setenv(api_client.API_URL_VARIABLE, 'https://netcommand-server:8443')
    monkeypatch.delenv(api_client.CA_FILE_VARIABLE, raising=False)
    monkeypatch.delenv(api_client.ADDRESS_VARIABLE, raising=False)
    with pytest.raises(ApiConfigError) as err:
        client_from_environment(str(env))
    assert str(err.value) == api_client.CERT_NOT_CONFIGURED
    monkeypatch.setenv(api_client.CA_FILE_VARIABLE, certs['crt'])
    monkeypatch.setenv(api_client.ADDRESS_VARIABLE, '10.167.221.171')
    client = client_from_environment(str(env))
    assert client.base_url == 'https://netcommand-server:8443'
    assert client._open.__self__.handlers                       # the pinned opener


def test_relative_certificate_path_is_relative_to_the_project(monkeypatch, tmp_path):
    seen = {}
    monkeypatch.setattr(api_client, 'tls_context', lambda path: seen.setdefault('path', path))
    monkeypatch.setattr(api_client, '_https_opener', lambda context, address: lambda *a, **k: None)
    monkeypatch.setenv(api_client.API_URL_VARIABLE, 'https://netcommand-server:8443')
    monkeypatch.setenv(api_client.CA_FILE_VARIABLE, os.path.join('certs', 'server.crt'))
    monkeypatch.delenv(api_client.ADDRESS_VARIABLE, raising=False)
    client_from_environment(str(tmp_path / '.env'))
    assert seen['path'] == os.path.join(api_client.PROJECT_DIR, 'certs', 'server.crt')


# ------------------------------------------------------------------ local development unchanged
def test_loopback_http_backend_still_works():
    with Backend() as b:
        assert AuthApiClient(f'http://127.0.0.1:{b.port}').health() is True


def test_default_settings_are_unchanged(monkeypatch, tmp_path):
    for name in (api_client.API_URL_VARIABLE, api_client.CA_FILE_VARIABLE,
                 api_client.ADDRESS_VARIABLE):
        monkeypatch.delenv(name, raising=False)
    client = client_from_environment(str(tmp_path / 'missing.env'))
    assert client.base_url == 'http://127.0.0.1:8000'
