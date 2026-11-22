"""Phase B: HTTPS and LAN-mode settings, the TLS server configuration, and the
self-signed certificate generator. Offline; temporary files only."""
import ssl

import pytest

from backend import __main__ as backend_main
from backend import tls_cert
from backend.settings import Settings, SettingsError, describe, is_loopback_host, parse_settings


@pytest.fixture(scope='module')
def cert_files(tmp_path_factory):
    folder = tmp_path_factory.mktemp('tls')
    cert, key, _fp = tls_cert.write(folder, ['netcommand-server'])
    return str(cert), str(key)


def settings(**values):
    return parse_settings({f'BACKEND_{k}': v for k, v in values.items()})


def problems(**values):
    with pytest.raises(SettingsError) as err:
        settings(**values)
    return str(err.value)


# ------------------------------------------------------------------ defaults: local, plain HTTP
def test_default_is_loopback_http_without_lan_mode():
    s = settings()
    assert (s.host, s.port, s.scheme, s.lan_mode, s.tls_enabled) == \
        ('127.0.0.1', 8000, 'http', False, False)
    assert 'scheme=http' in describe(s) and 'lan_mode=off' in describe(s)


@pytest.mark.parametrize('host', ['127.0.0.1', '127.0.0.2', 'localhost', '::1'])
def test_loopback_addresses_need_no_lan_mode(host):
    assert settings(HOST=host).host == host
    assert is_loopback_host(host)


# ------------------------------------------------------------------ LAN mode is opt-in, HTTPS only
@pytest.mark.parametrize('host', ['0.0.0.0', '10.167.221.171', 'netcommand-server', '::'])
def test_listening_for_other_computers_needs_lan_mode(host, cert_files):
    text = problems(HOST=host, TLS_CERT_FILE=cert_files[0], TLS_KEY_FILE=cert_files[1])
    assert 'BACKEND_LAN_MODE=true' in text


def test_lan_mode_requires_https():
    text = problems(HOST='0.0.0.0', LAN_MODE='true', PORT='8443')
    assert 'requires HTTPS' in text


def test_lan_mode_with_https(cert_files):
    s = settings(HOST='0.0.0.0', PORT='8443', LAN_MODE='true', TLS_CERT_FILE=cert_files[0],
                 TLS_KEY_FILE=cert_files[1])
    assert (s.host, s.port, s.scheme, s.lan_mode) == ('0.0.0.0', 8443, 'https', True)
    assert 'scheme=https' in describe(s) and 'lan_mode=on' in describe(s)
    assert cert_files[1] not in repr(s) and cert_files[1] not in describe(s)   # key path hidden


def test_local_https_without_lan_mode_is_allowed(cert_files):
    s = settings(PORT='8443', TLS_CERT_FILE=cert_files[0], TLS_KEY_FILE=cert_files[1])
    assert s.scheme == 'https' and not s.lan_mode and s.host == '127.0.0.1'


@pytest.mark.parametrize('values', [{'TLS_CERT_FILE': 'x.crt'}, {'TLS_KEY_FILE': 'x.key'}])
def test_certificate_and_key_go_together(values):
    assert 'must be set together' in problems(**values)


def test_missing_files_are_reported_without_their_paths(tmp_path):
    missing = str(tmp_path / 'secret-folder' / 'server.key')
    text = problems(TLS_CERT_FILE=str(tmp_path / 'nope.crt'), TLS_KEY_FILE=missing)
    assert 'BACKEND_TLS_CERT_FILE does not name an existing file' in text
    assert 'BACKEND_TLS_KEY_FILE does not name an existing file' in text
    assert 'secret-folder' not in text and 'nope.crt' not in text


def test_lan_mode_must_be_a_boolean():
    assert 'BACKEND_LAN_MODE must be true or false' in problems(LAN_MODE='maybe')


# ------------------------------------------------------------------ the server's TLS setup
def test_tls_server_requires_tls_1_2(cert_files):
    s = settings(PORT='8443', TLS_CERT_FILE=cert_files[0], TLS_KEY_FILE=cert_files[1])
    config = backend_main.server_config(object(), s)
    assert config.ssl is not None and config.ssl.minimum_version == ssl.TLSVersion.TLSv1_2
    assert (config.host, config.port) == ('127.0.0.1', 8443)


def test_plain_http_server_for_local_development():
    config = backend_main.server_config(object(), Settings())
    assert config.ssl is None and (config.host, config.port) == ('127.0.0.1', 8000)


def test_unreadable_key_stops_startup_without_details(tmp_path, monkeypatch, capsys):
    cert, key, _ = tls_cert.write(tmp_path, ['netcommand-server'])
    key.write_text('-----BEGIN PRIVATE KEY-----\nnot a key\n-----END PRIVATE KEY-----\n')
    monkeypatch.setattr(backend_main, 'load_settings',
                        lambda: settings(TLS_CERT_FILE=str(cert), TLS_KEY_FILE=str(key)))
    monkeypatch.setattr('backend.logging_config.configure_logging', lambda s: None)
    assert backend_main.main() == 2
    err = capsys.readouterr().err
    assert 'could not be loaded' in err and str(key) not in err and 'not a key' not in err


# ------------------------------------------------------------------ the certificate generator
def test_generated_certificate_is_a_self_signed_server_certificate(tmp_path):
    from cryptography import x509
    from cryptography.x509.oid import ExtendedKeyUsageOID
    cert_path, key_path, fp = tls_cert.write(tmp_path, ['NetCommand-Server', 'laptop1'])
    cert = x509.load_pem_x509_certificate(cert_path.read_bytes())
    san = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
    assert san.get_values_for_type(x509.DNSName) == ['netcommand-server', 'laptop1', 'localhost']
    assert [str(i) for i in san.get_values_for_type(x509.IPAddress)] == ['127.0.0.1']
    assert cert.issuer == cert.subject
    assert not cert.extensions.get_extension_for_class(x509.BasicConstraints).value.ca
    assert ExtendedKeyUsageOID.SERVER_AUTH in \
        cert.extensions.get_extension_for_class(x509.ExtendedKeyUsage).value
    assert len(fp.split(':')) == 32 and fp == tls_cert.fingerprint(cert_path.read_bytes())
    assert b'PRIVATE KEY' in key_path.read_bytes() and b'PRIVATE KEY' not in cert_path.read_bytes()


def test_generator_never_replaces_a_key_silently(tmp_path):
    tls_cert.write(tmp_path, ['netcommand-server'])
    with pytest.raises(tls_cert.CertError):
        tls_cert.write(tmp_path, ['netcommand-server'])
    tls_cert.write(tmp_path, ['netcommand-server'], force=True)


@pytest.mark.parametrize('names', [[], ['bad name'], ['-x'], ['10.1.2.3']])
def test_generator_needs_valid_host_names(names, tmp_path):
    with pytest.raises(tls_cert.CertError):
        tls_cert.write(tmp_path, names)


def test_generator_output_never_shows_the_key(tmp_path, capsys):
    assert tls_cert.main(['--name', 'netcommand-server', '--out-dir', str(tmp_path)]) == 0
    out = capsys.readouterr().out
    key = (tmp_path / 'server.key').read_text()
    assert 'PRIVATE KEY' not in out and key.splitlines()[1] not in out
    assert 'SHA-256 fingerprint' in out and 'SECRET' in out


def test_default_certificate_folder_is_git_ignored():
    import subprocess
    import os
    root = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    for path in ('backend/tls/server.key', 'backend/tls/server.crt'):
        check = subprocess.run(['git', 'check-ignore', '-q', path], cwd=root)
        assert check.returncode == 0, f'{path} is not ignored by Git'
