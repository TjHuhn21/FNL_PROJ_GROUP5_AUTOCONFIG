"""ssh_options: strict SSH by default, old SHA-1 algorithms only for listed addresses,
the same options for Scan, Review and Configure, and safe error messages.

Offline: the handshake tests run a real Paramiko client and server over an in-process
socket pair (socket.socketpair), so no network is used."""
import os, socket, sys, threading
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))
import pytest

import ssh_options
from ssh_options import ALGORITHMS, AUTH, OTHER, REFUSED, TIMEOUT

LEGACY_IP, OTHER_IP = '192.168.10.1', '192.168.10.2'
SECRET = 'Sup3r-Secret-Pa55'


@pytest.fixture
def legacy(monkeypatch):
    """NETCOMMAND_LEGACY_SSH_HOSTS lists LEGACY_IP (plus one invalid entry)."""
    monkeypatch.setenv(ssh_options.SETTING, f' {LEGACY_IP}, not-an-ip ; ')


@pytest.fixture
def unset(monkeypatch, tmp_path):
    """No setting anywhere (and the real .env is never read)."""
    monkeypatch.delenv(ssh_options.SETTING, raising=False)
    monkeypatch.setattr(ssh_options, 'ENV_PATH', str(tmp_path / 'missing.env'))


# ---------------------------------------------------------------- which hosts are legacy
def test_only_listed_addresses_are_legacy(legacy):
    assert ssh_options.legacy_hosts() == {LEGACY_IP}
    assert ssh_options.is_legacy(LEGACY_IP) and ssh_options.is_legacy(f' {LEGACY_IP} ')
    for host in (OTHER_IP, '192.168.10.10', '127.0.0.11', 'router.local', '', None):
        assert not ssh_options.is_legacy(host)
    assert ssh_options.ignored_entries() == ['not-an-ip']


def test_nothing_is_legacy_without_the_setting(unset):
    assert ssh_options.legacy_hosts() == frozenset()
    assert not ssh_options.is_legacy(LEGACY_IP)


def test_the_setting_is_read_from_the_env_file_when_not_in_the_environment(monkeypatch, tmp_path):
    env = tmp_path / '.env'
    env.write_text(f'DB_NAME=x\n{ssh_options.SETTING}={LEGACY_IP}\n', encoding='utf-8')
    monkeypatch.delenv(ssh_options.SETTING, raising=False)
    assert ssh_options.legacy_hosts(env_path=str(env)) == {LEGACY_IP}
    monkeypatch.setenv(ssh_options.SETTING, '')                   # the environment wins
    assert ssh_options.legacy_hosts(env_path=str(env)) == frozenset()


# ---------------------------------------------------------------- the restrictions
def test_every_other_device_gets_strict_restrictions(legacy):
    strict = ssh_options.disabled_algorithms(OTHER_IP)
    for kex in ('diffie-hellman-group14-sha1', 'diffie-hellman-group-exchange-sha1',
                'diffie-hellman-group1-sha1'):
        assert kex in strict['kex']
    assert 'ssh-rsa' in strict['keys'] and 'ssh-rsa' in strict['pubkeys']
    for mac in ('hmac-sha1', 'hmac-sha1-96', 'hmac-md5', 'hmac-md5-96'):
        assert mac in strict['macs']
    assert 'rsa-sha2-256' not in strict['keys']                   # modern RSA still allowed


def test_a_listed_device_gets_only_the_needed_legacy_allowances(legacy):
    loose = ssh_options.disabled_algorithms(LEGACY_IP)
    assert 'diffie-hellman-group14-sha1' not in loose['kex']
    assert 'diffie-hellman-group-exchange-sha1' not in loose['kex']
    assert 'keys' not in loose and 'hmac-sha1' not in loose['macs']
    assert loose['kex'] == ['diffie-hellman-group1-sha1']         # never, not even for legacy
    assert set(loose['macs']) == {'hmac-md5', 'hmac-md5-96'}


def test_options_are_a_new_dict_every_time(legacy):
    a = ssh_options.connect_options(OTHER_IP)
    a['disabled_algorithms']['kex'].clear()
    assert ssh_options.connect_options(OTHER_IP)['disabled_algorithms']['kex']


def test_paramiko_itself_still_offers_sha1_so_the_restriction_matters():
    """Guards the reason for this module: Paramiko 4.x offers SHA-1 by default."""
    paramiko = pytest.importorskip('paramiko')
    a, b = socket.socketpair()
    t = paramiko.Transport(a)
    try:
        assert 'diffie-hellman-group14-sha1' in t.preferred_kex and 'ssh-rsa' in t.preferred_keys
    finally:
        t.close(); a.close(); b.close()


# ---------------------------------------------------------------- real handshakes (no network)
def _handshake(client_disabled, server_kex=None, server_keys=None, server_macs=None):
    """A real SSH key exchange between a Paramiko client and server over a socket pair.
    Returns (client_error, client_transport_info)."""
    paramiko = pytest.importorskip('paramiko')
    key = paramiko.RSAKey.generate(1024)          # test-only throwaway host key
    s_srv, s_cli = socket.socketpair()
    srv = paramiko.Transport(s_srv)
    opts = srv.get_security_options()
    if server_kex:
        opts.kex = server_kex
    if server_keys:
        opts.key_types = server_keys
    if server_macs:
        opts.digests = server_macs
    srv.add_server_key(key)

    def serve():
        try:
            srv.start_server(server=paramiko.ServerInterface())
        except Exception:
            pass
    thread = threading.Thread(target=serve, daemon=True)
    thread.start()
    cli = paramiko.Transport(s_cli, disabled_algorithms=client_disabled)
    error, info = None, None
    try:
        cli.start_client(timeout=15)
        info = {'host_key': cli.host_key_type}
    except Exception as err:
        error = err
    finally:
        cli.close(); srv.close(); s_cli.close(); s_srv.close()
        thread.join(5)
    return error, info


# Like the Cisco 1900: only SHA-1 key exchange, ssh-rsa, hmac-sha1. (group-exchange-sha1 is
# left out here only because a Paramiko SERVER without a moduli file cannot run group
# exchange; as a client - NetCommand's side - Paramiko supports it.)
ROUTER_LIKE = dict(server_kex=('diffie-hellman-group14-sha1', 'diffie-hellman-group1-sha1'),
                   server_keys=('ssh-rsa',), server_macs=('hmac-sha1', 'hmac-sha1-96'))


def test_strict_client_refuses_a_router_that_only_offers_sha1(legacy):
    error, info = _handshake(ssh_options.disabled_algorithms(OTHER_IP), **ROUTER_LIKE)
    assert error is not None and info is None
    assert ssh_options.classify(error) == ALGORITHMS


def test_listed_address_can_talk_to_that_router(legacy):
    error, info = _handshake(ssh_options.disabled_algorithms(LEGACY_IP), **ROUTER_LIKE)
    assert error is None, error
    # the server offers only group14-sha1 and group1-sha1, and the client refuses group1, so
    # this handshake used group14-sha1 (group1-only is refused: see the next test)
    assert info['host_key'] == 'ssh-rsa'


def test_listed_address_still_refuses_group1_only(legacy):
    error, _ = _handshake(ssh_options.disabled_algorithms(LEGACY_IP),
                          server_kex=('diffie-hellman-group1-sha1',), server_keys=('ssh-rsa',))
    assert error is not None and ssh_options.classify(error) == ALGORITHMS


def test_strict_client_still_talks_to_a_modern_server(legacy):
    error, info = _handshake(ssh_options.disabled_algorithms(OTHER_IP))
    assert error is None, error
    assert info['host_key'] != 'ssh-rsa'


# ---------------------------------------------------------------- Scan, Review and Configure share it
class _Conn:
    def find_prompt(self): return 'R1#'
    def send_command(self, cmd, **kw): return 'hostname R1\n' if 'running' in cmd else ''
    def disconnect(self): pass


@pytest.fixture
def recorder(monkeypatch, legacy):
    from config import connect
    from discovery import crawler
    calls = []
    def fake(**kw):
        calls.append(kw)
        return _Conn()
    monkeypatch.setattr(crawler, 'ConnectHandler', fake)
    monkeypatch.setattr(connect, 'ConnectHandler', fake)
    return calls


@pytest.mark.parametrize('host', [LEGACY_IP, OTHER_IP])
def test_scan_review_and_configure_use_the_same_options(recorder, host):
    import services
    from config import connect
    from discovery import crawler
    crawler._login(host, 'admin', SECRET)                                    # Scan
    connect.get_config({'host': host, 'username': 'admin', 'password': SECRET})   # Review
    class Store:
        def get_credentials(self, _id): return 'admin', SECRET
    services.fetch_configs(Store(), [{'id': 1, 'name': 'R1', 'ip': host, 'managed': True}])  # Review
    connect._open({'host': host, 'username': 'admin', 'password': SECRET})  # Configure (Apply)
    expected = ssh_options.disabled_algorithms(host)
    assert len(recorder) == 4
    assert all(kw['disabled_algorithms'] == expected for kw in recorder)
    assert crawler.ssh_options is connect.ssh_options is services.ssh_options


# ---------------------------------------------------------------- error messages
def _netmiko_wrapped(inner, outer_cls):
    """An exception raised the way Netmiko raises it: while handling `inner`."""
    try:
        try:
            raise inner
        except Exception:
            raise outer_cls('TCP connection to device failed.')
    except Exception as err:
        return err


def _errors():
    from netmiko.exceptions import NetmikoAuthenticationException, NetmikoTimeoutException
    import paramiko
    from paramiko.ssh_exception import IncompatiblePeer
    return [
        (NetmikoAuthenticationException(f'bad login {SECRET}'), AUTH),
        (paramiko.AuthenticationException(SECRET), AUTH),
        (_netmiko_wrapped(IncompatiblePeer('Incompatible ssh peer (no acceptable kex algorithm)'),
                          NetmikoTimeoutException), ALGORITHMS),
        (_netmiko_wrapped(ConnectionRefusedError(10061, SECRET), NetmikoTimeoutException), REFUSED),
        (_netmiko_wrapped(socket.timeout(SECRET), NetmikoTimeoutException), TIMEOUT),
        (NetmikoTimeoutException(SECRET), TIMEOUT),
        (KeyError(SECRET), OTHER),
    ]


def test_each_kind_of_failure_is_told_apart_and_never_shows_secrets(legacy):
    for err, kind in _errors():
        got, text = ssh_options.describe_error(err, OTHER_IP)
        assert got == kind, (err, got)
        assert SECRET not in text and text


def test_algorithm_message_names_the_setting_only_when_it_could_help(legacy):
    err = _errors()[2][0]
    assert ssh_options.SETTING in ssh_options.describe_error(err, OTHER_IP)[1]
    assert ssh_options.SETTING not in ssh_options.describe_error(err, LEGACY_IP)[1]


@pytest.mark.parametrize('index, words', [(0, 'Wrong username or password'), (2, 'Unsupported SSH algorithms'),
                                          (3, 'Connection refused'), (4, 'No answer'), (6, 'KeyError')])
def test_configure_reports_the_kind_of_failure(monkeypatch, tmp_path, legacy, index, words):
    from config import connect
    err = _errors()[index][0]
    def boom(creds):
        raise err
    monkeypatch.setattr(connect, '_open', boom)
    log = []
    ok, msg = connect.apply_config({'host': OTHER_IP, 'username': 'admin', 'password': SECRET},
                                   ['vlan 10'], backup_dir=str(tmp_path),
                                   log=lambda k, t: log.append(t))
    assert ok is False and words in msg
    assert SECRET not in msg and not any(SECRET in line for line in log)


def test_review_notes_say_why_a_device_was_skipped(monkeypatch, legacy):
    import services
    from config import connect
    err = _errors()[2][0]
    def boom(creds):
        raise err
    monkeypatch.setattr(connect, 'get_config', boom)
    class Store:
        def get_credentials(self, _id): return 'admin', SECRET
    _, notes = services.fetch_configs(Store(), [{'id': 1, 'name': 'R1', 'ip': OTHER_IP, 'managed': True}])
    assert notes and 'old SSH algorithms' in notes[0] and notes[0].endswith('skipped')
    assert SECRET not in notes[0]


def test_scan_reports_unsupported_algorithms_instead_of_no_answer(monkeypatch, legacy):
    from discovery import crawler
    err = _errors()[2][0]
    def boom(ip, u, p):
        raise err
    monkeypatch.setattr(crawler, '_login', boom)
    with pytest.raises(RuntimeError) as e:
        crawler.discover('admin', SECRET, OTHER_IP)
    text = str(e.value)
    assert 'old SSH algorithms' in text and 'no answer' not in text and SECRET not in text
