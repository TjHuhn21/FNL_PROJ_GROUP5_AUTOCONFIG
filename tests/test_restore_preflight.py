"""Phase 4E: the restore preflight (restore_preflight.py).

Read-only checks (backup re-verification, SSH/privilege, strict live identity, matching,
restore capabilities, management access), then, only after the exact typed
confirmation, the encrypted pre-restore safety backup.

Synthetic data only: throwaway in-memory backup keys (tests/conftest.py), synthetic
serial numbers, temporary folders, and the Mock Lab on free ports of 127.0.0.1 through the
REAL Netmiko ConnectHandler. No physical device, real credential or production key is used,
and no plaintext backup is ever written.
"""
import dataclasses
import hashlib
import json
import os
import sys

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
sys.path.insert(0, os.path.join(ROOT, 'mock-lab'))

netmiko = pytest.importorskip('netmiko')
from netmiko import ConnectHandler  # noqa: E402

import backup_catalogue as B  # noqa: E402
import backup_crypto as C  # noqa: E402
import restore_preflight as R  # noqa: E402
from config import connect  # noqa: E402
from mocklab import restore_sim  # noqa: E402
from mocklab.cli import Session  # noqa: E402
from mocklab.device import Device  # noqa: E402
from mocklab.lab import Lab, LabError, check_config, load_config  # noqa: E402

CONFIG = load_config()
SPEC = {d['name']: d for d in CONFIG['devices']}
SERIAL = 'FTX0000SYN1'                    # synthetic
OTHER_SERIAL = 'FTX0000SYN9'
PLATFORM = 'CISCO1941/K9'
MODEL = f'Cisco {PLATFORM} (revision 1.0)'   # show version line the identity parser reads
MGMT = '192.168.10.1'                     # MOCK-R1's LAN address (simulated management IP)
MARK = 'SynthPreflightMarker-7'           # appears only inside backup configurations


# ---------------------------------------------------------------- helpers
def r1_spec(scenario='success', **extra):
    spec = restore_sim.restore_spec(SPEC['MOCK-R1'], scenario)
    spec.update({'model': MODEL, 'serial': SERIAL})
    spec.update(extra)
    for key, value in list(spec.items()):
        if value is None:
            spec.pop(key)
    return spec


def target_text(dev, *commands):
    """The running configuration dev would have after an NTP line (documentation range),
    an interface description holding MARK, and these commands, built on a copy, as an
    Apply backup would hold it. MARK lets tests prove the configuration never reaches a
    message; it is a real configuration line, so it survives a restore."""
    other = Device(dev.spec, lab_hosts={})
    s = Session(other, privilege=15)
    s.handle('configure terminal')
    for c in ('ntp server 192.0.2.77', 'interface GigabitEthernet0/2',
              f'description {MARK}') + commands:
        out = s.handle(c).output
        assert not out.lstrip().startswith('%'), (c, out)
    s.handle('end')
    return other.running_config()


def identity(**over):
    out = {'serial': SERIAL, 'platform': PLATFORM, 'hostname': 'MOCK-R1', 'ios_version': None}
    out.update(over)
    return out


def write_backup(folder, key, text, host, ident=None, name='selected.ncbak', key_id=None):
    os.makedirs(folder, exist_ok=True)
    meta = {'host': host, 'source': 'show running-config', 'privilege': 15}
    if ident is not None:
        meta.update(ident)
    data = C.encrypt_backup(text.encode(), key.key, key_id or key.key_id, meta)
    path = os.path.join(str(folder), name)
    with open(path, 'wb') as f:
        f.write(data)
    return path


def select(path, key, device_ip, device_id=1):
    """A Selection made like the catalogue makes it (verified first). For backups the
    Phase 4B selection would refuse (changed IP, no device serial yet), the same fields are
    filled in directly from the VERIFIED header."""
    entry = B._entry_for(path, 'Test folder')
    v = B.verify(entry, key.key_for)
    assert v.status == B.VERIFIED, v
    try:
        return B.select(entry, v, B.Device(ip=device_ip, device_id=device_id), True)
    except B.SelectionRefused:
        h = v.header
        return B.Selection(path, entry.file_sha256, h['key_id'], h['plaintext_sha256'],
                           h['created_utc'], device_id, device_ip, '', False, True, (),
                           '2026-11-22T00:00:00Z')


def statuses(result, name):
    return [c.status for c in result.checks if c.name == name]


def all_text(result, log=()):
    return ' '.join([c.text for c in result.checks] + [t for _, t in log] + result.lines())


def no_secrets(result, log=()):
    text = all_text(result, log)
    for secret in (MARK, SPEC['MOCK-R1']['password'], 'username', '$1$mock$hidden',
                   CONFIG['shared_scan_account']['password']):
        assert secret not in text, secret


def state(dev):
    return (dev.running_config(), dev.startup, dev.saves, sorted(dev.flash.files),
            list(dev.events), dev.rollback, dev.archive_copies[:])


# ---------------------------------------------------------------- the lab (real Netmiko)
@pytest.fixture(scope='module')
def key_path(tmp_path_factory):
    return str(tmp_path_factory.mktemp('preflight-lab-key') / 'host_rsa.key')


@pytest.fixture
def lab_with(key_path, monkeypatch):
    """lab_with(spec, ...) starts the lab with these device specs on free loopback ports and
    routes config.connect's SSH there. lab.logins lists every SSH login attempt (by host)."""
    labs, logins, ports = [], [], {}

    def real_connect(**kw):
        logins.append(kw['host'])
        host, port = ports[kw['host']]
        return ConnectHandler(**dict(kw, host=host, port=port))
    monkeypatch.setattr(connect, 'ConnectHandler', real_connect)

    def make(*specs):
        lab = Lab({'devices': list(specs),
                   'shared_scan_account': CONFIG['shared_scan_account']},
                  key_path=key_path, overrides={s['name']: ('127.0.0.1', 0) for s in specs})
        lab.start()
        labs.append(lab)
        for s in specs:
            ports[s['host']] = lab.address(s['name'])
        lab.logins = logins
        return lab
    yield make
    for lab in labs:
        lab.stop()


def creds(spec, **over):
    out = {'host': spec['host'], 'username': spec['username'], 'password': spec['password']}
    out.update(over)
    return out


@pytest.fixture
def setup(lab_with, synthetic_backup_key, tmp_path):
    """setup(spec=..., text=..., ident=..., header_host=...) -> (lab, dev, selection, spec).
    The backup holds the device's configuration plus one NTP line, by default."""
    def make(spec=None, text=None, ident='default', header_host=None, extra=()):
        spec = spec or r1_spec()
        lab = lab_with(spec, *extra)
        dev = lab.devices[spec['name']]
        body = text if text is not None else target_text(dev)
        ident = identity() if ident == 'default' else ident
        path = write_backup(tmp_path / 'backups', synthetic_backup_key, body,
                            header_host or spec['host'], ident)
        return lab, dev, select(path, synthetic_backup_key, spec['host']), spec
    return make


def run(selection, spec, log=None, **kw):
    lines = []
    result = R.run_checks(selection, creds(spec, **kw.pop('creds', {})),
                          log=log or (lambda k, t: lines.append((k, t))), **kw)
    return result, lines


# ================================================================ pure parsing (no SSH)
VERSION = f'Cisco {PLATFORM} (revision 1.0) with 491520K/32768K bytes of memory.\n' \
          f'Processor board ID {SERIAL}\n'


def inventory(*entries):
    return '\n'.join(f'NAME: "{n}", DESCR: "{d}"\nPID: {p}  , VID: V01 , SN: {s}\n'
                     for n, d, p, s in entries)


CHASSIS = ('CISCO1941/K9 chassis', 'CISCO1941/K9 chassis', PLATFORM, SERIAL)
MODULE = ('EHWIC-4ESG', '4-port Gigabit Ethernet module', 'EHWIC-4ESG', 'FOC0000MOD1')


@pytest.mark.parametrize('version, inv, expected', [
    (VERSION, '', SERIAL),                                         # show version only
    (VERSION, '% Invalid input detected at \'^\' marker.', SERIAL),  # no show inventory
    (VERSION, inventory(CHASSIS), SERIAL),                         # both agree
    (VERSION, inventory(CHASSIS, MODULE), SERIAL),                 # module serial ignored
    ('no serial line here', inventory(CHASSIS, MODULE), SERIAL),   # inventory only
    ('', inventory(('1', 'WS-C2960-24TT-L', 'WS-C2960-24TT-L', SERIAL)), SERIAL),  # stack no.
])
def test_resolve_serial_accepts_one_consistent_chassis_serial(version, inv, expected):
    assert R.resolve_serial(version, inv) == (expected, None)


@pytest.mark.parametrize('version, inv, why', [
    ('', '', 'no chassis serial'),
    ('', inventory(MODULE), 'no chassis serial'),                   # modules never count
    (VERSION + f'Processor board ID {OTHER_SERIAL}\n', '', 'different processor board IDs'),
    (VERSION, inventory(CHASSIS, ('2', 'stack', PLATFORM, OTHER_SERIAL)),
     'different chassis serial numbers'),
    (VERSION, inventory(CHASSIS[:3] + (OTHER_SERIAL,)), 'disagree'),
    ('Processor board ID FTX1 with extra words\n', '', 'not a plain serial'),
    ('Processor board ID unknown\n', '', 'not a plain serial'),
    ('Processor board ID\n', '', 'not a plain serial'),
    (VERSION, inventory(CHASSIS[:3] + ('',)), 'no usable serial'),
    (VERSION, 'NAME: "x", DESCR: "y"\ngarbage', 'could not be read reliably'),
])
def test_resolve_serial_blocks_anything_ambiguous_or_unreadable(version, inv, why):
    serial, problem = R.resolve_serial(version, inv)
    assert serial is None and why in problem


def test_resolve_platform_cross_checks_the_chassis_pid():
    assert R.resolve_platform(PLATFORM, inventory(CHASSIS, MODULE)) == (PLATFORM, None)
    assert R.resolve_platform(None, inventory(CHASSIS)) == (PLATFORM, None)
    platform, problem = R.resolve_platform('CISCO2901/K9', inventory(CHASSIS))
    assert platform is None and 'different models' in problem


CURRENT = """hostname R1
username admin privilege 15 secret 9 x
interface GigabitEthernet0/0
 ip address 192.168.10.1 255.255.255.0
!
line vty 0 4
 login local
 transport input ssh
end"""


def facts_check(target_text_, current=CURRENT, mgmt=MGMT, user='admin'):
    result = R.PreflightResult('10.0.0.1', None)
    R.management_checks(result, R.parse_config(target_text_), R.parse_config(current), mgmt,
                         user)
    return result


def test_management_access_kept():
    result = facts_check(CURRENT)
    assert statuses(result, 'management-ip') == [R.PASS]
    assert statuses(result, 'ssh-vty') == [R.PASS]
    assert statuses(result, 'login') == [R.PASS]
    assert result.status == R.PASS


@pytest.mark.parametrize('change, check, status', [
    (('ip address 192.168.10.1 255.255.255.0', 'ip address 192.168.99.1 255.255.255.0'),
     'management-ip', R.BLOCKED),                                # address removed
    (('ip address 192.168.10.1 255.255.255.0',
      'ip address 192.168.10.1 255.255.255.0\n shutdown'), 'management-ip', R.BLOCKED),
    (('interface GigabitEthernet0/0', 'interface GigabitEthernet0/1'), 'management-ip',
     R.WARNING),                                                  # moved to another port
    (('transport input ssh', 'transport input telnet'), 'ssh-vty', R.BLOCKED),
    (('transport input ssh', 'transport input none'), 'ssh-vty', R.BLOCKED),
    ((' transport input ssh\n', '\n'), 'ssh-vty', R.WARNING),    # IOS default: unknown
    (('line vty 0 4\n login local\n transport input ssh\n', ''), 'ssh-vty', R.BLOCKED),
    (('username admin privilege 15 secret 9 x\n', ''), 'login', R.BLOCKED),
    (('username admin', 'username someone'), 'login', R.WARNING),
    (('username admin privilege 15', 'username admin privilege 1'), 'login', R.WARNING),
    (('hostname R1', 'hostname R1\naaa new-model'), 'login', R.WARNING),
    (('login local', 'login local\n access-class 10 in'), 'login', R.WARNING),
    (('login local', 'login'), 'login', R.WARNING),
])
def test_management_access_problems(change, check, status):
    result = facts_check(CURRENT.replace(*change))
    assert status in statuses(result, check), result.lines()
    assert result.status == max([status] + [c.status for c in result.checks],
                                key=R._SEVERITY.__getitem__)


def test_management_address_not_on_the_device_is_a_warning_not_a_pass():
    result = facts_check(CURRENT, mgmt='127.0.0.11')
    assert statuses(result, 'management-ip') == [R.WARNING]


def test_parse_config_reads_what_the_preflight_needs():
    f = R.parse_config(CURRENT + '\narchive\n path flash:archive\n maximum 5\n'
                       'ip scp server enable\naaa new-model\n')
    assert f.interfaces['GigabitEthernet0/0'] == {'ips': {MGMT}, 'shutdown': False}
    assert f.vty_lines() == {'vty 0 4': ['login local', 'transport input ssh']}
    assert f.users == {'admin': 15} and f.archive_path == 'flash:archive'
    assert f.scp_enabled and f.aaa


class _Transport:
    def __init__(self, banner, active=True):
        self.remote_version, self.active = banner, active

    def is_active(self):
        return self.active


class _Conn:
    def __init__(self, banner, active=True):
        self.remote_conn = type('C', (), {'get_transport': lambda s: _Transport(banner, active)})()


@pytest.mark.parametrize('banner, active, status', [
    ('SSH-2.0-Cisco-1.25', True, R.PASS),
    ('SSH-1.99-Cisco-1.25', True, R.WARNING),
    ('SSH-1.5-Old', True, R.BLOCKED),
    (None, True, R.FAILED),
    ('SSH-2.0-Cisco-1.25', False, R.FAILED),
])
def test_ssh_protocol_version_two_is_required(banner, active, status):
    result = R.PreflightResult('10.0.0.1', None)
    assert R._ssh_protocol(_Conn(banner, active), result) == status


def test_confirmation_phrases():
    assert R.confirmation_phrase('10.0.0.1', False) == 'RESTORE 10.0.0.1'
    assert R.confirmation_phrase('10.0.0.1', True) == 'RESTORE LEGACY 10.0.0.1'


# ================================================================ backup re-verification
@pytest.fixture
def offline(monkeypatch, synthetic_backup_key, tmp_path):
    """A selected backup, and config.connect._open replaced so that any SSH attempt fails
    the test: these checks must stop before connecting."""
    def no_ssh(creds):
        raise AssertionError('the preflight connected although the backup check failed')
    monkeypatch.setattr(connect, '_open', no_ssh)
    text = target_text(Device(r1_spec(), lab_hosts={}))
    path = write_backup(tmp_path / 'backups', synthetic_backup_key, text, '127.0.0.11',
                        identity())
    return path, select(path, synthetic_backup_key, '127.0.0.11'), text


def check_offline(selection, status, words, check='backup'):
    result = R.run_checks(selection, creds(r1_spec()))
    assert result.status == status and result.stage == R.STOPPED, result.lines()
    assert statuses(result, check) == [status]
    assert words in result.check(check).text
    assert not result.can_proceed and not result.required_confirmation
    no_secrets(result)
    return result


def test_missing_backup_file(offline):
    path, selection, _ = offline
    os.remove(path)
    check_offline(selection, R.BLOCKED, 'no longer exists')


def test_backup_replaced_after_selection(offline, synthetic_backup_key, tmp_path):
    path, selection, text = offline
    write_backup(tmp_path / 'backups', synthetic_backup_key, text, '127.0.0.11', identity())
    check_offline(selection, R.BLOCKED, 'changed after it was selected')


def test_backup_metadata_changed_after_selection(offline, synthetic_backup_key, tmp_path):
    """Another valid backup (different hostname in its authenticated header) in its place."""
    path, selection, text = offline
    write_backup(tmp_path / 'backups', synthetic_backup_key, text, '127.0.0.11',
                 identity(hostname='OTHER'))
    check_offline(selection, R.BLOCKED, 'changed after it was selected')


def test_tampered_backup_fails_authentication(offline):
    path, selection, _ = offline
    data = bytearray(open(path, 'rb').read())
    data[-5] ^= 0x01
    open(path, 'wb').write(bytes(data))
    again = dataclasses.replace(selection, file_sha256=hashlib.sha256(bytes(data)).hexdigest())
    check_offline(again, R.BLOCKED, 'could not be authenticated')


def _sealed(key, plaintext, header_changes):
    header = {'format': 'ncbak', 'alg': C.ALGORITHM, 'key_id': key.key_id,
              'nonce': C._b64(os.urandom(C.NONCE_BYTES)), 'created_utc': C.utc_now_text(),
              'plaintext_sha256': hashlib.sha256(plaintext).hexdigest(),
              'plaintext_size': len(plaintext), 'host': '127.0.0.11'}
    header.update(header_changes)
    return C.seal(C.MAGIC, header, plaintext, key.key), header


@pytest.mark.parametrize('changes, words', [
    ({'plaintext_sha256': '0' * 64}, 'does not match its recorded SHA-256'),
    ({'plaintext_size': 5}, 'truncated or has extra data'),
])
def test_hash_and_size_failures(offline, synthetic_backup_key, changes, words):
    path, selection, text = offline
    data, header = _sealed(synthetic_backup_key, text.encode(), changes)
    open(path, 'wb').write(data)
    again = dataclasses.replace(selection, file_sha256=hashlib.sha256(data).hexdigest(),
                                plaintext_sha256=header['plaintext_sha256'],
                                created_utc=header['created_utc'])
    check_offline(again, R.BLOCKED, words)


@pytest.mark.parametrize('field_name, words', [
    ('key_id', 'key id'), ('plaintext_sha256', 'configuration SHA-256'),
    ('created_utc', 'creation time')])
def test_selection_fields_must_match_the_authenticated_header(offline, field_name, words):
    _path, selection, _ = offline
    value = {'key_id': 'b7', 'plaintext_sha256': 'f' * 64,
             'created_utc': '2020-01-01T00:00:00Z'}[field_name]
    check_offline(dataclasses.replace(selection, **{field_name: value}), R.BLOCKED, words)


def test_missing_keyring(offline, monkeypatch):
    class Gone:
        def active_key(self):
            raise OSError(2, 'No such file or directory')
    monkeypatch.setattr(connect, 'KEY_SOURCE', Gone())
    check_offline(offline[1], R.FAILED, 'keyring cannot be used')


def test_key_not_in_the_keyring(offline, synthetic_backup_key, tmp_path):
    other = type(synthetic_backup_key)('b2')                    # a second synthetic key
    path = write_backup(tmp_path / 'other', other, offline[2], '127.0.0.11', identity())
    check_offline(select(path, other, '127.0.0.11'), R.FAILED, 'does not hold the key')


def test_unusable_configuration_is_blocked(offline, synthetic_backup_key, tmp_path):
    text = offline[2].rsplit('end', 1)[0]                       # cut off: no final "end"
    path = write_backup(tmp_path / 'cut', synthetic_backup_key, text, '127.0.0.11', identity())
    entry = B._entry_for(path, 'x')
    h = C.read_backup_header(open(path, 'rb').read())[0]
    sel = B.Selection(path, entry.file_sha256, h['key_id'], h['plaintext_sha256'],
                      h['created_utc'], 1, '127.0.0.11', '', False, True, (), 'now')
    check_offline(sel, R.BLOCKED, 'configuration is not usable')


def test_link_is_not_followed(offline, monkeypatch):
    monkeypatch.setattr(B, '_is_link', lambda p: True)
    check_offline(offline[1], R.BLOCKED, 'link or junction')


def test_no_selection_and_selection_for_another_device(offline):
    assert R.run_checks(None, creds(r1_spec())).check('selection').status == R.BLOCKED
    sw1 = creds(SPEC['SW1'])
    result = R.run_checks(offline[1], sw1)
    assert result.status == R.BLOCKED and 'was selected for 127.0.0.11' in result.check(
        'device').text


def test_reverification_writes_nothing(offline, tmp_path):
    before = sorted(os.listdir(tmp_path / 'backups'))
    os.remove(offline[0])
    R.run_checks(offline[1], creds(r1_spec()))
    assert sorted(os.listdir(tmp_path / 'backups')) == [n for n in before if n !=
                                                         'selected.ncbak']


# ================================================================ read-only checks (lab)
def test_preflight_passes_and_changes_nothing(setup, tmp_path):
    lab, dev, selection, spec = setup()
    before = state(dev)
    backups = sorted(os.listdir(tmp_path / 'backups'))
    log = []
    result = R.run_checks(selection, creds(spec), management_ip=MGMT,
                          log=lambda k, t: log.append((k, t)))
    assert result.status == R.PASS, result.lines()
    assert result.stage == R.CHECKED and result.can_proceed
    assert result.required_confirmation == f'RESTORE {spec["host"]}'
    assert result.identity == {'hostname': 'MOCK-R1', 'platform': PLATFORM, 'serial': SERIAL,
                               'ios_version': None}
    assert result.hardware_match and not result.requires_legacy_confirmation
    assert result.transfer_method == 'tcl'
    assert result.temp_name.startswith(R.TEMP_PREFIX) and \
        not dev.flash.exists(result.temp_name)
    caps = result.capabilities
    assert caps['archive'] and caps['configure_replace'] and caps['tcl'] and not caps['scp']
    assert caps['rollback_pending'] is False and caps['flash_free'] == dev.flash.free()
    for name in ('backup', 'ssh', 'privilege', 'identity', 'match-serial', 'match-platform',
                 'pending-rollback', 'archive', 'rollback', 'flash-space', 'temp-file',
                 'transfer', 'management-ip', 'ssh-vty', 'login'):
        assert statuses(result, name) == [R.PASS], name
    assert result.safety_backup_path is None
    assert state(dev) == before                                 # NOTHING changed
    assert sorted(os.listdir(tmp_path / 'backups')) == backups  # no file written
    assert any(t == 'SSH session closed.' for _, t in log)
    no_secrets(result, log)
    assert not any('show running-config' in t and 'hostname' in t for _, t in log)


def test_without_management_ip_the_lab_address_gives_a_warning(setup):
    lab, dev, selection, spec = setup()
    result, _ = run(selection, spec)
    assert result.status == R.WARNING and result.can_proceed
    assert statuses(result, 'management-ip') == [R.WARNING]


def test_serial_mismatch_blocks(setup):
    lab, dev, selection, spec = setup(ident=identity(serial=OTHER_SERIAL))
    before = state(dev)
    result, _ = run(selection, spec, management_ip=MGMT)
    assert result.status == R.BLOCKED and result.stage == R.STOPPED
    assert statuses(result, 'match-serial') == [R.BLOCKED]
    assert not result.required_confirmation and state(dev) == before


@pytest.mark.parametrize('extra, words', [
    ({'serial': [SERIAL, OTHER_SERIAL]}, 'different processor board IDs'),
    ({'serial': None}, 'no chassis serial'),
    ({'inventory': [{'name': 'CISCO1941/K9 chassis', 'descr': 'chassis', 'pid': PLATFORM,
                     'sn': OTHER_SERIAL}]}, 'disagree'),
    ({'inventory': [{'name': '1', 'descr': 'x', 'pid': PLATFORM, 'sn': SERIAL},
                    {'name': '2', 'descr': 'x', 'pid': PLATFORM, 'sn': OTHER_SERIAL}]},
     'different chassis serial numbers'),
])
def test_ambiguous_or_missing_live_serial_blocks(setup, extra, words):
    lab, dev, selection, spec = setup(spec=r1_spec(**extra))
    result, _ = run(selection, spec, management_ip=MGMT)
    assert result.status == R.BLOCKED
    assert statuses(result, 'identity') == [R.BLOCKED] and words in result.check('identity').text
    assert result.check('pending-rollback') is None             # stopped before probing


def test_module_serials_are_ignored_over_ssh(setup):
    inv = [{'name': 'CISCO1941/K9 chassis', 'descr': 'CISCO1941/K9 chassis', 'pid': PLATFORM,
            'sn': SERIAL},
           {'name': 'EHWIC-4ESG', 'descr': 'module', 'pid': 'EHWIC-4ESG', 'sn': 'FOC0000MOD1'},
           {'name': 'PVDM3-16', 'descr': 'DSP module', 'pid': 'PVDM3-16', 'sn': 'FOC0000MOD2'}]
    lab, dev, selection, spec = setup(spec=r1_spec(inventory=inv))
    result, _ = run(selection, spec, management_ip=MGMT)
    assert result.status == R.PASS and result.identity['serial'] == SERIAL


def test_platform_mismatch_blocks(setup):
    lab, dev, selection, spec = setup(ident=identity(platform='WS-C2960-24TT-L'))
    result, _ = run(selection, spec, management_ip=MGMT)
    assert result.status == R.BLOCKED and statuses(result, 'match-platform') == [R.BLOCKED]


def test_hostname_mismatch_is_only_a_warning(setup):
    lab, dev, selection, spec = setup(ident=identity(hostname='OLD-NAME'))
    result, _ = run(selection, spec, management_ip=MGMT)
    assert result.status == R.WARNING and result.can_proceed
    assert statuses(result, 'match-hostname') == [R.WARNING]
    assert result.required_confirmation == f'RESTORE {spec["host"]}'


def test_legacy_backup_needs_the_legacy_confirmation(setup):
    lab, dev, selection, spec = setup(ident=None)
    result, _ = run(selection, spec, management_ip=MGMT)
    assert result.status == R.WARNING and result.can_proceed
    assert not result.hardware_match and result.requires_legacy_confirmation
    assert statuses(result, 'match-serial') == [R.WARNING]
    assert result.required_confirmation == f'RESTORE LEGACY {spec["host"]}'


def test_changed_ip_with_serial_match_warns(setup):
    lab, dev, selection, spec = setup(header_host='127.0.0.99')
    result, _ = run(selection, spec, management_ip=MGMT)
    assert result.status == R.WARNING and result.can_proceed
    assert statuses(result, 'match-ip') == [R.WARNING] and result.hardware_match


def test_changed_ip_without_serial_match_blocks(setup):
    lab, dev, selection, spec = setup(header_host='127.0.0.99', ident=None)
    result, _ = run(selection, spec, management_ip=MGMT)
    assert result.status == R.BLOCKED
    assert any('IP address differs' in c.text for c in result.of(R.BLOCKED))


@pytest.mark.parametrize('scenario, check, words', [
    ('no_archive', 'archive', 'No archive path'),
    ('replace_unsupported', 'rollback', 'not supported'),
])
def test_missing_archive_or_rollback_support_blocks(setup, scenario, check, words):
    lab, dev, selection, spec = setup(spec=r1_spec(scenario))
    before = state(dev)
    result, _ = run(selection, spec, management_ip=MGMT)
    assert result.status == R.BLOCKED and statuses(result, check) == [R.BLOCKED]
    assert words in result.check(check).text
    assert state(dev) == before                                 # archive not configured
    assert 'archive' not in [e[1] for e in dev.events]          # no archive copy made


def test_pending_rollback_blocks(setup):
    lab, dev, selection, spec = setup()
    dev.rollback = restore_sim.Rollback(dev.config_state(), None, lab.clock.now(), 5)
    result, _ = run(selection, spec, management_ip=MGMT)
    assert statuses(result, 'pending-rollback') == [R.BLOCKED]
    assert dev.rollback is not None                            # never confirmed or reverted


@pytest.mark.parametrize('scenario, quirks, method, status', [
    ('success', [], 'tcl', R.PASS),
    ('scp', [], 'tcl', R.PASS),
    ('scp', ['no_tcl'], 'scp', R.WARNING),
    ('success', ['no_tcl'], None, R.BLOCKED),
])
def test_transfer_capabilities(setup, scenario, quirks, method, status):
    lab, dev, selection, spec = setup(spec=r1_spec(scenario, quirks=quirks))
    before = state(dev)
    result, _ = run(selection, spec, management_ip=MGMT)
    assert result.transfer_method == method
    assert statuses(result, 'transfer') == [status]
    assert result.capabilities['scp'] == (scenario == 'scp')
    assert result.capabilities['tcl'] == ('no_tcl' not in quirks)
    assert ('ip scp server enable' in dev.running_config()) == (scenario == 'scp')  # never enabled
    assert state(dev) == before


def test_insufficient_flash_blocks(setup):
    lab, dev, selection, spec = setup(spec=r1_spec(flash_bytes=100_000))
    result, _ = run(selection, spec, management_ip=MGMT)
    assert statuses(result, 'flash-space') == [R.BLOCKED]
    assert 'Not enough free space' in result.check('flash-space').text


def test_taken_temporary_names_are_skipped(setup, monkeypatch):
    lab, dev, selection, spec = setup()
    names = iter(['a' * 16, 'b' * 16])
    monkeypatch.setattr(R.secrets, 'token_hex', lambda n: next(names))
    dev.flash.write(f'{R.TEMP_PREFIX}{"a" * 16}{R.TEMP_SUFFIX}', b'existing')
    result, _ = run(selection, spec, management_ip=MGMT)
    assert result.temp_name == f'{R.TEMP_PREFIX}{"b" * 16}{R.TEMP_SUFFIX}'
    assert dev.flash.get(f'{R.TEMP_PREFIX}{"a" * 16}{R.TEMP_SUFFIX}').data == b'existing'


def test_no_free_temporary_name_blocks(setup, monkeypatch):
    lab, dev, selection, spec = setup()
    monkeypatch.setattr(R.secrets, 'token_hex', lambda n: 'c' * 16)
    dev.flash.write(f'{R.TEMP_PREFIX}{"c" * 16}{R.TEMP_SUFFIX}', b'existing')
    result, _ = run(selection, spec, management_ip=MGMT)
    assert statuses(result, 'temp-file') == [R.BLOCKED]


def test_backup_removing_the_management_ip_blocks(setup, lab_with):
    spec = r1_spec()
    dev = Device(spec, lab_hosts={})
    text = target_text(dev, 'interface GigabitEthernet0/0', 'no ip address')
    lab, dev, selection, spec = setup(spec=spec, text=text)
    result, _ = run(selection, spec, management_ip=MGMT)
    assert result.status == R.BLOCKED and statuses(result, 'management-ip') == [R.BLOCKED]


def test_backup_without_ssh_on_vty_blocks(setup):
    spec = r1_spec()
    text = target_text(Device(spec, lab_hosts={}), 'line vty 0 4', 'transport input telnet')
    lab, dev, selection, spec = setup(spec=spec, text=text)
    result, _ = run(selection, spec, management_ip=MGMT)
    assert result.status == R.BLOCKED and statuses(result, 'ssh-vty') == [R.BLOCKED]


def test_privilege_below_15_blocks(setup):
    lab, dev, selection, spec = setup()        # MOCK-R1 starts in user mode
    result, _ = run(selection, spec, creds={'secret': 'Synthetic-wrong-enable'})
    assert result.status == R.BLOCKED and statuses(result, 'privilege') == [R.BLOCKED]
    assert result.check('identity') is None


def test_wrong_password_fails_closed(setup):
    lab, dev, selection, spec = setup()
    result, _ = run(selection, spec, creds={'password': 'Synthetic-wrong-pass'})
    assert result.status == R.FAILED and statuses(result, 'connection') == [R.FAILED]
    assert 'Synthetic-wrong-pass' not in all_text(result)


def test_unreachable_device_fails_closed(setup):
    lab, dev, selection, spec = setup()
    lab.stop()
    result, _ = run(selection, spec)
    assert result.status == R.FAILED and statuses(result, 'connection') == [R.FAILED]


def test_session_error_fails_closed(setup, monkeypatch):
    lab, dev, selection, spec = setup()

    def broken(*a, **k):
        raise EOFError('synthetic session failure')
    monkeypatch.setattr(R, '_identity_and_match', broken)
    result, _ = run(selection, spec)
    assert result.status == R.FAILED and statuses(result, 'session') == [R.FAILED]
    assert 'synthetic session failure' not in all_text(result)


# ================================================================ confirmation and safety backup
def decrypt(key, path):
    with open(path, 'rb') as f:
        return C.decrypt_backup(f.read(), key.key_for)


def test_safety_backup_after_exact_confirmation(setup, synthetic_backup_key, tmp_path):
    lab, dev, selection, spec = setup()
    result, _ = run(selection, spec, management_ip=MGMT)
    before = state(dev)
    out_dir = tmp_path / 'safety'
    R.create_safety_backup(result, result.required_confirmation, creds(spec),
                           backup_dir=str(out_dir))
    assert result.stage == R.SAFETY_BACKUP_CREATED, result.lines()
    path = result.safety_backup_path
    assert os.listdir(out_dir) == [os.path.basename(path)]      # ONLY the encrypted file
    assert os.path.basename(path).startswith(f'{spec["host"]}_pre-restore_') and \
        path.endswith('.ncbak')
    plaintext, header = decrypt(synthetic_backup_key, path)
    assert plaintext == dev.running_config().encode()           # the CURRENT configuration
    assert header['purpose'] == 'pre-restore' and header['host'] == spec['host']
    assert header['serial'] == SERIAL and header['platform'] == PLATFORM
    assert result.safety_backup_sha256 == hashlib.sha256(plaintext).hexdigest()
    assert open(path, 'rb').read().startswith(C.MAGIC)
    assert statuses(result, 'safety-backup') == [R.PASS]
    assert statuses(result, 'identity-recheck') == [R.PASS]
    assert state(dev) == before                                 # still unchanged
    no_secrets(result)
    with pytest.raises(R.ConfirmationRefused, match='already created'):
        R.create_safety_backup(result, result.required_confirmation, creds(spec),
                               backup_dir=str(out_dir))


@pytest.mark.parametrize('typed', ['', 'restore 127.0.0.11', 'RESTORE  127.0.0.11',
                                   'RESTORE 127.0.0.11 ', 'RESTORE LEGACY 127.0.0.11', None])
def test_wrong_confirmation_does_nothing(setup, tmp_path, typed):
    lab, dev, selection, spec = setup()
    result, _ = run(selection, spec, management_ip=MGMT)
    logins = len(lab.logins)
    before = state(dev)
    with pytest.raises(R.ConfirmationRefused, match='not typed exactly'):
        R.create_safety_backup(result, typed, creds(spec), backup_dir=str(tmp_path / 'safety'))
    assert len(lab.logins) == logins                            # no connection at all
    assert not (tmp_path / 'safety').exists() and state(dev) == before
    assert result.stage == R.CHECKED                            # may still be typed correctly


def test_legacy_backup_needs_the_legacy_phrase(setup, tmp_path):
    lab, dev, selection, spec = setup(ident=None)
    result, _ = run(selection, spec, management_ip=MGMT)
    with pytest.raises(R.ConfirmationRefused):
        R.create_safety_backup(result, f'RESTORE {spec["host"]}', creds(spec),
                               backup_dir=str(tmp_path / 's'))
    R.create_safety_backup(result, f'RESTORE LEGACY {spec["host"]}', creds(spec),
                           backup_dir=str(tmp_path / 's'))
    assert result.stage == R.SAFETY_BACKUP_CREATED


def test_cancel_before_the_safety_backup_leaves_everything_unchanged(setup, tmp_path):
    lab, dev, selection, spec = setup()
    before = state(dev)
    result, _ = run(selection, spec, management_ip=MGMT)
    logins = len(lab.logins)
    R.cancel(result)
    assert result.stage == R.CANCELLED and not result.can_proceed
    with pytest.raises(R.ConfirmationRefused, match='cancelled'):
        R.create_safety_backup(result, result.required_confirmation, creds(spec),
                               backup_dir=str(tmp_path / 'safety'))
    assert len(lab.logins) == logins and not (tmp_path / 'safety').exists()
    assert state(dev) == before


def test_blocked_preflight_cannot_continue(setup, tmp_path):
    lab, dev, selection, spec = setup(spec=r1_spec('no_archive'))
    result, _ = run(selection, spec, management_ip=MGMT)
    with pytest.raises(R.ConfirmationRefused, match='did not pass'):
        R.create_safety_backup(result, f'RESTORE {spec["host"]}', creds(spec),
                               backup_dir=str(tmp_path / 's'))
    assert not (tmp_path / 's').exists()


def test_stale_preflight_and_other_device_are_refused(setup, tmp_path):
    lab, dev, selection, spec = setup()
    t = [1000.0]
    result = R.run_checks(selection, creds(spec), management_ip=MGMT, clock=lambda: t[0])
    with pytest.raises(R.ConfirmationRefused, match='another device'):
        R.create_safety_backup(result, result.required_confirmation, creds(SPEC['SW1']),
                               clock=lambda: t[0], backup_dir=str(tmp_path / 's'))
    t[0] += R.FRESH_SECONDS + 1
    with pytest.raises(R.ConfirmationRefused, match='too old'):
        R.create_safety_backup(result, result.required_confirmation, creds(spec),
                               clock=lambda: t[0], backup_dir=str(tmp_path / 's'))
    assert not (tmp_path / 's').exists()


def test_safety_backup_key_failure(setup, monkeypatch, tmp_path):
    lab, dev, selection, spec = setup()
    result, _ = run(selection, spec, management_ip=MGMT)
    logins = len(lab.logins)

    class Gone:
        def active_key(self):
            raise OSError(13, 'Permission denied')
    monkeypatch.setattr(connect, 'KEY_SOURCE', Gone())
    R.create_safety_backup(result, result.required_confirmation, creds(spec),
                           backup_dir=str(tmp_path / 's'))
    assert result.stage == R.STOPPED and result.status == R.FAILED
    assert len(lab.logins) == logins and not (tmp_path / 's').exists()


def test_safety_backup_write_failure(setup, monkeypatch, tmp_path):
    lab, dev, selection, spec = setup()
    result, _ = run(selection, spec, management_ip=MGMT)

    def refuse(*a, **k):
        raise connect.BackupError('Backup of x failed: the file could not be written (Disk full)')
    monkeypatch.setattr(connect, '_save_backup', refuse)
    R.create_safety_backup(result, result.required_confirmation, creds(spec),
                           backup_dir=str(tmp_path / 's'))
    assert result.stage == R.STOPPED and statuses(result, 'safety-backup') == [R.FAILED]
    assert result.safety_backup_path is None


def test_safety_backup_verification_failure(setup, monkeypatch, tmp_path):
    lab, dev, selection, spec = setup()
    result, _ = run(selection, spec, management_ip=MGMT)
    monkeypatch.setattr(R, 'verify_safety_backup', lambda *a: 'synthetic mismatch')
    R.create_safety_backup(result, result.required_confirmation, creds(spec),
                           backup_dir=str(tmp_path / 's'))
    assert result.stage == R.STOPPED and statuses(result, 'safety-backup') == [R.FAILED]
    assert result.safety_backup_path is None and 'Do not continue' in \
        result.check('safety-backup').text


def test_verify_safety_backup_detects_differences(synthetic_backup_key, tmp_path):
    running = target_text(Device(r1_spec(), lab_hosts={}))
    path, _sha, _ = connect._save_backup('127.0.0.11', running, str(tmp_path),
                                         synthetic_backup_key.active_key(), identity(),
                                         purpose=R.PURPOSE)
    key_for = synthetic_backup_key.key_for
    assert R.verify_safety_backup(path, running, key_for, '127.0.0.11', identity()) is None
    assert 'differs' in R.verify_safety_backup(path, running + '!', key_for, '127.0.0.11',
                                               identity())
    assert 'labelled' in R.verify_safety_backup(path, running, key_for, '127.0.0.12',
                                                identity())
    assert 'identity' in R.verify_safety_backup(path, running, key_for, '127.0.0.11',
                                                identity(serial=OTHER_SERIAL))
    data = bytearray(open(path, 'rb').read())
    data[-1] ^= 1
    open(path, 'wb').write(bytes(data))
    assert 'decrypt' in R.verify_safety_backup(path, running, key_for, '127.0.0.11', identity())
    os.remove(path)
    assert 'read back' in R.verify_safety_backup(path, running, key_for, '127.0.0.11',
                                                 identity())


def test_device_swapped_between_stages_blocks(setup, tmp_path):
    lab, dev, selection, spec = setup()
    result, _ = run(selection, spec, management_ip=MGMT)
    dev.serials = [OTHER_SERIAL]                     # another chassis now answers here
    R.create_safety_backup(result, result.required_confirmation, creds(spec),
                           backup_dir=str(tmp_path / 's'))
    assert result.stage == R.STOPPED and statuses(result, 'identity-recheck') == [R.BLOCKED]
    assert not (tmp_path / 's').exists()


def test_backup_changed_between_stages_blocks_before_connecting(setup, synthetic_backup_key,
                                                                 tmp_path):
    lab, dev, selection, spec = setup()
    result, _ = run(selection, spec, management_ip=MGMT)
    logins = len(lab.logins)
    with open(selection.path, 'ab') as f:
        f.write(b'x')
    R.create_safety_backup(result, result.required_confirmation, creds(spec),
                           backup_dir=str(tmp_path / 's'))
    assert result.stage == R.STOPPED and statuses(result, 'backup-recheck') == [R.BLOCKED]
    assert len(lab.logins) == logins and not (tmp_path / 's').exists()


# ================================================================ several devices
def test_preflight_touches_only_its_own_device(setup, tmp_path):
    sw1 = dict(SPEC['SW1'], serial='FOC0000SW01')
    lab, dev, selection, spec = setup(extra=(sw1,))
    other = lab.devices['SW1']
    other_before = state(other)
    result, _ = run(selection, spec, management_ip=MGMT)
    R.create_safety_backup(result, result.required_confirmation, creds(spec),
                           backup_dir=str(tmp_path / 's'))
    assert result.stage == R.SAFETY_BACKUP_CREATED
    assert set(lab.logins) == {spec['host']}                    # SW1 never contacted
    assert state(other) == other_before
    # the R1 selection cannot be used for SW1
    refused = R.run_checks(selection, creds(sw1))
    assert refused.status == R.BLOCKED and refused.check('device') is not None
    assert set(lab.logins) == {spec['host']}


# ================================================================ supporting changes
def test_save_backup_purpose_label(synthetic_backup_key, tmp_path):
    running = target_text(Device(r1_spec(), lab_hosts={}))
    path, _, _ = connect._save_backup('10.0.0.2', running, str(tmp_path),
                                      synthetic_backup_key.active_key(), purpose='pre-restore')
    assert os.path.basename(path).startswith('10.0.0.2_pre-restore_')
    assert decrypt(synthetic_backup_key, path)[1]['purpose'] == 'pre-restore'
    plain, _, _ = connect._save_backup('10.0.0.2', running, str(tmp_path),
                                       synthetic_backup_key.active_key())
    assert 'purpose' not in decrypt(synthetic_backup_key, plain)[1]     # Apply: unchanged
    for bad in ('Pre Restore', '../x', 'a' * 40, ''):
        with pytest.raises(connect.BackupError, match='purpose'):
            connect._save_backup('10.0.0.2', running, str(tmp_path),
                                 synthetic_backup_key.active_key(), purpose=bad)
    assert sorted(os.listdir(tmp_path)) == sorted([os.path.basename(path),
                                                   os.path.basename(plain)])


def test_purpose_must_be_text_in_the_header(synthetic_backup_key):
    with pytest.raises(C.BackupCryptoError):
        C.encrypt_backup(b'x', synthetic_backup_key.key, 'b1', {'purpose': 5})


def test_mock_lab_default_shows_no_serial_and_no_inventory():
    dev = Device(SPEC['MOCK-R1'], lab_hosts={})
    s = Session(dev, privilege=15)
    assert 'Processor board ID' not in dev.show_version()
    assert 'Invalid input' in s.handle('show inventory').output


def test_mock_lab_serial_and_inventory():
    inv = [{'name': 'CISCO1941/K9 chassis', 'descr': 'CISCO1941/K9 chassis', 'pid': PLATFORM,
            'vid': 'V05', 'sn': SERIAL}]
    dev = Device(r1_spec(inventory=inv), lab_hosts={})
    s = Session(dev, privilege=15)
    assert f'Processor board ID {SERIAL}' in s.handle('show version').output
    out = s.handle('show inventory').output
    assert R.parse_inventory(out) == (R.INVENTORY_OK, [('CISCO1941/K9 chassis',
                                                        'CISCO1941/K9 chassis', PLATFORM,
                                                        SERIAL)])
    assert connect.parse_identity(dev.show_version(), dev.running_config())['platform'] == \
        PLATFORM


@pytest.mark.parametrize('change', [
    {'serial': ''}, {'serial': []}, {'serial': 5}, {'serial': ['ok', 'bad\nline']},
    {'inventory': {}}, {'inventory': [{'descr': 'no name'}]},
    {'inventory': [{'name': 'x', 'sn': 'has"quote'}]},
    {'inventory': [{'name': 'x', 'other': 'key'}]},
])
def test_lab_config_refuses_bad_identity_keys(change):
    config = json.loads(json.dumps(CONFIG))
    config['devices'][0].update(change)
    with pytest.raises(LabError):
        check_config(config)


# ================================================================ changed IP and legacy review
# (Phase 4E review, kept as regression tests; adapted to the Phase 4B follow-up in which a
# changed-IP backup that records a serial and platform is selected as a PENDING candidate.)
OLD_IP = '127.0.0.99'


def test_catalogue_selects_changed_ip_only_as_a_pending_candidate(synthetic_backup_key,
                                                                  tmp_path):
    text = target_text(Device(r1_spec(), lab_hosts={}))
    path = write_backup(tmp_path, synthetic_backup_key, text, OLD_IP, identity())
    entry = B._entry_for(path, 'x')
    v = B.verify(entry, synthetic_backup_key.key_for)
    sel = B.select(entry, v, B.Device(ip='127.0.0.11', device_id=1), True)
    assert sel.live_identity_required and not sel.hardware_match     # pending, not a match
    known = B.select(entry, v, B.Device(ip='127.0.0.11', serial=SERIAL, platform=PLATFORM,
                                        device_id=1), True)
    assert known.hardware_match and not known.live_identity_required
    legacy = write_backup(tmp_path, synthetic_backup_key, text, OLD_IP, None, name='old.ncbak')
    entry = B._entry_for(legacy, 'x')
    with pytest.raises(B.SelectionRefused, match='IP address differs'):
        B.select(entry, B.verify(entry, synthetic_backup_key.key_for),
                 B.Device(ip='127.0.0.11', device_id=1), True)


def test_changed_ip_serial_and_platform_match_is_eligible(setup, tmp_path):
    lab, dev, selection, spec = setup(header_host=OLD_IP)
    assert selection.device_ip == spec['host']                  # selected FOR the new IP
    assert selection.live_identity_required and not selection.hardware_match
    result, _ = run(selection, spec, management_ip=MGMT)
    assert result.status == R.WARNING and result.can_proceed, result.lines()
    assert statuses(result, 'match-ip') == [R.WARNING]
    assert statuses(result, 'match-serial') == [R.PASS]
    assert statuses(result, 'match-platform') == [R.PASS]
    assert statuses(result, 'live-identity') == [R.PASS] and result.live_identity_verified
    assert result.required_confirmation == f'RESTORE {spec["host"]}'
    R.create_safety_backup(result, result.required_confirmation, creds(spec),
                           backup_dir=str(tmp_path / 's'))
    assert result.stage == R.SAFETY_BACKUP_CREATED


@pytest.mark.parametrize('ident, check', [
    (identity(platform='WS-C2960-24TT-L'), 'match-platform'),
    (identity(serial=OTHER_SERIAL), 'match-serial'),
])
def test_changed_ip_with_any_hardware_mismatch_blocks(setup, ident, check):
    lab, dev, selection, spec = setup(header_host=OLD_IP, ident=ident)
    result, _ = run(selection, spec, management_ip=MGMT)
    assert result.status == R.BLOCKED and statuses(result, check) == [R.BLOCKED]


def test_changed_ip_backup_that_drops_the_current_management_ip_blocks(setup):
    spec = r1_spec()
    text = target_text(Device(spec, lab_hosts={}), 'interface GigabitEthernet0/0',
                       'ip address 192.168.20.1 255.255.255.0')   # the OLD addressing
    lab, dev, selection, spec = setup(spec=spec, text=text, header_host=OLD_IP)
    result, _ = run(selection, spec, management_ip=MGMT)
    assert statuses(result, 'match-serial') == [R.PASS]
    assert statuses(result, 'management-ip') == [R.BLOCKED]


def test_unrelated_device_selection_blocked_without_any_login(setup):
    sw1 = dict(SPEC['SW1'], serial='FOC0000SW01')
    lab, dev, selection, spec = setup(extra=(sw1,))
    result = R.run_checks(selection, creds(sw1))
    assert result.status == R.BLOCKED and result.check('device') is not None
    assert lab.logins == []                                   # no SSH attempt at all
    with pytest.raises(R.ConfirmationRefused):
        R.create_safety_backup(result, f'RESTORE {sw1["host"]}', creds(sw1))


@pytest.mark.parametrize('ident', [None, identity(serial=None), identity(serial='unknown'),
                                   identity(serial='n/a')])
def test_missing_or_placeholder_serial_is_never_a_match(setup, ident):
    lab, dev, selection, spec = setup(ident=ident)
    result, _ = run(selection, spec, management_ip=MGMT)
    assert not result.hardware_match and result.requires_legacy_confirmation
    assert statuses(result, 'match-serial') == [R.WARNING]
    assert result.required_confirmation == f'RESTORE LEGACY {spec["host"]}'


@pytest.mark.parametrize('extra', [
    {'serial': [SERIAL, OTHER_SERIAL]}, {'serial': None},
    {'inventory': [{'name': 'x chassis', 'descr': 'c', 'pid': PLATFORM, 'sn': OTHER_SERIAL}]}])
def test_legacy_still_enforces_strict_live_serial(setup, extra):
    lab, dev, selection, spec = setup(spec=r1_spec(**extra), ident=None)
    result, _ = run(selection, spec, management_ip=MGMT)
    assert result.status == R.BLOCKED and statuses(result, 'identity') == [R.BLOCKED]


def test_legacy_live_platform_inconsistency_blocks(setup):
    inv = [{'name': 'x chassis', 'descr': 'c', 'pid': 'CISCO2901/K9', 'sn': SERIAL}]
    lab, dev, selection, spec = setup(spec=r1_spec(inventory=inv), ident=None)
    result, _ = run(selection, spec, management_ip=MGMT)
    assert result.status == R.BLOCKED and 'different models' in result.check('identity').text


def test_partial_legacy_with_recorded_platform_mismatch_blocks(setup):
    lab, dev, selection, spec = setup(ident=identity(serial=None, platform='WS-C2960-24TT-L'))
    result, _ = run(selection, spec, management_ip=MGMT)
    assert result.status == R.BLOCKED and statuses(result, 'match-platform') == [R.BLOCKED]


@pytest.mark.parametrize('typed', ['RESTORE 127.0.0.11', 'restore legacy 127.0.0.11',
                                   'RESTORE LEGACY  127.0.0.11', 'RESTORE LEGACY 127.0.0.12'])
def test_legacy_requires_the_exact_phrase(setup, tmp_path, typed):
    lab, dev, selection, spec = setup(ident=None)
    result, _ = run(selection, spec, management_ip=MGMT)
    n = len(lab.logins)
    with pytest.raises(R.ConfirmationRefused, match='not typed exactly'):
        R.create_safety_backup(result, typed, creds(spec), backup_dir=str(tmp_path / 's'))
    assert len(lab.logins) == n and not (tmp_path / 's').exists()


def test_legacy_stage_two_rechecks_live_identity(setup, tmp_path):
    lab, dev, selection, spec = setup(ident=None)
    result, _ = run(selection, spec, management_ip=MGMT)
    dev.serials = [OTHER_SERIAL]
    R.create_safety_backup(result, f'RESTORE LEGACY {spec["host"]}', creds(spec),
                           backup_dir=str(tmp_path / 's'))
    assert result.stage == R.STOPPED and statuses(result, 'identity-recheck') == [R.BLOCKED]
    assert not (tmp_path / 's').exists()


# ================================================================ pending candidates: regressions
def _refused_without_login(lab, result, spec, tmp_path, typed=None):
    n = len(lab.logins)
    with pytest.raises(R.ConfirmationRefused):
        R.create_safety_backup(result, typed or f'RESTORE {spec["host"]}', creds(spec),
                               backup_dir=str(tmp_path / 's'))
    assert len(lab.logins) == n and not (tmp_path / 's').exists()


@pytest.mark.parametrize('extra, check', [
    ({'model': None}, 'live-identity'),             # live platform cannot be read
    ({'serial': None}, 'identity'),                 # live serial cannot be read
    ({'serial': OTHER_SERIAL}, 'match-serial'),     # another chassis at the new IP
    ({'model': 'Cisco CISCO2901/K9 (revision 1.0)'}, 'match-platform'),
])
def test_candidate_without_live_serial_and_platform_match_never_reaches_safety_backup(
        setup, tmp_path, extra, check):
    lab, dev, selection, spec = setup(spec=r1_spec(**extra), header_host=OLD_IP)
    assert selection.live_identity_required
    before = state(dev)
    result, _ = run(selection, spec, management_ip=MGMT)
    assert result.status == R.BLOCKED and statuses(result, check) == [R.BLOCKED], \
        result.lines()
    assert not result.live_identity_verified and not result.can_proceed
    assert result.check('pending-rollback') is None            # stopped before any probe
    _refused_without_login(lab, result, spec, tmp_path)
    assert state(dev) == before


def test_unrelated_device_cannot_use_a_candidate_to_bypass_identity(lab_with,
                                                                   synthetic_backup_key,
                                                                   tmp_path):
    """R1's backup selected (as a changed-IP candidate) for SW1's address: the catalogue
    cannot tell them apart, the live check must."""
    r1 = r1_spec()
    for sw1_serial, check in (('FOC0000SW01', 'match-serial'), (None, 'identity')):
        sw1 = dict(SPEC['SW1'], **({'serial': sw1_serial} if sw1_serial else {}))
        lab = lab_with(r1, sw1)
        text = target_text(Device(r1, lab_hosts={}))
        path = write_backup(tmp_path / str(sw1_serial), synthetic_backup_key, text,
                            r1['host'], identity())
        selection = select(path, synthetic_backup_key, sw1['host'])
        assert selection.live_identity_required and selection.device_ip == sw1['host']
        before = state(lab.devices['SW1'])
        result = R.run_checks(selection, creds(sw1))
        assert result.status == R.BLOCKED and statuses(result, check) == [R.BLOCKED]
        _refused_without_login(lab, result, sw1, tmp_path)
        assert state(lab.devices['SW1']) == before
        assert r1['host'] not in lab.logins                   # R1 never contacted
        lab.stop()


def test_candidate_flag_alone_requires_live_platform(setup, tmp_path):
    """Even when the recorded IP happens to be the device's, a candidate selection still
    needs the live serial AND platform (the mock router shows no platform here)."""
    lab, dev, selection, spec = setup(spec=r1_spec(model=None))
    flagged = dataclasses.replace(selection, live_identity_required=True)
    result, _ = run(flagged, spec, management_ip=MGMT)
    assert result.status == R.BLOCKED and statuses(result, 'live-identity') == [R.BLOCKED]
    plain, _ = run(selection, spec, management_ip=MGMT)          # same-IP: unchanged rules
    assert plain.check('live-identity') is None and plain.can_proceed


def test_safety_backup_refuses_a_changed_ip_result_without_live_verification(setup,
                                                                            tmp_path):
    lab, dev, selection, spec = setup(header_host=OLD_IP)
    result, _ = run(selection, spec, management_ip=MGMT)
    assert result.can_proceed and result.live_identity_verified
    result.live_identity_verified = False              # a result altered after the checks
    _refused_without_login(lab, result, spec, tmp_path, result.required_confirmation)
    assert result.stage == R.CHECKED and result.safety_backup_path is None


def test_candidate_device_swapped_between_stages_blocks(setup, tmp_path):
    lab, dev, selection, spec = setup(header_host=OLD_IP)
    result, _ = run(selection, spec, management_ip=MGMT)
    assert result.can_proceed
    dev.serials = [OTHER_SERIAL]
    R.create_safety_backup(result, result.required_confirmation, creds(spec),
                           backup_dir=str(tmp_path / 's'))
    assert result.stage == R.STOPPED and statuses(result, 'identity-recheck') == [R.BLOCKED]
    assert not (tmp_path / 's').exists()


def test_selecting_a_candidate_sends_no_command_and_makes_no_backup(lab_with,
                                                                    synthetic_backup_key,
                                                                    tmp_path, monkeypatch):
    lab = lab_with(r1_spec())
    dev = lab.devices['MOCK-R1']
    before = state(dev)
    monkeypatch.setattr(connect, '_save_backup', lambda *a, **k: pytest.fail('backup made'))
    path = write_backup(tmp_path / 'b', synthetic_backup_key, target_text(dev), OLD_IP,
                        identity())
    selection = select(path, synthetic_backup_key, '127.0.0.11')
    assert selection.live_identity_required
    assert lab.logins == [] and state(dev) == before
    assert os.listdir(tmp_path / 'b') == ['selected.ncbak']


# ================================================================ seal for the restore engine (4F)
def test_seal_exists_only_after_the_safety_backup_and_breaks_on_any_change(setup, tmp_path):
    lab, dev, selection, spec = setup()
    result, _ = run(selection, spec, management_ip=MGMT)
    assert result.seal is None and not R.seal_valid(result)
    R.create_safety_backup(result, result.required_confirmation, creds(spec),
                           backup_dir=str(tmp_path / 's'))
    assert R.seal_valid(result) and result.safety_backup_at is not None
    assert result.confirmed_phrase == result.required_confirmation
    result.temp_name = 'nc-restore-0000000000000000.cfg'
    assert not R.seal_valid(result)


def test_cancel_breaks_the_seal(setup, tmp_path):
    lab, dev, selection, spec = setup()
    result, _ = run(selection, spec, management_ip=MGMT)
    R.create_safety_backup(result, result.required_confirmation, creds(spec),
                           backup_dir=str(tmp_path / 's'))
    R.cancel(result)
    assert not R.seal_valid(result)
