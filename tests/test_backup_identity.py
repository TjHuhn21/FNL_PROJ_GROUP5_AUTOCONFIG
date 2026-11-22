"""Phase 4A: device identity (serial, platform, hostname, IOS version) recorded in new
encrypted backups. Synthetic "show version" output in Cisco's format and fake devices only;
no device is contacted and no real key is used."""
import json
import os
import struct
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import backup_crypto as C  # noqa: E402
import backup_tool as T  # noqa: E402
from config import connect, multi  # noqa: E402
from test_backup_security import Recording  # noqa: E402

ISR = """Cisco IOS Software, C1900 Software (C1900-UNIVERSALK9-M), Version 15.4(3)M2, RELEASE SOFTWARE (fc1)
Technical Support: http://www.cisco.com/techsupport
Copyright (c) 1986-2014 by Cisco Systems, Inc.

ROM: System Bootstrap, Version 15.0(1r)M15, RELEASE SOFTWARE (fc1)

SYNTH-R1 uptime is 2 days, 3 hours, 4 minutes
System image file is "flash0:c1900-universalk9-mz.SPA.154-3.M2.bin"
Cisco CISCO1941/K9 (revision 1.0) with 491520K/32768K bytes of memory.
Processor board ID FTX0000SYN1
2 Gigabit Ethernet interfaces
Configuration register is 0x2102
"""
SWITCH = """Cisco IOS Software, C2960 Software (C2960-LANBASEK9-M), Version 15.0(2)SE11, RELEASE SOFTWARE (fc3)
ROM: Bootstrap program is C2960 boot loader
BOOTLDR: C2960 Boot Loader (C2960-HBOOT-M) Version 12.2(44)SE5, RELEASE SOFTWARE (fc1)

SYNTH-SW1 uptime is 1 week
cisco WS-C2960-24TT-L (PowerPC405) processor (revision B0) with 65536K bytes of memory.
Processor board ID FOC0000SYN2
24 FastEthernet interfaces

Model number                    : WS-C2960-24TT-L
System serial number            : FOC0000SYN2
"""
OLD_IOS = """Cisco Internetwork Operating System Software
IOS (tm) C2950 Software (C2950-I6Q4L2-M), Version 12.1(22)EA14, RELEASE SOFTWARE (fc1)
cisco WS-C2950-24 (RC32300) processor (revision C0) with 19912K bytes of memory.
Processor board ID FHK0000SYN3
"""
IOS_XE = """Cisco IOS XE Software, Version 16.09.04
Cisco IOS Software [Fuji], ISR Software (X86_64_LINUX_IOSD-UNIVERSALK9-M), Version 16.9.4, RELEASE SOFTWARE (fc2)
cisco ISR4331/K9 (1RU) processor with 1795999K/6147K bytes of memory.
Processor board ID FLM0000SYN4
"""
RUNNING = ('Building configuration...\n\n!\nversion 15.4\nhostname SYNTH-R1\n!\n'
           'username admin privilege 15 secret 9 SynthHash-Not-Real\n!\nend\n')
FULL = {'serial': 'FTX0000SYN1', 'platform': 'CISCO1941/K9', 'ios_version': '15.4(3)M2',
        'hostname': 'SYNTH-R1'}


# ================================================================ 1-4: extraction
def test_isr_identity():
    assert connect.parse_identity(ISR, RUNNING) == FULL


def test_crlf_output_is_read_the_same():
    assert connect.parse_identity(ISR.replace('\n', '\r\n'), RUNNING.replace('\n', '\r\n')) == FULL
    switch = connect.parse_identity(SWITCH.replace('\n', '\r\n'), '')
    assert (switch['serial'], switch['platform']) == ('FOC0000SYN2', 'WS-C2960-24TT-L')


def test_switch_identity():
    assert connect.parse_identity(SWITCH, 'hostname SYNTH-SW1\nend\n') == {
        'serial': 'FOC0000SYN2', 'platform': 'WS-C2960-24TT-L', 'ios_version': '15.0(2)SE11',
        'hostname': 'SYNTH-SW1'}


@pytest.mark.parametrize('text, expected', [
    (OLD_IOS, {'serial': 'FHK0000SYN3', 'platform': 'WS-C2950-24', 'ios_version': '12.1(22)EA14'}),
    (IOS_XE, {'serial': 'FLM0000SYN4', 'platform': 'ISR4331/K9', 'ios_version': '16.09.04'}),
])
def test_other_ios_formats(text, expected):
    identity = connect.parse_identity(text, '')
    assert {k: identity[k] for k in expected} == expected


def test_the_boot_rom_version_is_never_taken_for_the_ios_version():
    without_ios_line = '\n'.join(l for l in ISR.splitlines() if 'IOS Software' not in l)
    assert connect.parse_identity(without_ios_line, '')['ios_version'] is None


def test_the_model_number_line_is_used_when_the_memory_line_is_missing():
    text = '\n'.join(l for l in SWITCH.splitlines() if 'bytes of memory' not in l)
    assert connect.parse_identity(text, '')['platform'] == 'WS-C2960-24TT-L'


@pytest.mark.parametrize('running, hostname', [
    ('!\nhostname SYNTH-R1\n!\nend\n', 'SYNTH-R1'),
    ('hostname SYNTH-R1   \r\nend\r\n', 'SYNTH-R1'),
    ('hostname FIRST\nhostname SECOND\n', 'FIRST'),
    (' description hostname NOT-THIS\nend\n', None),          # only a real hostname line
    ('!\nend\n', None),
])
def test_hostname_comes_from_the_running_configuration(running, hostname):
    assert connect.parse_identity('', running)['hostname'] == hostname


# ================================================================ 5: missing / incomplete
@pytest.mark.parametrize('version', [
    None, '', "% Invalid input detected at '^' marker.", 'Cisco IOS Software, truncated',
    ISR.split('Cisco CISCO1941')[0],                          # cut off before model and serial
    'Processor board ID\nCisco IOS Software',                   # no value
    'Processor board ID FTX 0000 SYN\n',                        # not a plain token
    'Processor board ID FTX;DROP\n', 12345,
])
def test_missing_or_incomplete_output_is_unavailable_never_guessed(version):
    identity = connect.parse_identity(version, None)
    assert identity['serial'] is None and identity['hostname'] is None
    if not isinstance(version, str) or 'CISCO1941' not in version:
        assert identity['platform'] is None


def test_values_with_unusual_characters_are_not_stored():
    assert connect.parse_identity('Processor board ID FTX0000\x07SYN\n', '')['serial'] is None
    assert connect.parse_identity('', 'hostname ' + 'x' * 65 + '\n')['hostname'] is None


# ================================================================ 6: collection failures
def apply(monkeypatch, tmp_path, fake):
    log = []
    monkeypatch.setattr(connect, '_open', lambda creds: fake)
    ok, msg = connect.apply_config({'host': '10.0.0.2', 'username': 'a', 'password': 'Synth-9'},
                                   ['vlan 10'], [], backup_dir=str(tmp_path),
                                   log=lambda k, t: log.append((k, t)))
    return ok, msg, log


class Identity(Recording):
    def __init__(self, version=ISR, fail=None, **kw):
        super().__init__(running=kw.pop('running', RUNNING), **kw)
        self.version, self.version_fail = version, fail

    def send_command(self, cmd):
        if cmd == 'show version':
            self.asked.append(cmd)
            if self.version_fail:
                raise self.version_fail
            return self.version
        return super().send_command(cmd)


def header_of(path, synthetic_backup_key):
    return synthetic_backup_key.decrypt(path)[1]


def test_a_failing_show_version_records_unavailable_and_apply_continues(
        monkeypatch, tmp_path, synthetic_backup_key):
    fake = Identity(fail=RuntimeError('synthetic channel error'))
    ok, msg, log = apply(monkeypatch, tmp_path, fake)
    assert ok and fake.sent == ['vlan 10'] and fake.saved
    header = header_of(multi.backup_path(msg), synthetic_backup_key)
    assert (header['serial'], header['platform'], header['ios_version']) == (None, None, None)
    assert header['hostname'] == 'SYNTH-R1'                    # still from the running config
    assert any(k == 'warn' and '"show version" failed (RuntimeError)' in t for k, t in log)
    assert 'synthetic channel error' not in ' '.join(t for _, t in log)


@pytest.mark.parametrize('version', ["% Invalid input detected at '^' marker.", '', 'garbage'])
def test_unusable_show_version_output_records_unavailable(monkeypatch, tmp_path,
                                                          synthetic_backup_key, version):
    ok, msg, log = apply(monkeypatch, tmp_path, Identity(version=version))
    assert ok
    header = header_of(multi.backup_path(msg), synthetic_backup_key)
    assert header['serial'] is None and 'serial' in header       # looked for: unavailable
    assert any('serial unavailable' in t for k, t in log if k == 'info')


def test_a_lost_session_during_show_version_still_sends_nothing(monkeypatch, tmp_path):
    from netmiko.exceptions import NetmikoTimeoutException
    fake = Identity(fail=NetmikoTimeoutException('t'))
    ok, msg, _ = apply(monkeypatch, tmp_path, fake)
    assert ok is False and 'No answer' in msg
    assert fake.sent == [] and fake.closed and list(tmp_path.iterdir()) == []


# ================================================================ 7: survives encryption
def test_identity_is_recorded_in_the_backup_and_shown_by_the_tool(monkeypatch, tmp_path,
                                                                 synthetic_backup_key):
    fake = Identity()
    ok, msg, log = apply(monkeypatch, tmp_path, fake)
    assert ok and fake.asked[:3] == ['show privilege', 'show version', 'show running-config']
    path = multi.backup_path(msg)
    plaintext, header = synthetic_backup_key.decrypt(path)
    assert {k: header[k] for k in FULL} == FULL
    assert header['host'] == '10.0.0.2' and header['privilege'] == 15
    assert C.identity_of(header) == FULL
    assert any(k == 'info' and 'hostname SYNTH-R1, platform CISCO1941/K9, serial FTX0000SYN1, '
               'IOS version 15.4(3)M2' in t for k, t in log)
    monkeypatch.setattr(T.K.Keyring, 'load', lambda path: pytest.fail('real keyring'))
    info = T.describe(header)
    assert info['identity'] == FULL
    printed = []
    T._show(printed.append, info)
    assert printed[1] == ('  identity: hostname SYNTH-R1, platform CISCO1941/K9, serial '
                          'FTX0000SYN1, IOS version 15.4(3)M2')


def test_the_three_identity_states_are_distinct():
    key = os.urandom(32)
    lookup = {'b1': key}.__getitem__
    recorded = C.encrypt_backup(b'hostname A\nend\n', key, 'b1', dict(FULL))
    unavailable = C.encrypt_backup(b'hostname A\nend\n', key, 'b1',
                                   {k: None for k in C.IDENTITY_FIELDS})
    older = C.encrypt_backup(b'hostname A\nend\n', key, 'b1', {'host': '10.0.0.2'})
    assert C.identity_of(C.decrypt_backup(recorded, lookup)[1]) == FULL
    assert set(C.identity_of(C.decrypt_backup(unavailable, lookup)[1]).values()) == {C.UNAVAILABLE}
    assert set(C.identity_of(C.decrypt_backup(older, lookup)[1]).values()) == {C.NOT_RECORDED}
    header = C.read_backup_header(unavailable)[0]
    assert header['serial'] is None and 'serial' in header


@pytest.mark.parametrize('bad', ['two words', 'x' * 65, 'semi;colon', '', 5, True])
def test_invalid_identity_values_are_refused_by_the_format(bad):
    with pytest.raises(C.BackupCryptoError):
        C.encrypt_backup(b'hostname A\nend\n', os.urandom(32), 'b1', {'serial': bad})


def test_apply_stores_an_invalid_identity_value_as_unavailable(tmp_path, synthetic_backup_key):
    identity = dict(FULL, serial='two words', platform='x' * 80)
    path, _, _ = connect._save_backup('10.0.0.2', RUNNING, str(tmp_path), identity=identity)
    header = synthetic_backup_key.decrypt(path)[1]
    assert header['serial'] is None and header['platform'] is None
    assert header['hostname'] == 'SYNTH-R1'


# ================================================================ 8: tampering
def split(data):
    (length,) = struct.unpack('>I', data[6:10])
    return data[10:10 + length], data[10 + length:]


def rebuilt(header, body):
    raw = json.dumps(header, sort_keys=True, separators=(',', ':')).encode()
    return C.MAGIC + bytes([1]) + struct.pack('>I', len(raw)) + raw + body


@pytest.mark.parametrize('change', [
    lambda h: h.update(serial='FTX0000SYN9'),              # another device's serial
    lambda h: h.update(serial=None),                       # "unavailable" instead of the value
    lambda h: h.pop('serial'),                             # "not recorded" instead
    lambda h: h.update(hostname='OTHER'),
    lambda h: h.update(platform='CISCO2911/K9'),
    lambda h: h.update(ios_version='15.9(3)M'),
])
def test_changing_identity_breaks_authentication(change):
    key = os.urandom(32)
    data = C.encrypt_backup(b'hostname A\nend\n', key, 'b1', dict(FULL))
    raw, body = split(data)
    header = json.loads(raw)
    change(header)
    with pytest.raises(C.AuthenticationFailed):
        C.decrypt_backup(rebuilt(header, body), {'b1': key}.__getitem__)


@pytest.mark.parametrize('value', ['two words', 7, ['FTX'], 'x' * 65])
def test_malformed_identity_in_a_header_is_refused_before_decryption(value):
    data = C.encrypt_backup(b'hostname A\nend\n', os.urandom(32), 'b1', dict(FULL))
    raw, body = split(data)
    header = json.loads(raw)
    header['serial'] = value
    with pytest.raises(C.FormatError):
        C.read_backup_header(rebuilt(header, body))


def test_apply_refuses_a_backup_whose_header_identity_differs_on_read_back(
        monkeypatch, tmp_path):
    real = C.decrypt_backup

    def altered(data, key_for):
        plaintext, header = real(data, key_for)
        return plaintext, dict(header, serial='FTX0000SYN9')
    monkeypatch.setattr(C, 'decrypt_backup', altered)
    fake = Identity()
    ok, msg, _ = apply(monkeypatch, tmp_path, fake)
    assert ok is False and fake.sent == [] and 'does not match' in msg
    assert list(tmp_path.iterdir()) == []


# ================================================================ 9: older backups
def test_backups_without_identity_still_verify_and_say_not_recorded(tmp_path):
    """A Phase 3B backup (no identity fields at all) is not rewritten and still verifies."""
    from test_backup_keys import FakeProtector, N, PHRASE
    import backup_keys as K
    ring = str(tmp_path / 'keys' / 'backup-keyring.json')
    K.init(ring, str(tmp_path / 'b1.ncrecovery'), PHRASE, FakeProtector(), n=N)
    key_id, key = K.Keyring.load(ring).active(FakeProtector())
    older = C.encrypt_backup(RUNNING.encode(), key, key_id,
                             {'host': '10.0.0.2', 'source': 'show running-config',
                              'privilege': 15})
    path = tmp_path / '10.0.0.2_20261122_120000.ncbak'
    path.write_bytes(older)
    before = path.read_bytes()
    info = T.verify(str(path), ring, FakeProtector())
    assert set(info['identity'].values()) == {C.NOT_RECORDED}
    assert path.read_bytes() == before                     # never rewritten


# ================================================================ 10: fail-closed unchanged
def test_identity_does_not_change_the_fail_closed_rules(monkeypatch, tmp_path):
    class Missing:
        def active_key(self):
            raise C.BackupCryptoError('synthetic: no keyring')
    monkeypatch.setattr(connect, 'KEY_SOURCE', Missing())
    monkeypatch.setattr(connect, '_open', lambda creds: pytest.fail('SSH opened'))
    ok, msg = connect.apply_config({'host': '10.0.0.2', 'username': 'a', 'password': 'S-9'},
                                   ['vlan 10'], [], backup_dir=str(tmp_path))
    assert ok is False and 'No SSH connection was opened' in msg


def test_privilege_failure_still_stops_before_show_version(monkeypatch, tmp_path):
    fake = Identity(privilege='Current privilege level is 1')
    ok, msg, _ = apply(monkeypatch, tmp_path, fake)
    assert ok is False and fake.asked == ['show privilege'] and fake.sent == []


def test_an_unusable_configuration_still_stops_with_identity_present(monkeypatch, tmp_path):
    fake = Identity(running="% Invalid input detected at '^' marker.\n")
    ok, msg, _ = apply(monkeypatch, tmp_path, fake)
    assert ok is False and fake.sent == [] and list(tmp_path.iterdir()) == []
