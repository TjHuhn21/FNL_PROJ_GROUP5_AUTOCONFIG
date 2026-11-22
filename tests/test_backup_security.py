"""Backup security, phases 1 and 2: secret masking (desktop config.connect.mask and backend
app_records.mask_secrets, kept identical), backup validation, atomic and unique backup
files with a SHA-256, and the fail-safe Apply (no usable backup -> nothing is sent).

Every secret below is SYNTHETIC. Fake devices only: nothing connects to any network device,
and every file is written in a temporary folder (never backups/ or mock-lab/backups/)."""
import hashlib
import os
import re
import sys
from datetime import datetime

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from backend.database import app_records  # noqa: E402
from config import connect, multi  # noqa: E402
from test_ssh_session import FakeIOS  # noqa: E402

S1, S2 = 'Synth3tic-Val1', 'Synth3tic-Val2'          # never real secrets
MASKERS = {'desktop': connect.mask, 'backend': app_records.mask_secrets}
VALID = ('Building configuration...\n\nCurrent configuration : 64 bytes\n!\nversion 15.2\n'
         '!\nhostname SW1\n!\ninterface Vlan1\n no ip address\n!\nend\n')


def hidden(text):
    """True when neither synthetic secret is visible (asserting a boolean keeps the secret
    out of pytest's failure output)."""
    return S1 not in text and S2 not in text


@pytest.fixture(params=sorted(MASKERS))
def mask(request):
    return MASKERS[request.param]


# ================================================================ phase 1: masking
@pytest.mark.parametrize('line, expected', [
    # 1. IKEv2 keyring: pre-shared-key local / remote
    (f' pre-shared-key local {S1}', ' pre-shared-key local ********'),
    (f' pre-shared-key remote 0 {S1}', ' pre-shared-key remote 0 ********'),
    (f' pre-shared-key address 10.0.0.1 key {S1}', ' pre-shared-key address 10.0.0.1 key ********'),
    (f' pre-shared-key address 10.0.0.0 255.0.0.0 key {S1}',
     ' pre-shared-key address 10.0.0.0 255.0.0.0 key ********'),
    (f' pre-shared-key hostname peer1 key {S1}', ' pre-shared-key hostname peer1 key ********'),
    # 2. OSPF message-digest-key N md5
    (f' ip ospf message-digest-key 1 md5 {S1}', ' ip ospf message-digest-key 1 md5 ********'),
    (f' ip ospf message-digest-key 2 md5 7 {S1}', ' ip ospf message-digest-key 2 md5 7 ********'),
    # 3. NTP authentication-key N md5 (the trailing encryption type stays)
    (f'ntp authentication-key 1 md5 {S1} 7', 'ntp authentication-key 1 md5 ******** 7'),
    # 4. HSRP (and VRRP / GLBP) authentication
    (f' standby 1 authentication {S1}', ' standby 1 authentication ********'),
    (f' standby authentication text {S1}', ' standby authentication text ********'),
    (f' vrrp 2 authentication text {S1}', ' vrrp 2 authentication text ********'),
    (f' glbp 5 authentication text {S1}', ' glbp 5 authentication text ********'),
    (f' standby 1 authentication md5 key-string 7 {S1}',
     ' standby 1 authentication md5 key-string 7 ********'),
    # 5. wireless PSK
    (f' wpa-psk ascii 0 {S1}', ' wpa-psk ascii 0 ********'),
    (f' wpa-psk hex {S1}', ' wpa-psk hex ********'),
    # 6. SNMPv3 users: BOTH keys on the same line
    (f'snmp-server user u1 grp v3 auth sha {S1} priv aes 128 {S2}',
     'snmp-server user u1 grp v3 auth sha ******** priv aes 128 ********'),
    (f'snmp-server user u1 grp v3 encrypted auth md5 {S1} priv des {S2}',
     'snmp-server user u1 grp v3 encrypted auth md5 ******** priv des ********'),
    (f'snmp-server user u1 grp v3 auth sha256 {S1} priv aes 256 {S2} access 10',
     'snmp-server user u1 grp v3 auth sha256 ******** priv aes 256 ******** access 10'),
    (f'snmp-server user u1 grp v3 auth sha {S1} priv 3des {S2}',
     'snmp-server user u1 grp v3 auth sha ******** priv 3des ********'),
])
def test_the_six_formats_are_masked_and_their_keywords_kept(mask, line, expected):
    out = mask(line)
    assert hidden(out)
    assert out == expected


@pytest.mark.parametrize('line', [
    f' IP OSPF Message-Digest-Key 12   MD5\t7 {S1}',
    f'NTP\tAUTHENTICATION-KEY 3 Md5  {S1}',
    f' STANDBY   10 Authentication\tTEXT {S1}',
    f' WPA-PSK  ASCII\t0 {S1}',
    f' Pre-Shared-Key   LOCAL {S1}',
    f'SNMP-SERVER USER u g v3 AUTH  SHA\t{S1}  PRIV AES   128 {S2}',
])
def test_capitalisation_and_spacing_do_not_matter(mask, line):
    assert hidden(mask(line))


def test_several_secrets_on_one_line_and_in_one_text(mask):
    text = (f'snmp-server user u1 grp v3 auth sha {S1} priv aes 128 {S2}\n'
            f'crypto isakmp key {S1} address 10.0.0.1\n'
            f'username admin privilege 15 secret 9 {S2}\n'
            f' pre-shared-key local {S1}\n pre-shared-key remote {S2}\n')
    out = mask(text)
    assert hidden(out)
    assert out.count('********') == 6
    assert 'address 10.0.0.1' in out and 'username admin privilege 15 secret 9' in out


def test_a_value_is_never_taken_from_the_next_line(mask):
    """Every rule stays on one line: "key 1" at the end of a line must not mask the next
    line's first word and leave the key-string value visible (the old rule did)."""
    out = mask(f'key chain K1\n key 1\n  key-string {S1}\n')
    assert hidden(out)
    assert out.splitlines()[2] == '  key-string ********'


@pytest.mark.parametrize('line', [
    'interface GigabitEthernet0/1', ' ip address 10.0.0.1 255.255.255.0', 'hostname R1',
    'snmp-server location LAB', 'snmp-server enable traps', ' standby 1 ip 10.0.0.254',
    ' standby 1 priority 110', ' standby 1 preempt',
    ' standby 1 authentication md5 key-chain HSRP-CHAIN', 'router ospf 1',
    ' area 0 authentication message-digest', ' ip ospf authentication message-digest',
    'ntp authenticate', 'ntp server 10.0.0.5', 'aaa authentication login default local',
    'crypto ikev2 profile P1', ' authentication remote pre-share',
    ' authentication local pre-share', ' match identity remote address 10.0.0.2 255.255.255.255',
    ' transport input ssh', 'ip ssh version 2', 'line vty 0 4', ' login local', '!', 'end',
    ' description uplink to core', 'vlan 10', ' name SALES',
])
def test_ordinary_lines_are_unchanged(mask, line):
    assert mask(line) == line


@pytest.mark.parametrize('line', [
    f'enable secret 9 {S1}', f'username bob password 7 {S1}', f' password 0 two {S1}',
    f'snmp-server community {S1} RO', f'tacacs-server key 7 {S1}', f' key 7 {S1}',
    f'crypto isakmp key {S1} address 10.0.0.1', f'ip ospf authentication-key {S1}',
    f' neighbor 10.0.0.2 password {S1}', f'ppp chap password {S1}',
    f'username x privilege 15 algorithm-type scrypt secret {S1}', f' key-string {S1}',
])
def test_the_formats_masked_before_are_still_masked(mask, line):
    assert hidden(mask(line))


def test_desktop_and_backend_masking_are_identical():
    assert connect._SECRET_WORD_RULES == app_records._SECRET_WORD_RULES
    assert connect._SECRET_TO_EOL.pattern == app_records._SECRET_TO_EOL.pattern
    assert connect._SECRET.pattern == app_records._SECRET_WORD.pattern
    assert connect.MASKED == app_records.MASK
    corpus = [f'snmp-server user u g v3 auth sha {S1} priv aes 128 {S2}',
              f' pre-shared-key local {S1}', 'interface Vlan1', f'enable secret 5 {S1}',
              f'key chain K\n key 1\n  key-string {S1}', '']
    for text in corpus:
        assert connect.mask(text) == app_records.mask_secrets(text)


def test_job_event_text_uses_the_same_masking():
    assert hidden(app_records.clean_job_text(f'snmp-server user u g v3 auth sha {S1} priv aes '
                                             f'128 {S2}', 2000))


# ================================================================ phase 2A: validation
@pytest.mark.parametrize('text, fragment', [
    ('', 'empty'),
    ('   \n\t\n  ', 'empty'),
    (None, 'empty'),
    ("% Invalid input detected at '^' marker.\n", 'an error instead of its configuration'),
    ('% Authorization failed.\n', 'an error instead of its configuration'),
    ('Command authorization failed.\n', 'an error instead of its configuration'),
    ('%Error opening tftp://x (Timed out)\n', 'an error instead of its configuration'),
    ('Building configuration...\n', 'no hostname line'),
    ('Building configuration...\n\nCurrent configuration : 900 bytes\n!\nversion 15.2\n',
     'no hostname line'),
    ('Building configuration...\n\nCurrent configuration : 900 bytes\n!\nhostname SW1\n!\n'
     'interface Vlan1\n', 'incomplete'),                                  # cut off
    (VALID.replace('\nend\n', '\nen\n'), 'incomplete'),
    (VALID + 'SW1#\n', 'incomplete'),                                     # something after end
])
def test_unusable_backups_are_refused(text, fragment):
    problem = connect.check_backup(text)
    assert problem and fragment in problem


@pytest.mark.parametrize('text', [
    VALID,
    VALID.replace('\n', '\r\n'),                                          # CRLF
    VALID + '\n\n   \n',                                                  # blank lines after end
    VALID.replace('\nend\n', '\nend   \n'),                               # spaces after end
    '!\nversion 15.2\nhostname R1\n!\nend',                               # no header, no newline
    'hostname R1\nbanner motd ^C\n% Authorized access only %\n^C\nend\n',  # % inside a banner
])
def test_usable_running_configurations_are_accepted(text):
    assert connect.check_backup(text) is None


def test_the_mock_labs_real_output_is_accepted():
    sys.path.insert(0, os.path.join(ROOT, 'mock-lab'))
    from mocklab.device import Device
    from mocklab.lab import load_config
    config = load_config()
    hosts = {d['name']: (d['host'], d['type']) for d in config['devices']}
    for spec in config['devices']:
        assert connect.check_backup(Device(spec, lab_hosts=hosts).running_config()) is None


def test_an_error_message_never_shows_a_secret():
    problem = connect.check_backup(f'% Invalid input: enable secret 5 {S1}\n')
    assert problem and hidden(problem)


# ================================================================ phase 2B-D: writing
def files(folder):
    return sorted(p.name for p in folder.iterdir())


def test_a_backup_is_written_with_its_sha256(tmp_path, synthetic_backup_key):
    path, sha, key_id = connect._save_backup('10.0.0.2', VALID, str(tmp_path))
    assert os.path.dirname(path) == str(tmp_path) and key_id == 'b1'
    assert re.fullmatch(r'10\.0\.0\.2_\d{8}_\d{6}\.ncbak', os.path.basename(path))
    plaintext, header = synthetic_backup_key.decrypt(path)
    assert plaintext == VALID.encode('utf-8')
    # The SHA-256 is now that of the CONFIGURATION (kept in the authenticated header).
    assert sha == header['plaintext_sha256'] == hashlib.sha256(VALID.encode()).hexdigest()
    assert files(tmp_path) == [os.path.basename(path)]                     # no temporary left


class FixedClock:
    @staticmethod
    def now():
        return datetime(2026, 11, 22, 14, 30, 5)


def test_same_second_backups_get_unique_names_and_never_overwrite(tmp_path, monkeypatch,
                                                                  synthetic_backup_key):
    monkeypatch.setattr(connect, 'datetime', FixedClock)
    existing = tmp_path / '10.0.0.2_20261122_143005.ncbak'
    existing.write_bytes(b'an older backup that must stay exactly as it is')
    texts = [VALID.replace('SW1', f'SW{i}') for i in range(3)]
    paths = [connect._save_backup('10.0.0.2', t, str(tmp_path))[0] for t in texts]
    assert [os.path.basename(p) for p in paths] == ['10.0.0.2_20261122_143005_2.ncbak',
                                                    '10.0.0.2_20261122_143005_3.ncbak',
                                                    '10.0.0.2_20261122_143005_4.ncbak']
    assert existing.read_bytes() == b'an older backup that must stay exactly as it is'
    assert [synthetic_backup_key.decrypt(p)[0].decode() for p in paths] == texts
    assert len(files(tmp_path)) == 4


def test_a_failed_write_leaves_nothing_behind(tmp_path, monkeypatch):
    def broken_fsync(fd):
        raise OSError(28, 'No space left on device')
    monkeypatch.setattr(connect.os, 'fsync', broken_fsync)
    with pytest.raises(connect.BackupError) as err:
        connect._save_backup('10.0.0.2', VALID, str(tmp_path))
    assert 'could not be written (No space left on device)' in str(err.value)
    assert str(tmp_path) not in str(err.value)                             # never the folder
    assert files(tmp_path) == []                                           # no .partial, no .txt


def test_a_failed_rename_leaves_nothing_behind(tmp_path, monkeypatch):
    def refuse(temp, final):
        raise PermissionError(13, 'Access is denied')
    monkeypatch.setattr(connect, '_place', refuse)
    with pytest.raises(connect.BackupError):
        connect._save_backup('10.0.0.2', VALID, str(tmp_path))
    assert files(tmp_path) == []


def test_the_final_name_appears_only_once_the_file_is_complete(tmp_path, monkeypatch):
    """Until the rename, only a hidden .partial file exists: nothing looks like a backup."""
    seen = []
    real_place = connect._place

    def watch(temp, final):
        seen.append((os.path.basename(temp), files(tmp_path), os.path.getsize(temp)))
        real_place(temp, final)
    monkeypatch.setattr(connect, '_place', watch)
    path, _, _ = connect._save_backup('10.0.0.2', VALID, str(tmp_path))
    temp_name, before, size = seen[0]
    assert temp_name.startswith('.10.0.0.2_') and temp_name.endswith('.partial')
    assert before == [temp_name] and size >= len(VALID)                    # complete, hidden
    assert files(tmp_path) == [os.path.basename(path)]


@pytest.mark.parametrize('text', ['', "% Invalid input detected at '^' marker.\n",
                                  'Building configuration...\n'])
def test_an_unusable_backup_writes_no_file(tmp_path, text):
    with pytest.raises(connect.BackupError):
        connect._save_backup('10.0.0.2', text, str(tmp_path))
    assert files(tmp_path) == []


@pytest.mark.parametrize('host', ['../evil', '..\\evil', 'a/b', 'C:x', '', None, '.hidden'])
def test_a_host_that_is_not_a_plain_address_is_refused(tmp_path, host):
    with pytest.raises(connect.BackupError):
        connect._save_backup(host, VALID, str(tmp_path))
    assert files(tmp_path) == []


# ================================================================ phase 2E: fail-safe Apply
def run(monkeypatch, tmp_path, fake, commands=('vlan 10', 'name SALES'), checks=()):
    log = []
    monkeypatch.setattr(connect, '_open', lambda creds: fake)
    ok, msg = connect.apply_config({'host': '10.0.0.2', 'username': 'admin',
                                    'password': 'Synth-Login-1'}, list(commands), list(checks),
                                   backup_dir=str(tmp_path), log=lambda k, t: log.append((k, t)))
    return ok, msg, log


@pytest.mark.parametrize('running', ['', '  \n', "% Invalid input detected at '^' marker.\n",
                                     'Building configuration...\n\n!\nhostname SW1\n!\n'
                                     'interface Vlan1\n'])
def test_an_unusable_backup_stops_the_apply_before_any_command(monkeypatch, tmp_path, running):
    fake = FakeIOS(running=running)
    ok, msg, log = run(monkeypatch, tmp_path, fake)
    assert ok is False
    assert fake.sent == [] and not fake.in_config and not fake.saved     # nothing was sent
    assert 'No configuration command was sent; the device was not changed.' in msg
    assert msg.startswith('Backup of 10.0.0.2 refused:')
    assert multi.backup_path(msg) is None and multi.classify(ok, msg) == multi.FAILED
    assert not any('Backup saved' in t for _, t in log)                  # no success claimed
    assert any(k == 'error' and t.startswith('BACKUP FAILED') for k, t in log)
    assert files(tmp_path) == [] and fake.closed


def test_a_failed_backup_write_stops_the_apply_before_any_command(monkeypatch, tmp_path):
    def refuse(temp, final):
        raise PermissionError(13, 'Access is denied')
    monkeypatch.setattr(connect, '_place', refuse)
    fake = FakeIOS()
    ok, msg, log = run(monkeypatch, tmp_path, fake)
    assert ok is False and fake.sent == [] and not fake.saved
    assert 'could not be written (Access is denied)' in msg and str(tmp_path) not in msg
    assert files(tmp_path) == []


def test_a_valid_backup_lets_the_apply_continue_with_its_checksum(monkeypatch, tmp_path,
                                                                  synthetic_backup_key):
    fake = FakeIOS(shows={'show vlan brief': '10 SALES active'})
    ok, msg, log = run(monkeypatch, tmp_path, fake, checks=[('show vlan brief', 'SALES')])
    assert ok and fake.sent == ['vlan 10', 'name SALES'] and fake.saved
    path = multi.backup_path(msg)
    sha = re.search(r'Backup SHA-256: ([0-9a-f]{64}) ', msg).group(1)
    plaintext, header = synthetic_backup_key.decrypt(path)
    assert path.endswith('.ncbak') and header['plaintext_sha256'] == sha
    assert hashlib.sha256(plaintext).hexdigest() == sha
    note = f'Backup SHA-256: {sha} (encrypted, key_id=b1; read it with backup_tool.py export).'
    assert msg == f'Applied and verified. {note} Backup: {path}'
    assert multi.reason_of(msg) == f'Applied and verified. {note}'.rstrip('.') + '.'
    # The console line is masked: its wording keeps the key id and checksum readable.
    assert any(k == 'ok' and f'Encrypted backup saved and verified (key_id=b1, configuration '
               f'SHA-256 {sha})' in t for k, t in log)
    assert not any('********' in t for _, t in log)


def test_verification_and_save_behave_as_before(monkeypatch, tmp_path):
    fake = FakeIOS(shows={'show vlan brief': 'nothing'})
    ok, msg, _ = run(monkeypatch, tmp_path, fake, checks=[('show vlan brief', 'SALES')])
    assert not ok and msg.startswith('Check failed') and not fake.saved   # applied, not saved
    assert fake.sent == ['vlan 10', 'name SALES']
    assert multi.classify(ok, msg) == multi.NOT_VERIFIED and os.path.exists(multi.backup_path(msg))
    assert 'Backup SHA-256: ' in msg

    fake = FakeIOS(reject={'name SALES'})
    ok, msg, _ = run(monkeypatch, tmp_path, fake)
    assert not ok and 'partially applied' in msg and not fake.saved
    assert multi.classify(ok, msg) == multi.PARTIAL and os.path.exists(multi.backup_path(msg))
    assert 'Backup SHA-256: ' in msg


# ================================================================ phase 2F: several devices
def test_one_devices_backup_failure_does_not_affect_the_others(monkeypatch, tmp_path):
    devices = [{'id': i, 'name': n, 'ip': ip, 'type': 'switch'}
               for i, (n, ip) in enumerate((('SW1', '10.0.0.11'), ('SW2', '10.0.0.12'),
                                            ('SW3', '10.0.0.13')), 1)]
    fakes = {'10.0.0.11': FakeIOS(), '10.0.0.12': FakeIOS(running='% Authorization failed.\n'),
             '10.0.0.13': FakeIOS()}
    monkeypatch.setattr(connect, '_open', lambda creds: fakes[creds['host']])
    jobs = [{'device': d, 'commands': ['vlan 10'], 'checks': [],
             'creds': {'host': d['ip'], 'username': 'u', 'password': 'Synth-Login-2'}}
            for d in devices]
    posted = []
    results = multi.run_devices(
        jobs, lambda c, cm, ch, log=None: connect.apply_config(c, cm, ch, backup_dir=str(tmp_path),
                                                               log=log),
        post=lambda kind, text, name=None: posted.append((kind, text, name)))
    assert [r['status'] for r in results] == [multi.SUCCESS, multi.FAILED, multi.SUCCESS]
    assert fakes['10.0.0.12'].sent == [] and not fakes['10.0.0.12'].saved
    assert fakes['10.0.0.11'].sent == ['vlan 10'] == fakes['10.0.0.13'].sent
    assert '10.0.0.12' in results[1]['message'] and results[1]['backup'] is None
    assert all(r['backup'] and os.path.exists(r['backup']) for r in (results[0], results[2]))
    assert any(name == 'SW2' and text.startswith('BACKUP FAILED') for _, text, name in posted)
    assert [f.split('_')[0] for f in files(tmp_path)] == ['10.0.0.11', '10.0.0.13']
    summary = multi.summary_text(results)
    assert 'SW2' in summary and 'FAILED' in summary


# ================================================================ follow-up: two more formats
@pytest.mark.parametrize('line, expected', [
    (f'snmp-server host 10.0.0.5 version 2c {S1}', 'snmp-server host 10.0.0.5 version 2c ********'),
    (f'snmp-server host 10.0.0.5 {S1}', 'snmp-server host 10.0.0.5 ********'),
    (f'snmp-server host 10.0.0.5 traps version 1 {S1}',
     'snmp-server host 10.0.0.5 traps version 1 ********'),
    (f'snmp-server host 10.0.0.5 informs version 2c {S1} udp-port 162 config snmp',
     'snmp-server host 10.0.0.5 informs version 2c ******** udp-port 162 config snmp'),
    (f'snmp-server host nms.example.com {S1} vrf MGMT',
     'snmp-server host nms.example.com ******** vrf MGMT'),
    (f'SNMP-SERVER  HOST\t10.0.0.5 INFORMS VERSION 2C {S1}',
     'SNMP-SERVER  HOST\t10.0.0.5 INFORMS VERSION 2C ********'),
    (f'key config-key password-encrypt {S1}', 'key config-key password-encrypt ********'),
    (f'Key  Config-Key\tPassword-Encrypt {S1}', 'Key  Config-Key\tPassword-Encrypt ********'),
    (f'key config-key 1 {S1}', 'key config-key 1 ********'),
])
def test_snmp_host_community_and_config_key_are_masked(mask, line, expected):
    out = mask(line)
    assert hidden(out)
    assert out == expected


@pytest.mark.parametrize('line', [
    'snmp-server host 10.0.0.5 version 3 priv v3user',          # v3: a user name, not a secret
    'snmp-server host 10.0.0.5 version 3 auth v3user udp-port 162',
    'snmp-server host 10.0.0.5 version 3 noauth v3user',
    'snmp-server enable traps snmp linkdown linkup', 'snmp-server trap-source Vlan1',
    'snmp-server location LAB', 'snmp-server contact NOC',
    'key config-key password-encrypt',                          # no value given: nothing to hide
    'service password-encryption',
])
def test_nearby_lines_are_not_over_masked(mask, line):
    assert mask(line) == line


def test_both_new_rules_are_identical_in_desktop_and_backend():
    lines = [f'snmp-server host 10.0.0.5 version 2c {S1}', f'key config-key password-encrypt {S1}',
             'key config-key password-encrypt', 'snmp-server host 10.0.0.5 version 3 priv v3user']
    assert [connect.mask(l) for l in lines] == [app_records.mask_secrets(l) for l in lines]


# ================================================================ follow-up: privilege 15
@pytest.mark.parametrize('output', ['Current privilege level is 15',
                                    '\r\nCurrent privilege level is 15\r\n',
                                    '  Current privilege level is   15  \n\n'])
def test_privilege_15_is_accepted(output):
    assert connect.privilege_problem(output) is None


@pytest.mark.parametrize('output, fragment', [
    ('Current privilege level is 1', 'privilege level 1'),
    ('Current privilege level is 7', 'privilege level 7'),
    ('Current privilege level is 0', 'privilege level 0'),
    ('', 'not recognised'),
    (None, 'not recognised'),
    ("% Invalid input detected at '^' marker.", 'not recognised'),
    ('% Authorization failed.', 'not recognised'),
    ('Current privilege level is fifteen', 'not recognised'),
    ('Current privilege level is 15 (custom view)', 'not recognised'),
    ('Current privilege level is 15\n%SYS-5-CONFIG_I: Configured', 'not recognised'),
    ('Privilege level is 15', 'not recognised'),
])
def test_lower_or_unrecognised_privilege_is_refused(output, fragment):
    problem = connect.privilege_problem(output)
    assert problem and fragment in problem


class Recording(FakeIOS):
    """A FakeIOS that remembers every show command it was asked."""

    def __init__(self, privilege='Current privilege level is 15', fail=None, **kw):
        super().__init__(**kw)
        self.asked, self.privilege, self.fail = [], privilege, fail

    def send_command(self, cmd):
        self.asked.append(cmd)
        if cmd == 'show privilege':
            if self.fail:
                raise self.fail
            return self.privilege
        return super().send_command(cmd)


@pytest.mark.parametrize('fake, fragment', [
    (Recording(privilege='Current privilege level is 1'), 'the session is at privilege level 1'),
    (Recording(privilege='Current privilege level is 7'), 'the session is at privilege level 7'),
    (Recording(privilege="% Invalid input detected at '^' marker."), 'was not recognised'),
    (Recording(privilege=''), 'was not recognised'),
    (Recording(fail=RuntimeError('channel closed')), 'command failed (RuntimeError)'),
])
def test_apply_stops_before_the_backup_without_privilege_15(monkeypatch, tmp_path, fake, fragment):
    ok, msg, log = run(monkeypatch, tmp_path, fake)
    assert ok is False and fragment in msg
    assert 'Privilege level 15 is required' in msg
    assert 'No configuration command was sent; the device was not changed.' in msg
    assert fake.asked == ['show privilege']                    # no backup was even read
    assert fake.sent == [] and not fake.in_config and not fake.saved
    assert files(tmp_path) == []                               # no backup file created
    assert fake.closed                                         # the SSH session was closed
    assert multi.classify(ok, msg) == multi.FAILED and multi.backup_path(msg) is None
    assert any(k == 'error' and t.startswith('PRIVILEGE CHECK FAILED') for k, t in log)
    assert not any('Backup saved' in t or 'Privilege level 15 confirmed' in t for _, t in log)
    assert 'channel closed' not in msg                         # never the exception's own text


def test_a_timeout_during_the_privilege_check_keeps_the_usual_message(monkeypatch, tmp_path):
    from netmiko.exceptions import NetmikoTimeoutException
    fake = Recording(fail=NetmikoTimeoutException('t'))
    ok, msg, _ = run(monkeypatch, tmp_path, fake)
    assert ok is False and 'No answer' in msg
    assert fake.sent == [] and not fake.saved and fake.closed and files(tmp_path) == []


def test_privilege_15_lets_the_apply_continue(monkeypatch, tmp_path):
    fake = Recording()
    ok, msg, log = run(monkeypatch, tmp_path, fake)
    # Phase 4A added the read-only "show version" (device identity) before the backup.
    assert ok and fake.asked[:3] == ['show privilege', 'show version', 'show running-config']
    assert fake.sent == ['vlan 10', 'name SALES'] and fake.saved
    assert any(k == 'ok' and t == 'Privilege level 15 confirmed.' for k, t in log)


def test_one_device_without_privilege_15_does_not_stop_the_others(monkeypatch, tmp_path):
    fakes = {'10.0.0.11': Recording(),
             '10.0.0.12': Recording(privilege='Current privilege level is 1'),
             '10.0.0.13': Recording()}
    monkeypatch.setattr(connect, '_open', lambda creds: fakes[creds['host']])
    jobs = [{'device': {'id': i, 'name': f'SW{i}', 'ip': ip, 'type': 'switch'},
             'commands': ['vlan 10'], 'checks': [],
             'creds': {'host': ip, 'username': 'u', 'password': 'Synth-Login-3'}}
            for i, ip in enumerate(sorted(fakes), 1)]
    results = multi.run_devices(jobs, lambda c, cm, ch: connect.apply_config(
        c, cm, ch, backup_dir=str(tmp_path)))
    assert [r['status'] for r in results] == [multi.SUCCESS, multi.FAILED, multi.SUCCESS]
    assert fakes['10.0.0.12'].sent == [] and fakes['10.0.0.12'].asked == ['show privilege']
    assert '10.0.0.12' in results[1]['message']
    assert [f.split('_')[0] for f in files(tmp_path)] == ['10.0.0.11', '10.0.0.13']
