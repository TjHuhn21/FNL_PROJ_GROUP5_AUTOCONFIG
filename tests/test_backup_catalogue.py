"""Phase 4B: the backup catalogue (backup_catalogue.py) and its window. Temporary folders,
synthetic configurations and keys (fake DPAPI) only; no device is contacted and the real
backup folders and keyring are never used."""
import json
import os
import struct
import sys
import time

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import backup_catalogue as B  # noqa: E402
import backup_crypto as C  # noqa: E402
import backup_keys as K  # noqa: E402
from config import connect  # noqa: E402
from test_backup_keys import FakeProtector, N, PHRASE, OTHER_PHRASE  # noqa: E402
from test_backup_keys import private_locations  # noqa: E402,F401  (autouse)

SECRET = 'SynthCatalogueSecret-42'


def config_for(hostname='SYNTH-R1', end=True):
    return (f'Building configuration...\n!\nhostname {hostname}\n!\nusername admin privilege '
            f'15 secret 9 {SECRET}\n!\n' + ('end\n' if end else '')).encode()


IDENTITY = {'serial': 'FTX0000SYN1', 'platform': 'CISCO1941/K9', 'hostname': 'SYNTH-R1',
            'ios_version': '15.4(3)M2'}
DEVICE = B.Device(ip='10.0.0.2', hostname='SYNTH-R1', device_id=7)


@pytest.fixture
def ring(tmp_path):
    path = str(tmp_path / 'keys' / 'backup-keyring.json')
    K.init(path, str(tmp_path / 'offline' / 'b1.ncrecovery'), PHRASE, FakeProtector(), n=N)
    return path


@pytest.fixture
def source(ring):
    return connect.KeyringKeySource(ring, protector_factory=FakeProtector)


def write_backup(folder, name, ring, plaintext=None, key=None, key_id=None, **meta):
    os.makedirs(folder, exist_ok=True)
    if key is None:
        key_id, key = K.Keyring.load(ring).active(FakeProtector())
    metadata = {'host': '10.0.0.2', 'source': 'show running-config', 'privilege': 15}
    metadata.update(meta)
    data = C.encrypt_backup(plaintext if plaintext is not None else config_for(), key,
                            key_id, metadata)
    path = os.path.join(folder, name)
    with open(path, 'wb') as f:
        f.write(data)
    return path


def locations(*folders):
    return B.approved_locations(candidates=[(str(f), f'Folder {i}') for i, f in
                                            enumerate(folders, 1)])


def verified(path, source, location='Folder 1'):
    entry = B._entry_for(path, location)
    key_for, problem = B.keyring_lookup(source)
    return entry, B.verify(entry, key_for, problem)


def no_secret(*texts):
    joined = ' '.join(str(t) for t in texts)
    return SECRET not in joined and 'username admin' not in joined


# ================================================================ locations
def test_the_folders_searched(tmp_path, monkeypatch):
    cands = B.candidate_folders(backup_dir=str(tmp_path / 'apply'), cwd=str(tmp_path / 'start'))
    labels = [label for _, label in cands]
    assert labels == ['Backup folder (Apply writes here)', 'Project backups',
                      'Mock Lab backups', 'Start-folder backups']
    assert cands[1][0] == os.path.join(B.PROJECT_DIR, 'backups')
    assert cands[3][0] == str(tmp_path / 'start' / 'backups')


def test_the_default_backup_folder_no_longer_depends_on_the_start_folder(tmp_path, monkeypatch):
    project = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    assert os.path.isabs(connect.BACKUP_DIR)
    assert connect.BACKUP_DIR == os.path.join(project, 'backups')   # where it always was
    monkeypatch.chdir(tmp_path)
    assert connect.BACKUP_DIR == os.path.join(project, 'backups')


def test_each_folder_is_listed_once(tmp_path):
    (tmp_path / 'b').mkdir()
    locs = B.approved_locations(candidates=[(str(tmp_path / 'b'), 'one'),
                                            (str(tmp_path / 'b' / '.'), 'two')])
    assert [l.label for l in locs] == ['one']


def test_missing_and_non_folder_locations_are_reported_not_fatal(tmp_path):
    (tmp_path / 'afile').write_text('x')
    locs = locations(tmp_path / 'missing', tmp_path / 'afile')
    assert [(l.status, l.problem) for l in locs] == [(B.MISSING, 'does not exist'),
                                                    (B.INACCESSIBLE, 'is not a folder')]
    entries, notes = B.scan(locs)
    assert entries == [] and len(notes) == 2


def test_an_unreadable_folder_is_reported(tmp_path, monkeypatch):
    (tmp_path / 'locked').mkdir()
    real = os.scandir

    def refuse(path):
        if str(path).endswith('locked'):
            raise PermissionError(13, 'Access is denied')
        return real(path)
    monkeypatch.setattr(B.os, 'scandir', refuse)
    (loc,) = locations(tmp_path / 'locked')
    assert loc.status == B.INACCESSIBLE and 'Access is denied' in loc.problem


def test_links_and_junctions_are_never_followed(tmp_path, ring, monkeypatch):
    linked = tmp_path / 'linked'
    write_backup(linked, 'a.ncbak', ring)
    real = B._is_link
    monkeypatch.setattr(B, '_is_link', lambda p: str(p).startswith(str(linked)) or real(p))
    (loc,) = locations(linked)
    assert loc.status == B.LINK_REFUSED
    normal = tmp_path / 'normal'
    write_backup(normal, 'b.ncbak', ring)
    monkeypatch.setattr(B, '_is_link', lambda p: str(p).endswith('b.ncbak'))
    entries, notes = B.scan(locations(normal))
    assert entries == [] and 'not followed' in notes[0]


# ================================================================ discovery
def test_backups_in_several_folders_are_found_newest_first(tmp_path, ring):
    one, two = tmp_path / 'one', tmp_path / 'two'
    write_backup(one, '10.0.0.2_20261122_100000.ncbak', ring)
    time.sleep(0.01)
    write_backup(two, '10.0.0.3_20261122_110000.ncbak', ring, host='10.0.0.3')
    (one / 'old.txt').write_text('plaintext backups are not listed')
    (one / '.10.0.0.2_x.partial').write_bytes(b'temporary')
    (one / '.hidden.ncbak').write_bytes(b'temporary')
    entries, notes = B.scan(locations(one, two))
    assert [e.filename for e in entries] == ['10.0.0.3_20261122_110000.ncbak',
                                             '10.0.0.2_20261122_100000.ncbak']
    assert [e.location for e in entries] == ['Folder 2', 'Folder 1']
    assert all(e.status == B.NOT_VERIFIED and not e.trusted for e in entries)
    assert notes == []


def test_same_names_in_two_folders_are_both_listed_and_copies_are_marked(tmp_path, ring):
    one, two, three = tmp_path / 'one', tmp_path / 'two', tmp_path / 'three'
    first = write_backup(one, 'same.ncbak', ring)
    write_backup(two, 'same.ncbak', ring, hostname='OTHER')        # same name, other backup
    (three).mkdir()
    (three / 'same.ncbak').write_bytes(open(first, 'rb').read())  # a byte-identical copy
    entries, _ = B.scan(locations(one, two, three))
    assert sorted(e.location for e in entries) == ['Folder 1', 'Folder 2', 'Folder 3']
    copies = [e for e in entries if e.duplicate_of]
    assert len(copies) == 1 and copies[0].location == 'Folder 3' and copies[0].duplicate_of == first


@pytest.mark.parametrize('content', [b'', b'garbage', b'NCBAK\x01\x00\x00\x00\x05{"a":',
                                     b'NCBAK\x09' + b'\x00' * 40])
def test_invalid_files_are_listed_as_invalid_without_stopping_the_scan(tmp_path, ring, content):
    folder = tmp_path / 'b'
    write_backup(folder, 'good.ncbak', ring)
    (folder / 'bad.ncbak').write_bytes(content)
    entries, _ = B.scan(locations(folder))
    status = {e.filename: e.status for e in entries}
    assert status == {'good.ncbak': B.NOT_VERIFIED, 'bad.ncbak': B.INVALID}


def test_a_truncated_backup_is_invalid(tmp_path, ring):
    path = write_backup(tmp_path / 'b', 'cut.ncbak', ring)
    data = open(path, 'rb').read()
    open(path, 'wb').write(data[:-5])
    (entry,) = B.scan(locations(tmp_path / 'b'))[0]
    assert entry.status == B.INVALID and entry.header is None


# ================================================================ verification
def test_verification_decrypts_in_memory_and_trusts_the_header(tmp_path, ring, source,
                                                               monkeypatch):
    monkeypatch.setattr(connect, '_open', lambda creds: pytest.fail('a device was contacted'))
    path = write_backup(tmp_path / 'b', 'a.ncbak', ring, **IDENTITY)
    before = open(path, 'rb').read()
    entry, result = verified(path, source)
    assert result.status == B.VERIFIED and entry.trusted
    assert entry.verified_header['serial'] == 'FTX0000SYN1'
    assert result.file_sha256 == entry.file_sha256
    assert open(path, 'rb').read() == before                   # never rewritten
    assert sorted(os.listdir(tmp_path / 'b')) == ['a.ncbak']   # nothing decrypted written


def test_header_metadata_is_not_trusted_before_verification(tmp_path, ring):
    path = write_backup(tmp_path / 'b', 'a.ncbak', ring, **IDENTITY)
    (entry,) = B.scan(locations(tmp_path / 'b'))[0]
    assert entry.header['serial'] == 'FTX0000SYN1' and not entry.trusted
    with pytest.raises(B.SelectionRefused) as err:
        B.select(entry, None, DEVICE, can_select=True)
    assert 'Only a verified backup' in str(err.value)


def test_a_tampered_header_fails_verification(tmp_path, ring, source):
    path = write_backup(tmp_path / 'b', 'a.ncbak', ring, **IDENTITY)
    data = open(path, 'rb').read()
    (length,) = struct.unpack('>I', data[6:10])
    header = json.loads(data[10:10 + length])
    header['serial'] = 'FTX0000SYN9'                         # claims another device
    raw = json.dumps(header, sort_keys=True, separators=(',', ':')).encode()
    open(path, 'wb').write(data[:6] + struct.pack('>I', len(raw)) + raw + data[10 + length:])
    entry, result = verified(path, source)
    assert entry.header['serial'] == 'FTX0000SYN9'           # readable, but...
    assert result.status == B.FAILED and not entry.trusted   # ...not authentic
    assert 'could not be authenticated' in result.problem


def test_corrupted_ciphertext_fails_verification(tmp_path, ring, source):
    path = write_backup(tmp_path / 'b', 'a.ncbak', ring)
    data = bytearray(open(path, 'rb').read())
    data[-20] ^= 1
    open(path, 'wb').write(bytes(data))
    entry, result = verified(path, source)
    assert result.status == B.FAILED and no_secret(result.problem)


def test_a_plaintext_hash_mismatch_fails_verification(tmp_path, ring, source, monkeypatch):
    key_id, key = K.Keyring.load(ring).active(FakeProtector())   # before faking sha256
    real = C.hashlib.sha256
    monkeypatch.setattr(C.hashlib, 'sha256', lambda data=b'': real(data + b'!'))
    path = write_backup(tmp_path / 'b', 'a.ncbak', ring, key=key, key_id=key_id)
    monkeypatch.setattr(C.hashlib, 'sha256', real)
    entry, result = verified(path, source)
    assert result.status == B.FAILED and 'SHA-256' in result.problem


def test_a_configuration_that_fails_the_ios_check_is_not_verified(tmp_path, ring, source):
    path = write_backup(tmp_path / 'b', 'a.ncbak', ring, plaintext=config_for(end=False))
    entry, result = verified(path, source)
    assert result.status == B.FAILED and 'not usable' in result.problem
    assert no_secret(result.problem) and 'hostname' not in result.problem


def test_an_error_configuration_never_quotes_its_first_line(tmp_path, ring, source):
    path = write_backup(tmp_path / 'b', 'a.ncbak', ring,
                        plaintext=f'% Invalid input {SECRET}\n'.encode())
    entry, result = verified(path, source)
    assert result.status == B.FAILED and SECRET not in result.problem


def test_a_missing_keyring_means_verification_unavailable(tmp_path, ring):
    path = write_backup(tmp_path / 'b', 'a.ncbak', ring)
    missing = connect.KeyringKeySource(str(tmp_path / 'none.json'), FakeProtector)
    entry, result = verified(path, missing)
    assert result.status == B.UNAVAILABLE and 'No backup keyring was found' in result.problem
    assert not entry.trusted


def test_a_key_this_account_cannot_open_means_unavailable(tmp_path, ring):
    path = write_backup(tmp_path / 'b', 'a.ncbak', ring)
    other = connect.KeyringKeySource(ring, lambda: FakeProtector(account='B'))
    entry, result = verified(path, other)
    assert result.status == B.UNAVAILABLE


def test_an_unknown_key_id_means_unavailable(tmp_path, ring, source):
    path = write_backup(tmp_path / 'b', 'a.ncbak', ring, key=os.urandom(32), key_id='b9')
    entry, result = verified(path, source)
    assert result.status == B.UNAVAILABLE and 'b9 is not in this keyring' in result.problem


def test_backups_made_with_an_older_key_still_verify_after_rotation(tmp_path, ring, source):
    old = write_backup(tmp_path / 'b', 'old.ncbak', ring)
    K.rotate(ring, str(tmp_path / 'offline' / 'b2.ncrecovery'), OTHER_PHRASE, FakeProtector(),
             n=N)
    new = write_backup(tmp_path / 'b', 'new.ncbak', ring)
    assert verified(old, source)[1].status == B.VERIFIED
    entry, result = verified(new, source)
    assert result.status == B.VERIFIED and entry.verified_header['key_id'] == 'b2'


def test_a_file_changed_after_listing_is_refused(tmp_path, ring, source):
    path = write_backup(tmp_path / 'b', 'a.ncbak', ring)
    entry = B._entry_for(path, 'Folder 1')
    write_backup(tmp_path / 'b', 'a.ncbak', ring)              # replaced meanwhile
    key_for, problem = B.keyring_lookup(source)
    assert B.verify(entry, key_for, problem).status == B.FAILED


def test_a_deleted_file_is_unreadable_not_a_crash(tmp_path, ring, source):
    path = write_backup(tmp_path / 'b', 'a.ncbak', ring)
    entry = B._entry_for(path, 'Folder 1')
    os.remove(path)
    key_for, problem = B.keyring_lookup(source)
    assert B.verify(entry, key_for, problem).status == B.UNREADABLE


# ================================================================ matching
def header(**fields):
    h = {'host': '10.0.0.2'}
    h.update(fields)
    return h


def test_serial_match():
    m = B.match(header(**IDENTITY), B.Device('10.0.0.2', 'SYNTH-R1', 'CISCO1941/K9',
                                             'FTX0000SYN1'))
    assert m.hardware_match and not m.blocked and not m.requires_legacy_confirmation
    assert m.summary == 'Serial match'
    assert ('platform', 'match', 'Platform match (CISCO1941/K9)') in m.checks


def test_serial_mismatch_blocks():
    m = B.match(header(**IDENTITY), B.Device('10.0.0.2', 'SYNTH-R1', serial='FTX0000SYN9'))
    assert m.blocked and m.summary.startswith('Identity mismatch')
    assert not m.hardware_match


def test_platform_mismatch_blocks_even_with_the_same_vendor():
    m = B.match(header(**IDENTITY), B.Device('10.0.0.2', platform='CISCO1921/K9'))
    assert m.blocked and m.summary.startswith('Platform mismatch')


@pytest.mark.parametrize('serial', [None, 'unavailable', 'UNKNOWN', 'N/A', 'two words', '', 5])
def test_unknown_serials_never_match(serial):
    h = header(**dict(IDENTITY, serial=serial)) if serial != 'absent' else header()
    m = B.match(h, B.Device('10.0.0.2', serial='FTX0000SYN1'))
    assert not m.hardware_match and m.requires_legacy_confirmation
    assert ('serial', 'unknown') == m.checks[0][:2]
    m = B.match(header(**IDENTITY), B.Device('10.0.0.2', serial=serial if serial != 5 else None))
    assert not m.hardware_match


def test_a_null_serial_on_both_sides_is_not_a_match():
    m = B.match(header(serial=None), B.Device('10.0.0.2', serial=None))
    assert not m.hardware_match and m.summary == 'Hardware identity not confirmed'


def test_a_changed_ip_with_a_serial_match_is_allowed_with_a_warning():
    m = B.match(header(**IDENTITY), B.Device('10.0.0.9', 'SYNTH-R1', serial='FTX0000SYN1'))
    assert not m.blocked and m.hardware_match
    assert any('IP address differs: backup made for 10.0.0.2, device is 10.0.0.9' in w
               for w in m.warnings)


def test_a_changed_ip_with_recorded_serial_and_platform_is_a_pending_candidate():
    """The device side has no serial (device records do not store one): the backup becomes
    a candidate whose identity the restore preflight must verify live. Never a match."""
    m = B.match(header(**IDENTITY), B.Device('10.0.0.9', 'SYNTH-R1'))
    assert not m.blocked and m.live_identity_required
    assert not m.hardware_match and not m.requires_legacy_confirmation
    assert m.summary == 'Candidate: live identity check required (IP differs)'
    assert 'match' not in m.summary.lower()                    # never called a match
    assert any('Pending restore candidate' in w for w in m.warnings)
    assert ('ip', 'mismatch') in [c[:2] for c in m.checks]
    same_ip = B.match(header(**IDENTITY), B.Device('10.0.0.2', 'SYNTH-R1'))
    assert not same_ip.live_identity_required                  # same-IP: unchanged


@pytest.mark.parametrize('identity, device, reason', [
    ({}, B.Device('10.0.0.9'), 'IP address differs'),                      # no identity
    (dict(IDENTITY, serial=None), B.Device('10.0.0.9'), 'IP address differs'),
    (dict(IDENTITY, serial='unknown'), B.Device('10.0.0.9'), 'IP address differs'),
    (dict(IDENTITY, platform=None), B.Device('10.0.0.9'), 'IP address differs'),
    ({k: v for k, v in IDENTITY.items() if k != 'platform'}, B.Device('10.0.0.9'),
     'IP address differs'),
    (IDENTITY, B.Device('10.0.0.9', serial='FTX0000SYN9'), 'Identity mismatch'),
    (IDENTITY, B.Device('10.0.0.9', platform='CISCO1921/K9'), 'Platform mismatch'),
])
def test_a_changed_ip_without_a_possible_live_check_still_blocks(identity, device, reason):
    m = B.match(header(**identity), device)
    assert m.blocked and reason in m.block_reason
    assert not m.live_identity_required and not m.hardware_match


def test_a_changed_hostname_is_a_warning_and_a_hostname_never_proves_identity():
    m = B.match(header(**IDENTITY), B.Device('10.0.0.2', 'OTHER-NAME'))
    assert not m.blocked and not m.hardware_match
    assert 'Hostname differs: backup SYNTH-R1, device OTHER-NAME' in m.warnings
    same = B.match(header(**IDENTITY), B.Device('10.0.0.2', 'synth-r1'))
    assert not same.hardware_match and same.requires_legacy_confirmation


def test_old_backups_are_marked_identity_not_recorded():
    m = B.match(header(), DEVICE)
    assert not m.identity_recorded and m.summary == 'Identity not recorded'
    assert m.requires_legacy_confirmation and not m.hardware_match and not m.blocked


def test_device_identity_values_that_are_not_plain_tokens_count_as_unknown():
    m = B.match(header(**IDENTITY), B.Device('10.0.0.2', serial='FTX 0000', platform='x;y'))
    assert not m.blocked and not m.hardware_match


# ================================================================ selection
def test_a_verified_backup_without_identity_is_selectable_for_inspection(tmp_path, ring,
                                                                       source, monkeypatch):
    monkeypatch.setattr(connect, '_open', lambda creds: pytest.fail('a device was contacted'))
    path = write_backup(tmp_path / 'b', 'a.ncbak', ring)          # no identity: older style
    entry, result = verified(path, source)
    sel = B.select(entry, result, DEVICE, can_select=True)
    assert sel.requires_legacy_confirmation and not sel.hardware_match
    assert sel.path == path and sel.file_sha256 == entry.file_sha256 and sel.key_id == 'b1'
    assert sel.device_ip == '10.0.0.2' and sel.device_id == 7
    assert no_secret(sel)


def test_a_serial_matched_backup_is_selected_without_legacy_confirmation(tmp_path, ring,
                                                                       source):
    path = write_backup(tmp_path / 'b', 'a.ncbak', ring, **IDENTITY)
    entry, result = verified(path, source)
    device = B.Device('10.0.0.2', 'SYNTH-R1', 'CISCO1941/K9', 'FTX0000SYN1')
    sel = B.select(entry, result, device, can_select=True)
    assert sel.hardware_match and not sel.requires_legacy_confirmation


def test_a_changed_ip_candidate_is_selected_as_pending_and_contacts_nothing(
        tmp_path, ring, source, monkeypatch):
    monkeypatch.setattr(connect, '_open', lambda creds: pytest.fail('a device was contacted'))
    monkeypatch.setattr(connect, 'ConnectHandler',
                        lambda **kw: pytest.fail('a device was contacted'))
    monkeypatch.setattr(connect, '_save_backup', lambda *a, **k: pytest.fail('backup made'))
    folder = tmp_path / 'b'
    path = write_backup(folder, 'a.ncbak', ring, **IDENTITY)        # recorded for 10.0.0.2
    entry, result = verified(path, source)
    sel = B.select(entry, result, B.Device('10.0.0.9', 'SYNTH-R1', device_id=8), True)
    assert sel.live_identity_required and not sel.hardware_match
    assert not sel.requires_legacy_confirmation and sel.device_ip == '10.0.0.9'
    assert any('Pending restore candidate' in w for w in sel.warnings)
    assert sorted(os.listdir(folder)) == ['a.ncbak']                # nothing written


def test_same_ip_selections_are_unchanged(tmp_path, ring, source):
    path = write_backup(tmp_path / 'b', 'a.ncbak', ring, **IDENTITY)
    entry, result = verified(path, source)
    sel = B.select(entry, result, DEVICE, can_select=True)
    assert not sel.live_identity_required and not sel.hardware_match
    assert sel.requires_legacy_confirmation
    legacy = write_backup(tmp_path / 'b', 'old.ncbak', ring)
    entry, result = verified(legacy, source)
    sel = B.select(entry, result, DEVICE, can_select=True)
    assert not sel.live_identity_required and sel.requires_legacy_confirmation
    with pytest.raises(B.SelectionRefused, match='IP address differs'):
        B.select(entry, result, B.Device('10.0.0.9', device_id=8), True)   # legacy elsewhere


@pytest.mark.parametrize('case', ['viewer', 'unverified', 'unavailable', 'failed',
                                  'serial-mismatch', 'platform-mismatch', 'other-file'])
def test_selection_is_refused(tmp_path, ring, source, case):
    path = write_backup(tmp_path / 'b', 'a.ncbak', ring, **IDENTITY)
    entry, result = verified(path, source)
    device = DEVICE
    can_select = case != 'viewer'
    if case == 'unverified':
        result = None
    elif case == 'unavailable':
        result = B.Verification(B.UNAVAILABLE, 'no key')
    elif case == 'failed':
        result = B.Verification(B.FAILED, 'tampered')
    elif case == 'serial-mismatch':
        device = B.Device('10.0.0.2', serial='FTX0000SYN9')
    elif case == 'platform-mismatch':
        device = B.Device('10.0.0.2', platform='WS-C2960-24TT-L')
    elif case == 'other-file':
        result = B.Verification(B.VERIFIED, '', result.header, 'f' * 64)
    with pytest.raises(B.SelectionRefused):
        B.select(entry, result, device, can_select)


def test_selection_uses_the_authenticated_header_not_the_readable_one(tmp_path, ring, source):
    """Changing the readable header after verification cannot change the decision."""
    path = write_backup(tmp_path / 'b', 'a.ncbak', ring, **IDENTITY)
    entry, result = verified(path, source)
    entry.header = dict(entry.header, serial='FTX0000SYN9')      # in memory only
    device = B.Device('10.0.0.2', serial='FTX0000SYN1')
    assert B.select(entry, result, device, can_select=True).hardware_match


def test_nothing_is_written_and_no_secret_appears_anywhere(tmp_path, ring, source):
    folder = tmp_path / 'b'
    paths = [write_backup(folder, f'{i}.ncbak', ring) for i in range(3)]
    (folder / 'bad.ncbak').write_bytes(b'garbage')
    before = {p: open(p, 'rb').read() for p in paths}
    entries, notes = B.scan(locations(folder))
    key_for, problem = B.keyring_lookup(source)
    results = [B.verify(e, key_for, problem) for e in entries]
    assert {p: open(p, 'rb').read() for p in paths} == before
    assert sorted(os.listdir(folder)) == ['0.ncbak', '1.ncbak', '2.ncbak', 'bad.ncbak']
    assert no_secret(notes, [r.problem for r in results], [e.problem for e in entries])


# ================================================================ the window
@pytest.fixture
def window_root(monkeypatch):
    pytest.importorskip('tkinter')
    from gui_helpers import new_root
    from tkinter import messagebox
    shown = []
    for name in ('showinfo', 'showerror', 'showwarning'):
        monkeypatch.setattr(messagebox, name,
                            lambda t, m, _n=name, **k: shown.append((_n, t, m)))
    monkeypatch.setattr(connect, '_open', lambda creds: pytest.fail('a device was contacted'))
    root = new_root()
    yield root, shown
    root.destroy()


def open_window(root, folder, source, can_select=True, selected=None):
    from gui.backup_catalogue_window import BackupCatalogueWindow
    win = BackupCatalogueWindow(root, DEVICE, can_select,
                                on_select=(selected.append if selected is not None else None),
                                backup_dir=str(folder), key_source=source)
    win.locations = locations(folder)
    win.entries = {e.path: e for e in B.scan(win.locations)[0]}
    win.fill()
    root.update()
    return win


def test_window_lists_marks_unverified_and_verifies_without_freezing(window_root, tmp_path,
                                                                     ring, source,
                                                                     monkeypatch):
    from gui_helpers import pump
    root, shown = window_root
    folder = tmp_path / 'b'
    path = write_backup(folder, 'a.ncbak', ring, **IDENTITY)
    write_backup(folder, 'other.ncbak', ring, host='10.0.0.99', hostname='ELSEWHERE')
    selected = []
    win = open_window(root, folder, source, selected=selected)
    assert win.tree.get_children() == (path,)                 # this device's backups only
    win.show_all.set(True)
    win.fill()
    assert len(win.tree.get_children()) == 2
    win.tree.selection_set(path)
    root.update()
    values = win.tree.item(path, 'values')
    assert values[-2] == B.NOT_VERIFIED and values[-1].endswith('(unverified)')
    assert win.select_btn.instate(['disabled'])               # not verified yet
    assert 'NOT yet verified' in win.details.get('1.0', 'end')

    real_verify, ticks = B.verify, []

    def slow_verify(*a, **k):
        time.sleep(0.3)
        return real_verify(*a, **k)
    monkeypatch.setattr(B, 'verify', slow_verify)
    win.verify_selected()
    root.after(20, lambda: ticks.append('tick'))
    assert pump(root, lambda: not win.busy)
    assert ticks == ['tick']                                  # the window kept running
    assert win.tree.item(path, 'values')[-2] == B.VERIFIED
    assert 'authenticated (verified)' in win.details.get('1.0', 'end')
    assert win.select_btn.instate(['!disabled'])
    win.select()
    assert len(selected) == 1 and selected[0].path == path
    assert shown[-1][1] == 'Backup selected' and 'Nothing was sent' in shown[-1][2]
    text = win.details.get('1.0', 'end')
    assert no_secret(text, shown)


def test_window_marks_a_changed_ip_candidate_as_pending_not_a_match(window_root, tmp_path,
                                                                    ring, source):
    from gui_helpers import pump
    root, shown = window_root
    path = write_backup(tmp_path / 'b', 'a.ncbak', ring, **dict(IDENTITY, host='10.0.0.99'))
    selected = []
    win = open_window(root, tmp_path / 'b', source, selected=selected)
    assert win.tree.get_children() == (path,)                 # shown: same hostname
    win.tree.selection_set(path)
    win.verify_selected()
    assert pump(root, lambda: not win.busy)
    text = win.details.get('1.0', 'end')
    assert 'PENDING RESTORE CANDIDATE, NOT a verified match' in text
    assert 'legacy-backup confirmation' not in text
    assert win.tree.item(path, 'values')[-1].startswith('Candidate: live identity check')
    win.select()
    assert selected[0].live_identity_required and not selected[0].hardware_match
    assert shown[-1][1] == 'Backup selected' and 'PENDING CANDIDATE' in shown[-1][2]
    assert 'Nothing was sent' in shown[-1][2]


def test_window_never_enables_selection_for_a_viewer(window_root, tmp_path, ring, source):
    from gui_helpers import pump
    root, shown = window_root
    path = write_backup(tmp_path / 'b', 'a.ncbak', ring)
    win = open_window(root, tmp_path / 'b', source, can_select=False)
    win.tree.selection_set(path)
    win.verify_selected()
    assert pump(root, lambda: not win.busy)
    assert win.select_btn.instate(['disabled'])
    win.select()
    assert shown[-1][1] == 'Cannot select this backup'


def test_window_reports_an_unavailable_keyring(window_root, tmp_path, ring):
    from gui_helpers import pump
    root, shown = window_root
    path = write_backup(tmp_path / 'b', 'a.ncbak', ring)
    missing = connect.KeyringKeySource(str(tmp_path / 'none.json'), FakeProtector)
    win = open_window(root, tmp_path / 'b', missing)
    win.tree.selection_set(path)
    win.verify_selected()
    assert pump(root, lambda: not win.busy)
    assert win.tree.item(path, 'values')[-2] == B.UNAVAILABLE
    assert win.select_btn.instate(['disabled'])


def test_devices_page_offers_backups_only_with_the_configure_permission(monkeypatch):
    pytest.importorskip('tkinter')
    import db_fake
    from desktop_auth.session import Access
    from gui.main_window import build_main_window
    from gui_helpers import new_root
    for role, enabled in (('viewer', False), ('operator', True), ('admin', True)):
        db_fake.reset()
        root = new_root()
        try:
            refs = build_main_window(root, db_fake, demo_store=True, access=Access(role))
            assert refs['devices'].backups_btn.instate(['!disabled' if enabled else 'disabled'])
            assert refs['devices'].backups_allowed is enabled
            if not enabled:
                refs['devices'].open_backups()                  # a no-op for viewers
                assert not hasattr(refs['devices'], 'backups_window')
        finally:
            root.destroy()


def test_selecting_from_the_devices_page_is_recorded_in_the_main_window(monkeypatch, tmp_path,
                                                                       ring, source):
    pytest.importorskip('tkinter')
    import db_fake
    from desktop_auth.session import Access
    from gui.main_window import build_main_window
    from gui_helpers import new_root
    db_fake.reset()
    root = new_root()
    try:
        refs = build_main_window(root, db_fake, demo_store=True, access=Access('operator'))
        path = write_backup(tmp_path / 'b', 'a.ncbak', ring)
        entry, result = verified(path, source)
        sel = B.select(entry, result, DEVICE, can_select=True)
        refs['devices'].on_backup_selected(sel)
        assert refs['backup_selection'] is sel
    finally:
        root.destroy()
