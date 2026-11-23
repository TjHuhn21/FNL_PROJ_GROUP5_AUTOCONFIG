"""Phase 4F: the restore engine (restore_engine.py) against the Mock Lab.

Every test goes through the real workflow: catalogue selection -> Phase 4E read-only
preflight -> typed confirmation -> encrypted pre-restore safety backup -> restore. The
Mock Lab runs on free ports of 127.0.0.1 and is reached through the REAL Netmiko
(InLineTransfer for Tcl) and the scp package. Rollback timers run on the lab's SIMULATED
clock: the engine's wait() advances it, so nothing waits for real minutes.

Synthetic configurations, synthetic logins and throwaway in-memory keys only. No physical
device, real credential or production key is used, and no plaintext file is written.
"""
import dataclasses
import os
import sys
import types

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

netmiko = pytest.importorskip('netmiko')

import backup_crypto as C  # noqa: E402
import restore_engine as E  # noqa: E402
import restore_preflight as R  # noqa: E402
from config import connect  # noqa: E402
from test_restore_preflight import (CONFIG, MARK, MGMT, OTHER_SERIAL, SERIAL,  # noqa: E402
                                    SPEC, Device, creds, key_path, lab_with, r1_spec, setup,
                                    state, target_text)

NTP = 'ntp server 192.0.2.77'                 # what the backup adds (documentation range)
__all__ = ['key_path', 'lab_with', 'setup']   # fixtures used from the Phase 4E tests


@pytest.fixture(autouse=True)
def fast_inline_transfer(monkeypatch):
    """Netmiko's InLineTransfer sleeps 4-25 s while pasting; the lab answers at once."""
    import time as real_time
    from netmiko.cisco import cisco_ios
    monkeypatch.setattr(cisco_ios, 'time', types.SimpleNamespace(
        sleep=lambda s: real_time.sleep(min(s, 0.05)), time=real_time.time,
        monotonic=real_time.monotonic))


@pytest.fixture
def prepared(setup, tmp_path):
    """prepared(spec=..., text=..., login=...) -> Case: lab, device, sealed preflight
    result (safety backup made), login details."""
    def make(spec=None, text=None, login=None, management_ip=MGMT, **kw):
        lab, dev, selection, spec = setup(spec=spec, text=text, **kw)
        login = login or creds(spec)
        pre = R.run_checks(selection, login, management_ip=management_ip)
        assert pre.can_proceed, pre.lines()
        R.create_safety_backup(pre, pre.required_confirmation, login,
                               backup_dir=str(tmp_path / 'safety'))
        assert pre.stage == R.SAFETY_BACKUP_CREATED, pre.lines()
        return types.SimpleNamespace(lab=lab, dev=dev, pre=pre, spec=spec, login=login,
                                     original=dev.running_config(), before=state(dev))
    return make


def restore(case, **kw):
    log = []
    kw.setdefault('wait', case.lab.advance)
    result = E.restore(case.pre, case.login, log=lambda k, t: log.append((k, t)), **kw)
    case.log = log
    return result


def files_on_disk(tmp_path):
    return sorted(os.path.relpath(os.path.join(d, f), tmp_path)
                  for d, _, fs in os.walk(tmp_path) for f in fs)


def assert_no_plaintext(tmp_path, case, result):
    """Only encrypted files exist, and nothing reported contains configuration text."""
    for name in files_on_disk(tmp_path):
        assert name.endswith('.ncbak'), name
        with open(tmp_path / name, 'rb') as f:
            data = f.read()
        assert data.startswith(C.MAGIC) and MARK.encode() not in data and \
            b'ntp server' not in data
    text = ' '.join([t for _, t in case.log] + result.lines() +
                    [t for _, t in result.steps])
    for secret in (MARK, NTP, '$1$mock$hidden', SPEC['MOCK-R1']['password'],
                   CONFIG['shared_scan_account']['password'], 'username labadmin'):
        assert secret not in text, secret


def temp_files(dev):
    return [n for n in dev.flash.files if n.startswith('nc-restore-')]


def events(dev):
    return [e[1] for e in dev.events]


# ================================================================ success
def test_successful_restore_by_tcl(prepared, tmp_path):
    case = prepared()
    result = restore(case)
    assert result.status == E.SUCCESS, result.lines()
    dev = case.dev
    assert NTP in dev.running_config()                          # the backup is live
    assert result.device_state == E.RESTORED and result.confirmed
    assert result.timer_state == 'cancelled (verified)' and dev.rollback is None
    assert result.transfer_method == 'tcl' and result.md5_verified
    assert result.comparison.startswith('match') and result.cleanup == 'deleted and verified'
    assert temp_files(dev) == []                               # temporary file gone
    assert dev.archive_copies and all(dev.flash.exists(n) for n in dev.archive_copies)
    assert dev.saves == 0 and dev.startup == case.before[1]    # startup never touched
    assert events(dev).count('replace') == 1 and 'confirm' in events(dev)
    assert not result.rollback_attempted and not result.manual_actions
    assert result.backup_file == case.pre.selection.path
    assert result.safety_backup_file == case.pre.safety_backup_path
    assert result.identity['serial'] == SERIAL
    assert case.pre.stage == R.RESTORE_STARTED
    assert_no_plaintext(tmp_path, case, result)


def test_engine_never_uses_netmiko_disconnect(prepared, monkeypatch):
    """A newline from disconnect() would answer a pending "[confirm]" with yes."""
    from netmiko.base_connection import BaseConnection
    case = prepared()
    monkeypatch.setattr(BaseConnection, 'disconnect',
                        lambda self: pytest.fail('the engine called disconnect()'))
    assert restore(case).status == E.SUCCESS


def test_plaintext_goes_to_tcl_from_memory_only(prepared, monkeypatch, tmp_path):
    from netmiko.cisco import cisco_ios
    seen = []
    real = cisco_ios.InLineTransfer.__init__

    def spy(self, *a, **kw):
        seen.append(kw)
        return real(self, *a, **kw)
    monkeypatch.setattr(cisco_ios.InLineTransfer, '__init__', spy)
    case = prepared()
    result = restore(case)
    assert result.status == E.SUCCESS
    assert len(seen) == 1 and seen[0]['source_config'] and not seen[0].get('source_file')
    assert seen[0]['dest_file'] == case.pre.temp_name and seen[0]['file_system'] == 'flash:'
    assert_no_plaintext(tmp_path, case, result)


SCAN = {'username': CONFIG['shared_scan_account']['username'],
        'password': CONFIG['shared_scan_account']['password']}


def test_successful_restore_by_scp_from_an_in_memory_stream(prepared, monkeypatch, tmp_path):
    import io
    import scp
    streams = []
    real = scp.SCPClient.putfo

    def spy(self, fl, remote_path, *a, **kw):
        streams.append((type(fl), remote_path))
        return real(self, fl, remote_path, *a, **kw)
    monkeypatch.setattr(scp.SCPClient, 'putfo', spy)
    spec = r1_spec('scp', quirks=['no_tcl'])
    case = prepared(spec=spec, login=creds(spec, **SCAN))
    result = restore(case)
    assert result.status == E.SUCCESS, result.lines()
    assert result.transfer_method == 'scp' and result.md5_verified
    assert streams == [(io.BytesIO, f'flash:/{case.pre.temp_name}')]
    assert 'ip scp server enable' in case.dev.running_config()     # it was already there
    assert_no_plaintext(tmp_path, case, result)


def test_tcl_unsafe_configuration_uses_scp_when_enabled(prepared):
    spec = r1_spec('scp')
    text = target_text(Device(spec, lab_hosts={}), 'interface GigabitEthernet0/2',
                       'description {braces}')
    case = prepared(spec=spec, text=text, login=creds(spec, **SCAN))
    assert case.pre.transfer_method == 'tcl'
    result = restore(case)
    assert result.status == E.SUCCESS and result.transfer_method == 'scp', result.lines()
    assert 'description {braces}' in case.dev.running_config()


def test_tcl_unsafe_configuration_without_scp_sends_nothing(prepared):
    spec = r1_spec()
    text = target_text(Device(spec, lab_hosts={}), 'interface GigabitEthernet0/2',
                       'description {braces}')
    case = prepared(spec=spec, text=text)
    logins = len(case.lab.logins)
    result = restore(case)
    assert result.status == E.FAILED and result.device_state == E.NOTHING_SENT
    assert len(case.lab.logins) == logins and state(case.dev) == case.before


def test_restore_that_changes_the_hostname(prepared):
    spec = r1_spec()
    text = target_text(Device(spec, lab_hosts={}), 'hostname R1-RESTORED')
    case = prepared(spec=spec, text=text)
    result = restore(case)
    assert result.status == E.SUCCESS, result.lines()
    assert case.dev.hostname == 'R1-RESTORED'


@pytest.mark.parametrize('minutes', [3, 10])
def test_timer_range_limits_are_accepted(prepared, minutes):
    case = prepared()
    result = restore(case, timer_minutes=minutes)
    assert result.status == E.SUCCESS
    assert any(k == 'command' and t.endswith(f'list force time {minutes}')
               for k, t in case.log)


# ================================================================ refusals (nothing sent)
def refused(case, words, **kw):
    logins = len(case.lab.logins)
    result = restore(case, **kw)
    assert result.status == E.FAILED, result.lines()
    assert result.device_state == E.NOTHING_SENT
    assert any(words in t for _, t in result.steps), result.steps
    assert not result.transferred and not result.replace_attempted
    assert temp_files(case.dev) == [] and 'replace' not in events(case.dev)
    return result, len(case.lab.logins) - logins


@pytest.mark.parametrize('minutes', [2, 11, 0, '5', 5.0, True, None])
def test_timer_outside_3_to_10_minutes_is_refused(prepared, minutes):
    case = prepared()
    _, logins = refused(case, 'must be 3 to 10 minutes', timer_minutes=minutes)
    assert logins == 0
    assert case.pre.stage == R.SAFETY_BACKUP_CREATED          # not used up by a refusal


@pytest.mark.parametrize('change', [
    lambda p: setattr(p, 'temp_name', 'nc-restore-0000000000000000.cfg'),
    lambda p: setattr(p, 'transfer_method', 'scp'),
    lambda p: p.identity.update(serial=OTHER_SERIAL),
    lambda p: setattr(p, 'device_ip', '127.0.0.12'),
    lambda p: setattr(p, 'safety_backup_path', p.selection.path),
    lambda p: setattr(p, 'selection', dataclasses.replace(p.selection, key_id='b9')),
    lambda p: setattr(p, 'required_confirmation', 'RESTORE 127.0.0.12'),
    lambda p: setattr(p, 'seal', None),
])
def test_a_modified_preflight_result_is_refused(prepared, change):
    case = prepared()
    change(case.pre)
    _, logins = refused(case, 'changed after the safety backup')
    assert logins == 0


def test_preflight_without_safety_backup_cancelled_or_reused_is_refused(setup, prepared):
    lab, dev, selection, spec = setup()
    pre = R.run_checks(selection, creds(spec), management_ip=MGMT)
    for result in (E.restore(pre, creds(spec)), E.restore(None, creds(spec))):
        assert result.status == E.FAILED and result.device_state == E.NOTHING_SENT
    case = prepared()
    R.cancel(case.pre)
    refused(case, 'not ready for a restore')
    case = prepared()
    assert restore(case).status == E.SUCCESS
    logins, before = len(case.lab.logins), state(case.dev)
    again = restore(case)                                     # used once only
    assert again.status == E.FAILED and again.device_state == E.NOTHING_SENT
    assert any('not ready for a restore' in t for _, t in again.steps)
    assert len(case.lab.logins) == logins and state(case.dev) == before


def test_stale_safety_backup_and_other_device_are_refused(prepared):
    case = prepared()
    t = case.pre.safety_backup_at + E.START_WINDOW_SECONDS + 1
    refused(case, 'too old', clock=lambda: t)
    other = dict(case.login, host='127.0.0.12')
    logins = len(case.lab.logins)
    result = E.restore(case.pre, other)
    assert result.status == E.FAILED and 'another device' in result.steps[0][1]
    assert len(case.lab.logins) == logins


def test_selected_backup_changed_after_the_safety_backup(prepared):
    case = prepared()
    with open(case.pre.selection.path, 'ab') as f:
        f.write(b'!')
    refused(case, 'changed after it was selected')


@pytest.mark.parametrize('damage', ['delete', 'tamper', 'key'])
def test_unusable_safety_backup_is_refused(prepared, monkeypatch, damage):
    case = prepared()
    path = case.pre.safety_backup_path
    if damage == 'delete':
        os.remove(path)
    elif damage == 'tamper':
        data = bytearray(open(path, 'rb').read())
        data[-3] ^= 1
        open(path, 'wb').write(bytes(data))
    else:
        class Gone:
            def active_key(self):
                raise OSError(13, 'Permission denied')
        monkeypatch.setattr(connect, 'KEY_SOURCE', Gone())
    refused(case, 'keyring' if damage == 'key' else 'safety backup')


@pytest.mark.parametrize('change, words', [
    (lambda case: case.dev.serials.__setitem__(0, OTHER_SERIAL), 'a different device'),
    (lambda case: case.dev.global_lines.append('ip domain-name changed.example'),
     'changed after the safety backup'),
    (lambda case: setattr(case.dev, 'archive', None), 'No archive path'),
    (lambda case: case.dev.flash.write(case.pre.temp_name, b'unrelated file'),
     'already exists'),
])
def test_device_changed_between_preflight_and_restore(prepared, change, words):
    case = prepared()
    change(case)
    before = state(case.dev)
    logins = len(case.lab.logins)
    result = restore(case)
    assert result.status == E.FAILED and result.device_state == E.NOTHING_SENT, result.lines()
    assert any(words in t for _, t in result.steps), result.steps
    assert state(case.dev) == before and len(case.lab.logins) == logins + 1
    if words == 'already exists':
        assert case.dev.flash.get(case.pre.temp_name).data == b'unrelated file'


def test_pending_rollback_before_the_restore(prepared):
    from mocklab import restore_sim
    case = prepared()
    case.dev.rollback = restore_sim.Rollback(case.dev.config_state(), None,
                                             case.lab.clock.now(), 5)
    result = restore(case)
    assert result.status == E.FAILED and result.device_state == E.NOTHING_SENT
    assert case.dev.rollback is not None                       # never touched


# ================================================================ transfer failures
@pytest.mark.parametrize('quirk', ['transfer_fails', 'transfer_corrupt'])
def test_transfer_failure_and_md5_mismatch_stop_before_replace(prepared, tmp_path, quirk):
    case = prepared(spec=r1_spec(quirks=[quirk]))
    result = restore(case)
    assert result.status == E.FAILED, result.lines()
    assert result.device_state == E.UNCHANGED_VERIFIED and not result.md5_verified
    assert not result.replace_attempted and 'replace' not in events(case.dev)
    assert case.dev.running_config() == case.original
    assert temp_files(case.dev) == [] and result.cleanup == 'deleted and verified'
    assert_no_plaintext(tmp_path, case, result)


def test_transfer_failure_with_cleanup_failure_needs_a_manual_action(prepared):
    case = prepared(spec=r1_spec(quirks=['transfer_corrupt', 'delete_fails']))
    result = restore(case)
    assert result.status == E.FAILED and result.cleanup.startswith('FAILED')
    assert any('delete' in a.lower() for a in result.manual_actions)
    assert case.dev.running_config() == case.original


# ================================================================ replace / verify failures
def rolled_back(case, result, method='configure revert now'):
    assert result.status == E.FAILED, result.lines()
    assert result.rollback_attempted and result.rollback_verified, result.lines()
    assert result.device_state == E.ORIGINAL_VERIFIED
    assert method in (result.rollback_method or '')
    assert case.dev.running_config() == case.original and case.dev.rollback is None
    assert not result.confirmed and 'confirm' not in events(case.dev)
    assert temp_files(case.dev) == [] and result.cleanup == 'deleted and verified'
    assert case.dev.saves == 0


def test_unexpected_prompt_is_never_answered(prepared):
    case = prepared(spec=r1_spec(quirks=['replace_prompts']))
    result = restore(case)
    rolled_back(case, result)
    assert 'replace' not in events(case.dev)                   # the question was not answered
    assert any('NOT answered' in t for _, t in result.steps)


def test_partial_replacement_is_rolled_back(prepared):
    case = prepared(spec=r1_spec(quirks=['replace_partial']))
    result = restore(case)
    rolled_back(case, result)
    assert 'replace_partial' in events(case.dev) and 'rollback' in events(case.dev)


def test_connection_lost_during_replace(prepared):
    case = prepared(spec=r1_spec(quirks=['drop_during_replace']))
    result = restore(case)
    rolled_back(case, result)


def test_failed_reconnect_rolls_back_on_the_first_session(prepared):
    case = prepared(spec=r1_spec(quirks=['reconnect_refused']))
    result = restore(case)
    rolled_back(case, result)


def test_configuration_mismatch_is_rolled_back(prepared):
    case = prepared(spec=r1_spec(quirks=['verify_mismatch']))
    result = restore(case)
    rolled_back(case, result)
    assert result.comparison.startswith('mismatch: 1 line(s) differ')


def test_failed_rollback_is_unknown_and_never_claimed(prepared):
    case = prepared(spec=r1_spec(quirks=['verify_mismatch', 'revert_fails']))
    result = restore(case)
    assert result.status == E.UNKNOWN, result.lines()
    assert result.rollback_attempted and not result.rollback_verified
    assert result.device_state == E.STATE_UNKNOWN and result.manual_actions
    assert 'confirm' not in events(case.dev) and 'rollback_failed' in events(case.dev)
    assert any(case.pre.safety_backup_path in a for a in result.manual_actions)


def test_timer_expiring_before_confirmation(prepared, monkeypatch):
    case = prepared()
    real = E._cmd

    def late(ctx, conn, command, *a, **kw):
        if command == 'configure confirm':
            case.lab.advance(6 * 60)                           # the verification took too long
        return real(ctx, conn, command, *a, **kw)
    monkeypatch.setattr(E, '_cmd', late)
    result = restore(case)
    assert result.status == E.FAILED and result.rollback_verified, result.lines()
    assert case.dev.running_config() == case.original
    assert ('rollback', 'timer expired') in [e[1:] for e in case.dev.events]
    assert 'confirm' not in events(case.dev)


def test_confirmation_that_leaves_the_timer_running(prepared):
    case = prepared(spec=r1_spec(quirks=['confirm_ignored']))
    result = restore(case)
    assert result.status == E.FAILED and result.rollback_verified, result.lines()
    assert not result.confirmed and 'confirm_ignored' in events(case.dev)
    assert case.dev.running_config() == case.original and case.dev.rollback is None


def test_cleanup_failure_after_success_is_partial(prepared):
    case = prepared(spec=r1_spec(quirks=['delete_fails']))
    result = restore(case)
    assert result.status == E.PARTIAL, result.lines()
    assert result.device_state == E.RESTORED and result.confirmed
    assert result.cleanup.startswith('FAILED') and result.manual_actions
    assert temp_files(case.dev) == [case.pre.temp_name]


def test_device_identity_change_after_replace_is_unknown(prepared, monkeypatch):
    case = prepared()
    real = E._replace

    def swap(ctx, a):
        outcome = real(ctx, a)
        case.dev.serials = [OTHER_SERIAL]          # another chassis answers from now on
        return outcome
    monkeypatch.setattr(E, '_replace', swap)
    result = restore(case)
    assert result.status == E.UNKNOWN, result.lines()
    assert not result.confirmed and 'confirm' not in events(case.dev)
    assert result.rollback_attempted and not result.rollback_verified
    assert 'rollback' in events(case.dev)          # reverted on the original session


def test_management_ip_removal_falls_back_to_the_timer(prepared):
    spec = r1_spec('management_ip_change')
    text = target_text(Device(spec, lab_hosts={}), 'interface GigabitEthernet0/0',
                       'no ip address')
    case = prepared(spec=spec, text=text, management_ip=None)   # the preflight only warned
    result = restore(case)
    rolled_back(case, result, method='rollback timer (fallback)')
    assert ('rollback', 'timer expired') in [e[1:] for e in case.dev.events]


def test_reboot_during_restore(prepared):
    case = prepared(spec=r1_spec(quirks=['reboot_during_restore']))
    result = restore(case)
    rolled_back(case, result, method='rollback timer (fallback)')
    assert 'reload' in events(case.dev) and case.dev.boot_count == 1


def test_device_that_never_answers_again_is_unknown(prepared, monkeypatch):
    case = prepared()
    real = E._replace

    def vanish(ctx, a):
        outcome = real(ctx, a)
        case.lab.stop()
        return outcome
    monkeypatch.setattr(E, '_replace', vanish)
    result = restore(case)
    assert result.status == E.UNKNOWN and result.device_state == E.STATE_UNKNOWN
    assert not result.rollback_verified and result.manual_actions
    assert 'rollback timer (fallback)' in (result.rollback_method or '')


# ================================================================ several devices
def test_only_the_intended_device_is_contacted(prepared):
    sw1 = dict(SPEC['SW1'], serial='FOC0000SW01')
    case = prepared(extra=(sw1,))
    other = case.lab.devices['SW1']
    before = state(other)
    assert restore(case).status == E.SUCCESS
    assert set(case.lab.logins) == {case.spec['host']} and state(other) == before


# ================================================================ comparison rules
BASE = ('Building configuration...\n\nCurrent configuration : 99 bytes\n!\n'
        '! Last configuration change at 10:15:00 UTC Wed Nov 18 2026 by admin\n'
        '! NVRAM config last updated at 10:15:00 UTC Wed Nov 18 2026 by admin\n'
        'version 15.4\n!\nhostname R1\n!\ninterface Gi0/0\n ip address 10.0.0.1 '
        '255.255.255.0\n!\nntp clock-period 17179860\nntp server 192.0.2.1\n!\nend\n')


def same(a, b):
    return E.compare_configs(a, b)[0] and E.compare_configs(b, a)[0]


def differs(a, b):
    equal, desc = E.compare_configs(a, b)
    assert 'hostname' not in desc and '10.0.0.1' not in desc        # never the content
    return not equal


def test_comparison_different_ntp_clock_period_values_are_equal():
    assert same(BASE, BASE.replace('17179860', '17180027'))
    assert same(BASE, BASE.replace('ntp clock-period 17179860\n', ''))


def test_comparison_crlf_and_lf_are_equal():
    assert same(BASE, BASE.replace('\n', '\r\n'))
    assert same(BASE, BASE.replace('\n', '\r'))


def test_comparison_trailing_whitespace_is_ignored():
    assert same(BASE, BASE.replace('hostname R1\n', 'hostname R1  \t\n').replace('end\n',
                                                                                'end \n'))


def test_comparison_recognised_headers_and_timestamps_are_ignored():
    body = BASE.split('version 15.4', 1)[1]
    assert same(BASE, 'version 15.4' + body)                       # no header at all
    assert same(BASE, 'Using 1234 out of 262144 bytes\n\nversion 15.4' + body)
    assert same(BASE, BASE.replace('! Last configuration change at 10:15:00',
                                   '! Last configuration change at 23:59:59'))
    assert same(BASE, BASE.replace('! NVRAM config last updated at 10:15:00 UTC Wed Nov 18 '
                                   '2026 by admin', '! No configuration change since last '
                                   'restart'))


def test_comparison_standalone_separators_are_ignored():
    assert same(BASE, BASE.replace('!\n', ''))
    assert same(BASE, BASE.replace('hostname R1\n', 'hostname R1\n!\n!\n !\n'))


@pytest.mark.parametrize('change', [
    ('hostname R1', 'hostname R2'),
    (' ip address 10.0.0.1', ' ip address 10.0.0.2'),
    (' ip address', '  ip address'),                     # indentation is meaningful
    ('!\ninterface Gi0/0\n ip address 10.0.0.1 255.255.255.0\n',
     '!\n ip address 10.0.0.1 255.255.255.0\ninterface Gi0/0\n'),   # order is meaningful
    ('ntp server 192.0.2.1\n', ''),                       # an NTP line that is NOT generated
    ('ntp server 192.0.2.1', 'ntp server 192.0.2.2'),
    ('ntp clock-period 17179860', ' ntp clock-period 17179860'),   # not the top-level line
    ('ntp clock-period 17179860', 'ntp clock-period 17179860 extra'),
    ('version 15.4', 'version 15.5'),
    ('hostname R1\n', 'hostname R1\nno ip domain-lookup\n'),
    ('end\n', ''),                                        # incomplete
    ('end\n', 'end\nhostname AFTER-END\n'),               # content after the final end
])
def test_comparison_meaningful_lines_still_mismatch(change):
    assert differs(BASE.replace(*change), BASE)


@pytest.mark.parametrize('change', [
    ('hostname R1\n', 'hostname R1\n! site 42 - keep this comment\n'),   # a real comment
    ('hostname R1\n', 'hostname R1\n!!\n'),                               # not a bare "!"
    ('hostname R1\n', 'hostname R1\n! Last configuration change was planned\n'),
    ('! NVRAM config', '! NVRAM settings'),               # not the recognised wording
    ('hostname R1\n', 'hostname R1\n\n'),                 # a blank line in the body
    ('hostname R1\n', 'hostname R1\nbanner motd ^C\n\nend\n^C\n'),  # banner text incl. "end"
])
def test_comparison_comments_and_body_lines_are_not_silently_ignored(change):
    assert differs(BASE.replace(*change, 1), BASE)


# ================================================================ the dead-channel watchdog
class _FakeTransport:
    def __init__(self):
        self.active = True

    def is_active(self):
        return self.active


class _FakeChannel:
    """A paramiko channel stand-in: any write or close fails the test."""
    closed = eof_received = False

    def __init__(self, transport):
        self.transport = transport

    def get_transport(self):
        return self.transport

    def sendall(self, *a):
        raise AssertionError('the watchdog wrote to the device')

    def send(self, *a):
        raise AssertionError('the watchdog wrote to the device')

    def close(self):
        raise AssertionError('the watchdog closed a channel')


class _FakeConn:
    def __init__(self):
        self.transport = _FakeTransport()
        self.remote_conn = _FakeChannel(self.transport)
        self.channel = types.SimpleNamespace(remote_conn=self.remote_conn)

    def write_channel(self, *a):
        raise AssertionError('the watchdog wrote to the device')


def watchdogs():
    import threading
    return [t for t in threading.enumerate() if t.name == E.WATCHDOG_THREAD]


def test_watchdog_detaches_only_the_dead_session_and_never_writes_or_closes():
    import time
    dead, other = _FakeConn(), _FakeConn()
    with E._watch(dead), E._watch(other):
        assert len(watchdogs()) == 2
        dead.transport.active = False                # the device cut this session
        deadline = time.monotonic() + 3
        while dead.channel.remote_conn is not None and time.monotonic() < deadline:
            time.sleep(0.05)
        assert dead.channel.remote_conn is None      # Netmiko's next read raises at once
        assert other.channel.remote_conn is other.remote_conn   # the other session is intact
    assert dead.remote_conn.closed is False          # it detaches; it never closes
    assert watchdogs() == []                         # joined before returning


def test_watchdog_leaves_a_live_session_alone_and_stops_on_errors():
    import time
    conn = _FakeConn()
    with E._watch(conn):
        time.sleep(0.5)                              # several polling rounds
    assert conn.channel.remote_conn is conn.remote_conn and watchdogs() == []
    with pytest.raises(ValueError):
        with E._watch(conn):
            raise ValueError('a failing Netmiko call')
    assert watchdogs() == []


@pytest.mark.parametrize('quirks', [[], ['drop_during_replace'], ['transfer_fails']])
def test_no_watchdog_thread_outlives_a_restore(prepared, quirks):
    case = prepared(spec=r1_spec(quirks=quirks))
    result = restore(case)
    assert result.status in (E.SUCCESS, E.FAILED)
    assert watchdogs() == []


def test_apply_does_not_use_the_watchdog(monkeypatch):
    """Apply (config.connect) never goes through the restore engine's watchdog."""
    import inspect
    assert '_watch' not in inspect.getsource(connect)
    monkeypatch.setattr(E, '_watch', lambda conn: pytest.fail('watchdog used by Apply'))
    assert connect.apply_config({'host': '192.0.2.1', 'username': 'x', 'password': 'y'},
                                [])[0] is False


def test_transfer_text_and_tcl_safety():
    header = 'Building configuration...\n\nCurrent configuration : 99 bytes\n'
    assert E.transfer_text(BASE) == BASE[len(header):].rstrip('\n')   # only the header goes
    assert E.transfer_text('hostname R1\n') is None
    assert E.tcl_safe('hostname R1\nend') and not E.tcl_safe('description {x}')
    assert not E.tcl_safe('banner x' + chr(92) + '\nend')
    assert not E.tcl_safe('description caf' + chr(233))
