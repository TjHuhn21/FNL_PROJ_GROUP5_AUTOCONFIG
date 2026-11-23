"""Phase 4H: saving a verified restore to the startup configuration (startup_save.py).

Every test first runs the REAL workflow to a verified restore SUCCESS (catalogue selection,
preflight, safety backup, restore engine) on the Mock Lab, through the real Netmiko, then
the save checks and the save. Synthetic data, logins and in-memory keys only.
"""
import dataclasses
import os
import sys

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

pytest.importorskip('netmiko')

import backup_crypto as C  # noqa: E402
import restore_engine as E  # noqa: E402
import startup_save as S  # noqa: E402
from config import connect  # noqa: E402
from test_restore_engine import (fast_inline_transfer, prepared,  # noqa: E402,F401
                                 restore as run_restore)
from test_restore_preflight import (MARK, OTHER_SERIAL, SPEC, key_path,  # noqa: E402,F401
                                    lab_with, r1_spec, setup)
from mocklab import restore_sim  # noqa: E402  (mock-lab is on the path from here on)


@pytest.fixture
def restored(prepared):
    """restored(spec=...) -> a case whose restore finished with a verified SUCCESS."""
    def make(spec=None, **kw):
        case = prepared(spec=spec, **kw)
        case.result = run_restore(case)
        assert case.result.status == E.SUCCESS, case.result.lines()
        case.restored_running = case.dev.running_config()
        case.startup_before = case.dev.startup
        case.saves_before = case.dev.saves
        return case
    return make


def check(case, **kw):
    return S.check(case.result, case.login, wait=case.lab.advance, **kw)


def save(case, plan, tmp_path, typed=None, **kw):
    return S.save(plan, plan.required_confirmation if typed is None else typed, case.login,
                  backup_dir=str(tmp_path / 'startup'), wait=case.lab.advance, **kw)


def unchanged(case):
    return case.dev.startup == case.startup_before and case.dev.saves == case.saves_before


def no_plaintext(tmp_path):
    for d, _, files in os.walk(tmp_path):
        for f in files:
            assert f.endswith('.ncbak'), f
            with open(os.path.join(d, f), 'rb') as fh:
                data = fh.read()
            assert data.startswith(C.MAGIC) and MARK.encode() not in data


def messages(*objs):
    text = []
    for o in objs:
        text += [c.text for c in getattr(o, 'checks', [])]
        text += [t for _, t in getattr(o, 'steps', [])] + list(getattr(o, 'manual_actions', []))
        text += o.lines() if hasattr(o, 'lines') else []
    joined = ' '.join(text)
    for secret in (MARK, 'ntp server 192.0.2.77', SPEC['MOCK-R1']['password'],
                   '$1$mock$hidden'):
        assert secret not in joined, secret


# ================================================================ success
def test_successful_save_is_independently_verified(restored, tmp_path):
    case = restored()
    plan = check(case)
    assert plan.status == S.PASS and plan.can_proceed, [c.text for c in plan.checks]
    assert plan.required_confirmation == f'SAVE STARTUP {case.spec["host"]}'
    assert unchanged(case)                                    # the checks changed nothing
    res = save(case, plan, tmp_path)
    assert res.status == S.SUCCESS, res.lines()
    dev = case.dev
    assert dev.saves == case.saves_before + 1
    assert E.compare_configs(dev.startup, dev.running_config())[0]
    assert dev.running_config() == case.restored_running     # nothing else changed
    assert dev.boot_count == 0 and dev.rollback is None       # no reload, no timer
    assert res.startup_state == S.SAVED and res.command_outcome.startswith('ok')
    # the encrypted pre-save-startup backup holds exactly the OLD startup configuration
    path = res.startup_backup
    assert os.path.basename(path).startswith(f'{case.spec["host"]}_pre-save-startup_')
    with open(path, 'rb') as f:
        plain, header = C.decrypt_backup(f.read(), connect.KEY_SOURCE.key_for)
    assert header['purpose'] == 'pre-save-startup' and header['source'] == 'show startup-config'
    assert header['host'] == case.spec['host'] and header['serial'] == case.result.identity[
        'serial']
    assert E.compare_configs(plain.decode(), case.startup_before)[0]
    assert os.path.exists(path)                               # kept after the success
    no_plaintext(tmp_path)
    messages(plan, res)


def test_the_same_restore_cannot_be_saved_twice(restored, tmp_path):
    case = restored()
    assert save(case, check(case), tmp_path).status == S.SUCCESS
    again = check(case)
    assert again.status == S.BLOCKED and 'already been saved' in again.check('eligibility').text


def test_startup_already_equal_is_a_warning_and_still_verified(restored, tmp_path):
    case = restored()
    case.dev.startup = case.dev.running_config()
    case.startup_before = case.dev.startup
    plan = check(case)
    assert plan.status == S.WARNING and plan.can_proceed
    assert save(case, plan, tmp_path).status == S.SUCCESS


# ================================================================ eligibility
@pytest.mark.parametrize('quirks, status', [
    (['verify_mismatch'], E.FAILED), (['delete_fails'], E.PARTIAL),
    (['verify_mismatch', 'revert_fails'], E.UNKNOWN)])
def test_only_a_verified_success_can_be_saved(prepared, quirks, status):
    case = prepared(spec=r1_spec(quirks=quirks))
    result = run_restore(case)
    assert result.status == status
    assert not S.eligible(result)[0] and result.restored_digest is None
    logins = len(case.lab.logins)
    plan = S.check(result, case.login, wait=case.lab.advance)
    assert plan.status == S.BLOCKED and not plan.can_proceed
    assert len(case.lab.logins) == logins and case.dev.saves == 0


@pytest.mark.parametrize('change', [
    lambda r: setattr(r, 'status', E.SUCCESS) or setattr(r, 'timer_state', 'pending'),
    lambda r: setattr(r, 'device_ip', '127.0.0.12'),
    lambda r: r.identity.update(serial=OTHER_SERIAL),
    lambda r: setattr(r, 'restored_digest', 'f' * 64),
    lambda r: setattr(r, 'seal', None)])
def test_a_changed_or_foreign_restore_result_is_refused(restored, change):
    case = restored()
    change(case.result)
    logins = len(case.lab.logins)
    plan = check(case)
    assert plan.status == S.BLOCKED and 'not an unchanged result' in plan.check(
        'eligibility').text
    assert len(case.lab.logins) == logins and unchanged(case)
    forged = E.RestoreResult(status=E.SUCCESS, device_ip=case.spec['host'], confirmed=True,
                             timer_state='cancelled (verified)', device_state=E.RESTORED,
                             restored_digest='a' * 64, identity={'serial': 'X1'})
    assert not S.eligible(forged)[0]


def test_wrong_device_is_refused(restored):
    case = restored()
    other = dict(case.login, host='127.0.0.12')
    plan = S.check(case.result, other, wait=case.lab.advance)
    assert plan.status == S.BLOCKED and 'not 127.0.0.12' in plan.check('eligibility').text


# ================================================================ read-only checks
def test_changed_identity_blocks(restored):
    case = restored()
    case.dev.serials = [OTHER_SERIAL]
    plan = check(case)
    assert plan.status == S.BLOCKED and plan.check('identity') is not None
    assert unchanged(case)


def test_running_configuration_changed_after_restore_blocks(restored):
    case = restored()
    case.dev.global_lines.append('ip domain-name changed.example')
    plan = check(case)
    assert plan.status == S.BLOCKED and 'changed after the restore' in plan.check(
        'running-config').text
    assert unchanged(case)


def test_pending_rollback_timer_blocks(restored):
    case = restored()
    case.dev.rollback = restore_sim.Rollback(case.dev.config_state(), None,
                                             case.lab.clock.now(), 5)
    plan = check(case)
    assert plan.status == S.BLOCKED and plan.check('rollback-timer').status == S.BLOCKED
    assert case.dev.rollback is not None and unchanged(case)


def test_invalid_startup_configuration_blocks(restored):
    case = restored()
    case.dev.startup = 'Building configuration...\n\nCurrent configuration : 9 bytes\n!\n'
    case.startup_before = case.dev.startup
    plan = check(case)
    assert plan.status == S.BLOCKED and plan.check('startup-config').status == S.BLOCKED
    assert unchanged(case)


def test_invalid_running_configuration_fails(restored, monkeypatch):
    case = restored()
    monkeypatch.setattr(E, '_running', lambda ctx, conn: '% Command authorization failed.')
    plan = check(case)
    assert plan.status == S.FAILED and plan.check('running-config').status == S.FAILED


def test_missing_keyring_fails_before_connecting(restored, monkeypatch):
    case = restored()

    class Gone:
        def active_key(self):
            raise OSError(2, 'No such file or directory')
    monkeypatch.setattr(connect, 'KEY_SOURCE', Gone())
    logins = len(case.lab.logins)
    plan = check(case)
    assert plan.status == S.FAILED and plan.check('keyring') is not None
    assert len(case.lab.logins) == logins


# ================================================================ refusals before saving
@pytest.mark.parametrize('typed', ['', 'SAVE STARTUP', 'save startup 127.0.0.11',
                                   'SAVE STARTUP 127.0.0.11 ', 'SAVE STARTUP 127.0.0.12',
                                   'RESTORE 127.0.0.11', None])
def test_wrong_confirmation_saves_nothing(restored, tmp_path, typed):
    case = restored()
    plan = check(case)
    logins = len(case.lab.logins)
    with pytest.raises(S.SaveRefused, match='not typed exactly'):
        S.save(plan, typed, case.login, backup_dir=str(tmp_path / 'startup'))
    assert len(case.lab.logins) == logins and unchanged(case)
    assert not (tmp_path / 'startup').exists() and plan.stage == S.CHECKED


def test_stale_changed_reused_or_blocked_plans_are_refused(restored, tmp_path):
    case = restored()
    plan = check(case)
    with pytest.raises(S.SaveRefused, match='too old'):
        save(case, plan, tmp_path, clock=lambda: plan.checked_at + S.FRESH_SECONDS + 1)
    with pytest.raises(S.SaveRefused, match='another device'):
        S.save(plan, plan.required_confirmation, dict(case.login, host='127.0.0.12'))
    changed = dataclasses.replace(plan, startup_digest='0' * 64)
    with pytest.raises(S.SaveRefused, match='changed'):
        save(case, changed, tmp_path)
    assert save(case, plan, tmp_path).status == S.SUCCESS
    with pytest.raises(S.SaveRefused):
        save(case, plan, tmp_path)                            # single use
    case.dev.global_lines.append('ip domain-name x.example')
    blocked = check(case)
    with pytest.raises(S.SaveRefused):
        save(case, blocked, tmp_path, typed=f'SAVE STARTUP {case.spec["host"]}')


@pytest.mark.parametrize('change, words', [
    (lambda case: case.dev.serials.__setitem__(0, OTHER_SERIAL), 'verified session'),
    (lambda case: case.dev.global_lines.append('ip domain-name late.example'),
     'no longer the verified restored'),
    (lambda case: setattr(case.dev, 'startup', case.dev.startup.replace(
        '\nend', '\nip domain-name startup.example\nend')), 'startup configuration changed'),
])
def test_changes_between_checks_and_save_save_nothing(restored, tmp_path, change, words):
    case = restored()
    plan = check(case)
    change(case)
    startup = case.dev.startup
    res = save(case, plan, tmp_path)
    assert res.status == S.FAILED and not res.command_sent, res.lines()
    assert any(words in t for _, t in res.steps), res.steps
    assert case.dev.startup == startup and case.dev.saves == case.saves_before
    assert res.startup_backup is None


@pytest.mark.parametrize('failure', ['write', 'verify', 'key'])
def test_startup_backup_failure_saves_nothing(restored, tmp_path, monkeypatch, failure):
    case = restored()
    plan = check(case)
    if failure == 'write':
        monkeypatch.setattr(connect, '_save_backup', lambda *a, **k: (_ for _ in ()).throw(
            connect.BackupError('Backup of x failed: the file could not be written (Disk '
                                'full)')))
    elif failure == 'verify':
        monkeypatch.setattr(S, 'verify_startup_backup', lambda *a: 'synthetic mismatch')
    else:
        class Gone:
            def active_key(self):
                raise OSError(13, 'Permission denied')
        monkeypatch.setattr(connect, 'KEY_SOURCE', Gone())
    res = save(case, plan, tmp_path)
    assert res.status == S.FAILED and not res.command_sent and unchanged(case)
    assert res.startup_state == S.NOTHING_SAVED


def test_verify_startup_backup_detects_every_difference(restored, tmp_path):
    case = restored()
    ident = case.result.identity
    path, _, _ = connect._save_backup(case.spec['host'], case.startup_before, str(tmp_path),
                                      connect.KEY_SOURCE.active_key(), ident, purpose=S.PURPOSE,
                                      source=S.SHOW_STARTUP)
    key_for = connect.KEY_SOURCE.key_for
    ok = (path, case.startup_before, key_for, case.spec['host'], ident)
    assert S.verify_startup_backup(*ok) is None
    assert 'differs' in S.verify_startup_backup(path, case.startup_before + '!', key_for,
                                                case.spec['host'], ident)
    assert 'labelled' in S.verify_startup_backup(path, case.startup_before, key_for,
                                                 '127.0.0.12', ident)
    assert 'identity' in S.verify_startup_backup(path, case.startup_before, key_for,
                                                 case.spec['host'], dict(ident, serial='X9'))
    running, _, _ = connect._save_backup(case.spec['host'], case.startup_before,
                                         str(tmp_path / 'r'), connect.KEY_SOURCE.active_key(),
                                         ident, purpose=S.PURPOSE)
    assert 'labelled' in S.verify_startup_backup(running, case.startup_before, key_for,
                                                 case.spec['host'], ident)   # wrong source


# ================================================================ the save itself
def test_save_command_failure_is_failed_with_startup_verified_unchanged(restored, tmp_path):
    case = restored(spec=r1_spec(quirks=['save_fails']))
    res = save(case, check(case), tmp_path)
    assert res.status == S.FAILED and res.command_sent, res.lines()
    assert res.startup_state == S.UNCHANGED and res.command_outcome.startswith('error')
    assert unchanged(case) and os.path.exists(res.startup_backup)
    assert res.manual_actions


def test_unexpected_prompt_is_never_answered(restored, tmp_path, monkeypatch):
    """With this quirk a single Enter would save (IOS "[confirm]"): saves must stay 0."""
    from netmiko.base_connection import BaseConnection
    case = restored(spec=r1_spec(quirks=['save_prompts']))
    # From here on (the save workflow only) a newline-sending disconnect() is forbidden.
    monkeypatch.setattr(BaseConnection, 'disconnect', lambda self: pytest.fail('disconnect'))
    res = save(case, check(case), tmp_path)
    assert res.status == S.FAILED, res.lines()
    assert res.command_outcome.startswith('prompt') and res.startup_state == S.UNCHANGED
    assert unchanged(case)                                    # never answered: not saved


def test_connection_lost_during_save_is_never_success(restored, tmp_path):
    case = restored(spec=r1_spec(quirks=['drop_during_save']))
    res = save(case, check(case), tmp_path)
    assert res.status == S.UNKNOWN, res.lines()
    assert res.command_outcome.startswith('lost') and res.startup_state == S.LOOKS_SAVED
    assert any('interrupted NVRAM write' in a for a in res.manual_actions)


def test_startup_mismatch_after_save_is_unknown(restored, tmp_path):
    case = restored(spec=r1_spec(quirks=['startup_mismatch']))
    res = save(case, check(case), tmp_path)
    assert res.status == S.UNKNOWN and res.startup_state == S.STATE_UNKNOWN, res.lines()
    assert 'mismatch' in res.verification
    assert any(res.startup_backup in a and 'Do not reload' in a for a in res.manual_actions)


def test_identity_change_after_the_save_is_unknown(restored, tmp_path, monkeypatch):
    case = restored()
    real = E._cmd

    def swap(ctx, conn, command, *a, **k):
        out = real(ctx, conn, command, *a, **k)
        if command == S.SAVE_COMMAND:
            case.dev.serials = [OTHER_SERIAL]
        return out
    monkeypatch.setattr(E, '_cmd', swap)
    res = save(case, check(case), tmp_path)
    assert res.status == S.UNKNOWN and 'different device' in res.verification


def test_device_gone_after_the_save_is_unknown(restored, tmp_path, monkeypatch):
    case = restored()
    real = E._cmd

    def vanish(ctx, conn, command, *a, **k):
        out = real(ctx, conn, command, *a, **k)
        if command == S.SAVE_COMMAND:
            case.lab.stop()
        return out
    monkeypatch.setattr(E, '_cmd', vanish)
    res = save(case, check(case), tmp_path)
    assert res.status == S.UNKNOWN and res.startup_state == S.STATE_UNKNOWN
    assert res.manual_actions


def test_save_touches_nothing_but_the_startup_configuration(restored, tmp_path):
    case = restored(spec=r1_spec('scp'))
    before = (case.dev.archive, list(case.dev.global_lines), dict(case.dev.flash.files),
              case.dev.archive_copies[:])
    assert save(case, check(case), tmp_path).status == S.SUCCESS
    assert (case.dev.archive, case.dev.global_lines, dict(case.dev.flash.files),
            case.dev.archive_copies) == before
    assert case.dev.boot_count == 0


def test_save_backup_source_validation(tmp_path):
    with pytest.raises(connect.BackupError, match='source'):
        connect._save_backup('10.0.0.2', 'hostname x\nend\n', str(tmp_path), None,
                             source='show something')
    assert os.listdir(tmp_path) == []
