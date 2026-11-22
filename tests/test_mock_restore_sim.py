"""Phase 4D: the Mock Lab's restore simulation (mock-lab/mocklab/restore_sim.py).

Simulated flash (dir, delete, verify /md5), Tcl and SCP transfers into memory-only
flash, archive copies, `configure replace ... time N` with a SIMULATED clock,
`configure confirm`, `configure revert`, and every failure-injection scenario.

Most tests drive the CLI directly (no SSH); the end-to-end ones use the real Netmiko
ConnectHandler, InLineTransfer and the scp package against the lab on free ports of
127.0.0.1. Nothing waits for real minutes: the rollback timer only moves when a test
advances the simulated clock. No physical device is contacted, and no production
restore code exists or is exercised here.
"""
import hashlib
import io
import os
import sys
import time

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, 'mock-lab'))

from mocklab import restore_sim  # noqa: E402
from mocklab.cli import Session  # noqa: E402
from mocklab.device import CONFIG_ATTRS, QUIRKS, Device  # noqa: E402
from mocklab.lab import Lab, LabError, check_config, load_config  # noqa: E402
from mocklab.restore_sim import (BOOT_SECONDS, MISMATCH_LINE, NO_PENDING,  # noqa: E402
                                 RESTORE_SCENARIOS, Flash, FlashError, SimClock,
                                 flash_path, load_config_text, restore_spec)

CONFIG = load_config()
SPEC = {d['name']: d for d in CONFIG['devices']}
HOSTS = {n: (s['host'], s['type']) for n, s in SPEC.items()}
RESTORE_QUIRKS = ('replace_unsupported', 'no_tcl', 'no_scp', 'flash_overwrites',
                  'transfer_fails', 'transfer_corrupt', 'replace_partial', 'revert_fails',
                  'drop_during_replace', 'reconnect_refused', 'verify_mismatch', 'delete_fails',
                  'reboot_during_restore')
NTP_EXTRA = 'ntp server 192.0.2.123'          # documentation range: never a real server


# ---------------------------------------------------------------- helpers
def device(name='MOCK-R1', scenario='success', clock=None, **extra):
    spec = restore_spec(SPEC[name], scenario)
    spec.update(extra)
    return Device(spec, lab_hosts=HOSTS, clock=clock)


def session(dev):
    return Session(dev, privilege=15)


def run(s, *lines):
    return [s.handle(line).output for line in lines]


def target_config(dev, *commands):
    """The running configuration dev WOULD have after these configuration commands
    (built on a separate copy: dev itself is not touched)."""
    other = Device(dev.spec, lab_hosts=HOSTS)
    s = session(other)
    s.handle('configure terminal')
    for c in commands:
        out = s.handle(c).output
        assert not out.lstrip().startswith('%'), (c, out)
    s.handle('end')
    return other.running_config()


def body(text):
    """Configuration text without the two header lines (what a backup file holds)."""
    return text.split('\n', 3)[-1]


def tcl_put(s, name, text):
    """What Netmiko's InLineTransfer types: the content with \\n as \\r, inside braces."""
    lines = text.split('\n')
    replies = [s.handle(f'puts [open "flash:{name}" w+] {{{lines[0]}' +
                        ('}' if len(lines) == 1 else ''))]
    for n, line in enumerate(lines[1:], 1):
        replies.append(s.handle(line + ('}' if n == len(lines) - 1 else '')))
    return replies


def upload(dev, s, text, name=None):
    """A Tcl transfer of text to flash; returns the flash name."""
    name = name or dev.flash.temp_name()
    s.handle('tclsh')
    tcl_put(s, name, text)
    s.handle('tclquit')
    return name


def replace(dev, s, text, options='force time 5'):
    name = upload(dev, s, text)
    return name, s.handle(f'configure replace flash:{name} {options}')


# ---------------------------------------------------------------- simulated clock
def test_clock_only_moves_when_advanced_and_never_sleeps():
    clock = SimClock()
    assert clock.now() == 0
    started = time.monotonic()
    assert clock.advance(3600) == 3600
    assert time.monotonic() - started < 1                     # an hour, without waiting
    with pytest.raises(ValueError):
        clock.advance(-1)
    assert clock.stamp(0).startswith('Nov 18 2026 10:15:00')


def test_lab_devices_share_one_clock_and_advance_fires_timers(tmp_path):
    lab = Lab(CONFIG, key_path=str(tmp_path / 'k.key'))
    assert len({id(d.clock) for d in lab.devices.values()}) == 1
    assert lab.advance(10) == 10 and lab.devices['SW1'].clock.now() == 10


# ---------------------------------------------------------------- flash
def test_dir_listing_matches_what_netmiko_parses():
    import re
    dev = device()
    s = session(dev)
    out = s.handle('dir').output
    assert out.startswith('Directory of flash:/')
    assert re.search(r'(\d+) \w+ free', out)                    # remote_space_available
    assert 'c1900-' in out or 'netcommand-lab.bin' in out       # the simulated image
    free = int(re.search(r'\((\d+) bytes free\)', out).group(1))
    assert free == dev.flash.free() and free < dev.flash.total
    name = upload(dev, s, 'hostname X\nend')
    one = s.handle(f'dir flash:/{name}').output
    assert re.search(rf'Directory of .*{name}', one, re.S)      # check_file_exists: True
    rows = [l for l in one.split('\n') if l.endswith(name) and not l.startswith('Directory')]
    assert int(rows[0].split()[2]) == \
        dev.flash.get(name).size                                 # remote_file_size
    assert 'Error opening' in s.handle('dir flash:/missing.cfg').output   # exists: False
    assert 'No such device' in s.handle('dir nvram:').output
    assert s.handle('dir flash:').output == s.handle('dir flash:/').output


def test_flash_paths_and_names():
    assert flash_path('flash:a.cfg') == flash_path('flash:/a.cfg') == 'a.cfg'
    assert flash_path('flash:') == flash_path('FLASH:/') == ''
    for bad in ('nvram:x', 'tftp://192.0.2.1/x', 'disk0:x', 'flash:dir/x', ''):
        with pytest.raises(FlashError):
            flash_path(bad)
    flash = Flash(SimClock(), 10_000)
    for bad in ('', '../x', '-x', 'a b', 'x' * 65):
        with pytest.raises(FlashError):
            flash.write(bad, b'x')


def test_temporary_names_are_unique_and_never_overwrite():
    flash = Flash(SimClock(), 10_000_000)
    names = {flash.temp_name() for _ in range(200)}
    assert len(names) == 200
    assert all(n.startswith('nc-restore-') and n.endswith('.cfg') and len(n) == 31
               for n in names)
    flash.write('nc-restore-0000000000000000.cfg', b'first')
    with pytest.raises(FlashError, match='File exists'):
        flash.write('nc-restore-0000000000000000.cfg', b'second')
    assert flash.get('nc-restore-0000000000000000.cfg').data == b'first'
    real = flash.temp_name()
    assert not flash.exists(real)


def test_transfer_to_an_existing_name_is_refused_unless_flash_overwrites():
    dev = device()
    s = session(dev)
    name = upload(dev, s, 'one')
    s.handle('tclsh')
    replies = tcl_put(s, name, 'two')
    assert 'File exists' in replies[-1].output
    s.handle('tclquit')
    assert dev.flash.get(name).data == b'one\n'
    dev2 = device(quirks=['flash_overwrites'])                  # what real IOS does
    s2 = session(dev2)
    name2 = upload(dev2, s2, 'one')
    upload(dev2, s2, 'two', name=name2)
    assert dev2.flash.get(name2).data == b'two\n'


def test_images_and_archive_copies_are_never_overwritten_even_with_flash_overwrites():
    dev = device(quirks=['flash_overwrites'])
    image = next(f.name for f in dev.flash.files.values() if f.kind == 'image')
    assert restore_sim.store_transfer(dev, image, b'x') is not None
    with pytest.raises(FlashError):
        dev.flash.write(image, b'x', overwrite=True)
    assert dev.flash.get(image).kind == 'image'
    s = session(dev)
    s.handle('archive config')
    copy = dev.archive_copies[0]
    assert restore_sim.store_transfer(dev, copy, b'x') is not None
    assert dev.flash.get(copy).kind == 'archive'


def test_flash_space_is_enforced():
    dev = device(flash_bytes=4096)
    assert dev.flash.free() == 2048                              # half is the "image"
    s = session(dev)
    s.handle('tclsh')
    replies = tcl_put(s, 'big.cfg', 'x' * 5000)
    assert 'No space left' in replies[-1].output
    assert not dev.flash.exists('big.cfg')


def test_delete_force_confirm_prompts_and_errors():
    dev = device()
    s = session(dev)
    a, b = upload(dev, s, 'a'), upload(dev, s, 'b')
    assert s.handle(f'delete /force flash:{a}').output == ''
    assert not dev.flash.exists(a)
    assert 'File not found' in s.handle(f'delete /force flash:{a}').output
    assert s.handle(f'delete flash:{b}').output == f'Delete filename [{b}]? '
    assert s.handle('').output == f'Delete flash:/{b}? [confirm]'
    assert s.pending is not None                                 # never answered for us
    s.handle('n')
    assert dev.flash.exists(b)                                   # "n" keeps the file
    s.handle(f'delete flash:{b}'); s.handle(''); s.handle('')
    assert not dev.flash.exists(b)
    assert 'Is a directory' in s.handle('delete /force flash:').output
    assert 'Invalid input' in s.handle('delete /bogus flash:x').output


def test_verify_md5_output_parses_like_netmiko_expects():
    from netmiko.scp_handler import BaseFileTransfer
    dev = device()
    s = session(dev)
    text = 'hostname MD5-TEST\nend'
    name = upload(dev, s, text)
    expected = hashlib.md5((text + '\n').encode()).hexdigest()   # InLineTransfer.config_md5
    out = s.handle(f'verify /md5 flash:/{name}').output
    assert out.endswith(f'verify /md5 (flash:/{name}) = {expected}') and 'Done!' in out
    assert BaseFileTransfer.process_md5(out) == expected
    assert s.handle(f'verify /md5 flash:{name} {expected}').output == \
        f'Verified (flash:/{name}) = {expected}'
    wrong = s.handle(f'verify /md5 flash:{name} {"0" * 32}').output
    assert wrong.startswith('%Error verifying') and expected in wrong
    assert 'File not found' in s.handle('verify /md5 flash:missing').output
    assert 'Invalid input' in s.handle('verify /sha512 flash:x').output


# ---------------------------------------------------------------- Tcl transfer
def test_tcl_transfer_writes_exactly_the_text_and_prompts_like_tclsh():
    dev = device()
    s = session(dev)
    s.handle('tclsh')
    assert s.prompt() == 'MOCK-R1(tcl)#'
    text = body(dev.running_config())
    lines = text.split('\n')
    s.handle(f'puts [open "flash:copy.cfg" w+] {{{lines[0]}')
    assert s.prompt() == '+>'                                    # inside the braces
    for line in lines[1:-1]:
        s.handle(line)
    s.handle(lines[-1] + '}')
    assert s.prompt() == 'MOCK-R1(tcl)#'
    s.handle('tclquit')
    assert s.prompt() == 'MOCK-R1#'
    assert dev.flash.get('copy.cfg').data == (text + '\n').encode()
    assert dev.flash.get('copy.cfg').kind == 'file'
    assert ('transfer' in [e[1] for e in dev.events])


def test_tclsh_needs_privilege_and_no_tcl_removes_it():
    dev = device()
    s = Session(dev, privilege=1)
    assert 'Unknown command' in s.handle('tclsh').output
    gone = device(scenario='no_transfer')
    t = session(gone)
    out = t.handle('tclsh').output
    assert '% Unknown command' in out                            # what InLineTransfer checks
    assert t.prompt() == 'MOCK-R1#'


def test_tcl_runs_other_lines_as_exec_commands_and_rejects_other_file_systems():
    dev = device()
    s = session(dev)
    s.handle('tclsh')
    assert s.handle('show privilege').output == 'Current privilege level is 15'
    assert 'no such file' in s.handle('puts [open "nvram:x" w+] {a}').output
    assert 'directory' in s.handle('puts [open "flash:" w+] {a}').output
    assert s.prompt() == 'MOCK-R1(tcl)#'


def test_transfer_corrupt_gives_an_md5_mismatch():
    dev = device(scenario='md5_mismatch')
    s = session(dev)
    text = body(dev.running_config())
    name = upload(dev, s, text)
    expected = hashlib.md5((text + '\n').encode()).hexdigest()
    assert dev.flash.get(name).md5() != expected
    assert s.handle(f'verify /md5 flash:{name} {expected}').output.startswith('%Error verifying')


def test_transfer_fails_cuts_the_connection_and_leaves_a_partial_file():
    dev = device(scenario='transfer_fails')
    s = session(dev)
    text = body(dev.running_config())
    s.handle('tclsh')
    replies = tcl_put(s, 'half.cfg', text)
    assert replies[-1].drop                                      # the connection is cut
    partial = dev.flash.get('half.cfg')
    assert partial is not None and 0 < partial.size < len(text)
    assert any(e[1] == 'transfer_failed' for e in dev.events)


# ---------------------------------------------------------------- archive
def test_archive_configuration_mode_and_running_config_section():
    dev = Device(SPEC['MOCK-R1'], lab_hosts=HOSTS)
    assert 'archive' not in dev.running_config().split('\n')
    s = session(dev)
    assert s.handle('show archive').output.startswith('Archive feature not enabled')
    run(s, 'configure terminal', 'archive')
    assert s.prompt() == 'MOCK-R1(config-archive)#'
    run(s, 'path flash:nc-archive', 'maximum 3', 'write-memory', 'end')
    text = dev.running_config()
    assert '\narchive\n path flash:nc-archive\n maximum 3\n write-memory\n!' in text
    assert 'not a usable' in run(s, 'conf t', 'archive', 'path tftp://192.0.2.1/x')[-1]
    assert 'not a usable' in s.handle('path nvram:x').output
    run(s, 'no write-memory', 'end')
    assert ' write-memory' not in dev.running_config()
    run(s, 'conf t', 'no archive', 'end')
    assert 'archive' not in dev.running_config().split('\n')


def test_archive_copies_rotate_and_stay_separate_from_transfer_files():
    dev = device()                                               # archive path, maximum 5
    s = session(dev)
    temp = upload(dev, s, 'x')
    for _ in range(7):
        assert s.handle('archive config').output == ''
    assert dev.archive_copies == [f'archive-{n}' for n in range(3, 8)]
    assert not dev.flash.exists('archive-1') and not dev.flash.exists('archive-2')
    kinds = {f.name: f.kind for f in dev.flash.files.values()}
    assert all(kinds[n] == 'archive' for n in dev.archive_copies) and kinds[temp] == 'file'
    assert dev.flash.get('archive-7').data == dev.running_config().encode()
    out = s.handle('show archive').output
    assert 'The maximum archive configurations allowed is 5.' in out
    assert 'flash:archive-8' in out and 'flash:archive-7 <- Most Recent' in out


def test_archive_copy_never_takes_an_existing_name():
    dev = device()
    s = session(dev)
    upload(dev, s, 'mine', name='archive-1')
    s.handle('archive config')
    assert dev.archive_copies == ['archive-2']
    assert dev.flash.get('archive-1').data == b'mine\n'


def test_archive_config_without_a_path_is_refused():
    dev = device(scenario='no_archive')
    assert 'Archive path is not configured' in session(dev).handle('archive config').output
    assert dev.archive_copies == []


# ---------------------------------------------------------------- the configuration loader
@pytest.mark.parametrize('name', sorted(SPEC))
def test_every_lab_configuration_replays_to_itself(name):
    dev = device(name)
    before = dev.running_config()
    state, rejected = load_config_text(dev, before)
    assert rejected == []
    dev.set_config_state(state)
    assert dev.running_config() == before


def test_replay_keeps_physical_facts_and_hashed_secrets():
    dev = device('SW1')
    cables = {n: i.connected for n, i in dev.interfaces.items()}
    secret_lines = [g for g in dev.global_lines if 'secret' in g or 'password' in g]
    state, _ = load_config_text(dev, dev.running_config())
    dev.set_config_state(state)
    assert {n: i.connected for n, i in dev.interfaces.items()} == cables
    assert [g for g in dev.global_lines if 'secret' in g or 'password' in g] == secret_lines


def test_replayed_enable_secret_hash():
    dev = Device(SPEC['MOCK-R1'], lab_hosts=HOSTS)
    s = Session(dev)
    s.handle('enable'); s.handle(SPEC['MOCK-R1']['password'])
    run(s, 'conf t', 'enable secret Synthetic-Enable-1', 'end')
    line = next(g for g in dev.global_lines if g.startswith('enable secret 5 '))
    state, rejected = load_config_text(dev, dev.running_config())
    assert rejected == [] and state['enable_secret'] == 'Synthetic-Enable-1'
    assert line in state['global_lines']
    unknown = dev.running_config().replace(line, 'enable secret 5 $1$mock$notknown')
    state, _ = load_config_text(dev, unknown)
    assert state['enable_secret'] is None                       # enable would be refused


def test_loader_reports_rejected_lines_and_stops_at_end():
    dev = device()
    text = body(dev.running_config()).replace('\nend', '\nbogus command here\nend\nhostname AFTER-END')
    state, rejected = load_config_text(dev, text)
    assert [r[0] for r in rejected] == ['bogus command here']
    assert state['hostname'] == 'MOCK-R1'                        # nothing after "end"


# ---------------------------------------------------------------- configure replace
def test_successful_replace_with_list_matches_the_file_and_archives_the_old_one():
    dev = device()
    s = session(dev)
    before, startup = dev.running_config(), dev.startup
    target = target_config(dev, NTP_EXTRA, 'interface GigabitEthernet0/2',
                           'description Restored link')
    name, reply = replace(dev, s, body(target), 'list force time 5')
    out = reply.output
    assert '!List of Commands:' in out and NTP_EXTRA in out
    assert 'description Restored link' in out
    assert 'Total number of passes: 1' in out and 'Rollback Done' in out
    assert body(dev.running_config()) == body(target)
    archive = dev.archive_copies[-1]
    assert dev.flash.get(archive).data == before.encode()        # the archive copy
    assert dev.flash.get(name).kind == 'file'                    # the transfer file is apart
    assert dev.rollback is not None and dev.rollback.archive_name == archive
    assert dev.rollback.deadline == dev.clock.now() + 300
    assert dev.startup == startup and dev.saves == 0             # startup untouched
    timer = s.handle('show archive config rollback timer').output
    assert 'Timer value               : 5 min' in timer and '300 secs' in timer


def test_replace_never_touches_startup():
    dev = device()
    startup = dev.startup
    s = session(dev)
    replace(dev, s, body(target_config(dev, NTP_EXTRA)))
    s.handle('configure confirm')
    assert dev.startup == startup and dev.saves == 0


def test_confirm_before_expiry_cancels_the_rollback():
    dev = device()
    s = session(dev)
    target = target_config(dev, NTP_EXTRA)
    replace(dev, s, body(target))
    dev.clock.advance(299)
    assert s.handle('configure confirm').output == ''
    assert dev.rollback is None
    dev.clock.advance(3600)
    dev.tick()
    assert body(dev.running_config()) == body(target)            # kept
    assert s.handle('configure confirm').output == NO_PENDING
    assert s.handle('show archive config rollback timer').output == NO_PENDING
    assert [e[1] for e in dev.events].count('rollback') == 0


def test_timer_expiry_restores_the_previous_running_configuration():
    dev = device()
    s = session(dev)
    before = dev.running_config()
    replace(dev, s, body(target_config(dev, NTP_EXTRA)))
    dev.clock.advance(299)
    dev.tick()
    assert NTP_EXTRA in dev.running_config()                     # not yet
    dev.clock.advance(1)
    s.handle('show privilege')                                   # any command: timer fires
    assert dev.running_config() == before and dev.rollback is None
    assert ('rollback', 'timer expired') in [(e[1], e[2]) for e in dev.events]
    assert s.handle('configure confirm').output == NO_PENDING    # too late


def test_expiry_without_any_command_via_lab_advance(tmp_path):
    lab = Lab({'devices': [restore_spec(SPEC['MOCK-R1'], 'timer_expires')]},
              key_path=str(tmp_path / 'k.key'))
    dev = lab.devices['MOCK-R1']
    before = dev.running_config()
    s = session(dev)
    replace(dev, s, body(target_config(dev, NTP_EXTRA)), 'force time 3')
    lab.advance(180)
    assert dev.running_config() == before


def test_revert_now_and_revert_timer():
    dev = device()
    s = session(dev)
    before = dev.running_config()
    replace(dev, s, body(target_config(dev, NTP_EXTRA)))
    assert s.handle('configure revert timer 10').output == ''
    assert dev.rollback.deadline == dev.clock.now() + 600
    s.handle('configure revert timer idle 7')
    assert dev.rollback.minutes == 7
    assert s.handle('configure revert now').output == 'Rollback Done'
    assert dev.running_config() == before and dev.rollback is None
    assert s.handle('configure revert now').output == NO_PENDING


def test_replace_asks_without_force_and_is_never_answered_for_you():
    dev = device()
    s = session(dev)
    before = dev.running_config()
    name = upload(dev, s, body(target_config(dev, NTP_EXTRA)))
    out = s.handle(f'configure replace flash:{name} time 5').output
    assert out.endswith('? [no]: ') and s.pending is not None
    assert dev.running_config() == before                        # nothing yet
    s.handle('no')
    assert dev.running_config() == before and dev.rollback is None
    s.handle(f'configure replace flash:{name} time 5')
    assert 'Rollback Done' in s.handle('Y').output
    assert NTP_EXTRA in dev.running_config()


def test_replace_refusals_change_nothing():
    dev = device()
    s = session(dev)
    before = dev.running_config()
    assert 'File not found' in s.handle('configure replace flash:none.cfg force').output
    assert 'Is a directory' in s.handle('configure replace flash: force').output
    assert 'No such device' in s.handle('configure replace nvram:x force').output
    image = next(f.name for f in dev.flash.files.values() if f.kind == 'image')
    assert 'Invalid input' in s.handle(f'configure replace flash:{image} force').output
    assert 'Invalid input' in s.handle('configure replace flash:x force time 0').output
    assert dev.running_config() == before and dev.archive_copies == []


def test_a_second_replace_is_refused_while_a_rollback_is_pending():
    dev = device()
    s = session(dev)
    name, _ = replace(dev, s, body(target_config(dev, NTP_EXTRA)))
    current = dev.running_config()
    out = s.handle(f'configure replace flash:{name} force time 5').output
    assert 'already pending' in out and dev.running_config() == current


def test_missing_archive_refuses_the_timed_rollback():
    dev = device(scenario='no_archive')
    s = session(dev)
    before = dev.running_config()
    name = upload(dev, s, body(target_config(dev, NTP_EXTRA)))
    out = s.handle(f'configure replace flash:{name} force time 5').output
    assert 'needs the configuration archive' in out
    assert dev.running_config() == before and dev.rollback is None
    # without "time" IOS would replace with no way back: the simulation allows it
    s.handle(f'configure replace flash:{name} force')
    assert NTP_EXTRA in dev.running_config() and dev.rollback is None


def test_replace_unsupported():
    dev = device(scenario='replace_unsupported')
    s = session(dev)
    for line in ('configure replace flash:x force', 'configure confirm', 'configure revert now'):
        assert 'Invalid input' in s.handle(line).output
    assert 'Enter configuration commands' in s.handle('configure terminal').output


def test_partial_replace_applies_the_rest_and_can_be_reverted():
    dev = device(scenario='partial_replace')
    s = session(dev)
    before = dev.running_config()
    target = target_config(dev, NTP_EXTRA)
    _, reply = replace(dev, s, body(target))
    out = reply.output
    assert 'Rollback aborted after 5 passes' in out and 'transport input ssh' in out
    now = dev.running_config()
    assert NTP_EXTRA in now and now != target                    # partly applied
    assert any(e[1] == 'replace_partial' for e in dev.events)
    s.handle('configure revert now')
    assert dev.running_config() == before


def test_a_bad_line_in_the_file_is_a_partial_replace_too():
    dev = device()
    s = session(dev)
    text = body(target_config(dev, NTP_EXTRA)).replace('\nend', '\nnot-a-command 1\nend')
    _, reply = replace(dev, s, text)
    assert 'not-a-command 1' in reply.output and 'Rollback aborted' in reply.output


def test_failed_rollback_leaves_the_configuration_as_it_is():
    dev = device(scenario='rollback_fails')
    s = session(dev)
    target = target_config(dev, NTP_EXTRA)
    replace(dev, s, body(target))
    out = s.handle('configure revert now').output
    assert out.startswith('%Error: the rollback failed')
    assert body(dev.running_config()) == body(target) and dev.rollback is None
    dev2 = device(scenario='rollback_fails')
    s2 = session(dev2)
    replace(dev2, s2, body(target))
    dev2.clock.advance(300)
    dev2.tick()                                                  # the timer fails too
    assert NTP_EXTRA in dev2.running_config()
    assert [e[1] for e in dev2.events].count('rollback_failed') == 1


def test_rollback_fails_when_its_archive_copy_was_deleted():
    dev = device()
    s = session(dev)
    replace(dev, s, body(target_config(dev, NTP_EXTRA)))
    s.handle(f'delete /force flash:{dev.rollback.archive_name}')
    dev.clock.advance(300)
    dev.tick()
    assert NTP_EXTRA in dev.running_config()
    assert 'archive copy' in [e for e in dev.events if e[1] == 'rollback_failed'][0][2]


def test_verify_mismatch_makes_the_result_differ_from_the_file():
    dev = device(scenario='verify_mismatch')
    s = session(dev)
    target = target_config(dev, NTP_EXTRA)
    _, reply = replace(dev, s, body(target))
    assert 'Rollback Done' in reply.output                       # the device says success
    assert body(dev.running_config()) != body(target)
    assert MISMATCH_LINE in dev.running_config()
    s.handle('configure revert now')
    assert MISMATCH_LINE not in dev.running_config()


def test_drop_during_replace_applies_it_and_keeps_the_timer():
    dev = device(scenario='drop_during_replace')
    s = session(dev)
    before = dev.running_config()
    _, reply = replace(dev, s, body(target_config(dev, NTP_EXTRA)))
    assert reply.drop and reply.output == ''
    assert NTP_EXTRA in dev.running_config() and dev.rollback is not None
    dev.clock.advance(300)
    dev.tick()
    assert dev.running_config() == before


def test_reconnect_refused_until_rollback():
    dev = device(scenario='reconnect_refused')
    s = session(dev)
    replace(dev, s, body(target_config(dev, NTP_EXTRA)))
    assert dev.logins_refused
    s.handle('configure revert now')
    assert not dev.logins_refused


def test_management_ip_change_makes_the_device_unreachable_until_rollback():
    dev = device(scenario='management_ip_change')
    assert dev.management_ip == '192.168.10.1' and dev.reachable()
    s = session(dev)
    replace(dev, s, body(target_config(dev, 'interface GigabitEthernet0/0', 'no ip address')))
    assert not dev.reachable()
    dev.clock.advance(300)
    assert dev.reachable()                                       # the timer rolled it back
    assert any(i.ip == '192.168.10.1' for i in dev.interfaces.values())


def test_reboot_during_restore_falls_back_to_startup():
    dev = device(scenario='reboot_during_restore')
    s = session(dev)
    run(s, 'conf t', 'ntp server 192.0.2.77', 'end')             # an unsaved change
    _, reply = replace(dev, s, body(target_config(dev, NTP_EXTRA)))
    assert reply.drop
    assert dev.running_config() == dev.startup                   # the unsaved change is lost
    assert dev.rollback is None and dev.boot_count == 1
    assert not dev.reachable()
    dev.clock.advance(BOOT_SECONDS)
    assert dev.reachable()
    assert len(dev.archive_copies) == 1                          # flash survives a reload


def test_cleanup_failure():
    dev = device(scenario='cleanup_fails')
    s = session(dev)
    name, _ = replace(dev, s, body(target_config(dev, NTP_EXTRA)))
    out = s.handle(f'delete /force flash:{name}').output
    assert out.startswith(f'%Error deleting flash:/{name}')
    assert dev.flash.exists(name)
    assert s.handle(f'dir flash:{name}').output.startswith('Directory of')


def test_a_replace_restores_hostname_and_prompt():
    dev = device()
    s = session(dev)
    replace(dev, s, body(target_config(dev, 'hostname MOCK-R1-NEW')))
    assert s.prompt() == 'MOCK-R1-NEW#'
    s.handle('configure revert now')
    assert s.prompt() == 'MOCK-R1#'


def test_switch_replace_round_trip_with_vlans_and_ports():
    dev = device('SW1')
    s = session(dev)
    before = dev.running_config()
    target = target_config(dev, 'vlan 77', 'name RESTORED', 'interface FastEthernet0/2',
                           'switchport access vlan 77')
    replace(dev, s, body(target))
    assert body(dev.running_config()) == body(target)
    s.handle('configure revert now')
    assert dev.running_config() == before


# ---------------------------------------------------------------- scenarios and config
def test_every_restore_quirk_is_documented_and_every_scenario_builds():
    for quirk in RESTORE_QUIRKS:
        assert quirk in QUIRKS and QUIRKS[quirk]
    for name in RESTORE_SCENARIOS:
        for dev_name in SPEC:
            spec = restore_spec(SPEC[dev_name], name)
            check_config({'devices': [spec]})
            Device(spec, lab_hosts=HOSTS)
    assert 'archive' not in restore_spec(SPEC['MOCK-R1'], 'no_archive')
    with pytest.raises(ValueError):
        restore_spec(SPEC['MOCK-R1'], 'nope')


def test_restore_spec_does_not_change_the_lab_config():
    original = repr(SPEC['MOCK-R1'])
    restore_spec(SPEC['MOCK-R1'], 'scp')
    restore_spec(SPEC['MOCK-R1'], 'cleanup_fails')
    assert repr(SPEC['MOCK-R1']) == original


@pytest.mark.parametrize('change, message', [
    ({'management_ip': 'not-an-ip'}, 'management_ip'),
    ({'flash_bytes': 10}, 'flash_bytes'),
    ({'archive': 'flash:x'}, 'archive must be an object'),
    ({'archive': {'path': 'tftp://192.0.2.1/x'}}, 'archive path'),
    ({'archive': {'path': 'flash:a', 'maximum': 99}}, 'maximum'),
])
def test_config_check_refuses_bad_restore_keys(change, message):
    spec = dict(SPEC['MOCK-R1'], **change)
    with pytest.raises(LabError, match=message):
        check_config({'devices': [spec]})


def test_default_lab_is_unchanged_by_the_simulation():
    """No archive, no SCP, no management address, no restore quirk in lab_config.json:
    the default devices print the same running configuration as before Phase 4D."""
    for name, spec in SPEC.items():
        dev = Device(spec, lab_hosts=HOSTS)
        text = dev.running_config()
        assert '\narchive' not in text and 'ip scp' not in text
        assert dev.management_ip is None and dev.reachable()
        assert not dev.scp_enabled() and dev.rollback is None
        assert not set(spec.get('quirks') or []) & set(RESTORE_QUIRKS)
    assert set(CONFIG_ATTRS) >= {'hostname', 'interfaces', 'global_lines', 'archive'}


def test_ip_scp_server_enable_is_only_a_configuration_line():
    dev = Device(SPEC['MOCK-R1'], lab_hosts=HOSTS)
    s = session(dev)
    assert not dev.scp_enabled()
    run(s, 'conf t', 'ip scp server enable', 'end')
    assert dev.scp_enabled() and 'ip scp server enable' in dev.running_config()
    run(s, 'conf t', 'no ip scp server enable', 'end')
    assert not dev.scp_enabled()
    assert not device(scenario='scp', quirks=['no_scp']).scp_enabled()


# ---------------------------------------------------------------- end to end over SSH
netmiko = pytest.importorskip('netmiko')
from netmiko import ConnectHandler  # noqa: E402


@pytest.fixture(scope='module')
def key_path(tmp_path_factory):
    return str(tmp_path_factory.mktemp('mocklab-restore-key') / 'host_rsa.key')


def start_lab(key_path, scenario, name='MOCK-R1', quirks=None):
    spec = restore_spec(SPEC[name], scenario)
    if quirks is not None:
        spec['quirks'] = quirks
    return Lab({'devices': [spec], 'shared_scan_account': CONFIG['shared_scan_account']},
               key_path=key_path, overrides={name: ('127.0.0.1', 0)}).start()


def connect(lab, name='MOCK-R1', scan_account=False, **extra):
    """scan_account: the lab's synthetic privilege-15 account (SCP needs privilege 15)."""
    host, port = lab.address(name)
    assert host == '127.0.0.1'                                   # loopback only, never a device
    spec = CONFIG['shared_scan_account'] if scan_account else SPEC[name]
    conn = ConnectHandler(device_type='cisco_ios', host=host, port=port,
                          username=spec['username'], password=spec['password'],
                          secret=SPEC[name]['password'], conn_timeout=5, auth_timeout=5,
                          banner_timeout=5, **extra)
    conn.enable()
    return conn


@pytest.fixture
def lab_for(key_path):
    labs = []

    def make(scenario, name='MOCK-R1', quirks=None):
        lab = start_lab(key_path, scenario, name, quirks)
        labs.append(lab)
        return lab
    yield make
    for lab in labs:
        lab.stop()


def test_netmiko_inline_transfer_md5_replace_and_confirm(lab_for):
    from netmiko.cisco.cisco_ios import InLineTransfer
    lab = lab_for('success')
    dev = lab.devices['MOCK-R1']
    target = body(target_config(dev, NTP_EXTRA))
    name = dev.flash.temp_name()
    conn = connect(lab)
    try:
        with InLineTransfer(conn, source_config=target, dest_file=name,
                            file_system='flash:') as transfer:
            assert not transfer.check_file_exists()
            assert transfer.remote_space_available() == dev.flash.free()
            transfer.put_file()
            assert transfer.check_file_exists()
            assert transfer.remote_md5() == transfer.source_md5
        out = conn.send_command(f'configure replace flash:{name} force time 5', read_timeout=20)
        assert 'Rollback Done' in out
        assert conn.send_command('configure confirm') == ''
        assert dev.rollback is None and NTP_EXTRA in dev.running_config()
        assert conn.send_command(f'delete /force flash:{name}') == ''
        assert 'Error opening' in conn.send_command(f'dir flash:/{name}')
    finally:
        conn.disconnect()


def test_scp_putfo_only_when_already_enabled(lab_for):
    scp = pytest.importorskip('scp')
    off = lab_for('success')
    conn = connect(off, scan_account=True)
    try:
        with pytest.raises(Exception):
            scp.SCPClient(conn.remote_conn.get_transport()).putfo(io.BytesIO(b'x'), 'flash:/a.cfg')
        assert not off.devices['MOCK-R1'].flash.exists('a.cfg')
    finally:
        conn.disconnect()
    on = lab_for('scp')
    dev = on.devices['MOCK-R1']
    low = connect(on)                                            # not a privilege 15 login
    try:
        with pytest.raises(scp.SCPException, match='Privilege denied'):
            scp.SCPClient(low.remote_conn.get_transport()).putfo(io.BytesIO(b'x'), 'flash:/a.cfg')
        assert not dev.flash.exists('a.cfg')
    finally:
        low.disconnect()
    text = body(target_config(dev, NTP_EXTRA)).encode()
    conn = connect(on, scan_account=True)
    try:
        client = scp.SCPClient(conn.remote_conn.get_transport())
        client.putfo(io.BytesIO(text), 'flash:/nc-restore-scp.cfg')   # from memory only
        assert dev.flash.get('nc-restore-scp.cfg').data == text
        md5 = hashlib.md5(text).hexdigest()
        assert conn.send_command(f'verify /md5 flash:/nc-restore-scp.cfg {md5}').startswith('Verified')
        with pytest.raises(Exception):                         # never overwrites
            scp.SCPClient(conn.remote_conn.get_transport()).putfo(io.BytesIO(b'y'),
                                                                   'flash:/nc-restore-scp.cfg')
        assert dev.flash.get('nc-restore-scp.cfg').data == text
    finally:
        conn.disconnect()


def test_scp_transfer_fails_leaves_a_partial_file(lab_for):
    scp = pytest.importorskip('scp')
    lab = lab_for('scp', quirks=['transfer_fails'])
    conn = connect(lab, scan_account=True)
    with pytest.raises(Exception):
        scp.SCPClient(conn.remote_conn.get_transport(), socket_timeout=5).putfo(
            io.BytesIO(b'z' * 4000), 'flash:/part.cfg')
    part = lab.devices['MOCK-R1'].flash.get('part.cfg')
    assert part is not None and part.size == 2000
    assert any(e[1] == 'transfer_failed' for e in lab.devices['MOCK-R1'].events)


def _replace_over_ssh(lab, conn, text):
    dev = lab.devices['MOCK-R1']
    name = dev.flash.temp_name()
    restore_sim.store_transfer(dev, name, text.encode())         # transfer tested above
    return conn.send_command(f'configure replace flash:{name} force time 5', read_timeout=10)


def test_disconnect_during_replace_then_reconnect_and_timer_rollback(lab_for):
    lab = lab_for('drop_during_replace')
    dev = lab.devices['MOCK-R1']
    before = dev.running_config()
    conn = connect(lab)
    with pytest.raises(Exception):
        _replace_over_ssh(lab, conn, body(target_config(dev, NTP_EXTRA)))
    conn.disconnect()
    again = connect(lab)                                         # reconnection works
    try:
        assert NTP_EXTRA in again.send_command('show running-config')
        lab.advance(300)
        assert NTP_EXTRA not in again.send_command('show running-config')
        assert dev.running_config() == before
    finally:
        again.disconnect()


def test_management_ip_removed_cuts_ssh_until_rollback(lab_for):
    from netmiko.exceptions import NetmikoTimeoutException
    lab = lab_for('management_ip_change')
    dev = lab.devices['MOCK-R1']
    conn = connect(lab)
    with pytest.raises(Exception):
        _replace_over_ssh(lab, conn, body(target_config(dev, 'interface GigabitEthernet0/0',
                                                        'no ip address')))
    conn.disconnect()
    with pytest.raises((NetmikoTimeoutException, Exception)):
        connect(lab)
    lab.advance(300)
    again = connect(lab)
    try:
        assert 'ip address 192.168.10.1' in again.send_command('show running-config')
    finally:
        again.disconnect()


def test_reconnect_refused_over_ssh(lab_for):
    from netmiko.exceptions import NetmikoAuthenticationException
    lab = lab_for('reconnect_refused')
    dev = lab.devices['MOCK-R1']
    conn = connect(lab)
    try:
        assert 'Rollback Done' in _replace_over_ssh(lab, conn, body(target_config(dev, NTP_EXTRA)))
        with pytest.raises(NetmikoAuthenticationException):
            connect(lab)
        assert conn.send_command('configure revert now') == 'Rollback Done'   # old session
    finally:
        conn.disconnect()
    connect(lab).disconnect()                                    # logins work again


def test_reboot_during_restore_over_ssh(lab_for):
    lab = lab_for('reboot_during_restore')
    dev = lab.devices['MOCK-R1']
    conn = connect(lab)
    with pytest.raises(Exception):
        _replace_over_ssh(lab, conn, body(target_config(dev, NTP_EXTRA)))
    conn.disconnect()
    with pytest.raises(Exception):
        connect(lab)                                             # still booting
    lab.advance(BOOT_SECONDS)
    again = connect(lab)
    try:
        assert NTP_EXTRA not in again.send_command('show running-config')
    finally:
        again.disconnect()


def test_existing_apply_flow_still_works_on_a_restore_ready_device(lab_for):
    """Discovery-style show commands and a normal configuration change are unaffected
    by the archive section and the new exec commands."""
    lab = lab_for('success')
    conn = connect(lab)
    try:
        assert 'archive' in conn.send_command('show running-config')
        conn.send_config_set(['interface GigabitEthernet0/2', 'description After-4D'])
        assert 'description After-4D' in conn.send_command('show running-config')
        assert conn.send_command('show privilege') == 'Current privilege level is 15'
    finally:
        conn.disconnect()
