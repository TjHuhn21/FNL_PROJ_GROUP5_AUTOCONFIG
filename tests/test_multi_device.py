"""Configuring several devices: compatibility, sequential runs through the real
apply_config with fake SSH connections, per-device backups / checks / saves,
individual failures, stopping, and the summary. No device, no database."""
import threading

import pytest
from netmiko.exceptions import NetmikoAuthenticationException, NetmikoTimeoutException

from config import connect, multi
from test_ssh_session import FakeIOS

SW1 = {'id': 1, 'name': 'SW1', 'ip': '10.0.0.11', 'type': 'switch'}
SW2 = {'id': 2, 'name': 'SW2', 'ip': '10.0.0.12', 'type': 'switch'}
SW3 = {'id': 3, 'name': 'SW3', 'ip': '10.0.0.13', 'type': 'switch'}
R1 = {'id': 4, 'name': 'R1', 'ip': '10.0.0.1', 'type': 'router'}
AP = {'id': 5, 'name': 'AP-1', 'ip': '10.0.0.9', 'type': 'unknown'}
PASSWORD = 'Sup3r$ecret'
CHECKS = [('show vlan brief', 'STAFF')]
COMMANDS = ['vlan 10', 'name STAFF']


def job(d, commands=COMMANDS, checks=CHECKS):
    return {'device': d, 'commands': list(commands), 'checks': list(checks),
            'creds': {'host': d['ip'], 'username': 'admin', 'password': PASSWORD}}


@pytest.fixture
def lab(monkeypatch, tmp_path):
    """One FakeIOS per IP; `broken` maps an IP to an exception raised at login."""
    fakes = {d['ip']: FakeIOS(shows={'show vlan brief': '10   STAFF   active'})
             for d in (SW1, SW2, SW3, R1)}
    broken, opened = {}, []

    def open_(creds):
        opened.append(creds['host'])
        if creds['host'] in broken:
            raise broken[creds['host']]
        return fakes[creds['host']]
    monkeypatch.setattr(connect, '_open', open_)

    def apply_fn(creds, commands, checks, log=None):
        return connect.apply_config(creds, commands, checks, backup_dir=str(tmp_path), log=log)

    posted = []
    return {'fakes': fakes, 'broken': broken, 'opened': opened, 'apply': apply_fn,
            'posted': posted, 'post': lambda kind, text, name=None: posted.append((kind, text, name)),
            'backups': tmp_path}


# ---------------------------------------------------------------- compatibility
def test_switch_settings_only_go_to_switches():
    targets, skipped = multi.split_targets([SW1, R1, SW2, AP], 'switch')
    assert targets == [SW1, SW2]
    assert [(d['name'], why) for d, why in skipped] == [
        ('R1', 'switch settings cannot be sent to a router'),
        ('AP-1', 'its type is "unknown"; set it to switch or router on the Devices page '
                 'before sending switch settings')]


def test_router_settings_only_go_to_routers():
    targets, skipped = multi.split_targets([SW1, R1], 'router')
    assert targets == [R1] and skipped[0][0] == SW1
    assert 'router settings cannot be sent to a switch' == skipped[0][1]


def test_typed_commands_have_no_type_restriction():
    assert multi.incompatibility(R1, multi.CUSTOM) is None
    assert multi.incompatibility(AP, multi.CUSTOM) is None


# ---------------------------------------------------------------- running
def test_all_devices_succeed_each_with_its_own_backup_check_and_save(lab):
    results = multi.run_devices([job(SW1), job(SW2), job(SW3)], lab['apply'], post=lab['post'])
    assert [r['status'] for r in results] == ['SUCCESS'] * 3
    assert lab['opened'] == ['10.0.0.11', '10.0.0.12', '10.0.0.13']        # in order
    for d in (SW1, SW2, SW3):
        fake = lab['fakes'][d['ip']]
        assert fake.sent == COMMANDS and fake.saved and fake.closed
    backups = sorted(p.name for p in lab['backups'].iterdir())
    assert [b.split('_')[0] for b in backups] == ['10.0.0.11', '10.0.0.12', '10.0.0.13']
    assert all(r['backup'] and d['ip'] in r['backup'] for r, d in zip(results, (SW1, SW2, SW3)))
    # the console gets a heading per device, and each device's own lines
    heads = [t for k, t, _ in lab['posted'] if k == 'device']
    assert heads == ['DEVICE 1 OF 3:  SW1  (10.0.0.11)', 'DEVICE 2 OF 3:  SW2  (10.0.0.12)',
                     'DEVICE 3 OF 3:  SW3  (10.0.0.13)']
    assert {n for k, t, n in lab['posted'] if k == 'command'} == {'SW1', 'SW2', 'SW3'}
    assert sum(1 for k, t, _ in lab['posted'] if k == 'section' and t == 'VERIFICATION') == 3


def test_devices_run_one_after_the_other():
    active, peak, order = [0], [0], []
    lock = threading.Lock()

    def slow(creds, commands, checks, log=None):
        with lock:
            active[0] += 1
            peak[0] = max(peak[0], active[0])
        order.append(('start', creds['host']))
        threading.Event().wait(0.05)
        order.append(('end', creds['host']))
        with lock:
            active[0] -= 1
        return True, f"Applied and verified. Backup: backups/{creds['host']}.txt"
    multi.run_devices([job(SW1), job(SW2)], slow)
    assert peak[0] == 1
    assert order == [('start', '10.0.0.11'), ('end', '10.0.0.11'),
                     ('start', '10.0.0.12'), ('end', '10.0.0.12')]


@pytest.mark.parametrize('error, words', [
    (NetmikoAuthenticationException('x'), 'Wrong username or password'),
    (NetmikoTimeoutException('x'), 'No answer'),
])
def test_one_device_failing_does_not_fail_the_others(lab, error, words):
    lab['broken']['10.0.0.12'] = error
    seen = []
    results = multi.run_devices([job(SW1), job(SW2), job(SW3)], lab['apply'], post=lab['post'],
                                on_result=seen.append)
    assert [r['status'] for r in results] == ['SUCCESS', 'FAILED', 'SUCCESS']
    assert seen == results                                   # reported as each one finished
    assert words in results[1]['message'] and results[1]['backup'] is None
    assert lab['fakes']['10.0.0.11'].saved and lab['fakes']['10.0.0.13'].saved
    assert not lab['fakes']['10.0.0.12'].sent
    assert multi.counts(results) == {'completed': 2, 'failed': 1, 'not_run': 0, 'total': 3}


def test_failed_check_on_one_device_is_not_saved_there_only(lab):
    lab['fakes']['10.0.0.12'].shows['show vlan brief'] = '1   default   active'
    results = multi.run_devices([job(SW1), job(SW2), job(SW3)], lab['apply'])
    assert [r['status'] for r in results] == ['SUCCESS', multi.NOT_VERIFIED, 'SUCCESS']
    assert not lab['fakes']['10.0.0.12'].saved
    assert lab['fakes']['10.0.0.11'].saved and lab['fakes']['10.0.0.13'].saved
    assert results[1]['backup']                               # its backup is reported


def test_a_rejected_command_stops_the_remaining_devices(lab):
    lab['fakes']['10.0.0.11'].reject = {'name STAFF'}
    results = multi.run_devices([job(SW1), job(SW2), job(SW3)], lab['apply'], post=lab['post'])
    assert [r['status'] for r in results] == [multi.PARTIAL, multi.NOT_RUN, multi.NOT_RUN]
    assert lab['opened'] == ['10.0.0.11']                    # SW2 and SW3 never contacted
    assert 'rejected on SW1' in results[1]['message']
    assert any(k == 'warn' and n == 'SW2' and 'Not run' in t for k, t, n in lab['posted'])


def test_stop_on_failure_option(lab):
    lab['broken']['10.0.0.11'] = NetmikoAuthenticationException('x')
    results = multi.run_devices([job(SW1), job(SW2)], lab['apply'], stop_on_failure=True)
    assert [r['status'] for r in results] == ['FAILED', 'NOT RUN']
    assert lab['opened'] == ['10.0.0.11']


def test_stop_button_stops_before_the_next_device(lab):
    stop = threading.Event()
    results = multi.run_devices([job(SW1), job(SW2)], lab['apply'], stop=stop,
                                on_result=lambda r: stop.set())
    assert [r['status'] for r in results] == ['SUCCESS', 'NOT RUN']
    assert 'stopped by the user' in results[1]['message']


def test_a_crashing_apply_function_does_not_lose_the_other_devices(lab):
    def flaky(creds, commands, checks, log=None):
        if creds['host'] == '10.0.0.11':
            raise RuntimeError('socket closed')
        return lab['apply'](creds, commands, checks, log=log)
    results = multi.run_devices([job(SW1), job(SW2)], flaky, post=lab['post'])
    assert [r['status'] for r in results] == ['FAILED', 'SUCCESS']
    assert 'RuntimeError: socket closed' in results[0]['message']
    assert any(k == 'error' and n == 'SW1' and 'socket closed' in t for k, t, n in lab['posted'])


def test_three_argument_apply_functions_still_work():
    results = multi.run_devices([job(SW1)], lambda c, cmds, chk: (True, 'Applied and verified. '
                                                                       'Backup: b/x.txt'))
    assert results[0]['status'] == 'SUCCESS' and results[0]['backup'] == 'b/x.txt'


def test_passwords_never_reach_the_console(lab):
    multi.run_devices([job(SW1, commands=['username ops secret Hidden123'], checks=[]),
                       job(SW2)], lab['apply'], post=lab['post'])
    text = str(lab['posted'])
    assert PASSWORD not in text and 'Hidden123' not in text


# ---------------------------------------------------------------- summary
def test_summary_uses_the_real_results(lab):
    lab['broken']['10.0.0.12'] = NetmikoAuthenticationException('x')
    results = multi.run_devices([job(SW1), job(SW2), job(SW3)], lab['apply'])
    text = multi.summary_text(results, skipped=[(R1, 'switch settings cannot be sent to a router')])
    lines = text.splitlines()
    assert lines[:2] == ['MULTI-DEVICE CONFIGURATION SUMMARY', '']
    assert lines[2:4] == ['SW1 - 10.0.0.11', 'Status: SUCCESS']
    assert lines[4].startswith('Backup: ') and '10.0.0.11_' in lines[4]
    assert lines[6:9] == ['SW2 - 10.0.0.12', 'Status: FAILED', 'Reason: Wrong username or password.']
    assert 'R1 - 10.0.0.1' in lines and 'Status: SKIPPED (nothing sent)' in lines
    assert lines[-5:] == ['', 'Completed: 2', 'Failed: 1', 'Skipped (not compatible): 1', 'Total: 3']


def test_summary_helpers():
    assert multi.backup_path('Applied and verified. Backup: backups/a b.txt') == 'backups/a b.txt'
    msg = ('The device rejected a command: "x" (% Invalid). The change is partially applied: 1 of '
           '2 commands were applied before it, and it was not saved. Restore from the backup if '
           'needed: backups/1.txt')
    assert multi.backup_path(msg) == 'backups/1.txt'
    assert multi.classify(False, msg) == multi.PARTIAL
    assert multi.reason_of(msg).endswith('and it was not saved.')
    assert multi.classify(True, 'Applied and verified. Backup: x') == multi.SUCCESS
    assert multi.classify(False, 'Check failed: ...') == multi.NOT_VERIFIED
    assert multi.classify(False, 'Wrong username or password.') == multi.FAILED
