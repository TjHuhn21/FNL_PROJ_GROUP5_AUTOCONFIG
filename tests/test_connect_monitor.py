import os, sys
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))
import pytest
from netmiko.exceptions import NetmikoAuthenticationException, NetmikoTimeoutException

import db_fake
from config import connect
from monitor import monitor

CREDS = {'host': '192.168.1.3', 'username': 'admin', 'password': 'cisco123'}
# What a Cisco switch returns for show running-config (it always ends with "end").
RUNNING = 'Building configuration...\n\nCurrent configuration : 30 bytes\n!\nhostname SW1\n!\nend\n'


class Switch:
    """A fake device for apply_config: records what it was sent."""
    def __init__(self, reject=False, show_output='VLAN 10 SALES active'):
        self.sent, self.reject, self.show_output, self.saved, self.closed = [], reject, show_output, False, False

    def find_prompt(self): return 'SW1#'
    def enable(self): pass
    def send_command(self, cmd, **kw):
        if cmd == 'show privilege':
            return 'Current privilege level is 15'           # as a privileged IOS session
        return RUNNING if cmd == 'show running-config' else self.show_output
    def send_config_set(self, cmds, **kw):
        self.sent = list(cmds)
        return '% Invalid input detected at "^" marker.' if self.reject else ''
    def save_config(self): self.saved = True
    def disconnect(self): self.closed = True


def patch_open(monkeypatch, sw=None, error=None):
    def fake_open(creds):
        if error: raise error
        return sw
    monkeypatch.setattr(connect, '_open', fake_open)


def test_apply_backs_up_sends_checks_and_saves(monkeypatch, tmp_path, synthetic_backup_key):
    sw = Switch(); patch_open(monkeypatch, sw)
    ok, msg = connect.apply_config(CREDS, ['vlan 10', 'name SALES'], [('show vlan brief', 'SALES')],
                                   backup_dir=str(tmp_path))
    assert ok and 'Applied and verified' in msg
    assert sw.sent == ['vlan 10', 'name SALES'] and sw.saved and sw.closed
    files = list(tmp_path.iterdir())
    assert len(files) == 1 and files[0].suffix == '.ncbak'           # encrypted
    assert synthetic_backup_key.decrypt(files[0])[0] == RUNNING.encode()   # the OLD config


def test_comments_and_blank_lines_are_never_sent(monkeypatch, tmp_path):
    sw = Switch(); patch_open(monkeypatch, sw)
    connect.apply_config(CREDS, ['# EDIT this', '', 'vlan 10'], backup_dir=str(tmp_path))
    assert sw.sent == ['vlan 10']
    assert connect.apply_config(CREDS, ['# only a comment'], backup_dir=str(tmp_path))[0] is False


def test_rejected_command_is_reported_and_not_saved(monkeypatch, tmp_path):
    sw = Switch(reject=True); patch_open(monkeypatch, sw)
    ok, msg = connect.apply_config(CREDS, ['bad command'], backup_dir=str(tmp_path))
    assert not ok and 'rejected' in msg and not sw.saved
    assert sw.closed


def test_failed_check_is_reported(monkeypatch, tmp_path):
    sw = Switch(show_output='nothing here'); patch_open(monkeypatch, sw)
    ok, msg = connect.apply_config(CREDS, ['vlan 10'], [('show vlan brief', 'SALES')], backup_dir=str(tmp_path))
    assert not ok and 'Check failed' in msg and not sw.saved


@pytest.mark.parametrize('error,text', [
    (NetmikoTimeoutException('t'), 'No answer'),
    (NetmikoAuthenticationException('a'), 'Wrong username or password'),
    (RuntimeError('boom'), 'RuntimeError')])
def test_every_failure_is_a_clear_message_not_a_crash(monkeypatch, tmp_path, error, text):   # T7
    patch_open(monkeypatch, error=error)
    ok, msg = connect.apply_config(CREDS, ['vlan 10'], backup_dir=str(tmp_path))
    assert ok is False and text in msg


def test_get_config(monkeypatch):
    sw = Switch(); patch_open(monkeypatch, sw)
    assert connect.get_config(CREDS) == RUNNING and sw.closed


# ---------------------------------------------------------------- monitor
def test_monitor_needs_two_failures_and_only_logs_changes():
    db_fake.reset()
    a = db_fake.upsert_device({'name': 'SW1', 'ip': '10.0.0.1', 'type': 'switch', 'managed': True})
    up, fails = {'v': True}, {}
    check = lambda ip: up['v']
    assert monitor.check_all(db_fake, fails, check) == []                  # still up: nothing logged
    up['v'] = False
    assert monitor.check_all(db_fake, fails, check) == []                  # one failure: not down yet
    assert db_fake.get_device(a)['status'] == 'up'
    assert [n for _, n in monitor.check_all(db_fake, fails, check)] == ['down']
    assert monitor.check_all(db_fake, fails, check) == []                  # already down: no repeat alert
    up['v'] = True
    assert [n for _, n in monitor.check_all(db_fake, fails, check)] == ['up']
    assert [e['kind'] for e in db_fake.get_events()] == ['up', 'down']


def test_monitor_thread_starts_and_stops():
    db_fake.reset()
    db_fake.upsert_device({'name': 'SW1', 'ip': '10.0.0.1', 'type': 'switch', 'managed': True})
    seen = []
    stop = monitor.start_monitor(db_fake, interval=0.05, check=lambda ip: seen.append(ip) or True)
    import time; time.sleep(0.3); stop.set()
    assert len(seen) >= 2
