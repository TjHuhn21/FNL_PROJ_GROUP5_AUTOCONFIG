"""apply_config against a fake Cisco IOS device: the live SSH session log, rejected
commands, partial application, failed checks and connection errors.
No real device and no database are needed."""
import pytest
from netmiko.exceptions import NetmikoAuthenticationException, NetmikoTimeoutException

from config import connect

CREDS = {'host': '10.0.0.2', 'username': 'admin', 'password': 'S3cretPass!'}
# What a Cisco switch returns for show running-config (it always ends with "end").
RUNNING = 'Building configuration...\n\nCurrent configuration : 30 bytes\n!\nhostname SW1\n!\nend\n'


class FakeIOS:
    """Behaves like a Netmiko connection to a Cisco switch named SW1."""
    def __init__(self, reject=(), shows=None, start_prompt='SW1#', running=RUNNING):
        self.reject = set(reject)
        self.shows = shows or {}
        self.prompt = start_prompt
        self.running = running
        self.sent, self.saved, self.closed, self.in_config = [], False, False, False

    def find_prompt(self):
        return self.prompt

    def enable(self):
        self.prompt = 'SW1#'

    def send_command(self, cmd):
        if cmd == 'show running-config':
            return self.running
        if cmd == 'show privilege' and cmd not in self.shows:
            return 'Current privilege level is 15'           # as a privileged IOS session
        return self.shows.get(cmd, '')

    def config_mode(self):
        self.in_config = True
        return ('configure terminal\nEnter configuration commands, one per line.  '
                'End with CNTL/Z.\nSW1(config)#')

    def exit_config_mode(self):
        self.in_config = False
        return 'end\nSW1#'

    def send_config_set(self, cmds, enter_config_mode=True, exit_config_mode=True):
        assert self.in_config and not enter_config_mode and not exit_config_mode
        (cmd,) = cmds
        self.sent.append(cmd)
        if cmd in self.reject:
            return f"{cmd}\n{' ' * 10}^\n% Invalid input detected at '^' marker.\n\nSW1(config)#"
        nxt = 'SW1(config-vlan)#' if cmd.startswith('vlan') else \
            'SW1(config-if-range)#' if cmd.startswith('interface range') else 'SW1(config)#'
        return f'{cmd}\n{nxt}'

    def save_config(self):
        self.saved = True
        return 'write mem\nBuilding configuration...\n[OK]\nSW1#'

    def disconnect(self):
        self.closed = True


def run(monkeypatch, tmp_path, fake, commands, checks=()):
    monkeypatch.setattr(connect, '_open', lambda creds: fake)
    log = []
    ok, msg = connect.apply_config(CREDS, commands, checks, backup_dir=str(tmp_path),
                                   log=lambda kind, text: log.append((kind, text)))
    return ok, msg, log


def text_of(log):
    return '\n'.join(t for _, t in log)


def test_success_shows_every_stage_command_and_reply(monkeypatch, tmp_path):
    fake = FakeIOS(shows={'show vlan brief': '10   STAFF   active'})
    ok, msg, log = run(monkeypatch, tmp_path, fake, ['vlan 10', 'name STAFF'],
                       [('show vlan brief', 'STAFF')])
    assert ok and 'Applied and verified' in msg and fake.saved and fake.closed
    sections = [t for k, t in log if k == 'section']
    assert sections == ['CONNECT', 'BACKUP', 'CONFIGURATION', 'VERIFICATION', 'SAVE', 'RESULT']
    commands = [t for k, t in log if k == 'command']
    assert 'SW1# show running-config' in commands
    assert 'SW1(config)# vlan 10' in commands
    assert 'SW1(config-vlan)# name STAFF' in commands      # the prompt follows the device
    assert 'SW1# show vlan brief' in commands
    assert 'SW1# write mem' in commands
    assert any(k == 'output' and 'STAFF' in t for k, t in log)          # real reply shown
    assert any(k == 'output' and '[OK]' in t for k, t in log)           # save reply shown
    assert any(k == 'ok' and 'Encrypted backup saved and verified' in t for k, t in log)
    assert any(k == 'ok' and t.startswith('SUCCESS') for k, t in log)


def test_rejected_command_stops_and_reports_partial_application(monkeypatch, tmp_path):
    fake = FakeIOS(reject={'switchport trunk encapsulation dot1q'})
    cmds = ['vlan 10', 'name STAFF', 'interface Gi0/1', 'switchport trunk encapsulation dot1q',
            'switchport mode trunk']
    ok, msg, log = run(monkeypatch, tmp_path, fake, cmds)
    assert not ok and not fake.saved and fake.closed
    assert fake.sent == cmds[:4]                     # stopped at the rejected command
    assert 'rejected' in msg and 'partially applied: 3 of 5' in msg and 'backup' in msg
    assert any(k == 'output' and '% Invalid input' in t for k, t in log)
    assert any(k == 'error' and 'REJECTED: "switchport trunk encapsulation dot1q"' in t
               for k, t in log)
    assert any(k == 'warn' and 'PARTIALLY APPLIED' in t for k, t in log)
    assert 'VERIFICATION' not in [t for k, t in log if k == 'section']
    assert not fake.in_config                        # left configuration mode


def test_first_command_rejected_means_nothing_applied(monkeypatch, tmp_path):
    fake = FakeIOS(reject={'vlan 10'})
    ok, msg, log = run(monkeypatch, tmp_path, fake, ['vlan 10', 'name STAFF'])
    assert not ok and 'nothing was applied' in msg and fake.sent == ['vlan 10']
    assert any(k == 'warn' and 'Nothing was applied' in t for k, t in log)


def test_failed_check_is_not_saved(monkeypatch, tmp_path):
    fake = FakeIOS(shows={'show vlan brief': '1    default   active'})
    ok, msg, log = run(monkeypatch, tmp_path, fake, ['vlan 10', 'name STAFF'],
                       [('show vlan brief', 'STAFF')])
    assert not ok and 'Check failed' in msg and not fake.saved
    assert any(k == 'error' and 'CHECK FAILED' in t for k, t in log)
    assert 'SAVE' not in [t for k, t in log if k == 'section']
    assert any(k == 'error' and 'NOT saved' in t for k, t in log)


@pytest.mark.parametrize('error, message, logged', [
    (NetmikoTimeoutException('timed out'), 'No answer', 'No answer from 10.0.0.2'),
    (NetmikoAuthenticationException('auth'), 'Wrong username or password', 'refused the login'),
    (OSError('network unreachable'), 'Error: OSError', 'Could not connect'),
])
def test_connection_failures_are_reported(monkeypatch, tmp_path, error, message, logged):
    def boom(creds):
        raise error
    monkeypatch.setattr(connect, '_open', boom)
    log = []
    ok, msg = connect.apply_config(CREDS, ['vlan 10'], backup_dir=str(tmp_path),
                                   log=lambda k, t: log.append((k, t)))
    assert ok is False and message in msg
    assert any(k == 'error' and logged in t for k, t in log)
    assert list(tmp_path.iterdir()) == []            # no backup without a connection


def test_timeout_in_the_middle_of_the_session(monkeypatch, tmp_path):
    fake = FakeIOS()

    def stall(cmd):
        raise NetmikoTimeoutException('stopped')
    fake.send_command = stall
    ok, msg, log = run(monkeypatch, tmp_path, fake, ['vlan 10'])
    assert not ok and 'No answer' in msg and fake.closed
    assert any(k == 'error' and 'stopped answering' in t for k, t in log)


def test_credentials_never_appear_in_the_log(monkeypatch, tmp_path):
    fake = FakeIOS(start_prompt='SW1>', running='hostname SW1\nenable secret 5 $1$abc$XYZ\n'
                                                 'username admin password 0 S3cretPass!\nend\n')
    fake.netcommand_enabled = True
    ok, msg, log = run(monkeypatch, tmp_path, fake,
                       ['username backup secret Hidden123', 'snmp-server community Pub123 RO'])
    everything = text_of(log) + msg
    for secret in ('S3cretPass!', 'Hidden123', 'Pub123', '$1$abc$XYZ'):
        assert secret not in everything
    assert '********' in everything
    assert fake.sent[0] == 'username backup secret Hidden123'    # the device still gets it
    assert any(k == 'command' and t.endswith('> enable') for k, t in log)


def test_a_broken_log_callback_does_not_break_the_session(monkeypatch, tmp_path):
    fake = FakeIOS()
    monkeypatch.setattr(connect, '_open', lambda creds: fake)

    def bad_log(kind, text):
        raise RuntimeError('console gone')
    ok, msg = connect.apply_config(CREDS, ['vlan 10'], backup_dir=str(tmp_path), log=bad_log)
    assert ok and fake.saved


def test_long_backup_is_shortened_in_the_console_but_complete_on_disk(monkeypatch, tmp_path,
                                                                      synthetic_backup_key):
    running = ''.join(f'line {i}\n' for i in range(200)) + 'hostname SW1\nend\n'
    fake = FakeIOS(running=running)
    ok, msg, log = run(monkeypatch, tmp_path, fake, ['vlan 10'])
    assert ok
    backup_out = [t for k, t in log if k == 'output' and 'line 0' in t][0]
    assert 'line 24' in backup_out and 'line 25' not in backup_out
    assert any('177 more lines' in t for k, t in log if k == 'info')
    (file,) = list(tmp_path.iterdir())
    assert file.suffix == '.ncbak'
    assert synthetic_backup_key.decrypt(file)[0] == running.encode('utf-8')   # complete


def test_split_reply_and_rejection_helpers():
    assert connect.split_reply('vlan 10\nSW1(config-vlan)#', 'vlan 10') == ('', 'SW1(config-vlan)#')
    reply, prompt = connect.split_reply("bogus\n   ^\n% Invalid input detected\nSW1(config)#", 'bogus')
    assert prompt == 'SW1(config)#' and '% Invalid' in reply
    assert connect.rejection(reply) == '% Invalid input detected'
    assert connect.rejection('% Incomplete command.') == '% Incomplete command.'
    assert connect.rejection('Building configuration...\n[OK]') is None
    assert connect.mask('enable secret 5 abc') == 'enable secret 5 ********'
