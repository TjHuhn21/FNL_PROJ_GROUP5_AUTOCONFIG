"""console.detect: read-only device identification and SSH capability. Offline only.

* Parser tests use representative Cisco output written for these tests (in the format of
  IOS / IOS-XE / NX-OS; not captured from the lab hardware).
* ScriptedSession answers each show command from a dict (or raises), like ConsoleSession.
* MockLabSession runs the commands on the mock lab's simulated IOS CLI.
* One end-to-end test runs the REAL ConsoleSession + Netmiko cisco_ios_serial driver on a
  fake serial port (no COM port is opened) whose device is the mock lab CLI.
"""
import os
import sys

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, 'mock-lab'))

from console import detect, link  # noqa: E402
from console.detect import (DETECTION_COMMANDS, SshCapability, detect_device,  # noqa: E402
                            parse_interfaces, parse_ip_ssh, parse_rsa, parse_show_line,
                            parse_version, parse_vty, summarise_vty, management_candidate)
from console.link import ConsoleError, check_show_command  # noqa: E402
from mocklab.cli import Session as MockCli  # noqa: E402
from mocklab.device import Device as MockDevice  # noqa: E402
from mocklab.lab import LabError, check_config  # noqa: E402

S = SshCapability
INVALID = "              ^\n% Invalid input detected at '^' marker."

# ------------------------------------------------------------------ fixtures (text)
IOS_1941 = """Cisco IOS Software, C1900 Software (C1900-UNIVERSALK9-M), Version 15.4(3)M2, RELEASE SOFTWARE (fc2)
Technical Support: http://www.cisco.com/techsupport
Copyright (c) 1986-2015 by Cisco Systems, Inc.

ROM: System Bootstrap, Version 15.0(1r)M15, RELEASE SOFTWARE (fc1)

R1 uptime is 2 hours, 5 minutes
System returned to ROM by power-on
System image file is "flash0:c1900-universalk9-mz.SPA.154-3.M2.bin"

Cisco CISCO1941/K9 (revision 1.0) with 491520K/32768K bytes of memory.
Processor board ID FTX0000AAAA
2 Gigabit Ethernet interfaces
Configuration register is 0x2102
"""
IOS_2960_K9 = """Cisco IOS Software, C2960 Software (C2960-LANBASEK9-M), Version 15.0(2)SE11, RELEASE SOFTWARE (fc3)
Copyright (c) 1986-2017 by Cisco Systems, Inc.

SW1 uptime is 3 days, 1 hour
System image file is "flash:c2960-lanbasek9-mz.150-2.SE11.bin"

cisco WS-C2960-24TT-L (PowerPC405) processor (revision B0) with 65536K bytes of memory.
Model number                    : WS-C2960-24TT-L
Configuration register is 0xF
"""
IOS_2960_PLAIN = IOS_2960_K9.replace('LANBASEK9', 'LANBASE').replace('lanbasek9', 'lanbase')
IOS_XE_ISR = """Cisco IOS XE Software, Version 17.03.04a
Cisco IOS Software [Amsterdam], ISR Software (X86_64_LINUX_IOSD-UNIVERSALK9-M), Version 17.3.4a, RELEASE SOFTWARE (fc3)
Copyright (c) 1986-2021 by Cisco Systems, Inc.

BR1 uptime is 1 week, 2 days
System image file is "bootflash:isr4300-universalk9.17.03.04a.SPA.bin"

cisco ISR4331/K9 (1RU) processor with 1795979K/6147K bytes of memory.
Configuration register is 0x2102
"""
IOS_XE_9300 = """Cisco IOS XE Software, Version 17.06.05
Cisco IOS Software [Bengaluru], Catalyst L3 Switch Software (CAT9K_IOSXE), Version 17.6.5, RELEASE SOFTWARE (fc2)

CORE1 uptime is 10 weeks
System image file is "flash:packages.conf"

cisco C9300-24T (X86) processor with 1338934K/6147K bytes of memory.
Model Number                       : C9300-24T
"""
NXOS = """Cisco Nexus Operating System (NX-OS) Software
TAC support: http://www.cisco.com/tac
Software
  NXOS: version 9.3(8)
  NXOS image file is: bootflash:///nxos.9.3.8.bin
Hardware
  cisco Nexus9000 C93180YC-EX Chassis
  Device name: LEAF1
"""
OTHER_OS = 'Linux box 5.15.0 #1 SMP x86_64 GNU/Linux\n'

SSH_ON = """SSH Enabled - version 2.0
Authentication methods:publickey,keyboard-interactive,password
Authentication timeout: 120 secs; Authentication retries: 3
IOS Keys in SECSH format(ssh-rsa, base64 encoded): R1.lab.local
AAAAB3NzaC1yc2EAAAADAQABAAABAQC"""
SSH_OFF = """SSH Disabled - version 1.99
%Please create RSA keys to enable SSH (and of atleast 768 bits for SSH v2).
Authentication timeout: 120 secs; Authentication retries: 3
IOS Keys in SECSH format(ssh-rsa, base64 encoded): NONE"""
RSA_KEY = """% Key pair was generated at: 10:15:00 UTC Nov 18 2026
Key name: R1.lab.local
Key type: RSA KEYS
 Storage Device: not specified
 Usage: General Purpose Key
 Key is not exportable.
 Key Data:
  30820122 300D0609 2A864886 F70D0101 01050003 82010F00 3082010A 02820101"""
VTY_SSH = """line vty 0 4
 password 7 0822455D0A16
 login local
 transport input ssh
line vty 5 15
 login
 transport input none"""
VTY_TELNET = """line vty 0 4
 password 7 0822455D0A16
 login
 transport input telnet"""
SHOW_LINE = """   Tty Line Typ     Tx/Rx    A Modem  Roty AccO AccI  Uses  Noise Overruns  Int
*     0    0 CTY              -    -      -    -    -     0      0    0/0      -
      1    1 AUX   9600/9600  -    -      -    -    -     0      0    0/0      -
      2    2 VTY              -    -      -    -    -     0      0    0/0      -
      3    3 VTY              -    -      -    -    -     0      0    0/0      -
      4    4 VTY              -    -      -    -    -     0      0    0/0      -
      5    5 VTY              -    -      -    -    -     0      0    0/0      -
      6    6 VTY              -    -      -    -    -     0      0    0/0      -"""
BRIEF = """Interface              IP-Address      OK? Method Status                Protocol
GigabitEthernet0/0     192.168.10.1    YES manual up                    up
GigabitEthernet0/1     10.0.0.1        YES NVRAM  administratively down down
GigabitEthernet0/2     unassigned      YES unset  down                  down
Loopback0              1.1.1.1         YES manual up                    up"""
BRIEF_SWITCH = """Interface              IP-Address      OK? Method Status                Protocol
Vlan1                  192.168.1.2     YES manual up                    up
FastEthernet0/1        unassigned      YES unset  up                    up
FastEthernet0/2        unassigned      YES unset  down                  down"""
BRIEF_NO_IP = """Interface              IP-Address      OK? Method Status                Protocol
Vlan1                  unassigned      YES unset  administratively down down
FastEthernet0/1        unassigned      YES unset  up                    up"""


def healthy(version=IOS_1941, **changes):
    """Answers of a privileged classic IOS router with SSH enabled."""
    answers = {
        'show version': version,
        'show privilege': 'Current privilege level is 15',
        'show running-config | include hostname': 'hostname R1',
        'show ip ssh': SSH_ON,
        'show crypto key mypubkey rsa': RSA_KEY,
        'show running-config | include username':
            'username admin privilege 15 secret 9 $9$abcdefghijkl$XYZsecretHASH',
        'show running-config | section line vty': VTY_SSH,
        'show line': SHOW_LINE,
        'show ip interface brief': BRIEF,
        'show running-config | include ip domain': 'ip domain-name lab.local',
        'show running-config | include ip ssh': 'ip ssh version 2',
        'show running-config | include aaa': '',
        detect.SHOW_GATEWAY: '',                       # no default gateway
    }
    answers.update(changes)
    return answers


ROUTER_COMMANDS = tuple(c for c in DETECTION_COMMANDS if c != detect.SHOW_VLAN)  # switches only


# ------------------------------------------------------------------ fake sessions
class ScriptedSession:
    """Behaves like ConsoleSession: answers come from a dict; a value that is an
    exception is raised. A ConsoleError with kind timeout/port_unavailable ends the
    session, as ConsoleSession does."""

    def __init__(self, answers, prompt='R1#', enable_to='R1#'):
        self.answers, self.prompt = answers, prompt
        self.enable_to = enable_to
        self.sent = []
        self.active = True

    def is_active(self):
        return self.active

    def find_prompt(self):
        if not self.active:
            raise ConsoleError(link.NOT_CONNECTED, 'Not connected.')
        return self.prompt

    def enable(self):
        self.sent.append('enable')
        if self.enable_to is None:
            raise ConsoleError(link.AUTH, 'The device refused the enable password.')
        self.prompt = self.enable_to
        return self.prompt

    def send_show(self, command, timeout=None):
        if not self.active:
            raise ConsoleError(link.NOT_CONNECTED, 'Not connected. Connect to the console first.')
        check_show_command(command)                       # the real guard
        self.sent.append(command)
        answer = self.answers.get(command, INVALID)
        if isinstance(answer, Exception):
            if isinstance(answer, ConsoleError) and answer.kind != link.REFUSED:
                self.active = False
            raise answer
        return answer


def mock_spec(kind='router', condition=None, privileged=True, **extra):
    spec = {'name': 'R1' if kind == 'router' else 'SW1', 'type': kind, 'host': '127.0.0.11',
            'username': 'labadmin', 'password': 'Lab-pass-1', 'start_privileged': privileged,
            'ports': {'GigabitEthernet': 2} if kind == 'router' else {'FastEthernet': 4,
                                                                      'GigabitEthernet': 2},
            'interfaces': ({'GigabitEthernet0/0': {'ip': '192.168.10.1', 'mask': '255.255.255.0',
                                                   'shutdown': False, 'connected': True}}
                           if kind == 'router' else
                           {'Vlan1': {'ip': '192.168.1.2', 'mask': '255.255.255.0',
                                      'shutdown': False}}),
            'global_lines': ['ip domain-name lab.local',
                             'username labadmin privilege 15 password 0 Lab-SW2-pass'],
            'line_config': {'con 0': [], 'vty 0 4': ['login local', 'transport input ssh']}}
    if condition:
        spec['ssh_condition'] = condition
    spec.update(extra)
    return spec


class MockLabSession(ScriptedSession):
    """The mock lab's simulated IOS CLI behind the ConsoleSession interface."""

    def __init__(self, spec):
        self.device = MockDevice(spec)
        self.cli = MockCli(self.device)
        super().__init__({}, prompt=self.cli.prompt())

    def find_prompt(self):
        return self.cli.prompt()

    def enable(self):
        self.sent.append('enable')
        self.cli.handle('enable')
        self.cli.handle(self.device.enable_secret)
        return self.cli.prompt()

    def send_show(self, command, timeout=None):
        check_show_command(command)
        self.sent.append(command)
        return self.cli.handle(command).output


FORBIDDEN = ('configure', 'conf t', 'hostname', 'ip address', 'username', 'crypto key generate',
             'write', 'copy', 'reload', 'no ', 'line ', 'transport', 'ip ssh', 'erase', 'delete')


def assert_read_only(sent):
    for line in sent:
        assert line == 'enable' or line in DETECTION_COMMANDS, line
        assert not line.startswith(FORBIDDEN), line


# ------------------------------------------------------------------ device identification
def test_classic_ios_router():
    d = parse_version(IOS_1941)
    assert (d.software, d.manufacturer, d.version) == ('IOS', 'Cisco', '15.4(3)M2')
    assert d.model == 'CISCO1941/K9'
    assert d.image == 'c1900-universalk9-mz.SPA.154-3.M2.bin'
    assert d.image_path == 'flash0:c1900-universalk9-mz.SPA.154-3.M2.bin'
    assert (d.platform, d.feature_set) == ('C1900', 'C1900-UNIVERSALK9-M')
    assert d.crypto_image is True and d.device_type == 'router'
    assert (d.hostname, d.hostname_source) == ('R1', 'show version')


def test_classic_ios_switch():
    d = parse_version(IOS_2960_K9)
    assert d.device_type == 'switch' and d.model == 'WS-C2960-24TT-L'
    assert d.version == '15.0(2)SE11' and d.crypto_image is True and d.platform == 'C2960'


def test_image_without_k9():
    d = parse_version(IOS_2960_PLAIN)
    assert d.feature_set == 'C2960-LANBASE-M' and d.crypto_image is False


def test_ios_xe_router():
    d = parse_version(IOS_XE_ISR)
    assert d.software == 'IOS-XE' and d.version == '17.03.04a'
    assert d.model == 'ISR4331/K9' and d.platform == 'ISR' and d.device_type == 'router'
    assert d.image == 'isr4300-universalk9.17.03.04a.SPA.bin' and d.crypto_image is True


def test_ios_xe_switch():
    d = parse_version(IOS_XE_9300)
    assert d.software == 'IOS-XE' and d.device_type == 'switch' and d.model == 'C9300-24T'
    assert d.feature_set == 'CAT9K_IOSXE'
    assert d.crypto_image is None             # IOS-XE names do not follow the K9 convention


def test_nx_os():
    d = parse_version(NXOS)
    assert d.software == 'NX-OS' and d.version == '9.3(8)' and d.image == 'nxos.9.3.8.bin'
    assert d.model == 'Nexus9000 C93180YC-EX' and d.manufacturer == 'Cisco'


def test_unknown_device():
    d = parse_version(OTHER_OS)
    assert d.software is None and d.manufacturer is None and d.model is None
    assert d.device_type == 'unknown' and d.crypto_image is None and d.image is None
    assert parse_version('System image file is "flash:odd.bin"').crypto_image is None


def test_hostname_prefers_running_config_then_prompt():
    r = detect_device(ScriptedSession(healthy(**{
        'show running-config | include hostname': 'hostname Edge-R1'})))
    assert (r.device.hostname, r.device.hostname_source) == ('Edge-R1', 'running-config')
    r = detect_device(ScriptedSession(healthy(version=OTHER_OS, **{
        'show running-config | include hostname': INVALID}), prompt='box1#'))
    assert (r.device.hostname, r.device.hostname_source) == ('box1', 'prompt')


# ------------------------------------------------------------------ SSH classification
def test_ssh_enabled():
    r = detect_device(ScriptedSession(healthy()))
    assert r.ssh.status == S.SUPPORTED_ENABLED and r.ssh.enabled and r.ssh.version == '2.0'
    assert r.ssh.rsa.present and r.ssh.rsa.key_names == ['R1.lab.local']
    assert any('SSH Enabled' in e for e in r.ssh.evidence)
    assert r.ssh.config_present is True and r.complete and not r.failed


def test_ssh_supported_but_disabled():
    r = detect_device(ScriptedSession(healthy(**{'show ip ssh': SSH_OFF,
                                                 'show crypto key mypubkey rsa': ''})))
    assert r.ssh.status == S.SUPPORTED_DISABLED and r.ssh.enabled is False
    assert r.ssh.version == '1.99' and r.ssh.rsa.present is False
    assert any('RSA keys must be created' in e for e in r.ssh.evidence)


def test_ssh_unsupported_needs_clear_evidence():
    answers = healthy(version=IOS_2960_PLAIN, **{'show ip ssh': INVALID,
                                                'show crypto key mypubkey rsa': INVALID})
    r = detect_device(ScriptedSession(answers, prompt='SW1#'))
    assert r.ssh.status == S.UNSUPPORTED
    assert any('no crypto' in e for e in r.ssh.evidence)
    assert any('does not show that SSH is unsupported' in e for e in r.ssh.evidence)
    assert r.limitations and 'not been confirmed' in r.limitations[0]


@pytest.mark.parametrize('why, changes, prompt', [
    ('K9 image', {}, 'SW1#'),
    ('privilege 1', {'show privilege': 'Current privilege level is 1'}, 'SW1>'),
    ('privilege unknown', {'show privilege': INVALID}, 'SW1#'),
    ('rsa command works', {'show crypto key mypubkey rsa': RSA_KEY}, 'SW1#'),
    ('timeout, not rejection', {'show ip ssh': ConsoleError(link.TIMEOUT, 'timed out')}, 'SW1#'),
])
def test_a_failed_show_ip_ssh_alone_is_not_unsupported(why, changes, prompt):
    version = IOS_2960_K9 if why == 'K9 image' else IOS_2960_PLAIN
    answers = healthy(version=version, **{'show ip ssh': INVALID,
                                          'show crypto key mypubkey rsa': INVALID})
    answers.update(changes)
    r = detect_device(ScriptedSession(answers, prompt=prompt))
    assert r.ssh.status == S.UNKNOWN, why


@pytest.mark.parametrize('version', [IOS_XE_ISR, IOS_XE_9300, NXOS, OTHER_OS])
def test_other_software_is_never_called_unsupported(version):
    answers = healthy(version=version, **{'show ip ssh': INVALID,
                                          'show crypto key mypubkey rsa': INVALID})
    r = detect_device(ScriptedSession(answers))
    assert r.ssh.status == S.UNKNOWN


def test_nx_os_explains_why():
    r = detect_device(ScriptedSession(healthy(version=NXOS, **{
        'show ip ssh': INVALID, 'show crypto key mypubkey rsa': INVALID})))
    assert any('NX-OS uses different commands' in e for e in r.ssh.evidence)
    assert any('NX-OS' in l for l in r.limitations)


def test_unknown_when_ssh_commands_are_blocked_by_authorization():
    denied = '% Command authorization failed.'
    r = detect_device(ScriptedSession(healthy(**{'show ip ssh': denied,
                                                 'show crypto key mypubkey rsa': denied})))
    assert r.ssh.status == S.UNKNOWN
    assert r.command('show ip ssh').status == detect.DENIED
    assert any('authorization' in e for e in r.ssh.evidence)


def test_unknown_when_show_ip_ssh_output_is_unexpected():
    r = detect_device(ScriptedSession(healthy(**{'show ip ssh': 'something unusual'})))
    assert r.ssh.status == S.UNKNOWN
    assert any('not recognised' in w for w in r.warnings)


def test_conflicting_evidence_is_unknown():
    r = detect_device(ScriptedSession(healthy(**{'show crypto key mypubkey rsa': ''})))
    assert r.ssh.status == S.UNKNOWN
    assert any('Contradictory' in w for w in r.warnings)


def test_disabled_from_missing_keys_when_show_ip_ssh_is_blocked():
    r = detect_device(ScriptedSession(healthy(**{'show ip ssh': '% Command authorization failed.',
                                                 'show crypto key mypubkey rsa': ''})))
    assert r.ssh.status == S.SUPPORTED_DISABLED
    assert any('No RSA key pair exists' in e for e in r.ssh.evidence)


def test_keys_present_but_state_unreadable_is_unknown():
    r = detect_device(ScriptedSession(healthy(**{'show ip ssh': INVALID})))
    assert r.ssh.status == S.UNKNOWN
    assert any('RSA key pair present' in e for e in r.ssh.evidence)


# ------------------------------------------------------------------ RSA keys
def test_rsa_parsing():
    info = parse_rsa(RSA_KEY)
    assert info.present and info.key_names == ['R1.lab.local']
    assert info.usage == 'General Purpose Key' and info.modulus_bits is None
    assert parse_rsa('').present is False
    assert parse_rsa('Key name: R1.x\n Modulus size (bits): 2048').modulus_bits == 2048
    assert parse_rsa('garbage output') is None


def test_rsa_command_unavailable():
    r = detect_device(ScriptedSession(healthy(**{'show crypto key mypubkey rsa': INVALID})))
    assert r.ssh.rsa.present is None
    assert r.ssh.status == S.SUPPORTED_ENABLED           # show ip ssh is still clear


def test_unexpected_rsa_output():
    r = detect_device(ScriptedSession(healthy(**{'show crypto key mypubkey rsa': 'odd'})))
    assert r.ssh.rsa.present is None
    assert any('mypubkey' in w for w in r.warnings)


def test_only_self_signed_key_warns():
    text = RSA_KEY.replace('R1.lab.local', 'TP-self-signed-12345')
    r = detect_device(ScriptedSession(healthy(**{'show crypto key mypubkey rsa': text})))
    assert any('TP-self-signed' in w for w in r.warnings)


# ------------------------------------------------------------------ VTY
def test_vty_with_ssh():
    v = summarise_vty(parse_vty(VTY_SSH), True)
    assert v.configured and v.ranges == ['0 4', '5 15']
    assert v.ssh_transport is True and v.login_configured is True
    assert v.blocks[0].login == 'local' and v.blocks[0].has_password
    assert v.blocks[1].transport_input == ['none']


def test_vty_without_ssh_transport():
    v = summarise_vty(parse_vty(VTY_TELNET), True)
    assert v.ssh_transport is False and v.login_configured is True


def test_vty_transport_not_shown_is_unknown():
    v = summarise_vty(parse_vty('line vty 0 4\n login local'), True)
    assert v.ssh_transport is None and v.login_configured is True


def test_vty_login_without_password():
    v = summarise_vty(parse_vty('line vty 0 4\n login\n transport input ssh'), True)
    assert v.login_configured is False


def test_vty_aaa_login():
    v = summarise_vty(parse_vty('line vty 0 15\n login authentication VTY\n transport input all'),
                      True)
    assert v.blocks[0].login == 'authentication VTY' and v.ssh_transport is True


def test_missing_vty_configuration():
    v = summarise_vty(parse_vty(''), True)
    assert v.configured is False and v.ranges == []


def test_vty_password_is_never_kept():
    r = detect_device(ScriptedSession(healthy()))
    out = r.command('show running-config | section line vty').output
    assert '0822455D0A16' not in out and '********' in out
    assert '0822455D0A16' not in repr(r.to_dict())


def test_vty_unreadable_without_privilege():
    r = detect_device(ScriptedSession(healthy(**{
        'show running-config | section line vty': INVALID,
        'show running-config | include hostname': INVALID,
        'show running-config | include username': INVALID})))
    assert r.vty.configured is None and r.vty.ssh_transport is None
    assert r.access.config_readable is False


def test_show_line_counts_vty_lines():
    assert parse_show_line(SHOW_LINE) == 5
    assert parse_show_line('nothing') is None


# ------------------------------------------------------------------ management interfaces
def test_interfaces_parsed():
    found = parse_interfaces(BRIEF)
    assert [i.name for i in found] == ['GigabitEthernet0/0', 'GigabitEthernet0/1',
                                       'GigabitEthernet0/2', 'Loopback0']
    assert found[1].status == 'administratively down' and not found[1].up
    assert found[2].ip is None


def test_management_ip_present_and_multiple_ips():
    name, reason = management_candidate(parse_interfaces(BRIEF))
    assert name == 'GigabitEthernet0/0' and '192.168.10.1' in reason   # not the loopback


def test_switch_vlan_interface_is_management():
    assert management_candidate(parse_interfaces(BRIEF_SWITCH))[0] == 'Vlan1'


def test_no_management_ip():
    name, reason = management_candidate(parse_interfaces(BRIEF_NO_IP))
    assert name is None and 'no interface has an IP address' in reason


def test_admin_down_interface_with_ip_is_not_chosen():
    text = BRIEF.splitlines()[0] + '\n' + BRIEF.splitlines()[2]
    name, reason = management_candidate(parse_interfaces(text))
    assert name is None and 'not up' in reason


def test_interface_command_unavailable():
    r = detect_device(ScriptedSession(healthy(**{'show ip interface brief': INVALID})))
    assert r.interfaces == [] and r.management_interface is None
    assert r.ssh.status == S.SUPPORTED_ENABLED


# ------------------------------------------------------------------ error handling
def test_individual_command_rejection_does_not_stop_detection():
    r = detect_device(ScriptedSession(healthy(**{'show privilege': INVALID})))
    assert r.complete and len(r.commands) == len(ROUTER_COMMANDS)
    assert [c.command for c in r.failed] == ['show privilege']
    assert r.access.privilege_level is None


def test_command_timeout_keeps_partial_results():
    session = ScriptedSession(healthy(**{'show crypto key mypubkey rsa':
                                         ConsoleError(link.TIMEOUT, 'stopped answering')}))
    r = detect_device(session)
    assert not r.complete
    assert r.command('show version').ok and r.device.model == 'CISCO1941/K9'
    assert r.ssh.status == S.SUPPORTED_ENABLED                 # read before the timeout
    skipped = [c.command for c in r.commands if c.status == detect.SKIPPED]
    assert skipped == list(ROUTER_COMMANDS[5:])
    assert any('partial' in w for w in r.warnings)


def test_disconnect_during_detection():
    session = ScriptedSession(healthy())
    original = session.send_show

    def unplug(command, timeout=None):
        if command == 'show line':
            session.active = False
            raise ConsoleError(link.PORT_UNAVAILABLE, 'COM4 stopped working')
        return original(command, timeout)
    session.send_show = unplug
    r = detect_device(session)
    assert not r.complete and r.vty.configured is True
    assert r.command('show ip interface brief').status == detect.SKIPPED


def test_unexpected_output_everywhere():
    answers = {c: 'unexpected text' for c in DETECTION_COMMANDS}
    r = detect_device(ScriptedSession(answers))
    assert r.complete
    assert r.device.software is None and r.ssh.status == S.UNKNOWN
    assert r.access.privilege_level is None and r.interfaces == []


def test_inactive_session_is_refused():
    session = ScriptedSession(healthy())
    session.active = False
    with pytest.raises(ConsoleError) as err:
        detect_device(session)
    assert err.value.kind == link.NOT_CONNECTED
    assert session.sent == []


def test_user_mode_without_elevation():
    answers = healthy(**{'show privilege': 'Current privilege level is 1'})
    for c in ('show ip ssh', 'show crypto key mypubkey rsa',
              'show running-config | include hostname', 'show running-config | include username',
              'show running-config | section line vty'):
        answers[c] = INVALID
    session = ScriptedSession(answers, prompt='R1>')
    r = detect_device(session)
    assert 'enable' not in session.sent
    assert r.access.privilege_level == 1 and r.access.privileged_exec is None
    assert r.ssh.status == S.UNKNOWN
    assert any('Privilege level 1' in e for e in r.ssh.evidence)
    assert any('without trying "enable"' in l for l in r.limitations)


def test_elevation_when_asked():
    session = ScriptedSession(healthy(), prompt='R1>')
    r = detect_device(session, elevate=True)
    assert session.sent[0] == 'enable' and r.access.privileged_exec is True


def test_elevation_refused():
    session = ScriptedSession(healthy(), prompt='R1>', enable_to=None)
    r = detect_device(session, elevate=True)
    assert r.access.privileged_exec is False
    assert any('enable' in w for w in r.warnings)


def test_progress_callback_errors_are_ignored():
    def bad(text):
        raise RuntimeError('broken')
    detect_device(ScriptedSession(healthy()), progress=bad)


def test_usernames_kept_without_secrets():
    r = detect_device(ScriptedSession(healthy()))
    assert r.ssh.local_usernames == ['admin']
    assert 'XYZsecretHASH' not in repr(r.to_dict())


def test_summary_text():
    text = detect_device(ScriptedSession(healthy())).summary()
    assert 'R1 (router)' in text and 'SSH: supported_enabled (version 2.0)' in text


# ------------------------------------------------------------------ safety
FAILURE_CASES = [
    healthy(),
    healthy(**{'show ip ssh': SSH_OFF, 'show crypto key mypubkey rsa': ''}),
    healthy(version=IOS_2960_PLAIN, **{'show ip ssh': INVALID,
                                       'show crypto key mypubkey rsa': INVALID}),
    {c: INVALID for c in DETECTION_COMMANDS},
    {c: '% Command authorization failed.' for c in DETECTION_COMMANDS},
    healthy(**{'show ip ssh': ConsoleError(link.TIMEOUT, 'timeout')}),
]


@pytest.mark.parametrize('answers', FAILURE_CASES)
@pytest.mark.parametrize('elevate', [False, True])
def test_detection_only_sends_read_only_commands(answers, elevate):
    session = ScriptedSession(answers, prompt='R1>')
    detect_device(session, elevate=elevate)
    assert_read_only(session.sent)
    for forbidden in ('configure terminal', 'hostname', 'ip address', 'username',
                      'crypto key generate', 'write memory', 'copy running-config '
                      'startup-config'):
        assert not any(s.startswith(forbidden) for s in session.sent)


def test_detection_commands_all_pass_the_show_guard():
    for command in DETECTION_COMMANDS:
        assert check_show_command(command) == command


# ------------------------------------------------------------------ mock lab
@pytest.mark.parametrize('kind, condition, expected', [
    ('router', 'enabled', S.SUPPORTED_ENABLED),
    ('router', 'disabled', S.SUPPORTED_DISABLED),
    ('router', 'unsupported', S.UNSUPPORTED),
    ('router', 'unknown', S.UNKNOWN),
    ('switch', 'enabled', S.SUPPORTED_ENABLED),
    ('switch', 'disabled', S.SUPPORTED_DISABLED),
    ('switch', 'unsupported', S.UNSUPPORTED),
    ('switch', 'unknown', S.UNKNOWN),
])
def test_mock_lab_conditions(kind, condition, expected):
    session = MockLabSession(mock_spec(kind, condition))
    before = session.device.running_config()
    r = detect_device(session)
    assert r.ssh.status == expected, r.ssh.evidence
    assert r.simulated and r.warnings[0] == detect.SIMULATION_WARNING
    assert r.device.manufacturer is None                    # never presented as Cisco hardware
    assert r.device.device_type == kind
    assert r.device.hostname == ('R1' if kind == 'router' else 'SW1')
    assert r.vty.ssh_transport is True and r.vty.ranges == ['0 4']
    assert r.vty.available_lines == 5
    assert r.management_interface == ('GigabitEthernet0/0' if kind == 'router' else 'Vlan1')
    assert r.ssh.local_usernames == ['labadmin']
    assert 'Lab-SW2-pass' not in repr(r.to_dict())
    assert session.device.running_config() == before and session.device.saves == 0
    assert_read_only(session.sent)


def test_mock_lab_default_device_is_unchanged_and_enabled():
    session = MockLabSession(mock_spec('router'))
    r = detect_device(session)
    assert r.simulated and r.device.software is None        # original mock show version
    assert r.ssh.status == S.SUPPORTED_ENABLED


def test_mock_lab_user_mode_is_unknown():
    session = MockLabSession(mock_spec('router', 'enabled', privileged=False))
    r = detect_device(session)
    assert r.access.privilege_level == 1 and r.ssh.status == S.UNKNOWN
    r = detect_device(MockLabSession(mock_spec('router', 'enabled', privileged=False)),
                      elevate=True)
    assert r.access.privileged_exec and r.ssh.status == S.SUPPORTED_ENABLED


def test_mock_lab_new_commands():
    dev = MockDevice(mock_spec('router', 'disabled'))
    cli = MockCli(dev)
    assert 'SSH Disabled' in cli.handle('show ip ssh').output
    assert cli.handle('show crypto key mypubkey rsa').output == ''
    assert 'VTY' in cli.handle('show line').output
    assert cli.handle('show running-config | include hostname').output == 'hostname R1'
    assert cli.handle('show running-config | section line vty').output.startswith('line vty 0 4')
    # generating keys in the simulation turns SSH on (as on IOS)
    cli.handle('configure terminal')
    cli.handle('crypto key generate rsa')
    cli.handle('end')
    assert 'SSH Enabled' in cli.handle('show ip ssh').output
    assert 'Key name: R1.lab.local' in cli.handle('show crypto key mypubkey rsa').output


def test_mock_lab_unsupported_has_no_ssh_commands():
    cli = MockCli(MockDevice(mock_spec('switch', 'unsupported')))
    assert 'Invalid input' in cli.handle('show ip ssh').output
    assert 'Invalid input' in cli.handle('show crypto key mypubkey rsa').output
    cli.handle('configure terminal')
    assert 'Invalid input' in cli.handle('crypto key generate rsa').output
    assert 'Invalid input' in cli.handle('ip ssh version 2').output


def test_mock_lab_condition_is_validated():
    spec = mock_spec('router', 'sometimes')
    with pytest.raises(LabError):
        check_config({'devices': [spec]})


# ------------------------------------------------------------------ end to end
class MockLabConsole:
    """The mock lab CLI as the device behind test_console_link.FakeSerial."""

    def __init__(self, spec):
        self.device = MockDevice(spec)
        self.cli = MockCli(self.device)
        self.lines = []
        self.hide_next = False

    def line(self, text):
        self.lines.append(text)
        echo = '' if self.hide_next else text
        reply = self.cli.handle(text)
        self.hide_next = not reply.echo_next
        if reply.raw:
            return echo + '\r\n' + reply.output
        body = (reply.output + '\r\n') if reply.output else ''
        return echo + '\r\n' + body.replace('\n', '\r\n').replace('\r\r', '\r') + \
            self.cli.prompt()


def test_end_to_end_real_netmiko_on_a_fake_serial_port(monkeypatch):
    import serial
    import serial.tools.list_ports as list_ports
    from types import SimpleNamespace
    from test_console_link import FakeSerial

    FakeSerial.instances, FakeSerial.open_error, FakeSerial.block = [], None, False
    FakeSerial.on_open = ''
    FakeSerial.device = MockLabConsole(mock_spec('router', 'disabled', privileged=False))
    monkeypatch.setattr(serial, 'Serial', FakeSerial)
    monkeypatch.setattr(list_ports, 'comports',
                        lambda: [SimpleNamespace(device='COM4', description='USB Serial',
                                                 hwid='USB VID:PID=067B:2303')])
    session = link.ConsoleSession('COM4', enable_password='Lab-pass-1', timeout=20,
                                  listen_seconds=0.1, listen_quiet=0.05)
    try:
        session.connect(confirm_idle=True)      # phase 5.1.6: an idle console, operator-confirmed
        before = FakeSerial.device.device.running_config()
        r = detect_device(session, elevate=True)
    finally:
        session.disconnect()
    assert r.simulated and r.ssh.status == S.SUPPORTED_DISABLED, r.ssh.evidence
    assert r.access.privileged_exec and r.access.privilege_level == 15
    assert r.device.hostname == 'R1' and r.management_interface == 'GigabitEthernet0/0'
    assert FakeSerial.device.device.running_config() == before
    sent = [l for l in FakeSerial.device.lines if l not in ('', 'Lab-pass-1')]
    allowed = set(DETECTION_COMMANDS) | {'terminal width 511', 'terminal length 0', 'enable',
                                          'exit'}
    assert set(sent) <= allowed, set(sent) - allowed
    assert FakeSerial.instances[0].is_open is False
