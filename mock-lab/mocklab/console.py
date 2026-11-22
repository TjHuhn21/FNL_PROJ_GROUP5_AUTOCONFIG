"""SIMULATED console connections for the Initial Setup page (no COM port is used).

Only active when NetCommand is started with --mock-console (main.py). It gives the page
a list of simulated ports, and sessions that answer like ConsoleSession but run every
command on the mock lab's simulated IOS CLI. Every port, status line and `show version`
says it is a simulation; detection then marks the result as simulated.

    backend = MockConsoleBackend()
    backend.discover_ports()               # PortScan of SIM1 ... SIM17
    session = backend.open_session('SIM2', 9600, '', '', '', log)
    session.connect()                      # like console.link.ConsoleSession.connect()

The simulated ports (SCENARIOS):
    SIM1  router, SSH fully set up     SIM7  router whose cable is "pulled" during detection
    SIM2  router, no RSA keys yet      SIM8  router as from the factory: nothing set up
    SIM3  switch, no SSH in its image  SIM9  router using AAA for logins, SSH on
    SIM4  router, SSH unknown          SIM10 switch, VTY lines allow Telnet and SSH
    SIM5  switch, console login refused   SIM11 router, VTY lines without a login line
    SIM6  no answer (connection timeout)  SIM12 router with conflicting SSH settings
    SIM13 SSH off, only an HTTPS self-signed key   SIM16 switch, VTY 0-4 SSH / 5-15 Telnet
    SIM14 SSH off, a key of unknown purpose        SIM17 switch, 16 VTY lines, only 0-4 set
    SIM15 SSH off although its SSH key exists

Like the real session, it only sends single-line `show` commands (the same guard,
console.link.check_show_command), plus `enable` when asked.
"""
import threading
import time

from console.link import (AUTH, CANCELLED, NETMIKO_SETUP_DIALOG_NOTICE, NOT_CONNECTED, OTHER,
                          PORT_UNAVAILABLE, TIMEOUT, ConnectResult, ConsoleError,
                          check_show_command)
from console.ports import ComPort, PortScan

from .cli import Session
from .device import Device

SIMULATED_HWID = 'SIMULATED (NetCommand mock lab)'
MODE_NOTE = ('MOCK CONSOLE MODE: the ports below are simulated by the NetCommand mock lab. '
             'No COM port is opened and no real device is contacted.')

_ROUTER = {'type': 'router', 'ports': {'GigabitEthernet': 2},
           'interfaces': {'GigabitEthernet0/0': {'ip': '192.168.10.1', 'mask': '255.255.255.0',
                                                 'shutdown': False, 'connected': True}}}
_SWITCH = {'type': 'switch', 'ports': {'FastEthernet': 4, 'GigabitEthernet': 2},
           'interfaces': {'Vlan1': {'ip': '192.168.1.2', 'mask': '255.255.255.0',
                                    'shutdown': False}}}
_DOMAIN = 'ip domain-name lab.local'
_ADMIN = 'username labadmin privilege 15 secret 5 $1$mock$hidden'
_GLOBALS = [_DOMAIN, _ADMIN]
_VTY_SSH = {'con 0': [], 'vty 0 4': ['login local', 'transport input ssh']}


def _scenario(host, base, ssh, text, behaviour=None, global_lines=None, line_config=None,
              console=None, scenario_id=None, **device):
    """device: further Device spec keys (extra_rsa_keys, vty_count, quirks, failure).
    console: simulated console-session events, each {event: show command}:
        timeout_on            that command times out (the session ends, as on a real console)
        partial_timeout_on    part of its output arrives, then it times out
        unexpected_prompt_on  the device answers with a boot-loader prompt from then on
        unplug_on             the connection is lost during that command"""
    return {'host': host, 'base': base, 'ssh': ssh, 'text': text, 'behaviour': behaviour,
            'global_lines': list(_GLOBALS if global_lines is None else global_lines),
            'line_config': dict(_VTY_SSH if line_config is None else line_config),
            'device': device, 'console': dict(console or {}), 'id': scenario_id}


SCENARIOS = {
    'SIM1': _scenario('R1', _ROUTER, 'enabled', 'Simulated router, SSH fully set up',
                      global_lines=_GLOBALS + ['ip ssh version 2']),
    'SIM2': _scenario('R2', _ROUTER, 'disabled', 'Simulated router, SSH not enabled (no RSA keys)'),
    'SIM3': _scenario('SW3', _SWITCH, 'unsupported', 'Simulated switch, no SSH in its image'),
    'SIM4': _scenario('R4', _ROUTER, 'unknown', 'Simulated router, SSH cannot be determined'),
    'SIM5': _scenario('SW5', _SWITCH, 'enabled', 'Simulated switch, console login refused',
                      behaviour='refuse_login'),
    'SIM6': _scenario('R6', _ROUTER, 'enabled', 'Simulated device that never answers',
                      behaviour='no_answer'),
    'SIM7': _scenario('R7', _ROUTER, 'enabled', 'Simulated router, cable pulled during detection',
                      behaviour='unplug'),
    'SIM8': _scenario('Router', _ROUTER, 'disabled',
                      'Simulated router as from the factory (nothing set up)',
                      global_lines=[], line_config={'con 0': [], 'vty 0 4': ['login']}),
    'SIM9': _scenario('R9', _ROUTER, 'enabled', 'Simulated router using AAA for logins',
                      global_lines=_GLOBALS + ['aaa new-model',
                                               'aaa authentication login default local',
                                               'ip ssh version 2'],
                      line_config={'con 0': [], 'vty 0 4': ['login authentication default',
                                                            'transport input ssh']}),
    'SIM10': _scenario('SW10', _SWITCH, 'enabled', 'Simulated switch, VTY allows Telnet and SSH',
                       global_lines=_GLOBALS + ['ip ssh version 2'],
                       line_config={'con 0': [], 'vty 0 4': ['login local',
                                                             'transport input telnet ssh']}),
    'SIM11': _scenario('R11', _ROUTER, 'disabled', 'Simulated router, VTY lines without login',
                       line_config={'con 0': [], 'vty 0 4': ['transport input ssh']}),
    'SIM12': _scenario('R12', _ROUTER, 'enabled', 'Simulated router, conflicting SSH settings',
                       global_lines=[_DOMAIN, 'ip ssh version 2'],
                       line_config={'con 0': [], 'vty 0 4': ['login local',
                                                             'transport input telnet']}),
    'SIM13': _scenario('R13', _ROUTER, 'disabled',
                       'Simulated router, SSH off, only an HTTPS self-signed key',
                       extra_rsa_keys=['TP-self-signed-4001']),
    'SIM14': _scenario('R14', _ROUTER, 'disabled',
                       'Simulated router, SSH off, a key of unknown purpose',
                       extra_rsa_keys=['LEGACY-KEY']),
    'SIM15': _scenario('R15', _ROUTER, 'disabled',
                       'Simulated router, SSH off although its SSH key exists',
                       extra_rsa_keys=['R15.lab.local']),
    'SIM16': _scenario('SW16', _SWITCH, 'enabled',
                       'Simulated switch, VTY 0-4 SSH, VTY 5-15 Telnet with line password',
                       global_lines=_GLOBALS + ['ip ssh version 2'],
                       line_config={'con 0': [],
                                    'vty 0 4': ['login local', 'transport input ssh'],
                                    'vty 5 15': ['password 7 0822455D0A16', 'login',
                                                 'transport input telnet']}),
    'SIM17': _scenario('SW17', _SWITCH, 'enabled',
                       'Simulated switch, 16 VTY lines but only vty 0 4 configured',
                       global_lines=_GLOBALS + ['ip ssh version 2'], vty_count=16),
}


# Edge cases for future console configuration work (phase 5.1.1). Kept out of the default
# port list (MockConsoleBackend(edge_cases=True) lists them); each has a stable identifier.
# They SIMULATE situations NetCommand must handle safely; they do not show how real Cisco
# hardware behaves (to be checked on the router).
_E = 'Simulated edge case: '
EDGE_SCENARIOS = {
    'SIM18': _scenario('R18', _ROUTER, 'disabled', _E + 'slow RSA key generation',
                       scenario_id='rsa-slow', quirks=['rsa_slow']),
    'SIM19': _scenario('R19', _ROUTER, 'disabled', _E + 'RSA key generation fails',
                       scenario_id='rsa-fails', quirks=['rsa_fails']),
    'SIM20': _scenario('R20', _ROUTER, 'enabled', _E + 'RSA keys exist (replace question)',
                       scenario_id='rsa-replace-question',
                       global_lines=_GLOBALS + ['ip ssh version 2']),
    'SIM21': _scenario('R21', _ROUTER, 'disabled', _E + 'key size asked when not given',
                       scenario_id='rsa-modulus-question', quirks=['rsa_ask_modulus']),
    'SIM22': _scenario('Router', _ROUTER, 'disabled', _E + 'factory hostname blocks keys',
                       scenario_id='rsa-missing-hostname'),
    'SIM23': _scenario('R23', _ROUTER, 'disabled', _E + 'no domain name blocks keys',
                       scenario_id='rsa-missing-domain', global_lines=[_ADMIN]),
    'SIM24': _scenario('R24', _ROUTER, 'disabled', _E + 'key generation output incomplete',
                       scenario_id='rsa-partial', quirks=['rsa_partial']),
    'SIM25': _scenario('R25', _ROUTER, 'disabled', _E + 'old prompt shown after a rename',
                       scenario_id='prompt-lag', quirks=['prompt_lag']),
    'SIM26': _scenario('R26', _ROUTER, 'disabled', _E + 'cut-off prompt after a rename',
                       scenario_id='prompt-garbled', quirks=['prompt_garbled']),
    'SIM27': _scenario('R27', _ROUTER, 'disabled', _E + 'domain name rejected',
                       scenario_id='domain-rejected', global_lines=[_ADMIN],
                       quirks=['domain_rejected']),
    'SIM28': _scenario('R28', _ROUTER, 'enabled', _E + 'SSH v2 accepted but stays 1.99',
                       scenario_id='ssh-v2-ignored', quirks=['ssh_v2_ignored']),
    'SIM29': _scenario('R29', _ROUTER, 'disabled', _E + 'SSH v2 rejected',
                       scenario_id='ssh-v2-rejected', quirks=['ssh_v2_rejected']),
    'SIM30': _scenario('R30', _ROUTER, 'enabled', _E + 'SSH on, not reachable over Ethernet',
                       scenario_id='ssh-ethernet-unavailable',
                       global_lines=_GLOBALS + ['ip ssh version 2'], failure='offline'),
    'SIM31': _scenario('R31', _ROUTER, 'enabled', _E + 'SSH server with only SHA-1 algorithms',
                       scenario_id='ssh-legacy-algorithms',
                       global_lines=_GLOBALS + ['ip ssh version 2'], quirks=['legacy_ssh_only']),
    'SIM32': _scenario('R32', _ROUTER, 'disabled', _E + 'Telnet-only VTY, SSH not ready',
                       scenario_id='vty-ssh-not-verified',
                       line_config={'con 0': [], 'vty 0 4': ['login local',
                                                             'transport input telnet']}),
    'SIM33': _scenario('R33', _ROUTER, 'enabled', _E + 'system log lines in the output',
                       scenario_id='console-syslog', quirks=['syslog'],
                       global_lines=_GLOBALS + ['ip ssh version 2']),
    'SIM34': _scenario('R34', _ROUTER, 'enabled', _E + 'a show command times out',
                       scenario_id='console-timeout',
                       console={'timeout_on': 'show ip ssh'}),
    'SIM35': _scenario('R35', _ROUTER, 'enabled', _E + 'partial output, then a timeout',
                       scenario_id='console-partial-timeout',
                       console={'partial_timeout_on': 'show running-config | section line vty'}),
    'SIM36': _scenario('R36', _ROUTER, 'enabled', _E + 'boot-loader prompt mid-session',
                       scenario_id='console-unexpected-prompt',
                       console={'unexpected_prompt_on': 'show ip ssh'}),
    'SIM37': _scenario('R37', _ROUTER, 'enabled', _E + 'connection lost during a show command',
                       scenario_id='console-interrupted',
                       console={'unplug_on': 'show crypto key mypubkey rsa'}),
}
ALL_SCENARIOS = {**SCENARIOS, **EDGE_SCENARIOS}
# identifier -> port; the existing scenarios that already cover a required case are listed
# under that case's identifier too
SCENARIO_IDS = {s['id']: port for port, s in EDGE_SCENARIOS.items()}
SCENARIO_IDS.update({
    'ssh-keys-but-disabled': 'SIM15', 'vty-multiple-ranges': 'SIM16',
    'vty-uncovered-lines': 'SIM17', 'vty-login-local': 'SIM1',
    'vty-password-login': 'SIM16', 'vty-different-settings': 'SIM16',
})


def scenario_port(identifier):
    """The simulated port of a scenario identifier ('rsa-slow' -> 'SIM18')."""
    return SCENARIO_IDS[identifier]


def device_spec(port):
    s = ALL_SCENARIOS[port]
    return dict(s['base'], name=s['host'], hostname=s['host'], host='127.0.0.99',
                username='sim', password='sim', start_privileged=True, ssh_condition=s['ssh'],
                global_lines=list(s['global_lines']),
                line_config={k: list(v) for k, v in s['line_config'].items()},
                **s['device'])


class MockConsoleBackend:
    """What the Initial Setup page uses instead of the real COM ports (see main.py)."""
    simulated = True
    mode_note = MODE_NOTE

    def __init__(self, delay=0.05, timeout=3, edge_cases=False):
        """delay: seconds each simulated serial operation takes (tests: 0).
        edge_cases: also list the phase 5.1.1 edge-case scenarios (EDGE_SCENARIOS)."""
        self.delay, self.timeout = delay, timeout
        self.scenarios = ALL_SCENARIOS if edge_cases else SCENARIOS

    def discover_ports(self):
        return PortScan(ports=tuple(
            ComPort(device=port, description=f"{s['text']} (SIMULATED)", hwid=SIMULATED_HWID,
                    confidence='possible', reason='simulated console, not a real adapter')
            for port, s in self.scenarios.items()))

    def open_session(self, port, baudrate, username, password, enable_password, log=None):
        if port not in self.scenarios:
            raise ValueError(f'"{port}" is not one of the simulated ports.')
        s = self.scenarios[port]
        return MockConsoleSession(port, baudrate, enable_password, s['behaviour'],
                                  delay=self.delay, timeout=self.timeout, log=log,
                                  console=s['console'])


class MockConsoleSession:
    """Answers like console.link.ConsoleSession, from the mock lab CLI."""

    def __init__(self, port, baudrate, enable_password, behaviour, delay=0.05, timeout=3,
                 log=None, console=None):
        self.port, self.baudrate = port, baudrate
        self._enable_password = enable_password or ''
        self.behaviour, self.delay, self.timeout = behaviour, delay, timeout
        self.console = dict(console or {})               # simulated console events
        self._log = log or (lambda kind, text: None)
        self.device = Device(device_spec(port))
        self.cli = None
        self.sent = []                                   # every line "typed" (tests)
        self._cancelled = threading.Event()
        self._lock = threading.Lock()
        self.commands_run = 0
        self.rommon = False                              # unexpected_prompt_on happened
        self.partial_output = None                       # what arrived before a timeout

    def __repr__(self):
        return f'MockConsoleSession(port={self.port!r}, SIMULATED)'

    def _wait(self, seconds):
        if self._cancelled.wait(seconds):
            raise ConsoleError(CANCELLED, 'Cancelled. The serial port was closed.')

    def connect(self):
        with self._lock:
            if self.cli is not None:
                raise ConsoleError(OTHER, f'{self.port} is already connected.')
            self._cancelled.clear()
            self._log('info', f'Opening {self.port} (SIMULATED) at {self.baudrate} baud...')
            self._wait(self.delay)
            if self.behaviour == 'no_answer':
                self._wait(self.timeout)
                raise ConsoleError(TIMEOUT, f'No usable answer on {self.port} within '
                                            f'{self.timeout} seconds. Check the cable, that the '
                                            f'device is on, and the speed ({self.baudrate} baud).')
            if self.behaviour == 'refuse_login':
                raise ConsoleError(AUTH, 'The device refused the console login (wrong username '
                                         'or password).')
            self.cli = Session(self.device)
            prompt = self.cli.prompt()
            self._log('ok', f'Connected on {self.port} (SIMULATED). Device prompt: {prompt}')
            return ConnectResult(self.port, self.baudrate, prompt, [NETMIKO_SETUP_DIALOG_NOTICE])

    def _require(self):
        if self.cli is None:
            raise ConsoleError(NOT_CONNECTED, 'Not connected. Connect to the console first.')
        if self._cancelled.is_set():
            raise ConsoleError(CANCELLED, 'Cancelled. The serial port was closed.')

    def find_prompt(self):
        with self._lock:
            self._require()
            return 'rommon 1 >' if self.rommon else self.cli.prompt()

    def _lost(self, kind, message):
        """The session ends, as ConsoleSession closes the port when a call fails."""
        self.cli = None
        raise ConsoleError(kind, message)

    def send_show(self, command, timeout=None):
        text = check_show_command(command)
        with self._lock:
            self._require()
            self._wait(self.delay)
            self.commands_run += 1
            if self.behaviour == 'unplug' and self.commands_run == 4:
                self._lost(PORT_UNAVAILABLE, f'{self.port} stopped working (was the cable '
                                             f'unplugged?).')
            self.sent.append(text)
            self._log('command', text)
            event = next((e for e, c in self.console.items() if c == text), None)
            if event == 'unplug_on':
                self._lost(PORT_UNAVAILABLE, f'{self.port} stopped working (was the cable '
                                             f'unplugged?).')
            if event == 'timeout_on':
                self._lost(TIMEOUT, f'The device on {self.port} stopped answering in time.')
            if event == 'partial_timeout_on':
                full = self.cli.handle(text).output
                self.partial_output = full[:len(full) // 2]      # never returned to the caller
                self._lost(TIMEOUT, f'The device on {self.port} stopped answering in time.')
            if event == 'unexpected_prompt_on':
                self.rommon = True
            if self.rommon:
                return f'\nrommon {self.commands_run} > '
            return self.cli.handle(text).output

    def enable(self):
        with self._lock:
            self._require()
            if self.cli.prompt().endswith('#'):
                return self.cli.prompt()
            if not self._enable_password:
                raise ConsoleError(AUTH, 'Privileged mode needs the enable password.')
            self.sent.append('enable')
            self.cli.handle('enable')
            self.cli.handle(self._enable_password)
            if not self.cli.prompt().endswith('#'):
                raise ConsoleError(AUTH, 'The device refused the enable password.')
            return self.cli.prompt()

    def is_active(self):
        return self.cli is not None and not self._cancelled.is_set()

    def cancel(self):
        self._cancelled.set()

    def disconnect(self):
        self.cli = None
        self._log('info', f'Disconnected from {self.port} (SIMULATED).')
