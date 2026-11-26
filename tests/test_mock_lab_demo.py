"""Demo preparation (F1-F4): the mock lab launcher's two modes, the simulated console
ports, the display-only "MOCK LAB" label, and `python -m mocklab reset`.

Nothing here starts the real lab on 127.0.0.11-13:22, opens a COM port, signs in to a
backend or opens a database: processes, sign-in and stores are stand-ins."""
import argparse
import importlib.util
import inspect
import json
import os
import socket
import sys

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
LAB = os.path.join(ROOT, 'mock-lab')
sys.path.insert(0, ROOT)
sys.path.insert(0, LAB)
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from mocklab import __main__ as labcli  # noqa: E402
from mocklab.console import SCENARIOS, MockConsoleBackend  # noqa: E402
from mocklab.lab import Lab, load_config  # noqa: E402

LABEL = 'MOCK LAB — simulated devices'


def load_launcher():
    spec = importlib.util.spec_from_file_location('run_netcommand_under_test',
                                                  os.path.join(LAB, 'run_netcommand.py'))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@pytest.fixture
def launcher(monkeypatch):
    """The launcher with everything it changes put back afterwards."""
    from config import connect
    monkeypatch.setattr(connect, 'BACKUP_DIR', connect.BACKUP_DIR)
    monkeypatch.setattr(sys, 'argv', list(sys.argv))
    monkeypatch.delenv('NETCOMMAND_MOCK_LAB', raising=False)
    monkeypatch.chdir(ROOT)
    return load_launcher()


def run_launcher(launcher, argv):
    seen = {}

    def fake_netcommand():
        from config import connect
        seen.update(argv=list(sys.argv), label=os.environ.get('NETCOMMAND_MOCK_LAB'),
                    backups=connect.BACKUP_DIR, layout=os.environ['NETCOMMAND_LAYOUT_FILE'])
    launcher.main(argv, run=fake_netcommand)
    return seen


# ================================================================ F1 / F3: the launcher
def test_default_mode_is_demo_with_the_mock_console(launcher):
    seen = run_launcher(launcher, [])
    assert seen['argv'][1:] == ['--demo', '--mock-console']
    assert seen['argv'][0] == os.path.join(ROOT, 'main.py')


def test_signed_in_mode_uses_the_normal_start_with_the_mock_console(launcher):
    seen = run_launcher(launcher, ['--signed-in'])
    assert seen['argv'][1:] == ['--mock-console']                  # no --demo: normal sign-in


@pytest.mark.parametrize('argv', [[], ['--signed-in']])
def test_both_modes_label_the_lab_and_keep_lab_files_apart(launcher, argv):
    seen = run_launcher(launcher, argv)
    assert seen['label'] == '1'
    assert seen['backups'] == os.path.join(LAB, 'backups')
    assert seen['layout'] == os.path.join(LAB, 'state', 'topology_layout.json')


def test_the_label_variable_names_match():
    from gui import main_window
    assert load_launcher().MOCK_LAB_VARIABLE == main_window.MOCK_LAB_VARIABLE


def test_unknown_launcher_options_are_refused(launcher):
    with pytest.raises(SystemExit):
        launcher.main(['--no-sign-in'], run=lambda: pytest.fail('started'))


def test_signed_in_mode_still_requires_signing_in(launcher, monkeypatch):
    """Through the real main.main(): without --demo, the sign-in window comes first; closing
    it opens neither the database nor the workbench."""
    import main
    calls = []
    monkeypatch.setattr('desktop_auth.api_client.client_from_environment',
                        lambda *a, **k: calls.append('client') or object())
    monkeypatch.setattr(main, 'sign_in', lambda client: calls.append('sign_in') or None)
    monkeypatch.setattr(main, 'choose_store', lambda *a: pytest.fail('opened a store'))
    monkeypatch.setattr(main, 'run_workbench', lambda *a, **k: pytest.fail('opened the workbench'))
    launcher.main(['--signed-in'], run=main.main)
    assert calls == ['client', 'sign_in']


def test_default_mode_opens_the_sample_store_without_sign_in(launcher, monkeypatch):
    import db_fake
    import main
    seen = {}
    monkeypatch.setattr(main, 'sign_in', lambda client: pytest.fail('signed in'))
    monkeypatch.setattr(main, 'run_workbench',
                        lambda store, demo, problem, access=None: seen.update(
                            store=store, demo=demo, access=access))
    launcher.main([], run=main.main)
    assert seen['store'] is db_fake and seen['demo'] and seen['access'].demo


@pytest.mark.parametrize('argv', [[], ['--signed-in']])
def test_both_modes_give_initial_setup_the_simulated_ports(launcher, argv, monkeypatch):
    import main
    from console import ports
    monkeypatch.setattr(ports, 'discover_ports', lambda *a, **k: pytest.fail('real ports'))
    seen = run_launcher(launcher, argv)
    backend = main.console_backend(seen['argv'])
    assert isinstance(backend, MockConsoleBackend) and backend.simulated
    names = [p.device for p in backend.discover_ports().ports]
    # SIM1-SIM17, then the brand-new switch and router (SIM47, SIM48), then the real-hardware
    # look-alikes: the CISCO1941 R1 as tested (SIM49) and a factory-new 2960 (SIM50)
    assert names == [f'SIM{n}' for n in range(1, 18)] + ['SIM47', 'SIM48', 'SIM49', 'SIM50'] \
        == list(SCENARIOS)
    assert all('SIMULATED' in p.description for p in backend.discover_ports().ports)


def test_without_the_option_the_real_ports_are_used():
    import main
    assert main.console_backend(['main.py', '--demo']) is None     # unchanged default


# ================================================================ F2: display-only label
def test_label_only_when_the_launcher_sets_it():
    from gui.main_window import mock_lab_label
    assert mock_lab_label({'NETCOMMAND_MOCK_LAB': '1'}) == LABEL
    for env in ({}, {'NETCOMMAND_MOCK_LAB': '0'}, {'NETCOMMAND_MOCK_LAB': 'yes'}):
        assert mock_lab_label(env) == ''


def test_window_title_shows_the_label():
    import main
    from desktop_auth.session import Access
    assert main.window_title(True, None, Access(None, demo=True), LABEL) == \
        f'NetCommand  [sample mode]  [DEMO MODE]  [{LABEL}]'
    assert main.window_title(False, None, Access('admin'), LABEL) == f'NetCommand  [{LABEL}]'
    # Without the launcher, the titles are exactly what they were.
    assert main.window_title(True, None, Access(None, demo=True)) == \
        'NetCommand  [sample mode]  [DEMO MODE]'
    assert main.window_title(False, None, Access('viewer')) == 'NetCommand'
    assert main.window_title(True, 'down', None) == \
        'NetCommand  [sample mode: database unavailable at startup]'


def build_window(monkeypatch, label):
    tk = pytest.importorskip('tkinter')
    from tkinter import messagebox
    import db_fake
    from gui.main_window import build_main_window
    from gui_helpers import new_root
    if label:
        monkeypatch.setenv('NETCOMMAND_MOCK_LAB', '1')
    else:
        monkeypatch.delenv('NETCOMMAND_MOCK_LAB', raising=False)
    for name in ('showinfo', 'showerror', 'showwarning'):
        monkeypatch.setattr(messagebox, name, lambda *a, **k: None)
    db_fake.reset()
    root = new_root()
    refs = build_main_window(root, db_fake, demo_store=True,
                             console_backend=MockConsoleBackend(delay=0))
    root.update()
    return tk, root, refs


def test_status_bar_shows_the_label_and_nothing_else_changes(monkeypatch):
    tk, root, plain = build_window(monkeypatch, label=False)
    plain_keys = set(plain)
    root.destroy()
    tk, root, refs = build_window(monkeypatch, label=True)
    try:
        assert refs['status_mock_lab'].cget('text') == LABEL
        assert set(refs) - plain_keys == {'status_mock_lab'}       # display only
        assert isinstance(refs['setup'].backend, MockConsoleBackend)
    finally:
        root.destroy()
    assert 'status_mock_lab' not in plain_keys


# ================================================================ F4: mocklab reset
@pytest.fixture
def lab_files(tmp_path, monkeypatch):
    """The reset command pointed at a temporary copy of lab_config.json and state folder."""
    config = json.loads(open(os.path.join(LAB, 'lab_config.json'), encoding='utf-8').read())
    path = tmp_path / 'lab_config.json'
    path.write_text(json.dumps(config), encoding='utf-8')
    state = tmp_path / 'state'
    state.mkdir()
    for name, value in (('CONFIG', str(path)), ('STATE', str(state)),
                        ('CONTROL', str(state / 'failures.json')), ('PID', str(state / 'lab.pid')),
                        ('STOP', str(state / 'stop.request')), ('LOG', str(state / 'lab.log'))):
        monkeypatch.setattr(labcli, name, value)
    monkeypatch.setattr(labcli.time, 'sleep', lambda s: None)
    return {'config': config, 'path': path, 'state': state}


@pytest.fixture
def no_connections(monkeypatch):
    """Any outgoing connection (SSH, Telnet, serial, plain TCP) fails the test."""
    def refuse(*a, **k):
        raise AssertionError('the reset tried to open a connection')
    monkeypatch.setattr(socket.socket, 'connect', refuse)
    monkeypatch.setattr(socket.socket, 'connect_ex', refuse)
    monkeypatch.setattr(socket, 'create_connection', refuse)
    import paramiko
    monkeypatch.setattr(paramiko.SSHClient, 'connect', refuse)
    monkeypatch.setattr(paramiko, 'Transport', refuse)
    netmiko = pytest.importorskip('netmiko')
    monkeypatch.setattr(netmiko, 'ConnectHandler', refuse)
    import telnetlib
    monkeypatch.setattr(telnetlib.Telnet, 'open', refuse)


class FakeProcesses:
    """The lab process as the reset sees it: a pid file, the stop file, and Popen."""

    def __init__(self, monkeypatch, files, running):
        self.files, self.running, self.started = files, running, []
        if running:
            (files['state'] / 'lab.pid').write_text('4242')
        monkeypatch.setattr(labcli, '_alive', self.alive)
        monkeypatch.setattr(labcli.subprocess, 'Popen', self.popen)
        monkeypatch.setattr(labcli.os, 'kill', lambda *a: pytest.fail('had to kill'))

    def alive(self, pid):
        if self.running and (self.files['state'] / 'stop.request').exists():
            self.running = False                       # the lab saw its stop file and ended
            (self.files['state'] / 'stop.request').unlink()
            (self.files['state'] / 'lab.pid').unlink()
        return self.running and pid is not None

    def popen(self, cmd, **kwargs):
        self.started.append(cmd)
        (self.files['state'] / 'lab.pid').write_text('4343')
        self.running = True


def answer(text):
    def ask(prompt):
        assert 'RESET MOCK LAB' in prompt
        return text
    return ask


@pytest.mark.parametrize('typed', ['', 'yes', 'reset mock lab', 'RESET MOCK LAB ', 'RESET',
                                   ' RESET MOCK LAB', 'RESET  MOCK LAB', None])
def test_reset_needs_the_exact_phrase(lab_files, no_connections, monkeypatch, capsys, typed):
    procs = FakeProcesses(monkeypatch, lab_files, running=True)
    (lab_files['state'] / 'failures.json').write_text('{"SW2": {"failure": "auth_fail"}}')

    def ask(prompt):
        if typed is None:
            raise EOFError
        return typed
    assert labcli.cmd_reset(argparse.Namespace(), ask=ask) == 1
    assert 'Reset cancelled. Nothing was changed.' in capsys.readouterr().out
    assert procs.running and procs.started == []                   # not stopped, not started
    assert (lab_files['state'] / 'failures.json').exists()
    assert not (lab_files['state'] / 'stop.request').exists()


def test_reset_says_it_is_a_simulation_before_asking(lab_files, no_connections, monkeypatch,
                                                     capsys):
    FakeProcesses(monkeypatch, lab_files, running=False)
    shown = []
    labcli.cmd_reset(argparse.Namespace(), ask=lambda p: shown.append(capsys.readouterr().out))
    assert 'SIMULATION ONLY' in shown[0] and 'No real device is contacted' in shown[0]


@pytest.mark.parametrize('host', ['192.168.10.1', '10.167.221.171', '0.0.0.0', 'router.local',
                                  '', None])
def test_reset_refuses_a_configuration_with_a_non_loopback_device(lab_files, no_connections,
                                                                  monkeypatch, capsys, host):
    lab_files['config']['devices'][1]['host'] = host
    lab_files['path'].write_text(json.dumps(lab_files['config']), encoding='utf-8')
    procs = FakeProcesses(monkeypatch, lab_files, running=True)
    code = labcli.cmd_reset(argparse.Namespace(), ask=lambda p: pytest.fail('asked'))
    out = capsys.readouterr().out
    assert code == 2 and 'Reset refused' in out and 'loopback' in out and 'SW1' in out
    assert procs.running and procs.started == []


def test_reset_restarts_a_running_lab_and_clears_failure_modes(lab_files, no_connections,
                                                               monkeypatch, capsys):
    procs = FakeProcesses(monkeypatch, lab_files, running=True)
    (lab_files['state'] / 'failures.json').write_text('{"SW2": {"failure": "auth_fail"}}')
    assert labcli.cmd_reset(argparse.Namespace(), ask=answer('RESET MOCK LAB')) == 0
    out = capsys.readouterr().out
    assert 'Mock lab stopped.' in out and 'rebuilt from lab_config.json' in out
    assert not (lab_files['state'] / 'failures.json').exists()
    assert len(procs.started) == 1
    started = procs.started[0]
    assert started[1:4] == ['-m', 'mocklab', 'start'] and '--fail' not in started
    assert procs.running


def test_reset_accepts_the_typed_line_ending(lab_files, no_connections, monkeypatch):
    FakeProcesses(monkeypatch, lab_files, running=False)
    assert labcli.cmd_reset(argparse.Namespace(), ask=answer('RESET MOCK LAB\r\n')) == 0


def test_reset_of_a_stopped_lab_only_clears_failure_modes(lab_files, no_connections,
                                                          monkeypatch, capsys):
    procs = FakeProcesses(monkeypatch, lab_files, running=False)
    (lab_files['state'] / 'failures.json').write_text('{"MOCK-R1": {"failure": "slow"}}')
    assert labcli.cmd_reset(argparse.Namespace(), ask=answer('RESET MOCK LAB')) == 0
    assert not (lab_files['state'] / 'failures.json').exists()
    assert procs.started == [] and 'was not running' in capsys.readouterr().out


def test_reset_is_registered_on_the_command_line(lab_files, no_connections, monkeypatch):
    FakeProcesses(monkeypatch, lab_files, running=False)
    monkeypatch.setattr('builtins.input', lambda prompt: 'no')
    assert labcli.main(['reset']) == 1


def code_without_docstrings(function):
    """The function's code (names and statements), its docstring removed."""
    import ast
    import textwrap
    tree = ast.parse(textwrap.dedent(inspect.getsource(function)))
    body = tree.body[0].body
    if body and isinstance(body[0], ast.Expr) and isinstance(body[0].value, ast.Constant):
        body.pop(0)
    return ast.unparse(tree).lower()


def test_reset_code_contains_no_device_connection_or_destructive_command():
    code = ''.join(code_without_docstrings(f) for f in (labcli.cmd_reset,
                                                        labcli._start_background,
                                                        labcli.loopback_problems))
    for word in ('netmiko', 'connecthandler', 'paramiko', 'serial', 'telnet', 'socket',
                 'send_command', 'send_config', 'write erase', 'erase startup', 'reload',
                 'factory', 'address_in_use', 'sshclient'):
        assert word not in code, word
    module = open(labcli.__file__, encoding='utf-8').read().lower()
    for word in ('write erase', 'erase startup', 'reload'):
        assert word not in module, word


def test_a_rebuilt_lab_is_back_in_its_starting_state(tmp_path, no_connections):
    """What reset relies on: the restarted lab builds its devices from lab_config.json and
    (with the failure file cleared) from its configured failure modes, whatever happened to
    the previous one."""
    from mocklab.cli import Session
    from mocklab.lab import read_control
    config = load_config()
    key = str(tmp_path / 'host_rsa.key')
    first = Lab(config, key_path=key)
    original = first.devices['MOCK-R1'].running_config()
    session = Session(first.devices['MOCK-R1'])
    for line in ('enable', 'Lab-R1-pass', 'configure terminal', 'hostname CHANGED', 'end'):
        session.handle(line)
    first.endpoints['SW2'].set_failure('auth_fail')
    assert first.devices['MOCK-R1'].hostname == 'CHANGED'
    control = tmp_path / 'failures.json'
    control.write_text('{"SW2": {"failure": "auth_fail"}}')
    control.unlink()                                       # what reset does
    rebuilt = Lab(load_config(), key_path=key, control_path=str(control))
    assert rebuilt.devices['MOCK-R1'].hostname == 'MOCK-R1'
    assert rebuilt.devices['MOCK-R1'].running_config() == original
    assert rebuilt.endpoints['SW2'].failure == 'none' and read_control(str(control)) == {}
