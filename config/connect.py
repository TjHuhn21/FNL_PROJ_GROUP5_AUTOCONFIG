"""Talks to one device over SSH: read its config, or apply commands safely.

apply_config does, in this order:
    connect -> back up -> send commands -> check -> save
and reports every step, with the real commands and the device's real replies,
through an optional log(kind, text) callback (the Configure page's SSH console):

    kind      meaning                                     example text
    'info'    progress                                    Connecting to 192.168.1.2 through SSH...
    'section' a stage starts                              BACKUP
    'command' a command, after the device's prompt        SW1(config)# vlan 10
    'output'  what the device answered                    % Invalid input detected at '^' marker.
    'ok' / 'warn' / 'error'   outcome lines

Passwords and secrets are never reported: commands and replies are masked
before they are logged (what is SENT is not changed).

Every failure comes back as (False, 'a clear message'). Nothing crashes the app.

Every connection uses ssh_options.connect_options(host): strict SSH algorithms, with the
old SHA-1 ones allowed only for the addresses in NETCOMMAND_LEGACY_SSH_HOSTS.
"""
import os
import re
from datetime import datetime

from netmiko import ConnectHandler
from netmiko.exceptions import NetmikoAuthenticationException, NetmikoTimeoutException

import ssh_options

LOGIN_TIMEOUTS = {'conn_timeout': 8, 'auth_timeout': 10, 'banner_timeout': 10}
BACKUP_DIR = 'backups'
# What a Cisco device prints when it rejects a command (it does not raise an error)
REJECTED = ('% Invalid', '% Incomplete', '% Ambiguous', '% Unknown command',
            '% Unrecognized', '% Bad ', '% Error', '% Cannot', '% Command rejected')
SAVE_COMMAND = 'write mem'          # what Netmiko's save_config() sends to Cisco IOS
BACKUP_PREVIEW_LINES = 25           # the console shows the start; the file has everything
OUTPUT_PREVIEW_LINES = 40
_PROMPT = re.compile(r'^\S+(\([^)]*\))?[#>]\s*$')
_SECRET = re.compile(r'(\b(?:password|secret|key-string|community|key)\s+(?:\d\s+)?)(\S+)',
                     re.IGNORECASE)


def mask(text):
    """Hide values that follow password / secret / key words."""
    return _SECRET.sub(lambda m: m.group(1) + '********', text or '')


class _Report:
    """Sends lines to log(kind, text), masked and never raising."""
    def __init__(self, log):
        self.log = log

    def __call__(self, kind, text):
        if self.log:
            try:
                self.log(kind, mask(text))
            except Exception:
                pass                     # the console must never break an SSH session

    def output(self, text, limit=OUTPUT_PREVIEW_LINES, note=''):
        lines = (text or '').rstrip().splitlines()
        if not lines:
            return
        shown = lines[:limit]
        self('output', '\n'.join(shown))
        if len(lines) > limit:
            self('info', f'... {len(lines) - limit} more lines{note}')


def _open(creds):
    conn = ConnectHandler(device_type='cisco_ios', host=creds['host'],
                          username=creds['username'], password=creds['password'],
                          secret=creds.get('secret') or creds['password'], **LOGIN_TIMEOUTS,
                          **ssh_options.connect_options(creds['host']))
    if conn.find_prompt().endswith('>'):
        try:
            conn.enable()
            conn.netcommand_enabled = True      # so the console can show the step
        except Exception:
            pass
    return conn


def get_config(creds):
    """The running-config text of a device. creds = {'host','username','password'}."""
    conn = _open(creds)
    try:
        return conn.send_command('show running-config')
    finally:
        conn.disconnect()


def _save_backup(host, text, backup_dir=None):
    folder = backup_dir or BACKUP_DIR
    os.makedirs(folder, exist_ok=True)
    stamp = datetime.now().strftime('%Y%m%d_%H%M%S')
    path = os.path.join(folder, f'{host}_{stamp}.txt')
    with open(path, 'w', encoding='utf-8') as f:
        f.write(text)
    return path


def rejection(output):
    """The device's error line if `output` contains a rejection, else None."""
    for line in (output or '').splitlines():
        if any(line.strip().startswith(bad.strip()) or bad in line for bad in REJECTED):
            return line.strip()
    return None


def split_reply(raw, command):
    """Netmiko's text for one config command is: the echoed command, the device's
    reply, then the next prompt. Returns (reply, next_prompt or None)."""
    lines = (raw or '').splitlines()
    if lines and lines[0].strip().endswith(command.strip()):
        lines = lines[1:]                               # the echo of what we typed
    prompt = None
    while lines and not lines[-1].strip():
        lines.pop()
    if lines and _PROMPT.match(lines[-1].strip()):
        prompt = lines.pop().strip()
    return '\n'.join(lines).strip(), prompt


def apply_config(creds, commands, checks=(), backup_dir=None, log=None):
    """Returns (True or False, message).
    checks is a list of (show command, text that must appear in its output).
    log(kind, text), if given, receives every step (see the module notes)."""
    host = creds['host']
    report = _Report(log)
    commands = [c for c in commands if c and c.strip() and not c.strip().startswith('#')]
    if not commands:
        return False, 'There are no commands to send.'
    report('section', 'CONNECT')
    report('info', f'Connecting to {host} through SSH...')
    try:
        conn = _open(creds)
    except Exception as err:
        return _connect_failed(err, host, report)
    try:
        return _session(conn, host, commands, checks, backup_dir, report)
    except NetmikoTimeoutException:
        report('error', 'The device stopped answering during the session.')
        return False, 'No answer (wrong IP, device off, or SSH not enabled).'
    except NetmikoAuthenticationException:
        report('error', 'The device refused the login (wrong username or password).')
        return False, 'Wrong username or password.'
    except Exception as err:
        detail = mask(str(err))
        report('error', f'The session failed: {type(err).__name__}: {detail}')
        return False, f'Error: {type(err).__name__}: {detail}'
    finally:
        try:
            conn.disconnect()
            report('info', 'SSH session closed.')
        except Exception:
            pass


def _connect_failed(err, host, report):
    """(False, message) for a connection that could not be opened. The message comes
    from ssh_options.describe_error: fixed text, never the exception's own text."""
    kind, text = ssh_options.describe_error(err, host)
    if kind == ssh_options.AUTH:
        report('error', 'The device refused the login (wrong username or password).')
        return False, 'Wrong username or password.'
    if kind == ssh_options.TIMEOUT:
        report('error', f'No answer from {host}: {text}.')
        return False, 'No answer (the connection timed out: wrong IP, device off, or not reachable).'
    if kind == ssh_options.REFUSED:
        report('error', f'{host}: {text}.')
        return False, 'Connection refused (SSH is not enabled on the device, or port 22 is blocked).'
    if kind == ssh_options.ALGORITHMS:
        report('error', f'Unsupported SSH algorithms: {text}.')
        return False, f'Unsupported SSH algorithms: {text}.'
    report('error', f'Could not connect: {text}.')
    return False, f'Error: {type(err).__name__} (the SSH connection could not be opened).'


def _session(conn, host, commands, checks, backup_dir, report):
    prompt = conn.find_prompt().strip()
    report('ok', f'SSH connection established. Device prompt: {prompt}')
    if getattr(conn, 'netcommand_enabled', False):
        report('command', f'{prompt.rstrip("#")}> enable')
        report('info', 'Entered privileged mode (the enable secret is not shown).')

    # ---- 1. backup
    report('section', 'BACKUP')
    report('command', f'{prompt} show running-config')
    running = conn.send_command('show running-config')
    backup = _save_backup(host, running, backup_dir)
    report.output(running, BACKUP_PREVIEW_LINES, ' (the complete copy is in the backup file)')
    report('ok', f'Backup saved: {backup}')

    # ---- 2. configuration
    report('section', 'CONFIGURATION')
    applied, rejected = _send(conn, prompt, commands, report)
    if rejected:
        cmd, error = rejected
        report('error', f'REJECTED: "{cmd}"  ->  {error}')
        if applied is None:
            report('warn', 'POSSIBLY PARTIALLY APPLIED: the commands were sent as one batch, so '
                           'some of them may be in the running configuration. Nothing was saved.')
            state = 'possibly partially applied'
        elif applied:
            not_sent = len(commands) - len(applied) - 1
            report('warn', f'PARTIALLY APPLIED: {len(applied)} command(s) before it are now in the '
                           f'running configuration; {not_sent} after it were not sent. '
                           f'Nothing was saved.')
            state = (f'partially applied: {len(applied)} of {len(commands)} commands were applied '
                     f'before it')
        else:
            report('warn', 'Nothing was applied: the first command was rejected. Nothing was saved.')
            state = 'nothing was applied'
        report('section', 'RESULT')
        report('error', f'FAILED ({state}). Restore from the backup if needed: {backup}')
        return False, (f'The device rejected a command: "{cmd}" ({error}). The change is '
                       f'{state}, and it was not saved. Restore from the backup if needed: {backup}')

    # ---- 3. verification
    report('section', 'VERIFICATION')
    if not checks:
        report('info', 'No automatic check is defined for these commands.')
    for show_cmd, expected in checks:
        report('command', f'{prompt} {show_cmd}')
        out = conn.send_command(show_cmd)
        report.output(out)
        if expected not in out:
            report('error', f'CHECK FAILED: "{expected}" was not found in "{show_cmd}".')
            report('section', 'RESULT')
            report('error', f'FAILED: all {len(commands)} commands were applied but the result '
                            f'could not be verified, so the configuration was NOT saved. '
                            f'Backup: {backup}')
            return False, (f'Check failed: "{expected}" was not found in {show_cmd}. The commands '
                           f'were applied but not saved. Backup: {backup}')
        report('ok', f'OK: "{expected}" found.')

    # ---- 4. save
    report('section', 'SAVE')
    report('command', f'{prompt} {SAVE_COMMAND}')
    saved = conn.save_config()
    report.output(saved if isinstance(saved, str) else '')
    report('section', 'RESULT')
    report('ok', f'SUCCESS: {len(commands)} command(s) applied, verified and saved. Backup: {backup}')
    return True, f'Applied and verified. Backup: {backup}'


def _send(conn, prompt, commands, report):
    """Send the configuration commands. Returns (applied, rejected or None).
    Normally: one configuration session, one command at a time, so each reply
    belongs to its command and sending stops at the first rejected one. A
    connection object without config_mode() (a simple fake) gets them as one batch."""
    if not hasattr(conn, 'config_mode'):
        for cmd in commands:
            report('command', f'(config)# {cmd}')
        output = conn.send_config_set(commands)
        report.output(output)
        error = rejection(output)
        # all commands went in one batch: which of them took effect is unknown
        return (commands, None) if not error else (None, ('one of the commands', error))

    entered = conn.config_mode()
    reply, now = split_reply(entered, 'configure terminal')
    report('command', f'{prompt} configure terminal')
    report.output(reply)
    now = now or prompt
    applied = []
    try:
        for cmd in commands:
            raw = conn.send_config_set([cmd], enter_config_mode=False, exit_config_mode=False)
            reply, after = split_reply(raw, cmd)
            report('command', f'{now} {cmd}')
            report.output(reply)
            error = rejection(reply)
            if error:
                return applied, (cmd, error)
            applied.append(cmd)
            now = after or now
    finally:
        try:
            report('command', f'{now} end')
            conn.exit_config_mode()
        except Exception as err:
            report('warn', f'Could not leave configuration mode cleanly: {err}')
    return applied, None
