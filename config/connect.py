"""Talks to one device over SSH: read its config, or apply commands safely.

apply_config does, in this order: back up -> send commands -> check -> save.
Every failure comes back as (False, 'a clear message'). Nothing crashes the app.
"""
import os
from datetime import datetime

from netmiko import ConnectHandler
from netmiko.exceptions import NetmikoAuthenticationException, NetmikoTimeoutException

LOGIN_TIMEOUTS = {'conn_timeout': 8, 'auth_timeout': 10, 'banner_timeout': 10}
BACKUP_DIR = 'backups'
# What a Cisco device prints when it rejects a command (it does not raise an error)
REJECTED = ('% Invalid', '% Incomplete', '% Ambiguous')


def _open(creds):
    conn = ConnectHandler(device_type='cisco_ios', host=creds['host'],
                          username=creds['username'], password=creds['password'],
                          secret=creds.get('secret') or creds['password'], **LOGIN_TIMEOUTS)
    if conn.find_prompt().endswith('>'):
        try:
            conn.enable()
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
    with open(path, 'w') as f:
        f.write(text)
    return path


def apply_config(creds, commands, checks=(), backup_dir=None):
    """Returns (True or False, message).
    checks is a list of (show command, text that must appear in its output)."""
    host = creds['host']
    commands = [c for c in commands if c and c.strip() and not c.strip().startswith('#')]
    if not commands:
        return False, 'There are no commands to send.'
    try:
        conn = _open(creds)
        try:
            backup = _save_backup(host, conn.send_command('show running-config'), backup_dir)
            output = conn.send_config_set(commands)
            if any(bad in output for bad in REJECTED):
                return False, (f'The device rejected a command, so the change may be partly '
                               f'applied. Restore from the backup if needed: {backup}')
            for show_cmd, expected in checks:
                if expected not in conn.send_command(show_cmd):
                    return False, (f'Check failed: "{expected}" was not found in '
                                   f'{show_cmd}. Backup: {backup}')
            conn.save_config()
            return True, f'Applied and verified. Backup: {backup}'
        finally:
            try:
                conn.disconnect()
            except Exception:
                pass
    except NetmikoTimeoutException:
        return False, 'No answer (wrong IP, device off, or SSH not enabled).'
    except NetmikoAuthenticationException:
        return False, 'Wrong username or password.'
    except Exception as err:
        return False, f'Error: {type(err).__name__}: {err}'
