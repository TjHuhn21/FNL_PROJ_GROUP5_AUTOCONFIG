"""Watches the registered devices in the background.

Every INTERVAL seconds each device is checked (ping, then the SSH port). The
status is changed, and an event is saved, ONLY when it really changes, so the
log is not spammed. A device must fail twice in a row before it is marked down,
so one lost packet does not cause a false alarm.
"""
import socket
import subprocess
import sys
import threading

INTERVAL = 30
FAILS_BEFORE_DOWN = 2


def ping(ip, timeout_s=1):
    flags = ['-n', '1', '-w', str(timeout_s * 1000)] if sys.platform.startswith('win') \
        else ['-c', '1', '-W', str(timeout_s)]
    try:
        return subprocess.run(['ping'] + flags + [ip], capture_output=True,
                              timeout=timeout_s + 3).returncode == 0
    except Exception:
        return False


def ssh_open(ip, timeout_s=1):
    try:
        with socket.create_connection((ip, 22), timeout=timeout_s):
            return True
    except OSError:
        return False


def is_up(ip):
    return ping(ip) or ssh_open(ip)


def check_all(store, fails, check=is_up):
    """One round. fails is a dict {device_id: failures in a row}, kept between rounds.
    Returns the list of (device, new_status) that changed."""
    changed = []
    for d in store.get_devices('', 'name', 1, 1000):
        if check(d['ip']):
            fails[d['id']] = 0
            new = 'up'
        else:
            fails[d['id']] = fails.get(d['id'], 0) + 1
            new = 'down' if fails[d['id']] >= FAILS_BEFORE_DOWN else d['status']
        if new != d['status']:
            store.set_status(d['id'], new)
            store.add_event(d['id'], new, f"{d['name']} ({d['ip']}) is now {new}")
            changed.append((d, new))
    return changed


def start_monitor(store, interval=INTERVAL, on_change=None, check=is_up):
    """Start the background thread. Call stop.set() on the returned Event to stop it."""
    stop, fails = threading.Event(), {}

    def loop():
        while not stop.is_set():
            try:
                for d, new in check_all(store, fails, check):
                    if on_change:
                        on_change(d, new)
            except Exception:
                pass                      # never let the monitor crash the app
            stop.wait(interval)

    threading.Thread(target=loop, daemon=True).start()
    return stop
