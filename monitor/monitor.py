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
    Returns the list of (device, new_status) that changed AND were recorded.

    The status and its event are saved together (store.record_status_change: one
    transaction) or not at all. A failed save raises (the caller reports it); the status
    in the database is then unchanged, so the next round tries again: no event is lost
    and none is recorded twice. A device changed meanwhile by someone else is skipped."""
    record = getattr(store, 'record_status_change', None)
    changed = []
    for d in store.get_devices('', 'name', 1, 1000):
        if check(d['ip']):
            fails[d['id']] = 0
            new = 'up'
        else:
            fails[d['id']] = fails.get(d['id'], 0) + 1
            new = 'down' if fails[d['id']] >= FAILS_BEFORE_DOWN else d['status']
        if new != d['status']:
            detail = f"{d['name']} ({d['ip']}) is now {new} (was {d['status']})"
            if record is not None:
                if not record(d['id'], d['status'], new, detail):
                    continue                  # changed meanwhile: nothing recorded
            else:                             # a store without it (older stand-ins)
                store.set_status(d['id'], new)
                store.add_event(d['id'], new, detail)
            changed.append((d, new))
    return changed


def start_monitor(store, interval=INTERVAL, on_change=None, check=is_up, on_error=None):
    """Start the background thread. Call stop.set() on the returned Event to stop it.

    on_error(err) is called (from the monitor thread, so it must be thread-safe) when a
    round fails, for example because the database is unavailable: once per run of
    failures, not every round. The monitor keeps running and carries on by itself when
    the database is back; a failed round changes no status and records no event."""
    stop, fails = threading.Event(), {}
    state = {'failing': False}

    def loop():
        while not stop.is_set():
            try:
                for d, new in check_all(store, fails, check):
                    if on_change:
                        on_change(d, new)
                state['failing'] = False
            except Exception as err:      # never let the monitor crash the app...
                if not state['failing']:  # ...but never hide the failure either
                    state['failing'] = True
                    if on_error:
                        try:
                            on_error(err)
                        except Exception:
                            pass
            stop.wait(interval)

    threading.Thread(target=loop, daemon=True).start()
    return stop
