"""python -m mocklab <command>      (run from the mock-lab folder)

    start [--fail NAME=MODE ...] [--background]
                     start every device from lab_config.json (configs are reset)
    stop             stop a lab started in another window or in the background
    status           which devices answer, and the lab's process
    fail NAME MODE   change a device's failure mode while the lab runs
                     (none, auth_fail, offline, hang, drop, slow; new connections only)
    check            check that every address in lab_config.json can be used, then exit
"""
import argparse
import json
import logging
import os
import signal
import subprocess
import sys
import time

from .lab import CONFIG, CONTROL, HERE, STATE, Lab, load_config, read_control
from .server import FAILURES, LabError, address_in_use

PID = os.path.join(STATE, 'lab.pid')
STOP = os.path.join(STATE, 'stop.request')
LOG = os.path.join(STATE, 'lab.log')


def _pid():
    try:
        with open(PID) as f:
            return int(f.read().strip())
    except (OSError, ValueError):
        return None


def _alive(pid):
    if not pid:
        return False
    if sys.platform == 'win32':
        out = subprocess.run(['tasklist', '/FI', f'PID eq {pid}', '/NH'], capture_output=True,
                             text=True).stdout
        return str(pid) in out
    try:
        os.kill(pid, 0)
        return True
    except OSError:
        return False


def table(config):
    rows = [f"  {'Device':<6} {'Type':<7} {'SSH address':<17} {'Login user':<11} Failure"]
    for d in config['devices']:
        rows.append(f"  {d['name']:<6} {d['type']:<7} {d['host'] + ':' + str(d.get('port', 22)):<17} "
                    f"{d['username']:<11} {d.get('failure', 'none')}")
    return '\n'.join(rows)


def cmd_start(args):
    os.makedirs(STATE, exist_ok=True)
    if _alive(_pid()):
        print(f'The lab is already running (process {_pid()}). Use: python -m mocklab stop')
        return 1
    if args.background:
        # Windows: detached, own process group, and (when allowed) outside the job object of
        # the window that started it, so closing that window does not end the lab.
        detached, breakaway = 0x00000008 | 0x00000200, 0x01000000
        cmd = [sys.executable, '-m', 'mocklab', 'start'] + sum((['--fail', f] for f in args.fail), [])
        with open(LOG, 'a', encoding='utf-8') as out:
            options = dict(cwd=HERE, stdout=out, stderr=out, stdin=subprocess.DEVNULL, close_fds=True)
            if sys.platform == 'win32':
                try:
                    subprocess.Popen(cmd, creationflags=detached | breakaway, **options)
                except OSError:                      # the job does not allow breaking away
                    subprocess.Popen(cmd, creationflags=detached, **options)
            else:
                subprocess.Popen(cmd, start_new_session=True, **options)
        for _ in range(50):
            time.sleep(0.2)
            if _alive(_pid()):
                print(f'Mock lab started in the background. Log: {LOG}')
                return 0
        print(f'The lab did not start. See {LOG}')
        return 1

    logging.basicConfig(level=logging.INFO, format='%(asctime)s %(message)s', datefmt='%H:%M:%S',
                        stream=sys.stdout)
    config = load_config(CONFIG)
    for item in args.fail:
        name, _, mode = item.partition('=')
        match = [d for d in config['devices'] if d['name'] == name]
        if not match or mode not in FAILURES:
            print(f'--fail {item}: use NAME=MODE with a device name and one of {", ".join(FAILURES)}')
            return 2
        match[0]['failure'] = mode
    for path in (STOP, CONTROL):
        if os.path.exists(path):
            os.remove(path)
    try:
        lab = Lab(config, control_path=CONTROL).start()
    except LabError as err:
        print(f'Could not start the mock lab: {err}')
        return 1
    with open(PID, 'w') as f:
        f.write(str(os.getpid()))
    print('NetCommand Mock Lab is running (simulated devices; not Cisco software).')
    print('Configurations were reset from lab_config.json. Logins are in that file.')
    print(table(config))
    print('Stop with Ctrl+C here, or "python -m mocklab stop" in another window.', flush=True)
    try:
        while not os.path.exists(STOP):
            time.sleep(0.3)
    except KeyboardInterrupt:
        pass
    finally:
        lab.stop()
        for path in (PID, STOP, CONTROL):
            if os.path.exists(path):
                os.remove(path)
        print('Mock lab stopped.', flush=True)
    return 0


def cmd_stop(args):
    pid = _pid()
    if not _alive(pid):
        print('The lab is not running.')
        if os.path.exists(PID):
            os.remove(PID)
        return 0
    os.makedirs(STATE, exist_ok=True)
    open(STOP, 'w').close()
    for _ in range(25):
        time.sleep(0.2)
        if not _alive(pid):
            print('Mock lab stopped.')
            return 0
    os.kill(pid, signal.SIGTERM)
    for path in (PID, STOP):
        if os.path.exists(path):
            os.remove(path)
    print('The lab did not stop by itself, so its process was ended.')
    return 0


def cmd_status(args):
    config = load_config(CONFIG)
    pid = _pid()
    print(f"Lab process: {'running (' + str(pid) + ')' if _alive(pid) else 'not running'}")
    live = read_control()
    for d in config['devices']:
        port = int(d.get('port', 22))
        state = 'answering' if address_in_use(d['host'], port) else 'not answering'
        failure = (live.get(d['name']) or {}).get('failure', d.get('failure', 'none'))
        print(f"  {d['name']:<6} {d['host']}:{port:<6} {state:<14} failure: {failure}")
    return 0


def cmd_fail(args):
    config = load_config(CONFIG)
    if args.name not in [d['name'] for d in config['devices']]:
        print(f'There is no device named {args.name}.')
        return 2
    if args.mode not in FAILURES:
        print(f'Unknown mode {args.mode}. Use one of: {", ".join(FAILURES)}')
        return 2
    if not _alive(_pid()):
        print('The lab is not running. Use: python -m mocklab start --fail NAME=MODE')
        return 1
    live = read_control()
    live[args.name] = {'failure': args.mode}
    os.makedirs(STATE, exist_ok=True)
    with open(CONTROL, 'w', encoding='utf-8') as f:
        json.dump(live, f)
    print(f'{args.name}: failure mode is now {args.mode} (for new connections).')
    return 0


def cmd_check(args):
    config = load_config(CONFIG)
    import socket
    problems = 0
    for d in config['devices']:
        host, port = d['host'], int(d.get('port', 22))
        if address_in_use(host, port):
            print(f"  {d['name']}: {host}:{port} is ALREADY IN USE")
            problems += 1
            continue
        s = socket.socket()
        try:
            if sys.platform == 'win32':
                s.setsockopt(socket.SOL_SOCKET, socket.SO_EXCLUSIVEADDRUSE, 1)
            s.bind((host, port))
            print(f"  {d['name']}: {host}:{port} can be used")
        except OSError as err:
            print(f"  {d['name']}: {host}:{port} cannot be used: {err.strerror}")
            problems += 1
        finally:
            s.close()
    print('All addresses are free.' if not problems else f'{problems} problem(s).')
    return 1 if problems else 0


def main(argv=None):
    p = argparse.ArgumentParser(prog='python -m mocklab', description=__doc__,
                                formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = p.add_subparsers(dest='command', required=True)
    s = sub.add_parser('start')
    s.add_argument('--fail', action='append', default=[], metavar='NAME=MODE')
    s.add_argument('--background', action='store_true')
    sub.add_parser('stop')
    sub.add_parser('status')
    sub.add_parser('check')
    f = sub.add_parser('fail')
    f.add_argument('name')
    f.add_argument('mode')
    args = p.parse_args(argv)
    try:
        return {'start': cmd_start, 'stop': cmd_stop, 'status': cmd_status, 'fail': cmd_fail,
                'check': cmd_check}[args.command](args)
    except LabError as err:
        print(err)
        return 1


if __name__ == '__main__':
    sys.exit(main())
