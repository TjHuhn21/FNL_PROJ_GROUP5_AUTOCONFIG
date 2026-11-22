"""The complete Netmiko workflow, run directly against the mock lab with the REAL
netmiko.ConnectHandler(device_type='cisco_ios'). NetCommand is not involved.

    python netmiko_workflow.py               the lab must be running (python -m mocklab start)
    python netmiko_workflow.py --own-lab     start the lab inside this script, then stop it
    python netmiko_workflow.py --device SW1  another device (default MOCK-R1)

Steps: connect -> initial prompt -> enable (if needed) -> show running-config ->
configure terminal -> hostname -> end -> verification -> write mem -> disconnect.

It also reproduces, on purpose, the hostname-change timeout described in
README.md: after the hostname changes, Netmiko still waits for the OLD prompt.
"""
import argparse
import json
import os
import sys
import time

from netmiko import ConnectHandler
from netmiko.exceptions import ReadTimeout

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)


def step(n, text):
    print(f'\n=== {n}. {text}')


def show(text, limit=12):
    lines = text.splitlines()
    for line in lines[:limit]:
        print(f'    {line}')
    if len(lines) > limit:
        print(f'    ... ({len(lines) - limit} more lines)')


def run(device):
    host, port = device['host'], int(device.get('port', 22))
    new_name = 'BRANCH-' + ('RTR' if device['type'] == 'router' else 'SW')

    step(1, f"Connect: ConnectHandler(device_type='cisco_ios', host='{host}', port={port}, "
            f"username='{device['username']}', password=<hidden>)")
    start = time.time()
    conn = ConnectHandler(device_type='cisco_ios', host=host, port=port,
                          username=device['username'], password=device['password'],
                          secret=device['password'], conn_timeout=8, auth_timeout=10,
                          banner_timeout=10)
    prompt = conn.find_prompt()
    print(f'    connected in {time.time() - start:.2f} s; initial prompt: {prompt!r}')
    print(f'    Netmiko base prompt: {conn.base_prompt!r}')

    step(2, 'Enable mode if needed')
    if prompt.endswith('>'):
        conn.enable()
        print(f"    'enable' sent, password answered; prompt now {conn.find_prompt()!r}")
    else:
        print('    already privileged (prompt ends with #): enable not needed')

    step(3, 'Read the running configuration: show running-config')
    running = conn.send_command('show running-config')
    show(running, 14)

    step(4, 'Enter configuration mode: configure terminal')
    out = conn.config_mode()
    show(out)
    print(f'    check_config_mode() = {conn.check_config_mode()}')

    step(5, f'Change the hostname: hostname {new_name}')
    out = conn.send_config_set([f'hostname {new_name}'], enter_config_mode=False,
                               exit_config_mode=False)
    show(out)

    step(6, 'Exit configuration mode: end')
    out = conn.exit_config_mode()
    show(out)
    print(f'    check_config_mode() = {conn.check_config_mode()}')

    step(7, 'Verification (send_command finds the current prompt itself, so it works)')
    print(f'    Netmiko base prompt is still {conn.base_prompt!r}')
    out = conn.send_command('show running-config | include ^hostname')
    show(out)
    ok = f'hostname {new_name}' in out                 # the same rule NetCommand's checks use
    print(f"    hostname check (expected text found in the output): {'PASSED' if ok else 'FAILED'}")
    if out.strip().endswith(f'{new_name}#'):
        print(f'    note: the output ends with the new prompt {new_name + "#"!r}; Netmiko only '
              f'strips prompts that match the old base prompt')
    out = conn.send_command('show ip interface brief')
    show(out, 6)

    step(8, 'Save: write mem')
    print(f'    8a. save_config() while the base prompt is still {conn.base_prompt!r} '
          f'(KNOWN ISSUE, see README):')
    conn.read_timeout_override = 5            # 5 s instead of 10 s, only to keep the demo short
    saved_before = None
    try:
        out = conn.save_config()
        print('        saved without a timeout (the new name contains the old prompt text)')
    except ReadTimeout as err:
        print('        ReadTimeout: save_config() first calls enable() -> check_enable_mode(),')
        print(f'        which waits for the OLD prompt: {str(err).strip().splitlines()[0][:70]}')
        print('        "write mem" was NOT sent at that point.')
        conn.read_timeout_override = None
        conn.clear_buffer()
        conn.set_base_prompt()
        print(f'    8b. after conn.set_base_prompt() the base prompt is {conn.base_prompt!r}; '
              f'saving again:')
        out = conn.save_config()
    conn.read_timeout_override = None
    show(out)
    ok = ok and '[OK]' in out

    step(9, 'Disconnect')
    conn.disconnect()
    print(f"    disconnected cleanly; whole workflow took {time.time() - start:.1f} s")
    return ok


def main():
    p = argparse.ArgumentParser()
    p.add_argument('--device', default='MOCK-R1')
    p.add_argument('--own-lab', action='store_true')
    args = p.parse_args()
    with open(os.path.join(HERE, 'lab_config.json'), encoding='utf-8') as f:
        devices = {d['name']: d for d in json.load(f)['devices']}
    if args.device not in devices:
        sys.exit(f'No device named {args.device}')
    lab = None
    if args.own_lab:
        from mocklab.lab import Lab
        lab = Lab().start()
        print('Started the mock lab inside this script (configs reset from lab_config.json).')
    try:
        ok = run(devices[args.device])
    finally:
        if lab:
            lab.stop()
            print('Stopped the mock lab.')
    sys.exit(0 if ok else 1)


if __name__ == '__main__':
    main()
