"""Loading lab_config.json and running the whole lab.

    lab = Lab()                     # reads mock-lab/lab_config.json
    lab.start()                     # checks every address first, then listens
    lab.devices['R1'].hostname      # the live simulated state (for tests)
    lab.set_failure('SW2', 'auth_fail')
    lab.stop()

Every start builds the devices again from the file: changes made over SSH,
including `write mem`, last only until the lab stops.
"""
import ipaddress
import json
import logging
import os

from .device import Device
from .server import FAILURES, Endpoint, LabError, load_host_key

HERE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))     # mock-lab/
CONFIG = os.path.join(HERE, 'lab_config.json')
STATE = os.path.join(HERE, 'state')
KEY = os.path.join(HERE, 'keys', 'host_rsa.key')
CONTROL = os.path.join(STATE, 'failures.json')
log = logging.getLogger('mocklab')


def load_config(path=CONFIG):
    try:
        with open(path, encoding='utf-8') as f:
            config = json.load(f)
    except FileNotFoundError:
        raise LabError(f'The lab configuration file is missing: {path}')
    except json.JSONDecodeError as err:
        raise LabError(f'{path} is not valid JSON: {err}')
    check_config(config)
    return config


def check_config(config):
    devices = config.get('devices') or []
    if not devices:
        raise LabError('lab_config.json has no devices.')
    names, addresses = set(), set()
    for d in devices:
        for key in ('name', 'type', 'host', 'username', 'password'):
            if not d.get(key):
                raise LabError(f'A device in lab_config.json has no "{key}".')
        if d['type'] not in ('router', 'switch'):
            raise LabError(f"{d['name']}: type must be router or switch.")
        if d['name'] in names:
            raise LabError(f"Two devices are named {d['name']}.")
        try:
            ip = ipaddress.IPv4Address(d['host'])
        except ValueError:
            raise LabError(f"{d['name']}: host {d['host']!r} is not an IPv4 address.")
        if not ip.is_loopback:
            raise LabError(f"{d['name']}: host {d['host']} is not a loopback address (127.x.x.x). "
                           f"The mock lab only listens on this computer.")
        address = (d['host'], int(d.get('port', 22)))
        if address in addresses:
            raise LabError(f"{d['name']}: {address[0]}:{address[1]} is used twice.")
        if d.get('failure', 'none') not in FAILURES:
            raise LabError(f"{d['name']}: failure must be one of {', '.join(FAILURES)}.")
        names.add(d['name'])
        addresses.add(address)


def read_control(path=CONTROL):
    """Failure modes changed while the lab runs (`python -m mocklab fail ...`)."""
    try:
        with open(path, encoding='utf-8') as f:
            return json.load(f)
    except (OSError, ValueError):
        return {}


class Lab:
    def __init__(self, config=None, key_path=KEY, overrides=None, control_path=None):
        """config: a dict, or a path (default lab_config.json).
        overrides: {'R1': ('127.0.0.1', 0)} to listen elsewhere (tests: free ports).
        control_path: a JSON file of live failure modes, re-read for each new connection."""
        self.config = config if isinstance(config, dict) else load_config(config or CONFIG)
        check_config(self.config)
        self.key = load_host_key(key_path)
        shared = self.config.get('shared_scan_account') or {}
        hosts = {d['name']: (d['host'], d['type']) for d in self.config['devices']}
        control = (lambda: read_control(control_path)) if control_path else None
        self.devices, self.endpoints = {}, {}
        for spec in self.config['devices']:
            dev = Device(spec, lab_hosts=hosts)
            accounts = {spec['username']: (spec['password'], None)}
            if shared.get('username'):                    # like 'username labscan privilege 15'
                accounts[shared['username']] = (shared['password'], int(shared.get('privilege', 15)))
            host, port = (overrides or {}).get(spec['name'], (spec['host'], int(spec.get('port', 22))))
            self.devices[dev.name] = dev
            self.endpoints[dev.name] = Endpoint(dev, host, port, accounts, self.key,
                                                failure=spec.get('failure', 'none'),
                                                delay_ms=int(spec.get('delay_ms', 0)),
                                                drop_after=int(spec.get('drop_after', 1)),
                                                control=control)
        self.running = False

    def start(self):
        """Check every address first (nothing is started if one is taken), then listen."""
        for ep in self.endpoints.values():
            ep.check_free()
        started = []
        try:
            for ep in self.endpoints.values():
                ep.start()
                started.append(ep)
        except LabError:
            for ep in started:
                ep.stop()
            raise
        self.running = True
        return self

    def stop(self):
        for ep in self.endpoints.values():
            ep.stop()
        self.running = False

    def address(self, name):
        ep = self.endpoints[name]
        return ep.host, ep.port

    def set_failure(self, name, failure, **options):
        if name not in self.endpoints:
            raise LabError(f'There is no device named {name}.')
        self.endpoints[name].set_failure(failure, **options)

    def __enter__(self):
        return self.start()

    def __exit__(self, *exc):
        self.stop()
