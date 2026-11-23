"""Loading lab_config.json and running the whole lab.

    lab = Lab()                     # reads mock-lab/lab_config.json
    lab.start()                     # checks every address first, then listens
    lab.devices['MOCK-R1'].hostname      # the live simulated state (for tests)
    lab.set_failure('SW2', 'auth_fail')
    lab.advance(300)                # simulated time: rollback timers, reloads (no sleeping)
    lab.stop()

Every start builds the devices again from the file: changes made over SSH,
including `write mem`, last only until the lab stops.
"""
import ipaddress
import json
import logging
import os

from . import restore_sim
from .device import QUIRKS, SSH_CONDITIONS, Device
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
        unknown = set(d.get('quirks') or []) - set(QUIRKS)
        if unknown:
            raise LabError(f"{d['name']}: unknown quirk(s) {', '.join(sorted(unknown))}; use "
                           f"{', '.join(QUIRKS)}.")
        if d.get('ssh_condition', 'enabled') not in SSH_CONDITIONS:
            raise LabError(f"{d['name']}: ssh_condition must be one of "
                           f"{', '.join(SSH_CONDITIONS)}.")
        _check_restore_keys(d)
        names.add(d['name'])
        addresses.add(address)


def _check_restore_keys(d):
    """The restore-simulation keys of a device spec (all optional)."""
    name = d['name']
    if 'management_ip' in d:
        try:
            ipaddress.IPv4Address(d['management_ip'])
        except (ValueError, TypeError):
            raise LabError(f"{name}: management_ip {d['management_ip']!r} is not an IPv4 "
                           f"address.")
    if 'flash_bytes' in d and (not isinstance(d['flash_bytes'], int) or d['flash_bytes'] < 1024):
        raise LabError(f'{name}: flash_bytes must be a whole number of at least 1024.')
    archive = d.get('archive')
    if archive is not None:
        if not isinstance(archive, dict):
            raise LabError(f'{name}: archive must be an object such as {{"path": "flash:archive"}}.')
        path = archive.get('path')
        try:
            ok = path is None or bool(restore_sim.flash_path(path))
        except restore_sim.FlashError:
            ok = False
        if not ok:
            raise LabError(f'{name}: archive path must look like flash:<name>.')
        maximum = archive.get('maximum')
        if maximum is not None and (not isinstance(maximum, int) or not 1 <= maximum <= 14):
            raise LabError(f'{name}: archive maximum must be 1 to 14.')
    _check_identity_keys(d)


def _plain(value):
    """A single-line value without the characters that delimit show output."""
    return isinstance(value, str) and value.isprintable() and '"' not in value and \
        len(value) <= 80


def _check_identity_keys(d):
    """The restore-preflight keys (optional, synthetic): "serial" (a string, or a list of
    them for an ambiguous device) and "inventory" (a list of {"name", "descr", "pid", "vid",
    "sn"} entries)."""
    name = d['name']
    if 'serial' in d:
        serial = d['serial']
        values = [serial] if isinstance(serial, str) else serial
        if not isinstance(values, list) or not values or \
                not all(_plain(v) and v.strip() for v in values):
            raise LabError(f'{name}: serial must be a non-empty string or a list of them.')
    if 'inventory' in d:
        items = d['inventory']
        if not isinstance(items, list) or not all(
                isinstance(i, dict) and _plain(i.get('name')) and
                set(i) <= {'name', 'descr', 'pid', 'vid', 'sn'} and
                all(_plain(v) for v in i.values()) for i in items):
            raise LabError(f'{name}: inventory must be a list of {{"name", "descr", "pid", '
                           f'"vid", "sn"}} entries (single-line text).')


def read_control(path=CONTROL):
    """Failure modes changed while the lab runs (`python -m mocklab fail ...`)."""
    try:
        with open(path, encoding='utf-8') as f:
            return json.load(f)
    except (OSError, ValueError):
        return {}


class Lab:
    def __init__(self, config=None, key_path=KEY, overrides=None, control_path=None, clock=None):
        """config: a dict, or a path (default lab_config.json).
        overrides: {'MOCK-R1': ('127.0.0.1', 0)} to listen elsewhere (tests: free ports).
        control_path: a JSON file of live failure modes, re-read for each new connection.
        clock: a restore_sim.SimClock shared by every device (default: a new one at 0)."""
        self.config = config if isinstance(config, dict) else load_config(config or CONFIG)
        check_config(self.config)
        self.clock = clock or restore_sim.SimClock()
        self.key = load_host_key(key_path)
        shared = self.config.get('shared_scan_account') or {}
        hosts = {d['name']: (d['host'], d['type']) for d in self.config['devices']}
        control = (lambda: read_control(control_path)) if control_path else None
        self.devices, self.endpoints = {}, {}
        for spec in self.config['devices']:
            dev = Device(spec, lab_hosts=hosts, clock=self.clock)
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

    def advance(self, seconds):
        """Move simulated time on; expired rollback timers fire now."""
        self.clock.advance(seconds)
        for dev in self.devices.values():
            dev.tick()
        return self.clock.now()

    def set_failure(self, name, failure, **options):
        if name not in self.endpoints:
            raise LabError(f'There is no device named {name}.')
        self.endpoints[name].set_failure(failure, **options)

    def __enter__(self):
        return self.start()

    def __exit__(self, *exc):
        self.stop()
