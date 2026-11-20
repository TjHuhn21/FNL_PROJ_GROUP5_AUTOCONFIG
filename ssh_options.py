"""SSH settings shared by every NetCommand connection to a device (Scan, Review, Configure).

Strict by default. Every device gets Netmiko's `disabled_algorithms` with the old SHA-1
key exchanges, the `ssh-rsa` (SHA-1) host-key signature and the SHA-1/MD5 MACs turned
off, so a modern device is always reached with modern algorithms.

Some older Cisco IOS images (for example on Cisco 1900 routers) offer nothing newer. For
those, and ONLY for the IPv4 addresses listed in NETCOMMAND_LEGACY_SSH_HOSTS (environment
or the root .env), the SHA-1 key exchanges group14-sha1 and group-exchange-sha1, the
ssh-rsa host key and hmac-sha1 are allowed. diffie-hellman-group1-sha1 (a 1024-bit group)
and the MD5 MACs stay refused even then.

    NETCOMMAND_LEGACY_SSH_HOSTS=192.168.10.1, 192.168.10.2

Entries that are not IPv4 addresses are ignored (the device then stays strict).

describe_error() turns a failed connection into a short, fixed message. It never shows
the text of the exception, so no password or key can end up on screen or in a log.
"""
import errno
import ipaddress
import os
import socket

SETTING = 'NETCOMMAND_LEGACY_SSH_HOSTS'
ENV_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), '.env')

# allowed only for the listed hosts
LEGACY_KEX = ('diffie-hellman-group-exchange-sha1', 'diffie-hellman-group14-sha1')
LEGACY_HOST_KEYS = ('ssh-rsa',)
LEGACY_MACS = ('hmac-sha1', 'hmac-sha1-96')
# never allowed, for any host
NEVER_KEX = ('diffie-hellman-group1-sha1',)
NEVER_MACS = ('hmac-md5', 'hmac-md5-96')

# describe_error() kinds
AUTH, ALGORITHMS, TIMEOUT, REFUSED, OTHER = 'auth', 'algorithms', 'timeout', 'refused', 'other'


# ---------------------------------------------------------------- the setting
def _raw_setting(env_path=None):
    """The setting's text: the environment wins, else the root .env file."""
    if SETTING in os.environ:
        return os.environ[SETTING]
    path = env_path or ENV_PATH
    if os.path.exists(path):
        from dotenv import dotenv_values
        return dotenv_values(path).get(SETTING) or ''
    return ''


def _entries(text):
    return [e for e in (text or '').replace(',', ' ').replace(';', ' ').split() if e]


def _ipv4(text):
    try:
        return str(ipaddress.IPv4Address((text or '').strip()))
    except (ipaddress.AddressValueError, ValueError):
        return None


def legacy_hosts(env_path=None):
    """The IPv4 addresses that may use the old algorithms (a frozenset of strings)."""
    return frozenset(ip for ip in map(_ipv4, _entries(_raw_setting(env_path))) if ip)


def ignored_entries(env_path=None):
    """Entries of the setting that are not IPv4 addresses (they are ignored)."""
    return [e for e in _entries(_raw_setting(env_path)) if not _ipv4(e)]


def is_legacy(host, env_path=None):
    ip = _ipv4(host)
    return bool(ip) and ip in legacy_hosts(env_path)


# ---------------------------------------------------------------- connection options
def disabled_algorithms(host, env_path=None):
    """Paramiko's disabled_algorithms for this host (a new dict every time)."""
    if is_legacy(host, env_path):
        return {'kex': list(NEVER_KEX), 'macs': list(NEVER_MACS)}
    return {'kex': list(LEGACY_KEX + NEVER_KEX),
            'keys': list(LEGACY_HOST_KEYS),
            'pubkeys': list(LEGACY_HOST_KEYS),
            'macs': list(LEGACY_MACS + NEVER_MACS)}


def connect_options(host, env_path=None):
    """Extra keyword arguments for netmiko.ConnectHandler for this host."""
    return {'disabled_algorithms': disabled_algorithms(host, env_path)}


# ---------------------------------------------------------------- errors
def _chain(err):
    """err and the exceptions it was raised from (Netmiko wraps socket/Paramiko errors)."""
    seen, out = set(), []
    while err is not None and id(err) not in seen and len(out) < 10:
        seen.add(id(err))
        out.append(err)
        err = err.__cause__ or err.__context__
    return out


def _is(err, module, name):
    """True when err is (a subclass of) the class `name` from `module`. By name, so this
    file does not import Netmiko or Paramiko."""
    return any(c.__name__ == name and c.__module__.startswith(module)
               for c in type(err).__mro__)


def classify(err):
    """One of AUTH, ALGORITHMS, TIMEOUT, REFUSED, OTHER."""
    chain = _chain(err)
    if any(_is(e, 'netmiko', 'NetmikoAuthenticationException')
           or _is(e, 'paramiko', 'AuthenticationException') for e in chain):
        return AUTH
    text = ' '.join(str(e) for e in chain)      # only inspected, never shown
    if any(_is(e, 'paramiko', 'IncompatiblePeer') for e in chain) \
            or 'Incompatible ssh' in text or 'no acceptable' in text:
        return ALGORITHMS
    if any(isinstance(e, ConnectionRefusedError)
           or getattr(e, 'errno', None) in (errno.ECONNREFUSED, 10061) for e in chain):
        return REFUSED
    if any(isinstance(e, (socket.timeout, TimeoutError))
           or _is(e, 'netmiko', 'NetmikoTimeoutException') for e in chain):
        return TIMEOUT
    return OTHER


def describe_error(err, host=None):
    """(kind, message) for a failed SSH connection. The message is fixed text plus, for
    unknown errors, the exception's class name: never the exception's own text."""
    kind = classify(err)
    if kind == AUTH:
        return kind, 'the device rejected the username or password'
    if kind == ALGORITHMS:
        if host and is_legacy(host):
            return kind, ('the device and NetCommand have no SSH algorithm in common, even '
                          'with legacy SSH allowed for this address')
        return kind, ('the device offers only old SSH algorithms (SHA-1 key exchange or an '
                      'ssh-rsa host key), which NetCommand refuses by default. If it is an '
                      f'older Cisco device you control, add its IP address to {SETTING} in '
                      '.env and restart NetCommand')
    if kind == REFUSED:
        return kind, ('the connection to port 22 was refused (SSH is not enabled on the '
                      'device, or it is blocked)')
    if kind == TIMEOUT:
        return kind, ('no answer (the connection timed out: is the IP right, is the device '
                      'on, is it reachable?)')
    return kind, f'SSH error ({type(err).__name__})'
