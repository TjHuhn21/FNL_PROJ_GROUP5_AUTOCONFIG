"""Values allowed in the shared application tables (migrations 2-4), checked BEFORE any
database work by both repositories (AppRepository and InMemoryAppRepository).

The device rules are the desktop's own (validation.check_name / check_mac / check_login,
db._check_name): the backend does not import the desktop modules, so they are repeated
here and a test keeps the two in step.

The checks also stop secrets from being stored or shown by mistake:
  * a saved login's password must arrive ENCRYPTED (a Fernet token): a plaintext password
    is refused, and so is a token that is not well formed. Messages never repeat a value;
  * a backup's content must be a Fernet token too (a running configuration holds password
    hashes);
  * job parameters refuse keys that look like secrets and values that look like tokens;
  * job event text is masked (the desktop's rule: values after password / secret to the
    end of the line, and the word after key / key-string / community) and length-limited.
"""
import base64
import binascii
import ipaddress
import json
import re

from backend.database.errors import InvalidValue

DEVICE_TYPES = ('switch', 'router', 'unknown')
DEVICE_STATUSES = ('up', 'down')
LOG_STATUSES = ('success', 'failed')
SEVERITIES = ('high', 'medium', 'low')
EVENT_SOURCES = ('monitor', 'user', 'job', 'legacy')
JOB_STATES = ('queued', 'running', 'succeeded', 'failed', 'cancelled', 'interrupted')
FINISHED_STATES = ('succeeded', 'failed', 'cancelled', 'interrupted')
# Allowed changes; a finished state never changes again.
JOB_TRANSITIONS = {'queued': ('running', 'cancelled', 'interrupted'),
                   'running': ('succeeded', 'failed', 'cancelled', 'interrupted')}
JOB_EVENT_KINDS = ('info', 'command', 'output', 'warning', 'error', 'state')
BACKUP_KINDS = ('running', 'startup')
SORT_KEYS = ('name', 'ip', 'type', 'status', 'created_at')
CREDENTIAL_CHOICES = ('keep', 'replace')

NAME_MAX = 80
LOGIN_USERNAME_MAX = 50
PORT_MAX = 40
RULE_MAX = 60
ACTION_MAX = 100
EVENT_KIND_MAX = 30
JOB_KIND_MAX = 32
PURPOSE_MAX = 64
SUMMARY_MAX = 1000
JOB_MESSAGE_MAX = 1000             # app_job_devices.message
JOB_EVENT_MAX = 2000               # app_job_events.message (after masking)
TEXT_MAX_BYTES = 65535             # TEXT columns (details, detail, message, commands)
SEARCH_MAX = 200
PER_PAGE_MAX = 500
EVENTS_LIMIT_MAX = 1000
PARAMS_MAX_BYTES = 8192
TOKEN_MIN = 100                    # a Fernet token of an empty password is 100 characters
TOKEN_MAX = 255                    # app_device_credentials.password_enc VARCHAR(255)
BACKUP_MAX_BYTES = 4 * 1024 * 1024  # plaintext configuration (size_bytes CHECK)
BACKUP_TOKEN_MAX = 16 * 1024 * 1024 - 1   # MEDIUMBLOB
LOCK_MIN_SECONDS = 5
LOCK_MAX_SECONDS = 3600
DEFAULT_KEY_ID = 'k1'
TRUNCATED = ' [truncated]'

_NAME = re.compile(r'^[A-Za-z0-9._-]+$')
_MAC = re.compile(r'^([0-9A-Fa-f]{2}([:-])[0-9A-Fa-f]{2}(\2[0-9A-Fa-f]{2}){4}'
                  r'|[0-9A-Fa-f]{4}\.[0-9A-Fa-f]{4}\.[0-9A-Fa-f]{4})$')
_KEY_ID = re.compile(r'^[a-z0-9][a-z0-9_-]{0,15}$')
_IDENT = re.compile(r'^[a-z][a-z0-9_.-]*$')
_HEX64 = re.compile(r'^[0-9a-f]{64}$')
_LEASE = re.compile(r'^[0-9a-f]{32}$')
_B64URL = re.compile(r'^[A-Za-z0-9_-]+={0,2}$')
_CONTROL = re.compile(r'[\x00-\x08\x0b-\x1f\x7f]')   # keeps \t and \n
_SECRET_KEY = re.compile(r'(?i)pass|secret|token|credential|community|private|key')
# The desktop's masking rules (config.connect.mask), repeated EXACTLY (a test compares
# them): values after password / secret are hidden to the end of the line; one word after
# key / key-string / community, SNMPv3 auth and priv, OSPF/NTP md5 keys, HSRP/VRRP/GLBP
# authentication, wpa-psk and IKEv2 pre-shared-key local/remote/address/hostname. Every
# rule stays on one line ([ \t], never \s), so a value is never taken from the next line.
MASK = '********'
_SECRET_TO_EOL = re.compile(r'(\b(?:password|secret)[ \t]+(?:\d{1,2}[ \t]+)?)\S[^\r\n]*',
                            re.IGNORECASE)
_SECRET_WORD_RULES = (
    r'\bauth[ \t]+(?:md5|sha\d*)[ \t]+',                        # SNMPv3 user: auth key
    r'\bpriv[ \t]+(?:3des|des\d*|aes(?:[ \t]+\d+)?)[ \t]+',     # SNMPv3 user: privacy key
    r'\b(?:message-digest-key|authentication-key)[ \t]+\d+[ \t]+md5[ \t]+(?:\d[ \t]+)?',
    r'\b(?:standby|vrrp|glbp)[ \t]+(?:\d+[ \t]+)?authentication[ \t]+(?:text[ \t]+)?'
    r'(?!md5\b)',                                               # md5: key-string below
    r'\bwpa-psk[ \t]+(?:ascii|hex)[ \t]+(?:\d[ \t]+)?',
    r'\bpre-shared-key[ \t]+(?:local|remote)[ \t]+(?:\d[ \t]+)?',
    r'\bpre-shared-key[ \t]+(?:address|hostname)[ \t]+(?:\S+[ \t]+){1,2}?key[ \t]+'
    r'(?:\d[ \t]+)?',
    # SNMP v1/v2c notification host: the community after the address (v3 has a user name
    # there, not a secret, so "version 3" lines are left alone).
    r'\bsnmp-server[ \t]+host[ \t]+\S+[ \t]+(?:(?:informs|traps)[ \t]+)?'
    r'(?:version[ \t]+(?:1|2c)[ \t]+)?(?!version\b)',
    r'\bkey[ \t]+config-key[ \t]+(?:password-encrypt|\d+)[ \t]+',  # type 6 master key
    # The original rule; never the word config-key itself (nor the "key" inside it).
    r'(?<!config-)\b(?:key-string|community|key)[ \t]+(?:\d[ \t]+)?(?!config-key\b)',
)
_SECRET_WORD = re.compile('(' + '|'.join(f'(?:{r})' for r in _SECRET_WORD_RULES) + r')(\S+)',
                          re.IGNORECASE)


# ---------------------------------------------------------------- generic
def check_id(value, what='id'):
    if isinstance(value, bool) or not isinstance(value, int) or value < 1:
        raise InvalidValue(f'{what} must be a positive whole number.')
    return value


def check_optional_id(value, what):
    return None if value is None else check_id(value, what)


def check_choice(value, choices, what):
    if value not in choices:
        raise InvalidValue(f'{what} must be one of: {", ".join(choices)}.')
    return value


def check_line(value, what, max_chars, required=True):
    """One line of text (VARCHAR). Empty is allowed only when not required."""
    if value is None and not required:
        return None
    if not isinstance(value, str):
        raise InvalidValue(f'{what} must be text.')
    if required and not value.strip():
        raise InvalidValue(f'{what} is required.')
    if len(value) > max_chars or '\n' in value or '\r' in value or _CONTROL.search(value):
        raise InvalidValue(f'{what} must be one line of at most {max_chars} characters.')
    return value


def check_text(value, what, max_bytes=TEXT_MAX_BYTES):
    """Free text for a TEXT column ('' and None are stored as '')."""
    if value is None:
        return ''
    if not isinstance(value, str):
        raise InvalidValue(f'{what} must be text.')
    try:
        size = len(value.encode('utf-8'))
    except UnicodeError:
        raise InvalidValue(f'{what} contains characters that cannot be stored.') from None
    if size > max_bytes:
        raise InvalidValue(f'{what} is too long (at most {max_bytes} bytes).')
    return value


def check_identifier(value, what, max_chars):
    """A lower-case code such as a job kind or a lock purpose."""
    if not isinstance(value, str) or not _IDENT.match(value) or len(value) > max_chars:
        raise InvalidValue(f'{what} must be a lower-case code of at most {max_chars} '
                           f'characters (letters, digits, . _ -).')
    return value


def check_page(page, per_page):
    for value, what in ((page, 'page'), (per_page, 'per_page')):
        check_id(value, what)
    if per_page > PER_PAGE_MAX:
        raise InvalidValue(f'per_page must be at most {PER_PAGE_MAX}.')
    return page, per_page


def check_search(value):
    if value is None:
        return ''
    return check_line(value, 'The search text', SEARCH_MAX, required=False)


def check_limit(value, maximum=EVENTS_LIMIT_MAX):
    check_id(value, 'limit')
    if value > maximum:
        raise InvalidValue(f'limit must be at most {maximum}.')
    return value


# ---------------------------------------------------------------- devices
def check_name(name):
    """validation.check_name, and no spaces around the name (as db._check_name)."""
    if not isinstance(name, str):
        raise InvalidValue('The name is required.')
    stripped = name.strip()
    if not stripped:
        raise InvalidValue('The name is required.')
    if len(stripped) > NAME_MAX:
        raise InvalidValue('The name must be 80 characters or fewer.')
    if not _NAME.match(stripped):
        raise InvalidValue('The name can only use letters, numbers, dots, dashes, and '
                           'underscores.')
    if name != stripped:
        raise InvalidValue('The name cannot start or end with a space.')
    return name


def name_key(name):
    """What uniqueness compares: the name in lower case (ASCII only, so MySQL's LOWER()
    and Python agree; see m0002)."""
    return name.lower()


def check_ip(ip):
    if not isinstance(ip, str):
        raise InvalidValue('Enter a valid IPv4 address, like 192.168.1.10')
    try:
        address = ipaddress.IPv4Address(ip.strip())
    except ValueError:
        raise InvalidValue('Enter a valid IPv4 address, like 192.168.1.10') from None
    if str(address) != ip:
        raise InvalidValue('Enter the IPv4 address without spaces or leading zeros, like '
                           '192.168.1.10')
    return ip


def check_mac(mac):
    """'' (unknown) or a MAC address as the desktop stores it."""
    if mac is None or mac == '':
        return ''
    if not isinstance(mac, str) or not _MAC.match(mac.strip()) or mac != mac.strip():
        raise InvalidValue('This is not a MAC address (use aa:bb:cc:dd:ee:ff or '
                           'aabb.ccdd.eeff).')
    return mac


def check_device(data, require_ip=True):
    """A cleaned copy of the device fields the tables store."""
    if not isinstance(data, dict):
        raise InvalidValue('The device details are required.')
    cleaned = {'name': check_name(data.get('name')),
               'type': check_choice(data.get('type', 'unknown'), DEVICE_TYPES, 'type'),
               'status': check_choice(data.get('status', 'up'), DEVICE_STATUSES, 'status'),
               'managed': bool(data.get('managed')),
               'mac': check_mac(data.get('mac', ''))}
    if require_ip or 'ip' in data:
        cleaned['ip'] = check_ip(data.get('ip'))
    return cleaned


# ---------------------------------------------------------------- credentials
def check_login_username(username):
    """validation.check_login's username rules (the password arrives encrypted)."""
    if not isinstance(username, str) or not username.strip():
        raise InvalidValue('The login username is required.')
    user = username.strip()
    if '\n' in user or '\r' in user or _CONTROL.search(user):
        raise InvalidValue('The login username must be on one line (no line breaks).')
    if len(user) > LOGIN_USERNAME_MAX:
        raise InvalidValue(f'The login username must be {LOGIN_USERNAME_MAX} characters or '
                           f'fewer (this one has {len(user)}).')
    return user


def is_fernet_token(value, min_chars=TOKEN_MIN, max_chars=TOKEN_MAX):
    """True if value has the exact shape of a Fernet token: URL-safe base64 of version
    0x80, an 8-byte time, a 16-byte IV, whole AES blocks and a 32-byte HMAC. It does NOT
    prove the token decrypts (only the key can), but a plaintext password never passes."""
    if isinstance(value, (bytes, bytearray)):
        try:
            value = bytes(value).decode('ascii')
        except UnicodeDecodeError:
            return False
    if not isinstance(value, str) or not (min_chars <= len(value) <= max_chars):
        return False
    if len(value) % 4 or not _B64URL.match(value) or not value.startswith('gAAAAA'):
        return False
    try:
        raw = base64.urlsafe_b64decode(value)
    except (binascii.Error, ValueError):
        return False
    body = len(raw) - 1 - 8 - 16 - 32
    return raw[0] == 0x80 and body >= 16 and body % 16 == 0


def check_password_token(token):
    if not is_fernet_token(token):
        raise InvalidValue('The saved login password must be given encrypted (a Fernet token '
                           'made with the backend key); this value is not one. Nothing was '
                           'saved.')
    return token


def check_key_id(key_id):
    if not isinstance(key_id, str) or not _KEY_ID.match(key_id):
        raise InvalidValue('key_id must be a short lower-case name such as k1.')
    return key_id


# ---------------------------------------------------------------- links and findings
def check_port(port, what):
    return check_line(port, what, PORT_MAX)


def check_link(link):
    try:
        a, pa, b, pb = link
    except (TypeError, ValueError):
        raise InvalidValue('A link is (device_a, port_a, device_b, port_b).') from None
    for value in (a, b):
        check_line(value, 'A link device name', NAME_MAX)
    return (a, check_port(pa, 'port_a'), b, check_port(pb, 'port_b'))


def check_finding(f):
    if not isinstance(f, dict):
        raise InvalidValue('A finding must be a dictionary.')
    commands = f.get('commands') or []
    if isinstance(commands, str) or not all(isinstance(c, str) and '\n' not in c
                                            for c in commands):
        raise InvalidValue('A finding\'s commands must be a list of one-line texts.')
    cleaned = {'device': check_line(f.get('device'), 'The finding\'s device', NAME_MAX),
               'rule': check_line(f.get('rule'), 'The finding\'s rule', RULE_MAX),
               'severity': check_choice(f.get('severity'), SEVERITIES, 'severity'),
               'message': check_text(f.get('message'), 'The finding\'s message'),
               'commands': list(commands)}
    if not cleaned['message'].strip():
        raise InvalidValue('The finding\'s message is required.')
    check_text('\n'.join(cleaned['commands']), 'The finding\'s commands')
    return cleaned


def escape_like(text):
    """For MySQL LIKE: the search text is matched literally (as the in-memory search)."""
    return text.replace('\\', '\\\\').replace('%', '\\%').replace('_', '\\_')


# ---------------------------------------------------------------- jobs and locks
def check_job_transition(current, new):
    check_choice(new, JOB_STATES, 'state')
    if new not in JOB_TRANSITIONS.get(current, ()):
        from backend.database.errors import InvalidTransition
        raise InvalidTransition(f'A {current} job (or job device) cannot become {new}. '
                                f'Nothing was changed.')
    return new


def check_params(params):
    """Job options as JSON text (or None). Secrets never belong here: keys that look like
    secrets and values that look like Fernet tokens are refused."""
    if params is None:
        return None
    if not isinstance(params, dict):
        raise InvalidValue('Job parameters must be a dictionary.')

    def walk(value):
        if isinstance(value, dict):
            for k, v in value.items():
                if not isinstance(k, str):
                    raise InvalidValue('Job parameter names must be text.')
                if _SECRET_KEY.search(k):
                    raise InvalidValue('Job parameters must not contain secrets (a name such '
                                       'as password, secret, token or key was given). Nothing '
                                       'was saved.')
                walk(v)
        elif isinstance(value, (list, tuple)):
            for v in value:
                walk(v)
        elif isinstance(value, str):
            if is_fernet_token(value, min_chars=TOKEN_MIN, max_chars=BACKUP_TOKEN_MAX):
                raise InvalidValue('Job parameters must not contain encrypted secrets. '
                                   'Nothing was saved.')
        elif value is not None and not isinstance(value, (bool, int, float)):
            raise InvalidValue('Job parameters must be plain JSON values.')
    walk(params)
    text = json.dumps(params, sort_keys=True, separators=(',', ':'))
    if len(text.encode('utf-8')) > PARAMS_MAX_BYTES:
        raise InvalidValue(f'Job parameters must be at most {PARAMS_MAX_BYTES} bytes.')
    return text


def mask_secrets(text):
    text = _SECRET_TO_EOL.sub(lambda m: m.group(1) + MASK, text or '')
    return _SECRET_WORD.sub(lambda m: m.group(1) + MASK, text)


def clean_job_text(text, limit):
    """Masked first, then control characters removed and the text cut to limit characters
    (masking first, so a cut can never leave part of a secret behind a removed keyword)."""
    if not isinstance(text, str):
        raise InvalidValue('The job message must be text.')
    cleaned = _CONTROL.sub('', mask_secrets(text))
    if len(cleaned) > limit:
        cleaned = cleaned[:limit - len(TRUNCATED)] + TRUNCATED
    return cleaned


def check_lock_seconds(seconds):
    if isinstance(seconds, bool) or not isinstance(seconds, int) or \
            not LOCK_MIN_SECONDS <= seconds <= LOCK_MAX_SECONDS:
        raise InvalidValue(f'A device lock lasts {LOCK_MIN_SECONDS} to {LOCK_MAX_SECONDS} '
                           f'seconds.')
    return seconds


def check_lease(lease_id):
    if not isinstance(lease_id, str) or not _LEASE.match(lease_id):
        raise InvalidValue('The lock lease id is not valid.')
    return lease_id


# ---------------------------------------------------------------- backups
def check_sha256(value):
    if not isinstance(value, str) or not _HEX64.match(value):
        raise InvalidValue('sha256 must be 64 lower-case hexadecimal characters.')
    return value


def check_backup_size(size):
    if isinstance(size, bool) or not isinstance(size, int) or not 0 <= size <= BACKUP_MAX_BYTES:
        raise InvalidValue(f'A backup is at most {BACKUP_MAX_BYTES} bytes.')
    return size


def check_backup_content(content_enc):
    """The encrypted backup as bytes (a Fernet token). Plaintext is refused."""
    if isinstance(content_enc, str):
        content_enc = content_enc.encode('ascii', 'replace')
    if not isinstance(content_enc, (bytes, bytearray)) or \
            not is_fernet_token(bytes(content_enc), max_chars=BACKUP_TOKEN_MAX):
        raise InvalidValue('A backup must be stored encrypted (a Fernet token made with the '
                           'backend key); this content is not one. Nothing was saved.')
    return bytes(content_enc)
