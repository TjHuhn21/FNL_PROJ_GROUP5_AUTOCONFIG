"""Typed backend settings.

Where they come from (and where they never come from):
  * the backend's OWN environment file: backend/.env, or the file named by the
    NETCOMMAND_BACKEND_ENV_FILE environment variable. A missing file is fine;
  * process environment variables, which override the file;
  * ONLY names starting with BACKEND_. The desktop application's .env (DB_HOST,
    DB_PASSWORD, FERNET_KEY, ...) is never read, and its names are ignored even when
    they are in the environment, so the backend can never fall back to the desktop's
    database configuration.

Secret values are kept in Secret objects: printing, repr() or logging one shows
'**********', and every error message names the setting, never its value.

Nothing here connects to anything. Feature groups (database, SMTP) are checked only
when explicitly enabled; the health endpoint needs none of them.
"""
import base64
import binascii
import os
import re
from dataclasses import dataclass, field
from pathlib import Path

from dotenv import dotenv_values

PREFIX = 'BACKEND_'
ENV_FILE_VARIABLE = 'NETCOMMAND_BACKEND_ENV_FILE'
DEFAULT_ENV_FILE = Path(__file__).resolve().parent / '.env'

ENVIRONMENTS = ('development', 'test', 'production')
LOG_LEVELS = ('DEBUG', 'INFO', 'WARNING', 'ERROR', 'CRITICAL')
_TRUE = {'1', 'true', 'yes', 'on'}
_FALSE = {'0', 'false', 'no', 'off', ''}
_EMAIL = re.compile(r'^[^@\s]+@[^@\s]+\.[^@\s]+$')
_HOST = re.compile(r'^[A-Za-z0-9.\-:]+$')          # name, IPv4 or IPv6 literal; no spaces
_DB_NAME = re.compile(r'^[A-Za-z0-9_]{1,64}$')
OTP_PEPPER_MIN_LENGTH = 32


class SettingsError(ValueError):
    """One or more settings are missing or invalid. .problems lists them; every message
    names a setting, never its value."""

    def __init__(self, problems):
        self.problems = list(problems)
        super().__init__('Invalid backend settings: ' + '; '.join(self.problems))


class Secret:
    """A secret setting. str(), repr() and f-strings show only '**********'.
    reveal() returns the real value, for the code that must use it."""
    __slots__ = ('_value',)
    MASK = '**********'

    def __init__(self, value):
        self._value = value

    def reveal(self):
        return self._value

    def __bool__(self):
        return bool(self._value)

    def __eq__(self, other):
        return isinstance(other, Secret) and other._value == self._value

    def __hash__(self):
        return hash(self._value)

    def __repr__(self):
        return f'Secret({self.MASK})'

    def __str__(self):
        return self.MASK

    def __format__(self, spec):
        return self.MASK

    def __reduce__(self):              # never pickled with its value
        raise TypeError('Secret values cannot be pickled')


@dataclass(frozen=True)
class DatabaseSettings:
    host: str
    port: int
    user: str
    password: Secret = field(repr=False)
    name: str


@dataclass(frozen=True)
class SmtpSettings:
    host: str
    port: int
    username: str
    password: Secret = field(repr=False)
    sender: str


@dataclass(frozen=True)
class Settings:
    environment: str = 'development'
    host: str = '127.0.0.1'
    port: int = 8000
    log_level: str = 'INFO'
    database: DatabaseSettings = None           # None unless BACKEND_DB_ENABLED=true
    smtp: SmtpSettings = None                   # None unless BACKEND_SMTP_ENABLED=true
    fernet_key: Secret = field(default=None, repr=False)
    otp_pepper: Secret = field(default=None, repr=False)
    # The MIGRATION account (python -m backend.database.migrate only; never the web app).
    migrate_user: str = ''
    migrate_password: Secret = field(default=None, repr=False)

    @property
    def docs_enabled(self):
        return self.environment != 'production'

    def secret_values(self):
        """Every secret value that is set (for the logging redaction filter)."""
        found = [s.reveal() for s in (self.fernet_key, self.otp_pepper,
                                      self.migrate_password) if s]
        for group in (self.database, self.smtp):
            if group is not None and group.password:
                found.append(group.password.reveal())
        return found


# ---------------------------------------------------------------- loading
def env_file_path(environ=None):
    environ = os.environ if environ is None else environ
    named = environ.get(ENV_FILE_VARIABLE)
    return Path(named) if named else DEFAULT_ENV_FILE


def read_raw(env_file=None, environ=None, use_file=True):
    """The BACKEND_ settings as plain strings: file first, then the environment on top.
    Other names (the desktop's DB_*, FERNET_KEY, ...) are dropped."""
    environ = os.environ if environ is None else environ
    raw = {}
    if use_file:
        path = Path(env_file) if env_file is not None else env_file_path(environ)
        if path.is_file():
            raw.update({k: v for k, v in dotenv_values(path).items()
                        if k.startswith(PREFIX) and v is not None})
    raw.update({k: v for k, v in environ.items() if k.startswith(PREFIX)})
    return raw


def load_settings(env_file=None, environ=None, use_file=True):
    """Settings from the backend env file and environment; raises SettingsError."""
    return parse_settings(read_raw(env_file, environ, use_file))


def parse_settings(raw):
    problems = []
    get = lambda name, default=None: (raw.get(PREFIX + name, default) or default)

    def text(name, default=''):
        value = get(name, default)
        return value.strip() if isinstance(value, str) else value

    def flag(name):
        value = text(name, '').lower()
        if value in _TRUE:
            return True
        if value not in _FALSE:
            problems.append(f'{PREFIX}{name} must be true or false.')
        return False

    def port(name, default=None):
        value = text(name, default)
        if value in (None, ''):
            problems.append(f'{PREFIX}{name} is required.')
            return None
        try:
            number = int(value)
        except (TypeError, ValueError):
            problems.append(f'{PREFIX}{name} must be a whole number.')
            return None
        if not 1 <= number <= 65535:
            problems.append(f'{PREFIX}{name} must be from 1 to 65535.')
            return None
        return number

    def required(name):
        value = text(name)
        if not value:
            problems.append(f'{PREFIX}{name} is required.')
        return value

    def required_secret(name):
        value = get(name)                 # secrets are not stripped: kept exactly
        if not value:
            problems.append(f'{PREFIX}{name} is required.')
        return Secret(value or '')

    def host(name, default=None):
        value = text(name, default) if default else required(name)
        if value and not _HOST.match(value):
            problems.append(f'{PREFIX}{name} is not a valid host name or address.')
        return value

    environment = text('ENV', 'development').lower()
    if environment not in ENVIRONMENTS:
        problems.append(f'{PREFIX}ENV must be one of: {", ".join(ENVIRONMENTS)}.')
    log_level = text('LOG_LEVEL', 'INFO').upper()
    if log_level not in LOG_LEVELS:
        problems.append(f'{PREFIX}LOG_LEVEL must be one of: {", ".join(LOG_LEVELS)}.')
    bind_host = host('HOST', '127.0.0.1')
    bind_port = port('PORT', '8000')

    database = None
    if flag('DB_ENABLED'):
        name = required('DB_NAME')
        if name and not _DB_NAME.match(name):
            problems.append(f'{PREFIX}DB_NAME may only use letters, numbers and underscores.')
        database = DatabaseSettings(host=host('DB_HOST'), port=port('DB_PORT'),
                                    user=required('DB_USER'),
                                    password=required_secret('DB_PASSWORD'), name=name)

    smtp = None
    if flag('SMTP_ENABLED'):
        sender = required('SMTP_FROM')
        if sender and not _EMAIL.match(sender):
            problems.append(f'{PREFIX}SMTP_FROM must be an email address.')
        smtp = SmtpSettings(host=host('SMTP_HOST'), port=port('SMTP_PORT', '587'),
                            username=required('SMTP_USERNAME'),
                            password=required_secret('SMTP_PASSWORD'), sender=sender)

    fernet_key = None
    if get('FERNET_KEY'):                 # optional now; checked when present
        fernet_key = Secret(get('FERNET_KEY'))
        if not _valid_fernet_key(fernet_key.reveal()):
            problems.append(f'{PREFIX}FERNET_KEY is not a valid Fernet key '
                            f'(32 bytes, URL-safe base64).')

    otp_pepper = None
    if get('OTP_PEPPER'):
        otp_pepper = Secret(get('OTP_PEPPER'))
        if len(otp_pepper.reveal()) < OTP_PEPPER_MIN_LENGTH:
            problems.append(f'{PREFIX}OTP_PEPPER must be at least {OTP_PEPPER_MIN_LENGTH} '
                            f'characters.')

    migrate_user = text('MIGRATE_USER')
    migrate_password = Secret(get('MIGRATE_PASSWORD')) if get('MIGRATE_PASSWORD') else None
    if (migrate_user and database is not None and database.user
            and migrate_user.lower() == database.user.lower()):
        problems.append(f'{PREFIX}MIGRATE_USER must be a different account from {PREFIX}DB_USER '
                        f'(the runtime account must not be able to create or drop tables).')

    if problems:
        raise SettingsError(problems)
    return Settings(environment=environment, host=bind_host, port=bind_port,
                    log_level=log_level, database=database, smtp=smtp,
                    fernet_key=fernet_key, otp_pepper=otp_pepper,
                    migrate_user=migrate_user, migrate_password=migrate_password)


def _valid_fernet_key(value):
    try:
        return len(base64.urlsafe_b64decode(value.encode('ascii'))) == 32
    except (binascii.Error, ValueError, UnicodeEncodeError):
        return False


def describe(settings):
    """A safe one-line summary for startup logs: no secret values, only whether set."""
    parts = [f'environment={settings.environment}', f'bind={settings.host}:{settings.port}',
             f'log_level={settings.log_level}',
             f"database={'enabled' if settings.database else 'disabled'}",
             f"smtp={'enabled' if settings.smtp else 'disabled'}",
             f"fernet_key={'set' if settings.fernet_key else 'not set'}",
             f"otp_pepper={'set' if settings.otp_pepper else 'not set'}"]
    return ' '.join(parts)


__all__ = ['Settings', 'DatabaseSettings', 'SmtpSettings', 'Secret', 'SettingsError',
           'load_settings', 'parse_settings', 'read_raw', 'env_file_path', 'describe']
