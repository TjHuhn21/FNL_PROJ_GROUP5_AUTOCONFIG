"""The authentication policy: one validated place for every limit.

The defaults are the approved policy. An administrator may override a value with a
BACKEND_AUTH_* setting, but only within bounds that are never WEAKER than the approved
policy (for example, the code lifetime can be shortened to 60 seconds but never made
longer than 5 minutes). The code length (6 digits) and the longest accepted password
are fixed and cannot be configured.

  setting (BACKEND_AUTH_...)   default   allowed
  PASSWORD_MIN_LENGTH          12        12 .. 64 characters
  LOCKOUT_THRESHOLD            5         3 .. 5 failed passwords in a row
  LOCKOUT_SECONDS              900       900 .. 86400 (15 minutes .. 1 day)
  OTP_TTL_SECONDS              300       60 .. 300 (1 .. 5 minutes)
  OTP_MAX_ATTEMPTS             5         1 .. 5 wrong codes per code
  RESEND_COOLDOWN_SECONDS      60        60 .. 900
  SESSION_LIFETIME_SECONDS     28800     900 .. 28800 (15 minutes .. 8 hours)
  IDLE_TIMEOUT_SECONDS         1800      300 .. 1800 (5 .. 30 minutes), and not longer
                                         than the session lifetime

This module imports nothing from the rest of the backend, so settings.py can use it.
"""
from dataclasses import dataclass, fields

OTP_DIGITS = 6                      # fixed: not configurable
PASSWORD_MAX_LENGTH = 128           # fixed: longest password accepted (characters)
SETTING_PREFIX = 'BACKEND_AUTH_'

# field -> (minimum, maximum). The approved value is the strict end of each range.
BOUNDS = {
    'password_min_length': (12, 64),
    'lockout_threshold': (3, 5),
    'lockout_seconds': (900, 86400),
    'otp_ttl_seconds': (60, 300),
    'otp_max_attempts': (1, 5),
    'resend_cooldown_seconds': (60, 900),
    'session_lifetime_seconds': (900, 28800),
    'idle_timeout_seconds': (300, 1800),
}


class PolicyError(ValueError):
    """The policy values are invalid. .problems lists them (names and ranges only)."""

    def __init__(self, problems):
        self.problems = list(problems)
        super().__init__('Invalid authentication policy: ' + '; '.join(self.problems))


@dataclass(frozen=True)
class AuthPolicy:
    password_min_length: int = 12
    lockout_threshold: int = 5
    lockout_seconds: int = 15 * 60
    otp_ttl_seconds: int = 5 * 60
    otp_max_attempts: int = 5
    resend_cooldown_seconds: int = 60
    session_lifetime_seconds: int = 8 * 3600
    idle_timeout_seconds: int = 30 * 60

    def __post_init__(self):
        problems = _check(self)
        if problems:
            raise PolicyError(problems)

    @property
    def otp_digits(self):
        return OTP_DIGITS

    @property
    def password_max_length(self):
        return PASSWORD_MAX_LENGTH


def setting_name(field_name):
    return SETTING_PREFIX + field_name.upper()


def _check(policy):
    problems = []
    for name, (low, high) in BOUNDS.items():
        value = getattr(policy, name)
        if isinstance(value, bool) or not isinstance(value, int):
            problems.append(f'{setting_name(name)} must be a whole number.')
        elif not low <= value <= high:
            problems.append(f'{setting_name(name)} must be from {low} to {high}.')
    lifetime, idle = policy.session_lifetime_seconds, policy.idle_timeout_seconds
    if (not problems and idle > lifetime):
        problems.append(f'{setting_name("idle_timeout_seconds")} must not be longer than '
                        f'{setting_name("session_lifetime_seconds")}.')
    return problems


def parse_policy(raw):
    """(AuthPolicy, problems) from raw settings {'BACKEND_AUTH_...': '...'}. Missing or
    empty values use the approved defaults. With problems, the policy is None."""
    values, problems = {}, []
    for f in fields(AuthPolicy):
        text = raw.get(setting_name(f.name))
        if text is None or not str(text).strip():
            continue
        text = str(text).strip()
        if not text.isascii() or not text.isdigit():
            problems.append(f'{setting_name(f.name)} must be a whole number.')
            continue
        values[f.name] = int(text)
    if problems:
        return None, problems
    try:
        return AuthPolicy(**values), []
    except PolicyError as err:
        return None, err.problems


DEFAULT_POLICY = AuthPolicy()
