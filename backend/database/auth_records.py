"""Values allowed in the authentication tables, checked BEFORE any database work by both
repositories (AuthRepository and InMemoryAuthRepository).

The checks also stop secrets from being stored by mistake: a password where an Argon2id
hash belongs, an OTP code where its HMAC belongs, or a raw session token where its hash
belongs are all refused (InvalidValue). Error messages never repeat the value.
"""
import re

from backend.database.errors import InvalidValue

ROLES = ('admin', 'operator', 'viewer')
STATUSES = ('pending_verification', 'pending_approval', 'active', 'rejected', 'disabled')
PURPOSES = ('register', 'login')
OUTCOMES = ('success', 'failure', 'denied')

EMAIL_MAX = 254
NAME_MAX = 100
LABEL_MAX = 100
IP_MAX = 45
DETAIL_MAX = 1000
ACTION_MAX = 64
REASON_MAX = 40
MAX_CHALLENGE_TTL = 3600            # seconds (policy: 5 minutes; the limit is a sanity cap)
MAX_SESSION_LIFETIME = 24 * 3600    # seconds (policy: 8 hours)

_EMAIL = re.compile(r'^[^@\s]{1,64}@[^@\s]+\.[^@\s]+$')
_HEX64 = re.compile(r'^[0-9a-f]{64}$')
_CONTROL = re.compile(r'[\x00-\x1f\x7f]')
_ACTION = re.compile(r'^[a-z][a-z0-9_.]{0,63}$')
_REASON = re.compile(r'^[a-z][a-z0-9_]{0,39}$')
ARGON2ID_PREFIX = '$argon2id$'


def normalize_email(email):
    """The form used for uniqueness and lookup: trimmed, lower case."""
    if not isinstance(email, str):
        raise InvalidValue('The email address is required.')
    value = email.strip()
    if not value or len(value) > EMAIL_MAX or not _EMAIL.match(value):
        raise InvalidValue('The email address is not valid.')
    if not value.isascii():
        # Python and MySQL lower-case some non-ASCII letters differently, and look-alike
        # letters would make visually identical addresses distinct: plain ASCII only.
        raise InvalidValue('The email address must use plain ASCII characters.')
    return value.lower()


def check_email(email):
    normalize_email(email)
    return email.strip()


def check_full_name(name):
    if not isinstance(name, str) or not name.strip():
        raise InvalidValue('The full name is required.')
    value = name.strip()
    if len(value) > NAME_MAX or _CONTROL.search(value):
        raise InvalidValue(f'The full name must be one line of at most {NAME_MAX} characters.')
    return value


def check_password_hash(value):
    """Only an Argon2id hash string is accepted: never a plaintext password."""
    if (not isinstance(value, str) or not value.startswith(ARGON2ID_PREFIX)
            or len(value) > 255 or len(value) < 40 or _CONTROL.search(value)):
        raise InvalidValue('password_hash must be an Argon2id hash ($argon2id$...); '
                           'a plaintext password is never stored.')
    return value


def check_hex64(value, what):
    """code_hmac / token_hash: a 64-character lower-case hex digest, never the code or
    token itself."""
    if not isinstance(value, str) or not _HEX64.match(value):
        raise InvalidValue(f'{what} must be a 64-character hex digest (HMAC/SHA-256); the '
                           f'code or token itself is never stored.')
    return value


_PUBLIC_ID = re.compile(r'^[A-Za-z0-9_-]{20,64}$')


def check_public_id(value):
    if not isinstance(value, str) or not _PUBLIC_ID.match(value):
        raise InvalidValue('The challenge id is not valid.')
    return value


def check_choice(value, allowed, what):
    if value not in allowed:
        raise InvalidValue(f'{what} must be one of: {", ".join(allowed)}.')
    return value


def check_id(value, what='id'):
    if not isinstance(value, int) or isinstance(value, bool) or value < 1:
        raise InvalidValue(f'{what} must be a positive whole number.')
    return value


def check_seconds(value, maximum, what):
    if not isinstance(value, int) or isinstance(value, bool) or not 1 <= value <= maximum:
        raise InvalidValue(f'{what} must be a whole number of seconds from 1 to {maximum}.')
    return value


def check_optional_text(value, maximum, what):
    if value is None:
        return None
    if not isinstance(value, str) or len(value) > maximum or _CONTROL.search(value):
        raise InvalidValue(f'{what} must be one line of at most {maximum} characters.')
    return value or None


def check_action(value):
    if not isinstance(value, str) or not _ACTION.match(value):
        raise InvalidValue('action must be lower case letters, digits, dots or underscores '
                           '(for example auth.login).')
    return value


def check_reason(value):
    if not isinstance(value, str) or not _REASON.match(value):
        raise InvalidValue('The revocation reason must be a short code such as logout.')
    return value


def clean_detail(detail):
    """Audit detail: secrets redacted (same rules as the logs), one line, length-capped."""
    if detail is None:
        return None
    from backend.logging_config import redact
    text = redact(str(detail))
    text = _CONTROL.sub(' ', text).strip()
    return text[:DETAIL_MAX] or None


def check_max_attempts(value):
    if not isinstance(value, int) or isinstance(value, bool) or not 1 <= value <= 20:
        raise InvalidValue('max_attempts must be from 1 to 20.')
    return value


def audit_context(actor_user_id, client_ip=None, workstation_label=None):
    """Who made a privileged change (actor_user_id None = the system itself, for example
    the first-admin command)."""
    if actor_user_id is not None:
        check_id(actor_user_id, 'actor_user_id')
    return {'actor_user_id': actor_user_id,
            'client_ip': check_optional_text(client_ip, IP_MAX, 'client_ip'),
            'workstation_label': check_optional_text(workstation_label, LABEL_MAX,
                                                     'workstation_label')}


def audit_values(action, outcome, actor_user_id=None, actor_email=None, target_type=None,
                 target_id=None, client_ip=None, workstation_label=None, detail=None):
    """One audit record, checked and with its detail redacted."""
    check_action(action)
    check_choice(outcome, OUTCOMES, 'outcome')
    if actor_user_id is not None:
        check_id(actor_user_id, 'actor_user_id')
    return {'action': action, 'outcome': outcome, 'actor_user_id': actor_user_id,
            'actor_email': check_optional_text(actor_email, EMAIL_MAX, 'actor_email'),
            'target_type': check_optional_text(target_type, 32, 'target_type'),
            'target_id': check_optional_text(None if target_id is None else str(target_id), 64,
                                             'target_id'),
            'client_ip': check_optional_text(client_ip, IP_MAX, 'client_ip'),
            'workstation_label': check_optional_text(workstation_label, LABEL_MAX,
                                                     'workstation_label'),
            'detail': clean_detail(detail)}
