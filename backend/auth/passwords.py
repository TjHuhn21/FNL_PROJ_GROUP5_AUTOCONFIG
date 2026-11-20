"""NetCommand account passwords: Argon2id (argon2-cffi), one-way.

These are the passwords people use to sign in to NetCommand. They are HASHED, never
encrypted, and have nothing to do with the device passwords that the desktop encrypts
with FERNET_KEY (security.py), which must stay reversible.

  hash_password(password, policy)   -> '$argon2id$v=19$m=65536,t=3,p=4$...'
  verify_password(stored, password) -> True / False (wrong password)
  needs_rehash(stored)              -> True when stored with other parameters
  check_hash_parameters(stored)     -> the parameters; PasswordHashError if unusable
  dummy_verify(password)            -> False, after the same work as a real check (use it
                                       for an unknown email, so timing reveals nothing)

Passwords are normalised (Unicode NFKC) before hashing and verifying, so the same
password typed on different keyboards or systems gives the same result. Whitespace is
kept exactly. Error messages never contain the password or the hash.
"""
import secrets
import threading
import unicodedata

from argon2 import PasswordHasher, Type, extract_parameters
from argon2.exceptions import InvalidHashError, VerificationError, VerifyMismatchError

from backend.auth.policy import DEFAULT_POLICY, PASSWORD_MAX_LENGTH

# Explicit parameters (RFC 9106 "low memory" profile), so a library upgrade can never
# change them silently. Raising any of them later makes needs_rehash() true for old hashes.
TIME_COST = 3
MEMORY_COST = 64 * 1024          # KiB = 64 MiB
PARALLELISM = 4
HASH_LEN = 32
SALT_LEN = 16
ARGON2_VERSION = 19

# Stored hashes weaker than this are refused outright (OWASP minimum for Argon2id).
MIN_TIME_COST = 2
MIN_MEMORY_COST = 19 * 1024
MIN_HASH_LEN = 32
MIN_SALT_LEN = 16
MAX_STORED_HASH_LENGTH = 255     # users.password_hash is VARCHAR(255)

_hasher = PasswordHasher(time_cost=TIME_COST, memory_cost=MEMORY_COST,
                         parallelism=PARALLELISM, hash_len=HASH_LEN, salt_len=SALT_LEN,
                         type=Type.ID)


class PasswordPolicyError(ValueError):
    """A new password does not meet the policy. The message never contains it."""


class PasswordHashError(ValueError):
    """A stored hash is malformed, not Argon2id, or below the minimum parameters. This
    is a data problem, not a wrong password. The message never contains the hash."""


def _normalise(password):
    return unicodedata.normalize('NFKC', password)


def _has_control_characters(text):
    return any(unicodedata.category(ch) == 'Cc' for ch in text)


def check_new_password(password, policy=DEFAULT_POLICY):
    """The normalised password if it meets the policy; PasswordPolicyError otherwise."""
    if not isinstance(password, str):
        raise PasswordPolicyError('The password is required.')
    value = _normalise(password)
    if len(value) < policy.password_min_length:
        raise PasswordPolicyError(f'The password must be at least '
                                  f'{policy.password_min_length} characters long.')
    if len(value) > PASSWORD_MAX_LENGTH:
        raise PasswordPolicyError(f'The password must be at most {PASSWORD_MAX_LENGTH} '
                                  f'characters long.')
    if not value.strip():
        raise PasswordPolicyError('The password cannot be only spaces.')
    if _has_control_characters(value):
        raise PasswordPolicyError('The password cannot contain control characters '
                                  '(such as tabs or line breaks).')
    return value


def hash_password(password, policy=DEFAULT_POLICY):
    """An Argon2id hash (with its own random salt) of a password that meets the policy."""
    return _hasher.hash(check_new_password(password, policy))


def check_hash_parameters(stored_hash):
    """The Argon2 parameters of a stored hash. PasswordHashError unless it is a
    well-formed Argon2id (version 19) hash at or above the minimum parameters."""
    if (not isinstance(stored_hash, str) or not stored_hash.startswith('$argon2id$')
            or len(stored_hash) > MAX_STORED_HASH_LENGTH or not stored_hash.isascii()):
        raise PasswordHashError('The stored password hash is not a valid Argon2id hash.')
    try:
        params = extract_parameters(stored_hash)
    except (InvalidHashError, ValueError, TypeError, IndexError):
        raise PasswordHashError('The stored password hash is not a valid Argon2id hash.') \
            from None
    if params.type is not Type.ID or params.version != ARGON2_VERSION:
        raise PasswordHashError('The stored password hash is not a valid Argon2id hash.')
    if (params.time_cost < MIN_TIME_COST or params.memory_cost < MIN_MEMORY_COST
            or params.parallelism < 1 or params.hash_len < MIN_HASH_LEN
            or params.salt_len < MIN_SALT_LEN):
        raise PasswordHashError('The stored password hash uses parameters below the '
                                'minimum and cannot be used.')
    return params


def needs_rehash(stored_hash):
    """True when the stored hash is valid but uses other parameters than today's (hash
    the password again after the next successful login). PasswordHashError if unusable."""
    check_hash_parameters(stored_hash)
    return _hasher.check_needs_rehash(stored_hash)


def verify_password(stored_hash, password):
    """True only if password matches stored_hash. A wrong, missing, too long or
    otherwise impossible password is simply False (after the same amount of work).
    PasswordHashError if the stored hash itself is unusable."""
    check_hash_parameters(stored_hash)
    candidate = _candidate(password)
    if candidate is None:
        return dummy_verify(password)
    try:
        return _hasher.verify(stored_hash, candidate)
    except VerifyMismatchError:
        return False
    except InvalidHashError:
        raise PasswordHashError('The stored password hash is not a valid Argon2id hash.') \
            from None
    except VerificationError:
        raise PasswordHashError('The stored password hash could not be checked.') from None


def _candidate(password):
    """The normalised password to check, or None if it could never have been accepted."""
    if not isinstance(password, str) or not password:
        return None
    value = _normalise(password)
    if len(value) > PASSWORD_MAX_LENGTH or _has_control_characters(value):
        return None
    return value


_dummy_hash = None
_dummy_lock = threading.Lock()


def _get_dummy_hash():
    global _dummy_hash
    with _dummy_lock:
        if _dummy_hash is None:
            _dummy_hash = _hasher.hash(secrets.token_urlsafe(24))
        return _dummy_hash


def dummy_verify(password=None):
    """Always False, after an Argon2id verification with today's parameters, so an
    unknown account takes as long as a wrong password."""
    try:
        _hasher.verify(_get_dummy_hash(), password if isinstance(password, str) and password
                       and len(password) <= PASSWORD_MAX_LENGTH * 4 else 'x')
    except VerificationError:
        pass
    return False
