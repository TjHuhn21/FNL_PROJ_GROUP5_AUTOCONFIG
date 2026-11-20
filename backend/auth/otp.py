"""Six-digit email codes (OTP) for registration AND login.

  issue_otp(pepper, purpose, user_id)                 -> IssuedOtp(code, code_hmac)
  verify_otp(pepper, purpose, user_id, code, stored)  -> True / False (constant time)

Only code_hmac is ever stored (email_challenges.code_hmac); the code itself goes to the
user's email and nowhere else. code_hmac = HMAC-SHA256(pepper, domain | purpose |
user_id | code), hex: a stolen database cannot be brute-forced without the pepper
(BACKEND_OTP_PEPPER), and a code issued for registration can never pass as a login code
or for another account. purpose is 'register' or 'login'.

Codes come from the operating system's secure random generator (secrets). repr() of an
IssuedOtp hides the code; no error message repeats a code or the pepper.
"""
import hashlib
import hmac
import re
import secrets
from dataclasses import dataclass, field

from backend.auth.policy import OTP_DIGITS
from backend.database.auth_records import PURPOSES, check_hex64
from backend.database.errors import InvalidValue
from backend.settings import OTP_PEPPER_MIN_LENGTH, Secret

_DOMAIN = b'netcommand-otp-v1'
_CODE = re.compile(r'^[0-9]{%d}$' % OTP_DIGITS)
_HIDDEN = '[hidden]'


class OtpConfigurationError(RuntimeError):
    """BACKEND_OTP_PEPPER is missing or too short. The message never contains it."""


@dataclass(frozen=True)
class IssuedOtp:
    code: str = field(repr=False)        # send by email only; never store or log it
    code_hmac: str

    def __repr__(self):
        return f'IssuedOtp(code={_HIDDEN}, code_hmac={self.code_hmac[:8]}...)'

    __str__ = __repr__


def generate_otp():
    """A uniformly random six-digit code ('000000' .. '999999')."""
    return f'{secrets.randbelow(10 ** OTP_DIGITS):0{OTP_DIGITS}d}'


def _pepper_bytes(pepper):
    if not isinstance(pepper, Secret) or not pepper:
        raise OtpConfigurationError('BACKEND_OTP_PEPPER is not set.')
    value = pepper.reveal()
    if not isinstance(value, str) or len(value) < OTP_PEPPER_MIN_LENGTH:
        raise OtpConfigurationError(f'BACKEND_OTP_PEPPER must be at least '
                                    f'{OTP_PEPPER_MIN_LENGTH} characters.')
    return value.encode('utf-8')


def _check_binding(purpose, user_id):
    if purpose not in PURPOSES:
        raise InvalidValue(f'purpose must be one of: {", ".join(PURPOSES)}.')
    if isinstance(user_id, bool) or not isinstance(user_id, int) or user_id < 1:
        raise InvalidValue('user_id must be a positive whole number.')


def _mac(key, purpose, user_id, code):
    message = b'\x00'.join((_DOMAIN, purpose.encode('ascii'), str(user_id).encode('ascii'),
                            code.encode('ascii')))
    return hmac.new(key, message, hashlib.sha256).hexdigest()


def otp_hmac(pepper, purpose, user_id, code):
    """The value to store for this code (64 lower-case hex characters)."""
    key = _pepper_bytes(pepper)
    _check_binding(purpose, user_id)
    if not isinstance(code, str) or not _CODE.match(code):
        raise InvalidValue(f'The code must be exactly {OTP_DIGITS} digits.')
    return _mac(key, purpose, user_id, code)


def issue_otp(pepper, purpose, user_id):
    """A new code for this user and purpose, with the HMAC to store."""
    code = generate_otp()
    return IssuedOtp(code=code, code_hmac=otp_hmac(pepper, purpose, user_id, code))


def normalise_submitted_code(code):
    """The code as typed, without surrounding spaces and the spaces or dashes people add
    when copying ('123 456', '123-456'); None if it cannot be a code."""
    if not isinstance(code, str) or len(code) > 32:
        return None
    value = code.strip().replace(' ', '').replace('-', '')
    return value if _CODE.match(value) else None


def verify_otp(pepper, purpose, user_id, submitted_code, stored_hmac):
    """True only if submitted_code is the code behind stored_hmac for this purpose and
    user. Compared in constant time; a malformed submission is False after the same
    work. InvalidValue if stored_hmac is not a stored HMAC (a data problem)."""
    key = _pepper_bytes(pepper)
    _check_binding(purpose, user_id)
    check_hex64(stored_hmac, 'code_hmac')
    code = normalise_submitted_code(submitted_code)
    expected = _mac(key, purpose, user_id, code if code is not None else '0' * OTP_DIGITS)
    matches = hmac.compare_digest(expected, stored_hmac)
    return matches and code is not None
