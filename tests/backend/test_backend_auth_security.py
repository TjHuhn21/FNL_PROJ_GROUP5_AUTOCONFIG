"""Authentication security building blocks (backend/auth): policy, Argon2id passwords,
email codes (OTP) and session tokens. Fully offline: no database, network or files
(except reading backend/.env.example). Every password, pepper and code here is a
test-only value."""
import hashlib
import json
import logging
import os
import subprocess
import sys
from pathlib import Path

import pytest
from argon2 import PasswordHasher, Type
from argon2.low_level import hash_secret

from backend.auth import otp, passwords, policy, tokens
from backend.auth.otp import IssuedOtp, OtpConfigurationError, issue_otp, otp_hmac, verify_otp
from backend.auth.passwords import (PasswordHashError, PasswordPolicyError, check_hash_parameters,
                                    check_new_password, dummy_verify, hash_password,
                                    needs_rehash, verify_password)
from backend.auth.policy import DEFAULT_POLICY, AuthPolicy, PolicyError, parse_policy
from backend.auth.tokens import InvalidSessionToken, hash_session_token, issue_session_token
from backend.database import auth_records as R
from backend.database.errors import InvalidValue
from backend.logging_config import clear_registered_secrets, redact, register_secrets
from backend.settings import Secret, SettingsError, describe, load_settings, parse_settings

ROOT = Path(__file__).resolve().parents[2]


def short_id(value):
    """Short test ids, never a long value: pytest puts the id in an environment variable,
    which Windows limits to 32767 characters."""
    text = repr(value)
    return text if len(text) <= 24 else f'{type(value).__name__}-len{len(value)}'
TEST_PASSWORD = 'Test-only passw0rd!'
PEPPER = Secret('test-only-pepper-' + 'p' * 32)
OTHER_PEPPER = Secret('test-only-other-pepper-' + 'q' * 32)


# ================================================================== policy
def test_defaults_are_the_approved_policy():
    p = DEFAULT_POLICY
    assert (p.password_min_length, p.password_max_length) == (12, 128)
    assert (p.lockout_threshold, p.lockout_seconds) == (5, 15 * 60)
    assert (p.otp_digits, p.otp_ttl_seconds, p.otp_max_attempts) == (6, 5 * 60, 5)
    assert p.resend_cooldown_seconds == 60
    assert (p.session_lifetime_seconds, p.idle_timeout_seconds) == (8 * 3600, 30 * 60)


def test_empty_or_missing_settings_give_the_defaults():
    assert parse_policy({}) == (DEFAULT_POLICY, [])
    assert parse_policy({'BACKEND_AUTH_OTP_TTL_SECONDS': '  '}) == (DEFAULT_POLICY, [])
    assert parse_settings({}).auth_policy == DEFAULT_POLICY


def test_stricter_values_are_accepted():
    raw = {'BACKEND_AUTH_PASSWORD_MIN_LENGTH': '16', 'BACKEND_AUTH_LOCKOUT_THRESHOLD': '3',
           'BACKEND_AUTH_LOCKOUT_SECONDS': '3600', 'BACKEND_AUTH_OTP_TTL_SECONDS': '120',
           'BACKEND_AUTH_OTP_MAX_ATTEMPTS': '3', 'BACKEND_AUTH_RESEND_COOLDOWN_SECONDS': '120',
           'BACKEND_AUTH_SESSION_LIFETIME_SECONDS': '3600',
           'BACKEND_AUTH_IDLE_TIMEOUT_SECONDS': '600'}
    p = parse_settings(raw).auth_policy
    assert (p.password_min_length, p.lockout_threshold, p.lockout_seconds, p.otp_ttl_seconds,
            p.otp_max_attempts, p.resend_cooldown_seconds, p.session_lifetime_seconds,
            p.idle_timeout_seconds) == (16, 3, 3600, 120, 3, 120, 3600, 600)


WEAKER = [('PASSWORD_MIN_LENGTH', '11'), ('PASSWORD_MIN_LENGTH', '65'),
          ('LOCKOUT_THRESHOLD', '6'), ('LOCKOUT_THRESHOLD', '2'),
          ('LOCKOUT_SECONDS', '899'), ('LOCKOUT_SECONDS', '86401'),
          ('OTP_TTL_SECONDS', '301'), ('OTP_TTL_SECONDS', '59'),
          ('OTP_MAX_ATTEMPTS', '6'), ('OTP_MAX_ATTEMPTS', '0'),
          ('RESEND_COOLDOWN_SECONDS', '59'), ('RESEND_COOLDOWN_SECONDS', '901'),
          ('SESSION_LIFETIME_SECONDS', '28801'), ('SESSION_LIFETIME_SECONDS', '899'),
          ('IDLE_TIMEOUT_SECONDS', '1801'), ('IDLE_TIMEOUT_SECONDS', '299')]


@pytest.mark.parametrize('name, value', WEAKER)
def test_values_outside_the_approved_bounds_are_refused(name, value):
    setting = 'BACKEND_AUTH_' + name
    result, problems = parse_policy({setting: value})
    assert result is None and len(problems) == 1 and problems[0].startswith(setting)
    with pytest.raises(SettingsError) as err:
        parse_settings({setting: value})
    assert setting in str(err.value)


@pytest.mark.parametrize('value', ['abc', '1.5', '-5', '+5', '5 0', '0x10', '５', '1e3'])
def test_non_numbers_are_refused(value):
    result, problems = parse_policy({'BACKEND_AUTH_OTP_MAX_ATTEMPTS': value})
    assert result is None
    assert problems == ['BACKEND_AUTH_OTP_MAX_ATTEMPTS must be a whole number.']


def test_idle_timeout_cannot_exceed_the_session_lifetime():
    result, problems = parse_policy({'BACKEND_AUTH_SESSION_LIFETIME_SECONDS': '900',
                                     'BACKEND_AUTH_IDLE_TIMEOUT_SECONDS': '1200'})
    assert result is None and 'must not be longer than' in problems[0]


def test_direct_construction_is_validated_too():
    with pytest.raises(PolicyError):
        AuthPolicy(otp_ttl_seconds=3600)
    with pytest.raises(PolicyError):
        AuthPolicy(lockout_threshold=True)           # a bool is not a number here
    with pytest.raises(PolicyError):
        AuthPolicy(password_min_length='12')
    with pytest.raises(TypeError):
        AuthPolicy(otp_digits=4)                     # the code length is fixed
    with pytest.raises(Exception):
        DEFAULT_POLICY.otp_ttl_seconds = 3600        # frozen


def test_policy_bounds_fit_the_database_limits():
    """Every value the policy allows is accepted by the repository's own checks."""
    assert policy.BOUNDS['otp_ttl_seconds'][1] <= R.MAX_CHALLENGE_TTL
    assert policy.BOUNDS['session_lifetime_seconds'][1] <= R.MAX_SESSION_LIFETIME
    assert policy.BOUNDS['idle_timeout_seconds'][1] <= R.MAX_SESSION_LIFETIME
    low, high = policy.BOUNDS['otp_max_attempts']
    for n in (low, high):
        R.check_max_attempts(n)


def test_the_env_example_gives_the_default_policy():
    s = load_settings(env_file=ROOT / 'backend' / '.env.example', environ={})
    assert s.auth_policy == DEFAULT_POLICY


# ================================================================== passwords
@pytest.fixture(scope='module')
def stored():
    return hash_password(TEST_PASSWORD)


def test_hash_is_argon2id_with_the_explicit_parameters(stored):
    assert stored.startswith('$argon2id$v=19$m=65536,t=3,p=4$')
    R.check_password_hash(stored)                    # what users.password_hash accepts
    assert len(stored) <= 255                        # VARCHAR(255)
    p = check_hash_parameters(stored)
    assert (p.type, p.time_cost, p.memory_cost, p.parallelism, p.hash_len, p.salt_len) == \
        (Type.ID, 3, 65536, 4, 32, 16)
    assert TEST_PASSWORD not in stored


def test_each_hash_has_its_own_salt(stored):
    assert hash_password(TEST_PASSWORD) != stored


def test_correct_password_verifies(stored):
    assert verify_password(stored, TEST_PASSWORD) is True


@pytest.mark.parametrize('attempt', [
    TEST_PASSWORD.upper(), TEST_PASSWORD + ' ', ' ' + TEST_PASSWORD, TEST_PASSWORD[:-1],
    'something else entirely', '', None, 12345, b'Test-only passw0rd!',
    'x' * 129, 'x' * 100000, TEST_PASSWORD + '\n', 'Test-only\tpassw0rd!',
], ids=short_id)
def test_wrong_or_impossible_passwords_are_false(stored, attempt):
    assert verify_password(stored, attempt) is False


def test_unicode_is_normalised_before_hashing_and_checking():
    composed, decomposed = 'Café-test-only-pw', 'Café-test-only-pw'
    assert composed != decomposed
    assert verify_password(hash_password(composed), decomposed) is True


@pytest.mark.parametrize('password, problem', [
    ('a' * 11, 'at least 12'), ('', 'at least 12'), (None, 'required'), (b'x' * 20, 'required'),
    ('a' * 129, 'at most 128'), (' ' * 12, 'only spaces'),
    ('abcdefghijk\tl', 'control characters'), ('abcdefghijkl\n', 'control characters'),
    ('abcdefghijk\x00l', 'control characters'),
])
def test_new_password_policy(password, problem):
    with pytest.raises(PasswordPolicyError) as err:
        hash_password(password)
    assert problem in str(err.value)
    if isinstance(password, str) and password.strip():
        assert password not in str(err.value)


def test_policy_length_limits_are_inclusive_and_configurable():
    assert check_new_password('a' * 12) == 'a' * 12
    assert check_new_password('a' * 128) == 'a' * 128
    stricter = AuthPolicy(password_min_length=16)
    with pytest.raises(PasswordPolicyError, match='at least 16'):
        check_new_password('a' * 15, stricter)
    assert check_new_password('a' * 16, stricter)


def _argon2_variant(kind):
    return hash_secret(TEST_PASSWORD.encode(), os.urandom(16), time_cost=3, memory_cost=65536,
                       parallelism=4, hash_len=32, type=kind).decode()


def _malformed_hashes():
    good = hash_password(TEST_PASSWORD)
    return [
        '', 'plain-text-password', TEST_PASSWORD, None, 42, good.encode(),
        _argon2_variant(Type.I), _argon2_variant(Type.D),
        '$2b$12$C6UzMDM.H6dfI/f/IKcEeO5x9hXZy1ZRrQVQ2dG3s1i6dQhKk9yW2',      # bcrypt-shaped
        good[:-10],                                                       # truncated
        good.replace('$v=19$', '$v=16$'),
        good.replace('m=65536', 'm=abc'),
        good + 'x' * 250,                                                 # too long
        good[:-1] + 'é',                                              # non-ASCII
        PasswordHasher(time_cost=1, memory_cost=8, parallelism=1).hash(TEST_PASSWORD),  # weak
        PasswordHasher(salt_len=8).hash(TEST_PASSWORD),                   # short salt
    ]


@pytest.mark.parametrize('index', range(16))
def test_malformed_or_unsupported_hashes_are_refused(index):
    bad = _malformed_hashes()[index]
    for call in (lambda: verify_password(bad, TEST_PASSWORD), lambda: needs_rehash(bad),
                 lambda: check_hash_parameters(bad)):
        with pytest.raises(PasswordHashError) as err:
            call()
        message = str(err.value)
        assert TEST_PASSWORD not in message
        if isinstance(bad, str) and len(bad) > 8:
            assert bad not in message and bad[-20:] not in message


def test_current_hash_needs_no_rehash(stored):
    assert needs_rehash(stored) is False


def test_older_but_acceptable_parameters_still_verify_and_need_rehash():
    old = PasswordHasher(time_cost=2, memory_cost=19 * 1024, parallelism=1).hash(TEST_PASSWORD)
    assert verify_password(old, TEST_PASSWORD) is True
    assert needs_rehash(old) is True


def test_unknown_account_does_the_same_work(monkeypatch, stored):
    """dummy_verify (unknown email) and an impossible password both run one real Argon2id
    verification with today's parameters, like a wrong password does."""
    real = passwords._hasher
    calls = []

    class Counting:
        def verify(self, h, p):
            calls.append(check_hash_parameters(h).memory_cost)
            return real.verify(h, p)

        def __getattr__(self, name):
            return getattr(real, name)
    monkeypatch.setattr(passwords, '_hasher', Counting())
    assert dummy_verify(TEST_PASSWORD) is False
    assert dummy_verify(None) is False
    assert verify_password(stored, 'x' * 500) is False           # impossible password
    assert verify_password(stored, 'wrong but possible') is False
    assert calls == [65536] * 4


# ================================================================== email codes (OTP)
def test_codes_are_six_ascii_digits_from_the_secure_generator(monkeypatch):
    codes = [otp.generate_otp() for _ in range(2000)]
    assert all(len(c) == 6 and c.isascii() and c.isdigit() for c in codes)
    assert len(set(codes)) > 1900
    seen = []
    monkeypatch.setattr(otp.secrets, 'randbelow', lambda n: seen.append(n) or 42)
    assert otp.generate_otp() == '000042'                     # leading zeros kept
    assert seen == [10 ** 6]


@pytest.mark.parametrize('purpose', ['register', 'login'])
def test_issue_and_verify_for_both_purposes(purpose):
    issued = issue_otp(PEPPER, purpose, 7)
    R.check_hex64(issued.code_hmac, 'code_hmac')              # what email_challenges stores
    assert issued.code not in issued.code_hmac
    assert verify_otp(PEPPER, purpose, 7, issued.code, issued.code_hmac) is True


def test_the_hmac_is_deterministic_and_bound_to_everything():
    base = otp_hmac(PEPPER, 'login', 7, '123456')
    assert base == otp_hmac(Secret(PEPPER.reveal()), 'login', 7, '123456')
    others = {otp_hmac(PEPPER, 'register', 7, '123456'), otp_hmac(PEPPER, 'login', 8, '123456'),
              otp_hmac(PEPPER, 'login', 7, '123457'), otp_hmac(OTHER_PEPPER, 'login', 7, '123456'),
              hashlib.sha256(b'123456').hexdigest()}            # not a plain hash
    assert base not in others and len(others) == 5


@pytest.mark.parametrize('submitted', ['123456', ' 123456 ', '123 456', '123-456'])
def test_typed_variants_of_the_right_code_pass(submitted):
    stored = otp_hmac(PEPPER, 'login', 7, '123456')
    assert verify_otp(PEPPER, 'login', 7, submitted, stored) is True


@pytest.mark.parametrize('purpose, user_id, code, pepper', [
    ('login', 7, '123457', PEPPER),             # wrong code
    ('register', 7, '123456', PEPPER),          # a login code never completes a registration
    ('login', 8, '123456', PEPPER),             # another account
    ('login', 7, '123456', OTHER_PEPPER),       # another pepper
])
def test_wrong_code_purpose_account_or_pepper_fails(purpose, user_id, code, pepper):
    stored = otp_hmac(PEPPER, 'login', 7, '123456')
    assert verify_otp(pepper, purpose, user_id, code, stored) is False


@pytest.mark.parametrize('submitted', ['', '12345', '1234567', 'abcdef', '12345a', None,
                                       123456, '１２３４５６',
                                       '١٢٣٤٥٦', '1' * 1000],
                         ids=short_id)
def test_malformed_submissions_fail_after_a_constant_time_compare(monkeypatch, submitted):
    stored = otp_hmac(PEPPER, 'login', 7, '000000')    # even the filler value cannot pass
    compared = []
    real = otp.hmac.compare_digest
    monkeypatch.setattr(otp.hmac, 'compare_digest',
                        lambda a, b: compared.append(1) or real(a, b))
    assert verify_otp(PEPPER, 'login', 7, submitted, stored) is False
    assert compared == [1]


def test_valid_submissions_are_compared_in_constant_time(monkeypatch):
    compared = []
    real = otp.hmac.compare_digest
    monkeypatch.setattr(otp.hmac, 'compare_digest',
                        lambda a, b: compared.append(1) or real(a, b))
    stored = otp_hmac(PEPPER, 'login', 7, '123456')
    assert verify_otp(PEPPER, 'login', 7, '654321', stored) is False
    assert compared == [1]


@pytest.mark.parametrize('pepper, problem', [
    (None, 'not set'), (Secret(''), 'not set'), (Secret(None), 'not set'),
    ('a-plain-string-pepper-' + 'z' * 32, 'not set'),          # must be a Secret
    (Secret('short-test-pepper'), 'at least 32'),
])
def test_a_missing_or_short_pepper_is_refused(pepper, problem):
    for call in (lambda: issue_otp(pepper, 'login', 7),
                 lambda: verify_otp(pepper, 'login', 7, '123456', '0' * 64)):
        with pytest.raises(OtpConfigurationError) as err:
            call()
        assert problem in str(err.value)
        assert 'short-test-pepper' not in str(err.value) and 'zzzz' not in str(err.value)


@pytest.mark.parametrize('purpose, user_id', [('reset', 7), ('', 7), (None, 7), ('LOGIN', 7),
                                              ('login', 0), ('login', -1), ('login', True),
                                              ('login', '7'), ('login', 7.0)])
def test_invalid_purpose_or_account_is_refused(purpose, user_id):
    with pytest.raises(InvalidValue):
        issue_otp(PEPPER, purpose, user_id)
    with pytest.raises(InvalidValue):
        verify_otp(PEPPER, purpose, user_id, '123456', '0' * 64)


@pytest.mark.parametrize('stored', ['', 'A' * 64, '0' * 63, '0' * 65, 'g' * 64, None, 123])
def test_a_malformed_stored_hmac_is_a_data_problem(stored):
    with pytest.raises(InvalidValue) as err:
        verify_otp(PEPPER, 'login', 7, '123456', stored)
    if isinstance(stored, str) and stored:
        assert stored not in str(err.value)


def test_otp_hmac_refuses_a_code_that_is_not_six_digits():
    for code in ('12345', '1234567', 'abcdef', '123 456', None):
        with pytest.raises(InvalidValue):
            otp_hmac(PEPPER, 'login', 7, code)


def test_issued_code_is_hidden_from_repr_and_str():
    issued = IssuedOtp(code='314159', code_hmac=otp_hmac(PEPPER, 'login', 7, '314159'))
    for text in (repr(issued), str(issued), f'{issued}', f'{issued!r}'):
        assert '314159' not in text and '[hidden]' in text


# ================================================================== session tokens
def test_tokens_are_256_bit_url_safe_and_unique(monkeypatch):
    import base64
    many = {tokens.generate_session_token() for _ in range(1000)}
    assert len(many) == 1000
    for t in list(many)[:50]:
        assert len(t) == 43 and tokens.is_well_formed(t)
        assert len(base64.urlsafe_b64decode(t + '=')) == 32
    seen = []
    real = tokens.secrets.token_urlsafe
    monkeypatch.setattr(tokens.secrets, 'token_urlsafe', lambda n: seen.append(n) or real(n))
    tokens.generate_session_token()
    assert seen == [32]


def test_token_hash_is_plain_sha256_hex():
    issued = issue_session_token()
    assert issued.token_hash == hashlib.sha256(issued.token.encode('ascii')).hexdigest()
    assert hash_session_token(issued.token) == issued.token_hash      # deterministic
    R.check_hex64(issued.token_hash, 'token_hash')                    # what sessions stores
    assert hash_session_token(issue_session_token().token) != issued.token_hash


@pytest.mark.parametrize('bad', ['', None, 42, 'a' * 42, 'a' * 44, 'a' * 42 + '=',
                                 'a' * 42 + '+', 'a' * 42 + '/', 'a' * 21 + ' ' + 'a' * 21,
                                 'a' * 42 + 'é', b'a' * 43, 'Bearer ' + 'a' * 36])
def test_malformed_tokens_are_refused_without_repeating_them(bad):
    with pytest.raises(InvalidSessionToken) as err:
        hash_session_token(bad)
    assert str(err.value) == 'The session token is not valid.'


def test_issued_token_is_hidden_from_repr_and_str():
    issued = issue_session_token()
    for text in (repr(issued), str(issued), f'{issued}', f'{issued!r}'):
        assert issued.token not in text and '[hidden]' in text


# ================================================================== redaction and isolation
def test_redacting_logs_hide_codes_tokens_and_the_pepper():
    issued_token = issue_session_token()
    clear_registered_secrets()
    try:
        register_secrets(parse_settings({'BACKEND_OTP_PEPPER': PEPPER.reveal()}).secret_values())
        text = redact(f'otp_code=123456 session_token={issued_token.token} '
                      f'Authorization: Bearer {issued_token.token} pepper is {PEPPER.reveal()}')
    finally:
        clear_registered_secrets()
    for secret in ('123456', issued_token.token, PEPPER.reveal()):
        assert secret not in text


def test_settings_never_show_the_pepper():
    s = parse_settings({'BACKEND_OTP_PEPPER': PEPPER.reveal()})
    for text in (repr(s), str(s), describe(s), repr(s.otp_pepper), f'{s.otp_pepper}',
                 repr(s.auth_policy)):
        assert PEPPER.reveal() not in text


def test_logging_an_issued_code_or_token_shows_neither(caplog):
    code = issue_otp(PEPPER, 'register', 3)
    session = issue_session_token()
    with caplog.at_level(logging.DEBUG, logger='test.auth'):
        logging.getLogger('test.auth').info('issued %s and %r', code, session)
    assert code.code not in caplog.text and session.token not in caplog.text


def test_auth_modules_are_separate_from_device_password_encryption():
    """No auth module uses the desktop's FERNET_KEY / security.py, and importing them
    loads neither security.py nor PyMySQL (they are pure)."""
    import ast
    imported = set()
    for path in (ROOT / 'backend' / 'auth').glob('*.py'):
        for node in ast.walk(ast.parse(path.read_text(encoding='utf-8'))):
            if isinstance(node, ast.Import):
                imported |= {a.name for a in node.names}
            elif isinstance(node, ast.ImportFrom):
                imported.add(node.module or '')
            elif isinstance(node, ast.Name):
                assert 'fernet' not in node.id.lower(), path.name
    assert imported, 'no imports found'
    for name in imported:
        assert name.split('.')[0] not in ('security', 'cryptography', 'db', 'db_fake', 'pymysql',
                                          'smtplib', 'socket', 'urllib', 'httpx'), name
    probe = ('import json, sys\n'
             'import backend.auth.policy, backend.auth.passwords, backend.auth.otp, '
             'backend.auth.tokens\n'
             'print(json.dumps(sorted(m for m in sys.modules if m in ("security", "pymysql", '
             '"db", "cryptography.fernet"))))\n')
    env = {k: v for k, v in os.environ.items() if not k.startswith(('BACKEND_', 'FERNET'))}
    out = subprocess.run([sys.executable, '-c', probe], cwd=ROOT, env=env, capture_output=True,
                         text=True, timeout=120)
    assert out.returncode == 0, out.stderr
    assert json.loads(out.stdout.strip().splitlines()[-1]) == []
