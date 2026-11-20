"""Phase 4B: backend settings: own env file, BACKEND_ names only, validation only when a
feature is enabled, and no secret value in any message. No real .env is read."""
import os
import pickle
import subprocess
from pathlib import Path

import pytest
from cryptography.fernet import Fernet

from backend import settings as S
from backend.settings import Secret, SettingsError, load_settings, parse_settings

ROOT = Path(__file__).resolve().parents[2]
DB_SECRET = 'Db-Secret-Value-4421-x'
SMTP_SECRET = 'Smtp-App-Password-9930'


def db_settings(**override):
    raw = {'BACKEND_DB_ENABLED': 'true', 'BACKEND_DB_HOST': '127.0.0.1',
           'BACKEND_DB_PORT': '3307', 'BACKEND_DB_USER': 'netcommand_app',
           'BACKEND_DB_PASSWORD': DB_SECRET, 'BACKEND_DB_NAME': 'netcommand_test'}
    raw.update(override)
    return {k: v for k, v in raw.items() if v is not None}


def smtp_settings(**override):
    raw = {'BACKEND_SMTP_ENABLED': 'true', 'BACKEND_SMTP_HOST': 'smtp.gmail.com',
           'BACKEND_SMTP_USERNAME': 'sender@example.com', 'BACKEND_SMTP_PASSWORD': SMTP_SECRET,
           'BACKEND_SMTP_FROM': 'sender@example.com'}
    raw.update(override)
    return {k: v for k, v in raw.items() if v is not None}


# ---------------------------------------------------------------- defaults and sources
def test_safe_defaults_with_nothing_set():
    s = parse_settings({})
    assert (s.environment, s.host, s.port, s.log_level) == ('development', '127.0.0.1', 8000, 'INFO')
    assert s.database is None and s.smtp is None and s.fernet_key is None and s.otp_pepper is None
    assert s.docs_enabled


def test_desktop_settings_are_never_used():
    """The desktop's names are ignored even in the environment: no silent fallback."""
    environ = {'DB_HOST': '127.0.0.1', 'DB_PORT': '3307', 'DB_USER': 'netcommand_app',
               'DB_PASSWORD': DB_SECRET, 'DB_NAME': 'netcommand',
               'FERNET_KEY': Fernet.generate_key().decode()}
    s = load_settings(environ=environ, use_file=False)
    assert s.database is None and s.fernet_key is None
    assert S.read_raw(environ=environ, use_file=False) == {}


def test_default_env_file_is_the_backends_own_not_the_desktops():
    """Checked in a fresh interpreter (the test fixture patches it here). Only the path
    is printed; no file is read."""
    import sys
    out = subprocess.run([sys.executable, '-c', 'from backend.settings import DEFAULT_ENV_FILE;'
                          'print(DEFAULT_ENV_FILE)'], cwd=ROOT, capture_output=True,
                         text=True, timeout=60)
    assert out.returncode == 0, out.stderr
    path = Path(out.stdout.strip())
    assert path == ROOT / 'backend' / '.env' and path != ROOT / '.env'


def test_env_file_then_environment(tmp_path):
    f = tmp_path / 'backend.env'
    f.write_text('BACKEND_PORT=9001\nBACKEND_LOG_LEVEL=debug\n'
                 f'DB_PASSWORD={DB_SECRET}\nFERNET_KEY=not-read\n', encoding='utf-8')
    s = load_settings(env_file=f, environ={'BACKEND_PORT': '9100'})
    assert s.port == 9100 and s.log_level == 'DEBUG'       # environment wins over the file
    assert S.read_raw(env_file=f, environ={}) == {'BACKEND_PORT': '9001',
                                                 'BACKEND_LOG_LEVEL': 'debug'}


def test_env_file_can_be_chosen_and_may_be_missing(tmp_path):
    f = tmp_path / 'chosen.env'
    f.write_text('BACKEND_PORT=8123\n', encoding='utf-8')
    assert load_settings(environ={S.ENV_FILE_VARIABLE: str(f)}).port == 8123
    assert load_settings(environ={S.ENV_FILE_VARIABLE: str(tmp_path / 'missing.env')}).port == 8000


def test_example_file_has_placeholders_only_and_loads():
    example = ROOT / 'backend' / '.env.example'
    text = example.read_text(encoding='utf-8')
    s = load_settings(env_file=example, environ={})
    assert s.database is None and s.smtp is None              # disabled in the example
    assert s.fernet_key is None and s.otp_pepper is None      # left empty
    assert 'change-me' in text
    for line in text.splitlines():
        if line.startswith('BACKEND_') and ('PASSWORD' in line or 'KEY' in line or 'PEPPER' in line):
            value = line.split('=', 1)[1].split('#')[0].strip()
            assert value in ('', 'change-me'), line


def test_backend_env_file_is_ignored_by_git_and_the_example_is_not():
    try:
        ignored = subprocess.run(['git', 'check-ignore', '-q', 'backend/.env'], cwd=ROOT)
        example = subprocess.run(['git', 'check-ignore', '-q', 'backend/.env.example'], cwd=ROOT)
    except FileNotFoundError:
        pytest.skip('git is not available')
    if 128 in (ignored.returncode, example.returncode):
        pytest.skip('not inside a git repository (for example a copy of the project)')
    assert ignored.returncode == 0 and example.returncode == 1


# ---------------------------------------------------------------- validation
@pytest.mark.parametrize('raw, message', [
    ({'BACKEND_ENV': 'staging'}, 'BACKEND_ENV must be one of'),
    ({'BACKEND_LOG_LEVEL': 'loud'}, 'BACKEND_LOG_LEVEL must be one of'),
    ({'BACKEND_PORT': 'eighty'}, 'BACKEND_PORT must be a whole number'),
    ({'BACKEND_PORT': '70000'}, 'BACKEND_PORT must be from 1 to 65535'),
    ({'BACKEND_HOST': 'bad host'}, 'BACKEND_HOST is not a valid'),
    ({'BACKEND_DB_ENABLED': 'maybe'}, 'BACKEND_DB_ENABLED must be true or false'),
])
def test_invalid_general_settings_are_rejected(raw, message):
    with pytest.raises(SettingsError) as err:
        parse_settings(raw)
    assert message in str(err.value)


def test_database_settings_are_checked_only_when_enabled():
    assert parse_settings({'BACKEND_DB_PORT': 'nonsense'}).database is None   # disabled
    s = parse_settings(db_settings())
    assert (s.database.host, s.database.port, s.database.name) == ('127.0.0.1', 3307,
                                                                 'netcommand_test')
    assert s.database.password.reveal() == DB_SECRET


def test_enabled_database_needs_every_value_and_never_shows_the_password():
    raw = db_settings(BACKEND_DB_HOST=None, BACKEND_DB_USER=None, BACKEND_DB_NAME=None,
                      BACKEND_DB_PORT='99999')
    with pytest.raises(SettingsError) as err:
        parse_settings(raw)
    text = str(err.value)
    for name in ('BACKEND_DB_HOST is required', 'BACKEND_DB_USER is required',
                 'BACKEND_DB_NAME is required', 'BACKEND_DB_PORT must be from 1 to 65535'):
        assert name in text
    assert DB_SECRET not in text and DB_SECRET not in repr(err.value.problems)


def test_enabled_database_password_is_required():
    with pytest.raises(SettingsError) as err:
        parse_settings(db_settings(BACKEND_DB_PASSWORD=None))
    assert 'BACKEND_DB_PASSWORD is required' in str(err.value)


def test_database_name_is_checked():
    with pytest.raises(SettingsError) as err:
        parse_settings(db_settings(BACKEND_DB_NAME='netcommand; DROP'))
    assert 'BACKEND_DB_NAME may only use' in str(err.value)


def test_smtp_is_checked_only_when_enabled_and_defaults_to_587():
    assert parse_settings({'BACKEND_SMTP_FROM': 'not an email'}).smtp is None
    s = parse_settings(smtp_settings())
    assert s.smtp.port == 587 and s.smtp.password.reveal() == SMTP_SECRET


def test_enabled_smtp_rejects_bad_values_without_showing_the_password():
    with pytest.raises(SettingsError) as err:
        parse_settings(smtp_settings(BACKEND_SMTP_FROM='nobody', BACKEND_SMTP_USERNAME=None))
    text = str(err.value)
    assert 'BACKEND_SMTP_FROM must be an email address' in text
    assert 'BACKEND_SMTP_USERNAME is required' in text and SMTP_SECRET not in text


def test_fernet_key_is_checked_when_set_and_never_shown():
    good = Fernet.generate_key().decode()
    assert parse_settings({'BACKEND_FERNET_KEY': good}).fernet_key.reveal() == good
    bad = 'definitely-not-a-fernet-key-but-secret'
    with pytest.raises(SettingsError) as err:
        parse_settings({'BACKEND_FERNET_KEY': bad})
    assert 'BACKEND_FERNET_KEY is not a valid Fernet key' in str(err.value)
    assert bad not in str(err.value)


def test_otp_pepper_is_checked_when_set():
    assert parse_settings({'BACKEND_OTP_PEPPER': 'p' * 32}).otp_pepper
    with pytest.raises(SettingsError) as err:
        parse_settings({'BACKEND_OTP_PEPPER': 'short-pepper'})
    assert 'at least 32 characters' in str(err.value) and 'short-pepper' not in str(err.value)


def test_all_problems_are_reported_together():
    with pytest.raises(SettingsError) as err:
        parse_settings({'BACKEND_ENV': 'x', 'BACKEND_PORT': '0', 'BACKEND_LOG_LEVEL': 'y'})
    assert len(err.value.problems) == 3


# ---------------------------------------------------------------- secrets stay hidden
def test_secret_values_are_masked_everywhere():
    s = parse_settings(dict(db_settings(), **smtp_settings(),
                            BACKEND_OTP_PEPPER='o' * 40,
                            BACKEND_FERNET_KEY=Fernet.generate_key().decode()))
    shown = ' '.join([str(s), repr(s), f'{s}', str(s.database), repr(s.smtp),
                      f'{s.database.password}', str(s.otp_pepper), S.describe(s)])
    for secret in (DB_SECRET, SMTP_SECRET, 'o' * 40, s.fernet_key.reveal()):
        assert secret not in shown
    assert Secret.MASK in shown
    assert sorted(s.secret_values()) == sorted([DB_SECRET, SMTP_SECRET, 'o' * 40,
                                                s.fernet_key.reveal()])


def test_secrets_cannot_be_pickled():
    with pytest.raises(TypeError):
        pickle.dumps(Secret('value'))


def test_describe_says_only_whether_secrets_are_set():
    text = S.describe(parse_settings(db_settings(BACKEND_OTP_PEPPER='q' * 32)))
    assert 'database=enabled' in text and 'otp_pepper=set' in text and 'fernet_key=not set' in text
    assert DB_SECRET not in text and 'q' * 32 not in text


def test_module_runner_refuses_bad_settings_without_values(capsys, monkeypatch):
    from backend import __main__ as runner
    monkeypatch.setenv('BACKEND_DB_ENABLED', 'true')
    monkeypatch.setenv('BACKEND_DB_PASSWORD', DB_SECRET)
    assert runner.main() == 2                                   # never reaches uvicorn
    err = capsys.readouterr().err
    assert 'NetCommand backend not started' in err and 'BACKEND_DB_HOST is required' in err
    assert DB_SECRET not in err


# ---------------------------------------------------------------- production database safety
PROD_UUID = '3e11fa47-71ca-11e1-9e33-c80aa9429562'


def test_server_uuid_is_optional_validated_and_stored_lower_case():
    assert parse_settings(db_settings()).database.server_uuid == ''
    s = parse_settings(db_settings(BACKEND_DB_SERVER_UUID=PROD_UUID.upper()))
    assert s.database.server_uuid == PROD_UUID
    with pytest.raises(SettingsError) as err:
        parse_settings(db_settings(BACKEND_DB_SERVER_UUID='not-a-uuid'))
    assert 'BACKEND_DB_SERVER_UUID must be a MySQL server UUID' in str(err.value)


def test_production_database_needs_the_production_environment_and_a_uuid():
    s = parse_settings(db_settings(BACKEND_DB_NAME='netcommand_backend', BACKEND_ENV='production',
                                   BACKEND_DB_SERVER_UUID=PROD_UUID))
    assert (s.environment, s.database.name, s.database.server_uuid) == (
        'production', 'netcommand_backend', PROD_UUID)
    for raw, problem in [
        (db_settings(BACKEND_DB_NAME='netcommand_backend', BACKEND_DB_SERVER_UUID=PROD_UUID),
         'used only with BACKEND_ENV=production'),
        (db_settings(BACKEND_DB_NAME='netcommand_backend', BACKEND_ENV='test',
                     BACKEND_DB_SERVER_UUID=PROD_UUID), 'used only with BACKEND_ENV=production'),
        (db_settings(BACKEND_DB_NAME='netcommand_backend', BACKEND_ENV='production'),
         'BACKEND_DB_SERVER_UUID is required for the production database'),
        (db_settings(BACKEND_ENV='production'), 'BACKEND_ENV=production requires BACKEND_DB_NAME'),
        (db_settings(BACKEND_ENV='production', BACKEND_DB_NAME='netcommand'),
         'BACKEND_ENV=production requires BACKEND_DB_NAME'),
        (db_settings(BACKEND_ENV='production', BACKEND_DB_NAME='other_db'),
         'BACKEND_ENV=production requires BACKEND_DB_NAME'),
    ]:
        with pytest.raises(SettingsError) as err:
            parse_settings(raw)
        assert problem in str(err.value) and DB_SECRET not in str(err.value)


def test_current_development_configuration_is_unchanged():
    s = parse_settings(db_settings(BACKEND_DB_USER='netcommand_api'))
    assert (s.environment, s.database.name, s.database.server_uuid) == (
        'development', 'netcommand_test', '')


def test_production_without_a_database_behaves_as_before():
    s = parse_settings({'BACKEND_ENV': 'production'})
    assert s.environment == 'production' and s.database is None and not s.docs_enabled
