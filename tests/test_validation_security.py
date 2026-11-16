import os, sys
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))
import pytest

import security
import validation as v


def test_ip():
    assert v.check_ip('192.168.1.10') is None
    for bad in ('999.1.1.1', 'hello', '', '192.168.1', '1.2.3.4.5'):
        assert 'IPv4' in v.check_ip(bad)


def test_name():
    assert v.check_name('SW-1.lab') is None
    assert v.check_name('') and v.check_name('bad name') and v.check_name('x' * 81)


def test_vlan_id():
    assert v.check_vlan(10, {20}) is None and v.check_vlan('10') is None
    assert 'number' in v.check_vlan('abc')
    assert '2 to 4094' in v.check_vlan(1) and '2 to 4094' in v.check_vlan(5000)
    assert 'reserved' in v.check_vlan(1003)
    assert 'already' in v.check_vlan(10, {10})


def test_vlan_name_port_mask():
    assert v.check_vlan_name('SALES') is None
    assert v.check_vlan_name('bad name') and v.check_vlan_name('') and v.check_vlan_name('x' * 33)
    assert v.check_port('Fa0/1') is None and v.check_port('Gi1/0/2') is None
    assert v.check_port('') and v.check_port('hello world')
    assert v.check_mask('255.255.255.0') is None and v.check_mask('300.0.0.0')


def test_encrypt_roundtrip(monkeypatch):
    from cryptography.fernet import Fernet
    monkeypatch.setenv('FERNET_KEY', Fernet.generate_key().decode())
    token = security.encrypt('cisco123')
    assert token != 'cisco123' and 'cisco' not in token
    assert security.decrypt(token) == 'cisco123'


def test_missing_key_gives_clear_message(monkeypatch, tmp_path):
    monkeypatch.setenv('FERNET_KEY', '')
    monkeypatch.setattr(security, 'ENV_PATH', str(tmp_path / '.env'))   # ignore the real .env
    with pytest.raises(RuntimeError) as err:
        security.encrypt('x')
    assert 'FERNET_KEY' in str(err.value)


# ---------------------------------------------------------------- B1: key checks (never show the key)
@pytest.fixture
def env_file(monkeypatch, tmp_path):
    """A private .env path for the test; the real .env and real environment are ignored."""
    path = tmp_path / '.env'
    monkeypatch.setattr(security, 'ENV_PATH', str(path))
    monkeypatch.delenv('FERNET_KEY', raising=False)
    return path


def new_key():
    from cryptography.fernet import Fernet
    return Fernet.generate_key().decode()


def test_check_key_missing_placeholder_truncated_and_valid(env_file):
    assert 'FERNET_KEY' in security.check_key()                      # no .env at all
    env_file.write_text('FERNET_KEY=generate-your-own\n')
    assert 'not set' in security.check_key()
    key = new_key()
    env_file.write_text(f'FERNET_KEY={key[:-1]}\n')                   # the B1 bug: "=" lost
    problem = security.check_key()
    assert '44' in problem and '43' in problem and key[:-1] not in problem
    env_file.write_text(f'FERNET_KEY={key}\n')
    assert security.check_key() is None


def test_errors_never_contain_the_key(env_file, monkeypatch):
    bad = new_key()[:-1]
    for where in ('file', 'env'):
        if where == 'file':
            env_file.write_text(f'FERNET_KEY={bad}\n')
        else:
            env_file.write_text('')
            monkeypatch.setenv('FERNET_KEY', bad)
        with pytest.raises(RuntimeError) as err:
            security.encrypt('cisco123')
        assert bad not in str(err.value) and 'FERNET_KEY' in str(err.value)


def test_the_checked_key_is_the_key_that_is_used(env_file, monkeypatch):
    from cryptography.fernet import Fernet
    file_key, env_key = new_key(), new_key()
    env_file.write_text(f'FERNET_KEY={file_key}\n')
    monkeypatch.setenv('FERNET_KEY', env_key)                         # environment variable wins
    assert security.check_key() is None
    token = security.encrypt('cisco123')
    assert Fernet(env_key.encode()).decrypt(token.encode()) == b'cisco123'
    monkeypatch.setenv('FERNET_KEY', env_key[:-1])                    # bad env var, good .env:
    assert 'environment variable' in security.check_key()             # reported, never skipped
    with pytest.raises(RuntimeError):
        security.encrypt('x')
    monkeypatch.setenv('FERNET_KEY', file_key)                        # same as .env (db.py copies it)
    assert security._resolve_key()[1] == '.env file'


def test_decrypt_after_the_key_changed_gives_a_clear_message(env_file):
    env_file.write_text(f'FERNET_KEY={new_key()}\n')
    token = security.encrypt('cisco123')
    env_file.write_text(f'FERNET_KEY={new_key()}\n')
    with pytest.raises(RuntimeError) as err:
        security.decrypt(token)
    assert 'enter its login again' in str(err.value)


def test_write_new_key_keeps_other_lines_and_prints_nothing(env_file, monkeypatch, capsys):
    monkeypatch.setattr(security, 'env_git_status', lambda path=None: 'ignored')
    env_file.write_bytes(b'DB_HOST=localhost\r\nDB_PASSWORD=secret\r\nFERNET_KEY= short\r\n\r\n')
    changed, message = security.write_new_key()
    assert changed and capsys.readouterr().out == ''
    raw = env_file.read_bytes().decode()
    assert raw.startswith('DB_HOST=localhost\r\nDB_PASSWORD=secret\r\nFERNET_KEY=')
    assert raw.endswith('\r\n\r\n') and raw.count('FERNET_KEY') == 1    # CRLF and blank line kept
    key = security._file_key()
    assert security.check_key() is None and key not in message
    assert not (env_file.parent / '.env.tmp').exists()
    changed, message = security.write_new_key()                      # valid key: left alone
    assert not changed and 'already valid' in message and security._file_key() == key
    changed, _ = security.write_new_key(force=True)
    assert changed and security._file_key() != key


@pytest.mark.parametrize('status,gitignore,allowed', [
    ('tracked', '.env\n', False), ('not-ignored', '', False),
    ('no-repo', '', False), ('no-repo', 'venv/\n.env\n', True), ('ignored', '', True)])
def test_write_new_key_refuses_when_git_could_expose_env(env_file, monkeypatch, status,
                                                        gitignore, allowed):
    monkeypatch.setattr(security, 'env_git_status', lambda path=None: status)
    if gitignore:
        (env_file.parent / '.gitignore').write_text(gitignore)
    env_file.write_text('DB_HOST=localhost\n')
    changed, message = security.write_new_key()
    assert changed is allowed
    if not allowed:
        assert env_file.read_text() == 'DB_HOST=localhost\n' and 'Nothing changed' in message


def test_env_git_status_with_real_git(tmp_path):
    import shutil, subprocess
    if not shutil.which('git'):
        pytest.skip('git is not installed')
    env = tmp_path / '.env'
    env.write_text('DB_HOST=x\n')
    assert security.env_git_status(str(env)) in ('no-repo', 'ignored', 'not-ignored', 'tracked')
    subprocess.run(['git', 'init', '-q', str(tmp_path)], check=True)
    assert security.env_git_status(str(env)) == 'not-ignored'
    (tmp_path / '.gitignore').write_text('.env\n')
    assert security.env_git_status(str(env)) == 'ignored'
    subprocess.run(['git', '-C', str(tmp_path), 'add', '-f', '.env'], check=True)
    assert security.env_git_status(str(env)) == 'tracked'


def test_command_line_never_prints_the_key(env_file, monkeypatch, capsys):
    monkeypatch.setattr(security, 'env_git_status', lambda path=None: 'ignored')
    env_file.write_text('FERNET_KEY=generate-your-own\n')
    assert security.main(['--check']) == 1
    assert security.main(['--new-key']) == 0
    assert security.main(['--check']) == 0
    out = capsys.readouterr().out
    assert security._file_key() not in out and 'FERNET_KEY is valid' in out
