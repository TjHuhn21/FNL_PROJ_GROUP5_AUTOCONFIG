"""Encrypts the device passwords that are saved in the database.

We ENCRYPT (not hash) device passwords, because the app must send the real
password to the switch later. Hashing is one-way, so it could not be used.
The key lives in the FERNET_KEY setting of the .env file, never in the code.

Where the key comes from (ONE rule, used by both the check and the encryption,
so the app can never check one key and then encrypt with another):
  1. a FERNET_KEY environment variable, when one is set and not empty
  2. otherwise the FERNET_KEY line of the .env file next to this file (ENV_PATH)

Check or fix the key from the netcommand folder:
    python security.py --check      says whether FERNET_KEY is usable
    python security.py --new-key    writes a new key into .env (the key is never printed)

No message in this file ever contains a key, only its length.
"""
import os
import re
import subprocess
import sys

from dotenv import dotenv_values

ENV_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), '.env')
_KEY_LINE = re.compile(r'^\s*FERNET_KEY\s*=')
_FILE = '.env file'
_ENV_VAR = 'FERNET_KEY environment variable'


# ---------------------------------------------------------------- finding and checking the key
def _file_key(env_path=None):
    """FERNET_KEY from the .env file at env_path (default ENV_PATH), or ''."""
    path = env_path or ENV_PATH
    if not os.path.exists(path):
        return ''
    return (dotenv_values(path).get('FERNET_KEY') or '').strip()


def _resolve_key():
    """(key, where it came from). The ONLY place the key is looked up.
    When the environment variable holds the same value as .env (db.py copies
    .env into the environment at startup), the source is reported as .env."""
    env_key = os.environ.get('FERNET_KEY', '').strip()
    file_key = _file_key()
    if env_key and env_key != file_key:
        return env_key, _ENV_VAR
    return file_key, _FILE


def _key_problem(key, where=_FILE):
    """None when key is a usable Fernet key, otherwise a message that never contains the key."""
    from cryptography.fernet import Fernet
    fix = ('Fix it with:  python security.py --new-key' if where == _FILE else
           'Set it to a valid key, or remove it so the key in .env is used.')
    if not key or key.startswith('generate'):
        return f'FERNET_KEY is not set in the {where}. {fix}'
    try:
        Fernet(key.encode())
    except (ValueError, TypeError):
        return (f'The FERNET_KEY in the {where} is not a valid key (a valid key is 44 '
                f'characters long and ends with "="; this one has {len(key)}). {fix}')
    return None


def check_key():
    """Startup check. None when the key is fine, otherwise a safe message."""
    key, where = _resolve_key()
    return _key_problem(key, where)


def _fernet():
    from cryptography.fernet import Fernet
    key, where = _resolve_key()
    problem = _key_problem(key, where)
    if problem:
        raise RuntimeError(problem)
    return Fernet(key.encode())


# ---------------------------------------------------------------- encrypting
class CredentialError(RuntimeError):
    """A saved login cannot be read: the stored value is damaged, or FERNET_KEY is missing,
    invalid or different from the key that encrypted it. The message never contains the
    key, the stored value or the password. It is a RuntimeError, so code that already
    catches RuntimeError keeps working."""


DECRYPT_FAILED = ('A saved login could not be decrypted with the current FERNET_KEY '
                  '(the key was changed). Edit the device and enter its login again.')


def encrypt(text):
    return _fernet().encrypt(text.encode()).decode()


def decrypt(token):
    from cryptography.fernet import InvalidToken
    try:
        fernet = _fernet()
    except RuntimeError as err:           # key missing/invalid: _key_problem's text has no key in it
        raise CredentialError(str(err)) from None
    try:
        return fernet.decrypt(str(token).encode()).decode()
    except (InvalidToken, UnicodeError):  # wrong key or damaged value; InvalidToken's text is empty
        raise CredentialError(DECRYPT_FAILED) from None


# ---------------------------------------------------------------- making a new key
def env_git_status(env_path=None):
    """How Git sees the .env file: 'tracked', 'not-ignored', 'ignored',
    'no-repo' (the folder is not in a Git repository), or 'no-git'."""
    path = env_path or ENV_PATH
    folder, name = os.path.dirname(path), os.path.basename(path)

    def git(*args):
        return subprocess.run(['git', '-C', folder, *args], capture_output=True,
                              text=True, timeout=10).returncode

    try:
        if git('rev-parse', '--is-inside-work-tree') != 0:
            return 'no-repo'
        if git('ls-files', '--error-unmatch', '--', name) == 0:
            return 'tracked'
        return 'ignored' if git('check-ignore', '-q', '--', name) == 0 else 'not-ignored'
    except (OSError, subprocess.SubprocessError):
        return 'no-git'


def _gitignore_lists_env(env_path):
    """True when the .gitignore next to .env has a rule for it (used outside a repository)."""
    path = os.path.join(os.path.dirname(env_path), '.gitignore')
    if not os.path.exists(path):
        return False
    with open(path, encoding='utf-8') as f:
        rules = {line.strip() for line in f}
    return bool(rules & {'.env', '/.env', '*.env'})


def write_new_key(env_path=None, force=False):
    """Put a new key in .env without ever printing it. Every other line is kept.
    Returns (changed, message). Refuses when Git could expose .env, and refuses
    to replace a key that already works unless force=True, because logins
    saved with the old key could no longer be read."""
    from cryptography.fernet import Fernet
    path = env_path or ENV_PATH
    git = env_git_status(path)
    if git == 'tracked':
        return False, ('.env is tracked by Git, so a key written there could be committed. '
                       'Run  git rm --cached .env  and commit, then try again. Nothing changed.')
    if git == 'not-ignored':
        return False, ('.env is not ignored by Git. Add the line  .env  to .gitignore, then '
                       'try again. Nothing changed.')
    if git in ('no-repo', 'no-git') and not _gitignore_lists_env(path):
        return False, ('.gitignore does not list .env, so the key could be committed once Git '
                       'is set up. Add the line  .env  to .gitignore, then try again. '
                       'Nothing changed.')

    current = _file_key(path)
    if current and _key_problem(current) is None and not force:
        return False, ('FERNET_KEY in .env is already valid, nothing changed. Use --force to '
                       'replace it (device logins saved with the old key will have to be '
                       'entered again).')

    raw = ''
    if os.path.exists(path):
        with open(path, encoding='utf-8-sig', newline='') as f:
            raw = f.read()
    newline = '\r\n' if '\r\n' in raw else '\n'
    new_line = 'FERNET_KEY=' + Fernet.generate_key().decode()
    lines, replaced = [], False
    for line in raw.splitlines():
        if _KEY_LINE.match(line):
            if not replaced:                  # first FERNET_KEY line becomes the new key,
                lines.append(new_line)        # any duplicates are dropped
                replaced = True
        else:
            lines.append(line)
    if not replaced:
        lines.append(new_line)

    tmp = path + '.tmp'
    try:
        with open(tmp, 'w', encoding='utf-8', newline='') as f:
            f.write(newline.join(lines) + newline)
        os.replace(tmp, path)                 # all or nothing: .env is never half-written
    finally:
        if os.path.exists(tmp):
            os.remove(tmp)

    message = ('A new FERNET_KEY was written to .env (not shown). Teammates who share this '
               'database need the same key: copy the .env line to them privately, never '
               'through Git or a group chat.')
    if os.environ.get('FERNET_KEY', '').strip():
        message += (' NOTE: a FERNET_KEY environment variable is also set and is used before '
                    '.env. Remove it so the new key is used.')
    return True, message


def main(argv):
    if '--new-key' in argv:
        changed, message = write_new_key(force='--force' in argv)
        print(message)
        return 0 if changed or 'already valid' in message else 1
    if '--check' in argv:
        problem = check_key()
        if problem:
            print(problem)
            return 1
        print(f'FERNET_KEY is valid (read from the {_resolve_key()[1]}).')
        return 0
    print(__doc__)
    return 0


if __name__ == '__main__':
    sys.exit(main(sys.argv[1:]))
