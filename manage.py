"""Server-side maintenance commands for NetCommand.

    .\\venv\\Scripts\\python.exe manage.py unlock-user <email>
    .\\venv\\Scripts\\python.exe manage.py lock-status <email>

unlock-user is the recovery path when nobody who could unlock an account can sign in (for
example the only administrator was locked after failed device logins). It does exactly what
an administrator's Unlock does: it clears the temporary or permanent device-login lock, the
failure count and the lockout count, and writes an audit record ('security.unlocked', by
"the recovery command on the server").

It runs on the server with the backend's own settings (backend/.env: the runtime database
account), so only someone who can already run the backend there can use it. It never
changes a password, a role or an account status.
"""
import sys

EXIT_DONE, EXIT_USAGE, EXIT_FAILED = 0, 2, 1
USAGE = ('Usage:\n'
         '  python manage.py unlock-user <email>   clear a lock after failed device logins\n'
         '  python manage.py lock-status <email>   show the lock state of an account')


def _service():
    from backend.settings import SettingsError, load_settings
    from backend.auth.service import AuthService
    try:
        settings = load_settings()
    except SettingsError as err:                  # names settings, never their values
        raise SystemExit(f'Settings problem: {err}')
    if settings.database is None:
        raise SystemExit('The backend database is not configured (backend/.env).')
    return AuthService.from_settings(settings, mailer=object())    # no email is sent here


def run(argv=None, out=print, service=None):
    from backend.auth import device_lockout as DL
    from backend.auth.errors import AuthError
    from backend.database.errors import RepositoryError
    argv = sys.argv[1:] if argv is None else argv
    if len(argv) != 2 or argv[0] not in ('unlock-user', 'lock-status'):
        out(USAGE)
        return EXIT_USAGE
    command, email = argv
    service = service or _service()
    try:
        if command == 'lock-status':
            user = service.repo.find_user_by_email(service._email(email))
            if user is None:
                out('No account has this email address.')
                return EXIT_FAILED
            state, now, lockouts = service.repo.device_login_state(user['id'])
            kind = DL.is_locked(state, now)
            if kind == 'permanent':
                text = 'LOCKED until an administrator unlocks it'
            elif kind == 'temporary':
                text = f"locked for {DL.minutes_left(state['locked_until'], now)} more minute(s)"
            else:
                text = 'not locked'
            out(f"{user['email']}: {text}; {state['failed_count']} failed device login(s) in "
                f'the current window; {lockouts} lockout(s) counted in the last '
                f'{DL.LOCKOUT_COUNT_WINDOW_HOURS} hours.')
            return EXIT_DONE
        user, cleared = service.recovery_unlock(email)
    except AuthError as err:
        out(f'{err} Nothing was changed.')
        return EXIT_FAILED
    except RepositoryError as err:
        out(f'The backend database could not be used: {err} Nothing was changed.')
        return EXIT_FAILED
    what = {'permanent': 'The permanent lock was cleared.',
            'temporary': 'The 15-minute lock was cleared.'}.get(cleared, 'It was not locked.')
    out(f"{user['email']}: {what} The failure and lockout counts are reset; the account can "
        f'sign in again. (Audited as security.unlocked.)')
    return EXIT_DONE


if __name__ == '__main__':
    sys.exit(run())
