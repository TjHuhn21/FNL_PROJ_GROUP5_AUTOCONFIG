"""Local administrator commands (run on the server; there is no API endpoint for them).

    .\\venv\\Scripts\\python.exe -m backend.auth.bootstrap_admin                  (create)
    .\\venv\\Scripts\\python.exe -m backend.auth.bootstrap_admin verify-existing

Every NetCommand account must prove its email address with an emailed one-time code
before it may be active. These commands apply that rule to administrators:

create (the default): create the FIRST administrator.
  1. Refuses at once if an active administrator already exists, or the address is taken.
  2. Asks for the email address, full name and password (typed twice, hidden), checked
     with the normal rules (plain-ASCII email, password policy).
  3. Emails a six-digit code to that address and asks for it (5 tries per code, the
     policy's expiry, up to 2 new codes 60 s apart). The code is kept only in this
     command's memory, as an HMAC under a key made for this run: nothing is written to
     the database before the address is confirmed.
  4. Only then creates the account (active, role admin, email verified) atomically:
     AuthRepository.create_first_admin takes a per-database lock, re-reads the active
     admins with a locking read and writes the account and its audit record in one
     transaction, so two runs at the same time cannot both succeed.

verify-existing: verify the email address of an EXISTING active administrator that was
  created before this rule (its address was never verified, so it cannot sign in).
  Asks for the account's email address, emails a code to it, and after the right code
  records the verification time. Nothing else about the account changes: not its id,
  password, role, status or history. No account is deleted or created.

Both use the backend's settings (backend/.env or BACKEND_* variables: the RUNTIME account
BACKEND_DB_USER on BACKEND_DB_NAME, and the mail settings BACKEND_MAIL_BACKEND /
BACKEND_SMTP_*). The desktop application's database and .env are never used. Database
names follow the migration rules: *_test is allowed; any other name needs
--authorize-database NAME, and the main 'netcommand' database also --allow-main-database.
The PRODUCTION database (netcommand_backend) also needs BACKEND_ENV=production,
--production and --confirm-database NAME, and the server must pass the identity check
(SELECT DATABASE(), @@server_uuid against BACKEND_DB_NAME / BACKEND_DB_SERVER_UUID: a
wrong-server safeguard, not proof of identity) before anything is asked.
Nothing secret is printed: not the password, its hash, the code or any setting's value.
Audited: codes sent, failed to send or wrong; the creation; the verification; refusals.

Exit codes: 0 done (or the address was already verified); 1 refused (an active admin
exists, the address is taken / not an active admin, or the database name is not
approved); 2 invalid input; 3 settings, database or email delivery unavailable; 4 the
email code was not confirmed (nothing was created or changed); 130 cancelled.
"""
import argparse
import getpass
import hashlib
import hmac
import math
import secrets
import sys
import time

EXIT_DONE, EXIT_REFUSED, EXIT_INVALID, EXIT_UNAVAILABLE = 0, 1, 2, 3
EXIT_NOT_CONFIRMED, EXIT_CANCELLED = 4, 130
EXIT_CREATED = EXIT_DONE
WORKSTATION_LABEL = 'local bootstrap command'
ACTIONS = ('create', 'verify-existing')
MAX_NEW_CODES = 2
LABELS = {'admin_setup': 'first-administrator', 'admin_verify': 'administrator verification'}


def parse_args(argv):
    p = argparse.ArgumentParser(prog='python -m backend.auth.bootstrap_admin',
                                description='Create the first NetCommand administrator, or '
                                            'verify the email address of an existing one.')
    p.add_argument('action', nargs='?', choices=ACTIONS, default='create',
                   help='create (default) or verify-existing')
    p.add_argument('--authorize-database', metavar='NAME',
                   help='allow a database whose name does not end in _test')
    p.add_argument('--allow-main-database', action='store_true',
                   help="also needed for the main 'netcommand' database")
    p.add_argument('--confirm-database', metavar='NAME',
                   help='needed (with --production) for the production database')
    p.add_argument('--production', action='store_true',
                   help='required (with BACKEND_ENV=production) for the production database, '
                        'refused for any other')
    return p.parse_args(argv)


def run(argv=None, *, settings=None, repository=None, mailer=None, ask=input,
        ask_secret=getpass.getpass, out=print, clock=time.monotonic, identity_connect=None):
    """The command; returns the exit code. Every argument after argv is for tests."""
    args = parse_args(sys.argv[1:] if argv is None else argv)
    io = {'ask': ask, 'ask_secret': ask_secret, 'out': out, 'clock': clock}
    try:
        prepared = _prepare(args, settings, repository, mailer, out, identity_connect)
        if isinstance(prepared, int):
            return prepared
        if args.action == 'verify-existing':
            return _verify_existing(*prepared, io)
        return _create(*prepared, io)
    except (KeyboardInterrupt, EOFError):
        out('Cancelled. Nothing was created or changed.')
        return EXIT_CANCELLED


# ---------------------------------------------------------------- shared
def _prepare(args, settings, repository, mailer, out, identity_connect=None):
    """(settings, repository, mailer), or an exit code. Nothing is asked before this."""
    from backend.database import production
    from backend.database.errors import MigrationError, RepositoryError
    from backend.database.migrations import check_database_name
    from backend.settings import SettingsError, load_settings
    if settings is None:
        try:
            settings = load_settings()
        except SettingsError as err:              # names settings, never their values
            out(f'Settings problem: {err}')
            return EXIT_UNAVAILABLE
    if settings.database is None:
        out('The backend database is not configured (BACKEND_DB_ENABLED is not true). '
            'Nothing was changed.')
        return EXIT_UNAVAILABLE
    verb = ('verify an administrator in' if args.action == 'verify-existing'
            else 'create an administrator in')
    try:
        kind = production.check_target(settings.database.name, settings.environment,
                                       production_flag=args.production,
                                       authorized=args.authorize_database,
                                       confirmed=args.confirm_database)
        check_database_name(settings.database.name, args.authorize_database,
                            args.allow_main_database, action=verb)
    except MigrationError as err:
        out(f'{err} Nothing was changed.')
        return EXIT_REFUSED
    try:                                          # wrong server / database safeguard
        if production.check_runtime_identity(settings, kind, connect=identity_connect):
            out(f'Identity checked: database {settings.database.name} '
                f'{production.SAFEGUARD_NOTE}.')
    except MigrationError as err:
        out(str(err))
        return EXIT_REFUSED
    except RepositoryError as err:
        out(f'The backend database could not be used: {err} Nothing was changed.')
        return EXIT_UNAVAILABLE
    if mailer is None:
        from backend.mail.delivery import MailConfigurationError, create_mailer
        try:
            mailer = create_mailer(settings)
        except MailConfigurationError as err:
            out(f'{err} The email address must be confirmed with an emailed code, so email '
                f'delivery (BACKEND_MAIL_BACKEND) must be set up first. Nothing was changed.')
            return EXIT_UNAVAILABLE
    if repository is None:
        from backend.database.auth_repository import AuthRepository
        repository = AuthRepository.from_settings(settings)
    return settings, repository, mailer


def _audit(repository, action, outcome, email, detail, user_id=None):
    try:
        repository.write_audit(action, outcome, actor_user_id=user_id, actor_email=email,
                               target_type='user' if user_id else None,
                               target_id=str(user_id) if user_id else None,
                               workstation_label=WORKSTATION_LABEL, detail=detail)
    except Exception:
        pass                                      # the command's own result matters more


def _mac(key, code):
    return hmac.new(key, code.encode('ascii'), hashlib.sha256).digest()


def confirm_email(mailer, repository, email, full_name, purpose, policy, io, user_id=None):
    """Email a code to `email` and ask for it. Returns 'confirmed', 'not_confirmed' or
    'mail_failed'. The code exists only in the email and, as an HMAC under a key made
    for this call, in memory."""
    from backend.auth.otp import generate_otp, normalise_submitted_code
    from backend.mail.delivery import MailError
    from backend.mail.messages import build_admin_email
    ask, out, clock = io['ask'], io['out'], io['clock']
    label = LABELS[purpose]
    key = secrets.token_bytes(32)
    state = {'mac': None, 'sent_at': 0.0, 'attempts': 0}
    ttl, tries = policy.otp_ttl_seconds, policy.otp_max_attempts

    def send():
        code = generate_otp()
        outgoing = build_admin_email(email, full_name, purpose, code, ttl)
        try:
            mailer.send(outgoing)
        except MailError as err:                  # fixed message: never the server reply
            _audit(repository, 'auth.code_email_failed', 'failure', email,
                   f'{label} code not sent ({type(err).__name__})', user_id)
            out(f'The code could not be emailed: {err}')
            return False
        state.update(mac=_mac(key, code), sent_at=clock(), attempts=0)
        _audit(repository, 'auth.code_sent', 'success', email, f'{label} code sent', user_id)
        out(f'A 6-digit code was emailed to {email}. It expires in {ttl // 60} minute(s) '
            f'and allows {tries} tries.')
        return True

    if not send():
        return 'mail_failed'
    new_codes = 0
    while True:
        answer = ask('Code from the email (or R for a new code): ').strip()
        if not answer:
            continue
        if answer.lower() == 'r':
            if new_codes >= MAX_NEW_CODES:
                out('No more new codes in this run. Nothing was changed.')
                return 'not_confirmed'
            wait = policy.resend_cooldown_seconds - (clock() - state['sent_at'])
            if wait > 0:
                out(f'Wait {math.ceil(wait)} seconds before asking for a new code.')
                continue
            new_codes += 1
            if not send():
                return 'mail_failed'
            continue
        if state['mac'] is None or clock() - state['sent_at'] >= ttl:
            state['mac'] = None
            if new_codes >= MAX_NEW_CODES:
                out('The code has expired or was used up, and no more new codes can be sent '
                    'in this run. Nothing was changed.')
                return 'not_confirmed'
            out('That code can no longer be used (expired or too many tries). Type R for a '
                'new code.')
            continue
        state['attempts'] += 1
        submitted = normalise_submitted_code(answer)
        candidate = _mac(key, submitted if submitted is not None else '0' * 6)
        if hmac.compare_digest(candidate, state['mac']) and submitted is not None:
            state['mac'] = None                   # used once
            return 'confirmed'
        _audit(repository, 'auth.code_failed', 'failure', email,
               f"wrong {label} code (attempt {state['attempts']} of {tries})", user_id)
        if state['attempts'] >= tries:
            state['mac'] = None
            out('Wrong code. That code is used up; type R for a new one.')
        else:
            out(f"Wrong code. {tries - state['attempts']} try/tries left.")


# ---------------------------------------------------------------- create
def _create(settings, repository, mailer, io):
    from backend.auth import passwords
    from backend.database import auth_records as R
    from backend.database.errors import (AdminExists, DuplicateEmail, InvalidValue,
                                         RepositoryError)
    out, ask, ask_secret = io['out'], io['ask'], io['ask_secret']
    policy = settings.auth_policy
    name = settings.database.name

    # early checks, so nobody types a password for nothing (the real check is atomic)
    try:
        if any(u['role'] == 'admin' for u in repository.list_users(status='active', limit=1000)):
            out('An active administrator already exists, so this command is not needed. '
                'Ask an administrator to approve new accounts. Nothing was created.')
            return EXIT_REFUSED
    except RepositoryError as err:
        out(f'The backend database could not be used: {err} Nothing was created.')
        return EXIT_UNAVAILABLE

    out(f'Creating the first NetCommand administrator in database {name}.')
    try:
        email = R.check_email(ask('Administrator email address: '))
        normalized = R.normalize_email(email)
        full_name = R.check_full_name(ask('Full name: '))
    except InvalidValue as err:
        out(f'{err} Nothing was created.')
        return EXIT_INVALID
    try:
        if repository.find_user_by_email(normalized) is not None:
            _audit(repository, 'user.bootstrap_admin', 'denied', normalized,
                   'first administrator not created: email address already registered')
            out('An account with this email address already exists. Use another address. '
                'Nothing was created.')
            return EXIT_REFUSED
    except RepositoryError as err:
        out(f'The backend database could not be used: {err} Nothing was created.')
        return EXIT_UNAVAILABLE
    password = ask_secret(f'Password (at least {policy.password_min_length} characters, '
                          f'not shown): ')
    try:
        passwords.check_new_password(password, policy)
    except passwords.PasswordPolicyError as err:
        out(f'{err} Nothing was created.')
        return EXIT_INVALID
    if ask_secret('Type the password again: ') != password:
        out('The two passwords are not the same. Nothing was created.')
        return EXIT_INVALID
    password_hash = passwords.hash_password(password, policy)
    del password

    # the email address must be confirmed before anything is written
    result = confirm_email(mailer, repository, normalized, full_name, 'admin_setup', policy, io)
    if result == 'mail_failed':
        out('Nothing was created. Check the mail settings and try again.')
        return EXIT_UNAVAILABLE
    if result != 'confirmed':
        out('The email address was not confirmed. Nothing was created.')
        return EXIT_NOT_CONFIRMED

    try:
        created = repository.create_first_admin(email, full_name, password_hash,
                                                workstation_label=WORKSTATION_LABEL)
    except AdminExists as err:
        _audit(repository, 'user.bootstrap_admin', 'denied', normalized,
               'first administrator not created: an active admin already exists')
        out(str(err))
        return EXIT_REFUSED
    except DuplicateEmail:
        _audit(repository, 'user.bootstrap_admin', 'denied', normalized,
               'first administrator not created: email address already registered')
        out('An account with this email address already exists. Nothing was created.')
        return EXIT_REFUSED
    except InvalidValue as err:
        out(f'{err} Nothing was created.')
        return EXIT_INVALID
    except RepositoryError as err:                # unavailable, busy, database error
        out(f'The administrator could not be created: {err}')
        return EXIT_UNAVAILABLE

    out(f"First administrator created: {email} (user id {created['user_id']}), email address "
        f'verified.')
    if created['inactive_admins']:
        out(f"Note: {created['inactive_admins']} disabled or inactive admin account(s) already "
            f'existed; they were not changed.')
    out('Sign in from the NetCommand desktop with this email address and password; a '
        'sign-in code will be emailed to it.')
    return EXIT_DONE


# ---------------------------------------------------------------- verify-existing
def _verify_existing(settings, repository, mailer, io):
    from backend.database import auth_records as R
    from backend.database.errors import InvalidValue, RepositoryError
    out, ask = io['out'], io['ask']
    out(f'Verifying the email address of an existing administrator in database '
        f'{settings.database.name}.')
    try:
        normalized = R.normalize_email(ask('Administrator email address: '))
    except InvalidValue as err:
        out(f'{err} Nothing was changed.')
        return EXIT_INVALID
    try:
        user = repository.find_user_by_email(normalized)
    except RepositoryError as err:
        out(f'The backend database could not be used: {err} Nothing was changed.')
        return EXIT_UNAVAILABLE
    if user is None:
        out('No account uses this email address. Nothing was changed.')
        return EXIT_REFUSED
    if user['role'] != 'admin' or user['status'] != 'active':
        out('This command only verifies ACTIVE ADMINISTRATOR accounts (other accounts verify '
            'their address when they register). Nothing was changed.')
        return EXIT_REFUSED
    if user.get('email_verified_at') is not None:
        out(f"The email address of {user['email']} is already verified. Nothing to do.")
        return EXIT_DONE

    result = confirm_email(mailer, repository, normalized, user['full_name'], 'admin_verify',
                           settings.auth_policy, io, user_id=user['id'])
    if result == 'mail_failed':
        out('Nothing was changed. Check the mail settings and try again.')
        return EXIT_UNAVAILABLE
    if result != 'confirmed':
        out('The email address was not confirmed. Nothing was changed.')
        return EXIT_NOT_CONFIRMED
    try:
        marked = repository.mark_existing_admin_email_verified(
            user['id'], workstation_label=WORKSTATION_LABEL)
    except RepositoryError as err:
        out(f'The verification could not be saved: {err}')
        return EXIT_UNAVAILABLE
    if not marked:
        out('The account changed while the code was being confirmed (it is no longer an '
            'unverified active administrator). Nothing was changed.')
        return EXIT_REFUSED
    out(f"Email address verified for {user['email']} (user id {user['id']}). Nothing else "
        f'about the account was changed. It can sign in again.')
    return EXIT_DONE


def main():
    sys.exit(run())


if __name__ == '__main__':
    main()
