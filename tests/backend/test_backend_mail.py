"""Email delivery of the six-digit codes (backend/mail): templates, eligibility, SMTP with
stand-in connections, the development outbox, settings and secret handling.

No real email is sent and no network connection is opened: socket.create_connection
fails the test if anything tries. Every address, password and code is test-only.
"""
import logging
import smtplib
import socket
import ssl
import traceback
from email import policy as email_policy
from email.parser import BytesParser

import pytest

from backend.database.errors import InvalidValue
from backend.mail import delivery, messages
from backend.mail.delivery import (DevOutboxMailer, MailConfigurationError, MailDeliveryError,
                                   SmtpMailer, create_mailer, send_otp_email)
from backend.mail.messages import NotEligibleForCode, build_otp_email, check_eligibility
from backend.settings import Settings, SettingsError, describe, parse_settings

CODE = '482915'
SMTP_PASSWORD = 'Test-only-smtp-app-password-7731'
SENDER = 'netcommand-test-sender@example.com'
NEW = {'id': 1, 'email': 'New.User@example.com', 'full_name': 'New User',
       'status': 'pending_verification'}
ACTIVE = {'id': 2, 'email': 'active.user@example.com', 'full_name': 'Active User',
          'status': 'active', 'email_verified_at': '2026-11-19 08:00:00'}


@pytest.fixture(autouse=True)
def no_network(monkeypatch):
    monkeypatch.setattr(socket, 'create_connection',
                        lambda *a, **k: pytest.fail('tried to open a network connection'))


def smtp_settings(port='587'):
    return parse_settings({'BACKEND_SMTP_ENABLED': 'true', 'BACKEND_SMTP_HOST': 'smtp.example.com',
                           'BACKEND_SMTP_PORT': port, 'BACKEND_SMTP_USERNAME': SENDER,
                           'BACKEND_SMTP_PASSWORD': SMTP_PASSWORD, 'BACKEND_SMTP_FROM': SENDER,
                           'BACKEND_MAIL_BACKEND': 'smtp'})


def register_email(**kw):
    return build_otp_email(NEW, 'register', CODE, 300, **kw)


def login_email(**kw):
    return build_otp_email(ACTIVE, 'login', CODE, 300, **kw)


# ================================================================ templates
def test_registration_message():
    m = register_email()
    assert m.to == 'New.User@example.com' and m.purpose == 'register'
    assert m.subject == 'NetCommand: verify your email address'
    for part in (m.text, m.html):
        assert CODE in part and 'New User' in part
        assert 'verify the email address' in part and 'administrator must approve' in part
        assert 'expires in 5 minutes' in part and 'used only once' in part
        assert 'did not create a NetCommand account' in part
        assert 'sign in' not in part.split('approve')[0]          # not a login message


def test_login_message():
    m = login_email(workstation_label='LAB-PC-07')
    assert m.subject == 'NetCommand: your sign-in code' and m.purpose == 'login'
    for part in (m.text, m.html):
        assert CODE in part and 'finish signing in' in part
        assert 'LAB-PC-07' in part and 'contact your NetCommand administrator' in part
        assert 'verify the email address' not in part


def test_the_two_messages_are_clearly_different():
    reg, login = register_email(), login_email()
    assert reg.subject != login.subject and reg.text != login.text
    assert CODE not in reg.subject and CODE not in login.subject


@pytest.mark.parametrize('ttl, words', [(300, '5 minutes'), (60, '1 minute'),
                                        (90, '90 seconds'), (120, '2 minutes')])
def test_expiry_wording(ttl, words):
    assert f'expires in {words} ' in build_otp_email(ACTIVE, 'login', CODE, ttl).text


def test_names_are_escaped_and_kept_on_one_line():
    account = dict(ACTIVE, full_name='<script>alert(1)</script>\r\nBcc: x@example.net')
    m = build_otp_email(account, 'login', CODE, 300)
    assert '<script>' not in m.html and '&lt;script&gt;' in m.html
    assert '\r' not in m.text.split('\n\n')[0]


@pytest.mark.parametrize('kwargs', [{'code': '12345'}, {'code': '1234567'}, {'code': 'abcdef'},
                                    {'code': 482915}, {'code': None}, {'ttl_seconds': 0},
                                    {'ttl_seconds': 3601}, {'workstation_label': 'a\nb'}])
def test_invalid_values_are_refused(kwargs):
    args = dict(account=ACTIVE, purpose='login', code=CODE, ttl_seconds=300)
    args.update(kwargs)
    with pytest.raises(InvalidValue) as err:
        build_otp_email(**args)
    assert CODE not in str(err.value)


def test_outgoing_email_hides_its_bodies():
    m = login_email()
    for text in (repr(m), str(m), f'{m}'):
        assert CODE not in text and 'active.user@example.com' not in text and '[hidden]' in text


# ================================================================ eligibility
@pytest.mark.parametrize('purpose, status, allowed', [
    ('register', 'pending_verification', True),
    ('register', 'pending_approval', False), ('register', 'active', False),
    ('register', 'rejected', False), ('register', 'disabled', False),
    ('login', 'active', True),
    ('login', 'pending_verification', False), ('login', 'pending_approval', False),
    ('login', 'rejected', False), ('login', 'disabled', False),
])
def test_only_eligible_accounts_receive_codes(purpose, status, allowed):
    account = dict(ACTIVE, status=status)
    if allowed:
        assert check_eligibility(purpose, account) == ACTIVE['email']
    else:
        with pytest.raises(NotEligibleForCode) as err:
            build_otp_email(account, purpose, CODE, 300)
        assert status not in str(err.value) and ACTIVE['email'] not in str(err.value)


@pytest.mark.parametrize('account', [None, {}, {'email': 'a@example.com'}, 'a@example.com'])
def test_missing_accounts_are_not_eligible(account):
    with pytest.raises(NotEligibleForCode):
        check_eligibility('login', account)


def test_unknown_purpose_and_injected_addresses_are_refused():
    with pytest.raises(InvalidValue):
        check_eligibility('reset', ACTIVE)
    for bad in ('a@example.com\r\nBcc: x@example.net', 'not-an-address', '', None):
        with pytest.raises(InvalidValue):
            build_otp_email(dict(ACTIVE, email=bad), 'login', CODE, 300)


# ================================================================ SMTP (stand-in connections)
class FakeSmtp:
    """Records every call; fails at a chosen step. Never touches the network."""

    def __init__(self, log, fail_at=None, error=None, refused=None):
        self.log, self.fail_at, self.error, self.refused = log, fail_at, error, refused or {}

    def __call__(self, host, port, timeout=None, context=None):
        self.log.append(('connect', host, port, timeout, context))
        self._step('connect')
        return self

    def _step(self, name):
        if self.fail_at == name:
            raise self.error

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.log.append(('quit',))
        return False

    def set_debuglevel(self, level):
        self.log.append(('debuglevel', level))

    def ehlo(self):
        self.log.append(('ehlo',))
        self._step('ehlo')

    def starttls(self, context=None):
        self.log.append(('starttls', context))
        self._step('starttls')

    def login(self, user, password):
        self.log.append(('login', user, password))
        self._step('login')

    def send_message(self, msg, from_addr=None, to_addrs=None):
        self.log.append(('send', msg, from_addr, to_addrs))
        self._step('send')
        return self.refused


def mailer_with(port='587', **fake):
    log = []
    fake_class = FakeSmtp(log, **fake)
    kwargs = {'smtp_class': fake_class} if port != '465' else {'smtp_ssl_class': fake_class}
    other = 'smtp_ssl_class' if port != '465' else 'smtp_class'
    kwargs[other] = lambda *a, **k: pytest.fail('wrong SMTP class used')
    return SmtpMailer(smtp_settings(port).smtp, **kwargs), log


def steps(log):
    return [entry[0] for entry in log]


def test_smtp_587_requires_starttls_before_login():
    mailer, log = mailer_with()
    mailer.send(login_email())
    assert steps(log) == ['connect', 'debuglevel', 'ehlo', 'starttls', 'ehlo', 'login', 'send',
                          'quit']
    _, host, port, timeout, _ = log[0]
    assert (host, port, timeout) == ('smtp.example.com', 587, delivery.SMTP_TIMEOUT)
    assert ('debuglevel', 0) in log
    context = log[3][1]
    assert isinstance(context, ssl.SSLContext)
    assert context.verify_mode == ssl.CERT_REQUIRED and context.check_hostname
    assert log[5] == ('login', SENDER, SMTP_PASSWORD)
    _, msg, from_addr, to_addrs = log[6]
    assert from_addr == SENDER and to_addrs == ['active.user@example.com']
    assert msg['Subject'] == 'NetCommand: your sign-in code' and msg['To'] == ACTIVE['email']
    assert msg['From'] == SENDER and msg['Auto-Submitted'] == 'auto-generated'
    plain = msg.get_body(preferencelist=('plain',)).get_content()
    rich = msg.get_body(preferencelist=('html',)).get_content()
    assert CODE in plain and CODE in rich


def test_smtp_465_uses_tls_from_the_start():
    mailer, log = mailer_with(port='465')
    mailer.send(register_email())
    assert steps(log) == ['connect', 'debuglevel', 'login', 'send', 'quit']
    assert isinstance(log[0][4], ssl.SSLContext)


def test_no_starttls_means_the_password_is_never_sent():
    mailer, log = mailer_with(fail_at='starttls',
                              error=smtplib.SMTPNotSupportedError('STARTTLS not supported'))
    with pytest.raises(MailDeliveryError) as err:
        mailer.send(login_email())
    assert err.value.reason == 'tls_unavailable'
    assert 'login' not in steps(log) and 'send' not in steps(log)


REPLY = f'5.7.8 Username and Password not accepted {SMTP_PASSWORD} {CODE} server-detail-xyz'
FAILURES = [
    ('login', smtplib.SMTPAuthenticationError(535, REPLY.encode()), 'authentication'),
    ('send', smtplib.SMTPRecipientsRefused({ACTIVE['email']: (550, REPLY.encode())}),
     'recipient_refused'),
    ('send', smtplib.SMTPSenderRefused(553, REPLY.encode(), SENDER), 'sender_refused'),
    ('send', smtplib.SMTPDataError(554, REPLY.encode()), 'smtp_error'),
    ('connect', ConnectionRefusedError(10061, REPLY), 'connection'),
    ('connect', socket.timeout(REPLY), 'connection'),
    ('connect', smtplib.SMTPConnectError(421, REPLY.encode()), 'connection'),
    ('ehlo', smtplib.SMTPServerDisconnected(REPLY), 'connection'),
    ('starttls', ssl.SSLCertVerificationError(1, REPLY), 'tls_failed'),
    ('login', smtplib.SMTPException(REPLY), 'smtp_error'),
]


@pytest.mark.parametrize('fail_at, error, reason', FAILURES)
def test_failures_have_a_fixed_reason_and_reveal_nothing(fail_at, error, reason, caplog):
    mailer, _ = mailer_with(fail_at=fail_at, error=error)
    with caplog.at_level(logging.DEBUG):
        with pytest.raises(MailDeliveryError) as err:
            mailer.send(login_email())
    e = err.value
    assert e.reason == reason and str(e) == f'The email could not be sent: {delivery.REASONS[reason]}.'
    assert e.__cause__ is None and e.__suppress_context__
    shown = ' '.join([str(e), repr(e), ''.join(traceback.format_exception(e)), caplog.text])
    for secret in (SMTP_PASSWORD, CODE, 'server-detail-xyz', ACTIVE['email']):
        assert secret not in shown
    assert reason in caplog.text and 'a***@example.com' in caplog.text


def test_a_refused_recipient_in_the_reply_is_a_failure():
    mailer, _ = mailer_with(refused={ACTIVE['email']: (550, b'no such user')})
    with pytest.raises(MailDeliveryError) as err:
        mailer.send(login_email())
    assert err.value.reason == 'recipient_refused'


def test_success_logs_only_purpose_and_masked_address(caplog):
    mailer, _ = mailer_with()
    with caplog.at_level(logging.DEBUG):
        mailer.send(register_email())
    assert 'Email sent: register code to N***@example.com' in caplog.text
    for secret in (CODE, SMTP_PASSWORD, NEW['email']):
        assert secret not in caplog.text


def test_smtp_mailer_needs_settings_and_hides_the_password():
    with pytest.raises(MailConfigurationError):
        SmtpMailer(None)
    mailer, _ = mailer_with()
    assert SMTP_PASSWORD not in repr(mailer) and SMTP_PASSWORD not in str(mailer)


def test_only_outgoing_emails_can_be_sent():
    mailer, log = mailer_with()
    with pytest.raises(TypeError):
        mailer.send({'to': 'a@example.com', 'text': CODE})
    assert log == []


# ================================================================ development outbox
def read(path):
    with open(path, 'rb') as f:
        return BytesParser(policy=email_policy.default).parse(f)


def test_outbox_writes_one_file_per_message(tmp_path, caplog):
    box = DevOutboxMailer(tmp_path / 'outbox', 'development')
    with caplog.at_level(logging.DEBUG):
        box.send(register_email())
        box.send(login_email())
    files = sorted((tmp_path / 'outbox').glob('*.eml'))
    assert len(files) == 2
    assert all(CODE not in f.name for f in files)
    assert files[0].name.split('-')[1] in ('register', 'login')
    msgs = box.messages()
    assert [m['Subject'] for m in msgs] == ['NetCommand: verify your email address',
                                            'NetCommand: your sign-in code']
    assert CODE in msgs[0].get_body(preferencelist=('plain',)).get_content()
    assert [m['To'] for m in box.messages(to='active.user@EXAMPLE.com')] == [ACTIVE['email']]
    assert CODE not in caplog.text and 'development outbox' in caplog.text


@pytest.mark.parametrize('environment', ['production', 'staging', '', None])
def test_outbox_is_refused_outside_development_and_test(tmp_path, environment):
    with pytest.raises(MailConfigurationError):
        DevOutboxMailer(tmp_path, environment)


def test_outbox_rechecks_the_environment_on_every_use(tmp_path):
    box = DevOutboxMailer(tmp_path, 'test')
    box.send(login_email())
    box._environment = 'production'                    # e.g. an object kept too long
    with pytest.raises(MailConfigurationError):
        box.send(login_email())
    with pytest.raises(MailConfigurationError):
        box.messages()
    assert len(list(tmp_path.glob('*.eml'))) == 1


def test_outbox_must_be_outside_the_project_folder():
    for inside in (delivery.PROJECT_ROOT / 'outbox', delivery.PROJECT_ROOT / 'backend' / 'x'):
        with pytest.raises(MailConfigurationError, match='outside the NetCommand project'):
            DevOutboxMailer(inside, 'development')
    assert not (delivery.PROJECT_ROOT / 'outbox').exists()


def test_outbox_default_folder_is_in_the_system_temp_folder(monkeypatch, tmp_path):
    import tempfile
    monkeypatch.setattr(tempfile, 'tempdir', str(tmp_path))
    box = DevOutboxMailer('', 'development')
    assert box.directory == tmp_path / 'netcommand-dev-outbox'
    assert box.messages() == []                          # nothing created until a send


# ================================================================ settings and choosing
def test_mail_settings_default_to_none_and_are_validated():
    assert parse_settings({}).mail_backend == 'none'
    s = parse_settings({'BACKEND_MAIL_BACKEND': 'Outbox', 'BACKEND_MAIL_OUTBOX_DIR': 'C:/tmp/x'})
    assert (s.mail_backend, s.mail_outbox_dir) == ('outbox', 'C:/tmp/x')
    assert 'mail=outbox' in describe(s)
    for raw, problem in [
        ({'BACKEND_MAIL_BACKEND': 'sendmail'}, 'BACKEND_MAIL_BACKEND must be one of'),
        ({'BACKEND_MAIL_BACKEND': 'smtp'}, 'needs BACKEND_SMTP_ENABLED=true'),
        ({'BACKEND_MAIL_BACKEND': 'outbox', 'BACKEND_ENV': 'production'},
         'refused when BACKEND_ENV=production'),
    ]:
        with pytest.raises(SettingsError) as err:
            parse_settings(raw)
        assert problem in str(err.value)


def test_smtp_settings_never_show_the_password():
    s = smtp_settings()
    for text in (repr(s), str(s), describe(s), repr(s.smtp)):
        assert SMTP_PASSWORD not in text
    with pytest.raises(SettingsError) as err:
        parse_settings({'BACKEND_MAIL_BACKEND': 'smtp', 'BACKEND_SMTP_PASSWORD': SMTP_PASSWORD})
    assert SMTP_PASSWORD not in str(err.value)


def test_create_mailer(tmp_path):
    with pytest.raises(MailConfigurationError, match='not configured'):
        create_mailer(parse_settings({}))
    assert isinstance(create_mailer(smtp_settings()), SmtpMailer)
    box = create_mailer(parse_settings({'BACKEND_MAIL_BACKEND': 'outbox',
                                        'BACKEND_MAIL_OUTBOX_DIR': str(tmp_path)}))
    assert isinstance(box, DevOutboxMailer) and box.directory == tmp_path


def test_create_mailer_refuses_the_outbox_in_production_even_if_settings_were_built_by_hand():
    with pytest.raises(MailConfigurationError):
        create_mailer(Settings(environment='production', mail_backend='outbox'))


# ================================================================ sending a code
def test_send_otp_email_for_registration_and_login(tmp_path, caplog):
    box = DevOutboxMailer(tmp_path, 'development')
    with caplog.at_level(logging.DEBUG):
        assert send_otp_email(box, NEW, 'register', CODE, 300) is None     # nothing returned
        assert send_otp_email(box, ACTIVE, 'login', CODE, 300, 'LAB-PC-07') is None
    reg, login = box.messages()
    assert reg['To'] == NEW['email'] and 'verify' in reg['Subject']
    assert login['To'] == ACTIVE['email'] and 'sign-in' in login['Subject']
    assert CODE not in caplog.text


@pytest.mark.parametrize('account, purpose', [(ACTIVE, 'register'), (NEW, 'login'),
                                              (dict(ACTIVE, status='disabled'), 'login'),
                                              (dict(NEW, status='rejected'), 'register')])
def test_ineligible_accounts_get_nothing(tmp_path, account, purpose):
    box = DevOutboxMailer(tmp_path, 'development')
    with pytest.raises(NotEligibleForCode):
        send_otp_email(box, account, purpose, CODE, 300)
    assert box.messages() == []


def test_mail_modules_do_not_touch_the_database_or_device_encryption():
    import ast
    from pathlib import Path
    imported = set()
    for path in (Path(delivery.__file__).parent).glob('*.py'):
        for node in ast.walk(ast.parse(path.read_text(encoding='utf-8'))):
            if isinstance(node, ast.Import):
                imported |= {a.name for a in node.names}
            elif isinstance(node, ast.ImportFrom):
                imported.add(node.module or '')
    for name in imported:
        assert name.split('.')[0] not in ('security', 'db', 'pymysql', 'cryptography'), name
        assert name not in ('backend.database.connection', 'backend.database.auth_repository')
