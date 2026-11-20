"""Sending the code emails: real SMTP, or a development-only outbox.

  create_mailer(settings)                       -> SmtpMailer or DevOutboxMailer
  send_otp_email(mailer, account, purpose, code, ttl_seconds, workstation_label=None)

SmtpMailer (BACKEND_MAIL_BACKEND=smtp, the BACKEND_SMTP_* settings):
  * always encrypted: port 465 uses TLS from the first byte; any other port (587) must
    accept STARTTLS before the password is sent, or nothing is sent at all. The server
    certificate and host name are verified (ssl.create_default_context());
  * one connection per message, with a timeout; smtplib's debug output (which would
    show the login) stays off;
  * failures raise MailDeliveryError with a fixed reason (authentication, connection,
    tls_unavailable, tls_failed, recipient_refused, sender_refused, smtp_error): never the
    server's reply, the password or the code, and never the original exception.

DevOutboxMailer (BACKEND_MAIL_BACKEND=outbox; development and test only):
  * refused in production, when created AND on every send or read;
  * writes each message to its own .eml file in BACKEND_MAIL_OUTBOX_DIR (default: a
    'netcommand-dev-outbox' folder in the system temporary directory), never inside the
    project folder, so a code can never be committed by accident.
"""
import logging
import os
import secrets
import smtplib
import ssl
import tempfile
from datetime import datetime, timezone
from email import policy as email_policy
from email.message import EmailMessage
from email.parser import BytesParser
from email.utils import formatdate, make_msgid
from pathlib import Path

from backend.mail.messages import OutgoingEmail, build_otp_email, mask_address

log = logging.getLogger('backend.mail')

PROJECT_ROOT = Path(__file__).resolve().parents[2]
OUTBOX_FOLDER = 'netcommand-dev-outbox'
OUTBOX_ENVIRONMENTS = ('development', 'test')
DEV_SENDER = 'NetCommand (development) <no-reply@netcommand.invalid>'
SMTP_TIMEOUT = 20
IMPLICIT_TLS_PORT = 465

REASONS = {
    'authentication': 'the mail server refused the sender account',
    'connection': 'the mail server could not be reached',
    'tls_unavailable': 'the mail server does not offer an encrypted connection',
    'tls_failed': 'the encrypted connection to the mail server failed',
    'recipient_refused': 'the mail server refused the recipient address',
    'sender_refused': 'the mail server refused the sender address',
    'smtp_error': 'the mail server reported an error',
}


class MailError(Exception):
    """Base class. Messages never contain a password, code or server reply."""


class MailConfigurationError(MailError):
    """Email delivery is not configured, or the configuration is not allowed here."""


class MailDeliveryError(MailError):
    """The message was not sent. .reason is one of REASONS."""

    def __init__(self, reason):
        self.reason = reason if reason in REASONS else 'smtp_error'
        super().__init__(f'The email could not be sent: {REASONS[self.reason]}.')


def to_mime(outgoing, sender):
    """The message as a standard email (plain text with an HTML alternative)."""
    if not isinstance(outgoing, OutgoingEmail):
        raise TypeError('send() takes an OutgoingEmail (build it with build_otp_email).')
    msg = EmailMessage(policy=email_policy.SMTP)      # refuses line breaks in headers
    msg['Subject'] = outgoing.subject
    msg['From'] = sender
    msg['To'] = outgoing.to
    msg['Date'] = formatdate(usegmt=True)
    msg['Message-ID'] = make_msgid(domain=sender.rpartition('@')[2].strip('> ') or None)
    msg['Auto-Submitted'] = 'auto-generated'
    msg.set_content(outgoing.text)
    msg.add_alternative(outgoing.html, subtype='html')
    return msg


# ---------------------------------------------------------------- SMTP
class SmtpMailer:
    def __init__(self, smtp_settings, *, timeout=SMTP_TIMEOUT, ssl_context=None,
                 smtp_class=smtplib.SMTP, smtp_ssl_class=smtplib.SMTP_SSL):
        if smtp_settings is None:
            raise MailConfigurationError('SMTP is not configured (BACKEND_SMTP_ENABLED is '
                                         'not true).')
        self._smtp = smtp_settings
        self._timeout = timeout
        self._context = ssl_context
        self._smtp_class, self._smtp_ssl_class = smtp_class, smtp_ssl_class

    def __repr__(self):
        return f'SmtpMailer(host={self._smtp.host}, port={self._smtp.port})'

    def send(self, outgoing):
        msg = to_mime(outgoing, self._smtp.sender)
        try:
            self._deliver(msg, outgoing.to)
        except MailDeliveryError as err:
            log.warning('Email not sent: %s code to %s (%s)', outgoing.purpose,
                        mask_address(outgoing.to), err.reason)
            raise
        log.info('Email sent: %s code to %s', outgoing.purpose, mask_address(outgoing.to))

    def _deliver(self, msg, recipient):
        s = self._smtp
        context = self._context or ssl.create_default_context()
        try:
            if s.port == IMPLICIT_TLS_PORT:
                server = self._smtp_ssl_class(s.host, s.port, timeout=self._timeout,
                                              context=context)
            else:
                server = self._smtp_class(s.host, s.port, timeout=self._timeout)
            with server:
                server.set_debuglevel(0)
                if s.port != IMPLICIT_TLS_PORT:
                    server.ehlo()
                    server.starttls(context=context)     # refused -> nothing else is sent
                    server.ehlo()
                server.login(s.username, s.password.reveal())
                refused = server.send_message(msg, from_addr=s.sender, to_addrs=[recipient])
                if refused:
                    raise MailDeliveryError('recipient_refused')
        except MailDeliveryError:
            raise
        except smtplib.SMTPAuthenticationError:
            raise MailDeliveryError('authentication') from None
        except smtplib.SMTPNotSupportedError:
            raise MailDeliveryError('tls_unavailable') from None
        except smtplib.SMTPRecipientsRefused:
            raise MailDeliveryError('recipient_refused') from None
        except smtplib.SMTPSenderRefused:
            raise MailDeliveryError('sender_refused') from None
        except (smtplib.SMTPConnectError, smtplib.SMTPServerDisconnected):
            raise MailDeliveryError('connection') from None
        except smtplib.SMTPException:
            raise MailDeliveryError('smtp_error') from None
        except ssl.SSLError:
            raise MailDeliveryError('tls_failed') from None
        except OSError:                                   # refused, unreachable, timed out
            raise MailDeliveryError('connection') from None


# ---------------------------------------------------------------- development outbox
def default_outbox_dir():
    return Path(tempfile.gettempdir()) / OUTBOX_FOLDER


def _inside_project(path):
    try:
        path.resolve().relative_to(PROJECT_ROOT)
        return True
    except ValueError:
        return False


class DevOutboxMailer:
    """Development only: messages are written to files instead of being sent."""

    def __init__(self, directory, environment, sender=DEV_SENDER):
        self._environment = environment
        self._check_environment()
        self.directory = Path(directory) if directory else default_outbox_dir()
        if _inside_project(self.directory):
            raise MailConfigurationError('BACKEND_MAIL_OUTBOX_DIR must be outside the '
                                         'NetCommand project folder (codes must never be '
                                         'committed).')
        self._sender = sender or DEV_SENDER

    def __repr__(self):
        return 'DevOutboxMailer(development only)'

    def _check_environment(self):
        if self._environment not in OUTBOX_ENVIRONMENTS:
            raise MailConfigurationError('The development email outbox is refused unless '
                                         'BACKEND_ENV is development or test.')

    def send(self, outgoing):
        self._check_environment()
        msg = to_mime(outgoing, self._sender)
        self.directory.mkdir(parents=True, exist_ok=True, mode=0o700)
        stamp = datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%S%fZ')
        path = self.directory / f'{stamp}-{outgoing.purpose}-{secrets.token_hex(4)}.eml'
        with open(path, 'xb') as f:
            f.write(msg.as_bytes())
        try:
            os.chmod(path, 0o600)
        except OSError:                                   # pragma: no cover (Windows)
            pass
        log.info('Email written to the development outbox: %s code to %s', outgoing.purpose,
                 mask_address(outgoing.to))

    def messages(self, to=None):
        """The stored messages, oldest first (optionally only those to one address).
        Development helper; refused in production like everything else here."""
        self._check_environment()
        if not self.directory.is_dir():
            return []
        parser = BytesParser(policy=email_policy.default)
        found = []
        for path in sorted(self.directory.glob('*.eml')):
            with open(path, 'rb') as f:
                msg = parser.parse(f)
            if to is None or str(msg['To']).lower() == to.lower():
                found.append(msg)
        return found


# ---------------------------------------------------------------- choosing and sending
def create_mailer(settings):
    backend = getattr(settings, 'mail_backend', 'none')
    if backend == 'smtp':
        return SmtpMailer(settings.smtp)
    if backend == 'outbox':
        sender = settings.smtp.sender if settings.smtp else DEV_SENDER
        return DevOutboxMailer(settings.mail_outbox_dir, settings.environment, sender=sender)
    raise MailConfigurationError('Email delivery is not configured '
                                 '(BACKEND_MAIL_BACKEND is none).')


def send_otp_email(mailer, account, purpose, code, ttl_seconds, workstation_label=None):
    """Build and send the code email for this account and purpose. The account must be
    eligible (registration: pending_verification; login: active) or nothing is sent.
    Returns nothing: the code is never handed back."""
    mailer.send(build_otp_email(account, purpose, code, ttl_seconds, workstation_label))
