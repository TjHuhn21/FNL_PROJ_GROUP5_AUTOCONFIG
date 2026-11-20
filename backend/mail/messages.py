"""Who may receive a code, and the registration and login messages.

The two messages are deliberately different (subject, wording, what to do if it was not
you) so a login code can never be mistaken for a registration code. The code is never
put in the subject: subjects appear in notifications and on lock screens.
"""
import html
import re
from dataclasses import dataclass, field

from backend.auth.policy import OTP_DIGITS
from backend.database import auth_records as R
from backend.database.errors import InvalidValue

PRODUCT = 'NetCommand'
_CODE = re.compile(r'^[0-9]{%d}$' % OTP_DIGITS)
_CONTROL = re.compile(r'[\x00-\x1f\x7f]')
_HIDDEN = '[hidden]'

# purpose -> the account statuses that may receive that code
ELIGIBLE_STATUSES = {
    'register': ('pending_verification',),     # verifying the email of a new account
    'login': ('active',),                      # second step after a correct password
}

SUBJECTS = {
    'register': f'{PRODUCT}: verify your email address',
    'login': f'{PRODUCT}: your sign-in code',
}


class NotEligibleForCode(ValueError):
    """This account may not receive a code for this purpose. Nothing was sent. The
    message never names the account or its status."""


@dataclass(frozen=True)
class OutgoingEmail:
    """One message ready to send. repr() hides the bodies (they contain the code)."""
    to: str
    purpose: str
    subject: str
    text: str = field(repr=False)
    html: str = field(repr=False)

    def __repr__(self):
        return (f'OutgoingEmail(to={mask_address(self.to)}, purpose={self.purpose}, '
                f'body={_HIDDEN})')

    __str__ = __repr__


def mask_address(address):
    """'alice@example.com' -> 'a***@example.com', for logs."""
    if not isinstance(address, str) or '@' not in address:
        return '***'
    local, _, domain = address.rpartition('@')
    return f'{local[:1]}***@{domain}'


def check_eligibility(purpose, account):
    """The recipient address if `account` (a user row: email, status) may receive a
    code for `purpose`; NotEligibleForCode otherwise."""
    R.check_choice(purpose, R.PURPOSES, 'purpose')
    if not isinstance(account, dict) or account.get('status') not in ELIGIBLE_STATUSES[purpose]:
        raise NotEligibleForCode('This account cannot receive a code for this operation.')
    if purpose == 'login' and account.get('email_verified_at') is None:
        raise NotEligibleForCode('This account cannot receive a code for this operation.')
    return R.check_email(account.get('email'))


def _expiry_text(ttl_seconds):
    if ttl_seconds % 60 == 0:
        minutes = ttl_seconds // 60
        return f'{minutes} minute' + ('' if minutes == 1 else 's')
    return f'{ttl_seconds} seconds'


def _display_name(account):
    name = account.get('full_name')
    if isinstance(name, str):
        name = _CONTROL.sub(' ', name).strip()[:R.NAME_MAX]
    return name or 'there'


ADMIN_PURPOSES = {
    'admin_setup': 'the first NetCommand administrator account, which is being set up on the '
                   'NetCommand server',
    'admin_verify': 'your existing NetCommand administrator account',
}
ADMIN_SUBJECT = f'{PRODUCT}: confirm your administrator email address'


def build_admin_email(email, full_name, purpose, code, ttl_seconds):
    """The code email of the local administrator commands (not stored as a challenge):
    'admin_setup' (the first administrator) or 'admin_verify' (an existing administrator
    whose address was never verified)."""
    if purpose not in ADMIN_PURPOSES:
        raise InvalidValue(f'purpose must be one of: {", ".join(ADMIN_PURPOSES)}.')
    to = R.check_email(email)
    if not isinstance(code, str) or not _CODE.match(code):
        raise InvalidValue(f'The code must be exactly {OTP_DIGITS} digits.')
    R.check_seconds(ttl_seconds, R.MAX_CHALLENGE_TTL, 'ttl_seconds')
    name = _display_name({'full_name': full_name})
    intro = (f'Use this code to confirm that this email address belongs to '
             f'{ADMIN_PURPOSES[purpose]}:')
    validity = f'The code expires in {_expiry_text(ttl_seconds)} and can be used only once.'
    warning = (f'If you are not setting up or verifying a {PRODUCT} administrator account, do '
               f'not use the code: someone with access to the {PRODUCT} server entered your '
               f'address. Tell the person responsible for that server.')
    never = f'Never share this code. {PRODUCT} staff will never ask you for it.'
    text = '\n\n'.join([f'Hello {name},', intro, f'    {code}', validity, warning, never]) + '\n'
    body = ''.join(f'<p>{html.escape(p)}</p>' for p in (f'Hello {name},', intro))
    body += (f'<p style="font-size:24px;font-weight:bold;letter-spacing:4px;'
             f'font-family:monospace">{code}</p>')
    body += ''.join(f'<p>{html.escape(p)}</p>' for p in (validity, warning, never))
    return OutgoingEmail(to=to, purpose=purpose, subject=ADMIN_SUBJECT, text=text,
                         html=f'<!DOCTYPE html><html><body>{body}</body></html>')


def build_otp_email(account, purpose, code, ttl_seconds, workstation_label=None):
    """The message for this account and purpose. NotEligibleForCode / InvalidValue
    before anything is built."""
    to = check_eligibility(purpose, account)
    if not isinstance(code, str) or not _CODE.match(code):
        raise InvalidValue(f'The code must be exactly {OTP_DIGITS} digits.')
    R.check_seconds(ttl_seconds, R.MAX_CHALLENGE_TTL, 'ttl_seconds')
    label = R.check_optional_text(workstation_label, R.LABEL_MAX, 'workstation_label')
    name, expiry = _display_name(account), _expiry_text(ttl_seconds)

    if purpose == 'register':
        intro = (f'Use this code to verify the email address of your new {PRODUCT} '
                 f'account:')
        after = [f'After you verify your email address, an administrator must approve your '
                 f'account before you can sign in.',
                 f'If you did not create a {PRODUCT} account, ignore this email: nothing is '
                 f'activated without this code.']
    else:
        where = f' on workstation "{label}"' if label else ''
        intro = (f'Your {PRODUCT} email address and password were just used to sign in'
                 f'{where}. To finish signing in, enter this code:')
        after = ['If this was not you, do not enter or share the code. Someone may know '
                 f'your password: contact your {PRODUCT} administrator.']
    validity = f'The code expires in {expiry} and can be used only once.'
    never = f'Never share this code. {PRODUCT} staff will never ask you for it.'

    text = '\n\n'.join([f'Hello {name},', intro, f'    {code}', validity, *after, never]) + '\n'
    paragraphs = [f'Hello {html.escape(name)},', html.escape(intro)]
    body = ''.join(f'<p>{p}</p>' for p in paragraphs)
    body += (f'<p style="font-size:24px;font-weight:bold;letter-spacing:4px;'
             f'font-family:monospace">{code}</p>')
    body += ''.join(f'<p>{html.escape(p)}</p>' for p in [validity, *after, never])
    return OutgoingEmail(to=to, purpose=purpose, subject=SUBJECTS[purpose], text=text,
                         html=f'<!DOCTYPE html><html><body>{body}</body></html>')
