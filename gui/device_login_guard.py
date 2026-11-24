"""Reporting device logins to the server's security lockout (Scan, Configure).

The server counts the failures and decides about locks (backend/auth/device_lockout.py);
this module only reports each login, turns the answer into the warning shown in the
popup and the Console, and signs the user out when the server has locked the account.

  outcome_of_scan_error(text)      the outcome a failed scan counts as (or None)
  outcome_of_apply(result)         the outcome of one device's Apply result (or None)
  DeviceLoginGuard(account)        report(widget, ip, outcome, on_done)

Nothing is counted in demo mode (sample data, no network) or without a signed-in account
(the --demo start): the guard is then disabled and reports nothing.
"""
from desktop_auth.api_client import ApiError
from gui import background
from gui.auth_window import mask_email
from gui.event_log import log_event

AUTH_FAILED, UNREACHABLE, SUCCESS = 'auth_failed', 'unreachable', 'success'
REASON = {AUTH_FAILED: 'wrong username or password',
          UNREACHABLE: 'no answer (wrong IP, device off, or not reachable)'}


def outcome_of_scan_error(text):
    """A failed scan's message (the crawler's fixed texts) -> AUTH_FAILED, UNREACHABLE or
    None (another problem, for example a refused connection: not counted)."""
    text = text or ''
    if 'rejected the username or password' in text:
        return AUTH_FAILED
    if 'no answer (the connection timed out' in text.lower():
        return UNREACHABLE
    return None


def outcome_of_apply(result):
    """One device's Apply result -> SUCCESS (the login worked), AUTH_FAILED, UNREACHABLE
    or None (not run, or another problem)."""
    from config import multi
    message = result.get('message') or ''
    if result.get('status') == multi.NOT_RUN:
        return None
    if message.startswith('Wrong username or password'):
        return AUTH_FAILED
    if message.startswith('No answer (the connection timed out'):
        return UNREACHABLE
    from config import connect
    if connect.is_type_mismatch(message):     # logged in fine; the type was wrong
        return SUCCESS
    if result.get('status') in (multi.SUCCESS, multi.PARTIAL, multi.NOT_VERIFIED) or \
            'The device rejected a command' in message:
        return SUCCESS
    return None


def warning_text(answer):
    """What a failure answer means for the user, or '' (success / unknown)."""
    if not answer:
        return ''
    if answer.get('locked'):
        return answer.get('message') or 'Your account has been locked.'
    remaining = answer.get('remaining')
    if remaining is None or answer.get('event') != 'failed':
        return ''
    if remaining == 1:
        return '1 attempt left. One more failed login will lock your account and sign you out.'
    return f'{remaining} attempts left before your account is locked.'


class DeviceLoginGuard:
    def __init__(self, account=None):
        """account: the workbench's SignedInContext (None: demo start, nothing counted)."""
        self.account = account

    @property
    def enabled(self):
        return self.account is not None

    def _who(self):
        session = getattr(self.account, 'session', None)
        return mask_email(getattr(session, 'email', '') or '')

    def report(self, widget, device_ip, outcome, on_done=None):
        """Report one device login in the background; then on_done(answer or None) on the
        window's thread. A failure is logged with the attempts left; a lock is logged and
        the user is signed out (after on_done, so a popup can still say why)."""
        on_done = on_done or (lambda answer: None)
        if not self.enabled or outcome is None:
            on_done(None)
            return
        token = self.account.session.token()
        if token is None:
            on_done(None)
            return
        client = self.account.client

        def done(answer, error):
            if error is not None:
                if isinstance(error, ApiError) and error.status == 401:
                    on_done(None)
                    self.account.on_session_end('ended')
                    return
                log_event('security', f'{device_ip}: the failed login could not be reported '
                                      f'to the server ({error}).', 'warn')
                on_done(None)
                return
            self._log(answer, device_ip, outcome)
            on_done(answer)
            if answer.get('locked'):
                log_event('security', f'{self._who()}: signed out by the server (account '
                                      f'locked). Session ended.', 'error')
                self.account.on_session_end('security_lock', answer.get('message'))
        background.run_async(widget, lambda: client.report_device_login(token, device_ip,
                                                                        outcome), done)

    def _log(self, answer, ip, outcome):
        who = self._who()
        if outcome == SUCCESS:
            return                                    # the feature logs its own success
        reason = REASON[outcome]
        event = answer.get('event')
        if event == 'failed':
            log_event('security', f'{who}: login to {ip} FAILED ({reason}). '
                                  f'{warning_text(answer)}', 'error', device=ip, ip=ip)
            if answer.get('remaining') is not None:          # "1 attempt left": a warning
                log_event('security', f'{who}: {warning_text(answer)}', 'warn', device=ip,
                          ip=ip)
        elif event == 'temporary':
            log_event('security', f"{who}: login to {ip} FAILED ({reason}). Account LOCKED "
                                  f"for {answer.get('lock_minutes', 15)} minutes (lockout "
                                  f"{answer.get('lockouts')} of {answer.get('max_lockouts', 3)} "
                                  f'in 24 hours).', 'error', tags=['change'], device=ip, ip=ip)
        elif event == 'permanent':
            log_event('security', f'{who}: login to {ip} FAILED ({reason}). Account LOCKED '
                                  f'until an administrator unlocks it.', 'error',
                      tags=['change'], device=ip, ip=ip)
