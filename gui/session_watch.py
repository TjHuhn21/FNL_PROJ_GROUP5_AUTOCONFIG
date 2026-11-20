"""Keeps the signed-in session honest while the workbench is open.

  * Local idle limit: no key press or click for the session's idle timeout (30 minutes)
    ends the session here, as it ends on the server.
  * Absolute limit: the session's lifetime (8 hours) ends it here too.
  * Server check: after the user has been active, the session is confirmed with
    GET /auth/session at most once a minute. Revoked, expired or disabled-account
    sessions (401) end it; a changed role ends it too (sign in again for the new rights).
    An unreachable server does not end it (the next check tries again).
Only activity triggers a server check, so an idle window never keeps a session alive.
Ending a session clears the token from memory first, then calls on_end(reason).
"""
import time

from desktop_auth.api_client import ApiError, ApiUnavailable
from gui import background

CHECK_EVERY = 60          # seconds between server checks (while the user is active)
TICK_MS = 5000

ENDED_MESSAGES = {
    'idle': 'You were signed out after 30 minutes without activity.',
    'expired': 'Your session has reached its time limit. Sign in again.',
    'ended': 'Your session has ended (it was signed out elsewhere, expired, or the account '
             'was disabled). Sign in again.',
    'role_changed': 'Your account permissions have changed. Sign in again.',
}


class SignedInContext:
    """What the workbench needs for account features: the API client, the session and
    what to do on sign-out or when the session ends."""

    def __init__(self, client, session, on_sign_out, on_session_end):
        self.client, self.session = client, session
        self.on_sign_out, self.on_session_end = on_sign_out, on_session_end


class SessionWatcher:
    def __init__(self, root, client, session, on_end, clock=time.monotonic, start=True):
        self.root, self.client, self.session, self.on_end = root, client, session, on_end
        self.clock = clock
        now = clock()
        self.last_activity = self.last_check = now
        self.checking, self.ended, self.unreachable = False, False, False
        self._job = None
        for sequence in ('<KeyPress>', '<ButtonPress>'):
            root.bind_all(sequence, self._activity, add='+')
        if start:
            self._job = root.after(TICK_MS, self._scheduled_tick)

    def _activity(self, _event=None):
        self.last_activity = self.clock()

    def _scheduled_tick(self):
        self._job = None
        self.tick()
        if not self.ended:
            try:
                self._job = self.root.after(TICK_MS, self._scheduled_tick)
            except Exception:
                pass

    def tick(self):
        if self.ended:
            return
        if not self.session.active:
            self.end('ended')
            return
        now = self.clock()
        if now - self.last_activity >= self.session.idle_timeout_seconds:
            self.end('idle')
        elif now >= self.session.expires_at:
            self.end('expired')
        elif (self.last_activity > self.last_check and now - self.last_check >= CHECK_EVERY
              and not self.checking):
            self.check()

    def check(self):
        self.checking, self.last_check = True, self.clock()
        token = self.session.token()
        background.run_async(self.root, lambda: self.client.get_session(token), self._checked)

    def _checked(self, result, error):
        self.checking = False
        if self.ended:
            return
        if isinstance(error, ApiUnavailable):
            self.unreachable = True                   # try again at the next check
            return
        if isinstance(error, ApiError):
            if error.status in (401, 403):
                self.end('ended')
            return
        if error is not None:
            return
        self.unreachable = False
        if result.get('role') != self.session.role:
            self.end('role_changed')

    def end(self, reason):
        if self.ended:
            return
        self.ended = True
        self.session.clear()
        if self._job is not None:
            try:
                self.root.after_cancel(self._job)
            except Exception:
                pass
        self.on_end(reason)
