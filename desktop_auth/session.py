"""The signed-in session (token kept in memory only) and what each role may do in the GUI.

The token lives in one private attribute of one AuthSession object for as long as the
window is open. It is never written to a file, the database, the settings, the
environment or a log, and repr()/str() never show it. clear() drops it (sign-out,
expiry, or any authentication failure).

Access is the GUI's view of the role. It decides which pages and buttons are offered;
the backend API stays authoritative for everything it handles (account administration
is refused there for non-admins whatever the GUI shows). Device operations do not go
through the API yet: for those, these GUI limits are the only check (an access gate,
not a security boundary; see backend/README.md).
"""
import threading
import time

VIEW = 'view'
SCAN = 'scan'
CONFIGURE = 'configure'
EDIT_DEVICES = 'devices.edit'
RUN_REVIEW = 'findings.run'
MANAGE_ACCOUNTS = 'accounts'

_OPERATOR = frozenset({VIEW, SCAN, CONFIGURE, EDIT_DEVICES, RUN_REVIEW})
PERMISSIONS = {
    'viewer': frozenset({VIEW}),                                  # read-only
    'operator': _OPERATOR,                                        # scan, configure, devices
    'admin': _OPERATOR | {MANAGE_ACCOUNTS},                       # + account management
}
# Pages that need a permission (others need only VIEW).
# Initial Setup ('setup') talks to devices over the console and will configure them in a
# later phase, so it needs the same permission as Configure.
PAGE_PERMISSIONS = {'scan': SCAN, 'configure': CONFIGURE, 'setup': CONFIGURE,
                    'accounts': MANAGE_ACCOUNTS}
ROLE_TITLES = {'viewer': 'Viewer', 'operator': 'Operator', 'admin': 'Admin'}


class Access:
    """role: viewer / operator / admin, or demo (sample mode without sign-in: operator
    rights on in-memory data, no account management)."""

    def __init__(self, role, demo=False):
        if demo:
            self.role, self.demo, self._perms = 'demo', True, _OPERATOR
        else:
            if role not in PERMISSIONS:
                raise ValueError('Unknown role.')
            self.role, self.demo, self._perms = role, False, PERMISSIONS[role]

    def can(self, permission):
        return permission in self._perms

    def can_open(self, page_key):
        return self.can(PAGE_PERMISSIONS.get(page_key, VIEW))

    @property
    def title(self):
        return 'DEMO MODE' if self.demo else ROLE_TITLES[self.role]

    def __repr__(self):
        return f'Access({self.title})'


FULL_ACCESS = None          # build_main_window(access=None): everything (tests, legacy)


class AuthSession:
    """One signed-in session. The token is reachable only through token(), and only
    until clear()."""

    def __init__(self, token, user_id, role, email, session_id=None, idle_timeout_seconds=1800,
                 expires_in_seconds=8 * 3600, clock=time.monotonic):
        if role not in PERMISSIONS:
            raise ValueError('Unknown role.')
        self.__token = token
        self.user_id, self.role, self.email, self.session_id = user_id, role, email, session_id
        self.idle_timeout_seconds = idle_timeout_seconds
        self.expires_at = clock() + expires_in_seconds
        self._clock = clock
        self._lock = threading.Lock()
        self.access = Access(role)

    def token(self):
        """The raw token for one API call; None once the session was cleared."""
        with self._lock:
            return self.__token

    @property
    def active(self):
        return self.token() is not None

    def clear(self):
        with self._lock:
            self.__token = None

    def __repr__(self):
        state = 'active' if self.active else 'ended'
        return f'AuthSession(user_id={self.user_id}, role={self.role}, {state}, token=[hidden])'

    __str__ = __repr__

    def __reduce__(self):
        raise TypeError('A session cannot be pickled or saved.')
