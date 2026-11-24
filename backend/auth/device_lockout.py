"""Security lockout for failed DEVICE logins (Scan, Configure): the one place for its limits
and its rules. Pure functions, no I/O: both repositories (MySQL and in-memory) call
decide() inside their own transaction / lock, so the rules cannot drift apart.

  A failed device login (the device rejected the username or password, or the device did
  not answer: wrong IP, off, unreachable) counts against the SIGNED-IN NetCommand user.
  * Failures count within a FAILED_WINDOW_MINUTES window that starts at the first failure;
    a successful device login sets the count back to 0.
  * The MAX_FAILED_DEVICE_LOGINS-th failure in the window locks the NetCommand account for
    LOCKOUT_MINUTES (temporary lock) and records a lockout.
  * The MAX_LOCKOUTS_BEFORE_PERMANENT-th lockout within LOCKOUT_COUNT_WINDOW_HOURS is a
    PERMANENT lock instead: only an administrator (or the server's recovery command) can
    unlock it.
  * Locking signs the account out everywhere (the service revokes its sessions) and a
    locked account cannot sign in (checked after the password, so only someone who knows
    the password learns that the account is locked).
  * An unlock clears both locks, the failure count AND the lockout count (lockouts before
    the unlock no longer count; their history is kept).
Demo mode never reports anything, so it never counts or locks.
"""
from dataclasses import dataclass
from datetime import timedelta

# ---------------------------------------------------------------- the limits (one place)
MAX_FAILED_DEVICE_LOGINS = 5
FAILED_WINDOW_MINUTES = 10
LOCKOUT_MINUTES = 15
MAX_LOCKOUTS_BEFORE_PERMANENT = 3
LOCKOUT_COUNT_WINDOW_HOURS = 24

# TESTING MODE (temporary): True = every backend start, and every start of the desktop app
# (through POST /dev/reset-locks), resets every account's failed device logins, its
# temporary and permanent locks and its lockout count. Users, devices, logs and the lockout
# history are kept. Never active with BACKEND_ENV=production. Set it to False before the
# app is finalized: attempts and locks then survive restarts and /dev/reset-locks is gone.
DEV_RESET_LOCKS_ON_RESTART = True

OUTCOMES = ('success', 'auth_failed', 'unreachable')
REASONS = {'auth_failed': 'wrong username or password',
           'unreachable': 'no answer (wrong IP, device off, or not reachable)'}
PERMANENT_STATUS = 'locked_by_security'          # how a permanent lock is reported

# Fixed messages (shown on the desktop; the server sends them).
PERMANENT_MESSAGE = ('Your account has been locked because of repeated failed device login '
                     'attempts. Only an administrator can unlock it.')


@dataclass(frozen=True)
class DeviceLockoutPolicy:
    max_failed: int = MAX_FAILED_DEVICE_LOGINS
    failed_window: timedelta = timedelta(minutes=FAILED_WINDOW_MINUTES)
    lockout: timedelta = timedelta(minutes=LOCKOUT_MINUTES)
    max_lockouts: int = MAX_LOCKOUTS_BEFORE_PERMANENT
    lockout_count_window: timedelta = timedelta(hours=LOCKOUT_COUNT_WINDOW_HOURS)


DEFAULT_DEVICE_POLICY = DeviceLockoutPolicy()


def empty_state(user_id):
    return {'user_id': user_id, 'failed_count': 0, 'first_failed_at': None,
            'locked_until': None, 'permanent_locked_at': None, 'lockouts_reset_at': None}


def is_locked(state, now):
    """None, 'temporary' or 'permanent'."""
    if not state:
        return None
    if state.get('permanent_locked_at') is not None:
        return 'permanent'
    if state.get('locked_until') is not None and state['locked_until'] > now:
        return 'temporary'
    return None


def lockouts_since(state, now, policy=DEFAULT_DEVICE_POLICY):
    """Lockouts recorded after this time count towards the permanent lock."""
    since = now - policy.lockout_count_window
    reset = (state or {}).get('lockouts_reset_at')
    return max(since, reset) if reset is not None else since


def decide(state, recent_lockouts, outcome, now, policy=DEFAULT_DEVICE_POLICY):
    """(new_state, result) for one reported device login.

    state: the user's current state (empty_state() if none); recent_lockouts: lockouts
    recorded since lockouts_since(state, now). result:
      {'event': 'reset' | 'failed' | 'temporary' | 'permanent' | 'already_locked',
       'failed_count', 'remaining', 'locked' (None/'temporary'/'permanent'),
       'locked_until', 'lockouts' (in the window, this one included), 'lockouts_left'}
    A new lockout must be recorded (with its time) by the caller when event is
    'temporary' or 'permanent'."""
    if outcome not in OUTCOMES:
        raise ValueError('outcome must be one of: ' + ', '.join(OUTCOMES))
    new = dict(state)
    locked = is_locked(state, now)
    result = {'event': None, 'failed_count': state['failed_count'], 'remaining': None,
              'locked': locked, 'locked_until': state.get('locked_until'),
              'lockouts': recent_lockouts,
              'lockouts_left': max(0, policy.max_lockouts - recent_lockouts)}
    if locked:                               # nothing changes while locked
        result['event'] = 'already_locked'
        return new, result
    if outcome == 'success':
        new.update(failed_count=0, first_failed_at=None)
        result.update(event='reset', failed_count=0, remaining=policy.max_failed)
        return new, result
    first = state.get('first_failed_at')
    if first is None or now - first > policy.failed_window:
        count, first = 1, now                 # a new window starts with this failure
    else:
        count = state['failed_count'] + 1
    if count < policy.max_failed:
        new.update(failed_count=count, first_failed_at=first)
        result.update(event='failed', failed_count=count, remaining=policy.max_failed - count)
        return new, result
    lockouts = recent_lockouts + 1           # this one
    new.update(failed_count=0, first_failed_at=None)
    if lockouts >= policy.max_lockouts:
        new.update(permanent_locked_at=now, locked_until=None)
        result.update(event='permanent', locked='permanent', locked_until=None)
    else:
        new.update(locked_until=now + policy.lockout)
        result.update(event='temporary', locked='temporary', locked_until=new['locked_until'])
    result.update(failed_count=count, remaining=0, lockouts=lockouts,
                  lockouts_left=max(0, policy.max_lockouts - lockouts))
    return new, result


def unlocked_state(state, now):
    """The state after an unlock (admin or recovery command)."""
    new = dict(state)
    new.update(failed_count=0, first_failed_at=None, locked_until=None,
               permanent_locked_at=None, lockouts_reset_at=now)
    return new


def minutes_left(locked_until, now):
    """Whole minutes left (at least 1) of a temporary lock."""
    seconds = max(0, (locked_until - now).total_seconds())
    return max(1, int(-(-seconds // 60)))


def temporary_message(lockouts_left, policy=DEFAULT_DEVICE_POLICY):
    minutes = int(policy.lockout.total_seconds() // 60)
    hours = int(policy.lockout_count_window.total_seconds() // 3600)
    left = (f'{lockouts_left} more lockout{"" if lockouts_left == 1 else "s"} will make it '
            f'permanent.' if lockouts_left > 1 else
            'One more lockout will make it permanent.')
    return (f'Your account has been locked for {minutes} minutes because of too many failed '
            f'device login attempts. Warning: after {policy.max_lockouts} lockouts in {hours} '
            f'hours, your account will be locked until an administrator unlocks it. {left}')


def sign_in_refusal(state, now, policy=DEFAULT_DEVICE_POLICY):
    """The message for a locked account that tries to sign in, or None if not locked."""
    kind = is_locked(state, now)
    if kind == 'permanent':
        return PERMANENT_MESSAGE
    if kind == 'temporary':
        n = minutes_left(state['locked_until'], now)
        return (f'Your account is locked for {n} more minute{"" if n == 1 else "s"} because of '
                f'too many failed device login attempts. Try again later.')
    return None


def dev_reset_enabled(environment):
    """Testing mode is on: the flag is True and this is not a production backend."""
    return bool(DEV_RESET_LOCKS_ON_RESTART) and environment != 'production'
