"""Request rate limiting (sliding window, in memory) for the authentication service.

Keys are built from what the client SENT (the email address as typed, normalised, and
the client IP), so unknown email addresses are limited exactly like registered ones and
the limits reveal nothing about which addresses exist.

In memory and per process: right for the single backend process NetCommand runs today.
Several backend processes would each keep their own counts (a shared store would then be
needed); the database-side limits (lockout, resend cooldown) hold regardless.
"""
import threading
import time
from collections import deque
from dataclasses import dataclass


@dataclass(frozen=True)
class Limit:
    count: int          # at most this many requests ...
    seconds: int        # ... in any window of this length

    def __post_init__(self):
        if not (isinstance(self.count, int) and self.count >= 1
                and isinstance(self.seconds, int) and self.seconds >= 1):
            raise ValueError('A limit needs a positive count and window.')


class SlidingWindowLimiter:
    """hit(key, limit) -> 0 if allowed (and counted), otherwise the whole seconds to wait
    (and nothing is counted). Thread-safe."""

    def __init__(self, clock=time.monotonic, max_keys=100000):
        self._clock = clock
        self._lock = threading.Lock()
        self._hits = {}
        self._max_keys = max_keys

    def hit(self, key, limit):
        now = self._clock()
        with self._lock:
            times = self._hits.setdefault(key, deque())
            while times and times[0] <= now - limit.seconds:
                times.popleft()
            if len(times) >= limit.count:
                return max(1, int(times[0] + limit.seconds - now + 0.999))
            times.append(now)
            if len(self._hits) > self._max_keys:
                self._prune(now)
            return 0

    def _prune(self, now, longest=24 * 3600):
        for key in [k for k, t in self._hits.items() if not t or t[-1] <= now - longest]:
            del self._hits[key]

    def reset(self):
        with self._lock:
            self._hits.clear()
