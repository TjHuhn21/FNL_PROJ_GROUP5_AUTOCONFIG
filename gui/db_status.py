"""Whether the database can be reached right now, for the whole window.

One DatabaseStatus per window (database mode only; sample mode has no database).
It is changed in two ways:
  * report(err): a screen got DatabaseUnavailable (main thread), or post(err) from any
    other thread (the background monitor);
  * a health check: store.ping() in a worker thread, every CHECK_UP_MS while connected
    and every CHECK_DOWN_MS while not, or at once with check_now() (the Retry button).

Threads never touch a widget: they put results on a queue.Queue, and the main thread
reads it with after(). Only one health check runs at a time. Everything stops when the
window is destroyed. A recovered connection never repeats a failed save by itself:
on_up() only refreshes what the screens show.
"""
import queue
import threading
import tkinter as tk

from store_errors import DATABASE_ERRORS, DatabaseError, DatabaseUnavailable

CHECK_UP_MS = 15000
CHECK_DOWN_MS = 5000
POLL_MS = 200

UNAVAILABLE_ACTION = ('The database is not available, so this cannot be done now. '
                      'Nothing was changed.\n\nNetCommand checks the connection every few '
                      'seconds; you can also click "Retry now" in the yellow bar.')


class DatabaseStatus:
    def __init__(self, root, store, on_down=None, on_up=None, log=None,
                 check_up_ms=CHECK_UP_MS, check_down_ms=CHECK_DOWN_MS, poll_ms=POLL_MS):
        self.root, self.store = root, store
        self.on_down, self.on_up, self.log = on_down, on_up, log
        self.check_up_ms, self.check_down_ms, self.poll_ms = check_up_ms, check_down_ms, poll_ms
        self.available, self.reason = True, ''
        self.checking, self.closed = False, False
        self.checks_started = 0                    # handy for tests
        self._events = events = queue.Queue()
        self._timers = {}

        def post(err, source='monitor'):
            """Thread-safe: report an error from a background thread. (A plain function
            holding only the queue, so a thread never keeps the window alive.)"""
            events.put(('error', (source, err)))
        self.post = post
        root.db_status = self                      # how report_error() finds it
        root.bind('<Destroy>', self._on_destroy, add='+')
        self._after('poll', self.poll_ms, self._poll)
        self._after('check', self.check_up_ms, self._check_tick)

    # ---------------------------------------------------------------- main thread
    def report(self, err):
        """A screen hit err. Returns True if it was a database error (handled here)."""
        if isinstance(err, DatabaseUnavailable):
            self._set_down(str(err))
            return True
        if isinstance(err, DatabaseError):         # reachable, one request failed
            self._log(f'Database error: {err}', 'error')
            return True
        return False

    def check_now(self):
        """Start one health check in the background, unless one is already running."""
        if self.closed or self.checking:
            return False
        self.checking = True
        self.checks_started += 1
        # The thread gets only ping and the queue: never self or a widget, so no Tk
        # object can be used, or cleaned up, outside the main thread.
        threading.Thread(target=_check_worker, args=(self.store.ping, self._events),
                         daemon=True).start()
        return True

    def stop(self):
        self.closed = True
        for key in list(self._timers):
            try:
                self.root.after_cancel(self._timers.pop(key))
            except (tk.TclError, KeyError):
                pass

    # ---------------------------------------------------------------- internals
    def _poll(self):
        try:
            while True:
                kind, data = self._events.get_nowait()
                if kind == 'ok':
                    self.checking = False
                    self._set_up()
                elif kind == 'failed':
                    self.checking = False
                    if isinstance(data, DatabaseError):
                        # The server answered but refused the check: say so, but it is
                        # reachable, so the screens are not blanked.
                        self._log(f'Health check: {data}', 'error')
                    else:
                        self._set_down(str(data) if isinstance(data, DatabaseUnavailable)
                                       else f'The database check failed ({type(data).__name__}).')
                else:
                    source, err = data
                    if isinstance(err, DATABASE_ERRORS):
                        self._log(f'{source}: paused, {err}', 'warn')
                        self.report(err)
                    else:
                        self._log(f'{source}: failed ({type(err).__name__}: {err})', 'error')
        except queue.Empty:
            pass
        self._after('poll', self.poll_ms, self._poll)

    def _check_tick(self):
        self.check_now()
        self._after('check', self.check_up_ms if self.available else self.check_down_ms,
                    self._check_tick)

    def _set_down(self, reason):
        was_available = self.available
        self.available, self.reason = False, reason
        if was_available:
            self._log(f'Database connection lost: {reason}', 'error')
            # check again soon, not only after the normal (longer) interval
            self._after('check', self.check_down_ms, self._check_tick)
        if self.on_down:
            self.on_down(reason)                   # also on a new reason: keeps the bar current

    def _set_up(self):
        if self.available:
            return
        self.available, self.reason = True, ''
        self._log('Database connection restored. The lists were refreshed; nothing that '
                  'failed was repeated automatically.', 'ok')
        self._after('check', self.check_up_ms, self._check_tick)
        if self.on_up:
            self.on_up()

    def _log(self, message, level):
        if self.log:
            self.log('database', message, level)

    def _after(self, key, ms, func):
        if self.closed:
            return
        old = self._timers.pop(key, None)
        try:
            if old:
                self.root.after_cancel(old)
            self._timers[key] = self.root.after(ms, func)
        except tk.TclError:                        # window already gone
            self.closed = True

    def _on_destroy(self, event):
        if event.widget is self.root:
            self.stop()


def _check_worker(ping, events):                   # worker thread: no widgets here
    try:
        ping()
        events.put(('ok', None))
    except Exception as err:                       # any failure: report it, never crash
        events.put(('failed', err))


def get_status(widget):
    """The window's DatabaseStatus, or None (sample mode, or not built yet)."""
    try:
        return getattr(widget._root(), 'db_status', None)
    except Exception:
        return None


def report_error(widget, err):
    """Pass a store error to the window's DatabaseStatus. Returns True if err is a
    database error (DatabaseUnavailable / DatabaseError), even without a status."""
    if not isinstance(err, DATABASE_ERRORS):
        return False
    status = get_status(widget)
    if status is not None:
        status.report(err)
    return True


def database_ready(widget, parent=None):
    """For actions that write: False (after telling the user) while the database is
    known to be unavailable, so nothing is attempted. True otherwise."""
    status = get_status(widget)
    if status is None or status.available:
        return True
    from tkinter import messagebox
    messagebox.showerror('Database unavailable', UNAVAILABLE_ACTION, parent=parent)
    return False
