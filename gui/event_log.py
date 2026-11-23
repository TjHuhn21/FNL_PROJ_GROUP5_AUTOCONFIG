"""The one shared way to write to the Console: log_event(category, message, level).

Every feature calls log_event (or receives it as its log= callback); nothing writes to the
Console widget directly. log_event may be called from any thread.

Levels (aliases accepted):
  info                          normal text (an action starting, a plain event)
  ok      / success / successful green, the line says SUCCESSFUL
  error   / failed / fail       red,   the line says FAILED
  warn    / warning             amber, the line says WARNING
An outcome line that does not already say its word gets it added in front, so every
outcome is labelled SUCCESSFUL, FAILED or WARNING.

The running app (main.py) calls keep_history(): from then on every line since the app
started is kept, and a Console that opens later (the first workbench, or the next one after
a sign-out and sign-in) is first given that whole history with the original times. Error
and warning dialogs are logged too (install_dialog_logging), so a failure that is only shown
in a dialog is never silent.
"""
import threading

from gui.timefmt import now_text

LEVELS = {'info': 'info', '': 'info', None: 'info',
          'ok': 'ok', 'success': 'ok', 'successful': 'ok',
          'error': 'error', 'failed': 'error', 'fail': 'error',
          'warn': 'warn', 'warning': 'warn'}
OUTCOME_WORD = {'ok': 'SUCCESSFUL', 'error': 'FAILED', 'warn': 'WARNING'}

_lock = threading.Lock()
_sinks = []                  # callables (category, message, level, when=...), e.g. Console.log
_history = []                # every line since keep_history() (the running app only)
_keeping = [False]
_recent = []                 # the last few messages (a dialog repeating one is not logged twice)


def event_word(level):
    """'SUCCESSFUL', 'FAILED', 'WARNING' (or '' for info) for a level or its alias."""
    return OUTCOME_WORD.get(LEVELS.get(str(level).lower(), 'info'), '')


def normalize(message, level='info'):
    """(message, level) with the level's canonical name and the outcome word present."""
    level = LEVELS.get(level if level is None else str(level).lower(), 'info')
    message = ' '.join(str(message or '').split()) or '(no details)'
    word = OUTCOME_WORD.get(level)
    if word and word not in message.upper().replace('FAILURE', 'FAILED'):
        message = f'{word}: {message}'
    return message, level


def log_event(category, message, level='info'):
    """Write one line to the Console (the newest open one: there is one workbench).
    Safe from any thread."""
    message, level = normalize(message, level)
    category, when = str(category or 'app'), now_text(seconds=True)
    with _lock:
        _recent.append(message)
        del _recent[:-8]
        if _keeping[0]:
            _history.append((category, message, level, when))
        sink = _sinks[-1] if _sinks else None        # the workbench's Console (newest)
    if sink is not None:
        try:
            sink(category, message, level, when=when)
        except Exception:            # a closed Console never breaks the caller
            pass


def keep_history():
    """The running app (main.py): keep every line from now on, for every later Console."""
    with _lock:
        _keeping[0] = True


def attach(sink):
    """Start sending lines to sink; it is first given the history kept so far (only when
    keep_history() was called: the running app, never tests)."""
    with _lock:
        history = list(_history)
        _sinks.append(sink)
    for category, message, level, when in history:
        sink(category, message, level, when=when)


def detach(sink):
    with _lock:
        if sink in _sinks:
            _sinks.remove(sink)


# ---------------------------------------------------------------- dialogs
_DIALOG_LEVEL = {'showerror': 'error', 'showwarning': 'warn'}


def install_dialog_logging():
    """Error and warning message boxes are also written to the Console (once per
    process; calling it again changes nothing)."""
    from tkinter import messagebox
    for name, level in _DIALOG_LEVEL.items():
        current = getattr(messagebox, name)
        if getattr(current, '_logs_to_console', False):
            continue

        def logged(title=None, message=None, _show=current, _level=level, **options):
            body = ' '.join(str(message or '').split())
            with _lock:
                already = bool(body) and any(body in m for m in _recent)
            if not already:                  # the feature itself logged it just now
                log_event('dialog', f'{title}: {body}' if title and body else
                          (title or body or ''), _level)
            return _show(title, message, **options)
        logged._logs_to_console = True
        setattr(messagebox, name, logged)
