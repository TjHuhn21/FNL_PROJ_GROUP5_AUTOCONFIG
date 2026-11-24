"""The one shared way to write to the Console:

    log_event(category, message, level='info', *, tags=None, device=None, user=None,
              detail=None, command=False, result=None, ip=None)

Every feature calls log_event (or receives it as its log= callback); nothing writes to the
Console widget directly. log_event may be called from any thread.

Levels (aliases accepted):
  info                          normal text (an action starting, a plain event)
  ok      / success / successful green, the line says SUCCESSFUL
  error   / failed / fail       red,   the line says FAILED
  warn    / warning             amber, the line says WARNING
An outcome line that does not already say its word gets it added in front, so every
outcome is labelled SUCCESSFUL, FAILED or WARNING.

Every line is a RECORD: time, user (the signed-in account's masked email, or "system" for
automatic work such as the monitor), category, device, message, result, tags and an optional
detail (a command's full output, a configuration's before/after) shown by double-clicking.
Tags (the Console's quick filters; a line may have several):
  successful / failed / warning   from the level
  change                          the line records something that CHANGED (tags=['change'])
  command                         a command sent to a device (command=True, see device_log)
E-mail addresses in a message are masked. Command lines and details are masked for
secrets by device_log before they get here.

Saved history: once the app has a store (set_store), every record is also saved, in the
background, to the store's append-only Console history (db: the console_log table, which
the app cannot change or delete; the Logs page shows it). Lines from before (the start,
the sign-in) are saved then too. Nothing is lost while the database is unavailable: saving
is retried. Clearing the Console never touches the saved history.

The running app (main.py) calls keep_history(): from then on every line is kept, and a
Console that opens later is first given that history with the original times. At each
sign-out main.py calls clear_history(): the next person's Console starts fresh (their own
sign-in onwards). Everyone's lines stay in the saved history (the Logs page, by role). Error and warning dialogs are logged too (install_dialog_logging).
"""
import re
import threading
from datetime import datetime

from gui.timefmt import format_time

LEVELS = {'info': 'info', '': 'info', None: 'info',
          'ok': 'ok', 'success': 'ok', 'successful': 'ok',
          'error': 'error', 'failed': 'error', 'fail': 'error',
          'warn': 'warn', 'warning': 'warn'}
OUTCOME_WORD = {'ok': 'SUCCESSFUL', 'error': 'FAILED', 'warn': 'WARNING'}

SUCCESSFUL, FAILED, WARNING, CHANGE, COMMAND = 'successful', 'failed', 'warning', 'change', \
    'command'
FILTER_TAGS = (SUCCESSFUL, FAILED, WARNING, CHANGE)
LEVEL_TAG = {'ok': SUCCESSFUL, 'error': FAILED, 'warn': WARNING}
SYSTEM = 'system'
_EMAIL = re.compile(r'(?<![\w.+*-])[\w.+-]+@[\w-]+(?:\.[\w-]+)+')

_lock = threading.Lock()
_sinks = []                  # callables (category, message, level, when=..., record=...)
_history = []                # every record since keep_history() (the running app only)
_keeping = [False]
_recent = []                 # the last few messages (a dialog repeating one is not logged twice)
_user = [None]               # the signed-in account's masked e-mail (set_user)


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


def _mask_email(email):
    from gui.auth_window import mask_email
    return mask_email(email)


def mask_emails(text):
    """Every e-mail address in text masked (mask_email); already masked ones are left."""
    return _EMAIL.sub(lambda m: _mask_email(m.group(0)), text or '')


def set_user(email):
    """The account now signed in (None: signed out). Lines are logged under its masked
    e-mail; with nobody signed in, under 'system'."""
    _user[0] = _mask_email(email) if email else None


def current_user():
    return _user[0] or SYSTEM


def make_record(category, message, level='info', *, tags=None, device=None, user=None,
                detail=None, command=False, result=None, ip=None, when=None):
    """The record of one Console line (see the module notes)."""
    if command:              # "R1 > show version": the result is shown after it, not in front
        level = LEVELS.get(level if level is None else str(level).lower(), 'info')
        message = ' '.join(str(message or '').split())
    else:
        message, level = normalize(message, level)
    message = mask_emails(message)
    all_tags = set(tags or ())
    if command:
        all_tags.add(COMMAND)
        if level in ('error', 'warn'):          # a failed or timed-out command is shown too
            all_tags.add(LEVEL_TAG[level])
    elif level in LEVEL_TAG:
        all_tags.add(LEVEL_TAG[level])
    now = datetime.now()
    return {'time': now, 'when': when or format_time(now, seconds=True),
            'user': user or current_user(), 'category': str(category or 'app'),
            'device': device or '', 'ip': ip or '', 'message': message, 'level': level,
            'result': mask_emails(result or ''), 'tags': tuple(sorted(all_tags)),
            'detail': detail or '', 'command': bool(command)}


def log_event(category, message, level='info', *, tags=None, device=None, user=None,
              detail=None, command=False, result=None, ip=None):
    """Write one line to the Console (the newest open one: there is one workbench), and
    queue it for the saved history. Safe from any thread."""
    record = make_record(category, message, level, tags=tags, device=device, user=user,
                         detail=detail, command=command, result=result, ip=ip)
    with _lock:
        _recent.append(record['message'])
        del _recent[:-8]
        if _keeping[0]:
            _history.append(record)
        sink = _sinks[-1] if _sinks else None        # the workbench's Console (newest)
    _queue_for_saving(record)
    if sink is not None:
        try:
            sink(record['category'], record['message'], record['level'], when=record['when'],
                 record=record)
        except Exception:            # a closed Console never breaks the caller
            pass
    return record


def keep_history():
    """The running app (main.py): keep every line from now on, for every later Console."""
    with _lock:
        _keeping[0] = True


def clear_history():
    """At sign-out: forget the lines kept for later Consoles, so the next person who signs
    in on this computer starts with an empty Console (plus what is logged from then on,
    such as the sign-in itself). Nothing saved is touched; lines not saved yet stay queued."""
    with _lock:
        for r in _history:
            if _store[0] is not None and not _saving['off'] and not r.get('queued'):
                r['queued'] = True
                _pending.append(r)                    # never lost by being forgotten here
        _history.clear()
        _recent.clear()


def attach(sink):
    """Start sending lines to sink; it is first given the history kept so far (only when
    keep_history() was called: the running app, never tests)."""
    with _lock:
        history = list(_history)
        _sinks.append(sink)
    for r in history:
        sink(r['category'], r['message'], r['level'], when=r['when'], record=r)


def detach(sink):
    with _lock:
        if sink in _sinks:
            _sinks.remove(sink)


# ---------------------------------------------------------------- device commands
def _from_devices(category, message, level='info', **fields):
    log_event(category, message, level, **fields)


def connect_device_log():
    """Lines from device_log (the SSH sessions) go through log_event."""
    import device_log
    device_log.set_sink(_from_devices)


connect_device_log()


# ---------------------------------------------------------------- the saved history
_store = [None]
_pending = []                # records waiting to be saved
_saving = {'off': False, 'thread': None}
_wake = threading.Event()
SAVE_EVERY = 1.0             # seconds between saves
RETRY_AFTER = 5.0            # after a failed save
MAX_PENDING = 20000          # while the database is unavailable for a long time
NO_TABLE = 1146              # MySQL: the console_log table does not exist (update not run)


def row_of(record):
    """The stored form of a record (the store's add_console_events)."""
    return {'created_at': record['time'], 'user_label': record['user'],
            'category': record['category'], 'device': record['device'] or None,
            'device_ip': record['ip'] or None, 'message': record['message'],
            'result': record['result'] or None, 'level': record['level'],
            'tags': ','.join(record['tags']), 'detail': record['detail'] or None}


def _queue_for_saving(record):
    if _store[0] is None or _saving['off']:
        return
    with _lock:
        record['queued'] = True                 # never queued a second time (set_store,
        _pending.append(record)                 # clear_history)
        del _pending[:-MAX_PENDING]
    _wake.set()


def set_store(store):
    """Save every record to this store from now on (records kept since the start too).
    A store without add_console_events (older stand-ins) saves nothing."""
    if store is None or not hasattr(store, 'add_console_events'):
        _store[0] = None
        return
    _store[0] = store
    _saving['off'] = False
    with _lock:
        unsaved = [r for r in _history if not r.get('queued')]
        for r in unsaved:
            r['queued'] = True
        _pending[:0] = unsaved
    if _saving['thread'] is None:
        t = threading.Thread(target=_save_loop, daemon=True, name='console-history')
        _saving['thread'] = t
        t.start()
    _wake.set()


def save_now():
    """Save what is waiting (the writer thread, and on shutdown). True when nothing is
    left waiting."""
    store = _store[0]
    if store is None or _saving['off']:
        return True
    with _lock:
        batch = list(_pending)
        del _pending[:]
    if not batch:
        return True
    try:
        store.add_console_events([row_of(r) for r in batch])
        return True
    except Exception as err:
        if getattr(err, 'code', None) == NO_TABLE:   # schema_update_console_log.sql not run
            _saving['off'] = True
            _tell_not_saved()
            return True
        with _lock:                                   # keep them, in order, and retry later
            _pending[:0] = batch
            del _pending[:-MAX_PENDING]
        return False


def _tell_not_saved():
    """Shown in the Console only (it is not saved: there is nowhere to save it)."""
    record = make_record('app', 'The Console history is not saved to the database: the '
                         'console_log table is missing. Run schema_update_console_log.sql '
                         'once (see the file).', 'warn', user=SYSTEM)
    with _lock:
        sink = _sinks[-1] if _sinks else None
    if sink is not None:
        try:
            sink(record['category'], record['message'], record['level'], when=record['when'],
                 record=record)
        except Exception:
            pass


def _save_loop():
    while True:
        _wake.wait(SAVE_EVERY)
        _wake.clear()
        if not save_now():
            _wake.wait(RETRY_AFTER)


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
