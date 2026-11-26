"""NetCommand entry point.  python main.py          (sign in, then MySQL; falls back to
                                                     sample mode if the database is down)
                           python main.py --demo   (DEMO MODE: sample data, no sign-in)
                           python main.py --no-monitor  (do not ping devices in the background)
                           python main.py --mock-console  (Initial Setup page uses SIMULATED
                                                          console ports from the mock lab)

Signing in uses the NetCommand backend API (NETCOMMAND_API_URL; default
http://127.0.0.1:8000, see desktop_auth/api_client.py). Without --demo there is no way
around it: if the API cannot be reached the sign-in window says so, and nothing falls
back to demo mode. The session token is kept in memory only, for as long as the
workbench window is open."""
import sys
import threading
from tkinter import messagebox

from gui import event_log
from gui.event_log import keep_history, log_event

SIGNED_OUT, CLOSED = 'signed_out', 'closed'
LOGOUT_WAIT = 3              # seconds to wait for the server to end the session on exit


def console_backend(argv=None):
    """The Initial Setup page's ports and sessions. None (the computer's real COM ports)
    unless --mock-console asks for the mock lab's SIMULATED console ports."""
    if '--mock-console' not in (sys.argv if argv is None else argv):
        return None
    import os
    here = os.path.dirname(os.path.abspath(__file__))
    sys.path.insert(0, os.path.join(here, 'mock-lab'))
    from mocklab.console import MockConsoleBackend
    print('MOCK CONSOLE MODE: the Initial Setup page shows simulated ports only.')
    return MockConsoleBackend()


def choose_store(force_demo=False):
    """Returns (store_module, is_demo, startup_problem).

    Only here, at startup, can the app fall back to sample mode, and then startup_problem
    says why (shown in the window, so the fallback is never mistaken for the database).
    --demo: sample mode on purpose, startup_problem None. Once running with the database,
    an outage never switches to sample mode (see gui/db_status.py)."""
    if not force_demo:
        from store_errors import DATABASE_ERRORS
        try:
            import db
            db.ping()
            return db, False, None
        except Exception as err:              # our own message: never a password or key
            problem = (str(err) if isinstance(err, DATABASE_ERRORS)
                       else f'{type(err).__name__} while connecting.')
            print(f'Database not available. {problem} Starting in sample mode.')
            import db_fake
            return db_fake, True, problem
    import db_fake
    return db_fake, True, None


def fit_to_screen(root, width=1200, height=720):
    """Open the window at width x height app units, made smaller when the screen
    has less room, and centered. Tk reports the screen size in the same app units
    the window uses (with Windows scaling, a 1920x1080 screen at 150% is 1280x720),
    so the two can be compared directly."""
    screen_w, screen_h = root.winfo_screenwidth(), root.winfo_screenheight()
    w = int(min(width, screen_w * 0.92))
    h = int(min(height, screen_h * 0.85))     # leaves room for the title bar and taskbar
    x, y = int((screen_w - w) / 2), int((screen_h - h) / 3)
    root.geometry(f'{w}x{h}+{x}+{y}')
    root.minsize(min(900, w), min(560, h))


def close_sign_in_question(window):
    """(message, confirm_text, danger) asked before the sign-in window closes:
    a request still being sent, a verification code waiting, an account form being
    filled in, or else the plain "Close NetCommand?"."""
    from gui.auth_window import CODE_SCREENS
    current = getattr(window, 'current', None)
    if getattr(window, 'busy', False):
        return ('A request is still being sent to the NetCommand server (signing in, '
                'creating an account or sending a code). Close NetCommand anyway?',
                'Close anyway', True)
    if current in CODE_SCREENS:
        return ('A verification code was sent to your e-mail and has not been entered yet. '
                'If you close now you will have to start again (and wait for a new code). '
                'Close NetCommand?', 'Close anyway', True)
    if current and current.startswith('register'):
        filled = any(str(var.get()).strip() for name, var in getattr(window, 'vars', {}).items()
                     if name.startswith('reg_'))
        if filled:
            return ('The new account form is filled in but not sent. Close NetCommand and '
                    'discard it?', 'Discard and close', True)
    return 'Close NetCommand?', 'Close', False


def sign_in(client):
    """The sign-in window. Returns the AuthSession, or None if the window was closed."""
    import customtkinter as ctk
    from gui import theme
    from gui.auth_window import SignInWindow
    from gui.components.dialogs import confirm
    root = ctk.CTk()
    root.title('NetCommand - sign in')
    theme.apply(root)
    fit_to_screen(root, width=560, height=760)        # centered; the card sits in the middle
    result = {}

    def signed_in(session):
        result['session'] = session
        root.destroy()
    window = SignInWindow(root, client, signed_in, server_text=f'Server: {client.base_url}')
    window.pack(fill='both', expand=True)

    def close():
        """The X button (or Alt+F4): ask first."""
        message, button, danger = close_sign_in_question(window)
        if confirm('Close NetCommand?', message, button, parent=root, danger=danger,
                   log=('app', 'Closing the sign-in window')):
            root.destroy()
    root.protocol('WM_DELETE_WINDOW', close)
    root.mainloop()
    return result.get('session')


def end_server_session(client, session):
    """Clear the token here, then ask the server to end the session (best effort: a
    few seconds at most; the server ends it anyway when it expires)."""
    token = session.token()
    session.clear()
    if not token:
        return

    def logout():
        try:
            client.logout(token)
        except Exception:
            pass
    worker = threading.Thread(target=logout, daemon=True)
    worker.start()
    worker.join(LOGOUT_WAIT)


def window_title(demo, startup_problem, access, mock_lab=''):
    """The workbench title. mock_lab: the mock lab launcher's label (display only)."""
    return ('NetCommand' + ('  [sample mode: database unavailable at startup]'
                            if startup_problem else '  [sample mode]' if demo else '')
            + ('  [DEMO MODE]' if access is not None and access.demo else '')
            + (f'  [{mock_lab}]' if mock_lab else ''))


APPLY_POLL_MS = 200          # how often a postponed close checks whether an SSH Apply ended
GC_EVERY_MS = 5000           # the workbench collects garbage itself, on the Tk thread


def collect_on_main_thread(root, every_ms=GC_EVERY_MS):
    """Python's automatic garbage collection can run in ANY thread (an SSH worker, the
    monitor). If it frees a Tk object there (a StringVar, a font, an image left in a
    reference cycle), Tcl aborts the whole program. So while the workbench is open the
    automatic collection is off and the window collects every few seconds on its own
    (main) thread. Returns a function that turns the automatic collection back on."""
    import gc
    was_enabled = gc.isenabled()
    gc.disable()
    state = {'job': None}

    def tick():
        gc.collect()
        try:
            state['job'] = root.after(every_ms, tick)
        except Exception:
            state['job'] = None
    state['job'] = root.after(every_ms, tick)

    def restore():
        if was_enabled:
            gc.enable()
    return restore


def confirm_leaving(root, refs, verb):
    """Ask before closing or signing out (verb 'close' / 'sign out'). True = go ahead.

    Running work (a scan, a configuration Apply, a review) is named first: [Wait] or
    [Close anyway]. Then unsaved settings (the Configure form): [Discard] or [Stay].
    Otherwise the plain question: "Close NetCommand?" / "Sign out of NetCommand?".
    Every answer is written to the Console."""
    from gui import activity
    from gui.components.dialogs import confirm
    what = 'Close' if verb == 'close' else 'Sign out'
    busy = activity.running()
    if busy:
        text = ' '.join(busy) + (f'\n\n{what} now may leave the work unfinished (a device '
                                 f'half-configured, a scan or review lost).')
        if not confirm(f'{what} NetCommand?', text, f'{what} anyway', cancel_text='Wait',
                       parent=root, danger=True, log=('app', f'{what} while work is running')):
            return False
        return True
    configure = (refs or {}).get('configure')
    unsaved = getattr(configure, 'has_unsaved', lambda: False)()
    if unsaved:
        return confirm('Unsaved changes', 'You have unsaved changes in the Configure settings '
                                          '(entered but not applied). Discard them?',
                       'Discard', cancel_text='Stay', parent=root, danger=True,
                       log=('app', f'{what}: discarding the unsaved Configure settings'))
    question = 'Close NetCommand?' if verb == 'close' else 'Sign out of NetCommand?'
    setup = (refs or {}).get('setup')
    where = setup.connection_text() if setup is not None and \
        hasattr(setup, 'connection_text') else ''
    text = question + (f'\n\nThe console connection to {where} is still open; it will be '
                       f'closed.' if where else '')
    return confirm(question, text, what, parent=root, log=('app', what))


def dev_reset_locks(client):
    """TESTING MODE: when the backend's DEV_RESET_LOCKS_ON_RESTART is on, it clears every
    account's failed device logins and locks now (POST /dev/reset-locks). True if it did;
    False when testing mode is off (the endpoint is missing or refuses) or the backend is
    not reachable (the sign-in window then says so)."""
    from desktop_auth.api_client import ApiError
    reset = getattr(client, 'dev_reset_locks', None)
    if reset is None:                         # a client without it (an older or stand-in one)
        return False
    try:
        reset()
    except ApiError:
        return False
    log_event('dev', '[DEV] Lockout attempts and locks reset (testing mode).', 'warn')
    return True


def run_workbench(store, demo, startup_problem, access=None, client=None, session=None,
                  make_root=None, dev_lock_reset=False):
    """Open the workbench. Returns SIGNED_OUT (show the sign-in window again) or CLOSED.
    make_root: the window factory (tests only; default customtkinter.CTk)."""
    from gui.main_window import build_main_window, mock_lab_label
    from gui import apply_guard, restore_window
    import customtkinter as ctk
    from gui import window_state
    root = (make_root or ctk.CTk)()          # a Tk window with the dark title bar and scaling support
    root.title(window_title(demo, startup_problem, access, mock_lab_label()))
    window_state.place(root)                 # the remembered size and place, or a good first one
    window_state.remember(root)
    outcome = {'value': CLOSED, 'done': False, 'deferred': None, 'after_apply': None,
               'apply_wait': False, 'asked': False}
    account = None
    holder = {}                              # the workbench refs (once built)

    def may_leave(verb):
        """Asked once per close / sign-out (a postponed one is not asked again)."""
        if outcome['asked']:
            return True
        if not confirm_leaving(root, holder.get('refs'), verb):
            return False
        outcome['asked'] = True
        return True
    # Every normal way out of the workbench checks restore_window.block_shutdown first: while
    # a restore (safety backup, replacement or rollback verification) runs, NetCommand stays
    # open and the worker is left alone. There is deliberately no force-quit.
    # Then gui.apply_guard (phase 5.1.3, H1): while an SSH setup is being applied through the
    # console, the close or sign-out is postponed. The run is asked to stop after its current
    # step (an exchange is never cut off); its worker closes the console port and ends its
    # protection; wait_for_apply (Tk's after(), never blocking) then carries out the request.

    def apply_blocks(then, verb):
        """True while an SSH Apply runs: `then` (the close or sign-out) is carried out once
        it has stopped. The latest request wins."""
        if not apply_guard.block_shutdown(root, verb):
            return False
        outcome['after_apply'] = then
        if not outcome['apply_wait']:
            outcome['apply_wait'] = True
            root.after(APPLY_POLL_MS, wait_for_apply)
        return True

    def wait_for_apply():
        if outcome['done']:
            return
        if apply_guard.active():
            root.after(APPLY_POLL_MS, wait_for_apply)
            return
        outcome['apply_wait'] = False
        then, outcome['after_apply'] = outcome['after_apply'], None
        if then is not None:
            then()                               # checks every guard again
    if session is not None:
        from gui.session_watch import ENDED_MESSAGES, SessionWatcher, SignedInContext

        def finish(value, message=None):
            if outcome['done']:
                return
            outcome.update(value=value, done=True)
            session.clear()
            if message:
                messagebox.showinfo('Signed out', message, parent=root)
            root.destroy()

        def sign_out():
            if restore_window.block_shutdown(root):
                return
            if not outcome['after_apply'] and not may_leave('sign out'):
                return
            if apply_blocks(sign_out, 'sign out'):
                return
            log_event('app', 'Signing out...')
            end_server_session(client, session)
            log_event('app', 'Sign-out SUCCESSFUL.', 'ok')
            finish(SIGNED_OUT)

        def session_ended(reason, message=None):
            """message: the server's own text (a security lock says how long, or that only
            an administrator can unlock it); otherwise the fixed text for the reason."""
            message = message or ENDED_MESSAGES.get(reason, ENDED_MESSAGES['ended'])
            if outcome['done'] or outcome['deferred']:
                return
            log_event('app', f'Signed out by the server: {message}', 'warn')
            if restore_window.restore_activity():
                # The session is over (its token is already cleared), but a restore is
                # running: hide the workbench, let the restore finish and show its result,
                # and sign out once its window is closed.
                apply_guard.request_shutdown()       # an SSH Apply stops after its step too
                outcome['deferred'] = message
                root.withdraw()
                messagebox.showwarning('Signed out after the restore', (
                    f'{message}\n\nA restore is still running. NetCommand stays open until '
                    f'it has finished and its result can be verified. The workbench is hidden; '
                    f'NetCommand signs out when you close the Restore window.'), parent=root)
                wait_for_restore()
                return
            if apply_guard.active():
                # an SSH setup is being applied: let its current step finish, then sign out
                outcome['deferred'] = message
                ports = apply_guard.request_shutdown()
                messagebox.showwarning('Signed out after the current SSH step', (
                    f'{message}\n\n' + apply_guard.shutdown_message(ports, 'sign out')),
                    parent=root)
                wait_for_restore()
                return
            finish(SIGNED_OUT, message)

        def wait_for_restore():
            if restore_window.restore_activity() or apply_guard.active():
                root.after(500, wait_for_restore)
                return
            finish(SIGNED_OUT)

        def close_window():
            if restore_window.block_shutdown(root):
                return
            if not outcome['after_apply'] and not may_leave('close'):
                return
            if apply_blocks(close_window, 'close'):
                return
            log_event('app', 'Closing NetCommand (signing out)...')
            end_server_session(client, session)
            finish(CLOSED)

        account = SignedInContext(client, session, sign_out, session_ended)
    refs = build_main_window(root, store, demo, startup_problem=startup_problem,
                             access=access, account=account, console_backend=console_backend(),
                             dev_lock_reset=dev_lock_reset)
    holder['refs'] = refs
    # the first sign-in of this user: "Take a quick tour?" (not modal; never blocks the app)
    root.after(800, refs['guide'].maybe_welcome)
    from gui import theme as _theme
    _theme.watch_dpi(root)                   # another monitor / scaling: sizes follow
    if session is not None:
        refs['session_watcher'] = SessionWatcher(root, client, session, session_ended)
        root.protocol('WM_DELETE_WINDOW', close_window)
    else:                                                # demo / sample mode: no session

        def close_demo():
            if restore_window.block_shutdown(root):
                return
            if not outcome['after_apply'] and not may_leave('close'):
                return
            if apply_blocks(close_demo, 'close'):
                return
            root.destroy()
        root.protocol('WM_DELETE_WINDOW', close_demo)
    refs['close_window'] = root.protocol('WM_DELETE_WINDOW')     # (tests: the X button)
    if not demo:                                         # sample mode never encrypts anything
        import security
        problem = security.check_key()
        if problem:                                      # warn and keep running
            print(f'Warning: {problem}')                 # safe: the message never contains the key
            log_event('app', f'Encryption key check: {problem}', 'warn')
            root.after(200, lambda: messagebox.showwarning(
                'Encryption key problem',
                problem + '\n\nNetCommand will run, but device logins cannot be saved '
                          'or used until this is fixed. Restart after fixing it.'))
    if not demo and '--no-monitor' not in sys.argv:      # background up/down checks (real data only)
        from monitor.monitor import start_monitor
        # Recorded changes go to the console (Status events tab); failures to the database
        # status. Both callbacks are thread-safe and never touch a widget themselves.
        stop = start_monitor(store, on_change=refs['console'].status_changed,
                             on_error=refs['db_status'].post)
        log_event('monitor', 'Background status monitor started (devices are checked for '
                             'up/down).')
        root.bind('<Destroy>', lambda e: stop.set() if e.widget is root else None, add='+')
    restore_gc = collect_on_main_thread(root)
    try:
        root.mainloop()
    finally:
        restore_gc()
    restore_window.workbench_closed()
    return outcome['value']


def main():
    from gui import ui_scale
    ui_scale.enable_dpi_awareness()          # before any window: sharp text at 125 % / 150 %
    keep_history()                           # the Console shows everything since app start
    log_event('app', 'NetCommand started.')
    if '--demo' in sys.argv:                 # DEMO MODE: only ever by asking for it
        from desktop_auth.session import Access
        store, demo, startup_problem = choose_store(True)
        event_log.set_store(store)           # the in-memory store: kept for this run only
        run_workbench(store, demo, startup_problem, access=Access(None, demo=True))
        event_log.save_now()
        return
    from desktop_auth.api_client import ApiConfigError, client_from_environment
    try:
        client = client_from_environment()   # http:// (this computer) or pinned https://
    except ApiConfigError as err:            # the message names the setting, nothing secret
        print(f'NetCommand not started: {err}')
        messagebox.showerror('NetCommand', f'{err}\n\nFix the server settings in .env '
                                           f'(NETCOMMAND_API_URL, NETCOMMAND_API_CA_FILE, '
                                           f'NETCOMMAND_API_ADDRESS), or start with --demo to '
                                           f'use sample data without signing in.')
        return
    store = None
    testing_mode = dev_reset_locks(client)    # before sign-in, so a locked account can sign in
    while True:
        log_event('app', 'Waiting for sign-in...')
        session = sign_in(client)
        if session is None:                  # the sign-in window was closed
            log_event('app', 'Sign-in window closed without signing in.', 'warn')
            return
        event_log.set_user(getattr(session, 'email', None))  # lines are now this user's
        if store is None:
            log_event('app', 'Connecting to the database...')
            store, demo, startup_problem = choose_store(False)
            if startup_problem:
                log_event('app', f'Connecting to the database FAILED: {startup_problem} '
                                 f'Using sample mode.', 'error')
            event_log.set_store(store)       # the Console history is saved from now on
        try:
            ended = run_workbench(store, demo, startup_problem, access=session.access,
                                  client=client, session=session, dev_lock_reset=testing_mode)
        finally:
            event_log.set_user(None)
            event_log.save_now()             # nothing logged is lost on sign-out or close
            # The next person's Console starts fresh: this user's lines leave memory (they
            # stay saved; the Logs page shows them to whoever may see them).
            event_log.clear_history()
        if ended != SIGNED_OUT:
            return


if __name__ == '__main__':
    main()
