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


def sign_in(client):
    """The sign-in window. Returns the AuthSession, or None if the window was closed."""
    import customtkinter as ctk
    from gui import theme
    from gui.auth_window import SignInWindow
    root = ctk.CTk()
    root.title('NetCommand - sign in')
    theme.apply(root)
    fit_to_screen(root, width=560, height=760)        # centered; the card sits in the middle
    result = {}

    def signed_in(session):
        result['session'] = session
        root.destroy()
    SignInWindow(root, client, signed_in,
                 server_text=f'Server: {client.base_url}').pack(fill='both', expand=True)
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


def run_workbench(store, demo, startup_problem, access=None, client=None, session=None,
                  make_root=None):
    """Open the workbench. Returns SIGNED_OUT (show the sign-in window again) or CLOSED.
    make_root: the window factory (tests only; default customtkinter.CTk)."""
    from gui.main_window import build_main_window, mock_lab_label
    from gui import apply_guard, restore_window
    import customtkinter as ctk
    root = (make_root or ctk.CTk)()          # a Tk window with the dark title bar and scaling support
    root.title(window_title(demo, startup_problem, access, mock_lab_label()))
    fit_to_screen(root)
    outcome = {'value': CLOSED, 'done': False, 'deferred': None, 'after_apply': None,
               'apply_wait': False}
    account = None
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
            if restore_window.block_shutdown(root) or apply_blocks(sign_out, 'sign out'):
                return
            log_event('app', 'Signing out...')
            end_server_session(client, session)
            log_event('app', 'Sign-out SUCCESSFUL.', 'ok')
            finish(SIGNED_OUT)

        def session_ended(reason):
            message = ENDED_MESSAGES.get(reason, ENDED_MESSAGES['ended'])
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
            if restore_window.block_shutdown(root) or apply_blocks(close_window, 'close'):
                return
            log_event('app', 'Closing NetCommand (signing out)...')
            end_server_session(client, session)
            finish(CLOSED)

        account = SignedInContext(client, session, sign_out, session_ended)
    refs = build_main_window(root, store, demo, startup_problem=startup_problem,
                             access=access, account=account, console_backend=console_backend())
    if session is not None:
        refs['session_watcher'] = SessionWatcher(root, client, session, session_ended)
        root.protocol('WM_DELETE_WINDOW', close_window)
    else:                                                # demo / sample mode: no session

        def close_demo():
            if restore_window.block_shutdown(root) or apply_blocks(close_demo, 'close'):
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
    root.mainloop()
    restore_window.workbench_closed()
    return outcome['value']


def main():
    keep_history()                           # the Console shows everything since app start
    log_event('app', 'NetCommand started.')
    if '--demo' in sys.argv:                 # DEMO MODE: only ever by asking for it
        from desktop_auth.session import Access
        store, demo, startup_problem = choose_store(True)
        run_workbench(store, demo, startup_problem, access=Access(None, demo=True))
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
    while True:
        log_event('app', 'Waiting for sign-in...')
        session = sign_in(client)
        if session is None:                  # the sign-in window was closed
            log_event('app', 'Sign-in window closed without signing in.', 'warn')
            return
        if store is None:
            log_event('app', 'Connecting to the database...')
            store, demo, startup_problem = choose_store(False)
            if startup_problem:
                log_event('app', f'Connecting to the database FAILED: {startup_problem} '
                                 f'Using sample mode.', 'error')
        if run_workbench(store, demo, startup_problem, access=session.access, client=client,
                         session=session) != SIGNED_OUT:
            return


if __name__ == '__main__':
    main()
