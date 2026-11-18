"""NetCommand entry point.  python main.py          (MySQL, falls back to sample mode)
                           python main.py --demo   (force sample mode)
                           python main.py --no-monitor  (do not ping devices in the background)"""
import sys
from tkinter import messagebox


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


def main():
    store, demo, startup_problem = choose_store('--demo' in sys.argv)
    from gui.main_window import build_main_window
    import customtkinter as ctk
    root = ctk.CTk()                         # a Tk window with the dark title bar and scaling support
    root.title('NetCommand' + ('  [sample mode: database unavailable at startup]'
                               if startup_problem else '  [sample mode]' if demo else ''))
    fit_to_screen(root)
    refs = build_main_window(root, store, demo, startup_problem=startup_problem)
    if not demo:                                         # sample mode never encrypts anything
        import security
        problem = security.check_key()
        if problem:                                      # warn and keep running
            print(f'Warning: {problem}')                 # safe: the message never contains the key
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
        root.bind('<Destroy>', lambda e: stop.set() if e.widget is root else None, add='+')
    root.mainloop()


if __name__ == '__main__':
    main()
