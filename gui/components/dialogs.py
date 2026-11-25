"""Dialogs: where they open, and the ONE confirmation dialog every page uses.

    place_window(win, parent)                    # a dialog: its content decides the size
    place_window(win, parent, size=(1000, 760))  # a big window: design pixels, scaled
                                                 # (gui/ui_scale.py) and clamped to the screen

    confirm('Delete device', 'Delete MOCK-R1 (127.0.0.11)? ...', 'Delete device',
            parent=self, danger=True, log=('devices', 'Delete of MOCK-R1'))

Every confirmation looks the same: the question, an optional "View commands" area, and
two buttons. The confirm button says what it does ("Sign out", "Apply to 3 devices"),
never just "OK"; Cancel is always there and Esc means Cancel. A dangerous action
(danger=True: delete, apply, reject, disable...) gets a red button and Cancel has the
focus, so an accidental Enter does nothing harmful. Dialogs are centered on the main
window and use the app's scaled fonts. log=(category, what): "<what> confirmed." or
"<what> cancelled." is written to the Console.

Tests never see a real dialog: they set a runner (set_runner) that answers instead.
"""
import tkinter as tk
from tkinter import ttk

from gui import theme, ui_scale

SCREEN_SHARE = (0.92, 0.88)          # a window never covers more of the screen than this
MESSAGE_WIDTH = 460                  # design pixels: the question wraps at this width
DETAILS_HEIGHT = 12                  # lines of the "View commands" area

_runner = None                        # tests: answers instead of a real dialog


def place_window(win, parent=None, size=None):
    """Size and center `win` (see the module notes). Returns (width, height, x, y)."""
    try:
        win.update_idletasks()
        sw, sh = win.winfo_screenwidth(), win.winfo_screenheight()
        if size:
            w, h = ui_scale.space(size[0]), ui_scale.space(size[1])
        else:
            w, h = win.winfo_reqwidth(), win.winfo_reqheight()
        w, h = min(w, int(sw * SCREEN_SHARE[0])), min(h, int(sh * SCREEN_SHARE[1]))
        owner = parent.winfo_toplevel() if parent is not None else None
        if owner is not None and owner.winfo_ismapped() and owner.winfo_width() > 1:
            cx = owner.winfo_rootx() + owner.winfo_width() // 2
            cy = owner.winfo_rooty() + owner.winfo_height() // 2
        else:
            cx, cy = sw // 2, sh // 2
        x = max(0, min(cx - w // 2, sw - w))
        y = max(0, min(cy - h // 2, sh - h))
        if size:
            win.geometry(f'{w}x{h}+{x}+{y}')
        else:                      # the content decides the size (it may grow later)
            win.geometry(f'+{x}+{y}')
        return w, h, x, y
    except tk.TclError:
        return None


# ---------------------------------------------------------------- the confirmation dialog
def set_runner(runner):
    """Tests: runner(title, message, **options) -> bool answers every confirm() and
    inform() instead of a dialog (options: confirm_text, cancel_text, danger, details,
    kind). None: real dialogs again. Returns the previous runner."""
    global _runner
    previous, _runner = _runner, runner
    return previous


class ConfirmDialog(tk.Toplevel):
    """The shared confirmation window (see the module notes). .result: True = confirmed."""

    def __init__(self, parent, title, message, confirm_text, cancel_text='Cancel',
                 danger=False, details=None, details_label='View commands'):
        super().__init__(parent)
        self.result = False
        self.title(title)
        self.configure(background=theme.BG)
        self.resizable(False, False)
        pad = ui_scale.space(16)
        body = ttk.Frame(self, padding=pad)
        body.pack(fill='both', expand=True)
        self.message = ttk.Label(body, text=message, justify='left', font=theme.FONT,
                                 wraplength=ui_scale.space(MESSAGE_WIDTH))
        self.message.pack(anchor='w')
        self.details_box = None
        if details:
            self.details_button = ttk.Button(body, text=details_label,
                                             command=self.toggle_details)
            self.details_button.pack(anchor='w', pady=(theme.PAD, 0))
            holder = ttk.Frame(body)
            self.details_box = tk.Text(holder, height=DETAILS_HEIGHT, wrap='none',
                                       font=theme.mono(theme.CODE_SIZE - 1), relief='solid',
                                       borderwidth=1, padx=6, pady=4,
                                       width=max(40, min(90, max(len(l) for l in
                                                                 details.splitlines() or [''])
                                                         + 2)))
            scroll = ttk.Scrollbar(holder, orient='vertical', command=self.details_box.yview)
            self.details_box.configure(yscrollcommand=scroll.set)
            self.details_box.insert('1.0', details)
            self.details_box.configure(state='disabled')
            self.details_box.pack(side='left', fill='both', expand=True)
            scroll.pack(side='right', fill='y')
            self.details_holder = holder
        buttons = ttk.Frame(body)
        buttons.pack(anchor='e', pady=(ui_scale.space(14), 0))
        self.cancel_button = ttk.Button(buttons, text=cancel_text, command=self.cancel)
        self.cancel_button.pack(side='right')
        self.confirm_button = ttk.Button(buttons, text=confirm_text,
                                         style='Danger.TButton' if danger else 'Accent.TButton',
                                         command=self.ok)
        self.confirm_button.pack(side='right', padx=(0, theme.PAD))
        self.danger = bool(danger)
        self.protocol('WM_DELETE_WINDOW', self.cancel)
        self.bind('<Escape>', lambda e: self.cancel())
        self.bind('<Return>', self._enter)
        place_window(self, parent)
        try:
            self.transient(parent.winfo_toplevel())
        except (tk.TclError, AttributeError):
            pass
        # Cancel has the focus on a dangerous action: Enter by accident does nothing harmful
        (self.cancel_button if danger else self.confirm_button).focus_set()

    def toggle_details(self):
        if self.details_holder.winfo_manager():
            self.details_holder.pack_forget()
            self.details_button.configure(text='View commands')
        else:
            self.details_holder.pack(fill='both', expand=True, pady=(theme.PAD, 0),
                                     before=self.confirm_button.master)
            self.details_button.configure(text='Hide commands')

    def _enter(self, _event=None):
        """Enter presses the button that has the focus (never one it does not have)."""
        focused = self.focus_get()
        if focused is self.confirm_button:
            self.ok()
        elif focused is self.cancel_button:
            self.cancel()

    def ok(self):
        self.result = True
        self.destroy()

    def cancel(self):
        self.result = False
        self.destroy()


def _log(log, answer):
    if not log:
        return
    from gui.event_log import log_event
    category, what = log
    log_event(category, f"{what} {'confirmed' if answer else 'cancelled'}.")


def confirm(title, message, confirm_text, *, parent=None, danger=False, cancel_text='Cancel',
            details=None, details_label='View commands', log=None):
    """Ask before an important action. True when the user clicked the confirm button.
    See the module notes for the look and the keys."""
    if _runner is not None:
        answer = bool(_runner(title, message, confirm_text=confirm_text,
                              cancel_text=cancel_text, danger=danger, details=details,
                              kind='confirm'))
        _log(log, answer)
        return answer
    parent = parent if parent is not None else tk._default_root
    grabbed = None
    try:
        grabbed = parent.grab_current() if parent is not None else None
    except tk.TclError:
        grabbed = None
    dialog = ConfirmDialog(parent, title, message, confirm_text, cancel_text, danger, details,
                           details_label)
    try:
        dialog.grab_set()
    except tk.TclError:
        pass
    dialog.wait_window()
    if grabbed is not None:                       # a modal dialog under this one is modal again
        try:
            grabbed.grab_set()
        except tk.TclError:
            pass
    _log(log, dialog.result)
    return dialog.result


def inform(title, message, *, parent=None, level='info'):
    """A plain notice (level 'info', 'warning' or 'error') in the system message box.
    Tests: answered by the runner like confirm()."""
    if _runner is not None:
        _runner(title, message, kind=level)
        return
    from tkinter import messagebox
    show = {'warning': messagebox.showwarning, 'error': messagebox.showerror}.get(
        level, messagebox.showinfo)
    show(title, message, parent=parent)
