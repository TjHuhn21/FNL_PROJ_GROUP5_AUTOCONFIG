"""The SSH login dialog: asked when a device has no usable saved login.

A real modal dialog (a Toplevel that belongs to the main window, centered over it, with
the keyboard grab), instead of two separate prompts. It explains WHY a login is needed,
takes the username and a masked password, and offers to save the login for later. It
never logs or shows the password.

    result = ask_device_login(parent, devices, reason='missing', replaces=())
    # None (cancelled) or {'username': ..., 'password': ..., 'save': bool}

reason:   'missing'    no saved login
          'unreadable' a saved login exists but cannot be decrypted (key changed)
          'refused'    the device refused the login that was used
replaces: devices whose EXISTING saved login would be overwritten if 'save' is chosen;
          saving over them must be confirmed.

The dialog does not save anything itself: the caller saves the login (through the
store's normal, encrypted save) only after the device accepted it.
"""
import tkinter as tk
from tkinter import messagebox, ttk

import validation
from gui import theme

TITLE = 'SSH login needed'


def _names(devices):
    return ', '.join(f"{d['name']} ({d['ip']})" for d in devices)


def explanation(devices, reason):
    """The sentence at the top of the dialog (no secrets: names and IPs only)."""
    several = len(devices) > 1
    who = _names(devices)
    if reason == 'refused':
        text = (f'{who} refused the SSH login that was used. Nothing was changed on '
                f'{"them" if several else "it"}. Enter the correct login to try again.')
    elif reason == 'unreadable':
        text = (f'The saved SSH login for {who} cannot be read (the encryption key may have '
                f'changed), so NetCommand needs the login again.')
    else:
        text = (f'NetCommand has no saved SSH login for {who}.' if not several else
                f'NetCommand has no saved SSH login for {len(devices)} devices: {who}.')
    if several:
        text += ' The login you enter is used for all of them.'
    return text


class DeviceLoginDialog(tk.Toplevel):
    def __init__(self, parent, devices, reason='missing', replaces=()):
        top = parent.winfo_toplevel()
        super().__init__(top)
        self.withdraw()                                   # placed first, then shown
        self.parent_window = top
        self.devices, self.reason = list(devices), reason
        self.replaces = list(replaces)
        self.result = None
        self.title(TITLE)
        self.configure(background=theme.SURFACE, padx=22, pady=18)
        self.resizable(False, False)
        self.transient(top)                               # stays above the main window

        self.username, self.password = tk.StringVar(), tk.StringVar()
        self.save = tk.IntVar(value=0)

        tk.Label(self, text=TITLE, font=theme.FONT_TITLE, background=theme.SURFACE,
                 foreground=theme.TEXT, anchor='w').grid(row=0, column=0, columnspan=2,
                                                          sticky='w')
        self.info = tk.Label(self, text=explanation(self.devices, reason), wraplength=400,
                             justify='left', anchor='w', background=theme.SURFACE,
                             foreground=theme.TEXT_SOFT, font=theme.FONT)
        self.info.grid(row=1, column=0, columnspan=2, sticky='w', pady=(4, 2))
        tk.Label(self, text="Enter the device's SSH login (not your NetCommand account).",
                 wraplength=400, justify='left', anchor='w', background=theme.SURFACE,
                 foreground=theme.TEXT_MUTED, font=theme.FONT_SMALL).grid(
                     row=2, column=0, columnspan=2, sticky='w', pady=(0, 12))

        tk.Label(self, text='Username', background=theme.SURFACE, foreground=theme.TEXT,
                 font=theme.FONT).grid(row=3, column=0, sticky='w', pady=4)
        self.user_entry = ttk.Entry(self, textvariable=self.username, width=32)
        self.user_entry.grid(row=3, column=1, sticky='ew', padx=(12, 0), pady=4)
        tk.Label(self, text='Password', background=theme.SURFACE, foreground=theme.TEXT,
                 font=theme.FONT).grid(row=4, column=0, sticky='w', pady=4)
        self.password_entry = ttk.Entry(self, textvariable=self.password, width=32, show='*')
        self.password_entry.grid(row=4, column=1, sticky='ew', padx=(12, 0), pady=4)

        save_text = ('Replace the saved login with this one (stored encrypted)'
                     if self.replaces else 'Save this login for future use (stored encrypted)')
        self.save_box = ttk.Checkbutton(self, text=save_text, variable=self.save,
                                        command=self._show_save_note)
        self.save_box.grid(row=5, column=0, columnspan=2, sticky='w', pady=(10, 0))
        self.save_note = tk.Label(self, text='', wraplength=400, justify='left', anchor='w',
                                  background=theme.SURFACE, foreground=theme.TEXT_MUTED,
                                  font=theme.FONT_SMALL)
        self.save_note.grid(row=6, column=0, columnspan=2, sticky='w')
        self._show_save_note()

        self.error = tk.Label(self, text='', wraplength=400, justify='left', anchor='w',
                              background=theme.SURFACE, foreground=theme.DANGER,
                              font=theme.FONT)
        self.error.grid(row=7, column=0, columnspan=2, sticky='w', pady=(8, 0))

        buttons = tk.Frame(self, background=theme.SURFACE)
        buttons.grid(row=8, column=0, columnspan=2, sticky='e', pady=(14, 0))
        self.cancel_button = ttk.Button(buttons, text='Cancel', command=self.cancel)
        self.cancel_button.pack(side='right')
        self.ok_button = ttk.Button(buttons, text='Use this login', style='Accent.TButton',
                                    command=self.ok)
        self.ok_button.pack(side='right', padx=(0, 8))
        self.grid_columnconfigure(1, weight=1)

        self.bind('<Return>', lambda e: self.ok())
        self.bind('<Escape>', lambda e: self.cancel())
        self.protocol('WM_DELETE_WINDOW', self.cancel)
        self._place()
        self.deiconify()
        try:
            self.grab_set()                               # modal: the main window waits
        except tk.TclError:
            pass                                          # not viewable yet (rare): still usable
        self.user_entry.focus_set()

    # ------------------------------------------------------------ placement
    def _place(self):
        """Centered over the main window, kept on the screen."""
        self.update_idletasks()
        top = self.parent_window
        w, h = self.winfo_reqwidth(), self.winfo_reqheight()
        if top.winfo_ismapped() and top.winfo_width() > 1:
            x = top.winfo_rootx() + (top.winfo_width() - w) // 2
            y = top.winfo_rooty() + (top.winfo_height() - h) // 3
        else:
            x = (self.winfo_screenwidth() - w) // 2
            y = (self.winfo_screenheight() - h) // 3
        x = max(0, min(x, self.winfo_screenwidth() - w))
        y = max(0, min(y, self.winfo_screenheight() - h))
        self.geometry(f'+{x}+{y}')

    def _show_save_note(self):
        if self.save.get():
            text = ('Saved only after the device accepts it, encrypted, like logins saved on '
                    'the Devices page.')
            if self.replaces:
                text += f' The saved login of {_names(self.replaces)} will be replaced.'
        else:
            text = 'Not saved: used for this Apply only.'
        self.save_note.config(text=text)

    # ------------------------------------------------------------ answers
    def ok(self):
        user, password = self.username.get().strip(), self.password.get()
        if not user or not password:
            self.error.config(text='Enter both the username and the password.')
            return
        problem = validation.check_login(user, password)       # never contains the password
        if problem:
            self.error.config(text=problem)
            return
        if self.save.get() and self.replaces:
            if not messagebox.askyesno(
                    'Replace the saved login?',
                    f'{_names(self.replaces)} already {"has" if len(self.replaces) == 1 else "have"} '
                    f'a saved login. Replace it with this one once the device accepts it?',
                    parent=self):
                return
        self.result = {'username': user, 'password': password, 'save': bool(self.save.get())}
        self._close()

    def cancel(self):
        self.result = None
        self._close()

    def _close(self):
        self.password.set('')                              # drop the dialog's copy
        try:
            self.grab_release()
        except tk.TclError:
            pass
        self.destroy()

    def show(self):
        """Wait until the dialog is closed. The answer, or None."""
        self.wait_window(self)
        return self.result


def ask_device_login(parent, devices, reason='missing', replaces=()):
    """Show the dialog and wait. None = cancelled. (Tests replace this function.)"""
    return DeviceLoginDialog(parent, devices, reason=reason, replaces=replaces).show()
