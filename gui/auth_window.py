"""The sign-in window: sign in, sign-in code, create an account, verify the account.

Screens (one shown at a time, on a centered card):
  login            email + password            -> POST /auth/login
  login_code       the emailed sign-in code    -> POST /auth/login/verify (the session)
  register         email, full name, password twice  -> POST /auth/register
  register_code    the emailed verification code     -> POST /auth/register/verify
  register_resend  email (verify an account created earlier) -> POST /auth/register/resend

Everything is decided by the server; this window only collects input and shows the
server's fixed messages. Passwords and codes are cleared from the fields as soon as they
were sent, never logged, and never shown in a message. The session token goes straight
into an AuthSession (memory only) handed to on_signed_in.

Usability, without changing any rule:
  * a progress bar and locked buttons while a request runs; a second click or Enter is
    ignored (checked BEFORE any field is read or cleared);
  * the code field takes digits only, at most CODE_LENGTH;
  * a countdown to the code's expiry (the server's expires_in_seconds);
  * "Send a new code" is unavailable for RESEND_MIN_WAIT seconds after a code was sent,
    or for the server's Retry-After when it refused a resend. This is display only: the
    server enforces the real cooldown and refuses early resends itself;
  * the password hints under the registration form only inform: the server checks the
    password policy and its message is shown as it is.
"""
import time
import tkinter as tk
from tkinter import ttk

from desktop_auth.api_client import ApiError
from desktop_auth.session import AuthSession
from gui import background, theme
from gui.event_log import log_event

APPROVAL_NEEDED = ('Email address verified. An administrator must approve your account '
                   'before you can sign in.')
GENERIC_FAILURE = 'Something went wrong. Try again.'
SCREENS = ('login', 'login_code', 'register', 'register_code', 'register_resend')
CODE_SCREENS = ('login_code', 'register_code')
CODE_LENGTH = 6
RESEND_MIN_WAIT = 60        # the server's smallest resend cooldown (it can only be stricter)
PASSWORD_HINT_LENGTH = 12   # the default minimum; a stricter server policy explains itself
SECRET_FIELDS = ('password', 'code', 'reg_password', 'reg_confirm', 'reg_code')

TITLES = {
    'login': ('Sign in', 'Use your NetCommand account.'),
    'login_code': ('Enter your sign-in code', 'A 6-digit code was sent to {email}.'),
    'register': ('Create an account', 'After you verify your email address, an administrator '
                                      'approves the account.'),
    'register_code': ('Verify your email address', 'Enter the 6-digit code sent to {email}.'),
    'register_resend': ('Verify an account', 'Created an account earlier? Get a new '
                                             'verification code for it.'),
}
BANNER = {'error': (theme.DANGER_SOFT, theme.DANGER), 'success': (theme.SUCCESS_SOFT, theme.SUCCESS),
          'info': (theme.ACCENT_SOFT, theme.TEXT)}


MASK = '*****'              # always 5, so the masked text does not reveal the name's length
NO_EMAIL_TEXT = 'your email'


def mask_email(email):
    """The email address as shown on screen: the name before the @ is partly hidden
    (first 2 + ***** + last 2; names of 4 characters or fewer: first 1 + *****), the
    domain is kept. Display only: requests always use the real address.
    Empty or no '@' -> 'your email'."""
    local, at, domain = (email or '').strip().rpartition('@')
    if not at or not local or not domain:
        return NO_EMAIL_TEXT
    if len(local) <= 4:
        return f'{local[0]}{MASK}@{domain}'
    return f'{local[:2]}{MASK}{local[-2:]}@{domain}'


def mmss(seconds):
    seconds = max(0, int(round(seconds)))
    return f'{seconds // 60}:{seconds % 60:02d}'


class SignInWindow(ttk.Frame):
    def __init__(self, parent, client, on_signed_in, server_text=''):
        self._styles(parent)
        super().__init__(parent, padding=24, style='Auth.TFrame')
        self.client, self.on_signed_in = client, on_signed_in
        self.challenge, self.pending_email, self.busy = None, '', False
        self._clock = time.monotonic          # tests may replace it
        self._expires_at = self._resend_at = None
        self._timer = None
        self.vars = {name: tk.StringVar() for name in (
            'email', 'password', 'code', 'reg_email', 'reg_name', 'reg_password',
            'reg_confirm', 'reg_code', 'resend_email')}
        for name in ('code', 'reg_code'):
            self.vars[name].trace_add('write', lambda *a, n=name: self._digits_only(n))

        card = tk.Frame(self, background=theme.CARD, highlightthickness=1,
                        highlightbackground=theme.BORDER, padx=32, pady=26)
        card.pack(expand=True)
        self.card = card
        brand = tk.Frame(card, background=theme.CARD)
        brand.pack(fill='x', pady=(0, 18))
        tk.Label(brand, text='NC', font=theme.mono(11, 'bold'), background=theme.RAIL_BG,
                 foreground=theme.WHITE, width=4, pady=6).pack(side='left')
        names = tk.Frame(brand, background=theme.CARD)
        names.pack(side='left', padx=(10, 0))
        tk.Label(names, text='NetCommand', font=theme.FONT_BRAND, background=theme.CARD,
                 foreground=theme.TEXT).pack(anchor='w')
        tk.Label(names, text='network administration workbench', font=theme.mono(8),
                 background=theme.CARD, foreground=theme.TEXT_MUTED).pack(anchor='w')

        self.heading = tk.Label(card, text='', font=theme.FONT_TITLE, background=theme.CARD,
                                foreground=theme.TEXT, anchor='w')
        self.heading.pack(fill='x')
        self.subtitle = tk.Label(card, text='', font=theme.FONT, background=theme.CARD,
                                 foreground=theme.TEXT_SOFT, anchor='w', justify='left',
                                 wraplength=360)
        self.subtitle.pack(fill='x', pady=(2, 14))

        self.banner = tk.Frame(card, background=theme.ACCENT_SOFT)
        self.message = tk.Label(self.banner, text='', wraplength=350, justify='left', anchor='w',
                                font=theme.FONT, background=theme.ACCENT_SOFT,
                                foreground=theme.TEXT, padx=10, pady=7)
        self.message.pack(fill='x')

        self.body = tk.Frame(card, background=theme.CARD)
        self.body.pack(fill='both', expand=True)

        self.progress_row = tk.Frame(card, background=theme.CARD)
        self.progress = ttk.Progressbar(self.progress_row, mode='indeterminate', length=360)
        self.progress.pack(fill='x')
        self.busy_label = tk.Label(self.progress_row, text='', font=theme.FONT_SMALL,
                                   background=theme.CARD, foreground=theme.TEXT_MUTED,
                                   anchor='w')
        self.busy_label.pack(fill='x', pady=(2, 0))

        footer = server_text or ''
        tk.Label(card, text=footer, font=theme.mono(8), background=theme.CARD,
                 foreground=theme.TEXT_MUTED, anchor='w').pack(fill='x', side='bottom',
                                                               pady=(16, 0))
        self.buttons = []
        self.resend_buttons, self.expiry_labels, self.first_field = {}, {}, {}
        self.screens = {name: getattr(self, f'_build_{name}')() for name in SCREENS}
        self.current = None
        self.bind('<Destroy>', self._stop_timer, add='+')
        self.show('login')

    # ------------------------------------------------------------ styles and layout helpers
    @staticmethod
    def _styles(widget):
        style = ttk.Style(widget)
        style.configure('Auth.TFrame', background=theme.APP_BG)
        style.configure('Card.TCheckbutton', background=theme.CARD, foreground=theme.TEXT_SOFT)
        style.map('Card.TCheckbutton', background=[('active', theme.CARD)])
        style.configure('Link.TButton', background=theme.CARD, foreground=theme.ACCENT,
                        bordercolor=theme.CARD, lightcolor=theme.CARD,
                        darkcolor=theme.CARD, relief='flat', padding=(2, 2))
        style.map('Link.TButton', background=[('active', theme.ACCENT_SOFT)],
                  foreground=[('disabled', theme.TEXT_MUTED)])
        style.configure('Primary.TButton', padding=(10, 7))

    def _label(self, frame, text):
        tk.Label(frame, text=text, font=theme.FONT_BOLD, background=theme.CARD,
                 foreground=theme.TEXT, anchor='w').pack(fill='x', pady=(0, 3))

    def _field(self, frame, label, var, secret=False):
        self._label(frame, label)
        entry = ttk.Entry(frame, textvariable=var, width=40, show='*' if secret else '',
                          font=(theme.FONT_FAMILY, 11))
        entry.pack(fill='x', pady=(0, 10), ipady=3)
        return entry

    def _code_field(self, frame, var, label):
        self._label(frame, label)
        entry = ttk.Entry(frame, textvariable=var, width=10, justify='center',
                          font=theme.mono(18, 'bold'))
        entry.pack(anchor='w', pady=(0, 4), ipady=4)
        tk.Label(frame, text=f'{CODE_LENGTH} digits, from the email.', font=theme.FONT_SMALL,
                 background=theme.CARD, foreground=theme.TEXT_MUTED,
                 anchor='w').pack(fill='x')
        return entry

    def _show_toggle(self, frame, entries):
        shown = tk.IntVar(value=0)

        def toggle():
            for e in entries:
                e.config(show='' if shown.get() else '*')
        ttk.Checkbutton(frame, text='Show password', variable=shown, command=toggle,
                        style='Card.TCheckbutton').pack(anchor='w', pady=(0, 10))
        return shown

    def _primary(self, frame, text, command):
        b = ttk.Button(frame, text=text, command=command, style='Accent.TButton')
        b.pack(fill='x', pady=(4, 8), ipady=4)
        self.buttons.append(b)
        return b

    def _link(self, frame, text, command, side='left'):
        b = ttk.Button(frame, text=text, command=command, style='Link.TButton')
        b.pack(side=side, padx=(0, 10))
        self.buttons.append(b)
        return b

    # ------------------------------------------------------------ screens
    def _build_login(self):
        f = tk.Frame(self.body, background=theme.CARD)
        self.login_entry = self._field(f, 'Email address', self.vars['email'])
        pw = self._field(f, 'Password', self.vars['password'], secret=True)
        self._show_toggle(f, [pw])
        self.login_entry.bind('<Return>', lambda e: pw.focus_set())
        pw.bind('<Return>', lambda e: self.submit_login())
        self._primary(f, 'Sign in', self.submit_login)
        row = tk.Frame(f, background=theme.CARD)
        row.pack(fill='x')
        self._link(row, 'Create account', lambda: self.show('register', ''))
        self._link(row, 'Verify a new account', lambda: self.show('register_resend', ''),
                   side='right')
        self.first_field['login'] = self.login_entry
        return f

    def _code_screen(self, name, var, submit):
        f = tk.Frame(self.body, background=theme.CARD)
        e = self._code_field(f, var, 'Sign-in code' if name == 'login_code' else 'Verification code')
        e.bind('<Return>', lambda ev: submit())
        self.expiry_labels[name] = tk.Label(f, text='', font=theme.FONT_SMALL,
                                            background=theme.CARD, foreground=theme.TEXT_SOFT,
                                            anchor='w')
        self.expiry_labels[name].pack(fill='x', pady=(2, 10))
        self._primary(f, 'Verify', submit)
        row = tk.Frame(f, background=theme.CARD)
        row.pack(fill='x')
        self.resend_buttons[name] = self._link(row, 'Send a new code', self.resend_code)
        self._link(row, 'Back to sign in', self.back_to_login, side='right')
        self.first_field[name] = e
        return f

    def _build_login_code(self):
        return self._code_screen('login_code', self.vars['code'], self.submit_login_code)

    def _build_register_code(self):
        return self._code_screen('register_code', self.vars['reg_code'], self.submit_register_code)

    def _build_register(self):
        f = tk.Frame(self.body, background=theme.CARD)
        self.first_field['register'] = self._field(f, 'Email address', self.vars['reg_email'])
        self._field(f, 'Full name', self.vars['reg_name'])
        pw = self._field(f, 'Password', self.vars['reg_password'], True)
        confirm = self._field(f, 'Confirm password', self.vars['reg_confirm'], True)
        confirm.bind('<Return>', lambda e: self.submit_register())
        self.password_hint = tk.Label(f, text='', font=theme.FONT_SMALL, background=theme.CARD,
                                      foreground=theme.TEXT_MUTED, anchor='w', justify='left')
        self.password_hint.pack(fill='x', pady=(0, 6))
        for name in ('reg_password', 'reg_confirm'):
            self.vars[name].trace_add('write', lambda *a: self._update_password_hint())
        self._update_password_hint()
        self._show_toggle(f, [pw, confirm])
        self._primary(f, 'Create account', self.submit_register)
        row = tk.Frame(f, background=theme.CARD)
        row.pack(fill='x')
        self._link(row, 'Back to sign in', self.back_to_login)
        return f

    def _build_register_resend(self):
        f = tk.Frame(self.body, background=theme.CARD)
        e = self._field(f, 'Email address', self.vars['resend_email'])
        e.bind('<Return>', lambda ev: self.submit_register_resend())
        self._primary(f, 'Send code', self.submit_register_resend)
        row = tk.Frame(f, background=theme.CARD)
        row.pack(fill='x')
        self._link(row, 'Back to sign in', self.back_to_login)
        self.first_field['register_resend'] = e
        return f

    # ------------------------------------------------------------ state
    def show(self, name, message=None):
        for frame in self.screens.values():
            frame.pack_forget()
        self.screens[name].pack(fill='both', expand=True)
        self.current = name
        title, subtitle = TITLES[name]
        self.heading.config(text=title)
        self.subtitle.config(text=subtitle.format(email=mask_email(self.pending_email)))
        if message is not None:
            self.say(message)
        if name in CODE_SCREENS:
            self._update_countdowns()
            self._start_timer()
        field = self.first_field.get(name)
        if field is not None:
            try:
                field.focus_set()
            except tk.TclError:
                pass

    def say(self, text, error=False, kind=None):
        """Show a message in the banner: 'error', 'success' or 'info' (the default)."""
        kind = 'error' if error else (kind or 'info')
        bg, fg = BANNER[kind]
        self.banner.config(background=bg)
        self.message.config(text=text, background=bg, foreground=fg)
        self.message_kind = kind
        if text:
            if not self.banner.winfo_manager():
                self.banner.pack(fill='x', pady=(0, 12), before=self.body)
        else:
            self.banner.pack_forget()

    def back_to_login(self):
        self.challenge = None
        self._expires_at = self._resend_at = None
        for name in ('code', 'reg_code', 'password', 'reg_password', 'reg_confirm'):
            self.vars[name].set('')
        self.show('login', '')

    def _set_busy(self, busy, text=''):
        self.busy = busy
        for b in self.buttons:
            b.state(['disabled'] if busy else ['!disabled'])
        if busy:
            self.busy_label.config(text=text)
            self.progress_row.pack(fill='x', pady=(10, 0), after=self.body)
            self.progress.start(12)
        else:
            self.progress.stop()
            self.progress_row.pack_forget()
            self._update_countdowns()              # the resend cooldown may still apply

    def _call(self, fn, on_ok, busy_text='Please wait...', on_error=None):
        """Run one API call in the background; show the server's message on refusal."""
        if self.busy:
            return
        self._set_busy(True, busy_text)
        self.say(busy_text)
        step = busy_text.rstrip('.').strip()            # e.g. 'Verifying the code'
        log_event('sign-in', f'{step}...')              # never a password or a code

        def done(result, error):
            self._set_busy(False)
            if isinstance(error, ApiError):
                log_event('sign-in', f'{step}: FAILED. {error}', 'error')
                if on_error:
                    on_error(error)
                self.say(str(error), error=True)
            elif error is not None:
                log_event('sign-in', f'{step}: FAILED. {GENERIC_FAILURE}', 'error')
                self.say(GENERIC_FAILURE, error=True)
            else:
                log_event('sign-in', f'{step}: SUCCESSFUL.', 'ok')
                on_ok(result)
        background.run_async(self, fn, done)

    def _take(self, *names):
        """Read fields and clear the secret ones at once."""
        values = [self.vars[n].get() for n in names]
        for n in names:
            if n in SECRET_FIELDS:
                self.vars[n].set('')
        return values

    # ------------------------------------------------------------ input helpers
    def _digits_only(self, name):
        """The code fields keep digits only, at most CODE_LENGTH (pasting '123 456' works)."""
        var = self.vars[name]
        value = var.get()
        clean = ''.join(ch for ch in value if ch.isdigit())[:CODE_LENGTH]
        if clean != value:
            var.set(clean)

    def _update_password_hint(self):
        if not hasattr(self, 'password_hint'):
            return
        pw, confirm = self.vars['reg_password'].get(), self.vars['reg_confirm'].get()
        long_enough = len(pw) >= PASSWORD_HINT_LENGTH
        parts = [f"{'✓' if long_enough else '•'} At least {PASSWORD_HINT_LENGTH} characters "
                 f"({min(len(pw), 99)}/{PASSWORD_HINT_LENGTH})"]
        if confirm:
            parts.append('✓ The passwords match' if confirm == pw else
                         '• The passwords do not match yet')
        self.password_hint.config(text='\n'.join(parts),
                                  foreground=theme.SUCCESS if long_enough and confirm == pw
                                  else theme.TEXT_MUTED)

    # ------------------------------------------------------------ countdowns
    def _new_challenge(self, challenge):
        """A code was sent: remember the challenge, start the expiry and resend countdowns."""
        self.challenge = challenge
        now = self._clock()
        expires = challenge.get('expires_in_seconds') if isinstance(challenge, dict) else None
        self._expires_at = now + expires if isinstance(expires, int) and expires > 0 else None
        self._resend_at = now + RESEND_MIN_WAIT

    def _resend_refused(self, error):
        """The server refused a resend: wait as long as it says (Retry-After)."""
        if error.retry_after:
            self._resend_at = self._clock() + int(error.retry_after)
            self._update_countdowns()

    def resend_wait(self):
        """Seconds until 'Send a new code' is offered again (0 = now)."""
        if self._resend_at is None:
            return 0
        return max(0, self._resend_at - self._clock())

    def _update_countdowns(self):
        now = self._clock()
        for name, label in self.expiry_labels.items():
            if self._expires_at is None:
                label.config(text='', foreground=theme.TEXT_SOFT)
            elif now < self._expires_at:
                label.config(text=f'The code expires in {mmss(self._expires_at - now)}.',
                             foreground=theme.TEXT_SOFT)
            else:
                label.config(text='The code has expired. Send a new code.',
                             foreground=theme.DANGER)
        wait = self.resend_wait()
        for button in self.resend_buttons.values():
            if wait > 0:
                button.config(text=f'Send a new code ({mmss(wait)})')
                button.state(['disabled'])
            else:
                button.config(text='Send a new code')
                if not self.busy:
                    button.state(['!disabled'])

    def _start_timer(self):
        if self._timer is None:
            try:
                self._timer = self.after(1000, self._tick)
            except tk.TclError:
                self._timer = None

    def _tick(self):
        self._timer = None
        if self.current not in CODE_SCREENS:
            return
        self._update_countdowns()
        self._start_timer()

    def _stop_timer(self, event=None):
        if self._timer is not None and (event is None or event.widget is self):
            try:
                self.after_cancel(self._timer)
            except tk.TclError:
                pass
            self._timer = None

    # ------------------------------------------------------------ actions
    def submit_login(self):
        if self.busy:                              # a second click / Enter: ignored, nothing cleared
            return
        email = self.vars['email'].get().strip()
        if not email or not self.vars['password'].get():
            self.say('Enter your email address and password.', error=True)
            return
        (password,) = self._take('password')

        def ok(challenge):
            self._new_challenge(challenge)
            self.purpose, self.pending_email = 'login', email
            self.show('login_code', challenge.get('message') or '')
        self._call(lambda: self.client.login(email, password), ok, 'Checking your password...')

    def submit_login_code(self):
        if self.busy:
            return
        (code,) = self._take('code')
        if not code.strip() or not self.challenge:
            self.say('Enter the sign-in code from your email.', error=True)
            return
        if len(code.strip()) != CODE_LENGTH:
            self.say(f'The code has {CODE_LENGTH} digits. Check the email and type it again.',
                     error=True)
            return
        challenge_id, email = self.challenge['challenge_id'], self.pending_email

        def ok(data):
            session = AuthSession(token=data['token'], user_id=data['user_id'],
                                  role=data['role'], email=email,
                                  session_id=data.get('session_id'),
                                  idle_timeout_seconds=data['idle_timeout_seconds'],
                                  expires_in_seconds=data['expires_in_seconds'])
            data.clear()                                   # drop our copy of the token
            self.challenge = None
            self._expires_at = self._resend_at = None
            self.say('Signed in.', kind='success')
            self.on_signed_in(session)
        self._call(lambda: self.client.verify_login(challenge_id, code.strip()), ok,
                   'Verifying the code...')

    def submit_register(self):
        if self.busy:
            return
        email = self.vars['reg_email'].get().strip()
        name = self.vars['reg_name'].get().strip()
        if not email or not name or not self.vars['reg_password'].get():
            self.say('Fill in every field.', error=True)
            return
        password, confirm = self._take('reg_password', 'reg_confirm')
        if password != confirm:
            self.say('The two passwords are not the same.', error=True)
            return

        def ok(challenge):
            self._new_challenge(challenge)
            self.purpose, self.pending_email = 'register', email
            self.show('register_code', challenge.get('message') or '')
        self._call(lambda: self.client.register(email, name, password), ok,
                   'Creating the account...')

    def submit_register_code(self):
        if self.busy:
            return
        (code,) = self._take('reg_code')
        if not code.strip() or not self.challenge:
            self.say('Enter the verification code from your email.', error=True)
            return
        if len(code.strip()) != CODE_LENGTH:
            self.say(f'The code has {CODE_LENGTH} digits. Check the email and type it again.',
                     error=True)
            return
        challenge_id = self.challenge['challenge_id']

        def ok(_status):
            self.challenge = None
            self._expires_at = self._resend_at = None
            self.vars['email'].set(self.pending_email)
            self.show('login')
            self.say(APPROVAL_NEEDED, kind='success')
        self._call(lambda: self.client.verify_registration(challenge_id, code.strip()), ok,
                   'Verifying the code...')

    def submit_register_resend(self):
        if self.busy:
            return
        email = self.vars['resend_email'].get().strip()
        if not email:
            self.say('Enter the email address of the account.', error=True)
            return

        def ok(challenge):
            self._new_challenge(challenge)
            self.purpose, self.pending_email = 'register', email
            self.show('register_code', challenge.get('message') or '')
        self._call(lambda: self.client.resend_registration(email), ok, 'Sending a code...')

    def resend_code(self):
        """Ask the server for a new code. The server decides (it refuses early resends
        with a Retry-After, which then drives the countdown)."""
        if self.busy:
            return
        if not self.challenge:
            self.back_to_login()
            return
        if self.current == 'login_code':
            challenge_id = self.challenge['challenge_id']
            call = lambda: self.client.resend_login(challenge_id)       # noqa: E731
        else:
            email = self.pending_email
            call = lambda: self.client.resend_registration(email)       # noqa: E731

        def ok(challenge):
            self._new_challenge(challenge)
            self._update_countdowns()
            self.say('A new code was sent. Use the newest code.', kind='success')
        self._call(call, ok, 'Sending a new code...', on_error=self._resend_refused)
