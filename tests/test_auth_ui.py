"""The redesigned sign-in window: code field, countdowns, busy state and messages.
The real desktop client talks to the real backend API in-process (no network, no
database, no real email); background calls are synchronous. The server still decides
everything: these tests also check that no rule became weaker."""
import os, sys
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))
sys.path.insert(0, os.path.dirname(__file__))
import pytest

tk = pytest.importorskip('tkinter')

from auth_api_harness import PASSWORD, Backend  # noqa: E402
from gui import background, theme  # noqa: E402
from gui import auth_window  # noqa: E402
from gui.auth_window import CODE_LENGTH, RESEND_MIN_WAIT, SignInWindow  # noqa: E402
from gui_helpers import new_root  # noqa: E402


class Clock:
    def __init__(self):
        self.now = 1000.0

    def __call__(self):
        return self.now


@pytest.fixture(autouse=True)
def synchronous(monkeypatch):
    monkeypatch.setattr(background, 'run_async', background.run_now)


@pytest.fixture
def env():
    root = new_root()
    theme.apply(root)
    backend = Backend()
    signed = []
    win = SignInWindow(root, backend.client, signed.append, server_text='Server: test')
    win.pack(fill='both', expand=True)
    clock = Clock()
    win._clock = clock
    root.update()
    yield root, win, backend, signed, clock
    root.destroy()


def to_code_screen(win, backend):
    backend.user()
    win.vars['email'].set('user@example.com')
    win.vars['password'].set(PASSWORD)
    win.submit_login()
    assert win.current == 'login_code'


# ---------------------------------------------------------------- look and structure
def test_every_screen_has_a_title_and_subtitle(env):
    root, win, *_ = env
    for name in auth_window.SCREENS:
        win.show(name)
        assert win.heading.cget('text') == auth_window.TITLES[name][0]
        assert win.subtitle.cget('text')
    win.show('login')
    assert win.heading.cget('text') == 'Sign in'


def test_messages_use_coloured_banners(env):
    root, win, *_ = env
    win.say('Wrong', error=True)
    assert win.message.cget('foreground') == theme.DANGER and win.banner.winfo_manager()
    win.say('Done', kind='success')
    assert win.message.cget('foreground') == theme.SUCCESS
    win.say('')
    assert not win.banner.winfo_manager()                      # no empty banner


def test_password_fields_are_masked_and_can_be_shown(env):
    root, win, *_ = env
    secret_entries = [w for w in win.screens['login'].winfo_children()
                      if isinstance(w, tk.ttk.Entry) and w.cget('show') == '*']
    assert len(secret_entries) == 1
    toggle = [w for w in win.screens['login'].winfo_children()
              if isinstance(w, tk.ttk.Checkbutton)][0]
    toggle.invoke()
    assert secret_entries[0].cget('show') == ''
    toggle.invoke()
    assert secret_entries[0].cget('show') == '*'


# ---------------------------------------------------------------- the code field
def test_code_field_keeps_digits_only_and_at_most_six(env):
    root, win, *_ = env
    win.vars['code'].set('12 34-56789')
    assert win.vars['code'].get() == '123456'
    win.vars['reg_code'].set('abc')
    assert win.vars['reg_code'].get() == ''


def test_a_short_code_is_refused_before_it_is_sent(env):
    root, win, backend, signed, clock = env
    to_code_screen(win, backend)
    win.vars['code'].set('123')
    win.submit_login_code()
    assert win.current == 'login_code' and signed == []
    assert f'{CODE_LENGTH} digits' in win.message.cget('text')
    win.vars['code'].set(backend.mailer.last_code())             # the right code still works
    win.submit_login_code()
    assert len(signed) == 1


# ---------------------------------------------------------------- countdowns
def test_expiry_and_resend_countdowns(env):
    root, win, backend, signed, clock = env
    to_code_screen(win, backend)
    expiry = win.expiry_labels['login_code']
    resend = win.resend_buttons['login_code']
    assert expiry.cget('text') == 'The code expires in 5:00.'
    assert resend.instate(['disabled']) and resend.cget('text') == f'Send a new code (1:00)'
    clock.now += 30
    win._update_countdowns()
    assert expiry.cget('text') == 'The code expires in 4:30.'
    assert resend.cget('text') == 'Send a new code (0:30)'
    clock.now += RESEND_MIN_WAIT
    win._update_countdowns()
    assert not resend.instate(['disabled']) and resend.cget('text') == 'Send a new code'
    clock.now += 300
    win._update_countdowns()
    assert expiry.cget('text') == 'The code has expired. Send a new code.'


def test_server_refusal_drives_the_resend_countdown(env):
    """The server decides: an early resend is refused with Retry-After, shown as the wait."""
    root, win, backend, signed, clock = env
    to_code_screen(win, backend)
    win.resend_code()                                    # too early (direct call, not the button)
    assert 'Try again in' in win.message.cget('text')
    assert len(backend.mailer.sent) == 1                 # the server sent nothing
    assert 0 < win.resend_wait() <= RESEND_MIN_WAIT
    backend.clock.advance(61)
    clock.now += 61
    win._update_countdowns()
    win.resend_code()
    assert len(backend.mailer.sent) == 2 and 'new code was sent' in win.message.cget('text')
    assert win.resend_wait() == RESEND_MIN_WAIT          # a fresh cooldown after a new code


def test_countdown_timer_stops_off_the_code_screens(env):
    root, win, backend, signed, clock = env
    to_code_screen(win, backend)
    assert win._timer is not None
    win.back_to_login()
    win._tick()
    assert win._timer is None


# ---------------------------------------------------------------- busy state
def test_requests_show_progress_and_lock_the_buttons(env, monkeypatch):
    root, win, backend, signed, clock = env
    seen = {}
    real = background.run_now

    def observe(widget, fn, done):
        seen['busy'] = win.busy
        seen['locked'] = all(b.instate(['disabled']) for b in win.buttons)
        seen['progress'] = bool(win.progress_row.winfo_manager())
        seen['text'] = win.busy_label.cget('text')
        return real(widget, fn, done)
    monkeypatch.setattr(background, 'run_async', observe)
    backend.user()
    win.vars['email'].set('user@example.com')
    win.vars['password'].set(PASSWORD)
    win.submit_login()
    assert seen == {'busy': True, 'locked': True, 'progress': True,
                    'text': 'Checking your password...'}
    assert not win.busy and not win.progress_row.winfo_manager()


def test_a_second_submit_while_busy_changes_nothing(env):
    root, win, backend, signed, clock = env
    backend.user()
    win.vars['email'].set('user@example.com')
    win.vars['password'].set(PASSWORD)
    win.busy = True                                      # a request is still running
    win.submit_login()
    assert win.vars['password'].get() == PASSWORD        # not read, not cleared
    assert backend.mailer.sent == [] and win.current == 'login'


# ---------------------------------------------------------------- registration hints
def test_password_hints_inform_but_do_not_replace_the_server_check(env):
    root, win, backend, signed, clock = env
    win.show('register')
    win.vars['reg_password'].set('short')
    assert '(5/12)' in win.password_hint.cget('text')
    win.vars['reg_confirm'].set('shorx')
    assert 'do not match' in win.password_hint.cget('text')
    for name, value in [('reg_email', 'new@example.com'), ('reg_name', 'New'),
                        ('reg_password', 'short'), ('reg_confirm', 'short')]:
        win.vars[name].set(value)
    win.submit_register()                                # the server still enforces the policy
    assert win.current == 'register' and '12 characters' in win.message.cget('text')
    assert backend.mailer.sent == []
    assert win.vars['reg_password'].get() == ''          # cleared once sent, as before


def test_successful_verification_is_shown_as_success(env):
    root, win, backend, signed, clock = env
    win.show('register')
    for name, value in [('reg_email', 'new@example.com'), ('reg_name', 'New Person'),
                        ('reg_password', PASSWORD), ('reg_confirm', PASSWORD)]:
        win.vars[name].set(value)
    win.submit_register()
    assert win.subtitle.cget('text') == 'Enter the 6-digit code sent to new@example.com.'
    win.vars['reg_code'].set(backend.mailer.last_code())
    win.submit_register_code()
    assert win.message.cget('text') == auth_window.APPROVAL_NEEDED
    assert win.message.cget('foreground') == theme.SUCCESS
