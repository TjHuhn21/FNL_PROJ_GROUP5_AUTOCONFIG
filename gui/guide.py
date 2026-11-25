"""The new-user guide: the first-run welcome tour, the ? Help menu, "Help for this page"
and "Keyboard shortcuts". All wording is in gui/guide_content.py.

    guide = Guide(root, refs, store, user_key)   # built by the main window
    guide.maybe_welcome()                        # the first sign-in: "Take a quick tour?"
    guide.start_tour() / guide.page_help() / guide.shortcuts()

Nothing here is modal: the welcome question, the tour popups and the help windows never
grab the app, so skipping or ignoring them never blocks anything. The tour highlights one
part of the workbench at a time (a coloured frame around it) with a small popup next to it
(Back / Next / Skip tour, "Step 3 of 9"); it shows only the steps for pages the user's
role can open (administrators also get the Accounts step).

"Tour completed" (finished or skipped) is saved per user in the database
(user_settings, see schema_update_user_settings.sql); without that table it is kept in
this computer's settings file (gui/window_state.py) instead, so the tour is still shown once.
"""
import os
import tkinter as tk
from tkinter import ttk

from gui import guide_content as G
from gui import theme, ui_scale, window_state
from gui.components.dialogs import place_window
from gui.event_log import log_event

TOUR_DONE = 'tour_completed'
CHECKLIST_HIDDEN = 'checklist_hidden'
TOPOLOGY_VIEWED = 'topology_viewed'
LOCAL_KEY = 'user_flags'                 # the window_state fallback: {user_key: {name: value}}
TOUR_ENV = 'NETCOMMAND_TOUR'             # 'off': never offer the tour by itself (the tests)
FRAME = 3                                # design pixels: the highlight frame's thickness
GAP = 12                                 # between the highlighted part and the popup
POPUP_WIDTH = 340                        # design pixels
FOLLOW_MS = 300                          # the popup follows the window while it moves


# ---------------------------------------------------------------- per-user flags
def get_flag(store, user_key, name):
    """True when this user's flag is set (database, else the local settings file)."""
    getter = getattr(store, 'get_user_setting', None)
    if getter is not None:
        try:
            value = getter(user_key, name)
            if value is not None:
                return value == '1'
        except Exception:                          # table missing / database down
            pass
    flags = window_state.get_setting(LOCAL_KEY, {}) or {}
    return bool((flags.get(str(user_key)) or {}).get(name))


def set_flag(store, user_key, name, on=True):
    """Save this user's flag: in the database when it can, and always locally too."""
    setter = getattr(store, 'set_user_setting', None)
    saved = False
    if setter is not None:
        try:
            setter(user_key, name, '1' if on else '0')
            saved = True
        except Exception:
            saved = False
    flags = dict(window_state.get_setting(LOCAL_KEY, {}) or {})
    mine = dict(flags.get(str(user_key)) or {})
    mine[name] = bool(on)
    flags[str(user_key)] = mine
    window_state.put_setting(LOCAL_KEY, flags)
    return saved


def steps_for(available):
    """The tour steps for the pages this user can open (available: page keys)."""
    available = set(available)
    return [s for s in G.TOUR_STEPS if s['needs'] is None or s['needs'] in available]


# ---------------------------------------------------------------- the tour
class Tour:
    """One step at a time: a highlight around the part, and a popup next to it."""

    def __init__(self, root, refs, steps, on_end=None):
        self.root, self.refs, self.steps = root, refs, list(steps)
        self.on_end = on_end or (lambda completed: None)
        self.index, self.ended, self._job, self._placed = 0, False, None, None
        self.edges = []
        for _ in range(4):
            edge = tk.Toplevel(root)
            edge.wm_overrideredirect(True)
            edge.configure(background=theme.WARNING)
            self.edges.append(edge)
        self.popup = tk.Toplevel(root)
        self.popup.wm_overrideredirect(True)
        self.popup.configure(background=theme.ACCENT)          # a 2 px dark green border
        try:
            self.popup.transient(root)
            for edge in self.edges:
                edge.transient(root)
        except tk.TclError:
            pass
        body = tk.Frame(self.popup, background=theme.CARD, padx=ui_scale.space(14),
                        pady=ui_scale.space(12))
        body.pack(fill='both', expand=True, padx=2, pady=2)
        self.counter = tk.Label(body, text='', font=theme.FONT_SMALL, background=theme.CARD,
                                foreground=theme.TEXT_MUTED, anchor='w')
        self.counter.pack(fill='x')
        self.title = tk.Label(body, text='', font=theme.FONT_BOLD, background=theme.CARD,
                              foreground=theme.ACCENT, anchor='w', justify='left')
        self.title.pack(fill='x', pady=(2, 4))
        self.text = tk.Label(body, text='', font=theme.FONT, background=theme.CARD,
                             foreground=theme.TEXT, anchor='w', justify='left',
                             wraplength=ui_scale.space(POPUP_WIDTH))
        self.text.pack(fill='x')
        buttons = tk.Frame(body, background=theme.CARD)
        buttons.pack(fill='x', pady=(ui_scale.space(12), 0))
        self.skip_btn = ttk.Button(buttons, text=G.TOUR_SKIP, command=self.skip)
        self.skip_btn.pack(side='left')
        self.next_btn = ttk.Button(buttons, text=G.TOUR_NEXT, style='Accent.TButton',
                                   command=self.next)
        self.next_btn.pack(side='right')
        self.back_btn = ttk.Button(buttons, text=G.TOUR_BACK, command=self.back)
        self.back_btn.pack(side='right', padx=(0, theme.PAD))
        for w in (self.popup, *self.edges):
            w.bind('<Escape>', lambda e: self.skip())
        self.popup.bind('<Right>', lambda e: self.next())
        self.popup.bind('<Left>', lambda e: self.back())
        log_event('guide', f'Welcome tour started ({len(self.steps)} steps).')
        self.show(0)
        self._follow()

    # ---- steps
    def show(self, index):
        if self.ended or not self.steps:
            return
        self.index = max(0, min(index, len(self.steps) - 1))
        step = self.steps[self.index]
        page = step.get('page')
        if page and page in self.refs.get('pages', ()) and 'show_page' in self.refs:
            self.refs['show_page'](page)
        if step['target'] == 'inspector' and 'set_inspector' in self.refs:
            self.refs['set_inspector'](True)
        self.counter.config(text=G.TOUR_STEP_TEXT.format(n=self.index + 1,
                                                         total=len(self.steps)))
        self.title.config(text=step['title'])
        self.text.config(text=step['text'])
        last = self.index == len(self.steps) - 1
        self.next_btn.config(text=G.TOUR_DONE if last else G.TOUR_NEXT)
        self.back_btn.state(['disabled'] if self.index == 0 else ['!disabled'])
        self._placed = None
        try:
            self.root.update_idletasks()
        except tk.TclError:
            return
        self.place()
        try:
            self.next_btn.focus_set()
        except tk.TclError:
            pass

    def next(self):
        if self.index >= len(self.steps) - 1:
            self.end(True)
        else:
            self.show(self.index + 1)

    def back(self):
        if self.index > 0:
            self.show(self.index - 1)

    def skip(self):
        self.end(False)

    def end(self, completed):
        if self.ended:
            return
        self.ended = True
        if self._job is not None:
            try:
                self.root.after_cancel(self._job)
            except tk.TclError:
                pass
        for w in (self.popup, *self.edges):
            try:
                w.destroy()
            except tk.TclError:
                pass
        log_event('guide', 'Welcome tour finished.' if completed else
                  f'Welcome tour skipped at step {self.index + 1} of {len(self.steps)}.')
        self.on_end(completed)

    # ---- where things go
    def target(self):
        """The widget the current step highlights (the page area when it is not shown)."""
        step = self.steps[self.index]
        key = step['target']
        if key == 'page':
            widget = self.refs.get(step.get('page'))
        else:
            widget = self.refs.get({'rail': 'nav', 'command': 'command',
                                    'inspector': 'inspector', 'console': 'console',
                                    'help': 'help_button'}.get(key, ''))
        try:
            if widget is not None and widget.winfo_ismapped() and widget.winfo_width() > 1:
                return widget
        except tk.TclError:
            pass
        return self.root

    def place(self):
        """Put the highlight around the target and the popup next to it (inside it for a
        big area such as a page), always within the screen."""
        if self.ended:
            return
        try:
            w = self.target()
            x, y, width, height = (w.winfo_rootx(), w.winfo_rooty(), w.winfo_width(),
                                   w.winfo_height())
            box = (x, y, width, height)
            if box == self._placed:
                return
            self._placed = box
            t = max(2, ui_scale.space(FRAME))
            for edge, geo in zip(self.edges, (
                    (width + 2 * t, t, x - t, y - t), (width + 2 * t, t, x - t, y + height),
                    (t, height, x - t, y), (t, height, x + width, y))):
                edge.wm_geometry(f'{geo[0]}x{geo[1]}+{geo[2]}+{geo[3]}')
                edge.deiconify()
                edge.lift()
            self.popup.update_idletasks()
            pw, ph = self.popup.winfo_reqwidth(), self.popup.winfo_reqheight()
            sw, sh = self.popup.winfo_screenwidth(), self.popup.winfo_screenheight()
            gap = ui_scale.space(GAP)
            root_w = max(self.root.winfo_width(), 1)
            if width > root_w * 0.5:
                px, py = x + width - pw - gap, y + gap          # inside a big area, top right
            elif x + width + gap + pw <= sw:
                px, py = x + width + gap, y                     # to the right
            elif x - gap - pw >= 0:
                px, py = x - gap - pw, y                        # to the left
            else:
                px, py = x, y + height + gap                    # below
            px = max(0, min(px, sw - pw))
            py = max(0, min(py, sh - ph))
            self.popup.wm_geometry(f'+{px}+{py}')
            self.popup.deiconify()
            self.popup.lift()
        except tk.TclError:
            pass

    def _follow(self):
        """Keep the highlight on its part when the window moves or is resized."""
        if self.ended:
            return
        self.place()
        try:
            self._job = self.root.after(FOLLOW_MS, self._follow)
        except tk.TclError:
            self._job = None


# ---------------------------------------------------------------- help windows
class HelpWindow(tk.Toplevel):
    """A short, scrollable help text (not modal). sections: [(heading, [lines])]."""

    def __init__(self, parent, title, intro, sections, size=(600, 520)):
        super().__init__(parent)
        self.title(title)
        self.configure(background=theme.BG)
        frame = ttk.Frame(self, padding=ui_scale.space(14))
        frame.pack(fill='both', expand=True)
        # the Close button first (at the bottom), so the text never pushes it out of sight
        ttk.Button(frame, text='Close', command=self.destroy).pack(side='bottom', anchor='e',
                                                                    pady=(theme.PAD, 0))
        holder = ttk.Frame(frame)
        holder.pack(fill='both', expand=True)
        self.text = tk.Text(holder, wrap='word', font=theme.FONT, relief='flat',
                            background=theme.CARD, foreground=theme.TEXT, padx=12, pady=10,
                            spacing1=2, spacing3=2)
        scroll = ttk.Scrollbar(holder, orient='vertical', command=self.text.yview)
        self.text.configure(yscrollcommand=scroll.set)
        self.text.pack(side='left', fill='both', expand=True)
        scroll.pack(side='right', fill='y')
        self.text.tag_configure('title', font=theme.FONT_TITLE, foreground=theme.ACCENT,
                                spacing3=6)
        self.text.tag_configure('heading', font=theme.FONT_BOLD, foreground=theme.ACCENT,
                                spacing1=10)
        self.text.tag_configure('key', font=theme.mono(theme.CODE_SIZE - 1, 'bold'))
        self.text.tag_configure('soft', foreground=theme.TEXT_SOFT)
        self.text.insert('end', title + '\n', ('title',))
        if intro:
            self.text.insert('end', intro + '\n', ())
        for heading, lines in sections:
            self.text.insert('end', heading + '\n', ('heading',))
            for line in lines:
                if isinstance(line, tuple):
                    self.text.insert('end', line[0], ('key',))
                    self.text.insert('end', '  ' + line[1] + '\n', ('soft',))
                else:
                    self.text.insert('end', line + '\n')
        self.text.configure(state='disabled')
        self.bind('<Escape>', lambda e: self.destroy())
        place_window(self, parent, size=size)
        try:
            self.transient(parent.winfo_toplevel())
        except tk.TclError:
            pass
        self.focus_set()


def page_help_sections(page):
    """(title, intro, sections) of "Help for this page" (None for an unknown page)."""
    info = G.PAGE_HELP.get(page)
    if not info:
        return None
    sections = [('Main steps', [f'{i}. {s}' for i, s in enumerate(info['steps'], 1)])]
    if info.get('errors'):
        sections.append(('Common problems and how to fix them',
                         [f'• {problem}: {fix}' for problem, fix in info['errors']]))
    return f"Help: {info['title']}", info['what'], sections


# ---------------------------------------------------------------- the controller
class Guide:
    def __init__(self, root, refs, store, user_key):
        self.root, self.refs, self.store = root, refs, store
        self.user_key = str(user_key or 'local')
        self.tour, self.welcome, self.help_window = None, None, None

    # ---- the welcome question and the tour
    def tour_done(self):
        return get_flag(self.store, self.user_key, TOUR_DONE)

    def maybe_welcome(self):
        """The first sign-in of this user: "Take a quick tour?" (never when it was
        completed or skipped before, nor with NETCOMMAND_TOUR=off)."""
        if os.environ.get(TOUR_ENV, '').lower() == 'off' or self.tour_done():
            return False
        self.show_welcome()
        return True

    def show_welcome(self):
        win = tk.Toplevel(self.root)
        win.title(G.WELCOME_TITLE)
        win.configure(background=theme.BG)
        win.resizable(False, False)
        body = ttk.Frame(win, padding=ui_scale.space(18))
        body.pack(fill='both', expand=True)
        ttk.Label(body, text=G.WELCOME_TITLE, style='Title.TLabel').pack(anchor='w')
        ttk.Label(body, text=G.WELCOME_TEXT, justify='left', font=theme.FONT,
                  wraplength=ui_scale.space(420)).pack(anchor='w', pady=(6, 0))
        buttons = ttk.Frame(body)
        buttons.pack(anchor='e', pady=(ui_scale.space(16), 0))
        self.welcome_skip = ttk.Button(buttons, text=G.WELCOME_SKIP,
                                       command=lambda: self._welcome_answer(False))
        self.welcome_skip.pack(side='right')
        self.welcome_start = ttk.Button(buttons, text=G.WELCOME_START, style='Accent.TButton',
                                        command=lambda: self._welcome_answer(True))
        self.welcome_start.pack(side='right', padx=(0, theme.PAD))
        win.protocol('WM_DELETE_WINDOW', lambda: self._welcome_answer(False))
        win.bind('<Escape>', lambda e: self._welcome_answer(False))
        win.bind('<Return>', lambda e: self._welcome_answer(True))
        place_window(win, self.root)
        try:
            win.transient(self.root)
        except tk.TclError:
            pass
        self.welcome_start.focus_set()
        self.welcome = win
        log_event('guide', 'Welcome: offered the quick tour.')
        return win

    def _welcome_answer(self, start):
        if self.welcome is not None:
            try:
                self.welcome.destroy()
            except tk.TclError:
                pass
            self.welcome = None
        if start:
            self.start_tour()
        else:
            log_event('guide', 'Welcome tour skipped (restart it from the ? Help button).')
            set_flag(self.store, self.user_key, TOUR_DONE)

    def start_tour(self):
        if self.tour is not None and not self.tour.ended:
            self.tour.show(0)
            return self.tour
        self.tour = Tour(self.root, self.refs, steps_for(self.refs.get('pages', ())),
                         on_end=lambda completed: set_flag(self.store, self.user_key,
                                                           TOUR_DONE))
        return self.tour

    # ---- help
    def page_help(self, page=None):
        page = page or (self.refs['current_page']() if 'current_page' in self.refs else None)
        found = page_help_sections(page)
        if found is None:
            found = ('Help', 'No help text for this page yet.', [])
        self._show_help(*found)
        log_event('guide', f"Opened the help for {G.PAGE_HELP.get(page, {}).get('title', page)}.")

    def shortcuts(self):
        self._show_help('Keyboard shortcuts', '', [('Shortcuts', list(G.SHORTCUTS))],
                        size=(520, 380))

    def _show_help(self, title, intro, sections, size=(600, 520)):
        if self.help_window is not None:
            try:
                self.help_window.destroy()
            except tk.TclError:
                pass
        self.help_window = HelpWindow(self.root, title, intro, sections, size=size)
        return self.help_window

    def menu(self, widget):
        """The ? button's menu: Restart the tour / Help for this page / Keyboard shortcuts."""
        menu = tk.Menu(self.root, tearoff=0, font=theme.FONT, background=theme.CARD,
                       foreground=theme.TEXT, activebackground=theme.ACCENT,
                       activeforeground=theme.WHITE)
        menu.add_command(label=G.HELP_MENU['page'], accelerator='F1', command=self.page_help)
        menu.add_command(label=G.HELP_MENU['shortcuts'], command=self.shortcuts)
        menu.add_separator()
        menu.add_command(label=G.HELP_MENU['tour'], command=self.start_tour)
        self.help_menu = menu
        try:
            menu.tk_popup(widget.winfo_rootx(),
                          widget.winfo_rooty() + widget.winfo_height())
        finally:
            try:
                menu.grab_release()
            except tk.TclError:
                pass
        return menu

    # ---- the Overview checklist
    def flag(self, name):
        return get_flag(self.store, self.user_key, name)

    def set(self, name, on=True):
        return set_flag(self.store, self.user_key, name, on)
