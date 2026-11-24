"""The operations console along the bottom of the workbench.

Three tabs:
  Console        timestamped events from this session, written by the app itself
                 (only real events; nothing is invented). log() may be called from
                 any thread: messages go through a queue and only the window's own
                 thread puts them on screen (Tk is not thread-safe).
                 Each line: time, user (masked e-mail or "system"), category, device,
                 message (a device command as "> show version") and result. Quick
                 filters All | Successful | Failed | Warnings | Changes (several at once,
                 with counts), plus Category, Device, User, Search and Show commands; they
                 only change what is SHOWN, never what is kept, and new lines that match
                 still appear live. Double-click a line for its full output or the
                 configuration's before/after. Everything is also saved (gui.event_log).
  Config log     the existing configuration log (store.get_logs), newest first,
                 reloaded when the tab is opened or Refresh is clicked.
  Status events  the recorded device status changes (store.get_events), newest first:
                 time, device, previous -> new status, detail. Reloaded when the tab is
                 opened, on Refresh, and after the monitor records a change.
Both stored-data tabs are read on the window's own thread. While the database is
unavailable they show that instead of their old contents (never old rows as current).

Refresh and Clear act on the tab that is shown:
  Console        Refresh shows any lines still waiting; Clear empties the console.
  Config log     Refresh reloads it; Clear only empties the VIEW (a note says so).
  Status events  Refresh reloads them; Clear only empties the VIEW.
Clearing never deletes anything from the database: the configuration log and the
status history stay stored, and Refresh (or opening the tab again) shows them again.
"""
import queue
import threading
import tkinter as tk
from tkinter import ttk

from gui import event_log, theme
from gui.db_status import report_error
from gui.timefmt import format_date_time, now_text

LEVEL_COLORS = {'info': None, 'ok': theme.SUCCESS, 'warn': theme.WARNING, 'error': theme.DANGER}
FILTER_TAGS = event_log.FILTER_TAGS
FILTER_LABELS = {'successful': 'Successful', 'failed': 'Failed', 'warning': 'Warnings',
                 'change': 'Changes'}
ALL_CATEGORIES, ALL_DEVICES, ALL_USERS = 'All', 'All devices', 'All users'
CATEGORIES = ('app', 'scan', 'ssh', 'config', 'monitor', 'security', 'findings')
# a category in the dropdown that covers several of the app's own categories
CATEGORY_GROUPS = {'config': ('config', 'configure', 'backups')}
USER_WIDTH = 22               # 'jf*****08@umak.edu.ph' / 'system'
DEVICE_WIDTH = 10
CONFIG_LOG_ROWS = 50
EVENT_ROWS = 50
CONFIG_TAB, EVENTS_TAB = 1, 2
UNAVAILABLE_TEXT = ('Database unavailable: this cannot be shown right now. It is reloaded '
                    'when the connection is back.\n')
CLEARED_TEXT = {CONFIG_TAB: 'Configuration log cleared from view (nothing was deleted). '
                            'Click Refresh to show it again.\n',
                EVENTS_TAB: 'Status events cleared from view (nothing was deleted). '
                            'Click Refresh to show them again.\n'}


class OperationsConsole(tk.Frame):
    def __init__(self, parent, store):
        super().__init__(parent, background=theme.SURFACE)
        self.store = store
        self._queue = queue.Queue()
        self.lines = []                     # (time, source, message, level): handy for tests

        self.records = []                   # every Console record since the last Clear
        self._shown = []                    # the records on screen, line by line
        self.counts = {}

        self.tabs = ttk.Notebook(self, style='Console.TNotebook')
        self.tabs.pack(fill='both', expand=True)

        page = tk.Frame(self.tabs, background=theme.SURFACE)
        self._make_filter_bar(page).pack(fill='x', pady=(2, 2))
        self.text = self._make_text(page)
        self.text.master.pack(fill='both', expand=True)
        self.text.tag_configure('command', foreground=theme.ACCENT)
        self.text.tag_configure('user', foreground=theme.TEXT_SOFT)
        self.text.tag_configure('device', foreground=theme.TEXT_SOFT)
        self.text.bind('<Double-1>', self._open_line)
        self.tabs.add(page, text='Console')
        self.config_text = self._make_text(self.tabs)
        self.tabs.add(self.config_text.master, text='Config log')
        self.events_text = self._make_text(self.tabs)
        self.tabs.add(self.events_text.master, text='Status events')
        self.tabs.bind('<<NotebookTabChanged>>', self._tab_changed)
        # Set from the monitor's thread when it recorded a change; read on this thread.
        self._events_changed = threading.Event()
        self.status_changed = self._make_status_callback(self._queue, self._events_changed)

        tools = tk.Frame(self, background=theme.SURFACE)
        tools.place(relx=1.0, x=-8, y=2, anchor='ne')          # sits on the tab row, right side
        self.clear_button = ttk.Button(tools, text='Clear', command=self.clear,
                                       style='Console.TButton')
        self.clear_button.pack(side='right')
        self.refresh_button = ttk.Button(tools, text='Refresh', command=self.refresh_current,
                                         style='Console.TButton')
        self.refresh_button.pack(side='right', padx=4)

        self._timer = self.after(150, self._drain)
        self.bind('<Destroy>', self._stop, add='+')
        event_log.attach(self.log)              # log_event(...) now writes here

    def _stop(self, event):
        if event.widget is not self:
            return
        event_log.detach(self.log)
        if self._timer:                          # window closing: stop the timer cleanly
            try:
                self.after_cancel(self._timer)
            except tk.TclError:
                pass
            self._timer = None

    def _make_text(self, parent):
        holder = tk.Frame(parent, background=theme.SURFACE)
        text = tk.Text(holder, height=6, wrap='none', font=theme.mono(theme.CONSOLE_SIZE),
                       relief='flat',
                       background=theme.CARD, foreground=theme.TEXT, padx=10, pady=6,
                       borderwidth=0, highlightthickness=0, state='disabled', cursor='arrow')
        scroll = ttk.Scrollbar(holder, orient='vertical', command=text.yview)
        text.configure(yscrollcommand=scroll.set)
        scroll.pack(side='right', fill='y')
        text.pack(side='left', fill='both', expand=True)
        text.tag_configure('time', foreground=theme.TEXT_MUTED)
        text.tag_configure('source', foreground=theme.ACCENT)
        for level, color in LEVEL_COLORS.items():
            if color:
                text.tag_configure(level, foreground=color)
        return text

    # ---------------------------------------------------------------- Console tab
    def log(self, source, message, level='info', when=None, record=None):
        """Add one line: the sink of event_log.log_event (features call log_event, not
        this). Safe from any thread. Outcome lines are labelled SUCCESSFUL / FAILED /
        WARNING (event_log.normalize). when: the original time of a replayed line;
        record: the full record (who, device, tags, detail) made by log_event."""
        if record is None:
            record = event_log.make_record(source, message, level, when=when)
        self._queue.put(record)

    @staticmethod
    def _make_status_callback(lines, changed):
        """The monitor's on_change(device, new_status): safe from any thread. A plain
        function holding only an Event, never a widget; the line goes through log_event,
        as the automatic work of 'system'."""
        def status_changed(device, new):
            name = f"{device['name']} ({device['ip']})"
            fields = {'device': device['name'], 'ip': device['ip'], 'user': event_log.SYSTEM}
            if new == 'up':
                event_log.log_event('monitor', f"{name}: status check SUCCESSFUL, the device "
                                               f"is UP (was {device['status']}). Recorded.", 'ok',
                                    **fields)
            else:
                event_log.log_event('monitor', f"{name}: status check WARNING, the device went "
                                               f"DOWN (was {device['status']}). Recorded.",
                                    'warn', **fields)
            changed.set()
        return status_changed

    # ---------------------------------------------------------------- filters
    def _make_filter_bar(self, parent):
        """All | Successful | Failed | Warnings | Changes (several may be chosen), then
        Category, Device, User, Search, Show commands and Reset filters. Filters only
        change what is shown: nothing is ever deleted."""
        bar = tk.Frame(parent, background=theme.SURFACE)
        self.selected_tags = set()                       # empty: All
        self.tag_buttons = {}
        for key, label in [('all', 'All')] + [(t, FILTER_LABELS[t]) for t in FILTER_TAGS]:
            b = tk.Button(bar, text=label, font=theme.FONT_SMALL, relief='flat', borderwidth=1,
                          padx=8, pady=1, cursor='hand2',
                          command=lambda k=key: self.toggle_filter(k))
            b.pack(side='left', padx=(0, 3))
            self.tag_buttons[key] = b
        self.category = tk.StringVar(value=ALL_CATEGORIES)
        self.device = tk.StringVar(value=ALL_DEVICES)
        self.user = tk.StringVar(value=ALL_USERS)
        self.search = tk.StringVar()
        self.show_commands = tk.BooleanVar(value=True)
        self.boxes = {}
        for key, var, values, width in (
                ('category', self.category, [ALL_CATEGORIES] + list(CATEGORIES), 10),
                ('device', self.device, [ALL_DEVICES], 13),
                ('user', self.user, [ALL_USERS], 22)):
            box = ttk.Combobox(bar, textvariable=var, values=values, width=width,
                               state='readonly', font=theme.FONT_SMALL)
            box.pack(side='left', padx=(8 if key == 'category' else 3, 0))
            box.bind('<<ComboboxSelected>>', lambda e: self.apply_filters())
            self.boxes[key] = box
        tk.Label(bar, text='Search:', font=theme.FONT_SMALL, background=theme.SURFACE,
                 foreground=theme.TEXT_MUTED).pack(side='left', padx=(8, 2))
        entry = ttk.Entry(bar, textvariable=self.search, width=16, font=theme.FONT_SMALL)
        entry.pack(side='left')
        entry.bind('<KeyRelease>', lambda e: self.apply_filters())
        ttk.Checkbutton(bar, text='Show commands', variable=self.show_commands,
                        command=self.apply_filters).pack(side='left', padx=(8, 0))
        ttk.Button(bar, text='Reset filters', command=self.reset_filters,
                   style='Console.TButton').pack(side='left', padx=(8, 0))
        self._paint_buttons()
        return bar

    def toggle_filter(self, key):
        """'all' shows everything (and deselects the others); any other button is added or
        removed; with nothing selected, back to All."""
        if key == 'all':
            self.selected_tags.clear()
        elif key in self.selected_tags:
            self.selected_tags.discard(key)
        else:
            self.selected_tags.add(key)
        self._paint_buttons()
        self.apply_filters()

    def reset_filters(self):
        self.selected_tags.clear()
        self.category.set(ALL_CATEGORIES)
        self.device.set(ALL_DEVICES)
        self.user.set(ALL_USERS)
        self.search.set('')
        self.show_commands.set(True)
        self._paint_buttons()
        self.apply_filters()

    def _paint_buttons(self):
        total = len(self.records)
        for key, b in self.tag_buttons.items():
            on = (key == 'all' and not self.selected_tags) or key in self.selected_tags
            label = 'All' if key == 'all' else FILTER_LABELS[key]
            n = total if key == 'all' else self.counts.get(key, 0)
            b.configure(text=f'{label} ({n})',
                        background=theme.ACCENT if on else theme.CARD,
                        foreground=theme.WHITE if on else theme.TEXT,
                        activebackground=theme.ACCENT_HOVER if on else theme.ACCENT_SOFT,
                        activeforeground=theme.WHITE if on else theme.TEXT,
                        relief='sunken' if on else 'flat')

    def matches(self, r):
        """True when the record passes every filter (they all work together)."""
        if self.selected_tags and not self.selected_tags.intersection(r['tags']):
            return False
        category = self.category.get()
        if category != ALL_CATEGORIES and r['category'] not in CATEGORY_GROUPS.get(
                category, (category,)):
            return False
        if self.device.get() != ALL_DEVICES and r['device'] != self.device.get():
            return False
        if self.user.get() != ALL_USERS and r['user'] != self.user.get():
            return False
        if r['command'] and not self.show_commands.get():
            return False
        wanted = self.search.get().strip().lower()
        if wanted:
            text = ' '.join((r['when'], r['user'], r['category'], r['device'], r['ip'],
                             r['message'], r['result'])).lower()
            if wanted not in text:
                return False
        return True

    def apply_filters(self):
        """Show again every kept record that passes the filters (nothing is deleted)."""
        t = self.text
        t.configure(state='normal')
        t.delete('1.0', 'end')
        self._shown = []
        t.configure(state='disabled')
        self._show([r for r in self.records if self.matches(r)], follow=True)

    def _note_choices(self, r):
        """New devices and users appear in their dropdowns as soon as they are logged."""
        for key, value in (('device', r['device']), ('user', r['user'])):
            box = self.boxes[key]
            values = list(box.cget('values'))
            if value and value not in values:
                box.configure(values=[values[0]] + sorted(values[1:] + [value],
                                                          key=str.lower))
        if r['category'] not in self.boxes['category'].cget('values'):
            self.boxes['category'].configure(
                values=list(self.boxes['category'].cget('values')) + [r['category']])

    def _open_line(self, event):
        """Double-click: the full output / before-after of that line in a window."""
        from gui.components.detail_popup import show_detail
        try:
            line = int(self.text.index(f'@{event.x},{event.y}').split('.')[0])
        except (tk.TclError, ValueError):
            return 'break'
        if 1 <= line <= len(self._shown):
            r = self._shown[line - 1]
            show_detail(self, r, title=f"{r['device'] or r['category']}: Console entry")
        return 'break'

    def _drain(self):
        batch = []
        try:
            while True:
                batch.append(self._queue.get_nowait())
        except queue.Empty:
            pass
        if batch:
            self._write_many(batch)
        if self._events_changed.is_set():             # the monitor recorded a change
            self._events_changed.clear()
            if self._current_tab() == EVENTS_TAB:
                self.refresh_events()
        try:
            self._timer = self.after(150, self._drain)
        except tk.TclError:                      # window closed
            self._timer = None

    def flush(self):
        """Put every queued line on screen now (used by tests and on shutdown)."""
        batch = []
        try:
            while True:
                batch.append(self._queue.get_nowait())
        except queue.Empty:
            pass
        if batch:
            self._write_many(batch)

    def _at_bottom(self):
        """True unless the user scrolled up to read older lines."""
        try:
            return self.text.yview()[1] >= 0.999
        except tk.TclError:
            return True

    def _write_many(self, batch):
        """Keep new records and show those that pass the filters. The whole session is
        kept (nothing is trimmed); a tk Text widget handles a long history without slowing
        down, and lines are written in batches. Follows the newest line only when the view
        was already at the bottom."""
        records = []
        for item in batch:
            r = item if isinstance(item, dict) else event_log.make_record(
                item[1], item[2], item[3], when=item[0])
            records.append(r)
            self.records.append(r)
            self.lines.append((r['when'], r['category'], r['message'], r['level']))
            for tag in r['tags']:
                self.counts[tag] = self.counts.get(tag, 0) + 1
            self._note_choices(r)
        self._paint_buttons()
        self._show([r for r in records if self.matches(r)], follow=self._at_bottom())

    def _show(self, records, follow=True):
        """Append these records' lines:  time  user  category  device  message  result."""
        if not records:
            return
        t = self.text
        t.configure(state='normal')
        for r in records:
            self._shown.append(r)
            colour = (r['level'],) if LEVEL_COLORS.get(r['level']) else ()
            t.insert('end', f"{r['when']:>11}", ('time',))   # '12:59:59 PM' is 11 wide
            t.insert('end', '  ')
            t.insert('end', f"{r['user']:<{USER_WIDTH}} ", ('user',))
            t.insert('end', f"{r['category']:<9} ", ('source',))   # 'configure': 9 letters
            t.insert('end', f"{(r['device'] or '-'):<{DEVICE_WIDTH}} ", ('device',))
            if r['command']:
                command = r['message'].split(' > ', 1)[-1]
                t.insert('end', f'> {command}', ('command',))
                t.insert('end', f"   {r['result'] or ''}\n", colour)
            else:
                t.insert('end', r['message'] + (f"   {r['result']}" if r['result'] else '') +
                         '\n', colour)
        if follow:
            t.see('end')
        t.configure(state='disabled')

    def _write(self, when, source, message, level):
        self._write_many([(when, source, message, level)])

    def clear(self):
        """The Clear button: empty the tab that is shown. Only the SCREEN is emptied:
        nothing is deleted from the database (the Console history stays saved and the
        Logs page shows it). On the stored-data tabs only the view is emptied."""
        tab = self._current_tab()
        if tab in (CONFIG_TAB, EVENTS_TAB):
            t = self.config_text if tab == CONFIG_TAB else self.events_text
            t.configure(state='normal')
            t.delete('1.0', 'end')
            t.insert('end', CLEARED_TEXT[tab], ('time',))
            t.configure(state='disabled')
            return
        self.lines.clear()
        self.records.clear()
        self._shown = []
        self.counts = {}
        self._paint_buttons()
        self.text.configure(state='normal')
        self.text.delete('1.0', 'end')
        self.text.configure(state='disabled')

    # ---------------------------------------------------------------- stored-data tabs
    def _current_tab(self):
        try:
            return self.tabs.index('current')
        except tk.TclError:
            return None

    def _tab_changed(self, _event):
        tab = self._current_tab()
        if tab == CONFIG_TAB:
            self.refresh_config_log()
        elif tab == EVENTS_TAB:
            self.refresh_events()

    def refresh_current(self):
        """The Refresh button, and after the database is back: reload the tab shown.
        On the Console tab: show any lines that are still waiting in the queue."""
        tab = self._current_tab()
        if tab in (CONFIG_TAB, EVENTS_TAB):
            what = 'configuration log' if tab == CONFIG_TAB else 'status events'
            event_log.log_event('console', f'Refreshing the {what}...')
            rows = self.refresh_config_log() if tab == CONFIG_TAB else self.refresh_events()
            text = (self.config_text if tab == CONFIG_TAB else self.events_text).get('1.0', '2.0')
            if text.startswith(('Could not read', 'Database unavailable')):
                event_log.log_event('console', f'Refresh of the {what} FAILED. {text.strip()}',
                                    'error')
            else:
                event_log.log_event('console', f'Refresh of the {what} SUCCESSFUL '
                                               f'({len(rows)} entries shown).', 'ok')
        else:
            self.flush()

    def show_unavailable(self):
        """The database is unavailable: blank both stored-data tabs (no old rows shown as
        current). They are reloaded when the connection is back."""
        for t in (self.config_text, self.events_text):
            t.configure(state='normal')
            t.delete('1.0', 'end')
            t.insert('end', UNAVAILABLE_TEXT, ('error',))
            t.configure(state='disabled')

    def refresh_events(self):
        """Show the newest recorded status changes (read-only). Returns the rows, or []
        when they could not be read (the reason is shown instead)."""
        t = self.events_text
        t.configure(state='normal')
        t.delete('1.0', 'end')
        try:
            rows = self.store.get_events(EVENT_ROWS)
        except Exception as err:
            report_error(self, err)            # may blank this tab (outage): write after it
            t.configure(state='normal')
            t.delete('1.0', 'end')
            t.insert('end', f'Could not read the status events: {err}\n', ('error',))
            t.configure(state='disabled')
            return []
        if not rows:
            t.insert('end', 'No status changes have been recorded yet. The background '
                            'monitor records them (database mode only).\n', ('time',))
        for r in rows:
            when = format_date_time(r.get('created_at'), seconds=True)
            previous = r.get('previous') or '?'
            level = 'ok' if r['kind'] == 'up' else 'error' if r['kind'] == 'down' else 'info'
            t.insert('end', when, ('time',))
            t.insert('end', f"  {r['device']:<10} {previous:>4} -> ")
            t.insert('end', f"{r['kind']:<5}", (level,))
            t.insert('end', f" {r.get('detail') or ''}\n")
        t.configure(state='disabled')
        return rows

    # ---------------------------------------------------------------- Config log tab

    def refresh_config_log(self):
        """Show the newest configuration log entries (read-only)."""
        t = self.config_text
        t.configure(state='normal')
        t.delete('1.0', 'end')
        try:
            rows = self.store.get_logs('', 1, CONFIG_LOG_ROWS, '')
        except Exception as err:
            report_error(self, err)            # may blank this tab (outage): write after it
            t.configure(state='normal')
            t.delete('1.0', 'end')
            t.insert('end', f'Could not read the configuration log: {err}\n', ('error',))
            rows = None
        if rows is not None and not rows:
            t.insert('end', 'No configuration changes have been logged yet.\n', ('time',))
        for r in rows or []:
            when = format_date_time(r.get('created_at'), seconds=True)
            level = 'ok' if r['status'] == 'success' else 'error'
            t.insert('end', when, ('time',))
            t.insert('end', f"  {r['device']:<10} {r['action']:<14} ")
            t.insert('end', f"{r['status']:<8}", (level,))
            t.insert('end', f" {r['details'] or ''}\n")
        t.configure(state='disabled')
        return rows or []
