"""The Logs page. Two read-only views, chosen with "Show":

  Configuration log   the configuration changes (config_logs), as before.
  Activity history    everything the Console showed, as saved (console_log): who did what,
                      when, on which device, and what happened. Filter by result/tag and by
                      user; double-click an entry for its full output or before/after.

Nothing here can change or delete an entry (the activity history is append-only in the
database as well).
"""
import tkinter as tk
from tkinter import ttk

from gui import theme
from gui.db_status import report_error
from gui.event_log import log_event
from gui.timefmt import format_date_time
from store_errors import DATABASE_ERRORS

PER_PAGE = 15
CONFIG_LOG, ACTIVITY = 'Configuration log', 'Activity history'
# widths for the larger table text (theme.TABLE_SIZE)
COLUMNS = [('date', 'Date', 175), ('device', 'Device', 125), ('action', 'Action', 210),
           ('status', 'Status', 95), ('details', 'Details', 400)]
ACTIVITY_COLUMNS = [('date', 'Time', 175), ('user', 'User', 190), ('category', 'Category', 90),
                    ('device', 'Device', 110), ('message', 'Message', 470),
                    ('result', 'Result', 160)]
STATUS_CHOICES = {CONFIG_LOG: ['all', 'success', 'failed'],
                  ACTIVITY: ['all', 'successful', 'failed', 'warning', 'change', 'command']}
ALL_USERS = 'All users'


class LogsTab(ttk.Frame):
    def __init__(self, parent, store):
        super().__init__(parent, padding=theme.PAD)
        self.store, self.page = store, 1
        self.rows_by_iid = {}
        top = ttk.Frame(self); top.pack(fill='x')
        ttk.Label(top, text='Show:', style='Form.TLabel').pack(side='left')
        self.view = tk.StringVar(value=CONFIG_LOG)
        views = [CONFIG_LOG] + ([ACTIVITY] if hasattr(store, 'get_console_events') else [])
        view_box = ttk.Combobox(top, textvariable=self.view, width=17, state='readonly',
                                values=views, font=theme.FONT_FORM)
        view_box.pack(side='left', padx=(theme.PAD, theme.PAD * 2))
        view_box.bind('<<ComboboxSelected>>', lambda e: self.change_view())
        ttk.Label(top, text='Search:', style='Form.TLabel').pack(side='left')
        self.search = tk.StringVar()
        entry = ttk.Entry(top, textvariable=self.search, width=28, font=theme.FONT_FORM)
        entry.pack(side='left', padx=theme.PAD, ipady=2)
        entry.bind('<KeyRelease>', lambda e: self.go_first())
        ttk.Label(top, text='Status:', style='Form.TLabel').pack(side='left', padx=(theme.PAD, 0))
        self.status = tk.StringVar(value='all')
        self.status_box = ttk.Combobox(top, textvariable=self.status, width=10, state='readonly',
                                       values=STATUS_CHOICES[CONFIG_LOG], font=theme.FONT_FORM)
        self.status_box.pack(side='left', padx=theme.PAD)
        self.status_box.bind('<<ComboboxSelected>>', lambda e: self.go_first())
        self.user_label = ttk.Label(top, text='User:', style='Form.TLabel')
        self.user = tk.StringVar(value=ALL_USERS)
        self.user_box = ttk.Combobox(top, textvariable=self.user, width=24, state='readonly',
                                     values=[ALL_USERS], font=theme.FONT_FORM)
        self.user_box.bind('<<ComboboxSelected>>', lambda e: self.go_first())
        ttk.Button(top, text='Refresh', command=self.refresh_clicked).pack(side='right')

        self.tables = ttk.Frame(self)
        self.tables.pack(fill='both', expand=True, pady=theme.PAD)
        self.tree = self._table(COLUMNS)
        self.activity_tree = self._table(ACTIVITY_COLUMNS)
        self.activity_tree.bind('<Double-1>', self._open_entry)
        self.tree.pack(fill='both', expand=True)
        self.empty = ttk.Label(self, text='', foreground=theme.TEXT_MUTED); self.empty.pack()

        nav = ttk.Frame(self); nav.pack(fill='x', pady=(theme.PAD, 0))
        self.prev_btn = ttk.Button(nav, text='Previous', command=lambda: self.turn(-1))
        self.next_btn = ttk.Button(nav, text='Next', command=lambda: self.turn(1))
        self.page_label = ttk.Label(nav, text='')
        self.prev_btn.pack(side='left'); self.page_label.pack(side='left', padx=theme.PAD)
        self.next_btn.pack(side='left')
        self.refresh()

    def _table(self, columns):
        tree = ttk.Treeview(self.tables, columns=[c[0] for c in columns], show='headings',
                            style='Data.Treeview')
        for key, title, width in columns:
            tree.heading(key, text=title)
            tree.column(key, width=width, anchor='w')
        tree.tag_configure('failed', background=theme.SEVERITY_COLORS['high'])
        tree.tag_configure('error', background=theme.SEVERITY_COLORS['high'])
        tree.tag_configure('warn', background=theme.SEVERITY_COLORS.get('medium', theme.CARD))
        return tree

    @property
    def activity(self):
        return self.view.get() == ACTIVITY

    def change_view(self):
        """Switch between the configuration log and the activity history."""
        self.status.set('all')
        self.status_box.configure(values=STATUS_CHOICES[self.view.get()])
        self.tree.pack_forget()
        self.activity_tree.pack_forget()
        if self.activity:
            self.activity_tree.pack(fill='both', expand=True)
            self.user_label.pack(side='left', padx=(theme.PAD, 0))
            self.user_box.pack(side='left', padx=theme.PAD)
            self._load_users()
        else:
            self.user_label.pack_forget()
            self.user_box.pack_forget()
            self.tree.pack(fill='both', expand=True)
        self.go_first()

    def _load_users(self):
        try:
            users = self.store.console_event_users()
        except Exception:
            users = []
        self.user_box.configure(values=[ALL_USERS] + list(users))

    def refresh_clicked(self):
        """The Refresh button: reload, and say so in the Console."""
        log_event('logs', 'Refreshing the Logs page...')
        if self.activity:
            self._load_users()
        if self.refresh():
            log_event('logs', f'Refresh of the Logs page SUCCESSFUL ({self.total} entries).', 'ok')

    def go_first(self):
        self.page = 1
        self.refresh()

    def turn(self, step):
        self.page += step
        self.refresh()

    def refresh(self):
        text = self.search.get().strip()
        status = '' if self.status.get() == 'all' else self.status.get()
        user = '' if self.user.get() == ALL_USERS else self.user.get()
        try:
            if self.activity:
                total = self.store.count_console_events(text, status, user)
            else:
                total = self.store.count_logs(text, status)
            pages = max(1, -(-total // PER_PAGE))
            self.page = min(max(self.page, 1), pages)
            if self.activity:
                rows = self.store.get_console_events(text, self.page, PER_PAGE, status, user)
            else:
                rows = self.store.get_logs(text, self.page, PER_PAGE, status)
        except DATABASE_ERRORS as err:
            what = 'activity history' if self.activity else 'configuration log'
            log_event('logs', f'Reading the {what} FAILED. {err}', 'error')
            self.show_unavailable(str(err))
            report_error(self, err)
            return False
        self.total = total
        for tree in (self.tree, self.activity_tree):
            tree.delete(*tree.get_children())
        self.rows_by_iid = {}
        if self.activity:
            for r in rows:
                iid = self.activity_tree.insert(
                    '', 'end', tags=(r.get('level') or '',),
                    values=(format_date_time(r['created_at'], seconds=True), r['user_label'],
                            r['category'], r.get('device') or '', r['message'],
                            r.get('result') or ''))
                self.rows_by_iid[iid] = r
            empty = 'No activity saved yet.'
        else:
            for r in rows:
                when = r['created_at'].strftime('%Y-%m-%d %H:%M:%S')
                self.tree.insert('', 'end', tags=(r['status'],),
                                 values=(when, r['device'], r['action'], r['status'],
                                         r['details']))
            empty = 'No log entries yet. They appear after you apply a configuration.'
        self.empty.config(text='' if total else empty)
        self.page_label.config(text=f'Page {self.page} of {pages}  ({total} entries)')
        self.prev_btn.state(['!disabled'] if self.page > 1 else ['disabled'])
        self.next_btn.state(['!disabled'] if self.page < pages else ['disabled'])
        return True

    def _open_entry(self, event):
        from gui.components.detail_popup import show_detail
        iid = self.activity_tree.identify_row(event.y)
        row = self.rows_by_iid.get(iid)
        if row:
            show_detail(self, dict(row, when=format_date_time(row['created_at'], seconds=True)),
                        title='Activity history entry')

    def show_unavailable(self, reason=''):
        """The log could not be read: show no rows at all (never old rows as if current)."""
        for tree in (self.tree, self.activity_tree):
            tree.delete(*tree.get_children())
        self.empty.config(text='Database unavailable: the log cannot be shown right now. '
                               'It is refreshed automatically when the connection is back.')
        self.page_label.config(text='')
        self.prev_btn.state(['disabled'])
        self.next_btn.state(['disabled'])
