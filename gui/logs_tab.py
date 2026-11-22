import tkinter as tk
from tkinter import ttk

from gui import theme
from gui.db_status import report_error
from store_errors import DATABASE_ERRORS

PER_PAGE = 15
# widths for the larger table text (theme.TABLE_SIZE)
COLUMNS = [('date', 'Date', 175), ('device', 'Device', 125), ('action', 'Action', 210),
           ('status', 'Status', 95), ('details', 'Details', 400)]


class LogsTab(ttk.Frame):
    def __init__(self, parent, store):
        super().__init__(parent, padding=theme.PAD)
        self.store, self.page = store, 1
        top = ttk.Frame(self); top.pack(fill='x')
        ttk.Label(top, text='Search:', style='Form.TLabel').pack(side='left')
        self.search = tk.StringVar()
        entry = ttk.Entry(top, textvariable=self.search, width=28, font=theme.FONT_FORM)
        entry.pack(side='left', padx=theme.PAD, ipady=2)
        entry.bind('<KeyRelease>', lambda e: self.go_first())
        ttk.Label(top, text='Status:', style='Form.TLabel').pack(side='left', padx=(theme.PAD, 0))
        self.status = tk.StringVar(value='all')
        box = ttk.Combobox(top, textvariable=self.status, width=10, state='readonly',
                           values=['all', 'success', 'failed'], font=theme.FONT_FORM)
        box.pack(side='left', padx=theme.PAD)
        box.bind('<<ComboboxSelected>>', lambda e: self.go_first())
        ttk.Button(top, text='Refresh', command=self.refresh).pack(side='right')

        self.tree = ttk.Treeview(self, columns=[c[0] for c in COLUMNS], show='headings',
                                 style='Data.Treeview')
        for key, title, width in COLUMNS:
            self.tree.heading(key, text=title)
            self.tree.column(key, width=width, anchor='w')
        self.tree.tag_configure('failed', background=theme.SEVERITY_COLORS['high'])
        self.tree.pack(fill='both', expand=True, pady=theme.PAD)
        self.empty = ttk.Label(self, text='', foreground=theme.TEXT_MUTED); self.empty.pack()

        nav = ttk.Frame(self); nav.pack(fill='x', pady=(theme.PAD, 0))
        self.prev_btn = ttk.Button(nav, text='Previous', command=lambda: self.turn(-1))
        self.next_btn = ttk.Button(nav, text='Next', command=lambda: self.turn(1))
        self.page_label = ttk.Label(nav, text='')
        self.prev_btn.pack(side='left'); self.page_label.pack(side='left', padx=theme.PAD)
        self.next_btn.pack(side='left')
        self.refresh()

    def go_first(self):
        self.page = 1
        self.refresh()

    def turn(self, step):
        self.page += step
        self.refresh()

    def refresh(self):
        text = self.search.get().strip()
        status = '' if self.status.get() == 'all' else self.status.get()
        try:
            total = self.store.count_logs(text, status)
            pages = max(1, -(-total // PER_PAGE))
            self.page = min(max(self.page, 1), pages)
            rows = self.store.get_logs(text, self.page, PER_PAGE, status)
        except DATABASE_ERRORS as err:
            self.show_unavailable(str(err))
            report_error(self, err)
            return
        self.tree.delete(*self.tree.get_children())
        for r in rows:
            when = r['created_at'].strftime('%Y-%m-%d %H:%M:%S')
            self.tree.insert('', 'end', tags=(r['status'],),
                             values=(when, r['device'], r['action'], r['status'],
                                     r['details']))
        self.empty.config(text='' if total else
                          'No log entries yet. They appear after you apply a configuration.')
        self.page_label.config(text=f'Page {self.page} of {pages}  ({total} entries)')
        self.prev_btn.state(['!disabled'] if self.page > 1 else ['disabled'])
        self.next_btn.state(['!disabled'] if self.page < pages else ['disabled'])

    def show_unavailable(self, reason=''):
        """The log could not be read: show no rows at all (never old rows as if current)."""
        self.tree.delete(*self.tree.get_children())
        self.empty.config(text='Database unavailable: the log cannot be shown right now. '
                               'It is refreshed automatically when the connection is back.')
        self.page_label.config(text='')
        self.prev_btn.state(['disabled'])
        self.next_btn.state(['disabled'])
