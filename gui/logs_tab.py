"""The Logs page. Two read-only views, chosen with "Show":

  Configuration log   the configuration changes (config_logs), as before.
  Activity history    everything the Console showed, as saved (console_log): who did what,
                      when, on which device, and what happened. Filter by result/tag and by
                      user; double-click an entry for its full output or before/after.

Nothing here can change or delete an entry (the activity history is append-only in the
database as well).

Export (locked)... writes the log shown - its search and filters, ALL pages, and only the
lines this person may see - to a NEW .nclog file LOCKED with a password typed for it
(at least 8 characters; log_export.py: scrypt + AES-256-GCM). The password is not stored
anywhere: only it opens the file. Unlock export... asks for it and saves a readable CSV
copy.

Who sees what: an admin sees everyone's activity; an operator or viewer sees only their
own lines and the automatic 'system' ones. This is enforced by the app (its queries are
limited), not by the database: the desktop reads the history with the app's shared
database account.
"""
import os
import tkinter as tk
from datetime import datetime
from tkinter import filedialog, messagebox, ttk

import log_export
from gui import background, theme
from gui.db_status import report_error
from gui.event_log import log_event
from gui.timefmt import format_date_time, format_datetime
from store_errors import DATABASE_ERRORS
from gui.components.tables import setup_table

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
    def __init__(self, parent, store, scope_users=None):
        """scope_users: None (an admin, or nobody signed in) shows everyone's activity;
        otherwise a function returning the users whose lines may be shown (a non-admin:
        their own masked e-mail and 'system'). Every activity query is limited to them."""
        super().__init__(parent, padding=theme.PAD)
        self.store, self.page = store, 1
        self.scope_users = scope_users
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
        self.unlock_btn = ttk.Button(top, text='🔓 Unlock export...',
                                     command=self.unlock_clicked)
        self.unlock_btn.pack(side='right', padx=(0, theme.PAD))
        self.export_btn = ttk.Button(top, text='🔒 Export (locked)...',
                                     command=self.export_clicked)
        self.export_btn.pack(side='right', padx=(0, theme.PAD))

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
        setup_table(tree, columns)
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

    def _allowed(self):
        """The users this person may see, or None (everyone)."""
        return list(self.scope_users()) if self.scope_users else None

    def _load_users(self):
        allowed = self._allowed()
        if allowed is not None:                       # only their own lines and 'system'
            users = allowed
        else:
            try:
                users = self.store.console_event_users()
            except Exception:
                users = []
        self.user_box.configure(values=[ALL_USERS] + list(users))
        if self.user.get() != ALL_USERS and self.user.get() not in users:
            self.user.set(ALL_USERS)

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

    def _query(self):
        """(search, status, user, scope): what the page shows, and to whom it may show it.
        The page AND its export use this, so an export never holds more than the page."""
        text = self.search.get().strip()
        status = '' if self.status.get() == 'all' else self.status.get()
        user = '' if self.user.get() == ALL_USERS else self.user.get()
        allowed = self._allowed()
        if allowed is not None and user and user not in allowed:
            user = ''                                 # never another person's lines
        scope = {} if allowed is None else {'users': allowed}
        return text, status, user, scope

    def refresh(self):
        text, status, user, scope = self._query()
        try:
            if self.activity:
                total = self.store.count_console_events(text, status, user, **scope)
            else:
                total = self.store.count_logs(text, status)
            pages = max(1, -(-total // PER_PAGE))
            self.page = min(max(self.page, 1), pages)
            if self.activity:
                rows = self.store.get_console_events(text, self.page, PER_PAGE, status, user,
                                                     **scope)
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
                when = format_datetime(r['created_at'], seconds=True)
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

    # ---------------------------------------------------------------- locked export / unlock
    def export_clicked(self):
        """Export what the page shows (all pages) to a new file LOCKED with a password
        typed now (twice). Only that password opens it; it is not stored anywhere."""
        log = self.view.get()
        password = ask_password(self, confirm=True)
        if password is None:
            return                                    # cancelled: nothing was read
        name = 'activity' if self.activity else 'config-log'
        path = filedialog.asksaveasfilename(
            parent=self, title='Export the log (locked)', defaultextension=log_export.SUFFIX,
            initialfile=f'netcommand-{name}-{file_stamp()}{log_export.SUFFIX}',
            filetypes=[('NetCommand locked log', '*' + log_export.SUFFIX)])
        if not path:
            return
        activity = self.activity
        text, status, user, scope = self._query()
        filters = {'search': text, 'status': status or 'all',
                   'user': user or (ALL_USERS if activity else ''),
                   'limited_to': list(scope.get('users', [])) or 'everyone'}
        store = self.store
        self.export_btn.state(['disabled'])
        log_event('logs', f'Exporting the {log} (locked with a password)...')

        def work(pw=password):
            entries = collect_entries(store, activity, text, status, user, scope)
            data = log_export.export_bytes(log, entries, pw, filters=filters)
            log_export.write_export(path, data)
            return len(entries)
        password = None
        background.run_async(self, work, lambda n, err: self._exported(log, path, n, err))

    def unlock_clicked(self):
        """Open a locked export with its password and save a READABLE copy (CSV)."""
        source = filedialog.askopenfilename(
            parent=self, title='Unlock a log export',
            filetypes=[('NetCommand locked log', '*' + log_export.SUFFIX), ('All files', '*.*')])
        if not source:
            return
        name = os.path.basename(source)
        try:
            with open(source, 'rb') as f:
                data = f.read(log_export.C.MAX_FILE_BYTES + 1)
            header = log_export.read_header(data)
        except (OSError, log_export.C.BackupCryptoError) as err:
            text = str(err) if isinstance(err, log_export.C.BackupCryptoError) else \
                f'{name} could not be read.'
            messagebox.showerror('Cannot unlock', text, parent=self)
            return
        if log_export.is_key_locked(header):
            messagebox.showinfo('Cannot unlock here', (
                'This file was locked without a password (a test version). Export the log '
                'again: new exports are locked with a password.'), parent=self)
            return
        password = ask_password(self, confirm=False, file_name=name)
        if password is None:
            return
        try:
            _header, payload = log_export.open_export(data, password)
        except log_export.C.BackupCryptoError as err:
            log_event('logs', f'Unlock of {name} FAILED (wrong password, or a changed file).',
                      'error')
            messagebox.showerror('Cannot unlock', str(err), parent=self)
            return
        finally:
            password = None
        text = log_export.to_csv(payload)
        base = os.path.splitext(name)[0]
        target = filedialog.asksaveasfilename(
            parent=self, title='Save the unlocked (readable) copy', defaultextension='.csv',
            initialfile=f'{base}-unlocked.csv', filetypes=[('CSV (Excel)', '*.csv')])
        if not target:
            return
        try:
            log_export.write_export(target, text.encode('utf-8-sig'))   # Excel reads UTF-8
        except (OSError, log_export.LogExportError) as err:
            messagebox.showerror('Not saved', str(err) if isinstance(
                err, log_export.LogExportError) else 'The file could not be written.',
                parent=self)
            return
        log_event('logs', f'Unlocked {name} ({header["count"]} entries of the {header["log"]}) '
                          f'to {os.path.basename(target)} (readable).', 'ok')
        messagebox.showinfo('Export unlocked', (
            f'{header["count"]} entries of the {header["log"]} were saved, READABLE, to\n'
            f'{target}\n\nIt is not locked: keep it safe and delete it when you are done.'),
            parent=self)

    def _exported(self, log, path, count, err):
        try:
            self.export_btn.state(['!disabled'])
        except tk.TclError:
            return
        name = os.path.basename(path)
        if err is not None:
            text = str(err) if isinstance(err, (log_export.LogExportError,) +
                                          DATABASE_ERRORS) else \
                f'The export failed ({type(err).__name__}).'
            log_event('logs', f'Export of the {log} FAILED. {text}', 'error')
            messagebox.showerror('Export failed', f'Nothing was exported.\n\n{text}', parent=self)
            return
        log_event('logs', f'Exported {count} entries of the {log} (locked with a password) '
                          f'to {name}.', 'ok')
        messagebox.showinfo('Log exported', (
            f'{count} entries of the {log} were saved, LOCKED, to\n{path}\n\n'
            f'Only the password you typed opens it ("Unlock export..." on this page). It is '
            f'not stored anywhere: if it is lost, nobody can open the file.'), parent=self)


EXPORT_PAGE = 500                                    # rows read per query while exporting


def file_stamp(now=None):
    """'20261127-0530PM' for a file name (12-hour, like every time NetCommand shows)."""
    now = now or datetime.now()
    hour = now.hour % 12 or 12
    return f'{now.year:04d}{now.month:02d}{now.day:02d}-{hour:02d}{now.minute:02d}' \
           f'{"AM" if now.hour < 12 else "PM"}'


def collect_entries(store, activity, text, status, user, scope):
    """Every entry the page would show with these filters and limits, newest first, read
    page by page. An entry added meanwhile can shift the pages: entries are kept once,
    by id. Stops after log_export.MAX_ENTRIES + 1 (export_bytes then refuses)."""
    seen, out, page = set(), [], 1
    while len(out) <= log_export.MAX_ENTRIES:
        if activity:
            rows = store.get_console_events(text, page, EXPORT_PAGE, status, user, **scope)
        else:
            rows = store.get_logs(text, page, EXPORT_PAGE, status)
        if not rows:
            break
        for r in rows:
            key = r.get('id', id(r))
            if key in seen:
                continue
            seen.add(key)
            out.append({k: v for k, v in r.items() if k != 'id'})
        if len(rows) < EXPORT_PAGE:
            break
        page += 1
    return out


def ask_password(parent, confirm=True, file_name=''):
    """The export password in a masked dialog (typed twice when locking, once when
    unlocking), or None (cancelled). Never kept, logged or shown."""
    win = tk.Toplevel(parent)
    win.title('Lock the export' if confirm else 'Unlock the export')
    win.transient(parent.winfo_toplevel())
    win.resizable(False, False)
    frame = ttk.Frame(win, padding=theme.PAD * 2)
    frame.pack(fill='both', expand=True)
    text = (f'Type a password to lock this export (at least {log_export.PASSPHRASE_MIN} '
            f'characters).\nOnly this password opens the file. It is not stored anywhere:\n'
            f'if it is lost, nobody can open the file (NetCommand included).') if confirm else \
        f'Type the password of {file_name or "this export"}.'
    ttk.Label(frame, text=text, justify='left', style='Form.TLabel').pack(anchor='w')
    variables = [tk.StringVar(win)] + ([tk.StringVar(win)] if confirm else [])
    entries = []
    for label, var in zip(('Password', 'Password again'), variables):
        ttk.Label(frame, text=label).pack(anchor='w', pady=(theme.PAD, 0))
        entry = ttk.Entry(frame, textvariable=var, show='*', width=40, font=theme.FONT_FORM)
        entry.pack(anchor='w', ipady=2)
        entries.append(entry)
    problem = ttk.Label(frame, text='', foreground=theme.DANGER)
    problem.pack(anchor='w', pady=(theme.PAD, 0))
    result = {'value': None}

    def clear():
        for var in variables:
            var.set('')

    def ok(_event=None):
        values = [var.get() for var in variables]
        clear()
        if confirm and values[0] != values[1]:
            problem.configure(text='The two passwords do not match.')
            return
        try:
            log_export.check_passphrase(values[0])
        except log_export.LogExportError as err:
            problem.configure(text=str(err))
            return
        result['value'] = values[0]
        win.destroy()

    def cancel(_event=None):
        clear()
        win.destroy()
    bar = ttk.Frame(frame)
    bar.pack(anchor='e', pady=(theme.PAD, 0))
    ttk.Button(bar, text='Lock and choose file...' if confirm else 'Unlock',
               style='Accent.TButton', command=ok).pack(side='left')
    ttk.Button(bar, text='Cancel', command=cancel).pack(side='left', padx=(theme.PAD, 0))
    win.bind('<Return>', ok)
    win.bind('<Escape>', cancel)
    win.protocol('WM_DELETE_WINDOW', cancel)
    entries[0].focus_set()
    from gui.components.dialogs import place_window
    place_window(win, parent)
    win.grab_set()
    parent.wait_window(win)
    return result['value']