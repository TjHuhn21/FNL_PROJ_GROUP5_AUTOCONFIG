import tkinter as tk
from tkinter import ttk, messagebox

import validation
from gui import theme
from gui.db_status import database_ready, report_error
from store_errors import DATABASE_ERRORS, DeletedDeviceExists, DuplicateDeviceName, outcome_text

PER_PAGE = 15
COLUMNS = [('name', 'Name', 160), ('ip', 'IP', 130), ('type', 'Type', 90),
           ('status', 'Status', 70), ('managed', 'Managed', 80)]
SORTABLE = {'name', 'ip', 'type', 'status'}


class DevicesTab(ttk.Frame):
    def __init__(self, parent, store, on_change=None):
        super().__init__(parent, padding=theme.PAD)
        self.store, self.on_change = store, on_change
        self.page, self.sort_by = 1, 'name'

        top = ttk.Frame(self); top.pack(fill='x')
        ttk.Label(top, text='Search:').pack(side='left')
        self.search = tk.StringVar()
        entry = ttk.Entry(top, textvariable=self.search, width=30)
        entry.pack(side='left', padx=theme.PAD)
        entry.bind('<KeyRelease>', lambda e: self.go_first())
        self.read_only = False
        self.add_btn = ttk.Button(top, text='Add', command=self.add)
        self.add_btn.pack(side='right')
        self.delete_btn = ttk.Button(top, text='Delete', command=self.delete)
        self.delete_btn.pack(side='right', padx=4)
        self.edit_btn = ttk.Button(top, text='Edit', command=self.edit)
        self.edit_btn.pack(side='right')

        self.tree = ttk.Treeview(self, columns=[c[0] for c in COLUMNS],
                                 show='headings', selectmode='browse')
        for key, title, width in COLUMNS:
            cmd = (lambda k=key: self.sort(k)) if key in SORTABLE else ''
            self.tree.heading(key, text=title, command=cmd)
            self.tree.column(key, width=width, anchor='w')
        for status, color in theme.STATUS_COLORS.items():
            self.tree.tag_configure(status, background=color)
        self.tree.pack(fill='both', expand=True, pady=theme.PAD)
        self.tree.bind('<Double-1>', lambda e: self.edit())

        self.empty = ttk.Label(self, text='', foreground='#666')
        self.empty.pack()

        nav = ttk.Frame(self); nav.pack(fill='x', pady=(theme.PAD, 0))
        self.prev_btn = ttk.Button(nav, text='Previous', command=lambda: self.turn(-1))
        self.next_btn = ttk.Button(nav, text='Next', command=lambda: self.turn(1))
        self.page_label = ttk.Label(nav, text='')
        self.prev_btn.pack(side='left'); self.page_label.pack(side='left', padx=theme.PAD)
        self.next_btn.pack(side='left')
        self.refresh()

    # ----- data -----
    def go_first(self):
        self.page = 1
        self.refresh()

    def turn(self, step):
        self.page += step
        self.refresh()

    def sort(self, column):
        self.sort_by = column
        self.go_first()

    def refresh(self):
        text = self.search.get().strip()
        try:
            total = self.store.count_devices(text)
            pages = max(1, -(-total // PER_PAGE))
            self.page = min(max(self.page, 1), pages)
            rows = self.store.get_devices(text, self.sort_by, self.page, PER_PAGE)
        except DATABASE_ERRORS as err:
            self.show_unavailable(str(err))
            report_error(self, err)
            return
        self.tree.delete(*self.tree.get_children())
        for d in rows:
            self.tree.insert('', 'end', iid=str(d['id']), tags=(d['status'],),
                             values=(d['name'], d['ip'], d['type'], d['status'],
                                     'yes' if d['managed'] else 'no'))
        if total == 0:
            self.empty.config(text='No devices match your search.' if text else
                              'No devices yet. Run a scan or click Add.')
        else:
            self.empty.config(text='')
        self.page_label.config(text=f'Page {self.page} of {pages}  ({total} devices)')
        self.prev_btn.state(['!disabled'] if self.page > 1 else ['disabled'])
        self.next_btn.state(['!disabled'] if self.page < pages else ['disabled'])

    def show_unavailable(self, reason=''):
        """The list could not be read: show no rows at all (never old rows as if current)."""
        self.tree.delete(*self.tree.get_children())
        self.empty.config(text='Database unavailable: the device list cannot be shown right now. '
                               'It is refreshed automatically when the connection is back.')
        self.page_label.config(text='')
        self.prev_btn.state(['disabled'])
        self.next_btn.state(['disabled'])

    def selected_id(self):
        sel = self.tree.selection()
        if not sel:
            messagebox.showinfo('Select a device', 'Click a device in the list first.')
            return None
        return int(sel[0])

    # ----- actions -----
    def set_read_only(self, read_only):
        """Viewers: devices can be searched and viewed, not added, edited or deleted."""
        self.read_only = bool(read_only)
        for button in (self.add_btn, self.edit_btn, self.delete_btn):
            button.state(['disabled'] if self.read_only else ['!disabled'])

    def add(self):
        if not self.read_only and database_ready(self):
            DeviceDialog(self, self.store, None, self._saved)

    def edit(self):
        did = self.selected_id()
        if self.read_only or did is None or not database_ready(self):
            return
        try:
            d = self.store.get_device(did)
        except DATABASE_ERRORS as err:
            report_error(self, err)
            messagebox.showerror('Cannot edit', f'The device could not be read. {err}')
            return
        if d is None:
            messagebox.showinfo('Device gone', 'This device is no longer registered.')
            self.refresh()
            return
        DeviceDialog(self, self.store, d, self._saved)

    def delete(self):
        did = self.selected_id()
        if self.read_only or did is None or not database_ready(self):
            return
        try:
            d = self.store.get_device(did)
        except DATABASE_ERRORS as err:
            report_error(self, err)
            messagebox.showerror('Cannot delete', f'Nothing was deleted. {err}')
            return
        if d is None:
            messagebox.showinfo('Device gone', 'This device is no longer registered.')
            self.refresh()
            return
        if messagebox.askyesno('Delete device', f"Delete {d['name']} ({d['ip']})?"):
            try:
                self.store.delete_device(did)
            except DATABASE_ERRORS as err:
                report_error(self, err)
                messagebox.showerror('Delete failed',
                                     f"{outcome_text(err, 'Nothing was deleted.')} {err}")
                return
            self._saved()

    def _saved(self):
        self.refresh()
        if self.on_change:
            self.on_change()


class DeviceDialog(tk.Toplevel):
    def __init__(self, parent, store, device, on_saved):
        super().__init__(parent)
        self.store, self.device, self.on_saved = store, device, on_saved
        self.title('Edit device' if device else 'Add device')
        self.configure(padx=theme.PAD * 2, pady=theme.PAD * 2, background=theme.BG)
        self.resizable(False, False)
        d = device or {'name': '', 'ip': '', 'type': 'switch', 'status': 'up',
                       'managed': 1}
        self.vars = {'name': tk.StringVar(value=d['name']),
                     'ip': tk.StringVar(value=d['ip']),
                     'type': tk.StringVar(value=d['type']),
                     'status': tk.StringVar(value=d['status']),
                     'managed': tk.IntVar(value=int(d['managed'])),
                     'username': tk.StringVar(), 'password': tk.StringVar()}
        self.name_entry = ttk.Entry(self, textvariable=self.vars['name'], width=30)
        rows = [('Name', self.name_entry),
                ('IP address', ttk.Entry(self, textvariable=self.vars['ip'], width=30)),
                ('Type', ttk.Combobox(self, textvariable=self.vars['type'], width=27,
                                      values=['switch', 'router', 'unknown'], state='readonly')),
                ('Status', ttk.Combobox(self, textvariable=self.vars['status'], width=27,
                                        values=['up', 'down'], state='readonly')),
                ('', ttk.Checkbutton(self, text='Managed (we can log in)',
                                     variable=self.vars['managed'])),
                ('Login username', ttk.Entry(self, textvariable=self.vars['username'], width=30)),
                ('Login password', ttk.Entry(self, textvariable=self.vars['password'],
                                             show='*', width=30))]
        for r, (label, widget) in enumerate(rows):
            ttk.Label(self, text=label).grid(row=r, column=0, sticky='w', pady=3)
            widget.grid(row=r, column=1, pady=3, padx=theme.PAD)
        hint = 'Optional. Saved encrypted. Leave both blank to keep the current login.' \
            if device else 'Optional. Saved encrypted, used by Configure and Review.'
        ttk.Label(self, text=hint, foreground='#666').grid(row=len(rows), column=0,
                                                           columnspan=2, sticky='w')
        btns = ttk.Frame(self); btns.grid(row=len(rows) + 1, column=0, columnspan=2,
                                          sticky='e', pady=(theme.PAD, 0))
        ttk.Button(btns, text='Cancel', command=self.destroy).pack(side='right')
        ttk.Button(btns, text='Save', style='Accent.TButton',
                   command=self.save).pack(side='right', padx=4)
        self.transient(parent.winfo_toplevel())
        self.grab_set()

    def save(self):
        v = {k: var.get() for k, var in self.vars.items()}
        name, ip = v['name'].strip(), v['ip'].strip()
        username, password = v['username'].strip(), v['password']
        problem = (validation.check_name(name) or validation.check_ip(ip)
                   or validation.check_login(username, password))   # never shows the password
        try:
            existing = self.store.get_device_by_ip(ip) if not problem else None
        except DATABASE_ERRORS as err:
            report_error(self, err)
            messagebox.showerror('Cannot save', f'Nothing was saved. {err}', parent=self)
            return
        own_id = self.device['id'] if self.device else None
        if existing and existing['id'] != own_id:
            problem = f"A device with IP {ip} already exists ({existing['name']})."
        if problem:
            messagebox.showerror('Cannot save', problem, parent=self)
            return
        data = {'name': name, 'ip': ip, 'type': v['type'], 'status': v['status'],
                'managed': bool(v['managed'])}
        try:                       # device and login together: both are saved, or neither
            self.store.save_device(own_id, data, username or None,
                                   password if username else None)
        except DeletedDeviceExists as err:
            if self.device:        # editing: point at the deleted device, never restore it here
                gone = err.device
                messagebox.showerror(
                    'Cannot save',
                    f"Nothing was saved. IP {gone['ip']} belongs to the deleted device "
                    f"{gone['name']}. Choose another IP, or use Add with this IP to restore "
                    f"{gone['name']}.", parent=self)
                return
            self.restore_dialog = RestoreDialog(self, self.store, err.device, data,
                                                on_restored=self._restored)
            return
        except DuplicateDeviceName as err:  # the dialog stays open: correct the name, save again
            messagebox.showerror('Name already used', f'Nothing was saved. {err}\n\n'
                                 f'Choose another name.', parent=self)
            self.name_entry.focus_set()
            self.name_entry.select_range(0, 'end')
            return
        except Exception as err:
            report_error(self, err)            # an outage also shows in the main window
            messagebox.showerror('Cannot save', f'{outcome_text(err)} {err}', parent=self)
            return
        self.destroy()
        self.on_saved()

    def _restored(self):
        self.destroy()
        self.on_saved()


class RestoreDialog(tk.Toplevel):
    """Shown when Add is used with the IP of a soft-deleted device. Nothing happens until
    the user picks how to handle the saved login AND confirms. Cancel changes nothing.
    The old login is never shown or pre-filled (only whether one is saved)."""

    def __init__(self, parent, store, deleted, data, on_restored):
        super().__init__(parent)
        self.store, self.deleted, self.data, self.on_restored = store, deleted, data, on_restored
        self.title('Restore deleted device?')
        self.configure(padx=theme.PAD * 2, pady=theme.PAD * 2, background=theme.BG)
        self.resizable(False, False)
        d = deleted
        intro = (f"IP {d['ip']} belonged to the device {d['name']} ({d['type']}), which was "
                 f"deleted. It was not restored.\n\n"
                 f"Restoring brings back that same device record with its history (logs and "
                 f"events), using the details you entered: {data['name']}, {data['type']}, "
                 f"{data['status']}{', managed' if data['managed'] else ''}.")
        ttk.Label(self, text=intro, wraplength=420, justify='left').grid(
            row=0, column=0, columnspan=2, sticky='w', pady=(0, theme.PAD))
        self.choice = tk.StringVar(value='')            # no default: the user must choose
        keep_text = ('Keep its saved login (unchanged, not shown)' if d['has_login']
                     else 'Keep it without a login (none is saved)')
        ttk.Radiobutton(self, text=keep_text, value='keep', variable=self.choice).grid(
            row=1, column=0, columnspan=2, sticky='w')
        ttk.Radiobutton(self, text='Replace the login with:', value='replace',
                        variable=self.choice).grid(row=2, column=0, columnspan=2, sticky='w')
        self.username, self.password = tk.StringVar(), tk.StringVar()
        ttk.Label(self, text='Login username').grid(row=3, column=0, sticky='w', padx=(20, 0))
        ttk.Entry(self, textvariable=self.username, width=28).grid(row=3, column=1, pady=2)
        ttk.Label(self, text='Login password').grid(row=4, column=0, sticky='w', padx=(20, 0))
        ttk.Entry(self, textvariable=self.password, show='*', width=28).grid(row=4, column=1,
                                                                            pady=2)
        btns = ttk.Frame(self)
        btns.grid(row=5, column=0, columnspan=2, sticky='e', pady=(theme.PAD, 0))
        ttk.Button(btns, text='Cancel', command=self.cancel).pack(side='right')
        ttk.Button(btns, text=f"Restore {d['name']}", style='Accent.TButton',
                   command=self.confirm).pack(side='right', padx=4)
        self.protocol('WM_DELETE_WINDOW', self.cancel)
        self.transient(parent.winfo_toplevel())
        self.grab_set()

    def cancel(self):
        """Close without restoring: the deleted device is left exactly as it was."""
        parent = self.master
        self.destroy()
        try:
            parent.grab_set()                            # the Add dialog is modal again
        except tk.TclError:
            pass

    def confirm(self):
        choice = self.choice.get()
        if choice not in ('keep', 'replace'):
            messagebox.showerror('Choose an option', 'Choose whether to keep the saved login '
                                 'or replace it.', parent=self)
            return
        user, password = self.username.get().strip(), self.password.get()
        if choice == 'replace':
            problem = (validation.check_login(user, password) if (user or password)
                       else 'Enter the new login username and password.')
            if problem:                                  # never contains the password
                messagebox.showerror('Cannot restore', problem, parent=self)
                return
        d = self.deleted
        login_text = 'keep its saved login' if choice == 'keep' else f'use the new login ({user})'
        if not messagebox.askyesno('Restore device',
                                   f"Restore {d['name']} ({d['ip']}) as {self.data['name']} "
                                   f"and {login_text}?", parent=self):
            return
        try:
            if choice == 'keep':
                self.store.restore_device(d['id'], self.data, credentials='keep')
            else:
                self.store.restore_device(d['id'], self.data, credentials='replace',
                                          username=user, password=password)
        except DuplicateDeviceName as err:
            messagebox.showerror(
                'Name already used',
                f"Nothing was changed: {d['name']} was not restored. {err}\n\n"
                f"Click Cancel, change the name in the Add device dialog, and save again "
                f"(you will be asked about restoring again).", parent=self)
            return
        except Exception as err:
            report_error(self, err)
            messagebox.showerror('Restore failed',
                                 f"{outcome_text(err, 'Nothing was changed.')} {err}", parent=self)
            return
        self.destroy()
        self.on_restored()
