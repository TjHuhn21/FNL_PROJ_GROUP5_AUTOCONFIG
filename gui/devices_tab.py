import tkinter as tk
from tkinter import ttk, messagebox

import validation
from gui import theme

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
        ttk.Button(top, text='Add', command=self.add).pack(side='right')
        ttk.Button(top, text='Delete', command=self.delete).pack(side='right', padx=4)
        ttk.Button(top, text='Edit', command=self.edit).pack(side='right')

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
        total = self.store.count_devices(text)
        pages = max(1, -(-total // PER_PAGE))
        self.page = min(max(self.page, 1), pages)
        rows = self.store.get_devices(text, self.sort_by, self.page, PER_PAGE)
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

    def selected_id(self):
        sel = self.tree.selection()
        if not sel:
            messagebox.showinfo('Select a device', 'Click a device in the list first.')
            return None
        return int(sel[0])

    # ----- actions -----
    def add(self):
        DeviceDialog(self, self.store, None, self._saved)

    def edit(self):
        did = self.selected_id()
        if did is not None:
            DeviceDialog(self, self.store, self.store.get_device(did), self._saved)

    def delete(self):
        did = self.selected_id()
        if did is None:
            return
        d = self.store.get_device(did)
        if messagebox.askyesno('Delete device', f"Delete {d['name']} ({d['ip']})?"):
            self.store.delete_device(did)
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
        rows = [('Name', ttk.Entry(self, textvariable=self.vars['name'], width=30)),
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
        problem = validation.check_name(name) or validation.check_ip(ip)
        if bool(v['username'].strip()) != bool(v['password']):
            problem = problem or 'Enter both a login username and password, or neither.'
        existing = self.store.get_device_by_ip(ip) if not problem else None
        own_id = self.device['id'] if self.device else None
        if existing and existing['id'] != own_id:
            problem = f"A device with IP {ip} already exists ({existing['name']})."
        if problem:
            messagebox.showerror('Cannot save', problem, parent=self)
            return
        data = {'name': name, 'ip': ip, 'type': v['type'], 'status': v['status'],
                'managed': bool(v['managed'])}
        try:
            if self.device:
                did = own_id
                self.store.update_device(did, data)
            else:
                did = self.store.upsert_device(data)
            if v['username'].strip():
                self.store.save_credentials(did, v['username'].strip(), v['password'])
        except Exception as err:
            messagebox.showerror('Cannot save', str(err), parent=self)
            return
        self.destroy()
        self.on_saved()
