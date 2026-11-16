"""Configure tab: pick a device, fill in forms, Preview the commands, Apply.

Apply runs in a background thread (so the window never freezes) and hands its
result back through a queue. Only the main thread touches the window.
"""
import queue
import threading
import tkinter as tk
from tkinter import messagebox, simpledialog, ttk

import validation
from config import commands_router, commands_switch
from config import connect
from gui import theme


class ConfigureTab(ttk.Frame):
    def __init__(self, parent, store):
        super().__init__(parent, padding=theme.PAD)
        self.store = store
        self.apply_fn = connect.apply_config      # tests replace this with a fake
        self.results = queue.Queue()
        self.busy = False
        self.devices = []                         # managed devices shown in the box
        self.vlans, self.ports = [], []           # [(id, name)], [(port, vlan)]
        self._built = ([], [])                    # (commands, checks) behind the preview

        ttk.Label(self, text='Configure a device', style='Title.TLabel').pack(anchor='w')
        top = ttk.Frame(self); top.pack(fill='x', pady=(0, theme.PAD))
        ttk.Label(top, text='Device:').pack(side='left')
        self.device_var = tk.StringVar()
        self.device_box = ttk.Combobox(top, textvariable=self.device_var, width=34,
                                       state='readonly')
        self.device_box.pack(side='left', padx=theme.PAD)
        self.device_hint = ttk.Label(top, text='', foreground='#555')
        self.device_hint.pack(side='left')

        body = ttk.Frame(self); body.pack(fill='both', expand=True)
        left = ttk.Frame(body); left.pack(side='left', fill='y', padx=(0, theme.PAD))
        right = ttk.Frame(body); right.pack(side='left', fill='both', expand=True)
        self.forms = ttk.Notebook(left)             # one tab per device type: less clutter
        self.forms.pack(fill='y')
        switch_page = ttk.Frame(self.forms, padding=theme.PAD)
        router_page = ttk.Frame(self.forms, padding=theme.PAD)
        self.forms.add(switch_page, text='Switch settings')
        self.forms.add(router_page, text='Router settings')
        self._build_switch_forms(switch_page)
        self._build_router_forms(router_page)
        self.device_box.bind('<<ComboboxSelected>>', lambda e: self._show_forms_for_device())
        self._build_preview(right)
        self.refresh_devices()

    # ------------------------------------------------------------ forms
    def _build_switch_forms(self, parent):
        box = parent
        self.vid, self.vname = tk.StringVar(), tk.StringVar()
        row = ttk.Frame(box); row.pack(fill='x')
        ttk.Label(row, text='VLAN ID').grid(row=0, column=0, sticky='w')
        ttk.Label(row, text='Name').grid(row=0, column=1, sticky='w')
        ttk.Entry(row, textvariable=self.vid, width=8).grid(row=1, column=0, padx=(0, 4))
        ttk.Entry(row, textvariable=self.vname, width=16).grid(row=1, column=1, padx=(0, 4))
        ttk.Button(row, text='Add VLAN', command=self.add_vlan).grid(row=1, column=2)
        self.vlan_tree = ttk.Treeview(box, columns=('id', 'name'), show='headings', height=4)
        self.vlan_tree.heading('id', text='VLAN ID'); self.vlan_tree.heading('name', text='Name')
        self.vlan_tree.column('id', width=70); self.vlan_tree.column('name', width=150)
        self.vlan_tree.pack(fill='x', pady=4)
        ttk.Button(box, text='Remove selected VLAN', command=self.remove_vlan).pack(anchor='e')

        self.port, self.port_vlan = tk.StringVar(), tk.StringVar()
        prow = ttk.Frame(box); prow.pack(fill='x', pady=(theme.PAD, 0))
        ttk.Label(prow, text='Access port').grid(row=0, column=0, sticky='w')
        ttk.Label(prow, text='in VLAN').grid(row=0, column=1, sticky='w')
        ttk.Entry(prow, textvariable=self.port, width=10).grid(row=1, column=0, padx=(0, 4))
        self.port_vlan_box = ttk.Combobox(prow, textvariable=self.port_vlan, width=8, values=[])
        self.port_vlan_box.grid(row=1, column=1, padx=(0, 4))
        ttk.Button(prow, text='Add port', command=self.add_port).grid(row=1, column=2)
        self.port_tree = ttk.Treeview(box, columns=('port', 'vlan'), show='headings', height=3)
        self.port_tree.heading('port', text='Port'); self.port_tree.heading('vlan', text='VLAN')
        self.port_tree.column('port', width=110); self.port_tree.column('vlan', width=110)
        self.port_tree.pack(fill='x', pady=4)
        ttk.Button(box, text='Remove selected port', command=self.remove_port).pack(anchor='e')

    def _build_router_forms(self, parent):
        box = parent
        ttk.Label(box, text='Used when the selected device is a router.',
                  foreground='#555').grid(row=0, column=0, columnspan=2, sticky='w', pady=(0, 6))
        self.default_route = tk.StringVar()
        self.dhcp = {k: tk.StringVar() for k in
                     ('pool', 'network', 'mask', 'gateway', 'dns', 'ex_start', 'ex_end')}
        rows = [('Default route (next hop)', self.default_route),
                ('DHCP pool name', self.dhcp['pool']), ('DHCP network', self.dhcp['network']),
                ('DHCP mask', self.dhcp['mask']), ('DHCP gateway', self.dhcp['gateway']),
                ('DNS server', self.dhcp['dns']),
                ('Exclude from', self.dhcp['ex_start']), ('Exclude to', self.dhcp['ex_end'])]
        for r, (label, var) in enumerate(rows, start=1):
            ttk.Label(box, text=label).grid(row=r, column=0, sticky='w', pady=2)
            ttk.Entry(box, textvariable=var, width=18).grid(row=r, column=1, padx=4, pady=2)

    def _build_preview(self, parent):
        bar = ttk.Frame(parent); bar.pack(fill='x')
        ttk.Label(bar, text='Command preview (nothing is sent until you click Apply)',
                  font=theme.FONT_BOLD).pack(side='left')
        self.apply_btn = ttk.Button(bar, text='Apply', style='Accent.TButton', command=self.apply)
        self.apply_btn.pack(side='right')
        ttk.Button(bar, text='Preview', command=self.make_preview).pack(side='right', padx=4)
        self.preview = tk.Text(parent, height=12, font=('Consolas', 10), wrap='none')
        self.preview.pack(fill='both', expand=True, pady=4)
        self.status = ttk.Label(parent, text='Pick a device, fill in a form, and click Preview.')
        self.status.pack(anchor='w')
        ttk.Label(parent, text='Result', font=theme.FONT_BOLD).pack(anchor='w', pady=(theme.PAD, 0))
        self.output = tk.Text(parent, height=6, font=('Consolas', 10), wrap='word',
                              state='disabled', background='#fafafa')
        self.output.pack(fill='both', expand=True)

    # ------------------------------------------------------------ devices
    def refresh_devices(self):
        """Fill the box with the devices we can log in to (managed ones)."""
        keep = self.device_var.get()
        self.devices = [d for d in self.store.get_devices('', 'name', 1, 1000) if d['managed']]
        labels = [f"{d['name']} ({d['ip']}, {d['type']})" for d in self.devices]
        self.device_box['values'] = labels
        if keep in labels:
            self.device_var.set(keep)
        elif labels:
            self.device_box.current(0)
        else:
            self.device_var.set('')
        self.device_hint.config(text='' if labels else
                                'No managed devices yet. Run a scan and approve some.')
        self._show_forms_for_device()

    def _show_forms_for_device(self):
        device = self.selected_device()
        if device:
            self.forms.select(1 if device['type'] == 'router' else 0)

    def selected_device(self):
        i = self.device_box.current()
        return self.devices[i] if 0 <= i < len(self.devices) else None

    # ------------------------------------------------------------ VLANs and ports
    def add_vlan(self):
        problem = validation.check_vlan(self.vid.get().strip(), {v for v, _ in self.vlans}) \
            or validation.check_vlan_name(self.vname.get())
        if problem:
            messagebox.showerror('Cannot add VLAN', problem)
            return
        self.vlans.append((int(self.vid.get().strip()), self.vname.get().strip()))
        self.vid.set(''); self.vname.set('')
        self._show_lists()

    def remove_vlan(self):
        for item in self.vlan_tree.selection():
            del self.vlans[self.vlan_tree.index(item)]
        self._show_lists()

    def add_port(self):
        problem = validation.check_port(self.port.get()) \
            or validation.check_vlan(self.port_vlan.get().strip(), ())
        if problem:
            messagebox.showerror('Cannot add port', problem)
            return
        self.ports.append((self.port.get().strip(), int(self.port_vlan.get().strip())))
        self.port.set('')
        self._show_lists()

    def remove_port(self):
        for item in self.port_tree.selection():
            del self.ports[self.port_tree.index(item)]
        self._show_lists()

    def _show_lists(self):
        self.vlan_tree.delete(*self.vlan_tree.get_children())
        for vid, name in self.vlans:
            self.vlan_tree.insert('', 'end', values=(vid, name))
        self.port_tree.delete(*self.port_tree.get_children())
        for port, vid in self.ports:
            self.port_tree.insert('', 'end', values=(port, vid))
        self.port_vlan_box['values'] = [v for v, _ in self.vlans]

    # ------------------------------------------------------------ preview
    def _build_plan(self, device):
        """Returns (commands, checks) for the device, or None after showing a message."""
        if device['type'] == 'router':
            plan, selected = {}, []
            route = self.default_route.get().strip()
            if route:
                problem = validation.check_ip(route)
                if problem:
                    messagebox.showerror('Default route', problem); return None
                plan['default_route'] = route; selected.append('Default route')
            d = {k: v.get().strip() for k, v in self.dhcp.items()}
            if any(d.values()):
                problem = (validation.check_name(d['pool']) or validation.check_ip(d['network'])
                           or validation.check_mask(d['mask']) or validation.check_ip(d['gateway'])
                           or validation.check_ip(d['dns']))
                if d['ex_start'] or d['ex_end']:
                    problem = problem or validation.check_ip(d['ex_start']) \
                        or validation.check_ip(d['ex_end'])
                if problem:
                    messagebox.showerror('DHCP settings', problem); return None
                plan['dhcp'] = {'pool': d['pool'], 'network': d['network'], 'mask': d['mask'],
                                'gateway': d['gateway'], 'dns': d['dns'],
                                'excluded': (d['ex_start'], d['ex_end']) if d['ex_start'] else None}
                selected.append('DHCP')
            return commands_router.build_commands(plan, selected)
        plan = {'vlans': list(self.vlans), 'access_ports': list(self.ports)}
        selected = (['VLANs'] if self.vlans else []) + (['Access ports'] if self.ports else [])
        return commands_switch.build_commands(plan, selected)

    def make_preview(self):
        device = self.selected_device()
        if not device:
            messagebox.showinfo('Select a device', 'Pick a managed device first. '
                                'Run a scan and approve devices if the list is empty.')
            return
        built = self._build_plan(device)
        if built is None:
            return
        commands, checks = built
        if not commands:
            messagebox.showinfo('Nothing to preview', 'Fill in at least one setting '
                                '(a VLAN, an access port, a route, or DHCP) for this device.')
            return
        self._built = (list(commands), list(checks))
        self._set_preview(commands)
        self.status.config(text=f'{len(commands)} commands for {device["name"]}. '
                                f'Read them, then click Apply.')

    def _set_preview(self, commands):
        self.preview.delete('1.0', 'end')
        self.preview.insert('1.0', '\n'.join(commands))

    def commands_from_preview(self):
        """The commands in the preview box (blank lines and # comments left out)."""
        lines = [l.strip() for l in self.preview.get('1.0', 'end').splitlines()]
        return [l for l in lines if l and not l.startswith('#')]

    def load_commands(self, commands, device_name):
        """Used by the Findings tab: 'Send to Configure'."""
        self.refresh_devices()
        for i, d in enumerate(self.devices):
            if d['name'] == device_name:
                self.device_box.current(i)
        self._show_forms_for_device()
        self._set_preview(commands)
        self._built = ([c.strip() for c in commands if c.strip() and not c.startswith('#')], [])
        self.status.config(text=f'Loaded {len(commands)} suggested lines for {device_name}. '
                                f'Check and edit them, then click Apply.')

    # ------------------------------------------------------------ apply
    def _creds(self, device):
        user, password = self.store.get_credentials(device['id'])
        if not user:
            user = simpledialog.askstring('Login', f"Username for {device['name']}:", parent=self)
            if not user:
                return None
            password = simpledialog.askstring('Login', f"Password for {device['name']}:",
                                              show='*', parent=self)
            if password is None:
                return None
        return {'host': device['ip'], 'username': user, 'password': password}

    def apply(self):
        if self.busy:
            return
        device, commands = self.selected_device(), self.commands_from_preview()
        if not device:
            messagebox.showinfo('Select a device', 'Pick a managed device first.')
            return
        if not commands:
            messagebox.showinfo('Nothing to apply', 'Click Preview first, so you can read '
                                'the commands before they are sent.')
            return
        checks = self._built[1] if commands == self._built[0] else []
        if not messagebox.askyesno('Apply to device',
                                   f"Send {len(commands)} commands to {device['name']} "
                                   f"({device['ip']})?\n\nA backup of its configuration is "
                                   f"saved first, and the result is checked afterwards."):
            return
        creds = self._creds(device)
        if not creds:
            return
        self.busy = True
        self.apply_btn.state(['disabled'])
        self.status.config(text=f"Applying to {device['name']}... please wait.")
        threading.Thread(target=self._worker, args=(device, creds, commands, checks),
                         daemon=True).start()
        self.after(200, self.check_queue)

    def _worker(self, device, creds, commands, checks):
        try:
            ok, message = self.apply_fn(creds, commands, checks)
        except Exception as err:
            ok, message = False, f'Error: {type(err).__name__}: {err}'
        self.results.put((device, ok, message))

    def check_queue(self):
        try:
            device, ok, message = self.results.get_nowait()
        except queue.Empty:
            self.after(200, self.check_queue)
            return
        self.busy = False
        self.apply_btn.state(['!disabled'])
        try:
            self.store.add_log(device['id'], 'Configuration', 'success' if ok else 'failed', message)
        except Exception as err:
            message += f'  (could not write the log: {err})'
        self.output.config(state='normal')
        self.output.insert('end', f"[{'OK' if ok else 'FAILED'}] {device['name']}: {message}\n")
        self.output.see('end')
        self.output.config(state='disabled')
        self.status.config(text='Done.' if ok else 'The change did not complete. See the result.')
        if not ok:
            messagebox.showerror('Apply failed', message)
