"""Configure tab: pick one or more devices, fill in forms, Preview, Apply.

    +-------------+--------------------------+-------------------------------+
    |  DEVICES    |  SETTINGS                |  PREVIEW  (one section per    |
    |  [x] SW1    |  Switch | Router         |            device)            |
    |  [x] SW2    |   VLANs | Trunks | ...   +-------------------------------+
    |  [ ] R1     |   (scrolls when needed)  |  SSH SESSION (live)           |
    +-------------+--------------------------+-------------------------------+
    The three columns, and the preview / session split, can be resized.

Switch settings are only ever sent to switches and router settings to routers;
the preview lists every device that will receive the change and every device
that is skipped, with the reason. Nothing is sent until Apply is clicked.

Apply runs in a background thread (the window never freezes) and configures the
devices one after the other through config.multi.run_devices, which calls
apply_config for each: every device gets its own backup, checks and save. The
SSH session console shows each device's real commands and replies; the worker
thread only posts into queues, and only the window's own thread touches widgets.
"""
import inspect
import queue
import re
import threading
import tkinter as tk
from tkinter import messagebox, simpledialog, ttk

import validation
from config import commands_router, commands_switch
from config import connect, multi
from config.interfaces import parse_ports, port_count
from gui import theme
from gui.components.device_picker import DevicePicker, plural
from gui.components.list_editor import ListEditor, wrap_to_width
from gui.components.scroll_frame import ScrollFrame
from gui.components.ssh_console import SshConsole

PORT_HINT = 'One port, a range or a list: Fa0/1   Fa0/1-5   Fa0/1-Fa0/5   Fa0/1-5, Gi0/1'
KIND_OF_TAB = ['switch', 'router']              # self.forms tab index -> configuration kind
# '# ===== SW1  10.0.0.2  switch  |  Switch settings =====' starts a device's section
HEADER = re.compile(r'^#\s*=====\s*(\S+)\s+(\S+)\s+(\S+)\s+\|\s*(.+?)\s*=====\s*$')


def accepts_log(fn):
    """Can fn take a log= keyword? (Test fakes that take 3 arguments cannot.)"""
    try:
        params = inspect.signature(fn).parameters.values()
    except (TypeError, ValueError):
        return False
    return any(p.name == 'log' or p.kind == p.VAR_KEYWORD for p in params)


def header_line(device, label):
    return f"# ===== {device['name']}  {device['ip']}  {device['type']}  |  {label} ====="


def kind_of_label(label):
    for kind, text in multi.KINDS.items():
        if text == label:
            return kind
    return multi.CUSTOM


class _DeviceBox:
    """The old single-device box, kept so existing callers keep working:
    current() is the index of the (first) selected device; current(i) selects
    device i alone."""
    def __init__(self, tab):
        self.tab = tab

    def current(self, index=None):
        if index is None:
            d = self.tab.selected_device()
            return self.tab.devices.index(d) if d else -1
        self.tab.picker.select_only(self.tab.devices[index]['id'])
        return None

    def event_generate(self, *args, **kwargs):
        self.tab._show_forms_for_device()


def _caption(parent, text):
    return ttk.Label(parent, text=text, font=theme.mono(9, 'bold'), foreground=theme.TEXT_MUTED)


class ConfigureTab(ttk.Frame):
    def __init__(self, parent, store, log=None):
        """log(source, message, level): the workbench console, for one-line summaries."""
        super().__init__(parent, padding=(theme.PAD, 4, theme.PAD, theme.PAD))
        self.store = store
        self.log = log or (lambda *a, **k: None)
        self.apply_fn = connect.apply_config      # tests replace this with a fake
        self.results = queue.Queue()
        self.busy = False
        self.devices = []                         # managed devices offered in the picker
        self.vlans, self.ports = [], []           # [(id, name)], [(ports, vlan)]
        self._built = {}                          # device id -> (commands, checks) of the preview
        self._stop = threading.Event()
        self._auto_selected = False
        self.device_box = _DeviceBox(self)        # the old single-device API

        head = ttk.Frame(self)
        head.pack(fill='x', pady=(0, 6))
        ttk.Label(head, text='Configure devices', style='Title.TLabel').pack(side='left')
        ttk.Label(head, text='Tick one or more devices, fill in the settings, click Preview, '
                             'then Apply.', foreground=theme.TEXT_MUTED).pack(side='left', padx=12)

        self.columns = ttk.PanedWindow(self, orient='horizontal', style='Workbench.TPanedwindow')
        self.columns.pack(fill='both', expand=True)
        left = ttk.Frame(self.columns, padding=(0, 0, 10, 0))
        middle = ttk.Frame(self.columns, padding=(10, 0, 10, 0))
        right = ttk.Frame(self.columns, padding=(10, 0, 0, 0))
        self.columns.add(left, weight=0)
        self.columns.add(middle, weight=1)
        self.columns.add(right, weight=2)

        # ---- devices
        _caption(left, 'DEVICES').pack(anchor='w', pady=(0, 6))
        self.picker = DevicePicker(left, on_change=self._show_forms_for_device)
        self.picker.pack(fill='both', expand=True)
        self.device_hint = self.picker.empty

        # ---- settings
        _caption(middle, 'SETTINGS').pack(anchor='w', pady=(0, 2))
        self.target_note = ttk.Label(middle, text='', foreground=theme.TEXT_SOFT)
        self.target_note.pack(anchor='w', fill='x', pady=(0, 6))
        wrap_to_width(self.target_note)
        self.settings = ScrollFrame(middle)
        self.settings.pack(fill='both', expand=True)
        self.forms = ttk.Notebook(self.settings.inner)   # one tab per device type
        self.forms.pack(fill='both', expand=True, padx=(0, 4))
        switch_page = ttk.Frame(self.forms, padding=6)
        router_page = ttk.Frame(self.forms, padding=6)
        self.forms.add(switch_page, text='Switch settings')
        self.forms.add(router_page, text='Router settings')
        self._build_switch_forms(switch_page)
        self._build_router_forms(router_page)
        self.forms.bind('<<NotebookTabChanged>>', lambda e: self._update_target_note())

        # ---- preview and session
        self.right = ttk.PanedWindow(right, orient='vertical', style='Workbench.TPanedwindow')
        self.right.pack(fill='both', expand=True)
        top, bottom = ttk.Frame(self.right, padding=(0, 0, 0, 8)), ttk.Frame(self.right,
                                                                            padding=(0, 8, 0, 0))
        self.right.add(top, weight=2)
        self.right.add(bottom, weight=3)
        self._build_preview(top)
        self.session = SshConsole(bottom)
        self.session.pack(fill='both', expand=True)
        self._placed = False
        self.bind('<Configure>', self._place_dividers, add='+')
        self.refresh_devices()

    def _place_dividers(self, event=None):
        """Sensible starting sizes, once the page has its real size."""
        if self._placed:
            return
        width, height = self.columns.winfo_width(), self.right.winfo_height()
        if width < 500 or height < 200:
            return
        self._placed = True
        self.columns.sashpos(0, int(width * 0.22))
        self.columns.sashpos(1, int(width * 0.56))
        self.right.sashpos(0, int(height * 0.5))

    # ------------------------------------------------------------ switch forms
    def _build_switch_forms(self, parent):
        tabs = ttk.Notebook(parent)
        tabs.pack(fill='both', expand=True)
        self.switch_tabs = tabs
        vlan_page = ttk.Frame(tabs, padding=10)
        tabs.add(vlan_page, text='VLANs & access')
        self._build_vlan_access(vlan_page)

        trunk_page = ttk.Frame(tabs, padding=10)
        tabs.add(trunk_page, text='Trunks')
        self.trunk_editor = ListEditor(
            trunk_page, 'trunk',
            [{'key': 'ports', 'label': 'Ports', 'width': 16},
             {'key': 'allowed', 'label': 'Allowed VLANs', 'width': 14},
             {'key': 'native', 'label': 'Native VLAN', 'width': 8},
             {'key': 'encapsulation', 'label': 'encapsulation dot1q', 'kind': 'check',
              'default': 1}],
            [('ports', 'Ports', 110), ('allowed', 'Allowed', 90), ('native', 'Native', 60)],
            self._validate_trunk,
            note=PORT_HINT + '.  Allowed VLANs: for example 10,20,30-40 (empty = all).  '
                 'Untick dot1q on switches that only do 802.1Q (they reject the command).')
        self.trunk_editor.pack(fill='both', expand=True)

        sec_page = ttk.Frame(tabs, padding=10)
        tabs.add(sec_page, text='Port security')
        self.security_editor = ListEditor(
            sec_page, 'port security',
            [{'key': 'ports', 'label': 'Access ports', 'width': 16},
             {'key': 'maximum', 'label': 'Max MAC addresses', 'width': 6, 'default': '2'},
             {'key': 'violation', 'label': 'On violation', 'kind': 'combo',
              'values': ['shutdown', 'restrict', 'protect'], 'default': 'shutdown'},
             {'key': 'sticky', 'label': 'Learn MACs (sticky)', 'kind': 'check', 'default': 1}],
            [('ports', 'Ports', 110), ('maximum', 'Max', 45), ('violation', 'Violation', 80),
             ('sticky', 'Sticky', 55)],
            self._validate_port_security,
            note=PORT_HINT + '.  The ports are also set to access mode.')
        self.security_editor.pack(fill='both', expand=True)

        if_page = ttk.Frame(tabs, padding=10)
        tabs.add(if_page, text='Interfaces')
        self.switch_if_editor = ListEditor(
            if_page, 'interface',
            [{'key': 'ports', 'label': 'Ports', 'width': 16},
             {'key': 'state', 'label': 'State', 'kind': 'combo',
              'values': ['(leave)', 'no shutdown', 'shutdown'], 'default': '(leave)'},
             {'key': 'description', 'label': 'Description', 'width': 34}],
            [('ports', 'Ports', 110), ('state', 'State', 90), ('description', 'Description', 140)],
            self._validate_switch_interface,
            note=PORT_HINT + '.  "shutdown" turns the ports off; "no shutdown" turns them on.')
        self.switch_if_editor.pack(fill='both', expand=True)

    def _build_vlan_access(self, box):
        self.vid, self.vname = tk.StringVar(), tk.StringVar()
        row = ttk.Frame(box); row.pack(fill='x')
        ttk.Label(row, text='VLAN ID').grid(row=0, column=0, sticky='w')
        ttk.Label(row, text='Name').grid(row=0, column=1, sticky='w')
        ttk.Entry(row, textvariable=self.vid, width=8).grid(row=1, column=0, padx=(0, 8), pady=2)
        ttk.Entry(row, textvariable=self.vname, width=18).grid(row=1, column=1, padx=(0, 8),
                                                               pady=2)
        ttk.Button(row, text='Add VLAN', command=self.add_vlan).grid(row=1, column=2, pady=2)
        self.vlan_tree = ttk.Treeview(box, columns=('id', 'name'), show='headings', height=4)
        self.vlan_tree.heading('id', text='VLAN ID'); self.vlan_tree.heading('name', text='Name')
        self.vlan_tree.column('id', width=80, minwidth=70, stretch=False)
        self.vlan_tree.column('name', width=150, minwidth=80)
        self.vlan_tree.pack(fill='x', pady=(8, 4))
        ttk.Button(box, text='Remove selected VLAN', command=self.remove_vlan).pack(anchor='e')

        ttk.Separator(box).pack(fill='x', pady=12)
        self.port, self.port_vlan = tk.StringVar(), tk.StringVar()
        prow = ttk.Frame(box); prow.pack(fill='x')
        ttk.Label(prow, text='Access ports').grid(row=0, column=0, sticky='w')
        ttk.Label(prow, text='in VLAN').grid(row=0, column=1, sticky='w')
        ttk.Entry(prow, textvariable=self.port, width=20).grid(row=1, column=0, padx=(0, 8),
                                                               pady=2)
        self.port_vlan_box = ttk.Combobox(prow, textvariable=self.port_vlan, width=8, values=[])
        self.port_vlan_box.grid(row=1, column=1, padx=(0, 8), pady=2)
        ttk.Button(prow, text='Add ports', command=self.add_port).grid(row=1, column=2, pady=2)
        hint = ttk.Label(box, text=PORT_HINT, foreground=theme.TEXT_MUTED, justify='left')
        hint.pack(anchor='w', fill='x', pady=(4, 0))
        wrap_to_width(hint)
        self.port_tree = ttk.Treeview(box, columns=('port', 'vlan'), show='headings', height=3)
        self.port_tree.heading('port', text='Ports'); self.port_tree.heading('vlan', text='VLAN')
        self.port_tree.column('port', width=170, minwidth=100)
        self.port_tree.column('vlan', width=70, minwidth=60, stretch=False)
        self.port_tree.pack(fill='x', pady=(8, 4))
        ttk.Button(box, text='Remove selected ports', command=self.remove_port).pack(anchor='e')

    # ------------------------------------------------------------ router forms
    def _build_router_forms(self, parent):
        tabs = ttk.Notebook(parent)
        tabs.pack(fill='both', expand=True)
        self.router_tabs = tabs
        basics = ttk.Frame(tabs, padding=10)
        tabs.add(basics, text='Basics')
        note = ttk.Label(basics, text='Leave a field empty to skip it. A hostname can only be set '
                                      'on one router at a time.', foreground=theme.TEXT_MUTED,
                         justify='left')
        note.grid(row=0, column=0, columnspan=2, sticky='ew', pady=(0, 8))
        wrap_to_width(note)
        basics.grid_columnconfigure(1, weight=1)
        self.hostname, self.default_route = tk.StringVar(), tk.StringVar()
        self.dns_servers, self.ntp_server = tk.StringVar(), tk.StringVar()
        rows = [('Hostname', self.hostname), ('Default route (next hop)', self.default_route),
                ('DNS servers (comma list)', self.dns_servers), ('NTP server', self.ntp_server)]
        for r, (label, var) in enumerate(rows, start=1):
            ttk.Label(basics, text=label).grid(row=r, column=0, sticky='w', pady=3)
            ttk.Entry(basics, textvariable=var, width=20).grid(row=r, column=1, sticky='w',
                                                               padx=8, pady=3)

        dhcp_page = ttk.Frame(tabs, padding=10)
        tabs.add(dhcp_page, text='DHCP')
        self.dhcp = {k: tk.StringVar() for k in
                     ('pool', 'network', 'mask', 'gateway', 'dns', 'ex_start', 'ex_end')}
        rows = [('DHCP pool name', self.dhcp['pool']), ('DHCP network', self.dhcp['network']),
                ('DHCP mask', self.dhcp['mask']), ('DHCP gateway', self.dhcp['gateway']),
                ('DNS server', self.dhcp['dns']),
                ('Exclude from', self.dhcp['ex_start']), ('Exclude to', self.dhcp['ex_end'])]
        for r, (label, var) in enumerate(rows):
            ttk.Label(dhcp_page, text=label).grid(row=r, column=0, sticky='w', pady=3)
            ttk.Entry(dhcp_page, textvariable=var, width=20).grid(row=r, column=1, sticky='w',
                                                                  padx=8, pady=3)

        if_page = ttk.Frame(tabs, padding=10)
        tabs.add(if_page, text='Interfaces')
        self.router_if_editor = ListEditor(
            if_page, 'router interface',
            [{'key': 'name', 'label': 'Interface', 'width': 12},
             {'key': 'state', 'label': 'State', 'kind': 'combo',
              'values': ['(leave)', 'no shutdown', 'shutdown'], 'default': 'no shutdown'},
             {'key': 'ip', 'label': 'IP address', 'width': 15},
             {'key': 'mask', 'label': 'Subnet mask', 'width': 15},
             {'key': 'description', 'label': 'Description', 'width': 30}],
            [('name', 'Interface', 80), ('ip', 'IP', 105), ('mask', 'Mask', 105),
             ('state', 'State', 90)],
            self._validate_router_interface,
            note='One interface, for example Gi0/0. Leave the IP empty to change only the '
                 'state or description. IP addresses can only be set on one router at a time.')
        self.router_if_editor.pack(fill='both', expand=True)

        route_page = ttk.Frame(tabs, padding=10)
        tabs.add(route_page, text='Static routes')
        self.route_editor = ListEditor(
            route_page, 'static route',
            [{'key': 'network', 'label': 'Destination network', 'width': 15},
             {'key': 'mask', 'label': 'Subnet mask', 'width': 15},
             {'key': 'next_hop', 'label': 'Next hop', 'width': 15}],
            [('network', 'Network', 105), ('mask', 'Mask', 105), ('next_hop', 'Next hop', 105)],
            self._validate_route,
            note='For example 10.10.0.0  255.255.0.0  via 192.168.1.254. '
                 'Use Basics for the default route.')
        self.route_editor.pack(fill='both', expand=True)

    # ------------------------------------------------------------ preview area
    def _build_preview(self, parent):
        bar = ttk.Frame(parent); bar.pack(fill='x', pady=(0, 6))
        _caption(bar, 'PREVIEW').pack(side='left')
        ttk.Label(bar, text='  nothing is sent until you click Apply',
                  foreground=theme.TEXT_MUTED).pack(side='left')
        self.apply_btn = ttk.Button(bar, text='Apply', style='Accent.TButton', command=self.apply)
        self.apply_btn.pack(side='right')
        ttk.Button(bar, text='Preview', command=self.make_preview).pack(side='right', padx=6)
        self.stop_btn = ttk.Button(bar, text='Stop', command=self.stop)
        self.stop_btn.pack(side='right')
        self.stop_btn.state(['disabled'])

        holder = ttk.Frame(parent)
        holder.pack(fill='both', expand=True)
        holder.grid_columnconfigure(0, weight=1)
        holder.grid_rowconfigure(0, weight=1)
        self.preview = tk.Text(holder, height=8, font=theme.mono(10), wrap='none', undo=True,
                               relief='solid', borderwidth=1, padx=8, pady=6)
        ys = ttk.Scrollbar(holder, orient='vertical', command=self.preview.yview)
        xs = ttk.Scrollbar(holder, orient='horizontal', command=self.preview.xview)
        self.preview.configure(yscrollcommand=ys.set, xscrollcommand=xs.set)
        self.preview.grid(row=0, column=0, sticky='nsew')
        ys.grid(row=0, column=1, sticky='ns')
        xs.grid(row=1, column=0, sticky='ew')
        self.preview.tag_configure('comment', foreground=theme.TEXT_MUTED)
        self.preview.tag_configure('header', foreground=theme.ACCENT, font=theme.mono(10, 'bold'))
        self.preview.tag_configure('skipped', foreground=theme.WARNING)

        foot = ttk.Frame(parent); foot.pack(fill='x', pady=(6, 0))
        self.stop_on_failure = tk.IntVar(value=0)
        ttk.Checkbutton(foot, text='Stop at the first device that fails',
                        variable=self.stop_on_failure).pack(side='right')
        self.status = ttk.Label(foot, text='Tick a device, fill in the settings, and click Preview.')
        self.status.pack(side='left', fill='x', expand=True)
        wrap_to_width(self.status)

    # ------------------------------------------------------------ devices
    def refresh_devices(self):
        """Offer the devices we can log in to (managed ones). Ticks are kept."""
        self.devices = [d for d in self.store.get_devices('', 'name', 1, 1000) if d['managed']]
        self.picker.set_devices(self.devices)
        if self.devices and not self._auto_selected and not self.picker.checked:
            self._auto_selected = True             # the first time: one device, as before
            self.picker.set_checked([self.devices[0]['id']], notify=False)
        self._show_forms_for_device()

    def selected_devices(self):
        return self.picker.selected()

    def selected_device(self):
        """The first selected device (the single-device API), or None."""
        chosen = self.picker.selected()
        return chosen[0] if chosen else None

    def select_device(self, name):
        """Select only this device. False when it is not a managed device."""
        for d in self.devices:
            if d['name'] == name:
                self.picker.select_only(d['id'])
                return True
        return False

    def _show_forms_for_device(self):
        """Show the settings that fit the selection (all switches / all routers)."""
        types = {d['type'] for d in self.selected_devices()}
        if types == {'router'}:
            self.forms.select(1)
        elif types == {'switch'}:
            self.forms.select(0)
        self._update_target_note()

    def config_kind(self):
        return KIND_OF_TAB[self.forms.index(self.forms.select())]

    def _update_target_note(self):
        chosen = self.selected_devices()
        kind = self.config_kind()
        targets, skipped = multi.split_targets(chosen, kind)
        if not chosen:
            text = 'No device selected.'
        else:
            text = f'{multi.KINDS[kind]} will go to {plural(len(targets), kind)}'
            if targets and len(targets) <= 4:
                text += ': ' + ', '.join(d['name'] for d in targets)
            if skipped:
                text += f'.  Skipped (not a {kind}): ' + ', '.join(d['name'] for d, _ in skipped)
        self.target_note.config(text=text)

    # ------------------------------------------------------------ VLANs and access ports
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
        for item in sorted(self.vlan_tree.selection(), key=lambda i: -self.vlan_tree.index(i)):
            del self.vlans[self.vlan_tree.index(item)]
        self._show_lists()

    def add_port(self):
        spec = self.port.get().strip()
        problem = validation.check_port_list(spec) \
            or validation.check_vlan(self.port_vlan.get().strip(), ()) \
            or self._ports_unused(spec, [p for p, _ in self.ports])
        if problem:
            messagebox.showerror('Cannot add ports', problem)
            return
        self.ports.append((spec, int(self.port_vlan.get().strip())))
        self.port.set('')
        self._show_lists()

    def remove_port(self):
        for item in sorted(self.port_tree.selection(), key=lambda i: -self.port_tree.index(i)):
            del self.ports[self.port_tree.index(item)]
        self._show_lists()

    def _show_lists(self):
        self.vlan_tree.delete(*self.vlan_tree.get_children())
        for vid, name in self.vlans:
            self.vlan_tree.insert('', 'end', values=(vid, name))
        self.port_tree.delete(*self.port_tree.get_children())
        for port, vid in self.ports:
            n = port_count(port)
            self.port_tree.insert('', 'end', values=(port if n == 1 else f'{port}  ({n} ports)', vid))
        self.port_vlan_box['values'] = [v for v, _ in self.vlans]

    @staticmethod
    def _ports_unused(spec, others):
        """The same port must not be listed twice in one form."""
        mine = _port_set(spec)
        for other in others:
            both = mine & _port_set(other)
            if both:
                kind, prefix, p = sorted(both)[0]
                return f'{kind}{prefix}{p} is already in the list ({other}).'
        return None

    # ------------------------------------------------------------ validation of list items
    def _validate_trunk(self, v, items):
        problem = validation.check_port_list(v['ports']) \
            or self._ports_unused(v['ports'], [i['ports'] for i in items])
        if not problem and v['allowed']:
            problem = validation.check_vlan_list(v['allowed'])
        if not problem and v['native']:
            problem = validation.check_vlan_number(v['native'], allow_1=True)
        if problem:
            return problem, None
        allowed = validation.compress_vlans(validation.vlan_list(v['allowed'])) if v['allowed'] else ''
        return None, {'ports': v['ports'], 'allowed': allowed,
                      'native': int(v['native']) if v['native'] else None,
                      'encapsulation': v['encapsulation']}

    def _validate_port_security(self, v, items):
        problem = validation.check_port_list(v['ports']) \
            or self._ports_unused(v['ports'], [i['ports'] for i in items])
        if not problem and not (v['maximum'].isdigit() and 1 <= int(v['maximum']) <= 132):
            problem = 'Max MAC addresses must be a number from 1 to 132.'
        if problem:
            return problem, None
        return None, {'ports': v['ports'], 'maximum': int(v['maximum']),
                      'violation': v['violation'] or 'shutdown', 'sticky': v['sticky']}

    def _validate_switch_interface(self, v, items):
        problem = validation.check_port_list(v['ports']) \
            or self._ports_unused(v['ports'], [i['ports'] for i in items])
        state = '' if v['state'] in ('', '(leave)') else v['state']
        if not problem and not state and not v['description']:
            problem = 'Choose a state or type a description (or both).'
        if not problem and v['description']:
            problem = validation.check_description(v['description'])
        if problem:
            return problem, None
        return None, {'ports': v['ports'], 'state': state, 'description': v['description']}

    def _validate_router_interface(self, v, items):
        problem = validation.check_single_interface(v['name'])
        if not problem and any(_port_set(i['name']) & _port_set(v['name']) for i in items):
            problem = f"{v['name']} is already in the list."
        state = '' if v['state'] in ('', '(leave)') else v['state']
        if not problem and (v['ip'] or v['mask']):
            problem = validation.check_host_address(v['ip'], v['mask'])
        if not problem and v['description']:
            problem = validation.check_description(v['description'])
        if not problem and not (v['ip'] or state or v['description']):
            problem = 'Enter an IP address, a state or a description.'
        if problem:
            return problem, None
        return None, {'name': v['name'], 'ip': v['ip'], 'mask': v['mask'], 'state': state,
                      'description': v['description']}

    def _validate_route(self, v, items):
        problem = validation.check_network(v['network'], v['mask']) \
            or validation.check_ip(v['next_hop'])
        if not problem and (v['network'], v['mask']) in [(i['network'], i['mask']) for i in items]:
            problem = f"A route to {v['network']} {v['mask']} is already in the list."
        if not problem and v['network'] == '0.0.0.0':
            problem = 'Use the Default route field (Basics) for 0.0.0.0.'
        if problem:
            return problem, None
        return None, {'network': v['network'], 'mask': v['mask'], 'next_hop': v['next_hop']}

    # ------------------------------------------------------------ building the commands
    def _build_plan(self, kind, count=1):
        """(commands, checks, feature names) for `count` devices of this kind,
        or None after showing a message."""
        if kind == 'router':
            return self._router_plan(count)
        plan = {'vlans': list(self.vlans), 'access_ports': list(self.ports),
                'trunks': list(self.trunk_editor.items),
                'port_security': list(self.security_editor.items),
                'interfaces': list(self.switch_if_editor.items)}
        names = [('VLANs', 'vlans'), ('Access ports', 'access_ports'), ('Trunk ports', 'trunks'),
                 ('Port security', 'port_security'), ('Interface settings', 'interfaces')]
        selected = [feature for feature, key in names if plan[key]]
        return commands_switch.build_commands(plan, selected) + (selected,)

    def _router_plan(self, count=1):
        plan, selected = {}, []

        def fail(title, problem):
            messagebox.showerror(title, problem)
            return None
        hostname = self.hostname.get().strip()
        if hostname:
            problem = validation.check_hostname(hostname)
            if not problem and count > 1:
                problem = (f'A hostname must be unique, but {count} routers are selected. '
                           f'Select one router to set its hostname, or clear the field.')
            if problem:
                return fail('Hostname', problem)
            plan['hostname'] = hostname; selected.append('Hostname')
        route = self.default_route.get().strip()
        if route:
            problem = validation.check_ip(route)
            if problem:
                return fail('Default route', problem)
            plan['default_route'] = route; selected.append('Default route')
        dns = [s.strip() for s in self.dns_servers.get().split(',') if s.strip()]
        for server in dns:
            problem = validation.check_ip(server)
            if problem:
                return fail('DNS servers', problem)
        if dns:
            plan['dns_servers'] = dns; selected.append('DNS servers')
        ntp = self.ntp_server.get().strip()
        if ntp:
            problem = validation.check_ip(ntp)
            if problem:
                return fail('NTP server', problem)
            plan['ntp_server'] = ntp; selected.append('NTP')
        d = {k: v.get().strip() for k, v in self.dhcp.items()}
        if any(d.values()):
            problem = (validation.check_name(d['pool'])
                       or validation.check_network(d['network'], d['mask'])
                       or validation.check_ip_in_network(d['gateway'], d['network'], d['mask'],
                                                         'The DHCP gateway')
                       or validation.check_ip(d['dns']))
            if not problem and (d['ex_start'] or d['ex_end']):
                problem = validation.check_ip_order(d['ex_start'], d['ex_end']) \
                    or validation.check_ip_in_network(d['ex_start'], d['network'], d['mask'],
                                                      'The excluded range start') \
                    or validation.check_ip_in_network(d['ex_end'], d['network'], d['mask'],
                                                      'The excluded range end')
            if problem:
                return fail('DHCP settings', problem)
            plan['dhcp'] = {'pool': d['pool'], 'network': d['network'], 'mask': d['mask'],
                            'gateway': d['gateway'], 'dns': d['dns'],
                            'excluded': (d['ex_start'], d['ex_end']) if d['ex_start'] else None}
            selected.append('DHCP')
        if self.router_if_editor.items:
            with_ip = [i['name'] for i in self.router_if_editor.items if i['ip']]
            if with_ip and count > 1:
                return fail('Interfaces', f'IP addresses must be unique, but {count} routers are '
                                          f'selected ({", ".join(with_ip)} has an address). '
                                          f'Select one router, or remove the IP addresses.')
            plan['interfaces'] = list(self.router_if_editor.items); selected.append('Interfaces')
        if self.route_editor.items:
            plan['static_routes'] = [(r['network'], r['mask'], r['next_hop'])
                                     for r in self.route_editor.items]
            selected.append('Static routes')
        return commands_router.build_commands(plan, selected) + (selected,)

    # ------------------------------------------------------------ preview
    def make_preview(self):
        chosen = self.selected_devices()
        if not chosen:
            messagebox.showinfo('Select a device', 'Tick at least one managed device first. '
                                'Run a scan and approve devices if the list is empty.')
            return
        kind = self.config_kind()
        targets, skipped = multi.split_targets(chosen, kind)
        if not targets:
            messagebox.showinfo('No compatible device',
                                f'None of the selected devices can receive '
                                f'{multi.KINDS[kind].lower()}:\n\n'
                                + '\n'.join(f"{d['name']}: {why}" for d, why in skipped))
            return
        built = self._build_plan(kind, len(targets))
        if built is None:
            return
        commands, checks, features = built
        if not commands:
            messagebox.showinfo('Nothing to preview', 'Fill in at least one setting '
                                '(a VLAN, ports, a trunk, a route, DHCP...) first.')
            return
        label = multi.KINDS[kind]
        lines = [(f'# {label} for {len(targets)} device{"" if len(targets) == 1 else "s"}: '
                  f'{", ".join(features)}', 'comment')]
        if len(targets) > 1:
            lines.append(('# Every device gets the same commands, its own backup, its own '
                          'checks, and is saved only if its checks pass.', 'comment'))
            lines.append(('# Edit a section to change what one device receives.', 'comment'))
        for d, why in skipped:
            lines.append((f"# SKIPPED  {d['name']}  {d['ip']}  {d['type']}: {why}", 'skipped'))
        self._built = {}
        for d in targets:
            lines += [('', None), (header_line(d, label), 'header')]
            lines += [(c, None) for c in commands]
            if checks:
                lines += [(f'#   check: {show}  ->  {expected!r}' if '\n' in expected else
                           f'#   check: {show}  ->  {expected}', 'comment')
                          for show, expected in checks]
            else:
                lines.append(('#   no automatic check for these commands', 'comment'))
            self._built[d['id']] = (list(commands), list(checks))
        self._set_preview_lines(lines)
        text = f'{len(commands)} commands for {plural(len(targets), "device")}'
        if skipped:
            text += f', {len(skipped)} skipped'
        self.status.config(text=text + '. Read them, then click Apply.')

    def _set_preview_lines(self, lines):
        self.preview.delete('1.0', 'end')
        for i, (text, tag) in enumerate(lines):
            self.preview.insert('end', text + ('\n' if i < len(lines) - 1 else ''),
                                (tag,) if tag else ())

    def _set_preview(self, commands):
        self._set_preview_lines([(c, None) for c in commands])

    def commands_from_preview(self):
        """Every command in the preview (blank lines and # comments left out)."""
        lines = [l.strip() for l in self.preview.get('1.0', 'end').splitlines()]
        return [l for l in lines if l and not l.startswith('#')]

    def blocks_from_preview(self):
        """The preview split into device sections.
        -> ([{'name', 'ip', 'type', 'label', 'commands'}], commands before any section)"""
        blocks, loose, current = [], [], None
        for raw in self.preview.get('1.0', 'end').splitlines():
            line = raw.strip()
            m = HEADER.match(line)
            if m:
                current = {'name': m.group(1), 'ip': m.group(2), 'type': m.group(3),
                           'label': m.group(4), 'commands': []}
                blocks.append(current)
            elif line and not line.startswith('#'):
                (current['commands'] if current else loose).append(line)
        return blocks, loose

    def load_commands(self, commands, device_name):
        """Used by the Findings tab: 'Send to Configure'."""
        self.refresh_devices()
        found = self.select_device(device_name)
        clean = [c.strip() for c in commands if c.strip() and not c.strip().startswith('#')]
        if found:
            d = next(x for x in self.devices if x['name'] == device_name)
            self._set_preview_lines([(header_line(d, 'Findings suggestion'), 'header')]
                                    + [(c, None) for c in commands])
            self._built = {d['id']: (clean, [])}
        else:
            self._set_preview(commands)
            self._built = {}
        self.status.config(text=f'Loaded {len(commands)} suggested lines for {device_name}. '
                                f'Check and edit them, then click Apply.')

    # ------------------------------------------------------------ apply
    def _jobs_from_preview(self):
        """-> (jobs, problems). Checks that every section's device is selected,
        managed and of a type that may receive that kind of configuration."""
        blocks, loose = self.blocks_from_preview()
        selected = self.selected_devices()
        if not blocks and not loose:
            return [], ['There is nothing to apply. Click Preview first, so you can read the '
                        'commands before they are sent.']
        if not blocks:                                # typed by hand, no sections
            if len(selected) != 1:
                return [], ['The preview has no device sections, and more than one device '
                            '(or none) is selected. Select one device, or click Preview so '
                            'each device gets its own section.']
            d = selected[0]
            blocks = [{'name': d['name'], 'ip': d['ip'], 'type': d['type'],
                       'label': multi.CUSTOM, 'commands': loose}]
        elif loose:
            return [], ['Some commands are above the first device section of the preview, so '
                        'it is not clear which device they are for. Move them into a section '
                        'or click Preview again.']
        by_name = {d['name']: d for d in self.devices}
        chosen = {d['id'] for d in selected}
        jobs, problems, seen = [], [], set()
        for b in blocks:
            d = by_name.get(b['name'])
            if d is None:
                problems.append(f"{b['name']}: not a managed device (any more).")
            elif b['name'] in seen:
                problems.append(f"{b['name']}: has two sections in the preview.")
            elif d['id'] not in chosen:
                problems.append(f"{b['name']}: in the preview but not selected. Tick it, or "
                                f"click Preview again.")
            elif multi.incompatibility(d, kind_of_label(b['label'])):
                problems.append(f"{b['name']}: {multi.incompatibility(d, kind_of_label(b['label']))}.")
            elif not b['commands']:
                problems.append(f"{b['name']}: its section has no commands.")
            else:
                built = self._built.get(d['id'])
                checks = built[1] if built and built[0] == b['commands'] else []
                jobs.append({'device': d, 'commands': b['commands'], 'checks': checks,
                             'edited': not built or built[0] != b['commands']})
            seen.add(b['name'])
        return jobs, problems

    def _confirm_text(self, jobs):
        targets = {j['device']['id'] for j in jobs}
        left_out = [d for d in self.selected_devices() if d['id'] not in targets]
        if len(jobs) == 1 and not left_out:
            d = jobs[0]['device']
            text = (f"Send {len(jobs[0]['commands'])} commands to {d['name']} ({d['ip']})?\n\n"
                    f"A backup of its configuration is saved first, and the result is "
                    f"checked afterwards.")
        else:
            text = f'Configure {len(jobs)} device(s), one after the other:\n'
            text += ''.join(f"\n   {j['device']['name']}  ({j['device']['ip']})  -  "
                            f"{len(j['commands'])} commands" for j in jobs)
            if left_out:
                text += '\n\nSelected but NOT configured:'
                kind = self.config_kind()
                text += ''.join(f"\n   {d['name']}: "
                                f"{multi.incompatibility(d, kind) or 'not in the preview'}"
                                for d in left_out)
            text += ('\n\nEach device: backup first, then the commands, then its checks; it is '
                     'saved only if its own checks pass. If a device rejects a command, the '
                     'devices after it are not started.')
        edited = [j['device']['name'] for j in jobs if j['edited']]
        if edited:
            text += (f"\n\nEdited by hand, so not checked automatically: {', '.join(edited)}.")
        return text

    def _collect_creds(self, devices):
        """{device id: creds}, asking once for devices without a saved login. None = cancelled."""
        creds, missing = {}, []
        for d in devices:
            user, password = self.store.get_credentials(d['id'])
            if user:
                creds[d['id']] = {'host': d['ip'], 'username': user, 'password': password}
            else:
                missing.append(d)
        if missing:
            who = missing[0]['name'] if len(missing) == 1 else \
                f"{len(missing)} devices without a saved login ({', '.join(d['name'] for d in missing)})"
            user = simpledialog.askstring('Login', f'Username for {who}:', parent=self)
            if not user:
                return None
            password = simpledialog.askstring('Login', f'Password for {who}:', show='*',
                                              parent=self)
            if password is None:
                return None
            for d in missing:
                creds[d['id']] = {'host': d['ip'], 'username': user, 'password': password}
        return creds

    def apply(self):
        if self.busy:
            return
        if not self.selected_devices() and not self.blocks_from_preview()[0]:
            messagebox.showinfo('Select a device', 'Tick at least one managed device first.')
            return
        jobs, problems = self._jobs_from_preview()
        if problems:
            if len(problems) == 1 and problems[0].startswith('There is nothing'):
                messagebox.showinfo('Nothing to apply', problems[0])
            else:
                messagebox.showerror('Cannot apply', '\n'.join(problems))
            return
        if not messagebox.askyesno('Apply to devices' if len(jobs) > 1 else 'Apply to device',
                                   self._confirm_text(jobs)):
            return
        creds = self._collect_creds([j['device'] for j in jobs])
        if not creds:
            return
        for j in jobs:
            j['creds'] = creds[j['device']['id']]
        targets = {j['device']['id'] for j in jobs}
        kind = self.config_kind()
        self._skipped = [(d, multi.incompatibility(d, kind) or 'not in the preview')
                         for d in self.selected_devices() if d['id'] not in targets]
        self.busy = True
        self._stop = threading.Event()
        self._expected = len(jobs)
        self.apply_btn.state(['disabled'])
        self.stop_btn.state(['!disabled'] if len(jobs) > 1 else ['disabled'])
        names = ', '.join(j['device']['name'] for j in jobs)
        self.status.config(text=f'Applying to {names}... the SSH session is shown below.')
        if len(jobs) == 1:
            d = jobs[0]['device']
            self.session.start_run(d['name'], d['ip'], len(jobs[0]['commands']))
        else:
            self.session.start_batch([j['device']['name'] for j in jobs])
        threading.Thread(target=self._worker, args=(jobs, bool(self.stop_on_failure.get())),
                         daemon=True).start()
        self.after(200, self.check_queue)

    def stop(self):
        """Do not start any more devices (the one in progress finishes safely)."""
        if self.busy:
            self._stop.set()
            self.stop_btn.state(['disabled'])
            self.status.config(text='Stopping after the current device...')

    def _worker(self, jobs, stop_on_failure):
        """Runs in the background thread: never touches a widget."""
        try:
            results = multi.run_devices(
                jobs, self.apply_fn, post=self.session.post,
                on_result=lambda r: self.results.put(('device', r)),
                stop=self._stop, stop_on_failure=stop_on_failure)
        except Exception as err:                       # a bug, not a device problem
            self.session.post('error', f'Error: {type(err).__name__}: {err}')
            results = None
        self.results.put(('done', results))

    def check_queue(self):
        finished = None
        try:
            while True:
                kind, data = self.results.get_nowait()
                if kind == 'device':
                    self._record(data)
                else:
                    finished = data if data is not None else []
                    break
        except queue.Empty:
            pass
        if finished is None:
            self.after(200, self.check_queue)
            return
        self._finish(finished)

    def _record(self, r):
        """One device's result: into the device's log (database) and the workbench console."""
        d = r['device']
        if r['status'] == multi.NOT_RUN:
            self.log('configure', f"{d['name']}: NOT RUN. {r['message']}", 'warn')
            return
        try:
            self.store.add_log(d['id'], 'Configuration', 'success' if r['ok'] else 'failed',
                               r['message'])
        except Exception as err:
            r['message'] += f'  (could not write the log: {err})'
        self.log('configure', f"{d['name']}: {r['status']}. {r['message']}",
                 'ok' if r['ok'] else 'error')

    def _finish(self, results):
        self.busy = False
        self.apply_btn.state(['!disabled'])
        self.stop_btn.state(['disabled'])
        skipped = getattr(self, '_skipped', [])
        if len(results) > 1 or (results and skipped):
            self.session.post('section', 'SUMMARY')
            for line in multi.summary_text(results, skipped).splitlines():
                kind = 'ok' if line == f'Status: {multi.SUCCESS}' else \
                    'warn' if line.startswith(('Status: SKIPPED', f'Status: {multi.NOT_RUN}')) else \
                    'error' if line.startswith('Status:') else 'summary'
                self.session.post(kind, line)
        self.session.flush()
        self.last_results = results
        if not results:
            self.status.config(text='The change did not complete. See the SSH session.')
            messagebox.showerror('Apply failed', 'Something went wrong before any device was '
                                                 'configured. See the SSH session.')
            return
        c = multi.counts(results)
        if len(results) == 1:
            r = results[0]
            self.status.config(text='Done.' if r['ok'] else
                               'The change did not complete. See the SSH session.')
            if not r['ok']:
                messagebox.showerror('Apply failed', r['message'])
            return
        text = f"{c['completed']} of {c['total']} devices configured"
        if c['failed']:
            text += f", {c['failed']} failed"
        if c['not_run']:
            text += f", {c['not_run']} not run"
        self.status.config(text=text + '. The summary is in the SSH session.')
        self.log('configure', text + '.', 'ok' if c['completed'] == c['total'] else 'error')
        if c['completed'] != c['total']:
            messagebox.showerror('Some devices were not configured',
                                 multi.summary_text(results, skipped))


def _port_set(spec):
    try:
        return {(s['type'], s['prefix'], p) for s in parse_ports(spec)
                for p in range(s['start'], s['end'] + 1)}
    except ValueError:
        return set()
