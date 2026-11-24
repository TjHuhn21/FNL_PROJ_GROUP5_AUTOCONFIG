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
apply_config for each: every device gets its own encrypted backup (.ncbak; the backup
key is checked before anything starts), checks and save. The
SSH session console shows each device's real commands and replies; the worker
thread only posts into queues, and only the window's own thread touches widgets.

After an Apply, what SUCCEEDED (applied, verified and saved) is done:
  * a `hostname X` a device accepted renames that device in the device list (same record,
    so its links, findings and history stay with it);
  * the form sections the preview was built from are cleared - only when every device in
    the preview succeeded, the preview was not edited by hand, and the fields still hold
    the values that were previewed; and the applied sections leave the preview.
Anything that failed, was only partly applied or could not be verified keeps its inputs
and its preview section, so it can be corrected and retried.
"""
import inspect
import queue
import re
import threading
import tkinter as tk
from tkinter import messagebox, ttk

import validation
import validators as V
from config import commands_router, commands_switch
from config import connect, multi
from config.interfaces import parse_ports, port_count
from gui import theme
from gui.components.tables import setup_table
from gui.db_status import database_ready, report_error
from gui.device_login_guard import SUCCESS, DeviceLoginGuard, outcome_of_apply, warning_text
from gui.components.device_picker import DevicePicker, plural
from gui.components.field_check import CheckedEntry
from gui.components import login_dialog
from gui.components.list_editor import ListEditor, wrap_to_width
from gui.components.scroll_frame import ScrollFrame
from gui.components.ssh_console import SshConsole
from security import CredentialError
from store_errors import DATABASE_ERRORS, DuplicateDeviceName

_HOSTNAME_COMMAND = re.compile(r'^\s*hostname\s+(\S+)\s*$', re.IGNORECASE)


def login_refused(result):
    """The device refused the SSH login (so nothing was changed on it)."""
    return result['status'] == multi.FAILED and \
        (result.get('message') or '').startswith('Wrong username or password')


def login_worked(result):
    """The device accepted the SSH login (whatever happened to the commands after it)."""
    return result['status'] in (multi.SUCCESS, multi.PARTIAL, multi.NOT_VERIFIED) or \
        'The device rejected a command' in (result.get('message') or '')


def applied_hostname(commands):
    """The hostname the last `hostname X` command sets, or None."""
    name = None
    for command in commands or ():
        m = _HOSTNAME_COMMAND.match(command)
        if m:
            name = m.group(1)
    return name


PORT_HINT ='One port, a range or a list: Fa0/1   Fa0/1-5   Fa0/1-Fa0/5   Fa0/1-5, Gi0/1'
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


CONFIGURE_NARROW_BELOW = 1150       # logical pixels: the device list gets a bigger share


def _default_route_problem(text):
    """The default route's next hop: an IP address, not 0.0.0.0 or a broadcast address."""
    problem = V.check_ipv4(text)
    if not problem and V.clean(text) in ('0.0.0.0', '255.255.255.255'):
        problem = f'The next hop cannot be {V.clean(text)}.'
    return problem


def _caption(parent, text):
    return ttk.Label(parent, text=text, font=theme.mono(9, 'bold'), foreground=theme.TEXT_MUTED)


class ConfigureTab(ttk.Frame):
    def __init__(self, parent, store, log=None, on_change=None, on_applied=None):
        """log(source, message, level): the workbench console, for one-line summaries.
        on_change(): called after an Apply changed device data (a renamed device), so
        the other pages (Devices, inspector...) show the new data.
        on_applied(): called after every finished Apply (new configuration log entries)."""
        super().__init__(parent, padding=(theme.PAD, 4, theme.PAD, theme.PAD))
        self.store = store
        self.log = log or (lambda *a, **k: None)
        self.device_guard = DeviceLoginGuard()   # set by the main window (signed-in account)
        self.on_change = on_change or (lambda: None)
        self.on_applied = on_applied or (lambda: None)
        self._pending = None                      # what the current preview was built from
        self._applied = {}                        # device id -> edited?, SUCCESS since Preview
        self._jobs = {}                           # device id -> job of the running Apply
        self._pending_saves = {}                  # device id -> (user, password) to save if accepted
        self._cred_source = {}                    # device id -> 'saved' / 'typed' (this Apply)
        self.apply_fn = connect.apply_config      # tests replace this with a fake
        # Before any login is asked for or any SSH session opened: is the backup encryption
        # key usable? (None, or why not.) Without it nothing is sent to any device.
        self.backup_preflight = connect.backup_key_problem
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
        self.columns.bind('<ButtonRelease-1>', self._dividers_dragged, add='+')
        self.refresh_devices()

    def _place_dividers(self, event=None):
        """The three columns (devices | settings | preview and SSH session) keep their
        proportions when the window is resized: the starting ones, or the ones the user
        dragged. On a narrow window the device list gets a bigger share (names and IP
        addresses stay readable) until the user drags a divider."""
        from gui import ui_scale
        width, height = self.columns.winfo_width(), self.right.winfo_height()
        if width < 500 or height < 200:
            return
        if not self._placed:
            self._placed = True
            self.right.sashpos(0, int(height * 0.5))
        if width == getattr(self, '_placed_width', None):
            return
        self._placed_width = width
        fractions = getattr(self, '_column_fractions', None)
        if fractions is None:                          # not dragged: the defaults
            narrow = width / ui_scale.dpi_scale() < CONFIGURE_NARROW_BELOW
            fractions = (0.30, 0.61) if narrow else (0.25, 0.56)
        self.columns.sashpos(0, int(width * fractions[0]))
        self.columns.sashpos(1, int(width * fractions[1]))

    def _dividers_dragged(self, _event=None):
        """Remember the proportions the user chose (kept when the window is resized)."""
        width = self.columns.winfo_width()
        if width > 500:
            self._column_fractions = (self.columns.sashpos(0) / width,
                                      self.columns.sashpos(1) / width)

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
            [{'key': 'ports', 'label': 'Ports', 'width': 16, 'required': True,
              'check': V.check_port_list},
             {'key': 'allowed', 'label': 'Allowed VLANs', 'width': 14, 'typing': 'vlan_list',
              'check': V.check_vlan_list},
             {'key': 'native', 'label': 'Native VLAN', 'width': 8, 'typing': 'number',
              'check': lambda t: V.check_vlan_id(t, 'native VLAN')},
             {'key': 'encapsulation', 'label': 'encapsulation dot1q', 'kind': 'check',
              'default': 1}],
            [('ports', 'Ports', 180), ('allowed', 'Allowed', 150), ('native', 'Native', 60)],
            self._validate_trunk,
            note=PORT_HINT + '.  Allowed VLANs: for example 10,20,30-40 (empty = all).  '
                 'Untick dot1q on switches that only do 802.1Q (they reject the command).')
        self.trunk_editor.pack(fill='both', expand=True)

        sec_page = ttk.Frame(tabs, padding=10)
        tabs.add(sec_page, text='Port security')
        self.security_editor = ListEditor(
            sec_page, 'port security',
            [{'key': 'ports', 'label': 'Access ports', 'width': 16, 'required': True,
              'check': V.check_port_list},
             {'key': 'maximum', 'label': 'Max MAC addresses', 'width': 6, 'default': '2',
              'typing': 'number', 'required': True,
              'check': lambda t: V.check_number(t, 1, V.PORT_SECURITY_MAX, 'Max MAC addresses')},
             {'key': 'violation', 'label': 'On violation', 'kind': 'combo',
              'values': ['shutdown', 'restrict', 'protect'], 'default': 'shutdown'},
             {'key': 'sticky', 'label': 'Learn MACs (sticky)', 'kind': 'check', 'default': 1}],
            [('ports', 'Ports', 200), ('maximum', 'Max', 50), ('violation', 'Violation', 80),
             ('sticky', 'Sticky', 55)],
            self._validate_port_security,
            note=PORT_HINT + '.  The ports are also set to access mode.')
        self.security_editor.pack(fill='both', expand=True)

        if_page = ttk.Frame(tabs, padding=10)
        tabs.add(if_page, text='Interfaces')
        self.switch_if_editor = ListEditor(
            if_page, 'interface',
            [{'key': 'ports', 'label': 'Ports', 'width': 16, 'required': True,
              'check': V.check_port_list},
             {'key': 'state', 'label': 'State', 'kind': 'combo',
              'values': ['(leave)', 'no shutdown', 'shutdown'], 'default': '(leave)'},
             {'key': 'description', 'label': 'Description', 'width': 34,
              'check': V.check_description}],
            [('ports', 'Ports', 110), ('state', 'State', 90), ('description', 'Description', 140)],
            self._validate_switch_interface,
            note=PORT_HINT + '.  "shutdown" turns the ports off; "no shutdown" turns them on.')
        self.switch_if_editor.pack(fill='both', expand=True)

    def _build_vlan_access(self, box):
        self.vid, self.vname = tk.StringVar(), tk.StringVar()
        row = ttk.Frame(box); row.pack(fill='x')
        ttk.Label(row, text='VLAN ID').grid(row=0, column=0, sticky='w')
        ttk.Label(row, text='Name').grid(row=0, column=1, sticky='w')
        self.vid_entry = CheckedEntry(row, self.vid, typing='number', width=8, required=True,
                                      label='VLAN ID', check=self._vlan_id_problem,
                                      warn=V.vlan_id_warning)
        self.vid_entry.grid(row=1, column=0, padx=(0, 8), pady=2, sticky='nw')
        self.vname_entry = CheckedEntry(row, self.vname, width=18, label='VLAN name',
                                        check=lambda t: V.check_name(t, 'The VLAN name'))
        self.vname_entry.grid(row=1, column=1, padx=(0, 8), pady=2, sticky='nw')
        self.add_vlan_btn = ttk.Button(row, text='Add VLAN', command=self.add_vlan)
        self.add_vlan_btn.grid(row=1, column=2, pady=2, sticky='nw')
        for e in (self.vid_entry, self.vname_entry):
            e.on_change = self._update_add_buttons
        self.vlan_tree = ttk.Treeview(box, columns=('id', 'name'), show='headings', height=4)
        setup_table(self.vlan_tree, [('id', 'VLAN ID', 70), ('name', 'Name', 300)])
        self.vlan_tree.pack(fill='x', pady=(8, 4))
        ttk.Button(box, text='Remove selected VLAN', command=self.remove_vlan).pack(anchor='e')

        ttk.Separator(box).pack(fill='x', pady=12)
        self.port, self.port_vlan = tk.StringVar(), tk.StringVar()
        prow = ttk.Frame(box); prow.pack(fill='x')
        ttk.Label(prow, text='Access ports').grid(row=0, column=0, sticky='w')
        ttk.Label(prow, text='in VLAN').grid(row=0, column=1, sticky='w')
        self.port_entry = CheckedEntry(prow, self.port, width=20, required=True,
                                       label='Access ports', check=V.check_port_list)
        self.port_entry.grid(row=1, column=0, padx=(0, 8), pady=2, sticky='nw')
        # "in VLAN": a VLAN of the list above, or one that already exists on the device
        self.port_vlan_entry = CheckedEntry(prow, self.port_vlan, typing='number', width=8,
                                            required=True, label='in VLAN', combo_values=[],
                                            check=lambda t: V.check_vlan_id(t),
                                            warn=self._port_vlan_note)
        self.port_vlan_entry.grid(row=1, column=1, padx=(0, 8), pady=2, sticky='nw')
        self.port_vlan_box = self.port_vlan_entry.entry
        self.add_port_btn = ttk.Button(prow, text='Add ports', command=self.add_port)
        self.add_port_btn.grid(row=1, column=2, pady=2, sticky='nw')
        for e in (self.port_entry, self.port_vlan_entry):
            e.on_change = self._update_add_buttons
        self._update_add_buttons()
        hint = ttk.Label(box, text=PORT_HINT, foreground=theme.TEXT_MUTED, justify='left')
        hint.pack(anchor='w', fill='x', pady=(4, 0))
        wrap_to_width(hint)
        self.port_tree = ttk.Treeview(box, columns=('port', 'vlan'), show='headings', height=3)
        setup_table(self.port_tree, [('port', 'Ports', 300), ('vlan', 'VLAN', 70)])
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
        rows = [('Hostname', self.hostname, None, V.check_hostname),
                ('Default route (next hop)', self.default_route, 'ipv4',
                 _default_route_problem),
                ('DNS servers (comma list)', self.dns_servers, 'ipv4_list', V.check_ipv4_list),
                ('NTP server', self.ntp_server, 'ipv4', V.check_ipv4)]
        self.basic_entries = {}
        for r, (label, var, typing, check) in enumerate(rows, start=1):
            ttk.Label(basics, text=label).grid(row=r, column=0, sticky='nw', pady=3)
            entry = CheckedEntry(basics, var, check=check, typing=typing, width=20, label=label)
            entry.grid(row=r, column=1, sticky='w', padx=8, pady=3)
            self.basic_entries[label] = entry

        dhcp_page = ttk.Frame(tabs, padding=10)
        tabs.add(dhcp_page, text='DHCP')
        self.dhcp = {k: tk.StringVar() for k in V.DHCP_FIELDS}
        rows = [('DHCP pool name', 'pool', None, lambda t: V.check_name(t, 'The pool name')),
                ('DHCP network', 'network', 'ipv4', V.check_ipv4),
                ('DHCP mask', 'mask', 'mask', V.check_mask),
                ('DHCP gateway', 'gateway', 'ipv4', V.check_ipv4),
                ('DNS server', 'dns', 'ipv4', V.check_ipv4),
                ('Exclude from', 'ex_start', 'ipv4', V.check_ipv4),
                ('Exclude to', 'ex_end', 'ipv4', V.check_ipv4)]
        self.dhcp_entries = {}
        for r, (label, key, typing, check) in enumerate(rows):
            ttk.Label(dhcp_page, text=label).grid(row=r, column=0, sticky='nw', pady=3)
            entry = CheckedEntry(dhcp_page, self.dhcp[key], check=check, typing=typing, width=20,
                                 label=label)
            entry.grid(row=r, column=1, sticky='w', padx=8, pady=3)
            entry.on_change = self._recheck_dhcp      # the fields depend on each other
            self.dhcp_entries[key] = entry

        if_page = ttk.Frame(tabs, padding=10)
        tabs.add(if_page, text='Interfaces')
        self.router_if_editor = ListEditor(
            if_page, 'router interface',
            [{'key': 'name', 'label': 'Interface', 'width': 12, 'required': True,
              'check': V.check_interface_name},
             {'key': 'state', 'label': 'State', 'kind': 'combo',
              'values': ['(leave)', 'no shutdown', 'shutdown'], 'default': 'no shutdown'},
             {'key': 'ip', 'label': 'IP address', 'width': 15, 'typing': 'ipv4',
              'check': V.check_ipv4},
             {'key': 'mask', 'label': 'Subnet mask', 'width': 15, 'typing': 'mask',
              'check': V.check_mask},
             {'key': 'description', 'label': 'Description', 'width': 30,
              'check': V.check_description}],
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
            [{'key': 'network', 'label': 'Destination network', 'width': 15, 'typing': 'ipv4',
              'required': True, 'check': V.check_ipv4},
             {'key': 'mask', 'label': 'Subnet mask', 'width': 15, 'typing': 'mask',
              'required': True, 'check': V.check_mask},
             {'key': 'next_hop', 'label': 'Next hop', 'width': 15, 'required': True,
              'check': self._next_hop_problem}],
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
        self.preview = tk.Text(holder, height=8, font=theme.mono(theme.CODE_SIZE), wrap='none',
                               undo=True,
                               relief='solid', borderwidth=1, padx=8, pady=6)
        ys = ttk.Scrollbar(holder, orient='vertical', command=self.preview.yview)
        xs = ttk.Scrollbar(holder, orient='horizontal', command=self.preview.xview)
        self.preview.configure(yscrollcommand=ys.set, xscrollcommand=xs.set)
        self.preview.grid(row=0, column=0, sticky='nsew')
        ys.grid(row=0, column=1, sticky='ns')
        xs.grid(row=1, column=0, sticky='ew')
        self.preview.tag_configure('comment', foreground=theme.TEXT_MUTED)
        self.preview.tag_configure('header', foreground=theme.ACCENT,
                                   font=theme.mono(theme.CODE_SIZE, 'bold'))
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
        try:
            rows = self.store.get_devices('', 'name', 1, 1000)
        except DATABASE_ERRORS as err:
            self.show_unavailable(str(err))
            report_error(self, err)
            return
        self.devices = [d for d in rows if d['managed']]
        self.picker.set_devices(self.devices)
        held = getattr(self, '_ticks_held', None)
        if held is not None:                       # back after an outage: same ticks as before
            self._ticks_held = None
            self.picker.set_checked(held, notify=False)
        if self.devices and not self._auto_selected and not self.picker.checked:
            self._auto_selected = True             # the first time: one device, as before
            self.picker.set_checked([self.devices[0]['id']], notify=False)
        self._show_forms_for_device()

    def show_unavailable(self, reason=''):
        """The device list could not be read: offer no devices (never an old list as if
        it were current). A run already in progress finishes; its results are still shown."""
        if getattr(self, '_ticks_held', None) is None:
            self._ticks_held = set(self.picker.checked)   # given back when the list returns
        self.devices = []
        self.picker.set_devices([])
        self.picker.empty.config(text='Database unavailable: no device list.')
        if not self.busy and hasattr(self, 'status'):
            self.status.config(text='Database unavailable: the device list cannot be shown and '
                                    'nothing can be applied until the connection is back.')

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
    def _vlan_id_problem(self, text):
        """A VLAN ID 1-4094 that is not in the list yet."""
        problem = V.check_vlan_id(text)
        if not problem and int(V.clean(text)) in {v for v, _ in self.vlans}:
            problem = f'VLAN {V.clean(text)} is already in the list.'
        return problem

    def _port_vlan_note(self, text):
        """'in VLAN': fine when it is in the list above; otherwise it must already exist on
        the device (said, never blocked: the device's VLANs are not known here)."""
        if V.check_vlan_id(text):
            return None
        if int(V.clean(text)) in {v for v, _ in self.vlans}:
            return None
        return (f'VLAN {V.clean(text)} is not in the list above: it must already exist on '
                f'the device.')

    def _update_add_buttons(self):
        """Add VLAN / Add ports only while their required fields are valid."""
        for button, entries in ((getattr(self, 'add_vlan_btn', None),
                                 (getattr(self, 'vid_entry', None),
                                  getattr(self, 'vname_entry', None))),
                                (getattr(self, 'add_port_btn', None),
                                 (getattr(self, 'port_entry', None),
                                  getattr(self, 'port_vlan_entry', None)))):
            if button is None or None in entries:
                continue
            button.state(['!disabled'] if all(e.ready() for e in entries) else ['disabled'])

    def add_vlan(self):
        vid, name = V.clean(self.vid.get()), V.clean(self.vname.get())
        for entry, problem in ((self.vid_entry, self._vlan_id_problem(vid) if vid
                                else 'Enter a VLAN ID from 1 to 4094.'),
                               (self.vname_entry, name and
                                V.check_name(name, 'The VLAN name'))):
            if problem:
                entry.show_error(problem)
                messagebox.showerror('Cannot add VLAN', problem)
                return
        self.vlans.append((int(vid), name))
        self.vid.set(''); self.vname.set('')
        self._show_lists()

    def remove_vlan(self):
        for item in sorted(self.vlan_tree.selection(), key=lambda i: -self.vlan_tree.index(i)):
            del self.vlans[self.vlan_tree.index(item)]
        self._show_lists()

    def add_port(self):
        spec, vid = V.clean(self.port.get()), V.clean(self.port_vlan.get())
        port_problem = (V.check_port_list(spec) if spec else
                        'Enter the access ports, e.g. Fa0/1-5.') \
            or self._ports_unused(spec, [p for p, _ in self.ports])
        vlan_problem = V.check_vlan_id(vid) if vid else 'Choose the VLAN for these ports.'
        for entry, problem in ((self.port_entry, port_problem),
                               (self.port_vlan_entry, vlan_problem)):
            if problem:
                entry.show_error(problem)
                messagebox.showerror('Cannot add ports', problem)
                return
        self.ports.append((spec, int(vid)))
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
        self.vid_entry.recheck()                 # "already in the list" may have changed
        self.port_vlan_entry.recheck()

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
    # Each returns (problem, item). A problem is (field key, message): it is shown under
    # that field (validators.py has the rules; the backend checks them again).
    def _validate_trunk(self, v, items):
        problem = ('ports', V.check_port_list(v['ports']) if v['ports'] else 'Required.')
        if not problem[1]:
            problem = ('ports', self._ports_unused(v['ports'], [i['ports'] for i in items]))
        if not problem[1] and v['allowed']:
            problem = ('allowed', V.check_vlan_list(v['allowed']))
        if not problem[1] and v['native']:
            problem = ('native', V.check_vlan_id(v['native'], 'native VLAN'))
        if problem[1]:
            return problem, None
        allowed = validation.compress_vlans(V.parse_vlan_list(v['allowed'])) if v['allowed'] else ''
        return None, {'ports': v['ports'], 'allowed': allowed,
                      'native': int(v['native']) if v['native'] else None,
                      'encapsulation': v['encapsulation']}

    def _validate_port_security(self, v, items):
        problem = ('ports', V.check_port_list(v['ports']) if v['ports'] else 'Required.')
        if not problem[1]:
            problem = ('ports', self._ports_unused(v['ports'], [i['ports'] for i in items]))
        if not problem[1]:
            problem = ('maximum', V.check_number(v['maximum'], 1, V.PORT_SECURITY_MAX,
                                                 'Max MAC addresses'))
        if not problem[1] and (v['violation'] or 'shutdown') not in V.VIOLATIONS:
            problem = ('violation', 'Choose protect, restrict or shutdown.')
        if problem[1]:
            return problem, None
        return None, {'ports': v['ports'], 'maximum': int(v['maximum']),
                      'violation': v['violation'] or 'shutdown', 'sticky': v['sticky']}

    def _validate_switch_interface(self, v, items):
        problem = ('ports', V.check_port_list(v['ports']) if v['ports'] else 'Required.')
        if not problem[1]:
            problem = ('ports', self._ports_unused(v['ports'], [i['ports'] for i in items]))
        state = '' if v['state'] in ('', '(leave)') else v['state']
        if not problem[1] and v['description']:
            problem = ('description', V.check_description(v['description']))
        if not problem[1] and not state and not v['description']:
            problem = ('description', 'Choose a state or type a description (or both).')
        if problem[1]:
            return problem, None
        return None, {'ports': v['ports'], 'state': state, 'description': v['description']}

    def _validate_router_interface(self, v, items):
        problem = ('name', V.check_interface_name(v['name']) if v['name'] else 'Required.')
        if not problem[1] and V.interface_key(v['name']) in \
                {V.interface_key(i['name']) for i in items}:
            problem = ('name', f"{v['name']} is already in the list.")
        state = '' if v['state'] in ('', '(leave)') else v['state']
        if not problem[1]:
            problem = V.check_interface_address(v['ip'], v['mask']) or (None, None)
        if not problem[1] and v['description']:
            problem = ('description', V.check_description(v['description']))
        if not problem[1] and not (v['ip'] or state or v['description']):
            problem = ('ip', 'Enter an IP address, a state or a description.')
        if problem[1]:
            return problem, None
        mask = V.parse_mask(v['mask']) if v['mask'] else ''          # /24 -> 255.255.255.0
        return None, {'name': v['name'], 'ip': v['ip'], 'mask': mask, 'state': state,
                      'description': v['description']}

    @staticmethod
    def _next_hop_problem(text):
        """A static route's next hop on its own: an IP address or an interface name."""
        text = V.clean(text)
        if V.check_ipv4(text) is None:
            return None if text not in ('0.0.0.0', '255.255.255.255') else \
                f'The next hop cannot be {text}.'
        if text[:1].isdigit():
            return V.check_ipv4(text, 'next hop')
        return None if V.check_interface_name(text) is None else \
            'Enter an IP address (e.g. 192.168.1.1) or an interface (e.g. Gi0/0).'

    def _validate_route(self, v, items):
        problem = V.check_static_route(v['network'], v['mask'], v['next_hop'])
        if problem:
            return problem, None
        mask = V.parse_mask(v['mask'])                               # /16 -> 255.255.0.0
        if (v['network'], mask) in [(i['network'], i['mask']) for i in items]:
            return ('network', f"A route to {v['network']} {mask} is already in the "
                               f"list."), None
        return None, {'network': v['network'], 'mask': mask, 'next_hop': v['next_hop']}

    # ------------------------------------------------------------ the whole form
    def _recheck_dhcp(self):
        """The DHCP fields depend on each other (network address, gateway inside it...):
        show every problem under its field as soon as the fields involved are filled in."""
        if getattr(self, '_dhcp_busy', False):
            return
        self._dhcp_busy = True
        try:
            entries = self.dhcp_entries
            if len(entries) < len(V.DHCP_FIELDS):
                return
            values = {k: e.value() for k, e in entries.items()}
            together = {f: m for f, m in V.check_dhcp(values)
                        if m != 'Required when any DHCP field is filled in.'}
            for key, e in entries.items():
                own = e.problem() if e.value() else None
                if own:
                    continue                              # its own message is already shown
                if key in together:
                    e.show_error(together[key])
                elif e._forced:
                    e._show(None, None)
                    e._forced = None
        finally:
            self._dhcp_busy = False

    def form_problems(self, kind):
        """Everything in the form that is not valid: [(section > field, message)]. Preview
        and Apply are blocked while there is any."""
        out = []

        def own(section, entries):
            for e in entries:
                if e.value():
                    problem = e.problem()
                    if problem:
                        out.append((f'{section} > {e.label}', problem))
        if kind == 'router':
            own('Basics', self.basic_entries.values())
            labels = {key: e.label for key, e in self.dhcp_entries.items()}
            for field, message in V.check_dhcp({k: e.value()
                                                for k, e in self.dhcp_entries.items()}):
                out.append((f'DHCP > {labels[field]}', message))
            for section, editor in (('Interfaces', self.router_if_editor),
                                    ('Static routes', self.route_editor)):
                out += [(f'{section} > {label}', m) for label, m in editor.pending_problems()]
        else:
            own('VLANs & access', (self.vid_entry, self.vname_entry, self.port_entry,
                                   self.port_vlan_entry))
            for section, editor in (('Trunks', self.trunk_editor),
                                    ('Port security', self.security_editor),
                                    ('Interfaces', self.switch_if_editor)):
                out += [(f'{section} > {label}', m) for label, m in editor.pending_problems()]
        return out

    def _blocked_by_form(self, kind, action):
        """True (after saying what is wrong) when the form has invalid values."""
        problems = self.form_problems(kind)
        if not problems:
            return False
        text = '\n'.join(f'- {where}: {message}' for where, message in problems)
        self.log('configure', f'{action} blocked: {len(problems)} invalid field'
                              f"{'' if len(problems) == 1 else 's'} in "
                              f'{multi.KINDS[kind].lower()}. '
                              + '; '.join(f'{w}: {m}' for w, m in problems), 'error')
        messagebox.showerror(f'Cannot {action.lower()}: fix these fields first',
                             f'{text}\n\nNothing was sent to any device.')
        return True

    # ------------------------------------------------------------ building the commands
    def _build_plan(self, kind, count=1):
        """(commands, checks, feature names) for `count` devices of this kind,
        or None after showing a message."""
        try:
            return self._router_plan(count) if kind == 'router' else self._switch_plan()
        except (commands_switch.PlanError, commands_router.PlanError) as err:
            messagebox.showerror('Settings not accepted', str(err))   # the backend's check
            return None

    def _switch_plan(self):
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
        hostname = V.clean(self.hostname.get())
        if hostname:
            problem = V.check_hostname(hostname)
            if not problem and count > 1:
                problem = (f'A hostname must be unique, but {count} routers are selected. '
                           f'Select one router to set its hostname, or clear the field.')
            if problem:
                return fail('Hostname', problem)
            plan['hostname'] = hostname; selected.append('Hostname')
        route = V.clean(self.default_route.get())
        if route:
            problem = _default_route_problem(route)
            if problem:
                return fail('Default route', problem)
            plan['default_route'] = route; selected.append('Default route')
        if V.clean(self.dns_servers.get()):
            try:
                plan['dns_servers'] = V.parse_ipv4_list(self.dns_servers.get())
            except ValueError as err:
                return fail('DNS servers', str(err))
            selected.append('DNS servers')
        ntp = V.clean(self.ntp_server.get())
        if ntp:
            problem = V.check_ipv4(ntp)
            if problem:
                return fail('NTP server', problem)
            plan['ntp_server'] = ntp; selected.append('NTP')
        d = {k: V.clean(v.get()) for k, v in self.dhcp.items()}
        if any(d.values()):
            problems = V.check_dhcp(d)
            if problems:
                labels = {k: e.label for k, e in self.dhcp_entries.items()}
                return fail('DHCP settings', '\n'.join(f'{labels[f]}: {m}' for f, m in problems))
            plan['dhcp'] = {'pool': d['pool'], 'network': d['network'],
                            'mask': V.parse_mask(d['mask']), 'gateway': d['gateway'],
                            'dns': d['dns'],
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
        names = ', '.join(d['name'] for d in chosen)
        self.log('configure', f'{names}: validating the configuration...')
        if self._blocked_by_form(kind, 'Preview'):
            return
        targets, skipped = multi.split_targets(chosen, kind)
        if not targets:
            self.log('configure', f'{names}: validation FAILED: none of them can receive '
                                  f'{multi.KINDS[kind].lower()}.', 'error')
            messagebox.showinfo('No compatible device',
                                f'None of the selected devices can receive '
                                f'{multi.KINDS[kind].lower()}:\n\n'
                                + '\n'.join(f"{d['name']}: {why}" for d, why in skipped))
            return
        built = self._build_plan(kind, len(targets))
        if built is None:
            self.log('configure', f'{names}: validation FAILED (see the message shown).', 'error')
            return
        commands, checks, features = built
        if not commands:
            self.log('configure', f'{names}: validation WARNING: no setting was filled in, so '
                                  f'there is nothing to preview.', 'warn')
            messagebox.showinfo('Nothing to preview', 'Fill in at least one setting '
                                '(a VLAN, ports, a trunk, a route, DHCP...) first.')
            return
        label = multi.KINDS[kind]
        lines = [(f'# {label} for {len(targets)} device{"" if len(targets) == 1 else "s"}: '
                  f'{", ".join(features)}', 'comment')]
        if len(targets) > 1:
            lines.append(('# Every device gets the same commands, its own encrypted backup, its '
                          'own checks, and is saved only if its checks pass.', 'comment'))
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
        sections = self._sections(kind)
        self._applied = {}                        # a new preview: nothing applied yet
        self._pending = {'kind': kind, 'targets': {d['id'] for d in targets},
                         'values': {f: sections[f][0]() for f in features if f in sections}}
        self._set_preview_lines(lines)
        text = f'{len(commands)} commands for {plural(len(targets), "device")}'
        if skipped:
            text += f', {len(skipped)} skipped'
        self.status.config(text=text + '. Read them, then click Apply.')
        self.log('configure', f"{', '.join(d['name'] for d in targets)}: validation SUCCESSFUL. "
                              f"{text} ready to apply.", 'ok')
        for d, why in skipped:
            self.log('configure', f"{d['name']}: skipped ({why}).", 'warn')

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
        self._pending = None                      # not built from the forms
        self._applied = {}
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
                kind = kind_of_label(b['label'])
                jobs.append({'device': d, 'commands': b['commands'], 'checks': checks,
                             'edited': not built or built[0] != b['commands'],
                             # checked against the device itself before anything is sent
                             'expected_type': kind if kind in multi.KINDS else None})
            seen.add(b['name'])
        return jobs, problems

    def _confirm_text(self, jobs):
        targets = {j['device']['id'] for j in jobs}
        left_out = [d for d in self.selected_devices() if d['id'] not in targets]
        if len(jobs) == 1 and not left_out:
            d = jobs[0]['device']
            text = (f"Send {len(jobs[0]['commands'])} commands to {d['name']} ({d['ip']})?\n\n"
                    f"An encrypted backup of its configuration (.ncbak) is saved and "
                    f"verified first, and the result is checked afterwards.")
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
            text += ('\n\nEach device: encrypted backup first, then the commands, then its '
                     'checks; it is '
                     'saved only if its own checks pass. If a device rejects a command, the '
                     'devices after it are not started.')
        edited = [j['device']['name'] for j in jobs if j['edited']]
        if edited:
            text += (f"\n\nEdited by hand, so not checked automatically: {', '.join(edited)}.")
        return text

    def _collect_creds(self, devices):
        """{device id: creds}. Saved logins are used as they are; for devices without a
        usable saved login, ONE dialog (gui.components.login_dialog) asks for the login.
        A saved login that cannot be decrypted is explained in that dialog. A login the
        user asks to save is remembered in self._pending_saves and saved only after the
        device accepted it (see _save_confirmed_logins). None = cancelled."""
        creds, missing, unreadable = {}, [], []
        self._cred_source = {}
        for d in devices:
            try:
                user, password = self.store.get_credentials(d['id'])
            except CredentialError:
                unreadable.append(d)
                missing.append(d)
                continue
            if user:
                creds[d['id']] = {'host': d['ip'], 'username': user, 'password': password}
                self._cred_source[d['id']] = 'saved'
            else:
                missing.append(d)
        if missing:
            typed = self._ask_login(missing, 'unreadable' if unreadable else 'missing',
                                    replaces=unreadable)
            if typed is None:
                return None
            creds.update(typed)
        return creds

    def _ask_login(self, devices, reason, replaces=()):
        """Ask for one login for these devices. {device id: creds}, or None (cancelled)."""
        answer = login_dialog.ask_device_login(self, devices, reason=reason, replaces=replaces)
        if not answer:
            return None
        out = {}
        for d in devices:
            out[d['id']] = {'host': d['ip'], 'username': answer['username'],
                            'password': answer['password']}
            self._cred_source[d['id']] = 'typed'
            if answer.get('save'):
                self._pending_saves[d['id']] = (answer['username'], answer['password'])
            else:
                self._pending_saves.pop(d['id'], None)
        return out

    def apply(self):
        if self.busy:
            return
        if not self.selected_devices() and not self.blocks_from_preview()[0]:
            messagebox.showinfo('Select a device', 'Tick at least one managed device first.')
            return
        if self._blocked_by_form(self.config_kind(), 'Apply'):
            return
        jobs, problems = self._jobs_from_preview()
        for j in jobs:                      # the preview can be edited: check every line again
            for command in j['commands']:
                problem = V.check_cli_line(command)
                if problem:
                    problems.append(f"{j['device']['name']}: \"{command.strip()[:60]}\": {problem}")
        if problems:
            if len(problems) == 1 and problems[0].startswith('There is nothing'):
                messagebox.showinfo('Nothing to apply', problems[0])
            else:
                messagebox.showerror('Cannot apply', '\n'.join(problems))
            return
        if not database_ready(self):        # logins and the result log live in the database
            self.log('configure', 'Apply FAILED: the database is unavailable. Nothing was sent.',
                     'error')
            return
        key_problem = self.backup_preflight()
        if key_problem:                     # no encrypted backup possible: nothing may be sent
            self.log('configure', f'Apply FAILED: the backup encryption key is not available. '
                                  f'Nothing was sent. {key_problem}', 'error')
            self.status.config(text='Apply not started: the backup encryption key is not '
                                    'available. Nothing was sent.')
            messagebox.showerror('Backup encryption key not available',
                                 f'{key_problem}\n\nEvery device gets an encrypted backup before '
                                 f'any change, so nothing was sent to any device. Set up the key '
                                 f'with backup_keys.py (see docs/BACKUP_ENCRYPTION.md).')
            return
        if not messagebox.askyesno('Apply to devices' if len(jobs) > 1 else 'Apply to device',
                                   self._confirm_text(jobs)):
            self.log('configure', 'Apply cancelled. Nothing was sent.', 'warn')
            return
        self._pending_saves = {}
        try:
            creds = self._collect_creds([j['device'] for j in jobs])
        except DATABASE_ERRORS as err:
            report_error(self, err)
            messagebox.showerror('Cannot apply', f'The saved logins could not be read, so '
                                                 f'nothing was sent to any device. {err}')
            return
        if not creds:
            self.status.config(text='Apply cancelled: no login was entered. Nothing was sent.')
            self.log('configure', 'Apply cancelled: no login was entered. Nothing was sent.',
                     'warn')
            return
        for j in jobs:
            j['creds'] = creds[j['device']['id']]
        targets = {j['device']['id'] for j in jobs}
        kind = self.config_kind()
        self._skipped = [(d, multi.incompatibility(d, kind) or 'not in the preview')
                         for d in self.selected_devices() if d['id'] not in targets]
        self._start(jobs)

    def _start(self, jobs):
        """Run the jobs (each with its 'creds') in the background thread."""
        self._jobs = {j['device']['id']: j for j in jobs}
        self.busy = True
        self._stop = threading.Event()
        self._expected = len(jobs)
        self.apply_btn.state(['disabled'])
        self.stop_btn.state(['!disabled'] if len(jobs) > 1 else ['disabled'])
        names = ', '.join(j['device']['name'] for j in jobs)
        self.status.config(text=f'Applying to {names}... the SSH session is shown below.')
        for j in jobs:
            d = j['device']
            self.log('configure', f"{d['name']}: applying {len(j['commands'])} command"
                                  f"{'' if len(j['commands']) == 1 else 's'} to {d['ip']} "
                                  f"(encrypted backup first)...", device=d['name'], ip=d['ip'])
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
            self.log('configure', 'Stop requested: no more devices will be started (the one in '
                                  'progress finishes safely).', 'warn')
            self.stop_btn.state(['disabled'])
            self.status.config(text='Stopping after the current device...')

    def _worker(self, jobs, stop_on_failure):
        """Runs in the background thread: never touches a widget."""
        try:
            results = multi.run_devices(
                jobs, self.apply_fn, post=self.session.post,
                on_result=lambda r: self.results.put(('device', r)),
                stop=self._stop, stop_on_failure=stop_on_failure,
                preflight=self.backup_preflight)
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
            self.log('configure', f"{d['name']}: NOT RUN (WARNING). {r['message']}", 'warn')
            return
        try:
            self.store.add_log(d['id'], 'Configuration', 'success' if r['ok'] else 'failed',
                               r['message'])
        except Exception as err:
            report_error(self, err)
            r['message'] += f'  (could not write the log: {err})'
        who = {'device': d['name'], 'ip': d.get('ip')}
        if r['ok']:
            # a change: double-clicking it shows the running-config before/after
            self.log('configure', f"{d['name']}: configuration applied, apply SUCCESSFUL. "
                                  f"{r['message']}", 'ok', tags=['change'],
                     detail=connect.take_diff(d.get('ip')), **who)
        elif connect.is_type_mismatch(r['message']):   # it names the device itself
            self.log('configure', r['message'], 'error', **who)
        else:
            state = '' if r['status'] == multi.FAILED else f" ({r['status']})"
            changed = r['status'] in (multi.PARTIAL, multi.NOT_VERIFIED)  # something went in
            self.log('configure', f"{d['name']}: apply FAILED{state}. {r['message']}", 'error',
                     tags=['change'] if changed else None, **who)

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
        refused = [self._jobs[r['device']['id']] for r in results
                   if login_refused(r) and r['device']['id'] in self._jobs]
        if results:
            self._after_apply(results)
            self._save_confirmed_logins(results)
            self.on_applied()
        if not results:
            self.log('configure', 'Apply FAILED before any device was configured. See the SSH '
                                  'session.', 'error')
            self.status.config(text='The change did not complete. See the SSH session.')
            messagebox.showerror('Apply failed', 'Something went wrong before any device was '
                                                 'configured. See the SSH session.')
            return
        c = multi.counts(results)
        popup = None                                   # (title, text), shown after reporting
        if len(results) == 1:
            r = results[0]
            self.status.config(text='Done.' if r['ok'] else
                               'The change did not complete. See the SSH session.')
            if not r['ok'] and not refused:            # a refused login gets the retry question
                popup = ('Apply failed', r['message'])
        else:
            text = f"{c['completed']} of {c['total']} devices configured"
            if c['failed']:
                text += f", {c['failed']} failed"
            if c['not_run']:
                text += f", {c['not_run']} not run"
            self.status.config(text=text + '. The summary is in the SSH session.')
            self.log('configure', text + '.', 'ok' if c['completed'] == c['total'] else 'error')
            if c['completed'] != c['total']:
                popup = ('Some devices were not configured', multi.summary_text(results, skipped))

        def after_reports(answer):
            """answer: the server's answer to the last FAILED login reported (or None)."""
            if answer and answer.get('locked'):
                return                                 # signed out: the message says why
            extra = warning_text(answer)
            if popup:
                messagebox.showerror(popup[0], popup[1] + (f'\n\n{extra}' if extra else ''))
            elif extra:
                messagebox.showwarning('Failed device login', extra)
            if refused:
                self._offer_login_retry(refused)
        self._report_logins(results, after_reports)

    def _report_logins(self, results, then):
        """Report every device's login outcome to the server's lockout, one after the
        other (they count in order); then then(answer of the last failure, or None)."""
        reports = [(r['device']['ip'], outcome_of_apply(r)) for r in results]
        reports = [(ip, o) for ip, o in reports if o is not None]
        last = {'answer': None}

        def next_report(index=0):
            if index == len(reports):
                then(last['answer'])
                return
            ip, outcome = reports[index]

            def done(answer):
                if answer and outcome != SUCCESS:
                    last['answer'] = answer
                if answer and answer.get('locked'):
                    then(answer)                       # locked: no more reports, no retry
                    return
                next_report(index + 1)
            self.device_guard.report(self, ip, outcome, done)
        next_report()

    # ------------------------------------------------------------ logins after an Apply
    def _save_confirmed_logins(self, results):
        """Save the logins the user asked to save, but only for devices that accepted
        them. Uses the store's normal save (validated, encrypted, one transaction)."""
        for r in results:
            pending = self._pending_saves.pop(r['device']['id'], None)
            if not pending:
                continue
            if not login_worked(r):
                self.log('configure', f"{r['device']['name']}: the typed login was not saved "
                                      f"because the device did not accept it.", 'warn')
                continue
            self._save_login(r['device'], *pending)

    def _save_login(self, device, username, password):
        name = device['name']
        try:
            current = self.store.get_device(device['id'])
            if current is None:
                self.log('configure', f'{name}: the device is no longer registered, so its '
                                      f'login was not saved.', 'warn')
                return False
            data = {'name': current['name'], 'ip': current['ip'], 'type': current['type'],
                    'status': current['status'], 'managed': current['managed']}
            self.store.save_device(device['id'], data, username, password)
        except DATABASE_ERRORS as err:
            report_error(self, err)
            self.log('configure', f'{name}: the login could not be saved ({err}). It was used '
                                  f'for this Apply only.', 'warn')
            return False
        except Exception as err:                    # e.g. an encryption key problem
            self.log('configure', f'{name}: the login could not be saved '
                                  f'({type(err).__name__}). It was used for this Apply only.',
                     'warn')
            return False
        self._cred_source[device['id']] = 'saved'
        self.log('configure', f'{name}: SSH login saved (encrypted) for future use.', 'ok',
                 tags=['change'], device=name)
        return True

    def _offer_login_retry(self, jobs):
        """Some devices refused the SSH login (nothing was changed on them): offer to
        enter the login again and run those devices once more."""
        devices = [j['device'] for j in jobs]
        names = ', '.join(d['name'] for d in devices)
        it = 'them' if len(devices) > 1 else 'it'
        if not messagebox.askyesno(
                'SSH login refused',
                f'{names} refused the SSH login, so nothing was changed on {it}.\n\n'
                f'Enter the login again and retry {it}?', parent=self):
            self.log('configure', f'The SSH login was refused by {names}; not retried. Nothing '
                                  f'was changed on {it}.', 'warn')
            return
        replaces = [d for d in devices if self._cred_source.get(d['id']) == 'saved']
        typed = self._ask_login(devices, 'refused', replaces=replaces)
        if typed is None:
            self.log('configure', f'Retry for {names} cancelled. Nothing was sent.', 'warn')
            return
        for j in jobs:
            j['creds'] = typed[j['device']['id']]
        self._skipped = []
        self._start(jobs)

    # ------------------------------------------------------------ after an Apply
    def _sections(self, kind):
        """{feature name (as in the preview): (read its inputs, clear them)} for one kind."""
        def var(v):
            return v.get, lambda: v.set('')

        def editor(e):
            def clear():
                e.items.clear()
                e.show()
            return (lambda: [dict(i) for i in e.items]), clear

        if kind == 'router':
            def clear_dhcp():
                for v in self.dhcp.values():
                    v.set('')
            return {'Hostname': var(self.hostname), 'Default route': var(self.default_route),
                    'DNS servers': var(self.dns_servers), 'NTP': var(self.ntp_server),
                    'DHCP': ((lambda: {k: v.get() for k, v in self.dhcp.items()}), clear_dhcp),
                    'Interfaces': editor(self.router_if_editor),
                    'Static routes': editor(self.route_editor)}

        def clear_vlans():
            self.vlans = []
            self._show_lists()

        def clear_ports():
            self.ports = []
            self._show_lists()
        return {'VLANs': ((lambda: list(self.vlans)), clear_vlans),
                'Access ports': ((lambda: list(self.ports)), clear_ports),
                'Trunk ports': editor(self.trunk_editor),
                'Port security': editor(self.security_editor),
                'Interface settings': editor(self.switch_if_editor)}

    def _after_apply(self, results):
        """What succeeded is done: rename devices whose hostname changed, clear the form
        sections that were applied, and take the applied devices out of the preview.
        Failed, partly applied or unverified results keep everything for a retry."""
        jobs = self._jobs or {}
        done = [r for r in results if r['status'] == multi.SUCCESS]
        renamed = False
        for r in done:
            job = jobs.get(r['device']['id'])
            self._applied[r['device']['id']] = job.get('edited', True) if job else True
            new_name = applied_hostname(job['commands']) if job else None
            if new_name and new_name != r['device']['name']:
                renamed = self._rename_device(r['device'], new_name) or renamed
        cleared = self._clear_applied_sections()
        self._drop_applied_from_preview(done, cleared=cleared)
        self._jobs = {}
        if renamed:
            self.on_change()                  # Devices, inspector, status bar, this picker
        return cleared

    def _rename_device(self, device, new_name):
        """The device accepted `hostname new_name`: give its record the same name. The same
        record (same id) is updated, so links, findings and history stay with it. Never
        raises: a name that cannot be used is reported, and the record is left as it was."""
        old = device['name']
        keep = f'The device list keeps the name {old}; you can rename it on the Devices page.'
        problem = validation.check_name(new_name)
        if problem:
            self.log('configure', f'{old}: the hostname is now {new_name}, but it cannot be used '
                                  f'as a device name here ({problem}). {keep}', 'warn')
            return False
        try:
            current = self.store.get_device(device['id'])
            if current is None:
                self.log('configure', f'{old}: the device is no longer registered, so its new '
                                      f'hostname {new_name} was not recorded.', 'warn')
                return False
            data = {'name': new_name, 'ip': current['ip'], 'type': current['type'],
                    'status': current['status'], 'managed': current['managed']}
            self.store.save_device(device['id'], data)
        except DuplicateDeviceName:
            self.log('configure', f'{old}: the hostname is now {new_name}, but another registered '
                                  f'device already uses that name. {keep}', 'warn')
            return False
        except DATABASE_ERRORS as err:
            report_error(self, err)
            self.log('configure', f'{old}: the new hostname {new_name} could not be saved in the '
                                  f'device list ({err}). {keep}', 'warn')
            return False
        except ValueError as err:
            self.log('configure', f'{old}: the new hostname {new_name} could not be saved in the '
                                  f'device list ({err}). {keep}', 'warn')
            return False
        self.log('configure', f'{old}: name changed {old} -> {new_name} (hostname applied; same '
                              f'device record, links and history kept).', 'ok',
                 tags=['change'], device=new_name)
        return True

    def _clear_applied_sections(self):
        """Clear the form sections the applied preview was built from. Only when EVERY
        device the preview was built for has succeeded since that Preview (in this Apply,
        or in a retry after a refused login) with exactly the previewed commands, and only
        the sections whose fields still hold the previewed values (anything typed since
        then is a new, pending change). Returns the cleared section names."""
        pending = self._pending
        if not pending or not pending['values']:
            return []
        if not pending['targets'] or not pending['targets'] <= set(self._applied):
            return []                                       # failed / partial / not run: keep
        if any(self._applied[i] for i in pending['targets']):
            return []                                       # edited by hand: not the forms' commands
        sections = self._sections(pending['kind'])
        cleared = []
        for feature, value in pending['values'].items():
            read, clear = sections[feature]
            if read() == value:
                clear()
                cleared.append(feature)
        self._pending = None
        return cleared

    def _drop_applied_from_preview(self, done, cleared):
        """The preview shows only what is still pending: the sections of the devices that
        succeeded leave it; when no device section is left, a short note replaces it."""
        if not done:
            return
        names = {r['device']['name'] for r in done}
        ids = {r['device']['id'] for r in done}
        for i in ids:
            self._built.pop(i, None)
        blocks, _loose = self.blocks_from_preview()
        if not any(b['name'] not in names for b in blocks):     # nothing left to send
            note = f"# Applied and saved: {', '.join(sorted(names))}."
            if cleared:
                note += f" Cleared from the form: {', '.join(cleared)}."
            self._set_preview_lines([(note, 'comment'),
                                     ('# Fill in new settings and click Preview.', 'comment')])
            return
        lines, skipping = [], False
        for raw in self.preview.get('1.0', 'end').splitlines():
            m = HEADER.match(raw.strip())
            if m:
                skipping = m.group(1) in names
            if skipping:
                continue
            tag = 'header' if m else 'skipped' if raw.startswith('# SKIPPED') else \
                'comment' if raw.strip().startswith('#') else None
            lines.append((raw, tag))
        lines.insert(0, (f"# Applied and saved (removed below): {', '.join(sorted(names))}. "
                         f"The sections left are still pending.", 'comment'))
        self._set_preview_lines(lines)


def _port_set(spec):
    try:
        return {(s['type'], s['prefix'], p) for s in parse_ports(spec)
                for p in range(s['start'], s['end'] + 1)}
    except ValueError:
        return set()
