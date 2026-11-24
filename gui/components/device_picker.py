"""Pick one or more managed devices: a table with a check box per device, a
type filter, Select all / Clear, and a count.

Click a row (or press Space) to tick or untick it. Ticks are kept when the list
is refreshed and when the filter hides a device (the count says so).
"""
import tkinter as tk
from tkinter import ttk

from gui import theme
from gui.components.tables import setup_table

ON, OFF = '☑', '☐'
FILTERS = {'All types': None, 'Switches': 'switch', 'Routers': 'router'}


def plural(n, word):
    """plural(1, 'switch') -> '1 switch'; plural(3, 'switch') -> '3 switches'."""
    if n == 1:
        return f'{n} {word}'
    return f'{n} {word}es' if word.endswith(('s', 'sh', 'ch', 'x')) else f'{n} {word}s'


class DevicePicker(ttk.Frame):
    def __init__(self, parent, on_change=None):
        super().__init__(parent)
        self.on_change = on_change or (lambda: None)
        self.devices = []                 # every device offered, in display order
        self.checked = set()              # device ids
        self.grid_columnconfigure(0, weight=1)
        self.grid_rowconfigure(2, weight=1)

        bar = ttk.Frame(self)
        bar.grid(row=0, column=0, sticky='ew', pady=(0, 6))
        ttk.Label(bar, text='Show').pack(side='left')
        self.filter = tk.StringVar(value='All types')
        self.filter_box = ttk.Combobox(bar, textvariable=self.filter, values=list(FILTERS),
                                       state='readonly', width=10)
        self.filter_box.pack(side='left', padx=(6, 0))
        self.filter_box.bind('<<ComboboxSelected>>', lambda e: self.show())

        buttons = ttk.Frame(self)
        buttons.grid(row=1, column=0, sticky='ew', pady=(0, 6))
        self.all_button = ttk.Button(buttons, text='Select all', command=self.select_all)
        self.all_button.pack(side='left')
        self.clear_button = ttk.Button(buttons, text='Clear selection', command=self.clear)
        self.clear_button.pack(side='left', padx=(6, 0))

        holder = ttk.Frame(self)
        holder.grid(row=2, column=0, sticky='nsew')
        holder.grid_columnconfigure(0, weight=1)
        holder.grid_rowconfigure(0, weight=1)
        self.tree = ttk.Treeview(holder, columns=('check', 'name', 'ip', 'type'),
                                 show='headings', height=8, selectmode='browse',
                                 style='Data.Treeview')
        setup_table(self.tree, [('check', '', 30, 'center'), ('name', 'Device', 100),
                                ('ip', 'IP address', 118), ('type', 'Type', 66)])
        ys = ttk.Scrollbar(holder, orient='vertical', command=self.tree.yview)
        self.tree.configure(yscrollcommand=ys.set)
        self.tree.grid(row=0, column=0, sticky='nsew')
        ys.grid(row=0, column=1, sticky='ns')
        self.tree.bind('<ButtonRelease-1>', self._clicked)
        self.tree.bind('<space>', self._space)

        self.count = ttk.Label(self, text='', foreground=theme.TEXT_SOFT)
        self.count.grid(row=3, column=0, sticky='w', pady=(6, 0))
        self.empty = ttk.Label(self, text='', foreground=theme.TEXT_MUTED, wraplength=240,
                               justify='left')
        self.empty.grid(row=4, column=0, sticky='w')

    # ---------------------------------------------------------------- data
    def set_devices(self, devices):
        """Offer these devices; ticks on devices that are still offered are kept."""
        self.devices = list(devices)
        ids = {d['id'] for d in self.devices}
        self.checked &= ids
        self.empty.config(text='' if self.devices else
                          'No managed devices yet. Run a scan and approve some.')
        self.show()

    def visible(self):
        kind = FILTERS.get(self.filter.get())
        return [d for d in self.devices if kind is None or d['type'] == kind]

    def selected(self):
        """The ticked devices, in display order (hidden ones included)."""
        return [d for d in self.devices if d['id'] in self.checked]

    # ---------------------------------------------------------------- changes
    def set_checked(self, ids, notify=True):
        self.checked = {i for i in ids if i in {d['id'] for d in self.devices}}
        self.show()
        if notify:
            self.on_change()

    def select_only(self, device_id):
        self.set_checked([device_id])

    def toggle(self, device_id):
        self.checked ^= {device_id}
        self.show()
        self.on_change()

    def select_all(self):
        """Tick every device the filter shows."""
        self.set_checked(self.checked | {d['id'] for d in self.visible()})

    def clear(self):
        self.set_checked([])

    def _clicked(self, event):
        if self.tree.identify_region(event.x, event.y) != 'cell':
            return
        row = self.tree.identify_row(event.y)
        if row:
            self.toggle(int(row))

    def _space(self, event):
        row = self.tree.focus()
        if row:
            self.toggle(int(row))
        return 'break'

    # ---------------------------------------------------------------- display
    def show(self):
        focus = self.tree.focus()
        self.tree.delete(*self.tree.get_children())
        for d in self.visible():
            self.tree.insert('', 'end', iid=str(d['id']),
                             values=(ON if d['id'] in self.checked else OFF, d['name'], d['ip'],
                                     d['type']))
        if focus and self.tree.exists(focus):
            self.tree.focus(focus)
        chosen = self.selected()
        kinds = {}
        for d in chosen:
            kinds[d['type']] = kinds.get(d['type'], 0) + 1
        detail = ', '.join(plural(n, k) for k, n in sorted(kinds.items()))
        hidden = len([d for d in chosen if d not in self.visible()])
        text = f'{len(chosen)} of {len(self.devices)} selected'
        if detail:
            text += f'  ({detail})'
        if hidden:
            text += f'; {hidden} hidden by the filter'
        self.count.config(text=text)
