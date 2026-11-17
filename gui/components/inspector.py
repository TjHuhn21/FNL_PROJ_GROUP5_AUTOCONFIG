"""The inspector: the panel on the right that shows whatever is selected.

For now a device can be selected from the command strip; later the topology
canvas and the device table will select into it too. Everything shown comes
from the device's own record (store.get_device). The saved login is never
read here.
"""
import customtkinter as ctk

from gui import theme


class Inspector(ctk.CTkFrame):
    def __init__(self, parent, store, on_open_devices=None, on_configure=None):
        super().__init__(parent, fg_color=theme.SURFACE, corner_radius=0)
        self.store = store
        self.on_open_devices, self.on_configure = on_open_devices, on_configure
        self.on_focus_device = None          # set by the main window: select a device on the map
        self.on_hide = None                  # set by the main window: collapse the panel
        self.device = None
        self.selection = None                # ('device', id) | ('details', name) | ('link', (a, b))
        self.grid_columnconfigure(0, weight=1)
        ctk.CTkLabel(self, text='INSPECTOR', font=theme.mono(9, 'bold'), anchor='w',
                     text_color=theme.TEXT_MUTED).grid(row=0, column=0, sticky='ew', padx=14,
                                                       pady=(10, 0))
        self.hide_button = ctk.CTkButton(
            self, text='Hide  ›', width=56, height=22, corner_radius=3, font=theme.FONT_SMALL,
            fg_color=theme.SURFACE, hover_color=theme.SURFACE_2, text_color=theme.TEXT_SOFT,
            command=lambda: self.on_hide and self.on_hide())
        self.hide_button.grid(row=0, column=1, sticky='e', padx=(0, 10), pady=(10, 0))
        self.body = None
        self.clear()

    def _new_body(self):
        if self.body is not None:
            self.body.destroy()
        self.body = ctk.CTkFrame(self, fg_color=theme.SURFACE, corner_radius=0)
        self.body.grid(row=1, column=0, columnspan=2, sticky='nsew', padx=14, pady=(4, 12))
        self.body.grid_columnconfigure(1, weight=1)
        return self.body

    def clear(self):
        """Nothing selected."""
        self.device = None
        self.selection = None
        body = self._new_body()
        ctk.CTkLabel(body, text='Nothing selected', font=theme.FONT_BOLD, anchor='w',
                     text_color=theme.TEXT).grid(row=0, column=0, columnspan=2, sticky='ew',
                                                 pady=(6, 2))
        ctk.CTkLabel(body, text='Click a device or a link on the Topology map, or find a '
                                'device with the command strip (Ctrl+K).', font=theme.FONT_SMALL, anchor='w', justify='left',
                     wraplength=250, text_color=theme.TEXT_MUTED).grid(
            row=1, column=0, columnspan=2, sticky='ew')

    # ---------------------------------------------------------------- generic rows
    def _rows(self, body, rows, start):
        """Label / value rows. rows: [(label, value, is_mono)]. Returns the next free row."""
        self.fields = {}
        for i, (label, value, is_mono) in enumerate(rows, start=start):
            ctk.CTkLabel(body, text=label, font=theme.FONT_SMALL, anchor='w',
                         text_color=theme.TEXT_MUTED).grid(row=i, column=0, sticky='nw',
                                                           padx=(0, 12), pady=2)
            value_label = ctk.CTkLabel(body, text=str(value), anchor='w', justify='left',
                                       wraplength=190, text_color=theme.TEXT,
                                       font=theme.mono(9) if is_mono else theme.FONT_SMALL)
            value_label.grid(row=i, column=1, sticky='w', pady=2)
            self.fields[label] = value_label
        return start + len(rows)

    def _note(self, body, row, text, amber=True):
        self.note_label = ctk.CTkLabel(
            body, text=text, font=theme.FONT_SMALL, anchor='w', justify='left', wraplength=250,
            text_color=theme.WARNING if amber else theme.TEXT_MUTED,
            fg_color=theme.WARNING_SOFT if amber else theme.SURFACE, corner_radius=3)
        self.note_label.grid(row=row, column=0, columnspan=2, sticky='ew', pady=(8, 0))

    def show_details(self, title, status, rows, note=None):
        """A device that has no database record (sample data, or a neighbour that was
        seen but never registered), shown from the topology data itself."""
        self.device = None
        self.selection = ('details', title)
        body = self._new_body()
        ctk.CTkLabel(body, text=title, font=(theme.FONT_FAMILY, 16, 'bold'), anchor='w',
                     text_color=theme.TEXT).grid(row=0, column=0, columnspan=2, sticky='ew',
                                                 pady=(4, 0))
        self._status(body, status, 1)
        row = self._rows(body, rows, 2)
        if note:
            self._note(body, row, note)

    def show_link(self, a, b, ports_a, ports_b, info_a=None, info_b=None, note=None):
        """One connection: the two devices and the interface used at each end."""
        self.device = None
        self.selection = ('link', (a, b))
        body = self._new_body()
        ctk.CTkLabel(body, text='Link', font=(theme.FONT_FAMILY, 16, 'bold'), anchor='w',
                     text_color=theme.TEXT).grid(row=0, column=0, columnspan=2, sticky='ew',
                                                 pady=(4, 0))
        ctk.CTkLabel(body, text=f'{a}  ↔  {b}', font=theme.mono(10), anchor='w',
                     text_color=theme.TEXT_SOFT).grid(row=1, column=0, columnspan=2,
                                                      sticky='ew', pady=(0, 8))

        def describe(info):
            if not info:
                return 'not registered'
            parts = [info.get('status', '?'), info.get('type', '?')]
            parts.append('managed' if info.get('managed') else 'unmanaged')
            return ', '.join(parts)
        rows = [(f'{a} port', ', '.join(ports_a), True), (f'{a}', describe(info_a), False),
                (f'{b} port', ', '.join(ports_b), True), (f'{b}', describe(info_b), False)]
        row = self._rows(body, rows, 2)
        actions = ctk.CTkFrame(body, fg_color=theme.SURFACE, corner_radius=0)
        actions.grid(row=row, column=0, columnspan=2, sticky='ew', pady=(14, 0))
        actions.grid_columnconfigure(0, weight=1)
        self.link_buttons = {}
        for i, name in enumerate((a, b)):
            btn = ctk.CTkButton(
                actions, text=f'Inspect {name}', height=30, corner_radius=3, font=theme.FONT,
                fg_color=theme.SURFACE, hover_color=theme.SURFACE_2, text_color=theme.TEXT,
                border_width=1, border_color=theme.BORDER_STRONG,
                command=lambda n=name: self.on_focus_device and self.on_focus_device(n))
            btn.grid(row=i, column=0, sticky='ew', pady=(0 if i == 0 else 6, 0))
            self.link_buttons[name] = btn
        if note:
            self._note(body, row + 1, note)

    def _status(self, body, status, row):
        up = status == 'up'
        self.status_label = ctk.CTkLabel(
            body, text=('●  up' if up else '□  down'), font=theme.FONT_BOLD, anchor='w',
            text_color=theme.SUCCESS if up else theme.DANGER)
        self.status_label.grid(row=row, column=0, columnspan=2, sticky='ew', pady=(0, 8))

    # ---------------------------------------------------------------- a registered device
    def show_device(self, device_id, extra_rows=()):
        """Show one registered device (read from the store). extra_rows: more
        (label, value, is_mono) facts from the topology, e.g. single point of failure.
        Returns the device, or None if it is gone."""
        d = self.store.get_device(device_id)
        body = self._new_body()
        self.device = d
        self.selection = ('device', device_id)
        if d is None:
            ctk.CTkLabel(body, text='This device is no longer registered.', font=theme.FONT,
                         anchor='w', text_color=theme.TEXT_MUTED).grid(row=0, column=0,
                                                                        columnspan=2, sticky='ew')
            return None
        ctk.CTkLabel(body, text=d['name'], font=(theme.FONT_FAMILY, 16, 'bold'), anchor='w',
                     text_color=theme.TEXT).grid(row=0, column=0, columnspan=2, sticky='ew',
                                                 pady=(4, 0))
        self._status(body, d['status'], 1)
        rows = [('IP address', d['ip'], True), ('Type', d['type'], False),
                ('Managed', 'yes (NetCommand can log in)' if d['managed'] else 'no', False)]
        if d.get('created_at'):
            rows.append(('Registered', d['created_at'].strftime('%Y-%m-%d %H:%M'), True))
        rows += list(extra_rows)
        self._rows(body, rows, 2)

        actions = ctk.CTkFrame(body, fg_color=theme.SURFACE, corner_radius=0)
        actions.grid(row=len(rows) + 2, column=0, columnspan=2, sticky='ew', pady=(14, 0))
        actions.grid_columnconfigure(0, weight=1)        # buttons stacked: the panel is narrow
        # A disabled CTkButton keeps its colour, so give it a visibly greyed-out one
        self.configure_button = ctk.CTkButton(
            actions, text=f"Configure {d['name']}", height=30, corner_radius=3,
            font=theme.FONT_BOLD, hover_color=theme.ACCENT_HOVER,
            fg_color=theme.ACCENT if d['managed'] else theme.SURFACE_2,
            text_color_disabled=theme.TEXT_MUTED,
            state='normal' if d['managed'] else 'disabled',
            command=lambda: self.on_configure and self.on_configure(d['name']))
        self.configure_button.grid(row=0, column=0, sticky='ew')
        self.devices_button = ctk.CTkButton(
            actions, text='Show in Devices', height=30, corner_radius=3, font=theme.FONT,
            fg_color=theme.SURFACE, hover_color=theme.SURFACE_2, text_color=theme.TEXT,
            border_width=1, border_color=theme.BORDER_STRONG,
            command=lambda: self.on_open_devices and self.on_open_devices(d['name']))
        self.devices_button.grid(row=1, column=0, sticky='ew', pady=(6, 0))
        if not d['managed']:
            ctk.CTkLabel(body, text='Not managed: NetCommand cannot log in to configure it.',
                         font=theme.FONT_SMALL, anchor='w', justify='left', wraplength=250,
                         text_color=theme.TEXT_MUTED).grid(row=len(rows) + 3, column=0,
                                                           columnspan=2, sticky='ew', pady=(6, 0))
        return d
