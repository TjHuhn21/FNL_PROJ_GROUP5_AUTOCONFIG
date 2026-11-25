import tkinter as tk
from tkinter import ttk, messagebox

import device_types
import validation
from gui import theme
from gui.components.dialogs import confirm, place_window
from gui.components.tables import setup_table
from gui.components.wrap_frame import WrapFrame
from gui.db_status import database_ready, report_error
from gui.event_log import log_event
from store_errors import DATABASE_ERRORS, DeletedDeviceExists, DuplicateDeviceName, outcome_text

PER_PAGE = 15
# (key, title, relative width): gui/components/tables.setup_table aligns and fits them
COLUMNS = [('name', 'Name', 230), ('ip', 'IP', 140), ('type', 'Type', 190),
           ('status', 'Status', 80), ('managed', 'Managed', 85)]
SORTABLE = {'name', 'ip', 'type', 'status'}
TYPE_COLUMN = '#3'                    # the Type column, as Treeview.identify_column names it
MANUAL_MARK = '⚠'                     # before a type that differs from the scan's detection


class DevicesTab(ttk.Frame):
    def __init__(self, parent, store, on_change=None):
        super().__init__(parent, padding=theme.PAD)
        self.store, self.on_change = store, on_change
        self.page, self.sort_by = 1, 'name'

        # the search on the left, the buttons on the right; on a narrow window the buttons
        # wrap onto a second row instead of being cut off
        top = WrapFrame(self, background=theme.BG); top.pack(fill='x')
        top.add(ttk.Label(top, text='Search:'), padx=(0, 0))
        self.search = tk.StringVar()
        entry = ttk.Entry(top, textvariable=self.search, width=30)
        top.add(entry, padx=theme.PAD)
        entry.bind('<KeyRelease>', lambda e: self.go_first())
        self.read_only = False
        self.add_btn = ttk.Button(top, text='Add', command=self.add)
        self.delete_btn = ttk.Button(top, text='Delete', command=self.delete)
        self.edit_btn = ttk.Button(top, text='Edit', command=self.edit)
        # Backup & Restore catalogue (Phase 4B). Only for roles with the Configure
        # permission (set_backups_allowed); disabled until the main window allows it.
        self.backups_allowed, self.on_backup_selected = False, None
        self.on_restore_finished = None                     # Restore window results (4G)
        self.on_save_finished = None                        # Save to Startup results (4H)
        self.backups_btn = ttk.Button(top, text='Backups...', command=self.open_backups)
        self.backups_btn.state(['disabled'])
        top.add(self.backups_btn, padx=(0, 12), push_right=True)
        top.add(self.edit_btn, padx=(0, 0))
        top.add(self.delete_btn, padx=4)
        top.add(self.add_btn, padx=(0, 0))

        self.tree = ttk.Treeview(self, columns=[c[0] for c in COLUMNS],
                                 show='headings', selectmode='extended', style='Data.Treeview')
        setup_table(self.tree, COLUMNS, no_tooltip=('type',),      # Type has its own tooltip
                    commands={k: (lambda k=k: self.sort(k)) for k in SORTABLE})
        for status, color in theme.STATUS_COLORS.items():
            self.tree.tag_configure(status, background=color)
        self.tree.pack(fill='both', expand=True, pady=theme.PAD)
        self.tree.bind('<Double-1>', lambda e: self.edit())
        # "Detected as router by scan" when the pointer is on a manually changed Type
        self.type_tips, self._tip, self._tip_row = {}, None, None
        self.tree.bind('<Motion>', self._hover, add='+')
        self.tree.bind('<Leave>', lambda e: self._hide_tip(), add='+')

        # The empty state: what to do next instead of a blank table
        self.on_go_scan = None                       # set by the main window
        self.empty_box = ttk.Frame(self)
        self.empty_box.pack()
        self.empty = ttk.Label(self.empty_box, text='', foreground=theme.TEXT_MUTED)
        self.empty.pack(side='left')
        self.go_scan_btn = ttk.Button(self.empty_box, text='Go to Scan',
                                      command=lambda: self.on_go_scan and self.on_go_scan())

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
        self.type_tips = {}
        for d in rows:
            kind = device_types.type_label(d)
            if device_types.manually_changed(d):
                kind = f'{MANUAL_MARK} {kind}'
                self.type_tips[str(d['id'])] = device_types.detected_tooltip(d)
            self.tree.insert('', 'end', iid=str(d['id']), tags=(d['status'],),
                             values=(d['name'], d['ip'], kind, d['status'],
                                     'yes' if d['managed'] else 'no'))
        self.go_scan_btn.pack_forget()
        if total == 0:
            from gui import guide_content
            self.empty.config(text='No devices match your search.' if text else
                              guide_content.EMPTY['devices'])
            if not text and self.on_go_scan is not None:
                self.go_scan_btn.pack(side='left', padx=(theme.PAD, 0))
        else:
            self.empty.config(text='')
        self.page_label.config(text=f'Page {self.page} of {pages}  ({total} devices)')
        self.prev_btn.state(['!disabled'] if self.page > 1 else ['disabled'])
        self.next_btn.state(['!disabled'] if self.page < pages else ['disabled'])

    def type_tip_at(self, x, y):
        """(row id, tooltip text) for the Type cell at x, y, or (None, '')."""
        if self.tree.identify_column(x) != TYPE_COLUMN:
            return None, ''
        row = self.tree.identify_row(y)
        return (row, self.type_tips[row]) if row in self.type_tips else (None, '')

    def _hover(self, event):
        row, text = self.type_tip_at(event.x, event.y)
        if row == self._tip_row:
            return
        self._hide_tip()
        if not text:
            return
        self._tip_row = row
        self._tip = tk.Toplevel(self.tree)
        self._tip.wm_overrideredirect(True)
        self._tip.wm_geometry(f'+{event.x_root + 12}+{event.y_root + 14}')
        tk.Label(self._tip, text=text, font=theme.FONT_SMALL, background=theme.CARD,
                 foreground=theme.TEXT, relief='solid', borderwidth=1, padx=6,
                 pady=3).pack()

    def _hide_tip(self):
        self._tip_row = None
        if self._tip is not None:
            try:
                self._tip.destroy()
            except tk.TclError:
                pass
            self._tip = None

    def show_unavailable(self, reason=''):
        """The list could not be read: show no rows at all (never old rows as if current)."""
        self.tree.delete(*self.tree.get_children())
        self.go_scan_btn.pack_forget()
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

    def set_backups_allowed(self, allowed):
        """Roles with the Configure permission may open the backup catalogue and select a
        backup for a future restore; others (viewers) may not."""
        self.backups_allowed = bool(allowed)
        self.backups_btn.state(['!disabled'] if self.backups_allowed else ['disabled'])

    def open_backups(self):
        """The Backup & Restore catalogue for the selected device (read-only: it never
        connects to the device)."""
        if not self.backups_allowed:
            return
        device_id = self.selected_id()
        if device_id is None:
            return
        try:
            d = self.store.get_device(device_id)
        except Exception as err:
            report_error(self, err)
            return
        if not d:
            return
        import backup_catalogue
        from gui.backup_catalogue_window import BackupCatalogueWindow
        device = backup_catalogue.Device(ip=d['ip'], hostname=d.get('name'),
                                         device_id=d.get('id'))
        self.backups_window = BackupCatalogueWindow(
            self, device, self.backups_allowed, on_select=self.on_backup_selected,
            on_restore=lambda selection: self.open_restore(selection, d))

    def open_restore(self, selection, d):
        """The Restore window (Phase 4G) for a backup selected in the catalogue. Opening it
        connects to nothing; the login is read (or asked for) when the checks start."""
        if not self.backups_allowed:
            return
        import backup_catalogue
        from gui.restore_window import RestoreWindow
        device = backup_catalogue.Device(ip=d['ip'], hostname=d.get('name'),
                                         device_id=d.get('id'))
        self.restore_window = RestoreWindow(self, selection, device, self.backups_allowed,
                                            lambda: self._restore_login(d),
                                            on_finished=self.on_restore_finished)
        self.restore_window.on_save_finished = self.on_save_finished

    def _restore_login(self, d):
        """{'host', 'username', 'password'} from the saved login, else asked for (not
        saved); None when the user cancels."""
        from gui.components import login_dialog
        from security import CredentialError
        reason = 'missing'
        try:
            user, password = self.store.get_credentials(d['id'])
        except CredentialError:
            user, password, reason = None, None, 'unreadable'
        if user:
            return {'host': d['ip'], 'username': user, 'password': password}
        answer = login_dialog.ask_device_login(self, [d], reason=reason)
        if not answer:
            return None
        return {'host': d['ip'], 'username': answer['username'],
                'password': answer['password']}

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

    def selected_ids(self):
        """Every selected device id (in list order); says so when none is selected."""
        sel = self.tree.selection()
        if not sel:
            messagebox.showinfo('Select a device', 'Click a device in the list first.')
            return []
        return [int(i) for i in sel]

    def delete(self):
        ids = self.selected_ids() if not self.read_only else []
        if not ids or not database_ready(self):
            return
        try:
            devices = [self.store.get_device(did) for did in ids]
        except DATABASE_ERRORS as err:
            report_error(self, err)
            messagebox.showerror('Cannot delete', f'Nothing was deleted. {err}')
            return
        devices = [d for d in devices if d is not None]
        if not devices:
            messagebox.showinfo('Device gone', 'This device is no longer registered.')
            self.refresh()
            return
        names = ', '.join(f"{d['name']} ({d['ip']})" for d in devices)
        if not confirm('Delete device' if len(devices) == 1 else 'Delete devices',
                       delete_text(devices),
                       'Delete device' if len(devices) == 1 else f'Delete {len(devices)} devices',
                       parent=self, danger=True):
            log_event('devices', f'Delete of {names} cancelled. Nothing was deleted.')
            return
        deleted = []
        for d in devices:
            log_event('devices', f"Deleting {d['name']} ({d['ip']})...")
            try:
                self.store.delete_device(d['id'])
            except DATABASE_ERRORS as err:
                report_error(self, err)
                done = (f" Deleted before the error: {', '.join(x['name'] for x in deleted)}."
                        if deleted else '')
                log_event('devices', f"Delete of {d['name']} FAILED. "
                                     f"{outcome_text(err, 'Nothing was deleted.')} {err}{done}",
                          'error')
                who = f"{d['name']}: " if len(devices) > 1 else ''
                messagebox.showerror('Delete failed',
                                     f"{who}{outcome_text(err, 'Nothing was deleted.')} "
                                     f"{err}{done}")
                if deleted:
                    self._saved()
                return
            deleted.append(d)
            log_event('devices', f"Delete of {d['name']} ({d['ip']}) SUCCESSFUL (its history "
                                 f"is kept).", 'ok', tags=['change'], device=d['name'],
                      ip=d['ip'])
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
                     'managed': tk.IntVar(value=int(d['managed'])),
                     'username': tk.StringVar(), 'password': tk.StringVar()}
        self.name_entry = ttk.Entry(self, textvariable=self.vars['name'], width=30)
        self.type_box = ttk.Combobox(self, textvariable=self.vars['type'], width=27,
                                     values=list(device_types.TYPES), state='readonly')
        detected = device_types.detected_tooltip(device)
        # The status is the background monitor's (ping / SSH port): shown, never edited here.
        status_text = (f"{d['status']} (set automatically by the monitor)" if device
                       else 'Set automatically by the monitor')
        self.status_label = ttk.Label(self, text=status_text, foreground=theme.TEXT_MUTED)
        rows = [('Name', self.name_entry),
                ('IP address', ttk.Entry(self, textvariable=self.vars['ip'], width=30)),
                ('Type', self.type_box)]
        if detected:
            rows.append(('', ttk.Label(self, text=detected + '.', foreground=theme.TEXT_MUTED)))
        self.managed_box = ttk.Checkbutton(self, text='Managed (we can log in)',
                                           variable=self.vars['managed'])
        from gui.components.tooltip import tip
        tip(self.managed_box, 'managed')
        rows += [('Status', self.status_label),
                ('', self.managed_box),
                ('Login username', ttk.Entry(self, textvariable=self.vars['username'], width=30)),
                ('Login password', ttk.Entry(self, textvariable=self.vars['password'],
                                             show='*', width=30))]
        for r, (label, widget) in enumerate(rows):
            ttk.Label(self, text=label).grid(row=r, column=0, sticky='w', pady=3)
            widget.grid(row=r, column=1, pady=3, padx=theme.PAD)
        hint = 'Optional. Saved encrypted. Leave both blank to keep the current login.' \
            if device else 'Optional. Saved encrypted, used by Configure and Review.'
        ttk.Label(self, text=hint, foreground=theme.TEXT_MUTED).grid(row=len(rows), column=0,
                                                           columnspan=2, sticky='w')
        btns = ttk.Frame(self); btns.grid(row=len(rows) + 1, column=0, columnspan=2,
                                          sticky='e', pady=(theme.PAD, 0))
        ttk.Button(btns, text='Cancel', command=self.close).pack(side='right')
        ttk.Button(btns, text='Save', style='Accent.TButton',
                   command=self.save).pack(side='right', padx=4)
        self._initial = self._values()
        self.protocol('WM_DELETE_WINDOW', self.close)
        self.bind('<Escape>', lambda e: self.close())
        place_window(self, parent)                  # sized for its content, centered
        self.transient(parent.winfo_toplevel())
        self.grab_set()

    def _values(self):
        return {k: var.get() for k, var in self.vars.items()}

    def has_unsaved(self):
        return self._values() != self._initial

    def close(self):
        """Cancel / Esc / the X: ask first when something was typed or changed."""
        if self.has_unsaved() and not confirm(
                'Unsaved changes', 'You have unsaved changes. Discard them?', 'Discard',
                cancel_text='Stay', parent=self, danger=True,
                log=('devices', f"Discarding the {'edit' if self.device else 'new device'} "
                                f"form")):
            return False
        self.destroy()
        return True

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
        if not self._type_change_confirmed(name, v['type']):
            return                                   # the dialog stays open, nothing saved
        if self.device and ip != self.device['ip']:
            if not confirm('Change IP address', ip_change_text(name, self.device['ip'], ip),
                           'Change IP', parent=self,
                           log=('devices', f"{name}: IP change {self.device['ip']} -> {ip}")):
                return                               # the dialog stays open, nothing saved
        # A new device starts as up (the monitor corrects it); an edit keeps the monitor's.
        data = {'name': name, 'ip': ip, 'type': v['type'], 'managed': bool(v['managed'])}
        if not self.device:
            data['status'] = 'up'
        action = 'Saving changes to' if self.device else 'Adding'
        log_event('devices', f'{action} device {name} ({ip})...')
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
            log_event('devices', f"IP {ip} belongs to the deleted device {err.device['name']}: "
                                 f"asking whether to restore it. Nothing saved yet.", 'warn')
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
        login = ' (login saved, encrypted)' if username else ''
        if self.device:
            changes = changes_text(self.device, data, bool(username))
            log_event('devices', f'Edit of {name} ({ip}) SUCCESSFUL: '
                                 f"{changes or 'nothing was changed'}.", 'ok',
                      tags=['change'] if changes else None, device=name, ip=ip)
        else:
            log_event('devices', f"Add of {name} ({ip}, {data['type']}) SUCCESSFUL{login}.",
                      'ok', tags=['change'], device=name, ip=ip)
        self.destroy()
        self.on_saved()

    def _type_change_confirmed(self, name, new_type):
        """Editing a device's type needs a confirmation (only when the type changed).
        Cancel puts the original type back and saves nothing."""
        if not self.device or new_type == self.device['type']:
            return True
        old_type = self.device['type']
        title, text = type_change_text(name, self.device.get('detected_type'), new_type)
        if ask_type_change(self, title, text):
            log_event('devices', f'{name}: type change from {old_type} to {new_type} '
                                 f'confirmed.', 'warn', device=name)
            return True
        self.vars['type'].set(old_type)
        log_event('devices', f'{name}: type change to {new_type} cancelled. Nothing was saved.')
        return False

    def _restored(self):
        self.destroy()
        self.on_saved()


def delete_text(devices):
    """The delete question: what disappears, and what is kept (a delete is a soft delete)."""
    if len(devices) == 1:
        d = devices[0]
        head = f"Delete {d['name']} ({d['ip']})?"
        it, its = d['name'], 'its'
    else:
        head = f'Delete these {len(devices)} devices?\n' + ''.join(
            f"\n   {d['name']} ({d['ip']})" for d in devices)
        it, its = 'They', 'their'
    return (f'{head}\n\n{it} will be removed from the device list, the topology map (with '
            f'{its} links), Configure and the status monitor.\n\n'
            f'{its.capitalize()} history (logs, events) and backup files are kept, and so is '
            f'the saved login (hidden). A later scan or Add with the same IP can restore '
            f'{"it" if len(devices) == 1 else "them"}.')


def ip_change_text(name, old_ip, new_ip):
    return (f"Change {name}'s IP from {old_ip} to {new_ip}?\n\n"
            f'The monitor, Configure and the saved login will use the new IP. Make sure the '
            f'device really has this address, or NetCommand cannot reach it.')


CHANGE_FIELDS = (('name', 'name'), ('ip', 'IP'), ('type', 'type'), ('managed', 'managed'))


def changes_text(before, after, login_changed=False):
    """'type changed router -> switch; name changed R1 -> MOCK-R1' for an edit ('' when
    nothing changed). The login is only said to be replaced, never shown."""
    def shown(key, value):
        return ('yes' if value else 'no') if key == 'managed' else str(value)
    parts = [f'{label} changed {shown(key, before.get(key))} -> {shown(key, after[key])}'
             for key, label in CHANGE_FIELDS
             if key in after and shown(key, before.get(key)) != shown(key, after[key])]
    if login_changed:
        parts.append('login replaced (saved encrypted, not shown)')
    return '; '.join(parts)


def type_change_text(name, detected, new_type):
    """(title, text) of the confirmation: the full warning when the scan definitely
    detected another type, a simpler question otherwise (unknown, or added by hand)."""
    if detected in device_types.KNOWN and new_type != detected:
        what = {'switch': 'switch commands', 'router': 'router commands'}.get(
            new_type, 'no switch or router settings')
        effect = (f'NetCommand will send {what} to a {detected}' if new_type in device_types.KNOWN
                  else f'NetCommand will not send switch or router settings to it')
        return ('Change device type?',
                f'{name} was detected as a {detected.upper()} by the scan.\n'
                f'Are you sure you want to change it to {new_type.upper()}?\n\n'
                f'If this is wrong, configuration on this device may fail, because {effect}.')
    return 'Change device type?', f"Set {name}'s type to {new_type.upper()}?"


def ask_type_change(parent, title, text):
    """The shared confirmation with the buttons 'Yes, change it' and 'Cancel'. True for
    yes. (Tests replace it.)"""
    return confirm(title, text, 'Yes, change it', parent=parent)


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
        place_window(self, parent)
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
        log_event('devices', f"Restore of {d['name']} ({d['ip']}) as {self.data['name']} "
                             f"SUCCESSFUL.", 'ok', tags=['change'], device=self.data['name'],
                  ip=d['ip'])
        self.destroy()
        self.on_restored()
