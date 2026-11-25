"""Backup & Restore catalogue (Phase 4B): the encrypted backups (.ncbak), their metadata,
verification and matching against the selected device, and "Select for restore".

Selecting only RECORDS the choice for a future restore workflow: nothing is restored and
nothing is sent to any device. The decrypted configuration is never shown here.
Verification (decryption in memory) runs on a worker thread (gui.background.run_async)
so the window never freezes. Opened from the Devices page by roles with the Configure
permission; selection checks that permission again.
"""
import tkinter as tk
from tkinter import messagebox, ttk

import backup_catalogue as B
from gui import background, theme
from gui.components.dialogs import place_window
from gui.timefmt import format_timestamp_text
from gui.components.tables import setup_table

COLUMNS = [('created', 'Created (UTC)', 150), ('host', 'Device IP', 100),
           ('hostname', 'Hostname', 110), ('platform', 'Platform', 110),
           ('serial', 'Serial', 100), ('ios', 'IOS version', 90), ('key', 'Key', 40),
           ('source', 'Source', 120), ('size', 'Size', 70), ('sha', 'SHA-256', 90),
           ('status', 'Verification', 150), ('match', 'Match', 190)]


def short(value, length=12):
    return f'{value[:length]}…' if isinstance(value, str) and len(value) > length else (value or '')


class BackupCatalogueWindow(tk.Toplevel):
    def __init__(self, parent, device, can_select, on_select=None, backup_dir=None,
                 key_source=None, on_restore=None):
        """device: backup_catalogue.Device; on_select(selection) records a choice;
        on_restore(selection) opens the Restore window (Phase 4G) for the selected backup."""
        super().__init__(parent)
        self.device, self.can_select, self.on_select = device, bool(can_select), on_select
        self.on_restore = on_restore
        self.backup_dir, self.key_source = backup_dir, key_source
        self.entries, self.verifications, self.busy = {}, {}, False
        self.title(f'Backups - {device.hostname or device.ip} ({device.ip})')
        self.configure(background=theme.SURFACE)
        place_window(self, parent, size=(1180, 620))      # scaled, on screen, centered

        top = ttk.Frame(self, padding=theme.PAD)
        top.pack(fill='x')
        ttk.Label(top, text=f'Device: {device.hostname or "?"}  {device.ip}   -   encrypted '
                            f'backups (.ncbak). Selecting a backup sends nothing to the device.'
                  ).pack(side='left')
        self.show_all = tk.BooleanVar(value=False)
        ttk.Checkbutton(top, text='Show backups of all devices', variable=self.show_all,
                        command=self.fill).pack(side='right')

        self.tree = ttk.Treeview(self, columns=[c[0] for c in COLUMNS], show='headings',
                                 selectmode='browse', style='Data.Treeview', height=12)
        setup_table(self.tree, COLUMNS)
        self.tree.pack(fill='both', expand=True, padx=theme.PAD)
        self.tree.bind('<<TreeviewSelect>>', lambda e: self.show_details())

        self.details = tk.Text(self, height=11, wrap='word', background=theme.SURFACE,
                               foreground=theme.TEXT, relief='flat')
        self.details.pack(fill='x', padx=theme.PAD, pady=(theme.PAD, 0))
        self.details.configure(state='disabled')

        bar = ttk.Frame(self, padding=theme.PAD)
        bar.pack(fill='x')
        self.refresh_btn = ttk.Button(bar, text='Refresh', command=self.refresh)
        self.verify_btn = ttk.Button(bar, text='Verify selected', command=self.verify_selected)
        self.verify_all_btn = ttk.Button(bar, text='Verify all shown', command=self.verify_shown)
        self.select_btn = ttk.Button(bar, text='Select for restore', style='Accent.TButton',
                                     command=self.select)
        for b in (self.refresh_btn, self.verify_btn, self.verify_all_btn):
            b.pack(side='left', padx=(0, 6))
        ttk.Button(bar, text='Close', command=self.destroy).pack(side='right')
        self.restore_btn = ttk.Button(bar, text='Restore...', command=self.open_restore)
        self.restore_btn.pack(side='right')
        self.restore_btn.state(['disabled'])                # enabled once a backup is selected
        self.select_btn.pack(side='right', padx=6)
        self.status = ttk.Label(bar, text='', foreground=theme.TEXT_MUTED)
        self.status.pack(side='left', padx=theme.PAD)
        self.selection = None
        self.refresh()

    # ------------------------------------------------------------ listing
    def refresh(self):
        locations = B.approved_locations(self.backup_dir)
        entries, notes = B.scan(locations)
        self.entries = {e.path: e for e in entries}
        self.verifications = {}
        self.notes = notes
        self.locations = locations
        self.fill()

    def _for_device(self, e):
        if e.header is None:
            return True                                # invalid files stay visible
        hostname = e.field('hostname')
        return e.field('host') == self.device.ip or (
            isinstance(hostname, str) and self.device.hostname and
            hostname.casefold() == self.device.hostname.casefold())

    def shown(self):
        return [e for e in self.entries.values() if self.show_all.get() or self._for_device(e)]

    def fill(self):
        self.tree.delete(*self.tree.get_children())
        for e in sorted(self.shown(), key=lambda e: (e.field('created_utc') or '', e.filename),
                        reverse=True):
            ident = e.identity
            m = B.match(e.verified_header or e.header, self.device) if e.header else None
            match_text = m.summary if m else ''
            if m and not e.trusted:
                match_text += ' (unverified)'
            # shown in local 12-hour time; the order above uses the stored UTC value
            self.tree.insert('', 'end', iid=e.path, values=(
                format_timestamp_text(e.field('created_utc')), e.field('host') or '',
                ident['hostname'],
                ident['platform'], ident['serial'], ident['ios_version'], e.field('key_id') or '',
                e.field('source') or '', e.size, short(e.field('plaintext_sha256')),
                e.status + (' (duplicate copy)' if e.duplicate_of else ''), match_text))
        usable = [l for l in self.locations if l.status == B.OK]
        self.status.config(text=f'{len(self.shown())} shown of {len(self.entries)} backups in '
                                f'{len(usable)} folder(s).')
        self.show_details()

    def current(self):
        sel = self.tree.selection()
        return self.entries.get(sel[0]) if sel else None

    # ------------------------------------------------------------ details
    def details_text(self, e):
        lines = ['Folders searched (top level only; links and junctions are not followed):']
        lines += [f'  {l.label}: {l.path} - {l.status}' + (f' ({l.problem})' if l.problem else '')
                  for l in self.locations]
        lines += [f'  note: {n}' for n in self.notes]
        if e is None:
            return '\n'.join(lines + ['', 'Select a backup to see its details.'])
        ident = e.identity
        trusted = 'authenticated (verified)' if e.trusted else \
            'NOT yet verified: read from the readable header, not trusted until verified'
        lines += ['', f'File: {e.path}  ({e.location}, {e.size} bytes)',
                  f'File SHA-256: {e.file_sha256}',
                  f'Status: {e.status}' + (f' - {e.problem}' if e.problem else ''),
                  f'Metadata: {trusted}']
        if e.duplicate_of:
            lines.append(f'Duplicate copy of: {e.duplicate_of}')
        if e.header:
            lines += [f"Device IP {e.field('host') or 'not recorded'}, created "
                      f"{format_timestamp_text(e.field('created_utc'))}, source "
                      f"{e.field('source') or 'not recorded'}, "
                      f"key {e.field('key_id')}",
                      f"Configuration SHA-256: {e.field('plaintext_sha256')} "
                      f"({e.field('plaintext_size')} bytes)",
                      f"Identity: hostname {ident['hostname']}, platform {ident['platform']}, "
                      f"serial {ident['serial']}, IOS version {ident['ios_version']}"]
            m = B.match(e.verified_header or e.header, self.device)
            lines.append(f'Match with {self.device.hostname or "?"} ({self.device.ip}): '
                         f'{m.summary}')
            lines += [f'  - {text}' for _field, _outcome, text in m.checks]
            if m.live_identity_required and not m.blocked:
                lines.append('  PENDING RESTORE CANDIDATE, NOT a verified match: the restore '
                             'preflight must read the device\'s serial number and platform and '
                             'find both equal to this backup, or the restore is blocked.')
            elif m.requires_legacy_confirmation and not m.blocked:
                lines.append('  A future restore of this backup needs the legacy-backup '
                             'confirmation (matching IP and the typed device name).')
        return '\n'.join(lines)

    def show_details(self):
        e = self.current()
        self.details.configure(state='normal')
        self.details.delete('1.0', 'end')
        self.details.insert('1.0', self.details_text(e))
        self.details.configure(state='disabled')
        allowed = bool(self.can_select and e is not None and e.trusted and
                       not self.busy and not B.match(e.verified_header, self.device).blocked)
        self.select_btn.state(['!disabled'] if allowed else ['disabled'])
        self.verify_btn.state(['!disabled'] if e is not None and not self.busy else ['disabled'])

    # ------------------------------------------------------------ verification
    def verify_selected(self):
        e = self.current()
        if e is not None:
            self._verify([e])

    def verify_shown(self):
        self._verify([e for e in self.shown() if e.header is not None])

    def _verify(self, entries):
        if self.busy or not entries:
            return
        self.busy = True
        from gui import activity
        activity.start('backups', f'{len(entries)} backup(s) are still being verified.')
        for b in (self.refresh_btn, self.verify_btn, self.verify_all_btn, self.select_btn):
            b.state(['disabled'])
        self.status.config(text=f'Verifying {len(entries)} backup(s)...')
        key_source = self.key_source

        def work():                                   # worker thread: no widgets here
            key_for, problem = B.keyring_lookup(key_source)
            return [(e.path, B.verify(e, key_for, problem)) for e in entries]

        def done(results, error):
            self.busy = False
            activity.finish('backups')
            for b in (self.refresh_btn, self.verify_all_btn):
                b.state(['!disabled'])
            if error is not None:
                self.status.config(text=f'Verification stopped ({type(error).__name__}).')
            else:
                for path, result in results:
                    self.verifications[path] = result
                ok = sum(r.status == B.VERIFIED for _, r in results)
                self.status.config(text=f'{ok} of {len(results)} verified.')
            chosen = self.tree.selection()
            self.fill()
            if chosen and self.tree.exists(chosen[0]):
                self.tree.selection_set(chosen[0])      # keep the user's selection
            self.show_details()
        background.run_async(self, work, done)

    # ------------------------------------------------------------ selection
    def select(self):
        e = self.current()
        if e is None:
            return
        try:
            selection = B.select(e, self.verifications.get(e.path), self.device,
                                 self.can_select)
        except B.SelectionRefused as err:
            messagebox.showerror('Cannot select this backup', str(err), parent=self)
            return
        self.selection = selection
        if self.on_select:
            self.on_select(selection)
        if self.on_restore and self.can_select:
            self.restore_btn.state(['!disabled'])
        if selection.live_identity_required:
            note = ('\n\nThis is a PENDING CANDIDATE, not a verified match: its recorded IP '
                    'address differs. The restore preflight will read the device\'s serial '
                    'number and platform and block the restore unless both match.')
        elif selection.requires_legacy_confirmation:
            note = ('\n\nIts hardware identity is not confirmed by serial number: a future '
                    'restore will need the legacy-backup confirmation.')
        else:
            note = ''
        messagebox.showinfo('Backup selected',
                            f'{e.filename} is selected for a future restore of '
                            f'{self.device.hostname or self.device.ip}.\n\nNothing was sent to '
                            f'the device; restoring is not available yet.{note}', parent=self)

    def open_restore(self):
        """The Restore window for the selected backup (it connects only when the user runs
        its checks)."""
        if self.selection is None or not self.can_select or not self.on_restore:
            return
        self.on_restore(self.selection)
