import queue
import threading
import tkinter as tk
from tkinter import ttk, messagebox

import validation
from gui import theme
from gui.db_status import database_ready, report_error
from store_errors import DatabaseUnavailable, DuplicateDeviceName

SAMPLE_BLOCKED = ('These are sample devices. They can only be approved in sample mode '
                  '(python main.py --demo). Untick Demo mode and scan the real network '
                  'to register devices.')
BLOCK_NOTE = 'Sample devices cannot be added to the database'


def run_scan(results, discover, username, password, seed_ip, demo):
    """Worker thread: never touches the window, reports through the queue."""
    try:
        devices, links = discover(username, password, seed_ip, demo)
        results.put(('done', devices, links))
    except Exception as err:
        results.put(('error', str(err)))


class ScanTab(ttk.Frame):
    def __init__(self, parent, store, discover, on_approved=None,
                 demo_default=False, find_gateway=None, sample_store=None):
        """sample_store: True when store is the in-memory sample store (db_fake),
        False for the real database. Defaults to demo_default."""
        super().__init__(parent, padding=theme.PAD)
        self.store, self.discover, self.on_approved = store, discover, on_approved
        self.find_gateway = find_gateway
        self.sample_store = demo_default if sample_store is None else bool(sample_store)
        self.results = queue.Queue()
        self.found, self.found_links, self.scanning = [], [], False
        # Where the CURRENT results came from, fixed when they arrive. The Demo
        # checkbox can be changed afterwards, so it must not decide this.
        self.found_is_sample, self._scan_is_demo = False, False

        ttk.Label(self, text='Scan the network', style='Title.TLabel').pack(anchor='w')
        ttk.Label(self, text='Plug in, type one login, and scan. The login is used '
                  'for this scan only unless you tick the box below.',
                  foreground='#555').pack(anchor='w', pady=(0, theme.PAD))

        form = ttk.Frame(self); form.pack(fill='x')
        self.user, self.pw, self.seed = tk.StringVar(), tk.StringVar(), tk.StringVar()
        self.demo = tk.IntVar(value=int(demo_default))
        self.save_login = tk.IntVar(value=1)
        for col, (label, var, show) in enumerate(
                [('Username', self.user, ''), ('Password', self.pw, '*'),
                 ('Seed IP (optional)', self.seed, '')]):
            ttk.Label(form, text=label).grid(row=0, column=col * 2, sticky='w', padx=(0, 4))
            ttk.Entry(form, textvariable=var, show=show, width=18).grid(
                row=0, column=col * 2 + 1, padx=(0, theme.PAD * 2))
        self.scan_btn = ttk.Button(form, text='Scan', style='Accent.TButton',
                                   command=self.on_scan)
        self.scan_btn.grid(row=0, column=6)

        opts = ttk.Frame(self); opts.pack(fill='x', pady=theme.PAD)
        ttk.Checkbutton(opts, text='Demo mode (use sample data, no network)',
                        variable=self.demo).pack(side='left')
        ttk.Checkbutton(opts, text='Save the login (encrypted) with approved devices',
                        variable=self.save_login).pack(side='left', padx=theme.PAD * 2)

        self.status = ttk.Label(self, text='Ready.'); self.status.pack(anchor='w')
        cols = [('name', 'Name', 150), ('ip', 'IP', 130), ('type', 'Type', 90),
                ('managed', 'Managed', 80), ('source', 'Source', 150)]
        self.tree = ttk.Treeview(self, columns=[c[0] for c in cols], show='headings',
                                 selectmode='extended')
        for key, title, width in cols:
            self.tree.heading(key, text=title)
            self.tree.column(key, width=width, anchor='w')

        # The button bar is packed at the bottom BEFORE the table, so a short window
        # shrinks the table instead of squeezing the Approve button out of sight.
        bar = ttk.Frame(self); bar.pack(side='bottom', fill='x')
        self.tree.pack(fill='both', expand=True, pady=theme.PAD)
        ttk.Button(bar, text='Select all', command=self.select_all).pack(side='left')
        self.approve_btn = ttk.Button(bar, text='Approve selected', style='Accent.TButton',
                                      command=self.approve)
        self.approve_btn.pack(side='right')
        # Shown next to the button when approval is blocked, so it is never a silent no-op
        self.block_note = ttk.Label(bar, style='Sample.TLabel', padding=(8, 3),
                                    text=BLOCK_NOTE)
        # A disabled button ignores its command, but a click still arrives here: explain why.
        self.approve_btn.bind('<Button-1>', self._explain_if_blocked, add='+')
        self.last_result = None     # what the last approval did (read by the main window)

    # ----- scanning -----
    def on_scan(self):
        if self.scanning:
            return
        demo = bool(self.demo.get())
        seed = self.seed.get().strip()
        if not demo:
            if not self.user.get().strip() or not self.pw.get():
                messagebox.showerror('Login needed', 'Enter the username and password.')
                return
            if not seed and self.find_gateway:
                seed = self.find_gateway() or ''
            if not seed:
                messagebox.showerror('Starting point needed',
                                     'Could not find the default gateway. Type a seed IP '
                                     '(for example the core switch).')
                return
            problem = validation.check_ip(seed)
            if problem:
                messagebox.showerror('Seed IP', problem)
                return
        self.scanning = True
        self._scan_is_demo = demo
        self.scan_btn.state(['disabled'])
        self.status.config(text='Scanning... this can take a minute.' if not demo
                           else 'Loading sample data...')
        threading.Thread(target=run_scan, daemon=True,
                         args=(self.results, self.discover, self.user.get().strip(),
                               self.pw.get(), seed, demo)).start()
        self.after(200, self.check_queue)

    def check_queue(self):
        try:
            msg = self.results.get_nowait()
        except queue.Empty:
            self.after(200, self.check_queue)    # nothing yet, look again
            return
        self.scanning = False
        self.scan_btn.state(['!disabled'])
        if msg[0] == 'error':
            self.status.config(text='Scan failed.')
            messagebox.showerror('Scan failed', msg[1])
        else:
            self.show_found(msg[1], msg[2], sample=self._scan_is_demo)

    def show_found(self, devices, links, sample=False):
        self.found, self.found_links = list(devices), list(links)
        self.found_is_sample = bool(sample) or any(d.get('sample') for d in self.found)
        self.tree.delete(*self.tree.get_children())
        label = 'SAMPLE' if self.found_is_sample else 'scan'
        for i, d in enumerate(self.found):
            self.tree.insert('', 'end', iid=str(i),
                             values=(d['name'], d['ip'], d['type'],
                                     'yes' if d['managed'] else 'no', label))
        self.tree.selection_set(self.tree.get_children())
        n_managed = sum(1 for d in self.found if d['managed'])
        sample_note = ' (SAMPLE DATA)' if self.found_is_sample else ''
        blocked = self.found_is_sample and not self.sample_store
        self.approve_btn.state(['disabled'] if blocked else ['!disabled'])
        if blocked:
            self.block_note.pack(side='right', padx=(0, theme.PAD))
        else:
            self.block_note.pack_forget()
        next_step = SAMPLE_BLOCKED if blocked else \
            'Select the ones to register and click Approve.'
        self.status.config(text=f'Found {len(self.found)} devices ({n_managed} managed) '
                                f'and {len(self.found_links)} links{sample_note}. {next_step}')

    def select_all(self):
        self.tree.selection_set(self.tree.get_children())

    # ----- approving -----
    def _explain_if_blocked(self, _event=None):
        if self.approve_btn.instate(['disabled']) and self.found_is_sample and not self.sample_store:
            messagebox.showinfo('Sample devices', SAMPLE_BLOCKED)

    def approve(self):
        picked = [self.found[int(i)] for i in self.tree.selection()]
        if not picked:
            messagebox.showinfo('Nothing selected', 'Select at least one device.')
            return
        if not database_ready(self):
            self.status.config(text='Database unavailable. Nothing was saved.')
            return
        if self.found_is_sample and not self.sample_store:     # never into the real database
            messagebox.showerror('Sample devices', SAMPLE_BLOCKED)
            return
        # The shared login is checked once, before anything is saved.
        user, password = self.user.get().strip(), self.pw.get()
        save_login = bool(self.save_login.get()) and not self.found_is_sample and bool(user)
        if save_login:
            problem = validation.check_login(user, password)       # never shows the password
            if problem:
                messagebox.showerror('Cannot save', f'Nothing was saved. {problem}')
                return
        # IPs that belong to soft-deleted devices are never restored silently: find them
        # first (read-only) and let the user decide per device.
        deleted = []
        try:
            for d in picked:
                # A sample device is never looked up in a real database (no SQL at all for it).
                if not (d.get('sample') and not self.sample_store):
                    gone = self.store.get_deleted_device_by_ip(d['ip'])
                    if gone:
                        deleted.append((d, gone))
        except Exception as err:
            report_error(self, err)
            self.last_result = {'ok': False, 'total': len(picked), 'saved': 0, 'error': str(err)}
            self.status.config(text='Approval failed. Nothing was saved.')
            messagebox.showerror('Could not save', f'Nothing was saved.\n\n{err}')
            return
        if deleted:
            self.restore_dialog = ScanRestoreDialog(
                self, deleted, can_replace=save_login,
                on_done=lambda plan: self._save_approved(picked, user, password, save_login, plan))
            return
        self._save_approved(picked, user, password, save_login, {})

    def _save_approved(self, picked, user, password, save_login, plan):
        """Save the approved devices. plan: {ip: {'restore': bool, 'credentials': 'keep' |
        'replace', 'device_id': id}} for IPs of deleted devices; None = the user cancelled."""
        if plan is None:
            self.status.config(text='Approval cancelled. Nothing was saved.')
            return
        saved, restored, skipped, added, updated, links = [], [], [], 0, 0, []
        current = None
        try:
            for i, d in enumerate(picked):
                current = i
                if d['ip'] in plan:                     # the IP of a deleted device
                    choice = plan[d['ip']]
                    if not choice['restore']:
                        skipped.append(d)               # stays deleted, nothing written
                        continue
                    if choice['credentials'] == 'replace':
                        self.store.restore_device(choice['device_id'], d, credentials='replace',
                                                  username=user, password=password)
                    else:
                        self.store.restore_device(choice['device_id'], d, credentials='keep')
                    saved.append(d)
                    restored.append(d)
                    continue
                existed = (not (d.get('sample') and not self.sample_store)
                           and self.store.get_device_by_ip(d['ip']) is not None)
                # One transaction per device: the device and its login, or neither.
                if save_login and d['managed']:
                    self.store.save_device(None, d, user, password)
                else:
                    self.store.save_device(None, d)
                saved.append(d)
                added, updated = (added, updated + 1) if existed else (added + 1, updated)
            current = None
            names = {d['name'] for d in saved}
            links = [l for l in self.found_links if l[0] in names and l[2] in names]
            self.store.save_links(links)
        except Exception as err:
            # Never report success: say exactly what was and was not saved.
            report_error(self, err)
            uncertain = isinstance(err, DatabaseUnavailable) and err.uncertain
            self.last_result = {'ok': False, 'total': len(picked), 'saved': len(saved),
                                'error': str(err)}
            failed = picked[current] if current is not None else None
            not_tried = picked[current + 1:] if current is not None else []
            if saved:
                detail = (f'{len(saved)} of {len(picked)} devices were saved before the error. '
                          f'The other devices and the links between them were not saved.')
            else:
                detail = ('No device was confirmed as saved.' if uncertain
                          else 'Nothing was saved.')
            lines = []
            if saved:
                lines.append('Saved: ' + ', '.join(
                    d['name'] + (' (restored)' if d in restored else '') for d in saved) + '.')
            if failed and uncertain:
                lines.append(f"Failed: {failed['name']}. The connection was lost while it was "
                             f"being committed, so it may or may not have been saved.")
            elif failed and isinstance(err, DuplicateDeviceName):
                lines.append(f"Failed (not saved, nothing of it kept): {failed['name']}: the "
                             f"name is already used by {err.existing['name']} "
                             f"(ID {err.existing['id']}).")
            elif failed:
                lines.append(f"Failed (not saved, nothing of it kept): {failed['name']}.")
            elif saved:
                lines.append('The devices were saved, but saving the links between them failed.')
            if skipped:
                lines.append('Not restored (still deleted): '
                             + ', '.join(d['name'] for d in skipped) + '.')
            if not_tried:
                lines.append('Not attempted: ' + ', '.join(d['name'] for d in not_tried) + '.')
            detail = detail + '\n' + '\n'.join(lines) if lines else detail
            self.status.config(text=f'Approval failed. {detail}')
            messagebox.showerror('Could not save', f'{detail}\n\n{err}')
            if saved and self.on_approved:          # some data did change: refresh the lists
                self.on_approved()
            return
        self.last_result = {'ok': True, 'total': len(picked), 'added': added,
                            'updated': updated, 'links': len(links)}
        if restored:
            self.last_result['restored'] = len(restored)
        if skipped:
            self.last_result['skipped'] = len(skipped)
        n = len(saved)
        count = f"{n} device{'' if n == 1 else 's'}"
        message = f'{count} registered.'
        if updated:
            message = f'{count} registered ({added} new, {updated} already registered and updated).'
        if restored:
            message += ' Restored: ' + ', '.join(d['name'] for d in restored) + '.'
        if skipped:
            message += ' Not restored (still deleted): ' + ', '.join(d['name'] for d in skipped) + '.'
        self.status.config(text=f'{message} See the Devices page.')
        messagebox.showinfo('Approved', message)
        if self.on_approved:
            self.on_approved()


class ScanRestoreDialog(tk.Toplevel):
    """Some discovered IPs belong to soft-deleted devices. One dialog, one row per device:
    the user ticks which to restore and, for each ticked one, chooses explicitly whether
    to keep that device's own saved login or use this scan's login. Nothing is preselected.
    Cancel stops the whole approval; nothing is saved."""

    def __init__(self, parent, deleted, can_replace, on_done):
        super().__init__(parent)
        self.deleted, self.can_replace, self.on_done = deleted, can_replace, on_done
        self.title('Deleted devices found')
        self.configure(padx=theme.PAD * 2, pady=theme.PAD * 2, background=theme.BG)
        self.resizable(False, False)
        ttk.Label(self, wraplength=520, justify='left',
                  text=f'{len(deleted)} discovered device(s) use the IP of a device that was '
                       f'deleted. They are not restored unless you tick them. A restored device '
                       f'gets back its history (logs and events). Unticked ones stay deleted '
                       f'and are not saved.').grid(row=0, column=0, columnspan=3, sticky='w',
                                                  pady=(0, theme.PAD))
        self.rows = []
        for r, (found, gone) in enumerate(deleted, start=1):
            restore, choice = tk.IntVar(value=0), tk.StringVar(value='')
            login = 'a login is saved' if gone['has_login'] else 'no login saved'
            ttk.Checkbutton(self, variable=restore,
                            text=f"Restore {gone['name']} ({gone['ip']}, {gone['type']}; "
                                 f"{login}) as {found['name']}").grid(row=r, column=0, sticky='w')
            ttk.Radiobutton(self, text='Keep its saved login', value='keep',
                            variable=choice).grid(row=r, column=1, sticky='w', padx=(10, 0))
            replace = ttk.Radiobutton(self, text="Use this scan's login", value='replace',
                                      variable=choice)
            replace.grid(row=r, column=2, sticky='w', padx=(10, 0))
            if not can_replace:
                replace.state(['disabled'])
            self.rows.append({'found': found, 'gone': gone, 'restore': restore, 'choice': choice})
        btns = ttk.Frame(self)
        btns.grid(row=len(deleted) + 1, column=0, columnspan=3, sticky='e', pady=(theme.PAD, 0))
        ttk.Button(btns, text='Cancel approval', command=self.cancel).pack(side='right')
        ttk.Button(btns, text='Continue', style='Accent.TButton',
                   command=self.confirm).pack(side='right', padx=4)
        self.protocol('WM_DELETE_WINDOW', self.cancel)
        self.transient(parent.winfo_toplevel())
        self.grab_set()

    def confirm(self):
        missing = [row['gone']['name'] for row in self.rows
                   if row['restore'].get() and row['choice'].get() not in ('keep', 'replace')]
        if missing:
            messagebox.showerror('Choose a login option', 'For each device you restore, choose '
                                 'whether to keep its saved login or use this scan\'s login: '
                                 + ', '.join(missing) + '.', parent=self)
            return
        bad = [row['gone']['name'] for row in self.rows
               if row['restore'].get() and row['choice'].get() == 'replace' and not self.can_replace]
        if bad:
            messagebox.showerror('No scan login', 'There is no scan login to use for: '
                                 + ', '.join(bad) + '.', parent=self)
            return
        chosen = [row for row in self.rows if row['restore'].get()]
        if chosen:
            names = ', '.join(row['gone']['name'] for row in chosen)
            if not messagebox.askyesno('Restore deleted devices',
                                       f'Restore {names}?', parent=self):
                return
        plan = {row['found']['ip']: {'restore': bool(row['restore'].get()),
                                     'credentials': row['choice'].get() or 'keep',
                                     'device_id': row['gone']['id']}
                for row in self.rows}
        self.destroy()
        self.on_done(plan)

    def cancel(self):
        self.destroy()
        self.on_done(None)
