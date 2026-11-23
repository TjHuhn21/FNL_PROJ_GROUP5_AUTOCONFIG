import queue
import threading
from datetime import datetime
import tkinter as tk
from tkinter import ttk, messagebox

import validation
from gui import theme
from gui.db_status import database_ready, report_error
from gui.event_log import log_event
from store_errors import DatabaseUnavailable, DuplicateDeviceName

SAMPLE_BLOCKED = ('These are sample devices. They can only be approved in sample mode '
                  '(python main.py --demo). Untick Demo mode and scan the real network '
                  'to register devices.')
BLOCK_NOTE = 'Sample devices cannot be added to the database'
SEED_NEEDED = ('Type the management IP address of the switch or router to log in to. '
               'NetCommand logs in only to that device; its CDP/LLDP neighbours are '
               'listed without logging in to them.')
NEIGHBOUR_WARNING = ('NetCommand will also try this username and password on EVERY '
                     'CDP/LLDP neighbour that has a management IP address, so the login is '
                     'sent to those devices too.\n\nOnly do this on a network you control, '
                     'where all neighbours are expected to use this login.\n\nContinue?')


def run_scan(results, discover, username, password, seed_ip, demo, login_neighbours=False):
    """Worker thread: never touches the window, reports through the queue.
    The neighbour option is passed only when it is on (older discover callables
    take four arguments)."""
    try:
        args = (username, password, seed_ip, demo) + ((True,) if login_neighbours else ())
        devices, links = discover(*args)
        results.put(('done', devices, links))
    except Exception as err:
        results.put(('error', str(err)))


class ScanTab(ttk.Frame):
    def __init__(self, parent, store, discover, on_approved=None,
                 demo_default=False, sample_store=None):
        """sample_store: True when store is the in-memory sample store (db_fake),
        False for the real database. Defaults to demo_default."""
        super().__init__(parent, padding=theme.PAD)
        self.store, self.discover, self.on_approved = store, discover, on_approved
        self.sample_store = demo_default if sample_store is None else bool(sample_store)
        self.results = queue.Queue()
        self.found, self.found_links, self.scanning = [], [], False
        # Where the CURRENT results came from, fixed when they arrive. The Demo
        # checkbox can be changed afterwards, so it must not decide this.
        self.found_is_sample, self._scan_is_demo = False, False
        # This session's scans and approvals, newest last (memory only: a scan that is not
        # approved leaves nothing in the database). Read by the Overview page.
        self.history = []
        self.on_activity = None                  # called after each entry (Overview refresh)
        self._scan_seed = ''

        ttk.Label(self, text='Scan the network', style='Title.TLabel').pack(anchor='w')
        ttk.Label(self, text='Type the device login and its management IP (Seed IP), then '
                  'scan. Only that device is logged in to; its neighbours are listed from '
                  'CDP/LLDP. The login is used for this scan only unless you tick the box below.',
                  foreground=theme.TEXT_SOFT, wraplength=760, justify='left').pack(
                      anchor='w', pady=(0, theme.PAD))

        form = ttk.Frame(self); form.pack(fill='x')
        self.user, self.pw, self.seed = tk.StringVar(), tk.StringVar(), tk.StringVar()
        self.demo = tk.IntVar(value=int(demo_default))
        self.save_login = tk.IntVar(value=1)
        self.login_neighbours = tk.IntVar(value=0)       # off: only the seed gets the login
        # Larger form text (theme.FONT_FORM). Each label sits above its field, so the
        # wider text still fits on one line next to the inspector (no horizontal overflow).
        self.entries = {}
        for col, (label, var, show) in enumerate(
                [('Username', self.user, ''), ('Password', self.pw, '*'),
                 ('Seed IP', self.seed, '')]):
            ttk.Label(form, text=label, style='Form.TLabel').grid(
                row=0, column=col, sticky='w', padx=(0, theme.PAD * 2), pady=(0, 2))
            entry = ttk.Entry(form, textvariable=var, show=show, width=17, font=theme.FONT_FORM)
            entry.grid(row=1, column=col, sticky='w', padx=(0, theme.PAD * 2), ipady=2)
            self.entries[label] = entry
        self.scan_btn = ttk.Button(form, text='Scan', style='Large.Accent.TButton',
                                   command=self.on_scan)
        self.scan_btn.grid(row=1, column=3, sticky='w')

        # One option per line: with the larger text, side by side they could be cut off
        opts = ttk.Frame(self); opts.pack(fill='x', pady=theme.PAD)
        self.option_boxes = [
            ttk.Checkbutton(opts, text='Demo mode (use sample data, no network)',
                            variable=self.demo, style='Form.TCheckbutton'),
            ttk.Checkbutton(opts, text='Save the login (encrypted) with approved devices',
                            variable=self.save_login, style='Form.TCheckbutton'),
            ttk.Checkbutton(opts, text='Also log in to CDP/LLDP neighbours with this login\n'
                            '(sends the login to every neighbour; off = seed device only)',
                            variable=self.login_neighbours, style='Form.TCheckbutton')]
        for box in self.option_boxes:
            box.pack(anchor='w', pady=1)

        self.status = ttk.Label(self, text='Ready.'); self.status.pack(anchor='w')
        cols = [('name', 'Name', 170), ('ip', 'IP', 145), ('type', 'Type', 100),
                ('managed', 'Managed', 100), ('source', 'Source', 160)]
        self.tree = ttk.Treeview(self, columns=[c[0] for c in cols], show='headings',
                                 selectmode='extended', style='Data.Treeview')
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
        neighbours = False
        if not demo:
            if not self.user.get().strip() or not self.pw.get():
                messagebox.showerror('Login needed', 'Enter the username and password.')
                return
            if not seed:                     # never guessed (no default-gateway fallback)
                messagebox.showerror('Seed IP needed', SEED_NEEDED)
                return
            problem = validation.check_ip(seed)
            if problem:
                messagebox.showerror('Seed IP', problem)
                return
            neighbours = bool(self.login_neighbours.get())
            if neighbours and not messagebox.askyesno('Log in to neighbours?',
                                                      NEIGHBOUR_WARNING, icon='warning'):
                log_event('scan', 'Scan cancelled (the neighbour login was not confirmed). '
                                  'Nothing was scanned.', 'warn')
                return
        log_event('scan', 'Loading the sample network...' if demo else
                  f"Scanning from seed {seed}{' (also logging in to neighbours)' if neighbours else ''}...")
        self.scanning = True
        self._scan_seed = seed
        self._scan_is_demo = demo
        self.scan_btn.state(['disabled'])
        self.status.config(text='Scanning... this can take a minute.' if not demo
                           else 'Loading sample data...')
        threading.Thread(target=run_scan, daemon=True,
                         args=(self.results, self.discover, self.user.get().strip(),
                               self.pw.get(), seed, demo, neighbours)).start()
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
            log_event('scan', f"Scan from {self._scan_seed or 'the sample network'} FAILED. "
                              f"{msg[1]}", 'error')
            self._remember({'kind': 'scan', 'seed': self._scan_seed, 'failed': True,
                            'sample': self._scan_is_demo})
            messagebox.showerror('Scan failed', msg[1])
        else:
            self.show_found(msg[1], msg[2], sample=self._scan_is_demo)

    def _remember(self, entry):
        """Add one entry to this session's scan history (kept to the last 20)."""
        entry['when'] = datetime.now()
        self.history = (self.history + [entry])[-20:]
        if self.on_activity:
            self.on_activity()

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
        log_event('scan', f'Scan SUCCESSFUL: found {len(self.found)} devices ({n_managed} '
                          f'managed) and {len(self.found_links)} links{sample_note}.', 'ok')
        if blocked:
            log_event('scan', SAMPLE_BLOCKED, 'warn')
        self._remember({'kind': 'scan', 'seed': self._scan_seed, 'devices': len(self.found),
                        'managed': n_managed, 'links': len(self.found_links),
                        'sample': self.found_is_sample})

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
        log_event('scan', f"Approving {len(picked)} selected device{'' if len(picked) == 1 else 's'}...")
        if not database_ready(self):
            self.status.config(text='Database unavailable. Nothing was saved.')
            log_event('scan', 'Approval FAILED: the database is unavailable. Nothing was saved.',
                      'error')
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
            log_event('scan', 'Approval cancelled. Nothing was saved.', 'warn')
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
            if not saved:            # with saved devices the main window logs it (on_approved)
                log_event('scan', f'Approval FAILED. {detail} {err}', 'error')
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
        for d in saved:
            how = 'restored' if d in restored else 'registered'
            log_event('devices', f"{d['name']} ({d['ip']}, {d.get('type') or 'unknown'}): "
                                 f"{how} SUCCESSFUL.", 'ok')
        self._remember({'kind': 'approval', 'count': n})
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
