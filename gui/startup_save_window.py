"""Save to Startup window (Phase 4H): saves a verified restore to the startup configuration.

Opened only from a Restore window whose result is a verified SUCCESS. All the logic is in
startup_save.py; this window collects the decisions, runs its functions on worker threads
(gui.restore_window.run_worker: the device claim and the shutdown protection of the restore
workflow) and shows what they report. It sends nothing to a device itself.

    Run Checks (read-only) -> type SAVE STARTUP <ip> -> final question -> one worker:
    encrypted backup of the current startup configuration, write memory, verification.

Before the save starts, closing or cancelling changes nothing. Once it runs, NetCommand
cannot be closed and the window stays open until the result is verified.
"""
import os
import queue
import tkinter as tk
from tkinter import messagebox, ttk

import startup_save as S
from gui import restore_window as W
from gui.components.tables import setup_table
from gui import theme
from gui.components.dialogs import place_window

TITLE = 'Save to Startup'
IDLE, CHECKING, SAVING, DONE = 'idle', 'checking', 'saving', 'done'
CHECK_NAMES = {'eligibility': 'Verified restore', 'keyring': 'Backup keyring',
               'identity': 'Same device', 'connection': 'SSH connection',
               'session': 'SSH 2, privilege 15, identity', 'rollback-timer': 'No rollback timer',
               'running-config': 'Running = restored configuration',
               'startup-config': 'Startup configuration'}
RESULT_HELP = {
    S.SUCCESS: 'The restored configuration is saved: the startup configuration was read back '
               'and equals the running configuration. It will be used after a reload.',
    S.FAILED: 'Nothing was saved: the startup configuration is unchanged (verified, or the '
              'save never started). The restored configuration is lost at the next reload '
              'unless it is saved.',
    S.UNKNOWN: 'The startup configuration could not be verified. Follow the actions below '
               'and do not reload the device until it is resolved.'}


class StartupSaveWindow(tk.Toplevel):
    def __init__(self, parent, restore_result, device, can_save, creds, backup_dir=None,
                 key_source=None, on_finished=None):
        """restore_result: the restore_engine.RestoreResult of the Restore window; creds: the
        login that restore used."""
        root = parent.nametowidget('.')
        super().__init__(root)
        self.root_window = root
        self.restore_result, self.device, self.creds = restore_result, device, creds
        self.can_save = bool(can_save)
        self.backup_dir, self.key_source, self.on_finished = backup_dir, key_source, on_finished
        self.ip = device.ip
        self.state, self.alive = IDLE, True
        self.plan = self.result = None
        self.log_queue = queue.Queue()
        W._WINDOWS.add(self)
        self.bind('<Destroy>', self._destroyed, add='+')
        self.protocol('WM_DELETE_WINDOW', self.close)
        self.title(f'{TITLE} - {device.hostname or device.ip} ({device.ip})')
        self.configure(background=theme.SURFACE)
        place_window(self, parent, size=(920, 660))       # scaled, on screen, centered
        self._build()
        self._update()
        self.after(100, self._drain)

    # ------------------------------------------------------------ layout
    def _build(self):
        pad, r = theme.PAD, self.restore_result
        info = ttk.Frame(self, padding=pad)
        info.pack(fill='x')
        ident = r.identity or {}
        ttk.Label(info, justify='left', wraplength=880, text=(
            f'Device: {self.device.hostname or "?"}  {self.ip}   serial '
            f'{ident.get("serial")}, platform {ident.get("platform")}\n'
            f'Restored backup: {os.path.basename(r.backup_file or "?")} (restore result '
            f'{r.status}, rollback timer {r.timer_state})\n'
            f'Saving OVERWRITES the startup configuration, so the restored configuration is '
            f'used after a reload. The current startup configuration is first saved as an '
            f'encrypted backup. Opening this window and running the checks change nothing.'
        )).pack(anchor='w')
        self.tree = ttk.Treeview(self, columns=('status', 'check', 'text'), show='headings',
                                 height=7, style='Data.Treeview')
        setup_table(self.tree, [('status', 'Result', 80), ('check', 'Check', 220, 'w'),
                                ('text', 'Explanation', 600)])
        self.tree.pack(fill='x', padx=pad)
        self.summary_label = ttk.Label(self, text='', justify='left', wraplength=880)
        self.summary_label.pack(fill='x', padx=pad, pady=(4, 0))
        row = ttk.Frame(self, padding=pad)
        row.pack(fill='x')
        self.phrase_label = ttk.Label(row, text='Run the checks first.')
        self.phrase_label.pack(anchor='w')
        entry_row = ttk.Frame(row)
        entry_row.pack(fill='x', pady=(4, 0))
        ttk.Label(entry_row, text='Type the confirmation:').pack(side='left')
        self.typed = tk.StringVar()
        self.typed_entry = ttk.Entry(entry_row, textvariable=self.typed, width=36)
        self.typed_entry.pack(side='left', padx=pad)
        self.typed.trace_add('write', lambda *a: self._update())
        self.stage_label = ttk.Label(self, text='Stage: not started', padding=(pad, 0))
        self.stage_label.pack(anchor='w')
        self.backup_label = ttk.Label(self, text='Startup backup: not created yet',
                                      padding=(pad, 0))
        self.backup_label.pack(anchor='w')
        self.result_label = ttk.Label(self, text='', font=theme.FONT_TITLE, padding=(pad, 0))
        self.result_label.pack(anchor='w', pady=(4, 0))
        self.log_text = tk.Text(self, height=8, wrap='word', background=theme.CARD,
                                foreground=theme.TEXT, relief='flat', font=theme.FONT_MONO)
        self.log_text.pack(fill='both', expand=True, padx=pad, pady=(4, 0))
        self.log_text.configure(state='disabled')
        bar = ttk.Frame(self, padding=pad)
        bar.pack(fill='x')
        self.check_btn = ttk.Button(bar, text='Run Checks', command=self.run_checks)
        self.check_btn.pack(side='left')
        self.save_btn = ttk.Button(bar, text='Back up startup and save', style='Accent.TButton',
                                   command=self.start_save)
        self.save_btn.pack(side='left', padx=pad)
        self.close_btn = ttk.Button(bar, text='Close', command=self.close)
        self.close_btn.pack(side='right')
        self.status = ttk.Label(bar, text='', foreground=theme.TEXT_MUTED)
        self.status.pack(side='left', padx=pad)

    # ------------------------------------------------------------ state
    def keeps_open(self):
        """A save was started here and its result has not been dismissed yet (DONE is set
        only by a save result)."""
        return self.state in (SAVING, DONE)

    def _update(self):
        if not self.alive:
            return
        eligible = S.eligible(self.restore_result, self.ip)[0]
        idle = self.state in (IDLE, DONE) and self.result is None
        ready = (self.can_save and self.state == IDLE and self.plan is not None and
                 self.plan.can_proceed and self.typed.get() == self.plan.required_confirmation)
        self.check_btn.state(['!disabled'] if self.can_save and eligible and idle
                             else ['disabled'])
        self.save_btn.state(['!disabled'] if ready else ['disabled'])
        self.close_btn.state(['disabled'] if self.state == SAVING else ['!disabled'])
        can_type = self.plan is not None and self.plan.can_proceed and self.state == IDLE
        self.typed_entry.state(['!disabled'] if can_type else ['disabled'])

    def _say(self, text):
        if self.alive:
            self.status.config(text=text)

    def _worker_log(self):
        put = self.log_queue.put                  # never the window (see restore_window)
        return lambda kind, text: put((kind, text))

    def _drain(self):
        if not self.alive:
            return
        lines = []
        while True:
            try:
                kind, text = self.log_queue.get_nowait()
            except queue.Empty:
                break
            if kind == 'section':
                self.stage_label.config(text=f'Stage: {text}')
            lines.append(f'[{kind}] {text}' if kind != 'section' else f'== {text} ==')
        if lines:
            self.log_text.configure(state='normal')
            self.log_text.insert('end', '\n'.join(lines) + '\n')
            self.log_text.see('end')
            self.log_text.configure(state='disabled')
        self.after(100, self._drain)

    # ------------------------------------------------------------ checks
    def run_checks(self):
        if not self.can_save or self.state != IDLE or self.result is not None:
            return
        ok, why = S.eligible(self.restore_result, self.ip)
        if not ok:
            messagebox.showerror(TITLE, f'Saving is not allowed: {why}.', parent=self)
            return
        if not W.claim(self.ip):
            messagebox.showerror(TITLE, f'A check, restore or save is already running for '
                                        f'{self.ip}.', parent=self)
            return
        self.plan = None
        self.typed.set('')
        self.tree.delete(*self.tree.get_children())
        self.state = CHECKING
        self._update()
        self._say('Running the read-only checks...')
        result, creds, key_source, log = self.restore_result, self.creds, self.key_source, \
            self._worker_log()
        W.run_worker(self.root_window, self.ip,
                     lambda: S.check(result, creds, key_source=key_source, log=log),
                     self._checks_done)

    def _checks_done(self, plan, error):
        W.release(self.ip)
        if not self.alive:
            return
        self.state = IDLE
        if error is not None:
            self.summary_label.config(text=f'FAILED: the checks stopped unexpectedly '
                                           f'({type(error).__name__}). Nothing was changed.')
            self._update()
            return
        self.plan = plan
        for n, c in enumerate(plan.checks):
            self.tree.insert('', 'end', iid=str(n), values=(c.status, CHECK_NAMES.get(
                c.name, c.name), c.text))
        self.summary_label.config(text=f'Overall: {plan.status}. Nothing has been changed.')
        if plan.can_proceed:
            self.phrase_label.config(text=f'To back up the startup configuration and save the '
                                          f'restored configuration to it, type exactly:   '
                                          f'{plan.required_confirmation}')
            self._say('Checks passed. Type the confirmation to save.')
        else:
            self.phrase_label.config(text='Saving is not possible: see the BLOCKED or FAILED '
                                          'checks.')
            self._say('Saving is not possible.')
        self._update()

    # ------------------------------------------------------------ save
    def start_save(self):
        plan = self.plan
        if not self.can_save or self.state != IDLE or plan is None or not plan.can_proceed:
            return
        typed = self.typed.get()
        if typed != plan.required_confirmation:
            messagebox.showerror(TITLE, f'The confirmation was not typed exactly. Type:\n\n'
                                        f'{plan.required_confirmation}', parent=self)
            return
        if W.busy(self.ip):
            messagebox.showerror(TITLE, f'A check, restore or save is already running for '
                                        f'{self.ip}.', parent=self)
            return
        ident = plan.identity
        from gui.components.dialogs import confirm
        if not confirm(TITLE, (
                f'Save the restored configuration to the startup configuration?\n\n'
                f'Device: {self.device.hostname or "?"} {self.ip}\n'
                f'Serial {ident.get("serial")}, platform {ident.get("platform")}\n'
                f'Restored backup: {os.path.basename(self.restore_result.backup_file)}\n\n'
                f'The current startup configuration is first saved as an encrypted '
                f'pre-save-startup backup in the backup folder, then OVERWRITTEN with '
                f'"write memory". This makes the restored configuration persistent: the '
                f'device uses it after a reload. Nothing else is changed, and the device is '
                f'not reloaded.\n\nOnce started, this cannot be interrupted.'),
                'Save to startup', parent=self, danger=True,
                log=('backups', f'Save to startup on {self.ip}')):
            return
        if not W.claim(self.ip):
            messagebox.showerror(TITLE, f'A check, restore or save is already running for '
                                        f'{self.ip}.', parent=self)
            return
        self.state = SAVING
        self._update()
        self._say('Backing up the startup configuration and saving...')
        creds, backup_dir, key_source, log = self.creds, self.backup_dir, self.key_source, \
            self._worker_log()
        W.run_worker(self.root_window, self.ip,
                     lambda: S.save(plan, typed, creds, backup_dir=backup_dir,
                                    key_source=key_source, log=log),
                     self._save_done, protected=True)

    def _save_done(self, result, error):
        W.release(self.ip)
        if isinstance(error, S.SaveRefused):
            if self.alive:
                self.state = IDLE
                self.summary_label.config(text=f'Not saved: {error}')
                self._update()
            return
        if error is not None or result is None:
            result = S.SaveResult(status=S.UNKNOWN, device_ip=self.ip,
                                  restored_backup=self.restore_result.backup_file,
                                  startup_state=S.STATE_UNKNOWN)
            result.manual_actions.append(
                f'The save worker stopped unexpectedly ({type(error).__name__}). Check the '
                f'startup configuration of {self.ip} from its console before any reload.')
        self.result = result
        if self.on_finished:
            try:
                self.on_finished(result)
            except Exception:
                pass
        if not self.alive:
            return
        self.state = DONE
        self.result_label.config(text=f'Result: {result.status}')
        self.backup_label.config(text=f'Startup backup: {result.startup_backup or "not created"}')
        self.summary_label.config(text='\n'.join([RESULT_HELP[result.status]] +
                                                 result.lines()[1:]))
        self._say(f'Finished: {result.status}.')
        self._update()
        if result.status != S.SUCCESS:
            messagebox.showwarning(f'{TITLE}: {result.status}', '\n'.join(
                [RESULT_HELP[result.status]] +
                [f'ACTION REQUIRED: {a}' for a in result.manual_actions]), parent=self)

    # ------------------------------------------------------------ closing
    def _destroyed(self, event):
        if event.widget is self:
            self.alive = False
            W._WINDOWS.discard(self)

    def close(self):
        if self.state == SAVING:
            messagebox.showwarning(TITLE, 'The startup configuration is being saved and '
                                          'verified. It cannot be interrupted: the window stays '
                                          'open until the result is known.', parent=self)
            return
        self.alive = False
        W._WINDOWS.discard(self)
        try:
            self.destroy()
        except tk.TclError:
            pass
