"""Restore Backup window (Phase 4G): the graphical workflow around the Phase 4E preflight
(restore_preflight) and the Phase 4F engine (restore_engine). All restore logic, every
check, the confirmation rules, the sealing, the single use and the rollback live there;
this window only collects the user's decisions, runs those functions on a worker thread
and shows what they report. It never sends a command to a device itself.

    1. Opening the window touches nothing: no connection, no file.
    2. Run Checks: restore_preflight.run_checks (read-only), on a worker thread.
    3. The user types the exact phrase the preflight returned (RESTORE <ip>, or RESTORE
       LEGACY <ip> for a backup whose hardware is not confirmed by serial number).
    4. "Create safety backup and restore": restore_preflight.create_safety_backup, and only
       if it succeeded, restore_engine.restore (which checks the seal, the device and the
       backups again before it sends anything).

Cancelling and closing. Until the engine starts, Cancel or closing the window stops the
workflow: a running read-only check is left to finish in the background; a safety backup
being made is finished and the preflight is then cancelled, so no restore starts. Once the
engine runs, the window cannot be closed and nothing is interrupted: the engine finishes
its confirmation or its rollback and the result is shown. Workers are polled from the
application's root window, so their results are always collected (and the device claim
always released) even after this window was closed.

Only one check or restore runs per device at a time (claim/release). The startup
configuration is never saved (that is a later phase).
"""
import itertools
import os
import queue
import threading
import tkinter as tk
from tkinter import messagebox, ttk

import restore_engine as E
import restore_preflight as R
from gui import background, theme
from gui.components.dialogs import place_window
from gui.components.tables import setup_table
from gui.timefmt import format_timestamp_text

IDLE, CHECKING, SAFETY, RESTORING, DONE = 'idle', 'checking', 'safety backup', 'restoring', \
    'done'
TITLE = 'Restore backup'

CHECK_NAMES = {
    'selection': 'Backup selection', 'device': 'Target device', 'backup': 'Selected backup',
    'backup-recheck': 'Selected backup (checked again)', 'connection': 'SSH connection',
    'session': 'SSH session', 'ssh': 'SSH version 2', 'privilege': 'Privilege level 15',
    'running-config': 'Current configuration', 'identity': 'Device identity',
    'identity-recheck': 'Device identity (checked again)', 'match': 'Backup belongs to device',
    'match-serial': 'Serial number', 'match-platform': 'Platform', 'match-ip': 'IP address',
    'match-hostname': 'Hostname', 'live-identity': 'Live identity (changed IP)',
    'pending-rollback': 'No restore already pending', 'archive': 'Configuration archive',
    'rollback': 'Rollback support', 'flash-space': 'Flash space',
    'temp-file': 'Temporary file name', 'transfer': 'Transfer method',
    'management-ip': 'Management address kept', 'ssh-vty': 'SSH access kept',
    'login': 'Login after restore', 'safety-backup': 'Pre-restore safety backup'}
STATUS_HELP = {
    R.PASS: 'PASS: the check found no problem.',
    R.WARNING: 'WARNING: the restore may go on, but read why before you confirm.',
    R.BLOCKED: 'BLOCKED: a safety rule forbids this restore; the reason says what to fix.',
    R.FAILED: 'FAILED: something could not be done or checked; nothing was changed.'}
RESULT_HELP = {
    E.SUCCESS: 'The backup is restored: the configuration was verified, confirmed, and the '
               'rollback timer is cancelled. The startup configuration was not changed.',
    E.PARTIAL: 'The backup is restored and confirmed, but something was left to clean up. '
               'See the actions below.',
    E.FAILED: 'The backup was NOT restored. The device is in its original configuration '
              '(verified) or nothing was sent to it.',
    E.UNKNOWN: 'The state of the device could not be verified. Follow the actions below.'}

# ---------------------------------------------------------------- one operation per device
_ACTIVE, _ACTIVE_LOCK = set(), threading.Lock()


def claim(ip):
    """True when no other check or restore runs for this device (and records this one)."""
    with _ACTIVE_LOCK:
        if ip in _ACTIVE:
            return False
        _ACTIVE.add(ip)
        return True


def release(ip):
    """The device is free again for another check or restore. (Shutdown protection is
    separate: see _protect.)"""
    with _ACTIVE_LOCK:
        _ACTIVE.discard(ip)


def busy(ip):
    with _ACTIVE_LOCK:
        return ip in _ACTIVE


# ---------------------------------------------------------------- application shutdown
# While a safety-backup or restore worker runs for a device, the application must not
# close: ending the process would end the worker, and NetCommand could neither verify nor
# report the device's state. Protection is taken just before such a worker starts and is
# dropped only AFTER the Tk thread has collected its result and the completion handler has
# finished with it (recorded the result, shown its messages, released the device), or has
# raised (see RestoreWindow._run). Each protected worker has its own token, so the handler
# starting the next stage (safety backup -> engine) never drops that stage's protection.
# Read-only checks are not protected: ending them changes nothing.
_PROTECTED = {}                    # token -> device IP
_TOKENS = itertools.count(1)
_WINDOWS = set()                   # open Restore windows (Tk thread only)
SHUTDOWN_TITLE = 'Restore in progress'


def _protect(ip):
    """A new protection token for ip (the application may not close until it is
    dropped)."""
    with _ACTIVE_LOCK:
        token = next(_TOKENS)
        _PROTECTED[token] = ip
        return token


def _unprotect(token):
    with _ACTIVE_LOCK:
        _PROTECTED.pop(token, None)


def active_restores():
    """The devices whose safety backup or restore is running, or whose result is still
    being handled (sorted, each once)."""
    with _ACTIVE_LOCK:
        return sorted(set(_PROTECTED.values()))


def shutdown_message(ips):
    return (f'A restore or startup save of {", ".join(ips)} is still running (a safety '
            f'backup, the configuration replacement or rollback verification, or the save to '
            f'the startup configuration).\n\nNetCommand must stay open until it '
            f'has finished, so that the device\'s state can be verified and reported. Closing '
            f'now could leave the device unverified.\n\nWait until the Restore window shows '
            f'the result, then close NetCommand again.')


def block_shutdown(parent=None):
    """For every normal way of closing the application: True (and a message) while a
    restore is running, so the caller must NOT close; False otherwise. It only reads the
    registry: it never stops a worker or touches an SSH session."""
    ips = active_restores()
    if not ips:
        return False
    messagebox.showwarning(SHUTDOWN_TITLE, shutdown_message(ips), parent=parent)
    return True


def workbench_closed():
    """The workbench window is gone (closed or signed out, which is only possible when no
    restore runs). A read-only check may still be finishing in the background; its result
    can no longer be collected, so its device is freed here instead of staying claimed."""
    with _ACTIVE_LOCK:
        _ACTIVE.intersection_update(_PROTECTED.values())
    _WINDOWS.clear()


def run_worker(root_window, ip, work, done, protected=False):
    """Run work() on a worker thread; done(result, error) runs on the Tk thread, polled
    from the application root (so it runs even after the window that started it closed).
    protected: the application may not close from now until done() has returned (or
    raised) on the Tk thread: through the worker, the wait for the Tk thread to collect
    its result, and everything done() does, including any message box it shows (a message
    box runs a nested event loop in which the user could otherwise close NetCommand).
    done() may start the next stage, which takes its own token. If done() raises, the
    device is released unless another protected worker still runs for it. All of this
    runs on the Tk thread; the worker thread never waits for Tk. (Used by the Restore and
    the Save to Startup windows.)"""
    token = _protect(ip) if protected else None

    def finished(result, error):
        try:
            done(result, error)
        except Exception:
            if protected:
                _unprotect(token)
            if ip not in active_restores():
                release(ip)
            raise
        finally:
            if protected:
                _unprotect(token)
    background.run_async(root_window, work, finished)


def restore_activity():
    """True while a protected operation runs, or a window that ran one is still open (its
    result has not been dismissed). Used to delay an automatic sign-out."""
    return bool(active_restores()) or any(w.alive and w.keeps_open() for w in list(_WINDOWS))


class RestoreWindow(tk.Toplevel):
    def __init__(self, parent, selection, device, can_restore, get_creds, backup_dir=None,
                 key_source=None, on_finished=None):
        """selection: backup_catalogue.Selection; device: backup_catalogue.Device.
        get_creds(): {'host', 'username', 'password'} or None (called on the Tk thread,
        when the user starts the checks; it may ask for the login)."""
        root = parent.nametowidget('.')
        super().__init__(root)               # not a child of the catalogue: closing that
        self.root_window = root              # must never close a running restore
        self.selection, self.device = selection, device
        self.can_restore, self.get_creds = bool(can_restore), get_creds
        self.backup_dir, self.key_source, self.on_finished = backup_dir, key_source, on_finished
        self.ip = device.ip
        self.state, self.alive, self.cancel_requested = IDLE, True, False
        self.pre = self.creds = self.result = None
        self.minutes_used = None
        self.log_queue = queue.Queue()
        _WINDOWS.add(self)
        self.bind('<Destroy>', self._destroyed, add='+')
        self.title(f'{TITLE} - {device.hostname or device.ip} ({device.ip})')
        self.configure(background=theme.SURFACE)
        place_window(self, parent, size=(1000, 760))      # scaled, on screen, centered
        self.protocol('WM_DELETE_WINDOW', self.close)
        self._build()
        self._show_selection()
        self._update()
        self.after(100, self._drain)

    # ------------------------------------------------------------ layout
    def _build(self):
        pad = theme.PAD
        info = ttk.Frame(self, padding=pad)
        info.pack(fill='x')
        self.device_label = ttk.Label(info, text='', justify='left')
        self.device_label.pack(anchor='w')
        self.backup_label = ttk.Label(info, text='', justify='left')
        self.backup_label.pack(anchor='w', pady=(4, 0))
        self.note_label = ttk.Label(info, text='', justify='left', foreground=theme.TEXT_MUTED,
                                    wraplength=950)
        self.note_label.pack(anchor='w', pady=(4, 0))

        self.tree = ttk.Treeview(self, columns=('status', 'check', 'text'), show='headings',
                                 height=10, style='Data.Treeview')
        setup_table(self.tree, [('status', 'Result', 80), ('check', 'Check', 190, 'w'),
                                ('text', 'Explanation', 700)])
        self.tree.pack(fill='both', expand=True, padx=pad)
        self.summary_label = ttk.Label(self, text='', justify='left', wraplength=950)
        self.summary_label.pack(fill='x', padx=pad, pady=(4, 0))

        confirm = ttk.Frame(self, padding=pad)
        confirm.pack(fill='x')
        self.phrase_label = ttk.Label(confirm, text='Run the checks first.')
        self.phrase_label.pack(anchor='w')
        row = ttk.Frame(confirm)
        row.pack(fill='x', pady=(4, 0))
        ttk.Label(row, text='Type the confirmation:').pack(side='left')
        self.typed = tk.StringVar()
        self.typed_entry = ttk.Entry(row, textvariable=self.typed, width=40)
        self.typed_entry.pack(side='left', padx=pad)
        self.typed.trace_add('write', lambda *a: self._update())
        ttk.Label(row, text='Rollback timer (minutes):').pack(side='left', padx=(pad, 0))
        self.minutes = tk.StringVar(value=str(E.DEFAULT_TIMER_MINUTES))
        self.minutes_box = ttk.Spinbox(row, from_=E.MIN_TIMER_MINUTES, to=E.MAX_TIMER_MINUTES,
                                       textvariable=self.minutes, width=4, state='readonly')
        self.minutes_box.pack(side='left', padx=4)

        progress = ttk.Frame(self, padding=(pad, 0))
        progress.pack(fill='x')
        self.stage_label = ttk.Label(progress, text='Stage: not started')
        self.stage_label.pack(anchor='w')
        self.safety_label = ttk.Label(progress, text='Safety backup: not created yet')
        self.safety_label.pack(anchor='w')
        self.timer_label = ttk.Label(progress, text='Rollback timer: not started')
        self.timer_label.pack(anchor='w')
        self.result_label = ttk.Label(progress, text='', font=theme.FONT_TITLE)
        self.result_label.pack(anchor='w', pady=(4, 0))

        self.log_text = tk.Text(self, height=9, wrap='word', background=theme.CARD,
                                foreground=theme.TEXT, relief='flat', font=theme.FONT_MONO)
        self.log_text.pack(fill='both', expand=True, padx=pad, pady=(4, 0))
        self.log_text.configure(state='disabled')

        bar = ttk.Frame(self, padding=pad)
        bar.pack(fill='x')
        self.check_btn = ttk.Button(bar, text='Run Checks', command=self.run_checks)
        self.check_btn.pack(side='left')
        self.restore_btn = ttk.Button(bar, text='Create safety backup and restore',
                                      style='Accent.TButton', command=self.start_restore)
        self.restore_btn.pack(side='left', padx=pad)
        # Phase 4H: a separate, separately confirmed step, only after a verified SUCCESS.
        self.save_btn = ttk.Button(bar, text='Save to Startup...', command=self.open_save)
        self.save_btn.pack(side='left')
        self.close_btn = ttk.Button(bar, text='Close', command=self.close)
        self.close_btn.pack(side='right')
        self.cancel_btn = ttk.Button(bar, text='Cancel', command=self.cancel)
        self.cancel_btn.pack(side='right', padx=pad)
        self.status = ttk.Label(bar, text='', foreground=theme.TEXT_MUTED)
        self.status.pack(side='left', padx=pad)

    def _show_selection(self):
        s, d = self.selection, self.device
        self.device_label.config(text=f'Target device: {d.hostname or "?"}  {d.ip}   (live '
                                      f'identity is read by Run Checks)')
        folder, name = os.path.split(s.path)
        self.backup_label.config(text=(
            f'Backup: {name}  in {folder}\n'
            f'Created {format_timestamp_text(s.created_utc)}, key_id={s.key_id}, configuration '
            f'SHA-256 '
            f'{s.plaintext_sha256}\n'
            f'Verification: verified when it was selected (AES-GCM, SHA-256, size, '
            f'configuration check); Run Checks verifies it again before anything else.'))
        notes = []
        if getattr(s, 'live_identity_required', False):
            notes.append('PENDING CANDIDATE: this backup was recorded for another IP address. '
                         'The restore is blocked unless the device\'s live serial number AND '
                         'platform both match the backup.')
        elif s.requires_legacy_confirmation:
            notes.append('The hardware identity of this backup is not confirmed by serial '
                         'number: the legacy confirmation (RESTORE LEGACY <ip>) is required.')
        if not self.can_restore:
            notes.append('Your role may not restore backups (the Configure permission is '
                         'required).')
        notes.append('Opening this window and running the checks change nothing. A safety '
                     'backup is made only after you type the confirmation; the startup '
                     'configuration is never saved.')
        self.note_label.config(text='\n'.join(notes))

    # ------------------------------------------------------------ state and buttons
    def _set_state(self, state):
        self.state = state
        self._update()

    def _update(self):
        if not self.alive:
            return
        idle = self.state in (IDLE, DONE)
        ready = (self.can_restore and self.state == IDLE and self.pre is not None and
                 self.pre.can_proceed and self.typed.get() == self.pre.required_confirmation)
        self.check_btn.state(['!disabled'] if self.can_restore and idle else ['disabled'])
        self.restore_btn.state(['!disabled'] if ready else ['disabled'])
        self.save_btn.state(['!disabled'] if self.can_save_to_startup() else ['disabled'])
        self.cancel_btn.state(['disabled'] if self.state in (RESTORING, DONE) else
                              ['!disabled'])
        self.close_btn.state(['disabled'] if self.state == RESTORING else ['!disabled'])
        can_type = self.pre is not None and self.pre.can_proceed and self.state == IDLE
        self.typed_entry.state(['!disabled'] if can_type else ['disabled'])

    def _say(self, text):
        if self.alive:
            self.status.config(text=text)

    # ------------------------------------------------------------ worker output
    def _worker_log(self):
        """The log function handed to a worker: it only queues (shown by _drain). It holds
        the queue, NOT the window: a worker must never hold the last reference to Tk
        objects (they may only be destroyed on the Tk thread)."""
        put = self.log_queue.put
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
                if text == 'CONFIGURE REPLACE':
                    self.timer_label.config(text=f'Rollback timer: started '
                                                 f'({self.minutes_used} minutes)')
            lines.append(f'[{kind}] {text}' if kind != 'section' else f'== {text} ==')
        if lines:
            self.log_text.configure(state='normal')
            self.log_text.insert('end', '\n'.join(lines) + '\n')
            self.log_text.see('end')
            self.log_text.configure(state='disabled')
        self.after(100, self._drain)

    def _run(self, work, done, protected=False):
        """run_worker for this window's device (see there)."""
        run_worker(self.root_window, self.ip, work, done, protected)

    # ------------------------------------------------------------ 1. read-only checks
    def run_checks(self):
        if not self.can_restore or self.state not in (IDLE, DONE):
            return
        if not claim(self.ip):
            messagebox.showerror(TITLE, f'A check or restore is already running for '
                                        f'{self.ip}. Wait until it has finished.', parent=self)
            return
        try:
            creds = self.get_creds()
        except Exception as err:
            release(self.ip)
            messagebox.showerror(TITLE, f'The login could not be read ({type(err).__name__}). '
                                        f'Nothing was sent.', parent=self)
            return
        if not creds:
            release(self.ip)
            self._say('Checks not started: no login was given.')
            return
        self.creds, self.pre, self.result = creds, None, None
        self.typed.set('')
        self.tree.delete(*self.tree.get_children())
        self.summary_label.config(text='')
        self.result_label.config(text='')
        self._set_state(CHECKING)
        self._say('Running the read-only checks...')
        selection, key_source, log = self.selection, self.key_source, self._worker_log()
        self._run(lambda: R.run_checks(selection, creds, key_source=key_source, log=log),
                  self._checks_done)

    def _checks_done(self, pre, error):
        release(self.ip)
        if not self.alive:
            return
        self._set_state(IDLE)
        if error is not None:
            self.summary_label.config(text=f'FAILED: the checks stopped unexpectedly '
                                           f'({type(error).__name__}). Nothing was changed.')
            self._say('Checks failed.')
            return
        self.pre = pre
        self._show_checks(pre)
        self._update()

    def _show_checks(self, pre):
        self.tree.delete(*self.tree.get_children())
        for n, c in enumerate(pre.checks):
            self.tree.insert('', 'end', iid=str(n), values=(c.status, CHECK_NAMES.get(
                c.name, c.name), c.text))
        counts = {s: len(pre.of(s)) for s in (R.PASS, R.WARNING, R.BLOCKED, R.FAILED)}
        lines = [f'Overall: {pre.status}  ({", ".join(f"{v} {k}" for k, v in counts.items())})',
                 STATUS_HELP[pre.status]]
        if pre.identity:
            ident = pre.identity
            lines.append(f'Live device: hostname {ident.get("hostname") or "?"}, platform '
                         f'{ident.get("platform") or "?"}, serial {ident.get("serial") or "?"}')
            self.device_label.config(text=f'Target device: {self.device.hostname or "?"}  '
                                          f'{self.ip}   serial {ident.get("serial") or "?"}, '
                                          f'platform {ident.get("platform") or "?"}')
        if pre.can_proceed:
            lines.append(f'Transfer: {pre.transfer_method} to flash:{pre.temp_name}. Nothing '
                         f'has been changed on the device.')
            if pre.requires_legacy_confirmation:
                lines.append('LEGACY BACKUP: its hardware identity is not confirmed by serial '
                             'number. Restore it only if you are sure it belongs to this '
                             'device.')
            if pre.backup.get('host') != pre.device_ip:
                lines.append(f'CHANGED IP: the backup was recorded for '
                             f'{pre.backup.get("host")}; the live serial number and platform '
                             f'both match it.')
            self.phrase_label.config(text=f'To create the safety backup and restore '
                                          f'{self.ip}, type exactly:   '
                                          f'{pre.required_confirmation}')
            self._say('Checks passed. Read every warning, then type the confirmation.')
        else:
            self.phrase_label.config(text='The restore cannot continue: fix the BLOCKED or '
                                          'FAILED checks and run the checks again.')
            self._say('The restore cannot continue.')
        self.summary_label.config(text='\n'.join(lines))

    # ------------------------------------------------------------ 2-3. safety backup, restore
    def start_restore(self):
        pre = self.pre
        if not self.can_restore or self.state != IDLE or pre is None or not pre.can_proceed:
            return
        typed = self.typed.get()
        if typed != pre.required_confirmation:
            messagebox.showerror(TITLE, f'The confirmation was not typed exactly. Type:\n\n'
                                        f'{pre.required_confirmation}', parent=self)
            return
        try:
            minutes = int(self.minutes.get())
        except ValueError:
            minutes = None
        if minutes is None or not E.MIN_TIMER_MINUTES <= minutes <= E.MAX_TIMER_MINUTES:
            messagebox.showerror(TITLE, f'The rollback timer must be {E.MIN_TIMER_MINUTES} to '
                                        f'{E.MAX_TIMER_MINUTES} minutes.', parent=self)
            return
        if busy(self.ip):
            messagebox.showerror(TITLE, f'A check or restore is already running for '
                                        f'{self.ip}.', parent=self)
            return
        ident = pre.identity or {}
        if not messagebox.askyesno(TITLE, (
                f'Restore this backup to the device?\n\n'
                f'Device: {self.device.hostname or "?"} {self.ip}\n'
                f'Serial {ident.get("serial")}, platform {ident.get("platform")}\n'
                f'Backup: {os.path.basename(pre.selection.path)}\n\n'
                f'NetCommand will first save an encrypted safety backup of the current '
                f'configuration, then replace the running configuration with a '
                f'{minutes}-minute rollback timer, verify it and confirm it. Any failure is '
                f'rolled back. The startup configuration is not changed.\n\n'
                f'Once the replacement has started it cannot be interrupted.'), parent=self):
            return
        if not claim(self.ip):
            messagebox.showerror(TITLE, f'A check or restore is already running for '
                                        f'{self.ip}.', parent=self)
            return
        self.minutes_used, self.cancel_requested = minutes, False
        self._set_state(SAFETY)
        self._say('Creating the encrypted pre-restore safety backup...')
        creds, backup_dir, key_source = self.creds, self.backup_dir, self.key_source
        log = self._worker_log()

        def work():
            R.create_safety_backup(pre, typed, creds, backup_dir=backup_dir,
                                   key_source=key_source, log=log)
            return pre
        self._run(work, self._safety_done, protected=True)

    def _safety_done(self, _pre, error):
        pre = self.pre
        if error is not None:
            release(self.ip)
            if self.alive:
                self._set_state(IDLE)
                text = str(error) if isinstance(error, R.ConfirmationRefused) else \
                    f'The safety backup stopped unexpectedly ({type(error).__name__}).'
                self.summary_label.config(text=f'Restore not started: {text}')
                self._say('No safety backup; no restore.')
                self._update()
            return
        if pre.stage != R.SAFETY_BACKUP_CREATED:
            release(self.ip)
            if self.alive:
                self._set_state(IDLE)
                self._show_checks(pre)
                problems = pre.of(R.BLOCKED, R.FAILED)
                reason = problems[-1].text if problems else 'unknown reason'
                self.summary_label.config(text=f'FAILED: the safety backup was not made '
                                               f'({reason}). The restore did not start; the '
                                               f'device was not changed.')
                self._say('Restore not started.')
                self._update()
            return
        if self.cancel_requested or not self.alive:
            R.cancel(pre)                          # the engine will refuse it from now on
            release(self.ip)
            if self.alive:
                self._set_state(IDLE)
                self.safety_label.config(text=f'Safety backup: {pre.safety_backup_path}')
                self.summary_label.config(text='Cancelled after the safety backup: the restore '
                                               'did not start and the device was not changed. '
                                               'The encrypted safety backup is kept.')
                self._update()
            return
        if self.alive:
            self.safety_label.config(text=f'Safety backup: {pre.safety_backup_path} (encrypted, '
                                          f'verified)')
            self._set_state(RESTORING)
            self._say('Restoring. This window stays open until the result is verified.')
        creds, minutes, key_source = self.creds, self.minutes_used, self.key_source
        log = self._worker_log()
        self._run(lambda: E.restore(pre, creds, timer_minutes=minutes, key_source=key_source,
                                    log=log), self._restore_done, protected=True)

    def _restore_done(self, result, error):
        release(self.ip)
        pre = self.pre
        if error is not None or result is None:
            result = E.RestoreResult(status=E.UNKNOWN, device_ip=self.ip,
                                     backup_file=pre.selection.path,
                                     safety_backup_file=pre.safety_backup_path or '',
                                     device_state=E.STATE_UNKNOWN)
            result.manual_actions.append(
                f'The restore worker stopped unexpectedly ({type(error).__name__}). Check the '
                f'device {self.ip} from its console; if needed restore the safety backup '
                f'{pre.safety_backup_path}.')
        self.result = result
        if self.on_finished:
            try:
                self.on_finished(result)
            except Exception:
                pass
        if not self.alive:
            return
        self._set_state(DONE)
        self.result_label.config(text=f'Result: {result.status}')
        self.timer_label.config(text=f'Rollback timer: {result.timer_state}')
        self.safety_label.config(text=f'Safety backup: {result.safety_backup_file}')
        self.summary_label.config(text='\n'.join(
            [RESULT_HELP[result.status],
             f'Backup restored from: {result.backup_file}',
             f'Pre-restore safety backup: {result.safety_backup_file}'] +
            result.lines()[1:]))
        self._say(f'Finished: {result.status}.')
        if result.status != E.SUCCESS:
            messagebox.showwarning(f'{TITLE}: {result.status}', '\n'.join(
                [RESULT_HELP[result.status]] +
                [f'ACTION REQUIRED: {a}' for a in result.manual_actions]), parent=self)

    # ------------------------------------------------------------ cancel and close
    def cancel(self):
        if self.state == RESTORING:
            self._refuse_close()
            return
        if self.state == SAFETY:
            self.cancel_requested = True
            self._say('Cancelling: the safety backup is finished first; no restore will start.')
            return
        if self.pre is not None and self.pre.stage == R.CHECKED:
            R.cancel(self.pre)
        self.close()

    def _refuse_close(self):
        messagebox.showwarning(TITLE, 'The device is being restored or rolled back. It cannot be '
                                      'interrupted: the window stays open until NetCommand has '
                                      'verified the result.', parent=self)

    # ------------------------------------------------------------ 4. save to startup (4H)
    def can_save_to_startup(self):
        """Only a verified SUCCESS of this window's own restore, for this device."""
        import startup_save
        return (self.can_restore and self.state == DONE and self.result is not None and
                self.result.status == E.SUCCESS and
                startup_save.eligible(self.result, self.ip)[0])

    def open_save(self):
        if not self.can_save_to_startup():
            return
        from gui.startup_save_window import StartupSaveWindow
        self.save_window = StartupSaveWindow(self, self.result, self.device, self.can_restore,
                                             self.creds, backup_dir=self.backup_dir,
                                             key_source=self.key_source,
                                             on_finished=self.on_save_finished)

    on_save_finished = None                          # set by the opener (console log)

    def keeps_open(self):
        """A restore was started here and its result has not been dismissed yet."""
        return self.state in (SAFETY, RESTORING, DONE)

    def _destroyed(self, event):
        if event.widget is self:            # however the window went: not open any more
            self.alive = False
            _WINDOWS.discard(self)

    def close(self):
        if self.state == RESTORING:
            self._refuse_close()
            return
        if self.state == SAFETY:
            self.cancel_requested = True             # _safety_done cancels; no restore
        self.alive = False
        _WINDOWS.discard(self)
        try:
            self.destroy()
        except tk.TclError:
            pass
