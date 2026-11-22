"""The Initial Setup page: connect to a device's console port and run the read-only
device detection (Console-Based SSH Auto-Setup, phase 3).

    A  Console Connection   port list (Refresh Ports never opens a port), speed, optional
                            console login, Connect / Disconnect, connection status
    B  Device Detection     Detect Device (console.detect.detect_device, read-only)
    C  Detection Results    device information, SSH status and why, interfaces, warnings,
                            and the technical details (evidence, limitations, commands)
    D  SSH Configuration    (phase 4) a plan made by console.plan from the detection and the
       Preview              values typed here: status of each setting, the proposed commands
                            in order, what each does, conflicts and unknowns. PREVIEW ONLY:
                            there is no button that sends it.

Nothing on this page changes a device's configuration: it only reads. The preview
password fields are emptied when a preview is made; plans only contain <SSH_PASSWORD>.

Every serial operation (listing ports, connecting, detecting, disconnecting) runs on a
worker thread through gui.background.run_async; results come back on the Tk thread. One
console session at a time, one operation at a time (the page state decides which buttons
work). Closing the page or the window cancels any pending operation and closes the port.

backend: where ports and sessions come from. RealConsoleBackend (the default) uses the
computer's real COM ports. The simulated MockConsoleBackend (mock-lab/mocklab/console.py)
is used only when NetCommand is started with --mock-console.

Passwords are typed into masked fields, handed to the session once, and the fields are
emptied as soon as the connection attempt starts. They are never saved, logged or shown.
"""
import queue
import threading
import tkinter as tk
from datetime import datetime
from tkinter import ttk

from console.detect import SshCapability, detect_device
from console.link import (BAUD_RATES, CANCELLED, DEFAULT_BAUD, ConsoleError,
                          ConsoleSession, check_baudrate)
from console.plan import (CONFLICT, DEFAULT_KEY_SIZE, PREVIEW_NOTICE, STATUS_TEXT, UNKNOWN,
                          build_plan, key_sizes, plan_is_stale, validate_request)
from console.ports import discover_ports
from gui import background, theme
from gui.components.scroll_frame import ScrollFrame, bind_wheel

# ---------------------------------------------------------------- page states
DISCONNECTED, DISCOVERING_PORTS, CONNECTING = 'disconnected', 'discovering_ports', 'connecting'
CONNECTED, DETECTING, DETECTED = 'connected', 'detecting', 'detected'
DISCONNECTING, ERROR = 'disconnecting', 'error'
STATE_TEXT = {
    DISCONNECTED: ('Not connected', theme.TEXT_MUTED),
    DISCOVERING_PORTS: ('Looking for ports...', theme.TEXT_SOFT),
    CONNECTING: ('Connecting...', theme.WARNING),
    CONNECTED: ('Connected', theme.SUCCESS),
    DETECTING: ('Connected - detecting the device...', theme.WARNING),
    DETECTED: ('Connected - detection finished', theme.SUCCESS),
    DISCONNECTING: ('Disconnecting...', theme.WARNING),
    ERROR: ('Not connected - the last attempt failed', theme.DANGER),
}
BUSY = (DISCOVERING_PORTS, CONNECTING, DETECTING, DISCONNECTING)

SSH_TEXT = {
    SshCapability.SUPPORTED_ENABLED: (
        'Supported and enabled', theme.SUCCESS, theme.SUCCESS_SOFT,
        'SSH is supported and currently enabled.'),
    SshCapability.SUPPORTED_DISABLED: (
        'Supported, not enabled', theme.WARNING, theme.WARNING_SOFT,
        'SSH is supported but is not currently enabled.'),
    SshCapability.UNSUPPORTED: (
        'Not supported', theme.DANGER, theme.DANGER_SOFT,
        'The detected software appears not to support SSH.'),
    SshCapability.UNKNOWN: (
        'Unknown', theme.TEXT_SOFT, theme.SURFACE_2,
        'NetCommand could not determine SSH support with sufficient confidence.'),
}
SIMULATED_BANNER = 'SIMULATED DEVICE — NOT PHYSICAL HARDWARE'
NOT_AVAILABLE = 'Unknown'
NO_PORTS = ('No serial ports were found. Plug in the console cable (USB console cable or '
            'USB-to-serial adapter), check that its driver is installed, then click '
            'Refresh Ports.')
SSH_LATER = ('This page only reads the device. An SSH setup can be previewed below, but it is '
             'not sent to the device in this version.')
STEPS_NOTE = ('Each command as a step: what it needs first and how it would be checked '
              'afterwards with read-only show commands. These are definitions only; nothing '
              'is run or sent in this version.')
NO_NEW_PREVIEW = ('No new preview was made: detection did not finish (the console session ended '
                  'or was cancelled), so the configuration is not fully known. Connect again, '
                  'then use "Detect Again and Preview".')
COMMAND_STATUS = {'ok': 'worked', 'rejected': 'not recognised', 'denied': 'not authorised',
                  'failed': 'failed', 'skipped': 'not run',
                  'unexpected': 'unexpected answer (not used)'}


class RealConsoleBackend:
    """The computer's real COM ports and console sessions."""
    simulated = False
    mode_note = None

    def discover_ports(self):
        return discover_ports()                      # only lists ports; never opens one

    def open_session(self, port, baudrate, username, password, enable_password, log=None):
        return ConsoleSession(port, baudrate=baudrate, username=username, password=password,
                              enable_password=enable_password, log=log)


def show(value):
    """A value for the screen: never invented; missing values say so."""
    if value is None or value == '' or value == []:
        return NOT_AVAILABLE
    if isinstance(value, bool):
        return 'Yes' if value else 'No'
    return str(value)


def port_hint(port):
    """One line about a port for the user (only what the operating system reported)."""
    parts = [port.description or 'No description']
    parts.append(f'Hardware ID: {port.hwid or "not reported"}')
    if port.confidence == 'likely':
        parts.append(f'Looks like a console port ({port.reason}).')
    elif port.confidence == 'possible':
        parts.append(f'Possibly a console cable: {port.reason}. Make sure it is plugged into '
                     f'the device\'s CONSOLE port.')
    else:
        parts.append(f'Probably not a console cable ({port.reason}).')
    return '  ·  '.join(parts)


def describe_error(err, secrets=()):
    """A readable message for a failed console operation, never the driver's raw text
    and never a password."""
    if isinstance(err, (ConsoleError, ValueError)):
        text = str(err)
    else:
        text = f'The console operation failed ({type(err).__name__}).'
    for secret in secrets:
        if secret:
            text = text.replace(secret, '********')
    return text


class SetupTab(ttk.Frame):
    def __init__(self, parent, log=None, backend=None):
        """log(source, message, level): the operations console (never given a password)."""
        super().__init__(parent)
        self.backend = backend or RealConsoleBackend()
        self._log_fn = log
        self.phase = DISCONNECTED
        self.ports = []                    # ComPort list shown in the dropdown
        self.session = None                # the connected console session
        self._pending = None               # the session being connected (for Cancel)
        self.result = None                 # the last DetectionResult
        self.result_live = False           # False: from a session that has ended
        self.result_time = None
        self._stop_after_detection = False
        self.plan = None                   # the last SSH configuration preview (never executed)
        self._preview_after_detection = None   # a SetupRequest waiting for "Detect Again"
        self._closed = threading.Event()   # the page was destroyed
        self._progress = queue.Queue()
        self._shown_once = False
        self.bind('<Destroy>', self._on_destroy, add='+')

        box = ScrollFrame(self)
        box.pack(fill='both', expand=True)
        page = box.inner
        page.configure(padding=theme.PAD)
        self.page = page
        ttk.Label(page, text='Initial Setup', style='Title.TLabel').pack(anchor='w')
        ttk.Label(page, text='Connect to a new device through its console cable and find out '
                             'what it is and whether it can use SSH. ' + SSH_LATER,
                  style='Form.TLabel', foreground=theme.TEXT_SOFT, wraplength=820,
                  justify='left').pack(anchor='w', pady=(2, theme.PAD))
        if getattr(self.backend, 'mode_note', None):
            self.mode_banner = ttk.Label(page, text=self.backend.mode_note, style='Sample.TLabel',
                                         padding=(10, 5), wraplength=820, justify='left')
            self.mode_banner.pack(fill='x', pady=(0, theme.PAD))
        else:
            self.mode_banner = None
        self._build_connection(page)
        self._build_detection(page)
        self._build_results(page)
        self._build_preview(page)
        self._apply_state()

    # ================================================================ layout
    def _heading(self, parent, text):
        ttk.Separator(parent).pack(fill='x', pady=(theme.PAD * 2, theme.PAD))
        label = ttk.Label(parent, text=text, font=(theme.FONT_FAMILY, 12, 'bold'))
        label.pack(anchor='w', pady=(0, theme.PAD))
        return label

    def _build_connection(self, page):
        self._heading(page, '1  Console Connection')
        form = ttk.Frame(page)
        form.pack(fill='x')
        form.grid_columnconfigure(1, weight=1)
        ttk.Label(form, text='Console port', style='Form.TLabel').grid(row=0, column=0,
                                                                       sticky='w', pady=4)
        self.port_var = tk.StringVar()
        self.port_box = ttk.Combobox(form, textvariable=self.port_var, state='readonly',
                                     font=theme.FONT_FORM, width=60)
        self.port_box.grid(row=0, column=1, sticky='ew', padx=theme.PAD, pady=4)
        self.port_box.bind('<<ComboboxSelected>>', lambda e: self._show_port_hint())
        self.refresh_btn = ttk.Button(form, text='Refresh Ports', command=self.refresh_ports)
        self.refresh_btn.grid(row=0, column=2, sticky='w', pady=4)
        self.port_hint = ttk.Label(form, text='', foreground=theme.TEXT_MUTED, wraplength=760,
                                   justify='left')
        self.port_hint.grid(row=1, column=1, columnspan=2, sticky='w', padx=theme.PAD)

        ttk.Label(form, text='Speed (baud)', style='Form.TLabel').grid(row=2, column=0,
                                                                       sticky='w', pady=4)
        speed = ttk.Frame(form)
        speed.grid(row=2, column=1, columnspan=2, sticky='w', padx=theme.PAD, pady=4)
        self.baud_var = tk.StringVar(value=str(DEFAULT_BAUD))
        self.baud_box = ttk.Combobox(speed, textvariable=self.baud_var, state='readonly',
                                     values=[str(b) for b in BAUD_RATES], width=8,
                                     font=theme.FONT_FORM)
        self.baud_box.pack(side='left')
        ttk.Label(speed, text='Most Cisco devices use 9600.', foreground=theme.TEXT_MUTED).pack(
            side='left', padx=theme.PAD)

        login = ttk.Frame(page)
        login.pack(fill='x', pady=(theme.PAD, 0))
        ttk.Label(login, text='Console login (only if the device asks for one; it is not saved)',
                  style='Form.TLabel').grid(row=0, column=0, columnspan=3, sticky='w')
        self.user_var, self.password_var = tk.StringVar(), tk.StringVar()
        self.enable_var = tk.StringVar()
        self.use_enable = tk.IntVar(value=0)
        self.entries = {}
        for col, (label, var, masked) in enumerate([('Username', self.user_var, False),
                                                    ('Password', self.password_var, True)]):
            ttk.Label(login, text=label).grid(row=1, column=col, sticky='w', pady=(4, 0))
            entry = ttk.Entry(login, textvariable=var, width=22, font=theme.FONT_FORM,
                              show='*' if masked else '')
            entry.grid(row=2, column=col, sticky='w', padx=(0, theme.PAD * 2), ipady=2)
            self.entries[label] = entry
        self.enable_box = ttk.Checkbutton(
            login, text='Use privileged mode (enable) for detection - needs the enable password',
            variable=self.use_enable, style='Form.TCheckbutton', command=self._apply_state)
        self.enable_box.grid(row=3, column=0, columnspan=3, sticky='w', pady=(theme.PAD, 0))
        ttk.Label(login, text='Enable password').grid(row=4, column=0, sticky='w', pady=(4, 0))
        self.enable_entry = ttk.Entry(login, textvariable=self.enable_var, width=22, show='*',
                                      font=theme.FONT_FORM)
        self.enable_entry.grid(row=5, column=0, sticky='w', ipady=2)
        self.entries['Enable password'] = self.enable_entry

        bar = ttk.Frame(page)
        bar.pack(fill='x', pady=(theme.PAD * 1.5, 0))
        self.connect_btn = ttk.Button(bar, text='Connect', style='Large.Accent.TButton',
                                      command=self.connect)
        self.connect_btn.pack(side='left')
        self.disconnect_btn = ttk.Button(bar, text='Disconnect', command=self.disconnect)
        self.disconnect_btn.pack(side='left', padx=theme.PAD)
        self.status_dot = tk.Label(bar, text='●', font=(theme.FONT_FAMILY, 14),
                                   background=theme.BG)
        self.status_dot.pack(side='left', padx=(theme.PAD * 2, 4))
        self.status_label = ttk.Label(bar, text='', style='Form.TLabel')
        self.status_label.pack(side='left')
        self.message = ttk.Label(page, text='', wraplength=820, justify='left',
                                 style='Form.TLabel')
        self.message.pack(anchor='w', fill='x', pady=(theme.PAD, 0))

    def _build_detection(self, page):
        self._heading(page, '2  Device Detection')
        row = ttk.Frame(page)
        row.pack(fill='x')
        self.detect_btn = ttk.Button(row, text='Detect Device', style='Large.Accent.TButton',
                                     command=self.detect)
        self.detect_btn.pack(side='left')
        self.progress_bar = ttk.Progressbar(row, mode='indeterminate', length=160)
        self.progress_label = ttk.Label(row, text='Connect first, then detect the device. '
                                                  'Detection only reads (show commands).',
                                        foreground=theme.TEXT_MUTED)
        self.progress_label.pack(side='left', padx=theme.PAD)

    def _build_results(self, page):
        self._heading(page, '3  Detection Results')
        self.results = ttk.Frame(page)
        self.results.pack(fill='x', expand=True)
        self.empty = ttk.Label(self.results, text='No results yet. Connect to the device, then '
                                                  'click Detect Device.',
                               foreground=theme.TEXT_MUTED, style='Form.TLabel')
        self.empty.pack(anchor='w')
        self.result_widgets = {}

    # ================================================================ state
    def set_state(self, phase, message=None, level='info'):
        self.phase = phase
        if message is not None:
            color = {'error': theme.DANGER, 'warn': theme.WARNING, 'ok': theme.SUCCESS}.get(
                level, theme.TEXT)
            self.message.configure(text=message, foreground=color)
        self._apply_state()

    def _apply_state(self):
        s = self.phase
        no_session = self.session is None and s in (DISCONNECTED, ERROR)
        selected = self._selected_port() is not None

        def able(widget, on):
            widget.state(['!disabled'] if on else ['disabled'])
        able(self.refresh_btn, no_session)
        able(self.port_box, no_session)
        self.port_box.configure(state='readonly' if no_session else 'disabled')
        self.baud_box.configure(state='readonly' if no_session else 'disabled')
        for name in ('Username', 'Password'):
            able(self.entries[name], no_session)
        able(self.enable_box, no_session)
        able(self.enable_entry, no_session and bool(self.use_enable.get()))
        able(self.connect_btn, no_session and selected)
        able(self.detect_btn, s in (CONNECTED, DETECTED) and self.session is not None)
        can_stop = s in (CONNECTING, DETECTING) or (s in (CONNECTED, DETECTED)
                                                    and self.session is not None)
        able(self.disconnect_btn, can_stop)
        self.disconnect_btn.configure(text='Cancel' if s in (CONNECTING, DETECTING)
                                      else 'Disconnect')
        text, color = STATE_TEXT[s]
        if s in (CONNECTED, DETECTED, DETECTING) and self.session is not None:
            text += f' ({self.session.port}, {self.session.baudrate} baud)'
        self.status_label.configure(text=text, foreground=color)
        self.status_dot.configure(foreground=color)
        if s == DETECTING:
            if not self.progress_bar.winfo_manager():
                self.progress_bar.pack(side='left', padx=(theme.PAD, 0), before=self.progress_label)
                self.progress_bar.start(12)
        elif self.progress_bar.winfo_manager():
            self.progress_bar.stop()
            self.progress_bar.pack_forget()
        if hasattr(self, 'preview_btn'):
            idle_connected = s in (CONNECTED, DETECTED) and self.session is not None
            able(self.preview_btn, s == DETECTED and self.result is not None
                 and self.result_live)
            able(self.redetect_btn, idle_connected)
            for entry in self.preview_entries.values():
                able(entry, not self.busy)
            self.key_box.configure(state='disabled' if self.busy or not self.key_box.cget('values')
                                   else 'readonly')

    @property
    def busy(self):
        return self.phase in BUSY

    def _alive(self):
        if self._closed.is_set():
            return False
        try:
            return bool(self.winfo_exists())
        except tk.TclError:
            return False

    def _log(self, message, level='info'):
        if self._log_fn:
            try:
                self._log_fn('setup', message, level)
            except Exception:
                pass

    # ================================================================ ports
    def on_page_shown(self):
        if not self._shown_once:
            self._shown_once = True
            if self.phase == DISCONNECTED and not self.ports:
                self.refresh_ports()

    def refresh_ports(self):
        if self.busy or self.session is not None:
            return
        previous = self._selected_port()
        self.set_state(DISCOVERING_PORTS, 'Looking for serial ports (none is opened)...')
        background.run_async(self, self.backend.discover_ports,
                             lambda scan, err: self._ports_found(scan, err, previous))

    def _ports_found(self, scan, err, previous):
        if not self._alive():
            return
        if err is not None or scan is None:
            self.ports = []
            self._fill_ports(None)
            self.set_state(DISCONNECTED, 'The list of serial ports could not be read. Check the '
                                         'adapter driver, then try again.', 'error')
            return
        self.ports = list(scan.ports)
        keep = previous.device if previous else None
        self._fill_ports(keep)
        if scan.error:
            self.set_state(DISCONNECTED, scan.error, 'error')
        elif not self.ports:
            self.set_state(DISCONNECTED, NO_PORTS, 'warn')
        elif previous and not any(p.device == previous.device for p in self.ports):
            self.set_state(DISCONNECTED, f'{previous.device} is no longer listed (was the cable '
                                         f'unplugged?). Choose a port again.', 'warn')
        else:
            self.set_state(DISCONNECTED, f'{len(self.ports)} serial port'
                                         f'{"" if len(self.ports) == 1 else "s"} found. Choose '
                                         f'the one the console cable is connected to.')
        self._log(f'Serial ports: {", ".join(p.device for p in self.ports) or "none"}.')

    def _fill_ports(self, keep):
        labels = [p.label() for p in self.ports]
        self.port_box.configure(values=labels)
        chosen = next((p for p in self.ports if p.device == keep), None)
        if chosen is None and self.ports:
            likely = [p for p in self.ports if p.confidence == 'likely']
            chosen = likely[0] if len(likely) == 1 else (self.ports[0] if len(self.ports) == 1
                                                         else None)
        self.port_var.set(chosen.label() if chosen else '')
        self._show_port_hint()

    def _selected_port(self):
        label = self.port_var.get() if hasattr(self, 'port_var') else ''
        return next((p for p in self.ports if p.label() == label), None)

    def _show_port_hint(self):
        port = self._selected_port()
        self.port_hint.configure(text=port_hint(port) if port else
                                 ('Choose a port.' if self.ports else ''))
        self._apply_state()

    # ================================================================ connecting
    def connect(self):
        if self.busy or self.session is not None or self.phase not in (DISCONNECTED, ERROR):
            return                                           # one session, one attempt
        port = self._selected_port()
        if port is None:
            self.set_state(self.phase, 'Choose a serial port first.', 'error')
            return
        try:
            baud = check_baudrate(self.baud_var.get())
        except ValueError as err:
            self.set_state(self.phase, str(err), 'error')
            return
        username = self.user_var.get().strip()
        password = self.password_var.get()
        enable_password = self.enable_var.get() if self.use_enable.get() else ''
        if self.use_enable.get() and not enable_password:
            self.set_state(self.phase, 'Enter the enable password, or untick privileged mode.',
                           'error')
            return
        # The fields are emptied now: the passwords exist only in this attempt's session.
        self.password_var.set('')
        self.enable_var.set('')
        secrets = (password, enable_password)
        self.set_state(CONNECTING, f'Connecting to {port.device} at {baud} baud...')
        self._log(f'Connecting to {port.device} at {baud} baud.')
        closed, backend = self._closed, self.backend

        def work():
            session = backend.open_session(port.device, baud, username, password,
                                           enable_password, log=None)
            self._pending = session
            if closed.is_set():
                raise ConsoleError(CANCELLED, 'Cancelled.')
            try:
                result = session.connect()
            finally:
                if closed.is_set():                     # the page was closed meanwhile
                    session.disconnect()
            return session, result

        background.run_async(self, work, lambda res, err: self._connected(res, err, secrets))

    def _connected(self, res, err, secrets):
        self._pending = None
        if not self._alive():
            if res:
                res[0].cancel()
            return
        if err is not None:
            text = describe_error(err, secrets)
            self.set_state(ERROR, text, 'error')
            self._log(f'Connection failed: {text}', 'error')
            return
        self.session, result = res
        lines = [f'Connected to {result.port} at {result.baudrate} baud. Device prompt: '
                 f'{result.prompt}' + (' (privileged mode).' if result.privileged else
                                        ' (user mode).')]
        lines += [n for n in result.notices if 'answered "no"' in n and 'skipped' in n]
        lines.append('Click Detect Device to read what the device is.')
        self.set_state(CONNECTED, '\n'.join(lines), 'ok')
        self._log(f'Connected to {result.port} ({result.prompt}).', 'ok')
        if self.result is not None:
            self._mark_historical()

    # ================================================================ detection
    def detect(self):
        if self.phase not in (CONNECTED, DETECTED) or self.session is None or self.busy:
            return                                           # never two at once
        session = self.session
        elevate = bool(self.use_enable.get())
        self._stop_after_detection = False
        self.set_state(DETECTING, 'Reading the device (show commands only)...')
        self._log(f'Detecting the device on {session.port} (read-only).')
        progress = self._progress

        def work():
            return detect_device(session, elevate=elevate, progress=progress.put)

        background.run_async(self, work, lambda r, e: self._detected(session, r, e))
        self._drain_progress()

    def _drain_progress(self):
        if not self._alive():
            return
        last = None
        while True:
            try:
                last = self._progress.get_nowait()
            except queue.Empty:
                break
        if last and self.phase == DETECTING:
            self.progress_label.configure(text=last)
        if self.phase == DETECTING:
            try:
                self.after(100, self._drain_progress)
            except tk.TclError:
                pass

    def _detected(self, session, result, err):
        if not self._alive():
            return
        if session is not self.session:                      # a stale answer: ignore it
            return
        if err is not None:
            if self._preview_after_detection is not None:
                self.preview_error.configure(text=NO_NEW_PREVIEW)
            self._preview_after_detection = None
            text = describe_error(err)
            self.progress_label.configure(text='Detection did not finish.')
            self._log(f'Detection failed: {text}', 'error')
            self._session_lost(f'Detection stopped: {text}')
            return
        self.result, self.result_live, self.result_time = result, True, datetime.now()
        self.render_result(result)
        self._fill_key_sizes()
        request, self._preview_after_detection = self._preview_after_detection, None
        if request is not None and result.complete and session.is_active():
            self._show_plan(build_plan(result, request))
        else:
            if request is not None:
                self.preview_error.configure(text=NO_NEW_PREVIEW)
            self._refresh_staleness()
        self.progress_label.configure(text=f'Detection finished at '
                                           f'{self.result_time:%H:%M:%S}. ' +
                                           ('' if result.complete else 'Some commands were not '
                                                                       'run.'))
        self._log(f'Detection finished: SSH {SSH_TEXT[result.ssh.status][0].lower()}'
                  f'{" (SIMULATED device)" if result.simulated else ""}.',
                  'ok' if result.complete else 'warn')
        if self._stop_after_detection:
            self._stop_after_detection = False
            self._start_disconnect('Detection cancelled; disconnected.')
            return
        if not session.is_active():
            self._session_lost('The console connection ended during detection. The results '
                               'below are partial.')
            return
        self.set_state(DETECTED, 'Detection finished. Nothing was changed on the device.', 'ok')

    def _session_lost(self, message):
        """The session ended by itself (timeout, cable pulled): release it."""
        session, self.session = self.session, None
        if session is not None:
            threading.Thread(target=self._quiet_close, args=(session,), daemon=True).start()
        if self.result is not None:
            self._mark_historical()
        self.set_state(ERROR, message, 'error')

    @staticmethod
    def _quiet_close(session):
        for step in (session.cancel, session.disconnect):
            try:
                step()
            except Exception:
                pass

    # ================================================================ disconnecting
    def disconnect(self):
        if self.phase == CONNECTING:
            pending = self._pending
            if pending is not None:
                pending.cancel()
            self.message.configure(text='Cancelling the connection...')
            return
        if self.phase == DETECTING:
            self._stop_after_detection = True
            if self.session is not None:
                self.session.cancel()                        # the running command stops
            self.message.configure(text='Stopping detection...')
            return
        if self.phase in (CONNECTED, DETECTED) and self.session is not None:
            self._start_disconnect('Disconnected. The serial port is free again.')

    def _start_disconnect(self, done_message):
        session = self.session
        self.set_state(DISCONNECTING, 'Disconnecting...')

        def done(_r, err):
            if self.session is session:
                self.session = None
            if not self._alive():
                return
            if self.result is not None:
                self._mark_historical()
            if err is not None:
                self._quiet_close(session)                   # make sure the port is closed
                self.set_state(DISCONNECTED, f'Disconnecting reported a problem '
                                             f'({describe_error(err)}). The port was closed.',
                               'warn')
                self._log('Disconnect reported a problem; the port was closed.', 'warn')
                return
            self.set_state(DISCONNECTED, done_message, 'ok')
            self._log(f'Disconnected from {session.port}.', 'ok')
        background.run_async(self, session.disconnect, done)

    def _on_destroy(self, event):
        """The page or the window is closing: stop pending work and close the port. The
        worker threads find the page gone and never touch a widget."""
        if event.widget is not self or self._closed.is_set():
            return
        self._closed.set()
        for session in (self._pending, self.session):
            if session is not None:
                threading.Thread(target=self._quiet_close, args=(session,), daemon=True).start()
        self.session = self._pending = None

    # ================================================================ results
    def _mark_historical(self):
        self.result_live = False
        self._refresh_staleness()
        label = self.result_widgets.get('live')
        if label is not None:
            when = f'{self.result_time:%H:%M:%S}' if self.result_time else 'earlier'
            label.configure(text=f'EARLIER RESULT: read at {when} during a console session that '
                                 f'has ended. It is not live information.',
                            background=theme.WARNING_SOFT, foreground=theme.WARNING)

    def render_result(self, result):
        for child in self.results.winfo_children():
            child.destroy()
        w = self.result_widgets = {}
        parent = self.results
        if result.simulated:
            w['simulated'] = tk.Label(parent, text=SIMULATED_BANNER, font=(theme.FONT_FAMILY, 13,
                                                                           'bold'),
                                      background=theme.DANGER_SOFT, foreground=theme.DANGER,
                                      padx=12, pady=6, anchor='w')
            w['simulated'].pack(fill='x', pady=(0, 4))
        w['live'] = tk.Label(parent, text=f'Live result from the connected device (read at '
                                          f'{self.result_time:%H:%M:%S}).'
                             if self.result_time else 'Live result.',
                             background=theme.ACCENT_SOFT, foreground=theme.ACCENT,
                             font=theme.FONT, padx=10, pady=4, anchor='w')
        w['live'].pack(fill='x', pady=(0, 4))
        if not result.complete:
            w['incomplete'] = tk.Label(parent, text='INCOMPLETE: the console session ended during '
                                                    'detection, so some information is missing.',
                                       background=theme.WARNING_SOFT, foreground=theme.WARNING,
                                       font=theme.FONT_BOLD, padx=10, pady=4, anchor='w')
            w['incomplete'].pack(fill='x', pady=(0, 4))

        d, a, s, v = result.device, result.access, result.ssh, result.vty
        manufacturer = d.manufacturer if not result.simulated else 'None (simulated device)'
        self._section(parent, 'Device Information', [
            ('Hostname', d.hostname), ('Device type', d.device_type.capitalize()
                                       if d.device_type != 'unknown' else None),
            ('Manufacturer', manufacturer), ('Model', d.model),
            ('Software', d.software), ('Software version', d.version),
            ('Image file', d.image), ('Platform', d.platform),
            ('Privilege level', a.privilege_level),
        ], key='device')

        title, color, soft, sentence = SSH_TEXT[s.status]
        ssh_box = ttk.Frame(parent)
        ssh_box.pack(fill='x', pady=(theme.PAD, 0))
        ttk.Label(ssh_box, text='SSH Status', font=theme.FONT_FORM_BOLD).pack(anchor='w')
        w['ssh_badge'] = tk.Label(ssh_box, text=f'{title}   ({s.status.name})',
                                  font=(theme.FONT_FAMILY, 12, 'bold'), background=soft,
                                  foreground=color, padx=12, pady=5, anchor='w')
        w['ssh_badge'].pack(fill='x', pady=(4, 2))
        w['ssh_sentence'] = ttk.Label(ssh_box, text=sentence, style='Form.TLabel')
        w['ssh_sentence'].pack(anchor='w')
        rsa = s.rsa
        rsa_text = (NOT_AVAILABLE if rsa.present is None else
                    'No RSA key pair' if not rsa.present else
                    f'Present: {", ".join(rsa.key_names)}' +
                    (f' ({rsa.modulus_bits} bits)' if rsa.modulus_bits else ''))
        login = v.login_configured
        self._section(parent, None, [
            ('SSH version', s.version), ('RSA keys', rsa_text),
            ('VTY lines configured', ', '.join(f'vty {r}' for r in v.ranges) if v.ranges else
             (None if v.configured is None else 'None')),
            ('VTY lines on the device', v.available_lines),
            ('SSH allowed on VTY lines', v.ssh_transport),
            ('Login required on VTY lines', login),
            ('Local accounts', ', '.join(s.local_usernames) if s.local_usernames else None),
        ], key='ssh')

        self._interfaces(parent, result)

        notes = [x for x in result.warnings if not x.startswith('SIMULATION')]
        if a.privilege_level is not None and a.privilege_level < 15:
            notes.insert(0, f'Privilege level {a.privilege_level}: some information needs '
                            f'privileged mode (tick "Use privileged mode" and connect again).')
        if notes:
            ttk.Label(parent, text='Warnings', font=theme.FONT_FORM_BOLD).pack(
                anchor='w', pady=(theme.PAD, 2))
            w['warnings'] = ttk.Label(parent, text='\n'.join(f'•  {n}' for n in notes),
                                      foreground=theme.WARNING, wraplength=820, justify='left',
                                      style='Form.TLabel')
            w['warnings'].pack(anchor='w')
        self._details(parent, result)
        ttk.Label(parent, text=SSH_LATER, foreground=theme.TEXT_MUTED).pack(
            anchor='w', pady=(theme.PAD, 0))

    def _section(self, parent, title, rows, key):
        frame = ttk.Frame(parent)
        frame.pack(fill='x', pady=(theme.PAD, 0))
        if title:
            ttk.Label(frame, text=title, font=theme.FONT_FORM_BOLD).grid(
                row=0, column=0, columnspan=2, sticky='w', pady=(0, 4))
        values = {}
        for n, (label, value) in enumerate(rows, start=1):
            ttk.Label(frame, text=label, foreground=theme.TEXT_SOFT).grid(
                row=n, column=0, sticky='w', padx=(0, theme.PAD * 3), pady=1)
            text = show(value)
            cell = ttk.Label(frame, text=text, style='Form.TLabel',
                             foreground=theme.TEXT_MUTED if text == NOT_AVAILABLE else theme.TEXT)
            cell.grid(row=n, column=1, sticky='w', pady=1)
            values[label] = cell
        self.result_widgets[key] = values

    def _interfaces(self, parent, result):
        ttk.Label(parent, text='Management Interfaces', font=theme.FONT_FORM_BOLD).pack(
            anchor='w', pady=(theme.PAD, 2))
        if not result.interfaces:
            self.result_widgets['interfaces'] = None
            ttk.Label(parent, text='No interface information (the command did not work or the '
                                   'device listed none).', foreground=theme.TEXT_MUTED).pack(
                anchor='w')
            return
        holder = ttk.Frame(parent)
        holder.pack(fill='x')
        cols = [('name', 'Interface', 220), ('ip', 'IP address', 150), ('status', 'Status', 190),
                ('protocol', 'Protocol', 90), ('note', '', 200)]
        tree = ttk.Treeview(holder, columns=[c[0] for c in cols], show='headings',
                            height=min(len(result.interfaces), 8), style='Data.Treeview')
        for key, title, width in cols:
            tree.heading(key, text=title)
            tree.column(key, width=width, anchor='w')
        for i in result.interfaces:
            tree.insert('', 'end', values=(i.name, i.ip or 'none', i.status, i.protocol,
                                           'likely management interface'
                                           if i.name == result.management_interface else ''))
        tree.grid(row=0, column=0, sticky='ew')
        holder.grid_columnconfigure(0, weight=1)
        bind_wheel(tree)
        self.result_widgets['interfaces'] = tree
        text = (f'Likely management interface: {result.management_interface} '
                f'({result.management_reason})' if result.management_interface else
                f'No management interface identified: {result.management_reason or "unknown"}.')
        self.result_widgets['management'] = ttk.Label(parent, text=text, style='Form.TLabel')
        self.result_widgets['management'].pack(anchor='w', pady=(4, 0))

    def _details(self, parent, result):
        lines = ['Why this SSH status:'] + [f'  •  {e}' for e in result.ssh.evidence]
        if result.limitations:
            lines += ['', 'Limitations:'] + [f'  •  {x}' for x in result.limitations]
        lines += ['', 'Commands read:']
        lines += [f'  •  {c.command}: {COMMAND_STATUS.get(c.status, c.status)}'
                  + (f' ({c.error})' if c.error and c.status in ('failed', 'skipped') else '')
                  for c in result.commands]
        toggle = ttk.Button(parent, text='Show technical details')
        toggle.pack(anchor='w', pady=(theme.PAD, 2))
        body = ttk.Label(parent, text='\n'.join(lines), wraplength=820, justify='left',
                         font=theme.mono(10))

        def flip():
            if body.winfo_manager():
                body.pack_forget()
                toggle.configure(text='Show technical details')
            else:
                body.pack(anchor='w', after=toggle)
                toggle.configure(text='Hide technical details')
        toggle.configure(command=flip)
        self.result_widgets['details_toggle'] = toggle
        self.result_widgets['details'] = body

    # ================================================================ SSH configuration preview
    def _build_preview(self, page):
        self._heading(page, '4  SSH Configuration Preview')
        self.preview_notice = tk.Label(page, text=PREVIEW_NOTICE, font=theme.FONT_FORM_BOLD,
                                       background=theme.ACCENT_SOFT, foreground=theme.ACCENT,
                                       padx=10, pady=5, anchor='w')
        self.preview_notice.pack(fill='x', pady=(0, theme.PAD))
        ttk.Label(page, text='Enter only what you want to change or add; empty fields keep what '
                             'the device has. NetCommand proposes commands for what is missing and '
                             'explains each one. Nothing is sent to the device, and there is no '
                             'way to apply the plan in this version.',
                  wraplength=820, justify='left', foreground=theme.TEXT_SOFT).pack(anchor='w')
        form = ttk.Frame(page)
        form.pack(fill='x', pady=(theme.PAD, 0))
        self.want = {k: tk.StringVar() for k in ('hostname', 'domain_name', 'username',
                                                 'password', 'confirm')}
        self.preview_entries = {}
        fields = [('hostname', 'New hostname (optional)', False),
                  ('domain_name', 'Domain name (optional)', False),
                  ('username', 'New SSH username (optional)', False),
                  ('password', 'Password for the new account', True),
                  ('confirm', 'Password again', True)]
        for n, (key, label, masked) in enumerate(fields):
            row, col = divmod(n, 3)
            ttk.Label(form, text=label).grid(row=row * 2, column=col, sticky='w', pady=(4, 0))
            entry = ttk.Entry(form, textvariable=self.want[key], width=24, font=theme.FONT_FORM,
                              show='*' if masked else '')
            entry.grid(row=row * 2 + 1, column=col, sticky='w', padx=(0, theme.PAD * 2), ipady=2)
            self.preview_entries[key] = entry
        ttk.Label(form, text='RSA key size (bits)').grid(row=2, column=2, sticky='w', pady=(4, 0))
        self.key_var = tk.StringVar(value=str(DEFAULT_KEY_SIZE))
        self.key_box = ttk.Combobox(form, textvariable=self.key_var, state='disabled', width=8,
                                    font=theme.FONT_FORM, values=())
        self.key_box.grid(row=3, column=2, sticky='w')
        # any change to the values makes an existing preview out of date
        self._inputs_changed = False
        for var in list(self.want.values()) + [self.key_var]:
            var.trace_add('write', lambda *_a: self._on_input_changed())
        self.preview_error = ttk.Label(page, text='', foreground=theme.DANGER, wraplength=820,
                                       justify='left', style='Form.TLabel')
        self.preview_error.pack(anchor='w', pady=(4, 0))
        bar = ttk.Frame(page)
        bar.pack(fill='x', pady=(theme.PAD, 0))
        self.preview_btn = ttk.Button(bar, text='Preview SSH Configuration',
                                      style='Large.Accent.TButton', command=self.preview)
        self.preview_btn.pack(side='left')
        self.redetect_btn = ttk.Button(bar, text='Detect Again and Preview',
                                       command=self.detect_and_preview)
        self.redetect_btn.pack(side='left', padx=theme.PAD)
        self.preview_box = ttk.Frame(page)
        self.preview_box.pack(fill='x', expand=True, pady=(theme.PAD, 0))
        ttk.Label(self.preview_box, text='No preview yet. Detect the device first.',
                  foreground=theme.TEXT_MUTED, style='Form.TLabel').pack(anchor='w')
        self.preview_widgets = {}

    def _fill_key_sizes(self):
        sizes = [str(s) for s in key_sizes(self.result)]
        self.key_box.configure(values=sizes)
        if sizes and self.key_var.get() not in sizes:
            self.key_var.set(str(DEFAULT_KEY_SIZE) if str(DEFAULT_KEY_SIZE) in sizes else sizes[0])
        self._apply_state()

    def _read_request(self):
        """A SetupRequest from the form, or None (with the problems shown). The password
        fields are emptied here: the request only knows whether a password was given."""
        values = {k: v.get() for k, v in self.want.items()}
        self.want['password'].set('')
        self.want['confirm'].set('')
        request, errors = validate_request(values['hostname'], values['domain_name'],
                                           values['username'], values['password'],
                                           values['confirm'], self.key_var.get(), self.result)
        values.clear()
        if errors:
            self.preview_error.configure(text='\n'.join(errors.values()))
            return None
        self.preview_error.configure(text='')
        return request

    def preview(self):
        """Make a plan from the current (live) detection. Sends nothing."""
        if self.result is None or not self.result_live or self.phase != DETECTED:
            self.preview_error.configure(text='Connect and detect the device first, so the '
                                              'preview uses current information.')
            return
        request = self._read_request()
        if request is not None:
            self._show_plan(build_plan(self.result, request))

    def detect_and_preview(self):
        """Read the device again (show commands only), then make the plan from the fresh
        result, so the preview never relies on old information."""
        if self.phase not in (CONNECTED, DETECTED) or self.session is None or self.busy:
            return
        request = self._read_request()
        if request is None:
            return
        self._preview_after_detection = request
        self.detect()

    def _on_input_changed(self):
        if self.plan is not None:
            self._inputs_changed = True
            self._refresh_staleness()

    def _refresh_staleness(self):
        label = self.preview_widgets.get('stale')
        if label is None or self.plan is None:
            return
        why = plan_is_stale(self.plan, self.result, self.result_live) or (
            'The values entered below were changed after this preview was made.'
            if self._inputs_changed else None)
        if why:
            label.configure(text=f'OUT OF DATE: {why} Use "Detect Again and Preview" before '
                                 f'relying on this plan.')
            if not label.winfo_manager():
                label.pack(fill='x', pady=(0, 4), before=self.preview_widgets['first'])

    def _show_plan(self, plan):
        self.plan = plan
        self._inputs_changed = False
        self.preview_error.configure(text='')
        for child in self.preview_box.winfo_children():
            child.destroy()
        w = self.preview_widgets = {}
        box = self.preview_box
        w['stale'] = tk.Label(box, text='', background=theme.WARNING_SOFT,
                              foreground=theme.WARNING, font=theme.FONT_BOLD, padx=10, pady=4,
                              anchor='w', wraplength=900, justify='left')
        if plan.simulated:
            w['first'] = w['simulated'] = tk.Label(
                box, text=SIMULATED_BANNER + ' — this plan is for a simulated device.',
                font=(theme.FONT_FAMILY, 12, 'bold'), background=theme.DANGER_SOFT,
                foreground=theme.DANGER, padx=12, pady=5, anchor='w')
            w['simulated'].pack(fill='x', pady=(0, 4))
        when = f'{plan.detected_at:%H:%M:%S}' if plan.detected_at else 'unknown time'
        made = tk.Label(box, text=f'Based on the detection at {when}. {PREVIEW_NOTICE}',
                        background=theme.ACCENT_SOFT, foreground=theme.ACCENT, font=theme.FONT,
                        padx=10, pady=4, anchor='w')
        made.pack(fill='x', pady=(0, 4))
        w.setdefault('first', made)
        w['reason'] = ttk.Label(box, text=plan.reason, wraplength=900, justify='left',
                                style='Form.TLabel',
                                foreground=theme.TEXT if plan.available else theme.DANGER)
        w['reason'].pack(anchor='w', pady=(0, theme.PAD))

        ttk.Label(box, text='Current configuration', font=theme.FONT_FORM_BOLD).pack(anchor='w')
        holder = ttk.Frame(box)
        holder.pack(fill='x')
        cols = [('setting', 'Setting', 230), ('status', 'Status', 150), ('current', 'Now', 300),
                ('plan', 'What happens', 520)]
        tree = ttk.Treeview(holder, columns=[c[0] for c in cols], show='headings',
                            height=len(plan.items), style='Data.Treeview')
        for key, title, width in cols:
            tree.heading(key, text=title)
            tree.column(key, width=width, anchor='w', stretch=key == 'plan')
        colors = {'configured': theme.SUCCESS_SOFT, 'missing': theme.SURFACE, 'unknown': theme.SURFACE_2,
                  'needs_attention': theme.WARNING_SOFT, 'conflict': theme.DANGER_SOFT,
                  'unsupported': theme.DANGER_SOFT}
        for status, color in colors.items():
            tree.tag_configure(status, background=color)
        for item in plan.items:
            tree.insert('', 'end', iid=item.key, tags=(item.status,),
                        values=(item.title, STATUS_TEXT[item.status], item.current,
                                item.explanation))
        tree.grid(row=0, column=0, sticky='ew')
        holder.grid_columnconfigure(0, weight=1)
        bind_wheel(tree)
        tree.bind('<<TreeviewSelect>>', lambda e: self._show_item(tree))
        w['items'] = tree
        w['item_text'] = ttk.Label(box, text='Select a row to read the whole explanation.',
                                   wraplength=900, justify='left', foreground=theme.TEXT_SOFT)
        w['item_text'].pack(anchor='w', pady=(4, theme.PAD))

        attention = [i for i in plan.items if i.status in (CONFLICT, UNKNOWN)]
        if attention:
            ttk.Label(box, text='Conflicts and unknown settings', font=theme.FONT_FORM_BOLD).pack(
                anchor='w')
            w['attention'] = ttk.Label(
                box, wraplength=900, justify='left', style='Form.TLabel',
                text='\n'.join(f'•  {STATUS_TEXT[i.status]} - {i.title}: {i.explanation}'
                               for i in attention), foreground=theme.DANGER)
            w['attention'].pack(anchor='w', pady=(0, theme.PAD))

        ttk.Label(box, text='Proposed commands (in order)', font=theme.FONT_FORM_BOLD).pack(
            anchor='w')
        if plan.commands:
            lines = plan.lines()
            text = tk.Text(box, height=len(lines) + 1, font=theme.mono(theme.CODE_SIZE),
                           wrap='none', borderwidth=1, relief='solid', padx=8, pady=6)
            text.insert('1.0', '\n'.join(lines))
            text.configure(state='disabled')                     # read-only: nothing to run
            text.pack(fill='x', pady=(2, 4))
            w['commands'] = text
            groups = [('additions', 'Safe additions (nothing existing is changed)',
                       plan.additions, theme.SUCCESS),
                      ('modifications', 'Changes to existing settings', plan.modifications,
                       theme.WARNING)]
            for key, title, commands, color in groups:
                if not commands:
                    continue
                ttk.Label(box, text=title, font=theme.FONT_BOLD, foreground=color).pack(
                    anchor='w', pady=(theme.PAD, 0))
                body = '\n'.join(
                    f'•  {c.mode + ": " if c.mode else ""}{c.text}  -  {c.purpose}'
                    + ('  [MAY CUT OFF CURRENT USERS]' if c.disruptive else '')
                    for c in commands)
                label = ttk.Label(box, text=body, wraplength=900, justify='left')
                label.pack(anchor='w')
                w[key] = label
        else:
            w['commands'] = None
            ttk.Label(box, text='No commands are proposed.' if plan.available else
                      'No commands are proposed for this device (see above).',
                      foreground=theme.TEXT_MUTED, style='Form.TLabel').pack(anchor='w')
        if plan.steps:
            self._steps_view(box, plan)
        notes = plan.warnings + plan.limitations
        w['notes'] = ttk.Label(box, text='\n'.join(f'•  {n}' for n in notes), wraplength=900,
                               justify='left', foreground=theme.TEXT_SOFT)
        w['notes'].pack(anchor='w', pady=(theme.PAD, 0))
        self._log(f'SSH configuration preview made: {len(plan.commands)} proposed command(s), '
                  f'{len(plan.conflicts)} conflict(s). Nothing was sent to the device.')
        self._refresh_staleness()

    def _steps_view(self, box, plan):
        """The step definitions (dependencies and read-only checks), behind a toggle.
        Definitions only: nothing on this page runs them."""
        lines = [STEPS_NOTE, '']
        for n, step in enumerate(plan.steps + plan.invariants, start=1):
            what = step.command.text if step.command is not None else '(read-only check)'
            lines.append(f'{n}. {step.title}  [{step.step_id}]')
            lines.append(f'     command:  {what}')
            lines.append(f'     needs:    {", ".join(step.requires) or "nothing before it"}')
            for v in step.verifications:
                lines.append(f'     check:    {v.command}  ->  verified when {v.verified}'
                             + ('' if v.required else '  (supporting only)'))
            if step.prompt is not None and step.prompt.hostname_changes_to:
                lines.append(f'     prompt:   changes to {step.prompt.prompt_after}')
            if step.questions:
                lines.append('     never answered automatically: '
                             + ', '.join(f'"{q}"' for q in step.questions))
            if step.approval_required:
                lines.append(f'     SEPARATE APPROVAL NEEDED: {step.approval_reason}')
        toggle = ttk.Button(box, text='Show steps, dependencies and checks')
        toggle.pack(anchor='w', pady=(theme.PAD, 2))
        body = ttk.Label(box, text='\n'.join(lines), wraplength=900, justify='left',
                         font=theme.mono(10))

        def flip():
            if body.winfo_manager():
                body.pack_forget()
                toggle.configure(text='Show steps, dependencies and checks')
            else:
                body.pack(anchor='w', after=toggle)
                toggle.configure(text='Hide steps, dependencies and checks')
        toggle.configure(command=flip)
        self.preview_widgets['steps_toggle'] = toggle
        self.preview_widgets['steps'] = body

    def _show_item(self, tree):
        selected = tree.selection()
        item = self.plan.item(selected[0]) if selected and self.plan else None
        if item is not None:
            self.preview_widgets['item_text'].configure(
                text=f'{item.title} ({STATUS_TEXT[item.status]}): {item.explanation}')
