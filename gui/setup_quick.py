"""The simple Initial Setup screen ("Quick setup"), shown on top of the Setup page.

    1  Connect     choose the COM port, click Connect. Detection runs by itself.
    2  Your device what was found, and whether SSH can be set up on it.
    3  Set up SSH  device name, SSH username and password (typed ONCE), the management IP
                   address the Scan page will use; one button, one plain confirmation.
    4  Done        "Use in Scan page" fills in the Seed IP, username and password there.

It drives the same machinery as the detailed sections (now under "Advanced"): the same
read-only detection, the same plan, and the same step-by-step Apply that checks every step
with show commands. Nothing is skipped; only the questions are fewer:
  * the password is typed once (it is handed to the Apply itself, never saved here);
  * the typed username is created, or - if it already exists - gets the typed password
    (said plainly in the confirmation), so the login the Scan page needs is always known;
  * the configuration is always saved to startup-config at the end;
  * one confirmation dialog replaces the typed phrase and the approval tick boxes.
The password stays in memory only until you leave the page or disconnect (so "Test SSH
login" and "Use in Scan page" can use it); it is never written to disk or the log.
"""
import tkinter as tk
from tkinter import ttk

from console.detect import SshCapability
from console.plan import (DEFAULT_HOSTNAMES, account_exists, build_plan, existing_admins,
                          validate_request)
from gui import theme, ui_scale

DEFAULT_DOMAIN = 'lab.local'
DEFAULT_MASK = '255.255.255.0'
TYPE_WORDS = {'router': 'router', 'switch': 'switch'}
STEP_WORDS = {                               # the plan's steps in plain words
    'hostname': 'name the device',
    'domain': 'set a domain name (needed for the SSH key)',
    'user': 'create the SSH user',
    'rsa': 'create the SSH key (can take up to a minute)',
    'ssh_version': 'turn on SSH version 2',
    'ssh_ready': 'check that SSH is on',
    'mgmt_ip': 'give it the management IP address',
    'mgmt_up': 'switch that interface on',
    'gateway': 'set the default gateway',
    'save': 'save everything (write memory)',
}


CHECK_WORDS = {                              # console.plan.ssh_checklist rows in plain words
    'Hostname not "Router"/"Switch"': 'a device name',
    'Domain name': 'a domain name',
    'Local user with privilege 15': 'an SSH user',
    'RSA key 2048+': 'an SSH key',
    'SSH version 2': 'SSH version 2',
    'VTY: login local + transport ssh': 'remote logins by SSH',
    'Management IP on an "up" interface': 'a management IP address',
    'Default gateway': 'a default gateway (optional)',
}


def plain_step(step):
    """A step of the plan in plain words."""
    if step.step_id.startswith('vty_login'):
        return 'ask for the SSH username and password on remote logins'
    if step.step_id.startswith('vty_transport'):
        return 'allow SSH (only) for remote logins'
    if step.step_id == 'user' and step.title.startswith('Change the password of '):
        return f'set the new password for {step.title[len("Change the password of "):]}'
    return STEP_WORDS.get(step.step_id, step.title)


class QuickPanel:
    """The simple screen. tab: the SetupTab it drives."""

    def __init__(self, tab, parent):
        self.tab = tab
        self.secret = None                   # the typed password, until disconnect / leave
        self.frame = frame = ttk.Frame(parent)
        frame.pack(fill='x')
        wrap = ui_scale.space(860)

        # ---- 1 the console connection: the page's own section above (port, speed,
        # console login, privileged mode, Connect / Disconnect)

        # ---- 2 the device
        self.device_box = ttk.Frame(frame)
        self._title(self.device_box, '2  Your device')
        self.device_text = tk.Label(self.device_box, text='', font=theme.FONT_FORM_BOLD,
                                    anchor='w', justify='left', wraplength=wrap, padx=10, pady=6,
                                    background=theme.BG)
        self.device_text.pack(fill='x')
        self.device_detail = ttk.Label(self.device_box, text='', wraplength=wrap,
                                       justify='left', style='Form.TLabel')
        self.device_detail.pack(anchor='w', pady=(4, 0))

        # ---- 3 the form
        self.form_box = ttk.Frame(frame)
        self._title(self.form_box, '3  Set up SSH')
        form = ttk.Frame(self.form_box)
        form.pack(fill='x')
        self.vars = {k: tk.StringVar() for k in ('hostname', 'username', 'password', 'again',
                                                 'interface', 'ip', 'mask', 'gateway',
                                                 'domain')}
        self.entries = {}
        fields = [('hostname', 'Device name', False, 0, 0,
                   'For example R1 or SW1 (not "Router" / "Switch").'),
                  ('username', 'SSH username', False, 0, 1,
                   'You log in with this over SSH, and the Scan page uses it.'),
                  ('password', 'SSH password', True, 1, 0,
                   '8-25 characters, no spaces. Typed only here, once.'),
                  ('again', 'SSH password again', True, 1, 1,
                   'The same password again, to catch typing mistakes.')]
        for key, label, masked, r, c, note in fields:
            ttk.Label(form, text=label, font=theme.FONT_BOLD).grid(row=r * 3, column=c,
                                                                   sticky='w', pady=(6, 0))
            entry = ttk.Entry(form, textvariable=self.vars[key], width=26, font=theme.FONT_FORM,
                              show='*' if masked else '')
            entry.grid(row=r * 3 + 1, column=c, sticky='w', padx=(0, theme.PAD * 3), ipady=2)
            ttk.Label(form, text=note, foreground=theme.TEXT_MUTED, wraplength=ui_scale.space(
                300)).grid(row=r * 3 + 2, column=c, sticky='w', padx=(0, theme.PAD * 3))
            self.entries[key] = entry
        self.user_note = ttk.Label(self.form_box, text='', foreground=theme.TEXT_SOFT,
                                   wraplength=wrap, justify='left')
        self.user_note.pack(anchor='w', pady=(4, 0))
        ttk.Label(self.form_box, text='Management IP address (the Seed IP you will scan)',
                  font=theme.FONT_FORM_BOLD).pack(anchor='w', pady=(theme.PAD, 0))
        ttk.Label(self.form_box, text='The IP address the device gets, for example 192.168.1.1. '
                                      'The port is chosen for you (a router\'s Ethernet port, a '
                                      'switch\'s Vlan1); keep the mask 255.255.255.0 unless your '
                                      'network uses another. Gateway: leave it empty if you do '
                                      'not know it.', foreground=theme.TEXT_MUTED,
                  wraplength=wrap, justify='left').pack(anchor='w')
        mgmt = ttk.Frame(self.form_box)
        mgmt.pack(fill='x')
        ttk.Label(mgmt, text='Port').grid(row=0, column=0, sticky='w')
        self.iface_box = ttk.Combobox(mgmt, textvariable=self.vars['interface'], width=44,
                                      state='readonly', font=theme.FONT_FORM)
        self.iface_box.grid(row=1, column=0, sticky='w', padx=(0, theme.PAD * 2))
        for col, (key, label) in enumerate((('ip', 'IP address'), ('mask', 'Subnet mask'),
                                            ('gateway', 'Gateway (optional)')), start=1):
            ttk.Label(mgmt, text=label).grid(row=0, column=col, sticky='w')
            entry = ttk.Entry(mgmt, textvariable=self.vars[key], width=16, font=theme.FONT_FORM)
            entry.grid(row=1, column=col, sticky='w', padx=(0, theme.PAD * 2), ipady=2)
            self.entries[key] = entry
        self.mgmt_note = ttk.Label(self.form_box, text='', foreground=theme.TEXT_SOFT,
                                   wraplength=wrap, justify='left')
        self.mgmt_note.pack(anchor='w', pady=(4, 0))
        self.error = ttk.Label(self.form_box, text='', foreground=theme.DANGER, wraplength=wrap,
                               justify='left', style='Form.TLabel')
        self.error.pack(anchor='w', pady=(4, 0))
        self.setup_btn = ttk.Button(self.form_box, text='Set up SSH', style='Large.Accent.TButton',
                                    command=self.set_up)
        self.setup_btn.pack(anchor='w', pady=(theme.PAD, 0))
        self.progress = ttk.Label(self.form_box, text='', style='Form.TLabel', wraplength=wrap,
                                  justify='left')
        self.progress.pack(anchor='w', pady=(4, 0))

        # ---- 4 done
        self.done_box = ttk.Frame(frame)
        self._title(self.done_box, '4  Done')
        self.done_text = tk.Label(self.done_box, text='', font=theme.FONT_FORM_BOLD, anchor='w',
                                  justify='left', wraplength=wrap, padx=10, pady=6,
                                  background=theme.BG)
        self.done_text.pack(fill='x')
        bar = ttk.Frame(self.done_box)
        bar.pack(anchor='w', pady=(theme.PAD, 0))
        self.scan_btn = ttk.Button(bar, text='Use in Scan page', style='Accent.TButton',
                                   command=self.use_in_scan)
        self.scan_btn.pack(side='left')
        self.test_btn = ttk.Button(bar, text='Test SSH login', command=self.test_login)
        self.test_btn.pack(side='left', padx=theme.PAD)
        self.test_text = ttk.Label(self.done_box, text='', wraplength=wrap, justify='left',
                                   style='Form.TLabel')
        self.test_text.pack(anchor='w', pady=(4, 0))
        self.done = None                      # (ip, username) of a finished setup

        # before Connect: steps 2 and 3 are shown with what will happen there
        self.wait_box = ttk.Frame(frame)
        self._title(self.wait_box, '3  Set up SSH')
        ttk.Label(self.wait_box, text='This form appears after the device is read (click '
                                      'Connect in step 1).', foreground=theme.TEXT_MUTED,
                  style='Form.TLabel').pack(anchor='w')
        self.waiting()

    WAITING_TEXT = ('Not connected yet. Click Connect in step 1: the device is read '
                    'automatically and shown here.')

    def waiting(self):
        """Steps 2 and 3 as they look before a device is read."""
        for box in (self.form_box, self.done_box):
            box.pack_forget()
        self.device_text.configure(text=self.WAITING_TEXT, background=theme.SURFACE_2,
                                   foreground=theme.TEXT_SOFT)
        self.device_detail.configure(text='')
        if not self.device_box.winfo_manager():
            self.device_box.pack(fill='x')
        if not self.wait_box.winfo_manager():
            self.wait_box.pack(fill='x', after=self.device_box)

    @staticmethod
    def _title(parent, text):
        ttk.Separator(parent).pack(fill='x', pady=(theme.PAD * 1.5, theme.PAD))
        ttk.Label(parent, text=text, font=theme.font(12, 'bold')).pack(anchor='w',
                                                                       pady=(0, theme.PAD))

    # ------------------------------------------------------------ 1  connect
    def connect(self):
        """Connect, then detect by itself. Privileged mode is used (ticked for you): a new
        device has no enable password, so only "enable" is sent; a typed enable password is
        used when given."""
        self.tab.use_enable.set(1)
        self.tab._apply_state()
        self.tab.quick_flow = True
        self.secret = None
        self.waiting()
        self.tab.connect()

    def update_state(self):
        """Mirror the page state on the Set up SSH button."""
        tab = self.tab
        self.setup_btn.state(['!disabled'] if tab.phase == 'detected' and tab.result is not None
                             and tab.result_live else ['disabled'])
        if tab.session is None and tab.phase in ('disconnected', 'error'):
            if tab.phase == 'disconnected':
                self.secret = None
            if not self.done_box.winfo_manager():        # nothing finished: start over
                self.waiting()

    # ------------------------------------------------------------ 2  detected
    def detected(self):
        r = self.tab.result
        if r is None:
            return
        ok = self.show_device(r)
        if not ok:
            self.form_box.pack_forget()
            self.wait_box.pack_forget()
            return
        self._fill_form(r)
        self.wait_box.pack_forget()
        self.form_box.pack(fill='x', after=self.device_box)

    def show_device(self, r):
        """Section 2: what the device is, and what SSH still needs. True when SSH can be
        set up on it."""
        d = r.device
        kind = TYPE_WORDS.get(d.device_type, 'device')
        model = d.model or 'Cisco device'
        ok = r.ssh.status in (SshCapability.SUPPORTED_ENABLED, SshCapability.SUPPORTED_DISABLED)
        if ok:
            self.device_text.configure(
                text=f'✓  {model} {kind} "{d.hostname or "?"}" (IOS {d.version or "?"}) - SSH can '
                     f'be set up on it.', background=theme.SUCCESS_SOFT, foreground=theme.SUCCESS)
        else:
            why = {SshCapability.UNSUPPORTED: 'its software has no SSH (a non-crypto image)',
                   SshCapability.UNKNOWN: 'NetCommand could not tell whether it supports SSH'}
            self.device_text.configure(
                text=f'✗  {model} {kind} "{d.hostname or "?"}": SSH cannot be set up here - '
                     f'{why.get(r.ssh.status, "not supported")}.',
                background=theme.DANGER_SOFT, foreground=theme.DANGER)
        rows = self.tab_checklist()
        done = [CHECK_WORDS.get(what, what) for what, state, _d in rows if state == 'OK']
        todo = [CHECK_WORDS.get(what, what) for what, state, _d in rows if state != 'OK']
        self.device_detail.configure(text=('Already there: ' + ', '.join(done) + '.\n'
                                           if done else '') +
                                     ('Still needed: ' + ', '.join(todo) + '.' if todo else
                                      'Everything SSH needs is already there.'))
        if not self.device_box.winfo_manager():
            if self.form_box.winfo_manager():
                self.device_box.pack(fill='x', before=self.form_box)
            else:
                self.device_box.pack(fill='x')
        return ok

    def tab_checklist(self):
        from console.plan import ssh_checklist
        return ssh_checklist(self.tab.result)

    def _fill_form(self, r):
        v = self.vars
        host = r.device.hostname
        v['hostname'].set('' if host in DEFAULT_HOSTNAMES or not host else host)
        v['domain'].set(r.config.domain_name or DEFAULT_DOMAIN)
        admins = existing_admins(r)
        v['username'].set(admins[0] if admins else 'admin')
        v['password'].set('')
        v['again'].set('')
        self.user_note.configure(text=(
            f'"{admins[0]}" already exists on the device: the password you type here becomes '
            f'its new password. Type another username to create a new user instead.'
            if admins else 'This user is created on the device, with full rights (privilege 15).'))
        # the management port: a router's first Ethernet port (one that already has an
        # address or is up first), a switch's Vlan1
        tab = self.tab
        tab._fill_interfaces()
        names = list(getattr(tab, '_mgmt_names', {}).items())        # (shown, name)
        self.iface_box.configure(values=[shown for shown, _n in names])
        rows = {i.name: i for i in r.interfaces}

        def rank(item):
            row = rows.get(item[1])
            return (not (row and row.name.lower() == 'vlan1'), not (row and row.ip),
                    not (row and row.status == 'up'))
        best = sorted(names, key=rank)[0] if names else None
        v['interface'].set(best[0] if best else '')
        current = rows.get(best[1]) if best else None
        v['ip'].set(current.ip if current and current.ip else '')
        v['mask'].set(DEFAULT_MASK)
        v['gateway'].set(r.config.default_gateway or '')
        self.mgmt_note.configure(text='Your PC needs an address in the same network to reach '
                                      'it (for example 192.168.1.10 / 255.255.255.0) and a cable '
                                      'to this port.')
        self.error.configure(text='')
        self.progress.configure(text='')

    # ------------------------------------------------------------ 3  set up
    def set_up(self):
        tab, v = self.tab, self.vars
        r = tab.result
        if r is None or not tab.result_live or tab.phase != 'detected':
            self.error.configure(text='Connect to the device first.')
            return
        password, again = v['password'].get(), v['again'].get()
        username = v['username'].get().strip()
        if not v['ip'].get().strip():
            self.error.configure(text='•  Type the management IP address (for example '
                                      '192.168.1.1): it is the Seed IP the Scan page needs.')
            return
        interface = tab._mgmt_names.get(v['interface'].get(), v['interface'].get()) \
            if hasattr(tab, '_mgmt_names') else v['interface'].get()
        exists = account_exists(r, username)
        request, errors = validate_request(
            v['hostname'].get(), v['domain'].get() if not r.config.domain_name else '',
            username, password, again, 2048, r, mgmt_interface=interface,
            mgmt_ip=v['ip'].get(), mgmt_mask=v['mask'].get(), gateway=v['gateway'].get(),
            save=True, change_password=exists)
        if not password:
            errors.setdefault('password', 'Type the SSH password (8-25 characters), twice.')
        if errors:
            self.error.configure(text='\n'.join(f'•  {e}' for e in errors.values()))
            return
        if not request.mgmt_ip:
            self.error.configure(text='•  Type the management IP address: it is the Seed IP the '
                                      'Scan page needs.')
            return
        plan = build_plan(r, request)
        if not plan.available:
            self.error.configure(text=f'•  SSH cannot be set up on this device: {plan.reason}')
            return
        self.error.configure(text='')
        host = request.hostname or r.device.hostname
        lines = [f'   {n}. {plain_step(s)}' for n, s in enumerate(plan.steps, 1)]
        if exists:
            lines.insert(0, f'   •  "{username}" already exists: its password will be REPLACED '
                            f'with the one you typed.')
        from gui.components.dialogs import confirm
        if not confirm('Set up SSH', f'Set up SSH on {host} through the console cable?\n\n'
                                     f'NetCommand will:\n' + '\n'.join(lines) +
                       f'\n\nAfterwards you can scan it at {request.mgmt_ip} as "{username}". '
                       f'Keep the console cable plugged in until it says Done.',
                       'Set up SSH', parent=tab, details='\n'.join(plan.lines()),
                       log=('setup', f'Quick SSH setup on {host}')):
            return
        self.secret = password
        v['password'].set('')
        v['again'].set('')
        self.done = (request.mgmt_ip, username, host)
        self.steps_total = len(plan.steps)
        tab._show_plan(plan, request)                # the detailed view shows the same plan
        tab.apply_vars['password'].set(password)
        tab.apply_vars['confirm'].set(password)
        from console import apply as ssh_apply
        tab.apply_vars['phrase'].set(ssh_apply.confirmation_phrase(plan))
        for var in tab.approval_vars.values():        # approved in the dialog above
            var.set(1)
        tab.skip_apply_confirm = True
        try:
            tab.apply_ssh()
        finally:
            tab.skip_apply_confirm = False
        password = again = None

    def step_progress(self, step_id, status):
        """A row of the step table changed: one line of progress."""
        if self.tab.phase != 'applying' or not self.tab.plan:
            return
        ids = [s.step_id for s in self.tab.plan.steps]
        if step_id in ids and status == 'running':
            step = self.tab.plan.steps[ids.index(step_id)]
            self.progress.configure(text=f'Step {ids.index(step_id) + 1} of {len(ids)}: '
                                         f'{plain_step(step)}...', foreground=theme.TEXT)

    # ------------------------------------------------------------ 4  done
    def applied(self, res, error_text=None):
        from console import apply as ssh_apply
        ok = res is not None and res.outcome == ssh_apply.SUCCESS
        ip, username, host = self.done or ('', '', '')
        if ok:
            self.progress.configure(text='')
            if res.final_detection is not None:
                self.show_device(res.final_detection)        # now: what the device has
            self.done_text.configure(
                text=f'✓  SSH is ready on {host}.\n\nTo scan it on the Scan page use:\n'
                     f'    Seed IP:   {ip}\n    Username:  {username}\n'
                     f'    Password:  the SSH password you typed\n\n'
                     f'Click "Use in Scan page" to fill these in for you.',
                background=theme.SUCCESS_SOFT, foreground=theme.SUCCESS)
            self.scan_btn.state(['!disabled'])
            self.test_btn.state(['!disabled'])
        else:
            failed = next((s for s in (res.steps if res else []) if s.status in (
                'failed', 'uncertain')), None)
            why = error_text or (('; '.join(failed.reasons) if failed else '') or
                                 (res.message if res else 'it stopped unexpectedly'))
            step = f' at "{plain_step(failed)}"' if failed else ''
            self.done_text.configure(
                text=f'✗  The setup stopped{step}:\n{why}\n\nNothing after that step was sent. '
                     f'Fix the problem and click "Set up SSH" again (open "Advanced" below for '
                     f'every detail).', background=theme.DANGER_SOFT, foreground=theme.DANGER)
            self.scan_btn.state(['disabled'])
            self.test_btn.state(['disabled'])
            self.secret = None
        self.test_text.configure(text='')
        self.done_box.pack(fill='x', after=self.form_box)

    def use_in_scan(self):
        if not self.done:
            return
        ip, username, _host = self.done
        tab = self.tab
        if tab.on_use_in_scan is None:
            return
        password, self.secret = self.secret, None
        if tab.session is not None and tab.phase in ('connected', 'detected'):
            tab._start_disconnect('Disconnected: the console cable can be unplugged.')
        tab.on_use_in_scan(ip, username, password or '')

    def test_login(self):
        if not self.done or not self.secret:
            self.test_text.configure(text='The password is no longer kept: use the Scan page.')
            return
        ip, username, _host = self.done
        tab = self.tab
        tab.ssh_test_target_ip = ip
        tab.ssh_test_user.set(username)
        tab.ssh_test_pw.set(self.secret)
        self.test_text.configure(text=f'Testing an SSH login to {ip}...')
        tab.test_ssh()

    def tested(self, ok, text):
        self.test_text.configure(text=('✓  ' if ok else '✗  ') + text,
                                 foreground=theme.SUCCESS if ok else theme.DANGER)
