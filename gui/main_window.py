"""The main window: the Network Engineering Workbench.

    +----------------------------------------------------------------+
    | NC | NetCommand        [ command strip: find / operate ]  data |  header
    +----+-----------------------------------------+-----------------+
    |    |  page area (the selected page)          |  inspector      |  drag the
    | r  |                                         |                 |  dividers
    | a  +-----------------------------------------+-----------------+  to resize
    | i  |  operations console: Console | Config log                 |
    | l  |                                                           |
    +----+-----------------------------------------------------------+
    | status bar                                                      |
    +----------------------------------------------------------------+

All pages are created once at startup and only hidden or shown, so nothing a
page holds (scan results, a command preview) is lost when you switch.
"""
import os
import tkinter as tk
from tkinter import ttk

import customtkinter as ctk

import services
from gui import theme, ui_scale, window_state
from gui.auth_window import mask_email
from gui.event_log import event_word, install_dialog_logging, log_event
from gui.components.command_strip import CommandStrip
from gui.components.console import OperationsConsole
from gui.components.inspector import Inspector
from gui.components.rail import COMPACT_BELOW_HEIGHT, Rail
from gui.configure_tab import ConfigureTab
from gui.db_status import DatabaseStatus, report_error
from gui.device_login_guard import DeviceLoginGuard
from gui.devices_tab import DevicesTab
from gui.findings_tab import FindingsTab
from gui.guide import CHECKLIST_HIDDEN, TOPOLOGY_VIEWED, Guide
from gui.logs_tab import LogsTab
from gui.overview_page import OverviewPage
from gui.scan_tab import ScanTab
from gui.setup_tab import SetupTab
from gui.topology_tab import TopologyTab
from desktop_auth.session import CONFIGURE, EDIT_DEVICES, MANAGE_ACCOUNTS, RUN_REVIEW
from store_errors import DatabaseError

# (key, rail label) in rail order. 'dashboard' is the Overview workspace.
# 'setup' is the Initial Setup page (console connection); "Setup" fits the narrow rail.
PAGES = [('dashboard', 'Overview'), ('scan', 'Scan'), ('devices', 'Devices'),
         ('topology', 'Topology'), ('findings', 'Findings'), ('configure', 'Configure'),
         ('setup', 'Setup'), ('logs', 'Logs')]
FIRST_PAGE = 'dashboard'
# Layout by window size (logical pixels: after Windows scaling)
INSPECTOR_AUTO_HIDE_BELOW = 1400   # narrower: the inspector hides itself ('Show inspector')
CONSOLE_SHARE = 0.25               # the bottom panel's first height: a quarter of the window
CONSOLE_SHARE_COMPACT = 0.18       # on Configure, which has its own SSH session
CONSOLE_MIN_HEIGHT = 90            # design pixels: never smaller than this
CONSOLE_MAX_SHARE = 0.65           # nor taller than this share of the window
LAYOUT_HYSTERESIS = 60             # logical pixels between switching a layout off and on again
RESIZE_SETTLE_MS = 250             # layout changes wait until the window edge stops moving

# Set to 1 only by the mock lab launcher (mock-lab/run_netcommand.py). DISPLAY ONLY: it adds
# this label to the title and the status bar and changes nothing else.
MOCK_LAB_VARIABLE = 'NETCOMMAND_MOCK_LAB'
MOCK_LAB_TEXT = 'MOCK LAB — simulated devices'


def mock_lab_label(environ=None):
    """MOCK_LAB_TEXT when the mock lab launcher started this window, else ''."""
    return MOCK_LAB_TEXT if (os.environ if environ is None else environ).get(
        MOCK_LAB_VARIABLE) == '1' else ''


def _scaling(widget):
    """How much CustomTkinter enlarges sizes on this display (1.0 = 100%)."""
    try:
        return ctk.ScalingTracker.get_widget_scaling(widget)
    except Exception:
        return 1.0


SOURCE_CONNECTED = '●  database connected'
SOURCE_UNAVAILABLE = '●  database unavailable'
SOURCE_SAMPLE = '●  sample mode · in memory'
SOURCE_FALLBACK = '●  sample mode · database unavailable at startup'


DEV_LOCK_RESET_TEXT = 'DEV: lock reset on restart'


def add_tooltips(refs):
    """Short hover texts (gui/guide_content.TOOLTIPS) on the buttons and fields whose
    meaning is not obvious. Pages that are not built for this role are skipped."""
    from gui.components.tooltip import tip
    tip(refs.get('help_button'), 'help')
    scan = refs.get('scan')
    if scan is not None:
        tip(scan.entries.get('Seed IP'), 'seed_ip')
        for box, key in zip(scan.option_boxes, ('demo_scan', 'save_login', 'neighbours')):
            tip(box, key)
        tip(scan.approve_btn, 'approve')
    devices = refs.get('devices')
    if devices is not None:
        tip(devices.backups_btn, 'backups')
    conf = refs.get('configure')
    if conf is not None:
        tip(conf.apply_btn, 'apply')
        tip(conf.clear_form_btn, 'clear_form')
        for editor, labels in ((conf.trunk_editor, {'Native VLAN': 'native_vlan',
                                                    'encapsulation dot1q': 'dot1q'}),
                               (conf.security_editor, {'Learn MACs (sticky)': 'sticky',
                                                       'Max MAC addresses': 'max_mac',
                                                       'On violation': 'violation'})):
            for widget in _labelled(editor):
                key = labels.get(str(widget.cget('text')).strip())
                if key:
                    tip(widget, key)
    findings = refs.get('findings')
    if findings is not None:
        tip(findings.run_btn, 'run_review')
        tip(findings.send_btn, 'send_to_configure')
    accounts = refs.get('accounts')
    if accounts is not None:
        tip(getattr(accounts, 'role_box', None), 'approve_as')


def _labelled(widget):
    """Every label and check box under widget (their text names the field)."""
    out, stack = [], [widget]
    while stack:
        w = stack.pop()
        stack.extend(w.winfo_children())
        if w.winfo_class() in ('TLabel', 'TCheckbutton'):
            out.append(w)
    return out


def build_main_window(root, store, demo_store=False, startup_problem=None, access=None,
                      account=None, console_backend=None, dev_lock_reset=False):
    """Builds the workbench and every page. Returns refs: one entry per page key,
    plus 'nav', 'command', 'inspector', 'console', 'show_page', 'current_page', and in
    database mode 'db_status' (gui.db_status.DatabaseStatus).
    startup_problem: why the database could not be used at startup, when the app fell
    back to sample mode (shown, so the fallback is never mistaken for the database).
    access: desktop_auth.session.Access of the signed-in user (None: everything, as
    before sign-in existed). Pages and buttons the role may not use are not offered.
    account: gui.session_watch.SignedInContext (sign-out, and the Accounts page for
    admins); None in demo mode.
    console_backend: where the Initial Setup page gets serial ports and console sessions;
    None = the computer's real COM ports (the simulated one only with --mock-console)."""
    theme.apply(root)
    root.grid_columnconfigure(1, weight=1)
    root.grid_rowconfigure(2, weight=1)
    refs, state = {}, {'current': None}
    refs['access'] = access

    def allowed(key):
        return access is None or access.can_open(key)

    pages = [(key, label) for key, label in PAGES if allowed(key)]
    if account is not None and access is not None and access.can(MANAGE_ACCOUNTS):
        pages.append(('accounts', 'Accounts'))
    all_pages = PAGES + [p for p in pages if p not in PAGES]

    # ---------------------------------------------------------------- header
    header = ctk.CTkFrame(root, fg_color=theme.SURFACE, corner_radius=0, height=48)
    header.grid(row=0, column=0, columnspan=2, sticky='ew')
    header.grid_columnconfigure(2, weight=1)
    brand = ctk.CTkFrame(header, fg_color=theme.RAIL_BG, corner_radius=0,
                         width=theme.RAIL_WIDTH, height=48)
    brand.grid(row=0, column=0, sticky='ns')
    brand.grid_propagate(False)
    brand.grid_columnconfigure(0, weight=1)
    brand.grid_rowconfigure(0, weight=1)
    ctk.CTkLabel(brand, text='NC', font=theme.mono(12, 'bold'), text_color=theme.WHITE).grid(
        row=0, column=0)
    names = ctk.CTkFrame(header, fg_color=theme.SURFACE, corner_radius=0)
    names.grid(row=0, column=1, padx=(12, 20), sticky='w')
    ctk.CTkLabel(names, text='NetCommand', font=theme.FONT_BRAND, text_color=theme.TEXT,
                 height=18, anchor='w').grid(row=0, column=0, sticky='w')
    ctk.CTkLabel(names, text='network engineering workbench', font=theme.mono(8), height=14,
                 text_color=theme.TEXT_MUTED, anchor='w').grid(row=1, column=0, sticky='w')

    source_text = (SOURCE_CONNECTED if not demo_store else
                   SOURCE_FALLBACK if startup_problem else SOURCE_SAMPLE)
    refs['source_label'] = ctk.CTkLabel(
        header, text=source_text, font=theme.mono(9),
        text_color=theme.WARNING if demo_store else theme.SUCCESS)
    refs['source_label'].grid(row=0, column=3, padx=14)
    if access is not None and access.demo:
        refs['demo_label'] = ctk.CTkLabel(header, text='DEMO MODE · not signed in',
                                          font=theme.mono(10, 'bold'), text_color=theme.DANGER)
        refs['demo_label'].grid(row=0, column=4, padx=(0, 14))
    elif account is not None:
        who = ctk.CTkFrame(header, fg_color=theme.SURFACE, corner_radius=0)
        who.grid(row=0, column=4, padx=(0, 10))
        refs['user_label'] = ctk.CTkLabel(
            # shown masked; the full address stays in the session for the server calls
            who, text=f'{mask_email(account.session.email)} · {access.title}', font=theme.mono(9),
            text_color=theme.TEXT_SOFT)
        refs['user_label'].pack(side='left', padx=(0, 8))
        refs['sign_out_button'] = ctk.CTkButton(
            who, text='Sign out', font=theme.mono(9), height=24, width=80, corner_radius=3,
            fg_color=theme.SURFACE_2, hover_color=theme.BORDER, text_color=theme.TEXT,
            command=account.on_sign_out)
        refs['sign_out_button'].pack(side='left')
    if dev_lock_reset:          # TESTING MODE is on: a reminder to turn it off before release
        refs['dev_label'] = ctk.CTkLabel(header, text=DEV_LOCK_RESET_TEXT,
                                         font=theme.mono(9, 'bold'), text_color=theme.WARNING)
        refs['dev_label'].grid(row=0, column=5, padx=(0, 12))
    # ? Help: restart the tour, help for this page, keyboard shortcuts (gui/guide.py)
    refs['help_button'] = ctk.CTkButton(
        header, text='?', font=theme.mono(11, 'bold'), height=26, width=30, corner_radius=13,
        fg_color=theme.SURFACE_2, hover_color=theme.BORDER, text_color=theme.ACCENT,
        command=lambda: refs['guide'].menu(refs['help_button']))
    refs['help_button'].grid(row=0, column=6, padx=(0, 12))
    ctk.CTkFrame(root, height=1, corner_radius=0, fg_color=theme.BORDER).grid(
        row=1, column=0, columnspan=2, sticky='ew')

    # ---------------------------------------------------------------- workbench panels
    outer = ttk.PanedWindow(root, orient='vertical', style='Workbench.TPanedwindow')
    outer.grid(row=2, column=1, sticky='nsew')
    upper = ttk.PanedWindow(outer, orient='horizontal', style='Workbench.TPanedwindow')

    page_area = tk.Frame(upper, background=theme.SURFACE)
    if demo_store and startup_problem:
        ttk.Label(page_area, style='Sample.TLabel', padding=(12, 5), wraplength=900,
                  justify='left',
                  text=f'SAMPLE MODE: the database could not be used at startup. '
                       f'{startup_problem} Data is kept in memory and lost on exit. '
                       f'Restart NetCommand once the database is available.').pack(fill='x')
    elif demo_store:
        ttk.Label(page_area, style='Sample.TLabel', padding=(12, 5),
                  text='No database connected: data is kept in memory and lost on exit '
                       '(sample mode).').pack(fill='x')
    # Shown only while the database is unavailable at runtime (never in sample mode).
    outage_bar = tk.Frame(page_area, background=theme.DANGER_SOFT)
    refs['outage_text'] = ttk.Label(outage_bar, text='', wraplength=760, justify='left',
                                    background=theme.DANGER_SOFT, foreground=theme.DANGER,
                                    padding=(12, 5))
    refs['outage_text'].pack(side='left', fill='x', expand=True)
    refs['retry_button'] = ttk.Button(outage_bar, text='Retry now',
                                      command=lambda: refs['db_status'].check_now())
    refs['retry_button'].pack(side='right', padx=8, pady=4)
    refs['outage_bar'] = outage_bar
    host = tk.Frame(page_area, background=theme.SURFACE)
    host.pack(fill='both', expand=True, padx=12, pady=10)
    host.grid_columnconfigure(0, weight=1)
    host.grid_rowconfigure(0, weight=1)

    console = OperationsConsole(outer, store)      # log_event(...) writes here from now on
    refs['console'] = console
    install_dialog_logging()                       # error/warning dialogs are logged too

    # ---------------------------------------------------------------- database status
    # Database mode only. A runtime outage NEVER switches to sample mode: the pages show
    # 'unavailable' instead of their (now unverifiable) data, saving is blocked, and the
    # connection is re-checked in the background. Recovery refreshes the pages; nothing
    # that failed is repeated.
    def on_db_down(reason):
        refs['source_label'].configure(text=SOURCE_UNAVAILABLE, text_color=theme.DANGER)
        refs['outage_text'].config(
            text=f'{reason} Nothing can be saved until the connection is back; the lists are '
                 f'hidden rather than shown out of date. NetCommand retries automatically.')
        if not outage_bar.winfo_manager():
            outage_bar.pack(fill='x', before=host)
        for key in ('devices', 'logs', 'configure', 'topology'):
            if key in refs:
                refs[key].show_unavailable(reason)
        if 'inspector' in refs:
            insp = refs['inspector']
            device_id = insp.device['id'] if insp.device else (
                insp.selection[1] if insp.selection and insp.selection[0] == 'device' else None)
            insp.show_unavailable(device_id)
        if 'status_devices' in refs:
            refs['status_devices'].configure(text='device count unavailable')
        console.show_unavailable()                     # config log and status events
        if 'findings' in refs:                         # kept on screen, marked not refreshed
            refs['findings'].on_db_down(reason)
        if 'dashboard' in refs:
            refs['dashboard'].on_db_down(reason)

    def on_db_up():
        refs['source_label'].configure(text=SOURCE_CONNECTED, text_color=theme.SUCCESS)
        outage_bar.pack_forget()
        refs['devices'].refresh()
        refs['logs'].refresh()
        refs['configure'].refresh_devices()
        if state['current'] == 'topology':      # other pages: refreshed when shown
            refs['topology'].refresh()
        insp = refs['inspector']
        if insp.selection and insp.selection[0] == 'device' and insp.selection[1] is not None:
            insp.show_device(insp.selection[1])
        update_status()
        console.refresh_current()                      # the stored-data tab shown, if any
        refs['findings'].on_db_up()
        refs['dashboard'].on_db_up()

    if not demo_store:
        refs['db_status'] = DatabaseStatus(root, store, on_down=on_db_down, on_up=on_db_up,
                                           log=log_event)
        default_handler = root.report_callback_exception

        def on_callback_error(exc, val, tb):
            """A database error that a screen did not handle itself: show the outage
            (or the failed request) instead of a raw traceback. Anything else: as before."""
            if report_error(root, val):
                if isinstance(val, DatabaseError):
                    from tkinter import messagebox
                    messagebox.showerror('Database error', str(val))
                return
            default_handler(exc, val, tb)

        root.report_callback_exception = on_callback_error

    # ---------------------------------------------------------------- the same page wiring as before
    def get_network():
        # Real database mode never falls back to the sample network on the map.
        return services.get_network(store, allow_sample=demo_store)

    def overview_stale():
        if 'dashboard' in refs:                        # the Overview reloads (now or when shown)
            refs['dashboard'].mark_stale()

    def after_data_change():
        refs['devices'].refresh()
        refs['configure'].refresh_devices()
        update_status()
        overview_stale()
        if refs['inspector'].device:                   # keep the inspector up to date
            refs['inspector'].show_device(refs['inspector'].device['id'])

    def after_approval():
        """The Scan page saved devices (completely or partly): refresh, then log the result."""
        after_data_change()
        result = refs['scan'].last_result or {}
        if result.get('ok'):
            noun = 'device' if result['total'] == 1 else 'devices'
            log_event('scan', f"Approved {result['total']} {noun}: {result['added']} new, "
                              f"{result['updated']} already registered (updated), "
                              f"{result['links']} links saved.", 'ok', tags=['change'])
        elif result:
            log_event('scan', f"Approval FAILED after {result['saved']} of {result['total']} "
                              f"devices: {result['error']}", 'error')

    def send_to_configure(commands, device_name):
        if not allowed('configure'):
            refuse('configure')
            return
        refs['configure'].load_commands(commands, device_name)
        show_page('configure')
        log_event('findings', f'Sent {len(commands)} suggested lines for {device_name} to '
                              f'Configure: SUCCESSFUL.', 'ok')

    refs['devices'] = DevicesTab(host, store, on_change=after_data_change)
    refs['configure'] = ConfigureTab(host, store, log=log_event, on_change=after_data_change,
                                     on_applied=overview_stale)
    refs['scan'] = ScanTab(host, store, services.run_discovery,
                           on_approved=after_approval, demo_default=demo_store,
                           sample_store=demo_store)
    refs['scan'].on_activity = overview_stale
    # Failed device logins count against the signed-in account on the server (a lock
    # signs it out). Without an account (the --demo start) nothing is reported.
    refs['device_guard'] = DeviceLoginGuard(account)
    refs['scan'].device_guard = refs['device_guard']
    refs['configure'].device_guard = refs['device_guard']
    def on_map_select(kind, info):
        """A device or link was clicked on the interactive map: show it in the inspector.
        Registered devices are read from the store; anything without a record (sample
        data, an unregistered neighbour) is shown from the map data, clearly marked."""
        insp = refs['inspector']
        if kind is None:
            insp.clear()
            return
        set_inspector(True)                     # something to inspect: make sure it is visible
        sample_note = 'SAMPLE DATA: example network, not registered in your database.'
        if kind == 'device':
            extra = [('Topology', 'single point of failure', False)] if info['spof'] else []
            record = info['record']
            if record and record.get('id') is not None and not info['sample']:
                insp.show_device(record['id'], extra_rows=extra)
            else:
                rows = [('IP address', info['ip'], True), ('Type', info['type'], False),
                        ('Managed', 'yes' if info['managed'] else 'no', False)] + extra
                note = sample_note if info['sample'] else \
                    'Seen as a neighbour but not registered in your database.'
                insp.show_details(info['name'], info['status'], rows, note=note)
        else:
            insp.show_link(info['a'], info['b'], info['ports_a'], info['ports_b'],
                           info['info_a'], info['info_b'],
                           note=sample_note if info['sample'] else None)

    # Saved map layouts are kept per data source; the database one is named after the
    # database (no credentials), the sample one simply 'sample'.
    layout_scope = 'sample' if demo_store else \
        f"database:{os.getenv('DB_NAME', 'netcommand')}@{os.getenv('DB_HOST', 'localhost')}"
    refs['topology'] = TopologyTab(host, get_network, on_select=on_map_select,
                                   layout_scope=layout_scope, log=log_event)
    refs['findings'] = FindingsTab(host, store, lambda: services.collect_review_inputs(store, demo_store),
                                   send_to_configure, sample_store=demo_store)
    refs['findings'].on_saved = overview_stale
    # Activity history: admins see everyone's; other roles only their own lines and the
    # automatic ('system') ones. (Enforced by this app: see the Logs page notes.)
    if access is not None and not access.demo and not access.can(MANAGE_ACCOUNTS):
        from gui import event_log as _ev
        scope = lambda: (_ev.current_user(), _ev.SYSTEM)       # noqa: E731
    else:
        scope = None
    refs['logs'] = LogsTab(host, store, scope_users=scope)
    if allowed('setup'):                    # not even built for roles that may not use it
        refs['setup'] = SetupTab(host, log=log_event, backend=console_backend, store=store,
                                 on_registered=lambda: after_data_change())

        def use_in_scan(ip, username, password):
            """The Initial Setup page finished: fill in the Scan page and open it."""
            scan = refs['scan']
            scan.demo.set(0)
            scan.seed.set(ip)
            scan.user.set(username)
            scan.pw.set(password)
            log_event('setup', f'Scan page filled in: Seed IP {ip}, username {username} '
                               f'(password typed in Initial Setup).')
            show_page('scan')
        refs['setup'].on_use_in_scan = use_in_scan if allowed('scan') else None
    # the new-user guide (tour, help) for this user: their server account id, else 'demo'
    user_key = getattr(getattr(account, 'session', None), 'user_id', None) or 'demo'
    refs['guide'] = Guide(root, refs, store, user_key)
    refs['dashboard'] = OverviewPage(
        host, lambda key: show_page(key), store=store, can_open=allowed,
        scan_history=lambda: refs['scan'].history,
        last_review=lambda: refs['findings'].last_review,
        source_note='Sample mode: the data is kept in memory.' if demo_store else '',
        checklist_flags=lambda: {'topology': refs['guide'].flag(TOPOLOGY_VIEWED),
                                 'hidden': refs['guide'].flag(CHECKLIST_HIDDEN)},
        on_hide_checklist=lambda: refs['guide'].set(CHECKLIST_HIDDEN))
    refs['devices'].on_go_scan = (lambda: show_page('scan')) if allowed('scan') else None
    if access is not None:
        refs['devices'].set_read_only(not access.can(EDIT_DEVICES))
        refs['findings'].set_read_only(not access.can(RUN_REVIEW))
    # Backup catalogue (Phase 4B): the same permission as Configure. A selection is only
    # remembered for a future restore workflow; nothing is sent to any device.
    refs['devices'].set_backups_allowed(access is None or access.can(CONFIGURE))
    refs['backup_selection'] = None

    def backup_selected(selection):
        refs['backup_selection'] = selection
        log_event('backups', f'Selected backup {os.path.basename(selection.path)} for a '
                             f'future restore of {selection.device_name or selection.device_ip}'
                             f' (nothing was sent to the device).')
    refs['devices'].on_backup_selected = backup_selected

    def outcome_level(status):
        """A restore / save result's status as a console level."""
        status = str(status or '').upper()
        return 'ok' if status in ('SUCCESS', 'SUCCESSFUL', 'PASS') else \
            'error' if status in ('FAILED', 'FAIL', 'ERROR') else 'warn'

    def restore_finished(result):
        level = outcome_level(result.status)
        log_event('backups', f'Restore of {result.device_ip} {event_word(level)} '
                             f'({result.status}; backup '
                             f'{os.path.basename(result.backup_file or "?")}, safety backup '
                             f'{result.safety_backup_file or "none"}).', level,
                  tags=['change'] if level == 'ok' else None, device=result.device_ip,
                  ip=result.device_ip)       # a restore (rollback) changes the device
    refs['devices'].on_restore_finished = restore_finished

    def save_finished(result):
        level = outcome_level(result.status)
        log_event('backups', f'Save to startup on {result.device_ip} {event_word(level)} '
                             f'({result.status}; startup backup '
                             f'{result.startup_backup or "none"}).', level,
                  tags=['change'] if level == 'ok' else None, device=result.device_ip,
                  ip=result.device_ip)
    refs['devices'].on_save_finished = save_finished
    if any(key == 'accounts' for key, _label in pages):
        from gui.accounts_page import AccountsPage
        refs['accounts'] = AccountsPage(host, account)

    # ---------------------------------------------------------------- inspector and command strip
    def select_for_configure(name):
        """Select only this device on the Configure page (managed devices only)."""
        conf = refs['configure']
        conf.refresh_devices()
        if not conf.select_device(name):
            log_event('configure', f'{name} is not a managed device, so it cannot be configured.',
                      'warn')
            return False
        return True

    def open_in_devices(name):
        show_page('devices')
        refs['devices'].search.set(name)
        refs['devices'].go_first()

    def configure_device(name):
        if not allowed('configure'):
            refuse('configure')
            return
        show_page('configure')
        select_for_configure(name)

    refs['inspector'] = Inspector(upper, store, on_open_devices=open_in_devices,
                                  on_configure=configure_device)
    # "Inspect SW1" on a link: select that device on the map
    refs['inspector'].on_focus_device = lambda name: refs['topology'].interactive.select_node(name)

    def on_device(device_id):
        set_inspector(True)
        d = refs['inspector'].show_device(device_id)
        if d:
            log_event('find', f"Selected {d['name']} ({d['ip']}).")

    def on_operation(key, device_name):
        if not allowed(key):
            refuse(key)
            return
        show_page(key)
        if key == 'configure' and device_name:
            select_for_configure(device_name)

    refs['command'] = CommandStrip(header, store, on_device, on_operation)
    refs['command'].grid(row=0, column=2, sticky='ew', padx=10, pady=9)

    upper.add(page_area, weight=1)
    upper.add(refs['inspector'], weight=0)
    outer.add(upper, weight=1)
    outer.add(console, weight=0)
    refs['panels'] = {'upper': upper, 'outer': outer}

    # ---------------------------------------------------------------- status bar
    status = ctk.CTkFrame(root, fg_color=theme.SURFACE_2, corner_radius=0, height=24)
    status.grid(row=3, column=0, columnspan=2, sticky='ew')
    ctk.CTkFrame(status, height=1, corner_radius=0, fg_color=theme.BORDER).pack(fill='x', side='top')
    refs['status_devices'] = ctk.CTkLabel(status, text='', font=theme.mono(8), height=20,
                                          text_color=theme.TEXT_SOFT)
    refs['status_devices'].pack(side='left', padx=(12, 0))
    if mock_lab_label():                   # display only: the mock lab launcher's label
        refs['status_mock_lab'] = ctk.CTkLabel(status, text=mock_lab_label(),
                                               font=theme.mono(8, 'bold'), height=20,
                                               text_color=theme.WARNING)
        refs['status_mock_lab'].pack(side='left', padx=(16, 0))
    ctk.CTkLabel(status, text='Ctrl+K  command strip', font=theme.mono(8), height=20,
                 text_color=theme.TEXT_SOFT).pack(side='right', padx=12)
    refs['inspector_toggle'] = ctk.CTkButton(
        status, text='Hide inspector', font=theme.mono(8), height=20, width=110,
        corner_radius=3, fg_color=theme.SURFACE_2, hover_color=theme.BORDER,
        text_color=theme.TEXT_SOFT, command=lambda: toggle_inspector())
    refs['inspector_toggle'].pack(side='right', padx=(0, 4))

    # ---------------------------------------------------------------- collapsible inspector
    # Each page remembers whether it shows the inspector; Configure starts without it
    # (it needs the width). Selecting something to inspect always brings it back.
    inspector_pref = {'configure': False, 'setup': False}
    # page -> console height (pixels) chosen there; kept between starts (window_state)
    console_size = dict(window_state.get_setting('console_heights', {}) or {})
    state['narrow'] = state['forced'] = False      # narrow window: inspector auto-hidden

    def inspector_shown():
        return str(refs['inspector']) in [str(p) for p in upper.panes()]

    def set_inspector(visible, remember=False):
        if remember or visible:
            if state['current']:
                inspector_pref[state['current']] = visible
        if visible and not inspector_shown():
            upper.add(refs['inspector'], weight=0)
            root.update_idletasks()
            width, wanted = upper.winfo_width(), theme.INSPECTOR_WIDTH   # already scaled
            if width > 2 * wanted:
                upper.sashpos(0, width - wanted)
        elif not visible and inspector_shown():
            upper.forget(refs['inspector'])
        refs['inspector_toggle'].configure(text='Hide inspector' if inspector_shown()
                                           else 'Show inspector')

    refs['inspector'].on_hide = lambda: set_inspector(False, remember=True)
    refs['set_inspector'] = set_inspector
    refs['inspector_shown'] = inspector_shown

    def console_limits(height):
        """(minimum, maximum) height of the bottom panel for a window area this tall."""
        low = ui_scale.space(CONSOLE_MIN_HEIGHT)
        return low, max(low, int(height * CONSOLE_MAX_SHARE))

    def remember_console(page):
        height = outer.winfo_height()
        if page and height > 200:
            console_size[page] = height - outer.sashpos(0)
            window_state.put_setting('console_heights', dict(console_size))

    def restore_console(page):
        """The bottom panel's height for this page: the one chosen there (also in an
        earlier session), else CONSOLE_SHARE of the window; never below the minimum."""
        height = outer.winfo_height()
        if height <= 200:
            return                                 # not laid out yet: place_dividers does it
        share = CONSOLE_SHARE_COMPACT if page == 'configure' else CONSOLE_SHARE
        low, high = console_limits(height)
        wanted = min(high, max(low, console_size.get(page, int(height * share))))
        outer.sashpos(0, height - wanted)

    def divider_released(_event=None):
        """After dragging the bottom panel's divider: keep it within its limits, and
        remember the size for this page."""
        height = outer.winfo_height()
        if height <= 200:
            return
        low, high = console_limits(height)
        console = height - outer.sashpos(0)
        if not low <= console <= high:
            outer.sashpos(0, height - min(high, max(low, console)))
        remember_console(state['current'])
    outer.bind('<ButtonRelease-1>', divider_released, add='+')

    def adapt_layout():
        """The window changed size: hide the inspector on a narrow window (the 'Show
        inspector' button still brings it back), and show the rail as icons only on a
        short one. Debounced, so dragging the window edge stays smooth."""
        state['adapt_job'] = None
        if 'nav' not in refs:
            return
        try:
            width, height = root.winfo_width(), root.winfo_height()
        except tk.TclError:
            return
        if width <= 1:
            return
        scale = ui_scale.dpi_scale()
        # a margin (LAYOUT_HYSTERESIS) between hiding and showing again, so dragging the edge
        # near the limit does not make the inspector or the rail labels flicker
        if state['narrow']:
            narrow = width / scale < INSPECTOR_AUTO_HIDE_BELOW + LAYOUT_HYSTERESIS
        else:
            narrow = width / scale < INSPECTOR_AUTO_HIDE_BELOW
        if narrow != state['narrow']:
            state['narrow'], state['forced'] = narrow, False
            if narrow:
                set_inspector(False)
            elif state['current']:
                set_inspector(inspector_pref.get(state['current'], True))
        limit = COMPACT_BELOW_HEIGHT + (LAYOUT_HYSTERESIS if refs['nav'].compact else 0)
        refs['nav'].set_compact(height / scale < limit)

    def window_resized(event):
        if event.widget is not root:
            return
        job = state.get('adapt_job')
        if job is not None:
            try:
                root.after_cancel(job)
            except tk.TclError:
                pass
        state['adapt_job'] = root.after(RESIZE_SETTLE_MS, adapt_layout)   # once dragging pauses
    root.bind('<Configure>', window_resized, add='+')
    refs['adapt_layout'] = adapt_layout

    def toggle_inspector():
        show = not inspector_shown()
        if show and state['narrow']:
            state['forced'] = True                 # asked for on a narrow window: keep it
        set_inspector(show, remember=True)

    def update_status():
        try:
            n = store.count_devices()
            text = f'{n} registered device' + ('' if n == 1 else 's')
        except Exception as err:
            report_error(root, err)
            text = 'device count unavailable'
        refs['status_devices'].configure(text=text)

    # ---------------------------------------------------------------- rail and page switching
    on_show = {'devices': lambda: refs['devices'].refresh(),
               'logs': lambda: refs['logs'].refresh(),
               'configure': lambda: refs['configure'].refresh_devices(),
               'topology': lambda: refs['topology'].refresh(),
               'findings': lambda: refs['findings'].on_page_shown(),
               'dashboard': lambda: refs['dashboard'].refresh(),
               'accounts': lambda: refs['accounts'].refresh(),
               'setup': lambda: refs['setup'].on_page_shown()}

    def refuse(key):
        label = dict(all_pages).get(key, key)
        log_event('access', f'Your role ({access.title}) cannot use {label}.', 'warn')

    def show_page(key):
        """Show one page, hide the others. Opening the page already shown does
        nothing, exactly like clicking the tab that was already open. A page the role
        may not use is refused (whatever asked for it: rail, command strip, inspector)."""
        if key == state['current']:
            return
        if not any(key == k for k, _label in pages):
            refuse(key)
            return
        if state['current'] == 'setup' and 'setup' in refs and \
                not refs['setup'].confirm_leave():
            refs['nav'].set_active('setup')            # stay: the console is still in use
            return
        remember_console(state['current'])
        for other, _label in all_pages:
            if other != key and other in refs:
                refs[other].grid_remove()
        refs[key].grid(row=0, column=0, sticky='nsew')
        refs['nav'].set_active(key)
        state['current'] = key
        set_inspector(inspector_pref.get(key, True) and (not state['narrow'] or state['forced']))
        restore_console(key)
        if key in on_show:
            on_show[key]()
        if key == 'topology' and not refs['guide'].flag(TOPOLOGY_VIEWED):
            refs['guide'].set(TOPOLOGY_VIEWED)       # the getting-started checklist ticks it
            overview_stale()
        update_status()

    refs['nav'] = Rail(root, pages, show_page)
    refs['pages'] = [key for key, _label in pages]
    refs['nav'].grid(row=2, column=0, sticky='ns')
    refs['show_page'] = show_page
    refs['current_page'] = lambda: state['current']

    def place_dividers():
        """Start with the inspector and console at their default sizes."""
        root.update_idletasks()
        width, height = upper.winfo_width(), outer.winfo_height()
        if inspector_shown() and width > 2 * theme.INSPECTOR_WIDTH:
            upper.sashpos(0, int(width - theme.INSPECTOR_WIDTH))
        if height > 2 * theme.CONSOLE_HEIGHT:
            restore_console(state['current'])

    if demo_store:
        log_event('app', 'Sample mode: no database connected. Data is kept in memory and '
                         'lost on exit.', 'warn')
    else:
        log_event('app', 'Connected to the database: SUCCESSFUL.', 'ok')
    if access is not None and access.demo:
        log_event('app', 'DEMO MODE: started with --demo, so nobody is signed in.', 'warn')
    elif account is not None:
        log_event('app', f'Sign-in SUCCESSFUL: {mask_email(account.session.email)} '
                         f'({access.title}).', 'ok')
    log_event('app', 'NetCommand workbench started.')
    root.bind_all('<F1>', lambda e: refs['guide'].page_help(), add='+')
    add_tooltips(refs)
    show_page(FIRST_PAGE)
    root.after(50, place_dividers)
    root.after(80, adapt_layout)
    return refs
