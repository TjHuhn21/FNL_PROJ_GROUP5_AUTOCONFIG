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
from gui import theme
from gui.components.command_strip import CommandStrip
from gui.components.console import OperationsConsole
from gui.components.inspector import Inspector
from gui.components.rail import Rail
from gui.configure_tab import ConfigureTab
from gui.db_status import DatabaseStatus, report_error
from gui.devices_tab import DevicesTab
from gui.findings_tab import FindingsTab
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
         # ('setup', 'Setup'),    # Initial Setup hidden for the presentation: uncomment to show
         ('logs', 'Logs')]
FIRST_PAGE = 'dashboard'

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


def build_main_window(root, store, demo_store=False, startup_problem=None, access=None,
                      account=None, console_backend=None):
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
            who, text=f'{account.session.email} · {access.title}', font=theme.mono(9),
            text_color=theme.TEXT_SOFT)
        refs['user_label'].pack(side='left', padx=(0, 8))
        refs['sign_out_button'] = ctk.CTkButton(
            who, text='Sign out', font=theme.mono(9), height=24, width=80, corner_radius=3,
            fg_color=theme.SURFACE_2, hover_color=theme.BORDER, text_color=theme.TEXT,
            command=account.on_sign_out)
        refs['sign_out_button'].pack(side='left')
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

    console = OperationsConsole(outer, store)
    refs['console'] = console

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
                                           log=console.log)
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
            console.log('scan', f"Approved {result['total']} {noun}: {result['added']} new, "
                                f"{result['updated']} already registered (updated), "
                                f"{result['links']} links saved.", 'ok')
        elif result:
            console.log('scan', f"Approval stopped after {result['saved']} of {result['total']} "
                                f"devices: {result['error']}", 'error')

    def send_to_configure(commands, device_name):
        if not allowed('configure'):
            refuse('configure')
            return
        refs['configure'].load_commands(commands, device_name)
        show_page('configure')
        console.log('findings', f'Sent {len(commands)} suggested lines for {device_name} to Configure.')

    refs['devices'] = DevicesTab(host, store, on_change=after_data_change)
    refs['configure'] = ConfigureTab(host, store, log=console.log, on_change=after_data_change,
                                     on_applied=overview_stale)
    refs['scan'] = ScanTab(host, store, services.run_discovery,
                           on_approved=after_approval, demo_default=demo_store,
                           sample_store=demo_store)
    refs['scan'].on_activity = overview_stale
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
                                   layout_scope=layout_scope, log=console.log)
    refs['findings'] = FindingsTab(host, store, lambda: services.collect_review_inputs(store, demo_store),
                                   send_to_configure)
    refs['findings'].on_saved = overview_stale
    refs['logs'] = LogsTab(host, store)
    if allowed('setup'):                    # not even built for roles that may not use it
        refs['setup'] = SetupTab(host, log=console.log, backend=console_backend)
    refs['dashboard'] = OverviewPage(
        host, lambda key: show_page(key), store=store, can_open=allowed,
        scan_history=lambda: refs['scan'].history,
        source_note='Sample mode: the data is kept in memory.' if demo_store else '')
    if access is not None:
        refs['devices'].set_read_only(not access.can(EDIT_DEVICES))
        refs['findings'].set_read_only(not access.can(RUN_REVIEW))
    # Backup catalogue (Phase 4B): the same permission as Configure. A selection is only
    # remembered for a future restore workflow; nothing is sent to any device.
    refs['devices'].set_backups_allowed(access is None or access.can(CONFIGURE))
    refs['backup_selection'] = None

    def backup_selected(selection):
        refs['backup_selection'] = selection
        console.log('backups', f'Selected backup {os.path.basename(selection.path)} for a '
                               f'future restore of {selection.device_name or selection.device_ip}'
                               f' (nothing was sent to the device).')
    refs['devices'].on_backup_selected = backup_selected

    def restore_finished(result):
        console.log('backups', f'Restore of {result.device_ip}: {result.status} (backup '
                               f'{os.path.basename(result.backup_file or "?")}, safety backup '
                               f'{result.safety_backup_file or "none"}).')
    refs['devices'].on_restore_finished = restore_finished

    def save_finished(result):
        console.log('backups', f'Save to startup on {result.device_ip}: {result.status} '
                               f'(startup backup {result.startup_backup or "none"}).')
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
            console.log('configure', f'{name} is not a managed device, so it cannot be configured.',
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
            console.log('find', f"Selected {d['name']} ({d['ip']}).")

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
        text_color=theme.TEXT_SOFT, command=lambda: set_inspector(not inspector_shown(),
                                                                   remember=True))
    refs['inspector_toggle'].pack(side='right', padx=(0, 4))

    # ---------------------------------------------------------------- collapsible inspector
    # Each page remembers whether it shows the inspector; Configure starts without it
    # (it needs the width). Selecting something to inspect always brings it back.
    inspector_pref = {'configure': False, 'setup': False}
    console_size = {}                          # page -> console height (pixels) chosen there

    def inspector_shown():
        return str(refs['inspector']) in [str(p) for p in upper.panes()]

    def set_inspector(visible, remember=False):
        if remember or visible:
            if state['current']:
                inspector_pref[state['current']] = visible
        if visible and not inspector_shown():
            upper.add(refs['inspector'], weight=0)
            root.update_idletasks()
            width, wanted = upper.winfo_width(), int(theme.INSPECTOR_WIDTH * _scaling(root))
            if width > 2 * wanted:
                upper.sashpos(0, width - wanted)
        elif not visible and inspector_shown():
            upper.forget(refs['inspector'])
        refs['inspector_toggle'].configure(text='Hide inspector' if inspector_shown()
                                           else 'Show inspector')

    refs['inspector'].on_hide = lambda: set_inspector(False, remember=True)
    refs['set_inspector'] = set_inspector
    refs['inspector_shown'] = inspector_shown

    def remember_console(page):
        height = outer.winfo_height()
        if page and height > 200:
            console_size[page] = height - outer.sashpos(0)

    def restore_console(page):
        height = outer.winfo_height()
        if height <= 200:
            return                                 # not laid out yet: place_dividers does it
        s = _scaling(root)
        default = theme.CONSOLE_HEIGHT_COMPACT if page == 'configure' else theme.CONSOLE_HEIGHT
        wanted = console_size.get(page, int(default * s))
        outer.sashpos(0, max(int(height * 0.35), height - wanted))

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
        console.log('access', f'Your role ({access.title}) cannot use {label}.', 'warn')

    def show_page(key):
        """Show one page, hide the others. Opening the page already shown does
        nothing, exactly like clicking the tab that was already open. A page the role
        may not use is refused (whatever asked for it: rail, command strip, inspector)."""
        if key == state['current']:
            return
        if not any(key == k for k, _label in pages):
            refuse(key)
            return
        remember_console(state['current'])
        for other, _label in all_pages:
            if other != key and other in refs:
                refs[other].grid_remove()
        refs[key].grid(row=0, column=0, sticky='nsew')
        refs['nav'].set_active(key)
        state['current'] = key
        set_inspector(inspector_pref.get(key, True))
        restore_console(key)
        if key in on_show:
            on_show[key]()
        update_status()

    refs['nav'] = Rail(root, pages, show_page)
    refs['pages'] = [key for key, _label in pages]
    refs['nav'].grid(row=2, column=0, sticky='ns')
    refs['show_page'] = show_page
    refs['current_page'] = lambda: state['current']

    def place_dividers():
        """Start with the inspector and console at their default sizes."""
        root.update_idletasks()
        s = _scaling(root)
        width, height = upper.winfo_width(), outer.winfo_height()
        if inspector_shown() and width > 2 * theme.INSPECTOR_WIDTH * s:
            upper.sashpos(0, int(width - theme.INSPECTOR_WIDTH * s))
        if height > 2 * theme.CONSOLE_HEIGHT * s:
            restore_console(state['current'])

    show_page(FIRST_PAGE)
    root.after(50, place_dividers)
    if demo_store:
        console.log('app', 'Sample mode: no database connected. Data is kept in memory and '
                           'lost on exit.', 'warn')
    else:
        console.log('app', 'Connected to the database.', 'ok')
    if access is not None and access.demo:
        console.log('app', 'DEMO MODE: started with --demo, so nobody is signed in.', 'warn')
    elif account is not None:
        console.log('app', f'Signed in as {account.session.email} ({access.title}).', 'ok')
    return refs
