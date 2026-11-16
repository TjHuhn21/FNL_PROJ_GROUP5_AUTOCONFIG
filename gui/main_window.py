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
from gui.devices_tab import DevicesTab
from gui.findings_tab import FindingsTab
from gui.logs_tab import LogsTab
from gui.overview_page import OverviewPage
from gui.scan_tab import ScanTab
from gui.topology_tab import TopologyTab

# (key, rail label) in rail order. 'dashboard' is the Overview workspace.
PAGES = [('dashboard', 'Overview'), ('scan', 'Scan'), ('devices', 'Devices'),
         ('topology', 'Topology'), ('findings', 'Findings'), ('configure', 'Configure'),
         ('logs', 'Logs')]
FIRST_PAGE = 'dashboard'


def _scaling(widget):
    """How much CustomTkinter enlarges sizes on this display (1.0 = 100%)."""
    try:
        return ctk.ScalingTracker.get_widget_scaling(widget)
    except Exception:
        return 1.0


def build_main_window(root, store, demo_store=False):
    """Builds the workbench and every page. Returns refs: one entry per page key,
    plus 'nav', 'command', 'inspector', 'console', 'show_page', 'current_page'."""
    theme.apply(root)
    root.grid_columnconfigure(1, weight=1)
    root.grid_rowconfigure(2, weight=1)
    refs, state = {}, {'current': None}

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
    ctk.CTkLabel(brand, text='NC', font=theme.mono(12, 'bold'), text_color='#FFFFFF').grid(
        row=0, column=0)
    names = ctk.CTkFrame(header, fg_color=theme.SURFACE, corner_radius=0)
    names.grid(row=0, column=1, padx=(12, 20), sticky='w')
    ctk.CTkLabel(names, text='NetCommand', font=theme.FONT_BRAND, text_color=theme.TEXT,
                 height=18, anchor='w').grid(row=0, column=0, sticky='w')
    ctk.CTkLabel(names, text='network engineering workbench', font=theme.mono(8), height=14,
                 text_color=theme.TEXT_MUTED, anchor='w').grid(row=1, column=0, sticky='w')

    source_text = ('●  sample mode · in memory' if demo_store
                   else '●  database connected')
    refs['source_label'] = ctk.CTkLabel(
        header, text=source_text, font=theme.mono(9),
        text_color=theme.WARNING if demo_store else theme.SUCCESS)
    refs['source_label'].grid(row=0, column=3, padx=14)
    ctk.CTkFrame(root, height=1, corner_radius=0, fg_color=theme.BORDER).grid(
        row=1, column=0, columnspan=2, sticky='ew')

    # ---------------------------------------------------------------- workbench panels
    outer = ttk.PanedWindow(root, orient='vertical', style='Workbench.TPanedwindow')
    outer.grid(row=2, column=1, sticky='nsew')
    upper = ttk.PanedWindow(outer, orient='horizontal', style='Workbench.TPanedwindow')

    page_area = tk.Frame(upper, background=theme.SURFACE)
    if demo_store:
        ttk.Label(page_area, style='Sample.TLabel', padding=(12, 5),
                  text='No database connected: data is kept in memory and lost on exit '
                       '(sample mode).').pack(fill='x')
    host = tk.Frame(page_area, background=theme.SURFACE)
    host.pack(fill='both', expand=True, padx=12, pady=10)
    host.grid_columnconfigure(0, weight=1)
    host.grid_rowconfigure(0, weight=1)

    console = OperationsConsole(outer, store)
    refs['console'] = console

    # ---------------------------------------------------------------- the same page wiring as before
    def get_network():
        # Real database mode never falls back to the sample network on the map.
        return services.get_network(store, allow_sample=demo_store)

    def after_data_change():
        refs['devices'].refresh()
        refs['configure'].refresh_devices()
        update_status()
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
        refs['configure'].load_commands(commands, device_name)
        show_page('configure')
        console.log('findings', f'Sent {len(commands)} suggested lines for {device_name} to Configure.')

    refs['devices'] = DevicesTab(host, store, on_change=after_data_change)
    refs['configure'] = ConfigureTab(host, store)
    refs['scan'] = ScanTab(host, store, services.run_discovery,
                           on_approved=after_approval, demo_default=demo_store,
                           sample_store=demo_store,
                           find_gateway=lambda: __import__(
                               'discovery.crawler', fromlist=['x']).default_gateway())
    def on_map_select(kind, info):
        """A device or link was clicked on the interactive map: show it in the inspector.
        Registered devices are read from the store; anything without a record (sample
        data, an unregistered neighbour) is shown from the map data, clearly marked."""
        insp = refs['inspector']
        if kind is None:
            insp.clear()
            return
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

    refs['topology'] = TopologyTab(host, get_network, on_select=on_map_select)
    refs['findings'] = FindingsTab(host, store, lambda: services.collect_review_inputs(store, demo_store),
                                   send_to_configure)
    refs['logs'] = LogsTab(host, store)
    refs['dashboard'] = OverviewPage(host, lambda key: show_page(key))

    # ---------------------------------------------------------------- inspector and command strip
    def select_for_configure(name):
        """Pick a device in the Configure page's device box (managed devices only)."""
        conf = refs['configure']
        conf.refresh_devices()
        names = [d['name'] for d in conf.devices]
        if name not in names:
            console.log('configure', f'{name} is not a managed device, so it cannot be configured.',
                        'warn')
            return False
        conf.device_box.current(names.index(name))
        conf.device_box.event_generate('<<ComboboxSelected>>')
        return True

    def open_in_devices(name):
        show_page('devices')
        refs['devices'].search.set(name)
        refs['devices'].go_first()

    def configure_device(name):
        show_page('configure')
        select_for_configure(name)

    refs['inspector'] = Inspector(upper, store, on_open_devices=open_in_devices,
                                  on_configure=configure_device)
    # "Inspect SW1" on a link: select that device on the map
    refs['inspector'].on_focus_device = lambda name: refs['topology'].interactive.select_node(name)

    def on_device(device_id):
        d = refs['inspector'].show_device(device_id)
        if d:
            console.log('find', f"Selected {d['name']} ({d['ip']}).")

    def on_operation(key, device_name):
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
    ctk.CTkLabel(status, text='Ctrl+K  command strip', font=theme.mono(8), height=20,
                 text_color=theme.TEXT_SOFT).pack(side='right', padx=12)

    def update_status():
        try:
            n = store.count_devices()
            text = f'{n} registered device' + ('' if n == 1 else 's')
        except Exception:
            text = 'device count unavailable'
        refs['status_devices'].configure(text=text)

    # ---------------------------------------------------------------- rail and page switching
    on_show = {'devices': lambda: refs['devices'].refresh(),
               'logs': lambda: refs['logs'].refresh(),
               'configure': lambda: refs['configure'].refresh_devices(),
               'topology': lambda: refs['topology'].refresh(),
               'dashboard': lambda: refs['dashboard'].refresh()}

    def show_page(key):
        """Show one page, hide the others. Opening the page already shown does
        nothing, exactly like clicking the tab that was already open."""
        if key == state['current']:
            return
        for other, _label in PAGES:
            if other != key:
                refs[other].grid_remove()
        refs[key].grid(row=0, column=0, sticky='nsew')
        refs['nav'].set_active(key)
        state['current'] = key
        if key in on_show:
            on_show[key]()
        update_status()

    refs['nav'] = Rail(root, PAGES, show_page)
    refs['nav'].grid(row=2, column=0, sticky='ns')
    refs['show_page'] = show_page
    refs['current_page'] = lambda: state['current']

    def place_dividers():
        """Start with the inspector and console at their default sizes."""
        root.update_idletasks()
        s = _scaling(root)
        width, height = upper.winfo_width(), outer.winfo_height()
        if width > 2 * theme.INSPECTOR_WIDTH * s:
            upper.sashpos(0, int(width - theme.INSPECTOR_WIDTH * s))
        if height > 2 * theme.CONSOLE_HEIGHT * s:
            outer.sashpos(0, int(height - theme.CONSOLE_HEIGHT * s))

    show_page(FIRST_PAGE)
    root.after(50, place_dividers)
    if demo_store:
        console.log('app', 'Sample mode: no database connected. Data is kept in memory and '
                           'lost on exit.', 'warn')
    else:
        console.log('app', 'Connected to the database.', 'ok')
    return refs
