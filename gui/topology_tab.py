"""Topology page: the network map, in two views.

  Interactive   gui.topology_canvas.TopologyCanvas: click, drag, zoom, pan.
  Static image  the Matplotlib picture from topology.graph.draw_map(), kept as the
                fallback. It is still drawn on every refresh, so it stays ready.

Both are drawn from the same layout plan, at the size of the visible area, and
follow window resizing. Sample data is always marked as such, and in real-database
mode with nothing registered the page says so instead of showing sample devices.
"""
import os
import tempfile
import tkinter as tk
from tkinter import ttk, messagebox

from gui import theme
from gui.db_status import report_error
from gui.topology_canvas import TopologyCanvas
from topology.graph import build_graph, draw_map, find_single_points
from topology.layout_store import LayoutStore
from store_errors import DATABASE_ERRORS

EMPTY_MESSAGE = ('No registered devices yet.\n'
                 'Run a scan and approve the devices you find to see your network here.')
UNAVAILABLE_MESSAGE = ('Database unavailable: the map cannot be shown right now.\n'
                       'It is redrawn when the connection is back.')
SAMPLE_BANNER = 'SAMPLE DATA: example network, not your registered devices'
DEFAULT_SIZE = (900, 520)        # used before the page has been laid out
RESIZE_DELAY_MS = 250


class TopologyTab(ttk.Frame):
    def __init__(self, parent, get_data, on_select=None, layout_scope='sample',
                 layout_file=None, log=None):
        """get_data() -> (devices, links, source_label).
        on_select(kind, info): a device or link was clicked on the interactive map.
        layout_scope: which saved layout belongs to this data ('database:...' or 'sample').
        log(source, message, level): where to report layout events (the console)."""
        super().__init__(parent, padding=theme.PAD)
        self.get_data = get_data
        self.img = None
        self.shown_names = []        # the devices on the current map (for tests and checks)
        self.drawn_size = None
        self._data, self._pending = None, None
        self.layouts = LayoutStore(layout_file)
        self.layout_scope = layout_scope
        self.log = log or (lambda *a, **k: None)

        top = ttk.Frame(self); top.pack(fill='x')
        ttk.Button(top, text='Refresh map', style='Accent.TButton',
                   command=self.refresh).pack(side='left')
        self.source = ttk.Label(top, text=''); self.source.pack(side='left', padx=theme.PAD)
        # Interactive canvas (new) or the static Matplotlib picture (the tested fallback)
        self.view = tk.StringVar(value='interactive')
        for value, text in (('static', 'Static image'), ('interactive', 'Interactive')):
            ttk.Radiobutton(top, text=text, value=value, variable=self.view,
                            command=self._show_view).pack(side='right', padx=(6, 0))
        ttk.Label(top, text='View:').pack(side='right')
        self.single = ttk.Label(self, text='', foreground=theme.SAMPLE_COLOR)
        self.single.pack(side='bottom', anchor='w', pady=(4, 0))
        self.holder = tk.Frame(self, background=theme.SURFACE)
        self.holder.pack(fill='both', expand=True, pady=(theme.PAD, 0))
        self.interactive = TopologyCanvas(self.holder, on_select=on_select)
        # Saved layouts: a Save button and a line saying which layout is shown
        self.save_button = ttk.Button(self.interactive.bar, text='Save layout',
                                      command=self.save_layout)
        self.save_button.pack(side='left', padx=(0, 6), before=self.interactive.zoom_label)
        self.layout_state = tk.Label(self.interactive.bar, text='', font=theme.FONT_SMALL,
                                     background=theme.SURFACE, foreground=theme.TEXT_MUTED)
        self.layout_state.pack(side='right')
        self._set_state(None)
        self.interactive.on_change = lambda: self._set_state('unsaved')
        self.interactive.on_reset_request = self.reset_layout
        self.area = tk.Frame(self.holder, background='#F8F9F7', highlightthickness=1,
                             highlightbackground=theme.BORDER)
        self.label = tk.Label(self.area, background='#F8F9F7', foreground=theme.TEXT_SOFT,
                              font=theme.FONT, justify='center')
        self.label.place(relx=0.5, rely=0.5, anchor='center')
        self.area.bind('<Configure>', self._on_resize)
        self._show_view()

    def _show_view(self):
        if self.view.get() == 'interactive':
            self.area.pack_forget()
            self.interactive.pack(fill='both', expand=True)
        else:
            self.interactive.pack_forget()
            self.area.pack(fill='both', expand=True)
            if self._data and self._data[0]:
                self.after_idle(self._resize_now)       # draw at the size now visible

    # ---------------------------------------------------------------- loading
    def refresh(self):
        try:
            devices, links, source = self.get_data()
        except DATABASE_ERRORS as err:
            self.show_unavailable(str(err))
            report_error(self, err)
            return
        self._data = (devices, links, source)
        is_sample = source.startswith('SAMPLE')
        self.source.config(text=source, style='Sample.TLabel' if is_sample else 'TLabel')
        status = self.interactive.load(devices, links, sample=is_sample, empty_text=EMPTY_MESSAGE)
        if status == 'new':                            # freshly laid out: bring back saved places
            self.restore_layout()
        elif status == 'empty':
            self._set_state(None)
        if not devices:                                # real database, nothing registered
            self.img, self.shown_names, self.drawn_size = None, [], None
            self.label.config(image='', text=EMPTY_MESSAGE)
            self.single.config(text='')
            return
        self._render()
        points = find_single_points(devices, links)
        self.single.config(text=('Single points of failure: ' + ', '.join(points))
                           if points else '')

    def show_unavailable(self, reason=''):
        """The devices could not be read: show no map at all (never the old one as if it
        were current). Saved layouts are not touched."""
        self._data = ([], [], 'Database unavailable')
        self.source.config(text='Database unavailable', style='TLabel')
        self.interactive.load([], [], sample=False, empty_text=UNAVAILABLE_MESSAGE)
        self._set_state(None)
        self.img, self.shown_names, self.drawn_size = None, [], None
        self.label.config(image='', text=UNAVAILABLE_MESSAGE)
        self.single.config(text='')

    # ---------------------------------------------------------------- saved layouts
    def device_key(self, name):
        """A stable identifier for a device in the saved layout. Real database devices
        use their database id (stable across sessions); sample devices use their IP
        (the in-memory sample store hands out ids 1, 2, 3... again every session);
        anything else uses its name."""
        d = self.interactive.by_name.get(name)
        if d and d.get('id') is not None and self.layout_scope.startswith('database'):
            return f"id:{d['id']}"
        if d and d.get('ip'):
            return f"ip:{d['ip']}"
        return f'name:{name}'

    def restore_layout(self):
        """Put devices where they were saved. New devices keep their automatic place;
        saved devices that no longer exist are ignored. Returns the names restored."""
        saved = self.layouts.load(self.layout_scope)
        if self.layouts.problem:
            self.log('topology', f'The saved layout could not be read: {self.layouts.problem}. '
                                 f'Using the automatic layout.', 'warn')
            self._set_state('auto')
            return []
        by_ip = {e['ip']: e for e in saved.values() if e.get('ip')}
        wanted = {}
        for name in self.interactive.nodes:
            key = self.device_key(name)
            entry = saved.get(key)
            if entry is None and key.startswith('id:'):     # same device, new database id
                d = self.interactive.by_name.get(name)
                entry = by_ip.get(d.get('ip')) if d else None
            if entry is not None:
                wanted[name] = (entry['x'], entry['y'])
        restored = self.interactive.apply_positions(wanted)
        new = len(self.interactive.nodes) - len(restored)
        if restored:
            self._set_state('saved', restored=len(restored), new=new)
            note = f' {new} new device(s) placed automatically.' if new else ''
            self.log('topology', f'Restored the saved layout for {len(restored)} device(s).{note}')
        else:
            self._set_state('auto')
        return restored

    def save_layout(self):
        """Save where every device is now (positions only; nothing sensitive)."""
        canvas = self.interactive
        if not canvas.nodes:
            messagebox.showinfo('Save layout', 'There is no network on the map to save.')
            return False
        entries = {}
        for name, (x, y) in canvas.positions().items():
            d = canvas.by_name.get(name)
            entries[self.device_key(name)] = {'x': round(x, 4), 'y': round(y, 4), 'name': name,
                                              'ip': d['ip'] if d else ''}
        try:
            self.layouts.save(self.layout_scope, entries)
        except OSError as err:
            self.log('topology', f'Could not save the layout: {err}', 'error')
            messagebox.showerror('Save layout', f'The layout could not be saved.\n\n{err}')
            return False
        self._set_state('saved', restored=len(entries), new=0)
        self.log('topology', f'Saved the layout of {len(entries)} device(s) to {self.layouts.path}', 'ok')
        messagebox.showinfo('Save layout', f'Layout saved for {len(entries)} devices.\n\n'
                                           f'It will be used the next time this map is opened.')
        return True

    def reset_layout(self):
        """Back to the automatic layout. If a layout was saved, ask first, and remove
        the saved layout only when the user agrees."""
        canvas = self.interactive
        if not canvas.nodes:
            return False
        if self.layouts.has(self.layout_scope):
            if not messagebox.askyesno(
                    'Reset layout',
                    'Put every device back in the automatic layout?\n\n'
                    'Your saved layout will be deleted, so the map will open in the '
                    'automatic layout from now on. This cannot be undone.'):
                return False
            try:
                self.layouts.delete(self.layout_scope)
            except OSError as err:
                messagebox.showerror('Reset layout', f'The saved layout could not be deleted.\n\n{err}')
                return False
            self.log('topology', 'Reset to the automatic layout and deleted the saved layout.')
        else:
            self.log('topology', 'Reset to the automatic layout.')
        canvas.reset_layout()
        self._set_state('auto')
        return True

    def _set_state(self, state, restored=0, new=0):
        """The line next to the map's buttons saying which layout is shown."""
        text = {None: '',
                'auto': 'Layout: automatic',
                'unsaved': 'Layout: changed, not saved',
                'saved': f'Layout: saved ({restored} devices'
                         + (f', {new} new placed automatically)' if new else ')')}[state]
        self.layout_state.config(text=text, foreground=theme.WARNING if state == 'unsaved'
                                 else theme.TEXT_MUTED)
        self.layout_state_key = state

    # ---------------------------------------------------------------- static map size
    def _area_size(self):
        self.area.update_idletasks()
        w, h = self.area.winfo_width() - 2, self.area.winfo_height() - 2
        return (w, h) if w > 200 and h > 150 else DEFAULT_SIZE

    def _render(self):
        devices, links, source = self._data
        size = self._area_size()
        dpi = float(self.tk.call('tk', 'scaling')) * 72      # text the same size as the app's
        path = os.path.join(tempfile.gettempdir(), 'netcommand_topology.png')
        try:
            draw_map(devices, links, path, size=size, dpi=dpi,
                     banner=SAMPLE_BANNER if source.startswith('SAMPLE') else None)
            self.img = tk.PhotoImage(file=path)   # keep a reference, or it vanishes
        except Exception as err:
            messagebox.showerror('Map failed', str(err))
            return
        self.label.config(image=self.img, text='')
        self.drawn_size = size
        self.shown_names = list(build_graph(devices, links).nodes)

    # ---------------------------------------------------------------- window resizing
    def _on_resize(self, _event):
        if not (self._data and self._data[0]):
            return
        if self._pending:
            self.after_cancel(self._pending)
        self._pending = self.after(RESIZE_DELAY_MS, self._resize_now)   # wait until dragging stops

    def _resize_now(self):
        self._pending = None
        if not self.winfo_ismapped() or not (self._data and self._data[0]):
            return
        new = self._area_size()
        if self.drawn_size is None or abs(new[0] - self.drawn_size[0]) > 24 \
                or abs(new[1] - self.drawn_size[1]) > 24:
            self._render()
