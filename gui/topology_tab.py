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
from gui.topology_canvas import TopologyCanvas
from topology.graph import build_graph, draw_map, find_single_points

EMPTY_MESSAGE = ('No registered devices yet.\n'
                 'Run a scan and approve the devices you find to see your network here.')
SAMPLE_BANNER = 'SAMPLE DATA: example network, not your registered devices'
DEFAULT_SIZE = (900, 520)        # used before the page has been laid out
RESIZE_DELAY_MS = 250


class TopologyTab(ttk.Frame):
    def __init__(self, parent, get_data, on_select=None):
        """get_data() -> (devices, links, source_label).
        on_select(kind, info): a device or link was clicked on the interactive map."""
        super().__init__(parent, padding=theme.PAD)
        self.get_data = get_data
        self.img = None
        self.shown_names = []        # the devices on the current map (for tests and checks)
        self.drawn_size = None
        self._data, self._pending = None, None

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
        devices, links, source = self.get_data()
        self._data = (devices, links, source)
        is_sample = source.startswith('SAMPLE')
        self.source.config(text=source, style='Sample.TLabel' if is_sample else 'TLabel')
        self.interactive.load(devices, links, sample=is_sample, empty_text=EMPTY_MESSAGE)
        if not devices:                                # real database, nothing registered
            self.img, self.shown_names, self.drawn_size = None, [], None
            self.label.config(image='', text=EMPTY_MESSAGE)
            self.single.config(text='')
            return
        self._render()
        points = find_single_points(devices, links)
        self.single.config(text=('Single points of failure: ' + ', '.join(points))
                           if points else '')

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
