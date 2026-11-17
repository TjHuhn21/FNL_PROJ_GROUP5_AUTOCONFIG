"""The interactive topology: a tkinter.Canvas you can click, drag, zoom and pan.

Where things go comes from topology.graph.plan_map(), the same plan the static
Matplotlib map is drawn from, so both views always show the same devices,
links and interface names. Nothing is invented: only the devices and links
given to load() are drawn.

The canvas keeps a small model (each device's position in "world" units, plus
a zoom factor and a pan offset) and redraws everything from it, so text and
lines stay sharp at every zoom level. Screen position = world * zoom + offset.

Mouse:
    click a device or a link   select it (shown in the inspector)
    click empty space          clear the selection
    drag a device              move it (its links become straight and follow)
    drag empty space           pan
    mouse wheel                zoom around the pointer
"""
import math
import tkinter as tk
from tkinter import ttk

from gui import theme
from topology import graph
from topology.graph import plan_map, port_label, TYPE_TAG

EDGE_HIT = 6                # a click this close (px) to a link selects it
DRAG_START = 4              # px the mouse must move before a press becomes a drag
ZOOM_MIN, ZOOM_MAX, ZOOM_STEP = 0.3, 3.0, 1.2
FIT_MAX = 1.6               # "Fit" never enlarges a small network more than this
FIT_MARGIN = 20
LABEL_MIN_ZOOM = 0.55       # below this, port labels would be unreadably small: hidden
DEFAULT_SIZE = (900, 520)   # used before the canvas has been laid out
RESIZE_DELAY_MS = 150
SAMPLE_BANNER = 'SAMPLE DATA: example network, not your registered devices'
HINT = 'click: inspect   drag: move   drag empty space: pan   wheel: zoom'
LEGEND = graph.LEGEND_PARTS          # the same symbol legend as the static map


class TopologyCanvas(tk.Frame):
    def __init__(self, parent, on_select=None):
        """on_select(kind, info): kind is 'device', 'link' or None (selection cleared)."""
        super().__init__(parent, background=theme.SURFACE)
        self.on_select = on_select
        self.on_change = None            # called after the user drags a device
        self.on_reset_request = None     # if set, the Reset button asks this instead

        bar = tk.Frame(self, background=theme.SURFACE)
        bar.pack(fill='x', pady=(0, 6))
        self.bar = bar                   # the page adds its own buttons here (Save layout)
        self.buttons = {}
        for key, text, command in (('fit', 'Fit', self.fit), ('in', 'Zoom +', self.zoom_in),
                                   ('out', 'Zoom −', self.zoom_out),
                                   ('reset', 'Reset layout', self._reset_clicked)):
            self.buttons[key] = ttk.Button(bar, text=text, command=command)
            self.buttons[key].pack(side='left', padx=(0, 6))
        self.zoom_label = tk.Label(bar, text='', font=theme.mono(9), background=theme.SURFACE,
                                   foreground=theme.TEXT_MUTED)
        self.zoom_label.pack(side='left', padx=(6, 0))

        self.canvas = tk.Canvas(self, background=graph.BG, highlightthickness=1,
                                highlightbackground=theme.BORDER, cursor='arrow')
        self.canvas.pack(fill='both', expand=True)

        self.devices, self.links, self.sample = [], [], False
        self.by_name = {}
        self.nodes, self.edges = {}, []       # world model (y grows downwards)
        self.scale_k, self.label_pt, self.label_gap = 1.0, 7.5, 3.0
        self.zoom, self.off_x, self.off_y = 1.0, 0.0, 0.0
        self.selected = None                  # ('node', name) | ('edge', index) | None
        self.fitted, self.moved = True, False
        self.empty_text = ''
        self._signature = None
        self._layout_size = self._view_size = None
        self._press, self._pending = None, None

        c = self.canvas
        c.bind('<ButtonPress-1>', self._on_press)
        c.bind('<B1-Motion>', self._on_motion)
        c.bind('<ButtonRelease-1>', self._on_release)
        c.bind('<MouseWheel>', self._on_wheel)
        c.bind('<Configure>', self._on_configure)

    # ---------------------------------------------------------------- loading
    @property
    def px(self):
        """Screen pixels per point (the same scale the app's text uses)."""
        return float(self.tk.call('tk', 'scaling'))

    def load(self, devices, links, sample=False, empty_text=''):
        """Show these devices and links. Reloading the same network keeps the
        current positions and view (only states such as up/down are refreshed).
        Returns 'new' (laid out from scratch), 'same' (kept) or 'empty'."""
        devices, links = list(devices), list(links)
        signature = (sorted(d['name'] for d in devices), sorted(tuple(l) for l in links), sample)
        same = signature == self._signature and self.nodes
        self.devices, self.links, self.sample = devices, links, sample
        self.by_name = {d['name']: d for d in devices}
        self.empty_text = empty_text
        self._signature = signature
        if not devices:
            self.nodes, self.edges, self.selected = {}, [], None
            self.render()
            return 'empty'
        if same:
            self._refresh_states()
            self.render()
            return 'same'
        self.selected, self.moved = None, False
        self._layout()
        self.fit()
        return 'new'

    def _size(self):
        self.canvas.update_idletasks()
        w, h = self.canvas.winfo_width(), self.canvas.winfo_height()
        return (w, h) if w > 100 and h > 80 else DEFAULT_SIZE

    def _top_reserve(self):
        return 28 * self.px if self.sample else 0

    def _layout(self):
        """Positions from plan_map() for the current canvas size (y flipped for Tk)."""
        w, h = self._size()
        plan = plan_map(self.devices, self.links, w, h, dpi=self.px * 72,
                        top_reserve=self._top_reserve())
        flip = lambda y: h - y
        self.nodes = {name: dict(n, y=flip(n['y'])) for name, n in plan['nodes'].items()}
        self.edges = []
        for e in plan['edges']:
            self.edges.append(dict(
                e, points=[(x, flip(y)) for x, y in e['points']],
                labels=[dict(l, y=flip(l['y'])) for l in e['labels']]))
        self.scale_k, self.label_pt, self.label_gap = plan['scale'], plan['label_pt'], plan['label_gap']
        self._layout_size = (w, h)

    def _refresh_states(self):
        """Same devices and links as before: update up/down, managed and SPOF only."""
        spofs = set(graph.find_single_points(self.devices, self.links))
        for name, n in self.nodes.items():
            d = self.by_name.get(name)
            if d:
                n.update(status=d.get('status', 'up'), managed=bool(d.get('managed')),
                         ip=d['ip'], type=d.get('type', 'unknown'))
            n['spof'] = name in spofs

    # ---------------------------------------------------------------- view: fit, zoom, pan, reset
    def to_screen(self, x, y):
        return x * self.zoom + self.off_x, y * self.zoom + self.off_y

    def to_world(self, sx, sy):
        return (sx - self.off_x) / self.zoom, (sy - self.off_y) / self.zoom

    def _world_bounds(self):
        boxes = [(n['x'] - n['w'] / 2, n['y'] - n['h'] / 2, n['x'] + n['w'] / 2, n['y'] + n['h'] / 2)
                 for n in self.nodes.values()]
        boxes += [(l['x'] - l['w'] / 2, l['y'] - l['h'] / 2, l['x'] + l['w'] / 2, l['y'] + l['h'] / 2)
                  for e in self.edges for l in e['labels']]
        return (min(b[0] for b in boxes), min(b[1] for b in boxes),
                max(b[2] for b in boxes), max(b[3] for b in boxes))

    def fit(self):
        """Zoom and centre so the whole network is visible."""
        if self.nodes:
            w, h = self._size()
            top = self._top_reserve()
            bottom = 3 * 8 * 1.35 * self.px            # the legend and hint lines
            room_h = h - top - bottom
            x0, y0, x1, y1 = self._world_bounds()
            bw, bh = max(x1 - x0, 1), max(y1 - y0, 1)
            zoom = min((w - 2 * FIT_MARGIN) / bw, (room_h - 2 * FIT_MARGIN) / bh, FIT_MAX)
            self.zoom = max(ZOOM_MIN, min(ZOOM_MAX, zoom))
            self.off_x = (w - bw * self.zoom) / 2 - x0 * self.zoom
            self.off_y = top + (room_h - bh * self.zoom) / 2 - y0 * self.zoom
            self._view_size = (w, h)
        self.fitted = True
        self.render()

    def zoom_at(self, sx, sy, factor):
        """Zoom by `factor`, keeping the point under (sx, sy) where it is."""
        new = max(ZOOM_MIN, min(ZOOM_MAX, self.zoom * factor))
        if abs(new - self.zoom) < 1e-9:
            return
        wx, wy = self.to_world(sx, sy)
        self.zoom = new
        self.off_x, self.off_y = sx - wx * new, sy - wy * new
        self.fitted = False
        self.render()

    def zoom_in(self):
        w, h = self._size()
        self.zoom_at(w / 2, h / 2, ZOOM_STEP)

    def zoom_out(self):
        w, h = self._size()
        self.zoom_at(w / 2, h / 2, 1 / ZOOM_STEP)

    def pan(self, dx, dy):
        self.off_x += dx
        self.off_y += dy
        self.fitted = False
        self.render()

    def _reset_clicked(self):
        if self.on_reset_request:        # the page may ask for confirmation first
            self.on_reset_request()
        else:
            self.reset_layout()

    def reset_layout(self):
        """Put every device back where the automatic layout places it, then fit."""
        if not self.devices:
            return
        keep = self.selected
        self.moved = False
        self._layout()
        self.selected = keep if self._selection_valid(keep) else None
        self.fit()

    def _selection_valid(self, sel):
        if not sel:
            return False
        kind, key = sel
        return key in self.nodes if kind == 'node' else 0 <= key < len(self.edges)

    # ---------------------------------------------------------------- moving devices
    def move_node(self, name, x, y):
        """Put a device at world position (x, y); its links follow as straight lines."""
        n = self.nodes[name]
        n['x'], n['y'] = x, y
        self.moved = True
        self._straighten({name})
        self.render()

    def _straighten(self, names):
        """Links touching these devices become straight lines with their labels re-placed."""
        for e in self.edges:
            if e['a'] in names or e['b'] in names:
                a, b = self.nodes[e['a']], self.nodes[e['b']]
                e['points'] = [(a['x'], a['y']), (b['x'], b['y'])]
                e.pop('bus', None)
                e['labels'] = [port_label(a, b, ', '.join(e['ports_a']), self.label_pt,
                                          self.label_gap, self.px),
                               port_label(b, a, ', '.join(e['ports_b']), self.label_pt,
                                          self.label_gap, self.px)]

    # ---------------------------------------------------------------- saved positions
    def positions(self):
        """{name: (x, y)} in device-box units (x / box width, y / box height), which
        bring back the same arrangement at any window size."""
        return {name: (n['x'] / n['w'], n['y'] / n['h']) for name, n in self.nodes.items()}

    def apply_positions(self, saved):
        """Put the devices listed in `saved` ({name: (x, y)} in box units) where they
        were saved. Devices not listed (new ones) keep their automatic place, moved
        aside if a restored device now sits there. Returns the names restored."""
        restored = [name for name in saved if name in self.nodes]
        if not restored:
            return []
        for name in restored:
            n = self.nodes[name]
            n['x'], n['y'] = saved[name][0] * n['w'], saved[name][1] * n['h']
        shifted, placed = set(), list(restored)
        for name, n in self.nodes.items():
            if name in restored:
                continue
            for _ in range(200):                     # step right until it is free
                if not any(_boxes_touch(n, self.nodes[p]) for p in placed):
                    break
                n['x'] += n['w'] * 1.3
                shifted.add(name)
            placed.append(name)
        self._straighten(set(restored) | shifted)
        self.moved = True
        self.fit()
        return restored

    # ---------------------------------------------------------------- hit testing
    def node_at(self, sx, sy):
        wx, wy = self.to_world(sx, sy)
        for name in reversed(list(self.nodes)):
            n = self.nodes[name]
            if abs(wx - n['x']) <= n['w'] / 2 and abs(wy - n['y']) <= n['h'] / 2:
                return name
        return None

    def edge_at(self, sx, sy):
        best, best_d = None, EDGE_HIT
        for i, e in enumerate(self.edges):
            pts = [self.to_screen(x, y) for x, y in e['points']]
            for (x1, y1), (x2, y2) in zip(pts, pts[1:]):
                d = _segment_distance(sx, sy, x1, y1, x2, y2)
                if d <= best_d:
                    best, best_d = i, d
        return best

    def hit(self, sx, sy):
        name = self.node_at(sx, sy)
        if name is not None:
            return ('node', name)
        i = self.edge_at(sx, sy)
        return ('edge', i) if i is not None else None

    # ---------------------------------------------------------------- selection
    def select_node(self, name):
        self._select(('node', name) if name in self.nodes else None)

    def select_edge_between(self, a, b):
        for i, e in enumerate(self.edges):
            if {e['a'], e['b']} == {a, b}:
                return self._select(('edge', i))
        self._select(None)

    def clear_selection(self):
        self._select(None)

    def _select(self, sel):
        self.selected = sel
        self.render()
        if not self.on_select:
            return
        if sel is None:
            self.on_select(None, None)
        elif sel[0] == 'node':
            self.on_select('device', self.device_info(sel[1]))
        else:
            self.on_select('link', self.link_info(sel[1]))

    def device_info(self, name):
        """What the map knows about one device (its record, if it has one)."""
        n = self.nodes[name]
        return {'name': name, 'record': self.by_name.get(name), 'sample': self.sample,
                'registered': n['registered'], 'ip': n['ip'], 'type': n['type'],
                'status': n['status'], 'managed': n['managed'], 'spof': n['spof']}

    def link_info(self, index):
        e = self.edges[index]
        return {'a': e['a'], 'b': e['b'], 'ports_a': list(e['ports_a']),
                'ports_b': list(e['ports_b']), 'info_a': self.by_name.get(e['a']),
                'info_b': self.by_name.get(e['b']), 'sample': self.sample}

    # ---------------------------------------------------------------- mouse
    def _on_press(self, event):
        hit = self.hit(event.x, event.y)
        if hit and hit[0] == 'node':
            n = self.nodes[hit[1]]
            start = (n['x'], n['y'])
        else:
            start = (self.off_x, self.off_y)
        self._press = {'x': event.x, 'y': event.y, 'hit': hit, 'start': start, 'drag': False}

    def _on_motion(self, event):
        p = self._press
        if not p:
            return
        dx, dy = event.x - p['x'], event.y - p['y']
        if not p['drag']:
            if math.hypot(dx, dy) < DRAG_START:
                return
            p['drag'] = True
            self.canvas.configure(cursor='fleur')
        if p['hit'] and p['hit'][0] == 'node':
            sx, sy = p['start']
            self.move_node(p['hit'][1], sx + dx / self.zoom, sy + dy / self.zoom)
        else:
            self.off_x, self.off_y = p['start'][0] + dx, p['start'][1] + dy
            self.fitted = False
            self.render()

    def _on_release(self, event):
        p, self._press = self._press, None
        self.canvas.configure(cursor='arrow')
        if p and not p['drag']:                 # a click, not a drag
            self._select(p['hit'])
        elif p and p['hit'] and p['hit'][0] == 'node' and self.on_change:
            self.on_change()                    # a device was moved by hand

    def _on_wheel(self, event):
        self.zoom_at(event.x, event.y, ZOOM_STEP if event.delta > 0 else 1 / ZOOM_STEP)

    def _on_configure(self, _event):
        if self._pending:
            self.after_cancel(self._pending)
        self._pending = self.after(RESIZE_DELAY_MS, self._resized)

    def _resized(self):
        """New canvas size: a hand-arranged map is only refitted; an untouched one is
        laid out again for the new size, so it uses the space well."""
        self._pending = None
        size = self._size()
        if size == self._view_size:
            return
        self._view_size = size
        if not self.nodes:
            self.render()
        elif self.fitted and not self.moved:
            keep = self.selected
            self._layout()
            self.selected = keep if self._selection_valid(keep) else None
            self.fit()
        elif self.fitted:
            self.fit()
        else:
            self.render()

    # ---------------------------------------------------------------- drawing
    def render(self):
        c = self.canvas
        c.delete('all')
        self.zoom_label.configure(text=f'{round(self.zoom * 100)}%' if self.nodes else '')
        w, h = self._size()
        if not self.nodes:
            c.create_text(w / 2, h / 2, text=self.empty_text, justify='center',
                          font=theme.FONT, fill=theme.TEXT_SOFT, tags=('empty',))
            return
        z, k, px = self.zoom, self.scale_k, self.px
        u = z * k * px                                      # one "point" on screen, in pixels

        for i, e in enumerate(self.edges):
            selected = self.selected == ('edge', i)
            pts = [v for x, y in e['points'] for v in self.to_screen(x, y)]
            c.create_line(*pts, fill=theme.ACCENT if selected else graph.EDGE,
                          width=max(1.0, 1.4 * u) + (2 if selected else 0),
                          dash=(4, 3) if e['dashed'] else (), capstyle='butt',
                          joinstyle='miter', tags=('edge', f'edge-{i}'))

        for i, (name, n) in enumerate(self.nodes.items()):
            self._draw_node(name, n, u, z, k)

        if z * k >= LABEL_MIN_ZOOM:
            size = max(5, round(self.label_pt * z))
            for i, e in enumerate(self.edges):
                for lab in e['labels']:
                    x, y = self.to_screen(lab['x'], lab['y'])
                    t = c.create_text(x, y, text=lab['text'], font=(theme.MONO_FAMILY, size),
                                      fill=graph.TEXT_SOFT, tags=('label', f'label-{i}'))
                    x0, y0, x1, y1 = c.bbox(t)
                    r = c.create_rectangle(x0 - 2, y0 - 1, x1 + 2, y1 + 1, fill='white',
                                           outline='#CDD2D6', tags=('label-bg',))
                    c.tag_lower(r, t)

        if self.sample:
            t = c.create_text(12, 10, anchor='nw', text=SAMPLE_BANNER, fill=graph.AMBER,
                              font=theme.FONT_BOLD, tags=('banner',))
            x0, y0, x1, y1 = c.bbox(t)
            c.tag_lower(c.create_rectangle(x0 - 6, y0 - 3, x1 + 6, y1 + 3, fill=graph.AMBER_SOFT,
                                           outline=graph.AMBER_EDGE, tags=('banner-bg',)), t)
        legend, _size = graph.legend_text(LEGEND, w - 20, self.px)
        c.create_text(10, h - 8, anchor='sw', text=legend + '\n' + HINT, font=theme.mono(8),
                      fill=theme.TEXT_MUTED, tags=('hint',))

    def _draw_node(self, name, n, u, z, k):
        c = self.canvas
        tag = ('node', f'node-{name}')
        x, y = self.to_screen(n['x'], n['y'])
        w, h = n['w'] * z, n['h'] * z
        x0, y0, x1, y1 = x - w / 2, y - h / 2, x + w / 2, y + h / 2
        plain = n['managed'] and n['registered']
        down = plain and n['status'] == 'down'
        selected = self.selected == ('node', name)
        outline = theme.ACCENT if selected else graph.DOWN if down else \
            graph.BORDER if plain else graph.MUTED
        width = 3 if selected else (2 if down else 1)
        fill = graph.NODE_FILL if plain else graph.NODE_FILL_MUTED
        dash = () if plain else (3, 2)
        if n['type'] == 'router':                       # rounded box = router
            r = min(9 * u, h / 2)
            c.create_polygon(_rounded(x0, y0, x1, y1, r), smooth=True, fill=fill,
                             outline=outline, width=width, dash=dash, tags=tag)
        else:                                           # square box = switch / other
            c.create_rectangle(x0, y0, x1, y1, fill=fill, outline=outline, width=width,
                               dash=dash, tags=tag)
        # status marker: filled dot = up, hollow square = down, hollow dot = unmanaged
        mx, my, rr = x0 + 9 * u, y, 3.2 * u
        if not plain:
            c.create_oval(mx - rr, my - rr, mx + rr, my + rr, outline=graph.MUTED,
                          width=max(1, 1.2 * z), tags=tag)
        elif down:
            c.create_rectangle(mx - rr, my - rr, mx + rr, my + rr, outline=graph.DOWN,
                               width=max(1, 1.6 * z), tags=tag)
        else:
            c.create_oval(mx - rr, my - rr, mx + rr, my + rr, fill=graph.UP, outline=graph.UP,
                          tags=tag)
        name_size = round(9 * k * z)
        if name_size >= 4:
            c.create_text(x0 + 17 * u, y - 4.5 * u, anchor='w', text=name,
                          font=(theme.FONT_FAMILY, name_size, 'bold'),
                          fill=graph.TEXT if plain else graph.TEXT_SOFT, tags=tag)
        small = round(7 * k * z)
        if small >= 4:
            c.create_text(x0 + 17 * u, y + 6 * u, anchor='w', text=n['ip'],
                          font=(theme.MONO_FAMILY, small), fill=graph.TEXT_MUTED, tags=tag)
            c.create_text(x1 - 5 * u, y - 4.5 * u, anchor='e', text=TYPE_TAG.get(n['type'], 'DEV'),
                          font=(theme.MONO_FAMILY, small), fill=graph.TEXT_MUTED, tags=tag)
            if n['spof']:
                t = c.create_text(x1 - 5 * u, y + 6 * u, anchor='e', text='SPOF',
                                  font=(theme.MONO_FAMILY, small, 'bold'), fill=graph.AMBER,
                                  tags=tag + ('spof',))
                bx0, by0, bx1, by1 = c.bbox(t)
                c.tag_lower(c.create_rectangle(bx0 - 2, by0, bx1 + 2, by1, fill=graph.AMBER_SOFT,
                                               outline=graph.AMBER_EDGE, tags=tag), t)

    # ---------------------------------------------------------------- for tests and checks
    def screen_center(self, name):
        n = self.nodes[name]
        return self.to_screen(n['x'], n['y'])

    def edge_midpoint(self, index):
        """A point on the longest segment of a link, in screen pixels."""
        pts = [self.to_screen(x, y) for x, y in self.edges[index]['points']]
        (x1, y1), (x2, y2) = max(zip(pts, pts[1:]),
                                 key=lambda s: math.hypot(s[1][0] - s[0][0], s[1][1] - s[0][1]))
        return (x1 + x2) / 2, (y1 + y2) / 2


def _boxes_touch(a, b, gap=0.15):
    """Do two device boxes overlap (or come closer than `gap` of a box size)?"""
    return (abs(a['x'] - b['x']) < (a['w'] + b['w']) / 2 * (1 + gap) and
            abs(a['y'] - b['y']) < (a['h'] + b['h']) / 2 * (1 + gap))


def _segment_distance(px, py, x1, y1, x2, y2):
    dx, dy = x2 - x1, y2 - y1
    if dx == dy == 0:
        return math.hypot(px - x1, py - y1)
    t = max(0.0, min(1.0, ((px - x1) * dx + (py - y1) * dy) / (dx * dx + dy * dy)))
    return math.hypot(px - (x1 + t * dx), py - (y1 + t * dy))


def _rounded(x0, y0, x1, y1, r):
    """Corner points for a smoothed polygon that looks like a rounded rectangle."""
    return [x0 + r, y0, x1 - r, y0, x1, y0, x1, y0 + r, x1, y1 - r, x1, y1,
            x1 - r, y1, x0 + r, y1, x0, y1, x0, y1 - r, x0, y0 + r, x0, y0]
