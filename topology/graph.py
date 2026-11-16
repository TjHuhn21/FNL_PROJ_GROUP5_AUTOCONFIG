"""The network graph: building it, finding single points of failure, and drawing the map.

The map is drawn with Matplotlib into a PNG. Drawing happens in two steps:
  plan_map()  works out WHERE everything goes (pure arithmetic, easy to test);
  draw_map()  paints that plan.

Layout: a layered, top-down tree. Each connected part of the network starts at
a router when it has one (otherwise at its best-connected device); its
neighbours go one layer below, and so on (breadth-first). Every device sits
under the devices it connects to, and the whole drawing is scaled and centred
to fit the picture size, so nothing is clipped.

When a layer is too wide for the picture (a switch with many neighbours), it
wraps onto several rows arranged either side of a free centre column. Its links
then run as a "bus": down that column, along the gap above the row, and down
into each device, so no line passes behind another device and every port label
has its own place.

Only devices and links that are passed in are drawn: nothing is invented.
"""
import math
from collections import defaultdict

import networkx as nx
import matplotlib
matplotlib.use('Agg')  # draw to a file, not to a window
import matplotlib.pyplot as plt
from matplotlib.patches import FancyBboxPatch, Rectangle

# ---------------------------------------------------------------- look (matches the workbench)
BG = '#F8F9F7'
NODE_FILL = '#FFFFFF'
NODE_FILL_MUTED = '#F1F2EF'
EDGE = '#6F7A82'
TEXT = '#1F2428'
TEXT_SOFT = '#3D454C'
TEXT_MUTED = '#59626B'
BORDER = '#8A949C'
UP = '#1B7A3A'
DOWN = '#B42318'
MUTED = '#8A949C'
AMBER = '#7A4600'
AMBER_SOFT = '#F6E9D2'
AMBER_EDGE = '#C98A2E'
SANS = ['Segoe UI', 'DejaVu Sans']
MONO = ['Consolas', 'DejaVu Sans Mono']
TYPE_TAG = {'router': 'RTR', 'switch': 'SW'}            # anything else: 'DEV'
LEGEND_PARTS = ['● up', '□ down', '○ unmanaged', 'rounded = router',
                'square = switch / other', 'SPOF = single point of failure',
                'labels = interface at each end']

# sizes in points (1/72 inch); scaled down together when space is short
BOX_W, BOX_H = 112, 36
GAP_X_MIN, GAP_X_MAX = 34, 150
GAP_Y_MIN, GAP_Y_MAX = 48, 120
MARGIN = 16
LEGEND_H = 20
LABEL_FONT = 7.5
LABEL_GAP = 3
WRAP_SCALE = 0.7          # wrap a wide row rather than shrink below 70%


def build_graph(devices, links):
    g = nx.Graph()
    for d in devices:
        g.add_node(d['name'])
    for a, port_a, b, port_b in links:
        g.add_edge(a, b)
    return g


def find_single_points(devices, links):
    """Names of devices whose failure would split the network."""
    return sorted(nx.articulation_points(build_graph(devices, links)))


# ---------------------------------------------------------------- layout (grid units)
def _pick_root(sub, by_name):
    """A router if the part has one (top of the drawing), else its best-connected device."""
    routers = [n for n in sub.nodes if by_name.get(n, {}).get('type') == 'router']
    candidates = routers or list(sub.nodes)
    return min(candidates, key=lambda n: (-sub.degree(n), str(n)))


def _spread(order, bary):
    """Columns for one row: as close to each device's wanted column as possible,
    at least one column apart, the row centred on the wanted columns."""
    placed = []
    for n in order:
        x = bary[n]
        if placed and x < placed[-1] + 1:
            x = placed[-1] + 1
        placed.append(x)
    shift = sum(bary[n] for n in order) / len(order) - sum(placed) / len(placed)
    return [x + shift for x in placed]


def _part_layout(sub, root, max_cols):
    """One connected part: ({name: [column, row]}, {name: (trunk column, row)}).
    The second dict lists devices placed in a wrapped "bus" layer."""
    xs, pos, bus, row = {}, {}, {}, 0
    for layer in nx.bfs_layers(sub, [root]):
        # each device goes under the average position of its neighbours above it
        bary = {n: (sum(xs[p] for p in sub.neighbors(n) if p in xs) /
                    max(1, sum(1 for p in sub.neighbors(n) if p in xs))) for n in layer}
        order = sorted(layer, key=lambda n: (bary[n], str(n)))
        if not max_cols or len(order) <= max_cols:
            for n, x in zip(order, _spread(order, bary)):
                xs[n], pos[n] = x, [x, row]
            row += 1
            continue
        # too wide: rows either side of a trunk line under the devices above. The
        # trunk runs in the gap between the two middle boxes (half a column each way).
        trunk = sum(bary.values()) / len(order)
        per_side = max(1, max_cols // 2)
        for start in range(0, len(order), 2 * per_side):
            chunk = order[start:start + 2 * per_side]
            half = (len(chunk) + 1) // 2
            left, right = chunk[:half], chunk[half:]
            for i, n in enumerate(left):
                x = trunk - 0.5 - (len(left) - 1 - i)
                xs[n], pos[n] = x, [x, row]
            for i, n in enumerate(right):
                x = trunk + 0.5 + i
                xs[n], pos[n] = x, [x, row]
            for n in chunk:
                bus[n] = (trunk, row)
            row += 1
    low = min(x for x, _ in pos.values())
    for p in pos.values():
        p[0] -= low
    return pos, {n: (t - low, r) for n, (t, r) in bus.items()}


def layout(devices, links, max_cols=None):
    """({name: (column, row)}, {name: (trunk column, row)}) in grid units, row 0 at
    the top. With max_cols, wide layers wrap (see the module notes) and separate
    parts of the network are packed onto shelves no wider than max_cols columns."""
    g = build_graph(devices, links)
    by_name = {d['name']: d for d in devices}
    parts = sorted(nx.connected_components(g), key=lambda c: (-len(c), min(map(str, c))))
    blocks = []
    for part in (p for p in parts if len(p) > 1):
        sub = g.subgraph(part)
        blocks.append(_part_layout(sub, _pick_root(sub, by_name), max_cols))
    single = sorted((next(iter(p)) for p in parts if len(p) == 1), key=str)
    if single:                                         # unconnected devices: a small grid
        cols = max(1, math.ceil(math.sqrt(len(single))))
        if max_cols:
            cols = min(cols, max_cols)
        blocks.append(({n: [i % cols, i // cols] for i, n in enumerate(single)}, {}))

    pos, bus, x, y, shelf_h = {}, {}, 0.0, 0.0, 0.0
    for block_pos, block_bus in blocks:
        bw = max(p[0] for p in block_pos.values())
        bh = max(p[1] for p in block_pos.values())
        if max_cols and x > 0 and x + bw > max_cols - 1:   # does not fit: next shelf down
            x, y, shelf_h = 0.0, y + shelf_h + 1, 0.0
        for n, (bx, by) in block_pos.items():
            pos[n] = (bx + x, by + y)
        for n, (t, r) in block_bus.items():
            bus[n] = (t + x, r + y)
        x += bw + 1.5
        shelf_h = max(shelf_h, bh)
    return pos, bus


def layered_positions(devices, links, max_cols=None):
    """{name: (column, row)} in grid units; row 0 is the top."""
    return layout(devices, links, max_cols)[0]


# ---------------------------------------------------------------- plan (pixels)
def _label_size(text, size_pt, px):
    """Approximate width/height in pixels of one line of monospace text."""
    return len(text) * 0.6 * size_pt * px, size_pt * 1.25 * px


def plan_map(devices, links, width=800, height=600, dpi=100, top_reserve=0):
    """Where every node, link and port label goes, in pixels (origin bottom-left,
    as Matplotlib draws). top_reserve: pixels kept free at the top (for a banner).
    Returns a dict that draw_map() paints."""
    px = dpi / 72.0                                    # pixels per point
    by_name = {d['name']: d for d in devices}
    box_w, box_h = BOX_W * px, BOX_H * px
    margin, legend_h = MARGIN * px, LEGEND_H * px
    room_w = width - 2 * margin
    room_h = height - 2 * margin - legend_h - top_reserve
    # how many columns fit side by side at a still-readable size; wider layers wrap
    max_cols = max(2, int((room_w + GAP_X_MIN * px * WRAP_SCALE) /
                          ((BOX_W + GAP_X_MIN) * px * WRAP_SCALE)))
    grid, bus = layout(devices, links, max_cols=max_cols)
    spofs = set(find_single_points(devices, links))
    plan = {'width': width, 'height': height, 'dpi': dpi, 'nodes': {}, 'edges': [],
            'labels': [], 'scale': 1.0}
    if not grid:
        return plan

    cols = [x for x, _ in grid.values()]
    rows = [y for _, y in grid.values()]
    span_x, span_y = max(cols) - min(cols), max(rows) - min(rows)

    def step(span, room, box, lo, hi):
        if span == 0:
            return box + lo * px
        return min(max((room - box) / span, box + lo * px), box + hi * px)

    step_x = step(span_x, room_w, box_w, GAP_X_MIN, GAP_X_MAX)
    step_y = step(span_y, room_h, box_h, GAP_Y_MIN, GAP_Y_MAX)
    need_w, need_h = span_x * step_x + box_w, span_y * step_y + box_h
    # Shrink everything together if it does not fit. There is deliberately no lower
    # limit: a device must never be cut off (a bigger window redraws it bigger).
    k = min(1.0, room_w / need_w, room_h / need_h)
    box_w, box_h, step_x, step_y = box_w * k, box_h * k, step_x * k, step_y * k
    plan['scale'] = k

    draw_w, draw_h = span_x * step_x, span_y * step_y
    left = (width - draw_w) / 2                        # centre of the first column
    top = margin + top_reserve + (room_h - draw_h) / 2   # centre of the first row, from the top

    def col_x(c):
        return left + (c - min(cols)) * step_x

    def row_y(r):
        return height - (top + (r - min(rows)) * step_y)

    for name, (gx, gy) in grid.items():
        d = by_name.get(name)
        plan['nodes'][name] = {
            'x': col_x(gx), 'y': row_y(gy), 'w': box_w, 'h': box_h,
            'registered': d is not None,
            'ip': d['ip'] if d else 'not registered',
            'type': (d or {}).get('type', 'unknown'),
            'managed': bool(d and d.get('managed')),
            'status': (d or {}).get('status', 'up'),
            'spof': name in spofs,
        }

    # links: one line per connected pair, every port kept (pairs may share several links)
    ports = defaultdict(lambda: defaultdict(list))     # (a, b) -> {a: [ports], b: [ports]}
    for a, pa, b, pb in links:
        key = tuple(sorted((a, b)))
        ports[key][a].append(pa)
        ports[key][b].append(pb)
    label_pt = LABEL_FONT * k
    gap = LABEL_GAP * px * k
    nodes = plan['nodes']
    for (a, b), at in ports.items():
        na, nb = nodes[a], nodes[b]
        edge = {'a': a, 'b': b, 'ports_a': at[a], 'ports_b': at[b],
                'dashed': not (na['managed'] and nb['managed'])}
        parent, child = None, None
        if b in bus and grid[a][1] < grid[b][1]:
            parent, child = a, b
        elif a in bus and grid[b][1] < grid[a][1]:
            parent, child = b, a
        edge_labels = []
        if parent:
            _bus_edge(edge, nodes[parent], nodes[child], col_x(bus[child][0]), step_y,
                      at[parent], at[child], label_pt, gap, px, edge_labels)
        else:
            edge['points'] = [(na['x'], na['y']), (nb['x'], nb['y'])]
            for here, there, names in ((na, nb, at[a]), (nb, na, at[b])):
                edge_labels.append(port_label(here, there, ', '.join(names), label_pt, gap, px))
        edge['labels'] = edge_labels               # this link's own two port labels
        plan['labels'] += edge_labels
        plan['edges'].append(edge)
    plan['label_pt'], plan['label_gap'] = label_pt, gap
    return plan


def port_label(here, there, text, label_pt, gap, px):
    """A port label just outside `here`'s box, on the straight line towards `there`.
    Works the same with y pointing up (Matplotlib) or down (a Tk canvas)."""
    lw, lh = _label_size(text, label_pt, px)
    dx, dy = there['x'] - here['x'], there['y'] - here['y']
    dist = math.hypot(dx, dy) or 1.0
    ux, uy = dx / dist, dy / dist
    to_edge = min((here['w'] / 2) / abs(ux) if ux else math.inf,
                  (here['h'] / 2) / abs(uy) if uy else math.inf)
    # push the label past the box edge by half its own size in that direction
    reach = to_edge + gap + abs(ux) * lw / 2 + abs(uy) * lh / 2
    return {'text': text, 'x': here['x'] + ux * reach, 'y': here['y'] + uy * reach,
            'w': lw, 'h': lh, 'size': label_pt}


def _bus_edge(edge, parent, child, trunk_x, step_y, parent_ports, child_ports,
              label_pt, gap, px, labels):
    """Route parent -> trunk -> bus above the child's row -> down into the child,
    with both port labels on the child's short drop line (parent's port on top)."""
    ptext, ctext = ', '.join(parent_ports), ', '.join(child_ports)
    pw, ph = _label_size(ptext, label_pt, px)
    cw, chh = _label_size(ctext, label_pt, px)
    child_top = child['y'] + child['h'] / 2
    row_gap = step_y - child['h']                      # free space between two rows
    drop = min(ph + chh + 3 * gap, row_gap * 0.8)
    bus_y = child_top + drop
    parent_bottom = parent['y'] - parent['h'] / 2
    points = [(parent['x'], parent_bottom)]
    if abs(parent['x'] - trunk_x) > 0.5:                # step across to the trunk first
        turn_y = parent_bottom - (step_y - parent['h']) / 2
        points += [(parent['x'], turn_y), (trunk_x, turn_y)]
    points += [(trunk_x, bus_y), (child['x'], bus_y), (child['x'], child_top)]
    edge['points'] = points
    edge['bus'] = True
    labels.append({'text': ptext, 'x': child['x'], 'y': bus_y - gap - ph / 2,
                   'w': pw, 'h': ph, 'size': label_pt})
    labels.append({'text': ctext, 'x': child['x'], 'y': child_top + gap + chh / 2,
                   'w': cw, 'h': chh, 'size': label_pt})


# ---------------------------------------------------------------- drawing
def legend_text(parts, room_px, px, size=7.0, smallest=5.5):
    """The legend as one line, or two when one line would not fit room_px.
    Returns (text, font size in points)."""
    sep = '   '
    one = sep.join(parts)
    fit = room_px / (len(one) * 0.6 * px)
    if fit >= smallest:
        return one, min(size, fit)
    half = (len(parts) + 1) // 2
    lines = [sep.join(parts[:half]), sep.join(parts[half:])]
    longest = max(len(line) for line in lines)
    return '\n'.join(lines), max(4.5, min(size, room_px / (longest * 0.6 * px)))


def draw_map(devices, links, path='topology.png', size=(800, 600), dpi=100, banner=None):
    """Draw the network map into a PNG of `size` pixels and return the path.
    banner: optional text shown at the top (used to mark SAMPLE DATA)."""
    width, height = int(size[0]), int(size[1])
    px = dpi / 72.0
    plan = plan_map(devices, links, width, height, dpi, top_reserve=24 * px if banner else 0)
    k = plan['scale']
    fig = plt.figure(figsize=(width / dpi, height / dpi), dpi=dpi, facecolor=BG)
    ax = fig.add_axes([0, 0, 1, 1])
    ax.set_xlim(0, width)
    ax.set_ylim(0, height)
    ax.axis('off')
    nodes = plan['nodes']

    for e in plan['edges']:
        xs, ys = zip(*e['points'])
        ax.plot(xs, ys, color=EDGE, linewidth=1.4 * k, zorder=1, solid_capstyle='butt',
                solid_joinstyle='miter', linestyle=(0, (4, 3)) if e['dashed'] else '-')

    for name, n in nodes.items():
        x0, y0 = n['x'] - n['w'] / 2, n['y'] - n['h'] / 2
        plain = n['managed'] and n['registered']
        edge = DOWN if (plain and n['status'] == 'down') else BORDER if plain else MUTED
        rounding = 9 * px * k if n['type'] == 'router' else 1.5 * px * k
        ax.add_patch(FancyBboxPatch(
            (x0, y0), n['w'], n['h'], boxstyle=f'round,pad=0,rounding_size={rounding}',
            facecolor=NODE_FILL if plain else NODE_FILL_MUTED, edgecolor=edge,
            linewidth=(1.6 if n['status'] == 'down' and plain else 1.0) * k,
            linestyle='-' if plain else (0, (3, 2)), zorder=2))
        # status marker: filled dot = up, hollow square = down, hollow dot = unmanaged
        mx, my, r = x0 + 9 * px * k, n['y'], 3.2 * px * k
        if not plain:
            ax.add_patch(plt.Circle((mx, my), r, facecolor='none', edgecolor=MUTED,
                                    linewidth=1.2 * k, zorder=3))
        elif n['status'] == 'down':
            ax.add_patch(Rectangle((mx - r, my - r), 2 * r, 2 * r, facecolor='none',
                                   edgecolor=DOWN, linewidth=1.6 * k, zorder=3))
        else:
            ax.add_patch(plt.Circle((mx, my), r, color=UP, zorder=3))
        tx = x0 + 17 * px * k
        ax.text(tx, n['y'] + 4.5 * px * k, name, fontsize=9 * k, fontweight='bold',
                family=SANS, color=TEXT if plain else TEXT_SOFT, va='center', ha='left', zorder=4)
        ax.text(tx, n['y'] - 6 * px * k, n['ip'], fontsize=7 * k, family=MONO,
                color=TEXT_MUTED, va='center', ha='left', zorder=4)
        ax.text(x0 + n['w'] - 5 * px * k, n['y'] + 4.5 * px * k, TYPE_TAG.get(n['type'], 'DEV'),
                fontsize=6.5 * k, family=MONO, color=TEXT_MUTED, va='center', ha='right', zorder=4)
        if n['spof']:      # inside the box, so it can never cover a port label
            ax.text(x0 + n['w'] - 5 * px * k, n['y'] - 6 * px * k, 'SPOF', fontsize=6.5 * k,
                    family=MONO, fontweight='bold', color=AMBER, va='center', ha='right',
                    zorder=4, bbox=dict(boxstyle='square,pad=0.15', facecolor=AMBER_SOFT,
                                        edgecolor=AMBER_EDGE, linewidth=0.5))

    for lab in plan['labels']:
        ax.text(lab['x'], lab['y'], lab['text'], fontsize=lab['size'], family=MONO,
                color=TEXT_SOFT, ha='center', va='center', zorder=5,
                bbox=dict(boxstyle='square,pad=0.15', facecolor='white', edgecolor='#CDD2D6',
                          linewidth=0.5))

    legend, size = legend_text(LEGEND_PARTS, width - 2 * MARGIN * px, px)
    ax.text(MARGIN * px, MARGIN * px * 0.5, legend, fontsize=size, family=MONO,
            color=TEXT_MUTED, ha='left', va='bottom', linespacing=1.3)
    if banner:
        ax.text(MARGIN * px, height - MARGIN * px * 0.6, banner, fontsize=8, family=SANS,
                fontweight='bold', color=AMBER, ha='left', va='top',
                bbox=dict(boxstyle='square,pad=0.35', facecolor=AMBER_SOFT, edgecolor=AMBER_EDGE,
                          linewidth=0.6))
    fig.savefig(path, dpi=dpi, facecolor=BG)
    plt.close(fig)
    return path
