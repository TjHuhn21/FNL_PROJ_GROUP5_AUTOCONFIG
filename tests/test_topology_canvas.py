"""The interactive topology canvas: rendering, selection, inspector, links, dragging,
zoom, pan, reset, resizing, and agreement with the static Matplotlib map's plan.
db_fake stands in for the database; mouse actions are real Tk events on the canvas."""
import math
import os, sys
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))
sys.path.insert(0, os.path.dirname(__file__))
import pytest

tk = pytest.importorskip('tkinter')
from tkinter import messagebox

import db_fake
from discovery import crawler
from fakes import fake_login_factory, lab
from gui_helpers import new_root, pump
from gui import theme
from topology import graph

BUTTON1 = 0x0100              # "left button held" in a Tk event's state


# ---------------------------------------------------------------- helpers
def register_lab(monkeypatch):
    """The fake lab as registered devices (SW1 down, SW3 unmanaged)."""
    monkeypatch.setattr(crawler, '_login', fake_login_factory(lab()))
    devices, links = crawler.discover('admin', 'cisco123', '192.168.1.2', login_neighbours=True)
    for d in devices:
        if d['name'] == 'SW1':
            d['status'] = 'down'
        db_fake.upsert_device(d)
    db_fake.save_links(links)
    return devices, links


def make_app(monkeypatch, demo_store, before=None, size='1300x850'):
    root = new_root()
    root.geometry(size)
    for name in ('showinfo', 'showerror', 'showwarning'):
        monkeypatch.setattr(messagebox, name, lambda *a, **k: None)
    db_fake.reset()
    if before:
        before()
    from gui.main_window import build_main_window
    refs = build_main_window(root, db_fake, demo_store=demo_store)
    refs['show_page']('topology')
    canvas = refs['topology'].interactive
    root.update()
    assert pump(root, lambda: canvas.canvas.winfo_width() > 100)
    canvas.reset_layout()                              # lay out at the real, visible size
    root.update()
    return root, refs, canvas


@pytest.fixture
def lab_app(monkeypatch):
    root, refs, canvas = make_app(monkeypatch, demo_store=False,
                                  before=lambda: register_lab(monkeypatch))
    yield root, refs, canvas
    root.destroy()


@pytest.fixture
def sample_app(monkeypatch):
    root, refs, canvas = make_app(monkeypatch, demo_store=True)
    yield root, refs, canvas
    root.destroy()


def click(root, tc, x, y):
    tc.canvas.event_generate('<ButtonPress-1>', x=int(x), y=int(y))
    tc.canvas.event_generate('<ButtonRelease-1>', x=int(x), y=int(y))
    root.update()


def drag(root, tc, x0, y0, x1, y1, steps=6):
    c = tc.canvas
    c.event_generate('<ButtonPress-1>', x=int(x0), y=int(y0))
    for i in range(1, steps + 1):
        c.event_generate('<Motion>', x=int(x0 + (x1 - x0) * i / steps),
                         y=int(y0 + (y1 - y0) * i / steps), state=BUTTON1)
    c.event_generate('<ButtonRelease-1>', x=int(x1), y=int(y1), state=BUTTON1)
    root.update()


def items(tc, tag):
    return tc.canvas.find_withtag(tag)


def node_box(tc, name):
    n = tc.nodes[name]
    return n['x'] - n['w'] / 2, n['y'] - n['h'] / 2, n['x'] + n['w'] / 2, n['y'] + n['h'] / 2


def edge_index(tc, a, b):
    return next(i for i, e in enumerate(tc.edges) if {e['a'], e['b']} == {a, b})


# ---------------------------------------------------------------- rendering: real data only
def test_shows_exactly_the_registered_network(lab_app):
    root, r, tc = lab_app
    assert set(tc.nodes) == {'CORE', 'SW1', 'SW2', 'SW3', 'R1'}
    assert {frozenset((e['a'], e['b'])) for e in tc.edges} == {
        frozenset(p) for p in [('CORE', 'SW1'), ('CORE', 'SW2'), ('CORE', 'R1'), ('SW2', 'SW3')]}
    for name in tc.nodes:
        assert items(tc, f'node-{name}'), name
    texts = sorted(tc.canvas.itemcget(i, 'text') for i in items(tc, 'label'))
    assert texts == sorted(['Gi0/1', 'Gi0/1', 'Gi0/2', 'Gi0/1', 'Gi0/3', 'Gi0/0', 'Gi0/2', 'Gi0/1'])
    assert not items(tc, 'banner')                          # registered data: no sample banner


def test_layout_is_the_same_plan_as_the_static_matplotlib_map(lab_app):
    root, r, tc = lab_app
    w, h = tc._layout_size
    plan = graph.plan_map(tc.devices, tc.links, w, h, dpi=tc.px * 72)
    for name, n in plan['nodes'].items():
        assert math.isclose(tc.nodes[name]['x'], n['x']) and math.isclose(tc.nodes[name]['y'], h - n['y'])
        assert (tc.nodes[name]['w'], tc.nodes[name]['h']) == (n['w'], n['h'])
    assert [l['text'] for l in plan['labels']] == [l['text'] for e in tc.edges for l in e['labels']]


def test_device_states_types_and_spof_are_drawn(lab_app):
    root, r, tc = lab_app
    c = tc.canvas

    def first_shape(name):
        return items(tc, f'node-{name}')[0]                # the box is drawn first
    assert c.itemcget(first_shape('SW1'), 'outline') == graph.DOWN          # down = red
    assert c.itemcget(first_shape('SW3'), 'dash') != ''                     # unmanaged = dashed
    assert c.type(first_shape('R1')) == 'polygon' and c.type(first_shape('CORE')) == 'rectangle'
    spof = {c.itemcget(i, 'text') for i in items(tc, 'spof')}
    assert spof == {'SPOF'} and len(items(tc, 'spof')) == 2                 # CORE and SW2
    assert {n for n, v in tc.nodes.items() if v['spof']} == {'CORE', 'SW2'}


def test_the_legend_and_hint_never_cover_a_device(lab_app, monkeypatch):
    root, r, tc = lab_app
    hint = [tc.canvas.itemcget(i, 'text') for i in items(tc, 'hint')][0]
    assert 'SPOF = single point of failure' in hint and 'wheel: zoom' in hint
    hx0, hy0, hx1, hy1 = tc.canvas.bbox('hint')
    for name in tc.nodes:
        x0, y0, x1, y1 = node_box(tc, name)
        (sx0, sy0), (sx1, sy1) = tc.to_screen(x0, y0), tc.to_screen(x1, y1)
        assert not (sx0 < hx1 and hx0 < sx1 and sy0 < hy1 and hy0 < sy1), name


# ---------------------------------------------------------------- selecting devices
def test_clicking_a_device_shows_its_database_record(lab_app):
    root, r, tc = lab_app
    insp = r['inspector']
    click(root, tc, *tc.screen_center('SW1'))
    assert tc.selected == ('node', 'SW1')
    assert insp.selection == ('device', db_fake.get_device_by_name('SW1')['id'])
    assert insp.fields['IP address'].cget('text') == '192.168.1.3'
    assert 'down' in insp.status_label.cget('text')
    assert c_outline(tc, 'SW1') == theme.ACCENT                                 # highlighted
    click(root, tc, *tc.screen_center('CORE'))
    assert insp.fields['Topology'].cget('text') == 'single point of failure'


def c_outline(tc, name):
    return tc.canvas.itemcget(items(tc, f'node-{name}')[0], 'outline')


def test_clicking_empty_space_clears_the_selection(lab_app):
    root, r, tc = lab_app
    click(root, tc, *tc.screen_center('SW2'))
    w = tc.canvas.winfo_width()
    assert tc.hit(w - 6, 6) is None
    click(root, tc, w - 6, 6)
    assert tc.selected is None and r['inspector'].selection is None


def test_sample_devices_are_marked_as_sample_data(sample_app):
    root, r, tc = sample_app
    banner = [tc.canvas.itemcget(i, 'text') for i in items(tc, 'banner')]
    assert banner and banner[0].startswith('SAMPLE DATA')
    click(root, tc, *tc.screen_center('AP-1'))
    insp = r['inspector']
    assert insp.selection == ('details', 'AP-1') and insp.device is None
    assert insp.note_label.cget('text').startswith('SAMPLE DATA')
    assert insp.fields['IP address'].cget('text') == '192.168.1.9'


def test_a_neighbour_without_a_record_is_shown_from_map_data_only():
    root = new_root()
    try:
        from gui import theme
        from gui.topology_canvas import TopologyCanvas
        theme.apply(root)
        got = []
        tc = TopologyCanvas(root, on_select=lambda kind, info: got.append((kind, info)))
        tc.pack(fill='both', expand=True)
        root.geometry('900x600'); root.update()
        tc.load([{'id': 1, 'name': 'A', 'ip': '10.0.0.1', 'type': 'switch', 'managed': True,
                  'status': 'up'}], [('A', 'Gi0/1', 'GHOST', 'Gi0/9')])
        root.update()
        click(root, tc, *tc.screen_center('GHOST'))
        kind, info = got[-1]
        assert kind == 'device' and info['record'] is None and info['registered'] is False
        assert info['ip'] == 'not registered'
    finally:
        root.destroy()


# ---------------------------------------------------------------- selecting links
def test_clicking_a_link_shows_both_devices_and_interfaces(lab_app):
    root, r, tc = lab_app
    i = edge_index(tc, 'CORE', 'SW2')
    x, y = tc.edge_midpoint(i)
    assert tc.node_at(x, y) is None
    click(root, tc, x, y)
    assert tc.selected == ('edge', i)
    insp = r['inspector']
    assert insp.selection[0] == 'link' and set(insp.selection[1]) == {'CORE', 'SW2'}
    assert insp.fields['CORE port'].cget('text') == 'Gi0/2'
    assert insp.fields['SW2 port'].cget('text') == 'Gi0/1'
    assert tc.canvas.itemcget(items(tc, f'edge-{i}')[0], 'fill') == theme.ACCENT
    insp.link_buttons['SW2'].invoke()                    # "Inspect SW2" selects it on the map
    root.update()
    assert tc.selected == ('node', 'SW2') and insp.selection[0] == 'device'


def test_a_click_near_a_link_selects_it_but_far_away_does_not(lab_app):
    root, r, tc = lab_app
    i = edge_index(tc, 'CORE', 'R1')
    x, y = tc.edge_midpoint(i)
    assert tc.edge_at(x + 4, y) == i
    assert tc.edge_at(x + 40, y) is None


# ---------------------------------------------------------------- dragging, zooming, panning
def test_dragging_a_device_moves_it_and_its_links_follow(lab_app):
    root, r, tc = lab_app
    before = {n: (v['x'], v['y']) for n, v in tc.nodes.items()}
    x, y = tc.screen_center('SW3')
    drag(root, tc, x, y, x + 120, y - 30)
    nx_, ny_ = tc.nodes['SW3']['x'], tc.nodes['SW3']['y']
    assert math.isclose(nx_ - before['SW3'][0], 120 / tc.zoom, abs_tol=1.5 / tc.zoom)
    assert math.isclose(ny_ - before['SW3'][1], -30 / tc.zoom, abs_tol=1.5 / tc.zoom)
    for n in before:
        if n != 'SW3':
            assert (tc.nodes[n]['x'], tc.nodes[n]['y']) == before[n]      # others stay
    e = tc.edges[edge_index(tc, 'SW2', 'SW3')]
    assert (nx_, ny_) in e['points'] and len(e['points']) == 2             # follows, straight
    x0, y0, x1, y1 = node_box(tc, 'SW3')
    for lab_ in e['labels']:                                               # labels re-placed
        assert not (x0 < lab_['x'] < x1 and y0 < lab_['y'] < y1)
    assert tc.moved and tc.selected is None                                # a drag is not a click
    assert r['inspector'].selection is None


def test_mouse_wheel_zooms_around_the_pointer(lab_app):
    root, r, tc = lab_app
    x, y = tc.screen_center('CORE')
    before = tc.zoom
    tc.canvas.event_generate('<MouseWheel>', x=int(x), y=int(y), delta=120)
    root.update()
    assert math.isclose(tc.zoom, before * 1.2)
    sx, sy = tc.screen_center('CORE')
    assert abs(sx - int(x)) < 1.5 and abs(sy - int(y)) < 1.5               # CORE stays put
    for _ in range(30):
        tc.canvas.event_generate('<MouseWheel>', x=int(x), y=int(y), delta=-120)
    root.update()
    assert math.isclose(tc.zoom, 0.3)                                      # lower limit
    assert not tc.fitted


def test_zoom_buttons_fit_and_labels_follow_zoom(lab_app):
    root, r, tc = lab_app
    z = tc.zoom
    tc.buttons['in'].invoke(); assert math.isclose(tc.zoom, z * 1.2)
    tc.buttons['out'].invoke(); tc.buttons['out'].invoke()
    assert math.isclose(tc.zoom, z / 1.2)
    while tc.zoom * tc.scale_k >= 0.55:
        tc.zoom_out()
    assert not items(tc, 'label')                    # too small to read: port labels hidden
    tc.buttons['fit'].invoke()
    assert tc.fitted and items(tc, 'label')
    w, h = tc.canvas.winfo_width(), tc.canvas.winfo_height()
    for name in tc.nodes:
        x0, y0, x1, y1 = node_box(tc, name)
        (sx0, sy0), (sx1, sy1) = tc.to_screen(x0, y0), tc.to_screen(x1, y1)
        assert 0 <= sx0 and sx1 <= w and 0 <= sy0 and sy1 <= h, name


def test_dragging_empty_space_pans(lab_app):
    root, r, tc = lab_app
    w = tc.canvas.winfo_width()
    before = tc.screen_center('R1')
    drag(root, tc, w - 10, 10, w - 70, 50)
    after = tc.screen_center('R1')
    assert abs(after[0] - (before[0] - 60)) < 1.5 and abs(after[1] - (before[1] + 40)) < 1.5
    assert not tc.fitted and tc.selected is None


def test_reset_layout_puts_everything_back(lab_app):
    root, r, tc = lab_app
    original = {n: (v['x'], v['y']) for n, v in tc.nodes.items()}
    x, y = tc.screen_center('SW1')
    drag(root, tc, x, y, x - 50, y + 60)
    tc.zoom_in()
    tc.buttons['reset'].invoke()
    assert {n: (v['x'], v['y']) for n, v in tc.nodes.items()} == original
    assert tc.fitted and not tc.moved


# ---------------------------------------------------------------- resizing and reloading
# Window sizes stay within a 1280x720 screen (a 1920x1080 display at 150% scaling):
# Windows refuses to make a window larger than the screen, which would make a
# "grow" test meaningless.
def test_an_untouched_map_is_laid_out_again_when_the_window_grows(monkeypatch):
    root, r, tc = make_app(monkeypatch, demo_store=False,
                           before=lambda: register_lab(monkeypatch), size='1000x600')
    try:
        _check_grow(root, tc)
    finally:
        root.destroy()


def _check_grow(root, tc):
    spread = lambda: max(v['x'] for v in tc.nodes.values()) - min(v['x'] for v in tc.nodes.values())
    first_size, first_spread = tc._view_size, spread()
    root.geometry('1270x700')
    assert pump(root, lambda: tc._view_size != first_size, timeout=5)
    assert tc._view_size[0] > first_size[0]
    assert spread() > first_spread                         # uses the extra room
    w, h = tc.canvas.winfo_width(), tc.canvas.winfo_height()
    for name in tc.nodes:
        x0, y0, x1, y1 = node_box(tc, name)
        (sx0, sy0), (sx1, sy1) = tc.to_screen(x0, y0), tc.to_screen(x1, y1)
        assert 0 <= sx0 and sx1 <= w and 0 <= sy0 and sy1 <= h, name


def test_a_hand_arranged_map_keeps_its_positions_when_resized(lab_app):
    root, r, tc = lab_app
    x, y = tc.screen_center('SW3')
    drag(root, tc, x, y, x + 90, y)
    moved = (tc.nodes['SW3']['x'], tc.nodes['SW3']['y'])
    first_size = tc._view_size
    root.geometry('1000x600')                              # shrink (always possible)
    assert pump(root, lambda: tc._view_size != first_size, timeout=5)
    assert (tc.nodes['SW3']['x'], tc.nodes['SW3']['y']) == moved
    w, h = tc.canvas.winfo_width(), tc.canvas.winfo_height()
    x0, y0, x1, y1 = node_box(tc, 'SW3')                   # refitted: still in view
    (sx0, sy0), (sx1, sy1) = tc.to_screen(x0, y0), tc.to_screen(x1, y1)
    assert 0 <= sx0 and sx1 <= w and 0 <= sy0 and sy1 <= h


def test_refreshing_the_same_network_keeps_positions_and_updates_states(lab_app):
    root, r, tc = lab_app
    x, y = tc.screen_center('SW2')
    drag(root, tc, x, y, x + 40, y + 40)
    moved = (tc.nodes['SW2']['x'], tc.nodes['SW2']['y'])
    db_fake.set_status(db_fake.get_device_by_name('SW2')['id'], 'down')
    r['topology'].refresh()
    root.update()
    assert (tc.nodes['SW2']['x'], tc.nodes['SW2']['y']) == moved
    assert tc.nodes['SW2']['status'] == 'down' and c_outline(tc, 'SW2') == graph.DOWN


# ---------------------------------------------------------------- the fallback and empty states
def test_the_static_matplotlib_map_is_still_available(lab_app):
    root, r, tc = lab_app
    topo = r['topology']
    assert topo.view.get() == 'interactive' and tc.winfo_ismapped()
    assert topo.img is not None                            # drawn on every refresh anyway
    topo.view.set('static'); topo._show_view(); root.update()
    assert topo.area.winfo_ismapped() and not tc.winfo_ismapped()
    assert str(topo.label.cget('image')) != ''
    topo.view.set('interactive'); topo._show_view(); root.update()
    assert tc.winfo_ismapped()


def test_real_mode_with_nothing_registered_draws_no_network(monkeypatch):
    from gui.topology_tab import EMPTY_MESSAGE
    root, r, tc = make_app(monkeypatch, demo_store=False)
    try:
        assert tc.nodes == {} and tc.edges == []
        assert [tc.canvas.itemcget(i, 'text') for i in items(tc, 'empty')] == [EMPTY_MESSAGE]
        assert not items(tc, 'node') and not items(tc, 'banner')
    finally:
        root.destroy()
