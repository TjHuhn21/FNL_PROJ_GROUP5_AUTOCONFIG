"""The network map: layout plan (no window needed), drawing, and the Topology page."""
import os, sys, time
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))
sys.path.insert(0, os.path.dirname(__file__))
import pytest

import db_fake
import sample_data
import services
from discovery import crawler
from fakes import fake_login_factory, lab
from topology.graph import draw_map, layered_positions, legend_text, plan_map, TYPE_TAG

SIZES = [(640, 380), (900, 520), (1300, 620), (1600, 900)]


def dev(name, kind='switch', managed=True, status='up', ip=None):
    return {'name': name, 'ip': ip or f'10.0.0.{sum(map(ord, name)) % 250 + 1}', 'mac': '',
            'type': kind, 'managed': managed, 'status': status}


def lab_network(monkeypatch):
    monkeypatch.setattr(crawler, '_login', fake_login_factory(lab()))
    return crawler.discover('admin', 'cisco123', '192.168.1.2', login_neighbours=True)


def networks(monkeypatch):
    star = [dev('HUB')] + [dev(f'A{i:02d}') for i in range(12)]
    chain = [dev(f'C{i}') for i in range(10)]
    split = [dev('X1', 'router'), dev('X2'), dev('Y1'), dev('Y2'), dev('LONE1'), dev('LONE2')]
    return {
        'lab': lab_network(monkeypatch),
        'sample': (sample_data.DEVICES, sample_data.LINKS),
        'star of 12': (star, [('HUB', f'Gi0/{i}', f'A{i:02d}', 'Gi0/1') for i in range(12)]),
        'chain of 10': (chain, [(f'C{i}', 'Gi0/2', f'C{i+1}', 'Gi0/1') for i in range(9)]),
        'two parts + loose devices': (split, [('X1', 'Gi0/0', 'X2', 'Gi0/1'),
                                             ('Y1', 'Gi0/1', 'Y2', 'Gi0/1')]),
    }


def box(n):
    return n['x'] - n['w'] / 2, n['y'] - n['h'] / 2, n['x'] + n['w'] / 2, n['y'] + n['h'] / 2


def overlap(a, b, slack=0.5):
    return a[0] < b[2] - slack and b[0] < a[2] - slack and a[1] < b[3] - slack and b[1] < a[3] - slack


def label_box(l):
    return l['x'] - l['w'] / 2, l['y'] - l['h'] / 2, l['x'] + l['w'] / 2, l['y'] + l['h'] / 2


# ---------------------------------------------------------------- layout shape
def test_lab_is_a_clean_top_down_tree(monkeypatch):
    devices, links = lab_network(monkeypatch)
    pos = layered_positions(devices, links)
    layer = {n: y for n, (x, y) in pos.items()}
    assert layer == {'R1': 0, 'CORE': 1, 'SW1': 2, 'SW2': 2, 'SW3': 3}   # router on top
    assert pos['CORE'][0] == pos['R1'][0]                  # CORE straight under R1
    assert pos['SW3'][0] == pos['SW2'][0]                  # SW3 straight under SW2
    assert pos['SW1'][0] < pos['CORE'][0] < pos['SW2'][0]  # balanced either side


def test_without_a_router_the_best_connected_device_is_on_top():
    devices = [dev('A'), dev('HUB'), dev('B'), dev('C')]
    links = [('HUB', 'g1', 'A', 'g1'), ('HUB', 'g2', 'B', 'g1'), ('HUB', 'g3', 'C', 'g1')]
    pos = layered_positions(devices, links)
    assert pos['HUB'][1] == 0 and {pos[n][1] for n in 'ABC'} == {1}


def test_layout_is_the_same_every_time(monkeypatch):
    devices, links = lab_network(monkeypatch)
    assert layered_positions(devices, links) == layered_positions(devices, links)


# ---------------------------------------------------------------- fits, centred, consistent, no overlap
@pytest.mark.parametrize('size', SIZES)
def test_every_device_is_inside_the_picture_and_centred(monkeypatch, size):
    for label, (devices, links) in networks(monkeypatch).items():
        plan = plan_map(devices, links, *size, dpi=96)
        w, h = size
        boxes = [box(n) for n in plan['nodes'].values()]
        for x0, y0, x1, y1 in boxes:
            assert 0 <= x0 and x1 <= w and 0 <= y0 and y1 <= h, (label, size)
        left, right = min(b[0] for b in boxes), max(b[2] for b in boxes)
        assert abs((left + right) / 2 - w / 2) < 1.5, (label, size)      # centred left-right


@pytest.mark.parametrize('size', SIZES)
def test_nodes_have_one_size_and_never_overlap(monkeypatch, size):
    for label, (devices, links) in networks(monkeypatch).items():
        nodes = list(plan_map(devices, links, *size, dpi=96)['nodes'].values())
        assert len({(round(n['w'], 3), round(n['h'], 3)) for n in nodes}) == 1, label
        boxes = [box(n) for n in nodes]
        for i in range(len(boxes)):
            for j in range(i + 1, len(boxes)):
                assert not overlap(boxes[i], boxes[j]), (label, size)


@pytest.mark.parametrize('size', SIZES)
def test_port_labels_never_cover_a_device(monkeypatch, size):
    for label, (devices, links) in networks(monkeypatch).items():
        plan = plan_map(devices, links, *size, dpi=96)
        boxes = [box(n) for n in plan['nodes'].values()]
        for lab_ in plan['labels']:
            assert not any(overlap(label_box(lab_), b) for b in boxes), (label, size, lab_['text'])


@pytest.mark.parametrize('size', SIZES)
def test_port_labels_do_not_overlap_each_other(monkeypatch, size):
    for label, (devices, links) in networks(monkeypatch).items():
        labels = plan_map(devices, links, *size, dpi=96)['labels']
        boxes = [label_box(l) for l in labels]
        for i in range(len(boxes)):
            for j in range(i + 1, len(boxes)):
                assert not overlap(boxes[i], boxes[j]), (label, size, labels[i]['text'],
                                                         labels[j]['text'])


def passes_through(points, b, steps=60, inset=1.0):
    """Does the polyline enter box b (shrunk by `inset` px)?"""
    x0, y0, x1, y1 = b[0] + inset, b[1] + inset, b[2] - inset, b[3] - inset
    for (ax_, ay), (bx, by) in zip(points, points[1:]):
        for s in range(steps + 1):
            t = s / steps
            x, y = ax_ + (bx - ax_) * t, ay + (by - ay) * t
            if x0 < x < x1 and y0 < y < y1:
                return True
    return False


@pytest.mark.parametrize('size', SIZES)
def test_no_link_passes_behind_another_device(monkeypatch, size):
    for label, (devices, links) in networks(monkeypatch).items():
        plan = plan_map(devices, links, *size, dpi=96)
        for e in plan['edges']:
            for name, n in plan['nodes'].items():
                if name not in (e['a'], e['b']):
                    assert not passes_through(e['points'], box(n)), (label, size, e['a'],
                                                                     e['b'], name)


def test_a_wide_fan_out_wraps_into_a_bus_in_a_narrow_picture(monkeypatch):
    devices, links = networks(monkeypatch)['star of 12']
    narrow = plan_map(devices, links, 900, 520, dpi=144)
    assert all(e.get('bus') for e in narrow['edges'])
    rows = {round(n['y']) for name, n in narrow['nodes'].items() if name != 'HUB'}
    assert len(rows) > 1                                    # wrapped onto several rows
    wide = plan_map(devices, links, 2600, 700, dpi=96)
    assert not any(e.get('bus') for e in wide['edges'])     # room enough: one straight row


def test_a_large_window_is_used_rather_than_left_empty(monkeypatch):
    devices, links = lab_network(monkeypatch)
    plan = plan_map(devices, links, 1300, 620, dpi=96)
    ys = [n['y'] for n in plan['nodes'].values()]
    assert max(ys) - min(ys) > 0.6 * 620                 # spread over most of the height
    small = plan_map(devices, links, 640, 380, dpi=96)
    assert small['scale'] <= 1 and plan['scale'] == 1     # shrinks only when space is short


# ---------------------------------------------------------------- nothing invented, everything kept
def test_only_the_given_devices_and_links_are_drawn_with_every_port(monkeypatch):
    for label, (devices, links) in networks(monkeypatch).items():
        plan = plan_map(devices, links, 900, 520, dpi=96)
        expected = {d['name'] for d in devices} | {l[0] for l in links} | {l[2] for l in links}
        assert set(plan['nodes']) == expected, label
        assert {tuple(sorted((e['a'], e['b']))) for e in plan['edges']} == \
               {tuple(sorted((l[0], l[2]))) for l in links}, label
        assert len(plan['labels']) == 2 * len(plan['edges'])
    devices = [dev('A'), dev('B')]
    links = [('A', 'Gi0/1', 'B', 'Gi0/1'), ('A', 'Gi0/2', 'B', 'Gi0/2')]     # two cables
    plan = plan_map(devices, links, 900, 520, dpi=96)
    assert len(plan['edges']) == 1 and plan['edges'][0]['ports_a'] == ['Gi0/1', 'Gi0/2']
    assert sorted(l['text'] for l in plan['labels']) == ['Gi0/1, Gi0/2', 'Gi0/1, Gi0/2']


def test_a_link_to_an_unregistered_device_is_kept_and_marked(monkeypatch):
    plan = plan_map([dev('A')], [('A', 'Gi0/1', 'GHOST', 'Gi0/9')], 900, 520, dpi=96)
    ghost = plan['nodes']['GHOST']
    assert ghost['registered'] is False and ghost['ip'] == 'not registered'
    assert plan['edges'][0]['dashed'] is True


def test_device_types_and_states_are_kept_for_drawing(monkeypatch):
    devices, links = lab_network(monkeypatch)
    nodes = plan_map(devices, links, 900, 520, dpi=96)['nodes']
    assert nodes['R1']['type'] == 'router' and nodes['CORE']['type'] == 'switch'
    assert nodes['SW3']['managed'] is False
    assert nodes['CORE']['spof'] and nodes['SW2']['spof'] and not nodes['SW1']['spof']
    assert TYPE_TAG == {'router': 'RTR', 'switch': 'SW'}


# ---------------------------------------------------------------- drawing
def test_draw_map_keeps_its_old_call_and_draws_any_size(tmp_path, monkeypatch):
    from PIL import Image
    p = draw_map(sample_data.DEVICES, sample_data.LINKS, str(tmp_path / 'old.png'))
    assert Image.open(p).size == (800, 600)                 # the original default
    devices, links = lab_network(monkeypatch)
    p = draw_map(devices, links, str(tmp_path / 'big.png'), size=(1300, 620), dpi=144,
                 banner='SAMPLE DATA')
    assert Image.open(p).size == (1300, 620)
    assert os.path.getsize(draw_map([], [], str(tmp_path / 'empty.png'))) > 0


def test_legend_wraps_when_the_picture_is_narrow():
    parts = ['one item', 'two items', 'three items', 'four items']
    text, size = legend_text(parts, room_px=2000, px=1.0)
    assert '\n' not in text and size == 7.0
    text, size = legend_text(parts, room_px=110, px=1.0)
    assert text.count('\n') == 1 and size >= 4.5


# ---------------------------------------------------------------- sample data vs registered devices
def test_get_network_never_passes_sample_devices_off_as_registered():
    db_fake.reset()
    devices, links, source = services.get_network(db_fake)                  # sample mode default
    assert source.startswith('SAMPLE') and devices == sample_data.DEVICES
    assert services.get_network(db_fake, allow_sample=False) == ([], [], services.NO_DEVICES)
    db_fake.upsert_device(dev('SW9'))
    devices, links, source = services.get_network(db_fake, allow_sample=False)
    assert [d['name'] for d in devices] == ['SW9'] and source == 'Registered devices (1)'


# ---------------------------------------------------------------- the Topology page
tk = pytest.importorskip('tkinter')


def make_app(monkeypatch, demo_store):
    from tkinter import messagebox
    from gui_helpers import new_root
    root = new_root()
    root.geometry('1200x800')
    for name in ('showinfo', 'showerror', 'showwarning'):
        monkeypatch.setattr(messagebox, name, lambda *a, **k: None)
    db_fake.reset()
    from gui.main_window import build_main_window
    refs = build_main_window(root, db_fake, demo_store=demo_store)
    root.update()
    return root, refs


def test_real_mode_with_nothing_registered_shows_no_sample_devices(monkeypatch):
    from gui.topology_tab import EMPTY_MESSAGE
    root, r = make_app(monkeypatch, demo_store=False)
    try:
        r['show_page']('topology')
        topo = r['topology']
        assert topo.img is None and topo.shown_names == []
        assert topo.label.cget('text') == EMPTY_MESSAGE
        assert topo.source.cget('text') == services.NO_DEVICES
    finally:
        root.destroy()


def test_sample_mode_marks_the_sample_map_clearly(monkeypatch):
    root, r = make_app(monkeypatch, demo_store=True)
    try:
        r['show_page']('topology')
        topo = r['topology']
        assert topo.img is not None and topo.source.cget('text').startswith('SAMPLE')
        assert str(topo.source.cget('style')) == 'Sample.TLabel'
        assert sorted(topo.shown_names) == sorted(d['name'] for d in sample_data.DEVICES)
    finally:
        root.destroy()


def test_map_is_redrawn_to_fit_when_the_window_is_resized(monkeypatch):
    from gui_helpers import pump
    root, r = make_app(monkeypatch, demo_store=True)
    try:
        r['show_page']('topology')
        topo = r['topology']
        topo.view.set('static')                       # the static map redraws while it is shown
        topo._show_view()
        visible = lambda: (topo.area.winfo_width() - 2, topo.area.winfo_height() - 2)
        assert pump(root, lambda: topo.area.winfo_ismapped() and topo.drawn_size == visible())
        first = topo.drawn_size                       # drawn at the size actually on screen
        root.geometry('1000x600')                     # shrink (a window cannot outgrow the screen)
        assert pump(root, lambda: topo.drawn_size != first, timeout=5)
        assert topo.drawn_size[0] < first[0] and topo.drawn_size == visible()
    finally:
        root.destroy()
