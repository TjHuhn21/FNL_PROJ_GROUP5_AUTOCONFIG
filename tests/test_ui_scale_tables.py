"""Sizing and tables: gui/ui_scale.py (one text-size setting, DPI, screen size), the
scaled theme, gui/window_state.py (remembered window place) and gui/components/tables.py
(setup_table: the same alignment for headers and cells, proportional widths, tooltips).
No device, no database."""
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))
sys.path.insert(0, os.path.dirname(__file__))

import pytest

tk = pytest.importorskip('tkinter')
from tkinter import ttk  # noqa: E402

from gui import theme, ui_scale, window_state  # noqa: E402
from gui.components import tables  # noqa: E402
from gui_helpers import new_root  # noqa: E402


@pytest.fixture
def root():
    r = new_root()
    yield r
    try:
        r.destroy()
    except tk.TclError:
        pass


# ---------------------------------------------------------------- ui_scale
def test_screen_size_nudges_the_text_size():
    assert ui_scale.screen_factor(1366) == 0.95          # small laptop at 100 %
    assert ui_scale.screen_factor(1280) == 0.95          # 1920 x 1080 at 150 %
    assert ui_scale.screen_factor(1920) == 1.0
    assert ui_scale.screen_factor(2560) == 1.12          # 2560 x 1440 at 100 %


def test_one_setting_makes_all_text_bigger_or_smaller(root, monkeypatch):
    sizes = {}
    for word in ('small', 'normal', 'large', 'larger'):
        monkeypatch.setenv('NETCOMMAND_UI_TEXT_SIZE', word)
        theme.apply(root)
        sizes[word] = (theme.FONT[1], theme.TABLE_SIZE, theme.mono(9)[1], theme.PAD,
                       theme.TABLE_ROW_HEIGHT)
    assert sizes['normal'] <= sizes['large'] <= sizes['larger']
    assert sizes['larger'][0] > sizes['normal'][0] and sizes['larger'][3] > sizes['normal'][3]
    assert sizes['small'][0] >= ui_scale.MIN_BODY         # never below the readable minimum
    monkeypatch.setenv('NETCOMMAND_UI_TEXT_SIZE', 'enormous')   # unknown word: normal
    assert ui_scale.text_size_setting() == 'normal'


def test_pixel_sizes_follow_the_dpi(root):
    theme.apply(root)
    at_100 = ui_scale.space(8)
    ui_scale._state['dpi'] = 144.0                        # 150 %
    try:
        assert ui_scale.space(8) == round(at_100 * 1.5)
    finally:
        ui_scale.measure(root)


def test_rows_fit_their_font(root):
    theme.apply(root)
    line = tk.font.Font(root=root, family=theme.FONT_FAMILY,
                        size=theme.TABLE_SIZE).metrics('linespace')
    assert theme.TABLE_ROW_HEIGHT > line
    assert ttk.Style(root).lookup('Data.Treeview', 'rowheight') == theme.TABLE_ROW_HEIGHT


# ---------------------------------------------------------------- tables
@pytest.mark.parametrize('key, title, align', [
    ('name', 'Name', 'w'), ('ip', 'IP', 'w'), ('details', 'Details', 'w'),
    ('email', 'Email', 'w'), ('date', 'Date', 'w'),
    ('type', 'Type', 'center'), ('status', 'Status', 'center'), ('managed', 'Managed', 'center'),
    ('role', 'Role', 'center'), ('verified', 'Email verified', 'center'),
    ('locked', 'Lock', 'center'), ('source', 'Source', 'center'),
    ('maximum', 'Max', 'center'), ('sticky', 'Sticky', 'center'),
    ('id', 'ID', 'e'), ('size', 'Size', 'e'),
    # short VLAN numbers are centered (right-aligned they touched the next header)
    ('id', 'VLAN ID', 'center'), ('vlan', 'VLAN', 'center'), ('native', 'Native', 'center')])
def test_alignment_rules(key, title, align):
    assert tables.align_for(key, title) == align


def test_headers_and_cells_share_alignment_and_fill_the_width(root):
    theme.apply(root)
    tree = ttk.Treeview(root, columns=('name', 'ip', 'status'), show='headings',
                        style='Data.Treeview')
    tables.setup_table(tree, [('name', 'Name', 200), ('ip', 'IP', 100),
                              ('status', 'Status', 50)])
    for key in ('name', 'ip', 'status'):
        assert tree.heading(key, 'anchor') == tree.column(key, 'anchor')
    widths = tables.fit_columns(tree, width=1000)
    assert widths['name'] > widths['ip'] > widths['status']          # proportional
    assert sum(widths.values()) == 1000 - ui_scale.space(tables.EDGE)  # no empty gap
    narrow = tables.fit_columns(tree, width=120)
    assert all(w >= ui_scale.space(min(base, tables.MIN_WIDTH))       # never below minimum
               for (k, w), base in zip(narrow.items(), (200, 100, 50)))


def test_a_date_column_always_fits_the_whole_date(root):
    theme.apply(root)
    tree = ttk.Treeview(root, columns=('date', 'details'), show='headings')
    tables.setup_table(tree, [('date', 'Date', 50), ('details', 'Details', 900)])
    needed = tables.table_font(tree).measure(tables.DATE_SAMPLE)       # the real text width
    assert tables.fit_columns(tree, width=700)['date'] >= needed
    short = ttk.Treeview(root, columns=('when', 'what'), show='headings')
    tables.setup_table(short, [('when', 'When', 50), ('what', 'Activity', 100)],
                       min_widths={'when': tables.DATE_SAMPLE_SHORT})
    assert tables.fit_columns(short, width=400)['when'] >= \
        tables.table_font(short).measure(tables.DATE_SAMPLE_SHORT)


def test_columns_at_their_minimum_leave_the_rest_to_share(root):
    """A narrow table: the date keeps its full width, the others share what is left in
    proportion (none is squeezed to nothing while another has room)."""
    theme.apply(root)
    tree = ttk.Treeview(root, columns=('when', 'what', 'detail'), show='headings')
    tables.setup_table(tree, [('when', 'When', 90), ('what', 'Activity', 150),
                              ('detail', 'Details', 240)])
    widths = tables.fit_columns(tree, width=520)
    assert widths['when'] >= tables.table_font(tree).measure(tables.DATE_SAMPLE)
    assert widths['detail'] > widths['what'] > ui_scale.space(tables.MIN_WIDTH)
    assert sum(widths.values()) == 520 - ui_scale.space(tables.EDGE)


def test_the_widest_column_stretches_so_no_empty_strip_is_left(root):
    theme.apply(root)
    tree = ttk.Treeview(root, columns=('name', 'ip', 'status'), show='headings')
    tables.setup_table(tree, [('name', 'Name', 230), ('ip', 'IP', 140), ('status', 'Status', 80)])
    assert tree.column('name', 'stretch') and not tree.column('ip', 'stretch')


def test_clipped_cells_get_their_full_text_as_a_tooltip(root):
    theme.apply(root)
    tree = ttk.Treeview(root, columns=('name', 'details'), show='headings')
    tables.setup_table(tree, [('name', 'Name', 60), ('details', 'Details', 60)])
    long_text = 'Applied 4 commands to SW1; backup R3_20261125_101500.ncbak saved and verified'
    iid = tree.insert('', 'end', values=('R1', long_text))
    tree.pack()
    root.geometry('400x200')
    root.update()
    tables.fit_columns(tree, width=300)
    root.update()
    tip = tree.nc_tooltip
    x = tree.bbox(iid, 'details')
    cell, text = tip.clipped_text(x[0] + 5, x[1] + 5)
    assert cell == (iid, 'details') and text == long_text
    x = tree.bbox(iid, 'name')
    assert tip.clipped_text(x[0] + 5, x[1] + 5) == (None, '')       # it fits: no tooltip
    assert tree.set(iid, 'details') == long_text                      # values never changed


def test_every_table_in_the_workbench_lines_up(root, monkeypatch):
    """All tables of the real main window: the header and its cells use the same alignment."""
    from tkinter import messagebox
    import db_fake
    from desktop_auth.session import Access
    from gui.main_window import build_main_window
    for name in ('showinfo', 'showerror', 'showwarning'):
        monkeypatch.setattr(messagebox, name, lambda *a, **k: None)
    db_fake.reset()
    build_main_window(root, db_fake, demo_store=True, access=Access(None, demo=True))
    trees, stack = [], [root]
    while stack:
        w = stack.pop()
        stack.extend(w.winfo_children())
        if isinstance(w, ttk.Treeview):
            trees.append(w)
    assert len(trees) >= 8
    for tree in trees:
        assert getattr(tree, 'nc_specs', None), f'{tree} is not set up with setup_table'
        for col in tree['columns']:
            assert tree.heading(col, 'anchor') == tree.column(col, 'anchor'), (tree, col)


# ---------------------------------------------------------------- window_state
def test_first_start_fits_the_screen():
    (w, h, x, y), maximized = window_state.first_geometry(1920, 1080, 1.0)
    assert (w, int(1920 * 0.9)) == (w, w) and x == (1920 - w) // 2 and not maximized
    (_g, maximized) = window_state.first_geometry(1366, 768, 1.0)
    assert maximized                                   # small laptop: maximized
    (_g, maximized) = window_state.first_geometry(1920, 1080, 1.5)
    assert maximized                                   # 1280 logical pixels wide


def test_minimum_size_never_exceeds_the_screen():
    assert window_state.minimum_size(1920, 1080) == (1024, 640)
    assert window_state.minimum_size(800, 600) == (800, 510)


def test_the_window_place_is_remembered_and_restored(root, tmp_path, monkeypatch):
    path = tmp_path / 'window.json'
    monkeypatch.setenv('NETCOMMAND_WINDOW_FILE', str(path))
    path.write_text(json.dumps({'geometry': '1100x700+30+40', 'maximized': False}))
    assert window_state.place(root) == 'remembered'
    root.update()
    assert root.geometry().startswith('1100x700')


def test_a_place_on_a_missing_monitor_is_not_used(root, tmp_path, monkeypatch):
    path = tmp_path / 'window.json'
    monkeypatch.setenv('NETCOMMAND_WINDOW_FILE', str(path))
    path.write_text(json.dumps({'geometry': '1100x700+9000+9000', 'maximized': False}))
    monkeypatch.setattr(window_state, 'on_a_monitor', lambda x, y: False)
    assert window_state.place(root) in ('first', 'first-maximized')


def test_the_place_is_saved_on_close(tmp_path, monkeypatch):
    path = tmp_path / 'window.json'
    monkeypatch.setenv('NETCOMMAND_WINDOW_FILE', str(path))
    r = new_root()
    r.geometry('1050x660+20+30')
    r.update()
    window_state.remember(r, delay_ms=1)
    r.event_generate('<Configure>')
    r.after(20)
    r.update()
    r.destroy()
    saved = json.loads(path.read_text())
    assert saved['geometry'].startswith('1050x660') and saved['maximized'] is False


def test_a_broken_state_file_is_ignored(tmp_path, monkeypatch):
    path = tmp_path / 'window.json'
    monkeypatch.setenv('NETCOMMAND_WINDOW_FILE', str(path))
    path.write_text('{not json')
    assert window_state.load() == {}
    assert window_state.parse_geometry('nonsense') is None
