"""The layout follows the window (part C) and dialogs open in the right place (part D):
button rows wrap instead of being cut off, the Overview reflows (4 / 2 / 1 cards) and
scrolls when it is too tall, the inspector hides itself on a narrow window, the rail shows
icons only on a short one, the bottom panel keeps its limits and its remembered size, and
dialogs are centered on their window and never larger than the screen.
No device, no database."""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))
sys.path.insert(0, os.path.dirname(__file__))

import pytest

tk = pytest.importorskip('tkinter')
from tkinter import ttk  # noqa: E402

import db_fake  # noqa: E402
from gui import theme, ui_scale, window_state  # noqa: E402
from gui_helpers import new_root  # noqa: E402


def settle(root, n=25):
    for _ in range(n):
        root.update()
        root.after(10)


@pytest.fixture
def root():
    r = new_root()
    theme.apply(r)
    yield r
    try:
        r.destroy()
    except tk.TclError:
        pass


@pytest.fixture
def workbench(root, monkeypatch):
    from tkinter import messagebox
    from desktop_auth.session import Access
    from gui.main_window import build_main_window
    for name in ('showinfo', 'showerror', 'showwarning'):
        monkeypatch.setattr(messagebox, name, lambda *a, **k: None)
    db_fake.reset()
    root.geometry('1600x900+0+0')
    refs = build_main_window(root, db_fake, demo_store=True, access=Access(None, demo=True))
    settle(root)
    return refs


def resize(root, refs, w, h):
    root.geometry(f'{int(w * ui_scale.dpi_scale())}x{int(h * ui_scale.dpi_scale())}+0+0')
    settle(root)
    refs['adapt_layout']()
    settle(root)


# ---------------------------------------------------------------- wrapping rows
def test_a_row_of_controls_wraps_instead_of_being_cut_off(root):
    from gui.components.wrap_frame import WrapFrame
    bar = WrapFrame(root)
    bar.pack(fill='x')
    buttons = [bar.add(ttk.Button(bar, text=f'Button number {i}')) for i in range(6)]
    root.geometry('1400x200')
    settle(root)
    bar.relayout()
    assert bar.row_count == 1
    root.geometry('360x200')
    settle(root)
    bar.relayout()
    assert bar.row_count >= 3
    assert all(b.winfo_ismapped() for b in buttons)          # nothing is hidden


def test_push_right_keeps_buttons_on_the_right_while_they_fit(root):
    from gui.components.wrap_frame import WrapFrame
    bar = WrapFrame(root)
    bar.pack(fill='x')
    bar.add(ttk.Label(bar, text='Search:'))
    right = bar.add(ttk.Button(bar, text='Add'), push_right=True)
    root.geometry('900x100')
    settle(root)
    bar.relayout()
    settle(root)
    assert right.winfo_rootx() - root.winfo_rootx() > 600


# ---------------------------------------------------------------- the main window
def test_the_inspector_hides_on_a_narrow_window_and_can_be_brought_back(root, workbench):
    refs = workbench
    resize(root, refs, 1600, 900)
    assert refs['inspector_shown']()
    resize(root, refs, 1200, 800)
    assert not refs['inspector_shown']()
    refs['inspector_toggle'].invoke()                       # 'Show inspector'
    settle(root)
    assert refs['inspector_shown']()
    refs['show_page']('devices')                            # stays: the user asked for it
    assert refs['inspector_shown']()
    resize(root, refs, 1600, 900)
    assert refs['inspector_shown']()


def test_the_rail_shows_icons_only_on_a_short_window(root, workbench):
    refs = workbench
    if not any(i.icon is not None for i in refs['nav'].items.values()):
        pytest.skip('no icon font on this computer: the rail keeps its labels')
    resize(root, refs, 1400, 900)
    assert not refs['nav'].compact
    resize(root, refs, 1400, 640)
    assert refs['nav'].compact
    item = next(iter(refs['nav'].items.values()))
    assert not item.text.winfo_ismapped()                   # the label is a tooltip now


def test_the_overview_reflows_with_the_width(root, workbench):
    page = workbench['dashboard']
    for width, cards in ((1500, 4), (800, 2), (420, 1)):
        page.reflow(int(width * ui_scale.dpi_scale()))
        settle(root, 5)
        rows = {c['frame'].grid_info()['row'] for c in page.cards.values()}
        assert len(rows) == 4 // cards, (width, rows)


def test_the_overview_scrolls_when_the_window_is_short(root, workbench):
    refs = workbench
    refs['show_page']('dashboard')
    resize(root, refs, 1100, 640)
    refs['dashboard'].reflow(int(500 * ui_scale.dpi_scale()))   # one card per row: tall
    settle(root)
    assert refs['dashboard'].scroll.bar_shown


def test_the_bottom_panel_keeps_its_limits_and_is_remembered(root, workbench):
    refs = workbench
    console = refs['console']
    outer = console.master
    height = outer.winfo_height()
    outer.sashpos(0, height - 5)                            # dragged almost shut
    outer.event_generate('<ButtonRelease-1>')
    settle(root)
    assert height - outer.sashpos(0) >= ui_scale.space(90) - 2
    saved = window_state.get_setting('console_heights')
    assert saved and saved.get('dashboard', 0) >= ui_scale.space(90) - 2


# ---------------------------------------------------------------- no flicker while resizing
def test_the_inspector_does_not_flip_near_its_limit(root, workbench):
    """Hidden below 1400 px; shown again only above 1400 + LAYOUT_HYSTERESIS."""
    from gui import main_window
    refs = workbench
    resize(root, refs, 1600, 900)
    resize(root, refs, 1390, 900)
    assert not refs['inspector_shown']()
    resize(root, refs, main_window.INSPECTOR_AUTO_HIDE_BELOW + 20, 900)   # just above
    assert not refs['inspector_shown']()                    # still hidden: no flicker
    resize(root, refs, main_window.INSPECTOR_AUTO_HIDE_BELOW
           + main_window.LAYOUT_HYSTERESIS + 20, 900)
    assert refs['inspector_shown']()


def test_a_shown_scroll_bar_stays_until_there_is_room_to_spare(root):
    """Showing the bar narrows the content (which can make it shorter): it must not then
    disappear at once and come back, again and again."""
    from gui.components.scroll_frame import SCROLL_HYSTERESIS, ScrollFrame
    root.geometry('400x300')
    box = ScrollFrame(root, fill_height=True)
    box.pack(fill='both', expand=True)
    filler = tk.Frame(box.inner, height=320, width=10)
    filler.pack()
    settle(root)
    assert box.bar_shown
    view = box.canvas.winfo_height()
    filler.configure(height=view - SCROLL_HYSTERESIS // 2)  # fits, but only just
    settle(root)
    assert box.bar_shown                                    # kept: no on/off flicker
    filler.configure(height=view - SCROLL_HYSTERESIS * 3)   # clearly fits
    settle(root)
    assert not box.bar_shown


def test_a_height_change_does_not_refit_the_columns(root):
    from gui.components import tables
    tree = ttk.Treeview(root, columns=('name', 'ip'), show='headings')
    tables.setup_table(tree, [('name', 'Name', 200), ('ip', 'IP', 100)])
    tree.pack(fill='both', expand=True)
    root.geometry('800x300')
    settle(root, 40)
    before = (tree.column('name', 'width'), getattr(tree, 'nc_fitted_width', None))
    calls = []
    real = tables.fit_columns
    tables.fit_columns = lambda t, width=None: calls.append(1) or real(t, width)
    try:
        root.geometry('800x500')                            # taller, same width
        settle(root, 40)
    finally:
        tables.fit_columns = real
    assert calls == [] and tree.column('name', 'width') == before[0]


# ---------------------------------------------------------------- dialogs
def test_dialogs_are_centered_on_their_window_and_fit_the_screen(root):
    from gui.components.dialogs import place_window
    root.geometry('1000x700+100+50')
    settle(root)
    win = tk.Toplevel(root)
    ttk.Label(win, text='A dialog').pack(padx=40, pady=40)
    w, h, x, y = place_window(win, root)
    centre_x = root.winfo_rootx() + root.winfo_width() // 2
    assert abs((x + w // 2) - centre_x) <= 2
    big = tk.Toplevel(root)
    w, h, x, y = place_window(big, root, size=(99999, 99999))
    assert w <= root.winfo_screenwidth() and h <= root.winfo_screenheight()
    assert x >= 0 and y >= 0


def test_no_window_has_a_fixed_pixel_size():
    import re
    gui = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'gui')
    for folder, _dirs, files in os.walk(gui):
        for name in files:
            if name.endswith('.py'):
                text = open(os.path.join(folder, name), encoding='utf-8').read()
                assert not re.search(r"\.geometry\('\d+x\d+", text), name
