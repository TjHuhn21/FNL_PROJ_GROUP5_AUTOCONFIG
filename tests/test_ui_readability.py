"""UI readability: larger Scan form text, mouse-wheel scrolling of the Overview lists, and
larger command text on Configure. No device, no database server (db_fake)."""
import os, sys
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))
sys.path.insert(0, os.path.dirname(__file__))
import pytest

tk = pytest.importorskip('tkinter')
from tkinter import font as tkfont, ttk  # noqa: E402

import db_fake  # noqa: E402
from gui import theme  # noqa: E402
from gui.components.scroll_frame import WHEEL_STEP, auto_scrollbar, bind_wheel  # noqa: E402
from gui_helpers import new_root  # noqa: E402


@pytest.fixture
def root():
    r = new_root()
    theme.apply(r)
    r.geometry('1000x700+40+40')
    r.update()
    yield r
    r.destroy()


def size_of(font_spec):
    return tkfont.Font(font=font_spec).actual('size')


def wheel(widget, delta):
    widget.event_generate('<MouseWheel>', delta=delta, x=5, y=5)
    widget.update()


def table(parent, rows=60, height=5):
    holder = ttk.Frame(parent)
    holder.grid_columnconfigure(0, weight=1)
    tree = ttk.Treeview(holder, columns=('a',), show='headings', height=height)
    tree.grid(row=0, column=0, sticky='nsew')
    bar = auto_scrollbar(holder, tree)
    bind_wheel(tree)
    for i in range(rows):
        tree.insert('', 'end', values=(f'row {i}',))
    return holder, tree, bar


def first_row(tree):
    return round(tree.yview()[0] * len(tree.get_children()))


# ---------------------------------------------------------------- the wheel helper
def test_wheel_scrolls_only_the_list_under_the_pointer(root):
    a_holder, a, _ = table(root)
    b_holder, b, _ = table(root)
    a_holder.pack(side='left', fill='both', expand=True)
    b_holder.pack(side='left', fill='both', expand=True)
    root.update()
    wheel(a, -WHEEL_STEP)                       # one notch down over list A
    assert first_row(a) == 1                    # exactly one row: no double scroll
    assert first_row(b) == 0                    # list B did not move
    wheel(b, -3 * WHEEL_STEP)
    assert first_row(b) == 3 and first_row(a) == 1


def test_small_wheel_steps_add_up_in_both_directions(root):
    holder, tree, _ = table(root)
    holder.pack(fill='both', expand=True)
    root.update()
    wheel(tree, -2 * WHEEL_STEP)
    assert first_row(tree) == 2
    for _ in range(3):                          # three small steps up (delta 40) = one notch
        wheel(tree, 40)
    assert first_row(tree) == 1                 # Tk's own binding would not move up at all


def test_wheel_does_not_reach_application_wide_handlers(root):
    seen = []
    root.bind_all('<MouseWheel>', lambda e: seen.append(e.widget), add='+')
    holder, tree, _ = table(root)
    holder.pack(fill='both', expand=True)
    root.update()
    wheel(tree, -WHEEL_STEP)
    assert seen == []                           # e.g. a ScrollFrame does not scroll too
    root.unbind_all('<MouseWheel>')


def test_scrollbar_only_when_the_rows_do_not_fit(root):
    few_holder, few, few_bar = table(root, rows=3, height=6)
    many_holder, many, many_bar = table(root, rows=40, height=6)
    few_holder.pack(fill='x')
    many_holder.pack(fill='x')
    root.update()
    assert not few_bar.winfo_manager()
    assert many_bar.winfo_manager() == 'grid'
    many.delete(*many.get_children())           # the rows shrink: the bar goes away again
    root.update()
    assert not many_bar.winfo_manager()


# ---------------------------------------------------------------- the Overview lists
@pytest.fixture
def overview(root):
    from gui.overview_page import OverviewPage
    db_fake.reset()
    ids = [db_fake.save_device(None, {'name': f'R{i}', 'ip': f'10.0.0.{i}', 'type': 'router',
                                      'managed': True, 'status': 'up'}) for i in range(1, 4)]
    for n in range(30):                         # more changes than any list shows at once
        db_fake.add_log(ids[n % 3], 'Configuration', 'success' if n % 2 else 'failed', f'change {n}')
    db_fake.record_status_change(ids[0], 'up', 'down', 'no answer')
    page = OverviewPage(root, lambda key: None, store=db_fake)
    page.pack(fill='both', expand=True)
    root.update()
    page.refresh(force=True)
    root.update()
    return page


def test_overview_lists_load_more_rows_and_scroll(overview):
    from gui import overview_page
    config = overview.lists['config']
    assert len(config['tree'].get_children()) == overview_page.LIST_ROWS
    assert config['bar'].winfo_manager() == 'grid'           # more rows than fit: a scroll bar
    status = overview.lists['status']
    assert not status['bar'].winfo_manager()                 # one row: no scroll bar


def test_each_overview_list_scrolls_independently(overview):
    config, scan = overview.lists['config']['tree'], overview.lists['scan']['tree']
    before_scan = scan.yview()
    wheel(config, -2 * WHEEL_STEP)
    assert config.yview()[0] > 0
    assert scan.yview() == before_scan


def test_overview_keeps_columns_tags_and_starts_at_the_newest_row(overview):
    tree = overview.lists['config']['tree']
    assert tree['columns'] == ('when', 'device', 'result', 'detail')
    first = tree.get_children()[0]
    assert tree.item(first)['values'][3] == 'change 29'      # newest first
    wheel(tree, -3 * WHEEL_STEP)
    overview.refresh(force=True)                             # a reload shows the top again
    overview.update()
    assert tree.yview()[0] == 0.0


# ---------------------------------------------------------------- the Scan form
def test_scan_form_uses_the_larger_form_text(root):
    from gui.scan_tab import ScanTab
    scan = ScanTab(root, db_fake, lambda *a: None, sample_store=True)
    scan.pack(fill='both', expand=True)
    root.update()
    normal = size_of(theme.FONT)
    for name, entry in scan.entries.items():
        assert size_of(entry.cget('font')) == theme.FONT_FORM[1] > normal, name
    style = ttk.Style(root)
    assert size_of(style.lookup('Form.TLabel', 'font')) == theme.FONT_FORM[1]
    assert scan.scan_btn.cget('style') == 'Large.Accent.TButton'
    assert size_of(style.lookup('Large.Accent.TButton', 'font')) == theme.FONT_FORM[1]
    assert all(b.cget('style') == 'Form.TCheckbutton' for b in scan.option_boxes)
    assert size_of(style.lookup('Form.TCheckbutton', 'font')) == theme.FONT_FORM[1]
    # each label above its field, all three fields and the button on one line
    rows = {int(e.grid_info()['row']) for e in scan.entries.values()}
    assert rows == {1} and int(scan.scan_btn.grid_info()['row']) == 1
    # the masked password stays masked
    assert scan.entries['Password'].cget('show') == '*'


def test_scan_form_fits_next_to_the_inspector(root):
    """The login line must fit the page area of a 1200-wide window with the inspector open
    (about 1200 - rail - inspector - margins), so nothing is cut off."""
    from gui.scan_tab import ScanTab
    scan = ScanTab(root, db_fake, lambda *a: None, sample_store=True)
    scan.pack(fill='both', expand=True)
    root.update()
    form = scan.scan_btn.master
    available = 1200 - theme.RAIL_WIDTH - theme.INSPECTOR_WIDTH - 60
    assert form.winfo_reqwidth() <= available
    widest_box = max(b.winfo_reqwidth() for b in scan.option_boxes)
    assert widest_box <= available


# ---------------------------------------------------------------- Configure text
def test_configure_preview_and_session_use_larger_command_text(root):
    from gui.configure_tab import ConfigureTab
    db_fake.reset()
    conf = ConfigureTab(root, db_fake)
    conf.pack(fill='both', expand=True)
    root.update()
    assert size_of(conf.preview.cget('font')) == theme.CODE_SIZE
    assert size_of(conf.preview.tag_cget('header', 'font')) == theme.CODE_SIZE
    assert size_of(conf.session.text.cget('font')) == theme.SESSION_SIZE
    assert size_of(conf.session.text.tag_cget('command', 'font')) == theme.SESSION_SIZE
    assert theme.CODE_SIZE > 10 and theme.SESSION_SIZE > 9      # larger than before
    assert conf.preview.tag_cget('header', 'foreground') == theme.ACCENT   # colors kept


# ---------------------------------------------------------------- larger tables and console
@pytest.fixture
def workbench(root, monkeypatch):
    from tkinter import messagebox
    for name in ('showinfo', 'showerror', 'showwarning'):
        monkeypatch.setattr(messagebox, name, lambda *a, **k: None)
    db_fake.reset()
    from gui.main_window import build_main_window
    refs = build_main_window(root, db_fake, demo_store=True)
    root.update()
    return refs


def test_devices_logs_scan_and_picker_tables_use_the_larger_style(root, workbench):
    style = ttk.Style(root)
    assert size_of(style.lookup('Data.Treeview', 'font')) == theme.TABLE_SIZE > size_of(theme.FONT)
    assert size_of(style.lookup('Data.Treeview.Heading', 'font')) == theme.TABLE_HEADING_SIZE
    assert int(style.lookup('Data.Treeview', 'rowheight')) == theme.TABLE_ROW_HEIGHT
    for tree in (workbench['devices'].tree, workbench['logs'].tree, workbench['scan'].tree,
                 workbench['configure'].picker.tree):
        assert tree.cget('style') == 'Data.Treeview'
    # columns, headings and widths kept/widened (nothing removed)
    assert workbench['devices'].tree['columns'] == ('name', 'ip', 'type', 'status', 'managed')
    assert workbench['logs'].tree['columns'] == ('date', 'device', 'action', 'status', 'details')
    assert workbench['scan'].tree['columns'] == ('name', 'ip', 'type', 'managed', 'source')


def test_logs_search_and_status_filter_are_larger(root, workbench):
    logs = workbench['logs']
    top = logs.winfo_children()[0]
    labels = [w for w in top.winfo_children() if isinstance(w, ttk.Label)]
    assert [w.cget('text') for w in labels] == ['Show:', 'Search:', 'Status:', 'User:']
    assert all(w.cget('style') == 'Form.TLabel' for w in labels)
    entry = next(w for w in top.winfo_children() if isinstance(w, ttk.Entry)
                 and not isinstance(w, ttk.Combobox))
    boxes = [w for w in top.winfo_children() if isinstance(w, ttk.Combobox)]
    assert len(boxes) == 3
    assert {size_of(w.cget('font')) for w in boxes + [entry]} == {theme.FONT_FORM[1]}


def test_console_text_tabs_and_buttons_are_larger(root, workbench):
    console = workbench['console']
    style = ttk.Style(root)
    for text in (console.text, console.config_text, console.events_text):
        assert size_of(text.cget('font')) == theme.CONSOLE_SIZE > 9
    assert console.tabs.cget('style') == 'Console.TNotebook'
    assert size_of(style.lookup('Console.TNotebook.Tab', 'font')) == theme.CONSOLE_TAB_SIZE
    for button in (console.refresh_button, console.clear_button):
        assert button.cget('style') == 'Console.TButton'
    assert size_of(style.lookup('Console.TButton', 'font')) == theme.CONSOLE_TAB_SIZE
    # the colors are kept
    assert console.text.tag_cget('error', 'foreground') == theme.DANGER
    assert console.text.tag_cget('source', 'foreground') == theme.ACCENT


# ---------------------------------------------------------------- Refresh / Clear per tab
def show_tab(console, index):
    console.tabs.select(index)
    console.update()


def test_console_tab_refresh_shows_waiting_lines_and_clear_empties_it(root, workbench):
    console = workbench['console']
    show_tab(console, 0)
    console.flush()
    console.log('test', 'waiting line', 'ok')            # queued, not on screen yet
    assert 'waiting line' not in console.text.get('1.0', 'end')
    console.refresh_button.invoke()
    assert 'waiting line' in console.text.get('1.0', 'end')
    console.clear_button.invoke()
    assert console.text.get('1.0', 'end').strip() == '' and console.lines == []


def test_config_log_tab_refresh_and_clear_without_deleting_anything(root, workbench):
    console = workbench['console']
    did = db_fake.save_device(None, {'name': 'R1', 'ip': '10.0.0.1', 'type': 'router',
                                     'managed': True, 'status': 'up'})
    console.log('app', 'console line stays', 'info')
    console.flush()
    show_tab(console, 1)                                  # opening the tab loads it
    db_fake.add_log(did, 'Configuration', 'failed', 'Wrong username or password.')
    console.refresh_button.invoke()
    assert 'Wrong username or password.' in console.config_text.get('1.0', 'end')
    console.clear_button.invoke()
    shown = console.config_text.get('1.0', 'end')
    assert 'Wrong username' not in shown and 'nothing was deleted' in shown
    assert len(db_fake.get_logs()) == 1                   # the stored log is untouched
    assert 'console line stays' in console.text.get('1.0', 'end')   # other tab untouched
    console.refresh_button.invoke()
    assert 'Wrong username or password.' in console.config_text.get('1.0', 'end')


def test_status_events_tab_refresh_and_clear_without_deleting_anything(root, workbench):
    console = workbench['console']
    did = db_fake.save_device(None, {'name': 'SW1', 'ip': '10.0.0.2', 'type': 'switch',
                                     'managed': True, 'status': 'up'})
    show_tab(console, 2)
    db_fake.record_status_change(did, 'up', 'down', 'no answer')
    console.refresh_button.invoke()
    assert 'up -> down' in console.events_text.get('1.0', 'end')
    console.clear_button.invoke()
    shown = console.events_text.get('1.0', 'end')
    assert 'up -> down' not in shown and 'nothing was deleted' in shown
    assert len(db_fake.get_events()) == 1                 # the status history is untouched
    show_tab(console, 0)
    show_tab(console, 2)                                  # opening the tab again reloads it
    assert 'up -> down' in console.events_text.get('1.0', 'end')
