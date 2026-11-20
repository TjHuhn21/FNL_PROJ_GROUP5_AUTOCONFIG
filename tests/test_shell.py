"""The workbench shell: rail navigation, resizable panels, command strip,
inspector, operations console and status bar.
db_fake stands in for the database; message boxes are captured, never shown."""
import os, sys, threading
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))
sys.path.insert(0, os.path.dirname(__file__))
import pytest

tk = pytest.importorskip('tkinter')
from tkinter import messagebox

import db_fake
from gui.components import icons
from gui_helpers import new_root

EXPECTED = [('dashboard', 'Overview'), ('scan', 'Scan'), ('devices', 'Devices'),
            ('topology', 'Topology'), ('findings', 'Findings'), ('configure', 'Configure'),
            ('logs', 'Logs')]


def make_app(monkeypatch, demo_store):
    root = new_root()
    root.geometry('1200x800')
    shown = []
    for name in ('showinfo', 'showerror', 'showwarning'):
        monkeypatch.setattr(messagebox, name, lambda t, m, _n=name, **k: shown.append((_n, t, m)))
    db_fake.reset()
    from gui.main_window import build_main_window
    refs = build_main_window(root, db_fake, demo_store=demo_store)
    root.update()
    return root, refs, shown


@pytest.fixture
def app(monkeypatch):
    root, refs, _ = make_app(monkeypatch, demo_store=True)
    yield root, refs
    root.destroy()


@pytest.fixture
def real_app(monkeypatch):
    root, refs, _ = make_app(monkeypatch, demo_store=False)
    yield root, refs
    root.destroy()


def visible(root, widget):
    root.update()
    return bool(widget.winfo_ismapped())


def click(root, widget):
    """A real mouse click on a widget and its inner parts (CustomTkinter draws a
    label as a canvas plus a label, and both carry the click binding)."""
    root.update()
    for w in [widget] + list(widget.winfo_children()):
        w.event_generate('<Button-1>', x=5, y=5)
    root.update()


def add(name, ip, managed=True, status='up', kind='switch'):
    did = db_fake.upsert_device({'name': name, 'ip': ip, 'type': kind, 'managed': managed,
                                 'status': status})
    return did


# ---------------------------------------------------------------- rail navigation
def test_opens_on_overview_with_seven_rail_items_in_order(app):
    root, r = app
    nav = r['nav']
    assert [(k, item.label_text) for k, item in nav.items.items()] == EXPECTED
    assert r['current_page']() == 'dashboard' and nav.active == 'dashboard'
    assert visible(root, r['dashboard'])
    assert not any(visible(root, r[k]) for k, _ in EXPECTED[1:])
    assert [k for k, item in nav.items.items() if item._active] == ['dashboard']


def test_clicking_each_rail_item_shows_only_that_page(app):
    root, r = app
    for key, _ in EXPECTED:
        click(root, r['nav'].items[key].text)
        assert r['current_page']() == key and r['nav'].active == key
        assert visible(root, r[key])
        assert not any(visible(root, r[k]) for k, _ in EXPECTED if k != key), key


def test_pages_reload_their_data_when_opened(app):
    root, r = app
    did = add('SW9', '10.0.0.9')
    r['show_page']('devices')
    assert len(r['devices'].tree.get_children()) == 1
    db_fake.add_log(did, 'Configuration', 'success', 'ok')
    r['show_page']('logs')
    assert len(r['logs'].tree.get_children()) == 1
    r['show_page']('configure')
    assert [d['name'] for d in r['configure'].devices] == ['SW9']
    r['show_page']('topology')
    assert r['topology'].img is not None                 # the existing matplotlib map still draws


def test_opening_the_page_already_shown_does_not_reload_it(app):
    root, r = app
    calls = []
    original = r['devices'].refresh
    r['devices'].refresh = lambda: (calls.append(1), original())
    r['show_page']('devices'); r['show_page']('devices')
    assert len(calls) == 1


def test_send_to_configure_switches_page_and_is_logged(app):
    root, r = app
    r['findings'].send(['line vty 0 4', 'transport input ssh'], 'SW1')
    assert r['current_page']() == 'configure' and r['nav'].active == 'configure'
    assert r['configure'].commands_from_preview() == ['line vty 0 4', 'transport input ssh']
    r['console'].flush()
    assert any(s == 'findings' and 'SW1' in m for _, s, m, _ in r['console'].lines)


def test_overview_shows_stored_data_and_opens_topology(app):
    root, r = app
    assert 'PLACEHOLDER' not in r['dashboard'].message.cget('text')
    assert r['dashboard'].data is not None                    # loaded from the store
    r['dashboard'].open_topology.invoke()
    assert r['current_page']() == 'topology'


def test_without_an_icon_font_the_rail_shows_text_only(monkeypatch):
    monkeypatch.setattr(icons, 'ICON_FONTS', ('No Such Icon Font',))
    monkeypatch.setattr(icons, '_family_cache', {})
    root, r, _ = make_app(monkeypatch, demo_store=True)
    try:
        assert all(item.icon is None for item in r['nav'].items.values())
        assert [i.text.cget('text') for i in r['nav'].items.values()] == [l for _, l in EXPECTED]
        click(root, r['nav'].items['devices'].text)
        assert r['current_page']() == 'devices'
    finally:
        root.destroy()


def test_every_page_has_an_icon():
    assert set(icons.GLYPHS) == {k for k, _ in EXPECTED}


# ---------------------------------------------------------------- resizable panels
def test_workbench_panels_can_be_resized(app):
    root, r = app
    upper, outer = r['panels']['upper'], r['panels']['outer']
    assert len(upper.panes()) == 2 and len(outer.panes()) == 2   # page|inspector over console
    root.update()
    upper.sashpos(0, 400); outer.sashpos(0, 300); root.update()
    assert abs(upper.sashpos(0) - 400) <= 2 and abs(outer.sashpos(0) - 300) <= 2


# ---------------------------------------------------------------- command strip
def test_command_strip_finds_devices_by_name_and_ip(app):
    root, r = app
    add('SW1', '10.0.0.1'); add('SW2', '10.0.0.2'); add('R1', '10.0.9.1', kind='router')
    strip = r['command']
    strip.set_text('SW')
    names = [t.split()[0] for k, t, _ in strip.update_suggestions() if k == 'device']
    assert names == ['SW1', 'SW2']
    strip.set_text('10.0.9')
    assert [t.split()[0] for k, t, _ in strip.update_suggestions() if k == 'device'] == ['R1']
    strip.set_text('zzz-no-such')
    assert strip.update_suggestions() == []


def test_choosing_a_device_shows_it_in_the_inspector_and_console(app):
    root, r = app
    did = add('SW1', '10.0.0.1')
    strip = r['command']
    strip.set_text('SW1')
    items = strip.update_suggestions()
    strip.run([i for i, (k, _, _) in enumerate(items) if k == 'device'][0])
    assert r['inspector'].device['id'] == did
    assert r['inspector'].fields['IP address'].cget('text') == '10.0.0.1'
    assert strip.get_text() == ''
    r['console'].flush()
    assert any(s == 'find' and 'SW1' in m for _, s, m, _ in r['console'].lines)


def test_operation_words_open_their_pages(app):
    root, r = app
    strip = r['command']
    for word, key in [('dev', 'devices'), ('scan', 'scan'), ('map', 'topology'),
                      ('review', 'findings'), ('logs', 'logs'), ('overview', 'dashboard')]:
        strip.set_text(word)
        items = strip.update_suggestions()
        assert items[0][0] == 'op', word
        strip.run(0)
        assert r['current_page']() == key, word


def test_configure_with_a_device_name_selects_it_on_the_configure_page(app):
    root, r = app
    add('SW1', '10.0.0.1'); add('SW3', '10.0.0.3', managed=False)
    strip = r['command']
    strip.set_text('configure SW')
    labels = [t for _, t, _ in strip.update_suggestions()]
    assert labels == ['Configure SW1']                      # unmanaged SW3 is not offered
    strip.run(0)
    assert r['current_page']() == 'configure'
    assert r['configure'].selected_device()['name'] == 'SW1'


def test_command_strip_still_offers_operations_when_the_database_fails(app):
    root, r = app

    class Broken:
        def get_devices(self, *a, **k):
            raise RuntimeError('database down')
    r['command'].store = Broken()
    r['command'].set_text('dev')
    assert [k for k, _, _ in r['command'].update_suggestions()] == ['op']


# ---------------------------------------------------------------- inspector
def test_inspector_starts_empty(app):
    _, r = app
    assert r['inspector'].device is None


def test_inspector_shows_the_real_record_and_never_reads_the_login(app, monkeypatch):
    root, r = app
    did = add('SW1', '10.0.0.1', status='down')
    db_fake.save_credentials(did, 'admin', 'secret')
    monkeypatch.setattr(db_fake, 'get_credentials',
                        lambda *a: (_ for _ in ()).throw(AssertionError('login was read')))
    insp = r['inspector']
    insp.show_device(did)
    assert insp.fields['IP address'].cget('text') == '10.0.0.1'
    assert insp.fields['Type'].cget('text') == 'switch'
    assert 'down' in insp.status_label.cget('text')
    assert 'secret' not in str([w.cget('text') for w in insp.fields.values()])


def test_inspector_buttons_open_devices_and_configure(app):
    root, r = app
    did = add('SW1', '10.0.0.1'); add('SW2', '10.0.0.2')
    insp = r['inspector']
    insp.show_device(did)
    insp.devices_button.invoke()
    assert r['current_page']() == 'devices' and r['devices'].search.get() == 'SW1'
    assert len(r['devices'].tree.get_children()) == 1
    insp.configure_button.invoke()
    assert r['current_page']() == 'configure'
    assert r['configure'].selected_device()['name'] == 'SW1'


def test_inspector_disables_configure_for_unmanaged_and_handles_deleted(app):
    root, r = app
    did = add('SW3', '10.0.0.3', managed=False)
    insp = r['inspector']
    insp.show_device(did)
    assert insp.configure_button.cget('state') == 'disabled'
    from gui import theme                                    # and it must not LOOK clickable
    assert insp.configure_button.cget('fg_color') != theme.ACCENT
    db_fake.delete_device(did)
    assert insp.show_device(did) is None and insp.device is None


# ---------------------------------------------------------------- console and status
def test_console_reports_the_data_source(app, real_app):
    _, demo = app
    _, real = real_app
    demo['console'].flush(); real['console'].flush()
    assert 'Sample mode' in demo['console'].lines[0][2]
    assert 'Connected' in real['console'].lines[0][2]
    assert 'sample mode' in demo['source_label'].cget('text')
    assert 'database connected' in real['source_label'].cget('text')


def test_console_accepts_messages_from_worker_threads(app):
    _, r = app
    console = r['console']
    t = threading.Thread(target=lambda: console.log('test', 'from a worker thread', 'ok'))
    t.start(); t.join()
    console.flush()
    assert console.lines[-1][1:] == ('test', 'from a worker thread', 'ok')
    assert 'from a worker thread' in console.text.get('1.0', 'end')
    console.clear()
    assert console.lines == [] and console.text.get('1.0', 'end').strip() == ''


def test_config_log_tab_shows_the_existing_configuration_log(app):
    _, r = app
    console = r['console']
    assert console.refresh_config_log() == []
    assert 'No configuration changes' in console.config_text.get('1.0', 'end')
    did = add('SW1', '10.0.0.1')
    db_fake.add_log(did, 'Configuration', 'failed', 'Wrong username or password.')
    rows = console.refresh_config_log()
    assert len(rows) == 1
    text = console.config_text.get('1.0', 'end')
    assert 'SW1' in text and 'failed' in text and 'Wrong username or password.' in text


def test_status_bar_counts_registered_devices(app):
    root, r = app
    assert r['status_devices'].cget('text') == '0 registered devices'
    add('SW1', '10.0.0.1')
    r['show_page']('devices')
    assert r['status_devices'].cget('text') == '1 registered device'
