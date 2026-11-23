"""The Overview page: real figures from the store (db_fake here), empty states, refresh
rules, database errors and role-filtered quick actions. No device, no database server."""
import os, sys
from datetime import datetime, timedelta
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))
sys.path.insert(0, os.path.dirname(__file__))
import pytest

import db_fake
from gui import overview_page
from gui.overview_page import summarize, when_text
from store_errors import DatabaseUnavailable


@pytest.fixture(autouse=True)
def empty_store():
    db_fake.reset()


def populate():
    ids = {}
    for name, ip, kind, status in [('R1', '10.0.0.1', 'router', 'up'),
                                   ('SW1', '10.0.0.2', 'switch', 'up'),
                                   ('SW2', '10.0.0.3', 'switch', 'up'),     # goes down below
                                   ('X1', '10.0.0.4', 'unknown', 'up')]:
        ids[name] = db_fake.save_device(None, {'name': name, 'ip': ip, 'type': kind,
                                               'managed': name != 'X1', 'status': status})
    for rule, severity, device in [('telnet_enabled', 'high', 'SW1'),
                                   ('no_password_encryption', 'medium', 'R1'),
                                   ('no_port_security', 'medium', 'SW2'),
                                   ('trunk_all_vlans', 'low', 'SW2')]:
        db_fake.add_finding({'device': device, 'rule': rule, 'severity': severity, 'message': 'm',
                             'commands': []})
    db_fake.add_log(ids['R1'], 'Configuration', 'success', 'Applied and verified. Backup: a')
    db_fake.add_log(ids['SW1'], 'Configuration', 'failed', 'Wrong username or password.')
    db_fake.record_status_change(ids['SW2'], 'up', 'down', 'no answer to ping or TCP 22')
    return ids


# ---------------------------------------------------------------- the data
def test_empty_store_gives_zeros_and_empty_lists():
    d = summarize(db_fake)
    assert (d['devices'], d['routers'], d['switches'], d['unknown']) == (0, 0, 0, 0)
    assert (d['online'], d['offline'], d['findings'], d['changes']) == (0, 0, 0, 0)
    assert d['recent_changes'] == [] and d['recent_events'] == [] and d['recent_activity'] == []
    assert d['review_saved_at'] is None


def test_populated_store_is_counted_exactly():
    populate()
    d = summarize(db_fake)
    assert (d['devices'], d['routers'], d['switches'], d['unknown'], d['managed']) == (4, 1, 2, 1, 3)
    assert (d['online'], d['offline']) == (3, 1)                 # the stored status, not a guess
    assert (d['findings'], d['high'], d['medium'], d['low']) == (4, 1, 2, 1)
    assert (d['changes'], d['changes_ok'], d['changes_failed']) == (2, 1, 1)
    assert [l['device'] for l in d['recent_changes']] == ['SW1', 'R1']          # newest first
    assert [(e['device'], e['previous'], e['kind']) for e in d['recent_events']] == \
        [('SW2', 'up', 'down')]
    assert {a['detail'].split(' ')[0] for a in d['recent_activity']} == {'R1', 'SW1', 'SW2', 'X1'}
    assert all(a['what'] == 'Device registered' for a in d['recent_activity'])


def test_findings_of_deleted_devices_are_not_counted():
    ids = populate()
    db_fake.delete_device(ids['SW2'])
    d = summarize(db_fake)
    assert d['devices'] == 3 and (d['findings'], d['medium'], d['low']) == (2, 1, 0)


def test_this_sessions_scans_are_listed_with_the_registrations():
    populate()
    later = datetime.now() + timedelta(minutes=1)
    history = [{'kind': 'scan', 'seed': '10.0.0.1', 'devices': 4, 'managed': 1, 'links': 3,
                'sample': False, 'when': later},
               {'kind': 'scan', 'seed': '10.9.9.9', 'failed': True, 'when': later},
               {'kind': 'approval', 'count': 1, 'when': later}]
    d = summarize(db_fake, history)
    texts = [(a['what'], a['detail']) for a in d['recent_activity']]
    assert ('Scan (this session)', 'seed 10.0.0.1: 4 devices (1 managed), 3 links') in texts
    assert ('Scan (this session)', 'seed 10.9.9.9: failed (see the Scan page)') in texts
    assert ('Approval (this session)', '1 device saved') in texts
    assert len(d['recent_activity']) == 7       # 3 session entries + 4 registrations (all fit)


def test_when_text():
    today = datetime(2026, 11, 20, 14, 2).date()
    assert when_text(datetime(2026, 11, 20, 14, 2), today) == '2:02 PM'
    assert when_text(datetime(2026, 11, 19, 9, 5), today) == 'Nov 19 9:05 AM'
    assert when_text(None) == '' and when_text('not a date') == ''


def test_format_time_is_12_hour():
    from gui.timefmt import format_date_time, format_time
    assert format_time(datetime(2026, 11, 24, 3, 19, 39)) == '3:19 AM'
    assert format_time(datetime(2026, 11, 24, 3, 19, 39), seconds=True) == '3:19:39 AM'
    assert format_time(datetime(2026, 11, 24, 0, 5)) == '12:05 AM'          # midnight
    assert format_time(datetime(2026, 11, 24, 12, 0)) == '12:00 PM'         # noon
    assert format_time(datetime(2026, 11, 24, 23, 59, 1), True) == '11:59:01 PM'
    assert format_time(None) == ''
    assert format_date_time(datetime(2026, 11, 24, 15, 4, 5), True) == '2026-11-24 3:04:05 PM'


def age_logs(hours):
    """Move every stored log entry back in time (display tests only)."""
    for log in db_fake._logs:
        log['created_at'] -= timedelta(hours=hours)


def test_configuration_changes_count_only_the_last_24_hours():
    ids = populate()
    age_logs(24 * 3)                                       # the two from populate: 3 days old
    db_fake.add_log(ids['R1'], 'Configuration', 'failed', 'now')
    d = summarize(db_fake)
    assert (d['changes'], d['changes_ok'], d['changes_failed']) == (1, 0, 1)
    assert [l['details'] for l in d['recent_changes']] == ['now']
    assert db_fake.count_logs() == 3 and len(db_fake.get_logs()) == 3     # all still stored


def test_status_is_broken_down_by_the_types_that_exist():
    populate()                                     # R1 up, SW1 up, SW2 down, X1 up
    assert summarize(db_fake)['by_type'] == [('Routers', 1, 0), ('Switches', 1, 1),
                                             ('Unknown', 1, 0)]
    db_fake.reset()
    db_fake.save_device(None, {'name': 'S', 'ip': '10.0.0.9', 'type': 'switch', 'status': 'up'})
    assert summarize(db_fake)['by_type'] == [('Switches', 1, 0)]        # only existing types


def test_a_review_that_stored_nothing_is_still_shown_with_its_time():
    when = datetime.now()
    found = [{'device': 'R1', 'rule': 'r', 'severity': 'high', 'message': 'm', 'commands': []}]
    d = summarize(db_fake, last_review={'at': when, 'findings': found})
    assert (d['findings'], d['high'], d['review_saved_at']) == (1, 1, when)
    d = summarize(db_fake, last_review={'at': when, 'findings': []})     # found nothing
    assert (d['findings'], d['review_saved_at']) == (0, when)


def test_sample_mode_review_reaches_the_overview():
    """The Findings bug: a sample-mode review was never stored, so the Overview said 0."""
    import queue
    import sample_data, services
    from gui.findings_tab import _review_worker
    for dev in sample_data.DEVICES:
        db_fake.upsert_device(dict(dev))
    results = queue.Queue()
    _review_worker(lambda: services.collect_review_inputs(db_fake, True), db_fake, True, results)
    kind, findings, *_rest = results.get()
    assert kind == 'done' and findings
    d = summarize(db_fake)
    assert d['findings'] == len(findings) and d['review_saved_at'] is not None


def test_database_mode_never_stores_sample_findings():
    import queue
    from gui.findings_tab import _review_worker
    calls, results = [], queue.Queue()

    class Store:
        def replace_findings(self, f):
            calls.append(f)
    sample = ([{'name': 'R1'}], [], {}, [], 'SAMPLE DATA (demo)')
    _review_worker(lambda: sample, Store(), False, results)
    assert results.get()[0] == 'done' and calls == []


# ---------------------------------------------------------------- the page
tk = pytest.importorskip('tkinter')


class CountingStore:
    """db_fake, counting the reads, optionally failing like a database outage."""
    def __init__(self):
        self.reads, self.down = 0, False

    def __getattr__(self, name):
        real = getattr(db_fake, name)

        def call(*a, **k):
            if self.down:
                raise DatabaseUnavailable('The database is not available.')
            self.reads += 1
            return real(*a, **k)
        return call


@pytest.fixture
def page(monkeypatch):
    from gui_helpers import new_root
    from gui import theme
    from gui.overview_page import OverviewPage
    root = new_root()
    theme.apply(root)
    store, opened = CountingStore(), []
    p = OverviewPage(root, opened.append, store=store,
                     can_open=lambda key: key not in ('scan', 'configure'))
    p.pack(fill='both', expand=True)
    root.update()
    yield root, p, store, opened
    root.destroy()


def theme_danger():
    from gui import theme
    return theme.DANGER


def card(p, key):
    c = p.cards[key]
    return c['value'].cget('text'), c['detail'].cget('text')


def test_empty_database_shows_friendly_empty_states(page):
    root, p, store, _ = page
    p.refresh(force=True)
    assert card(p, 'devices') == ('0', 'No devices registered yet.')
    assert card(p, 'findings')[1] == 'No review saved yet.'
    assert card(p, 'changes') == ('0', 'No configuration changes in the last 24 hours.')
    for key, text in overview_page.NONE_YET.items():
        assert p.lists[key]['empty'].cget('text') == text
        assert p.lists[key]['empty'].winfo_manager() and not p.lists[key]['holder'].winfo_manager()


def test_populated_database_fills_cards_and_lists(page):
    root, p, store, _ = page
    populate()
    p.refresh(force=True)
    assert card(p, 'devices') == ('4', '1 routers  ·  2 switches  ·  1 unknown')
    assert card(p, 'status') == ('▲ 3', '●  3 online    ■  1 offline')
    assert p.cards['status']['down'].cget('text') == '▼ 1'
    types = p.cards['status']['types']
    cell = {(int(w.grid_info()['row']), int(w.grid_info()['column'])): w
            for w in types.winfo_children()}
    assert [cell[(r, 0)].cget('text') for r in range(3)] == ['Routers', 'Switches', 'Unknown']
    assert cell[(1, 2)].cget('text') == '1 down'
    assert str(cell[(1, 2)].cget('foreground')) == theme_danger()           # down > 0: red
    assert str(cell[(0, 2)].cget('foreground')) != theme_danger()           # 0 down: not red
    assert card(p, 'findings') == ('4', '4 findings  ·  1 high  ·  2 medium  ·  1 low')
    assert card(p, 'changes') == ('2', '1 successful  ·  1 failed  ·  last 24 hours')
    config = p.lists['config']['tree']
    rows = [config.item(i)['values'] for i in config.get_children()]
    assert [r[1:3] for r in rows] == [['SW1', 'failed'], ['R1', 'success']]
    assert config.item(config.get_children()[0])['tags'] == ['failed']
    status = p.lists['status']['tree']
    assert status.item(status.get_children()[0])['values'][1:3] == ['SW2', 'up → down']
    assert 'Updated' in p.updated.cget('text')


@pytest.mark.parametrize('statuses, up, down, tip', [
    (['up'] * 5, ('▲ 5', 'SUCCESS'), None, '5 devices up, 0 devices down'),
    (['down'] * 5, ('▼ 5', 'DANGER'), None, '0 devices up, 5 devices down'),
    (['up'] * 3 + ['down'] * 2, ('▲ 3', 'SUCCESS'), '▼ 2', '3 devices up, 2 devices down'),
    ([], ('—', 'TEXT_MUTED'), None, 'No devices detected')])
def test_status_indicator_uses_coloured_arrows(page, statuses, up, down, tip):
    from gui import theme
    root, p, store, _ = page
    for i, status in enumerate(statuses):
        db_fake.save_device(None, {'name': f'D{i}', 'ip': f'10.0.1.{i + 1}', 'type': 'switch',
                                   'status': status})
    p.refresh(force=True)
    root.update()
    s = p.cards['status']
    assert s['value'].cget('text') == up[0]
    assert str(s['value'].cget('foreground')) == getattr(theme, up[1])
    assert s['value'].cget('font') == s['down'].cget('font') == p.cards['devices']['value'].cget('font')
    if down:
        assert s['down'].winfo_manager() and s['down'].cget('text') == down
        assert str(s['down'].cget('foreground')) == theme.DANGER
    else:
        assert not s['down'].winfo_manager()
    assert s['tooltip'].text == tip
    if not statuses:
        assert s['detail'].cget('text') == 'No devices detected'


def test_opening_the_page_again_does_not_query_again_while_fresh(page):
    root, p, store, _ = page
    p.refresh(force=True)
    reads = store.reads
    p.refresh()                                  # shown again within FRESH_SECONDS
    assert store.reads == reads
    p.loaded_at -= overview_page.FRESH_SECONDS + 1
    p.refresh()                                  # older: reloaded
    assert store.reads > reads


def test_marked_stale_reloads_and_refresh_button_always_reloads(page):
    root, p, store, _ = page
    p.refresh(force=True)
    db_fake.save_device(None, {'name': 'R9', 'ip': '10.0.0.9', 'type': 'router', 'managed': True,
                               'status': 'up'})
    p.mark_stale()                               # e.g. a scan approval or an Apply
    assert card(p, 'devices')[0] == '1'
    reads = store.reads
    p.refresh_button.invoke()
    assert store.reads > reads


def test_database_error_shows_a_banner_and_no_old_figures(page):
    root, p, store, _ = page
    populate()
    p.refresh(force=True)
    store.down = True
    p.refresh(force=True, manual=True)
    assert p.banner.winfo_manager() and 'Overview unavailable' in p.banner.cget('text')
    assert all(c['value'].cget('text') == '—' for c in p.cards.values())
    assert p.data is None
    store.down = False
    p.refresh(force=True, manual=True)
    assert not p.banner.winfo_manager() and card(p, 'devices')[0] == '4'


def test_known_outage_blocks_automatic_reloads(page):
    root, p, store, _ = page
    p.on_db_down('The database is not available.')
    reads = store.reads
    p.mark_stale()
    p.refresh(force=True)
    assert store.reads == reads                  # nothing attempted during the outage
    p.on_db_up()                                 # recovery: reloads at once
    assert store.reads > reads and not p.banner.winfo_manager()


def test_quick_actions_respect_the_role(page):
    root, p, store, opened = page
    assert set(p.actions) == {'devices', 'topology', 'findings', 'logs'}   # no scan, no configure
    p.open_topology.invoke()
    assert opened == ['topology']


def test_main_window_overview_follows_a_sample_mode_review(monkeypatch):
    """Wiring: Run review on the Findings page (sample mode) updates the Overview card."""
    from tkinter import messagebox
    from gui_helpers import new_root, pump
    for name in ('showinfo', 'showerror', 'showwarning'):
        monkeypatch.setattr(messagebox, name, lambda *a, **k: None)
    root = new_root()
    try:
        from gui.main_window import build_main_window
        r = build_main_window(root, db_fake, demo_store=True)
        r['show_page']('dashboard')
        root.update()
        assert card(r['dashboard'], 'findings')[1] == 'No review saved yet.'
        r['findings'].run()
        assert pump(root, lambda: r['findings'].last_review is not None)
        r['show_page']('dashboard')
        value, detail = card(r['dashboard'], 'findings')
        assert int(value) == len(r['findings'].findings) > 0
        assert detail.startswith(f'{value} findings')
        assert r['dashboard'].cards['findings']['note'].cget('text').startswith('Last review: ')
    finally:
        root.destroy()


def test_main_window_overview_follows_scan_approval(monkeypatch):
    """Wiring: a sample scan + approval in the real window updates the Overview."""
    from tkinter import messagebox
    from gui_helpers import new_root, pump
    for name in ('showinfo', 'showerror', 'showwarning'):
        monkeypatch.setattr(messagebox, name, lambda *a, **k: None)
    root = new_root()
    try:
        from gui.main_window import build_main_window
        r = build_main_window(root, db_fake, demo_store=True)
        root.update()
        assert card(r['dashboard'], 'devices')[0] == '0'
        scan = r['scan']
        scan.on_scan()
        assert pump(root, lambda: scan.found)
        scan.approve()
        r['show_page']('dashboard')
        assert card(r['dashboard'], 'devices')[0] == '5'
        whats = [a['what'] for a in r['dashboard'].data['recent_activity']]
        assert 'Scan (this session)' in whats and 'Approval (this session)' in whats
    finally:
        root.destroy()
