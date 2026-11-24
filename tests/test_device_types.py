"""Device types: the type the scan detected vs. the type the user chose.

* device_types: the rescan rule and the "(changed manually)" mark.
* db_fake / db.py: a scan records detected_type and keeps a type the user changed; db.py
  still works before schema_update_detected_type.sql was run (MySQL error 1054).
* Edit device: Status is read-only (the monitor's), a type change needs a confirmation.
* Devices table: the mark and its tooltip.
* Configure: Switch / Router settings stop before the backup when the device itself shows
  the other type; an unrecognised device is not refused; typed commands are not checked;
  it is logged as FAILED, counted as a failed change, and never as a failed login.
No MySQL, no device, no network.
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))
sys.path.insert(0, os.path.dirname(__file__))

import pymysql
import pytest

import db
import db_fake
import device_types as T
from config import connect, multi

ROUTER_VERSION = ('Cisco IOS Software, C1900 Software (C1900-UNIVERSALK9-M), Version 15.4(3)M2, '
                  'RELEASE SOFTWARE (fc1)\nCisco CISCO1941/K9 (revision 1.0) with 491520K/32768K '
                  'bytes of memory.')
SWITCH_VERSION = ('Cisco IOS Software, C2960 Software (C2960-LANBASEK9-M), Version 15.0(2)SE, '
                  'RELEASE SOFTWARE (fc1)')


def scanned(name, ip, kind, managed=True):
    return {'name': name, 'ip': ip, 'mac': '', 'type': kind, 'managed': managed,
            'status': 'up', 'detected_type': kind}


@pytest.fixture
def store():
    db_fake.reset()
    yield db_fake
    db_fake.reset()


# ---------------------------------------------------------------- the rules
@pytest.mark.parametrize('current, before, scan, kept', [
    ('unknown', 'unknown', 'switch', 'switch'),    # an unknown type takes the scan's answer
    ('switch', 'switch', 'unknown', 'switch'),     # a known type is never replaced by unknown
    ('switch', 'router', 'router', 'switch'),      # changed by the user: kept
    ('router', None, 'switch', 'router'),          # added by hand: kept
    ('switch', 'switch', 'router', 'router'),      # not changed by the user: the new detection
    ('router', 'router', 'router', 'router'),
])
def test_type_after_scan(current, before, scan, kept):
    assert T.type_after_scan(current, before, scan) == kept


def test_the_manual_mark_only_for_a_real_difference():
    assert T.type_label({'type': 'switch', 'detected_type': 'router'}) == \
        'switch (changed manually)'
    assert T.detected_tooltip({'type': 'switch', 'detected_type': 'router'}) == \
        'Detected as router by scan'
    for d in ({'type': 'switch', 'detected_type': 'unknown'},     # unknown set by the user
              {'type': 'switch', 'detected_type': None},          # added by hand
              {'type': 'switch'},                                 # before the update
              {'type': 'router', 'detected_type': 'router'}):
        assert not T.manually_changed(d) and T.type_label(d) == d['type']


# ---------------------------------------------------------------- db_fake (sample store)
def test_a_rescan_keeps_the_users_type_and_records_the_detection(store):
    did = store.save_device(None, scanned('R1', '10.0.0.1', 'router'))
    assert store.get_device(did)['detected_type'] == 'router'
    store.save_device(did, {'name': 'R1', 'ip': '10.0.0.1', 'type': 'switch', 'managed': True})
    store.save_device(None, scanned('R1', '10.0.0.1', 'router'))          # the rescan
    d = store.get_device(did)
    assert (d['type'], d['detected_type']) == ('switch', 'router') and T.manually_changed(d)


def test_a_rescan_fills_in_an_unknown_type_and_never_blanks_a_known_one(store):
    did = store.save_device(None, scanned('AP-1', '10.0.0.9', 'unknown'))
    store.save_device(None, scanned('AP-1', '10.0.0.9', 'switch'))
    assert store.get_device(did)['type'] == 'switch'
    store.save_device(None, scanned('AP-1', '10.0.0.9', 'unknown'))
    d = store.get_device(did)
    assert (d['type'], d['detected_type']) == ('switch', 'unknown')


def test_a_device_added_by_hand_keeps_its_type(store):
    did = store.save_device(None, {'name': 'X1', 'ip': '10.0.0.4', 'type': 'router',
                                   'managed': True, 'status': 'up'})
    assert store.get_device(did).get('detected_type') is None
    store.save_device(None, scanned('X1', '10.0.0.4', 'switch'))
    d = store.get_device(did)
    assert (d['type'], d['detected_type']) == ('router', 'switch')


def test_an_edit_keeps_the_monitors_status(store):
    did = store.save_device(None, scanned('SW1', '10.0.0.2', 'switch'))
    store.set_status(did, 'down')
    store.save_device(did, {'name': 'SW1b', 'ip': '10.0.0.2', 'type': 'switch', 'managed': True})
    assert store.get_device(did)['status'] == 'down'


# ---------------------------------------------------------------- db.py (stand-in connection)
class Conn:
    def __init__(self, existing=None, missing_column=False):
        self.existing, self.missing_column = existing, missing_column
        self.sql, self.commits = [], 0

    def cursor(self):
        return Cur(self)

    def commit(self):
        self.commits += 1

    def rollback(self):
        pass

    def close(self):
        pass


class Cur:
    def __init__(self, conn):
        self.conn, self.last, self.lastrowid, self.rowcount = conn, '', 5, 1

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False

    def execute(self, sql, params=()):
        if 'detected_type FROM devices' in sql and self.conn.missing_column:
            raise pymysql.err.OperationalError(1054, "Unknown column 'detected_type'")
        self.conn.sql.append((sql, params))
        self.last = sql

    def fetchone(self):
        if self.last.startswith('SELECT type, detected_type'):
            return self.conn.existing
        if self.last.startswith('SELECT name FROM devices WHERE id'):   # an edit: it exists
            return {'name': 'X1'}
        return None


@pytest.fixture
def mysql(monkeypatch):
    made = []

    def connect_(**kw):
        made.append(Conn(**kw))
        return made[-1]
    holder = {'kw': {}}
    monkeypatch.setattr(db, 'get_conn', lambda *a, **k: connect_(**holder['kw']))
    monkeypatch.setattr(db, '_run', lambda *a, **k: pytest.fail('unexpected _run call'))
    return made, holder


def inserts(conn):
    return [(s, p) for s, p in conn.sql if s.startswith('INSERT')]


def test_db_scan_records_the_detection_and_keeps_the_users_type(mysql):
    made, holder = mysql
    holder['kw'] = {'existing': {'type': 'switch', 'detected_type': 'router'}}
    db.save_device(None, scanned('R1', '10.0.0.1', 'router'))
    ((sql, params),) = inserts(made[0])
    assert 'detected_type' in sql and params[3] == 'switch' and params[-1] == 'router'
    assert made[0].commits == 1


def test_db_scan_without_the_column_still_saves(mysql):
    made, holder = mysql
    holder['kw'] = {'missing_column': True}
    db.save_device(None, scanned('R1', '10.0.0.1', 'router'))
    ((sql, params),) = inserts(made[0])
    assert 'detected_type' not in sql and params[3] == 'router' and made[0].commits == 1


def test_db_manual_add_and_edit_do_not_touch_the_detection_and_edit_keeps_the_status(mysql):
    made, _ = mysql
    db.save_device(None, {'name': 'X1', 'ip': '10.0.0.4', 'type': 'router', 'managed': True})
    assert 'detected_type' not in inserts(made[0])[0][0]
    db.save_device(3, {'name': 'X1', 'ip': '10.0.0.4', 'type': 'switch', 'managed': True})
    sql, params = [r for r in made[1].sql if r[0].startswith('UPDATE devices')][0]
    assert 'COALESCE(%s, status)' in sql and params[3] is None and 'detected_type' not in sql


# ---------------------------------------------------------------- Edit device
@pytest.fixture
def gui(monkeypatch, store):
    from tkinter import messagebox
    from gui import theme
    from gui_helpers import new_root
    root = new_root()
    theme.apply(root)
    shown = []
    for name in ('showinfo', 'showerror', 'showwarning'):
        monkeypatch.setattr(messagebox, name, lambda t, m, _n=name, **k: shown.append((_n, t, m)))
    yield root, shown
    root.destroy()


def edit(root, monkeypatch, device, new_type, answer):
    from gui import devices_tab
    asked = []
    monkeypatch.setattr(devices_tab, 'ask_type_change',
                        lambda parent, title, text: asked.append((title, text)) or answer)
    saved = []
    dlg = devices_tab.DeviceDialog(root, db_fake, device, lambda: saved.append(1))
    dlg.vars['type'].set(new_type)
    dlg.save()
    return dlg, asked, saved


def test_changing_a_detected_type_asks_first_and_cancel_saves_nothing(gui, monkeypatch, store):
    root, _ = gui
    did = store.save_device(None, scanned('MOCK-R1', '10.0.0.1', 'router'))
    dlg, asked, saved = edit(root, monkeypatch, store.get_device(did), 'switch', False)
    ((title, text),) = asked
    assert title == 'Change device type?'
    assert 'MOCK-R1 was detected as a ROUTER by the scan.' in text
    assert 'Are you sure you want to change it to SWITCH?' in text
    assert 'NetCommand will send switch commands to a router' in text
    assert saved == [] and dlg.winfo_exists() and dlg.vars['type'].get() == 'router'
    assert store.get_device(did)['type'] == 'router'
    dlg, asked, saved = edit(root, monkeypatch, store.get_device(did), 'switch', True)
    assert saved == [1] and store.get_device(did)['type'] == 'switch'


def test_simple_question_for_unknown_and_none_for_other_fields(gui, monkeypatch, store):
    root, _ = gui
    did = store.save_device(None, scanned('AP-1', '10.0.0.9', 'unknown'))
    _, asked, saved = edit(root, monkeypatch, store.get_device(did), 'switch', True)
    assert asked == [('Change device type?', "Set AP-1's type to SWITCH?")] and saved == [1]
    _, asked, saved = edit(root, monkeypatch, store.get_device(did), 'switch', False)
    assert asked == [] and saved == [1]                    # the type did not change


def test_status_is_read_only_and_kept(gui, monkeypatch, store):
    root, _ = gui
    did = store.save_device(None, scanned('SW1', '10.0.0.2', 'switch'))
    store.set_status(did, 'down')
    dlg, _, _ = edit(root, monkeypatch, store.get_device(did), 'switch', True)
    assert 'status' not in dlg.vars
    assert store.get_device(did)['status'] == 'down'


def test_the_table_marks_manual_changes_with_a_tooltip(gui, store):
    from gui.devices_tab import DevicesTab
    root, _ = gui
    a = store.save_device(None, scanned('R1', '10.0.0.1', 'router'))
    b = store.save_device(None, scanned('AP-1', '10.0.0.9', 'unknown'))
    store.save_device(a, {'name': 'R1', 'ip': '10.0.0.1', 'type': 'switch', 'managed': True})
    store.save_device(b, {'name': 'AP-1', 'ip': '10.0.0.9', 'type': 'switch', 'managed': True})
    tab = DevicesTab(root, db_fake)
    assert tab.tree.item(str(a))['values'][2] == '⚠ switch (changed manually)'
    assert tab.tree.item(str(b))['values'][2] == 'switch'      # unknown before: no conflict
    assert tab.type_tips == {str(a): 'Detected as router by scan'}


# ---------------------------------------------------------------- Configure: the live check
def apply(monkeypatch, tmp_path, version, expected, vlan=''):
    from test_ssh_session import CREDS, FakeIOS
    fake = FakeIOS(shows={'show version': version, 'show vlan brief': vlan})
    monkeypatch.setattr(connect, '_open', lambda creds: fake)
    log = []
    ok, msg = connect.apply_config(CREDS, ['vlan 10'], backup_dir=str(tmp_path),
                                   log=lambda kind, text: log.append((kind, text)),
                                   expected_type=expected, device_name='MOCK-R1')
    return ok, msg, log, fake


def test_a_mismatch_stops_before_the_backup_and_any_command(monkeypatch, tmp_path):
    ok, msg, log, fake = apply(monkeypatch, tmp_path, ROUTER_VERSION, 'switch')
    assert not ok and msg.startswith('Configuration FAILED on MOCK-R1: the device type is set '
                                     'to SWITCH, but the device is a ROUTER. Fix the type on the '
                                     'Devices page (Edit) and try again.')
    assert connect.is_type_mismatch(msg)
    assert fake.sent == [] and not fake.saved and os.listdir(tmp_path) == []   # no backup
    assert any(k == 'error' and 'DEVICE TYPE MISMATCH' in t for k, t in log)


def test_a_matching_or_unrecognised_device_goes_on(monkeypatch, tmp_path):
    ok, _, log, fake = apply(monkeypatch, tmp_path, SWITCH_VERSION, 'switch')
    assert ok and fake.sent == ['vlan 10']
    assert ('ok', 'Device type confirmed: switch.') in log
    ok, _, log, fake = apply(monkeypatch, tmp_path, '', 'router')      # nothing recognisable
    assert ok and fake.sent == ['vlan 10']
    assert any(k == 'warn' and 'could not be confirmed' in t for k, t in log)
    # no model, but a VLAN table: a switch, so router settings stop
    ok, msg, _, fake = apply(monkeypatch, tmp_path, '', 'router',
                             vlan='VLAN Name Status Ports\n1    default    active')
    assert not ok and 'is set to ROUTER, but the device is a SWITCH' in msg and fake.sent == []


def test_typed_commands_are_not_checked(monkeypatch, tmp_path):
    ok, _, log, _ = apply(monkeypatch, tmp_path, ROUTER_VERSION, None)
    assert ok and not any('Device type' in t for _, t in log)


def test_run_devices_passes_the_type_only_to_functions_that_take_it():
    seen = []

    def typed(creds, commands, checks, log=None, expected_type=None, device_name=None):
        seen.append((expected_type, device_name))
        return True, 'ok'

    def plain(creds, commands, checks):
        return True, 'ok'
    job = {'device': {'id': 1, 'name': 'SW1', 'ip': '10.0.0.2'}, 'creds': {}, 'commands': ['x'],
           'checks': [], 'expected_type': 'switch'}
    multi.run_devices([job], typed)
    multi.run_devices([dict(job, expected_type=None)], typed)
    assert seen == [('switch', 'SW1'), (None, None)]
    assert multi.run_devices([job], plain)[0]['ok']


def test_a_mismatch_is_a_failed_change_and_not_a_failed_login(monkeypatch, store):
    from gui import event_log
    from gui.configure_tab import ConfigureTab
    from gui.device_login_guard import SUCCESS, outcome_of_apply
    from gui_helpers import new_root
    message = connect.type_mismatch_message('MOCK-R1', 'switch', 'router')
    result = {'device': None, 'status': multi.classify(False, message), 'ok': False,
              'message': message}
    assert result['status'] == multi.FAILED and outcome_of_apply(result) == SUCCESS
    lines = []
    monkeypatch.setattr(event_log, 'log_event', lambda *a: lines.append(a))
    root = new_root()
    try:
        did = store.save_device(None, scanned('MOCK-R1', '10.0.0.1', 'router'))
        conf = ConfigureTab(root, db_fake)
        conf.log = lambda *a, **k: lines.append(a)
        conf._record(dict(result, device=store.get_device(did)))
        assert store.count_logs(status='failed') == 1
        assert ('configure', message, 'error') in lines
    finally:
        root.destroy()
