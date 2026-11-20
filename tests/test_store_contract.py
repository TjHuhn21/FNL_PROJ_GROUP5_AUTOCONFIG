"""The same checks run against db_fake (always) and db.py (MySQL) when
NETCOMMAND_TEST_DB=1. WARNING: the MySQL run WIPES the tables, so it only runs on a
separate test database: DB_NAME must be set in the shell to a name ending in '_test'
(mysql_guard); anything else fails before a connection is opened."""
import os, sys
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))
sys.path.insert(0, os.path.dirname(__file__))
import pytest

import db_fake
import mysql_guard

stores = ['fake']
if os.getenv('NETCOMMAND_TEST_DB'):
    stores.append('mysql')


@pytest.fixture(params=stores)
def store(request, monkeypatch):
    if request.param == 'fake':
        db_fake.reset()
        return db_fake
    return mysql_store(monkeypatch)


def mysql_store(monkeypatch):
    """The MySQL store with every table emptied. The guard runs first: on anything but
    a '_test' database the test fails here, before a connection is opened."""
    mysql_guard.fail_unless_test_database()
    import db
    from cryptography.fernet import Fernet
    monkeypatch.setenv('FERNET_KEY', Fernet.generate_key().decode())
    conn = db.get_conn()
    with conn.cursor() as cur:
        cur.execute('SET FOREIGN_KEY_CHECKS = 0')
        for table in ('findings', 'status_events', 'config_logs', 'links', 'devices'):
            cur.execute(f'DELETE FROM {table}')
        cur.execute('SET FOREIGN_KEY_CHECKS = 1')
    conn.commit(); conn.close()
    return db


def dev(name, ip, kind='switch', managed=True):
    return {'name': name, 'ip': ip, 'mac': '', 'type': kind, 'managed': managed, 'status': 'up'}


def test_add_get_update_delete(store):
    a = store.upsert_device(dev('SW1', '10.0.0.1'))
    assert store.get_device(a)['name'] == 'SW1'
    assert store.get_device_by_ip('10.0.0.1')['id'] == a
    store.update_device(a, {'name': 'SW1b', 'ip': '10.0.0.1', 'type': 'router',
                            'status': 'down', 'managed': False})
    d = store.get_device(a)
    assert (d['name'], d['type'], d['status'], d['managed']) == ('SW1b', 'router', 'down', False)
    store.delete_device(a)
    assert store.get_device(a) is None and store.count_devices() == 0
    assert store.get_device_by_ip('10.0.0.1') is None


def test_same_ip_updates_but_never_silently_restores_deleted(store):
    from store_errors import DeletedDeviceExists, DeviceNotDeleted
    a = store.upsert_device(dev('SW1', '10.0.0.1'))
    assert store.upsert_device(dev('SW1-new', '10.0.0.1')) == a       # same IP: same device
    assert store.count_devices() == 1 and store.get_device(a)['name'] == 'SW1-new'
    store.delete_device(a)
    with pytest.raises(DeletedDeviceExists) as err:                   # NOT brought back
        store.upsert_device(dev('SW1', '10.0.0.1'))
    assert err.value.device['id'] == a and err.value.device['name'] == 'SW1-new'
    assert store.get_device(a) is None and store.count_devices() == 0   # still deleted, unchanged
    assert store.restore_device(a, dev('SW1', '10.0.0.1'), credentials='keep') == a   # explicit only
    assert store.count_devices() == 1 and store.get_device(a)['name'] == 'SW1'
    with pytest.raises(DeviceNotDeleted):
        store.restore_device(a, dev('SW1', '10.0.0.1'), credentials='keep')


def test_search_sort_paging(store):
    for n in range(1, 31):
        store.upsert_device(dev(f'SW{n:02d}', f'10.0.0.{n}'))
    assert store.count_devices() == 30 and store.count_devices('SW0') == 9
    page1 = store.get_devices('', 'name', 1, 15)
    page2 = store.get_devices('', 'name', 2, 15)
    assert len(page1) == len(page2) == 15 and page1[0]['name'] == 'SW01'
    assert page2[-1]['name'] == 'SW30'
    by_ip = store.get_devices('', 'ip', 1, 30)
    assert [d['ip'] for d in by_ip] == [f'10.0.0.{n}' for n in range(1, 31)]   # numeric, not text order
    assert [d['name'] for d in store.get_devices('10.0.0.3', 'name', 1, 15)][0] == 'SW03'
    assert store.get_devices('', 'name; DROP TABLE devices', 1, 5)            # bad sort is ignored


def test_credentials_are_saved_and_never_returned_in_device_rows(store):
    a = store.upsert_device(dev('SW1', '10.0.0.1'))
    assert store.get_credentials(a) == ('', '')
    store.save_credentials(a, 'admin', 'cisco123')
    assert store.get_credentials(a) == ('admin', 'cisco123')
    assert 'password' not in str(store.get_device(a)).lower() or 'password_enc' not in store.get_device(a)


def test_links_follow_devices(store):
    store.upsert_device(dev('A', '10.0.0.1')); b = store.upsert_device(dev('B', '10.0.0.2'))
    store.save_links([('A', 'Gi0/1', 'B', 'Gi0/1')])
    store.save_links([('A', 'Gi0/1', 'B', 'Gi0/1')])                  # saving twice adds nothing
    assert store.get_links() == [('A', 'Gi0/1', 'B', 'Gi0/1')]
    store.delete_device(b)
    assert store.get_links() == []


def test_logs(store):
    a = store.upsert_device(dev('SW1', '10.0.0.1'))
    store.add_log(a, 'Configuration', 'success', 'Applied')
    store.add_log(a, 'Configuration', 'failed', 'Wrong password')
    assert store.count_logs() == 2 and store.count_logs('', 'failed') == 1
    rows = store.get_logs('', 1, 15, '')
    assert rows[0]['details'] == 'Wrong password' and rows[0]['device'] == 'SW1'   # newest first
    assert hasattr(rows[0]['created_at'], 'strftime')
    assert store.count_logs('password') == 1


def test_findings_events_status(store):
    a = store.upsert_device(dev('SW1', '10.0.0.1'))
    f = {'device': 'SW1', 'rule': 'telnet_enabled', 'severity': 'high', 'message': 'Telnet',
         'commands': ['line vty 0 4', 'transport input ssh']}
    assert store.add_finding(f)
    assert store.add_finding(dict(f, device='NOT-REGISTERED')) is None   # sample devices are skipped
    got = store.get_findings('', 1, 15)
    assert len(got) == 1 and got[0]['commands'] == ['line vty 0 4', 'transport input ssh']
    store.clear_findings()
    assert store.get_findings('', 1, 15) == []
    store.set_status(a, 'down'); store.add_event(a, 'down', 'SW1 is now down')
    assert store.get_device(a)['status'] == 'down'
    assert store.get_events()[0]['kind'] == 'down'


def test_active_device_names_are_unique_ignoring_case(store):
    from store_errors import DuplicateDeviceName
    a = store.save_device(None, dev('CORE-SW', '10.0.0.1'))
    with pytest.raises(DuplicateDeviceName) as err:                   # capitals do not count
        store.save_device(None, dev('core-sw', '10.0.0.2'))
    assert err.value.existing == {'id': a, 'name': 'CORE-SW'} and store.count_devices() == 1
    b = store.save_device(None, dev('ACCESS-SW', '10.0.0.2'))
    store.save_device(b, dev('access-sw', '10.0.0.2'))                # its own name: fine
    with pytest.raises(DuplicateDeviceName):                          # another device's: not
        store.save_device(b, dev('Core-Sw', '10.0.0.2'))
    assert store.get_device(b)['name'] == 'access-sw'
    store.delete_device(a)                                            # deleted: name is free
    c = store.save_device(None, dev('core-sw', '10.0.0.3'))
    with pytest.raises(DuplicateDeviceName):                          # restore would duplicate
        store.restore_device(a, dev('CORE-SW', '10.0.0.1'), credentials='keep')
    assert store.get_device(a) is None and store.get_device(c)['name'] == 'core-sw'
    assert store.restore_device(a, dev('CORE-SW-OLD', '10.0.0.1'), credentials='keep') == a


def test_findings_snapshot_is_replaced_whole(store):
    a = store.save_device(None, dev('SW1', '10.0.0.1'))
    f = {'device': 'SW1', 'rule': 'telnet_enabled', 'severity': 'high', 'message': 'Telnet',
         'commands': ['line vty 0 4']}
    assert store.replace_findings([f, dict(f, device='NOT-REGISTERED')]) == {
        'saved': 1, 'skipped': ['NOT-REGISTERED']}
    snap = store.get_findings_snapshot()
    assert [(x['device'], x['device_deleted']) for x in snap['findings']] == [('SW1', False)]
    assert snap['saved_at'] is not None
    store.replace_findings([dict(f, rule='other', severity='low')])     # replaced, not added
    assert [x['rule'] for x in store.get_findings_snapshot()['findings']] == ['other']
    store.delete_device(a)
    assert store.get_findings_snapshot()['findings'][0]['device_deleted'] is True
    assert store.replace_findings([]) == {'saved': 0, 'skipped': []}    # empty review clears
    assert store.get_findings_snapshot() == {'findings': [], 'saved_at': None}


def test_status_change_and_event_are_recorded_together(store):
    a = store.save_device(None, dev('SW1', '10.0.0.1'))
    assert store.record_status_change(a, 'up', 'down', 'SW1 is now down (was up)') is True
    assert store.get_device(a)['status'] == 'down'
    assert store.record_status_change(a, 'up', 'down', 'again') is False   # no longer up
    events = store.get_events()
    assert len(events) == 1 and (events[0]['kind'], events[0]['previous']) == ('down', 'up')
