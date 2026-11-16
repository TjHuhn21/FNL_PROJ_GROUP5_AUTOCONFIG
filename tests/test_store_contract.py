"""The same checks run against db_fake (always) and db.py (MySQL) when
NETCOMMAND_TEST_DB=1. WARNING: the MySQL run WIPES the netcommand tables."""
import os, sys
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))
import pytest

import db_fake

stores = ['fake']
if os.getenv('NETCOMMAND_TEST_DB'):
    stores.append('mysql')


@pytest.fixture(params=stores)
def store(request, monkeypatch):
    if request.param == 'fake':
        db_fake.reset()
        return db_fake
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


def test_same_ip_updates_and_restores_deleted(store):
    a = store.upsert_device(dev('SW1', '10.0.0.1'))
    assert store.upsert_device(dev('SW1-new', '10.0.0.1')) == a       # same IP: same device
    assert store.count_devices() == 1 and store.get_device(a)['name'] == 'SW1-new'
    store.delete_device(a)
    assert store.upsert_device(dev('SW1', '10.0.0.1')) == a           # comes back
    assert store.count_devices() == 1


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
