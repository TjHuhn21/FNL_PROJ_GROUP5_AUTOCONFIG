"""B3: sample (demo) devices must never reach the real database.
The 'sample' marker is an in-app safety flag only: never a column, never in SQL."""
import os, sys
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))
sys.path.insert(0, os.path.dirname(__file__))
import copy
import pytest

import db
import db_fake
import sample_data
from discovery import crawler
from fakes import fake_login_factory, lab


def test_discover_demo_marks_every_device_and_leaves_sample_data_alone():
    before = copy.deepcopy(sample_data.DEVICES)
    devices, links = crawler.discover_demo()
    assert len(devices) == 5 and all(d['sample'] is True for d in devices)
    assert sample_data.DEVICES == before and all('sample' not in d for d in sample_data.DEVICES)
    assert links == sample_data.LINKS


def test_real_discovery_has_no_marker(monkeypatch):
    monkeypatch.setattr(crawler, '_login', fake_login_factory(lab()))
    devices, _ = crawler.discover('admin', 'cisco123', '192.168.1.2', login_neighbours=True)
    assert len(devices) == 5 and all('sample' not in d for d in devices)


def no_sql(*a, **k):
    raise AssertionError('SQL was sent to the database')


def test_db_refuses_a_sample_device_before_any_sql(monkeypatch):
    monkeypatch.setattr(db, '_run', no_sql)
    monkeypatch.setattr(db, 'get_conn', no_sql)
    for d in crawler.discover_demo()[0]:
        with pytest.raises(ValueError) as err:
            db.upsert_device(d)
        assert 'Sample (demo) devices' in str(err.value)


@pytest.mark.parametrize('marker', [None, False])
def test_db_real_device_sql_never_mentions_the_marker(monkeypatch, marker):
    # upsert_device runs in save_device's transaction (3C-5 follow-up): a stand-in
    # connection whose read-only checks (deleted IP, taken name) find nothing.
    from test_device_save import FakeConnection
    conns = []
    monkeypatch.setattr(db, 'get_conn', lambda *a, **k: conns.append(FakeConnection()) or conns[-1])
    monkeypatch.setattr(db, '_run', no_sql)
    d = {'name': 'CORE', 'ip': '192.168.1.2', 'mac': '', 'type': 'switch',
         'managed': True, 'status': 'up'}                 # same name/IP as the sample: allowed
    if marker is not None:
        d['sample'] = marker
    assert db.upsert_device(d) == 7
    conn, = conns
    assert conn.commits == 1
    assert all('sample' not in sql.lower() for sql, _ in conn.committed)
    (sql, params), = [c for c in conn.committed if c[0].startswith('INSERT')]
    assert params == ('CORE', '192.168.1.2', '', 'switch', 1, 'up')


def test_sample_mode_store_still_accepts_sample_devices_without_storing_the_marker():
    db_fake.reset()
    devices, links = crawler.discover_demo()
    for d in devices:
        db_fake.upsert_device(d)
    db_fake.save_links(links)
    rows = db_fake.get_devices('', 'name', 1, 50)
    assert len(rows) == 5 and all('sample' not in r for r in rows)
    assert len(db_fake.get_links()) == 4
