"""Findings in each mode:
  real database, nothing registered -> clear empty state, never the sample network,
                                       stored findings left untouched
  sample mode                       -> sample findings, visibly marked SAMPLE DATA
  real database, devices registered -> the registered network and its real configs
db_fake stands in for the database; SSH is replaced by a fake get_config."""
import os, sys
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))
sys.path.insert(0, os.path.dirname(__file__))
import pytest

import db_fake
import sample_data
import services
from config import connect
from discovery import crawler
from fakes import fake_login_factory, lab

CONFIGS_BY_IP = {'192.168.1.3': sample_data.CONFIGS['SW1'], '192.168.1.4': sample_data.CONFIGS['SW2'],
                 '192.168.1.2': 'hostname CORE\nservice password-encryption\n',
                 '192.168.1.1': 'hostname R1\nservice password-encryption\n'}


def register_lab(monkeypatch, with_logins=True):
    """The fake lab, discovered and registered as real (non-sample) devices."""
    monkeypatch.setattr(crawler, '_login', fake_login_factory(lab()))
    devices, links = crawler.discover('admin', 'cisco123', '192.168.1.2', login_neighbours=True)
    for d in devices:
        did = db_fake.upsert_device(d)
        if with_logins and d['managed']:
            db_fake.save_credentials(did, 'admin', 'cisco123')
    db_fake.save_links(links)
    asked = []
    monkeypatch.setattr(connect, 'get_config',
                        lambda creds: asked.append(creds['host']) or CONFIGS_BY_IP[creds['host']])
    return asked


# ---------------------------------------------------------------- the data the review gets
def test_real_mode_with_nothing_registered_gets_nothing_to_review():
    db_fake.reset()
    assert services.collect_review_inputs(db_fake, demo=False) == ([], [], {}, [], services.NO_DEVICES)


def test_sample_mode_reviews_the_sample_network_labelled():
    db_fake.reset()
    devices, links, configs, notes, source = services.collect_review_inputs(db_fake, demo=True)
    assert devices == sample_data.DEVICES and configs == sample_data.CONFIGS
    assert source.startswith('SAMPLE DATA')


def test_real_mode_with_devices_reviews_their_real_configs(monkeypatch):
    db_fake.reset()
    asked = register_lab(monkeypatch)
    devices, links, configs, notes, source = services.collect_review_inputs(db_fake, demo=False)
    assert source == 'Registered devices (5)'
    assert sorted(configs) == ['CORE', 'R1', 'SW1', 'SW2']        # SW3 is unmanaged
    assert configs['SW1'] == CONFIGS_BY_IP['192.168.1.3']
    assert sorted(asked) == sorted(CONFIGS_BY_IP)                  # read from each device


# ---------------------------------------------------------------- the Findings page
tk = pytest.importorskip('tkinter')


def make_app(monkeypatch, demo_store, before=None):
    from tkinter import messagebox
    from gui_helpers import new_root
    root = new_root()
    root.geometry('1200x800')
    shown = []
    for name in ('showinfo', 'showerror', 'showwarning'):
        monkeypatch.setattr(messagebox, name, lambda t, m, _n=name, **k: shown.append((_n, t, m)))
    db_fake.reset()
    if before:
        before()
    from gui.main_window import build_main_window
    refs = build_main_window(root, db_fake, demo_store=demo_store)
    root.update()
    return root, refs, shown


def run_review(root, findings):
    from gui_helpers import pump
    findings.run()
    assert pump(root, lambda: not findings.busy)


def test_real_mode_empty_shows_an_empty_state_and_keeps_stored_findings(monkeypatch):
    from gui.findings_tab import EMPTY_MESSAGE

    def old_finding_of_a_deleted_device():
        did = db_fake.upsert_device({'name': 'OLD', 'ip': '10.9.9.9', 'type': 'switch',
                                     'managed': True})
        db_fake.add_finding({'device': 'OLD', 'rule': 'telnet_enabled', 'severity': 'high',
                             'message': 'Telnet', 'commands': []})
        db_fake.delete_device(did)                          # soft delete: 0 registered now
    root, r, shown = make_app(monkeypatch, demo_store=False, before=old_finding_of_a_deleted_device)
    try:
        f = r['findings']
        run_review(root, f)
        assert f.findings == [] and f.tree.get_children() == ()
        assert 'no registered devices' in f.score.cget('text') and '/ 100' not in f.score.cget('text')
        assert f.note.cget('text') == EMPTY_MESSAGE
        assert 'SAMPLE' not in f.score.cget('text') + f.note.cget('text')
        assert len(db_fake.get_findings('', 1, 50)) == 1         # the stored record was kept
        assert shown == []
    finally:
        root.destroy()


def test_sample_mode_findings_are_visibly_sample_data(monkeypatch):
    from gui import theme
    root, r, shown = make_app(monkeypatch, demo_store=True)
    try:
        f = r['findings']
        run_review(root, f)
        assert {'telnet_enabled', 'no_password_encryption'} <= {x['rule'] for x in f.findings}
        assert f.score.cget('text').endswith('SAMPLE DATA')
        assert f.note.cget('text').startswith('SAMPLE DATA')
        assert str(f.note.cget('style')) == 'Sample.TLabel'
        assert str(f.note.cget('foreground')) == theme.SAMPLE_COLOR   # amber, not the old grey
    finally:
        root.destroy()


def test_real_mode_with_registered_devices_reviews_the_real_network(monkeypatch):
    holder = {}
    root, r, shown = make_app(monkeypatch, demo_store=False,
                              before=lambda: holder.update(asked=register_lab(monkeypatch)))
    try:
        f = r['findings']
        run_review(root, f)
        rules = {(x['device'], x['rule']) for x in f.findings}
        assert ('SW1', 'telnet_enabled') in rules and ('SW2', 'trunk_all_vlans') in rules
        assert ('CORE', 'single_point_of_failure') in rules
        assert 'AP-1' not in {x['device'] for x in f.findings}      # no sample-only devices
        assert 'SAMPLE' not in f.score.cget('text') + f.note.cget('text')
        assert f.note.cget('text').startswith('Registered devices (5)')
        assert len(db_fake.get_findings('', 1, 50)) == len(f.findings)   # stored as before
        assert sorted(holder['asked']) == sorted(CONFIGS_BY_IP)
    finally:
        root.destroy()


def test_real_mode_devices_without_logins_are_reported_not_replaced_by_samples(monkeypatch):
    root, r, shown = make_app(monkeypatch, demo_store=False,
                              before=lambda: register_lab(monkeypatch, with_logins=False))
    try:
        f = r['findings']
        run_review(root, f)
        assert {x['rule'] for x in f.findings} == {'single_point_of_failure'}   # topology only
        assert 'no saved login, skipped' in f.note.cget('text')
        assert 'SAMPLE' not in f.note.cget('text')
    finally:
        root.destroy()
