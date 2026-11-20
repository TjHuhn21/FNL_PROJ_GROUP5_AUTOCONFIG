"""Whole app on REAL MySQL with the fake lab instead of real switches.
Runs only with NETCOMMAND_TEST_DB=1 (it WIPES the tables), and only on a separate test
database: DB_NAME must be set in the shell to a name ending in '_test' (mysql_guard).
Needs a display (on Linux: xvfb-run python -m pytest tests/test_integration_mysql.py)."""
import os, sys, time
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))
sys.path.insert(0, os.path.dirname(__file__))
import pytest

pytestmark = pytest.mark.skipif(not os.getenv('NETCOMMAND_TEST_DB'), reason='needs MySQL (NETCOMMAND_TEST_DB=1)')
tk = pytest.importorskip('tkinter')
from tkinter import messagebox, simpledialog

import sample_data
from fakes import fake_login_factory, lab


def pump(root, cond, timeout=10):
    end = time.time() + timeout
    while time.time() < end:
        root.update()
        if cond():
            return True
        time.sleep(0.02)
    return False


def test_scan_register_review_configure_on_mysql(monkeypatch):
    import mysql_guard
    mysql_guard.fail_unless_test_database()       # BEFORE any connection or DELETE
    import db
    from cryptography.fernet import Fernet
    from config import connect
    from discovery import crawler
    monkeypatch.setenv('FERNET_KEY', Fernet.generate_key().decode())
    conn = db.get_conn()
    with conn.cursor() as cur:
        cur.execute('SET FOREIGN_KEY_CHECKS = 0')
        for t in ('findings', 'status_events', 'config_logs', 'links', 'devices'):
            cur.execute(f'DELETE FROM {t}')
        cur.execute('SET FOREIGN_KEY_CHECKS = 1')
    conn.commit(); conn.close()

    try:
        root = tk.Tk()
    except tk.TclError:
        pytest.skip('no display')
    shown = []
    for name in ('showinfo', 'showerror', 'showwarning'):
        monkeypatch.setattr(messagebox, name, lambda t, m, _n=name, **k: shown.append((_n, t, m)))
    monkeypatch.setattr(messagebox, 'askyesno', lambda *a, **k: True)
    monkeypatch.setattr('gui.components.login_dialog.ask_device_login',
                        lambda *a, **k: {'username': 'admin', 'password': 'admin', 'save': False})
    monkeypatch.setattr(crawler, '_login', fake_login_factory(lab()))
    configs = {'192.168.1.3': sample_data.CONFIGS['SW1'], '192.168.1.4': sample_data.CONFIGS['SW2'],
               '192.168.1.2': 'hostname CORE\nservice password-encryption\n', '192.168.1.1': 'hostname R1\n'}
    asked = []
    monkeypatch.setattr(connect, 'get_config', lambda creds: asked.append(creds) or configs[creds['host']])

    from gui.main_window import build_main_window
    r = build_main_window(root, db, demo_store=False)
    scan, devices, topo, findings, conf, logs = (r[k] for k in ('scan', 'devices', 'topology', 'findings', 'configure', 'logs'))

    scan.demo.set(0); scan.user.set('admin'); scan.pw.set('cisco123'); scan.seed.set('192.168.1.2')
    scan.on_scan()
    assert pump(root, lambda: scan.found), shown
    assert len(scan.found) == 5 and sum(d['managed'] for d in scan.found) == 4        # SW3 is gray
    scan.approve()
    devices.refresh()
    assert len(devices.tree.get_children()) == 5 and len(db.get_links()) == 4

    core = db.get_device_by_ip('192.168.1.2')
    assert db.get_credentials(core['id']) == ('admin', 'cisco123')                    # saved, encrypted, readable
    raw = db._run('SELECT password_enc FROM devices WHERE id = %s', (core['id'],), 'one')['password_enc']
    assert raw and 'cisco123' not in raw
    assert db.get_credentials(db.get_device_by_ip('192.168.1.5')['id']) == ('', '')   # unmanaged: no login saved

    topo.refresh()
    assert 'Registered' in topo.source.cget('text')

    findings.run()
    assert pump(root, lambda: findings.findings)
    rules = {f['rule'] for f in findings.findings}
    assert {'telnet_enabled', 'no_port_security', 'single_point_of_failure'} <= rules
    assert len(asked) == 4 and all(c['password'] == 'cisco123' for c in asked)         # real logins were used
    assert db.get_findings('', 1, 50)                                                  # and saved in MySQL

    sent = []
    conf.apply_fn = lambda creds, cmds, checks: (sent.append((creds, cmds, checks)), (True, 'Applied and verified. Backup: x'))[1]
    conf.refresh_devices()
    conf.device_box.current([d['name'] for d in conf.devices].index('SW1'))
    for vid, name in [(10, 'SALES'), (20, 'HR'), (30, 'IT')]:
        conf.vid.set(str(vid)); conf.vname.set(name); conf.add_vlan()
    conf.make_preview(); conf.apply()
    assert pump(root, lambda: not conf.busy and sent)
    assert sent[0][0] == {'host': '192.168.1.3', 'username': 'admin', 'password': 'cisco123'}
    logs.refresh()
    assert len(logs.tree.get_children()) == 1 and db.count_logs('', 'success') == 1
    root.destroy()
