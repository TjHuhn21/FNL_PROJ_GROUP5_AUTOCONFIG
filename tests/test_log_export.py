"""Encrypted export of the Logs page (log_export.py, gui/logs_tab.py). Offline: the fake
store, temporary files, synthetic passphrases (never real ones)."""
import json
import os
import sys
from datetime import datetime

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path[:0] = [ROOT, os.path.dirname(__file__)]

import backup_crypto as C  # noqa: E402
import db_fake  # noqa: E402
import log_export as X  # noqa: E402

PASS = 'Synthetic export pass 42'
FAST = 2 ** 14                                  # the lowest allowed scrypt N: quick tests
ENTRIES = [{'created_at': datetime(2026, 11, 26, 14, 38, 33), 'user_label': 'tj*****de@gmail.com',
            'category': 'setup', 'device': 'R1', 'device_ip': '', 'level': 'error',
            'message': 'SSH apply: failed. MARKER-SECRET-LINE', 'result': 'failed',
            'tags': 'failed', 'detail': 'username netadmin privilege 15 secret ********'}]


def make(entries=ENTRIES, log='Activity history', passphrase=PASS, **kw):
    return X.export_bytes(log, entries, passphrase, filters={'search': ''}, n=FAST, **kw)


# ================================================================ the file
def test_round_trip_keeps_every_entry():
    header, payload = X.open_export(make(), PASS)
    assert header['log'] == 'Activity history' and header['count'] == 1
    assert payload['entries'][0]['message'] == ENTRIES[0]['message']
    assert payload['entries'][0]['created_at'] == '2026-11-26T14:38:33'
    assert payload['filters'] == {'search': ''}


def test_the_file_reveals_nothing_without_the_passphrase():
    data = make()
    assert data.startswith(X.MAGIC)
    for secret in (b'MARKER-SECRET-LINE', b'netadmin', PASS.encode()):
        assert secret not in data
    header = X.read_header(data)                       # only what it says about itself
    assert header['count'] == 1 and header['log'] == 'Activity history'


def test_every_export_uses_a_new_salt_and_nonce():
    a, b = X.read_header(make()), X.read_header(make())
    assert a['salt'] != b['salt'] and a['nonce'] != b['nonce']


def test_a_wrong_passphrase_is_refused_without_revealing_anything():
    with pytest.raises(X.LogExportError) as err:
        X.open_export(make(), 'Not the right passphrase')
    assert 'passphrase is wrong' in str(err.value) and PASS not in str(err.value)


@pytest.mark.parametrize('where', ['header', 'ciphertext', 'tag'])
def test_any_changed_byte_is_detected(where):
    data = bytearray(make())
    _h, aad, _ct = C.parse(bytes(data), X.MAGIC, 'log export')
    index = {'header': len(aad) - 5, 'ciphertext': len(aad) + 3, 'tag': len(data) - 1}[where]
    data[index] ^= 0x01
    with pytest.raises(C.BackupCryptoError):
        X.open_export(bytes(data), PASS)


def test_header_count_cannot_be_rewritten():
    data = make()
    forged = data.replace(b'"count":1', b'"count":0')
    with pytest.raises(C.BackupCryptoError):
        X.open_export(forged, PASS)


def test_unsupported_scrypt_parameters_are_refused_before_scrypt_runs():
    with pytest.raises(C.FormatError):
        X.export_bytes('Activity history', ENTRIES, PASS, n=2 ** 30)
    with pytest.raises(C.FormatError):
        X.export_bytes('Activity history', ENTRIES, PASS, n=3000)


@pytest.mark.parametrize('bad', ['', 'short pass', 'x' * 11, None, 'y' * 1025])
def test_weak_or_missing_passphrases_are_refused(bad):
    with pytest.raises(X.LogExportError) as err:
        make(passphrase=bad)
    assert '12 characters' in str(err.value) or 'required' in str(err.value)


def test_too_many_entries_are_refused(monkeypatch):
    monkeypatch.setattr(X, 'MAX_ENTRIES', 2)
    with pytest.raises(X.LogExportError, match='Narrow'):
        make(entries=ENTRIES * 3)


def test_unknown_log_and_not_an_export():
    with pytest.raises(X.LogExportError):
        make(log='Something else')
    with pytest.raises(C.FormatError):
        X.read_header(b'NCBAK' + b'\x01' * 40)


def test_an_existing_file_is_never_replaced(tmp_path):
    path = str(tmp_path / 'logs.nclog')
    X.write_export(path, make())
    first = open(path, 'rb').read()
    with pytest.raises(X.LogExportError, match='already exists'):
        X.write_export(path, make())
    assert open(path, 'rb').read() == first
    assert [p.name for p in tmp_path.iterdir()] == ['logs.nclog']     # no temp file left


# ================================================================ the command line
def test_cli_info_and_decrypt_to_csv(tmp_path):
    src, out = tmp_path / 'a.nclog', tmp_path / 'a.csv'
    X.write_export(str(src), make())
    lines = []
    assert X.main(['info', str(src)], out=lines.append) == 0
    assert 'Activity history: 1 entries' in lines[0] and PASS not in lines[0]
    assert X.main(['decrypt', str(src), '--out', str(out)], ask=lambda _p: PASS,
                  out=lines.append) == 0
    text = out.read_text(encoding='utf-8')
    assert text.splitlines()[0].startswith('created_at,user_label,category,device')
    assert 'MARKER-SECRET-LINE' in text and 'READABLE' in lines[-1]


def test_cli_json_wrong_passphrase_and_no_overwrite(tmp_path):
    src, out = tmp_path / 'a.nclog', tmp_path / 'a.json'
    X.write_export(str(src), make())
    lines = []
    assert X.main(['decrypt', str(src), '--out', str(out), '--format', 'json'],
                  ask=lambda _p: 'Wrong passphrase here', out=lines.append) == 2
    assert not out.exists() and 'passphrase is wrong' in lines[-1]
    assert X.main(['decrypt', str(src), '--out', str(out), '--format', 'json'],
                  ask=lambda _p: PASS, out=lines.append) == 0
    assert json.loads(out.read_text(encoding='utf-8'))['count'] == 1
    assert X.main(['decrypt', str(src), '--out', str(out)], ask=lambda _p: PASS,
                  out=lines.append) == 2                       # never replaces a file
    assert 'already exists' in lines[-1]


# ================================================================ what is collected
@pytest.fixture
def fake_store():
    db_fake.reset()
    yield db_fake
    db_fake.reset()


def activity(n, who):
    return [{'created_at': datetime(2026, 11, 26, 10, 0, i % 60), 'user_label': who,
             'category': 'app', 'device': '', 'device_ip': '', 'message': f'{who} line {i}',
             'result': '', 'level': 'info', 'tags': '', 'detail': ''} for i in range(n)]


def test_all_pages_are_collected_once(fake_store, monkeypatch):
    from gui import logs_tab as L
    monkeypatch.setattr(L, 'EXPORT_PAGE', 7)
    fake_store.add_console_events(activity(23, 'system'))
    rows = L.collect_entries(fake_store, True, '', '', '', {})
    assert len(rows) == 23 and len({r['message'] for r in rows}) == 23
    assert all('id' not in r for r in rows)


def test_the_export_is_limited_like_the_page(fake_store):
    from gui import logs_tab as L
    fake_store.add_console_events(activity(3, 'vi*****er@example.com') +
                                  activity(4, 'ad*****in@example.com') + activity(2, 'system'))
    scope = {'users': ['vi*****er@example.com', 'system']}
    rows = L.collect_entries(fake_store, True, '', '', 'ad*****in@example.com', scope)
    assert rows == []                                  # never another person's lines
    rows = L.collect_entries(fake_store, True, '', '', '', scope)
    assert {r['user_label'] for r in rows} == {'vi*****er@example.com', 'system'}
    assert len(rows) == 5
    assert len(L.collect_entries(fake_store, True, 'line 1', '', '', {})) == 3   # the search


# ================================================================ the Logs page
tk = pytest.importorskip('tkinter')


@pytest.fixture
def page(fake_store, monkeypatch, tmp_path):
    from gui import logs_tab as L
    from gui import theme
    from gui_helpers import new_root
    root = new_root()
    theme.apply(root)
    said, shown = [], []
    monkeypatch.setattr(L, 'log_event', lambda cat, msg, level='info', **k: said.append(msg))
    monkeypatch.setattr(L.messagebox, 'showinfo', lambda *a, **k: shown.append(('info', a)))
    monkeypatch.setattr(L.messagebox, 'showerror', lambda *a, **k: shown.append(('error', a)))
    target = tmp_path / 'export.nclog'
    monkeypatch.setattr(L.filedialog, 'asksaveasfilename', lambda **k: str(target))
    fake_store.add_console_events(activity(3, 'vi*****er@example.com') +
                                  activity(2, 'ad*****in@example.com'))
    tab = L.LogsTab(root, fake_store, scope_users=lambda: ('vi*****er@example.com', 'system'))
    tab.view.set(L.ACTIVITY)
    tab.change_view()
    yield root, tab, target, said, shown, L, monkeypatch
    root.destroy()


def wait(root, cond, seconds=20):
    import time
    end = time.time() + seconds
    while time.time() < end and not cond():
        root.update()
        time.sleep(0.02)
    return cond()


def test_the_page_exports_what_it_shows_encrypted(page):
    root, tab, target, said, shown, L, monkeypatch = page
    monkeypatch.setattr(L, 'ask_passphrase', lambda parent: PASS)
    assert tab.export_btn.cget('text') == 'Export (encrypted)...'
    tab.export_clicked()
    assert wait(root, lambda: shown)
    assert shown[0][0] == 'info' and target.exists()
    header, payload = X.open_export(target.read_bytes(), PASS)
    assert header['log'] == 'Activity history' and header['count'] == 3
    assert {e['user_label'] for e in payload['entries']} == {'vi*****er@example.com'}
    assert payload['filters']['limited_to'] == ['vi*****er@example.com', 'system']
    assert any('Exported 3 entries of the Activity history (encrypted)' in m for m in said)
    assert PASS not in ' '.join(said) + repr(shown)
    assert not tab.export_btn.instate(['disabled'])


def test_cancelling_the_passphrase_exports_nothing(page):
    root, tab, target, said, shown, L, monkeypatch = page
    monkeypatch.setattr(L, 'ask_passphrase', lambda parent: None)
    tab.export_clicked()
    root.update()
    assert not target.exists() and said == [] and shown == []


def test_an_existing_target_is_reported_not_replaced(page):
    root, tab, target, said, shown, L, monkeypatch = page
    target.write_bytes(b'keep me')
    monkeypatch.setattr(L, 'ask_passphrase', lambda parent: PASS)
    tab.export_clicked()
    assert wait(root, lambda: shown)
    assert shown[0][0] == 'error' and target.read_bytes() == b'keep me'
    assert any('FAILED' in m and 'already exists' in m for m in said)


def test_the_passphrase_dialog_requires_a_matching_strong_passphrase(page):
    root, tab, target, said, shown, L, monkeypatch = page
    answers = iter([('short', 'short'), ('Synthetic export pass 42', 'different pass 42!'),
                    (PASS, PASS)])
    problems = []

    def drive():
        win = [w for w in tab.winfo_children() if isinstance(w, tk.Toplevel)][-1]
        entries = [w for w in win.winfo_children()[0].winfo_children()
                   if w.winfo_class() == 'TEntry']
        label = [w for w in win.winfo_children()[0].winfo_children()
                 if w.winfo_class() == 'TLabel'][-1]
        bar = [w for w in win.winfo_children()[0].winfo_children()
               if w.winfo_class() == 'TFrame'][-1]
        ok = next(b for b in bar.winfo_children() if 'Encrypt' in str(b.cget('text')))
        for a, b in answers:
            entries[0].delete(0, 'end'); entries[0].insert(0, a)
            entries[1].delete(0, 'end'); entries[1].insert(0, b)
            ok.invoke()
            root.update()
            if not win.winfo_exists():
                return
            problems.append(label.cget('text'))
    root.after(50, drive)
    assert L.ask_passphrase(tab) == PASS
    assert '12 characters' in problems[0] and 'do not match' in problems[1]
