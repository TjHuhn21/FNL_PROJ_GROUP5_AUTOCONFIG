"""The simple Initial Setup screen (gui/setup_quick.py) on the MOCK console: Connect
(detection runs by itself) -> one form, password typed ONCE -> Set up SSH (one plain
confirmation) -> Done -> "Use in Scan page" fills in the Scan page. No real device."""
import os
import sys

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path[:0] = [ROOT, os.path.join(ROOT, 'mock-lab'), os.path.dirname(__file__)]
tk = pytest.importorskip('tkinter')

from gui.components import dialogs  # noqa: E402
from gui.setup_tab import SetupTab  # noqa: E402
from mocklab.console import MockConsoleBackend  # noqa: E402
from test_setup_tab import root, settle  # noqa: E402,F401
from gui_helpers import pump  # noqa: E402

PW = 'Lab-Pass1234'


@pytest.fixture
def asked(monkeypatch):
    seen = []
    monkeypatch.setattr(dialogs, '_runner', lambda t, m, **o: seen.append((t, m, o)) or True)
    return seen


def connected(root, port):
    tab = SetupTab(root, backend=MockConsoleBackend(delay=0))
    tab.pack(fill='both', expand=True)
    filled = []
    tab.on_use_in_scan = lambda ip, user, pw: filled.append((ip, user, pw))
    tab.filled = filled
    tab.refresh_ports()
    settle(root, tab)
    tab.port_var.set(next(p.label() for p in tab.ports if p.device == port))
    tab.quick.connect()
    assert pump(root, lambda: tab.quick.form_box.winfo_manager() and not tab.busy, 20)
    return tab


def test_the_simple_flow_on_the_r1(root, asked):
    tab = connected(root, 'SIM49')
    q = tab.quick
    assert '✓' in q.device_text.cget('text') and 'CISCO1941' in q.device_text.cget('text')
    assert q.vars['hostname'].get() == 'R1' and q.vars['username'].get() == 'admin'
    assert 'already exists' in q.user_note.cget('text')
    assert q.vars['interface'].get().startswith('GigabitEthernet0/0')
    assert not tab.advanced.winfo_manager()                     # the details are tucked away
    q.vars['password'].set(PW)
    q.vars['again'].set(PW)
    q.vars['ip'].set('192.168.1.1')
    q.set_up()
    title, message, options = asked[-1]
    assert title == 'Set up SSH' and options['confirm_text'] == 'Set up SSH'
    assert 'its password will be REPLACED' in message
    assert 'set the new password for admin' in message
    assert 'scan it at 192.168.1.1 as "admin"' in message
    assert q.vars['password'].get() == ''                       # typed once, then cleared
    assert pump(root, lambda: q.done_box.winfo_manager(), 30)
    root.update()
    assert tab.apply_result.outcome == 'success'
    assert tab.apply_result.saved                               # always saved
    text = q.done_text.cget('text')
    assert 'SSH is ready on R1' in text and 'Seed IP:   192.168.1.1' in text
    q.use_in_scan()
    assert tab.filled == [('192.168.1.1', 'admin', PW)]
    assert q.secret is None                                     # handed over, not kept


def test_a_new_switch_needs_a_name_and_the_ip(root, asked):
    tab = connected(root, 'SIM50')
    q = tab.quick
    assert q.vars['hostname'].get() == ''                       # "Switch" is not kept
    assert q.vars['interface'].get().startswith('Vlan1')
    q.set_up()
    assert 'Seed IP' in q.error.cget('text')                    # the IP is needed for Scan
    q.vars['ip'].set('192.168.1.2')
    q.set_up()
    assert 'Required' in q.error.cget('text')                   # the name (not "Switch")
    q.vars['hostname'].set('SW1')
    q.vars['password'].set(PW)
    q.vars['again'].set(PW)
    q.set_up()
    assert pump(root, lambda: q.done_box.winfo_manager(), 30)
    assert tab.apply_result.outcome == 'success'
    assert 'SSH is ready on SW1' in q.done_text.cget('text')


def test_a_device_without_ssh_gets_no_form(root, asked):
    tab = SetupTab(root, backend=MockConsoleBackend(delay=0))
    tab.pack(fill='both', expand=True)
    tab.refresh_ports()
    settle(root, tab)
    tab.port_var.set(next(p.label() for p in tab.ports if p.device == 'SIM3'))
    tab.quick.connect()
    assert pump(root, lambda: tab.quick.device_box.winfo_manager() and not tab.busy, 20)
    assert '✗' in tab.quick.device_text.cget('text')
    assert not tab.quick.form_box.winfo_manager()
