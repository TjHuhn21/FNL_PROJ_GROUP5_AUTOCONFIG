"""Initial Setup for a BRAND-NEW device, without any other terminal program: the SSH setup
plus the management IP address the operator types and, optionally, saving (write memory).

Against the mock lab's simulated consoles (SIM47 brand-new switch, SIM48 brand-new
router). Offline: no COM port, no device, no network. The password is synthetic.
"""
import os
import sys

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path[:0] = [ROOT, os.path.join(ROOT, 'mock-lab')]

from console.apply import approvals_needed, apply_plan, confirmation_phrase  # noqa: E402
from console.detect import detect_device  # noqa: E402
from console.link import SAVE_COMMAND, ConsoleError, check_config_line  # noqa: E402
from console.plan import build_plan, validate_request  # noqa: E402
from console.steps import FAILED, VERIFIED  # noqa: E402
from mocklab.console import MockConsoleBackend  # noqa: E402

PW = 'Synth3tic-Pass!'
NEW_SWITCH = dict(port='SIM47', iface='Vlan1', ip='192.168.1.2', gw='192.168.1.1')
NEW_ROUTER = dict(port='SIM48', iface='GigabitEthernet0/0', ip='192.168.1.1',
                  gw='192.168.1.254')


def session(port):
    s = MockConsoleBackend(delay=0).open_session(port, 9600, '', '', '', None)
    s.connect()
    return s, detect_device(s)


def request(r, iface='', ip='', mask='/24', gw='', save=True, host='NEW-1'):
    return validate_request(host, 'lab.local', 'netadmin', PW, PW, 2048, r,
                            mgmt_interface=iface, mgmt_ip=ip, mgmt_mask=mask if ip else '',
                            gateway=gw, save=save)


def apply(s, r, req, plan, approve=True):
    return apply_plan(s, plan, r, req, password=PW, confirm=PW,
                      confirmation=confirmation_phrase(plan),
                      approvals={x.step_id for x in approvals_needed(plan)} if approve else ())


@pytest.mark.parametrize('dev', [NEW_SWITCH, NEW_ROUTER], ids=['switch', 'router'])
def test_a_brand_new_device_is_made_ready_from_the_app(dev):
    s, r = session(dev['port'])
    assert r.device.hostname in ('Switch', 'Router') and not any(i.ip for i in r.interfaces)
    req, errors = request(r, dev['iface'], dev['ip'], gw=dev['gw'])
    assert errors == {} and req.mgmt_mask == '255.255.255.0'       # /24 converted
    plan = build_plan(r, req)
    lines = plan.lines()
    assert f"interface {dev['iface']}" in lines and f" ip address {dev['ip']} 255.255.255.0" in lines
    assert ' no shutdown' in lines and SAVE_COMMAND not in lines    # saving is not a config line
    gateway = ('ip default-gateway ' if dev['port'] == 'SIM47' else 'ip route 0.0.0.0 0.0.0.0 ')
    assert gateway + dev['gw'] in lines
    assert [st.step_id for st in plan.steps][-4:] == ['mgmt_ip', 'mgmt_up', 'gateway', 'save']
    assert plan.step('save').approval_required
    res = apply(s, r, req, plan)
    assert res.outcome == 'success' and res.saved, res.message
    assert all(st.status == VERIFIED for st in res.steps)
    assert res.commands_sent[-1] == SAVE_COMMAND                    # the very last thing sent
    assert dev['ip'] in s.device.startup and 'hostname NEW-1' in s.device.startup
    assert 'Saved:' in res.message and PW not in repr(res)


def test_without_management_fields_nothing_about_an_address_is_proposed():
    s, r = session('SIM47')
    req, errors = request(r, save=False)
    assert errors == {}
    plan = build_plan(r, req)
    assert not any(l.startswith(('interface ', 'ip default-gateway')) for l in plan.lines())
    assert plan.item('management').commands == []
    assert plan.item('save').status == 'needs_attention'            # changes would be lost


def test_an_interface_alone_sets_no_management_address():
    """The switch's Vlan1 is preselected: without an IP it simply means "no management IP"."""
    s, r = session('SIM47')
    req, errors = validate_request('NEW-1', 'lab.local', 'netadmin', 'Str0ng-Pass!',
                                   'Str0ng-Pass!', 2048, r, mgmt_interface='Vlan1')
    assert not errors and req.mgmt_interface == '' and req.mgmt_ip == ''


@pytest.mark.parametrize('fields, key, words', [
    (dict(iface='Vlan99', ip='192.168.1.2'), 'mgmt_interface', 'was not found'),
    (dict(iface='Vlan1', ip='', mask='/24'), 'mgmt_ip', 'Required'),   # a mask, but no IP
    (dict(iface='Vlan1', ip='300.1.1.1'), 'mgmt_ip', '0-255'),
    (dict(iface='Vlan1', ip='192.168.1.0'), 'mgmt_ip', 'network address'),
    (dict(iface='Vlan1', ip='192.168.1.2', mask='255.0.255.0'), 'mgmt_mask', 'contiguous'),
    (dict(iface='Vlan1', ip='192.168.1.2', gw='10.0.0.1'), 'gateway', 'not inside'),
    (dict(iface='Vlan1', ip='192.168.1.2', gw='192.168.1.2'), 'gateway', 'own address'),
])
def test_the_management_fields_are_checked(fields, key, words):
    s, r = session('SIM47')
    if not fields.get('ip'):
        _req, errors = validate_request('NEW-1', 'lab.local', '', '', '', 2048, r,
                                        mgmt_interface=fields['iface'],
                                        mgmt_mask=fields.get('mask', ''))
    else:
        _req, errors = request(r, fields['iface'], fields['ip'],
                               mask=fields.get('mask', '/24'), gw=fields.get('gw', ''))
    assert words in errors.get(key, ''), errors


def test_saving_needs_its_own_approval_and_runs_only_after_everything_is_verified():
    s, r = session('SIM47')
    req, _ = request(r, 'Vlan1', '192.168.1.2')
    plan = build_plan(r, req)
    refused = apply(s, r, req, plan, approve=False)
    assert refused.outcome == 'refused' and refused.commands_sent == []
    s.device.quirks.add('save_fails')                               # NVRAM error on write
    res = apply(s, r, req, plan)
    assert res.step('save').status == FAILED and res.saved is False
    assert 'Nothing was saved' in res.message


def test_the_session_never_saves_unless_the_plan_asked_for_it():
    s, _r = session('SIM47')
    with pytest.raises(ConsoleError):
        s.save_config()
    assert SAVE_COMMAND not in s.config_sent


def test_only_the_exact_no_shutdown_line_is_an_exception():
    assert check_config_line('no shutdown') == 'no shutdown'
    for line in ('no ip address', 'no username admin', 'shutdown', 'write memory',
                 'no shutdown ; reload'):
        with pytest.raises(ConsoleError):
            check_config_line(line)
