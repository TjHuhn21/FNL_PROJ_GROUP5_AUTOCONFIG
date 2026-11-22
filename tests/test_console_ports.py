"""console.ports: listing COM ports and hinting which look like a console adapter.
Offline: the operating system's port list is replaced by fake entries; nothing is opened."""
from types import SimpleNamespace

import pytest

from console import ports
from console.ports import ComPort, check_port_name, classify, discover_ports, port_sort_key


def entry(device, description='', hwid='', vid=None, pid=None, manufacturer=None):
    return SimpleNamespace(device=device, description=description, hwid=hwid, vid=vid, pid=pid,
                           manufacturer=manufacturer)


def listing(*items):
    return lambda: list(items)


def test_discovery_reports_name_description_hwid_and_hint():
    scan = discover_ports(listing(
        entry('COM4', 'Prolific USB-to-Serial Comm Port (COM4)',
              'USB VID:PID=067B:2303 SER=5 LOCATION=1-3', 0x067B, 0x2303, 'Prolific'),
        entry('COM3', 'Cisco Serial (COM3)', 'USB VID:PID=05A6:0001', 0x05A6, 0x0001, 'Cisco')))
    assert scan.error is None
    assert [p.device for p in scan.ports] == ['COM3', 'COM4']
    cisco, prolific = scan.ports
    assert cisco.description == 'Cisco Serial (COM3)' and cisco.hwid.startswith('USB VID:PID=05A6')
    assert cisco.likely_console and cisco.confidence == 'likely'
    assert prolific.confidence == 'possible' and not prolific.likely_console
    assert scan.console_ports == (cisco,)
    assert 'possible console adapter' in prolific.label()


def test_no_ports():
    scan = discover_ports(listing())
    assert scan.ports == () and scan.error is None and scan.console_ports == ()


def test_enumeration_failure_is_reported_not_raised():
    def broken():
        raise OSError('SetupDiGetClassDevs failed')
    scan = discover_ports(broken)
    assert scan.ports == ()
    assert scan.error == ports.ENUMERATION_FAILED
    assert 'SetupDi' not in scan.error


def test_entries_without_a_device_name_are_skipped():
    scan = discover_ports(listing(entry(''), entry(None), entry('COM5', 'Communications Port')))
    assert [p.device for p in scan.ports] == ['COM5']


def test_description_equal_to_the_name_is_dropped_and_na_is_blank():
    scan = discover_ports(listing(entry('COM7', 'COM7', 'n/a')))
    port = scan.ports[0]
    assert port.description == '' and port.hwid == '' and port.label() == 'COM7'


def test_com10_and_above_sort_naturally():
    scan = discover_ports(listing(entry('COM10'), entry('COM2'), entry('COM1'), entry('COM100'),
                                  entry('/dev/ttyUSB0')))
    assert [p.device for p in scan.ports] == ['COM1', 'COM2', 'COM10', 'COM100', '/dev/ttyUSB0']
    assert port_sort_key('COM9') < port_sort_key('COM10')


@pytest.mark.parametrize('description, hwid, vid, expected', [
    ('Cisco USB Console', 'USB VID:PID=05A6:0001', 0x05A6, 'likely'),
    ('USB Console Cable', '', None, 'likely'),
    ('USB Serial Port (COM6)', 'FTDIBUS\\VID_0403+PID_6001', 0x0403, 'possible'),
    ('Silicon Labs CP210x USB to UART Bridge', 'USB VID:PID=10C4:EA60', 0x10C4, 'possible'),
    ('USB-SERIAL CH340 (COM8)', 'USB VID:PID=1A86:7523', 0x1A86, 'possible'),
    ('Some USB Serial Device', 'USB VID:PID=1234:5678', 0x1234, 'possible'),
    ('Communications Port (COM1)', 'ACPI\\PNP0501\\0', None, 'possible'),
    ('Standard Serial over Bluetooth link (COM5)', 'BTHENUM\\{00001101}', None, 'unlikely'),
    ('Intel(R) Active Management Technology - SOL (COM3)', 'PCI\\VEN_8086', None, 'unlikely'),
    ('com0com - serial port emulator', 'COM0COM\\PORT', None, 'unlikely'),
    ('USB Modem', 'USB VID:PID=0403:0001', 0x0403, 'unlikely'),
    ('Unknown device', 'PCI\\VEN_ABCD', None, 'unlikely'),
])
def test_classify(description, hwid, vid, expected):
    assert classify(description, hwid, vid)[0] == expected


def test_a_generic_usb_serial_adapter_is_never_called_a_console():
    """A USB-to-serial chip can be wired to anything: only 'possible', with that said."""
    confidence, reason = classify('USB Serial Port', 'USB VID:PID=067B:2303', 0x067B)
    assert confidence == 'possible'
    assert 'could be another serial device' in reason


@pytest.mark.parametrize('name, expected', [
    ('COM4', 'COM4'), ('com4', 'COM4'), (' COM10 ', 'COM10'), ('COM255', 'COM255'),
])
def test_windows_port_names(name, expected):
    assert check_port_name(name, platform='win32') == expected


@pytest.mark.parametrize('name', ['', None, 'COM0', 'COM', 'COM1000', 'LPT1', 'COM4;show',
                                  '\\\\.\\COM4', '/dev/ttyUSB0'])
def test_bad_windows_port_names(name):
    with pytest.raises(ValueError):
        check_port_name(name, platform='win32')


def test_other_platforms_need_a_dev_path():
    assert check_port_name('/dev/ttyUSB0', platform='linux') == '/dev/ttyUSB0'
    with pytest.raises(ValueError):
        check_port_name('COM4', platform='linux')


def test_the_real_listing_function_is_used_by_default(monkeypatch):
    import serial.tools.list_ports as lp
    monkeypatch.setattr(lp, 'comports', listing(entry('COM12', 'USB Serial Port')))
    assert [p.device for p in discover_ports().ports] == ['COM12']


def test_comport_is_immutable():
    port = ComPort('COM4', '', '')
    with pytest.raises(Exception):
        port.device = 'COM5'
