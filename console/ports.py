"""Which serial (COM) ports exist, and which of them look like a console adapter.

    scan = discover_ports()
    scan.ports      -> (ComPort, ...) sorted naturally: COM2 before COM10
    scan.error      -> None, or a fixed message when the ports could not be listed

Nothing is opened: this only reads the operating system's list of ports
(serial.tools.list_ports.comports()).

"Likely console" is only a hint for the user, never a fact: a USB-to-serial adapter can
be connected to anything. The confidence levels are:

    likely     Cisco's own USB console, or the port describes itself as a console
    possible   a generic USB-to-serial adapter (FTDI, Prolific, Silicon Labs, WCH) or a
               built-in serial port: often used for console cables, but not proven
    unlikely   Bluetooth, modems, virtual and remote-management ports
"""
import re
import sys
from dataclasses import dataclass

# USB vendor ids (hexadecimal, as in USB\VID_xxxx) of chips found in console cables
CISCO_VENDOR = 0x05A6                    # Cisco Systems: built-in USB console ports
USB_SERIAL_VENDORS = {
    0x0403: 'FTDI',
    0x067B: 'Prolific',
    0x10C4: 'Silicon Labs CP210x',
    0x1A86: 'WCH CH34x',
}
NOT_CONSOLE_WORDS = ('bluetooth', 'bthenum', 'modem', 'com0com', 'virtual', 'active management',
                     'amt sol', 'printer')
CONSOLE_WORDS = ('console', 'cisco serial')
ENUMERATION_FAILED = ('The list of serial ports could not be read from the operating system. '
                      'Check that the adapter driver is installed, then try again.')
WINDOWS_PORT = re.compile(r'^COM([1-9][0-9]{0,2})$', re.IGNORECASE)     # COM1 .. COM999


@dataclass(frozen=True)
class ComPort:
    device: str                  # COM4, COM10, /dev/ttyUSB0
    description: str
    hwid: str
    vid: int = None
    pid: int = None
    manufacturer: str = ''
    confidence: str = 'unlikely' # likely / possible / unlikely
    reason: str = ''

    @property
    def likely_console(self):
        return self.confidence == 'likely'

    def label(self):
        """'COM4 - USB Serial Port (possible console adapter: Prolific USB-to-serial)'"""
        text = f'{self.device} - {self.description}' if self.description else self.device
        if self.confidence != 'unlikely':
            text += f' ({self.confidence} console adapter: {self.reason})'
        return text


@dataclass(frozen=True)
class PortScan:
    ports: tuple = ()
    error: str = None

    @property
    def console_ports(self):
        return tuple(p for p in self.ports if p.likely_console)


def _text(value):
    return str(value).strip() if value not in (None, 'n/a') else ''


def classify(description='', hwid='', vid=None, manufacturer=''):
    """(confidence, reason) for one port. Only a hint for the user."""
    words = f'{description} {hwid} {manufacturer}'.lower()
    if any(w in words for w in NOT_CONSOLE_WORDS):
        return 'unlikely', 'Bluetooth, modem, virtual or remote-management port'
    if vid == CISCO_VENDOR or any(w in words for w in CONSOLE_WORDS):
        return 'likely', 'Cisco USB console' if vid == CISCO_VENDOR else 'describes itself as a console'
    if vid in USB_SERIAL_VENDORS:
        return 'possible', (f'{USB_SERIAL_VENDORS[vid]} USB-to-serial adapter; often a console '
                            f'cable, but it could be another serial device')
    if 'usb' in words and 'serial' in words:
        return 'possible', 'USB-to-serial adapter of unknown type'
    if 'pnp0501' in words or 'communications port' in words:
        return 'possible', 'built-in serial port (needs a console cable plugged into it)'
    return 'unlikely', 'not recognised as a console adapter'


def port_sort_key(device):
    """COM2 before COM10 (natural order); other names after, alphabetically."""
    m = WINDOWS_PORT.match(device or '')
    return (0, int(m.group(1)), '') if m else (1, 0, (device or '').lower())


def _from_listing(item):
    device = _text(getattr(item, 'device', ''))
    description = _text(getattr(item, 'description', ''))
    if description == device:
        description = ''
    hwid = _text(getattr(item, 'hwid', ''))
    vid, pid = getattr(item, 'vid', None), getattr(item, 'pid', None)
    manufacturer = _text(getattr(item, 'manufacturer', ''))
    confidence, reason = classify(description, hwid, vid, manufacturer)
    return ComPort(device=device, description=description, hwid=hwid, vid=vid, pid=pid,
                   manufacturer=manufacturer, confidence=confidence, reason=reason)


def discover_ports(comports=None):
    """Every serial port the operating system reports, as a PortScan. Never raises:
    an enumeration error is returned as PortScan(error=...) with no ports."""
    if comports is None:
        try:
            from serial.tools.list_ports import comports
        except Exception:                                  # pyserial missing or broken
            return PortScan(error=ENUMERATION_FAILED)
    try:
        listing = list(comports())
    except Exception:
        return PortScan(error=ENUMERATION_FAILED)
    ports = [_from_listing(item) for item in listing]
    ports = [p for p in ports if p.device]
    return PortScan(ports=tuple(sorted(ports, key=lambda p: port_sort_key(p.device))))


def check_port_name(name, platform=None):
    """The port name, normalised ('com10' -> 'COM10'), or ValueError with a message.
    Windows names are COM1 .. COM999 (pyserial adds the \\\\.\\ prefix needed above COM9);
    elsewhere a /dev/... path."""
    text = (name or '').strip()
    if not text:
        raise ValueError('Choose a serial port (for example COM4).')
    windows = (platform or sys.platform).startswith('win')
    if windows:
        m = WINDOWS_PORT.match(text)
        if not m:
            raise ValueError(f'"{text}" is not a Windows serial port name (COM1 to COM999).')
        return f'COM{int(m.group(1))}'
    if not text.startswith('/dev/'):
        raise ValueError(f'"{text}" is not a serial device path (for example /dev/ttyUSB0).')
    return text
