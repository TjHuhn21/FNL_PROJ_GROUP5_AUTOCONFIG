"""How dates and times are shown on screen: 12-hour clock with AM/PM, everywhere.

    format_time(dt)                 '3:19 AM'      (seconds=True: '3:19:39 AM')
    format_datetime(dt)             'Nov 24, 2026 1:50 PM'   (seconds=True: '1:50:17 PM')
    format_timestamp_text(text)     a stored text timestamp ('2026-11-24T05:50:17Z', UTC, or
                                    '2026-11-24 13:50:17') shown the same way, in local time
    now_text()                      the current time, as format_time shows it

Display only: timestamps are stored, sorted and compared exactly as before (always sort
by the real value, never by these texts).
"""
from datetime import datetime, timezone

MONTHS = ('Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun', 'Jul', 'Aug', 'Sep', 'Oct', 'Nov', 'Dec')


def format_time(dt, seconds=False):
    """'3:19 AM' (or '3:19:39 AM' with seconds=True); '' when dt is None.
    Built by hand: strftime's no-padding flags differ between Windows and Linux."""
    if dt is None:
        return ''
    hour = dt.hour % 12 or 12
    text = f'{hour}:{dt.minute:02d}'
    if seconds:
        text += f':{dt.second:02d}'
    return f"{text} {'AM' if dt.hour < 12 else 'PM'}"


def format_date(dt):
    """'Nov 24, 2026'; '' when dt is None."""
    if dt is None:
        return ''
    return f'{MONTHS[dt.month - 1]} {dt.day}, {dt.year}'


def format_datetime(dt, seconds=False):
    """'Nov 24, 2026 1:50 PM' (or '... 1:50:17 PM' with seconds=True); '' when dt is None."""
    if dt is None:
        return ''
    return f'{format_date(dt)} {format_time(dt, seconds)}'


format_date_time = format_datetime            # the older name, still used by some pages


def parse_timestamp(text):
    """A stored text timestamp -> a LOCAL datetime, or None when it is not one.
    'Z' / '+00:00' (UTC, as backups record it) is converted to this computer's time."""
    if isinstance(text, datetime):
        return text
    value = str(text or '').strip()
    if not value:
        return None
    try:
        dt = datetime.fromisoformat(value.replace('Z', '+00:00'))
    except ValueError:
        return None
    if dt.tzinfo is not None:
        dt = dt.astimezone().replace(tzinfo=None)    # UTC -> local time
    return dt


def format_timestamp_text(text, seconds=True):
    """A stored text timestamp shown as format_datetime does; the original text when it
    cannot be read (never hidden)."""
    dt = parse_timestamp(text)
    return format_datetime(dt, seconds) if dt is not None else str(text or '')


def now_text(seconds=True):
    """The current time, as format_time shows it."""
    return format_time(datetime.now(), seconds)


def utc_now():
    return datetime.now(timezone.utc)
