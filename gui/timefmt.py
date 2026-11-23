"""How times are shown on screen: 12-hour clock with AM/PM ('3:19 AM', '3:19:39 AM').
Display only: timestamps are stored and compared exactly as before."""
from datetime import datetime


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


def format_date_time(dt, seconds=False):
    """'2026-11-24 3:19:39 AM'; '' when dt is None."""
    if dt is None:
        return ''
    return f'{dt:%Y-%m-%d} {format_time(dt, seconds)}'


def now_text(seconds=True):
    """The current time, as format_time shows it."""
    return format_time(datetime.now(), seconds)
