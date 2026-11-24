"""Device types: what the scan detected and what the user chose.

Every device has two type values:
  type           the one the app uses (Configure, Topology, Overview). The user may change it
                 on the Devices page (Edit), after a confirmation.
  detected_type  what the last scan detected. Only scans write it. None: never scanned
                 (added by hand).

A rescan updates detected_type, and updates type only when the user has not changed it
(type_after_scan). The Devices table marks a device whose type differs from a definite
detection (manually_changed). Used by db.py, db_fake.py and the screens; no window code.
"""
SWITCH, ROUTER, UNKNOWN = 'switch', 'router', 'unknown'
TYPES = (SWITCH, ROUTER, UNKNOWN)
KNOWN = (SWITCH, ROUTER)
MANUAL_NOTE = 'changed manually'


def clean(value):
    """A valid type, or 'unknown'."""
    return value if value in TYPES else UNKNOWN


def type_after_scan(current, detected_before, scanned):
    """The type a device keeps when a scan finds it again.

    current: its type now; detected_before: what the previous scan detected (None: never
    scanned, so the type was chosen by hand); scanned: what this scan detected.
      * an unknown type takes the scan's answer;
      * a known type is never replaced by 'unknown';
      * a type the user chose (added by hand, or changed after the last scan) is kept;
      * otherwise the scan's answer (the device itself changed)."""
    scanned = clean(scanned)
    if current not in KNOWN:
        return scanned
    if scanned == UNKNOWN:
        return current
    if detected_before is None or current != detected_before:
        return current
    return scanned


def manually_changed(device):
    """True when the device's type differs from what a scan definitely detected (a
    detection of 'unknown', or none at all, is never a conflict)."""
    detected = (device or {}).get('detected_type')
    return detected in KNOWN and (device or {}).get('type') != detected


def type_label(device):
    """The Type shown in the Devices table: 'switch' or 'switch (changed manually)'."""
    kind = (device or {}).get('type') or UNKNOWN
    return f'{kind} ({MANUAL_NOTE})' if manually_changed(device) else kind


def detected_tooltip(device):
    """'Detected as router by scan', or '' when nothing definite was detected."""
    detected = (device or {}).get('detected_type')
    return f'Detected as {detected} by scan' if detected in KNOWN else ''
