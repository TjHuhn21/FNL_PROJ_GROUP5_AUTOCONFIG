"""Icons come from the Segoe Fluent Icons font that ships with Windows 11
(or Segoe MDL2 Assets on Windows 10). No image files are needed.

If neither font is installed, icon_font() returns None and the interface shows
text only, so the app still works everywhere.
"""
import tkinter.font as tkfont

ICON_FONTS = ('Segoe Fluent Icons', 'Segoe MDL2 Assets')   # first one found is used

# Code points checked by rendering them from the font itself.
GLYPHS = {
    'dashboard': '',   # tiles
    'scan':      '',   # magnifying glass
    'devices':   '',   # network device
    'topology':  '',   # hierarchy
    'findings':  '',   # shield
    'configure': '',   # gear
    'setup':     '',   # screen with a plugged-in cable (console connection)
    'logs':      '',   # history
    'accounts':  '',   # people (user accounts; admins only)
}

_family_cache = {}


def icon_family(root):
    """Name of the installed icon font, or None. Looked up once per window."""
    key = str(root)
    if key not in _family_cache:
        installed = set(tkfont.families(root))
        _family_cache[key] = next((f for f in ICON_FONTS if f in installed), None)
    return _family_cache[key]


def icon_font(root, size=16):
    """A (family, size) font for icons, or None when no icon font is installed."""
    family = icon_family(root)
    return (family, size) if family else None


def glyph(name):
    """The icon character for a page name ('' if there is none)."""
    return GLYPHS.get(name, '')
