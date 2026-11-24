"""One place for every size on screen: text, spacing, row heights.

    UI_TEXT_SIZE = 'normal'        # 'small' | 'normal' | 'large' | 'larger'

Change UI_TEXT_SIZE (or set the environment variable NETCOMMAND_UI_TEXT_SIZE to one of those
words) to make ALL text, spacing and table rows bigger or smaller. Nothing else needs to
change: gui/theme.py takes every font and size from here.

How the factor is made (factor()):
  * Windows display scaling (100 % / 125 % / 150 %) is handled by the operating system and
    the toolkit: the app is made DPI-aware (sharp, not blurry text; enable_dpi_awareness),
    and fonts are given in POINTS, which Tk converts with the real screen DPI. So a 10 pt
    font is the same physical size at every scaling;
  * the screen's size in logical pixels nudges it: a small laptop screen (e.g. 1366 x 768)
    a little smaller, a large screen (e.g. 2560 x 1440 at 100 %) a little larger;
  * UI_TEXT_SIZE multiplies the result.
Text never goes below MIN_BODY / MIN_SMALL points. Spacing and row heights are in PIXELS,
which Tk does NOT scale itself, so space() multiplies them by the DPI as well.

The size is fixed for the session (text that changed while a window edge is dragged would
make the layout jump); only the Overview's big numbers follow the window (overview_page).
When the window moves to a monitor with another DPI, rescale() updates the shared fonts and
table styles (gui/theme.watch_dpi).
"""
import os
import sys

UI_TEXT_SIZE = 'normal'
TEXT_SIZES = {'small': 0.9, 'normal': 1.0, 'large': 1.15, 'larger': 1.3}
MIN_BODY, MIN_SMALL = 10, 9          # points: body text never smaller than this
BASE_DPI = 96.0                       # 100 % Windows scaling

_state = {'dpi': BASE_DPI, 'factor': 1.0, 'screen': 1.0}


def text_size_setting():
    """The chosen text size word (environment variable first, then UI_TEXT_SIZE)."""
    word = os.environ.get('NETCOMMAND_UI_TEXT_SIZE', UI_TEXT_SIZE).strip().lower()
    return word if word in TEXT_SIZES else 'normal'


def enable_dpi_awareness():
    """Windows: make the process DPI-aware BEFORE any window exists, so text is drawn at
    the real resolution (sharp at 125 % / 150 %) instead of being stretched (blurry).
    Per-monitor aware when possible. Does nothing elsewhere; never fails."""
    if not sys.platform.startswith('win'):
        return False
    try:
        import ctypes
        try:
            ctypes.windll.shcore.SetProcessDpiAwareness(2)     # per-monitor
        except Exception:
            ctypes.windll.user32.SetProcessDPIAware()          # older Windows: system-wide
        return True
    except Exception:
        return False


def screen_factor(logical_width):
    """A small adjustment for the screen's size in logical pixels (after Windows scaling):
    small laptop screens a little smaller, very large screens a little larger."""
    if logical_width < 1500:          # e.g. 1366 x 768 at 100 %, 1920 x 1080 at 150 %
        return 0.95
    if logical_width < 2300:          # e.g. 1920 x 1080 at 100 %, 2560 x 1440 at 150 %
        return 1.0
    return 1.12                       # e.g. 2560 x 1440 at 100 %


def measure(root):
    """Read the screen (DPI and size) and set the factor. Returns the factor."""
    try:
        dpi = float(root.winfo_fpixels('1i'))
        width = float(root.winfo_screenwidth())
    except Exception:
        dpi, width = BASE_DPI, 1920.0
    dpi = dpi if dpi > 0 else BASE_DPI
    _state['dpi'] = dpi
    _state['screen'] = screen_factor(width / (dpi / BASE_DPI))
    _state['factor'] = TEXT_SIZES[text_size_setting()] * _state['screen']
    return _state['factor']


def rescale(dpi):
    """The window moved to a monitor with another DPI: keep the factor, use the new DPI
    for pixel sizes. Returns True when it changed."""
    if not dpi or abs(dpi - _state['dpi']) < 1:
        return False
    _state['dpi'] = float(dpi)
    return True


def factor():
    return _state['factor']


def dpi_scale():
    """Pixels per 'design pixel' (1.0 at 100 %, 1.5 at 150 %)."""
    return _state['dpi'] / BASE_DPI


def font_size(points, minimum=None):
    """A font size in points, scaled; never below `minimum` (default MIN_SMALL)."""
    low = MIN_SMALL if minimum is None else minimum
    return max(low, int(round(points * _state['factor'])))


def space(pixels):
    """A spacing / padding / width in pixels, scaled by the DPI and the text size."""
    return max(1, int(round(pixels * dpi_scale() * _state['factor'])))


# The spacing scale (use these instead of loose numbers): 4 / 8 / 12 / 16 / 24 design px
def xs():
    return space(4)


def sm():
    return space(8)


def md():
    return space(12)


def lg():
    return space(16)


def xl():
    return space(24)


def row_height(font_linespace):
    """A table row: the font's line height plus room above and below."""
    return int(font_linespace + space(10))
