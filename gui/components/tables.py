"""One way to set up every table (ttk.Treeview) in NetCommand, so they all look the same.

    setup_table(tree, [('name', 'Name', 180), ('ip', 'IP', 150), ('status', 'Status', 85)],
                commands={'name': sort_by_name})

Each column is (key, title, relative width) or (key, title, relative width, align):
  * HEADER AND CELLS USE THE SAME ALIGNMENT (they used to differ: centered headers over
    left-aligned values). The alignment follows the column (align_for): text left, short
    status/value columns centered, numbers right; a 4th item overrides it.
  * The width is RELATIVE: columns share the table's width in these proportions (short
    columns stay narrow, long ones get the extra room) and are refitted when the table is
    resized, never below a minimum. Sizes are scaled by gui/ui_scale.py.
  * A cell whose text does not fit shows its full text in a tooltip when the pointer is on
    it (the row values themselves are never changed, so sorting, selection and double-click
    work as before).
Row height and fonts come from the table's style (gui/theme.py: 'Treeview' / 'Data.Treeview'),
which scale with the text size.
"""
import tkinter as tk
import tkinter.font as tkfont
from tkinter import ttk

from gui import theme, ui_scale

LEFT, CENTER, RIGHT = 'w', 'center', 'e'
# column key or title (lower case) -> alignment
# Short numbers such as a VLAN read best centered in a narrow column (right-aligned, they
# end up against the next column's header or at the far edge of a small table).
CENTER_COLUMNS = {'vlan id', 'vlan', 'native', 'native vlan', 'max', 'max mac addresses',
                  'type', 'status', 'managed', 'role', 'verified', 'email verified', 'lock',
                  'locked', 'result', 'source', 'max', 'maximum', 'sticky', 'severity',
                  'check', 'state', 'level', 'violation'}
RIGHT_COLUMNS = {'id', 'size', 'count', 'devices', 'commands', 'port count', 'lines'}
MIN_WIDTH = 48                       # design pixels: no column narrower than this
# Date / time columns always show the whole date: their minimum is MEASURED from this
# sample in the table's own font (so it fits at every text size and Windows scaling)
DATE_COLUMNS = {'date', 'when', 'created', 'time', 'created_at', 'saved'}
DATE_SAMPLE = 'Nov 30, 2026 12:59:59 PM'
DATE_SAMPLE_SHORT = 'Nov 30, 2026 12:59 PM'          # dates shown without seconds
DATE_MIN_WIDTH = 200                                  # design pixels, before measuring
CELL_PADDING = 16                                     # design pixels around a cell's text
EDGE = 4                             # design pixels kept free at the table's right edge
FIT_SETTLE_MS = 180                  # refit this long after the last size change


def is_date_column(key, title):
    names = {str(key).lower(), str(title).lower().split(' (')[0].strip()}
    return bool(names & DATE_COLUMNS)


def min_width(key, title, width):
    """A column's minimum width in design pixels (before a date column is measured)."""
    if is_date_column(key, title):
        return DATE_MIN_WIDTH
    return min(width, MIN_WIDTH)


def min_pixels(tree, spec):
    """A column's minimum width in real pixels: never narrower than its own header text
    (measured in the header font), and a sample text (dates, or a min_widths entry given as
    text) is measured in the table's font; numbers are design pixels."""
    key, title, width, _align = spec
    own = getattr(tree, 'nc_min', {}).get(key)
    sample = own if isinstance(own, str) else (DATE_SAMPLE if own is None and
                                                is_date_column(key, title) else None)
    pad = ui_scale.space(CELL_PADDING)
    try:
        header = heading_font(tree).measure(str(title)) + pad if title else 0
    except tk.TclError:
        header = 0
    if sample:
        try:
            return max(header, table_font(tree).measure(sample) + pad)
        except tk.TclError:
            return max(header, ui_scale.space(DATE_MIN_WIDTH))
    return max(header, ui_scale.space(own if own is not None else min_width(key, title, width)))


def align_for(key, title=''):
    """The alignment of a column by its key or title (see the module notes)."""
    names = {str(key).lower(), str(title).lower().strip()}
    if names & CENTER_COLUMNS:          # checked first: 'id' alone is right, 'VLAN ID' centered
        return CENTER
    if names & RIGHT_COLUMNS:
        return RIGHT
    return LEFT


def _spec(column):
    key, title, width = column[0], column[1], column[2]
    align = column[3] if len(column) > 3 and column[3] else align_for(key, title)
    return key, title, max(int(width), 1), align


def setup_table(tree, columns, commands=None, fit=True, tooltips=True, no_tooltip=(),
                min_widths=None):
    """Configure the tree's columns (see the module notes). commands: {key: function}
    called when that column's heading is clicked (sorting). no_tooltip: columns that show
    their own tooltip. min_widths: {key: design pixels} instead of the usual minimum (e.g.
    a short date without seconds; a TEXT is measured in the table's font, e.g.
    DATE_SAMPLE_SHORT). Returns the specs.

    The widest column also stretches by itself (Tk), so the table never shows an empty
    strip on the right, even before (or without) a refit."""
    tree.nc_no_tooltip = set(no_tooltip)
    tree.nc_min = dict(min_widths or {})
    specs = [_spec(c) for c in columns]
    commands = commands or {}
    widest = max(specs, key=lambda s: s[2])[0] if specs else None
    for spec in specs:
        key, title, width, align = spec
        heading = {'text': title, 'anchor': align}
        if key in commands:
            heading['command'] = commands[key]
        tree.heading(key, **heading)
        low = min_pixels(tree, spec)
        tree.column(key, width=max(ui_scale.space(width), low), anchor=align,
                    stretch=key == widest, minwidth=low)
    tree.nc_specs = specs
    if fit:
        tree.bind('<Configure>', lambda e: _fit_later(tree), add='+')
        tree.bind('<Map>', lambda e: _fit_later(tree), add='+')     # shown again
    if tooltips:
        CellTooltip(tree)
    return specs


def _fit_later(tree):
    """Refit once the size settles (a drag sends many <Configure> events): while the edge
    moves, Tk's own stretching of the widest column keeps the table filled smoothly; the
    proportions are set once, FIT_SETTLE_MS after the last change. A change of height
    only (e.g. the bottom panel) does not refit at all."""
    try:
        if tree.winfo_width() == getattr(tree, 'nc_fitted_width', None):
            return
    except tk.TclError:
        return
    job = getattr(tree, 'nc_fit_job', None)
    if job is not None:
        try:
            tree.after_cancel(job)
        except tk.TclError:
            pass
    try:
        tree.nc_fit_job = tree.after(FIT_SETTLE_MS, lambda: fit_columns(tree))
    except tk.TclError:
        pass


def fit_columns(tree, width=None):
    """Share the table's width between the columns in proportion to their relative
    widths, never below their minimum. Returns {key: width}."""
    tree.nc_fit_job = None
    specs = getattr(tree, 'nc_specs', None)
    if not specs:
        return {}
    try:
        width = width or tree.winfo_width()
        shown = [c for c in tree['displaycolumns'] if c != '#all'] or [s[0] for s in specs]
    except tk.TclError:
        return {}
    specs = [s for s in specs if s[0] in shown]
    if width <= 1 or not specs:
        return {}
    tree.nc_fitted_width = width
    avail = width - ui_scale.space(EDGE)
    if 'tree' in str(tree.cget('show')):
        avail -= int(tree.column('#0', 'width'))
    mins = {s[0]: min_pixels(tree, s) for s in specs}
    # Columns whose share would be below their minimum get exactly the minimum; the rest of
    # the width is shared between the others in proportion (repeated until it settles).
    widths, flexible, left = {}, list(specs), avail
    while flexible:
        total = sum(s[2] for s in flexible)
        short = [s for s in flexible if left * s[2] / total < mins[s[0]]]
        if not short:
            break
        for s in short:
            widths[s[0]] = mins[s[0]]
            left -= mins[s[0]]
            flexible.remove(s)
    total = sum(s[2] for s in flexible) or 1
    for s in flexible:
        widths[s[0]] = max(mins[s[0]], int(left * s[2] / total))
    spare = avail - sum(widths.values())
    if spare > 0:                                  # rounding: to the widest column
        widest = max(specs, key=lambda s: s[2])[0]
        widths[widest] += spare
    for key, w in widths.items():
        try:
            tree.column(key, width=w)
        except tk.TclError:
            pass
    return widths


def heading_font(tree):
    """The font the tree's headers are drawn with (from its style)."""
    style = ttk.Style(tree)
    name = str(tree.cget('style') or 'Treeview')
    spec = style.lookup(f'{name}.Heading', 'font') or style.lookup('Treeview.Heading', 'font') \
        or theme.FONT_MONO_BOLD
    cache = getattr(tree, 'nc_heading_font', None)
    if cache is None or cache[0] != spec:
        tree.nc_heading_font = (spec, tkfont.Font(root=tree, font=spec))
    return tree.nc_heading_font[1]


def table_font(tree):
    """The font the tree's cells are drawn with (from its style)."""
    style = ttk.Style(tree)
    name = str(tree.cget('style') or 'Treeview')
    spec = style.lookup(name, 'font') or style.lookup('Treeview', 'font') or theme.FONT
    try:
        return tkfont.Font(root=tree, font=spec)
    except tk.TclError:
        return tkfont.nametofont('TkDefaultFont', root=tree)


class CellTooltip:
    """The full text of a cell that is too narrow for it, shown under the pointer."""

    def __init__(self, tree):
        self.tree, self.tip, self.cell = tree, None, None
        self.font = None
        tree.bind('<Motion>', self.motion, add='+')
        tree.bind('<Leave>', lambda e: self.hide(), add='+')
        tree.bind('<ButtonPress>', lambda e: self.hide(), add='+')
        tree.nc_tooltip = self

    def clipped_text(self, x, y):
        """(cell, full text) when the cell at x, y does not show all of its text."""
        tree = self.tree
        row, col = tree.identify_row(y), tree.identify_column(x)
        if not row or not col or col == '#0':
            return None, ''
        try:
            shown = [c for c in tree['displaycolumns'] if c != '#all'] or list(tree['columns'])
            key = shown[int(col[1:]) - 1]           # '#2' -> the second column shown
            text = str(tree.set(row, key))
            width = int(tree.column(key, 'width'))
        except (tk.TclError, IndexError, ValueError):
            return None, ''
        if key in getattr(tree, 'nc_no_tooltip', ()):
            return None, ''
        if self.font is None:
            self.font = table_font(tree)
        if not text or self.font.measure(text) + ui_scale.space(12) <= width:
            return None, ''
        return (row, key), text

    def motion(self, event):
        cell, text = self.clipped_text(event.x, event.y)
        if cell == self.cell:
            return
        self.hide()
        if not cell:
            return
        self.cell = cell
        self.tip = tk.Toplevel(self.tree)
        self.tip.wm_overrideredirect(True)
        self.tip.wm_geometry(f'+{event.x_root + 12}+{event.y_root + 16}')
        tk.Label(self.tip, text=text, font=theme.FONT_SMALL, background=theme.CARD,
                 foreground=theme.TEXT, relief='solid', borderwidth=1, justify='left',
                 wraplength=ui_scale.space(520), padx=6, pady=3).pack()

    def hide(self):
        self.cell = None
        if self.tip is not None:
            try:
                self.tip.destroy()
            except tk.TclError:
                pass
            self.tip = None
