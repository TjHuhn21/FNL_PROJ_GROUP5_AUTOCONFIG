"""NetCommand's look: dark green and beige ("Balanced Dark Green and Beige").

A dark green navigation rail, a warm off-white workspace with beige strips, white
fields and tables, dark green for primary actions and selection, and muted status
colors used sparingly. Status colors always come with a shape (filled dot = up, hollow
square = down), so they never rely on color alone.

Every color of the interface is defined here; pages and components use these names.
The older names (BG, PAD, FONT, ACCENT, SEVERITY_COLORS, STATUS_COLORS, SAMPLE_COLOR)
are kept because the existing pages use them.

Contrast (WCAG ratio) of the main text pairs, checked when the palette was chosen:
    TEXT on APP_BG 11.4, on WHITE 12.9, on BEIGE 9.7; TEXT_SOFT on APP_BG 7.2;
    TEXT_MUTED on APP_BG 5.0; WHITE on GREEN_DARK 12.0, on GREEN 9.2;
    BEIGE on GREEN_DARK 9.0; status text on its soft background >= 5.0.
"""
import tkinter.font as tkfont
from tkinter import ttk

# ---------------------------------------------------------------- brand colors
GREEN_DARK = '#183D32'      # primary dark green: rail, primary buttons, selection
GREEN = '#294F40'           # secondary green: hover and selected states
BEIGE = '#E8DFC8'           # strips, headings, rail text
CREAM = '#F5F1E7'           # main background
WHITE = '#FFFFFF'           # fields, tables, cards
TEXT_PRIMARY = '#26352E'
TEXT_SECONDARY = '#66736A'  # 5.0:1 on white; on CREAM only 4.4:1, so small muted labels
                            # on the workspace use TEXT_MUTED (same hue, a little darker)

# ---------------------------------------------------------------- palette (roles)
APP_BG = CREAM              # workspace ground
SURFACE = CREAM             # pages and panels (the main content background)
SURFACE_2 = BEIGE           # panel headers, strips, status bar, table headings
CARD = WHITE                # fields, tables, text boxes, lists
CANVAS_BG = '#FBF9F4'       # map / drawing areas (a lighter warm white)
BORDER = '#D8CFB9'          # subtle warm border
BORDER_STRONG = '#B5AA8E'
TEXT = TEXT_PRIMARY
TEXT_SOFT = '#45534A'       # secondary body text
TEXT_MUTED = '#5E6B62'      # labels, timestamps
RAIL_BG = GREEN_DARK
RAIL_HOVER = GREEN
RAIL_ACTIVE = GREEN
RAIL_TEXT = BEIGE
RAIL_ACCENT = BEIGE         # the bar marking the active page
ACCENT = GREEN_DARK         # primary buttons, selection, links
ACCENT_HOVER = GREEN
ACCENT_SOFT = '#DCE5DB'     # pale green: selected/live highlights behind dark text
ACCENT_DISABLED = '#8FA398'
SUCCESS = '#2F6B3F'         # muted green
SUCCESS_SOFT = '#E1EBDD'
DANGER = '#A33A2C'          # muted red
DANGER_SOFT = '#F4DDD6'
WARNING = '#7A5A14'         # muted amber text
WARNING_SOFT = '#F3E6C4'
INFO = '#2F6461'            # muted blue-green
INFO_SOFT = '#DDEBE8'

# The live SSH session console: dark green-black, beige and soft colors (all >= 7:1)
TERMINAL_BG = '#13261F'
TERMINAL_COLORS = {
    'command': WHITE,
    'output': '#C9CFC4',
    'info': '#A3AE9F',
    'section': BEIGE,
    'ok': '#9DCFA8',
    'warn': '#E3B86A',
    'error': '#F0A193',
    'start': '#8EC5C0',
    'device': '#8EC5C0',
    'summary': '#F2F0E8',
}

# ---------------------------------------------------------------- names the existing pages use
BG = SURFACE
SAMPLE_COLOR = WARNING
SEVERITY_COLORS = {'high': DANGER_SOFT, 'medium': WARNING_SOFT, 'low': SUCCESS_SOFT}
STATUS_COLORS = {'up': SUCCESS_SOFT, 'down': DANGER_SOFT}

# ---------------------------------------------------------------- type and spacing
FONT_FAMILY = 'Segoe UI'
MONO_CANDIDATES = ('Cascadia Mono', 'Consolas', 'Courier New')   # first installed wins
MONO_FAMILY = 'Consolas'                                          # replaced in apply()
FONT = (FONT_FAMILY, 10)
FONT_SMALL = (FONT_FAMILY, 9)
FONT_BOLD = (FONT_FAMILY, 10, 'bold')
FONT_TITLE = (FONT_FAMILY, 13, 'bold')
FONT_BRAND = (FONT_FAMILY, 11, 'bold')
FONT_RAIL = (FONT_FAMILY, 8)
FONT_MONO = (MONO_FAMILY, 9)
FONT_MONO_BOLD = (MONO_FAMILY, 9, 'bold')
# Forms people type into while working (the Scan login line): one step larger than FONT
FONT_FORM = (FONT_FAMILY, 11)
FONT_FORM_BOLD = (FONT_FAMILY, 11, 'bold')
# Monospace sizes for command text: what Configure will send, and the live SSH session
CODE_SIZE = 11
SESSION_SIZE = 10
# Data tables people read row by row (Devices, Logs, Scan results, Configure's device
# list): one step larger than FONT, with taller rows and larger headings
TABLE_SIZE = 11
TABLE_ROW_HEIGHT = 28
TABLE_HEADING_SIZE = 10
# The bottom operations console (Console / Config log / Status events)
CONSOLE_SIZE = 11
CONSOLE_TAB_SIZE = 11
PAD = 8
RAIL_WIDTH = 64
INSPECTOR_WIDTH = 300
CONSOLE_HEIGHT = 170
CONSOLE_HEIGHT_COMPACT = 110    # on Configure, which has its own SSH session console


# The DESIGN sizes (at 100 % and UI_TEXT_SIZE 'normal'). The names above are recomputed
# from these by _scale_sizes() (gui/ui_scale.py) every time apply() runs.
_BASE = {'FONT': 10, 'FONT_SMALL': 9, 'FONT_TITLE': 13, 'FONT_BRAND': 11, 'FONT_RAIL': 8,
         'FONT_MONO': 9, 'FONT_FORM': 11, 'CODE_SIZE': 11, 'SESSION_SIZE': 10,
         'TABLE_SIZE': 11, 'TABLE_HEADING_SIZE': 10, 'CONSOLE_SIZE': 11,
         'CONSOLE_TAB_SIZE': 11}
_BASE_PX = {'PAD': 8, 'RAIL_WIDTH': 64, 'INSPECTOR_WIDTH': 300, 'CONSOLE_HEIGHT': 170,
            'CONSOLE_HEIGHT_COMPACT': 110}


def font(size=10, weight='normal', family=None):
    """A font of the app's family at a DESIGN size (scaled by gui/ui_scale.py)."""
    from gui import ui_scale
    scaled = ui_scale.font_size(size, minimum=1 if size < ui_scale.MIN_SMALL else None)
    family = family or FONT_FAMILY
    return (family, scaled, weight) if weight != 'normal' else (family, scaled)


def mono(size=9, weight='normal'):
    """The monospace font (for IPs, ports, timestamps, commands), at a DESIGN size."""
    return font(size, weight, family=MONO_FAMILY)


def _scale_sizes(root):
    """Recompute every font and pixel size from the design sizes (ui_scale)."""
    from gui import ui_scale
    global FONT, FONT_SMALL, FONT_BOLD, FONT_TITLE, FONT_BRAND, FONT_RAIL, FONT_MONO
    global FONT_MONO_BOLD, FONT_FORM, FONT_FORM_BOLD, CODE_SIZE, SESSION_SIZE, TABLE_SIZE
    global TABLE_ROW_HEIGHT, TABLE_HEADING_SIZE, CONSOLE_SIZE, CONSOLE_TAB_SIZE, PAD
    global RAIL_WIDTH, INSPECTOR_WIDTH, CONSOLE_HEIGHT, CONSOLE_HEIGHT_COMPACT
    ui_scale.measure(root)
    size = ui_scale.font_size
    body = size(_BASE['FONT'], ui_scale.MIN_BODY)
    FONT, FONT_BOLD = (FONT_FAMILY, body), (FONT_FAMILY, body, 'bold')
    FONT_SMALL = (FONT_FAMILY, size(_BASE['FONT_SMALL']))
    FONT_TITLE = (FONT_FAMILY, size(_BASE['FONT_TITLE']), 'bold')
    FONT_BRAND = (FONT_FAMILY, size(_BASE['FONT_BRAND']), 'bold')
    FONT_RAIL = (FONT_FAMILY, size(_BASE['FONT_RAIL'], minimum=8))
    mono_size = size(_BASE['FONT_MONO'])
    FONT_MONO, FONT_MONO_BOLD = (MONO_FAMILY, mono_size), (MONO_FAMILY, mono_size, 'bold')
    form = size(_BASE['FONT_FORM'], ui_scale.MIN_BODY)
    FONT_FORM, FONT_FORM_BOLD = (FONT_FAMILY, form), (FONT_FAMILY, form, 'bold')
    CODE_SIZE = size(_BASE['CODE_SIZE'], ui_scale.MIN_BODY)
    SESSION_SIZE = size(_BASE['SESSION_SIZE'], ui_scale.MIN_BODY)
    TABLE_SIZE = size(_BASE['TABLE_SIZE'], ui_scale.MIN_BODY)
    TABLE_HEADING_SIZE = size(_BASE['TABLE_HEADING_SIZE'], ui_scale.MIN_BODY)
    CONSOLE_SIZE = size(_BASE['CONSOLE_SIZE'], ui_scale.MIN_BODY)
    CONSOLE_TAB_SIZE = size(_BASE['CONSOLE_TAB_SIZE'], ui_scale.MIN_BODY)
    try:                                        # a row fits its font exactly
        line = tkfont.Font(root=root, family=FONT_FAMILY, size=TABLE_SIZE).metrics('linespace')
    except Exception:
        line = int(TABLE_SIZE * 1.6)
    TABLE_ROW_HEIGHT = ui_scale.row_height(line)
    space = ui_scale.space
    PAD = space(_BASE_PX['PAD'])
    # CustomTkinter widgets (the rail) apply the display scaling THEMSELVES: their sizes get
    # only the text-size factor, never the DPI (that would scale them twice)
    RAIL_WIDTH = int(round(_BASE_PX['RAIL_WIDTH'] * ui_scale.factor()))
    INSPECTOR_WIDTH = space(_BASE_PX['INSPECTOR_WIDTH'])
    CONSOLE_HEIGHT = space(_BASE_PX['CONSOLE_HEIGHT'])
    CONSOLE_HEIGHT_COMPACT = space(_BASE_PX['CONSOLE_HEIGHT_COMPACT'])
    for name in ('TkDefaultFont', 'TkTextFont', 'TkMenuFont', 'TkHeadingFont',
                 'TkTooltipFont', 'TkCaptionFont'):        # widgets without their own font
        try:
            tkfont.nametofont(name, root=root).configure(family=FONT_FAMILY, size=body)
        except Exception:
            pass


def _pick_mono(root):
    global MONO_FAMILY
    installed = set(tkfont.families(root))
    MONO_FAMILY = next((f for f in MONO_CANDIDATES if f in installed), 'Courier')


def apply(root):
    """Set the workbench look for the whole window."""
    import customtkinter as ctk
    ctk.set_appearance_mode('light')
    if isinstance(root, ctk.CTk):
        root.configure(fg_color=APP_BG)
    else:
        root.configure(background=APP_BG)
    _pick_mono(root)
    _scale_sizes(root)                     # every font and size from gui/ui_scale.py
    _styles(root)


def window_dpi(root):
    """The DPI of the monitor the window is on (Windows 10+), or None."""
    try:
        import ctypes
        dpi = ctypes.windll.user32.GetDpiForWindow(root.winfo_id())
        return float(dpi) if dpi else None
    except Exception:
        return None


def watch_dpi(root, delay_ms=400):
    """Moved to a monitor with another DPI (or the scaling was changed): recompute the
    sizes and the ttk styles, then send <<DpiChanged>>. Checked after the window moves or
    is resized, debounced so dragging stays smooth."""
    from gui import ui_scale
    job = {'id': None}

    def check():
        job['id'] = None
        dpi = window_dpi(root)
        if dpi and ui_scale.rescale(dpi):
            try:
                root.tk.call('tk', 'scaling', dpi / 72.0)    # points -> pixels on this monitor
                _scale_sizes(root)
                _styles(root)
                root.event_generate('<<DpiChanged>>')
            except Exception:
                pass

    def moved(event):
        if event.widget is not root:
            return
        if job['id'] is not None:
            try:
                root.after_cancel(job['id'])
            except Exception:
                pass
        try:
            job['id'] = root.after(delay_ms, check)
        except Exception:
            job['id'] = None
    root.bind('<Configure>', moved, add='+')


def _styles(root):
    """The ttk styles, from the current (scaled) sizes. Run again after a DPI change."""
    from gui import ui_scale
    sp = ui_scale.space
    style = ttk.Style(root)
    if 'clam' in style.theme_names():
        style.theme_use('clam')

    style.configure('.', font=FONT, background=BG, foreground=TEXT,
                    fieldbackground=CARD, bordercolor=BORDER_STRONG,
                    lightcolor=BG, darkcolor=BG, troughcolor=SURFACE_2,
                    selectbackground=ACCENT, selectforeground=WHITE,
                    insertcolor=TEXT, focuscolor=ACCENT)
    style.map('.', foreground=[('disabled', TEXT_MUTED)])
    style.configure('TFrame', background=BG)
    style.configure('TLabel', background=BG, foreground=TEXT)
    style.configure('Title.TLabel', font=FONT_TITLE, foreground=ACCENT)
    style.configure('Sample.TLabel', foreground=SAMPLE_COLOR, background=WARNING_SOFT,
                    font=FONT_BOLD)
    style.configure('TCheckbutton', background=BG, foreground=TEXT,
                    indicatorbackground=CARD, indicatorforeground=ACCENT)
    style.map('TCheckbutton', background=[('active', BG)],
              indicatorbackground=[('selected', CARD), ('active', ACCENT_SOFT)])
    style.configure('TRadiobutton', background=BG, foreground=TEXT,
                    indicatorbackground=CARD, indicatorforeground=ACCENT)
    style.map('TRadiobutton', background=[('active', BG)])

    # Secondary buttons: white with a visible 1 px border; beige when hovered
    style.configure('TButton', background=CARD, foreground=TEXT, bordercolor=BORDER_STRONG,
                    lightcolor=CARD, darkcolor=CARD, padding=(sp(10), sp(3)), relief='solid',
                    borderwidth=1)
    style.map('TButton', background=[('disabled', SURFACE_2), ('pressed', ACCENT_SOFT),
                                     ('active', SURFACE_2)],
              foreground=[('disabled', TEXT_MUTED)],
              bordercolor=[('focus', ACCENT)])
    # Primary buttons: dark green, secondary green when hovered or pressed
    style.configure('Accent.TButton', font=FONT_BOLD, foreground=WHITE, background=ACCENT,
                    bordercolor=ACCENT, lightcolor=ACCENT, darkcolor=ACCENT)
    style.map('Accent.TButton',
              background=[('disabled', ACCENT_DISABLED), ('pressed', ACCENT_HOVER),
                          ('active', ACCENT_HOVER)],
              bordercolor=[('disabled', ACCENT_DISABLED), ('focus', ACCENT_HOVER)],
              foreground=[('disabled', CREAM)])
    # Dangerous actions in confirmations (delete, apply, reject, disable): muted red
    style.configure('Danger.TButton', font=FONT_BOLD, foreground=WHITE, background=DANGER,
                    bordercolor=DANGER, lightcolor=DANGER, darkcolor=DANGER)
    style.map('Danger.TButton',
              background=[('disabled', DANGER_SOFT), ('pressed', '#8A2F23'),
                          ('active', '#8A2F23')],
              bordercolor=[('disabled', DANGER_SOFT), ('focus', TEXT)],
              foreground=[('disabled', TEXT_MUTED)])
    # Larger form controls (inherit everything else from TLabel / TCheckbutton /
    # Accent.TButton, so colors and states stay the same)
    style.configure('Form.TLabel', font=FONT_FORM)
    style.configure('Form.TCheckbutton', font=FONT_FORM)
    style.configure('Large.Accent.TButton', font=FONT_FORM_BOLD, padding=(sp(16), sp(5)))

    style.configure('TEntry', fieldbackground=CARD, foreground=TEXT, insertcolor=TEXT,
                    bordercolor=BORDER_STRONG, lightcolor=CARD, darkcolor=CARD)
    style.map('TEntry', bordercolor=[('focus', ACCENT)], lightcolor=[('focus', ACCENT)],
              fieldbackground=[('disabled', SURFACE_2)])
    style.configure('TCombobox', fieldbackground=CARD, background=CARD, foreground=TEXT,
                    arrowcolor=ACCENT, bordercolor=BORDER_STRONG,
                    lightcolor=CARD, darkcolor=CARD)
    style.map('TCombobox', fieldbackground=[('disabled', SURFACE_2), ('readonly', CARD)],
              foreground=[('disabled', TEXT_MUTED), ('readonly', TEXT)],
              selectbackground=[('readonly', CARD)],
              selectforeground=[('readonly', TEXT)], bordercolor=[('focus', ACCENT)])
    # an invalid field on the Configure page: red border (gui/components/field_check.py)
    for name in ('Invalid.TEntry', 'Invalid.TCombobox'):
        style.configure(name, fieldbackground=CARD, foreground=TEXT, bordercolor=DANGER,
                        lightcolor=DANGER, darkcolor=DANGER)
        style.map(name, bordercolor=[('focus', DANGER)], lightcolor=[('focus', DANGER)])
    root.option_add('*TCombobox*Listbox.background', CARD)
    root.option_add('*TCombobox*Listbox.foreground', TEXT)
    root.option_add('*TCombobox*Listbox.selectBackground', ACCENT)
    root.option_add('*TCombobox*Listbox.selectForeground', WHITE)
    root.option_add('*Listbox.background', CARD)
    root.option_add('*Listbox.foreground', TEXT)
    root.option_add('*Listbox.selectBackground', ACCENT)
    root.option_add('*Listbox.selectForeground', WHITE)

    # Dense, ruled tables (the "ledger" look): white rows, beige monospace headings,
    # dark green selection with white text
    # a heading's text starts where its cells' text starts (a cell's text sits 4 px in;
    # the heading's border takes 2 of them), so left-aligned headers line up with values
    HEADING_INSET = sp(2)
    style.configure('Treeview', background=CARD, fieldbackground=CARD, foreground=TEXT,
                    bordercolor=BORDER, lightcolor=CARD, darkcolor=CARD, rowheight=TABLE_ROW_HEIGHT,
                    font=(FONT_FAMILY, TABLE_SIZE))
    style.map('Treeview', background=[('selected', ACCENT)], foreground=[('selected', WHITE)])
    style.configure('Treeview.Heading', font=FONT_MONO_BOLD, background=SURFACE_2,
                    foreground=TEXT, bordercolor=BORDER, lightcolor=SURFACE_2,
                    darkcolor=SURFACE_2, relief='flat', padding=(HEADING_INSET, sp(4)))
    style.map('Treeview.Heading', background=[('active', BORDER)])
    # Larger tables (inherit the ledger look above; only size and row height change)
    style.configure('Data.Treeview', font=(FONT_FAMILY, TABLE_SIZE), rowheight=TABLE_ROW_HEIGHT)
    style.configure('Data.Treeview.Heading', font=(MONO_FAMILY, TABLE_HEADING_SIZE, 'bold'),
                    padding=(HEADING_INSET, sp(5)))

    style.configure('TNotebook', background=BG, bordercolor=BORDER, tabmargins=(0, 2, 0, 0))
    style.configure('TNotebook.Tab', background=SURFACE_2, foreground=TEXT_SOFT,
                    bordercolor=BORDER, lightcolor=SURFACE_2, darkcolor=SURFACE_2,
                    padding=(sp(12), sp(4)))
    style.map('TNotebook.Tab', background=[('selected', CARD), ('active', BORDER)],
              foreground=[('selected', ACCENT)])
    # The bottom operations console: slightly larger tab labels and buttons
    style.configure('Console.TNotebook', background=BG, bordercolor=BORDER,
                    tabmargins=(0, 2, 0, 0))
    style.configure('Console.TNotebook.Tab', font=(FONT_FAMILY, CONSOLE_TAB_SIZE),
                    padding=(sp(14), sp(5)))
    style.configure('Console.TButton', font=(FONT_FAMILY, CONSOLE_TAB_SIZE), padding=(sp(12), sp(3)))

    style.configure('TScrollbar', background=SURFACE_2, troughcolor=CREAM,
                    bordercolor=CREAM, arrowcolor=ACCENT,
                    lightcolor=SURFACE_2, darkcolor=SURFACE_2)
    style.map('TScrollbar', background=[('active', BORDER_STRONG)])
    style.configure('TProgressbar', background=ACCENT, troughcolor=SURFACE_2,
                    bordercolor=BORDER, lightcolor=ACCENT, darkcolor=ACCENT)
    style.configure('TSeparator', background=BORDER)
    style.configure('TLabelframe', background=BG, bordercolor=BORDER)
    style.configure('TLabelframe.Label', background=BG, foreground=ACCENT, font=FONT_BOLD)

    # Resizable workbench panels: a visible but quiet divider to drag
    style.configure('Workbench.TPanedwindow', background=BORDER)
    style.configure('Sash', sashthickness=sp(5), gripcount=0, background=SURFACE_2,
                    lightcolor=BORDER, bordercolor=BORDER)

    root.option_add('*Text.background', CARD)
    root.option_add('*Text.foreground', TEXT)
    root.option_add('*Text.insertBackground', TEXT)
    root.option_add('*Text.selectBackground', ACCENT)
    root.option_add('*Text.selectForeground', WHITE)
