"""NetCommand's look: the "Network Engineering Workbench".

A light industrial palette: off-white workspace, cool grays, a graphite
navigation rail, teal for actions and selection, amber only for warnings.
Status colors always come with a shape (filled dot = up, hollow square =
down), so they never rely on color alone.

The older names (BG, PAD, FONT, ACCENT, SEVERITY_COLORS, STATUS_COLORS,
SAMPLE_COLOR) are kept because the existing pages use them.
"""
import tkinter.font as tkfont
from tkinter import ttk

# ---------------------------------------------------------------- palette
APP_BG = '#F3F4F1'          # workspace ground (off-white)
SURFACE = '#FFFFFF'         # panels and pages
SURFACE_2 = '#ECEEEB'       # panel headers, strips, status bar
CANVAS_BG = '#F8F9F7'       # map / drawing areas
BORDER = '#CDD2D6'
BORDER_STRONG = '#AEB6BC'
TEXT = '#1F2428'            # graphite (about 15:1 on white)
TEXT_SOFT = '#3D454C'       # secondary text (about 10:1)
TEXT_MUTED = '#59626B'      # labels, timestamps (about 6:1 on white, 5.6:1 on APP_BG)
RAIL_BG = '#23292E'
RAIL_HOVER = '#2B3238'
RAIL_ACTIVE = '#313A41'
RAIL_TEXT = '#C9D1D6'       # about 10:1 on the rail
RAIL_ACCENT = '#4FD1C5'
ACCENT = '#0E6F67'          # teal (about 5.9:1 on white)
ACCENT_HOVER = '#0A524C'
ACCENT_SOFT = '#DCEEEB'
SUCCESS = '#1B7A3A'
DANGER = '#B42318'
DANGER_SOFT = '#F8E1DE'
WARNING = '#7A4600'         # amber text (about 7:1 on its soft background)
WARNING_SOFT = '#F6E9D2'

# ---------------------------------------------------------------- names the existing pages use
BG = SURFACE
SAMPLE_COLOR = WARNING
SEVERITY_COLORS = {'high': DANGER_SOFT, 'medium': WARNING_SOFT, 'low': '#E3F1E6'}
STATUS_COLORS = {'up': '#EEF6F0', 'down': DANGER_SOFT}

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


def mono(size=9, weight='normal'):
    """The monospace font (for IPs, ports, timestamps, commands)."""
    return (MONO_FAMILY, size, weight) if weight != 'normal' else (MONO_FAMILY, size)


def _pick_mono(root):
    global MONO_FAMILY, FONT_MONO, FONT_MONO_BOLD
    installed = set(tkfont.families(root))
    MONO_FAMILY = next((f for f in MONO_CANDIDATES if f in installed), 'Courier')
    FONT_MONO = (MONO_FAMILY, 9)
    FONT_MONO_BOLD = (MONO_FAMILY, 9, 'bold')


def apply(root):
    """Set the workbench look for the whole window."""
    import customtkinter as ctk
    ctk.set_appearance_mode('light')
    if isinstance(root, ctk.CTk):
        root.configure(fg_color=APP_BG)
    else:
        root.configure(background=APP_BG)
    _pick_mono(root)

    style = ttk.Style(root)
    if 'clam' in style.theme_names():
        style.theme_use('clam')

    style.configure('.', font=FONT, background=BG, foreground=TEXT,
                    fieldbackground=SURFACE, bordercolor=BORDER_STRONG,
                    lightcolor=SURFACE, darkcolor=SURFACE, troughcolor=SURFACE_2,
                    selectbackground=ACCENT, selectforeground='white',
                    insertcolor=TEXT, focuscolor=ACCENT)
    style.map('.', foreground=[('disabled', TEXT_MUTED)])
    style.configure('TFrame', background=BG)
    style.configure('TLabel', background=BG, foreground=TEXT)
    style.configure('Title.TLabel', font=FONT_TITLE, foreground=TEXT)
    style.configure('Sample.TLabel', foreground=SAMPLE_COLOR, background=WARNING_SOFT,
                    font=FONT_BOLD)
    style.configure('TCheckbutton', background=BG, foreground=TEXT,
                    indicatorbackground=SURFACE, indicatorforeground=ACCENT)
    style.map('TCheckbutton', background=[('active', BG)],
              indicatorbackground=[('selected', SURFACE), ('active', ACCENT_SOFT)])

    # A visible 1 px border, so buttons read as buttons on white panels
    style.configure('TButton', background=SURFACE, foreground=TEXT, bordercolor=BORDER_STRONG,
                    lightcolor=SURFACE, darkcolor=SURFACE, padding=(10, 3), relief='solid',
                    borderwidth=1)
    style.map('TButton', background=[('disabled', SURFACE_2), ('pressed', ACCENT_SOFT),
                                     ('active', SURFACE_2)],
              bordercolor=[('focus', ACCENT)])
    style.configure('Accent.TButton', font=FONT_BOLD, foreground='white', background=ACCENT,
                    bordercolor=ACCENT, lightcolor=ACCENT, darkcolor=ACCENT)
    style.map('Accent.TButton',
              background=[('disabled', '#9DBFBB'), ('pressed', ACCENT_HOVER),
                          ('active', ACCENT_HOVER)],
              foreground=[('disabled', SURFACE)])
    # Larger form controls (inherit everything else from TLabel / TCheckbutton /
    # Accent.TButton, so colors and states stay the same)
    style.configure('Form.TLabel', font=FONT_FORM)
    style.configure('Form.TCheckbutton', font=FONT_FORM)
    style.configure('Large.Accent.TButton', font=FONT_FORM_BOLD, padding=(16, 5))

    style.configure('TEntry', fieldbackground=SURFACE, foreground=TEXT, insertcolor=TEXT,
                    bordercolor=BORDER_STRONG, lightcolor=SURFACE, darkcolor=SURFACE)
    style.map('TEntry', bordercolor=[('focus', ACCENT)], lightcolor=[('focus', ACCENT)])
    style.configure('TCombobox', fieldbackground=SURFACE, background=SURFACE, foreground=TEXT,
                    arrowcolor=TEXT_SOFT, bordercolor=BORDER_STRONG,
                    lightcolor=SURFACE, darkcolor=SURFACE)
    style.map('TCombobox', fieldbackground=[('readonly', SURFACE)],
              foreground=[('readonly', TEXT)], selectbackground=[('readonly', SURFACE)],
              selectforeground=[('readonly', TEXT)], bordercolor=[('focus', ACCENT)])
    root.option_add('*TCombobox*Listbox.background', SURFACE)
    root.option_add('*TCombobox*Listbox.foreground', TEXT)
    root.option_add('*TCombobox*Listbox.selectBackground', ACCENT)
    root.option_add('*TCombobox*Listbox.selectForeground', 'white')

    # Dense, ruled tables (the "ledger" look): compact rows, monospace headings
    style.configure('Treeview', background=SURFACE, fieldbackground=SURFACE, foreground=TEXT,
                    bordercolor=BORDER, lightcolor=SURFACE, darkcolor=SURFACE, rowheight=24)
    style.map('Treeview', background=[('selected', ACCENT)], foreground=[('selected', 'white')])
    style.configure('Treeview.Heading', font=FONT_MONO_BOLD, background=SURFACE_2,
                    foreground=TEXT_SOFT, bordercolor=BORDER, lightcolor=SURFACE_2,
                    darkcolor=SURFACE_2, relief='flat', padding=(6, 4))
    style.map('Treeview.Heading', background=[('active', BORDER)])
    # Larger tables (inherit the ledger look above; only size and row height change)
    style.configure('Data.Treeview', font=(FONT_FAMILY, TABLE_SIZE), rowheight=TABLE_ROW_HEIGHT)
    style.configure('Data.Treeview.Heading', font=(MONO_FAMILY, TABLE_HEADING_SIZE, 'bold'),
                    padding=(6, 5))

    style.configure('TNotebook', background=BG, bordercolor=BORDER, tabmargins=(0, 2, 0, 0))
    style.configure('TNotebook.Tab', background=SURFACE_2, foreground=TEXT_SOFT,
                    bordercolor=BORDER, lightcolor=SURFACE_2, darkcolor=SURFACE_2,
                    padding=(12, 4))
    style.map('TNotebook.Tab', background=[('selected', SURFACE)], foreground=[('selected', TEXT)])
    # The bottom operations console: slightly larger tab labels and buttons
    style.configure('Console.TNotebook', background=BG, bordercolor=BORDER,
                    tabmargins=(0, 2, 0, 0))
    style.configure('Console.TNotebook.Tab', font=(FONT_FAMILY, CONSOLE_TAB_SIZE),
                    padding=(14, 5))
    style.configure('Console.TButton', font=(FONT_FAMILY, CONSOLE_TAB_SIZE), padding=(12, 3))

    style.configure('TScrollbar', background=SURFACE_2, troughcolor=SURFACE,
                    bordercolor=SURFACE, arrowcolor=TEXT_MUTED,
                    lightcolor=SURFACE_2, darkcolor=SURFACE_2)
    style.map('TScrollbar', background=[('active', BORDER)])

    # Resizable workbench panels: a visible but quiet divider to drag
    style.configure('Workbench.TPanedwindow', background=BORDER)
    style.configure('Sash', sashthickness=5, gripcount=0, background=SURFACE_2,
                    lightcolor=BORDER, bordercolor=BORDER)

    root.option_add('*Text.background', SURFACE)
    root.option_add('*Text.foreground', TEXT)
    root.option_add('*Text.insertBackground', TEXT)
    root.option_add('*Text.selectBackground', ACCENT)
    root.option_add('*Text.selectForeground', 'white')
