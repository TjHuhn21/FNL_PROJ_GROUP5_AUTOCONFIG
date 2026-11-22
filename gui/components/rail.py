"""The navigation rail: a narrow graphite column with one icon + short label
per workspace. The active workspace gets a teal bar on its left edge.

Each item is a small frame holding an icon label and a text label; a click
anywhere on it calls on_select(key). CustomTkinter widgets are used here
because they scale correctly with Windows display scaling.
"""
import customtkinter as ctk

from gui import theme
from gui.components import icons


class RailItem(ctk.CTkFrame):
    def __init__(self, master, key, label, on_click, icon_font):
        super().__init__(master, fg_color=theme.RAIL_BG, corner_radius=0, height=54,
                         cursor='hand2')
        self.key, self.label_text = key, label
        self._on_click, self._active, self._hover = on_click, False, False
        self.grid_columnconfigure(1, weight=1)
        # height=4 matters: a CTkFrame is 200 px tall by default, which would stretch the item
        self.marker = ctk.CTkFrame(self, width=3, height=4, corner_radius=0, fg_color=theme.RAIL_BG)
        self.marker.grid(row=0, column=0, rowspan=2, sticky='ns')
        self.icon = None
        if icon_font:                                    # no icon font: label only
            self.icon = ctk.CTkLabel(self, text=icons.glyph(key), font=icon_font, height=22,
                                     text_color=theme.RAIL_TEXT, cursor='hand2')
            self.icon.grid(row=0, column=1, pady=(8, 0))
        self.text = ctk.CTkLabel(self, text=label, font=theme.FONT_RAIL, height=14,
                                 text_color=theme.RAIL_TEXT, cursor='hand2')
        self.text.grid(row=1 if icon_font else 0, column=1, rowspan=1 if icon_font else 2,
                       pady=(0, 7) if icon_font else 14)
        for widget in self._parts():
            widget.bind('<Button-1>', lambda _e: self._on_click(self.key))
            widget.bind('<Enter>', lambda _e: self._set_hover(True))
            widget.bind('<Leave>', self._maybe_leave)

    def _parts(self):
        return [w for w in (self, self.marker, self.icon, self.text) if w is not None]

    def _maybe_leave(self, _event):
        # Moving onto one of the item's own labels also fires <Leave>.
        try:
            under = self.winfo_containing(self.winfo_pointerx(), self.winfo_pointery())
        except (KeyError, RuntimeError):
            under = None
        me = str(self)
        if not (under is not None and (str(under) == me or str(under).startswith(me + '.'))):
            self._set_hover(False)

    def _set_hover(self, on):
        self._hover = on
        self._paint()

    def set_active(self, on):
        self._active = on
        self._paint()

    def _paint(self):
        bg = theme.RAIL_ACTIVE if self._active else theme.RAIL_HOVER if self._hover else theme.RAIL_BG
        fg = theme.WHITE if (self._active or self._hover) else theme.RAIL_TEXT
        self.configure(fg_color=bg)
        self.marker.configure(fg_color=theme.RAIL_ACCENT if self._active else bg)
        self.text.configure(text_color=fg, fg_color=bg)
        if self.icon is not None:
            self.icon.configure(text_color=fg, fg_color=bg)


class Rail(ctk.CTkFrame):
    """items: [(key, label)]. on_select(key) is called when an item is clicked."""

    def __init__(self, master, items, on_select):
        super().__init__(master, fg_color=theme.RAIL_BG, corner_radius=0, width=theme.RAIL_WIDTH)
        self.grid_propagate(False)                       # keep the fixed width
        self.grid_columnconfigure(0, weight=1)
        self.active = None
        font = icons.icon_font(self, 16)
        self.items = {}
        for row, (key, label) in enumerate(items):
            item = RailItem(self, key, label, on_select, font)
            item.grid(row=row, column=0, sticky='ew', pady=(6 if row == 0 else 0, 0))
            self.items[key] = item

    def set_active(self, key):
        self.active = key
        for item_key, item in self.items.items():
            item.set_active(item_key == key)
