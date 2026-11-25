"""Short hover texts for buttons and fields whose meaning is not obvious.

    tip(widget, 'seed_ip')          # the text from gui/guide_content.TOOLTIPS
    tip(widget, text='Any text')

The text appears after a short pause under the pointer and goes away when the pointer
leaves or a key / button is pressed. It uses the app's scaled small font and wraps at a
scaled width, so it reads the same at every window size and display scaling.
"""
import tkinter as tk

from gui import theme, ui_scale

DELAY_MS = 450
WRAP = 300                       # design pixels


class HoverTip:
    def __init__(self, widget, text):
        self.widget, self.text = widget, text
        self.tip, self._job = None, None
        widget.bind('<Enter>', self._schedule, add='+')
        widget.bind('<Leave>', self.hide, add='+')
        widget.bind('<ButtonPress>', self.hide, add='+')
        widget.bind('<KeyPress>', self.hide, add='+')

    def _schedule(self, _event=None):
        self._cancel()
        try:
            self._job = self.widget.after(DELAY_MS, self.show)
        except tk.TclError:
            self._job = None

    def _cancel(self):
        if self._job is not None:
            try:
                self.widget.after_cancel(self._job)
            except tk.TclError:
                pass
            self._job = None

    def show(self):
        self._job = None
        self.hide_window()
        if not self.text:
            return
        try:
            x = self.widget.winfo_rootx() + ui_scale.space(10)
            y = self.widget.winfo_rooty() + self.widget.winfo_height() + ui_scale.space(4)
            self.tip = tk.Toplevel(self.widget)
            self.tip.wm_overrideredirect(True)
            self.tip.wm_geometry(f'+{x}+{y}')
            tk.Label(self.tip, text=self.text, font=theme.FONT_SMALL, background=theme.CARD,
                     foreground=theme.TEXT, relief='solid', borderwidth=1, justify='left',
                     wraplength=ui_scale.space(WRAP), padx=6, pady=3).pack()
        except tk.TclError:
            self.tip = None

    def hide_window(self):
        if self.tip is not None:
            try:
                self.tip.destroy()
            except tk.TclError:
                pass
            self.tip = None

    def hide(self, _event=None):
        self._cancel()
        self.hide_window()


def tip(widget, key=None, text=None):
    """Attach a hover text to widget (key: gui/guide_content.TOOLTIPS). Returns the tip."""
    if text is None:
        from gui import guide_content
        text = guide_content.TOOLTIPS.get(key, '')
    if widget is None or not text:
        return None
    hover = HoverTip(widget, text)
    widget.nc_tip = hover
    return hover
