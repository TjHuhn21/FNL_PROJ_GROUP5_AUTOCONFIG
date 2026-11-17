"""A frame that scrolls vertically, but only shows its scroll bar when the
content is taller than the space it has (no needless scroll bars).

    box = ScrollFrame(parent)
    ttk.Label(box.inner, text='...').pack()      # put widgets in .inner
"""
import tkinter as tk
from tkinter import ttk

from gui import theme


class ScrollFrame(ttk.Frame):
    def __init__(self, parent, background=None):
        super().__init__(parent)
        self.canvas = tk.Canvas(self, highlightthickness=0, borderwidth=0,
                                background=background or theme.BG)
        self.bar = ttk.Scrollbar(self, orient='vertical', command=self.canvas.yview)
        self.canvas.configure(yscrollcommand=self.bar.set)
        self.canvas.pack(side='left', fill='both', expand=True)
        self.inner = ttk.Frame(self.canvas)
        self._window = self.canvas.create_window(0, 0, window=self.inner, anchor='nw')
        self.inner.bind('<Configure>', lambda e: self._update())
        self.canvas.bind('<Configure>', lambda e: self._update())
        # one application-wide wheel handler that only acts when the pointer is over
        # this frame (Enter/Leave would fire every time the pointer crosses a child)
        self.canvas.bind_all('<MouseWheel>', self._scroll, add='+')
        self.bar_shown = False

    def _update(self):
        width, height = self.canvas.winfo_width(), self.canvas.winfo_height()
        need = self.inner.winfo_reqheight()
        # the content always gets exactly the visible width (wider content would be cut off
        # at the right edge, since there is no horizontal scroll bar)
        self.canvas.itemconfigure(self._window, width=width)
        self.canvas.configure(scrollregion=(0, 0, width, max(need, height)))
        overflow = need > height + 1 and height > 1
        if overflow and not self.bar_shown:
            self.bar.pack(side='right', fill='y', before=self.canvas)
            self.bar_shown = True
        elif not overflow and self.bar_shown:
            self.bar.pack_forget()
            self.canvas.yview_moveto(0)
            self.bar_shown = False

    def _scroll(self, event):
        try:
            inside = str(event.widget).startswith(str(self.canvas)) and self.winfo_ismapped()
        except (tk.TclError, AttributeError):
            return
        if not inside:
            return
        # tables and text boxes scroll themselves
        if isinstance(event.widget, (ttk.Treeview, tk.Text, tk.Listbox)):
            return
        if self.bar_shown:
            self.canvas.yview_scroll(int(-event.delta / 120) or (-1 if event.delta > 0 else 1),
                                     'units')
