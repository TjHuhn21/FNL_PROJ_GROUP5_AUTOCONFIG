"""A frame that scrolls vertically, but only shows its scroll bar when the
content is taller than the space it has (no needless scroll bars).

    box = ScrollFrame(parent)
    ttk.Label(box.inner, text='...').pack()      # put widgets in .inner

Two helpers for scrollable widgets (tables, text boxes) that are not inside a ScrollFrame:

    bind_wheel(tree)                 # the mouse wheel scrolls THIS widget only
    bar = auto_scrollbar(holder, tree)   # a scroll bar shown only when it is needed
"""
import tkinter as tk
from tkinter import ttk

from gui import theme

WHEEL_STEP = 120          # one notch of a classic Windows mouse wheel (event.delta)
SCROLL_HYSTERESIS = 24    # pixels: a shown scroll bar goes away only with this much room


def bind_wheel(widget, lines_per_notch=1):
    """The mouse wheel scrolls `widget` (anything with yview_scroll) and nothing else.

    Why not the default binding: Tk's own Treeview binding computes -(delta / 120) with
    integer division, so the small steps many Windows mice and touchpads send (delta 40,
    for example) scroll down but never up. This handler adds the steps up until a whole
    notch is reached, scrolls only the widget under the pointer, and returns 'break', so
    the class binding and any application-wide wheel handler (ScrollFrame) do not also
    scroll this or another section."""
    state = {'rest': 0}

    def on_wheel(event):
        state['rest'] += event.delta
        notches = int(state['rest'] / WHEEL_STEP)         # toward zero, both directions
        if notches:
            state['rest'] -= notches * WHEEL_STEP
            widget.yview_scroll(-notches * lines_per_notch, 'units')
        return 'break'
    widget.bind('<MouseWheel>', on_wheel)
    # X11 sends buttons 4/5 instead of <MouseWheel> (Linux test machines)
    widget.bind('<Button-4>', lambda e: (widget.yview_scroll(-lines_per_notch, 'units'), 'break')[1])
    widget.bind('<Button-5>', lambda e: (widget.yview_scroll(lines_per_notch, 'units'), 'break')[1])
    return on_wheel


def auto_scrollbar(parent, widget, row=0, column=1):
    """A vertical scroll bar for `widget`, placed with grid at (row, column) of `parent`
    and shown only while the content does not fit (widget must be gridded in `parent`)."""
    bar = ttk.Scrollbar(parent, orient='vertical', command=widget.yview)

    def on_scroll(first, last):
        bar.set(first, last)
        if float(first) <= 0.0 and float(last) >= 1.0:
            bar.grid_remove()                              # everything is visible
        elif not bar.winfo_manager():
            bar.grid(row=row, column=column, sticky='ns')
    widget.configure(yscrollcommand=on_scroll)
    bar.on_scroll = on_scroll                              # for tests
    return bar


class ScrollFrame(ttk.Frame):
    """fill_height=True (a whole page): the content is stretched to the visible height
    when it fits (so tables in it can grow), and scrolls when the window is shorter than
    the content needs."""

    def __init__(self, parent, background=None, fill_height=False):
        super().__init__(parent)
        self.fill_height = fill_height
        self.canvas = tk.Canvas(self, highlightthickness=0, borderwidth=0,
                                background=background or theme.BG)
        self.bar = ttk.Scrollbar(self, orient='vertical', command=self.canvas.yview)
        self.canvas.configure(yscrollcommand=self.bar.set)
        self.canvas.pack(side='left', fill='both', expand=True)
        self.inner = ttk.Frame(self.canvas)
        self._window = self.canvas.create_window(0, 0, window=self.inner, anchor='nw')
        # many <Configure> events arrive while a window edge is dragged: handled once, when
        # Tk is idle, and only when a size really changed (no repeated work, no flicker)
        self._pending, self._last = None, None
        self.inner.bind('<Configure>', lambda e: self._update_later())
        self.canvas.bind('<Configure>', lambda e: self._update_later())
        # one application-wide wheel handler that only acts when the pointer is over
        # this frame (Enter/Leave would fire every time the pointer crosses a child)
        self.canvas.bind_all('<MouseWheel>', self._scroll, add='+')
        self.bar_shown = False

    def _watch_children(self):
        """fill_height: the content frame keeps the view's height even when what is in it
        gets shorter (so it sends no <Configure>); its direct children do change size."""
        watched = getattr(self, '_watched', set())
        self._watched = watched
        for child in self.inner.winfo_children():
            if str(child) not in watched:
                watched.add(str(child))
                child.bind('<Configure>', lambda e: self._update_later(), add='+')

    def _update_later(self):
        if self._pending is None:
            try:
                self._pending = self.after_idle(self._update)
            except tk.TclError:
                self._pending = None

    def _update(self):
        self._pending = None
        try:
            width, height = self.canvas.winfo_width(), self.canvas.winfo_height()
            need = self.inner.winfo_reqheight()
        except tk.TclError:
            return
        if self.fill_height:
            self._watch_children()
        if (width, height, need) == self._last:
            return
        self._last = (width, height, need)
        # the content always gets exactly the visible width (wider content would be cut off
        # at the right edge, since there is no horizontal scroll bar)
        self.canvas.itemconfigure(self._window, width=width)
        if self.fill_height:
            self.canvas.itemconfigure(self._window, height=max(need, height))
        self.canvas.configure(scrollregion=(0, 0, width, max(need, height)))
        # The bar appears when the content is taller than the view, and goes away only when
        # it fits with some room to spare: showing the bar narrows the content (which can
        # make it shorter), so without this margin it could flicker on and off.
        if self.bar_shown:
            overflow = need > height - SCROLL_HYSTERESIS and height > 1
        else:
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
