"""A row of controls that wraps onto the next line when the window is too narrow, instead
of cutting the last ones off.

    bar = WrapFrame(parent, background=theme.SURFACE)
    b = ttk.Button(bar, text='Add'); bar.add(b, padx=(0, 6))
    bar.add(ttk.Button(bar, text='Backups'), push_right=True)    # kept on the right when it fits

Widgets are created with the WrapFrame as their parent and added in order. Whenever the
width changes, they are laid out left to right on as many rows as needed (using each
widget's requested width). Items marked push_right go to the right end of their row while
there is room; on a narrow window they simply follow on the next row.
"""
import tkinter as tk

WRAP_SETTLE_MS = 120            # re-wrap this long after the last size change


class WrapFrame(tk.Frame):
    def __init__(self, parent, **kwargs):
        super().__init__(parent, **kwargs)
        self.items = []                     # (widget, padx, pady, push_right)
        self._frames = []                   # one frame per row
        self._rows = None
        self._job = None
        self.bind('<Configure>', self._later, add='+')

    def add(self, widget, padx=(0, 4), pady=2, push_right=False):
        self.items.append((widget, padx, pady, push_right))
        self._rows = None
        self._later()
        return widget

    def _later(self, _event=None):
        if self._job is not None:
            try:
                self.after_cancel(self._job)
            except tk.TclError:
                pass
        try:                    # once the window edge stops moving: no jumping rows mid-drag
            self._job = self.after(WRAP_SETTLE_MS, self.relayout)
        except tk.TclError:
            self._job = None

    @staticmethod
    def _pad(padx):
        return sum(padx) if isinstance(padx, (tuple, list)) else 2 * padx

    def arrange(self, width):
        """[[item, ...], ...]: the items of each row for this width."""
        rows, row, used = [], [], 0
        for item in self.items:
            widget, padx, _pady, _right = item
            need = widget.winfo_reqwidth() + self._pad(padx)
            if row and used + need > width:
                rows.append(row)
                row, used = [], 0
            row.append(item)
            used += need
        if row:
            rows.append(row)
        return rows

    def relayout(self):
        self._job = None
        try:
            width = self.winfo_width()
        except tk.TclError:
            return
        if width <= 1:
            width = 10 ** 6                 # not laid out yet: one row
        rows = self.arrange(width)
        shape = [[id(i[0]) for i in r] for r in rows]
        if shape == self._rows:
            return
        self._rows = shape
        for widget, *_rest in self.items:
            widget.grid_forget()
        self.grid_columnconfigure(0, weight=1)
        while len(self._frames) < len(rows):           # one frame per row: its own columns
            self._frames.append(tk.Frame(self, background=self.cget('background')))
        for r, frame in enumerate(self._frames):
            if r >= len(rows):
                frame.grid_remove()
                continue
            frame.grid(row=r, column=0, sticky='ew')
            for c in range(len(self.items) + 1):
                frame.grid_columnconfigure(c, weight=0)
            col, pushed = 0, False
            for widget, padx, pady, right in rows[r]:
                if right and not pushed:
                    frame.grid_columnconfigure(col, weight=1)   # a spacer: push the rest right
                    col += 1
                    pushed = True
                widget.grid(in_=frame, row=0, column=col, padx=padx, pady=pady, sticky='w')
                widget.lift(frame)                  # the row frame was made after the widget
                col += 1

    @property
    def row_count(self):
        return len(self._rows or [])
