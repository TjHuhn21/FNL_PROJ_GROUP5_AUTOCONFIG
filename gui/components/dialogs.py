"""Where dialogs and secondary windows open: centered on the window they belong to,
sized for their content (or for a scaled design size), never larger than the screen.

    place_window(win, parent)                    # a dialog: its content decides the size
    place_window(win, parent, size=(1000, 760))  # a big window: design pixels, scaled
                                                 # (gui/ui_scale.py) and clamped to the screen

Call it at the end of the window's __init__ (after its widgets exist, before grab_set).
"""
import tkinter as tk

from gui import ui_scale

SCREEN_SHARE = (0.92, 0.88)          # a window never covers more of the screen than this


def place_window(win, parent=None, size=None):
    """Size and center `win` (see the module notes). Returns (width, height, x, y)."""
    try:
        win.update_idletasks()
        sw, sh = win.winfo_screenwidth(), win.winfo_screenheight()
        if size:
            w, h = ui_scale.space(size[0]), ui_scale.space(size[1])
        else:
            w, h = win.winfo_reqwidth(), win.winfo_reqheight()
        w, h = min(w, int(sw * SCREEN_SHARE[0])), min(h, int(sh * SCREEN_SHARE[1]))
        owner = parent.winfo_toplevel() if parent is not None else None
        if owner is not None and owner.winfo_ismapped() and owner.winfo_width() > 1:
            cx = owner.winfo_rootx() + owner.winfo_width() // 2
            cy = owner.winfo_rooty() + owner.winfo_height() // 2
        else:
            cx, cy = sw // 2, sh // 2
        x = max(0, min(cx - w // 2, sw - w))
        y = max(0, min(cy - h // 2, sh - h))
        if size:
            win.geometry(f'{w}x{h}+{x}+{y}')
        else:                      # the content decides the size (it may grow later)
            win.geometry(f'+{x}+{y}')
        return w, h, x, y
    except tk.TclError:
        return None
