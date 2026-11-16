"""Shared helpers for the window tests (not a test file itself)."""
import time
import tkinter as tk

import pytest


def new_root(attempts=5):
    """tk.Tk(), retried briefly. On Windows, opening a window right after another
    one closed sometimes fails with "Can't find a usable init.tcl / tk.tcl ...
    couldn't read file ...: No error" (Tcl's own start-up files are momentarily
    unreadable). That is not a missing display, so retry instead of skipping."""
    for attempt in range(attempts):
        try:
            return tk.Tk()
        except tk.TclError as err:
            text = str(err)
            transient = any(s in text for s in ('init.tcl', 'tk.tcl', "couldn't read file",
                                                'tcl_findLibrary'))   # defined in init.tcl
            if transient and attempt < attempts - 1:
                time.sleep(0.3)
                continue
            pytest.skip(f'cannot open a window: {text.splitlines()[0]}')


def pump(root, cond, timeout=10):
    """Let the window run until cond() is true (or the timeout passes)."""
    end = time.time() + timeout
    while time.time() < end:
        root.update()
        if cond():
            return True
        time.sleep(0.02)
    return False
