"""Serial console access to Cisco devices (Console-Based SSH Auto-Setup, phase 1).

    ports.py   which COM ports exist, and which look like a console adapter
    link.py    open / use / close one console session (read-only in this phase)
    detect.py  identify the device and its SSH capability (read-only; docs/CONSOLE_DETECTION.md)

Nothing in this package changes a device's configuration. All serial I/O blocks, so the
GUI must call it from a worker thread (gui.background.run_async), never from Tk's thread.
"""
