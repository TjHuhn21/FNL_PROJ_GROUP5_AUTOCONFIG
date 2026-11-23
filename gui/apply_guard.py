"""Application shutdown protection while an SSH setup is applied through the console
(phase 5.1.3, review finding H1).

Ending the process during an Apply would kill its worker thread in the middle of a
command exchange: the device could be left half-way through a step, and nobody would
know. So, as with a restore (gui.restore_window.block_shutdown), every normal way out of
the workbench (the window's X, Sign out, an ended session, demo-mode close) asks this
module first:

    begin(port, cancel) -> token    the Setup page, just before the Apply worker starts
    end(token)                      the worker itself, once apply_plan has returned and,
                                    if a shutdown was requested, the console is closed
    active()                        ports with an Apply running
    block_shutdown(parent)          True (and a message) while one runs: the caller must
                                    not close now; the run is asked to stop after its
                                    current step
    shutdown_requested(token)       the worker: close the console before ending

A shutdown request never cancels the serial exchange in progress: it sets the run's
`cancel` flag (read by console.apply between steps only) and its `finish_fast` flag (no
final re-detection). The worker then closes the console port without typing anything
and calls end(); the caller (main.py) polls active() with Tk's after() and carries out
the close or sign-out it postponed. The worker never waits for the Tk thread and the Tk
thread never blocks on the worker, so the two cannot deadlock.
"""
import itertools
import threading
from tkinter import messagebox

SHUTDOWN_TITLE = 'SSH setup in progress'
_LOCK = threading.Lock()
_RUNS = {}                          # token -> _Run
_TOKENS = itertools.count(1)


class _Run:
    def __init__(self, port, cancel):
        self.port = port
        self.cancel = cancel                       # console.apply: stop between steps
        self.finish_fast = threading.Event()       # console.apply: skip the re-detection
        self.shutdown = threading.Event()          # the worker closes the console at the end


def begin(port, cancel):
    """A new protection token: NetCommand will not close until end(token)."""
    with _LOCK:
        token = next(_TOKENS)
        _RUNS[token] = _Run(port, cancel)
        return token


def end(token):
    with _LOCK:
        _RUNS.pop(token, None)


def finish_fast_event(token):
    with _LOCK:
        run = _RUNS.get(token)
    return run.finish_fast if run is not None else threading.Event()


def shutdown_requested(token):
    with _LOCK:
        run = _RUNS.get(token)
    return run is not None and run.shutdown.is_set()


def active():
    """The console ports with an SSH Apply running (sorted, each once)."""
    with _LOCK:
        return sorted({run.port for run in _RUNS.values()})


def request_shutdown():
    """Ask every running Apply to stop after its current step and close its console.
    Never interrupts an exchange. Returns the ports concerned."""
    with _LOCK:
        runs = list(_RUNS.values())
    for run in runs:
        run.shutdown.set()
        run.finish_fast.set()
        run.cancel.set()
    return sorted({run.port for run in runs})


def shutdown_message(ports, then='close'):
    return (f'An SSH configuration is being applied through the console ({", ".join(ports)}).'
            f'\n\nThe command being sent now is never cut off. NetCommand finishes the current '
            f'step, does not start the next one, closes the console port (without typing '
            f'anything more), and then will {then}.\n\nNothing was saved on the device; '
            f'detect it again before relying on its state.')


def block_shutdown(parent=None, then='close'):
    """For every normal way of closing the application: True (and a message) while an
    Apply runs, so the caller must NOT close yet (it should wait for active() to become
    empty); False otherwise. It asks the run to stop after its current step."""
    ports = request_shutdown()
    if not ports:
        return False
    messagebox.showwarning(SHUTDOWN_TITLE, shutdown_message(ports, then), parent=parent)
    return True
