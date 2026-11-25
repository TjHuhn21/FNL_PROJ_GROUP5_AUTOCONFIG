"""What is running right now (a scan, a configuration Apply, a review, a backup check),
so closing or signing out can warn first:

    activity.start('configure', 'A configuration is still being applied to MOCK-R1.')
    ...
    activity.finish('configure')
    activity.running()      # -> ['A configuration is still being applied to MOCK-R1.']

Only the main (Tk) thread calls these. Nothing here stops any work; restores and SSH
setups through the console have their own, stricter guards (restore_window, apply_guard).
"""
_running = {}


def start(key, text):
    _running[key] = text


def finish(key):
    _running.pop(key, None)


def running():
    """The sentences describing the work in progress (oldest first)."""
    return list(_running.values())


def reset():
    """Tests: nothing is running."""
    _running.clear()
