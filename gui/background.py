"""Run a slow call (a network request) without freezing the window.

run_async(widget, fn, done): fn() runs on a worker thread; done(result, error) is then
called on the Tk thread (exactly one of them is not None). Tests replace run_async with
a synchronous version. Callers use background.run_async(...) so that works.
"""
import threading


def run_async(widget, fn, done, poll_ms=50):
    box = {}

    def work():
        try:
            box['result'] = fn()
        except Exception as err:                 # handed to done(); never printed here
            box['error'] = err

    thread = threading.Thread(target=work, daemon=True)
    thread.start()

    def poll():
        if thread.is_alive():
            try:
                widget.after(poll_ms, poll)
            except Exception:                    # the window was closed meanwhile
                pass
            return
        done(box.get('result'), box.get('error'))

    widget.after(poll_ms, poll)


def run_now(widget, fn, done):
    """Synchronous stand-in for tests."""
    try:
        result = fn()
    except Exception as err:
        done(None, err)
        return
    done(result, None)
