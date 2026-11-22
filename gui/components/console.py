"""The operations console along the bottom of the workbench.

Three tabs:
  Console        timestamped events from this session, written by the app itself
                 (only real events; nothing is invented). log() may be called from
                 any thread: messages go through a queue and only the window's own
                 thread puts them on screen (Tk is not thread-safe).
  Config log     the existing configuration log (store.get_logs), newest first,
                 reloaded when the tab is opened or Refresh is clicked.
  Status events  the recorded device status changes (store.get_events), newest first:
                 time, device, previous -> new status, detail. Reloaded when the tab is
                 opened, on Refresh, and after the monitor records a change.
Both stored-data tabs are read on the window's own thread. While the database is
unavailable they show that instead of their old contents (never old rows as current).

Refresh and Clear act on the tab that is shown:
  Console        Refresh shows any lines still waiting; Clear empties the console.
  Config log     Refresh reloads it; Clear only empties the VIEW (a note says so).
  Status events  Refresh reloads them; Clear only empties the VIEW.
Clearing never deletes anything from the database: the configuration log and the
status history stay stored, and Refresh (or opening the tab again) shows them again.
"""
import queue
import threading
import tkinter as tk
from datetime import datetime
from tkinter import ttk

from gui import theme
from gui.db_status import report_error

LEVEL_COLORS = {'info': None, 'ok': theme.SUCCESS, 'warn': theme.WARNING, 'error': theme.DANGER}
CONFIG_LOG_ROWS = 50
EVENT_ROWS = 50
CONFIG_TAB, EVENTS_TAB = 1, 2
UNAVAILABLE_TEXT = ('Database unavailable: this cannot be shown right now. It is reloaded '
                    'when the connection is back.\n')
CLEARED_TEXT = {CONFIG_TAB: 'Configuration log cleared from view (nothing was deleted). '
                            'Click Refresh to show it again.\n',
                EVENTS_TAB: 'Status events cleared from view (nothing was deleted). '
                            'Click Refresh to show them again.\n'}


class OperationsConsole(tk.Frame):
    def __init__(self, parent, store):
        super().__init__(parent, background=theme.SURFACE)
        self.store = store
        self._queue = queue.Queue()
        self.lines = []                     # (time, source, message, level): handy for tests

        self.tabs = ttk.Notebook(self, style='Console.TNotebook')
        self.tabs.pack(fill='both', expand=True)

        self.text = self._make_text(self.tabs)
        self.tabs.add(self.text.master, text='Console')
        self.config_text = self._make_text(self.tabs)
        self.tabs.add(self.config_text.master, text='Config log')
        self.events_text = self._make_text(self.tabs)
        self.tabs.add(self.events_text.master, text='Status events')
        self.tabs.bind('<<NotebookTabChanged>>', self._tab_changed)
        # Set from the monitor's thread when it recorded a change; read on this thread.
        self._events_changed = threading.Event()
        self.status_changed = self._make_status_callback(self._queue, self._events_changed)

        tools = tk.Frame(self, background=theme.SURFACE)
        tools.place(relx=1.0, x=-8, y=2, anchor='ne')          # sits on the tab row, right side
        self.clear_button = ttk.Button(tools, text='Clear', command=self.clear,
                                       style='Console.TButton')
        self.clear_button.pack(side='right')
        self.refresh_button = ttk.Button(tools, text='Refresh', command=self.refresh_current,
                                         style='Console.TButton')
        self.refresh_button.pack(side='right', padx=4)

        self._timer = self.after(150, self._drain)
        self.bind('<Destroy>', self._stop, add='+')

    def _stop(self, event):
        if event.widget is self and self._timer:     # window closing: stop the timer cleanly
            try:
                self.after_cancel(self._timer)
            except tk.TclError:
                pass
            self._timer = None

    def _make_text(self, parent):
        holder = tk.Frame(parent, background=theme.SURFACE)
        text = tk.Text(holder, height=6, wrap='none', font=theme.mono(theme.CONSOLE_SIZE),
                       relief='flat',
                       background=theme.CARD, foreground=theme.TEXT, padx=10, pady=6,
                       borderwidth=0, highlightthickness=0, state='disabled', cursor='arrow')
        scroll = ttk.Scrollbar(holder, orient='vertical', command=text.yview)
        text.configure(yscrollcommand=scroll.set)
        scroll.pack(side='right', fill='y')
        text.pack(side='left', fill='both', expand=True)
        text.tag_configure('time', foreground=theme.TEXT_MUTED)
        text.tag_configure('source', foreground=theme.ACCENT)
        for level, color in LEVEL_COLORS.items():
            if color:
                text.tag_configure(level, foreground=color)
        return text

    # ---------------------------------------------------------------- Console tab
    def log(self, source, message, level='info'):
        """Add one line. Safe to call from any thread."""
        self._queue.put((datetime.now().strftime('%H:%M:%S'), source, message, level))

    @staticmethod
    def _make_status_callback(lines, changed):
        """The monitor's on_change(device, new_status): safe from any thread. A plain
        function holding only a queue and an Event, never a widget."""
        def status_changed(device, new):
            lines.put((datetime.now().strftime('%H:%M:%S'), 'monitor',
                       f"{device['name']} ({device['ip']}): {device['status']} -> {new} "
                       f"(recorded)", 'ok' if new == 'up' else 'warn'))
            changed.set()
        return status_changed

    def _drain(self):
        try:
            while True:
                self._write(*self._queue.get_nowait())
        except queue.Empty:
            pass
        if self._events_changed.is_set():             # the monitor recorded a change
            self._events_changed.clear()
            if self._current_tab() == EVENTS_TAB:
                self.refresh_events()
        try:
            self._timer = self.after(150, self._drain)
        except tk.TclError:                      # window closed
            self._timer = None

    def flush(self):
        """Put every queued line on screen now (used by tests and on shutdown)."""
        try:
            while True:
                self._write(*self._queue.get_nowait())
        except queue.Empty:
            pass

    def _write(self, when, source, message, level):
        self.lines.append((when, source, message, level))
        t = self.text
        t.configure(state='normal')
        t.insert('end', when, ('time',))
        t.insert('end', '  ')
        t.insert('end', f'{source:<9} ', ('source',))     # 'configure' is 9 letters: keep a gap
        t.insert('end', message + '\n', (level,) if LEVEL_COLORS.get(level) else ())
        t.see('end')
        t.configure(state='disabled')

    def clear(self):
        """The Clear button: empty the tab that is shown. On the stored-data tabs only the
        view is emptied (nothing is deleted from the database)."""
        tab = self._current_tab()
        if tab in (CONFIG_TAB, EVENTS_TAB):
            t = self.config_text if tab == CONFIG_TAB else self.events_text
            t.configure(state='normal')
            t.delete('1.0', 'end')
            t.insert('end', CLEARED_TEXT[tab], ('time',))
            t.configure(state='disabled')
            return
        self.lines.clear()
        self.text.configure(state='normal')
        self.text.delete('1.0', 'end')
        self.text.configure(state='disabled')

    # ---------------------------------------------------------------- stored-data tabs
    def _current_tab(self):
        try:
            return self.tabs.index('current')
        except tk.TclError:
            return None

    def _tab_changed(self, _event):
        tab = self._current_tab()
        if tab == CONFIG_TAB:
            self.refresh_config_log()
        elif tab == EVENTS_TAB:
            self.refresh_events()

    def refresh_current(self):
        """The Refresh button, and after the database is back: reload the tab shown.
        On the Console tab: show any lines that are still waiting in the queue."""
        tab = self._current_tab()
        if tab == CONFIG_TAB:
            self.refresh_config_log()
        elif tab == EVENTS_TAB:
            self.refresh_events()
        else:
            self.flush()

    def show_unavailable(self):
        """The database is unavailable: blank both stored-data tabs (no old rows shown as
        current). They are reloaded when the connection is back."""
        for t in (self.config_text, self.events_text):
            t.configure(state='normal')
            t.delete('1.0', 'end')
            t.insert('end', UNAVAILABLE_TEXT, ('error',))
            t.configure(state='disabled')

    def refresh_events(self):
        """Show the newest recorded status changes (read-only). Returns the rows, or []
        when they could not be read (the reason is shown instead)."""
        t = self.events_text
        t.configure(state='normal')
        t.delete('1.0', 'end')
        try:
            rows = self.store.get_events(EVENT_ROWS)
        except Exception as err:
            report_error(self, err)            # may blank this tab (outage): write after it
            t.configure(state='normal')
            t.delete('1.0', 'end')
            t.insert('end', f'Could not read the status events: {err}\n', ('error',))
            t.configure(state='disabled')
            return []
        if not rows:
            t.insert('end', 'No status changes have been recorded yet. The background '
                            'monitor records them (database mode only).\n', ('time',))
        for r in rows:
            when = r['created_at'].strftime('%Y-%m-%d %H:%M:%S') if r.get('created_at') else ''
            previous = r.get('previous') or '?'
            level = 'ok' if r['kind'] == 'up' else 'error' if r['kind'] == 'down' else 'info'
            t.insert('end', when, ('time',))
            t.insert('end', f"  {r['device']:<10} {previous:>4} -> ")
            t.insert('end', f"{r['kind']:<5}", (level,))
            t.insert('end', f" {r.get('detail') or ''}\n")
        t.configure(state='disabled')
        return rows

    # ---------------------------------------------------------------- Config log tab

    def refresh_config_log(self):
        """Show the newest configuration log entries (read-only)."""
        t = self.config_text
        t.configure(state='normal')
        t.delete('1.0', 'end')
        try:
            rows = self.store.get_logs('', 1, CONFIG_LOG_ROWS, '')
        except Exception as err:
            report_error(self, err)            # may blank this tab (outage): write after it
            t.configure(state='normal')
            t.delete('1.0', 'end')
            t.insert('end', f'Could not read the configuration log: {err}\n', ('error',))
            rows = None
        if rows is not None and not rows:
            t.insert('end', 'No configuration changes have been logged yet.\n', ('time',))
        for r in rows or []:
            when = r['created_at'].strftime('%Y-%m-%d %H:%M:%S') if r.get('created_at') else ''
            level = 'ok' if r['status'] == 'success' else 'error'
            t.insert('end', when, ('time',))
            t.insert('end', f"  {r['device']:<10} {r['action']:<14} ")
            t.insert('end', f"{r['status']:<8}", (level,))
            t.insert('end', f" {r['details'] or ''}\n")
        t.configure(state='disabled')
        return rows or []
