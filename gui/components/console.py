"""The operations console along the bottom of the workbench.

Two tabs:
  Console     timestamped events from this session, written by the app itself
              (only real events; nothing is invented). log() may be called from
              any thread: messages go through a queue and only the window's own
              thread puts them on screen (Tk is not thread-safe).
  Config log  the existing configuration log (store.get_logs), newest first,
              reloaded when the tab is opened or Refresh is clicked.
"""
import queue
import tkinter as tk
from datetime import datetime
from tkinter import ttk

from gui import theme

LEVEL_COLORS = {'info': None, 'ok': theme.SUCCESS, 'warn': theme.WARNING, 'error': theme.DANGER}
CONFIG_LOG_ROWS = 50


class OperationsConsole(tk.Frame):
    def __init__(self, parent, store):
        super().__init__(parent, background=theme.SURFACE)
        self.store = store
        self._queue = queue.Queue()
        self.lines = []                     # (time, source, message, level): handy for tests

        self.tabs = ttk.Notebook(self)
        self.tabs.pack(fill='both', expand=True)

        self.text = self._make_text(self.tabs)
        self.tabs.add(self.text.master, text='Console')
        self.config_text = self._make_text(self.tabs)
        self.tabs.add(self.config_text.master, text='Config log')
        self.tabs.bind('<<NotebookTabChanged>>', self._tab_changed)

        tools = tk.Frame(self, background=theme.SURFACE)
        tools.place(relx=1.0, x=-8, y=2, anchor='ne')          # sits on the tab row, right side
        ttk.Button(tools, text='Clear', command=self.clear).pack(side='right')
        ttk.Button(tools, text='Refresh', command=self.refresh_config_log).pack(side='right', padx=4)

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
        text = tk.Text(holder, height=6, wrap='none', font=theme.mono(9), relief='flat',
                       background='#FAFAF8', foreground=theme.TEXT, padx=10, pady=6,
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

    def _drain(self):
        try:
            while True:
                self._write(*self._queue.get_nowait())
        except queue.Empty:
            pass
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
        self.lines.clear()
        self.text.configure(state='normal')
        self.text.delete('1.0', 'end')
        self.text.configure(state='disabled')

    # ---------------------------------------------------------------- Config log tab
    def _tab_changed(self, _event):
        if self.tabs.index('current') == 1:
            self.refresh_config_log()

    def refresh_config_log(self):
        """Show the newest configuration log entries (read-only)."""
        t = self.config_text
        t.configure(state='normal')
        t.delete('1.0', 'end')
        try:
            rows = self.store.get_logs('', 1, CONFIG_LOG_ROWS, '')
        except Exception as err:
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
