"""The SSH session console: a terminal-like panel that shows what NetCommand
really sends to a device and what the device answers.

    ===== 14:02:11  SW1 (192.168.1.3)  6 commands =====
    [CONNECT]
    [SW1] Connecting to 192.168.1.3 through SSH...
    [BACKUP]
    SW1# show running-config
    (the device's real output)
    [CONFIGURATION]
    SW1(config)# vlan 10
    ...

post() may be called from any thread (the SSH worker): lines go into a queue,
and only the window's own thread takes them out and puts them on screen
(Tkinter widgets must only be touched from that thread). Output stays visible
for the whole session until Clear console is clicked.
"""
import queue
import tkinter as tk
from datetime import datetime
from tkinter import ttk

from gui import theme

BG = '#1B2024'                  # terminal background
COLORS = {                      # all at least 4.5:1 against BG
    'command': '#FFFFFF',
    'output': '#B9C2C9',
    'info': '#98A3AC',
    'section': '#4FD1C5',
    'ok': '#62D394',
    'warn': '#F2B84B',
    'error': '#FF8A7F',
    'start': '#7FB3FF',
    'device': '#7FB3FF',        # one device of a multi-device run starts
    'summary': '#E6EAED',
}
DRAIN_MS = 60


class SshConsole(tk.Frame):
    def __init__(self, parent, title='SSH session'):
        super().__init__(parent, background=theme.SURFACE)
        self._queue = queue.Queue()
        self.lines = []                         # (kind, text) as shown: handy for tests

        bar = tk.Frame(self, background=theme.SURFACE)
        bar.pack(fill='x', pady=(0, 4))
        tk.Label(bar, text=title, font=theme.FONT_BOLD, background=theme.SURFACE,
                 foreground=theme.TEXT).pack(side='left')
        tk.Label(bar, text='  every command NetCommand sends, and the device’s real reply',
                 font=theme.FONT_SMALL, background=theme.SURFACE,
                 foreground=theme.TEXT_MUTED).pack(side='left')
        self.clear_button = ttk.Button(bar, text='Clear console', command=self.clear)
        self.clear_button.pack(side='right')

        holder = tk.Frame(self, background=BG)
        holder.pack(fill='both', expand=True)
        self.text = tk.Text(holder, height=10, wrap='none', font=theme.mono(theme.SESSION_SIZE),
                            background=BG, foreground=COLORS['output'], insertbackground=BG,
                            relief='flat', borderwidth=0, highlightthickness=0, padx=10, pady=8,
                            state='disabled', cursor='arrow')
        ys = ttk.Scrollbar(holder, orient='vertical', command=self.text.yview)
        xs = ttk.Scrollbar(holder, orient='horizontal', command=self.text.xview)
        self.text.configure(yscrollcommand=ys.set, xscrollcommand=xs.set)
        ys.pack(side='right', fill='y')
        xs.pack(side='bottom', fill='x')
        self.text.pack(side='left', fill='both', expand=True)
        for kind, color in COLORS.items():
            bold = kind in ('command', 'section', 'start', 'device', 'ok', 'error')
            self.text.tag_configure(kind, foreground=color,
                                    font=theme.mono(theme.SESSION_SIZE, 'bold') if bold
                                    else theme.mono(theme.SESSION_SIZE))
        self._device = None
        self._timer = self.after(DRAIN_MS, self._drain)
        self.bind('<Destroy>', self._stop, add='+')

    # ---------------------------------------------------------------- any thread
    def post(self, kind, text, device=None):
        """Queue one entry (kind: start, section, command, output, info, ok, warn, error)."""
        self._queue.put((kind, text, device))

    def start_run(self, device, ip, count):
        """A heading that separates one Apply from the next."""
        stamp = datetime.now().strftime('%H:%M:%S')
        self.post('start', f'===== {stamp}  {device} ({ip})  {count} command'
                           f'{"" if count == 1 else "s"} =====', device)

    def start_batch(self, names):
        """A heading for one Apply that configures several devices."""
        stamp = datetime.now().strftime('%H:%M:%S')
        self.post('start', f'===== {stamp}  {len(names)} devices, one after the other: '
                           f'{", ".join(names)} =====')

    # ---------------------------------------------------------------- window thread only
    def _drain(self):
        self.flush()
        try:
            self._timer = self.after(DRAIN_MS, self._drain)
        except tk.TclError:
            self._timer = None

    def flush(self):
        """Put everything queued on screen now."""
        try:
            while True:
                self._write(*self._queue.get_nowait())
        except queue.Empty:
            pass

    def _write(self, kind, text, device):
        if kind == 'section':
            shown = f'\n[{text}]'
        elif kind in ('info', 'ok', 'warn', 'error') and device:
            shown = '\n'.join(f'[{device}] {line}' for line in text.splitlines() or [''])
        elif kind == 'device':
            shown = f'\n{"-" * 12} {text} {"-" * 12}'
        elif kind == 'start':
            shown = ('\n' if self.lines else '') + text
        else:
            shown = text
        self.lines.append((kind, shown))
        t = self.text
        t.configure(state='normal')
        t.insert('end', shown + '\n', (kind if kind in COLORS else 'output',))
        t.see('end')
        t.configure(state='disabled')

    def clear(self):
        self.lines.clear()
        self.text.configure(state='normal')
        self.text.delete('1.0', 'end')
        self.text.configure(state='disabled')

    def content(self):
        return self.text.get('1.0', 'end')

    def _stop(self, event):
        if event.widget is self and self._timer:
            try:
                self.after_cancel(self._timer)
            except tk.TclError:
                pass
            self._timer = None
