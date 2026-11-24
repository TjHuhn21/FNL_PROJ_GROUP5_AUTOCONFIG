"""A read-only window with the full text of one Console / history entry: a command's
complete output, or a configuration change's before/after (already masked)."""
import tkinter as tk
from tkinter import ttk

from gui import theme
from gui.components.dialogs import place_window


def describe(record):
    """The popup text for a record (a Console record or a saved history row)."""
    from gui.timefmt import format_datetime
    get = record.get
    head = [f"Time:     {get('when') or format_datetime(get('created_at'), seconds=True)}",
            f"User:     {get('user') or get('user_label') or ''}",
            f"Category: {get('category') or ''}"]
    if get('device'):
        ip = get('ip') or get('device_ip')
        head.append(f"Device:   {get('device')}" + (f' ({ip})' if ip and ip != get('device') else ''))
    head.append(f"Message:  {get('message') or ''}")
    if get('result'):
        head.append(f"Result:   {get('result')}")
    tags = get('tags') or ()
    if isinstance(tags, str):
        tags = [t for t in tags.split(',') if t]
    if tags:
        head.append(f"Tags:     {', '.join(tags)}")
    body = get('detail') or ''
    return '\n'.join(head) + ('\n\n' + body if body else '\n\n(No further output for this line.)')


def show_detail(parent, record, title=None):
    """Open the window (not modal). Returns it."""
    win = tk.Toplevel(parent)
    win.title(title or 'Console entry')
    win.configure(background=theme.BG)
    place_window(win, parent, size=(900, 520))          # scaled, on screen, centered
    holder = tk.Frame(win, background=theme.BG)
    holder.pack(fill='both', expand=True, padx=theme.PAD, pady=theme.PAD)
    text = tk.Text(holder, wrap='none', font=theme.mono(theme.CONSOLE_SIZE), relief='flat',
                   background=theme.CARD, foreground=theme.TEXT, padx=10, pady=6,
                   borderwidth=0, highlightthickness=0)
    ys = ttk.Scrollbar(holder, orient='vertical', command=text.yview)
    xs = ttk.Scrollbar(holder, orient='horizontal', command=text.xview)
    text.configure(yscrollcommand=ys.set, xscrollcommand=xs.set)
    ys.pack(side='right', fill='y')
    xs.pack(side='bottom', fill='x')
    text.pack(side='left', fill='both', expand=True)
    text.tag_configure('added', foreground=theme.SUCCESS)
    text.tag_configure('removed', foreground=theme.DANGER)
    for line in describe(record).splitlines():
        tag = ('added',) if line.startswith('+') and not line.startswith('+++') else \
            ('removed',) if line.startswith('-') and not line.startswith('---') else ()
        text.insert('end', line + '\n', tag)
    text.configure(state='disabled')
    ttk.Button(win, text='Close', command=win.destroy).pack(anchor='e', padx=theme.PAD,
                                                           pady=(0, theme.PAD))
    win.bind('<Escape>', lambda e: win.destroy())
    win.text = text
    return win
