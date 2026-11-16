"""The command strip at the top of the workbench.

Type part of a device name or IP to find it (the same search the Devices page
uses: store.get_devices), or an operation word to jump there:
    scan, devices, topology / map, findings / review, configure [device], logs, overview
Up/Down choose a suggestion, Enter runs it, Esc closes the list, Ctrl+K focuses the strip.
Operations only open pages; nothing runs on a network from here.
"""
import tkinter as tk

import customtkinter as ctk

from gui import theme

# word -> (page key, label shown in the list)
OPERATIONS = [
    ('overview', 'dashboard', 'Open Overview'),
    ('scan', 'scan', 'Open Network Scan'),
    ('devices', 'devices', 'Open Devices'),
    ('topology', 'topology', 'Open Topology'),
    ('map', 'topology', 'Open Topology'),
    ('findings', 'findings', 'Open Findings'),
    ('review', 'findings', 'Open Findings (configuration review)'),
    ('configure', 'configure', 'Open Configure'),
    ('logs', 'logs', 'Open Activity Logs'),
]
MAX_DEVICES = 8


class CommandStrip(ctk.CTkFrame):
    def __init__(self, parent, store, on_device, on_operation):
        """on_device(device_id); on_operation(page_key, device_name_or_None)."""
        super().__init__(parent, fg_color='transparent', corner_radius=0)
        self.store, self.on_device, self.on_operation = store, on_device, on_operation
        self.items = []                      # [(kind, text, payload)] currently suggested
        self._pending = None
        self.entry = ctk.CTkEntry(
            self, width=520, height=30, corner_radius=3, border_width=1,
            border_color=theme.BORDER_STRONG, fg_color=theme.APP_BG, text_color=theme.TEXT,
            placeholder_text='Find a device or IP, or type an operation: scan, devices, configure SW1',
            placeholder_text_color=theme.TEXT_MUTED, font=theme.FONT)
        self.entry.grid(row=0, column=0, sticky='ew')
        self.grid_columnconfigure(0, weight=1)
        ctk.CTkLabel(self, text='Ctrl K', font=theme.mono(8), text_color=theme.TEXT_SOFT,
                     fg_color=theme.SURFACE, corner_radius=3, width=44, height=20).grid(
            row=0, column=1, padx=(8, 0))

        top = self.winfo_toplevel()
        self.popup = tk.Frame(top, background=theme.BORDER_STRONG, borderwidth=0)
        self.listbox = tk.Listbox(self.popup, font=theme.mono(9), activestyle='none',
                                  background=theme.SURFACE, foreground=theme.TEXT,
                                  selectbackground=theme.ACCENT_SOFT, selectforeground=theme.TEXT,
                                  highlightthickness=0, borderwidth=0, relief='flat')
        self.listbox.pack(fill='both', expand=True, padx=1, pady=1)
        self.listbox.bind('<ButtonRelease-1>', lambda _e: self.run(self._selected()))

        for sequence, handler in (('<KeyRelease>', self._on_key), ('<Down>', lambda e: self._move(1)),
                                  ('<Up>', lambda e: self._move(-1)),
                                  ('<Return>', lambda e: self.run(self._selected())),
                                  ('<Escape>', lambda e: self.close()),
                                  ('<FocusOut>', lambda e: self.after(200, self._maybe_close))):
            self.entry.bind(sequence, handler)
        top.bind_all('<Control-k>', lambda e: self.focus())
        top.bind_all('<Control-K>', lambda e: self.focus())

    # ---------------------------------------------------------------- public
    def focus(self):
        self.entry.focus_set()
        return 'break'

    def set_text(self, text):
        self.entry.delete(0, 'end')
        if text:
            self.entry.insert(0, text)

    def get_text(self):
        return self.entry.get().strip()

    def update_suggestions(self):
        """Rebuild the suggestion list from the current text."""
        self.items = self.suggestions(self.get_text())
        self.listbox.delete(0, 'end')
        for _kind, text, _payload in self.items:
            self.listbox.insert('end', ' ' + text)
        if self.items:
            self.listbox.selection_clear(0, 'end')
            self.listbox.selection_set(0)
            self._show_popup()
        else:
            self.close()
        return self.items

    def suggestions(self, text):
        """[(kind, text, payload)]: operations first, then matching devices."""
        if not text:
            return []
        words = text.split()
        first = words[0].lower()
        found, seen_labels = [], set()
        if first == 'configure' and len(words) > 1:               # "configure SW1"
            for d in self._devices(words[1]):
                if d['managed']:
                    found.append(('op', f"Configure {d['name']}", ('configure', d['name'])))
        for word, key, label in OPERATIONS:
            if len(words) == 1 and word.startswith(first) and label not in seen_labels:
                found.append(('op', label, (key, None)))
                seen_labels.add(label)
        if not (first == 'configure' and len(words) > 1):
            for d in self._devices(text):
                found.append(('device', f"{d['name']:<14}{d['ip']:<17}{d['type']}", d['id']))
        return found

    def run(self, index):
        """Carry out suggestion number `index` (0 = the first)."""
        if index is None or not (0 <= index < len(self.items)):
            return None
        kind, _text, payload = self.items[index]
        self.close()
        self.set_text('')
        if kind == 'device':
            self.on_device(payload)
        else:
            self.on_operation(*payload)
        return kind, payload

    def close(self):
        self.popup.place_forget()

    # ---------------------------------------------------------------- internals
    def _devices(self, text):
        try:
            return self.store.get_devices(text, 'name', 1, MAX_DEVICES)
        except Exception:                    # database unreachable: offer operations only
            return []

    def _on_key(self, event):
        if event.keysym in ('Up', 'Down', 'Return', 'Escape'):
            return
        if self._pending:
            self.after_cancel(self._pending)
        self._pending = self.after(120, self.update_suggestions)   # wait for a typing pause

    def _selected(self):
        sel = self.listbox.curselection()
        return sel[0] if sel else (0 if self.items else None)

    def _move(self, step):
        if not self.items:
            return 'break'
        i = (self._selected() or 0) + step
        i = max(0, min(len(self.items) - 1, i))
        self.listbox.selection_clear(0, 'end')
        self.listbox.selection_set(i)
        self.listbox.see(i)
        return 'break'

    def _maybe_close(self):
        focused = self.focus_get()
        if focused is not self.listbox:
            self.close()

    def _show_popup(self):
        top = self.winfo_toplevel()
        x = self.entry.winfo_rootx() - top.winfo_rootx()
        y = self.entry.winfo_rooty() - top.winfo_rooty() + self.entry.winfo_height() + 2
        self.listbox.configure(height=min(len(self.items), 10))
        self.popup.place(x=x, y=y, width=max(self.entry.winfo_width(), 300))
        self.popup.lift()
