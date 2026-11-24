"""An entry field that checks itself while the user types (validators.py rules).

    CheckedEntry(parent, var, check=validators.check_ipv4, typing='ipv4', width=15)

* typing: characters that cannot belong in the field are refused as they are typed (a
  paste too), e.g. letters in an IP address (validators.TYPING).
* check(text) -> message or None runs on every change. An invalid value gets a red
  border (style Invalid.TEntry / Invalid.TCombobox, defined in theme.apply) and a short
  red message under the field. An empty field
  is fine unless required (then it only counts as "not ready": no red while untouched).
* warn(text) -> message or None: an amber note that never blocks (e.g. VLAN 1).
* show_error(message): a problem found by a check that needs several fields (on Add).
* on_change(): called after every change (the form enables or disables its Add button).
"""
import tkinter as tk
from tkinter import ttk

import validators
from gui import theme

INVALID_STYLE, INVALID_COMBO = 'Invalid.TEntry', 'Invalid.TCombobox'
MESSAGE_WRAP = 240


class CheckedEntry(ttk.Frame):
    def __init__(self, parent, var, check=None, typing=None, width=14, required=False,
                 warn=None, label='', combo_values=None):
        super().__init__(parent)
        self.var, self.check, self.warn, self.required = var, check, warn, required
        self.label, self.on_change, self._forced = label, None, None
        if combo_values is not None:            # an editable dropdown (e.g. "in VLAN")
            self.entry = ttk.Combobox(self, textvariable=var, width=width, values=combo_values)
        else:
            self.entry = ttk.Entry(self, textvariable=var, width=width)
        self.entry.pack(anchor='w')
        if typing:
            ok = self.register(lambda proposed, kind=typing: validators.typing_ok(kind, proposed))
            self.entry.configure(validate='key', validatecommand=(ok, '%P'))
        self.message = ttk.Label(self, text='', foreground=theme.DANGER, font=theme.FONT_SMALL,
                                 wraplength=MESSAGE_WRAP, justify='left')
        var.trace_add('write', lambda *a: self.recheck())

    # ---- state
    def value(self):
        return validators.clean(self.var.get())

    def problem(self):
        """The field's own problem (None: fine). An empty required field is 'Required.'"""
        text = self.value()
        if not text:
            return 'Required.' if self.required else None
        return self.check(text) if self.check else validators.check_characters(text)

    def ready(self):
        return self.problem() is None

    def recheck(self):
        """Show the field's state now: red border and message, an amber warning, or clean.
        A required field that is still empty is not shown in red."""
        self._forced = None
        text = self.value()
        problem = self.problem() if text else None
        note = None if problem or not self.warn or not text else self.warn(text)
        self._show(problem, note)
        if self.on_change:
            self.on_change()
        return problem

    def show_error(self, message):
        """A problem found when the whole form is checked (Add, Preview)."""
        self._forced = message
        self._show(message, None)

    def _show(self, problem, note):
        combo = isinstance(self.entry, ttk.Combobox)
        normal, invalid = ('TCombobox', INVALID_COMBO) if combo else ('TEntry', INVALID_STYLE)
        try:
            self.entry.configure(style=invalid if problem else normal)
        except tk.TclError:
            pass
        text = problem or note or ''
        self.message.configure(text=text, foreground=theme.DANGER if problem else theme.WARNING)
        if text:
            self.message.pack(anchor='w')
        else:
            self.message.pack_forget()

    @property
    def shown_message(self):
        return self.message.cget('text')

