"""A small "add to a list" form: a few inputs, an Add button, a table of what was
added, and Remove selected. The Configure page uses one per feature (trunks,
port security, router interfaces, static routes...).

fields:   [{'key', 'label', 'kind': 'entry' | 'combo' | 'check', 'width',
            'values' (combo), 'default', 'hint',
            'check' (text -> message or None), 'typing' (validators.TYPING kind),
            'required' (bool), 'warn' (text -> note or None)}]
columns:  [(key, title, width)]   what the table shows for each added item
validate: validate(values, items) -> (error or None, item dict). The error is a message,
          or (field key, message) to show it under that field.

Entry fields check themselves while typing (gui/components/field_check.CheckedEntry): a
red border and message when invalid. Add stays disabled until every required field is
filled in and every field is valid; Add still runs the full check (several fields
together) and shows any problem under its field.
"""
import tkinter as tk
from tkinter import messagebox, ttk

from gui import theme
from gui.components.field_check import CheckedEntry
from gui.components.tables import setup_table


class ListEditor(ttk.Frame):
    def __init__(self, parent, title, fields, columns, validate, note='', height=4):
        super().__init__(parent)
        self.title, self.fields, self.columns, self.validate = title, fields, columns, validate
        self.items = []
        self.vars = {}
        self.entries = {}                                # key -> CheckedEntry
        if note:
            label = ttk.Label(self, text=note, foreground=theme.TEXT_MUTED, justify='left')
            label.pack(anchor='w', fill='x', pady=(0, 8))
            wrap_to_width(label)
        form = ttk.Frame(self)
        form.pack(fill='x')
        for i, f in enumerate(fields):
            row, col = divmod(i, 2)
            cell = ttk.Frame(form)
            cell.grid(row=row, column=col, sticky='nw', padx=(0, 14), pady=3)
            kind = f.get('kind', 'entry')
            if kind == 'check':
                var = tk.IntVar(value=int(f.get('default', 0)))
                ttk.Checkbutton(cell, text=f['label'], variable=var).pack(anchor='w', pady=(14, 0))
            else:
                ttk.Label(cell, text=f['label']).pack(anchor='w')
                var = tk.StringVar(value=str(f.get('default', '')))
                if kind == 'combo':
                    ttk.Combobox(cell, textvariable=var, values=f['values'], state='readonly',
                                 width=f.get('width', 12)).pack(anchor='w')
                else:
                    entry = CheckedEntry(cell, var, check=f.get('check'), typing=f.get('typing'),
                                         width=f.get('width', 14),
                                         required=f.get('required', False),
                                         warn=f.get('warn'), label=f['label'])
                    entry.pack(anchor='w')
                    entry.on_change = self._update_add
                    self.entries[f['key']] = entry
            self.vars[f['key']] = var
        buttons = ttk.Frame(self)
        buttons.pack(fill='x', pady=(8, 0))
        self.add_btn = ttk.Button(buttons, text='Add', command=self.add)
        self.add_btn.pack(side='left')
        ttk.Button(buttons, text='Remove selected', command=self.remove).pack(side='right')
        self._update_add()
        self.tree = ttk.Treeview(self, columns=[c[0] for c in columns], show='headings',
                                 height=height)
        setup_table(self.tree, columns)
        self.tree.pack(fill='x', pady=(8, 4))

    def values(self):
        return {k: (v.get().strip() if isinstance(v, tk.StringVar) else bool(v.get()))
                for k, v in self.vars.items()}

    def ready(self):
        """True when every required field is filled in and every field is valid."""
        return all(e.ready() for e in self.entries.values())

    def _update_add(self):
        if hasattr(self, 'add_btn'):
            self.add_btn.state(['!disabled'] if self.ready() else ['disabled'])

    def pending_problems(self):
        """[(field label, message)] for values typed here that are not valid (Preview and
        Apply are blocked while they are). Untouched empty fields are not a problem."""
        out = []
        for e in self.entries.values():
            if e.value():
                problem = e.problem()
                if problem:
                    out.append((e.label, problem))
        return out

    def add(self):
        problem, item = self.validate(self.values(), self.items)
        if problem:
            field, message = problem if isinstance(problem, tuple) else (None, problem)
            if field in self.entries:
                self.entries[field].show_error(message)
            messagebox.showerror(f'Cannot add ({self.title})', message)
            return None
        self.items.append(item)
        for f in self.fields:                            # clear typed values, keep choices
            if f.get('kind', 'entry') == 'entry':
                self.vars[f['key']].set(str(f.get('default', '')))
        self.show()
        return item

    def remove(self):
        for iid in sorted(self.tree.selection(), key=lambda i: -self.tree.index(i)):
            del self.items[self.tree.index(iid)]
        self.show()

    def show(self):
        self.tree.delete(*self.tree.get_children())
        for item in self.items:
            self.tree.insert('', 'end', values=[_shown(item.get(k)) for k, _, _ in self.columns])


def wrap_to_width(label, margin=8):
    """Let a label's text wrap at whatever width the label gets (no clipping, and
    no fixed width that leaves the text narrow in a wide panel)."""
    def fit(event):
        width = max(event.width - margin, 120)
        if abs(int(str(label.cget('wraplength') or 0)) - width) > 4:
            label.configure(wraplength=width)
    label.bind('<Configure>', fit, add='+')
    return label


def _shown(value):
    if value is True:
        return 'yes'
    if value in (None, False, ''):
        return '-'
    return value
