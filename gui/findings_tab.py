import queue
import threading
import tkinter as tk
from tkinter import ttk, messagebox

from gui import theme
from review.rules import review_network

EMPTY_MESSAGE = ('No registered devices yet, so there is nothing to review. '
                 'Run a scan and approve devices first.')


class FindingsTab(ttk.Frame):
    def __init__(self, parent, store, collect, send_to_configure):
        """collect() -> (devices, links, configs, notes, source), may be slow."""
        super().__init__(parent, padding=theme.PAD)
        self.store, self.collect, self.send = store, collect, send_to_configure
        self.results = queue.Queue()
        self.findings, self.busy = [], False

        top = ttk.Frame(self); top.pack(fill='x')
        ttk.Label(top, text='Config review', style='Title.TLabel').pack(side='left')
        self.run_btn = ttk.Button(top, text='Run review', style='Accent.TButton',
                                  command=self.run)
        self.run_btn.pack(side='right')
        self.score = ttk.Label(self, text='Health score: -', font=theme.FONT_BOLD)
        self.score.pack(anchor='w', pady=(theme.PAD, 0))
        self.note = ttk.Label(self, text='Click Run review.', foreground='#555')
        self.note.pack(anchor='w')

        cols = [('device', 'Device', 90), ('severity', 'Severity', 80),
                ('rule', 'Rule', 170), ('message', 'Message', 520)]
        self.tree = ttk.Treeview(self, columns=[c[0] for c in cols], show='headings',
                                 selectmode='browse')
        for key, title, width in cols:
            self.tree.heading(key, text=title)
            self.tree.column(key, width=width, anchor='w')
        for sev, color in theme.SEVERITY_COLORS.items():
            self.tree.tag_configure(sev, background=color)
        self.tree.pack(fill='both', expand=True, pady=theme.PAD)
        self.tree.bind('<<TreeviewSelect>>', lambda e: self.show_fix())
        self.fix = ttk.Label(self, text='', foreground='#333', justify='left')
        self.fix.pack(anchor='w')
        bar = ttk.Frame(self); bar.pack(fill='x', pady=(theme.PAD, 0))
        ttk.Button(bar, text='Send to Configure', command=self.send_selected).pack(side='right')

    def run(self):
        if self.busy:
            return
        self.busy = True
        self.run_btn.state(['disabled'])
        self.note.config(text='Reading configurations and reviewing...')
        threading.Thread(target=self._worker, daemon=True).start()
        self.after(200, self.check_queue)

    def _worker(self):
        try:
            devices, links, configs, notes, source = self.collect()
            if not devices:                    # nothing registered: nothing to review
                self.results.put(('empty', source))
                return
            findings, score = review_network(devices, links, configs)
            self.results.put(('done', findings, score, notes, source))
        except Exception as err:
            self.results.put(('error', str(err)))

    def check_queue(self):
        try:
            msg = self.results.get_nowait()
        except queue.Empty:
            self.after(200, self.check_queue)
            return
        self.busy = False
        self.run_btn.state(['!disabled'])
        if msg[0] == 'error':
            self.note.config(text='Review failed.')
            messagebox.showerror('Review failed', msg[1])
            return
        if msg[0] == 'empty':
            self.show_empty(msg[1])
            return
        _, findings, score, notes, source = msg
        self.show(findings, score, notes, source)

    def show_empty(self, source=''):
        """Real database with no registered devices: say so. No score is shown and
        the stored findings are left exactly as they are (nothing is cleared)."""
        self.findings = []
        self.tree.delete(*self.tree.get_children())
        self.score.config(text='Health score: -   (no registered devices)')
        self.note.config(text=EMPTY_MESSAGE, style='TLabel', foreground='#555')
        self.fix.config(text='')

    def show(self, findings, score, notes=(), source=''):
        self.findings = list(findings)
        self.tree.delete(*self.tree.get_children())
        for i, f in enumerate(self.findings):
            self.tree.insert('', 'end', iid=str(i), tags=(f['severity'],),
                             values=(f['device'], f['severity'], f['rule'], f['message']))
        sample = source.startswith('SAMPLE')
        self.score.config(text=f'Health score: {score} / 100   ({len(self.findings)} findings)'
                               + ('   SAMPLE DATA' if sample else ''))
        text = source + ('. ' + '; '.join(notes) if notes else '')
        # the explicit colour matters: it overrides the style, so set it every time
        self.note.config(text=text, style='Sample.TLabel' if sample else 'TLabel',
                         foreground=theme.SAMPLE_COLOR if sample else '#555')
        self.fix.config(text='')
        try:                                   # keep the results in the database
            self.store.clear_findings()
            for f in self.findings:
                self.store.add_finding(f)
        except Exception:
            pass

    def selected(self):
        sel = self.tree.selection()
        return self.findings[int(sel[0])] if sel else None

    def show_fix(self):
        f = self.selected()
        if f:
            self.fix.config(text='Suggested fix:  ' + '  |  '.join(f['commands']))

    def send_selected(self):
        f = self.selected()
        if not f:
            messagebox.showinfo('Select a finding', 'Click a finding first.')
            return
        if f['rule'] == 'single_point_of_failure':
            messagebox.showinfo('Needs cabling',
                                'This one is fixed by adding a second uplink, not by '
                                'commands, so there is nothing to send.')
            return
        commands = list(f['commands'])
        if f['rule'] == 'trunk_all_vlans':
            commands.insert(0, '# EDIT the VLAN list below to match your network')
        self.send(commands, f['device'])
