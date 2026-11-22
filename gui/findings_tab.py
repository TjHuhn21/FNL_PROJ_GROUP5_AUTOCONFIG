"""Findings page: the configuration review.

Two kinds of results, always labelled so they cannot be confused:
  * a STORED review: the snapshot kept in the database (store.get_findings_snapshot),
    loaded when the page is opened and after the database is back;
  * a review COMPLETED JUST NOW: run with "Run review". Its findings replace the stored
    snapshot in one transaction (store.replace_findings): all of them, or, if saving
    fails, none, and the previous snapshot is kept. The page says which happened.

The review and every database call run in a worker thread. Workers never touch a
widget: they put their result on a queue.Queue that the page reads with after().
"""
import queue
import threading
import tkinter as tk
from tkinter import ttk, messagebox

from gui import theme
from gui.db_status import database_ready, report_error
from review.rules import POINTS, review_network
from store_errors import outcome_text

EMPTY_MESSAGE = ('No registered devices yet, so there is nothing to review. '
                 'Run a scan and approve devices first.')
NO_STORED_MESSAGE = ('No stored findings. Either no review has been saved yet, or the last '
                     'saved review found no problems. Click Run review to check now.')
POLL_MS = 200


# ---------------------------------------------------------------- workers (no widgets here)
def _review_worker(collect, store, results):
    """Run the review, then store it (not sample data). Puts exactly one message."""
    try:
        devices, links, configs, notes, source = collect()
        if not devices:                    # nothing registered: nothing reviewed or stored
            results.put(('empty', source))
            return
        findings, score = review_network(devices, links, configs)
    except Exception as err:               # the error itself goes to the main thread
        results.put(('error', err))
        return
    saved, save_error = None, None
    if not source.startswith('SAMPLE'):    # sample data is never stored as a review
        try:
            saved = store.replace_findings(findings)   # empty list: clears the snapshot
        except Exception as err:
            save_error = err
    results.put(('done', findings, score, notes, source, saved, save_error))


def _snapshot_worker(store, results):
    try:
        results.put(('snapshot', store.get_findings_snapshot()))
    except Exception as err:
        results.put(('snapshot_error', err))


class FindingsTab(ttk.Frame):
    def __init__(self, parent, store, collect, send_to_configure):
        """collect() -> (devices, links, configs, notes, source), may be slow."""
        super().__init__(parent, padding=theme.PAD)
        self.store, self.collect, self.send = store, collect, send_to_configure
        self.results = queue.Queue()
        self.findings, self.busy = [], False
        # What the page shows: None (nothing yet), 'stored', 'fresh' (saved), 'unsaved'
        # (completed but not stored), 'sample', 'empty' or 'error'.
        self.view, self.view_label = None, ''

        top = ttk.Frame(self); top.pack(fill='x')
        ttk.Label(top, text='Config review', style='Title.TLabel').pack(side='left')
        self.run_btn = ttk.Button(top, text='Run review', style='Accent.TButton',
                                  command=self.run)
        self.run_btn.pack(side='right')
        self.stored_btn = ttk.Button(top, text='Show stored review',
                                     command=self.load_stored)
        self.stored_btn.pack(side='right', padx=4)
        self.score = ttk.Label(self, text='Health score: -', font=theme.FONT_BOLD)
        self.score.pack(anchor='w', pady=(theme.PAD, 0))
        self.note = ttk.Label(self, text='Click Run review.', foreground=theme.TEXT_SOFT,
                              wraplength=900, justify='left')
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
        self.fix = ttk.Label(self, text='', foreground=theme.TEXT, justify='left')
        self.fix.pack(anchor='w')
        bar = ttk.Frame(self); bar.pack(fill='x', pady=(theme.PAD, 0))
        self.send_btn = ttk.Button(bar, text='Send to Configure', command=self.send_selected)
        self.send_btn.pack(side='right')
        self.read_only = False

    def set_read_only(self, read_only):
        """Viewers: the stored review can be shown, but a new review (which replaces the
        stored one) cannot be run and nothing can be sent to Configure."""
        self.read_only = bool(read_only)
        for button in (self.run_btn, self.send_btn):
            button.state(['disabled'] if self.read_only else ['!disabled'])

    # ---------------------------------------------------------------- starting work
    def _start(self, text, target, *args):
        self.busy = True
        self.run_btn.state(['disabled'])
        self.stored_btn.state(['disabled'])
        self.note.config(text=text, style='TLabel', foreground=theme.TEXT_SOFT)
        # The thread gets only plain values and the queue, never self or a widget.
        threading.Thread(target=target, args=args + (self.results,), daemon=True).start()
        self.after(POLL_MS, self.check_queue)

    def run(self):
        if self.read_only or self.busy or not database_ready(self):
            return
        self._start('Reading configurations and reviewing...', _review_worker,
                    self.collect, self.store)

    def load_stored(self):
        """Load the stored review (in the background). False if busy."""
        if self.busy:
            return False
        self._start('Loading the stored review...', _snapshot_worker, self.store)
        return True

    def on_page_shown(self):
        """Opening the page shows the stored review, unless this session's own review
        (more detailed: it has the skipped-device notes) or one being run is shown."""
        if self.view in (None, 'stored', 'error', 'empty'):
            self.load_stored()

    def on_db_down(self, reason=''):
        """Keep what is shown (never cleared silently), but say it cannot be refreshed."""
        if self.findings:
            self.note.config(text=(self.view_label + ' ' if self.view_label else '')
                             + 'Database unavailable: these results could not be refreshed '
                               'and may be out of date.',
                             style='TLabel', foreground=theme.DANGER)

    def on_db_up(self):
        """The database is back: reload the stored review (as when the page is opened),
        and refresh the label of results that were kept on screen."""
        if self.view in (None, 'stored', 'error', 'empty'):
            self.load_stored()
        elif self.findings:
            self.note.config(text=self.view_label, style='TLabel', foreground=theme.TEXT_SOFT)

    # ---------------------------------------------------------------- results (main thread)
    def check_queue(self):
        try:
            msg = self.results.get_nowait()
        except queue.Empty:
            try:
                self.after(POLL_MS, self.check_queue)
            except tk.TclError:              # window closed
                pass
            return
        self.busy = False
        if not self.read_only:
            self.run_btn.state(['!disabled'])
        self.stored_btn.state(['!disabled'])
        kind = msg[0]
        if kind == 'error':
            self._review_failed(msg[1])
        elif kind == 'empty':
            self.show_empty(msg[1])
        elif kind == 'done':
            self.show(*msg[1:])
        elif kind == 'snapshot':
            self.show_stored(msg[1])
        elif kind == 'snapshot_error':
            self._snapshot_failed(msg[1])

    def _review_failed(self, err):
        kept = (' The results shown below are from before this attempt.' if self.findings
                else '')
        if report_error(self, err):            # database problem: shown in the window too
            text = 'Review failed: the database could not be read. Nothing was stored.'
        else:
            text = 'Review failed. Nothing was stored.'
        self.note.config(text=text + kept, style='TLabel', foreground=theme.DANGER)
        messagebox.showerror('Review failed', str(err))

    def _snapshot_failed(self, err):
        report_error(self, err)
        text = f'Could not load the stored review: {err}'
        if self.findings:                      # keep them, clearly not refreshed
            text += ' The results shown below were not refreshed and may be out of date.'
        else:
            self.view = 'error'
        self.note.config(text=text, style='TLabel', foreground=theme.DANGER)

    def _fill(self, findings):
        self.findings = list(findings)
        self.tree.delete(*self.tree.get_children())
        for i, f in enumerate(self.findings):
            device = f['device'] + (' (deleted)' if f.get('device_deleted') else '')
            self.tree.insert('', 'end', iid=str(i), tags=(f['severity'],),
                             values=(device, f['severity'], f['rule'], f['message']))
        self.fix.config(text='')

    def show_empty(self, source=''):
        """Real database with no registered devices: say so. No score is shown and
        the stored findings are left exactly as they are (nothing is cleared)."""
        self._fill([])
        self.view, self.view_label = 'empty', ''
        self.score.config(text='Health score: -   (no registered devices)')
        self.note.config(text=EMPTY_MESSAGE, style='TLabel', foreground=theme.TEXT_SOFT)

    def show(self, findings, score, notes=(), source='', saved=None, save_error=None):
        """A review completed just now. saved: store.replace_findings' result, or None
        when it was not stored (sample data, or save_error)."""
        if saved is not None and getattr(self, 'on_saved', None):
            self.on_saved()                        # e.g. the Overview's findings counts
        self._fill(findings)
        sample = source.startswith('SAMPLE')
        self.score.config(text=f'Health score: {score} / 100   ({len(self.findings)} findings)'
                               + ('   SAMPLE DATA' if sample else ''))
        text = source + ('. ' + '; '.join(notes) if notes else '')
        if sample:
            self.view, status = 'sample', ''
        elif save_error is not None:
            report_error(self, save_error)
            self.view = 'unsaved'
            if getattr(save_error, 'uncertain', False):   # lost while committing: unknown
                status = f'Review completed just now. {outcome_text(save_error)} {save_error}'
            else:
                status = (f'Review completed just now but NOT stored: the previously stored '
                          f'review was kept unchanged. {save_error}')
        else:
            self.view = 'fresh'
            n = saved['saved'] if saved else len(self.findings)
            status = f"Review completed just now and stored ({n} finding{'' if n == 1 else 's'})."
            if saved and saved['skipped']:
                status += (' Not stored (not registered devices): '
                           + ', '.join(saved['skipped']) + '.')
        full = text + ('. ' if text and status else '') + status
        self.view_label = full
        # the explicit colour matters: it overrides the style, so set it every time
        if sample:
            self.note.config(text=full, style='Sample.TLabel', foreground=theme.SAMPLE_COLOR)
        else:
            self.note.config(text=full, style='TLabel',
                             foreground=theme.DANGER if save_error is not None else theme.TEXT_SOFT)

    def show_stored(self, snapshot):
        """The stored review (snapshot from the database)."""
        found = snapshot['findings']
        self._fill(found)
        if not found:
            self.view, self.view_label = 'stored', ''
            self.score.config(text='Health score: -   (no stored findings)')
            self.note.config(text=NO_STORED_MESSAGE, style='TLabel', foreground=theme.TEXT_SOFT)
            return
        score = max(0, 100 - sum(POINTS[f['severity']] for f in found))
        when = snapshot['saved_at'].strftime('%Y-%m-%d %H:%M') if snapshot['saved_at'] else '?'
        gone = sorted({f['device'] for f in found if f.get('device_deleted')})
        self.score.config(text=f'Health score: {score} / 100   ({len(found)} findings)   '
                               f'STORED REVIEW')
        text = (f'Stored review from {when}, loaded from the database (not a new check). '
                f'The health score is recalculated from the stored findings; devices that '
                f'review skipped are not recorded.')
        if gone:
            text += ' Devices deleted since: ' + ', '.join(gone) + '.'
        self.view, self.view_label = 'stored', text
        self.note.config(text=text, style='TLabel', foreground=theme.TEXT_SOFT)

    # ---------------------------------------------------------------- selection
    def selected(self):
        sel = self.tree.selection()
        return self.findings[int(sel[0])] if sel else None

    def show_fix(self):
        f = self.selected()
        if f:
            self.fix.config(text='Suggested fix:  ' + '  |  '.join(f['commands']))

    def send_selected(self):
        if self.read_only:
            return
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
