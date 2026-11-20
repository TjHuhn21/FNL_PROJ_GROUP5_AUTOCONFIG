"""Overview: the workbench's home page - a summary of the stored data.

    +--------------------------------------------------------------------------+
    | Overview                                      Updated 14:02:31  [Refresh] |
    | [Devices 5]  [Status 4 online / 1 offline]  [Findings 7]  [Config 12]     |
    | Recent scan activity | Recent configuration activity | Recent status chg. |
    | Quick actions: Scan  Devices  Topology  Findings  Configure  Logs         |
    +--------------------------------------------------------------------------+

Everything comes from the existing store (database or sample store) through its normal
read functions; nothing is estimated or invented:
  * devices, types, last known status  - store.get_devices (status is what the background
    monitor last recorded; a device never checked keeps the status it was saved with)
  * findings by severity               - store.get_findings_snapshot (the stored review)
  * configuration results and history  - store.count_logs / store.get_logs
  * status changes                     - store.get_events (recorded by the monitor)
  * scans                              - a scan that is not approved is not stored, so the
    Scan page's in-memory history of THIS session is shown, next to the devices most
    recently registered in the store.

Loading is cheap (a handful of queries) and is not repeated needlessly: the page reloads
when it is opened and its data is older than FRESH_SECONDS or was marked stale by another
page (scan, approval, edit, Apply), when Refresh is clicked, and every AUTO_SECONDS while
it is on screen. A database error shows a banner and no figures (never old figures as if
they were current).
"""
import time
import tkinter as tk
from collections import Counter
from datetime import date, datetime
from tkinter import ttk

from gui import theme
from gui.db_status import report_error
from store_errors import DATABASE_ERRORS

FRESH_SECONDS = 15
AUTO_SECONDS = 60
RECENT = 6
SESSION_ROWS = 3
QUICK_ACTIONS = [('scan', 'Scan network'), ('devices', 'Devices'), ('topology', 'Open Topology'),
                 ('findings', 'Findings'), ('configure', 'Configure'), ('logs', 'Logs')]
NONE_YET = {
    'scan': 'No scans yet. Scans run on the Scan page; approved devices are listed here.',
    'config': 'No configuration changes recorded yet.',
    'status': 'No status changes recorded yet. The background monitor records a change '
              'when a device goes down or comes back up.',
}


# ---------------------------------------------------------------- data (no window code)
def _all_devices(store):
    rows, page = [], 1
    while True:
        batch = store.get_devices('', 'name', page, 500)
        rows += batch
        if len(batch) < 500:
            return rows
        page += 1


def summarize(store, scan_history=()):
    """Everything the page shows, read from the store. Raises the store's errors."""
    devices = _all_devices(store)
    types = Counter((d.get('type') or 'unknown') for d in devices)
    status = Counter(d.get('status') for d in devices)
    snapshot = store.get_findings_snapshot()
    findings = [f for f in snapshot['findings'] if not f.get('device_deleted')]
    severity = Counter(f['severity'] for f in findings)
    # This session's scans get up to SESSION_ROWS rows, so a scan that registered several
    # devices is not pushed off the list by those registrations; the rest are the newest
    # registrations from the store.
    session = sorted(scan_history, key=lambda h: _sortable(h['when']), reverse=True)[:SESSION_ROWS]
    registered = sorted((d for d in devices if d.get('created_at')),
                        key=lambda d: _sortable(d['created_at']),
                        reverse=True)[:RECENT - len(session)]
    activity = [{'when': d['created_at'], 'what': 'Device registered',
                 'detail': f"{d['name']} ({d['ip']}, {d.get('type') or 'unknown'})"}
                for d in registered]
    for h in session:
        if h['kind'] == 'approval':
            n = h['count']
            activity.append({'when': h['when'], 'what': 'Approval (this session)',
                             'detail': f"{n} device{'' if n == 1 else 's'} saved"})
        elif h.get('failed'):
            activity.append({'when': h['when'], 'what': 'Scan (this session)',
                             'detail': f"seed {h['seed'] or '-'}: failed (see the Scan page)"})
        else:
            detail = (f"seed {h['seed'] or '-'}: {h['devices']} devices "
                      f"({h['managed']} managed), {h['links']} links")
            if h.get('sample'):
                detail += ' (sample data)'
            activity.append({'when': h['when'], 'what': 'Scan (this session)', 'detail': detail})
    activity.sort(key=lambda a: _sortable(a['when']), reverse=True)
    return {
        'devices': len(devices),
        'routers': types.get('router', 0), 'switches': types.get('switch', 0),
        'unknown': len(devices) - types.get('router', 0) - types.get('switch', 0),
        'managed': sum(1 for d in devices if d.get('managed')),
        'online': status.get('up', 0), 'offline': status.get('down', 0),
        'findings': len(findings), 'high': severity.get('high', 0),
        'medium': severity.get('medium', 0), 'low': severity.get('low', 0),
        'review_saved_at': snapshot.get('saved_at'),
        'changes': store.count_logs(), 'changes_ok': store.count_logs(status='success'),
        'changes_failed': store.count_logs(status='failed'),
        'recent_changes': store.get_logs(page=1, per_page=RECENT),
        'recent_events': store.get_events(limit=RECENT),
        'recent_activity': activity[:RECENT],
    }


def _sortable(when):
    if isinstance(when, datetime):
        return when
    try:
        return datetime.fromisoformat(str(when))
    except ValueError:
        return datetime.min


def when_text(when, today=None):
    """'14:02' for today, 'Nov 19 14:02' for another day, '' when unknown."""
    if not when:
        return ''
    when = _sortable(when)
    if when == datetime.min:
        return ''
    if when.date() == (today or date.today()):
        return when.strftime('%H:%M')
    return when.strftime('%b %d %H:%M')


def _short(text, limit=70):
    text = ' '.join(str(text or '').split())
    return text if len(text) <= limit else text[:limit - 1] + '…'


# ---------------------------------------------------------------- the page
class OverviewPage(tk.Frame):
    def __init__(self, parent, open_page, store=None, can_open=None, scan_history=None,
                 source_note=''):
        """open_page(key) switches to another page; can_open(key) says whether the
        signed-in role may open it (quick actions are offered only for those);
        scan_history() returns the Scan page's session history."""
        super().__init__(parent, background=theme.SURFACE)
        self.open_page, self.store = open_page, store
        self.can_open = can_open or (lambda key: True)
        self.scan_history = scan_history or (lambda: [])
        self.data, self.loaded_at, self.stale, self.error = None, None, True, None
        self.db_down = False                     # a known outage: no automatic queries
        self._auto = None

        # ---- header
        head = tk.Frame(self, background=theme.SURFACE)
        head.pack(fill='x', padx=16, pady=(12, 4))
        titles = tk.Frame(head, background=theme.SURFACE)
        titles.pack(side='left')
        tk.Label(titles, text='Overview', font=theme.FONT_TITLE, background=theme.SURFACE,
                 foreground=theme.TEXT).pack(anchor='w')
        self.message = tk.Label(
            titles, text=('Summary of the stored network data. ' + source_note).strip(),
            font=theme.FONT_SMALL, background=theme.SURFACE, foreground=theme.TEXT_MUTED)
        self.message.pack(anchor='w')
        self.refresh_button = ttk.Button(head, text='Refresh', command=lambda: self.refresh(True, manual=True))
        self.refresh_button.pack(side='right')
        self.updated = tk.Label(head, text='', font=theme.mono(8), background=theme.SURFACE,
                                foreground=theme.TEXT_MUTED)
        self.updated.pack(side='right', padx=(0, 10))

        self.banner = tk.Label(self, text='', background=theme.DANGER_SOFT, foreground=theme.DANGER,
                               font=theme.FONT, anchor='w', justify='left', padx=12, pady=6,
                               wraplength=900)

        body = tk.Frame(self, background=theme.SURFACE)
        body.pack(fill='both', expand=True, padx=16, pady=(6, 12))
        self.body = body

        # ---- cards
        cards = tk.Frame(body, background=theme.SURFACE)
        cards.pack(fill='x')
        self.cards = {}
        for col, (key, title) in enumerate([('devices', 'DEVICES'), ('status', 'STATUS (LAST KNOWN)'),
                                            ('findings', 'FINDINGS'),
                                            ('changes', 'CONFIGURATION CHANGES')]):
            cards.grid_columnconfigure(col, weight=1, uniform='card')
            self.cards[key] = self._card(cards, title)
            self.cards[key]['frame'].grid(row=0, column=col, sticky='nsew',
                                          padx=(0 if col == 0 else 6, 0))

        # ---- recent lists
        lists = tk.Frame(body, background=theme.SURFACE)
        lists.pack(fill='both', expand=True, pady=(12, 0))
        self.lists = {}
        specs = [('scan', 'RECENT SCAN ACTIVITY', [('when', 'When', 90), ('what', 'Activity', 150),
                                                   ('detail', 'Details', 240)]),
                 ('config', 'RECENT CONFIGURATION ACTIVITY', [('when', 'When', 90),
                                                              ('device', 'Device', 110),
                                                              ('result', 'Result', 70),
                                                              ('detail', 'Details', 220)]),
                 ('status', 'RECENT STATUS CHANGES', [('when', 'When', 90), ('device', 'Device', 120),
                                                      ('change', 'Change', 110),
                                                      ('detail', 'Details', 160)])]
        for col, (key, title, columns) in enumerate(specs):
            lists.grid_columnconfigure(col, weight=1, uniform='list')
            self.lists[key] = self._list(lists, title, columns)
            self.lists[key]['frame'].grid(row=0, column=col, sticky='nsew',
                                          padx=(0 if col == 0 else 6, 0))
        lists.grid_rowconfigure(0, weight=1)
        tk.Label(body, text='Scans that were not approved are not stored, so scan activity shows '
                            'this session only; registered devices come from the database.',
                 font=theme.FONT_SMALL, background=theme.SURFACE, foreground=theme.TEXT_MUTED,
                 anchor='w').pack(fill='x', pady=(6, 0))

        # ---- quick actions (only pages this role may open)
        actions = tk.Frame(body, background=theme.SURFACE)
        actions.pack(fill='x', pady=(10, 0))
        tk.Label(actions, text='QUICK ACTIONS', font=theme.mono(8, 'bold'),
                 background=theme.SURFACE, foreground=theme.TEXT_MUTED).pack(side='left',
                                                                             padx=(0, 10))
        self.actions = {}
        for key, label in QUICK_ACTIONS:
            if not self.can_open(key):
                continue
            b = ttk.Button(actions, text=label, command=lambda k=key: self.open_page(k),
                           style='Accent.TButton' if key == 'scan' else 'TButton')
            b.pack(side='left', padx=(0, 6))
            self.actions[key] = b
        self.open_topology = self.actions.get('topology')     # kept for existing callers

    # ------------------------------------------------------------ building blocks
    def _card(self, parent, title):
        frame = tk.Frame(parent, background=theme.SURFACE, highlightthickness=1,
                         highlightbackground=theme.BORDER, padx=14, pady=10)
        tk.Label(frame, text=title, font=theme.mono(8, 'bold'), background=theme.SURFACE,
                 foreground=theme.TEXT_MUTED, anchor='w').pack(fill='x')
        value = tk.Label(frame, text='—', font=(theme.FONT_FAMILY, 22, 'bold'),
                         background=theme.SURFACE, foreground=theme.TEXT, anchor='w')
        value.pack(fill='x')
        detail = tk.Label(frame, text='', font=theme.FONT, background=theme.SURFACE,
                          foreground=theme.TEXT_SOFT, anchor='w', justify='left')
        detail.pack(fill='x')
        note = tk.Label(frame, text='', font=theme.FONT_SMALL, background=theme.SURFACE,
                        foreground=theme.TEXT_MUTED, anchor='w', justify='left', wraplength=230)
        note.pack(fill='x', pady=(2, 0))
        return {'frame': frame, 'value': value, 'detail': detail, 'note': note}

    def _list(self, parent, title, columns):
        frame = tk.Frame(parent, background=theme.SURFACE, highlightthickness=1,
                         highlightbackground=theme.BORDER)
        tk.Label(frame, text=title, font=theme.mono(8, 'bold'), background=theme.SURFACE_2,
                 foreground=theme.TEXT_SOFT, anchor='w', padx=10, pady=5).pack(fill='x')
        tree = ttk.Treeview(frame, columns=[c[0] for c in columns], show='headings',
                            height=RECENT, selectmode='none')
        for key, heading, width in columns:
            tree.heading(key, text=heading)
            tree.column(key, width=width, minwidth=50, anchor='w', stretch=True)
        tree.tag_configure('failed', foreground=theme.DANGER)
        tree.tag_configure('down', foreground=theme.DANGER)
        tree.tag_configure('up', foreground=theme.SUCCESS)
        empty = tk.Label(frame, text='', font=theme.FONT, background=theme.SURFACE,
                         foreground=theme.TEXT_MUTED, wraplength=280, justify='left', anchor='nw',
                         padx=10, pady=10)
        return {'frame': frame, 'tree': tree, 'empty': empty}

    # ------------------------------------------------------------ loading
    def mark_stale(self):
        """Another page changed the data: reload now if the page is on screen,
        otherwise the next time it is opened."""
        self.stale = True
        if self.winfo_ismapped() and not self.db_down:
            self.refresh(force=True)

    def refresh(self, force=False, manual=False):
        """Reload from the store when forced, stale or older than FRESH_SECONDS. During a
        known database outage only the Refresh button (manual) tries."""
        if self.store is None or (self.db_down and not manual):
            return
        age = None if self.loaded_at is None else time.monotonic() - self.loaded_at
        if not force and not self.stale and age is not None and age < FRESH_SECONDS:
            return
        try:
            data = summarize(self.store, self.scan_history())
        except DATABASE_ERRORS as err:
            report_error(self, err)
            self.show_unavailable(str(err))
            return
        except Exception as err:                       # never crash the home page
            self.show_unavailable(f'The overview could not be loaded ({type(err).__name__}).')
            return
        self.data, self.error, self.stale = data, None, False
        self.loaded_at = time.monotonic()
        self.banner.pack_forget()
        self._show(data)
        self.updated.config(text=f"Updated {datetime.now().strftime('%H:%M:%S')}")
        self._schedule()

    def show_unavailable(self, reason=''):
        """No figures at all (never old ones shown as current) and a banner."""
        self.data, self.error, self.stale = None, reason or 'The database is not available.', True
        self.banner.config(text=f'Overview unavailable: {self.error} Click Refresh to try again.')
        if not self.banner.winfo_manager():
            self.banner.pack(fill='x', padx=16, before=self.body)
        for card in self.cards.values():
            card['value'].config(text='—')
            card['detail'].config(text='')
            card['note'].config(text='')
        for key in self.lists:
            self._fill(key, [], 'Not available while the database cannot be read.')
        self.updated.config(text='')

    def on_db_down(self, reason=''):
        self.db_down = True
        self.show_unavailable(reason)

    def on_db_up(self):
        self.db_down = False
        self.mark_stale()

    def _schedule(self):
        """Reload every AUTO_SECONDS while the page is on screen (cheap, see the notes)."""
        if self._auto is not None:
            try:
                self.after_cancel(self._auto)
            except tk.TclError:
                pass

        def tick():
            self._auto = None
            if self.winfo_exists() and self.winfo_ismapped():
                self.refresh(force=True)
        try:
            self._auto = self.after(AUTO_SECONDS * 1000, tick)
        except tk.TclError:
            self._auto = None

    # ------------------------------------------------------------ drawing
    def _show(self, d):
        c = self.cards
        if d['devices'] == 0:
            c['devices']['value'].config(text='0')
            c['devices']['detail'].config(text='No devices registered yet.')
            c['devices']['note'].config(text='Scan the network or add a device.')
        else:
            c['devices']['value'].config(text=str(d['devices']))
            c['devices']['detail'].config(
                text=f"{d['routers']} routers  ·  {d['switches']} switches"
                     + (f"  ·  {d['unknown']} unknown" if d['unknown'] else ''))
            c['devices']['note'].config(text=f"{d['managed']} managed (NetCommand can log in)")

        if d['devices'] == 0:
            c['status']['value'].config(text='—', foreground=theme.TEXT)
            c['status']['detail'].config(text='No devices to monitor.')
            c['status']['note'].config(text='')
        else:
            c['status']['value'].config(text=f"{d['online']} up",
                                        foreground=theme.SUCCESS if not d['offline'] else theme.TEXT)
            c['status']['detail'].config(text=f"●  {d['online']} online    ■  {d['offline']} offline")
            c['status']['note'].config(text='As last recorded by the background monitor.')

        if d['findings'] == 0:
            c['findings']['value'].config(text='0')
            c['findings']['detail'].config(
                text='No review saved yet.' if not d['review_saved_at'] else
                'The last review found nothing.')
            c['findings']['note'].config(text='Run a review on the Findings page.'
                                         if not d['review_saved_at'] else '')
        else:
            c['findings']['value'].config(text=str(d['findings']))
            c['findings']['detail'].config(
                text=f"{d['high']} high  ·  {d['medium']} medium  ·  {d['low']} low")
            c['findings']['note'].config(text=f"Last review: {when_text(d['review_saved_at'])}")
        c['findings']['value'].config(foreground=theme.DANGER if d['high'] else theme.TEXT)

        c['changes']['value'].config(text=str(d['changes']))
        if d['changes'] == 0:
            c['changes']['detail'].config(text='No configuration applied yet.')
        else:
            c['changes']['detail'].config(
                text=f"{d['changes_ok']} successful  ·  {d['changes_failed']} failed")
        c['changes']['note'].config(text='Every Apply is logged (Logs page).')

        self._fill('scan', [((when_text(a['when']), a['what'], _short(a['detail'])), ())
                            for a in d['recent_activity']], NONE_YET['scan'])
        self._fill('config', [((when_text(l['created_at']), l['device'] or '?', l['status'],
                                _short(l.get('details'))),
                               ('failed',) if l['status'] == 'failed' else ())
                              for l in d['recent_changes']], NONE_YET['config'])
        self._fill('status', [((when_text(e['created_at']), e['device'] or '?',
                                f"{e.get('previous') or '?'} → {e['kind']}",
                                _short(e.get('detail'), 40)),
                               (e['kind'],) if e['kind'] in ('up', 'down') else ())
                              for e in d['recent_events']], NONE_YET['status'])

    def _fill(self, key, rows, empty_text):
        part = self.lists[key]
        tree, empty = part['tree'], part['empty']
        tree.delete(*tree.get_children())
        for values, tags in rows:
            tree.insert('', 'end', values=values, tags=tags)
        if rows:
            empty.pack_forget()
            if not tree.winfo_manager():
                tree.pack(fill='both', expand=True)
        else:
            tree.pack_forget()
            empty.config(text=empty_text)
            if not empty.winfo_manager():
                empty.pack(fill='both', expand=True)
