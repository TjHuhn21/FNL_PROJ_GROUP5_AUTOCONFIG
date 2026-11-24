"""Overview: the workbench's home page - a summary of the stored data.

    +--------------------------------------------------------------------------+
    | Overview                                    Updated 2:02:31 PM  [Refresh] |
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
import tkinter.font as tkfont
from collections import Counter
from datetime import date, datetime
from tkinter import ttk

from gui import theme
from gui.components.scroll_frame import ScrollFrame, auto_scrollbar, bind_wheel
from gui.db_status import report_error
from gui.event_log import log_event
from gui.timefmt import format_datetime, format_time, now_text
from store_errors import DATABASE_ERRORS
from gui.components.tables import DATE_SAMPLE_SHORT, setup_table

RECENT_HOURS = 24    # the configuration card and list show only this many past hours
# the page's layout by its width (logical pixels): 4 cards per row from CARDS_4_FROM, 2 from
# CARDS_2_FROM, else 1; the 3 recent lists side by side from LISTS_SIDE_BY_SIDE_FROM
CARDS_4_FROM, CARDS_2_FROM, LISTS_SIDE_BY_SIDE_FROM = 900, 520, 860
RESIZE_SETTLE_MS = 250          # cards and big numbers change once the window edge stops
BIG_NUMBER_POINTS = 22                            # the cards' big numbers at ~1200 px wide
BIG_NUMBER_RANGE = (16, 34)                       # never smaller / larger (points, scaled)


def big_number_size(page_width):
    """The big numbers' size for a page this wide: they grow and shrink with the window,
    within BIG_NUMBER_RANGE (both scaled by gui/ui_scale.py like every other font)."""
    from gui import ui_scale
    low, high = (ui_scale.font_size(n) for n in BIG_NUMBER_RANGE)
    wanted = ui_scale.font_size(BIG_NUMBER_POINTS) * max(page_width, 1) / (
        1200 * ui_scale.dpi_scale())
    return int(max(low, min(high, round(wanted))))
UP_ARROW, DOWN_ARROW = '▲', '▼'
FRESH_SECONDS = 15
AUTO_SECONDS = 60
RECENT = 6           # rows each list shows at least (its height); more scroll
LIST_ROWS = 25       # rows each list loads (scroll with the mouse wheel or its scroll bar)
SESSION_ROWS = 10    # of those, at most this many are this session's scans and approvals
QUICK_ACTIONS = [('scan', 'Scan network'), ('devices', 'Devices'), ('topology', 'Open Topology'),
                 ('findings', 'Findings'), ('configure', 'Configure'), ('logs', 'Logs')]
NONE_YET = {
    'scan': 'No scans yet. Scans run on the Scan page; approved devices are listed here.',
    'config': 'No configuration changes in the last 24 hours.',
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


TYPE_LABELS = {'router': 'Routers', 'switch': 'Switches', 'unknown': 'Unknown'}
TYPE_ORDER = ['router', 'switch']          # then any other type by name, 'unknown' last


def type_label(kind):
    return TYPE_LABELS.get(kind, kind.capitalize() + 's')


def status_by_type(devices):
    """[(label, up, down)] for the device types that exist, in TYPE_ORDER."""
    counts = {}
    for d in devices:
        up_down = counts.setdefault(d.get('type') or 'unknown', [0, 0])
        if d.get('status') == 'up':
            up_down[0] += 1
        elif d.get('status') == 'down':
            up_down[1] += 1
    order = TYPE_ORDER + sorted(k for k in counts if k not in TYPE_ORDER + ['unknown']) + ['unknown']
    return [(type_label(k), *counts[k]) for k in order if k in counts]


def latest_review(store, last_review=None):
    """(findings, when) of the most recent review. The stored snapshot, unless this
    session's own review (last_review, from the Findings page) is at least as new and
    left nothing stored: a review that found nothing, or found only devices that are not
    registered (sample data). when is None when no review is known."""
    snapshot = store.get_findings_snapshot()
    findings = [f for f in snapshot['findings'] if not f.get('device_deleted')]
    when = snapshot.get('saved_at')
    if last_review and last_review.get('at') and not findings and \
            (when is None or _sortable(last_review['at']) >= _sortable(when)):
        return list(last_review['findings']), last_review['at']
    return findings, when


def summarize(store, scan_history=(), last_review=None):
    """Everything the page shows, read from the store. Raises the store's errors."""
    devices = _all_devices(store)
    types = Counter((d.get('type') or 'unknown') for d in devices)
    status = Counter(d.get('status') for d in devices)
    findings, review_at = latest_review(store, last_review)
    severity = Counter(f['severity'] for f in findings)
    # This session's scans get up to SESSION_ROWS rows, so a scan that registered several
    # devices is not pushed off the list by those registrations; the rest are the newest
    # registrations from the store.
    session = sorted(scan_history, key=lambda h: _sortable(h['when']), reverse=True)[:SESSION_ROWS]
    registered = sorted((d for d in devices if d.get('created_at')),
                        key=lambda d: _sortable(d['created_at']),
                        reverse=True)[:LIST_ROWS - len(session)]
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
        'by_type': status_by_type(devices),
        'findings': len(findings), 'high': severity.get('high', 0),
        'medium': severity.get('medium', 0), 'low': severity.get('low', 0),
        'review_saved_at': review_at,
        # the last RECENT_HOURS only; older entries stay stored (Logs page)
        'changes': store.count_logs(within_hours=RECENT_HOURS),
        'changes_ok': store.count_logs(status='success', within_hours=RECENT_HOURS),
        'changes_failed': store.count_logs(status='failed', within_hours=RECENT_HOURS),
        'recent_changes': store.get_logs(page=1, per_page=LIST_ROWS, within_hours=RECENT_HOURS),
        'recent_events': store.get_events(limit=LIST_ROWS),
        'recent_activity': activity[:LIST_ROWS],
    }


def _sortable(when):
    if isinstance(when, datetime):
        return when
    try:
        return datetime.fromisoformat(str(when))
    except ValueError:
        return datetime.min


def when_text(when, today=None):
    """'2:02 PM' for today, 'Nov 19, 2026 2:02 PM' for another day, '' when unknown."""
    if not when:
        return ''
    when = _sortable(when)
    if when == datetime.min:
        return ''
    if when.date() == (today or date.today()):
        return format_time(when)
    return format_datetime(when)


def _short(text, limit=70):
    text = ' '.join(str(text or '').split())
    return text if len(text) <= limit else text[:limit - 1] + '…'


# ---------------------------------------------------------------- the page
class Tooltip:
    """A small hover text for one or more widgets (Tk has no built-in tooltip).
    Change .text at any time; an empty text shows nothing."""
    def __init__(self, widgets, text=''):
        self.text, self.tip = text, None
        for w in widgets:
            w.bind('<Enter>', lambda e, w=w: self.show(w), add='+')
            w.bind('<Leave>', lambda e: self.hide(), add='+')

    def show(self, widget):
        self.hide()
        if not self.text:
            return
        self.tip = tk.Toplevel(widget)
        self.tip.wm_overrideredirect(True)
        self.tip.wm_geometry(f'+{widget.winfo_rootx() + 10}+{widget.winfo_rooty() + widget.winfo_height() + 4}')
        tk.Label(self.tip, text=self.text, font=theme.FONT_SMALL, background=theme.CARD,
                 foreground=theme.TEXT, relief='solid', borderwidth=1, padx=6,
                 pady=3).pack()

    def hide(self):
        if self.tip is not None:
            try:
                self.tip.destroy()
            except tk.TclError:
                pass
            self.tip = None


class OverviewPage(tk.Frame):
    def __init__(self, parent, open_page, store=None, can_open=None, scan_history=None,
                 source_note='', last_review=None):
        """open_page(key) switches to another page; can_open(key) says whether the
        signed-in role may open it (quick actions are offered only for those);
        scan_history() returns the Scan page's session history; last_review() the
        Findings page's newest review of this session (or None)."""
        super().__init__(parent, background=theme.SURFACE)
        self.open_page, self.store = open_page, store
        self.can_open = can_open or (lambda key: True)
        self.scan_history = scan_history or (lambda: [])
        self.last_review = last_review or (lambda: None)
        self.data, self.loaded_at, self.stale, self.error = None, None, True, None
        self.db_down = False                     # a known outage: no automatic queries
        self._auto = None
        # the cards' big numbers: ONE shared font that follows the page width (debounced)
        self.big_font = tkfont.Font(root=self, family=theme.FONT_FAMILY,
                                    size=big_number_size(1200), weight='bold')
        self._big_job = None
        self.bind('<Configure>', self._resized, add='+')

        # ---- header
        # the whole page scrolls when the window is shorter than it needs; when it fits,
        # it fills the height (the recent lists grow)
        self.scroll = ScrollFrame(self, background=theme.SURFACE, fill_height=True)
        self.scroll.pack(fill='both', expand=True)
        page = self.scroll.inner
        head = tk.Frame(page, background=theme.SURFACE)
        head.pack(fill='x', padx=16, pady=(12, 4))
        titles = tk.Frame(head, background=theme.SURFACE)
        titles.pack(side='left')
        tk.Label(titles, text='Overview', font=theme.FONT_TITLE, background=theme.SURFACE,
                 foreground=theme.TEXT).pack(anchor='w')
        self.message = tk.Label(
            titles, text=('Summary of the stored network data. ' + source_note).strip(),
            font=theme.FONT_SMALL, background=theme.SURFACE, foreground=theme.TEXT_MUTED)
        self.message.pack(anchor='w')
        self.refresh_button = ttk.Button(head, text='Refresh', command=self.refresh_clicked)
        self.refresh_button.pack(side='right')
        self.updated = tk.Label(head, text='', font=theme.mono(8), background=theme.SURFACE,
                                foreground=theme.TEXT_MUTED)
        self.updated.pack(side='right', padx=(0, 10))

        self.banner = tk.Label(page, text='', background=theme.DANGER_SOFT, foreground=theme.DANGER,
                               font=theme.FONT, anchor='w', justify='left', padx=12, pady=6,
                               wraplength=900)

        body = tk.Frame(page, background=theme.SURFACE)
        body.pack(fill='both', expand=True, padx=16, pady=(6, 12))
        self.body = body

        # ---- cards
        cards = tk.Frame(body, background=theme.SURFACE)
        cards.pack(fill='x')
        self.cards = {}
        for key, title in [('devices', 'DEVICES'), ('status', 'STATUS (LAST KNOWN)'),
                           ('findings', 'FINDINGS'), ('changes', 'CONFIGURATION CHANGES')]:
            self.cards[key] = self._card(cards, title)
        self._cards_frame, self._card_columns = cards, None
        self._place_cards(4)
        # the status card's big indicator: green '▲ 3' and red '▼ 2' side by side (one
        # label cannot have two colours), replacing the card's single value label
        status = self.cards['status']
        status['value'].destroy()
        big = tk.Frame(status['frame'], background=theme.CARD)
        big.pack(fill='x', before=status['detail'])
        status['value'] = tk.Label(big, text='—', font=self.big_font, background=theme.CARD,
                                   foreground=theme.TEXT_MUTED, anchor='w')
        status['value'].pack(side='left')
        status['down'] = tk.Label(big, text='', font=self.big_font, background=theme.CARD,
                                  foreground=theme.DANGER, anchor='w')
        status['tooltip'] = Tooltip([big, status['value'], status['down']])
        # the status card's per-type rows (Routers 1 up · 0 down), filled by _show
        status['types'] = tk.Frame(status['frame'], background=theme.CARD)
        status['types'].pack(fill='x', pady=(4, 0), before=status['note'])

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
        for key, title, columns in specs:
            self.lists[key] = self._list(lists, title, columns)
        self._lists_frame, self._list_columns = lists, None
        self._place_lists(3)
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

    # ------------------------------------------------------------ layout for the width
    def reflow(self, width):
        """Cards: 4 in a row on wide windows, 2 x 2 on smaller ones, 1 per row on very
        narrow ones. The recent lists: 3 side by side, or one under the other."""
        from gui import ui_scale
        logical = width / ui_scale.dpi_scale()
        cards = 4 if logical >= CARDS_4_FROM else 2 if logical >= CARDS_2_FROM else 1
        self._place_cards(cards)
        self._place_lists(3 if logical >= LISTS_SIDE_BY_SIDE_FROM else 1)

    def _place_cards(self, per_row):
        if per_row == self._card_columns:
            return
        self._card_columns = per_row
        frame = self._cards_frame
        for c in range(4):
            frame.grid_columnconfigure(c, weight=1 if c < per_row else 0,
                                       uniform='card' if c < per_row else '')
        for i, card in enumerate(self.cards.values()):
            row, col = divmod(i, per_row)
            card['frame'].grid(row=row, column=col, sticky='nsew',
                               padx=(0 if col == 0 else 6, 0), pady=(0 if row == 0 else 6, 0))

    def _place_lists(self, per_row):
        if per_row == self._list_columns:
            return
        self._list_columns = per_row
        frame = self._lists_frame
        for c in range(3):
            frame.grid_columnconfigure(c, weight=1 if c < per_row else 0,
                                       uniform='list' if c < per_row else '')
            frame.grid_rowconfigure(c, weight=1 if (per_row == 1 or c == 0) else 0)
        for i, item in enumerate(self.lists.values()):
            row, col = divmod(i, per_row)
            item['frame'].grid(row=row, column=col, sticky='nsew',
                               padx=(0 if col == 0 else 6, 0), pady=(0 if row == 0 else 6, 0))

    # ------------------------------------------------------------ building blocks
    def _card(self, parent, title):
        frame = tk.Frame(parent, background=theme.CARD, highlightthickness=1,
                         highlightbackground=theme.BORDER, padx=14, pady=10)
        tk.Label(frame, text=title, font=theme.mono(8, 'bold'), background=theme.CARD,
                 foreground=theme.TEXT_MUTED, anchor='w').pack(fill='x')
        value = tk.Label(frame, text='—', font=self.big_font,
                         background=theme.CARD, foreground=theme.TEXT, anchor='w')
        value.pack(fill='x')
        detail = tk.Label(frame, text='', font=theme.FONT, background=theme.CARD,
                          foreground=theme.TEXT_SOFT, anchor='w', justify='left')
        detail.pack(fill='x')
        note = tk.Label(frame, text='', font=theme.FONT_SMALL, background=theme.CARD,
                        foreground=theme.TEXT_MUTED, anchor='w', justify='left', wraplength=230)
        note.pack(fill='x', pady=(2, 0))
        return {'frame': frame, 'value': value, 'detail': detail, 'note': note}

    def _list(self, parent, title, columns):
        frame = tk.Frame(parent, background=theme.CARD, highlightthickness=1,
                         highlightbackground=theme.BORDER)
        tk.Label(frame, text=title, font=theme.mono(8, 'bold'), background=theme.SURFACE_2,
                 foreground=theme.ACCENT, anchor='w', padx=10, pady=5).pack(fill='x')
        # the table and its own scroll bar (shown only when the rows do not fit); the
        # mouse wheel scrolls only the list under the pointer (bind_wheel)
        holder = tk.Frame(frame, background=theme.CARD)
        holder.grid_columnconfigure(0, weight=1)
        holder.grid_rowconfigure(0, weight=1)
        tree = ttk.Treeview(holder, columns=[c[0] for c in columns], show='headings',
                            height=RECENT, selectmode='none')
        tree.grid(row=0, column=0, sticky='nsew')
        bar = auto_scrollbar(holder, tree)
        bind_wheel(tree)
        # 'When' is short here ('3:56 AM' today, 'Nov 19, 2026 9:05 AM' before): no seconds
        setup_table(tree, columns, min_widths={'when': DATE_SAMPLE_SHORT})
        tree.tag_configure('failed', foreground=theme.DANGER)
        tree.tag_configure('down', foreground=theme.DANGER)
        tree.tag_configure('up', foreground=theme.SUCCESS)
        empty = tk.Label(frame, text='', font=theme.FONT, background=theme.CARD,
                         foreground=theme.TEXT_MUTED, wraplength=280, justify='left', anchor='nw',
                         padx=10, pady=10)
        return {'frame': frame, 'tree': tree, 'empty': empty, 'holder': holder, 'bar': bar}

    # ------------------------------------------------------------ loading
    def mark_stale(self):
        """Another page changed the data: reload now if the page is on screen,
        otherwise the next time it is opened."""
        self.stale = True
        if self.winfo_ismapped() and not self.db_down:
            self.refresh(force=True)

    def _resized(self, event):
        """The page changed size: resize the big numbers once the dragging pauses."""
        if event.widget is not self:
            return
        if self._big_job is not None:
            try:
                self.after_cancel(self._big_job)
            except tk.TclError:
                pass
        width = event.width
        self._big_job = self.after(RESIZE_SETTLE_MS, lambda: self._fit_big_numbers(width))

    def _fit_big_numbers(self, width):
        self._big_job = None
        if width == getattr(self, '_fitted_width', None):
            return                             # only the height changed: nothing to do
        self._fitted_width = width
        self.reflow(width)
        size = big_number_size(width)
        if self.big_font.cget('size') != size:
            self.big_font.configure(size=size)

    def refresh_clicked(self):
        """The Refresh button: reload now (even during an outage), and say so."""
        log_event('overview', 'Refreshing the Overview...')
        self.refresh(True, manual=True)
        if self.data is not None:
            log_event('overview', 'Refresh of the Overview SUCCESSFUL.', 'ok')

    def refresh(self, force=False, manual=False):
        """Reload from the store when forced, stale or older than FRESH_SECONDS. During a
        known database outage only the Refresh button (manual) tries."""
        if self.store is None or (self.db_down and not manual):
            return
        age = None if self.loaded_at is None else time.monotonic() - self.loaded_at
        if not force and not self.stale and age is not None and age < FRESH_SECONDS:
            return
        try:
            data = summarize(self.store, self.scan_history(), self.last_review())
        except DATABASE_ERRORS as err:
            log_event('overview', f'Loading the Overview FAILED. {err}', 'error')
            report_error(self, err)
            self.show_unavailable(str(err))
            return
        except Exception as err:                       # never crash the home page
            log_event('overview', f'Loading the Overview FAILED ({type(err).__name__}: {err}).',
                      'error')
            self.show_unavailable(f'The overview could not be loaded ({type(err).__name__}).')
            return
        self.data, self.error, self.stale = data, None, False
        self.loaded_at = time.monotonic()
        self.banner.pack_forget()
        self._show(data)
        self.updated.config(text=f'Updated {now_text(seconds=True)}')
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
        self._status_indicator(None, None)
        self.cards['status']['tooltip'].text = ''
        self._fill_types([])
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
            self._status_indicator(None, None)
            c['status']['detail'].config(text='No devices detected')
            c['status']['note'].config(text='')
            self._fill_types([])
        else:
            self._status_indicator(d['online'], d['offline'])
            c['status']['detail'].config(text=f"●  {d['online']} online    ■  {d['offline']} offline")
            c['status']['note'].config(text='As last recorded by the background monitor.')
            self._fill_types(d['by_type'])

        if d['review_saved_at'] is None:
            c['findings']['value'].config(text='0')
            c['findings']['detail'].config(text='No review saved yet.')
            c['findings']['note'].config(text='Run a review on the Findings page.')
        elif d['findings'] == 0:
            c['findings']['value'].config(text='0')
            c['findings']['detail'].config(text='The last review found nothing.')
            c['findings']['note'].config(text=f"Last review: {when_text(d['review_saved_at'])}")
        else:
            n = d['findings']
            parts = [f"{n} finding{'' if n == 1 else 's'}"] + \
                [f'{d[sev]} {sev}' for sev in ('high', 'medium', 'low') if d[sev]]
            c['findings']['value'].config(text=str(n))
            c['findings']['detail'].config(text='  ·  '.join(parts))
            c['findings']['note'].config(text=f"Last review: {when_text(d['review_saved_at'])}")
        c['findings']['value'].config(foreground=theme.DANGER if d['high'] else theme.TEXT)

        c['changes']['value'].config(text=str(d['changes']))
        if d['changes'] == 0:
            c['changes']['detail'].config(text=NONE_YET['config'])
        else:
            c['changes']['detail'].config(
                text=f"{d['changes_ok']} successful  ·  {d['changes_failed']} failed"
                     f"  ·  last {RECENT_HOURS} hours")
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

    def _status_indicator(self, up, down):
        """The big status figure: '▲ 5' (green), '▼ 5' (red), both side by side when
        mixed, or a grey '—' (up None: no devices / not available)."""
        s = self.cards['status']
        s['down'].pack_forget()
        if up is None:
            s['value'].config(text='—', foreground=theme.TEXT_MUTED)
            s['tooltip'].text = 'No devices detected'
            return
        if down and not up:
            s['value'].config(text=f'{DOWN_ARROW} {down}', foreground=theme.DANGER)
        else:
            s['value'].config(text=f'{UP_ARROW} {up}', foreground=theme.SUCCESS)
            if down:
                s['down'].config(text=f'{DOWN_ARROW} {down}')
                s['down'].pack(side='left', padx=(14, 0))
        s['tooltip'].text = (f"{up} device{'' if up == 1 else 's'} up, "
                             f"{down} device{'' if down == 1 else 's'} down")

    def _fill_types(self, by_type):
        """The status card's rows: 'Routers   1 up  ·  0 down', down in red when > 0."""
        frame = self.cards['status']['types']
        for child in frame.winfo_children():
            child.destroy()
        for row, (label, up, down) in enumerate(by_type):
            for col, (text, color) in enumerate([
                    (label, theme.TEXT_SOFT), (f'{up} up  ·  ', theme.TEXT_SOFT),
                    (f'{down} down', theme.DANGER if down else theme.TEXT_SOFT)]):
                tk.Label(frame, text=text, font=theme.FONT_SMALL, background=theme.CARD,
                         foreground=color, anchor='w').grid(row=row, column=col, sticky='w',
                                                            padx=(0, 10 if col == 0 else 0))

    def _fill(self, key, rows, empty_text):
        part = self.lists[key]
        tree, empty, holder = part['tree'], part['empty'], part['holder']
        tree.delete(*tree.get_children())
        for values, tags in rows:
            tree.insert('', 'end', values=values, tags=tags)
        tree.yview_moveto(0)                       # newest rows first after every reload
        if rows:
            empty.pack_forget()
            if not holder.winfo_manager():
                holder.pack(fill='both', expand=True)
        else:
            holder.pack_forget()
            empty.config(text=empty_text)
            if not empty.winfo_manager():
                empty.pack(fill='both', expand=True)
