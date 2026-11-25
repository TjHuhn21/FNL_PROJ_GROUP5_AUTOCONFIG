"""The Console as the record of WHO did WHAT, WHEN, on WHICH device, and WHAT HAPPENED.

* device_log: every SSH connection step and command, with a short result (OK, FAILED with
  the device's error, timed out); full output kept for a popup; secrets masked.
* event_log records: user (masked e-mail or "system"), device, tags, detail.
* Console filters: All | Successful | Failed | Warnings | Changes (several, with counts),
  Category, Device, User, Search, Show commands, Reset; they never delete anything and
  new matching lines still appear live. Double-click shows the full output.
* Saved history: every line is saved (append-only), retried while the database is away,
  and shown on the Logs page; Clear never touches it.
No device, no MySQL, no network.
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))
sys.path.insert(0, os.path.dirname(__file__))

import pytest

tk = pytest.importorskip('tkinter')

import db_fake  # noqa: E402
import device_log  # noqa: E402
from config import connect  # noqa: E402
from gui import event_log, theme  # noqa: E402
from gui.event_log import log_event  # noqa: E402

EMAIL = 'jfontillaz.9008@umak.edu.ph'


@pytest.fixture
def console():
    from gui.components.console import OperationsConsole
    from gui_helpers import new_root
    root = new_root()
    theme.apply(root)
    db_fake.reset()
    c = OperationsConsole(root, db_fake)
    c.pack(fill='both', expand=True)
    root.update()
    yield root, c
    root.destroy()
    db_fake.reset()


def shown(c):
    return [r['message'] for r in c._shown]


# ---------------------------------------------------------------- device_log
class Fake:
    """A Netmiko-like connection to MOCK-R1."""
    def __init__(self, replies=None, raise_on=None):
        self.replies, self.raise_on, self.closed = replies or {}, raise_on or {}, False

    def find_prompt(self):
        return 'MOCK-R1#'

    def send_command(self, command, **kw):
        if command in self.raise_on:
            raise self.raise_on[command]
        return self.replies.get(command, '')

    def config_mode(self):
        return 'MOCK-R1(config)#'

    def exit_config_mode(self):
        return 'MOCK-R1#'

    def send_config_set(self, commands, **kw):
        return self.replies.get(commands[0], '')

    def save_config(self):
        return '[OK]'

    def disconnect(self):
        self.closed = True


@pytest.fixture
def lines():
    got = []
    device_log.set_sink(lambda category, message, level='info', **f:
                        got.append(dict(f, category=category, message=message, level=level)))
    yield got
    event_log.connect_device_log()


def test_every_step_and_command_is_logged_with_its_result(lines):
    from netmiko.exceptions import ReadTimeout
    fake = Fake(replies={'show version': 'Cisco IOS ... C1900 ...',
                         'vlan 4095': "vlan 4095\n% Invalid input detected at '^' marker."},
                raise_on={'show slow': ReadTimeout('slow')})
    conn = device_log.open_logged(lambda: fake, '127.0.0.11', 'labscan')
    conn.find_prompt()
    conn.send_command('show version')
    conn.config_mode()
    conn.send_config_set(['vlan 4095'])
    with pytest.raises(ReadTimeout):
        conn.send_command('show slow')
    conn.save_config()
    conn.disconnect()
    got = [(l['category'], l['message'], l.get('result', ''), l['level']) for l in lines]
    assert got == [
        ('ssh', 'Connecting to 127.0.0.11:22 as labscan...', '', 'info'),
        ('ssh', 'Connected to MOCK-R1 (127.0.0.11).', '', 'ok'),
        ('config', 'MOCK-R1 > show version', 'OK', 'ok'),
        ('config', 'MOCK-R1 > configure terminal', 'OK', 'ok'),
        ('config', 'MOCK-R1 > vlan 4095', "FAILED  % Invalid input detected at '^' marker.",
         'error'),
        ('config', 'MOCK-R1 > show slow', 'timed out', 'warn'),
        ('config', 'MOCK-R1 > write memory', 'OK', 'ok'),
        ('ssh', 'Disconnected from MOCK-R1.', '', 'info')]
    assert all(l['device'] == 'MOCK-R1' for l in lines[1:]) and fake.closed
    assert lines[2]['detail'] == 'Cisco IOS ... C1900 ...'         # full output, for the popup


def test_secrets_are_masked_in_commands_and_output(lines):
    fake = Fake(replies={'show run': 'username admin secret 5 $1$abc\nsnmp-server community '
                                     'PUBLIC1 RO\nenable secret TopSecret'})
    conn = device_log.LoggedConnection(fake, '10.0.0.1', device_log.SCAN)
    for command in ('username admin secret Sup3rS3cret', 'enable secret TopSecret',
                    'snmp-server community PUBLIC1 RO', 'crypto isakmp key K3y address 1.2.3.4'):
        conn.send_config_set([command])
    conn.send_command('show run')
    text = str(lines)
    for secret in ('Sup3rS3cret', 'TopSecret', 'PUBLIC1', 'K3y', '$1$abc'):
        assert secret not in text
    messages = [l['message'] for l in lines]
    assert '10.0.0.1 > username admin secret ********' in messages
    assert '10.0.0.1 > snmp-server community ******** RO' in messages
    assert all(l['category'] == 'scan' for l in lines)


def test_a_failed_connection_says_why_without_the_exceptions_text(lines):
    from netmiko.exceptions import NetmikoAuthenticationException

    def refuse():
        raise NetmikoAuthenticationException('Authentication failed for pw=hunter2')
    with pytest.raises(NetmikoAuthenticationException):
        device_log.open_logged(refuse, '127.0.0.11', 'labscan')
    assert lines[-1]['level'] == 'error' and 'Connection to 127.0.0.11 FAILED' in \
        lines[-1]['message'] and 'hunter2' not in str(lines)


def test_apply_logs_its_commands_and_keeps_the_before_after(monkeypatch, tmp_path, console):
    root, c = console
    from test_ssh_session import FakeIOS
    after = ('Building configuration...\n!\nhostname SW1\n!\ninterface Gi0/1\n description '
             'Uplink to SW1\n!\nend\n')
    fake = FakeIOS()
    fake.running = 'Building configuration...\n!\nhostname SW1\n!\ninterface Gi0/1\n!\nend\n'
    reads = []
    real_send = fake.send_command

    def send(cmd):                         # the second read shows the change
        if cmd == 'show running-config':
            reads.append(1)
            return fake.running if len(reads) == 1 else after
        return real_send(cmd)
    fake.send_command = send
    monkeypatch.setattr(connect, 'ConnectHandler', lambda **kw: fake)
    ok, _msg = connect.apply_config({'host': '10.0.0.2', 'username': 'admin',
                                     'password': 'S3cretPass!'},
                                    ['interface Gi0/1', 'description Uplink to SW1'],
                                    backup_dir=str(tmp_path))
    assert ok
    c.flush()
    commands = [r['message'] for r in c.records if r['command']]
    assert 'SW1 > interface Gi0/1' in commands and 'SW1 > description Uplink to SW1' in commands
    assert 'SW1 > write memory' in commands and 'SW1 > end' in commands
    assert all(r['category'] == 'config' for r in c.records if r['command'])
    assert 'S3cretPass!' not in str(c.records)
    diff = connect.take_diff('10.0.0.2')
    assert '+ description Uplink to SW1' in diff and 'Building configuration' not in diff
    assert connect.take_diff('10.0.0.2') == ''                   # taken once


def test_config_diff_masks_secrets():
    diff = connect.config_diff('hostname R1\nend', 'hostname R1\nenable secret Hidden1\nend')
    assert '+enable secret ********' in diff and 'Hidden1' not in diff


# ---------------------------------------------------------------- records
def test_lines_say_who_did_it(console):
    root, c = console
    log_event('app', 'automatic line')
    event_log.set_user(EMAIL)
    log_event('devices', f'Edit by {EMAIL} SUCCESSFUL', 'ok', tags=['change'], device='R1')
    c.flush()
    first, second = c.records
    assert first['user'] == 'system'
    assert second['user'] == 'jf*****ph' or EMAIL not in second['user']
    assert EMAIL not in second['message'] and second['device'] == 'R1'
    assert set(second['tags']) == {'successful', 'change'}


# ---------------------------------------------------------------- the filters
def fill(c):
    event_log.set_user(EMAIL)
    log_event('scan', 'Scan SUCCESSFUL: 2 devices.', 'ok')
    log_event('config', 'MOCK-R1 > interface Gi0/1', 'ok', command=True, result='OK',
              device='MOCK-R1')
    log_event('configure', 'MOCK-R1: configuration applied, apply SUCCESSFUL.', 'ok',
              tags=['change'], device='MOCK-R1', detail='+ description Uplink')
    log_event('configure', 'SW1: apply FAILED. No answer.', 'error', device='SW1')
    log_event('monitor', 'SW1: device went DOWN', 'warn', device='SW1', user='system')
    log_event('security', '1 attempt left.', 'warn')
    c.flush()


def test_quick_filter_buttons(console):
    root, c = console
    fill(c)
    assert c.tag_buttons['failed'].cget('text') == 'Failed (1)'
    assert c.tag_buttons['change'].cget('text') == 'Changes (1)'
    assert c.tag_buttons['all'].cget('text') == 'All (6)'
    c.toggle_filter('failed')
    assert shown(c) == ['SW1: apply FAILED. No answer.']
    c.toggle_filter('warning')                                   # several at once
    assert len(shown(c)) == 3 and c.tag_buttons['all'].cget('relief') != 'sunken'
    assert c.tag_buttons['failed'].cget('background') == theme.ACCENT   # highlighted
    c.toggle_filter('failed'); c.toggle_filter('warning')        # nothing selected: All
    assert c.selected_tags == set() and len(shown(c)) == 6
    c.toggle_filter('change')
    c.toggle_filter('all')                                       # All deselects the others
    assert c.selected_tags == set() and len(shown(c)) == 6
    assert len(c.records) == 6                                   # nothing was ever deleted


def test_extra_filters_work_together_and_reset(console):
    root, c = console
    fill(c)
    c.category.set('config')                                     # config + configure
    c.apply_filters()
    assert len(shown(c)) == 3
    c.device.set('MOCK-R1'); c.toggle_filter('successful')
    assert shown(c) == ['MOCK-R1: configuration applied, apply SUCCESSFUL.']
    c.reset_filters()
    assert len(shown(c)) == 6
    c.show_commands.set(False); c.apply_filters()
    assert 'MOCK-R1 > interface Gi0/1' not in shown(c) and len(shown(c)) == 5
    c.reset_filters()
    c.search.set('gi0/1'); c.apply_filters()
    assert shown(c) == ['MOCK-R1 > interface Gi0/1']
    c.reset_filters()
    c.user.set('system'); c.apply_filters()
    assert shown(c) == ['WARNING: SW1: device went DOWN']
    assert 'MOCK-R1' in c.boxes['device'].cget('values')
    assert 'system' in c.boxes['user'].cget('values')


def test_new_lines_follow_the_filters_live(console):
    root, c = console
    fill(c)
    c.toggle_filter('failed')
    log_event('scan', 'another success', 'ok')
    log_event('scan', 'Scan FAILED. Timed out.', 'error')
    c.flush()
    assert shown(c) == ['SW1: apply FAILED. No answer.', 'Scan FAILED. Timed out.']
    assert c.tag_buttons['failed'].cget('text') == 'Failed (2)'


def test_double_click_shows_the_full_output(console, monkeypatch):
    root, c = console
    fill(c)
    opened = []
    from gui.components import detail_popup
    monkeypatch.setattr(detail_popup, 'show_detail', lambda parent, r, title=None:
                        opened.append(r))
    c.toggle_filter('change')
    root.update()
    x, y, _w, _h = c.text.bbox('1.0')
    c._open_line(type('E', (), {'x': x + 2, 'y': y + 2})())
    assert opened and opened[0]['detail'] == '+ description Uplink'
    text = detail_popup.describe(opened[0])
    assert 'Device:   MOCK-R1' in text and '+ description Uplink' in text


def test_the_line_shows_user_category_device_and_result(console):
    root, c = console
    fill(c)
    line = c.text.get('2.0', '2.end')
    assert 'jf*****' in line and 'config' in line and 'MOCK-R1' in line
    assert '> interface Gi0/1' in line and line.rstrip().endswith('OK')


# ---------------------------------------------------------------- the saved history
def test_everything_is_saved_and_clear_keeps_it(console):
    root, c = console
    event_log.keep_history()
    log_event('app', 'before the store was known')           # saved later, too
    event_log.set_store(db_fake)
    fill(c)
    assert event_log.save_now()
    assert db_fake.count_console_events() == 7
    assert db_fake.count_console_events(tag='change') == 1
    assert db_fake.count_console_events(user='system') == 2
    c.clear()                         # asks first; the confirmed Clear is logged (saved) too
    event_log.save_now()
    assert c.records == [] and db_fake.count_console_events() == 8     # nothing deleted
    assert db_fake.count_console_events(search='Clearing the Console screen confirmed') == 1
    row = db_fake.get_console_events(search='configuration applied')[0]
    assert row['detail'] == '+ description Uplink' and row['device'] == 'MOCK-R1'


def test_saving_is_retried_while_the_database_is_away():
    class Away:
        def __init__(self):
            self.rows, self.fail = [], True

        def add_console_events(self, rows):
            if self.fail:
                from store_errors import DatabaseUnavailable
                raise DatabaseUnavailable('down')
            self.rows += rows
    store = Away()
    event_log._store[0] = store                           # (no writer thread in this test)
    log_event('app', 'one'); log_event('app', 'two')
    assert event_log.save_now() is False and store.rows == []
    store.fail = False
    assert event_log.save_now() and [r['message'] for r in store.rows] == ['one', 'two']


def test_a_missing_table_is_said_once_and_saving_stops(console):
    root, c = console

    class NoTable:
        def add_console_events(self, rows):
            from store_errors import DatabaseError
            raise DatabaseError('no table', code=1146)
    event_log._store[0] = NoTable()
    log_event('app', 'x')
    event_log.save_now()
    c.flush()
    assert any('console_log table is missing' in r['message'] for r in c.records)
    assert event_log._saving['off']


def test_the_logs_page_shows_the_activity_history(console):
    root, c = console
    from gui.logs_tab import ACTIVITY, LogsTab
    event_log._store[0] = db_fake
    fill(c)
    event_log.save_now()
    page = LogsTab(root, db_fake)
    page.view.set(ACTIVITY)
    page.change_view()
    assert page.total == 6
    page.status.set('failed'); page.go_first()
    rows = [page.activity_tree.item(i)['values'] for i in page.activity_tree.get_children()]
    assert len(rows) == 1 and rows[0][3] == 'SW1'
    page.status.set('all'); page.user.set('system'); page.go_first()
    assert page.total == 1


def test_the_next_person_starts_with_a_fresh_console(monkeypatch):
    """Sign-out clears the Console's memory: the next user sees their own session only.
    Nothing saved is lost."""
    from gui.components.console import OperationsConsole
    from gui_helpers import new_root
    db_fake.reset()
    event_log.keep_history()
    event_log.set_store(db_fake)
    event_log.set_user(EMAIL)
    log_event('accounts', 'Account ju*****f1@yahoo.com: role admin -> viewer', 'ok',
              tags=['change'])
    event_log.set_user(None)                       # signed out (main.py)
    event_log.save_now()
    event_log.clear_history()
    log_event('app', 'Waiting for sign-in...')     # before the next sign-in: theirs
    event_log.set_user('justine_f1@yahoo.com')
    log_event('app', 'Sign-in SUCCESSFUL.', 'ok')
    root = new_root()
    try:
        c = OperationsConsole(root, db_fake)       # the next user's workbench
        c.flush()
        assert [r['message'] for r in c.records] == ['Waiting for sign-in...',
                                                     'Sign-in SUCCESSFUL.']
        assert not any('role admin' in r['message'] for r in c.records)
    finally:
        root.destroy()
    event_log.save_now()
    assert db_fake.count_console_events(search='role admin -> viewer') == 1   # still saved


def test_the_logs_page_shows_others_activity_only_to_admins(console):
    root, c = console
    from gui.logs_tab import ACTIVITY, ALL_USERS, LogsTab
    event_log._store[0] = db_fake
    for who in ('ad*****in@example.com', 'vi*****er@example.com', 'system'):
        log_event('app', f'line of {who}', user=who)
    event_log.save_now()

    def page_for(scope):
        p = LogsTab(root, db_fake, scope_users=scope)
        p.view.set(ACTIVITY)
        p.change_view()
        return p
    admin = page_for(None)
    assert admin.total == 3
    viewer = page_for(lambda: ('vi*****er@example.com', 'system'))
    messages = {viewer.activity_tree.item(i)['values'][4]
                for i in viewer.activity_tree.get_children()}
    assert messages == {'line of vi*****er@example.com', 'line of system'}
    assert list(viewer.user_box.cget('values')) == [ALL_USERS, 'vi*****er@example.com',
                                                    'system']
    viewer.user.set('ad*****in@example.com')       # even if set anyway: never shown
    viewer.go_first()
    assert viewer.total == 2


def test_the_database_query_is_limited_to_the_allowed_users():
    import db
    sql, params = db._console_filter(users=('me', 'system'))
    assert 'user_label IN (%s, %s)' in sql and params == ['me', 'system']
    sql, params = db._console_filter()
    assert 'user_label IN' not in sql


def test_the_store_has_no_way_to_change_or_delete_history():
    import db
    for store in (db, db_fake):
        names = [n for n in dir(store) if 'console' in n.lower()]
        assert not [n for n in names if any(w in n.lower() for w in
                                            ('delete', 'update', 'clear', 'remove', 'edit'))]
