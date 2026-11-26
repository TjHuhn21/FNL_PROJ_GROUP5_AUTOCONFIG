"""Every text of the new-user guide, in one place: edit the wording here without touching
the window code (gui/guide.py, the pages).

  WELCOME_*      the first-run question
  TOUR_STEPS     the welcome tour, one dict per step (see TOUR_STEPS below)
  PAGE_HELP      "Help for this page": what it does, the main steps, common errors
  SHORTCUTS      "Keyboard shortcuts"
  EMPTY          what a page says when it has no data yet
  GETTING_STARTED  the Overview checklist for a new installation
  TOOLTIPS       short hover texts for buttons and fields whose meaning is not obvious

Keep the texts short and plain. Nothing here is shown to a role that cannot use the page.
"""

WELCOME_TITLE = 'Welcome to NetCommand'
WELCOME_TEXT = ('Welcome to NetCommand. Take a quick tour?\n\n'
                'It shows each part of the workbench in a few short steps. You can skip it '
                'now and restart it any time from the ? Help button at the top.')
WELCOME_START = 'Start tour'
WELCOME_SKIP = 'Skip'

# One step per part of the app, in this order. Keys:
#   title, text  what the popup says
#   target       what is highlighted: 'rail' (the page buttons), 'page' (the page area),
#                'command' (the command strip), 'inspector', 'console', 'help'
#   page         the page opened for the step (None: stay on the current page)
#   needs        the page the role must be able to open (None: everyone)
TOUR_STEPS = [
    {'key': 'sidebar', 'target': 'rail', 'page': None, 'needs': None,
     'title': 'The sidebar',
     'text': 'Each button opens one page: Overview (the summary), Scan (find devices), '
             'Devices (the registered list), Topology (the map), Findings (configuration '
             'problems), Configure (change devices), Setup (a brand-new device on the console '
             'cable) and Logs (the full history). You only see the pages your role can use.'},
    {'key': 'overview', 'target': 'page', 'page': 'dashboard', 'needs': 'dashboard',
     'title': 'Overview',
     'text': 'The summary cards show how many devices are registered, which are up or down '
             '(as last seen by the background monitor), the findings of the last review, and '
             'the configuration changes of the last 24 hours. Below them: recent activity.'},
    {'key': 'scan', 'target': 'page', 'page': 'scan', 'needs': 'scan',
     'title': 'Scan',
     'text': 'Type the device login and the Seed IP (the management IP of one switch or '
             'router), then click Scan. Its CDP/LLDP neighbours are listed too. Nothing is '
             'saved until you select devices and click Approve selected.'},
    {'key': 'devices', 'target': 'page', 'page': 'devices', 'needs': 'devices',
     'title': 'Devices',
     'text': 'Every registered device. Search, sort, and double-click a device to edit it. '
             'Add registers a device by hand; Delete removes it from the list (its history '
             'is kept). Backups... opens the saved configuration backups.'},
    {'key': 'topology', 'target': 'page', 'page': 'topology', 'needs': 'topology',
     'title': 'Topology',
     'text': 'The network map. Click a device or a link to see its details in the Inspector. '
             'Drag devices to arrange the map and click Save layout to keep it.'},
    {'key': 'configure', 'target': 'page', 'page': 'configure', 'needs': 'configure',
     'title': 'Configure',
     'text': 'Tick one or more devices, fill in the settings (VLANs, ports, routes...), click '
             'Preview and read the commands, then Apply. An encrypted backup of each device '
             'is saved first, and every change is checked afterwards.'},
    {'key': 'setup', 'target': 'page', 'page': 'setup', 'needs': 'setup',
     'title': 'Setup',
     'text': 'For a new switch or router: plug in the console cable and click Connect, type a '
             'name, an SSH username and password and a management IP, then click Set up SSH. '
             '"Use in Scan page" then fills in the Scan page for you. No PuTTY needed.'},
    {'key': 'findings', 'target': 'page', 'page': 'findings', 'needs': 'findings',
     'title': 'Findings',
     'text': 'Click Run review to check the saved configurations for problems (security, '
             'unused ports, missing settings). Select a finding to see the fix, and Send to '
             'Configure to prepare the commands.'},
    {'key': 'logs', 'target': 'console', 'page': 'logs', 'needs': 'logs',
     'title': 'Logs and the Console',
     'text': 'The Console at the bottom shows everything the app does, as it happens: filter '
             'it with the buttons above it, and double-click a line for details. The Logs page '
             'keeps the full history (configuration log and activity) for later.'},
    {'key': 'command', 'target': 'command', 'page': None, 'needs': None,
     'title': 'Command strip and Inspector',
     'text': 'Press Ctrl+K (or click the search box at the top) to find a device or open an '
             'operation by typing. The Inspector on the right shows the details of whatever '
             'you select; hide it with the button in the status bar when you need the room.'},
    {'key': 'accounts', 'target': 'page', 'page': 'accounts', 'needs': 'accounts',
     'title': 'Accounts (administrators)',
     'text': 'New accounts wait here for approval. Approve them with a role (viewer, operator '
             'or admin), reject them, disable or enable them, change roles, and unlock accounts '
             'locked after failed device logins. Every action asks first.'},
    {'key': 'help', 'target': 'help', 'page': None, 'needs': None,
     'title': 'Help is always here',
     'text': 'The ? button opens help for the page you are on, the keyboard shortcuts, and '
             'this tour again. That is all: enjoy NetCommand!'},
]
TOUR_BACK, TOUR_NEXT, TOUR_DONE, TOUR_SKIP = 'Back', 'Next', 'Finish', 'Skip tour'
TOUR_STEP_TEXT = 'Step {n} of {total}'

HELP_MENU = {'tour': 'Restart the tour', 'page': 'Help for this page',
             'shortcuts': 'Keyboard shortcuts'}

# "Help for this page": what it does, the main steps, and common errors with the fix.
PAGE_HELP = {
    'dashboard': {
        'title': 'Overview',
        'what': 'A summary of the stored network data: devices, their last known status, '
                'the latest review findings and the configuration changes of the last 24 hours.',
        'steps': ['Read the cards for the state of the network.',
                  'Click Refresh to reload now (it also reloads by itself every minute).',
                  'Use the Quick actions to jump to a page.'],
        'errors': [('"Overview unavailable"', 'The database cannot be read. Check that MySQL '
                    'is running; the page reloads when the connection is back.')]},
    'scan': {
        'title': 'Scan',
        'what': 'Finds switches and routers: NetCommand logs in to the Seed IP and lists its '
                'CDP/LLDP neighbours. Nothing is saved until you approve.',
        'steps': ['Type the device username and password.',
                  'Type the Seed IP: the management IP of one switch or router.',
                  'Click Scan and wait for the results.',
                  'Select the devices to keep and click Approve selected.'],
        'errors': [('Scan failed: the device rejected the username or password',
                    'Check the login. Note that 5 failed device logins lock your NetCommand '
                    'account (an administrator can unlock it).'),
                   ('Scan failed: no answer / timed out',
                    'Check the Seed IP, the cable, and that SSH is enabled on the device (use '
                    'the Setup page for a brand-new device).'),
                   ('Approve is greyed out', 'Select at least one device in the results. '
                    'Sample devices cannot be saved to the real database.')]},
    'devices': {
        'title': 'Devices',
        'what': 'The registered devices: search, view, edit, add and delete them, and open '
                'their configuration backups.',
        'steps': ['Search by name or IP.',
                  'Double-click a device (or select it and click Edit) to change it.',
                  'Add registers a device by hand; Delete removes it from the list.'],
        'errors': [('"A device with IP ... already exists"', 'Each IP can be registered once. '
                    'Edit the existing device instead.'),
                   ('"Name already used"', 'Device names must be unique: choose another name.'),
                   ('⚠ next to a type', 'The type was changed by hand and differs from what the '
                    'scan detected; hover over it to see the detected type.')]},
    'topology': {
        'title': 'Topology',
        'what': 'The network map of the registered devices and the links between them.',
        'steps': ['Click a device or link to see it in the Inspector.',
                  'Drag devices to arrange the map; click Save layout to keep it.',
                  'Refresh map reloads the devices.'],
        'errors': [('The map is empty', 'No devices are registered yet: scan and approve '
                    'devices first.')]},
    'configure': {
        'title': 'Configure',
        'what': 'Sends configuration to one or more devices over SSH, with an encrypted '
                'backup first and checks afterwards.',
        'steps': ['Tick the devices on the left.',
                  'Fill in the settings (switch or router tab).',
                  'Click Preview and read the commands.',
                  'Click Apply, read the summary and confirm.'],
        'errors': [('"Settings changed since the last preview"', 'Click Preview again: Apply '
                    'only sends commands you have read.'),
                   ('A red field', 'The value is not valid; the message under it says why. '
                    'Preview and Apply stay blocked until it is fixed.'),
                   ('Apply failed: login refused', 'The device rejected the SSH login. Enter '
                    'it again when asked; 5 failed device logins lock your account.'),
                   ('"Backup encryption key not available"', 'Set up the key with '
                    'backup_keys.py; nothing is sent without a backup.')]},
    'setup': {
        'title': 'Setup',
        'what': 'First setup of a brand-new device through the console cable: SSH, a login, '
                'and a management IP, so the device can be scanned over the network.',
        'steps': ['Plug in the console cable, choose its COM port and click Connect (the '
                  'device is read by itself).',
                  'Fill in the device name, the SSH username and password (once), and the '
                  'management IP address.',
                  'Click Set up SSH and confirm. Keep the cable plugged in until it says Done.',
                  'Click "Use in Scan page": the Seed IP, username and password are filled in '
                  'there for you.'],
        'errors': [('No ports listed', 'Check the USB console cable and its driver, then '
                    'click Refresh Ports.'),
                   ('The device does not answer', 'Press Enter in the device session, check '
                    'the speed (9600 baud), and that no other program uses the port.')]},
    'findings': {
        'title': 'Findings',
        'what': 'Reviews the saved configurations and lists problems by severity.',
        'steps': ['Click Run review (it replaces the stored review).',
                  'Select a finding to see how to fix it.',
                  'Send to Configure prepares the suggested commands for you to read.'],
        'errors': [('"A review is already running"', 'Wait for it to finish; one review '
                    'runs at a time.'),
                   ('A device is skipped', 'Its configuration could not be read: check that '
                    'its login is saved and that it is reachable.')]},
    'logs': {
        'title': 'Logs',
        'what': 'The full history: the configuration log (every Apply and its result) and '
                'the activity history (everything shown in the Console).',
        'steps': ['Choose what to show, then filter or search.',
                  'Double-click an entry to see its details.'],
        'errors': [('History not saved', 'The database update for the Console history has '
                    'not been run (schema_update_console_log.sql).')]},
    'accounts': {
        'title': 'Accounts',
        'what': 'Administrators approve new accounts, change roles, disable, enable and '
                'unlock accounts.',
        'steps': ['Select an account in the list.',
                  'Choose the role, then click the action. Every action asks first.'],
        'errors': [('"There must be at least one active admin"', 'The last administrator '
                    'cannot be disabled or demoted.'),
                   ('You cannot change your own account', 'Ask another administrator.')]},
}

SHORTCUTS = [
    ('Ctrl+K', 'Find a device or open an operation (command strip)'),
    ('F1', 'Help for this page'),
    ('Esc', 'Cancel a dialog (the same as its Cancel button)'),
    ('Enter', 'Press the focused button in a dialog'),
    ('Double-click', 'Edit a device (Devices), open a Console line or log entry'),
    ('Space', 'Tick or untick a device in the Configure device list'),
]

EMPTY = {
    'devices': 'No devices yet. Go to Scan to find devices on your network.',
}

GETTING_STARTED_TITLE = 'GETTING STARTED'
GETTING_STARTED = [
    ('scan', 'Scan the network', 'scan'),
    ('approve', 'Approve devices', 'scan'),
    ('topology', 'View the topology', 'topology'),
    ('review', 'Run a findings review', 'findings'),
]

TOOLTIPS = {
    'seed_ip': 'The management IP of one switch or router. NetCommand logs in to it and '
               'lists its CDP/LLDP neighbours.',
    'demo_scan': 'Use the built-in sample network instead of real devices.',
    'save_login': 'Keep this login (encrypted) with the approved devices, so Configure and '
                  'the review can log in later.',
    'neighbours': 'Also log in to every neighbour with this login. Only on a network you '
                  'control.',
    'approve': 'Save the selected devices to the database.',
    'managed': 'NetCommand can log in to this device (it has a usable login). Only managed '
               'devices can be configured.',
    'sticky': 'Learn the MAC addresses seen on the port and keep them as allowed addresses.',
    'native_vlan': 'The VLAN that is sent untagged on the trunk (both ends must match).',
    'dot1q': 'Set 802.1Q trunk encapsulation. Untick it on switches that only do 802.1Q '
             '(they reject the command).',
    'max_mac': 'How many MAC addresses may use the port before the violation action runs.',
    'violation': 'What happens on a violation: shutdown (the port is disabled), restrict '
                 '(drop and log) or protect (drop silently).',
    'approve_as': 'The role the account gets: viewer (read only), operator (scan and '
                  'configure) or admin (also manage accounts).',
    'preview': 'Build the commands from the settings so you can read them. Nothing is sent.',
    'apply': 'Send the previewed commands (after a backup and a summary you confirm).',
    'stop_on_failure': 'Do not start the next device when one fails.',
    'clear_form': 'Empty every setting you entered (asks first).',
    'run_review': 'Check the saved configurations for problems. Replaces the stored review.',
    'send_to_configure': 'Prepare the suggested commands on the Configure page (nothing is '
                         'sent until you Apply).',
    'backups': 'The saved configuration backups of the selected device.',
    'help': 'Help: this page, keyboard shortcuts, the tour.',
}
