"""Accounts page (admins only): list accounts and act on the selected one.

Only the actions that make sense for the selected account are shown (ACTIONS_BY_STATUS):
  pending_approval   Approve (as the role chosen in the dropdown, default viewer), Reject
  active             Change role, Disable, Unlock (only when locked)
  disabled           Enable, Change role
  rejected           Re-open as pending (nothing is deleted)
There is ONE role dropdown: "Approve as:" for a pending account, "Role:" with the current
role for an active or disabled one (Change role only for a different role). An account that
is not approved yet has no role ("—"). Admin access, rejecting, disabling, enabling and
re-opening ask first. Admins see full e-mails here; the Console gets masked ones, with
before -> after.

Every action is an API call (GET /admin/users, POST /admin/users/{id}/approve|reject|
disable|enable|reopen|role|unlock) with the session token; the SERVER enforces every rule
(admins only, never one's own account, at least one active admin) and audits the action.
A 401 means the session has ended: the workbench signs out.
"""
import tkinter as tk
from datetime import datetime, timezone
from tkinter import messagebox, ttk

from desktop_auth.api_client import ApiError
from gui import background, theme
from gui.auth_window import mask_email
from gui.event_log import log_event
from gui.timefmt import format_time
from gui.components.tables import setup_table

FILTERS = ('pending_approval', 'all', 'active', 'pending_verification', 'rejected', 'disabled')
ROLES = ('viewer', 'operator', 'admin')
COLUMNS = (('id', 'ID', 50), ('email', 'Email', 230), ('full_name', 'Name', 170),
           ('role', 'Role', 80), ('status', 'Status', 140), ('verified', 'Email verified', 110),
           ('locked', 'Lock', 230))
PERMANENT_STATUS = 'locked_by_security'
NO_ROLE = '—'                         # an account that is not approved yet has no role
DEFAULT_ROLE = 'viewer'
ROLE_STATUSES = ('active', 'disabled')
# what each role can really do in NetCommand (desktop_auth/session.PERMISSIONS)
ROLE_INFO = {
    'viewer': 'can view the Overview, Devices, Topology, Findings and Logs; cannot change '
              'anything',
    'operator': 'can also scan, configure devices (Configure, Initial Setup), edit devices '
                'and run reviews; cannot manage accounts',
    'admin': 'full access, including approving and managing accounts',
}
# the actions offered for each status (the server enforces every rule again)
ACTIONS_BY_STATUS = {
    'pending_approval': ('approve', 'reject'),
    'active': ('change_role', 'disable', 'unlock'),
    'disabled': ('enable', 'change_role'),
    'rejected': ('reopen',),
    'pending_verification': (),
}
STATUS_TEXT = {'pending_approval': 'pending approval', 'pending_verification':
               'waiting for email verification', 'active': 'active', 'disabled': 'disabled',
               'rejected': 'rejected'}
ADMIN_CONFIRM = ('Give {email} full admin access? Admins can approve, disable, and change roles '
                 'of other accounts.')


def lock_text(user):
    """'Temporarily locked until 11:30 AM', 'Locked: admin unlock required', or ''."""
    lock = user.get('security_lock')
    if lock == 'permanent':
        return 'Locked: admin unlock required'
    if lock == 'temporary':
        until = user.get('security_locked_until')
        try:                                       # the server sends UTC
            when = datetime.fromisoformat(str(until).replace('Z', '')).replace(
                tzinfo=timezone.utc).astimezone()
            return f'Temporarily locked until {format_time(when)}'
        except ValueError:
            return 'Temporarily locked'
    if user.get('locked'):
        return 'Sign-in locked (wrong passwords)'
    return ''


def role_text(user):
    """The Role column: '—' for an account that is not approved yet (it has no role)."""
    if user.get('status') not in ROLE_STATUSES:
        return NO_ROLE
    return user.get('role') or NO_ROLE


class AccountsPage(ttk.Frame):
    def __init__(self, parent, account):
        super().__init__(parent, padding=theme.PAD)
        self.account, self.rows, self.busy = account, {}, False
        top = ttk.Frame(self)
        top.pack(fill='x')
        ttk.Label(top, text='Show:').pack(side='left')
        self.filter = tk.StringVar(value='pending_approval')
        box = ttk.Combobox(top, textvariable=self.filter, values=FILTERS, state='readonly',
                           width=22)
        box.pack(side='left', padx=theme.PAD)
        box.bind('<<ComboboxSelected>>', lambda e: self.refresh())
        self.refresh_btn = ttk.Button(top, text='Refresh', command=self.refresh)
        self.refresh_btn.pack(side='left')

        self.tree = ttk.Treeview(self, columns=[c[0] for c in COLUMNS], show='headings',
                                 selectmode='browse')
        setup_table(self.tree, COLUMNS)
        self.tree.pack(fill='both', expand=True, pady=theme.PAD)
        self.tree.bind('<<TreeviewSelect>>', lambda e: self.update_actions(), add='+')

        # ONE role dropdown: "Approve as:" for a pending account, "Role:" (its current role)
        # for an active or disabled one. The buttons shown follow the selected account.
        actions = ttk.Frame(self)
        actions.pack(fill='x')
        self.role_label = ttk.Label(actions, text='Role:', width=11)
        self.role_label.pack(side='left')
        self.role = tk.StringVar(value=DEFAULT_ROLE)
        self.role_box = ttk.Combobox(actions, textvariable=self.role, values=ROLES,
                                     state='readonly', width=10)
        self.role_box.pack(side='left', padx=(0, theme.PAD))
        self.role.trace_add('write', lambda *a: self._role_picked())
        self.role_note = ttk.Label(actions, text='', foreground=theme.TEXT_MUTED)
        self.role_note.pack(side='left', fill='x', expand=True)

        self.buttons_row = ttk.Frame(self)
        self.buttons_row.pack(fill='x', pady=(theme.PAD, 0))
        b = self.buttons = {
            'approve': ttk.Button(self.buttons_row, text='Approve', style='Accent.TButton',
                                  command=self.approve),
            'reject': ttk.Button(self.buttons_row, text='Reject', command=self.reject),
            'change_role': ttk.Button(self.buttons_row, text='Change role',
                                      command=self.change_role),
            'enable': ttk.Button(self.buttons_row, text='Enable', style='Accent.TButton',
                                 command=self.enable),
            'disable': ttk.Button(self.buttons_row, text='Disable', command=self.disable),
            'unlock': ttk.Button(self.buttons_row, text='Unlock', command=self.unlock),
            'reopen': ttk.Button(self.buttons_row, text='Re-open as pending',
                                 command=self.reopen)}
        self.approve_btn, self.reject_btn = b['approve'], b['reject']
        self.change_role_btn, self.disable_btn = b['change_role'], b['disable']
        self.unlock_btn, self.enable_btn, self.reopen_btn = b['unlock'], b['enable'], b['reopen']
        self.hint = ttk.Label(self, text='', foreground=theme.TEXT_SOFT)
        self.hint.pack(anchor='w', pady=(4, 0))
        self.status = ttk.Label(self, text='', wraplength=700, justify='left')
        self.status.pack(anchor='w', pady=(theme.PAD, 0))
        self._selected_id = None
        self.update_actions()

    # ------------------------------------------------------------ what can be done
    def update_actions(self):
        """Show only the actions that make sense for the selected account (see
        ACTIONS_BY_STATUS); the dropdown's label and value follow it. Selecting another
        account clears the previous result message."""
        user = self.selected()
        uid = user['id'] if user else None
        if uid != self._selected_id:
            self._selected_id = uid
            self.status.config(text='')
        status = (user or {}).get('status')
        keys = ACTIONS_BY_STATUS.get(status, ())
        if status == 'active' and not (user or {}).get('security_lock'):
            keys = tuple(k for k in keys if k != 'unlock')       # only when locked
        for key, button in self.buttons.items():
            button.pack_forget()
        for key in (keys or ('approve', 'reject')):               # nothing selected: disabled
            self.buttons[key].pack(side='left', padx=(0, 6))
        own = user is not None and uid == self.account.session.user_id
        for key, button in self.buttons.items():
            button.state(['!disabled'] if user and key in keys and not own else ['disabled'])
        if status == 'pending_approval':
            self.role_label.config(text='Approve as:')
            self.role.set(DEFAULT_ROLE)
        else:
            self.role_label.config(text='Role:')
            if status in ROLE_STATUSES and user.get('role') in ROLES:
                self.role.set(user['role'])                       # their CURRENT role
        uses_role = status in ('pending_approval',) + ROLE_STATUSES and not own
        self.role_box.configure(state='readonly' if uses_role else 'disabled')
        if user is None:
            self.hint.config(text='Select an account to see what can be done with it.')
        else:
            text = f"Selected: {user.get('email', user['id'])} ({STATUS_TEXT.get(status, status)})"
            if own:
                text += ' - this is your own account: ask another administrator to change it.'
            elif status == 'pending_verification':
                text += ' - nothing to do until its email address is verified.'
            self.hint.config(text=text)
        self._role_picked()

    def _role_picked(self):
        """The description of the chosen role; Change role only for a DIFFERENT role."""
        self.role_note.config(text=ROLE_INFO.get(self.role.get(), ''))
        user = self.selected()
        if not hasattr(self, 'buttons') or user is None:
            return
        own = user['id'] == self.account.session.user_id
        if user.get('status') in ROLE_STATUSES and not own:
            different = self.role.get() in ROLES and self.role.get() != user.get('role')
            self.change_role_btn.state(['!disabled'] if different else ['disabled'])

    # ------------------------------------------------------------ helpers
    def say(self, text, error=False):
        self.status.config(text=text, foreground=theme.DANGER if error else theme.TEXT)

    def selected(self):
        sel = self.tree.selection()
        return self.rows.get(sel[0]) if sel else None

    def _call(self, fn, on_ok):
        if self.busy:
            return
        token = self.account.session.token()
        if token is None:
            self.account.on_session_end('ended')
            return
        self.busy = True

        def done(result, error):
            self.busy = False
            if isinstance(error, ApiError):
                if error.status == 401:
                    self.account.on_session_end('ended')
                    return
                log_event('accounts', f'Account request FAILED: {error}', 'error')
                self.say(str(error), error=True)
            elif error is not None:
                self.say('The request failed. Try again.', error=True)
            else:
                on_ok(result)
        background.run_async(self, lambda: fn(token), done)

    # ------------------------------------------------------------ actions
    def refresh(self, note=None):
        """Reload the list. note: the result of the action that triggered the reload,
        kept on screen instead of the account count."""
        choice = self.filter.get()
        status = None if choice == 'all' else choice
        client = self.account.client

        def ok(users):
            keep = self._selected_id
            self.tree.delete(*self.tree.get_children())
            self.rows = {}
            for u in users:
                iid = str(u['id'])
                self.rows[iid] = u
                status = PERMANENT_STATUS if u.get('security_lock') == 'permanent' \
                    else u.get('status', '')
                self.tree.insert('', 'end', iid=iid, values=(
                    u['id'], u.get('email', ''), u.get('full_name', ''), role_text(u),
                    status, 'yes' if u.get('email_verified_at') else 'no', lock_text(u)))
            if keep is not None and str(keep) in self.rows:
                self.tree.selection_set(str(keep))     # the same account stays selected
            self.update_actions()
            self.say(note or (f'{len(users)} account(s).' if users else 'No accounts to show.'))
        self._call(lambda token: client.list_users(token, status=status), ok)

    def _me(self):
        return mask_email(getattr(self.account.session, 'email', '') or '')

    def _act(self, user, verb, call, changes, confirm=None, title=None):
        """Run one account action after an optional confirmation. changes: the before ->
        after text, logged to the Console (masked e-mails) and shown here (full e-mail)."""
        email = user.get('email', str(user['id']))
        if confirm and not messagebox.askyesno(title or f'{verb} account', confirm,
                                               parent=self):
            self.say(f'{verb}: cancelled. Nothing was changed.')
            return
        log_event('accounts', f'{verb} {mask_email(email)}...')

        def ok(_result):
            log_event('accounts', f'Account {mask_email(email)}: {changes} (by {self._me()}): '
                                  f'{verb} SUCCESSFUL.', 'ok', tags=['change'])
            self.refresh(note=f'{format_time(datetime.now())}: {verb} {email}: {changes}.')
        self._call(lambda token: call(token, user['id']), ok)

    def _selected_or_say(self):
        user = self.selected()
        if not user:
            self.say('Select an account first.', error=True)
        return user

    def approve(self):
        """Approve with the role chosen in the dropdown (admin: asks first)."""
        user = self._selected_or_say()
        if not user:
            return
        role, client = self.role.get(), self.account.client
        if role not in ROLES:
            self.say('Choose a role.', error=True)
            return
        confirm = ADMIN_CONFIRM.format(email=user.get('email', user['id'])) \
            if role == 'admin' else None
        self._act(user, 'Approve', lambda token, uid: client.approve_user(token, uid, role),
                  f'role {NO_ROLE} -> {role}; status pending_approval -> active',
                  confirm=confirm, title='Approve as admin')

    def reject(self):
        user = self._selected_or_say()
        if not user:
            return
        self._act(user, 'Reject', self.account.client.reject_user,
                  'status pending_approval -> rejected',
                  confirm=f"Reject the account {user.get('email', user['id'])}? It will not be "
                          f"able to sign in.")

    def change_role(self):
        """Change the selected account's role to the one in the dropdown, after a
        confirmation (admin: the full-access question). The server decides (admins only,
        never one's own role, never the last active admin) and signs it out everywhere."""
        user = self._selected_or_say()
        if not user:
            return
        if user['id'] == self.account.session.user_id:
            self.say('You cannot change your own role. Ask another administrator.', error=True)
            return
        old, new = user.get('role') or NO_ROLE, self.role.get()
        if new not in ROLES:
            self.say('Choose a role.', error=True)
            return
        if new == old:
            self.say(f"{user.get('email', user['id'])} already has the role {new}.")
            return
        email = user.get('email', user['id'])
        question = (ADMIN_CONFIRM.format(email=email) + '\n\n' if new == 'admin' else '') + \
            (f'Change the role of {email} from {old} to {new}?\n\nThe account is signed out '
             f'everywhere and must sign in again to get the new permissions.')
        client = self.account.client
        self._act(user, 'Change role', lambda token, uid: client.change_role(token, uid, new),
                  f'role {old} -> {new}; signed out everywhere', confirm=question,
                  title='Change role')

    def disable(self):
        user = self._selected_or_say()
        if not user:
            return
        self._act(user, 'Disable', self.account.client.disable_user,
                  'status active -> disabled; signed out everywhere',
                  confirm=f"Disable the account {user.get('email', user['id'])}? It is signed "
                          f"out everywhere and can no longer sign in.")

    def enable(self):
        user = self._selected_or_say()
        if not user:
            return
        self._act(user, 'Enable', self.account.client.enable_user,
                  f"status disabled -> active (role {user.get('role') or NO_ROLE})",
                  confirm=f"Enable the account {user.get('email', user['id'])}? It can sign in "
                          f"again as {user.get('role') or 'its role'}.")

    def reopen(self):
        """A rejected account waits for approval again (no role until approved)."""
        user = self._selected_or_say()
        if not user:
            return
        self._act(user, 'Re-open', self.account.client.reopen_user,
                  'status rejected -> pending_approval',
                  confirm=f"Re-open {user.get('email', user['id'])} as pending? It waits for "
                          f"approval again; nothing is deleted.")

    def unlock(self):
        """Clear the selected account's lock after failed device logins (temporary or
        permanent), with its failure and lockout counts. The server allows it only for an
        admin and never for one's own account; this only asks first."""
        user = self.selected()
        if not user:
            self.say('Select an account first.', error=True)
            return
        if user['id'] == self.account.session.user_id:
            self.say('You cannot unlock your own account. Ask another administrator, or use '
                     'the recovery command on the server.', error=True)
            return
        if not user.get('security_lock'):
            self.say(f"{user.get('email', user['id'])} is not locked.")
            return
        if not messagebox.askyesno('Unlock account',
                                   f"Unlock {user.get('email', user['id'])}? Its failed device "
                                   f'login count and lockout count are reset.', parent=self):
            self.say('Not unlocked.')
            return
        client, me = self.account.client, mask_email(getattr(self.account.session, 'email', ''))
        target = mask_email(user.get('email', ''))
        log_event('security', f'Unlocking {target}...')

        def ok(result):
            log_event('security', f"Unlock of {target} SUCCESSFUL: lock "
                                  f"{result.get('cleared') or 'none'} -> unlocked (by "
                                  f'administrator {me}).', 'ok', tags=['change'])
            self.refresh(note=f"{format_time(datetime.now())}: Unlocked "
                              f"{user.get('email', user['id'])}.")
        self._call(lambda token: client.unlock_user(token, user['id']), ok)
