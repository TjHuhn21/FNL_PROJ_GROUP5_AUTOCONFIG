"""Accounts page (admins only): list accounts, approve, reject or disable them, change
another account's role, and unlock an account that was locked after failed device logins.

Every action is an API call (GET /admin/users, POST /admin/users/{id}/approve|reject|
disable|role|unlock) with the session token; the server checks that the caller is an admin and
audits the action. A 401 means the session has ended: the workbench signs out.
"""
import tkinter as tk
from datetime import datetime, timezone
from tkinter import messagebox, ttk

from desktop_auth.api_client import ApiError
from gui import background, theme
from gui.auth_window import mask_email
from gui.event_log import log_event
from gui.timefmt import format_time

FILTERS = ('pending_approval', 'all', 'active', 'pending_verification', 'rejected', 'disabled')
ROLES = ('viewer', 'operator', 'admin')
COLUMNS = (('id', 'ID', 50), ('email', 'Email', 230), ('full_name', 'Name', 170),
           ('role', 'Role', 80), ('status', 'Status', 140), ('verified', 'Email verified', 110),
           ('locked', 'Lock', 230))
PERMANENT_STATUS = 'locked_by_security'
ACTION_STATUS = {'Approved': 'active', 'Rejected': 'rejected', 'Disabled': 'disabled'}


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
        for key, title, width in COLUMNS:
            self.tree.heading(key, text=title)
            self.tree.column(key, width=width, anchor='w')
        self.tree.pack(fill='both', expand=True, pady=theme.PAD)

        actions = ttk.Frame(self)
        actions.pack(fill='x')
        ttk.Label(actions, text='Approve as:').pack(side='left')
        self.role = tk.StringVar(value='viewer')
        ttk.Combobox(actions, textvariable=self.role, values=ROLES, state='readonly',
                     width=10).pack(side='left', padx=theme.PAD)
        self.approve_btn = ttk.Button(actions, text='Approve', style='Accent.TButton',
                                      command=self.approve)
        self.reject_btn = ttk.Button(actions, text='Reject', command=self.reject)
        self.disable_btn = ttk.Button(actions, text='Disable', command=self.disable)
        self.unlock_btn = ttk.Button(actions, text='Unlock', command=self.unlock)
        for b in (self.approve_btn, self.reject_btn, self.disable_btn, self.unlock_btn):
            b.pack(side='left', padx=(0, 6))

        roles = ttk.Frame(self)
        roles.pack(fill='x', pady=(theme.PAD, 0))
        ttk.Label(roles, text='Change role to:').pack(side='left')
        self.new_role = tk.StringVar(value='operator')
        ttk.Combobox(roles, textvariable=self.new_role, values=ROLES, state='readonly',
                     width=10).pack(side='left', padx=theme.PAD)
        self.change_role_btn = ttk.Button(roles, text='Change role', command=self.change_role)
        self.change_role_btn.pack(side='left')
        self.status = ttk.Label(self, text='', wraplength=700, justify='left')
        self.status.pack(anchor='w', pady=(theme.PAD, 0))

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
            self.tree.delete(*self.tree.get_children())
            self.rows = {}
            for u in users:
                iid = str(u['id'])
                self.rows[iid] = u
                status = PERMANENT_STATUS if u.get('security_lock') == 'permanent' \
                    else u.get('status', '')
                self.tree.insert('', 'end', iid=iid, values=(
                    u['id'], u.get('email', ''), u.get('full_name', ''), u.get('role', ''),
                    status, 'yes' if u.get('email_verified_at') else 'no', lock_text(u)))
            self.say(note or (f'{len(users)} account(s).' if users else 'No accounts to show.'))
        self._call(lambda token: client.list_users(token, status=status), ok)

    def _act(self, verb, call, confirm=None):
        user = self.selected()
        if not user:
            self.say('Select an account first.', error=True)
            return
        if confirm and not messagebox.askyesno(f'{verb} account', confirm.format(**user),
                                               parent=self):
            return

        def ok(_result):
            log_event('accounts', f"Account {mask_email(user.get('email', ''))}: {verb.lower()}, "
                                  f"status {user.get('status') or '?'} -> {ACTION_STATUS.get(verb, '?')}"
                                  f' (by {self._me()}): SUCCESSFUL.', 'ok', tags=['change'])
            self.refresh(note=f"{verb}: {user.get('email', user['id'])}.")
        self._call(lambda token: call(token, user['id']), ok)

    def _me(self):
        return mask_email(getattr(self.account.session, 'email', '') or '')

    def approve(self):
        role, client = self.role.get(), self.account.client
        self._act('Approved', lambda token, uid: client.approve_user(token, uid, role))

    def reject(self):
        client = self.account.client
        self._act('Rejected', client.reject_user,
                  confirm='Reject the account {email}? It will not be able to sign in.')

    def change_role(self):
        """Change the selected account's role after an explicit confirmation. The server
        decides (admins only, never one's own role, never the last active admin); this
        only asks first and shows the answer."""
        user = self.selected()
        if not user:
            self.say('Select an account first.', error=True)
            return
        if user['id'] == self.account.session.user_id:
            self.say('You cannot change your own role. Ask another administrator.', error=True)
            return
        old, new = user.get('role', ''), self.new_role.get()
        if new not in ROLES:
            self.say('Choose a role.', error=True)
            return
        if new == old:
            self.say(f"{user.get('email', user['id'])} already has the role {new}.")
            return
        if not messagebox.askyesno(
                'Change role',
                f"Change the role of {user.get('email', user['id'])} from {old} to {new}?\n\n"
                f'The account is signed out everywhere and must sign in again to get the '
                f'new permissions.', parent=self):
            self.say('Role not changed.')
            return
        client = self.account.client

        def ok(result):
            log_event('accounts', f"Account {mask_email(user.get('email', ''))}: role changed "
                                  f"{result['previous_role']} -> {result['role']} (by "
                                  f'{self._me()}; signed out everywhere): SUCCESSFUL.', 'ok',
                      tags=['change'])
            self.refresh(note=f"Role changed: {user.get('email', user['id'])} is now "
                              f"{result['role']} (was {result['previous_role']}); signed out "
                              f"everywhere.")
        self._call(lambda token: client.change_role(token, user['id'], new), ok)

    def disable(self):
        client = self.account.client
        self._act('Disabled', client.disable_user,
                  confirm='Disable the account {email}? It is signed out everywhere and '
                          'can no longer sign in.')

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
            log_event('security', f"Unlock of {target} SUCCESSFUL ({result.get('cleared') or 'no'} "
                                  f'lock cleared by administrator {me}).', 'ok', tags=['change'])
            self.refresh(note=f"Unlocked: {user.get('email', user['id'])}.")
        self._call(lambda token: client.unlock_user(token, user['id']), ok)
