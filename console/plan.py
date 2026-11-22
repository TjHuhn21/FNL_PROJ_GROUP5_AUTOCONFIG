"""SSH configuration PREVIEW for a detected device (Console-Based SSH Auto-Setup, phase 4).

    request, errors = validate_request(hostname, domain, username, password, confirm,
                                       key_size, result)
    plan = build_plan(result, request)       # a ConfigPlan; nothing is sent anywhere
    plan.lines()                             # the proposed commands, in order

This module only PLANS. It sends nothing to a device, has no access to a console
session, and there is no "apply" here.

Passwords: validate_request() checks the password and then drops it. The SetupRequest
and the ConfigPlan only know WHETHER a password was given; every proposed command shows
the placeholder <SSH_PASSWORD> instead, so no plan can be pasted into a device as is.

The plan looks at what the device already has (detection results), proposes only what is
missing, and never:
  * replaces an existing local account or its password,
  * regenerates an existing RSA key pair (or generates one when it is unknown whether one
    exists),
  * changes AAA,
  * proposes `login local` when no privilege-15 local account exists or is being added
    (that would lock everybody out of the VTY lines),
  * invents a hostname, domain name or IP address.
Changes to existing settings are marked as modifications, and the ones that can cut off
current users (Telnet removed, line-password logins replaced) as disruptive.

Commands are proposed only for classic IOS and IOS-XE devices whose SSH state is
SUPPORTED_ENABLED or SUPPORTED_DISABLED, detected completely at privilege level 15.
"""
import re
from dataclasses import dataclass, field
from datetime import datetime

import validation
from console import detect
from console.detect import SshCapability

PASSWORD_PLACEHOLDER = '<SSH_PASSWORD>'
PREVIEW_NOTICE = 'Preview only — no configuration commands have been sent to the device.'
DEFAULT_HOSTNAMES = ('Router', 'Switch')       # IOS will not generate RSA keys with these
# Key labels that belong to something other than SSH: IOS / IOS-XE create a
# "TP-self-signed-<number>" key for the HTTPS server's self-signed certificate.
NON_SSH_KEY_PREFIXES = ('TP-self-signed',)
MIN_SSH2_KEY_BITS = 768                        # "of atleast 768 bits for SSH v2" (show ip ssh)
KEY_SIZES = {'IOS': (1024, 2048), 'IOS-XE': (2048, 4096)}
DEFAULT_KEY_SIZE = 2048
NEW_USER_PRIVILEGE = 15

# item statuses
CONFIGURED, MISSING, ATTENTION = 'configured', 'missing', 'needs_attention'
CONFLICT, UNKNOWN, UNSUPPORTED = 'conflict', 'unknown', 'unsupported'
STATUS_TEXT = {CONFIGURED: 'Already configured', MISSING: 'Missing',
               ATTENTION: 'Needs attention', CONFLICT: 'Conflict detected',
               UNKNOWN: 'Unknown', UNSUPPORTED: 'Unsupported'}
_SEVERITY = {CONFIGURED: 0, MISSING: 1, UNKNOWN: 2, ATTENTION: 3, UNSUPPORTED: 4, CONFLICT: 5}
# command kinds
ADD, MODIFY = 'add', 'modify'

_USERNAME = re.compile(r'^[A-Za-z][A-Za-z0-9._-]{0,31}$')
_DOMAIN = re.compile(r'^(?=.{1,253}$)[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?'
                     r'(\.[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?)*$')
PASSWORD_MIN, PASSWORD_MAX = 8, 64


# ---------------------------------------------------------------- input
@dataclass(frozen=True)
class SetupRequest:
    """What the user wants. Never holds a password: only whether one was given."""
    hostname: str = ''
    domain_name: str = ''
    username: str = ''
    password_set: bool = False
    key_size: int = DEFAULT_KEY_SIZE


def key_sizes(result):
    """RSA key sizes offered for this device's software (empty: no keys can be planned)."""
    return KEY_SIZES.get(result.device.software, ()) if result is not None else ()


def check_password(password, confirm):
    """None, or a message (never containing the password)."""
    if not password:
        return 'Enter a password for the new SSH account.'
    if password != confirm:
        return 'The two passwords do not match.'
    if not PASSWORD_MIN <= len(password) <= PASSWORD_MAX:
        return f'The password must be {PASSWORD_MIN} to {PASSWORD_MAX} characters long.'
    if any(not (32 <= ord(c) <= 126) for c in password):
        return 'Use only letters, numbers, spaces and common symbols (no accents or tabs).'
    if password != password.strip():
        return 'The password must not start or end with a space.'
    if '?' in password:
        return 'The password must not contain "?" (Cisco IOS treats it as a help request).'
    return None


def validate_request(hostname='', domain_name='', username='', password='', confirm='',
                     key_size=DEFAULT_KEY_SIZE, result=None):
    """(SetupRequest, {field: message}). Empty fields mean "keep what the device has".
    The password is checked here and not kept anywhere."""
    errors = {}
    hostname, domain_name, username = (hostname or '').strip(), (domain_name or '').strip(), \
        (username or '').strip()
    if hostname:
        problem = validation.check_hostname(hostname)
        if problem:
            errors['hostname'] = problem
        elif hostname in DEFAULT_HOSTNAMES:
            errors['hostname'] = (f'"{hostname}" is the factory default; IOS will not create RSA '
                                  f'keys with it. Choose another name.')
    if domain_name and not _DOMAIN.match(domain_name):
        errors['domain_name'] = ('The domain name may use letters, numbers, dashes and dots '
                                 '(for example lab.local).')
    if username:
        if not _USERNAME.match(username):
            errors['username'] = ('The username must start with a letter and use at most 32 '
                                  'letters, numbers, dots, dashes or underscores.')
        else:
            problem = check_password(password, confirm)
            if problem:
                errors['password'] = problem
    elif password or confirm:
        errors['username'] = 'Enter the username for this password, or clear the password.'
    try:
        size = int(key_size)
    except (TypeError, ValueError):
        size = None
    allowed = key_sizes(result) if result is not None else (1024, 2048, 4096)
    if size is None or (allowed and size not in allowed):
        errors['key_size'] = ('Choose an RSA key size offered for this device: '
                              f'{", ".join(map(str, allowed)) or "none"}.')
    request = SetupRequest(hostname=hostname, domain_name=domain_name, username=username,
                           password_set=bool(username and password and 'password' not in errors),
                           key_size=size or DEFAULT_KEY_SIZE)
    return request, errors


# ---------------------------------------------------------------- output
@dataclass
class PlanCommand:
    text: str                     # with <SSH_PASSWORD> instead of a password
    purpose: str                  # plain-language reason
    kind: str = ADD               # add (safe addition) / modify (changes an existing setting)
    disruptive: bool = False      # can cut off current users
    mode: str = None              # None = global configuration, else e.g. 'line vty 0 4'
    setting: str = ''
    step_id: str = ''             # the console.steps.PlanStep that describes this command


@dataclass
class PlanItem:
    key: str
    title: str
    status: str
    current: str
    explanation: str
    commands: list = field(default_factory=list)


@dataclass
class ConfigPlan:
    available: bool
    reason: str
    hostname: str = None
    software: str = None
    ssh_status: SshCapability = SshCapability.UNKNOWN
    simulated: bool = False
    detected_at: object = None
    created_at: object = None
    items: list = field(default_factory=list)
    warnings: list = field(default_factory=list)
    limitations: list = field(default_factory=list)
    notice: str = PREVIEW_NOTICE
    # console.steps: one PlanStep per command (plus read-only check steps), in order, with
    # dependencies and verification definitions; invariants = settings that must not change.
    # Definitions only: nothing in this version runs them.
    steps: list = field(default_factory=list)
    invariants: list = field(default_factory=list)

    def step(self, step_id):
        return next((s for s in self.steps if s.step_id == step_id), None)

    @property
    def commands(self):
        return [c for item in self.items for c in item.commands]

    @property
    def additions(self):
        return [c for c in self.commands if c.kind == ADD]

    @property
    def modifications(self):
        return [c for c in self.commands if c.kind == MODIFY]

    @property
    def conflicts(self):
        return [i for i in self.items if i.status == CONFLICT]

    @property
    def unknowns(self):
        return [i for i in self.items if i.status == UNKNOWN]

    def item(self, key):
        return next((i for i in self.items if i.key == key), None)

    def lines(self):
        """The proposed commands in order, with the configuration-mode lines around them.
        Saving (write memory) is never part of a preview."""
        if not self.commands:
            return []
        out = ['configure terminal']
        globals_ = [c for c in self.commands if c.mode is None]
        out += [c.text for c in sorted(globals_, key=lambda c: _ORDER.index(c.setting))]
        modes = []
        for c in self.commands:
            if c.mode and c.mode not in modes:
                modes.append(c.mode)
        for mode in modes:
            out.append(mode)
            out += [' ' + c.text for c in self.commands if c.mode == mode]
        out.append('end')
        return out

    def text(self):
        return '\n'.join(self.lines())


_ORDER = ['hostname', 'domain', 'user', 'rsa', 'ssh_version', 'vty_login', 'vty_transport']


# ---------------------------------------------------------------- building the plan
def _availability(result):
    """None when commands may be proposed, else why not (and the status to show)."""
    d, s = result.device, result.ssh
    if not result.complete:
        return ('Detection did not finish (the console session ended), so the configuration '
                'is not fully known. Detect the device again.'), UNKNOWN
    if s.status == SshCapability.UNSUPPORTED:
        return ('The detected software appears not to support SSH (a crypto / K9 image would '
                'be needed). No SSH commands are proposed.'), UNSUPPORTED
    if s.status == SshCapability.UNKNOWN:
        return ('NetCommand could not determine whether this device supports SSH, so it does '
                'not propose commands that might not work. See the detection evidence; '
                'detecting in privileged mode may help.'), UNKNOWN
    if d.software not in KEY_SIZES:
        return (f'Configuration previews are only available for Cisco IOS and IOS-XE '
                f'(detected: {d.software or "not recognised"}).'), UNSUPPORTED
    if result.access.privilege_level is None:
        return ('The privilege level could not be read ("show privilege" did not work), so '
                'NetCommand cannot confirm that the whole configuration was visible: settings '
                'that seem missing might only be hidden. No commands are proposed. Detect again '
                '(in privileged mode if needed).'), UNKNOWN
    if result.access.privilege_level != 15:
        return (f'The configuration was read at privilege level '
                f'{result.access.privilege_level}; only level 15 shows all of it, so settings '
                f'that seem missing might only be hidden. No commands are proposed. Connect in '
                f'privileged mode and detect again.'), UNKNOWN
    return None, None


def build_plan(result, request=None):
    """A ConfigPlan from a DetectionResult and a SetupRequest. Sends nothing."""
    request = request or SetupRequest()
    plan = ConfigPlan(available=True, reason='', hostname=result.device.hostname,
                      software=result.device.software, ssh_status=result.ssh.status,
                      simulated=result.simulated, detected_at=result.detected_at,
                      created_at=datetime.now())
    ctx = _Context(result, request)
    plan.items = [ctx.hostname(), ctx.domain(), ctx.user(), ctx.rsa(), ctx.ssh_version(),
                  ctx.ssh_settings(), ctx.ssh_other(), ctx.aaa(), ctx.vty_login(),
                  ctx.vty_transport(), ctx.management()]
    reason, status = _availability(result)
    if reason:
        plan.available, plan.reason = False, reason
        for item in plan.items:
            if item.commands:
                item.commands = []
                item.explanation = 'No command is proposed (see why above).'
            if status == UNSUPPORTED and item.key in ('rsa', 'ssh_version'):
                item.status = UNSUPPORTED
                item.explanation = 'Not available: the software appears not to support SSH.'
    else:
        plan.reason = ('Commands are proposed only for what is missing. Review every line; '
                       'nothing is sent in this version.')
    if plan.simulated:
        plan.warnings.append('SIMULATED device: this plan was made for the NetCommand mock '
                             'lab, not for physical hardware.')
    odd = [c.command for c in result.commands if c.status == detect.UNEXPECTED]
    if odd:
        plan.warnings.append('Some answers did not look like answers to their command ('
                             + '; '.join(odd) + '). What they read is treated as unknown, '
                             'never as "not configured", and nothing depending on it is proposed.')
    if result.ssh.rsa.present and result.ssh.enabled is not True:
        plan.warnings.append('RSA keys exist (' + ', '.join(result.ssh.rsa.key_names) + '), but '
                             'SSH is not reported as enabled. Existing keys are not proof that '
                             'SSH is ready; see "RSA key pair for SSH".')
    if plan.commands:
        plan.warnings.append('Keep the console cable connected until SSH has been tested: if '
                             'a VTY change goes wrong, the console still works.')
    plan.limitations = [
        'Saving the configuration (write memory) is not part of the preview.',
        'The plan is based on the detection shown; if the device was changed since, detect '
        'again.',
        'RSA key sizes offered are a conservative choice per software family; the exact limits '
        'depend on the IOS release and have not been checked on hardware.',
        'Not yet tested on a physical router or switch.',
    ]
    if any(i.key == 'rsa' and i.commands for i in plan.items):
        plan.limitations.append('IOS turns SSH on by itself once an RSA key pair exists; key '
                                'generation can take up to a minute on older routers.')
    if plan.available and plan.commands:
        from console.steps import build_steps
        plan.steps, plan.invariants = build_steps(
            plan, result, request, ctx._ssh_key_name(request.hostname, request.domain_name))
    return plan


class _Context:
    def __init__(self, result, request):
        self.r, self.q = result, request
        self.d, self.s, self.v, self.c = result.device, result.ssh, result.vty, result.config
        self.xe = result.device.software == 'IOS-XE'
        self.admins = [u for u in self.c.local_users if u.privilege == NEW_USER_PRIVILEGE]
        names = {u.name for u in self.c.local_users}
        self.new_user = bool(request.username and request.password_set
                             and request.username not in names and self.c.local_users_known)
        # `login local` is proposed only together with a NEW account in this plan: an existing
        # account is not evidence that the operator knows its password (no lockout).
        self.login_account = self.new_user
        self.keys_planned = False          # set by rsa(), which runs before ssh_version()
        self.key_state = self._key_state()
        self.vty_total, self.vty_uncovered = self._vty_coverage()

    # ------------------------------------------------------------ which RSA key is SSH's
    def _ssh_key_name(self, hostname=None, domain=None):
        """The key label IOS uses for SSH: 'ip ssh rsa keypair-name', else hostname.domain."""
        if self.c.ssh_keypair_name:
            return self.c.ssh_keypair_name
        host = hostname or self.d.hostname
        dom = domain or self.c.domain_name
        return f'{host}.{dom}' if host and dom else None

    def _key_state(self):
        """'ssh' (a key SSH uses or would use exists), 'none' (no key at all), 'other' (only
        HTTPS self-signed keys), or 'unknown' (keys exist; the output does not show whether
        SSH uses them, or the key list could not be read)."""
        rsa = self.s.rsa
        if rsa.present is None:
            return 'unknown'
        if not rsa.present:
            return 'none'
        names = rsa.key_names
        secsh = self.c.ssh_secsh_key
        if self.s.enabled is True or (secsh and secsh != 'NONE' and secsh in names):
            return 'ssh'
        if self._ssh_key_name() in names:
            return 'ssh'
        if names and all(n.startswith(NON_SSH_KEY_PREFIXES) for n in names):
            return 'other'
        return 'unknown'

    # ------------------------------------------------------------ VTY coverage
    def _vty_coverage(self):
        """(lines on the device per show line or None, uncovered line numbers or None)."""
        total = self.v.available_lines
        if not total:
            return None, None
        covered = set()
        for block in self.v.blocks:
            a, *b = (int(x) for x in block.lines.split())
            covered.update(range(a, (b[0] if b else a) + 1))
        return total, sorted(set(range(total)) - covered)

    # ------------------------------------------------------------ identity
    def _mark_ssh_rename_risk(self, item, what):
        """A rename while SSH is running: the default SSH key is named hostname.domain, so
        renaming may affect the key SSH uses (exact IOS behaviour unverified on hardware).
        The change is marked disruptive; a future execution phase must ask for a separate
        approval before sending it."""
        if self.s.enabled is not True:
            return
        for command in item.commands:
            command.disruptive = True
        item.status = _worse(item.status, ATTENTION)
        item.explanation += (f' SSH is running now: changing the {what} may affect the RSA key '
                             f'SSH uses (its default name is hostname.domain) and so active or '
                             f'future SSH sessions. This needs a separate approval; how IOS '
                             f'behaves here has not been checked on hardware.')

    def hostname(self):
        cur, want = self.d.hostname, self.q.hostname
        item = PlanItem('hostname', 'Hostname', CONFIGURED, cur or 'unknown', '')
        if want and want != cur:
            item.status = MISSING if cur in DEFAULT_HOSTNAMES else ATTENTION
            item.commands.append(PlanCommand(
                f'hostname {want}', 'Gives the device its name. IOS needs a name other than '
                'Router/Switch before it can create RSA keys.' if cur in DEFAULT_HOSTNAMES else
                'Renames the device: the prompt changes, and NetCommand will show the new name.',
                kind=MODIFY, setting='hostname'))
            item.explanation = f'Will change from {cur or "unknown"} to {want}.'
            self._mark_ssh_rename_risk(item, 'hostname')
        elif cur in DEFAULT_HOSTNAMES:
            item.status = ATTENTION
            item.explanation = ('The device still has its factory name. IOS will not create RSA '
                                'keys until it has another name: enter a hostname.')
        elif cur is None:
            item.status, item.explanation = UNKNOWN, 'The hostname could not be read.'
        else:
            item.explanation = 'Kept as it is.'
        return item

    def domain(self):
        cur, want, known = self.c.domain_name, self.q.domain_name, self.c.domain_known
        needs = self.s.rsa.present is False
        item = PlanItem('domain', 'Domain name', CONFIGURED,
                        cur or ('none configured' if known else 'unknown'), '')
        command = f'ip domain name {want}' if self.xe else f'ip domain-name {want}'
        if cur:
            if want and want != cur:
                item.status = ATTENTION
                item.commands.append(PlanCommand(command, 'Replaces the domain name. Existing RSA '
                                                 'keys keep their current name.', kind=MODIFY,
                                                 setting='domain'))
                item.explanation = f'Will change from {cur} to {want}.'
                self._mark_ssh_rename_risk(item, 'domain name')
            else:
                item.explanation = 'Kept as it is.'
        elif known:
            if want:
                item.status = MISSING
                item.commands.append(PlanCommand(command, 'Sets the domain name; IOS uses it '
                                                 'with the hostname to name the RSA keys.',
                                                 setting='domain'))
                item.explanation = 'Not configured; will be added.'
            elif needs:
                item.status = ATTENTION
                item.explanation = ('Needed to create the RSA keys. Enter one (for example your '
                                    'lab\'s domain); NetCommand never invents it.')
            else:
                item.status = MISSING
                item.explanation = 'Not configured; not needed because RSA keys already exist.'
        else:
            item.status = UNKNOWN
            item.explanation = 'Could not be read.'
            if want:
                item.commands.append(PlanCommand(command, 'Sets the domain name (the current '
                                                 'value is unknown and would be replaced).',
                                                 kind=MODIFY, setting='domain'))
        return item

    # ------------------------------------------------------------ account
    def user(self):
        users, known, want = self.c.local_users, self.c.local_users_known, self.q.username
        listing = ', '.join(f'{u.name} (privilege {u.privilege if u.privilege is not None else "1, default"})'
                            for u in users) or ('none' if known else 'unknown')
        item = PlanItem('user', 'Local SSH account', CONFIGURED, listing, '')
        existing = next((u for u in users if u.name == want), None) if want else None
        if existing:
            item.status = CONFLICT
            item.explanation = (f'An account named {want} already exists. NetCommand never '
                                f'changes existing accounts or their passwords: choose another '
                                f'username, or leave it empty to use the existing account.')
        elif want and not known:
            item.status = UNKNOWN
            item.explanation = ('The local accounts could not be fully read, so a new account '
                                'is not proposed (it might replace one that exists).')
        elif want and not self.q.password_set:
            item.status = ATTENTION
            item.explanation = 'Enter a password for the new account.'
        elif want:
            item.status = MISSING
            item.commands.append(PlanCommand(
                f'username {want} privilege {NEW_USER_PRIVILEGE} secret {PASSWORD_PLACEHOLDER}',
                'Creates the account used to log in over SSH, with full rights; "secret" stores '
                'the password hashed. The password is not shown here.', setting='user'))
            item.explanation = f'A new account {want} will be added' + (
                ' (existing accounts are kept unchanged).' if users else '.')
        elif self.admins:
            item.explanation = ('Existing privilege-15 account(s): '
                                + ', '.join(u.name for u in self.admins)
                                + ' (passwords not shown or changed). NetCommand cannot tell '
                                  'whether you know their passwords, so it proposes changing the '
                                  'VTY login only together with a new account.')
        elif known and users:
            item.status = ATTENTION
            item.explanation = ('No local account has privilege 15. Enter a username and password '
                                'to add one.')
        elif known:
            item.status = MISSING
            item.explanation = 'No local account exists. Enter a username and password to add one.'
        else:
            item.status, item.explanation = UNKNOWN, 'The local accounts could not be read.'
        return item

    # ------------------------------------------------------------ keys and SSH
    def rsa(self):
        rsa, state = self.s.rsa, self.key_state
        item = PlanItem('rsa', 'RSA key pair for SSH', CONFIGURED, '', '')
        if rsa.present is None:
            item.status, item.current = UNKNOWN, 'unknown'
            item.explanation = ('The keys could not be read. No key generation is proposed: it '
                                'could replace keys that already exist.')
            return item
        if rsa.present:
            size = f', {rsa.modulus_bits} bits' if rsa.modulus_bits else ', size not shown'
            item.current = f'present ({", ".join(rsa.key_names)}{size})'
        if state == 'ssh':
            if rsa.modulus_bits and rsa.modulus_bits < MIN_SSH2_KEY_BITS:
                item.status = CONFLICT
                item.explanation = (f'The key has {rsa.modulus_bits} bits; SSH version 2 needs at '
                                    f'least {MIN_SSH2_KEY_BITS}. NetCommand does not replace keys '
                                    f'automatically (replacing them changes the device identity '
                                    f'SSH clients remember).')
            elif self.s.enabled is True:
                item.explanation = 'SSH is running with these keys. Kept: never regenerated.'
            else:
                item.status = ATTENTION
                item.explanation = (f'A key SSH would use exists ({self._ssh_key_name() or "named by show ip ssh"}), '
                                    f'but show ip ssh does not report SSH as enabled. NetCommand '
                                    f'never regenerates existing keys; check this by hand.')
            return item
        if state == 'unknown':
            item.status = UNKNOWN
            item.explanation = ('RSA keys exist, but the output does not show whether SSH uses '
                                'them (SSH is not reported as enabled, and no key has the name '
                                f'SSH would use: {self._ssh_key_name() or "hostname.domain unknown"}). '
                                'No key generation is proposed: it could duplicate or replace '
                                'keys.')
            return item
        if self.c.ssh_keypair_name:
            item.status = UNKNOWN
            item.explanation = (f'SSH is set to use the key "{self.c.ssh_keypair_name}" '
                                f'(ip ssh rsa keypair-name), which was not found. A generated key '
                                f'would get another name, so none is proposed; check this by hand.')
            return item
        if state == 'other':
            note = ('Only HTTPS self-signed key(s) exist (' + ', '.join(rsa.key_names) + '); SSH '
                    'does not use them. ')
        else:
            item.current = 'none'
            note = ''
        new_name = self._ssh_key_name(self.q.hostname, self.q.domain_name)
        if new_name and new_name in rsa.key_names:
            item.status = UNKNOWN
            item.explanation = note + f'A key named {new_name} already exists; not regenerated.'
            return item
        blockers = []
        name = self.q.hostname or self.d.hostname
        if not name or name in DEFAULT_HOSTNAMES:
            blockers.append('a hostname other than Router/Switch')
        if not (self.c.domain_name or self.q.domain_name):
            blockers.append('a domain name')
        if blockers:
            item.status = ATTENTION
            item.explanation = note + 'Keys cannot be created until the device has ' + \
                ' and '.join(blockers) + '.'
            return item
        item.status = MISSING
        self.keys_planned = True
        item.commands.append(PlanCommand(
            f'crypto key generate rsa modulus {self.q.key_size}',
            f'Creates the {self.q.key_size}-bit RSA key pair SSH needs. IOS turns SSH on as soon '
            f'as the keys exist.', setting='rsa'))
        item.explanation = note + ('No SSH key yet; one will be created.' if note else
                                   'No keys yet; they will be created.')
        return item

    def ssh_version(self):
        configured, shown = self.c.ssh_version_configured, self.s.version
        item = PlanItem('ssh_version', 'SSH version 2 only', CONFIGURED,
                        f'configured: {configured or "not set"}; reported: {shown or "unknown"}', '')
        if configured == '2':
            item.explanation = 'Already restricted to version 2.'
            return item
        small = self.s.rsa.modulus_bits and self.s.rsa.modulus_bits < MIN_SSH2_KEY_BITS
        if small:
            item.status = CONFLICT
            item.explanation = 'Needs a key of at least 768 bits (see RSA key pair).'
            return item
        item.status = ATTENTION if configured == '1' else (MISSING if self.c.ssh_lines_known
                                                           else UNKNOWN)
        if not (self.s.enabled is True or self.keys_planned):
            item.status = ATTENTION
            item.explanation = ('Proposed only when SSH is running or its key is created in this '
                                'plan (SSH version 2 needs an RSA key of at least 768 bits).')
            return item
        item.commands.append(PlanCommand(
            'ip ssh version 2', 'Allows only SSH version 2 (version 1 is outdated and insecure).',
            kind=MODIFY if configured == '1' else ADD, setting='ssh_version'))
        item.explanation = ('Version 1 is configured; will change to 2.' if configured == '1'
                            else 'Not restricted to version 2 yet.')
        return item

    def ssh_settings(self):
        t, r = self.c.ssh_timeout, self.c.ssh_retries
        item = PlanItem('ssh_settings', 'SSH timeout and retries',
                        CONFIGURED if t is not None else UNKNOWN,
                        f'timeout {t} s, {r} retries' if t is not None else 'unknown',
                        'Shown for information; not changed.')
        return item

    def ssh_other(self):
        """'ip ssh' settings the planner does not examine (source-interface, ...)."""
        c = self.c
        item = PlanItem('ssh_other', 'Other SSH settings', CONFIGURED, '', '')
        if not c.ssh_lines_known:
            item.status, item.current = UNKNOWN, 'unknown'
            item.explanation = 'The "ip ssh" configuration lines could not be read.'
            return item
        shown = list(c.ssh_other_lines)
        if c.ssh_keypair_name:
            shown.insert(0, f'ip ssh rsa keypair-name {c.ssh_keypair_name}')
        item.current = '; '.join(shown) or 'none'
        if c.ssh_other_lines:
            item.status = UNKNOWN
            item.explanation = ('These settings are outside what this preview examines; they are '
                                'kept as they are, and their effect on SSH is not checked.')
        else:
            item.explanation = ('No other "ip ssh" settings.' if not c.ssh_keypair_name else
                                'The key name SSH uses is taken into account above.')
        return item

    def aaa(self):
        c = self.c
        if c.aaa_new_model:
            lists = '; '.join(f'{k}: {v}' for k, v in c.aaa_login_lists.items()) or \
                'no login method list shown'
            return PlanItem('aaa', 'AAA (central login control)', ATTENTION, f'on ({lists})',
                            'AAA decides how VTY logins are checked, so "login local" on the '
                            'lines would have no effect. NetCommand does not change AAA; make '
                            'sure its login method list includes the account you will use.')
        if c.aaa_known:
            return PlanItem('aaa', 'AAA (central login control)', CONFIGURED, 'not enabled',
                            'Not used; the VTY lines use their own login setting.')
        return PlanItem('aaa', 'AAA (central login control)', UNKNOWN, 'unknown',
                        'Could not be read, so the VTY login is not changed.')

    # ------------------------------------------------------------ VTY lines
    def _blocks(self):
        """[(range, login, transport list, new, has_password)] for the ranges that exist in
        the configuration. With no VTY lines configured at all, one new range covering the
        lines `show line` reports; none when that number is unknown (never invented)."""
        if self.v.configured is False:
            if not self.vty_total:
                return []
            last = self.vty_total - 1
            return [(f'0 {last}' if last else '0', None, None, True, False)]
        return [(b.lines, b.login, b.transport_input, False, b.has_password)
                for b in self.v.blocks]

    def _coverage_note(self):
        """(status, sentence) about VTY lines outside the configured ranges, or (None, '')."""
        if self.v.configured is None:
            return None, ''
        if self.vty_total is None:
            return UNKNOWN, ('The number of VTY lines could not be read (show line), so lines '
                             'outside the ranges shown may exist; they are not checked or changed.')
        if self.v.configured is False or not self.vty_uncovered:
            return None, ''
        missing = _ranges(self.vty_uncovered)
        return ATTENTION, (f'show line reports {self.vty_total} VTY lines, but vty {missing} '
                           f'{"is" if len(self.vty_uncovered) == 1 else "are"} not in the '
                           f'configuration that was read: their login and protocols are unknown '
                           f'and NOT changed by this plan. Do not assume they are secure; check '
                           f'them by hand.')

    def vty_login(self):
        item = PlanItem('vty_login', 'VTY login', CONFIGURED, '', '')
        if self.v.configured is None:
            item.status, item.current = UNKNOWN, 'unknown'
            item.explanation = 'The VTY configuration could not be read.'
            return item
        item.current = '; '.join(f'vty {lines}: {login or "no login line shown"}'
                                 for lines, login, _t, _n, _p in self._blocks()) or 'none'
        cover_status, cover_note = self._coverage_note()
        if self.c.aaa_new_model:
            ok = all((login or '').startswith('authentication') for _l, login, _t, _n, _p in
                     self._blocks())
            item.status = CONFIGURED if ok else ATTENTION
            item.explanation = ('Logins are controlled by AAA; not changed.' if ok else
                                'Logins are controlled by AAA; the line settings are not changed.')
            if cover_status:
                item.status = _worse(item.status, cover_status)
                item.explanation += ' ' + cover_note
            return item
        if not self.c.aaa_known:
            item.status = UNKNOWN
            item.explanation = 'Whether AAA is on is unknown, so the login is not changed.'
            return item
        notes, worst = [], CONFIGURED
        if self.v.configured is False and not self._blocks():
            worst = UNKNOWN
            notes.append('No VTY lines are configured and their number is unknown, so no range '
                         'is proposed.')
        for lines, login, _t, new, has_password in self._blocks():
            mode = f'line vty {lines}'
            if login == 'local':
                if not self.c.local_users and self.c.local_users_known:
                    if self.new_user:
                        worst = _worse(worst, ATTENTION)
                        notes.append(f'vty {lines} asks for a local account, but none exists yet: '
                                     f'nobody can log in over the network now. The new account '
                                     f'fixes this.')
                    else:
                        worst = _worse(worst, CONFLICT)
                        notes.append(f'vty {lines} asks for a local account, but none exists: '
                                     f'nobody can log in over the network now. Add an account.')
                continue
            if (login or '').startswith('authentication'):
                worst = _worse(worst, CONFLICT)
                notes.append(f'vty {lines} uses an AAA login list, but AAA is not on. Not changed; '
                             f'check this configuration by hand.')
                continue
            if not self.login_account:
                worst = _worse(worst, ATTENTION)
                if self.admins:
                    notes.append(f'vty {lines}: "login local" is NOT proposed. Existing account(s) '
                                 f'({", ".join(u.name for u in self.admins)}) are not enough: '
                                 f'NetCommand cannot tell whether you know their passwords, and '
                                 f'switching would lock you out if you do not. Add a new account '
                                 f'in this plan to change the login.')
                else:
                    notes.append(f'vty {lines}: "login local" is NOT proposed because no new '
                                 f'privilege-15 account is being added (it would lock everybody '
                                 f'out). Add an account above.')
                continue
            disruptive = False
            if new:
                worst = _worse(worst, MISSING)
                text = f'No VTY lines are configured; vty {lines} will be set up.'
            elif login is None:
                worst = _worse(worst, UNKNOWN)
                text = f'vty {lines} shows no login line; "login local" will be set explicitly.'
            elif login == 'line password' and not has_password:
                worst = _worse(worst, ATTENTION)
                text = (f'vty {lines} asks for a line password, but none is set, so nobody can log '
                        f'in there now; it will ask for a local account.')
            elif login == 'line password':
                worst = _worse(worst, ATTENTION)
                disruptive = True
                text = (f'vty {lines} uses the line password; it will ask for a local account '
                        f'instead (people using the line password must use the new account).')
            else:                                                     # 'none'
                worst = _worse(worst, ATTENTION)
                disruptive = True
                text = (f'vty {lines} asks for no login at all; it will ask for a local account '
                        f'(anyone connecting now without a login will be asked for one).')
            notes.append(text)
            item.commands.append(PlanCommand(
                'login local', 'Asks for a local username and password on these lines.',
                kind=ADD if new or login is None else MODIFY,
                disruptive=disruptive, mode=mode, setting='vty_login'))
        if cover_status:
            worst = _worse(worst, cover_status)
            notes.append(cover_note)
        item.status = worst
        item.explanation = ' '.join(notes) or 'Every VTY line already asks for a local account.'
        return item

    def vty_transport(self):
        item = PlanItem('vty_transport', 'VTY protocols (SSH/Telnet)', CONFIGURED, '', '')
        if self.v.configured is None:
            item.status, item.current = UNKNOWN, 'unknown'
            item.explanation = 'The VTY configuration could not be read.'
            return item
        item.current = '; '.join(f'vty {lines}: {" ".join(t) if t else "not shown"}'
                                 for lines, _l, t, _n, _p in self._blocks()) or 'none'
        notes, worst = [], CONFIGURED
        if self.v.configured is False and not self._blocks():
            worst = UNKNOWN
            notes.append('No VTY lines are configured and their number is unknown, so no range '
                         'is proposed.')
        for lines, _login, t, new, _p in self._blocks():
            t = t or []
            mode = f'line vty {lines}'
            telnet = 'telnet' in t or 'all' in t
            if 'ssh' in t and not telnet:
                continue
            if new:
                worst, text, kind, disruptive = _worse(worst, MISSING), \
                    f'vty {lines} will allow SSH only.', ADD, False
            elif not t:
                worst, text, kind, disruptive = _worse(worst, UNKNOWN), \
                    (f'vty {lines} shows no "transport input" line (the default differs '
                     f'between IOS releases); SSH only will be set explicitly.'), MODIFY, False
            elif 'ssh' in t or 'all' in t:
                worst, text, kind, disruptive = _worse(worst, ATTENTION), \
                    (f'vty {lines} also allows Telnet, which sends passwords unencrypted. It will '
                     f'allow SSH only: anyone using Telnet must switch to SSH.'), MODIFY, True
            else:
                worst, text, kind, disruptive = _worse(worst, CONFLICT), \
                    (f'vty {lines} does not allow SSH ({" ".join(t)}). It will allow SSH only'
                     + (': Telnet will stop working there.' if telnet else '.')), MODIFY, telnet
            notes.append(text)
            item.commands.append(PlanCommand('transport input ssh', 'Allows only SSH on these '
                                             'lines.', kind=kind, disruptive=disruptive, mode=mode,
                                             setting='vty_transport'))
        cover_status, cover_note = self._coverage_note()
        if cover_status:
            worst = _worse(worst, cover_status)
            notes.append(cover_note)
        item.status = worst
        item.explanation = ' '.join(notes) or 'Every VTY line already allows SSH only.'
        return item

    # ------------------------------------------------------------ information
    def management(self):
        r = self.r
        if r.management_interface:
            return PlanItem('management', 'Management IP address', CONFIGURED,
                            f'{r.management_interface} ({r.management_reason})',
                            'SSH can reach the device through this address. Not changed.')
        return PlanItem('management', 'Management IP address',
                        ATTENTION if r.interfaces else UNKNOWN,
                        r.management_reason or 'unknown',
                        'SSH over the network needs an interface with an IP address that is up. '
                        'Setting one is not part of this preview, and NetCommand never invents '
                        'an IP address.')


def _worse(a, b):
    return a if _SEVERITY[a] >= _SEVERITY[b] else b


def _ranges(numbers):
    """[5, 6, 7, 9] -> '5-7, 9'."""
    out, start, prev = [], None, None
    for n in sorted(numbers):
        if start is None:
            start = prev = n
        elif n == prev + 1:
            prev = n
        else:
            out.append(f'{start}-{prev}' if prev > start else str(start))
            start = prev = n
    if start is not None:
        out.append(f'{start}-{prev}' if prev > start else str(start))
    return ', '.join(out)


def plan_is_stale(plan, result, live):
    """Why a plan can no longer be trusted, or None."""
    if plan is None:
        return None
    if result is None or plan.detected_at != result.detected_at:
        return 'The device was detected again after this preview was made.'
    if not live:
        return 'The console session that this preview is based on has ended.'
    return None
