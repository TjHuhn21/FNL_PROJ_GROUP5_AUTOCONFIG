"""Save a restored configuration to the startup configuration (Phase 4H).

A separate, explicitly confirmed step after a verified SUCCESS of restore_engine.restore.
A restore never saves; this module never restores, reloads, or changes any other setting.

Stage 1, check(restore_result, creds): READ-ONLY.
    * the restore result is eligible: sealed by the engine in this process, SUCCESS, the
      running configuration verified and confirmed, the rollback timer verified cancelled,
      for this device, not already saved;
    * the backup keyring is usable (a startup backup must be possible);
    * a verified session (restore_engine helpers): SSH 2, privilege 15, the restore's serial
      and platform; no pending rollback timer;
    * the running configuration is valid and still EXACTLY the restored one (the approved
      comparison rules: restore_engine.config_digest equals the digest the engine recorded
      when it verified the restore);
    * the startup configuration is valid (show startup-config).
    Result: a SavePlan with every check and the phrase SAVE STARTUP <ip>.

Stage 2, save(plan, typed, creds): only for a passing plan, at most 10 minutes old, with
the phrase typed exactly (otherwise SaveRefused: nothing was done).
    1. a new verified session; the same checks again; the startup configuration must be the
       one seen by the checks;
    2. the current startup configuration is backed up ENCRYPTED (config.connect._save_backup,
       purpose "pre-save-startup", source "show startup-config", the device identity), read
       back and decrypted in memory, and compared byte for byte; any failure: nothing saved;
    3. `write memory` (it asks nothing on IOS; `copy running-config startup-config` always
       asks for a file name, which would need an answer). A question is never answered: the
       session is closed at once. Its text alone never counts as success;
    4. a NEW verified session reads the startup and running configurations again.
Results: SUCCESS (the save command completed AND the startup configuration now equals the
running configuration, which is still the restored one), FAILED (the startup
configuration is verified unchanged), UNKNOWN (anything else, including a save that was
interrupted even if the startup configuration now looks right). The pre-save-startup
backup is always kept.

Messages never contain configuration text, keys or passwords.
"""
import hmac
import secrets
import time
import types
from dataclasses import dataclass, field

import backup_catalogue as B
import backup_crypto as C
import restore_engine as E
import restore_preflight as R
from config import connect

PASS, WARNING, BLOCKED, FAILED = R.PASS, R.WARNING, R.BLOCKED, R.FAILED
SUCCESS, UNKNOWN = E.SUCCESS, E.UNKNOWN
PURPOSE = 'pre-save-startup'
SHOW_STARTUP = 'show startup-config'
SAVE_COMMAND = 'write memory'
SAVE_TIMEOUT = 120
FRESH_SECONDS = 600
CHECKED, SAVE_STARTED, STOPPED = 'checked: waiting for the typed confirmation', \
    'save started', 'stopped'
_SEAL_KEY = secrets.token_bytes(32)
_SAVED = set()                 # seals of restore results already saved successfully
# what the verification found in the startup configuration
NOTHING_SAVED = 'unchanged: nothing was saved'
SAVED = 'equals the restored running configuration (verified)'
UNCHANGED = 'unchanged (verified): nothing was saved'
LOOKS_SAVED = ('matches the running configuration, but the save command did not complete '
               'normally')
STATE_UNKNOWN = 'unknown'


class SaveRefused(Exception):
    """The save stage did not start: no connection was opened and nothing was written."""


def confirmation_phrase(ip):
    return f'SAVE STARTUP {ip}'


# ---------------------------------------------------------------- eligibility
def eligible(result, ip=None):
    """(True, '') when this restore result may be saved to startup, else (False, why)."""
    if not E.result_seal_valid(result):
        return False, ('this is not an unchanged result of a restore made in this NetCommand '
                       'session')
    if result.status != E.SUCCESS:
        return False, f'the restore result is {result.status}, not SUCCESS'
    if not (result.confirmed and result.timer_state == 'cancelled (verified)' and
            result.device_state == E.RESTORED and result.restored_digest):
        return False, 'the restored configuration and the cancelled timer were not verified'
    if ip is not None and result.device_ip != ip:
        return False, f'the restore was for {result.device_ip}, not {ip}'
    if not B._known((result.identity or {}).get('serial')):
        return False, 'the restore recorded no device serial number'
    if result.seal in _SAVED:
        return False, 'this restore has already been saved to the startup configuration'
    return True, ''


# ---------------------------------------------------------------- results
@dataclass
class SavePlan:
    device_ip: str
    restore: object
    checks: list = field(default_factory=list)
    identity: dict = field(default_factory=dict)
    startup_digest: str = None
    startup_already_saved: bool = False
    required_confirmation: str = ''
    stage: str = STOPPED
    checked_at: float = None
    seal: str = None
    report: object = field(default=None, repr=False, compare=False)

    @property
    def status(self):
        if not self.checks:
            return FAILED
        return max((c.status for c in self.checks), key=R._SEVERITY.__getitem__)

    @property
    def can_proceed(self):
        return self.stage == CHECKED and self.status in (PASS, WARNING)

    def add(self, name, status, text):
        self.checks.append(R.Check(name, status, text))
        if self.report:
            self.report({PASS: 'ok', WARNING: 'warn'}.get(status, 'error'),
                        f'{status}  {name}: {text}')

    def check(self, name):
        for c in reversed(self.checks):
            if c.name == name:
                return c
        return None

    def of(self, *statuses):
        return [c for c in self.checks if c.status in statuses]


def _plan_seal(plan):
    """HMAC (a key that exists only in this process) over everything stage 2 relies on."""
    body = repr((plan.device_ip, getattr(plan.restore, 'seal', None),
                 sorted(plan.identity.items()), plan.startup_digest,
                 plan.startup_already_saved, plan.required_confirmation, plan.stage,
                 plan.checked_at, [(c.name, c.status, c.text) for c in plan.checks]))
    return hmac.new(_SEAL_KEY, body.encode('utf-8'), 'sha256').hexdigest()


def plan_seal_valid(plan):
    return isinstance(plan, SavePlan) and isinstance(plan.seal, str) and \
        hmac.compare_digest(plan.seal, _plan_seal(plan))


@dataclass
class SaveResult:
    status: str = UNKNOWN
    device_ip: str = ''
    identity: dict = field(default_factory=dict)
    restored_backup: str = ''
    startup_backup: str = None              # the encrypted pre-save-startup backup
    command_sent: bool = False
    command_outcome: str = 'not sent'       # ok / error / prompt / lost / not sent
    verification: str = 'not done'
    startup_state: str = NOTHING_SAVED
    steps: list = field(default_factory=list)
    manual_actions: list = field(default_factory=list)

    def lines(self):
        out = [f'Save to startup on {self.device_ip}: {self.status}',
               f'  Device: {connect.describe_identity(self.identity) if self.identity else "?"}',
               f'  Restored backup: {self.restored_backup}',
               f'  Pre-save-startup backup (encrypted): {self.startup_backup or "not created"}',
               f'  Save command ({SAVE_COMMAND}): {self.command_outcome}',
               f'  Verification: {self.verification}',
               f'  Startup configuration: {self.startup_state}']
        out += [f'  ACTION REQUIRED: {a}' for a in self.manual_actions]
        return out


class _Ctx:
    """What the restore engine's session helpers need (they are reused, not copied)."""

    def __init__(self, ip, creds, identity, report, wait, steps):
        self.ip, self.creds = ip, creds
        self.pre = types.SimpleNamespace(identity=identity)
        self.report, self.wait, self.steps = report, wait, steps
        self.identity_mismatch = False

    def step(self, kind, text):
        self.steps.append((kind, text))
        self.report(kind, text)


def _valid(text):
    return connect.check_backup(text) is None


# ---------------------------------------------------------------- stage 1
def check(restore_result, creds, key_source=None, log=None, clock=time.monotonic,
          wait=time.sleep):
    """The read-only checks. Returns a SavePlan; never raises for device problems."""
    report = connect._Report(log)
    ip = (creds or {}).get('host')
    plan = SavePlan(device_ip=ip, restore=restore_result, report=report)
    report('section', 'SAVE TO STARTUP: CHECKS (read-only: nothing is changed)')
    ok, why = eligible(restore_result, ip)
    if not ok:
        plan.add('eligibility', BLOCKED, f'Saving is not allowed: {why}.')
        return _finish_plan(plan, clock)
    plan.identity = dict(restore_result.identity)
    plan.add('eligibility', PASS, f'Verified restore of {restore_result.backup_file} '
                                  f'(SUCCESS, confirmed, rollback timer cancelled).')
    problem = connect.backup_key_problem(key_source)
    if problem:
        plan.add('keyring', FAILED, f'{problem} The startup configuration could not be backed '
                                    f'up, so it cannot be saved.')
        return _finish_plan(plan, clock)
    ctx = _Ctx(ip, creds, plan.identity, report, wait, [])
    conn = E._connect(ctx, 'Check session')
    if conn is None:
        if ctx.identity_mismatch:
            plan.add('identity', BLOCKED, 'The device answering at this address is not the one '
                                          'that was restored (serial or platform differs).')
        else:
            plan.add('connection', FAILED, 'The device could not be reached with a verified '
                                           'SSH 2, privilege 15 session.')
        return _finish_plan(plan, clock)
    try:
        plan.add('session', PASS, 'SSH 2, privilege 15, and the same serial number and '
                                  'platform as the restore.')
        _read_checks(ctx, conn, plan, restore_result)
    except E.UnexpectedPrompt:
        plan.add('session', FAILED, 'The device asked an unexpected question; it was not '
                                    'answered.')
    except Exception as err:
        plan.add('session', FAILED, f'The SSH session failed ({type(err).__name__}).')
    finally:
        E._hard_close(conn)
    return _finish_plan(plan, clock)


def _read_checks(ctx, conn, plan, restore_result):
    pending, _ = E._timer(ctx, conn)
    if pending is not False:
        plan.add('rollback-timer', BLOCKED, 'A rollback timer is pending (or its state cannot be '
                                            'read): the configuration is not final.')
        return
    plan.add('rollback-timer', PASS, 'No rollback timer is pending.')
    running = E._running(ctx, conn)
    if not _valid(running):
        plan.add('running-config', FAILED, 'The running configuration could not be read '
                                           'completely.')
        return
    if E.config_digest(running) != restore_result.restored_digest:
        plan.add('running-config', BLOCKED, 'The running configuration changed after the '
                                            'restore: it is no longer the verified restored '
                                            'configuration.')
        return
    plan.add('running-config', PASS, 'The running configuration is exactly the verified '
                                     'restored configuration.')
    startup = E._cmd(ctx, conn, SHOW_STARTUP)
    if not _valid(startup):
        plan.add('startup-config', BLOCKED, 'The startup configuration cannot be read as a '
                                            'complete configuration, so it cannot be backed up '
                                            'safely.')
        return
    plan.startup_digest = E.config_digest(startup)
    plan.startup_already_saved = E.compare_configs(startup, running)[0]
    plan.add('startup-config', PASS if not plan.startup_already_saved else WARNING,
             'The current startup configuration is valid and will be backed up (encrypted) '
             'before it is overwritten.' if not plan.startup_already_saved else
             'The startup configuration already equals the running configuration; saving '
             'again is not needed.')


def _finish_plan(plan, clock):
    if plan.status in (PASS, WARNING):
        plan.stage, plan.checked_at = CHECKED, clock()
        plan.required_confirmation = confirmation_phrase(plan.device_ip)
        plan.seal = _plan_seal(plan)
        plan.report('ok' if plan.status == PASS else 'warn',
                    f'{plan.status}: nothing was changed. To save, type '
                    f'{plan.required_confirmation}')
    else:
        plan.stage = STOPPED
        plan.report('error', f'{plan.status}: saving is not possible. Nothing was changed.')
    return plan


# ---------------------------------------------------------------- stage 2
def save(plan, typed, creds, backup_dir=None, key_source=None, log=None,
         clock=time.monotonic, wait=time.sleep):
    """Back up the startup configuration (encrypted), run `write memory`, verify. Raises
    SaveRefused before doing anything when the stage may not start."""
    if not isinstance(plan, SavePlan) or plan.stage != CHECKED or not plan_seal_valid(plan):
        raise SaveRefused('The checks were not run, did not pass, or were changed; run them '
                          'again. Nothing was done.')
    if not plan.can_proceed:
        raise SaveRefused(f'The checks did not pass ({plan.status}). Nothing was done.')
    if (creds or {}).get('host') != plan.device_ip:
        raise SaveRefused('These login details are for another device. Nothing was done.')
    if plan.checked_at is None or clock() - plan.checked_at > FRESH_SECONDS:
        raise SaveRefused('The checks are too old; run them again. Nothing was done.')
    if not isinstance(typed, str) or not hmac.compare_digest(
            typed.encode('utf-8'), plan.required_confirmation.encode('utf-8')):
        raise SaveRefused(f'The confirmation was not typed exactly '
                          f'({plan.required_confirmation}). Nothing was done.')
    ok, why = eligible(plan.restore, plan.device_ip)
    if not ok:
        raise SaveRefused(f'Saving is not allowed: {why}. Nothing was done.')
    plan.stage = SAVE_STARTED                     # single use: the seal no longer verifies

    report = connect._Report(log) if log else plan.report
    restore = plan.restore
    res = SaveResult(device_ip=plan.device_ip, identity=dict(plan.identity),
                     restored_backup=restore.backup_file)
    ctx = _Ctx(plan.device_ip, creds, plan.identity, report, wait, res.steps)
    report('section', 'SAVE TO STARTUP')
    try:
        backup_key = connect.load_backup_key(key_source)
    except connect.BackupKeyUnavailable as err:
        ctx.step('error', f'{err} Nothing was saved.')
        return _finish(res, report)
    a = E._connect(ctx, 'Save session')
    if a is None:
        ctx.step('error', 'The device could not be reached with a verified session; nothing '
                          'was saved.')
        return _finish(res, report)
    try:
        if _prepare(ctx, a, plan, restore, res, backup_key, backup_dir) is None:
            return _finish(res, report)
        res.command_sent = True
        res.startup_state = 'unknown until verified'
        try:
            out = E._cmd(ctx, a, SAVE_COMMAND, SAVE_TIMEOUT)
            if connect.rejection(out) or '[ok]' not in out.lower() or \
                    any(l.strip().startswith('%') for l in out.splitlines()):
                res.command_outcome = 'error (the device did not report [OK])'
                ctx.step('error', 'write memory did not report success.')
            else:
                res.command_outcome = 'ok ([OK]); not trusted until verified'
                ctx.step('ok', 'write memory reported [OK] (verified next).')
        except E.UnexpectedPrompt:
            res.command_outcome = 'prompt (an unexpected question was NOT answered)'
            ctx.step('error', 'write memory asked an unexpected question. It was NOT '
                              'answered; the session is closed.')
        except Exception as err:
            res.command_outcome = f'lost (the connection failed: {type(err).__name__})'
            ctx.step('error', f'The connection was lost during write memory '
                              f'({type(err).__name__}).')
    finally:
        E._hard_close(a)
    _verify(ctx, plan, restore, res)
    _finish(res, report)
    if res.status == SUCCESS:
        _SAVED.add(restore.seal)                  # this restore cannot be saved twice
    return res


def _prepare(ctx, a, plan, restore, res, backup_key, backup_dir):
    """The checks again on the save session, then the verified encrypted startup backup.
    Returns the captured startup configuration, or None (nothing saved)."""
    pending, _ = E._timer(ctx, a)
    if pending is not False:
        ctx.step('error', 'A rollback timer is pending; nothing was saved.')
        return None
    running = E._running(ctx, a)
    if not _valid(running) or E.config_digest(running) != restore.restored_digest:
        ctx.step('error', 'The running configuration is no longer the verified restored '
                          'configuration; nothing was saved.')
        return None
    startup = E._cmd(ctx, a, SHOW_STARTUP)
    if not _valid(startup) or E.config_digest(startup) != plan.startup_digest:
        ctx.step('error', 'The startup configuration changed after the checks (or cannot be '
                          'read); nothing was saved.')
        return None
    try:
        path, _sha, key_id = connect._save_backup(
            plan.device_ip, startup, backup_dir, backup_key, plan.identity, purpose=PURPOSE,
            source=SHOW_STARTUP)
    except connect.BackupError as err:
        ctx.step('error', f'{str(err).rstrip(".")}. The startup configuration was not backed '
                          f'up, so nothing was saved.')
        return None
    problem = verify_startup_backup(path, startup, backup_key.key_for, plan.device_ip,
                                    plan.identity)
    if problem:
        ctx.step('error', f'The startup backup could not be verified ({problem}); nothing was '
                          f'saved. File: {path}')
        return None
    res.startup_backup = path
    ctx.step('ok', f'Current startup configuration backed up (encrypted, key_id={key_id}), '
                   f'read back and verified: {path}')
    return startup


def verify_startup_backup(path, startup, key_for, ip, identity):
    """None when the file decrypts in memory to exactly `startup`, labelled as this device's
    pre-save-startup backup of show startup-config; otherwise why not."""
    try:
        data = B._read(path)
    except (OSError, C.FormatError):
        return 'the file cannot be read back'
    try:
        plaintext, header = C.decrypt_backup(data, key_for)
    except C.BackupCryptoError:
        return 'the file does not decrypt and authenticate'
    try:
        if not hmac.compare_digest(plaintext, startup.encode('utf-8')):
            return 'the decrypted text differs from the startup configuration'
    finally:
        del plaintext
    if header.get('purpose') != PURPOSE or header.get('source') != SHOW_STARTUP or \
            header.get('host') != ip:
        return 'the backup is not labelled as this device\'s pre-save-startup backup'
    if any(header.get(name) != identity.get(name) for name in ('serial', 'platform')):
        return 'the recorded identity differs'
    return None


def _verify(ctx, plan, restore, res):
    """A new verified session: what is the startup configuration now? Sets startup_state."""
    if not res.command_sent:
        return
    b = E._connect(ctx, 'Verification session')
    if b is None:
        res.verification = 'not possible (no verified session' + \
            (': a different device answers)' if ctx.identity_mismatch else ')')
        res.startup_state = STATE_UNKNOWN
        return
    try:
        running = E._running(ctx, b)
        startup = E._cmd(ctx, b, SHOW_STARTUP)
        valid = _valid(running) and _valid(startup)
        matches, desc = E.compare_configs(startup, running)
        restored = E.config_digest(running) == restore.restored_digest
        unchanged = valid and E.config_digest(startup) == plan.startup_digest
        res.verification = (f'startup vs. running: {desc}; running is '
                            f'{"" if restored else "NOT "}the restored configuration')
        ctx.step('ok' if matches and restored else 'warn', f'Verification: '
                                                           f'{res.verification}.')
        command_ok = res.command_outcome.startswith('ok')
        if valid and matches and restored and command_ok:
            res.startup_state = SAVED
        elif unchanged:
            res.startup_state = UNCHANGED
        elif valid and matches and restored:
            res.startup_state = LOOKS_SAVED
        else:
            res.startup_state = STATE_UNKNOWN
    except Exception as err:
        res.verification = f'failed ({type(err).__name__})'
        res.startup_state = STATE_UNKNOWN
    finally:
        E._hard_close(b)


def _finish(res, report):
    if res.command_sent and res.startup_state == SAVED:
        res.status = SUCCESS
    elif not res.command_sent or res.startup_state == UNCHANGED:
        res.status = FAILED
        if res.command_sent:
            res.manual_actions.append('The startup configuration was not changed. The device '
                                      'still runs the restored configuration, which is lost '
                                      'at the next reload unless it is saved.')
    else:
        res.status = UNKNOWN
        if res.startup_state == LOOKS_SAVED:
            res.manual_actions.append(
                f'The startup configuration now matches the running configuration, but the '
                f'save did not complete normally ({res.command_outcome}); an interrupted NVRAM '
                f'write is not trusted. Check the device ("show startup-config") and run Save '
                f'to Startup again.')
        else:
            res.manual_actions.append(
                f'The startup configuration of {res.device_ip} could not be verified. Check it '
                f'from the console. The previous startup configuration is in the encrypted '
                f'backup {res.startup_backup or "(not created)"}; restore it with '
                f'backup_tool.py export if needed. Do not reload the device until this is '
                f'resolved.')
    report('section', 'RESULT')
    for line in res.lines():
        report({SUCCESS: 'ok'}.get(res.status, 'error') if line.startswith('Save to') else
               'info', line)
    return res
