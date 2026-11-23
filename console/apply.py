"""Apply an approved SSH setup plan through the console, one step at a time
(Console-Based SSH Auto-Setup, phase 5.1.2).

    problems = check_request(plan, result, request, ...)      # nothing is sent
    outcome = apply_plan(session, plan, result, request, password=..., confirm=...,
                         confirmation='APPLY SSH R1', approvals={'vty_transport[0 4]'},
                         cancel=event, progress=callback)        # an ApplyResult

Before anything is sent (any problem: NOTHING is sent):
  * the plan is available, has steps, is not out of date, and its values were not edited;
  * the typed confirmation is exactly confirmation_phrase(plan) ("APPLY SSH <hostname>");
  * every step that needs a separate approval (disruptive) was approved;
  * the new account's password was typed again (twice) and passes the usual checks;
  * every plan line passes console.link.check_config_line;
  * the session is live, `show privilege` says 15, and a fresh read-only detection
    produces exactly the same plan (same lines, steps, approvals and AAA state).

Then, for each step in order:
  1. its prerequisites must be VERIFIED (console.steps.readiness);
  2. `configure terminal`, the expected "<host>(config)#" prompt;
  3. the step's own line(s) only (a `line vty` mode line first for VTY steps), each
     reply inspected: a question, a password or boot-loader prompt, a timeout or a lost
     connection stops everything at once (nothing is ever answered);
  4. `end` only when the prompt is the expected one;
  5. the step's read-only verification (show commands); only its evaluator can make it
     VERIFIED - an accepted command proves nothing.
The first step that is not VERIFIED stops the run: steps that depend on it are BLOCKED,
the others are NOT RUN. Cancelling takes effect only between steps.

Afterwards (when the console is back at the privileged prompt): the AAA invariant check
and a complete read-only re-detection.

Never sent: write memory / copy (D3: nothing is saved; changes stay in the running
configuration only), a management IP address, or a network SSH login (D2). The password
is substituted into its line only when that line is written; it is never stored,
logged, returned, or put in an exception (ApplyResult holds <SSH_PASSWORD> only).
"""
import re
import threading
from dataclasses import dataclass, field

from console import detect
from console.link import (BOOT_LOADER, CONFIG_TIMEOUT, PASSWORD_PROMPT, PROMPT, QUESTION,
                          UNSAFE_OUTPUT, ConsoleError, check_config_line, prompt_parts)
from console.plan import PASSWORD_PLACEHOLDER, build_plan, check_password, plan_is_stale
from console.steps import CHECK, FAILED, UNCERTAIN, VERIFIED, readiness

BLOCKED, NOT_RUN = 'blocked', 'not run'
STATUS_TEXT = {VERIFIED: 'VERIFIED', FAILED: 'FAILED', UNCERTAIN: 'UNCERTAIN',
               BLOCKED: 'BLOCKED', NOT_RUN: 'NOT RUN'}
# overall outcomes
REFUSED, SUCCESS, FAILURE, INCOMPLETE, CANCELLED = ('refused', 'success', 'failed', 'uncertain',
                                                    'cancelled')
RSA_TIMEOUT = 180            # seconds: key generation can take a minute or more on old routers
CONFIRM_WORDS = 'APPLY SSH'
NOT_SAVED = ('Nothing was saved: the changes are in the running configuration only. Saving '
             '(write memory) is a separate step that NetCommand does not perform here.')
REFRESH = '<Enter> (prompt read again)'


def confirmation_phrase(plan):
    return f'{CONFIRM_WORDS} {plan.hostname or "unknown"}'


def approvals_needed(plan):
    return [s for s in plan.steps if s.approval_required]


def needs_password(plan):
    return any(s.command is not None and PASSWORD_PLACEHOLDER in s.command.text
               for s in plan.steps)


def allowed_lines(plan):
    """Every line the plan may send, as written in the plan (placeholders included)."""
    return [l.strip() for l in plan.lines() if l.strip() not in ('configure terminal', 'end')]


@dataclass
class StepResult:
    step_id: str
    title: str
    status: str = NOT_RUN
    reasons: list = field(default_factory=list)
    commands: list = field(default_factory=list)      # as sent, <SSH_PASSWORD> never a value
    reply: str = ''                                   # the device's reply, secrets masked
    checks: dict = field(default_factory=dict)        # show command -> output (masked)


@dataclass
class ApplyResult:
    outcome: str = REFUSED
    message: str = ''
    problems: list = field(default_factory=list)      # why nothing was sent (REFUSED)
    steps: list = field(default_factory=list)         # StepResult, in plan order
    invariants: list = field(default_factory=list)    # StepResult (AAA unchanged)
    commands_sent: list = field(default_factory=list)  # every configuration line, in order
    checks_run: list = field(default_factory=list)    # every read-only show command
    recovery: list = field(default_factory=list)      # what the operator should do now
    final_detection: object = None                    # DetectionResult after the run
    cancelled: bool = False
    saved: bool = False                               # always False (D3)
    console_released: bool = False                   # the port was closed, nothing typed,
                                                      # because the console was not at '#'

    @property
    def changed(self):
        return bool(self.commands_sent)

    def step(self, step_id):
        return next((s for s in self.steps if s.step_id == step_id), None)

    @property
    def blocked(self):
        return [s.step_id for s in self.steps if s.status == BLOCKED]

    @property
    def not_run(self):
        return [s.step_id for s in self.steps if s.status == NOT_RUN]


class _Rejected(Exception):
    """The device answered a line with a known failure message (inside _Runner)."""

    def __init__(self, error, prompt, acceptable):
        super().__init__(error)
        self.error, self.prompt, self.acceptable = error, prompt, acceptable


class _Stop(Exception):
    """Stop the run at this step: status, reason, recovery, and what the console is now
    in ('exec', 'config' = configuration mode in an unexpected state, 'closed')."""

    def __init__(self, status, reason, recovery=None, console='closed'):
        super().__init__(reason)
        self.status, self.reason, self.recovery, self.console = status, reason, recovery, console


# ---------------------------------------------------------------- checks before sending
def _signature(plan):
    """What must be identical between the previewed plan and one made from a fresh
    detection: the lines, the steps, and every item's status and detected value."""
    return (plan.lines(),
            [(s.step_id, s.approval_required, tuple(s.requires)) for s in plan.steps],
            [(c.text, c.kind, c.disruptive, c.mode) for c in plan.commands],
            [(i.key, i.status, i.current) for i in plan.items])


def check_request(plan, result, request, live=True, stale_reason=None, confirmation='',
                  approvals=(), password='', confirm=''):
    """Problems that stop an apply before anything is sent (empty list: may proceed).
    Messages never contain the password."""
    problems = []
    if plan is None or result is None or request is None:
        return ['Make a preview first.']
    if not plan.available:
        problems.append('This plan cannot be applied: ' + plan.reason)
    if not plan.steps:
        problems.append('The plan has no commands to apply.')
    why = stale_reason or plan_is_stale(plan, result, live)
    if why:
        problems.append(f'The preview is out of date: {why} Detect again and preview.')
    if (confirmation or '').strip() != confirmation_phrase(plan):
        problems.append(f'Type "{confirmation_phrase(plan)}" exactly to confirm.')
    missing = [s.title for s in approvals_needed(plan) if s.step_id not in set(approvals or ())]
    if missing:
        problems.append('Approve each step that can cut off current users: ' + '; '.join(missing))
    if needs_password(plan):
        problem = check_password(password, confirm)
        if problem:
            problems.append('New account password: ' + problem)
    for line in allowed_lines(plan):
        try:
            check_config_line(line)
        except ConsoleError as err:
            problems.append(str(err))
    if any(PASSWORD_PLACEHOLDER in s.command.text for s in plan.steps
           if s.command is not None and s.step_id != 'user'):
            problems.append('Only the account step may contain the password.')
    return problems


# ---------------------------------------------------------------- the run
class _Runner:
    def __init__(self, session, plan, password, cancel, progress, out):
        self.session, self.plan, self.out = session, plan, out
        self._password = password                 # only substituted when its line is written
        self.cancel = cancel or threading.Event()
        self.progress = progress or (lambda *a: None)
        # 'exec': verified at '<host>#'; 'config': inside configuration mode at a verified
        # prompt (during a step); 'unknown': port open, state not verified; 'closed'
        self.console = 'exec'
        self.host = None
        self.finish_fast = threading.Event()

    def say(self, step_id, status, text):
        try:
            self.progress(step_id, status, text)
        except Exception:
            pass

    # ------------------------------------------------------------ device exchanges
    def _expect(self, rec, reply, expected, logged=False):
        """The reply must end at `expected`. A different (valid) prompt is read once more
        with an empty line; anything else stops the run, never answered."""
        if not logged:
            rec.reply += reply.text.rstrip() + '\n'
        if reply.state != PROMPT:
            self.console = 'closed'
            last = reply.last_line
            if reply.state == QUESTION:
                raise _Stop(UNCERTAIN, f'the device asked "{last}"; it was NOT answered and the '
                                       f'console port was closed',
                            f'At the console, read the question "{last}" and resolve it '
                            f'yourself (NetCommand never answers device questions), then detect '
                            f'again before anything else.')
            if reply.state == PASSWORD_PROMPT:
                raise _Stop(UNCERTAIN, 'the device asked for a password; it was NOT answered',
                            'At the console, deal with the password prompt yourself, then '
                            'detect again.')
            if reply.state == BOOT_LOADER:
                raise _Stop(UNCERTAIN, 'the device answered with a boot-loader prompt (ROMMON); '
                                       'nothing more was sent',
                            'The device is in its boot loader. Stop and ask the instructor; do '
                            'not type commands there.')
            raise _Stop(UNCERTAIN, 'the device reply did not end in a recognised prompt')
        if reply.prompt == expected:
            return
        again = self.session.refresh_prompt()
        self.out.commands_sent.append(REFRESH)
        rec.commands.append(REFRESH)
        rec.reply += again.text.rstrip() + '\n'
        if again.state == PROMPT and again.prompt == expected:
            rec.reasons.append(f'the device showed "{reply.prompt}" once; read again it shows '
                               f'"{expected}"')
            return
        if again.state != PROMPT:
            self.console = 'closed'
            raise _Stop(UNCERTAIN, f'after "{reply.prompt}" the prompt could not be read again',
                        'Check the console by hand, then detect again.')
        # a valid prompt, but not the one this step must reach: the console's state is not
        # verified. Nothing more is typed; apply_plan closes the port (see abandon()).
        self.console = 'unknown'
        raise _Stop(UNCERTAIN, f'the prompt is "{again.prompt}", expected "{expected}"; nothing '
                               f'more was sent', console='unknown')

    def _send(self, rec, line, before, after, markers, timeout=None, secrets=None):
        """One configuration line. A reply carrying a known IOS failure message is a
        rejection (checked BEFORE the prompt: a rejected `hostname` leaves the old prompt);
        otherwise the reply must end at `after`."""
        self.out.commands_sent.append(line)
        rec.commands.append(line)
        reply = self.session.send_config_line(line, expect=after, timeout=timeout,
                                              secrets=secrets)
        rec.reply += reply.text.rstrip() + '\n'
        if reply.state == PROMPT and markers:
            body, _logs = detect.strip_log_lines(reply.text)
            if any(m in body for m in markers):
                raise _Rejected(_first_error(body, markers), reply.prompt, (before, after))
        self._expect(rec, reply, after, logged=True)
        return reply

    def _end(self, rec, host):
        """`end`, which must bring back exactly '<host>#'."""
        self.out.commands_sent.append('end')
        rec.commands.append('end')
        end = self.session.end_config()
        self._expect(rec, end, f'{host}#')
        self.host = host
        self.console = 'exec'

    def configure(self, step, rec):
        """configure terminal / [mode line] / the command / end, every prompt checked.
        Returns the command's own reply text (masked). A clear rejection raises _Stop
        with FAILED: `end` is sent only when the prompt is exactly the one before or after
        the line; anything else leaves the console 'unknown' (closed by apply_plan)."""
        c = step.command
        new_host = (step.prompt.hostname_changes_to if step.prompt else None) or self.host
        markers = step.failure_replies
        self.out.commands_sent.append('configure terminal')
        rec.commands.append('configure terminal')
        reply = self.session.enter_config()
        self.console = 'config'
        config = f'{self.host}(config)#'
        self._expect(rec, reply, config)
        try:
            before = config
            if c.mode:
                line_mode = f'{self.host}(config-line)#'
                self._send(rec, c.mode, config, line_mode, markers)
                before = line_mode
            secrets = {PASSWORD_PLACEHOLDER: self._password} \
                if PASSWORD_PLACEHOLDER in c.text else None
            after = f'{new_host}(config-line)#' if c.mode else f'{new_host}(config)#'
            reply = self._send(rec, c.text, before, after, markers,
                               timeout=RSA_TIMEOUT if step.step_id == 'rsa' else CONFIG_TIMEOUT,
                               secrets=secrets)
        except _Rejected as rej:
            self._after_rejection(rec, rej)
        self._end(rec, new_host)
        return reply.text

    def _after_rejection(self, rec, rej):
        """The device refused a line: FAILED. Leave configuration mode only from a prompt
        that is exactly where it should be (before or after that line)."""
        reason = f'the device rejected the command: {rej.error}'
        parts = prompt_parts(rej.prompt)
        if rej.prompt not in rej.acceptable or parts is None:
            self.console = 'unknown'
            raise _Stop(FAILED, f'{reason}; the prompt is then "{rej.prompt}", which is not '
                                f'where it should be, so nothing more was sent',
                        console='unknown')
        try:
            self._end(rec, parts[0])
        except _Stop as stop:
            raise _Stop(FAILED, f'{reason}; leaving configuration mode did not work '
                                f'({stop.reason})', stop.recovery, console=stop.console)
        raise _Stop(FAILED, reason, console='exec')

    def verify(self, step, rec):
        outputs = {}
        for command in dict.fromkeys(step.check_commands):
            self.out.checks_run.append(command)
            try:
                outputs[command] = self.session.send_show(command)
            except ConsoleError as err:
                self.console = 'closed'
                outputs[command] = None
                rec.reasons.append(f'"{command}" did not run: {err}')
                break
            rec.checks[command] = outputs[command]
        return outputs

    # ------------------------------------------------------------ steps
    def run(self):
        plan, out = self.plan, self.out
        results = {s.step_id: StepResult(s.step_id, s.title) for s in plan.steps}
        out.steps = [results[s.step_id] for s in plan.steps]
        outcomes, stop_at = {}, None
        for step in plan.steps:
            rec = results[step.step_id]
            if self.cancel.is_set():
                out.cancelled = True
                break
            ready, why = readiness([step], outcomes)[step.step_id]
            if not ready:
                rec.status, rec.reasons = BLOCKED, [why]
                self.say(step.step_id, BLOCKED, why)
                stop_at = stop_at or step.step_id
                break
            self.say(step.step_id, 'running', step.title)
            try:
                status = self._one(step, rec)
            except _Stop as stop:
                status = stop.status
                rec.reasons.append(stop.reason)
                if stop.recovery:
                    out.recovery.append(stop.recovery)
                self.console = stop.console
            except ConsoleError as err:
                status = UNCERTAIN
                rec.reasons.append(f'the console session failed: {err}')
                if not self._active() and err.kind == UNSAFE_OUTPUT:
                    self.console = 'closed'                 # N2: nothing was written
                    out.recovery.append('The device showed a question or another prompt '
                                        'NetCommand did not expect, so nothing more was sent '
                                        'and the console port was closed. At the console, look '
                                        'at what it is asking and resolve it yourself '
                                        '(NetCommand never answers device questions), then '
                                        'connect and detect again.')
                elif not self._active():
                    self.console = 'closed'
                    out.recovery.append('Reconnect the console and detect again: whether the '
                                        'last line took effect is not known.')
                elif err.kind == 'refused' and self.console == 'config':
                    self._leave_config(rec)                 # nothing was written: leave cleanly
                elif self.console != 'exec':
                    self.console = 'unknown'
            rec.status = outcomes[step.step_id] = status
            self.say(step.step_id, status, '; '.join(rec.reasons))
            if status != VERIFIED:
                stop_at = step.step_id
                break
        self._mark_rest(results, stop_at)
        return outcomes

    def _leave_config(self, rec):
        self.out.commands_sent.append('end')
        rec.commands.append('end')
        try:
            end = self.session.end_config()
            self._expect(rec, end, f'{self.host}#')
            self.console = 'exec'
        except (_Stop, ConsoleError) as err:
            rec.reasons.append(f'leaving configuration mode did not work: {err}')
            self.console = 'closed' if not self._active() else 'unknown'

    def _active(self):
        try:
            return self.session.is_active()
        except Exception:
            return False

    def _one(self, step, rec):
        reply = None
        if step.kind != CHECK:
            text = self.configure(step, rec)
            reply, _logs = detect.strip_log_lines(text)
            if any(m in reply for m in step.failure_replies):   # (normally _send raises)
                rec.reasons.append('the device rejected the command: ' +
                                   _first_error(reply, step.failure_replies))
                return FAILED
        outputs = self.verify(step, rec)
        status, reasons = step.evaluate(outputs, reply=reply)
        rec.reasons += reasons
        return status

    def _mark_rest(self, results, stop_at):
        plan = self.plan
        failed = {stop_at} if stop_at else set()
        dependents = set()
        changed = True
        while changed:
            changed = False
            for s in plan.steps:
                if s.step_id not in dependents and set(s.requires) & (failed | dependents):
                    dependents.add(s.step_id)
                    changed = True
        for s in plan.steps:
            rec = results[s.step_id]
            if rec.status != NOT_RUN:
                continue
            if s.step_id in dependents:
                rec.status = BLOCKED
                rec.reasons = [f'needs {", ".join(r for r in s.requires)} to be VERIFIED; '
                               f'stopped at {stop_at}']
            else:
                rec.reasons = ['cancelled before this step' if self.out.cancelled else
                               f'not run: the run stopped at {stop_at}' if stop_at else 'not run']
            self.say(s.step_id, rec.status, rec.reasons[0])

    def abandon(self):
        """The console is not at a verified '<host>#' prompt: close the port at once.
        Nothing is typed (no Enter, end or exit): cancel() closes the port without
        Netmiko's graceful cleanup, then disconnect() only releases it."""
        for close in (self.session.cancel, self.session.disconnect):
            try:
                close()
            except Exception:
                pass
        self.console = 'closed'
        self.out.console_released = True
        self.out.recovery.insert(0, 'The console was not back at the privileged "#" prompt, '
                                    'so NetCommand closed the console port without typing '
                                    'anything (no Enter, end or exit). At the console, look at '
                                    'the prompt and resolve it yourself (for example leave '
                                    'configuration mode with "end"), then connect and detect '
                                    'again.')

    def final_checks(self, detect_fn):
        out = self.out
        for inv in self.plan.invariants:
            rec = StepResult(inv.step_id, inv.title)
            out.invariants.append(rec)
            outputs = self.verify(inv, rec)
            rec.status, reasons = inv.evaluate(outputs)
            rec.reasons += reasons
            self.say(inv.step_id, rec.status, '; '.join(rec.reasons))
            if rec.status == FAILED:
                out.recovery.insert(0, 'AAA IS NOT AS IT WAS DETECTED. NetCommand never changes '
                                       'AAA, so something else did: check "show running-config | '
                                       'include aaa" at the console before using SSH.')
            elif rec.status == UNCERTAIN:
                out.recovery.append('The AAA configuration could not be confirmed unchanged; '
                                    'check it at the console.')
        if self.finish_fast.is_set():
            out.recovery.append('NetCommand is closing: the final re-detection was skipped. '
                                'Detect the device again before relying on its state.')
            return
        if self.console == 'exec' and self._active():
            self.say('detect', 'running', 'Reading the device again (show commands only)')
            try:
                out.final_detection = detect_fn(self.session)
            except ConsoleError as err:
                out.recovery.append(f'The final re-detection did not run ({err}); detect again.')


def _first_error(text, markers):
    """The reply line that matched a failure marker."""
    for line in text.replace('\r', '').split('\n'):
        if any(m in line for m in markers):
            return line.strip()
    return 'see the reply'


def apply_plan(session, plan, result, request, password='', confirm='', confirmation='',
               approvals=(), stale_reason=None, cancel=None, progress=None,
               detect_fn=detect.detect_device, finish_fast=None):
    """Run an approved plan step by step (see the module text). Returns an ApplyResult;
    console errors are reported in it, never raised. The password is used only to write
    the account line and is not kept.

    finish_fast: an Event set when NetCommand is closing (together with `cancel`): the run
    stops after the current step and skips the final re-detection.

    The run ends with the console either at the verified '<host>#' prompt (the session is
    left open) or with the port closed: in every other state abandon() closes it without
    typing anything."""
    out = ApplyResult()
    try:
        live = session.is_active()
    except Exception:
        live = False
    out.problems = check_request(plan, result, request, live, stale_reason, confirmation,
                                 approvals, password, confirm)
    host = None
    if not out.problems:
        out.problems, host = _device_preflight(session, plan, result, request, progress,
                                               detect_fn, out)
    if out.problems:
        out.outcome = REFUSED
        out.message = 'Nothing was sent to the device: ' + ' '.join(out.problems)
        if plan is not None:
            out.steps = [StepResult(s.step_id, s.title, NOT_RUN, ['nothing was sent'])
                         for s in plan.steps]
        return out
    runner = _Runner(session, plan, password, cancel, progress, out)
    runner.finish_fast = finish_fast or threading.Event()
    password = confirm = None                       # the runner holds the only reference
    runner.host = host
    session.allow_config(allowed_lines(plan))
    try:
        runner.run()
    except BaseException:                           # a programming error: never leave the
        runner.abandon()                            # console in an unverified state
        raise
    finally:
        runner._password = None
    if runner.console == 'exec' and runner._active():
        runner.final_checks(detect_fn)
    else:
        if runner._active():
            runner.abandon()
        if out.changed:
            out.recovery.append('The final AAA check and re-detection could not run because '
                                'the console is not at the privileged prompt; check the '
                                'device by hand.')
    _conclude(out)
    return out


def _device_preflight(session, plan, result, request, progress, detect_fn, out):
    """Read-only checks on the device before the first change: (problems, host)."""
    say = progress or (lambda *a: None)
    try:
        say('preflight', 'running', 'Checking privilege level 15 (show privilege)')
        out.checks_run.append(detect.SHOW_PRIVILEGE)
        level = detect.parse_privilege(session.send_show(detect.SHOW_PRIVILEGE))
        if level != 15:
            return [f'The console is at privilege level {level if level is not None else "unknown"}, '
                    f'not 15. Nothing was sent.'], None
        m = re.match(r'^([A-Za-z][\w.\-]*)#$', session.find_prompt() or '')
        if not m:
            return ['The device is not at the privileged "#" prompt.'], None
        host = m.group(1)
        say('preflight', 'running', 'Reading the device again to check the plan is still right')
        fresh = detect_fn(session)
        out.checks_run += [c.command for c in fresh.commands]
    except ConsoleError as err:
        return [f'The device could not be checked before applying: {err}'], None
    if not fresh.complete:
        return ['The check before applying did not finish (the console session ended).'], None
    if fresh.access.privilege_level != 15:
        return ['The fresh detection did not run at privilege level 15.'], None
    again = build_plan(fresh, request)
    if not again.available or _signature(again) != _signature(plan):
        return ['The device changed since the preview was made (a fresh detection gives a '
                'different plan). Detect again and preview.'], None
    c1, c2 = result.config, fresh.config
    if (c1.aaa_known, c1.aaa_new_model, c1.aaa_login_lists) != \
            (c2.aaa_known, c2.aaa_new_model, c2.aaa_login_lists):
        return ['The AAA configuration changed since the preview was made.'], None
    if fresh.simulated != result.simulated:
        return ['The device answering is not the one that was previewed.'], None
    return [], host


def _conclude(out):
    statuses = [s.status for s in out.steps] + [s.status for s in out.invariants]
    if FAILED in statuses:
        out.outcome = FAILURE
    elif UNCERTAIN in statuses:
        out.outcome = INCOMPLETE
    elif out.cancelled:
        out.outcome = CANCELLED
    elif all(s.status == VERIFIED for s in out.steps):
        out.outcome = SUCCESS
    else:
        out.outcome = INCOMPLETE
    done = [s.step_id for s in out.steps if s.status == VERIFIED]
    stop = next((s for s in out.steps if s.status in (FAILED, UNCERTAIN)), None)
    words = {SUCCESS: 'Every step was applied and VERIFIED.',
             FAILURE: f'Stopped: {stop.title if stop else "a check"} FAILED.',
             INCOMPLETE: f'Stopped: {stop.title if stop else "a step"} could not be verified '
                         f'(UNCERTAIN).',
             CANCELLED: 'Cancelled between steps.'}
    out.message = words[out.outcome] + (f' Verified: {", ".join(done)}.' if done else '') + \
        ' ' + NOT_SAVED
    if out.changed and out.outcome != SUCCESS:
        out.recovery.append('Steps marked VERIFIED are in effect in the running configuration. '
                            'Steps marked BLOCKED or NOT RUN were not sent. Review the device at '
                            'the console before applying again; a new preview will only propose '
                            'what is still missing.')
    if out.changed:
        out.recovery.append(NOT_SAVED + ' Keep the console cable connected until SSH has been '
                                        'tested.')
