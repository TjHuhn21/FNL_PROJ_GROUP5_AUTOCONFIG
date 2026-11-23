"""Restore engine (Phase 4F): restore ONE device from a selected encrypted backup, with a
verified rollback. It runs only after the Phase 4E preflight (restore_preflight.py) has
passed, the user has typed the confirmation, and the encrypted pre-restore safety backup
has been written and verified.

    result = restore_engine.restore(preflight_result, creds)

Order (nothing is sent to the device before every offline gate has passed):

 1. Offline gates: the preflight result is sealed and unchanged since its safety backup,
    for this device, used once, recent; the timer is 3-10 minutes. The selected backup is
    re-verified (file SHA-256, AES-GCM, key id, plaintext SHA-256 and size, configuration
    check) and the safety backup is decrypted and checked; both stay in memory only.
 2. Session A (config.connect._open, strict SSH algorithms): SSH protocol 2, privilege 15,
    the SAME serial and platform as the preflight (strict rules), no pending rollback, an
    archive path, the running configuration still equal to the safety backup, the temporary
    file name still free, enough flash.
 3. Transfer from memory to flash:<preflight temporary name>: Tcl (Netmiko InLineTransfer
    with source_config) or SCP already enabled (scp putfo of an in-memory stream). Then
    `verify /md5` against the MD5 of exactly the bytes sent. Any failure: the file is
    deleted and nothing is replaced.
 4. `configure replace flash:<file> list force time <minutes>`. A question (even an
    unexpected one) is never answered: the session is hard-closed. Rejected lines,
    "Rollback aborted", an error or the absence of "Rollback Done" count as a failure.
 5. Session B, a NEW connection to the same management address: SSH 2, privilege 15, same
    serial and platform, a pending rollback timer, and the running configuration compared
    with the backup (compare_configs). Only on a match: `configure confirm`, then the timer
    must read as cancelled, then the running configuration is compared again.
 6. Any failure after the replace: `configure revert now` (on a trusted live session), then
    a new session must show the ORIGINAL configuration (the safety backup) and no pending
    timer. If that cannot be verified and the timer may still run, the engine waits for it
    (fallback) and checks again. Never reported as rolled back without that check.
 7. Cleanup: `delete /force flash:<file>`, then `dir` must not find it. Archive copies and
    other files are never touched.

Result: SUCCESS (restored, verified, confirmed, timer cancelled, file removed), PARTIAL
(restored and confirmed, but the temporary file could not be removed), FAILED (the device
is verified to be in its original configuration, or nothing was sent), UNKNOWN (anything
else: the user must act; manual_actions says what).

Sessions are always hard-closed (the SSH transport is closed): Netmiko's disconnect sends
a newline, which would answer a "[confirm]" question with yes. Messages and logs never
contain configuration text, keys or passwords.
"""
import difflib
import hashlib
import hmac
import io
import re
import threading
import time
from contextlib import contextmanager
from dataclasses import dataclass, field

import backup_catalogue as B
import backup_crypto as C
import restore_preflight as R
import ssh_options
from config import connect

SUCCESS, FAILED, PARTIAL, UNKNOWN = 'SUCCESS', 'FAILED', 'PARTIAL', 'UNKNOWN'
DEFAULT_TIMER_MINUTES, MIN_TIMER_MINUTES, MAX_TIMER_MINUTES = 5, 3, 10
START_WINDOW_SECONDS = 600            # the restore must start this soon after the safety backup
RECONNECT_ATTEMPTS, RECONNECT_WAIT_SECONDS = 3, 10
TIMER_MARGIN_SECONDS = 30
COMMAND_TIMEOUT, REPLACE_TIMEOUT, MD5_TIMEOUT = 60, 300, 120

# device states
NOTHING_SENT = 'unchanged: no configuration or transfer command was sent'
UNCHANGED_VERIFIED = 'unchanged (verified against the safety backup)'
ORIGINAL_VERIFIED = 'original configuration (verified against the safety backup)'
RESTORED = 'restored (verified)'
NOT_REPLACED = 'configuration not replaced (configure replace was never sent)'
STATE_UNKNOWN = 'unknown'

_TEMP = re.compile(r'^nc-restore-[0-9a-f]{16}\.cfg$')
_HEADER = re.compile(r'^(Building configuration\.\.\.|Current configuration : \d+ bytes|'
                     r'Using \d+ out of \d+ bytes)$')
_QUESTION = r'\[[^\]\r\n]*\][ \t]*[:?]?[ \t]*$'
_EXEC_PROMPT = r'(?:^|\n)[^\s#>()]+(?:\([^)\s]*\))?#[ \t]*$'
_EXPECT = f'(?:{_EXEC_PROMPT})|(?:{_QUESTION})'
_MD5 = re.compile(r'=\s*([0-9a-fA-F]{32})\s*$', re.MULTILINE)
_REMAINING = re.compile(r'Time remaining\s*:\s*(\d+)', re.IGNORECASE)
_NO_PENDING = 'no rollback confirmed change pending'
_NOT_FOUND = re.compile(r'file not found|no such file', re.IGNORECASE)


class UnexpectedPrompt(Exception):
    """The device asked a question. It was NOT answered."""


# ---------------------------------------------------------------- configuration comparison
_TIMESTAMP = re.compile(r'^! (Last configuration change at |NVRAM config last updated at |'
                        r'No configuration change since last restart$)')
_CLOCK_PERIOD = re.compile(r'^ntp clock-period \d+$')


def normalized(text):
    """The configuration lines that are compared, or None when the text does not end with
    a top-level "end" line (only blank lines may follow it). The approved rules:
    * CRLF / CR line ends become LF; trailing whitespace is removed from every line;
    * the header block before the first configuration line is skipped: blank lines and
      "Building configuration...", "Current configuration : N bytes", "Using N out of M
      bytes" (IOS prints a blank line between them);
    * recognised timestamp lines are skipped: "! Last configuration change at ...",
      "! NVRAM config last updated at ...", "! No configuration change since last restart";
    * generated "ntp clock-period <number>" lines (top level) are skipped;
    * standalone "!" separator lines (only "!", at any indentation) are skipped.
    Everything else is kept and compared in order and exactly: every other comment line,
    every blank line after the header (e.g. inside a banner) and indentation."""
    lines = [l.rstrip() for l in (text or '').replace('\r\n', '\n').replace('\r', '\n')
             .split('\n')]
    ends = [i for i, l in enumerate(lines) if l == 'end']
    if not ends or any(lines[ends[-1] + 1:]):
        return None
    out, started = [], False
    for line in lines[:ends[-1] + 1]:
        if not started and (not line or _HEADER.match(line)):
            continue                                   # the show-command header block
        started = True
        if line.strip() == '!' or _TIMESTAMP.match(line) or _CLOCK_PERIOD.match(line):
            continue
        out.append(line)
    return out


def config_digest(text):
    """SHA-256 of exactly the lines compare_configs compares (normalized), or None when the
    text is not comparable. Equal digests <=> compare_configs would find them equal. Used to
    recognise the restored configuration later without keeping its text."""
    lines = normalized(text)
    if lines is None:
        return None
    return hashlib.sha256('\n'.join(lines).encode('utf-8')).hexdigest()


def compare_configs(running, expected):
    """(equal, description). The description never contains configuration text."""
    a, b = normalized(running), normalized(expected)
    if a is None or b is None:
        return False, 'not comparable (a configuration does not end with a final "end")'
    if a == b:
        return True, f'match ({len(b)} configuration lines)'
    changed, first = 0, None
    for tag, i1, i2, j1, j2 in difflib.SequenceMatcher(a=a, b=b, autojunk=False).get_opcodes():
        if tag != 'equal':
            changed += max(i2 - i1, j2 - j1)
            first = j1 + 1 if first is None else first
    return False, (f'mismatch: {changed} line(s) differ (first difference at configuration '
                   f'line {first})')


def transfer_text(text):
    """The file written to flash: the configuration without the show-command header lines,
    up to and including "end", trailing spaces removed."""
    lines = [l.rstrip() for l in (text or '').replace('\r\n', '\n').replace('\r', '\n')
             .split('\n')]
    while lines and (not lines[0].strip() or _HEADER.match(lines[0].strip())):
        lines.pop(0)
    ends = [i for i, l in enumerate(lines) if l == 'end']
    return '\n'.join(lines[:ends[-1] + 1]) if ends else None


def tcl_safe(text):
    """Netmiko's InLineTransfer refuses curly braces and a trailing backslash; non-ASCII
    text is refused here as well."""
    return text.isascii() and not re.search(r'[{}]', text) and \
        not re.search(r'\\$', text, re.MULTILINE)


# ---------------------------------------------------------------- the result
@dataclass
class RestoreResult:
    status: str = UNKNOWN
    device_ip: str = ''
    identity: dict = field(default_factory=dict)
    backup_file: str = ''
    safety_backup_file: str = ''
    transfer_method: str = None
    temp_file: str = None
    timer_minutes: int = None
    transferred: bool = False
    md5_verified: bool = False
    replace_attempted: bool = False
    comparison: str = 'not compared'
    timer_state: str = 'not started'
    confirmed: bool = False
    rollback_attempted: bool = False
    rollback_method: str = None
    rollback_verified: bool = False
    device_state: str = NOTHING_SENT
    cleanup: str = 'not needed'
    steps: list = field(default_factory=list)            # (kind, text)
    manual_actions: list = field(default_factory=list)
    # Phase 4H: config_digest of the running configuration verified after the confirmation
    # (SUCCESS only), and the process-local seal over the result (see result_seal_valid).
    restored_digest: str = None
    seal: str = None

    def lines(self):
        out = [f'Restore of {self.device_ip}: {self.status}',
               f'  Device: {connect.describe_identity(self.identity) if self.identity else "?"}',
               f'  Backup restored: {self.backup_file}',
               f'  Pre-restore safety backup: {self.safety_backup_file}',
               f'  Transfer: {self.transfer_method or "none"} to flash:{self.temp_file or "?"}'
               f' (MD5 verified: {"yes" if self.md5_verified else "no"})',
               f'  Configuration comparison: {self.comparison}',
               f'  Rollback timer: {self.timer_state}',
               f'  Rollback attempted: {"yes" if self.rollback_attempted else "no"}'
               + (f' ({self.rollback_method})' if self.rollback_method else '')
               + f', verified: {"yes" if self.rollback_verified else "no"}',
               f'  Device state: {self.device_state}',
               f'  Temporary file cleanup: {self.cleanup}']
        out += [f'  ACTION REQUIRED: {a}' for a in self.manual_actions]
        return out


class _Ctx:
    """Everything one restore needs. Holds the two configurations in memory only."""

    def __init__(self, preflight, creds, minutes, key_source, report, wait, clock, res):
        self.pre, self.creds, self.minutes = preflight, creds, minutes
        self.key_source, self.report, self.wait, self.clock, self.res = \
            key_source, report, wait, clock, res
        self.ip = preflight.device_ip
        self.name = preflight.temp_name
        self.target = self.original = self.text = self.data = self.md5 = None
        self.replace_started = None
        self.identity_mismatch = False

    def step(self, kind, text):
        self.res.steps.append((kind, text))
        self.report(kind, text)

    def forget(self):
        self.target = self.original = self.text = self.data = None


# ---------------------------------------------------------------- entry point
def restore(preflight, creds, timer_minutes=DEFAULT_TIMER_MINUTES, key_source=None, log=None,
            clock=time.monotonic, wait=time.sleep):
    """Restore the preflight's selected backup to its device. Returns a RestoreResult;
    never raises for device, network or backup problems. wait(seconds) is used to wait for
    a reconnection or the rollback timer (tests pass the Mock Lab's simulated clock)."""
    report = connect._Report(log)
    res = RestoreResult(device_ip=getattr(preflight, 'device_ip', '') or '')
    report('section', 'RESTORE')
    problem = _gate(preflight, creds, timer_minutes, clock)
    if problem:
        res.steps.append(('error', problem))
        report('error', f'REFUSED: {problem}')
        return _finish(res, report)
    res.identity = dict(preflight.identity)
    res.backup_file = preflight.selection.path
    res.safety_backup_file = preflight.safety_backup_path
    res.temp_file, res.timer_minutes = preflight.temp_name, timer_minutes
    preflight.stage = R.RESTORE_STARTED           # single use: the seal no longer verifies
    ctx = _Ctx(preflight, creds, timer_minutes, key_source, report, wait, clock, res)
    try:
        if _load(ctx):
            _run(ctx)
    except Exception as err:                       # never crash; never claim anything
        ctx.step('error', f'The restore stopped unexpectedly ({type(err).__name__}).')
        if res.replace_attempted and res.device_state not in (RESTORED, ORIGINAL_VERIFIED):
            res.device_state = STATE_UNKNOWN
    finally:
        ctx.forget()
    return _finish(res, report)


def _gate(pre, creds, minutes, clock):
    """None, or why the restore may not start (nothing was sent)."""
    if not isinstance(pre, R.PreflightResult):
        return 'There is no preflight result.'
    if pre.stage != R.SAFETY_BACKUP_CREATED:
        return f'The preflight is not ready for a restore (stage: {pre.stage}).'
    if not R.seal_valid(pre):
        return ('The preflight result was changed after the safety backup was made (or was '
                'not produced by the preflight); run the preflight again.')
    if pre.status not in (R.PASS, R.WARNING):
        return f'The preflight did not pass ({pre.status}).'
    if not pre.confirmed_phrase or not pre.required_confirmation or not hmac.compare_digest(
            pre.confirmed_phrase.encode(), pre.required_confirmation.encode()):
        return 'The restore was not confirmed with the exact typed phrase.'
    if (creds or {}).get('host') != pre.device_ip:
        return 'These login details are for another device.'
    if isinstance(minutes, bool) or not isinstance(minutes, int) or \
            not MIN_TIMER_MINUTES <= minutes <= MAX_TIMER_MINUTES:
        return (f'The rollback timer must be {MIN_TIMER_MINUTES} to {MAX_TIMER_MINUTES} '
                f'minutes.')
    if pre.safety_backup_at is None or clock() - pre.safety_backup_at > START_WINDOW_SECONDS:
        return 'The safety backup is too old; run the preflight again.'
    if not pre.safety_backup_path or not pre.safety_backup_sha256:
        return 'There is no verified pre-restore safety backup.'
    if pre.transfer_method not in ('tcl', 'scp') or not _TEMP.match(pre.temp_name or ''):
        return 'The preflight chose no usable transfer method or temporary file name.'
    if R.needs_live_identity(pre, {'host': pre.backup.get('host')}) and \
            not pre.live_identity_verified:
        return 'The live serial number and platform were not verified for this backup.'
    if not B._known(pre.identity.get('serial')):
        return 'The preflight recorded no device serial number.'
    return None


def _load(ctx):
    """Re-verify the selected backup and the safety backup; keep both in memory."""
    pre, res = ctx.pre, ctx.res
    scratch = R.PreflightResult(ctx.ip, pre.selection)
    header, text = R._reverify(pre.selection, scratch, ctx.key_source, 'backup')
    if header is None:
        ctx.step('error', f'Selected backup: {scratch.checks[-1].text}')
        return False
    if header['plaintext_sha256'] != pre.backup.get('plaintext_sha256'):
        ctx.step('error', 'The selected backup is not the one the preflight checked.')
        return False
    ctx.target = text
    ctx.step('ok', scratch.checks[-1].text)
    try:
        key_for = connect.load_backup_key(ctx.key_source).key_for
        data = B._read(pre.safety_backup_path)
        plain, sheader = C.decrypt_backup(data, key_for)
    except (connect.BackupKeyUnavailable, OSError, C.BackupCryptoError) as err:
        reason = str(err) if isinstance(err, (C.BackupCryptoError, connect.BackupError)) \
            else type(err).__name__
        ctx.step('error', f'The pre-restore safety backup cannot be used: {reason}')
        return False
    try:
        ok = (sheader.get('purpose') == R.PURPOSE and sheader.get('host') == ctx.ip and
              sheader['plaintext_sha256'] == pre.safety_backup_sha256 and
              sheader.get('serial') == pre.identity.get('serial') and
              sheader.get('platform') == pre.identity.get('platform'))
        ctx.original = plain.decode('utf-8') if ok else None
    except UnicodeDecodeError:
        ok = False
    finally:
        del plain
    if not ok or connect.check_backup(ctx.original):
        ctx.step('error', 'The pre-restore safety backup does not match this restore.')
        return False
    ctx.step('ok', 'Pre-restore safety backup decrypted and checked in memory.')
    ctx.text = transfer_text(ctx.target)
    if not ctx.text:
        ctx.step('error', 'The backup has no complete configuration to transfer.')
        return False
    method = pre.transfer_method
    if method == 'tcl' and not tcl_safe(ctx.text):
        if pre.capabilities.get('scp'):
            method = 'scp'
            ctx.step('warn', 'The configuration cannot be sent through Tcl (curly braces, a '
                             'trailing backslash or non-ASCII text); SCP is used instead.')
        else:
            ctx.step('error', 'The configuration cannot be sent through Tcl (curly braces, a '
                              'trailing backslash or non-ASCII text) and SCP is not enabled.')
            return False
    res.transfer_method = method
    ctx.data = (ctx.text + '\n').encode('utf-8')      # the device stores a final newline
    ctx.md5 = hashlib.md5(ctx.data).hexdigest()
    return True


# ---------------------------------------------------------------- sessions
def _hard_close(conn):
    """Close the SSH transport directly: Netmiko's disconnect would send a newline."""
    if conn is None:
        return
    for close in (lambda: conn.remote_conn.get_transport().close(),
                  lambda: conn.remote_conn.close()):
        try:
            close()
        except Exception:
            pass


WATCHDOG_THREAD = 'netcommand-restore-ssh-watchdog'


def _alive(conn):
    try:
        chan = conn.remote_conn
        return not (chan.closed or chan.eof_received) and chan.get_transport().is_active()
    except Exception:
        return False


@contextmanager
def _watch(conn):
    """Netmiko keeps reading a closed channel until its read timeout (paramiko's
    recv_ready() stays False). While a Netmiko call runs, this watchdog detaches the
    channel as soon as the SSH transport is gone, so the call fails at once. It only reads
    the state of this one connection and sets its channel to None: it never writes to the
    device and never closes anything. The thread is joined before the call returns."""
    stop = threading.Event()

    def watch():
        while not stop.wait(0.2):
            if not _alive(conn):
                try:
                    conn.channel.remote_conn = None     # Netmiko then raises ReadException
                except Exception:
                    pass
                return
    thread = threading.Thread(target=watch, daemon=True, name=WATCHDOG_THREAD)
    thread.start()
    try:
        yield
    finally:
        stop.set()
        thread.join(1)               # it wakes within 0.2 s; nothing is left running


def _cmd(ctx, conn, command, timeout=COMMAND_TIMEOUT):
    """The device's answer (without the prompt). UnexpectedPrompt for a question, which is
    never answered; the caller must hard-close the session. Only the command is logged,
    never the answer."""
    ctx.report('command', command)
    with _watch(conn):
        out = conn.send_command(command, expect_string=_EXPECT, strip_prompt=False,
                                strip_command=True, read_timeout=timeout) or ''
    text = out.rstrip()
    if re.search(_QUESTION, text):
        raise UnexpectedPrompt(command)
    lines = text.split('\n')
    if lines and re.search(_EXEC_PROMPT, '\n' + lines[-1].strip()):
        lines = lines[:-1]
    return '\n'.join(lines)


def _connect(ctx, label):
    """A new, verified session (SSH 2, privilege 15, the preflight's serial and platform),
    or None. Retries a few times (wait between). A different device is never used."""
    for attempt in range(RECONNECT_ATTEMPTS):
        try:
            conn = connect._open(ctx.creds)
        except Exception as err:
            _kind, text = ssh_options.describe_error(err, ctx.ip)
            ctx.step('warn', f'{label}: the SSH connection could not be opened ({text}).')
            if attempt < RECONNECT_ATTEMPTS - 1:
                ctx.wait(RECONNECT_WAIT_SECONDS)
            continue
        try:
            problem = _verify_session(ctx, conn)
        except UnexpectedPrompt:
            problem = 'the device asked an unexpected question'
        except Exception as err:
            problem = f'the session failed ({type(err).__name__})'
        if problem is None:
            ctx.step('ok', f'{label}: connected; SSH 2, privilege 15 and the same serial '
                           f'number and platform confirmed.')
            return conn
        _hard_close(conn)
        ctx.step('error', f'{label}: {problem}.')
        if ctx.identity_mismatch:
            return None                    # never retried: it is not our device
    return None


def _verify_session(ctx, conn):
    scratch = R.PreflightResult(ctx.ip, None)
    if R._ssh_protocol(conn, scratch) in (R.BLOCKED, R.FAILED):
        return scratch.checks[-1].text.rstrip('.')
    problem = connect.privilege_problem(_cmd(ctx, conn, connect.SHOW_PRIVILEGE))
    if problem:
        return f'privilege level 15 is required ({problem})'
    identity, problems = R.live_identity(_cmd(ctx, conn, connect.SHOW_VERSION),
                                         _cmd(ctx, conn, R.SHOW_INVENTORY), '')
    if problems:
        ctx.identity_mismatch = True
        return problems[0][1].rstrip('.')
    want = ctx.pre.identity
    if identity['serial'] != want.get('serial') or \
            (identity['platform'] or '').casefold() != (want.get('platform') or '').casefold():
        ctx.identity_mismatch = True
        return (f'a different device answers at {ctx.ip} (serial {identity["serial"]}, '
                f'platform {identity["platform"]}); nothing is sent to it')
    return None


def _running(ctx, conn):
    return _cmd(ctx, conn, R.SHOW_RUNNING)


def _timer(ctx, conn):
    """(pending: True/False/None, remaining seconds or None)."""
    out = _cmd(ctx, conn, R.SHOW_ROLLBACK_TIMER)
    if _NO_PENDING in out.lower():
        return False, None
    m = _REMAINING.search(out)
    if m:
        return True, int(m.group(1))
    return None, None


def _file_exists(ctx, conn):
    out = _cmd(ctx, conn, f'dir flash:/{ctx.name}')
    if _NOT_FOUND.search(out):
        return False
    if ctx.name in out:
        return True
    return None


# ---------------------------------------------------------------- the restore
def _run(ctx):
    res = ctx.res
    ctx.report('section', 'CONNECT AND CHECK')
    a = _connect(ctx, 'Session A')
    if a is None:
        ctx.step('error', 'The restore did not start; nothing was sent to the device.')
        return
    try:
        if not _before_transfer(ctx, a):
            return
        ctx.report('section', 'TRANSFER')
        if not _transfer(ctx, a):
            a = None                              # _transfer closed it if it was unusable
            return
        ctx.report('section', 'CONFIGURE REPLACE')
        outcome = _replace(ctx, a)
        if outcome in ('prompt', 'lost'):
            _hard_close(a)                        # never reused: a question may be pending
            a = None
        if outcome != 'ok':
            _recover(ctx, [a] if a else [], f'configure replace did not complete ({outcome})')
        else:
            _after_replace(ctx, a)
        a = None
    finally:
        _hard_close(a)


def _before_transfer(ctx, a):
    res = ctx.res
    pending, _ = _timer(ctx, a)
    if pending is not False:
        ctx.step('error', 'A rollback timer is pending or its state cannot be read; nothing '
                          'was sent.')
        return False
    running = _running(ctx, a)
    facts = R.parse_config(running)
    if not facts.archive_path:
        ctx.step('error', 'No archive path is configured any more; nothing was sent.')
        return False
    equal, _desc = compare_configs(running, ctx.original)
    if not equal:
        ctx.step('error', 'The running configuration changed after the safety backup was '
                          'made; run the preflight again. Nothing was sent.')
        return False
    if res.transfer_method == 'scp' and not facts.scp_enabled:
        ctx.step('error', 'SCP is no longer enabled; nothing was sent.')
        return False
    exists = _file_exists(ctx, a)
    if exists is not False:
        ctx.step('error', f'flash:{ctx.name} already exists or cannot be checked; it is never '
                          f'overwritten. Nothing was sent.')
        return False
    found = R._FREE.findall(_cmd(ctx, a, 'dir flash:'))
    if len(found) != 1 or int(found[0][1]) < len(ctx.data) + len(running) + \
            R.FLASH_MARGIN_BYTES:
        ctx.step('error', 'There is not enough free flash space (or it cannot be read); '
                          'nothing was sent.')
        return False
    ctx.step('ok', 'Device unchanged since the safety backup; no pending rollback; archive '
                   'configured; temporary file name free; enough flash space.')
    return True


def _transfer(ctx, a):
    """True when flash:<name> holds exactly the configuration (MD5 verified)."""
    res = ctx.res
    res.transferred = True
    try:
        with _watch(a):
            _send_file(ctx, a)
        ctx.step('ok', f'Configuration sent by {res.transfer_method} to flash:{ctx.name} '
                       f'from memory.')
        out = _cmd(ctx, a, f'verify /md5 flash:/{ctx.name}', MD5_TIMEOUT)
        found = _MD5.findall(out)
        if len(found) == 1 and hmac.compare_digest(found[0].lower(), ctx.md5):
            res.md5_verified = True
            ctx.step('ok', f'MD5 verified on the device ({ctx.md5}).')
            return True
        ctx.step('error', 'The MD5 of the transferred file does not match the configuration; '
                          'configure replace is not run.')
        session = a
    except Exception as err:
        ctx.step('error', f'The transfer failed ({type(err).__name__}); configure replace is '
                          f'not run.')
        _hard_close(a)
        session = None
    _abandon_transfer(ctx, session)
    return False


def _send_file(ctx, a):
    """Write the configuration from memory to flash:<name> (Tcl or SCP)."""
    if ctx.res.transfer_method == 'tcl':
        from netmiko.cisco.cisco_ios import InLineTransfer
        with InLineTransfer(a, source_config=ctx.text, dest_file=ctx.name,
                            file_system='flash:') as transfer:
            transfer.put_file()
    else:
        import scp
        client = scp.SCPClient(a.remote_conn.get_transport(), socket_timeout=15)
        try:
            client.putfo(io.BytesIO(ctx.data), f'flash:/{ctx.name}')       # memory only
        finally:
            client.close()


def _abandon_transfer(ctx, session):
    """After a failed transfer: delete the file (if any) and check the configuration is
    unchanged. Nothing was replaced."""
    res = ctx.res
    try:
        if session is None:
            session = _connect(ctx, 'Cleanup session')
        if session is None:
            res.device_state = NOT_REPLACED
            res.cleanup = 'not possible (no connection)'
            res.manual_actions.append(f'Check flash:{ctx.name} on {ctx.ip} and delete it if it '
                                      f'exists. The configuration was not replaced.')
            return
        _cleanup(ctx, session)
        equal, _ = compare_configs(_running(ctx, session), ctx.original)
        pending, _ = _timer(ctx, session)
        res.device_state = UNCHANGED_VERIFIED if equal and pending is False else STATE_UNKNOWN
    except Exception as err:
        ctx.step('error', f'Cleanup after the failed transfer failed ({type(err).__name__}).')
        res.device_state = STATE_UNKNOWN
    finally:
        _hard_close(session)


def _replace(ctx, a):
    """'ok', 'failed' (an answer that is not a clean success), 'prompt' or 'lost'."""
    res = ctx.res
    res.replace_attempted = True
    ctx.replace_started = ctx.clock()
    res.timer_state = f'started ({ctx.minutes} minutes)'
    command = f'configure replace flash:{ctx.name} list force time {ctx.minutes}'
    try:
        out = _cmd(ctx, a, command, REPLACE_TIMEOUT)          # its output is never logged
    except UnexpectedPrompt:
        ctx.step('error', 'configure replace asked an unexpected question. It was NOT '
                          'answered; the session is closed.')
        return 'prompt'
    except Exception as err:
        ctx.step('error', f'The connection was lost during configure replace '
                          f'({type(err).__name__}).')
        return 'lost'
    text = out.lower()
    rejected = 'rejected' in text or 'aborted' in text or connect.rejection(out) or \
        any(l.strip().startswith('%') for l in out.splitlines())
    if 'rollback done' in text and not rejected:
        ctx.step('ok', 'configure replace reported "Rollback Done" with no rejected command.')
        return 'ok'
    ctx.step('error', 'configure replace did not complete cleanly (rejected commands, an '
                      'error, or no "Rollback Done"): this is treated as a partial '
                      'replacement.')
    return 'failed'


def _after_replace(ctx, a):
    res = ctx.res
    ctx.report('section', 'VERIFY (new session)')
    b = _connect(ctx, 'Session B')
    if b is None:
        # Session A is still the verified original device: revert there.
        _recover(ctx, [a], 'the device could not be verified over a new session')
        return
    try:
        pending, _ = _timer(ctx, b)
        if pending is not True:
            res.timer_state = 'not pending after the replace' if pending is False else 'unknown'
            _recover(ctx, [b, a], 'the rollback timer is not pending after the replace')
            b = None
            return
        res.timer_state = 'pending'
        equal, desc = compare_configs(_running(ctx, b), ctx.target)
        res.comparison = desc
        ctx.step('ok' if equal else 'error', f'Running configuration vs. backup: {desc}.')
        if not equal:
            _recover(ctx, [b, a], 'the running configuration does not match the backup')
            b = None
            return
        ctx.report('section', 'CONFIRM')
        out = _cmd(ctx, b, 'configure confirm')
        if _NO_PENDING in out.lower() or connect.rejection(out):
            res.timer_state = 'not pending at confirmation (it may have expired)'
            ctx.step('error', 'configure confirm found no pending change: the timer may have '
                              'expired and rolled the device back.')
            _recover(ctx, [b, a], 'the confirmation failed')
            b = None
            return
        pending, _ = _timer(ctx, b)
        if pending is not False:
            res.timer_state = 'still pending after configure confirm' if pending else 'unknown'
            ctx.step('error', 'The rollback timer is not cancelled after configure confirm.')
            _recover(ctx, [b, a], 'the confirmation could not be verified')
            b = None
            return
        res.confirmed, res.timer_state = True, 'cancelled (verified)'
        ctx.step('ok', 'configure confirm accepted; the rollback timer is cancelled.')
        running = _running(ctx, b)
        equal, desc = compare_configs(running, ctx.target)
        res.comparison = desc + ' (after confirm)'
        res.restored_digest = config_digest(running) if equal else None
        if not equal:
            res.device_state = STATE_UNKNOWN
            ctx.step('error', f'After the confirmation the running configuration differs from '
                              f'the backup ({desc}).')
            res.manual_actions.append(f'The device kept a configuration that differs from the '
                                      f'backup and the rollback timer is cancelled. Restore it '
                                      f'from the safety backup {res.safety_backup_file} if '
                                      f'needed.')
            return
        res.device_state = RESTORED
        ctx.step('ok', 'Running configuration equals the backup after the confirmation.')
        _cleanup(ctx, b)
    except UnexpectedPrompt:
        _hard_close(b)
        b = None
        ctx.step('error', 'The device asked an unexpected question during verification. It '
                          'was NOT answered.')
        if not res.confirmed:
            _recover(ctx, [a], 'an unexpected question during verification')
        else:
            res.device_state = STATE_UNKNOWN if res.device_state != RESTORED else RESTORED
    except Exception as err:
        _hard_close(b)
        b = None
        ctx.step('error', f'The verification session failed ({type(err).__name__}).')
        if not res.confirmed:
            _recover(ctx, [a], 'the verification session failed')
        elif res.device_state != RESTORED:
            res.device_state = STATE_UNKNOWN
    finally:
        _hard_close(b)
        _hard_close(a)


# ---------------------------------------------------------------- rollback
def _recover(ctx, sessions, reason):
    """Bring the device back to the safety backup and VERIFY it, or report UNKNOWN."""
    res = ctx.res
    ctx.report('section', 'ROLLBACK')
    ctx.step('warn', f'Rolling back: {reason}.')
    res.rollback_attempted = True
    trusted = [s for s in sessions if s is not None]
    if not trusted and not ctx.identity_mismatch:
        fresh = _connect(ctx, 'Rollback session')
        trusted = [fresh] if fresh else []
    sent = False
    for conn in trusted:
        try:
            out = _cmd(ctx, conn, 'configure revert now')
            sent = True
            res.rollback_method = 'configure revert now'
            if 'rollback done' in out.lower():
                ctx.step('ok', 'configure revert now: "Rollback Done" (not trusted until '
                               'verified).')
            elif _NO_PENDING in out.lower():
                ctx.step('warn', 'configure revert now: no pending change (nothing to revert, '
                                 'or the timer already rolled back).')
            else:
                ctx.step('error', 'configure revert now did not report success.')
            break
        except UnexpectedPrompt:
            ctx.step('error', 'configure revert now asked an unexpected question; not '
                              'answered.')
            _hard_close(conn)
        except Exception as err:
            ctx.step('warn', f'configure revert now could not be sent on this session '
                             f'({type(err).__name__}).')
            _hard_close(conn)
    for conn in sessions + trusted:
        _hard_close(conn)
    if not sent:
        ctx.step('warn', 'configure revert now could not be sent.')

    state = _verify_original(ctx)
    if state['verified']:
        return
    pending = state['pending']
    if res.replace_attempted and not res.confirmed and pending is not False:
        remaining = state['remaining']
        if remaining is None:
            elapsed = ctx.clock() - (ctx.replace_started or ctx.clock())
            remaining = max(0, int(ctx.minutes * 60 - elapsed))
        seconds = remaining + TIMER_MARGIN_SECONDS
        ctx.step('warn', f'Waiting {seconds} s for the rollback timer (fallback).')
        ctx.wait(seconds)
        res.rollback_method = ((res.rollback_method + ', then ') if res.rollback_method
                               else '') + 'rollback timer (fallback)'
        if _verify_original(ctx)['verified']:
            return
    res.device_state = STATE_UNKNOWN
    res.timer_state = res.timer_state if pending is None else \
        ('pending' if pending else 'not pending')
    res.manual_actions.append(
        f'The device at {ctx.ip} could not be verified to be in its original configuration. '
        f'Check it from its console. If needed, restore the pre-restore safety backup '
        f'{res.safety_backup_file} (backup_tool.py export, then configure it by hand), and '
        f'delete flash:{ctx.name} if it is still there.')


def _verify_original(ctx):
    """{'verified', 'pending', 'remaining'}. On success: device_state, rollback_verified,
    timer state and cleanup are recorded."""
    res = ctx.res
    out = {'verified': False, 'pending': None, 'remaining': None}
    if ctx.identity_mismatch:
        ctx.identity_mismatch = False         # look again: the device may answer now
    conn = _connect(ctx, 'Rollback check')
    if conn is None:
        return out
    try:
        out['pending'], out['remaining'] = _timer(ctx, conn)
        equal, desc = compare_configs(_running(ctx, conn), ctx.original)
        ctx.step('ok' if equal else 'error', f'Running configuration vs. the safety backup: '
                                             f'{desc}.')
        if equal and out['pending'] is False:
            out['verified'] = True
            res.rollback_verified = True
            res.device_state = ORIGINAL_VERIFIED
            res.timer_state = 'not pending (verified after the rollback)'
            ctx.step('ok', 'Rollback verified: the device is in its original configuration.')
            _cleanup(ctx, conn)
        elif equal:
            ctx.step('warn', 'The configuration is the original one, but a rollback timer is '
                             'still pending.')
    except Exception as err:
        ctx.step('error', f'The rollback check failed ({type(err).__name__}).')
    finally:
        _hard_close(conn)
    return out


# ---------------------------------------------------------------- cleanup
def _cleanup(ctx, conn):
    """Delete only flash:<the temporary file>, then make sure it is gone."""
    res = ctx.res
    try:
        exists = _file_exists(ctx, conn)
        if exists is False:
            res.cleanup = 'not needed (the file does not exist)'
            return
        _cmd(ctx, conn, f'delete /force flash:/{ctx.name}')
        if _file_exists(ctx, conn) is False:
            res.cleanup = 'deleted and verified'
            ctx.step('ok', f'Temporary file flash:{ctx.name} deleted (verified).')
            return
    except UnexpectedPrompt:
        _hard_close(conn)
    except Exception:
        pass
    res.cleanup = 'FAILED: the temporary file is still on flash (or cannot be checked)'
    ctx.step('error', f'flash:{ctx.name} could not be deleted.')
    res.manual_actions.append(f'Delete flash:{ctx.name} on {ctx.ip} ("delete '
                              f'flash:{ctx.name}") and check it is gone.')


# ---------------------------------------------------------------- outcome
_SEALED_FIELDS = ('status', 'device_ip', 'identity', 'backup_file', 'safety_backup_file',
                  'transfer_method', 'confirmed', 'timer_state', 'comparison',
                  'device_state', 'cleanup', 'restored_digest')


def result_seal_of(res):
    """HMAC (the preflight's process-local key) over what a later step relies on."""
    import json
    body = json.dumps({name: getattr(res, name) for name in _SEALED_FIELDS},
                      sort_keys=True, default=str).encode('utf-8')
    return hmac.new(R._SEAL_KEY, body, hashlib.sha256).hexdigest()


def result_seal_valid(res):
    """True only for an unchanged RestoreResult produced by restore() in this process."""
    return isinstance(res, RestoreResult) and isinstance(res.seal, str) and \
        hmac.compare_digest(res.seal, result_seal_of(res))


def _finish(res, report):
    clean = res.cleanup in ('deleted and verified', 'not needed',
                            'not needed (the file does not exist)')
    if res.device_state == RESTORED and res.confirmed and \
            res.timer_state == 'cancelled (verified)':
        res.status = SUCCESS if clean else PARTIAL
    elif res.device_state in (NOTHING_SENT, NOT_REPLACED, UNCHANGED_VERIFIED,
                              ORIGINAL_VERIFIED):
        res.status = FAILED                   # a cleanup problem is in manual_actions
    else:
        res.status = UNKNOWN
        if not res.manual_actions:
            res.manual_actions.append(f'Check the device {res.device_ip} from its console; its '
                                      f'state could not be verified.')
    if res.status != SUCCESS:
        res.restored_digest = None            # only a verified SUCCESS may be saved later
    res.seal = result_seal_of(res)
    report('section', 'RESULT')
    kind = {SUCCESS: 'ok', PARTIAL: 'warn'}.get(res.status, 'error')
    for line in res.lines():
        report(kind if line.startswith('Restore of') else 'info', line)
    return res
