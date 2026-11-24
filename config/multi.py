"""Configuring several devices with the same settings, one after the other.

No window code here: the Configure page uses these functions, and the tests
call them directly with fake devices.

    targets, skipped = split_targets(devices, 'switch')     who may receive it
    results = run_devices(jobs, apply_fn, post=...)        one device at a time
    print(summary_text(results))

Every device goes through config.connect.apply_config on its own, so every
device gets its own encrypted backup, its own checks, and is saved only when its own
checks pass. One failure never changes another device's result.
"""
import inspect
import re

# configuration kinds -> the device type that may receive them
KINDS = {'switch': 'Switch settings', 'router': 'Router settings'}
CUSTOM = 'Commands'                  # typed or suggested by Findings: no type restriction

SUCCESS, PARTIAL, NOT_VERIFIED, FAILED, NOT_RUN = (
    'SUCCESS', 'PARTIALLY APPLIED', 'APPLIED, NOT VERIFIED', 'FAILED', 'NOT RUN')

_BACKUP = re.compile(r'\s*(?:Restore from the backup if needed|Backup): (.+?)\s*$')


# ---------------------------------------------------------------- who receives what
def incompatibility(device, kind):
    """Why `device` must not receive a `kind` configuration, or None if it may."""
    if kind not in KINDS:
        return None
    dtype = (device.get('type') or 'unknown').lower()
    if dtype == kind:
        return None
    if dtype in KINDS:
        return f'{KINDS[kind].lower()} cannot be sent to a {dtype}'
    return (f'its type is "{dtype}"; set it to switch or router on the Devices page '
            f'before sending {KINDS[kind].lower()}')


def split_targets(devices, kind):
    """-> (devices that may receive it, [(device, reason), ...] that may not)."""
    targets, skipped = [], []
    for d in devices:
        reason = incompatibility(d, kind)
        if reason:
            skipped.append((d, reason))
        else:
            targets.append(d)
    return targets, skipped


# ---------------------------------------------------------------- results
def backup_path(message):
    m = _BACKUP.search(message or '')
    return m.group(1) if m else None


def classify(ok, message):
    if ok:
        return SUCCESS
    text = message or ''
    if 'partially applied' in text:
        return PARTIAL
    if text.startswith('Check failed'):
        return NOT_VERIFIED
    return FAILED


def reason_of(message):
    """The message without its backup part (the backup is shown on its own line)."""
    text = _BACKUP.sub('', message or '').strip()
    return text.rstrip(' .') + '.' if text else ''


def _accepts_log(fn):
    try:
        params = inspect.signature(fn).parameters.values()
    except (TypeError, ValueError):
        return False
    return any(p.name == 'log' or p.kind == p.VAR_KEYWORD for p in params)


def _accepts(fn, name):
    """True when fn takes the keyword argument `name` (test fakes often do not)."""
    try:
        params = inspect.signature(fn).parameters.values()
    except (TypeError, ValueError):
        return False
    return any(p.name == name for p in params)


def run_devices(jobs, apply_fn, post=None, on_result=None, stop=None, stop_on_failure=False,
                preflight=None):
    """Configure the devices one after the other.

    preflight: called ONCE before the first device (for example the backup encryption
    key check, config.connect.backup_key_problem). It returns None, or a reason: then no
    device is contacted at all and every device is NOT RUN with that reason.

    jobs:      [{'device': {...}, 'creds': {...}, 'commands': [...], 'checks': [...],
                 'expected_type': 'switch' / 'router' / None}]
    apply_fn:  apply_config(creds, commands, checks[, log=][, expected_type=, device_name=])
               (a fake in the tests); expected_type is passed only for Switch / Router
               settings and only to a function that takes it
    post:      post(kind, text, device_name) for the SSH console (any thread)
    on_result: called with each device's result as soon as it is known
    stop:      a threading.Event; when set, devices not started yet are not run
    stop_on_failure: stop after the first device that does not succeed

    A device that REJECTS a command always stops the run: the same commands would
    most likely be half-applied on the remaining devices too.
    Returns [{'device', 'status', 'ok', 'message', 'backup', 'live'}].
    """
    post = post or (lambda *a: None)
    live = _accepts_log(apply_fn)
    typed = _accepts(apply_fn, 'expected_type')
    results, halt = [], None
    if preflight is not None and jobs:
        try:
            problem = preflight()
        except Exception as err:                    # a failing check never lets devices run
            problem = f'the check before the first device failed ({type(err).__name__})'
        if problem:
            halt = f'{str(problem).rstrip(".")}. No device was contacted.'
            post('error', f'NOT STARTED: {halt}')
    for i, job in enumerate(jobs):
        d = job['device']
        if halt is None and stop is not None and stop.is_set():
            halt = 'stopped by the user before this device was started.'
        if halt:
            result = {'device': d, 'status': NOT_RUN, 'ok': False, 'live': False,
                      'message': f'Not run: {halt}', 'backup': None}
            post('warn', result['message'], d['name'])
        else:
            if len(jobs) > 1:
                post('device', f'DEVICE {i + 1} OF {len(jobs)}:  {d["name"]}  ({d["ip"]})')
            extra = {}
            if typed and job.get('expected_type'):     # Switch / Router settings only
                extra = {'expected_type': job['expected_type'], 'device_name': d['name']}
            try:
                if live:
                    ok, message = apply_fn(job['creds'], job['commands'], job['checks'],
                                           log=lambda kind, text, n=d['name']: post(kind, text, n),
                                           **extra)
                else:
                    ok, message = apply_fn(job['creds'], job['commands'], job['checks'], **extra)
                ran_live = live
            except Exception as err:                    # never lose the other devices
                ok, message, ran_live = False, f'Error: {type(err).__name__}: {err}', False
            result = {'device': d, 'status': classify(ok, message), 'ok': ok, 'live': ran_live,
                      'message': message, 'backup': backup_path(message)}
            if not ran_live:                        # the apply function did not report it
                post('ok' if ok else 'error', message, d['name'])
            if message.startswith('The device rejected a command'):
                halt = (f'a command was rejected on {d["name"]}, so the same commands were not '
                        f'sent to the remaining devices.')
            elif not ok and stop_on_failure:
                halt = f'{d["name"]} failed and "stop at the first failure" is on.'
        results.append(result)
        if on_result:
            on_result(result)
    return results


def counts(results):
    done = sum(r['status'] == SUCCESS for r in results)
    not_run = sum(r['status'] == NOT_RUN for r in results)
    return {'completed': done, 'failed': len(results) - done - not_run,
            'not_run': not_run, 'total': len(results)}


def summary_text(results, skipped=()):
    """The MULTI-DEVICE CONFIGURATION SUMMARY, from the real results.
    skipped: [(device, reason)] selected but never sent anything (not compatible)."""
    lines = ['MULTI-DEVICE CONFIGURATION SUMMARY', '']
    for r in results:
        d = r['device']
        lines.append(f"{d['name']} - {d['ip']}")
        lines.append(f"Status: {r['status']}")
        if r['status'] != SUCCESS:
            lines.append(f"Reason: {reason_of(r['message'])}")
        if r['backup']:
            lines.append(f"Backup: {r['backup']}")
        lines.append('')
    for d, reason in skipped:
        lines += [f"{d['name']} - {d['ip']}", 'Status: SKIPPED (nothing sent)', f'Reason: {reason}.',
                  '']
    c = counts(results)
    lines += [f"Completed: {c['completed']}", f"Failed: {c['failed']}"]
    if c['not_run']:
        lines.append(f"Not run: {c['not_run']}")
    if skipped:
        lines.append(f'Skipped (not compatible): {len(skipped)}')
    lines.append(f"Total: {c['total']}")
    return '\n'.join(lines)
