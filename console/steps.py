"""Dependency and verification DEFINITIONS for the commands of an SSH configuration
preview (Console-Based SSH Auto-Setup, phase 5.1).

This module is a model only. It describes, for every command console.plan proposes:

    step_id          a stable identifier ('hostname', 'rsa', 'vty_login[0 4]', ...)
    command          the PlanCommand (text with <SSH_PASSWORD>), or None for a check step
    requires         the steps that must be VERIFIED before this one is ready
    preconditions    the device state the step relies on (read at detection)
    prompt           the prompt expected after it (hostname changes included)
    failure_replies  immediate replies that mean the command did not work
    questions        device questions that must NEVER be answered automatically
    verifications    read-only `show` commands, and what counts as verified / failed /
                     uncertain in their output
    disruptive / approval_required   whether a separate approval would be needed

plus `invariants`: settings that must stay exactly as detected (AAA).

The evaluators below are PURE functions over text they are given. Nothing here opens a
session, sends a command, or answers a prompt: the runner is console.apply (phase
5.1.2), which uses these definitions as they are. A step is never VERIFIED because its
command was accepted: only its verification output can make it VERIFIED.

    VERIFIED   the read-only checks show the intended state
    FAILED     the checks show a different state (or the reply was a known failure)
    UNCERTAIN  no conclusion: a check could not run, its output was not recognised, the
               session ended, or the information needed is not printed by the device
"""
import re
from dataclasses import dataclass, field

from console import detect

VERIFIED, FAILED, UNCERTAIN = 'verified', 'failed', 'uncertain'
CONFIG, CHECK = 'config', 'check'
NOT_RUN = 'not verified yet'

# replies that mean a configuration command did not take effect (in addition to the
# usual "% Invalid input" family). Collected from IOS messages; to be confirmed on hardware.
COMMON_FAILURE_REPLIES = ('% Invalid', '% Incomplete', '% Ambiguous', '% Unknown command',
                          '% Unrecognized', '% Bad ', '% Error', '%Error', '% Cannot',
                          'Command rejected', '% Please define', '% Please create')
GENERAL_UNCERTAIN = (
    'the reply to the command could not be read completely (timeout)',
    'the console session ended or was cancelled before the checks ran',
    'a check command could not run, was rejected, or its output was not recognised',
)


@dataclass
class Verification:
    command: str                  # a read-only show command (detect constants)
    verified: str                 # what output counts as verified
    failed: str                   # what output counts as failed
    uncertain: str                # what leaves it uncertain
    check: object = field(default=None, repr=False, compare=False)   # text -> (outcome, why)
    required: bool = True         # False: supporting evidence; UNCERTAIN does not count

    def evaluate(self, text):
        """(outcome, reason) for the output of `command` (None = it did not run)."""
        if text is None:
            return UNCERTAIN, f'"{self.command}" did not run'
        text, _logs = detect.strip_log_lines(text)          # console log lines are not answers
        if detect._rejection(text):
            return UNCERTAIN, f'the device rejected "{self.command}"'
        odd = detect.unexpected_answer(self.command, text)
        if odd:                                              # never read as "not configured"
            return UNCERTAIN, f'unexpected answer to "{self.command}": {odd[1]}'
        return self.check(text)


@dataclass
class PromptExpectation:
    mode: str                     # 'global configuration' / 'line configuration'
    prompt_after: str             # e.g. 'Edge-R1(config)#'
    hostname_changes_to: str = None
    note: str = ''


@dataclass
class PlanStep:
    step_id: str
    title: str
    kind: str                     # config (has a command) / check (read-only, no command)
    command: object = None        # console.plan.PlanCommand, or None for a check step
    requires: tuple = ()
    preconditions: list = field(default_factory=list)
    prompt: PromptExpectation = None
    failure_replies: tuple = ()
    questions: tuple = ()         # never answered automatically
    verifications: list = field(default_factory=list)
    uncertain_when: tuple = GENERAL_UNCERTAIN
    disruptive: bool = False
    approval_required: bool = False
    approval_reason: str = ''
    limitations: list = field(default_factory=list)

    @property
    def check_commands(self):
        return [v.command for v in self.verifications]

    def evaluate(self, outputs, reply=None):
        """(outcome, reasons) from the outputs of the verification commands
        ({command: text or None}) and, optionally, the command's own reply.
        Only the verifications can make a step VERIFIED."""
        if reply is not None and any(marker in reply for marker in self.failure_replies):
            return FAILED, ['the device rejected the command']
        if reply is not None and any(q.lower() in reply.lower() for q in self.questions):
            return UNCERTAIN, ['the device asked a question; it is never answered automatically']
        if not self.verifications:
            return UNCERTAIN, ['no verification is defined']
        outcomes, reasons = [], []
        for v in self.verifications:
            outcome, why = v.evaluate(outputs.get(v.command))
            reasons.append(why)
            if v.required or outcome == FAILED:
                outcomes.append(outcome)
        if FAILED in outcomes:
            return FAILED, reasons
        if UNCERTAIN in outcomes or not outcomes:
            return UNCERTAIN, reasons
        return VERIFIED, reasons


def readiness(steps, outcomes):
    """{step_id: (ready, reason)}: a step is ready only when every step it requires is
    VERIFIED. FAILED, UNCERTAIN or not-yet-verified prerequisites block it."""
    out = {}
    for step in steps:
        blockers = [f'{r} is {outcomes.get(r, NOT_RUN)}' for r in step.requires
                    if outcomes.get(r) != VERIFIED]
        out[step.step_id] = (not blockers, 'ready' if not blockers else
                             'blocked: ' + '; '.join(blockers))
    return out


# ---------------------------------------------------------------- evaluators (pure)
def _hostname_check(want):
    def check(text):
        name = detect.parse_hostname(text)
        if name is None:
            return UNCERTAIN, 'no hostname line in the output'
        return (VERIFIED, f'hostname is {want}') if name == want else \
            (FAILED, f'hostname is {name}, not {want}')
    return check


def _domain_check(want):
    def check(text):
        name = detect.parse_domain(text)
        if name is None:
            return FAILED, 'no domain name is configured'
        return (VERIFIED, f'domain is {want}') if name == want else \
            (FAILED, f'domain is {name}, not {want}')
    return check


def _user_check(name, privilege):
    def check(text):
        line = next((l for l in (text or '').splitlines()
                     if re.match(rf'^username {re.escape(name)}(\s|$)', l)), None)
        if line is None:
            return FAILED, f'no account named {name}'
        users = detect.parse_local_users(line)
        if not users or users[0].privilege != privilege:
            return FAILED, f'{name} does not have privilege {privilege}'
        if not re.search(r'\bsecret\b', line):
            return UNCERTAIN, f'{name} exists, but its password is not shown as a "secret"'
        return VERIFIED, f'{name} exists with privilege {privilege}'
    return check


def _rsa_check(label, size):
    def check(text):
        rsa = detect.parse_rsa(text)
        if rsa is None:
            return UNCERTAIN, 'the key list was not recognised'
        if not rsa.present:
            return FAILED, 'no RSA key exists'
        if label not in rsa.key_names:
            return UNCERTAIN, f'keys exist, but none is named {label}'
        if rsa.modulus_bits and rsa.modulus_bits != size:
            return FAILED, f'{label} has {rsa.modulus_bits} bits, not {size}'
        return VERIFIED, f'{label} exists' + ('' if rsa.modulus_bits else
                                             ' (its size is not printed; not confirmed)')
    return check


def _secsh_check(label):
    def check(text):
        key = detect.parse_secsh_key(text)
        if key is None:
            return UNCERTAIN, 'show ip ssh does not name the key SSH uses'
        if key == 'NONE':
            return FAILED, 'show ip ssh reports no key for SSH'
        return (VERIFIED, f'SSH uses {label}') if key == label else \
            (UNCERTAIN, f'SSH uses {key}, not {label}')
    return check


def _ssh_check(version=None):
    def check(text):
        enabled, shown, _missing = detect.parse_ip_ssh(text)
        if enabled is None:
            return UNCERTAIN, 'the SSH state was not recognised'
        if not enabled:
            return FAILED, 'SSH is disabled'
        if version and shown != version:
            return FAILED, f'SSH is enabled but reports version {shown}, not {version}'
        return VERIFIED, f'SSH is enabled (version {shown})'
    return check


def _vty_check(lines, attribute, expected, name):
    def check(text):
        block = next((b for b in detect.parse_vty(text) if b.lines == lines), None)
        if block is None:
            return UNCERTAIN, f'line vty {lines} is not shown'
        value = getattr(block, attribute)
        if value is None:
            return UNCERTAIN, f'line vty {lines} shows no {name} line'
        return (VERIFIED, f'vty {lines}: {name} is {expected}') if value == expected else \
            (FAILED, f'vty {lines}: {name} is {value}, not {expected}')
    return check


def _aaa_check(new_model, lists):
    def check(text):
        found = detect.parse_aaa(text)
        return (VERIFIED, 'AAA is unchanged') if found == (new_model, lists) else \
            (FAILED, 'the AAA configuration changed')
    return check


# ---------------------------------------------------------------- building the steps
def build_steps(plan, result, request, ssh_key_label):
    """(steps, invariants) for the commands of an available plan. Pure: reads only the
    plan, the detection result and the request (which never holds a password)."""
    cfg, ssh = result.config, result.ssh
    by_setting = {}
    for c in plan.commands:
        by_setting.setdefault(c.setting, []).append(c)
    host_now = result.device.hostname or 'unknown'
    host_after = request.hostname or host_now
    steps = []

    def config_prompt(line=False):
        return PromptExpectation('line configuration' if line else 'global configuration',
                                 f'{host_after}(config-line)#' if line else
                                 f'{host_after}(config)#')

    def add(step):
        if step.command is not None:
            step.command.step_id = step.step_id
            step.disruptive = step.command.disruptive
            if step.disruptive and not step.approval_required:
                step.approval_required = True
                step.approval_reason = 'it can cut off people who use the device now'
        steps.append(step)
        return step.step_id

    ssh_running = ssh.enabled is True
    rename_reason = ('SSH is running: renaming may affect the RSA key SSH uses (default name '
                     'hostname.domain); IOS behaviour unverified on hardware')

    ids = {}
    for c in by_setting.get('hostname', []):
        ids['hostname'] = add(PlanStep(
            'hostname', 'Set the hostname', CONFIG, c,
            preconditions=[f'the device was named {host_now} at detection'],
            prompt=PromptExpectation(
                'global configuration', f'{request.hostname}(config)#',
                hostname_changes_to=request.hostname,
                note='The prompt changes at once; the session must refresh the prompt it '
                     'waits for (Netmiko set_base_prompt) before the next step.'),
            failure_replies=COMMON_FAILURE_REPLIES,
            verifications=[Verification(
                detect.SHOW_HOSTNAME, f'"hostname {request.hostname}"',
                'another hostname', 'no hostname line, or the check did not run',
                _hostname_check(request.hostname))],
            approval_required=ssh_running, approval_reason=rename_reason if ssh_running else ''))
    for c in by_setting.get('domain', []):
        ids['domain'] = add(PlanStep(
            'domain', 'Set the domain name', CONFIG, c,
            preconditions=[f'domain at detection: {cfg.domain_name or "none"}'],
            prompt=config_prompt(), failure_replies=COMMON_FAILURE_REPLIES,
            verifications=[Verification(
                detect.SHOW_DOMAIN, f'domain name {request.domain_name}',
                'no domain name, or another one', 'the check did not run',
                _domain_check(request.domain_name))],
            approval_required=ssh_running, approval_reason=rename_reason if ssh_running else ''))
    for c in by_setting.get('user', []):
        ids['user'] = add(PlanStep(
            'user', 'Create the new administrator account', CONFIG, c,
            preconditions=[f'no account named {request.username} existed at detection '
                           f'(accounts read at privilege 15)',
                           'the password is supplied at execution time only (never stored)'],
            prompt=config_prompt(), failure_replies=COMMON_FAILURE_REPLIES,
            verifications=[Verification(
                detect.SHOW_USERNAMES, f'"username {request.username} privilege 15 secret ..."',
                f'no {request.username} account, or another privilege level',
                'the password is not shown as a "secret", or the check did not run',
                _user_check(request.username, 15))],
            limitations=['The check proves the account exists with privilege 15; it cannot '
                         'prove the password is the one typed (only a login can).']))
    for c in by_setting.get('rsa', []):
        requires = tuple(ids[k] for k in ('hostname', 'domain') if k in ids)
        ids['rsa'] = add(PlanStep(
            'rsa', 'Generate the RSA key pair for SSH', CONFIG, c, requires=requires,
            preconditions=[f'hostname is not Router/Switch (after the plan: {host_after})',
                           f'a domain name is set (after the plan: '
                           f'{request.domain_name or cfg.domain_name})',
                           f'no key named {ssh_key_label} existed at detection'],
            prompt=PromptExpectation(
                'global configuration', f'{host_after}(config)#',
                note='IOS prints progress lines ("% The key modulus size is ...", "% Generating '
                     '... keys") and can take up to a minute; a long reply time is expected.'),
            failure_replies=COMMON_FAILURE_REPLIES,
            questions=('Do you really want to replace them', '[yes/no]',
                       'How many bits in the modulus'),
            verifications=[
                Verification(detect.SHOW_RSA, f'a key named {ssh_key_label}',
                             'no RSA key at all, or a different size than requested',
                             f'keys exist but none named {ssh_key_label}, or the list is not '
                             f'recognised', _rsa_check(ssh_key_label, request.key_size)),
                Verification(detect.SHOW_IP_SSH, f'show ip ssh names {ssh_key_label}',
                             'show ip ssh reports NONE',
                             'the key line is not printed (supporting evidence only)',
                             _secsh_check(ssh_key_label), required=False)],
            limitations=['Key identity: the check relies on the key name (hostname.domain). It '
                         'cannot prove the key is newly generated, only that none had this name '
                         'at detection.',
                         'Key size: many IOS releases do not print it; then it is not '
                         'confirmed.',
                         'A replace question means a key already existed: it is never answered '
                         'and the step is not verified.']))
    for c in by_setting.get('ssh_version', []):
        requires = (ids['rsa'],) if 'rsa' in ids else ()
        ids['ssh_version'] = add(PlanStep(
            'ssh_version', 'Allow SSH version 2 only', CONFIG, c, requires=requires,
            preconditions=['SSH is running, or its key was created (step rsa verified)'],
            prompt=config_prompt(), failure_replies=COMMON_FAILURE_REPLIES,
            verifications=[Verification(
                detect.SHOW_IP_SSH, '"SSH Enabled - version 2.0"',
                'SSH disabled, or still "version 1.99" (the command was accepted but has no '
                'effect)', 'the SSH state was not recognised', _ssh_check('2.0'))]))
    vty = [c for c in plan.commands if c.mode]
    if vty or 'rsa' in ids or 'ssh_version' in ids:
        requires = tuple(ids[k] for k in ('rsa', 'ssh_version') if k in ids)
        ids['ssh_ready'] = add(PlanStep(
            'ssh_ready', 'Confirm SSH is enabled and usable', CHECK, None, requires=requires,
            preconditions=['an RSA key for SSH exists (detected, or step rsa verified)'],
            verifications=[Verification(
                detect.SHOW_IP_SSH, '"SSH Enabled"', 'SSH disabled',
                'the SSH state was not recognised', _ssh_check())],
            limitations=['This checks the device side only. Whether SSH can be reached over '
                         'the network is a separate, later check.']))
    login_ids = {}
    for c in vty:
        lines = c.mode.split('line vty ', 1)[1]
        if c.setting == 'vty_login':
            requires = (ids['user'],) if 'user' in ids else ()
            login_ids[lines] = add(PlanStep(
                f'vty_login[{lines}]', f'Ask for a local account on vty {lines}', CONFIG, c,
                requires=requires,
                preconditions=[f'the NEW account {request.username} is VERIFIED (step user); '
                               f'an existing account is not enough'],
                prompt=config_prompt(line=True), failure_replies=COMMON_FAILURE_REPLIES,
                verifications=[Verification(
                    detect.SHOW_VTY, f'line vty {lines} shows "login local"',
                    'another login method', f'line vty {lines} or its login line is not shown',
                    _vty_check(lines, 'login', 'local', 'login'))]))
        else:
            requires = ((ids['ssh_ready'],) +
                        ((login_ids[lines],) if lines in login_ids else ()))
            add(PlanStep(
                f'vty_transport[{lines}]', f'Allow only SSH on vty {lines}', CONFIG, c,
                requires=requires,
                preconditions=['SSH is VERIFIED as enabled (step ssh_ready)'] +
                              ([f'login local on vty {lines} is VERIFIED'] if lines in login_ids
                               else []),
                prompt=config_prompt(line=True), failure_replies=COMMON_FAILURE_REPLIES,
                verifications=[Verification(
                    detect.SHOW_VTY, f'line vty {lines} shows "transport input ssh" only',
                    'other protocols (telnet, all, none)',
                    f'line vty {lines} or its transport line is not shown',
                    _vty_check(lines, 'transport_input', ['ssh'], 'transport input'))]))
    invariants = [PlanStep(
        'aaa_unchanged', 'AAA stays exactly as detected (out of scope)', CHECK, None,
        preconditions=['AAA is never changed by this plan'],
        verifications=[Verification(
            detect.SHOW_AAA, 'the same aaa lines as at detection',
            'any difference', 'AAA could not be read at detection',
            _aaa_check(cfg.aaa_new_model, cfg.aaa_login_lists) if cfg.aaa_known else
            (lambda text: (UNCERTAIN, 'AAA was not known at detection')))])]
    return steps, invariants
