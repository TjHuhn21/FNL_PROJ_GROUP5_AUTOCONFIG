# SSH Configuration Preview (Console-Based SSH Auto-Setup, phase 4)

After a device has been detected on the **Initial Setup** page, section **4 SSH
Configuration Preview** shows what an SSH setup of that device would involve: what is
already configured, what is missing, what would change, what conflicts, and the exact
commands, in order, with a plain explanation of each.

> **Preview only — no configuration commands have been sent to the device.**

This version only plans. The planner (`console/plan.py`) has no access to the console
session, the page has no Apply, Execute or Save button, and the command box is
read-only. Sending the commands (and saving with `write memory`) is left for a later
phase, after the preview has been checked on real hardware.

## Using it

1. Connect and click **Detect Device** (see `docs/INITIAL_SETUP.md`).
2. Optionally enter what you want to set. **Empty fields keep what the device has.**
   * *New hostname*: letters, numbers and dashes, starting with a letter; not `Router` or
     `Switch` (IOS will not create RSA keys with the factory name).
   * *Domain name*: for example `lab.local`.
   * *New SSH username* and the *password* (twice): 8–64 characters, no accents, no `?`
     (IOS treats `?` as a help request), no space at the start or end. These are
     NetCommand's own rules; they have **not** been checked against the limits of a real
     IOS release (maximum secret length, spaces inside a secret), which may be stricter.
   * *RSA key size*: only sizes offered for the detected software (classic IOS: 1024 or
     2048; IOS-XE: 2048 or 4096; default 2048).
3. Click **Preview SSH Configuration**, or **Detect Again and Preview** to read the device
   again first so the plan uses current information.

The password fields are masked and emptied as soon as you click either button. The
password is checked (length, matching, characters) and then dropped: the plan only
records *that* a password was given, and every command shows `<SSH_PASSWORD>` instead.
Nothing is saved, logged or shown. (Python keeps a copy of the typed text in memory until
it is garbage-collected; it is not referenced anywhere after the check. The console
session's own login password stays in memory until the session is closed.)

## What it checks

From the detection (all read with `show` commands; see `docs/CONSOLE_DETECTION.md`):

| Setting | Read from |
|---|---|
| Hostname | `show running-config \| include hostname` |
| Domain name | `show running-config \| include ip domain` |
| Local accounts and their privilege levels (never their secrets) | `show running-config \| include username` |
| RSA key pairs (names, and size when the output states it) | `show crypto key mypubkey rsa` |
| The key SSH uses | `show ip ssh` ("IOS Keys in SECSH format"), `ip ssh rsa keypair-name` |
| SSH version, timeout, retries | `show ip ssh`, `show running-config \| include ip ssh` |
| Other `ip ssh` settings (listed, not interpreted) | `show running-config \| include ip ssh` |
| AAA and its login method lists | `show running-config \| include aaa` |
| VTY ranges, login method, transport | `show running-config \| section line vty`, `show line` |
| Management IP | `show ip interface brief` |

A setting counts as "not configured" only when its search ran at **privilege level 15**.
At lower levels IOS can hide configuration lines, so a missing line then means
**unknown**, never "disabled".

## Statuses

| Status | Meaning |
|---|---|
| Already configured | Nothing to do. |
| Missing | Not configured; a command adds it (when the values are known). |
| Needs attention | Something you should know or decide (for example Telnet is also allowed, AAA controls logins, the factory hostname blocks key generation). |
| Conflict detected | Settings that contradict each other or cannot work now (for example `login local` without any local account, SSH not allowed on the VTY lines). |
| Unknown | Could not be read; the plan is careful about it (see below). |
| Unsupported | The device's software appears not to support SSH. |

## How the plan is made

Commands are proposed only when the device runs **classic IOS or IOS-XE**, its SSH state
is **Supported (enabled or not)**, detection **finished**, and it ran at **privilege
level 15** (confirmed by `show privilege`; when the level could not be read, nothing is
proposed, because settings that seem missing might only be hidden). Otherwise the page
explains why and proposes nothing; the statuses are still shown.

The proposed order is:

```
configure terminal
hostname <new name>                                   only if you entered one
ip domain-name <domain>                               (IOS-XE: ip domain name) only if entered
username <name> privilege 15 secret <SSH_PASSWORD>    only for a new account
crypto key generate rsa modulus <size>                only if SSH has no key (see below)
ip ssh version 2                                      only if not set yet (and SSH runs or
                                                      its key is created in this plan)
line vty <range>                                      for each configured range that needs it
 login local                                          only with a NEW account in this plan
 transport input ssh                                  only where SSH-only is not set yet
end
```

Each command is listed as a **safe addition** (nothing existing changes) or a **change to
an existing setting**; changes that can cut off people who use the device now are marked
**MAY CUT OFF CURRENT USERS** (for example Telnet removed, or a line password that works
today replaced by `login local`; a line that asks for a password but has none set is not
marked, because nobody can log in there now).

### Rules that prevent damage

* **Accounts.** An existing account is never changed. If the username you enter already
  exists, that is a conflict and no `username` command is proposed. A new account is only
  proposed when all local accounts could be read (otherwise it might replace one).
* **RSA keys.** Not every RSA key is an SSH key. The plan looks for the key SSH uses: the
  one `show ip ssh` names, the one set with `ip ssh rsa keypair-name`, or otherwise the
  one IOS names `hostname.domain`. Then:
  * SSH running, or SSH's key exists: kept, never regenerated (SSH's key existing while
    SSH is reported disabled needs attention: it is not proof that SSH is ready);
  * only `TP-self-signed-…` keys (the HTTPS server's self-signed certificate): SSH has no
    key, so one is proposed (it gets its own `hostname.domain` name);
  * keys whose purpose the output does not show, keys that could not be read, or a
    `keypair-name` pointing at a key that does not exist: **unknown**, and no key
    generation is proposed (it could duplicate or replace keys);
  * a key smaller than 768 bits is a conflict (SSH version 2 needs at least 768); it is
    not replaced automatically.
  A plan warning says so whenever keys exist but SSH is not reported as enabled.
* **Prerequisites.** Keys are only proposed when the device has (or will get) a hostname
  other than Router/Switch and a domain name. `ip ssh version 2` is only proposed once a
  key pair exists or is being created.
* **AAA.** AAA is never changed. With `aaa new-model`, logins follow AAA method lists,
  so the plan does not touch the VTY login and asks you to check the method list. If it is
  unknown whether AAA is on, the VTY login is not changed.
* **No lockout.** `login local` is proposed only when a **new** privilege-15 account is
  added in the same plan. An existing account is not enough: NetCommand cannot tell
  whether you know its password, and switching the login would lock you out if you do
  not.
* **VTY ranges.** Each configured range (`line vty 0 4`, `line vty 5 15`, ...) is planned
  separately, with its own login and protocols. The number of VTY lines comes from
  `show line`; lines it reports that are not in the configuration that was read are
  named, marked as needing attention, and NOT changed (do not assume they are secure).
  When the number cannot be read, that is stated, and when no VTY lines are configured at
  all and their number is unknown, no range is proposed.
* **Other SSH settings** (for example `ip ssh source-interface`) are listed as
  "Unknown": they are outside what the preview examines and are kept as they are.
* **Telnet.** Replacing `transport input telnet ssh` (or `all`) with `transport input ssh`
  is shown as a change that may cut off current users.
* **Nothing invented.** No hostname, domain name, username or IP address is ever made up.
  Management IP addresses are only reported; configuring one is not part of the preview.
* **Saving** (`write memory`) is never part of the plan.

### Out-of-date previews

Each preview states which detection it is based on. If you detect again, the console
session ends, or you change any of the values entered (including the key size), the
preview is marked **OUT OF DATE**; after a disconnect *Preview SSH Configuration* is
disabled until the device is detected again. **Detect Again and Preview** reads the device
first and then builds the plan from that fresh result; if that detection does not finish
(cable pulled, timeout, Cancel), the page says that no new preview was made and why.

## Steps, dependencies and checks (phase 5.1)

Every proposed command is also described as a **step** (`console/steps.py`; on the page:
*Show steps, dependencies and checks*). This is a model for a possible later execution
phase. **NetCommand still cannot execute configuration commands**: there is no runner,
the console session has no method that sends configuration, and the page has no Apply,
Execute or Save button. The steps are definitions; nothing runs them.

Each step has:

| Field | Meaning |
|---|---|
| `step_id` | stable name: `hostname`, `domain`, `user`, `rsa`, `ssh_version`, `ssh_ready`, `vty_login[0 4]`, `vty_transport[0 4]` |
| `command` | the plan's command (with `<SSH_PASSWORD>`), or none for a read-only check step |
| `requires` | steps that must be **verified** first |
| `preconditions` | the device state the step relies on (as read at detection) |
| `prompt` | the prompt expected afterwards, including the new name after `hostname` (the session would have to refresh the prompt it waits for) |
| `failure_replies` / `questions` | replies that mean "did not work", and device questions that are never answered automatically (for example the RSA "replace them? [yes/no]" question) |
| `verifications` | read-only `show` commands (all from the detection list) and what output counts as verified, failed or uncertain |
| `disruptive` / `approval_required` | whether a separate approval would be needed, and why |

Outcomes: **VERIFIED** (the checks show the intended state), **FAILED** (they show a
different state, or the reply was a known failure), **UNCERTAIN** (a check could not run,
was rejected or not recognised, the session ended, or the device does not print what is
needed). A step is never verified because its command was accepted: an accepted command
without checks is UNCERTAIN.

Dependencies:

| Step | Requires | Verified when |
|---|---|---|
| `hostname` | — | `show running-config \| include hostname` shows the new name |
| `domain` | — | `show running-config \| include ip domain` shows the new domain |
| `user` (new account) | — | `show running-config \| include username` shows it with privilege 15 and a secret |
| `rsa` | `hostname`, `domain` (when in the plan) | `show crypto key mypubkey rsa` lists `hostname.domain` (size checked only when printed); `show ip ssh` naming the key is supporting evidence |
| `ssh_version` | `rsa` (when in the plan) | `show ip ssh` reports "SSH Enabled - version 2.0" ("1.99" means the command had no effect: FAILED) |
| `ssh_ready` (check only) | `rsa`, `ssh_version` (when in the plan) | `show ip ssh` reports SSH enabled |
| `vty_login[range]` | `user` (the NEW account; an existing account is not enough) | that range shows `login local` |
| `vty_transport[range]` | `ssh_ready`, and `vty_login[range]` when it is in the plan | that range shows `transport input ssh` only |

A step is **ready** only when every step it requires is VERIFIED; a failed, uncertain or
not-yet-verified prerequisite blocks it, and everything that depends on it.

**AAA** is an *invariant*, not a step: `aaa_unchanged` checks that `show running-config |
include aaa` shows exactly what was detected. If AAA could not be read at detection, the
invariant can only be UNCERTAIN.

**Renames while SSH runs.** When SSH is running, changing the hostname or domain name is
marked disruptive and its step needs a separate approval, because the default SSH key is
named `hostname.domain` (what IOS does with a running SSH server after a rename has not
been checked on hardware).

**Known limits of the checks.** The RSA check relies on the key name: it cannot prove the
key is newly generated (only that none had this name at detection), and many releases do
not print the key size. The account check proves the account exists with privilege 15,
not that its password is the one typed (only a login can). Whether `show ip ssh` prints
the key line, and the exact failure messages, still need to be confirmed on hardware.

## Mock lab

With `python main.py --demo --mock-console`, simulated ports cover these cases (all
results and plans are marked SIMULATED):

| Port | Case |
|---|---|
| SIM1 | SSH fully set up (keys, version 2, admin account, VTY SSH only) |
| SIM2 | SSH supported but no RSA keys yet |
| SIM3 | image without SSH (unsupported) |
| SIM4 | SSH capability unknown |
| SIM8 | factory state: hostname `Router`, no domain, no accounts, no keys, VTY `login` |
| SIM9 | AAA (`aaa new-model`, `login authentication default`) |
| SIM10 | VTY allows Telnet and SSH |
| SIM11 | VTY lines without a login line |
| SIM12 | conflicting settings: `login local` without accounts, VTY allows Telnet only |
| SIM13 | SSH off, only an HTTPS `TP-self-signed` key |
| SIM14 | SSH off, a key of unknown purpose (`LEGACY-KEY`) |
| SIM15 | SSH off although its `hostname.domain` key exists |
| SIM16 | switch: `vty 0 4` local login + SSH, `vty 5 15` line password + Telnet |
| SIM17 | switch: `show line` reports 16 VTY lines, only `vty 0 4` configured |

(SIM5–SIM7 simulate connection problems; see `docs/INITIAL_SETUP.md`.)

Edge cases for future console configuration work (slow, failing or incomplete RSA key
generation, replace and key-size questions, prompt changes, SSH version mismatches,
log lines in the output, timeouts, a boot-loader prompt, a lost connection; SIM18–SIM37)
are described in `mock-lab/README.md`. They exist for automated tests and are not in the
normal `--mock-console` port list.

## Limitations and what is untested

* **Not tested on hardware.** The Cisco router is not available until Monday; everything
  here was verified with the mock lab and scripted output only.
* The command syntax follows common IOS 12.x/15.x usage. Exact behaviour per release
  (accepted RSA key sizes, whether `ip ssh version 2` is accepted before keys exist,
  IOS-XE's handling of `ip domain-name`, the default `transport input` when no line is
  shown) has not been verified and is reported as a limitation or unknown where it matters.
* `show crypto key mypubkey rsa` on many releases does not print the key size, so the size
  of existing keys is often "not shown".
* VTY lines that `show line` reports but the configuration does not show are only
  reported, never changed. Whether a real IOS release can show fewer ranges than it has
  lines has not been checked on hardware.
* Recognising HTTPS keys relies on the `TP-self-signed` name; other non-SSH key names are
  treated as unknown purpose. Whether the "IOS Keys in SECSH format" line of `show ip ssh`
  appears on every release has not been checked.
* Password rules (length 8–64, characters) are NetCommand's own and unverified against
  IOS limits.
* AAA servers (TACACS+/RADIUS) are not checked; the plan only shows the method lists.
* The preview does not set a management IP address, default gateway or SSH timeouts.
