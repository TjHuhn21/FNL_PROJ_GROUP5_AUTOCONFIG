# Console device detection (Console-Based SSH Auto-Setup, phase 2)

`console/detect.py` looks at a device over an already open console session and reports
what it is and whether it can do SSH. **It only reads.** It does not change the hostname,
an IP address, a username, SSH, RSA keys or the VTY lines, and it never saves the
configuration. The Initial Setup page (`gui/setup_tab.py`, see `docs/INITIAL_SETUP.md`)
runs it from the GUI.

```python
from console.link import ConsoleSession
from console.detect import detect_device

with ConsoleSession('COM4', enable_password='...') as session:   # phase 1
    session.connect()
    result = detect_device(session)            # or detect_device(session, elevate=True)
    print(result.summary())
```

Like `ConsoleSession`, `detect_device` blocks on serial I/O, so the GUI must call it from
a worker thread (`gui.background.run_async`).

## What is sent

Only these commands, in this order, each through `ConsoleSession.send_show` (which
refuses anything that is not a single `show ...` line):

| Command | Used for |
|---|---|
| `show version` | software (IOS, IOS-XE, NX-OS...), version, image file, feature set, model, router/switch |
| `show privilege` | the privilege level |
| `show running-config \| include hostname` | the hostname (and whether the configuration can be read) |
| `show ip ssh` | SSH enabled or disabled, SSH version |
| `show crypto key mypubkey rsa` | whether an RSA key pair exists |
| `show running-config \| include username` | local account names (never their secrets) |
| `show running-config \| section line vty` | VTY ranges, `login` method, `transport input` |
| `show line` | how many VTY lines the device has |
| `show ip interface brief` | interfaces, their IP addresses and status |
| `show running-config \| include ip domain` | the domain name |
| `show running-config \| include ip ssh` | SSH settings in the configuration (`ip ssh version 2`, ...) |
| `show running-config \| include aaa` | whether AAA is on, and its login method lists |

The last three (added for the SSH configuration preview, phase 4) fill `result.config`:
domain name, `ip ssh` lines, AAA, local accounts with their privilege level (never their
secrets) and the SSH timeout/retries from `show ip ssh`. A value is treated as "not
configured" only when its search ran at privilege level 15; below that, IOS can hide
lines, so a missing line means unknown.

Besides these, the console session itself (phase 1) sends `terminal width 511` and
`terminal length 0`, which are session display settings and not configuration. With
`elevate=True`, detection first sends `enable` (with the session's enable password) when
the prompt ends in `>`. Privileged EXEC is not a configuration change. The default is
`elevate=False`: detection runs at whatever level the session already has.

Values that could not be read stay `None` (or `unknown`). Nothing is guessed. Lines that
could contain a password or secret (the `username` and `line vty` output) are masked
before they are stored in the result, and only account names are kept.

## When something fails

A command the device rejects (`% Invalid input`, `% Command authorization failed`, ...)
is recorded with its reason, and detection goes on with the next command. If the console
session itself ends (a command times out, which closes the port in phase 1; the cable is
pulled; or the operation is cancelled), the remaining commands are marked `skipped`,
`result.complete` is `False`, and everything already read is kept.

### Unexpected answers (phase 5.1.2)

An answer that cannot be a real answer to its command is never read as "not configured".
Each answer is checked before it is used:

* **System log lines** (`*Nov 21 10:15:42.123: %LINK-3-UPDOWN: ...`) that the console
  prints in between are removed first (a warning says so); they are not part of any answer.
* **Boot-loader or login prompts** (`rommon 1 >`, `switch:`, `loader>`, `Username:`,
  `Password:`, `Press RETURN to get started`): the device is no longer at its IOS command
  line. The command is marked `unexpected`, **detection stops**, the remaining commands
  are `skipped`, `result.complete` is `False`, and a warning names the command.
* **Configuration searches** must have the right shape: every line of
  `show running-config | include X` must contain `X`, and `| section line vty` may only
  contain `line vty` lines and indented lines. Otherwise the command is marked
  `unexpected`, its content is not used, a warning is added, and detection goes on.

What an `unexpected` command reads stays **unknown**: for example `config.domain_known`,
`local_users_known`, `aaa_known` stay `False` and `vty.configured` stays `None` (never
"none configured"). Information read correctly before it is kept. A real empty answer to
a valid search at privilege level 15 still means "not configured".

Effect on the SSH configuration preview: an incomplete detection proposes nothing; for a
single unexpected answer, the settings it reads are unknown, so nothing that depends on
them is proposed (for example no VTY change when the VTY section was unexpected, no
`login local` when AAA was), and the plan says which answers were not used. The step
checks (`console/steps.py`) treat such answers the same way: UNCERTAIN, never FAILED or
"missing".

## The result

`DetectionResult` (a dataclass, `result.to_dict()` for plain data):

* `device`: hostname (and where it came from), `device_type` router / switch / unknown,
  manufacturer, model, software, version, image, feature set, platform, `crypto_image`
* `access`: prompt, privilege level, whether privileged EXEC is available, whether the
  running configuration could be read
* `ssh`: `status` (one of the four states below), enabled, version, RSA key information,
  local account names, `config_present`, and the `evidence` behind the status
* `vty`: whether VTY lines are configured, their ranges, SSH transport, login
* `interfaces`, `management_interface` and the reason it was chosen
* `commands`: each command with `ok` / `rejected` / `denied` / `failed` / `skipped`
* `warnings`, `limitations`, `simulated`, `complete`

Router or switch comes from the same model/image table the SSH scan uses
(`discovery.crawler.platform_type`), so both features name the same device the same way.
When the model is not in that table, the type is `unknown`.

The management interface is an interface with an IP address that is up/up: a dedicated
management port first (`Mgmt`, `GigabitEthernet0`, `FastEthernet0`), then a VLAN
interface, then other ports, loopbacks last. No IP address means no candidate.

## The four SSH states

| State | Meaning | How it is decided |
|---|---|---|
| `SUPPORTED_ENABLED` | SSH works now | `show ip ssh` says `SSH Enabled` (and nothing contradicts it) |
| `SUPPORTED_DISABLED` | the software can do SSH, but it is off | `show ip ssh` says `SSH Disabled` or asks to create RSA keys; or `show ip ssh` did not work but the key command ran and lists no RSA key, on a K9 or IOS-XE image |
| `UNSUPPORTED` | this image cannot do SSH | all of: classic IOS; privilege level 15 confirmed; **both** `show ip ssh` and `show crypto key mypubkey rsa` rejected as unknown commands; and a feature set without `K9` |
| `UNKNOWN` | not enough clear evidence | everything else |

Every status comes with `ssh.evidence`, a list of plain sentences that say why, so the
GUI can show them later.

### Why UNKNOWN is often the right answer

* A failed `show ip ssh` alone proves nothing: the user may lack privileges (many
  commands need level 15), AAA command authorization may block it, the command may have
  timed out, or the device may run another system.
* NX-OS, IOS-XR, ASA and unrecognised systems use other commands for SSH, so IOS
  commands failing there says nothing about SSH. They are never `UNSUPPORTED`.
* IOS-XE image names do not follow the classic `K9` convention, so a missing `K9` is
  only used as evidence on classic IOS.
* Contradictions give `UNKNOWN`. Example: `SSH Enabled`, but no RSA key pair listed.
* An unfamiliar model is never assumed to be unsupported.

When in doubt, detection reports `UNKNOWN` rather than risk a wrong answer.

## Mock lab

The mock lab can simulate the four conditions with `"ssh_condition"` in a device entry of
`mock-lab/lab_config.json` (see `mock-lab/README.md`). Its `show version` always starts
with `NetCommand Mock Lab - simulated ...`. Detection recognises that line and then sets
`result.simulated = True`, puts a `SIMULATION:` warning first, and reports no
manufacturer, so a mock result can never be mistaken for a physical device.

## Limitations

* Tested only offline: with output written in the format of Cisco IOS, IOS-XE and NX-OS,
  with the mock lab, and with the real Netmiko driver on a fake serial port. It has not
  yet been run on the lab's Cisco 1900 router or a physical switch.
* `UNSUPPORTED` relies on the image name and on the SSH commands being missing; it has
  not been checked against Cisco's feature documentation for each release.
* The SSH *capability state* is decided from `show ip ssh` and the RSA key command. The
  `ip ssh ...` configuration lines, `aaa new-model`, the AAA login method lists, the key
  SSH uses (`ip ssh rsa keypair-name`, and the key named by `show ip ssh`) are read as
  well (phase 4) and used by the SSH configuration preview; other `ip ssh` settings (for
  example `ip ssh source-interface`) are listed but not interpreted.
* VTY lines without a `transport input` line are reported as unknown, because the default
  differs between IOS releases.
* `rsa.present` means "some RSA key exists", not "SSH has a key": an HTTPS
  `TP-self-signed` key also counts. The preview decides which key is SSH's (see
  `docs/SSH_CONFIGURATION_PREVIEW.md`); a warning is added when the only key is a
  `TP-self-signed` key.
* Configuration lines with passwords or secrets are masked from the keyword to the end of
  the line (`password 0 two words` becomes `password 0 ********`) before they are stored.
* What stays in memory: the console session keeps the console password and enable
  password it was given (and so does Netmiko's connection object) until the session is
  closed. While logging in, at most 16 KB of the device's output is kept to explain a
  failed login; it is emptied as soon as the login succeeds or fails, output of later
  commands is not kept, and nothing is ever written to disk.
* A command that times out ends the console session (phase 1 closes the port when the
  device state is unknown); later commands are then skipped.
* Interface parsing understands the IOS / IOS-XE `show ip interface brief` table only.
