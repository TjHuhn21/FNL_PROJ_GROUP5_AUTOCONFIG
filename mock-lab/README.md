# NetCommand Mock Cisco SSH Lab

A local SSH server that imitates three small Cisco-like devices, so NetCommand
can be tested end to end (Netmiko `cisco_ios`, backups, checks, `write mem`,
multi-device runs, discovery, failures) **without real equipment**.

* Written from scratch in Python on top of Paramiko (already installed with Netmiko).
  It contains **no Cisco software or images**; it only *simulates* the commands
  listed below. Passing here does **not** prove compatibility with real Cisco IOS.
* Completely separate from NetCommand's database and real credentials: every
  login in `lab_config.json` is fake and only valid inside this lab.
* Device configurations are **reset from `lab_config.json` every time the lab
  starts**; `write mem` only lasts until the lab stops.

| Device | Type   | SSH address     | Own login                     | Notes |
|--------|--------|-----------------|-------------------------------|-------|
| MOCK-R1     | router | 127.0.0.11:22   | `labadmin` / `Lab-R1-pass`    | starts at `MOCK-R1>` (needs `enable`; secret = login password) |
| SW1    | switch | 127.0.0.12:22   | `labadmin` / `Lab-SW1-pass`   | trunks need `switchport trunk encapsulation dot1q` first |
| SW2    | switch | 127.0.0.13:22   | `labadmin` / `Lab-SW2-pass`   | 802.1Q only: the encapsulation command is **invalid**; telnet allowed (a Findings target) |

Shared scan account (all devices, privilege 15): `labscan` / `Lab-scan-pass`.
Cabling (CDP): MOCK-R1 Gi0/1 – SW1 Gi0/1, SW1 Gi0/2 – SW2 Gi0/1.

## Start and stop

All commands are run from the `mock-lab` folder with NetCommand's virtual environment:

```powershell
cd mock-lab
..\venv\Scripts\python.exe -m mocklab check        # are 127.0.0.11-13:22 free?
..\venv\Scripts\python.exe -m mocklab start        # foreground; Ctrl+C stops it
..\venv\Scripts\python.exe -m mocklab start --background   # log: state\lab.log
..\venv\Scripts\python.exe -m mocklab status
..\venv\Scripts\python.exe -m mocklab stop
```

Start with failures: `start --fail SW2=auth_fail --fail MOCK-R1=slow`.
Change a failure while it runs (new connections only): `python -m mocklab fail SW2 auth_fail`,
and back with `python -m mocklab fail SW2 none`.

| Mode       | What happens                                    | What NetCommand reports |
|------------|-------------------------------------------------|-------------------------|
| `auth_fail`| every login is refused                          | Wrong username or password. |
| `offline`  | not listening (at start) / closed at once (while running) | No answer (wrong IP, device off, or SSH not enabled). |
| `hang`     | TCP connects, SSH never answers                 | No answer ... (after the banner timeout, about 10 s) |
| `drop`     | connection cut right after the Nth configuration command (`drop_after`, default 1; that command is applied) | Error: ReadTimeout (see limitations) |
| `slow`     | every reply waits `delay_ms` (default 2000)     | works, slowly |

### Reset to the starting state (simulation only)

```powershell
..\venv\Scripts\python.exe -m mocklab reset
```

Asks you to type `RESET MOCK LAB` exactly (anything else cancels and changes nothing). It
then stops the lab and starts it again in the background, so every **simulated** device is
rebuilt from `lab_config.json` and every failure mode is cleared: the same as `stop`
followed by `start`. If the lab is not running it only clears the failure modes; the next
`start` builds the devices from the file anyway. It refuses to do anything unless every
device in `lab_config.json` uses a loopback address (127.x.x.x).

It is a mock lab command only: it opens no SSH, Telnet, serial or other connection, sends
no command to any device, and erases nothing on any device (it has no `write erase`,
`erase startup-config` or `reload`). NetCommand itself has no reset button. Backups in
`backups\` and the saved topology layout are kept.

If an address is taken (for example by Windows OpenSSH Server on port 22), the lab
refuses to start, starts **nothing**, and names the address. Change `host`/`port`
in `lab_config.json`, or stop the other program. Only loopback addresses
(127.x.x.x) are accepted.

## Check the protocol directly with Netmiko (no NetCommand)

```powershell
..\venv\Scripts\python.exe netmiko_workflow.py --own-lab            # MOCK-R1
..\venv\Scripts\python.exe netmiko_workflow.py --own-lab --device SW1
```

Uses the real `ConnectHandler(device_type='cisco_ios')`: connect, initial prompt,
`enable`, `show running-config`, `configure terminal`, `hostname`, `end`,
verification, `write mem`, disconnect. (`--own-lab` starts and stops the lab
itself; leave it out when the lab is already running.)

## Use it from the NetCommand window

Two launcher modes, both run from the `mock-lab` folder while the lab is running:

```powershell
..\venv\Scripts\python.exe run_netcommand.py              # sample store, no sign-in
..\venv\Scripts\python.exe run_netcommand.py --signed-in  # normal sign-in and database
```

| | default | `--signed-in` |
|---|---|---|
| NetCommand started as | `main.py --demo --mock-console` | `main.py --mock-console` |
| Sign-in | none (DEMO MODE) | the normal sign-in: password and emailed code, through the backend (`NETCOMMAND_API_URL`); the backend must be running |
| Data | in-memory sample store; forgotten when the window closes; the database is never opened | the database named in `.env`, exactly as `python main.py` (devices you approve are saved there) |
| Initial Setup | SIMULATED console ports SIM1-SIM17 only | the same |
| Label | title and status bar: **MOCK LAB — simulated devices** | the same |
| Backups / layout | `mock-lab\backups\` / `mock-lab\state\` | the same |

Neither mode changes authentication, the backend, the database settings or how NetCommand
talks to devices. The label comes from `NETCOMMAND_MOCK_LAB=1`, set by the launcher for its
own process only; it is display only. The Initial Setup page never lists or opens the
computer's real COM ports in either mode.

For `--signed-in` recordings, use a clean database if the usual one holds other devices:
NetCommand's Configure page sends configuration to whatever device is selected.

1. **Scan**: untick the sample option, seed `127.0.0.11`, login `labscan` / `Lab-scan-pass`.
   By default only MOCK-R1 is logged in to (SW1 is listed as an unmanaged neighbour). For the
   whole lab, tick *Also log in to CDP/LLDP neighbours* and confirm (fine here: every lab
   device is a local simulation sharing this lab account). MOCK-R1, SW1, SW2 and both links are
   then found; approve them.
2. **Configure**: tick SW1 and SW2, add VLAN 30 and ports `Fa0/5-8`, Preview, Apply.
   Both succeed, each with its own ENCRYPTED backup (`.ncbak`) in `mock-lab\backups\`.
   Apply needs the backup encryption key: create it once beforehand with
   `..\venv\Scripts\python.exe ..\backup_keys.py init --recovery <offline path>` (see
   `docs/BACKUP_ENCRYPTION.md`); without it Apply refuses to start and nothing is sent.
   Check a backup with `..\venv\Scripts\python.exe ..\backup_tool.py verify <file>.ncbak`.
3. Add a trunk on `Gi0/2` with "encapsulation dot1q" ticked and apply to SW1 + SW2:
   SW1 succeeds; SW2 rejects the encapsulation command (partially applied, not saved).
4. `python -m mocklab fail SW2 auth_fail`, apply again: SW1 succeeds, SW2 fails,
   and the summary shows both.
5. **Findings is not useful in this mode**: in sample mode NetCommand always reviews
   its built-in SAMPLE configs (labelled as such), never the registered devices
   (`services.collect_review_inputs(store, demo=True)`). Reviewing the lab's configs
   needs NetCommand's database mode, which this launcher deliberately avoids.
   (Run directly, NetCommand's review of the lab finds: SW1 no port security and a
   trunk allowing all VLANs, SW2 password encryption off and a trunk allowing all
   VLANs, SW1 a single point of failure.)

## Simulated commands

Exec: `enable`, `disable`, `exit`, `terminal length|width`, `configure terminal`,
`write [memory]`, `copy running-config startup-config`,
`show running-config [interface X] [| include|exclude|begin|section REGEX]`,
`show startup-config`, `show version`, `show vlan brief`, `show ip interface brief`,
`show ip route`, `show ip dhcp pool`, `show interfaces trunk`,
`show cdp neighbors [detail]`, `show privilege`, `show ip ssh`,
`show crypto key mypubkey rsa`, `show line`.

### Simulated SSH conditions (for console detection tests)

A device entry may set `"ssh_condition"` to one of these. Only what the show commands
report changes; the lab's own SSH server still accepts connections in every condition.

| `ssh_condition` | `show version` | `show ip ssh` / `show crypto key mypubkey rsa` |
|---|---|---|
| not set | the original mock text (unchanged) | SSH Enabled / a simulated key |
| `enabled` | a simulated K9 (crypto) image | SSH Enabled / a simulated key |
| `disabled` | a simulated K9 image | SSH Disabled, "Please create RSA keys" / nothing; `crypto key generate rsa` then turns SSH on |
| `unsupported` | a simulated image without K9 | both commands, and `ip ssh` / `crypto` in configuration mode, are invalid input |
| `unknown` | the original mock text | `% Command authorization failed.` |

`show ip ssh` reports version 2.0 only when `ip ssh version 2` is in the configuration
(otherwise 1.99), and shows `ip ssh time-out` / `ip ssh authentication-retries` values
when they are configured.

The simulated console ports for the Initial Setup page (`mocklab/console.py`, used only
with `python main.py --mock-console`) combine these conditions with different existing
configurations (accounts, AAA, VTY login and transport): see `SCENARIOS` there and
`docs/SSH_CONFIGURATION_PREVIEW.md`.

Every `show version` still starts with `NetCommand Mock Lab - simulated ...` and the
simulated image lines say `Simulated IOS Software`, so the output is always marked as a
simulation.

Configuration: `hostname`, `vlan` / `name`, `interface`, `interface range` (up to 5
pieces), `description`, `shutdown` / `no shutdown`, `switchport mode access|trunk`,
`switchport access vlan`, `switchport trunk encapsulation|native vlan|allowed vlan`,
`switchport port-security [maximum|violation|mac-address sticky]`, `ip address`,
`ip route`, `ip default-gateway`, `ip dhcp excluded-address`, `ip dhcp pool`
(`network`, `default-router`, `dns-server`), `ip name-server`, `ntp server`,
`service ...`, `enable secret`, `username`, `line con|vty` (`transport input`, `login`),
`do <exec command>`, `end`, `exit`, Ctrl+Z, many `no` forms.
Unique abbreviations work (`conf t`, `sh run`, `int ra fa0/1 - 5`).

Errors follow IOS's style: `% Invalid input detected at '^' marker.` (with the
caret under the bad word), `% Incomplete command.`, `% Ambiguous command`,
`Command rejected: ...`, `% Unknown command or computer name...`.

`crypto key generate rsa [modulus N]` behaves as IOS is understood to: `% Please define a
hostname other than Router.` with the factory name, `% Please define a domain-name
first.` without a domain, and, when SSH's key already exists, `% Do you really want to
replace them? [yes/no]:`. The mock never answers a question itself: the next line typed
is taken as the answer (anything but `yes` keeps the key).

### Edge cases for console configuration work (phase 5.1.1)

**Quirks** (`"quirks": [...]` on a device; `QUIRKS` in `mocklab/device.py`), all
simulated, deterministic, and without real waiting:

| Quirk | Simulates |
|---|---|
| `rsa_slow` | key generation reports 45 simulated seconds (`Reply.delay_s`, `Session.simulated_seconds`); nothing sleeps |
| `rsa_fails` | key generation prints `%Error: RSA key generation failed (SIMULATED)`; no key |
| `rsa_ask_modulus` | without `modulus N`, asks `How many bits in the modulus [512]:` |
| `rsa_partial` | output stops before `[OK]`; `show crypto key mypubkey rsa` is unreadable afterwards |
| `prompt_lag` | after `hostname X` the next prompt still shows the old name, once |
| `prompt_garbled` | after `hostname X` the next prompt is cut off (`Edg`), once |
| `domain_rejected` | `ip domain-name` is rejected |
| `ssh_v2_ignored` | `ip ssh version 2` is accepted and stored, `show ip ssh` keeps saying 1.99 |
| `ssh_v2_rejected` | `ip ssh version 2` is rejected (`... (SIMULATED rejection)`) |
| `syslog` | system log lines (`%LINK-3-UPDOWN`, ...) appear inside command output |
| `legacy_ssh_only` | the SSH server offers only `diffie-hellman-group14-sha1`, `ssh-rsa`, `hmac-sha1` |

**Console events** (`console={...}` on a scenario in `mocklab/console.py`):
`timeout_on`, `partial_timeout_on` (part of the output arrives, is kept in
`partial_output` for tests, and is never returned), `unexpected_prompt_on` (a
`rommon N >` boot-loader prompt from then on), `unplug_on` (connection lost).

**Scenarios** (`EDGE_SCENARIOS`; listed only by `MockConsoleBackend(edge_cases=True)`,
so the normal `--mock-console` port list is unchanged). Identifiers (`SCENARIO_IDS`,
`scenario_port('rsa-slow')`):

| Port | Identifier | | Port | Identifier |
|---|---|---|---|---|
| SIM18 | `rsa-slow` | | SIM28 | `ssh-v2-ignored` |
| SIM19 | `rsa-fails` | | SIM29 | `ssh-v2-rejected` |
| SIM20 | `rsa-replace-question` | | SIM30 | `ssh-ethernet-unavailable` (console: SSH on; lab endpoint `offline`) |
| SIM21 | `rsa-modulus-question` | | SIM31 | `ssh-legacy-algorithms` |
| SIM22 | `rsa-missing-hostname` | | SIM32 | `vty-ssh-not-verified` |
| SIM23 | `rsa-missing-domain` | | SIM33 | `console-syslog` |
| SIM24 | `rsa-partial` | | SIM34 | `console-timeout` |
| SIM25 | `prompt-lag` | | SIM35 | `console-partial-timeout` |
| SIM26 | `prompt-garbled` | | SIM36 | `console-unexpected-prompt` |
| SIM27 | `domain-rejected` | | SIM37 | `console-interrupted` |

Existing scenarios that already cover a case are listed under its identifier too:
`ssh-keys-but-disabled` (SIM15), `vty-multiple-ranges` / `vty-password-login` /
`vty-different-settings` (SIM16), `vty-uncovered-lines` (SIM17), `vty-login-local` (SIM1).

These are simulations for tests (`tests/test_mock_edge_cases.py`). Messages marked
`(SIMULATED)` are invented wording; the others follow IOS output as it is understood, not
as checked on the lab's router. A behaviour passing here says nothing about whether real
hardware behaves the same way.

### Restore simulation (Phase 4D, for the future restore engine)

`mocklab/restore_sim.py`, tested by `tests/test_mock_restore_sim.py`. There is **no
restore feature in NetCommand yet**: this only gives the lab the device side, so a
future engine can be tested. None of it is in `lab_config.json`, so the default
devices' running configurations and behaviour are unchanged.

* **Simulated clock.** `Lab.clock` (one `SimClock` for every device); `lab.advance(300)`
  moves it and fires expired rollback timers. Nothing ever sleeps.
* **Flash.** Per device, held in memory only: a simulated image, transferred files and
  archive copies, each marked by kind. `dir [flash:[/file]]` (with `N bytes total
  (M bytes free)`), `delete [/force] flash:file` (without `/force` it asks, and the mock
  never answers for you), `verify /md5 flash:file [expected]`. Optional spec keys
  `"flash_bytes"` (size) and `"management_ip"`.
* **Transfers (into simulated flash only).** `tclsh` then `puts [open "flash:x" w+] {...}`,
  as Netmiko's `InLineTransfer(source_config=...)` sends it; and an SCP sink
  (`scp -t`) **only** when the configuration already contains `ip scp server enable`,
  and only for a privilege-15 login. By default a transfer to an existing name is
  refused (`File exists`); the `flash_overwrites` quirk gives the real IOS behaviour
  (silent overwrite) to test an engine's own existence check. `flash.temp_name()` gives
  `nc-restore-<16 hex>.cfg` names that do not exist yet.
* **Archive.** `archive` / `path flash:<name>` / `maximum N` / `write-memory` /
  `time-period N` (and `no archive`), spec key `"archive": {"path": "flash:archive",
  "maximum": 5}`, `archive config`, `show archive`, `show archive config rollback timer`.
  Copies are named `<path>-N`, never overwrite a file, and the oldest beyond `maximum`
  are deleted.
* **`configure replace flash:file [list] [force] [time N] [nolock]`.** The file is
  replayed through the lab's own CLI on a blank copy of the device (ports, cables,
  keys and flash are kept). A line the CLI refuses makes it partial ("Rollback aborted
  after 5 passes"; the rest stays applied). With `time N` it needs the archive path,
  archives the current configuration first, and starts a rollback timer.
  `configure confirm` cancels the timer; `configure revert now` and an expired timer
  restore the exact previous running configuration; `configure revert timer [idle] N`
  resets the timer. Without `force` it asks, and the mock never answers for you.
  **The startup configuration is never touched.**
* **Restore quirks:** `replace_unsupported`, `no_tcl`, `no_scp`, `flash_overwrites`,
  `transfer_fails` (connection cut half way, partial file left), `transfer_corrupt`
  (MD5 mismatch), `replace_partial`, `revert_fails`, `drop_during_replace`,
  `reconnect_refused`, `verify_mismatch`, `delete_fails`, `reboot_during_restore`
  (running configuration back to startup, timer lost, refused for 180 simulated
  seconds). With `"management_ip"` set, removing that address from an up interface
  makes the device unreachable (sessions cut, connections refused) until a rollback.
  `RESTORE_SCENARIOS` / `restore_spec(spec, name)` build a device spec for each case.

The wording of these messages is written for the lab and is not copied from Cisco
output (uncertain wording is marked `(SIMULATED)`). **Mock Lab success says nothing
about Cisco 1900 compatibility:** `configure replace`, archive, Tcl and SCP behaviour
must be established separately on real hardware.

## Known issue reproduced here (NetCommand / Netmiko, left unchanged)

**Changing the hostname makes `write mem` time out.** After `hostname X`, Netmiko
keeps the old *base prompt*. `send_command()` is not affected (it looks the prompt
up again), so NetCommand's checks pass, but `save_config()` first calls
`enable()` → `check_enable_mode()`, which waits for the **old** prompt. After about
10 s NetCommand reports `Error: ReadTimeout`; `write mem` was never sent, so the
change stays unsaved. Calling `conn.set_base_prompt()` after the change avoids it
(shown in `netmiko_workflow.py`). This comes from Netmiko's own logic, so a real
device would behave the same way; it has not been checked on real hardware.

## Other NetCommand findings from the lab (not changed)

* **Telnet rule misses `transport input telnet ssh`.** `review/rules.py`
  `rule_telnet` only matches `transport input telnet` or `transport input all`
  exactly; SW2 is configured with `transport input telnet ssh` (telnet allowed) and is
  not flagged.
* **A dropped connection is reported without "partially applied".** When the
  connection breaks while a command is being sent (`drop` mode), NetCommand reports
  `Error: ReadTimeout` after about 15 s. The command in flight is not shown in the
  SSH console, and the message does not warn that earlier commands were applied.
* **Console wording.** NetCommand's masking turns "(the enable secret is not shown)"
  into "(the enable secret ******** not shown)", because the word after "secret" is
  masked. Cosmetic only.

## Limitations (honest list)

* A simulation: only the commands above, simplified output, no real protocols
  (no spanning tree, no actual forwarding, no MAC learning, no DHCP leases).
* `?` help, `banner`, paging (`--More--`), async log messages, telnet and SSH keys
  are not simulated. Wrong `enable` passwords get one try (`% Access denied`).
* The CDP "management address" is the lab's loopback SSH address.
* Interfaces are up only when the config marks a cable (`"connected": true`);
  routes via a down interface stay out of `show ip route`, as on real routers.
* NetCommand always connects to port 22, so each device needs its own address.
* Background start on Windows: if the window that started it belongs to a job
  that does not allow breaking away, closing that window may end the lab; use
  the foreground `start` in its own window in that case.
