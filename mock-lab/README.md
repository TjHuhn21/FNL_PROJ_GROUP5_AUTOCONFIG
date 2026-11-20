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
| R1     | router | 127.0.0.11:22   | `labadmin` / `Lab-R1-pass`    | starts at `R1>` (needs `enable`; secret = login password) |
| SW1    | switch | 127.0.0.12:22   | `labadmin` / `Lab-SW1-pass`   | trunks need `switchport trunk encapsulation dot1q` first |
| SW2    | switch | 127.0.0.13:22   | `labadmin` / `Lab-SW2-pass`   | 802.1Q only: the encapsulation command is **invalid**; telnet allowed (a Findings target) |

Shared scan account (all devices, privilege 15): `labscan` / `Lab-scan-pass`.
Cabling (CDP): R1 Gi0/1 – SW1 Gi0/1, SW1 Gi0/2 – SW2 Gi0/1.

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

Start with failures: `start --fail SW2=auth_fail --fail R1=slow`.
Change a failure while it runs (new connections only): `python -m mocklab fail SW2 auth_fail`,
and back with `python -m mocklab fail SW2 none`.

| Mode       | What happens                                    | What NetCommand reports |
|------------|-------------------------------------------------|-------------------------|
| `auth_fail`| every login is refused                          | Wrong username or password. |
| `offline`  | not listening (at start) / closed at once (while running) | No answer (wrong IP, device off, or SSH not enabled). |
| `hang`     | TCP connects, SSH never answers                 | No answer ... (after the banner timeout, about 10 s) |
| `drop`     | connection cut right after the Nth configuration command (`drop_after`, default 1; that command is applied) | Error: ReadTimeout (see limitations) |
| `slow`     | every reply waits `delay_ms` (default 2000)     | works, slowly |

If an address is taken (for example by Windows OpenSSH Server on port 22), the lab
refuses to start, starts **nothing**, and names the address. Change `host`/`port`
in `lab_config.json`, or stop the other program. Only loopback addresses
(127.x.x.x) are accepted.

## Check the protocol directly with Netmiko (no NetCommand)

```powershell
..\venv\Scripts\python.exe netmiko_workflow.py --own-lab            # R1
..\venv\Scripts\python.exe netmiko_workflow.py --own-lab --device SW1
```

Uses the real `ConnectHandler(device_type='cisco_ios')`: connect, initial prompt,
`enable`, `show running-config`, `configure terminal`, `hostname`, `end`,
verification, `write mem`, disconnect. (`--own-lab` starts and stops the lab
itself; leave it out when the lab is already running.)

## Use it from the NetCommand window

```powershell
..\venv\Scripts\python.exe run_netcommand.py
```

This is `main.py --demo` (memory store: the production database is never opened),
with backups written to `mock-lab\backups\` and the topology layout to `mock-lab\state\`.

1. **Scan**: untick the sample option, seed `127.0.0.11`, login `labscan` / `Lab-scan-pass`.
   By default only R1 is logged in to (SW1 is listed as an unmanaged neighbour). For the
   whole lab, tick *Also log in to CDP/LLDP neighbours* and confirm (fine here: every lab
   device is a local simulation sharing this lab account). R1, SW1, SW2 and both links are
   then found; approve them.
2. **Configure**: tick SW1 and SW2, add VLAN 30 and ports `Fa0/5-8`, Preview, Apply.
   Both succeed, each with its own backup in `mock-lab\backups\`.
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
`show cdp neighbors [detail]`, `show privilege`.

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
