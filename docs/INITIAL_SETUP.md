# The Initial Setup page

The **Initial Setup** page (rail item **Setup**) connects to a network device through its
**console cable** and finds out what the device is and whether it can use SSH. Use it for
a new or reset device that cannot be reached over the network yet.

**Detection and preview only read.** They send `show` commands and nothing else (plus
`enable` if you ask for privileged mode). Only section 5, **Apply SSH Configuration**,
changes the device: it sends the previewed SSH setup one step at a time, after you
confirm it, and checks each step. It never saves the configuration, never sets an IP
address and never logs in over the network.

**Who can use it.** Operators and administrators (the same permission as the Configure
page). Viewers do not see the page. In `--demo` mode it is available as well.

## 1. Console Connection

1. Plug the console cable into the device's **CONSOLE** port and into the computer (a
   USB console cable, or a USB-to-serial adapter with a rollover cable).
2. Click **Refresh Ports**. NetCommand asks Windows for the list of serial (COM) ports;
   this never opens a port. Each port shows its description, its hardware ID and a hint:
   * *Looks like a console port*: Cisco's own USB console, or the port says it is a console.
   * *Possibly a console cable*: a USB-to-serial adapter (FTDI, Prolific, Silicon Labs,
     WCH) or a built-in serial port. These are common for console cables, but they can be
     connected to anything, so check the cable.
   * *Probably not a console cable*: Bluetooth, modem and virtual ports.
3. Choose the port and the **speed (baud)**: 1200, 2400, 4800, 9600, 14400, 19200,
   38400, 57600 or 115200. Most Cisco devices use **9600** (the default). The connection
   is always 8 data bits, no parity, 1 stop bit.
4. If the device asks for a console login, type the username and password. Tick
   **Use privileged mode (enable)** and type the enable password only if you want
   detection to run in privileged mode (see below). The password fields are masked. They
   are emptied as soon as you click **Connect**; nothing is saved, logged or shown.
5. Click **Connect**. The status next to the buttons shows *Connecting...*, then
   *Connected (COM4, 9600 baud)*. While connecting, the **Cancel** button stops the attempt.

**What happens when you click Connect (phase 5.1.6).** NetCommand opens the port and first
only **listens** for a few seconds: nothing is sent, not even Enter. What the device printed
decides what happens next, and the page says which case applies:

| The page shows | What it means | What you do |
|---|---|---|
| **Normal prompt detected (verified by NetCommand)** | The device printed its `>` or `#` prompt. | Nothing: NetCommand connects. |
| Console silent | An idle console prints nothing until it receives a key. | Nothing: NetCommand sends Enter and reads the prompt (logged). No reply at all: *"No response. Check the cable is in the CONSOLE port, the COM port, and the speed."* |
| "Press RETURN to get started" | The device has just started (or a console session ended). | Nothing: NetCommand sends Enter (logged). |
| *"Would you like to enter the initial configuration dialog? [yes/no]"* | A new or erased device. | Nothing: NetCommand answers **no** (skips the setup wizard, changes nothing), then Enter at the "Press RETURN" that follows. It never answers "yes" here. |
| *"Would you like to terminate autoinstall? [yes]"* | A new device found no configuration server. | Nothing: NetCommand answers **yes** (logged). |
| `Username:` / `Password:` (console login) | The console line asks for a login. | Type the console username and password in **Console login** before connecting; without them nothing is sent and the port is closed. |
| **Unsafe or unknown state; connection refused** | Any other question or `[confirm]`, the boot loader (ROMMON / `switch:`), configuration mode, unreadable output, output still streaming, or anything not recognised. | Nothing was sent and the port was closed. Resolve it at the console in a terminal program, then connect again. |

The connected status reads, for example, **Connected: R1# (privileged mode)**. The old
behaviour (you decide each startup prompt and confirm a silent console yourself) is still
available to developers through `SetupTab.auto_startup = False`. If the port is busy
(PuTTY or Tera Term open), the page says *"COM3 is in use by another program..."*.
Leaving the Setup page or closing NetCommand while connected asks first and closes the
port. Every command sent and every reply (passwords and secrets masked) is logged to the
Console.

The same open port is then used for everything (it is never closed and reopened in between),
and NetCommand logs in itself: only the console's own username and password prompts are
answered, with what you typed above.

## 2. Device Detection

Click **Detect Device** (available only while connected). The page reads the device with
these commands, one after the other, without blocking the window:

`show version`, `show privilege`, `show running-config | include hostname`,
`show ip ssh`, `show crypto key mypubkey rsa`, `show running-config | include username`,
`show running-config | section line vty`, `show line`, `show ip interface brief`,
`show running-config | include ip domain`, `show running-config | include ip ssh`,
`show running-config | include aaa`,
`show running-config | include ip default-gateway|ip route 0.0.0.0 0.0.0.0`, and on
switches `show vlan brief`.

The results then show **What SSH needs**, each line OK / MISSING (or UNKNOWN when it could
not be read): a hostname other than Router/Switch, a domain name, a local user with
privilege 15, an RSA key of 2048 bits or more, SSH version 2, VTY `login local` +
`transport input ssh`, a management IP on an "up" interface, and a default gateway. The
device type (router / switch) can be corrected in section 4, after a confirmation.

While it runs, the other buttons are disabled and **Cancel** stops it (and disconnects).
You can run detection again while connected. How the answers are interpreted is
described in `docs/CONSOLE_DETECTION.md`.

**Privileged mode.** By default detection runs at the level the console session already
has. Several commands (the `running-config` ones, often `show ip ssh`) need privilege
level 15. If you connect in user mode (`>` prompt), the results say which information is
missing for that reason. To include it, disconnect, tick **Use privileged mode**, enter
the enable password and connect again: detection then sends `enable` first. `enable` is
not a configuration change.

**A factory device without an enable password (B1).** Tick **Use privileged mode** and
leave the enable password empty: NetCommand then sends only `enable` and accepts the `#`
prompt. If the device asks for a password instead, NetCommand does **not** answer it (no
guess, no Enter): it closes the console port and says so. The device is left at its
`Password:` prompt; connect again with the enable password.

## 3. Detection Results

* **Device Information**: hostname, device type (router / switch / unknown),
  manufacturer, model, software and version, image file, platform, privilege level.
  Anything the device did not report says **Unknown**; nothing is guessed.
* **SSH Status**, one of four states:

  | Shown as | State | Meaning |
  |---|---|---|
  | Supported and enabled | `SUPPORTED_ENABLED` | SSH is supported and currently enabled. |
  | Supported, not enabled | `SUPPORTED_DISABLED` | SSH is supported but is not currently enabled. |
  | Not supported | `UNSUPPORTED` | The detected software appears not to support SSH. |
  | Unknown | `UNKNOWN` | NetCommand could not determine SSH support with sufficient confidence. |

  Below it: SSH version, RSA keys, the VTY lines, whether SSH is allowed on them, whether
  they require a login, and the local account names (never their passwords).
* **Management Interfaces**: each interface with its IP address, status and protocol. An
  interface is marked *likely management interface* only when detection found one (it
  has an IP address and is up/up); otherwise the page says none was identified and why.
* **Warnings**, and **Show technical details**: why the SSH state was chosen (the
  evidence), the limitations, and what happened to each command.

**Live or earlier?** A result read on the current connection says *Live result*. After you
disconnect (or the connection is lost), it says **EARLIER RESULT ... not live information**,
so an old result is never mistaken for the device's current state.

## 4. SSH Configuration Preview

Below the results, enter what you want (new hostname, domain name, new SSH account, RSA
key size; empty fields keep what the device has) and click **Preview SSH Configuration**
or **Detect Again and Preview**. The page shows each setting's status, the proposed
commands in order with an explanation, conflicts and unknown settings, and which commands
only add something and which change existing settings.

**Preview only — no configuration commands have been sent to the device.** The preview
itself sends nothing; there is no button that saves. Passwords are shown only as
`<SSH_PASSWORD>`. How the plan is made, and its safety rules, are described in
`docs/SSH_CONFIGURATION_PREVIEW.md`.

## 5. Apply SSH Configuration

To send the previewed plan:

1. Type the new account's password again, twice (it was discarded after the preview).
2. Tick the approval of each step listed as able to cut off current users.
3. Type the confirmation shown, exactly: `APPLY SSH <hostname>`.
4. Click **Apply SSH Configuration**.

NetCommand first checks privilege level 15 and reads the device again; if anything differs
from the preview, nothing is sent. It then runs the steps one at a time: each in its own
`configure terminal` ... `end`, each checked with `show` commands before the next. The
table shows every step as VERIFIED, FAILED, UNCERTAIN, BLOCKED (needs a step that did not
pass) or NOT RUN. The first step that does not pass stops the run.

* **Only known questions are answered**, each logged: the RSA key size (*"How many bits in
  the modulus"*: the size you chose), *"Do you really want to replace them?"*: `yes` (only
  in the RSA step), and while saving `[confirm]` / *"Destination filename
  [startup-config]?"*: Enter. **Any other question** stops Apply, closes the console port
  and shows what was asked.
* **Any `%` error** from the device (`% Invalid input`, `% Incomplete command`,
  `% Invalid Password length`, `... overlaps with ...`) fails that step and stops the run,
  with the device's exact message. IOS's informational `%` lines during key generation are
  not errors.
* Before anything is sent: *"Apply 9 steps to R1 through the console?"* [Apply] [Cancel].
  At the end: one summary line, e.g. *"SSH setup complete on R1. SSH: enabled (v2). Login:
  admin. Management IP: 192.168.1.1 on Gi0/0 (up). Saved to startup-config."* The step
  table shows OK / FAILED / SKIPPED (already present) / NOT RUN. A management interface that
  is switched on but down is a warning, not a failure ("check that a cable is connected";
  for Vlan1 "connect at least one port in VLAN 1").
* **6 Test SSH over the network** (after a successful Apply with a management IP): logs in
  to the management IP with the new or existing account and says "SSH login OK" or the
  exact problem. It does not count toward the failed-login lockout; it is logged.
* **7 Register the device**: after a successful test, *"Add R1 (192.168.1.1, router) to
  Devices as managed, and save this login (encrypted)?"* [Add] [Not now]. An IP or name
  that is already registered is refused.
* **Stop after the current step** stops between steps, never in the middle of a command.
  Closing NetCommand (or signing out) during Apply works the same way: NetCommand stays
  open until the current step has finished, closes the console port, and then closes.
* If the console is not back at the normal `#` prompt at the end (for example an
  unexpected prompt), NetCommand closes the console port without typing anything and the
  page asks you to resolve the console by hand before connecting again.
* The new account's password may not contain spaces or other whitespace.
* **Nothing is saved.** The changes are in the running configuration only; saving is a
  separate, later feature. No IP address is configured and SSH is not tried over the
  network.
* Afterwards the page shows a fresh detection of the device, the lines that were sent
  (the password only as `<SSH_PASSWORD>`), and what to do next if something did not pass.
* Apply runs once per preview; make a new preview to apply again (it will only propose
  what is still missing).

Details: `docs/SSH_CONFIGURATION_PREVIEW.md`, *Applying the plan*.

## Simulated results

Started with `--mock-console`, the page uses the NetCommand mock lab instead of real COM
ports (only then):

```
python main.py --demo --mock-console
```

The page then shows *MOCK CONSOLE MODE* at the top, the ports are called SIM1 to SIM17 and
say SIMULATED, no COM port is opened and no device is contacted. Every result from them
shows the red banner **SIMULATED DEVICE — NOT PHYSICAL HARDWARE**, and no manufacturer.

| Port | Simulates |
|---|---|
| SIM1 | router, SSH enabled |
| SIM2 | router, SSH supported but not enabled |
| SIM3 | switch whose image has no SSH |
| SIM4 | router whose SSH state cannot be determined |
| SIM5 | switch that refuses the console login |
| SIM6 | a device that never answers (connection timeout) |
| SIM7 | router whose cable is "pulled" during detection |
| SIM8–SIM17 | different existing SSH configurations for the preview (see `docs/SSH_CONFIGURATION_PREVIEW.md`) |

## Common problems

| Message | What to do |
|---|---|
| No serial ports were found | Plug in the cable, check its driver (Device Manager), click Refresh Ports. |
| COM4 is no longer listed | The cable was unplugged or the adapter reset. Plug it in and refresh. |
| COM4 is in use by another program | Close PuTTY, Tera Term or any other program using the port. |
| COM4 is not available | The port disappeared or its driver is missing. Refresh the list. |
| The output is unreadable at 19200 baud | Wrong speed: try 9600. |
| No usable answer within 45 seconds | Check the cable is in the CONSOLE port, the device is on, and the speed. |
| The device refused the console login | Check the console username and password. Nothing is retried automatically. |
| The device is in its boot loader (ROMMON / switch:) | The device is not running its normal software. Ask the instructor; do not type commands there. |
| The device answered, but not with a Cisco IOS prompt | It may not be a Cisco IOS device, or it is in an unusual state. |

## Why results can be incomplete

* The user is not in privileged mode, so `running-config` and SSH commands are refused.
* AAA command authorization blocks some commands.
* The device runs another system (NX-OS, IOS-XR, ASA...) with different commands.
* A command took too long: the console session is then closed (the device's state is
  unknown), the remaining commands are skipped, and the page marks the result
  **INCOMPLETE** and asks you to connect again.
* The cable was unplugged during detection.

In these cases the SSH state is usually **Unknown**: NetCommand prefers saying it does
not know over guessing.

## Closing

Disconnect logs out of the console line (`exit`) and frees the COM port. Closing the page
or NetCommand while connecting or detecting cancels the work and closes the port.

## Limitations

* Tested offline only (simulated ports, the mock lab, and the real Netmiko serial driver
  over a fake port). It has not yet been used with a real console cable and device;
  Apply in particular needs a separately approved test on the router.
* One console session at a time.
* A command that times out ends the session (see above).
* Results are not saved anywhere; they are shown until the next detection.
