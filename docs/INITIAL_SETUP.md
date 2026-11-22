# The Initial Setup page

The **Initial Setup** page (rail item **Setup**) connects to a network device through its
**console cable** and finds out what the device is and whether it can use SSH. Use it for
a new or reset device that cannot be reached over the network yet.

**It only reads.** It sends `show` commands and nothing else (plus `enable` if you ask for
privileged mode). It does not change the hostname, IP addresses, users, SSH, RSA keys or
the VTY lines, and it never saves the configuration. It can show a **preview** of an SSH
setup (section 4), but it does not send it: executing configuration commands is planned
for a later phase, after the preview has been checked on real hardware.

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

If an unconfigured device asks *"Would you like to enter the initial configuration
dialog? [yes/no]"*, the console driver (Netmiko) answers **no**: this skips the setup
wizard and changes nothing. The page says so when it happens. NetCommand never answers
"yes".

## 2. Device Detection

Click **Detect Device** (available only while connected). The page reads the device with
these commands, one after the other, without blocking the window:

`show version`, `show privilege`, `show running-config | include hostname`,
`show ip ssh`, `show crypto key mypubkey rsa`, `show running-config | include username`,
`show running-config | section line vty`, `show line`, `show ip interface brief`,
`show running-config | include ip domain`, `show running-config | include ip ssh`,
`show running-config | include aaa`.

While it runs, the other buttons are disabled and **Cancel** stops it (and disconnects).
You can run detection again while connected. How the answers are interpreted is
described in `docs/CONSOLE_DETECTION.md`.

**Privileged mode.** By default detection runs at the level the console session already
has. Several commands (the `running-config` ones, often `show ip ssh`) need privilege
level 15. If you connect in user mode (`>` prompt), the results say which information is
missing for that reason. To include it, disconnect, tick **Use privileged mode**, enter
the enable password and connect again: detection then sends `enable` first. `enable` is
not a configuration change.

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

**Preview only — no configuration commands have been sent to the device.** There is no
button that sends or saves the plan. Passwords are shown only as `<SSH_PASSWORD>`. How the
plan is made, and its safety rules, are described in `docs/SSH_CONFIGURATION_PREVIEW.md`.

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

* Tested offline only (simulated ports and the mock lab). It has not yet been used with a
  real console cable and device.
* One console session at a time.
* A command that times out ends the session (see above).
* Results are not saved anywhere; they are shown until the next detection.
