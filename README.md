# NetCommand

Group 5, Section III-A NETAD. A Python desktop app: plug the laptop into a network,
type one login, and NetCommand finds the switches and routers, registers them after
approval, draws the topology, reviews their configurations, suggests improvements,
and applies fixes over SSH with preview, backup, and a check.

```
Scan -> review found devices -> Approve -> Devices (database)
     -> Topology map -> Findings (config review) -> Configure (preview, backup, apply, check, log)
```

> **New team member?** Follow **[docs/TEAM_INSTALLATION_GUIDE.md](docs/TEAM_INSTALLATION_GUIDE.md)**:
> a step-by-step Windows/PowerShell installation of the desktop app, the backend, both
> databases and the first administrator, with expected results and troubleshooting.
> The sections below are the short version.

## Install

1. Python **3.10** (tested on 3.10.0; tick "Add to PATH" and "tcl/tk"). Git. MySQL Community
   Server 8.4 (LTS).
2. In PowerShell, from the project folder (calling the venv's Python directly needs no
   activation, so PowerShell's script policy does not matter):
   ```powershell
   python -m venv venv
   .\venv\Scripts\python.exe -m pip install -r requirements.txt -r backend\requirements.txt
   ```
3. Database (MySQL 8.4, done once by the database administrator):
   * MySQL listens on **127.0.0.1, port 3307** (a non-default port, so it does not clash
     with another MySQL/MariaDB on 3306).
   * Create the `netcommand` database and a restricted application account,
     `netcommand_app`, with privileges on `netcommand.*` only (no global privileges, never
     root). The app connects with this account, so a leaked app password cannot touch other
     databases or administer the server. At runtime it needs `SELECT, INSERT, UPDATE,
     DELETE`; whoever creates the tables also needs `CREATE` and `REFERENCES` (three tables
     have foreign keys).
   * Create the tables with the tables-only `schema.sql` (it creates no users and changes
     no existing table or data). The app does **not** create tables by itself. Windows
     PowerShell has no `<` input redirection, so use the `mysql` client's `source` command,
     from the project folder (`-p` asks for the password; never put it on the command line):
     ```powershell
     & 'C:\Program Files\MySQL\MySQL Server 8.4\bin\mysql.exe' --host=127.0.0.1 --port=3307 --user=root -p --execute="source schema.sql"
     ```
     (In `cmd.exe`, `mysql ... < schema.sql` also works.)
4. Copy `.env.example` to `.env` **on your own computer** and fill in the `DB_` lines
   (`DB_HOST=127.0.0.1`, `DB_PORT=3307`, `DB_USER=netcommand_app`, your password,
   `DB_NAME=netcommand`). `.env` is excluded from Git and must never be committed.
   Then make the encryption key
   (it is written straight into `.env` and never shown, so it cannot be cut short by copy-paste):
   ```powershell
   .\venv\Scripts\python.exe security.py --new-key   # refuses if Git could expose .env, or if a valid key is already there
   .\venv\Scripts\python.exe security.py --check     # FERNET_KEY is valid (read from the .env file).
   ```
   `FERNET_KEY` encrypts and decrypts the device logins stored in the database, so it must stay
   the same: with a different key the saved logins can no longer be read.
   Everyone sharing a database needs the **same** `FERNET_KEY`: send the `.env` line privately.
   Never commit `.env`. A `FERNET_KEY` environment variable, if set, is used before `.env`.
   The app also checks the key at startup and warns (but keeps running) if it is missing or invalid.
5. The sign-in backend (its own database `netcommand_test`, accounts, migrations, email and the
   first administrator): see `backend/README.md` and the team installation guide.

## Run

```
python main.py            # sign in, then uses MySQL; if it is not reachable, starts in SAMPLE mode
python main.py --demo     # DEMO MODE: sample data, no sign-in (no database, no lab)
python main.py --demo --mock-console   # Initial Setup page with SIMULATED console ports
```

The **Initial Setup** page (rail item *Setup*, operators and admins) connects to a device's
console cable and reads what it is and whether it can use SSH. Detection and preview only
read; a separately confirmed **Apply** sends the SSH setup step by step, verifying each
step and never saving; see `docs/INITIAL_SETUP.md`.

**Signing in.** Without `--demo`, NetCommand first opens a sign-in window that talks to the
NetCommand backend (`python -m backend`, see `backend/README.md`) at `NETCOMMAND_API_URL`
(in `.env` or the environment; default `http://127.0.0.1:8000`; a server on another computer
must use `https://`). Sign in with your email address and password, then the code emailed
to you. New accounts: *Create account*, enter the emailed verification code, then wait for an
administrator to approve the account. The session token is kept in memory only, never on
disk; the session ends on *Sign out*, when the window closes, after 30 minutes without
activity, after 8 hours, or when an administrator disables the account.

Roles: **Viewer** can look but not change anything (no Scan or Configure, devices read-only,
stored review only); **Operator** can also scan, configure and edit devices; **Admin** can
also manage accounts (*Accounts* page: approve, reject, disable, and change another
account's role after a confirmation; the account is then signed out and signs in again with
the new role; nobody can change their own role, and the last active admin cannot be
demoted). The sign-in and account
actions are checked by the backend; device actions still go straight to MySQL, so for those
the role limits are applied by this application (an access gate, not yet a security
boundary). NetCommand accounts have nothing to do with the device logins used for SSH.
`--demo` never requires sign-in and is always labelled DEMO MODE; a normal start never falls
back to it.

Sample mode keeps data in memory only and labels everything as sample data. Use it if the
lab or MySQL fails: the Scan tab's *Demo mode* box loads `sample_data.py`.
When MySQL is connected, the *Demo mode* box only previews the sample devices: they cannot
be approved into the real database (Approve is disabled, and `db.py` refuses them too).

## The five-minute demo path

1. **Scan** tab: username, password, **Seed IP** (required: the device to log in to), Scan.
   Only the seed is logged in to; its CDP/LLDP neighbours are listed as unmanaged. To log
   in to them too, tick *Also log in to CDP/LLDP neighbours* (off by default; it sends the
   login to every neighbour). Older IOS that only offers SHA-1 SSH: see
   `NETCOMMAND_LEGACY_SSH_HOSTS` in `.env.example`.
2. Select devices, **Approve selected**. They appear in **Devices**.
3. **Topology** shows the map (gray = seen but not managed). Single points of failure are listed.
4. **Findings**: Run review (reads each device's config over SSH). Health score + fixes.
5. Select a finding, **Send to Configure**, check the preview, **Apply**.
6. Or in **Configure**: add 3 VLANs, Preview, Apply. Check with `show vlan brief` on the switch.
7. **Logs** shows every apply, success or failed. **Export (encrypted)...** saves the log
   being shown (its search and filters, all pages, and only the lines you may see) to a new
   `.nclog` file, encrypted with a passphrase you type (at least 12 characters; scrypt +
   AES-256-GCM, see `log_export.py`). The passphrase is not stored: without it nobody can
   open the file. To read it:
   `.\venv\Scripts\python.exe -m log_export decrypt FILE --out copy.csv` (asks the
   passphrase; `--format json` for JSON; it never replaces an existing file). The copy is
   readable, not encrypted: delete it when done.

## Build the lab

See `lab/lab_configs.txt` (GNS3 topology, device configs, and the planted mistakes).
GNS3 needs Cisco images from your school or the Cisco Networking Academy. Without
images, use Packet Tracer for the topology screenshot and demo mode for the app demo.

## Tests

```
python -m pytest -q                       # unit tests (no lab, no MySQL needed)
NETCOMMAND_TEST_DB=1 python -m pytest -q  # also tests db.py against MySQL (WIPES the tables!
                                          # only ever point .env at a separate test database
                                          # for this, never at the real netcommand database)
xvfb-run python -m pytest tests/test_gui.py   # Linux without a display; on Windows the GUI tests just run
```

`tests/` simulates the lab (fake switches) for discovery and apply logic, so most of T1 to T7
logic is covered by automated tests; the table below is for the **real lab** run.

## Test table (fill in on the real lab, with screenshots)

| Test | Steps | Expected | Actual | Pass or Fail |
|---|---|---|---|---|
| T1 Discovery | Scan from the core | Finds CORE, SW1, SW2, SW3, R1 and all links | | |
| T2 Different plug-in point | Move the Cloud node to SW1 and scan | The same map | | |
| T3 Unmanaged device | Change SW3's password and scan | SW3 is gray, the others are found | | |
| T4 Registration | Approve the found devices | They appear in Devices, password encrypted | | |
| T5 Review | Run the review | Each planted mistake is found | | |
| T6 Configure | Create 3 VLANs on SW1 | `show vlan brief` shows them, backup file exists | | |
| T7 Bad login | Apply with a wrong password | A clear message, no crash | | |

Performance evidence: time the same 3-VLAN job by hand (console/SSH) and with the app.

| Method | Time |
|---|---|
| By hand | |
| With NetCommand | |

## Project layout

```
main.py  services.py  sample_data.py  schema.sql  db.py  db_fake.py  security.py  validation.py
discovery/crawler.py          config/connect.py  commands_switch.py  commands_router.py
review/rules.py               topology/graph.py  monitor/monitor.py
gui/  main_window, scan_tab, devices_tab, topology_tab, findings_tab, configure_tab, logs_tab, theme
tests/  lab/  backups/ (config backups, not in Git)
```

## Rules

Only scan and configure networks and devices you own or have permission to use. The app uses
only the login the admin types and never tries guessed passwords.

## Status

| Part | State |
|---|---|
| Discovery (`discovery/crawler.py`) | Built. Seed-only by default (the login goes to the Seed IP only; CDP/LLDP neighbours are listed unmanaged), optional neighbour login after a confirmation, device type from the model in `show version` (router / switch / unknown) |
| SSH engine (`config/connect.py`, `ssh_options.py`), Configure | Built: preview, backup, one command at a time, checks, `write mem` only when the checks pass; strict SSH algorithms with per-device legacy SHA-1 support; SSH login dialog with optional encrypted saving; hostname changes rename the device record; applied form sections are cleared |
| Database (`schema.sql`, `db.py`), sample store (`db_fake.py`), `security.py`, `validation.py`, monitor | Built; `db.py` also tested against a real MySQL server |
| Review rules, Findings, Topology, Devices, Logs, Overview dashboard | Built |
| Console access and Initial Setup (`console/`, `gui/setup_tab.py`) | Built, read-only: COM port list, console connection, device and SSH capability detection. SSH configuration **preview** (`console/plan.py`) and step-by-step **Apply** (`console/apply.py`: typed confirmation, per-step approvals and verification, questions never answered, running configuration only, never saved; see `docs/SSH_CONFIGURATION_PREVIEW.md`). Tested offline only (fake serial ports, mock lab); not yet used on real hardware |
| Sign-in and accounts (`backend/`, `desktop_auth/`) | Built: FastAPI backend, registration with email verification, administrator approval, two-step sign-in with emailed codes, roles (viewer / operator / admin), *Accounts* page |
| Automated tests | About 1,670 offline tests (no MySQL, network or devices needed), including a simulated Cisco mock lab (`mock-lab/`) |

**Real hardware.** The app has been used against a physical Cisco 1900 router (scan, then a
hostname and a DHCP change through Configure). The fixes made after that test (router
classification, renaming the device after a hostname change, clearing applied form
sections, seed-only scanning, per-device legacy SSH, the login dialog) are covered by the
automated tests but have **not yet been re-run on the router**, and no physical **switch**
has been tested yet. If a scan finds the starting device but no neighbours, paste the
output of `show cdp neighbors detail` into `tests/test_crawler.py` (`parse_cdp`) to see
why, and confirm CDP is on (`show cdp neighbors`).

**The monitor** pings every registered device every 30 seconds (real database mode only) and
saves an event only when a device changes between up and down. The Devices tab and the
Overview show the status. Start with `python main.py --no-monitor` to turn it off.

**Not done yet:** HTTPS for the backend (today each member runs their own backend on
`127.0.0.1`); moving device operations behind the backend (device permissions are applied
by the desktop app only); verifying device SSH host keys; restoring a configuration from a
backup; learning extra subnets from router tables, MAC addresses and end devices; scheduled
rescans; more review rules (unused ports, native VLAN mismatch, user ports in VLAN 1,
duplicate IPs); and the optional console-cable setup mode.
