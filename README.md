# NetCommand

Group 5, Section III-A NETAD. A Python desktop app: plug the laptop into a network,
type one login, and NetCommand finds the switches and routers, registers them after
approval, draws the topology, reviews their configurations, suggests improvements,
and applies fixes over SSH with preview, backup, and a check.

```
Scan -> review found devices -> Approve -> Devices (database)
     -> Topology map -> Findings (config review) -> Configure (preview, backup, apply, check, log)
```

## Install

1. Python 3.10 to 3.12 (tick "Add to PATH"). Git. MySQL Server + Workbench (Part 2).
2. ```
   python -m venv venv
   venv\Scripts\activate          (Mac/Linux: source venv/bin/activate)
   pip install -r requirements.txt
   ```
3. Database: open `schema.sql` in Workbench as root, **change the password on the
   `CREATE USER` line**, and run it. The app connects as the limited `netcommand` user.
4. Copy `.env.example` to `.env` and fill in the `DB_` lines. Then make the encryption key
   (it is written straight into `.env` and never shown, so it cannot be cut short by copy-paste):
   ```
   python security.py --new-key     # refuses if Git could expose .env, or if a valid key is already there
   python security.py --check       # FERNET_KEY is valid (read from the .env file).
   ```
   Everyone sharing a database needs the **same** `FERNET_KEY`: send the `.env` line privately.
   Never commit `.env`. A `FERNET_KEY` environment variable, if set, is used before `.env`.
   The app also checks the key at startup and warns (but keeps running) if it is missing or invalid.

## Run

```
python main.py            # uses MySQL; if it is not reachable, starts in SAMPLE mode
python main.py --demo     # force sample mode (no database, no lab)
```

Sample mode keeps data in memory only and labels everything as sample data. Use it if the
lab or MySQL fails: the Scan tab's *Demo mode* box loads `sample_data.py`.
When MySQL is connected, the *Demo mode* box only previews the sample devices: they cannot
be approved into the real database (Approve is disabled, and `db.py` refuses them too).

## The five-minute demo path

1. **Scan** tab: username, password, optional seed IP (blank = default gateway), Scan.
2. Select devices, **Approve selected**. They appear in **Devices**.
3. **Topology** shows the map (gray = seen but not managed). Single points of failure are listed.
4. **Findings**: Run review (reads each device's config over SSH). Health score + fixes.
5. Select a finding, **Send to Configure**, check the preview, **Apply**.
6. Or in **Configure**: add 3 VLANs, Preview, Apply. Check with `show vlan brief` on the switch.
7. **Logs** shows every apply, success or failed.

## Build the lab

See `lab/lab_configs.txt` (GNS3 topology, device configs, and the planted mistakes).
GNS3 needs Cisco images from your school or the Cisco Networking Academy. Without
images, use Packet Tracer for the topology screenshot and demo mode for the app demo.

## Tests

```
python -m pytest -q                       # unit tests (no lab, no MySQL needed)
NETCOMMAND_TEST_DB=1 python -m pytest -q  # also tests db.py against MySQL (WIPES the tables!)
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

## Status: the 60% build

| Part | State |
|---|---|
| 1 Discovery crawl (`discovery/crawler.py`), SSH engine (`config/connect.py`), Configure tab | Built and tested against a fake lab (`tests/fakes.py`) |
| 2 MySQL (`schema.sql`, `db.py`), sample-mode twin (`db_fake.py`), `security.py`, `validation.py`, `monitor/monitor.py` | Built and tested, `db.py` also against a real MySQL-compatible server |
| 3 Review rules, topology map, command builders | Teammates' work, unchanged |
| 4 Findings and Topology tabs, lab, README | Teammates' work, unchanged |
| 5 Window, Devices, Logs, Scan tabs | Teammates' work, unchanged |

**Not yet tested on real Cisco devices.** The crawl and apply logic are tested with fake switches
that answer the same commands. On the real GNS3 lab, run T1 first. If the scan finds the
starting switch but no neighbors, paste the output of `show cdp neighbors detail` into
`tests/test_crawler.py` (`parse_cdp`) to see why. Also confirm CDP is on (`show cdp neighbors`).

**The monitor** pings every registered device every 30 seconds (real database mode only) and
saves an event only when a device changes between up and down. The Devices tab shows the
status. Start with `python main.py --no-monitor` to turn it off.

**Left for the remaining 40%:** learning extra subnets from router tables, MAC addresses and
end devices, scheduled rescans, an Events screen for the monitor, more review rules (unused ports,
native VLAN mismatch, user ports in VLAN 1, duplicate IPs), restore from a backup, and the
optional console-cable setup mode.
