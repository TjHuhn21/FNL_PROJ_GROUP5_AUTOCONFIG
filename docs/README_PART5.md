# Part 5: Window, Devices, Logs, and Scan screens

## Your files
- `main.py`
- `services.py`
- `gui/__init__.py`
- `gui/theme.py`
- `gui/main_window.py`
- `gui/devices_tab.py`
- `gui/logs_tab.py`
- `gui/scan_tab.py`
- `sample_data.py`, `conftest.py` (shared by everyone, identical in every package; do not edit)

## Needs from other parts
The store (db_fake.py now, db.py later: same function names), validation.py (Part 2), discovery/crawler.py (Part 1), and the other tabs that main_window builds (configure_tab, findings_tab, topology_tab). Unzip over the full project to run.

## Run
```
pip install -r requirements.txt
python main.py --demo      # sample mode, no database
python main.py             # MySQL, falls back to sample mode
```

## Done when
The window and all tabs open without errors, Devices searches, sorts and pages, bad input shows a clear message, and Scan shows sample results and Approve adds them to Devices.

## Notes
services.py is the small glue layer main_window uses (network data, config fetching, discovery wrapper); it lives with you because main_window imports it. To switch from fake data to MySQL you change nothing in your tabs: main.py picks db.py when it can connect and db_fake.py otherwise.

Branch name: `part5-...`; open a pull request when your piece works. The lead merges.
