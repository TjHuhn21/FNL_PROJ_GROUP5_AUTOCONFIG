# Phase 0A — Read-only MariaDB inspection

**Purpose.** Find out whether the local MariaDB (XAMPP) is healthy enough for
Phase 0B, which would create two separate databases and three accounts. Creating
accounts writes to MariaDB's own privilege tables, including `mysql.db`, which was
damaged before. Phase 0A itself changes nothing in MariaDB.

You run every step yourself and send the reports. They are analysed, and then
everything **stops** until you approve the next step.

## The files

| File (`docs/phase0/`) | Step | Contacts MariaDB? | Can it trigger automatic table recovery? |
|---|---|---|---|
| `0A1_step1_discover.ps1` | 0A-1 Step 1 | No | No |
| `0A1_readonly_server.sql` | 0A-1 Step 2 | Yes, read-only statements | Not expected (designed to open no table; see "Limits") |
| `0A1_step3_errorlog.ps1` | 0A-1 Step 3 | No | No |
| `0A2_readonly_tables.sql` | 0A-2, **only after approval** | Yes, read-only statements | **Yes, possible** (it opens tables; see below) |

## Read-only statements vs. what the server may do on its own

1. **What the scripts send.** Only read-only statements: `SELECT`, `SHOW` of
   variables/status/table cache, `information_schema` queries, a generated `SELECT`
   (0A-2), and session settings that affect only this connection. Never `CREATE`,
   `ALTER`, `DROP`, `INSERT`, `UPDATE`, `DELETE`, `GRANT`, `REVOKE`, `FLUSH`,
   `CHECK TABLE`, `REPAIR`, `ANALYZE`, `OPTIMIZE`. (On Aria and MyISAM even
   `CHECK TABLE` can update a table's state flags, so it is not used.) `SHOW GRANTS`
   is not used either, because its output can contain authentication information.
2. **What the server may do by itself.** The `mysql.*` privilege tables use the
   **Aria** engine. If an Aria or MyISAM table is marked as crashed and
   `aria_recover_options` / `myisam_recover_options` allow it, the server may
   **repair the table automatically when it is opened**, which writes to it.
   `SET SESSION TRANSACTION READ ONLY` does **not** prevent that.

## What each step reads, writes, and cannot guarantee

### 0A-1 Step 1 — `0A1_step1_discover.ps1` (PowerShell, no MariaDB contact)

* **Reads:** the running `mysqld.exe` processes and any Windows service that runs
  `mysqld` (Windows management data); the option-file names on their command lines;
  the existence, size and date of candidate option files; and from each existing
  file **only** section headers, `!include` / `!includedir` lines and these
  settings: `datadir`, `basedir`, `log_error`, `log_basename`, `log_warnings`,
  `console`, `port`, `bind_address`, `skip_networking`, `aria_recover_options`,
  `myisam_recover_options`, `skip_grant_tables`, `innodb_force_recovery`,
  `plugin_dir`.
* **Writes:** `0A1_step1_server_and_config.txt` in the report folder. Nothing else.
* **Redaction (reduces risk, does not guarantee):** before writing, the values of
  password-like arguments on command lines and service paths are replaced by
  `********`: options whose name contains `password`, `passwd`, `pwd`, `secret`,
  `key`, `token` or `credential` (with `=` or a space, plain or quoted, also inside a
  fully quoted argument) and the short form `-p<value>`. Option-file lines other than
  the list above (for example `password=` in a `[client]` section) are never printed.
  A secret in an unusual form can still appear, so the report must be checked by
  hand before it is shared.
* **How it chooses candidate files:** from the actual command line.
  `--no-defaults` → no option files. `--defaults-file` → only that file (plus its
  includes and any `--defaults-extra-file`). A **relative** `--defaults-file` (XAMPP
  uses `mysql\bin\my.ini`) is checked against each possible base folder, because
  Windows does not show a running process's working folder. Otherwise, the documented
  default Windows locations in reading order (system Windows directory, Windows
  directory, `C:\`, `INSTALLDIR`, `INSTALLDIR\data`, `%MARIADB_HOME%` /
  `%MYSQL_HOME%` where set). This list is taken from MariaDB's documentation and is to
  be compared with the documentation of your version once it is known.
* **Cannot guarantee:** this is **candidate discovery only**. That a file exists, or
  contains a setting, does **not** prove MariaDB loaded it or that its value is the
  one in effect: later files, later lines, a `--defaults-group-suffix` group or the
  command line can override it. If several candidates exist, this step cannot tell
  which one was loaded. The **confirmed active values** are the ones the server
  reports in Step 2; comparing candidates with them can only show which file is
  **consistent** with the active values.

### 0A-1 Step 2 — `0A1_readonly_server.sql` (read-only SQL)

* **Reads:** server variables and status counters (including `version`, `datadir`,
  `log_error`, `log_basename`, `hostname`, `aria_recover_options`,
  `myisam_recover_options`, `skip_grant_tables`, `innodb_force_recovery`); the list
  of databases; the `information_schema` privilege views (grantee names and privilege
  names only); the `mysql` tables present in the table cache, before and after.
* **Writes:** nothing in the database. The client's `tee` writes `0A1_report.txt`.
* **Cannot guarantee:**
  * It is **designed** not to open any table. In MariaDB the privilege tables are
    loaded into memory at start-up, and the `information_schema` privilege views are
    answered from that in-memory copy; `SCHEMATA` comes from the data-directory
    listing; `SHOW VARIABLES / STATUS / OPEN TABLES` from server memory. This is how
    MariaDB is built in general and is **not verified for your exact build** (the
    version is only known after this step). The before/after table-cache lists are
    evidence, not proof (another connection can change the cache at the same time).
  * The privilege views list only accounts with at least one visible privilege row,
    so they **cannot prove that an account name is unused**. The definitive name check
    is in 0A-2; and in 0B the accounts would be created with `CREATE USER` **without**
    `IF NOT EXISTS`, so an existing name makes the script stop instead of reusing it.

### 0A-1 Step 3 — `0A1_step3_errorlog.ps1` (PowerShell, no MariaDB contact)

* **Reads:** the Step 2 report (for the active values); the running `mysqld`
  command line (only to see whether `--console` was used); the names, sizes and dates
  of `*.err` / `*error*.log` files in `datadir`; the content of those files; the
  names of registered MariaDB/MySQL event sources; and, for those sources only, their
  entries in the Windows **Application event log** (last 60 days, newest 200).
  The event log is filtered by provider in the query itself, so the whole
  Application log is not read. If no MariaDB/MySQL source is registered, no events
  are read (MariaDB started by XAMPP normally logs to its file); `-ScanWholeApplicationLog`
  searches the whole log on request (slower).
* **Writes:** `0A1_errorlog.txt` in the report folder. Nothing else.
* **The three `log_error` cases are handled separately:**
  * **empty**: the server reported no file name. The documented Windows defaults
    `<datadir>\<log_basename>.err` (when `log_basename` is set) and
    `<datadir>\<hostname>.err` are listed as **candidates**; finding one does not
    prove it is the current log.
  * **`stderr`**: the server writes to standard error, **not to a file**. No file
    is assumed; any `.err` files in `datadir` are reported as **historical only**.
  * **a path**: that file (a relative path is placed in `datadir`). If it has no
    extension, `<path>.err` is checked as a labelled **alternative only**, never
    assumed.
  * In every case all `*.err` / `*error*.log` files in `datadir` are listed, and a
    `--console` start is noted (messages may then go to a hidden console window).
* **Large logs:** files are streamed line by line with a shared read handle (MariaDB
  can keep writing; nothing is locked or loaded whole). For each file the report
  keeps keyword counts, the **first 50** matching lines (oldest history, so an old
  incident is not lost), the **last 150** matching lines, and the last 200 lines.
  A file larger than 512 MB is scanned only over its last 512 MB, and the report
  says so (rerun with `-MaxScanMB` to scan more).
* **Redaction (reduces risk, does not guarantee):** output lines pass through a
  pattern-based filter for `PASSWORD('…')`, `IDENTIFIED BY [PASSWORD] '…'`,
  `IDENTIFIED VIA … USING/AS '…'`, `SET PASSWORD … = '…'` and `name=value` /
  `name: value` for password-like names (the harmless "using password: YES/NO" is
  kept). Error logs can still contain other sensitive details (user and host names,
  file paths, fragments of failed statements), and a secret in an unusual form is
  not recognised.
* **Cannot guarantee:** a log file can be incomplete (for example when `--console`
  was used, or after a manual log rotation), and the event log may hold only some
  start-up messages.

### 0A-2 — `0A2_readonly_tables.sql` (read-only SQL, only after approval)

* **Reads:** status and row counts of the `mysql.*` privilege tables; `Db/User/Host`
  of `mysql.db`; `User/Host` of `mysql.user` (no password or authentication column);
  a **definitive** check that `nc_lab_api`, `nc_lab_migrate`, `nc_test` do not exist;
  every object in the `netcommand` database and an exact `COUNT(*)` of **every** base
  table. The counting query is generated from the same `information_schema` list,
  so the list and the counts agree. Section 8 gives the number of base tables, which
  must equal the number of rows in section 9. Views are listed but not counted.
* **Truncation safeguard:** `GROUP_CONCAT` silently cuts long results. Section 9
  computes the exact expected length of the counting query separately, shows the
  expected and generated lengths and any truncation warning, and runs the counts
  **only if the query is complete**. Otherwise it prints
  `FINDING: … counts were NOT run` instead of any count, so partial counts can never
  be mistaken for complete ones.
* **Writes:** nothing through its statements. The client's `tee` writes
  `0A2_report.txt`.
* **Cannot guarantee "no write":** it **opens** the `mysql.*` system tables (Aria)
  and every `netcommand` table. If one of them is marked as crashed and the recovery
  settings allow it, the server may repair it automatically. That is why 0A-2 runs
  only after the 0A-1 findings (recovery settings, error log) have been analysed and
  you approve it.

## Never done in Phase 0A

* No database or account change of any kind; no `SHOW GRANTS`.
* No `aria_chk`, `myisamchk`, `mysql_upgrade`, `mysql_install_db`, repair or recovery
  command.
* No stopping, restarting, reinstalling or reinitialising MariaDB.
* No change to `my.ini` or any option file, service, or Windows setting.
* No password hashes or other secrets are selected or printed.
* **phpMyAdmin is not used** (it runs its own queries and may write to its own
  tables). Please keep it closed during 0A, so it does not disturb the table-cache
  evidence.

## Before you start

1. MariaDB is running (XAMPP Control Panel shows MySQL as running). Do **not**
   restart it for this inspection.
2. You know the MariaDB `root` password. (XAMPP's root account may have **no**
   password; if so, press Enter at the prompt and mention it, since that is a
   finding, but do not change it now.)
3. Create a report folder **outside the project**, so reports never end up in Git:

   ```powershell
   New-Item -ItemType Directory -Force "$env:USERPROFILE\Documents\NetCommand-0A" | Out-Null
   ```

4. Read the scripts in Notepad before running them, if you like.

---

## 0A-1 Step 1 — Running server and candidate option files

`<project folder>` in the commands below stands for the folder where you cloned NetCommand (for example `C:\Projects\netcommand`); replace it with your own path.

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "<project folder>\docs\phase0\0A1_step1_discover.ps1"
```

(`-ExecutionPolicy Bypass` applies to this single run only and changes no setting.)
Result: `0A1_step1_server_and_config.txt`. Note the **bin folder** (the folder of
`ExecutablePath`) for Step 2.

## 0A-1 Step 2 — Active server values (read-only SQL)

The MariaDB client's `tee` and `source` commands do not handle paths with spaces
reliably (a Windows user name such as `First Last` has one), so the script is copied into the report folder and the
client is started **from there**. Use the bin folder from Step 1 (here
`C:\xampp\mysql\bin`):

```powershell
$r = "$env:USERPROFILE\Documents\NetCommand-0A"
Copy-Item "<project folder>\docs\phase0\0A1_readonly_server.sql" $r
Set-Location $r
& 'C:\xampp\mysql\bin\mysql.exe' -u root -p --force --table --no-auto-rehash
```

* `--no-auto-rehash`: the client does not read table and column names for tab
  completion.
* `--force`: the client continues after an error, so one failing statement does
  not hide the rest. An error is a finding; keep it in the report.

Type the root password at the prompt (it is not shown and not saved). Then, at the
`MariaDB [(none)]>` prompt, type these lines one at a time:

```
tee 0A1_report.txt
source 0A1_readonly_server.sql
notee
exit
```

`tee` copies everything shown on screen, results **and** error messages, into
`0A1_report.txt`. If anything on screen is missing from the file, copy it in by hand.

## 0A-1 Step 3 — Error log and Windows event log

Run after Step 2 (it reads the active values from `0A1_report.txt`):

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "<project folder>\docs\phase0\0A1_step3_errorlog.ps1"
```

Result: `0A1_errorlog.txt`. If the report says a file is larger than 512 MB and was
only partly scanned, mention it; a rerun with `-MaxScanMB 2048` (for example) scans
more.

## 0A-1 Step 4 — Review and send, then stop

Look through the three files in `Documents\NetCommand-0A`:

* `0A1_step1_server_and_config.txt`
* `0A1_report.txt`
* `0A1_errorlog.txt`

**Inspect them by hand before sharing.** The scripts redact password-like values,
but redaction is pattern-based and cannot guarantee that nothing sensitive remains
(error logs in particular can contain user names, host names, paths and fragments of
failed statements). Replace anything you would rather not share with `****` before
sending.

**Then stop.** The reports are analysed. 0A-2 is run only if that analysis shows it
is reasonable to open the system tables, **and** you approve it.

---

## 0A-2 — Table inspection (ONLY after the 0A-1 analysis and your approval)

```powershell
$r = "$env:USERPROFILE\Documents\NetCommand-0A"
Copy-Item "<project folder>\docs\phase0\0A2_readonly_tables.sql" $r
Set-Location $r
& 'C:\xampp\mysql\bin\mysql.exe' -u root -p --force --table --no-auto-rehash
```

```
tee 0A2_report.txt
source 0A2_readonly_tables.sql
notee
exit
```

Reminder: its statements are read-only, but **opening the tables can trigger
automatic recovery** of a crashed Aria/MyISAM table (see above). Send
`0A2_report.txt`, then stop again.

---

## How the reports will be judged

**Healthy (Phase 0B may be proposed):**
* no errors in either report;
* no system table reported as crashed or unreadable;
* no recent Aria / checksum / corruption / "Got error" lines for `mysql.*` in the error
  log or the event log;
* the planned database names are free, and (0A-2) the planned account names are free;
* `skip_grant_tables` and `innodb_force_recovery` are off.

**Unhealthy (stop):** any read error on a `mysql.*` table, a "marked as crashed"
state, recent Aria or checksum errors, or the server running with `skip_grant_tables`
or forced recovery. Then nothing further is proposed except a written report. Any
repair would be a separate plan for your approval, never part of Phase 0.

## Note for later (Phase 0B): backup inspection is not a restore test

Phase 0B takes a `mysqldump` backup before anything is created. Two different
statements can be made about it, and they are kept apart:

* **Backup inspected**: the file finished (`-- Dump completed` line), it contains a
  `CREATE TABLE` for every table, and its row counts match the 0A-2 counts. This
  shows the file looks complete. It does **not** prove that it can be restored.
* **Restore-tested**: the dump has actually been loaded into a separate, isolated
  database or MariaDB instance, and its tables and counts compared. Only then is the
  backup called restore-tested. That step writes to a server and needs its own
  approval.
