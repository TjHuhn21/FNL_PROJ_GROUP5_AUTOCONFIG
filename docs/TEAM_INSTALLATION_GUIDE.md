# NetCommand – Team Installation Guide (Windows 10/11, PowerShell)

This guide installs NetCommand on **your own computer**, from nothing to a signed-in
desktop window. Follow the steps **in order**. Every command is meant for **Windows
PowerShell**, run from the project folder unless a step says otherwise.

> **Security rules (read first)**
> * Never commit, email, screenshot or paste into a chat: your `.env`, your `backend/.env`,
>   passwords, the `FERNET_KEY`, the `BACKEND_OTP_PEPPER`, email codes or the `backups`
>   folder.
> * `<placeholders>` in this guide mean "type your own value here", without the `< >`.
> * Every password you choose below is **your own**. Use a different password for each
>   MySQL account.

**Time needed:** about 60–90 minutes the first time.

---

## Contents

1. [What you are installing](#1-what-you-are-installing)
2. [Before you start](#2-before-you-start)
3. [Install Python, Git and MySQL](#3-install-python-git-and-mysql)
4. [Get the code and install the packages](#4-get-the-code-and-install-the-packages)
5. [Create the databases and the MySQL accounts](#5-create-the-databases-and-the-mysql-accounts)
6. [Create the desktop tables](#6-create-the-desktop-tables)
7. [Configure the desktop application (`.env`)](#7-configure-the-desktop-application-env)
8. [Configure the backend (`backend/.env`)](#8-configure-the-backend-backendenv)
9. [Create the backend tables (migrations)](#9-create-the-backend-tables-migrations)
10. [Create the backend's runtime account](#10-create-the-backends-runtime-account)
11. [Start and check the backend](#11-start-and-check-the-backend)
12. [Create the first administrator](#12-create-the-first-administrator)
13. [Start NetCommand and sign in](#13-start-netcommand-and-sign-in)
14. [Run the offline tests](#14-run-the-offline-tests)
15. [Optional: rehearse with the mock lab](#15-optional-rehearse-with-the-mock-lab)
16. [Every day: starting NetCommand](#16-every-day-starting-netcommand)
17. [Updating to a newer version](#17-updating-to-a-newer-version)
18. [Troubleshooting](#18-troubleshooting)
19. [Quick reference](#19-quick-reference)

---

## 1. What you are installing

```
 NetCommand desktop app (main.py)
   │  sign-in, accounts ──► NetCommand backend (python -m backend, http://127.0.0.1:8000)
   │                           └──► MySQL database  netcommand_test   (accounts, sessions, audit log)
   │                           └──► email (Gmail SMTP, or a development "outbox" folder)
   │  devices, findings, logs ──► MySQL database  netcommand          (directly)
   └  scan / configure ────────► Cisco switches and routers (SSH)
```

* **One MySQL server** on your computer, with **two databases**:
  `netcommand` (the desktop's device data) and `netcommand_test` (the backend's accounts).
* **Three MySQL accounts**, each with only the rights it needs:

  | Account | Used by | Database |
  |---|---|---|
  | `netcommand_app` | the desktop application | `netcommand` |
  | `netcommand_migrator` | the migration command (creates the backend tables) | `netcommand_test` |
  | `netcommand_api` | the running backend | `netcommand_test` |

* **Every team member runs everything locally.** The backend only listens on your own
  computer (`127.0.0.1`), so each of you has your own MySQL, backend, administrator account,
  encryption key and email setup.

---

## 2. Before you start

- [ ] Windows 10 or 11, and an account that may install programs.
- [ ] About 3 GB of free disk space.
- [ ] Access to the GitHub repository (ask the repository owner to add you).
- [ ] For real email codes: a Gmail account with **2-Step Verification** turned on (needed
      for an *app password*). Without it you can use the **development outbox** (step 8.4).
- [ ] Open **Windows PowerShell** (Start menu → type *PowerShell*). You do **not** need
      "Run as administrator" for this guide, except where a step says so.

---

## 3. Install Python, Git and MySQL

### 3.1 Python 3.10

NetCommand is tested on **Python 3.10** (3.10.0). Newer versions (3.11–3.13) are not tested.

1. Go to <https://www.python.org/downloads/windows/> and download a **Python 3.10.x**
   "Windows installer (64-bit)".
2. Run it. On the first screen tick **"Add python.exe to PATH"**.
3. Choose **Customize installation** and make sure **"tcl/tk and IDLE"** is ticked (the
   NetCommand window needs it). Finish the installation.
4. Close and reopen PowerShell, then check:

   ```powershell
   python --version
   ```

   **Expected:** `Python 3.10.x`

   If you have several Python versions, `py -3.10 --version` must also work; then use
   `py -3.10` instead of `python` in step 4.2.

### 3.2 Git

1. Download Git for Windows from <https://git-scm.com/download/win> and install it with
   the default options.
2. Reopen PowerShell and check:

   ```powershell
   git --version
   ```

   **Expected:** `git version 2.x.x.windows.x`

### 3.3 MySQL Community Server 8.4 (LTS)

NetCommand needs **MySQL 8.4** (MySQL 8.x). **MariaDB and XAMPP's MySQL do not work** for the
backend (it uses MySQL 8 features).

1. Download **MySQL Community Server 8.4 LTS** (Windows MSI installer) from
   <https://dev.mysql.com/downloads/mysql/>.
2. Install it. In the configuration screens:
   * **Type and Networking:** set **Port** to **3307**. (This guide uses 3307 so it never
     clashes with another MySQL/MariaDB on 3306. If you keep 3306, use 3306 everywhere this
     guide says 3307.)
   * **Accounts and Roles:** choose a strong **root** password and keep it safe. You need it
     in step 5 only; NetCommand itself never uses root.
   * **Windows Service:** keep "Configure MySQL Server as a Windows Service" and "Start the
     MySQL Server at System Startup" ticked.
3. Check that the service runs:

   ```powershell
   Get-Service MySQL*
   Test-NetConnection 127.0.0.1 -Port 3307
   ```

   **Expected:** `Status Running` for the MySQL service, and `TcpTestSucceeded : True`.

4. The MySQL command-line client is **not** on the PATH. Store its full path in a variable
   for this PowerShell window (repeat this line whenever you open a new window and need it):

   ```powershell
   $mysql = 'C:\Program Files\MySQL\MySQL Server 8.4\bin\mysql.exe'
   & $mysql --version
   ```

   **Expected:** `...mysql.exe  Ver 8.4.x for Win64 ...`. If the file is not found, look in
   `C:\Program Files\MySQL\` for the right folder name.

---

## 4. Get the code and install the packages

### 4.1 Clone the repository

Choose a folder **without spaces in its path** (for example `C:\Projects`):

```powershell
mkdir C:\Projects -Force
cd C:\Projects
git clone <repository URL> netcommand
cd netcommand
```

(`<repository URL>`: on the GitHub page, **Code → HTTPS**, copy the address.)

**Expected:** a `netcommand` folder containing `main.py`, `requirements.txt`, `backend\`,
`docs\` and more. **All later commands are run from this folder.**

### 4.2 Create the virtual environment and install the packages

```powershell
python -m venv venv
.\venv\Scripts\python.exe -m pip install --upgrade pip
.\venv\Scripts\python.exe -m pip install -r requirements.txt -r backend\requirements.txt
```

* `venv` is a private Python just for NetCommand (it is never committed).
* This guide always calls `.\venv\Scripts\python.exe` directly, so you never need to
  "activate" the environment. (Activating with `.\venv\Scripts\Activate.ps1` is optional; if
  PowerShell says *running scripts is disabled on this system*, simply keep using the full
  path as shown.)

**Expected:** the last line starts with `Successfully installed ...` and lists, among
others, `netmiko-4.8.0`, `paramiko-4.0.0`, `PyMySQL-1.2.4`, `customtkinter-5.2.2`,
`fastapi-0.162.5`. Check:

```powershell
.\venv\Scripts\python.exe -m pip check
```

**Expected:** `No broken requirements found.`

---

## 5. Create the databases and the MySQL accounts

This step uses the MySQL **root** account once, in the MySQL client.

### 5.1 Open the MySQL client as root

```powershell
$mysql = 'C:\Program Files\MySQL\MySQL Server 8.4\bin\mysql.exe'
& $mysql --host=127.0.0.1 --port=3307 --user=root -p
```

Type the root password (nothing is shown while you type). **Expected:** the `mysql>` prompt.

> Always use `--host=127.0.0.1`, never `localhost`: the accounts below are created for
> `127.0.0.1`, and NetCommand connects to `127.0.0.1`. Mixing them causes error 1045.

### 5.2 Create the two databases

At the `mysql>` prompt:

```sql
CREATE DATABASE IF NOT EXISTS netcommand CHARACTER SET utf8mb4;
CREATE DATABASE IF NOT EXISTS netcommand_test CHARACTER SET utf8mb4 COLLATE utf8mb4_0900_ai_ci;
SHOW DATABASES LIKE 'netcommand%';
```

**Expected:** two rows, `netcommand` and `netcommand_test`.

### 5.3 The desktop account `netcommand_app`

Replace `<desktop password>` with a password you choose (keep the single quotes):

```sql
CREATE USER 'netcommand_app'@'127.0.0.1' IDENTIFIED BY '<desktop password>';
GRANT SELECT, INSERT, UPDATE, DELETE ON `netcommand`.* TO 'netcommand_app'@'127.0.0.1';
```

The desktop only reads and writes its own rows; it cannot create or drop tables, or touch any
other database. (The tables are created by root in step 6.)

### 5.4 The migration account `netcommand_migrator`

This account only creates the backend's tables (step 9). These are exactly the statements
the project prints with `migrate recommended-grants`:

```sql
CREATE USER 'netcommand_migrator'@'127.0.0.1' IDENTIFIED BY '<migration password>';
GRANT SELECT, INSERT, DELETE, CREATE   ON `netcommand_test`.`schema_migrations` TO 'netcommand_migrator'@'127.0.0.1';
GRANT SELECT, CREATE, DROP, REFERENCES ON `netcommand_test`.`users` TO 'netcommand_migrator'@'127.0.0.1';
GRANT SELECT, CREATE, DROP             ON `netcommand_test`.`email_challenges` TO 'netcommand_migrator'@'127.0.0.1';
GRANT SELECT, CREATE, DROP             ON `netcommand_test`.`sessions` TO 'netcommand_migrator'@'127.0.0.1';
GRANT SELECT, CREATE                   ON `netcommand_test`.`audit_log` TO 'netcommand_migrator'@'127.0.0.1';
GRANT LOCK TABLES ON `netcommand\_test`.* TO 'netcommand_migrator'@'127.0.0.1';
```

(Yes, `netcommand\_test` with a backslash in the last line: at database level `_` would
otherwise be a wildcard.) **Expected:** `Query OK, 0 rows affected` for each line.

The **runtime** account `netcommand_api` is created later, in step 10, because its rights
can only be granted once the tables exist.

### 5.5 Leave the client

```sql
EXIT;
```

Then clear the screen, so the passwords you typed are not left visible:

```powershell
Clear-Host
```

---

## 6. Create the desktop tables

From the **project folder** (the `source` command reads `schema.sql` from the current folder):

```powershell
$mysql = 'C:\Program Files\MySQL\MySQL Server 8.4\bin\mysql.exe'
& $mysql --host=127.0.0.1 --port=3307 --user=root -p --execute="source schema.sql"
```

> PowerShell has **no** `<` input redirection, so `mysql ... < schema.sql` does **not** work
> here (*The '<' operator is reserved for future use*). Always use `source` as above.

`schema.sql` creates only the five desktop tables (`devices`, `links`, `findings`,
`status_events`, `config_logs`); it never creates accounts and never changes existing data.

**Check** (with the desktop account this time):

```powershell
& $mysql --host=127.0.0.1 --port=3307 --user=netcommand_app -p --execute="SHOW TABLES FROM netcommand;"
```

**Expected:** the five tables listed. If you get **error 1045**, see
[18.1](#181-mysql-errors).

---

## 7. Configure the desktop application (`.env`)

### 7.1 Create `.env`

```powershell
Copy-Item .env.example .env
notepad .env
```

Fill in the database lines (leave the other lines as they are for now):

```ini
DB_HOST=127.0.0.1
DB_PORT=3307
DB_USER=netcommand_app
DB_PASSWORD=<desktop password>
DB_NAME=netcommand
```

`NETCOMMAND_API_URL=http://127.0.0.1:8000` is already correct. Leave
`NETCOMMAND_LEGACY_SSH_HOSTS=` empty unless an old Cisco device needs it (see the complete
guide, section 8.9). Save and close Notepad.

`.env` is excluded from Git by `.gitignore` and must **never** be committed.

### 7.2 Generate the encryption key (`FERNET_KEY`)

The key encrypts the device logins NetCommand saves. Let the project write it (it is never
shown, so it cannot be copied wrongly):

```powershell
.\venv\Scripts\python.exe security.py --new-key
.\venv\Scripts\python.exe security.py --check
```

**Expected:**

```
A new FERNET_KEY was written to .env (not shown). ...
FERNET_KEY is valid (read from the .env file).
```

* `--new-key` **refuses** if Git could expose `.env` (that is a safety feature), and does
  not replace a key that already works.
* Keep this key. If it changes, saved device logins can no longer be read. You only need
  someone else's key if you share **their** database (normally you do not).

---

## 8. Configure the backend (`backend/.env`)

### 8.1 Create `backend/.env`

```powershell
Copy-Item backend\.env.example backend\.env
notepad backend\.env
```

The backend reads **only** this file (and `BACKEND_*` environment variables); it never reads
the desktop's `.env`.

### 8.2 Server and database settings

Set these lines (put passwords in **single quotes**: the file is read by python-dotenv, which
would change some characters in unquoted or double-quoted values):

```ini
BACKEND_ENV=development
BACKEND_HOST=127.0.0.1
BACKEND_PORT=8000
BACKEND_LOG_LEVEL=INFO

BACKEND_DB_ENABLED=true
BACKEND_DB_HOST=127.0.0.1
BACKEND_DB_PORT=3307
BACKEND_DB_USER=netcommand_api
BACKEND_DB_PASSWORD='<runtime password>'
BACKEND_DB_NAME=netcommand_test
BACKEND_DB_SERVER_UUID=

BACKEND_MIGRATE_USER=netcommand_migrator
BACKEND_MIGRATE_PASSWORD=
```

* `<runtime password>`: choose it now; you create the `netcommand_api` account with the same
  password in step 10.
* Leave `BACKEND_MIGRATE_PASSWORD` **empty**: the migration command then asks for it, so it
  is never stored in a file.
* Leave the `BACKEND_AUTH_*` lines empty (the approved defaults: 12-character passwords,
  5-minute codes, 8-hour sessions...). They can only be made stricter, never weaker.
* `BACKEND_FERNET_KEY` stays empty (not used yet).

### 8.3 Generate the code pepper (`BACKEND_OTP_PEPPER`)

The pepper is a secret (at least 32 characters) that protects the email codes in the
database. Generate a random one:

```powershell
.\venv\Scripts\python.exe -c "import secrets; print(secrets.token_urlsafe(48))"
```

**Expected:** one line of 64 random characters (letters, digits, `-` and `_`). Copy it into
`backend/.env`:

```ini
BACKEND_OTP_PEPPER='<the 64 characters>'
```

Then run `Clear-Host` so it does not stay on screen. Keep it unchanged afterwards: changing
it only invalidates codes that are still open.

### 8.4 Email: choose ONE option

The backend emails a six-digit code at registration and at every sign-in.

**Option A – real email through Gmail (recommended for the demonstration)**

1. In your Google account: **Security → 2-Step Verification** (turn it on), then
   **Security → App passwords** → create one (name it *NetCommand*). Google shows a
   16-character app password; this is **not** your Gmail password.
2. In `backend/.env`:

   ```ini
   BACKEND_MAIL_BACKEND=smtp
   BACKEND_MAIL_OUTBOX_DIR=
   BACKEND_SMTP_ENABLED=true
   BACKEND_SMTP_HOST=smtp.gmail.com
   BACKEND_SMTP_PORT=587
   BACKEND_SMTP_USERNAME=<your address>@gmail.com
   BACKEND_SMTP_PASSWORD='<the 16-character app password, without spaces>'
   BACKEND_SMTP_FROM=<your address>@gmail.com
   ```

   Port 587 uses STARTTLS; the connection is always encrypted and the certificate checked.

**Option B – development outbox (no email account needed; your computer only)**

```ini
BACKEND_ENV=development
BACKEND_MAIL_BACKEND=outbox
BACKEND_MAIL_OUTBOX_DIR=
BACKEND_SMTP_ENABLED=false
```

Every "email" is then written as a `.eml` file to `%TEMP%\netcommand-dev-outbox` (outside the
project folder). To read the newest code:

```powershell
Get-ChildItem "$env:TEMP\netcommand-dev-outbox\*.eml" | Sort-Object LastWriteTime | Select-Object -Last 1 | Get-Content
```

The code is in the text of the message. The outbox is refused when `BACKEND_ENV=production`.
Anyone who can open that folder can read the codes: delete it when you are done
(`Remove-Item "$env:TEMP\netcommand-dev-outbox" -Recurse`).

Save `backend/.env` and close Notepad.

### 8.5 Check the settings

```powershell
.\venv\Scripts\python.exe -m backend.database.migrate recommended-grants
```

This prints the account SQL for `netcommand_test` (the same statements as step 5.4 and
10.1) **without connecting** to anything, which proves the settings file is valid. If a
setting is wrong, the command stops with a Python error whose **last line** names the
setting (never its value), for example:

```
backend.settings.SettingsError: Invalid backend settings: BACKEND_OTP_PEPPER must be at least 32 characters.
```

Fix that line in `backend/.env` and run the command again until it prints the SQL.

---

## 9. Create the backend tables (migrations)

Migrations never run by themselves. Run them in this order:

```powershell
.\venv\Scripts\python.exe -m backend.database.migrate plan
```
Prints the SQL that will run (no connection). Read it if you are curious.

```powershell
.\venv\Scripts\python.exe -m backend.database.migrate status
```
Asks `Password for netcommand_migrator:` (type the migration password; it is not shown).
**Expected:** `Database: netcommand_test` and `pending  1 auth_tables`.

```powershell
.\venv\Scripts\python.exe -m backend.database.migrate up --dry-run
```
Asks for the migration password again (every command that connects does). **Expected last
line:** `[dry run] 1 migration(s): [1]` (checks only, changes nothing).

```powershell
.\venv\Scripts\python.exe -m backend.database.migrate up --confirm-database netcommand_test
```
**Expected last line:** `1 migration(s): [1]` (progress lines may come before it). The tables
`users`, `email_challenges`, `sessions`, `audit_log` and `schema_migrations` now exist in
`netcommand_test`.

```powershell
.\venv\Scripts\python.exe -m backend.database.migrate status
```
**Expected:** `applied  1 auth_tables ...` and
`audit_log protection: NOT PROTECTED` (normal at this point; see the optional step 10.3).
The command then ends with exit code 3 because of that line; that is expected.

`--confirm-database netcommand_test` is required for every command that changes a database,
so a typo can never change the wrong one.

---

## 10. Create the backend's runtime account

### 10.1 Create `netcommand_api` (as root, AFTER step 9)

```powershell
& $mysql --host=127.0.0.1 --port=3307 --user=root -p
```

```sql
CREATE USER 'netcommand_api'@'127.0.0.1' IDENTIFIED BY '<runtime password>';
GRANT SELECT, INSERT, UPDATE ON `netcommand_test`.`users` TO 'netcommand_api'@'127.0.0.1';
GRANT SELECT, INSERT, UPDATE ON `netcommand_test`.`email_challenges` TO 'netcommand_api'@'127.0.0.1';
GRANT SELECT, INSERT, UPDATE ON `netcommand_test`.`sessions` TO 'netcommand_api'@'127.0.0.1';
GRANT SELECT, INSERT         ON `netcommand_test`.`audit_log` TO 'netcommand_api'@'127.0.0.1';
GRANT SELECT                 ON `netcommand_test`.`schema_migrations` TO 'netcommand_api'@'127.0.0.1';
EXIT;
```

Use **the same** `<runtime password>` as `BACKEND_DB_PASSWORD` in `backend/.env`. Then
`Clear-Host`.

The runtime account can never delete rows or change the audit log.

### 10.2 Check the account

```powershell
.\venv\Scripts\python.exe -m backend.database.migrate check-runtime-grants
.\venv\Scripts\python.exe -m backend.database.migrate check-runtime-connection
```

**Expected:**
* `check-runtime-grants`: `Runtime account netcommand_api on netcommand_test:` followed by
  `ok: least privilege; ...` (exit code 0). `UNSAFE` or `MISSING` lines name what to fix.
* `check-runtime-connection`:
  `Runtime account netcommand_api on netcommand_test: READY (connected; SELECT 1; migrations and tables as expected)`.

### 10.3 Optional: protect the audit log with triggers (root)

This adds a second protection layer for `audit_log`. NetCommand works without it.

```powershell
.\venv\Scripts\python.exe -m backend.database.migrate audit-triggers-sql | Out-File -Encoding ascii .\audit_triggers.sql
& $mysql --host=127.0.0.1 --port=3307 --user=root -p --execute="source audit_triggers.sql"
Remove-Item .\audit_triggers.sql
```

(Do not use `>` instead of `Out-File -Encoding ascii`: it writes a format the `mysql` client
cannot read. `audit_triggers.sql` is git-ignored anyway.) Afterwards `migrate status`
reports `audit_log protection: PROTECTED (both triggers verified)`.

---

## 11. Start and check the backend

Open a **separate PowerShell window** for the backend and keep it open while you use
NetCommand:

```powershell
cd C:\Projects\netcommand
.\venv\Scripts\python.exe -m backend
```

**Expected** (the order may differ):

```
... Starting NetCommand backend: environment=development bind=127.0.0.1:8000 log_level=INFO database=enabled smtp=enabled mail=smtp fernet_key=not set otp_pepper=set
... Uvicorn running on http://127.0.0.1:8000
```

(With the outbox: `smtp=disabled mail=outbox`.) Secret values are never printed.

Check it from your **first** PowerShell window:

```powershell
curl.exe -s http://127.0.0.1:8000/health
curl.exe -s -w " HTTP %{http_code}`n" http://127.0.0.1:8000/ready
```

**Expected:** `{"status":"ok"}` and `{"status":"ready"} HTTP 200`.

* Use `curl.exe`, not `curl` (in PowerShell, `curl` is a different command).
* `/ready` answers `HTTP 503` with a reason if something is wrong: see
  [18.3](#183-backend-errors).
* Run only **one** backend at a time. Stop it with **Ctrl+C** in its window.

---

## 12. Create the first administrator

New accounts must be approved by an administrator, so the very first administrator is
created with a local command (once per installation). The backend may keep running.

```powershell
.\venv\Scripts\python.exe -m backend.auth.bootstrap_admin
```

It asks, in this order:

1. `Administrator email address:` – your real address (Option A) or any address (Option B).
2. `Full name:`
3. `Password (at least 12 characters, not shown):` and `Type the password again:` – this is
   your **NetCommand** password (not a MySQL or Gmail password).
4. It emails a six-digit code (Option B: read it from the outbox, step 8.4) and asks
   `Code from the email (or R for a new code):`.

**Expected:**

```
First administrator created: <your address> (user id 1), email address verified.
Sign in from the NetCommand desktop with this email address and password; a sign-in code will be emailed to it.
```

Nothing is written to the database until the code is confirmed. If an active administrator
already exists, the command refuses (that is correct: it is a one-time command). Other team
members' accounts are created from the desktop (*Create account*) and approved by an
administrator on the *Accounts* page.

---

## 13. Start NetCommand and sign in

With the backend running (step 11), in your first PowerShell window:

```powershell
.\venv\Scripts\python.exe main.py
```

1. The **sign-in** window opens. Enter the administrator's email address and password →
   **Sign in**.
2. Enter the six-digit code from the email (or the outbox) → **Verify**.
3. The NetCommand workbench opens on **Overview**. The header shows
   `database connected` and `<your address> · Admin`.

Other start options:

```powershell
.\venv\Scripts\python.exe main.py --demo        # DEMO MODE: no sign-in, sample data in memory
.\venv\Scripts\python.exe main.py --no-monitor  # normal start without background pinging
```

If the window shows **`sample mode · database unavailable at startup`**, the desktop could
not reach its database: see [18.4](#184-desktop-application-errors).

For using NetCommand (scanning, configuring, the Cisco switch demonstration), continue with
**[NETCOMMAND_COMPLETE_GUIDE.md](NETCOMMAND_COMPLETE_GUIDE.md)**.

---

## 14. Run the offline tests

The tests need **no** MySQL, backend, email, network or Cisco device:

```powershell
.\venv\Scripts\python.exe -m pytest -q
```

* Small windows open and close by themselves during the GUI tests: do not click them.
* It takes about 4–8 minutes.

**Expected:** a last line like `1671 passed, 1 skipped, ... warnings in ...s` (the numbers grow
as tests are added). The skipped test is the MySQL integration test, which only runs on
purpose (`NETCOMMAND_TEST_DB=1`) against a disposable `_test` database and **deletes** its
rows: never point it at your real `netcommand` database.

Only the backend tests: `.\venv\Scripts\python.exe -m pytest tests/backend -q`.

---

## 15. Optional: rehearse with the mock lab

The mock lab simulates three Cisco devices on your own computer (`127.0.0.11`–`127.0.0.13`,
port 22). Its logins are fake and only work inside the lab.

```powershell
cd mock-lab
..\venv\Scripts\python.exe -m mocklab check
..\venv\Scripts\python.exe -m mocklab start --background
..\venv\Scripts\python.exe run_netcommand.py
```

* `check` – every lab address can be used. If port 22 is taken (for example by Windows
  *OpenSSH Server*), stop that service or see `mock-lab\README.md`.
* `run_netcommand.py` opens NetCommand in DEMO MODE (memory only). In **Scan**: untick
  *Demo mode*, Seed IP `127.0.0.11`, and the scan login from `mock-lab\lab_config.json`.

Stop the lab afterwards and go back to the project folder:

```powershell
..\venv\Scripts\python.exe -m mocklab stop
cd ..
```

---

## 16. Every day: starting NetCommand

1. MySQL starts with Windows (check: `Get-Service MySQL*` → `Running`).
2. PowerShell window 1 (keep open): `cd C:\Projects\netcommand` then
   `.\venv\Scripts\python.exe -m backend`
3. PowerShell window 2: `cd C:\Projects\netcommand` then `.\venv\Scripts\python.exe main.py`
4. Sign in (password, then the emailed code).

To stop: close NetCommand (this also signs you out), then **Ctrl+C** in the backend window.

---

## 17. Updating to a newer version

```powershell
cd C:\Projects\netcommand
git pull
.\venv\Scripts\python.exe -m pip install -r requirements.txt -r backend\requirements.txt
.\venv\Scripts\python.exe -m backend.database.migrate status
```

If `status` shows a `pending` migration, stop the backend and run
`.\venv\Scripts\python.exe -m backend.database.migrate up --confirm-database netcommand_test`.
Your `.env`, `backend/.env` and databases are never changed by `git pull`.

---

## 18. Troubleshooting

### 18.1 MySQL errors

| You see | Cause | Fix |
|---|---|---|
| **ERROR 1045 (28000): Access denied for user '...'@'...'** (or in NetCommand: `The database refused the application login. Check DB_USER and DB_PASSWORD in .env.`) | Wrong password; or the account was created for `localhost` but you connect to `127.0.0.1` (or the reverse); or the `.env` password differs from the account's | Use `127.0.0.1` everywhere. As root: `SELECT user, host FROM mysql.user WHERE user LIKE 'netcommand%';` – each account must show host `127.0.0.1`. To set a new password (as root): `ALTER USER 'netcommand_app'@'127.0.0.1' IDENTIFIED BY '<new password>';` and put the same password in `.env` (or `backend/.env` for `netcommand_api`). |
| **ERROR 1049 (42000): Unknown database '...'** (NetCommand: `The database named in DB_NAME does not exist on the server.`) | Database not created, or a typo in `DB_NAME` / `BACKEND_DB_NAME` | Step 5.2; check the names (`netcommand`, `netcommand_test`). |
| **ERROR 2003 (HY000): Can't connect to MySQL server on '127.0.0.1:3307'** | MySQL service stopped, or it uses another port | `Get-Service MySQL*` → start it (`Start-Service MySQL84` as administrator; the name may differ). `Test-NetConnection 127.0.0.1 -Port 3307`. If MySQL uses 3306, set `DB_PORT` and `BACKEND_DB_PORT` to 3306. |
| **ERROR 1146: Table 'netcommand_test.users' doesn't exist** while creating `netcommand_api` | Step 10 was run before the migrations | Run step 9 first, then step 10 again. |
| **ERROR 1142: ... command denied to user** | A grant is missing | Repeat the GRANT lines of step 5 or 10; check with `migrate check-runtime-grants`. |
| **ERROR 1396: Operation CREATE USER failed** | The account already exists | Skip `CREATE USER`, or set its password with `ALTER USER` (row 1). |
| `& : The term '...mysql.exe' is not recognized` | Wrong path to the client | Look in `C:\Program Files\MySQL\` and set `$mysql` to the right `bin\mysql.exe`. |

### 18.2 PowerShell problems

| You see | Fix |
|---|---|
| `The '<' operator is reserved for future use.` | Use `--execute="source schema.sql"` (step 6). |
| `... cannot be loaded because running scripts is disabled on this system` (when activating the venv) | Do not activate: use `.\venv\Scripts\python.exe` as in this guide. |
| `python : The term 'python' is not recognized` | Reinstall Python with "Add python.exe to PATH", or use `py -3.10`. |
| `Invoke-RestMethod` / `curl` shows an error page for `/ready` | Use `curl.exe` exactly as in step 11 (PowerShell's `curl` is a different command). |
| A file written with `>` cannot be read by `mysql` | Use `Out-File -Encoding ascii` (step 10.3). |

### 18.3 Backend errors

| You see | Cause | Fix |
|---|---|---|
| `NetCommand backend not started. Invalid backend settings: BACKEND_... ` | A setting in `backend/.env` is missing or invalid (the message names it, never its value) | Fix that line (step 8). |
| `[Errno 10048] error while attempting to bind on address ('127.0.0.1', 8000)` | Port 8000 is used by another program (or a second backend) | Close the other backend; or set `BACKEND_PORT=8001` in `backend/.env` **and** `NETCOMMAND_API_URL=http://127.0.0.1:8001` in `.env`. |
| `/ready` → `database_not_configured` | `BACKEND_DB_ENABLED` is not `true` | Step 8.2. |
| `/ready` → `database_unavailable` | MySQL stopped, or wrong `netcommand_api` password (1045) | `migrate check-runtime-connection`; row 1 of 18.1. |
| `/ready` → `schema_not_ready` | Migrations not run | Step 9. |
| Sign-in: `The code could not be sent. Try again later.`; bootstrap: `Nothing was created. Check the mail settings and try again.` | Email delivery failed | Gmail: 2-Step Verification on, an **app password** (not your Gmail password), port 587, no spaces. The backend window logs the reason (for example *the mail server refused the sender account*). Or use the outbox (Option B). |
| No email arrives | Spam folder; `BACKEND_MAIL_BACKEND=none`; outbox mode (look in the folder) | Check Spam; set the mail option (step 8.4). |
| `An active administrator already exists, so this command is not needed.` | Step 12 was already done | Sign in with that administrator. |
| `migrate`: `Add --confirm-database netcommand_test to change that database` | Safety check | Add the option exactly as shown. |
| `migrate`: `BACKEND_MIGRATE_USER and BACKEND_DB_USER must be different accounts` | Same account in both settings | `netcommand_migrator` vs `netcommand_api` (step 8.2). |

### 18.4 Desktop application errors

| You see | Cause | Fix |
|---|---|---|
| `The NetCommand server could not be reached. Check that it is running.` | Backend not started, or another port | Step 11; `NETCOMMAND_API_URL` must match `BACKEND_PORT`. |
| `NETCOMMAND_API_URL must use https:// for a server on another computer ...` | The URL points to another computer | Use `http://127.0.0.1:8000` (each member runs their own backend). |
| Header `sample mode · database unavailable at startup` | The desktop could not use `netcommand` | Check MySQL (18.1), `DB_*` in `.env`, then restart NetCommand. |
| `Encryption key problem` | `FERNET_KEY` missing or invalid | `.\venv\Scripts\python.exe security.py --check`; if missing, `--new-key`. |
| `This account cannot sign in: it is waiting for email verification or administrator approval, or it has been disabled.` | New account not yet approved | An administrator approves it on the *Accounts* page. |
| `The email address or password is incorrect, or the account is locked.` | Wrong password, or 5 failures (locked 15 minutes) | Check; wait 15 minutes. |

### 18.5 Tests and mock lab

| You see | Fix |
|---|---|
| `ERROR collecting tests/test_mock_lab.py` ... `lab_config.json` | Your copy is older than the fix that added `mock-lab/lab_config.json` to Git: `git pull`. |
| Mock lab: an address or port 22 is in use | Stop Windows *OpenSSH Server* (`Get-Service sshd`), or see `mock-lab\README.md`. |
| GUI tests skipped with `no display available` | Run the tests in a normal, unlocked Windows session. |

---

## 19. Quick reference

| What | Command (from the project folder) |
|---|---|
| Install packages | `.\venv\Scripts\python.exe -m pip install -r requirements.txt -r backend\requirements.txt` |
| New desktop key / check | `.\venv\Scripts\python.exe security.py --new-key` / `--check` |
| Migration state | `.\venv\Scripts\python.exe -m backend.database.migrate status` |
| Apply migrations | `.\venv\Scripts\python.exe -m backend.database.migrate up --confirm-database netcommand_test` |
| Check runtime account | `.\venv\Scripts\python.exe -m backend.database.migrate check-runtime-grants` |
| Readiness check | `.\venv\Scripts\python.exe -m backend.database.migrate check-runtime-connection` |
| Start backend | `.\venv\Scripts\python.exe -m backend` |
| Backend health | `curl.exe -s http://127.0.0.1:8000/health` |
| First administrator | `.\venv\Scripts\python.exe -m backend.auth.bootstrap_admin` |
| Start NetCommand | `.\venv\Scripts\python.exe main.py` (`--demo`, `--no-monitor`) |
| Tests | `.\venv\Scripts\python.exe -m pytest -q` |

**Never commit:** `.env`, `backend/.env`, `venv/`, `backups/`, `mock-lab/keys/`,
`mock-lab/state/`, `mock-lab/backups/`, `*.log`, `*.eml`, `audit_triggers.sql`, database
dumps. These are already in `.gitignore`; before every commit, check `git status` anyway.

More: [README.md](../README.md) · [backend/README.md](../backend/README.md) ·
[NETCOMMAND_COMPLETE_GUIDE.md](NETCOMMAND_COMPLETE_GUIDE.md) · [mock-lab/README.md](../mock-lab/README.md)
