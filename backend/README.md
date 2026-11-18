# NetCommand backend

The future server for NetCommand: desktop clients → HTTPS → this FastAPI backend → MySQL.
So far it has: settings, safe logging, `GET /health` (liveness), `GET /ready` (read-only
database readiness), versioned migrations for the authentication tables (run only by an
operator, never on startup), audit-log protection and least-privilege accounts.
There is **no** login, email, or HTTPS yet: no endpoint reads or writes account data.

## Install

The backend uses the project's existing virtual environment. Pinned versions:

```powershell
.\venv\Scripts\python.exe -m pip install -r backend\requirements.txt
```

## Settings

* The backend reads **only** `backend/.env` (or the file named by the
  `NETCOMMAND_BACKEND_ENV_FILE` environment variable) and `BACKEND_*` environment
  variables. Environment variables override the file.
* The desktop application's `.env` (`DB_*`, `FERNET_KEY`) is **never** used.
* Copy `backend/.env.example` to `backend/.env` (git-ignored) only when real values are
  needed. For the health endpoint, no file is needed at all.
* Database and SMTP settings are checked only when `BACKEND_DB_ENABLED` /
  `BACKEND_SMTP_ENABLED` is `true`. `BACKEND_FERNET_KEY` and `BACKEND_OTP_PEPPER` are
  checked only when set.
* Invalid settings stop the backend with a message that names the setting, never its
  value.

## Start (local development)

From the project folder:

```powershell
.\venv\Scripts\python.exe -m backend
```

It listens on `http://127.0.0.1:8000` (plain HTTP, this computer only, until the HTTPS
phase). Check it:

```powershell
Invoke-RestMethod http://127.0.0.1:8000/health      # -> status: ok
```

Interactive API docs are at `/docs` in `development`/`test`, and switched off when
`BACKEND_ENV=production`.

## Database readiness

* `GET /health` is **liveness only**: it answers while the process runs and never touches
  the database.
* `GET /ready` is **readiness**: it connects with the runtime account (`BACKEND_DB_USER`)
  and, with `SELECT` statements only, checks `SELECT 1`, that every migration this code
  knows is recorded in `schema_migrations` with the same name and checksum, and that the
  four authentication tables exist. `200 {"status": "ready"}`, or
  `503 {"status": "not_ready", "reason": ...}` with one of `database_not_configured`,
  `database_unavailable`, `schema_not_ready`. The response never contains passwords, hosts,
  SQL or driver messages; the server log has the reason (and for a connection problem only
  the error class and MySQL error number). It never runs migrations.
* The same check from the command line (exit code 0 = ready, 6 = not ready):

  ```powershell
  .\venv\Scripts\python.exe -m backend.database.migrate check-runtime-connection
  ```

* Calling `GET /ready` from Windows PowerShell: `Invoke-RestMethod` treats the `503`
  answer as an error and throws, so catch it to see the status and reason:

  ```powershell
  try {
      Invoke-RestMethod http://127.0.0.1:8000/ready      # 200 -> status: ready
  } catch {
      # 503 -> HTTP 503 {"status":"not_ready","reason":"database_unavailable"} (or another reason)
      "HTTP $([int]$_.Exception.Response.StatusCode) $($_.ErrorDetails.Message)"
  }
  ```

  Or use `curl.exe` (built into Windows 10 and later; plain `curl` is an alias for
  `Invoke-WebRequest` in Windows PowerShell), which prints the body for both answers:

  ```powershell
  curl.exe -s -w " HTTP %{http_code}`n" http://127.0.0.1:8000/ready
  ```

**Configuring `backend/.env`** (git-ignored; never commit it): copy `backend/.env.example`
to `backend/.env` and set `BACKEND_DB_ENABLED=true`, `BACKEND_DB_HOST=127.0.0.1`,
`BACKEND_DB_PORT=3307`, `BACKEND_DB_NAME=netcommand_test`, `BACKEND_DB_USER=netcommand_api`
and `BACKEND_MIGRATE_USER=netcommand_migrator`. Type the runtime password into the file
yourself, in **single quotes** (`BACKEND_DB_PASSWORD='...'`): the file is read with
python-dotenv, which would change an unquoted or double-quoted value containing `${...}`
and can cut one at ` #`. Leave `BACKEND_MIGRATE_PASSWORD` empty so migrations ask for it.

## Logging

All log lines pass through a redacting formatter (`backend/logging_config.py`):
passwords, tokens, OTP codes, keys, Authorization headers, Fernet tokens and the exact
values of secret settings are replaced with `[REDACTED]`. Request bodies are never
logged. Validation errors (HTTP 422) do not echo submitted values back.

## Database migrations (Phase 4C)

The backend's own tables (`users`, `email_challenges`, `sessions`, `audit_log`, plus the
bookkeeping table `schema_migrations`) are created by versioned migrations in
`backend/database/`. They are **never** run when the backend starts, and they never touch
the five application tables (`devices`, `links`, `findings`, `status_events`,
`config_logs`).

```powershell
.\venv\Scripts\python.exe -m backend.database.migrate plan                  # SQL only, no connection
.\venv\Scripts\python.exe -m backend.database.migrate audit-triggers-sql    # admin SQL, no connection
.\venv\Scripts\python.exe -m backend.database.migrate status                # read-only
.\venv\Scripts\python.exe -m backend.database.migrate up --dry-run          # read-only check
.\venv\Scripts\python.exe -m backend.database.migrate up --confirm-database netcommand_test
.\venv\Scripts\python.exe -m backend.database.migrate check-runtime-grants  # read-only
.\venv\Scripts\python.exe -m backend.database.migrate check-runtime-connection  # read-only
.\venv\Scripts\python.exe -m backend.database.migrate recommended-grants    # SQL only, no connection
.\venv\Scripts\python.exe -m backend.database.migrate audit-purge-sql       # admin SQL, no connection
.\venv\Scripts\python.exe -m backend.database.migrate down --to 0 --confirm-database netcommand_test
```

* **Target database:** names ending in `_test` are allowed. Any other name needs
  `--authorize-database NAME`; the main database `netcommand` also needs
  `--allow-main-database` (not approved yet: back it up first). Changes also need
  `--confirm-database NAME`.
* **Accounts:** migrations use the **migration** account `BACKEND_MIGRATE_USER`
  (password from `BACKEND_MIGRATE_PASSWORD`, or asked for without echo). The web backend
  uses the **runtime** account `BACKEND_DB_USER`. They must be different accounts (grants below).
* **Not one transaction:** MySQL commits every `CREATE`/`DROP` immediately. If a
  statement fails, the message says how far it got; if the connection was lost, MySQL may
  or may not have completed that statement, so run `status`. `down --partial 1` removes
  migration 1's own **empty** tables. If a rollback is interrupted, run the same `down`
  again: it finishes it.
* **Stop the backend before `down`.** The tables are write-locked (`LOCK TABLES ... WRITE`)
  while they are checked and dropped, so no row can be written in between; a running
  backend would wait or fail. `down` refuses tables holding data
  (`--allow-data-loss`). It never drops `audit_log`: see *Rolling back* below.
* **Exit codes:** 0 ok, 1 inconsistent state, 2 refused/failed, 3 status ok but
  `audit_log` NOT confirmed protected, 4 runtime grants unsafe, 5 runtime grants
  missing, 6 runtime connection not ready, 130 interrupted.

### Audit log protection

Audit history is protected in three layers. Each stops different things:

| Layer | Stops | Does NOT stop |
|---|---|---|
| **Runtime account grants** (main protection) | the backend updating, deleting, dropping, truncating or altering `audit_log`, and managing its triggers | an administrator account |
| **Triggers** (second layer, installed by an administrator) | `UPDATE` of any audit row; `DELETE` of a row younger than one year | `DROP TABLE`, `TRUNCATE`, `ALTER TABLE` |
| **Migration account grants** (no `DROP` on `audit_log`) | the migration tool, or anyone holding its credentials, dropping or truncating `audit_log` | an administrator account |

Triggers do not stop DROP TABLE, TRUNCATE or ALTER TABLE: only the grants below do.

**Installing the triggers (administrator step).** With binary logging on (the MySQL 8.4
default), creating a trigger needs SUPER-level privilege unless
`log_bin_trust_function_creators` is ON. The migration account is not given that and the
server setting is not changed, so migration 1 creates the tables only, and an
administrator installs the two triggers once, from the project folder in Windows
PowerShell:

1. **Configure the `BACKEND_*` settings first**, in the same PowerShell window. The SQL is
   generated for `BACKEND_DB_NAME`, and the command stops if the settings are missing or
   invalid. Required: `BACKEND_DB_ENABLED=true`, `BACKEND_DB_HOST`, `BACKEND_DB_PORT`,
   `BACKEND_DB_NAME` (for example `netcommand_test`), `BACKEND_DB_USER` and
   `BACKEND_DB_PASSWORD`. Generating the SQL never connects, so `BACKEND_DB_PASSWORD` may
   be a non-secret placeholder here. If `BACKEND_MIGRATE_USER` is set, it must differ from
   `BACKEND_DB_USER`.
2. **Generate the SQL as an ASCII file.** Do not use `>`: in Windows PowerShell it writes
   UTF-16, which the `mysql` client cannot read.

   ```powershell
   .\venv\Scripts\python.exe -m backend.database.migrate audit-triggers-sql | Out-File -Encoding ascii .\audit_triggers.sql
   Select-String -Path .\audit_triggers.sql -Pattern '^USE '    # must name the intended database
   ```

3. **Run it with the `mysql` client's `source` command.** PowerShell has no `<` input
   redirection; `source` also understands the script's `DELIMITER` lines and stops at the
   first error. The administrator's password is asked for, never typed on the command line.

   ```powershell
   & 'C:\Program Files\MySQL\MySQL Server 8.4\bin\mysql.exe' --host=127.0.0.1 --port=3307 --user=root -p --execute="source audit_triggers.sql"
   ```

4. **Delete the generated file afterwards.** It contains no secrets, but it should not be
   left behind or committed.

   ```powershell
   Remove-Item .\audit_triggers.sql
   ```

`status` checks `information_schema.TRIGGERS` and reports `audit_log protection:
PROTECTED` only when both triggers are found with the right table, timing, event and body;
otherwise `NOT PROTECTED` or `UNKNOWN` (exit code 3).

**Trigger definer.** The script does not name a `DEFINER`, so MySQL records the
administrator account that runs it as the triggers' definer. Each time a trigger fires,
MySQL checks that definer's privileges, so for as long as the triggers exist the definer
account must:

* keep the `TRIGGER` privilege on `audit_log`;
* keep the `SELECT` privilege on `audit_log`, because the delete trigger reads
  `OLD.created_at`;
* not be dropped (or renamed).

If the definer is dropped or loses either privilege, every `UPDATE`/`DELETE` on
`audit_log` fails (for example error 1449, "The user specified as a definer does not
exist"): audit rows stay protected, but the yearly retention purge fails too. Whether
locking the definer account (`ALTER USER ... ACCOUNT LOCK`) is safe for trigger execution
is NOT verified yet: do not lock it until that has been tested on `netcommand_test`. To
retire that administrator, an administrator first re-creates the two triggers (drop them,
then run `audit-triggers-sql` again) as the account that will own them from then on, and
checks `status` again.

**Retention purge (administrator only).** Audit records are kept for at least one year.
Removing older records is a separate, administrator-controlled operation: the backend
never runs it, and the runtime account has no `DELETE` on `audit_log`. The purge deletes
exactly the rows the delete trigger allows (`created_at <= UTC_TIMESTAMP(6) - INTERVAL 1
YEAR`), so it can never reach a younger row:

```powershell
.\venv\Scripts\python.exe -m backend.database.migrate audit-purge-sql    # prints the SQL only
```

Run it with an administrator account that has `DELETE` on `audit_log` (archive the rows
first if they must be kept elsewhere; the script shows a `mysqldump` example).

### Rolling back: `audit_log` is removed by an administrator

The migration account deliberately has **no `DROP` privilege on `audit_log`**, so neither
the migration tool nor anyone holding its credentials can destroy audit history (`DROP
TABLE` and `TRUNCATE` bypass the triggers; only the missing privilege stops them).

While `audit_log` exists, `down` and `down --partial` stop **before dropping anything**
(no table is changed, the state stays consistent) and say what the administrator must do.
`--allow-audit-history-loss` does not override this.

**Full rollback** (`down --to 0`):

1. Stop the backend.
2. `migrate down --to 0 --confirm-database netcommand_test --dry-run`: stops with the
   message about `audit_log` (and reports whether it holds records).
3. **Administrator:** if `audit_log` holds records, archive them first: they cannot be
   recovered after the drop (for example `mysqldump --single-transaction netcommand_test
   audit_log > audit_log_backup.sql`, or the purge script's archive step). Then
   `DROP TABLE` `` `netcommand_test`.audit_log``, which also removes its triggers.
4. `migrate down --to 0 --confirm-database netcommand_test` again: `status` now shows an
   interrupted rollback (recorded, `audit_log` missing), and `down` drops the remaining
   tables (`sessions`, `email_challenges`, `users`) under the write lock and removes the
   bookkeeping row. If that is interrupted too, run it again.

**Partial migration recovery** (`down --partial 1`, after a failed `up`):

* If the failure happened **before** `audit_log` was created, `down --partial 1` removes
  the tables that were created; no administrator is needed.
* If `audit_log` **was** created (for example only the final bookkeeping step failed),
  `down --partial 1` stops in the same way. A newly created `audit_log` is empty, so the
  administrator drops it (no archive needed; check with `SELECT COUNT(*)` first), then
  `down --partial 1` removes the rest.

### Accounts and least-privilege grants (for the DBA; NOT executed by this project)

Two separate accounts with separate jobs (`migrate` refuses to use the same one for both):

* **Migration account** (`BACKEND_MIGRATE_USER`, used only by `python -m
  backend.database.migrate`): creates and drops the backend tables and keeps
  `schema_migrations`. Table-level grants only, so it cannot touch the application tables.
  It deliberately has no `DROP` on `audit_log` (removing audit history is an administrator
  step, see *Rolling back*).
* **Runtime account** (`BACKEND_DB_USER`, used by the running backend) needs only:
  * `SELECT`, `INSERT`, `UPDATE` on `users`, `email_challenges`, `sessions`;
  * `SELECT`, `INSERT` on `audit_log` (append-only);
  * `SELECT` on `schema_migrations`.

  It must not have: `DELETE` on any table; `UPDATE` on `audit_log`; `DROP`, `ALTER` or
  `TRIGGER` on `audit_log`; database-wide `CREATE`, `DROP`, `ALTER` or `TRIGGER`; or roles
  whose privileges are not reviewed. `check-runtime-grants` reports any such grant
  (exit code 4) and any missing required grant (exit code 5).

The script (also printed by `migrate recommended-grants`, for `netcommand_test`):

```sql
-- NetCommand backend accounts: least privilege. Review, then run as a MySQL
-- administrator. NOT executed by NetCommand. Choose the passwords yourself.

-- 1) MIGRATION account: creates/drops ONLY the backend tables (python -m
--    backend.database.migrate). Never used by the running backend.
CREATE USER 'netcommand_migrator'@'127.0.0.1' IDENTIFIED BY '<chosen by the DBA>';
GRANT SELECT, INSERT, DELETE, CREATE   ON `netcommand_test`.`schema_migrations` TO 'netcommand_migrator'@'127.0.0.1';
GRANT SELECT, CREATE, DROP, REFERENCES ON `netcommand_test`.`users` TO 'netcommand_migrator'@'127.0.0.1';
GRANT SELECT, CREATE, DROP             ON `netcommand_test`.`email_challenges` TO 'netcommand_migrator'@'127.0.0.1';
GRANT SELECT, CREATE, DROP             ON `netcommand_test`.`sessions` TO 'netcommand_migrator'@'127.0.0.1';
GRANT SELECT, CREATE                   ON `netcommand_test`.`audit_log` TO 'netcommand_migrator'@'127.0.0.1';
GRANT LOCK TABLES ON `netcommand\_test`.* TO 'netcommand_migrator'@'127.0.0.1';  -- only works on tables it can SELECT
-- Optional: lets `migrate status` VERIFY the audit triggers. It also lets this
-- account drop them; leave it out to verify as an administrator instead.
-- GRANT TRIGGER ON `netcommand_test`.`audit_log` TO 'netcommand_migrator'@'127.0.0.1';

-- 2) RUNTIME account: what the backend uses. Run AFTER `migrate up` (table
--    grants need the tables). No DELETE anywhere; audit_log is append-only.
CREATE USER 'netcommand_api'@'127.0.0.1' IDENTIFIED BY '<chosen by the DBA>';
GRANT SELECT, INSERT, UPDATE ON `netcommand_test`.`users` TO 'netcommand_api'@'127.0.0.1';
GRANT SELECT, INSERT, UPDATE ON `netcommand_test`.`email_challenges` TO 'netcommand_api'@'127.0.0.1';
GRANT SELECT, INSERT, UPDATE ON `netcommand_test`.`sessions` TO 'netcommand_api'@'127.0.0.1';
GRANT SELECT, INSERT         ON `netcommand_test`.`audit_log` TO 'netcommand_api'@'127.0.0.1';
GRANT SELECT                 ON `netcommand_test`.`schema_migrations` TO 'netcommand_api'@'127.0.0.1';
```

Grant the runtime account its table privileges after `migrate up` (MySQL needs the tables
to exist for table-level grants without `CREATE`).

## Tests

```powershell
.\venv\Scripts\python.exe -m pytest tests/backend -q
```

They need no database, network or `.env` file.
