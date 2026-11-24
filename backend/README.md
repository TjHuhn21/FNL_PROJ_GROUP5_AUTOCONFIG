# NetCommand backend

The FastAPI server behind the desktop's **sign-in and account management**: desktop →
HTTP (this computer only) → this backend → MySQL (`netcommand_test`).

What it does today:

* **Accounts and sign-in:** registration with an emailed verification code, administrator
  approval, two-step sign-in (password, then an emailed six-digit code), sessions, roles
  (viewer, operator, admin) and the admin endpoints used by the desktop's *Accounts* page
  (approve, reject, disable, change role). Passwords are hashed with Argon2id.
* **Email delivery** of the codes through SMTP (for example Gmail), or a development-only
  outbox that writes `.eml` files.
* **Operations:** settings checked at start-up, redacting logs, `GET /health` (liveness),
  `GET /ready` (read-only database readiness), versioned migrations (run only by an
  operator, never on start-up), audit-log protection and least-privilege accounts.
* A command to create the **first administrator** (`python -m backend.auth.bootstrap_admin`).

* **HTTPS for the local network (LAN mode)**, off by default: a self-signed certificate on
  port 8443, pinned by the desktop clients. See **[../docs/LAN_DEPLOYMENT.md](../docs/LAN_DEPLOYMENT.md)**.

Not yet: device operations behind the backend (the desktop still talks to its own
`netcommand` database and to the devices directly).

Installing everything from scratch, step by step: **[../docs/TEAM_INSTALLATION_GUIDE.md](../docs/TEAM_INSTALLATION_GUIDE.md)**.

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

It listens on `http://127.0.0.1:8000` (plain HTTP, this computer only) unless LAN mode is
turned on (HTTPS on port 8443, `docs/LAN_DEPLOYMENT.md`). Check it:

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

## Authentication building blocks (Phase 1)

Pure functions in `backend/auth/`, with no database, email or network access. The
authentication service and API below are built on them.

| Module | What it does |
|---|---|
| `policy.py` | The approved limits, validated: passwords of 12+ characters; lockout after 5 failed passwords for 15 minutes; 6-digit codes valid 5 minutes with 5 attempts; 60 s resend cooldown; sessions of 8 hours with a 30-minute idle timeout. `BACKEND_AUTH_*` settings can only make them stricter. |
| `passwords.py` | Argon2id (argon2-cffi, explicit parameters m=64 MiB, t=3, p=4): hash, verify, parameter check (refuses non-Argon2id and weak hashes), rehash detection, and a dummy check so an unknown email takes as long as a wrong password. |
| `otp.py` | Six-digit email codes from `secrets`, stored only as HMAC-SHA256 keyed with `BACKEND_OTP_PEPPER` and bound to the purpose (`register` or `login`) and the account; compared in constant time. |
| `tokens.py` | 256-bit session tokens (`secrets.token_urlsafe(32)`); only their SHA-256 is stored. |

Account passwords are **hashed** (one-way). They are unrelated to the device passwords
the desktop **encrypts** with `FERNET_KEY` (`security.py`), which are not changed.

## First administrator (Phase 7)

New accounts must be approved by an administrator, so the first one is created with a
local, one-time command (there is no API endpoint for it). From the project folder, with
the backend's runtime database settings in `backend/.env` (`BACKEND_DB_*`) and the
migrations applied:

```powershell
.\venv\Scripts\python.exe -m backend.auth.bootstrap_admin
```

It asks for the email address, full name and password (typed twice, not shown), checks
them with the normal rules (password policy, plain-ASCII email), **emails a six-digit code
to that address and asks for it**, and only then creates an **active admin with a verified
email address**. Nothing is written to the database before the code is confirmed (the code
is kept only in the command's memory). It refuses if an active administrator already exists
(disabled or other inactive admin accounts do not block it, so it can also recover a
database whose only admin was disabled; they are left unchanged). Two runs at the same time
cannot both succeed: a per-database `GET_LOCK` is held until after the commit, the active
admins are re-read with `SELECT ... FOR UPDATE`, and the account and its
`user.bootstrap_admin` audit record are one transaction. It never prints the password, its
hash, the code or any setting's secret value. Email delivery (`BACKEND_MAIL_BACKEND`) must
work before it is run.

Database names follow the migration rules: `*_test` is allowed; any other name needs
`--authorize-database NAME`, and the main `netcommand` database also
`--allow-main-database`. Exit codes: 0 done, 1 refused, 2 invalid input, 3 settings,
database or email unavailable, 4 email code not confirmed (nothing created or changed),
130 cancelled. The new administrator then signs in from the desktop (password, then the
emailed sign-in code).

### Every account verifies its email address

No account can be active, wait for approval, sign in or keep a session until its email
address has been verified with an emailed one-time code: registration does it with the
registration code, the first administrator with the bootstrap command's code. Approving,
re-activating (`set_status`) and creating accounts all refuse unverified addresses, and
sign-in and session checks require `email_verified_at` (an active but unverified account
gets `403 account_not_active`).

An administrator created **before** this rule (by the earlier bootstrap command) has no
verified address and therefore cannot sign in until it is verified, once, with:

```powershell
.\venv\Scripts\python.exe -m backend.auth.bootstrap_admin verify-existing
```

It asks for the administrator's email address (no password), emails a code to it and,
after the right code, records the verification time. Nothing else about the account
changes (id, password, role, status and history are kept); it only works for an active
admin whose address is not yet verified, and it is audited (`auth.email_verified`).
(A database CHECK constraint enforcing the rule is planned as a later migration.)

## Authentication API (Phase 5)

`backend/api/auth_routes.py`: a thin HTTP layer over `AuthService` (all rules live there).

| Endpoint | Success | Notes |
|---|---|---|
| `POST /auth/register` | 202 | `{email, full_name, password}`; same answer for any address |
| `POST /auth/register/verify` | 200 | `{challenge_id, code}` → `{"status": "pending_approval"}` |
| `POST /auth/register/resend` | 202 | `{email}`; same answer for any address |
| `POST /auth/login` | 202 | `{email, password}` → a login code is emailed; **no session yet** |
| `POST /auth/login/verify` | 200 | `{challenge_id, code}` → `{token, token_type: "bearer", ...}` (the only response with a token) |
| `POST /auth/login/resend` | 202 | `{challenge_id}` of the open login challenge |
| `POST /auth/logout` | 204 | `Authorization: Bearer <token>` |
| `GET /auth/session` | 200 | `Authorization: Bearer <token>` → `{user_id, role, session_id}` |
| `GET /admin/users?status=&limit=&after_id=` | 200 | admin only |
| `POST /admin/users/{id}/approve` | 200 | admin only; optional `{role}`; 409 if not pending approval |
| `POST /admin/users/{id}/reject` | 200 | admin only |
| `POST /admin/users/{id}/disable` | 200 | admin only; ends the account's sessions |
| `POST /admin/users/{id}/role` | 200 | admin only; `{"role": "viewer"\|"operator"\|"admin"}` → `{user_id, previous_role, role, sessions_ended}`; never one's own role (400), never the last active admin (400), 409 if unchanged; the account is signed out everywhere and signs in again with the new role; audited as `user.role_changed` (acting admin, target, `role old -> new`) |

* **Tokens** only in the `Authorization: Bearer` header, never in URLs; every response is
  `Cache-Control: no-store`.
* **Errors** are `{"detail": <fixed message>, "error": <code>}`: 400 `invalid_request` /
  `code_invalid`, 401 `login_failed` / `not_authenticated`, 403 `account_not_active` /
  `not_permitted`, 409 `no_change`, 413 `too_large`, 422 malformed body (values are never
  echoed), 429 `rate_limited` (with `Retry-After`), 503 `delivery_failed` / `unavailable`
  (database, mail or settings problems; details only in the server log, as a class name).
  Unknown address, wrong password and locked account all give the same 401.
* **Bodies:** JSON only, unknown fields refused, every string length-capped, at most 8 KiB.
* **Roles:** reusable dependencies `current_session`, `require_roles(...)`,
  `require_admin`, `require_operator` (operator or admin) and `require_viewer`.
* The service is built on the **first** `/auth` or `/admin` request: creating the app,
  `/health`, `/ready` and `/docs` never connect for it. Without database settings,
  `BACKEND_OTP_PEPPER` and a mail backend, these routes answer 503.
* An optional `X-NetCommand-Workstation` header names the workstation in the audit log
  and the login email.
* **Run ONE backend process.** The request limits (per IP for these routes, and the
  service's per-address and per-IP limits) are kept in that process's memory.
  `python -m backend` runs one process; do not start uvicorn with `--workers`. Several
  processes would each count separately (the database-side lockout, resend cooldown and
  hourly code limit would still hold).

## Authentication service (Phase 4)

`backend/auth/service.py` (`AuthService`) joins the pieces above; the API endpoints
(Authentication API, above) are a thin layer over it.

* **Registration:** `register()` creates a `pending_verification` account and emails a
  registration code; `verify_registration()` moves it to `pending_approval`; an admin then
  approves it. A taken address gets the same answer (a challenge id that can never be
  verified) and no email, so registration never reveals which addresses exist.
* **Login:** `login()` counts the attempt (lockout) **before** checking the password, uses a
  dummy Argon2id check for unknown or locked accounts, and for an active account emails a
  login code. **No session yet.** `verify_login()` checks the login code and only then
  creates the session; the raw token is returned once, only its SHA-256 is stored.
* **Codes:** registration and login codes never mix. Each code allows 5 checks (reserved
  before checking, so parallel guesses gain nothing), expires after 5 minutes, works once,
  at most one per 60 s and 5 per hour per account. A code that could not be emailed is
  voided. Login codes can be resent only with the open login challenge.
* **Sessions:** 8 hours at most, ended after 30 minutes without activity, on logout, and
  when the account is disabled (`disable_account()` also cancels open codes).
* **Rate limits** (in memory, per process) are keyed on the address and IP the client
  sent, so unknown addresses are limited exactly like registered ones.
* Every security event goes to `audit_log`; passwords, codes, tokens and hashes never do.

## Lockout after failed device logins (migration 5)

When the desktop's Scan or Configure page fails to log in to a network device (the device
rejected the username or password, or did not answer), it reports this with
`POST /security/device-login`; the server counts it against the **signed-in NetCommand
account**. The limits are in one place, `backend/auth/device_lockout.py`:

| Setting | Value |
|---|---|
| `MAX_FAILED_DEVICE_LOGINS` | 5 failures ... |
| `FAILED_WINDOW_MINUTES` | ... within 10 minutes lock the account |
| `LOCKOUT_MINUTES` | for 15 minutes (it expires by itself) |
| `MAX_LOCKOUTS_BEFORE_PERMANENT` | the 3rd lockout ... |
| `LOCKOUT_COUNT_WINDOW_HOURS` | ... within 24 hours is permanent (admin unlock only) |

* A successful device login sets the count back to 0. Demo mode reports nothing.
* A lock ends every session of the account at once; a locked account cannot sign in, even
  with a correct email code (checked after the correct password, and no code is sent).
* State: `security_device_login_state` (the count, `locked_until`, `permanent_locked_at`);
  history: `security_lockouts` (append-only). The `users` table is unchanged; a permanent
  lock is shown as status `locked_by_security` on the desktop's Accounts page.
* An administrator unlocks with `POST /admin/users/{id}/unlock` (the Accounts page's
  **Unlock** button): never their own account. It clears the lock and both counts.
* **Recovery** when no administrator can sign in (for example the only admin is locked),
  on the server, from the project folder:

  ```powershell
  .\venv\Scripts\python.exe manage.py lock-status <email>
  .\venv\Scripts\python.exe manage.py unlock-user <email>
  ```

  It uses `backend/.env` (the runtime account), changes nothing else about the account and
  is audited (`security.unlocked`, "recovery command on the server").

## Email delivery of codes (Phase 3)

`backend/mail/` sends the six-digit codes: one message for **registration** (verify your
email address; an admin approves afterwards) and a different one for **login** (finish
signing in; "if this was not you, contact your administrator"). The code is never in the
subject, never logged, never returned and never stored. A code is sent only to the
account's own address, and only when the account may receive it: registration codes to
`pending_verification` accounts, login codes to `active` accounts.

| `BACKEND_MAIL_BACKEND` | What happens |
|---|---|
| `none` (default) | No email can be sent. |
| `outbox` | Development/test only: each message is written to an `.eml` file in `BACKEND_MAIL_OUTBOX_DIR` (default `%TEMP%\netcommand-dev-outbox`, never inside the project folder). Refused when `BACKEND_ENV=production`, both at start-up and on every use. |
| `smtp` | Real email through `BACKEND_SMTP_*` (needs `BACKEND_SMTP_ENABLED=true`). Always encrypted: port 465 uses TLS from the start; other ports must accept STARTTLS before the password is sent. The certificate is verified. |

Failures give a fixed reason (for example "the mail server refused the sender account"),
never the server's reply, the SMTP password or the code. Logs show only the purpose and a
masked address (`a***@example.com`). Codes in the development outbox are readable by
anyone who can open that folder: delete it when you are done.

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

### Production database safety

`netcommand_backend` is the **production** database (`backend/database/production.py`).
On top of the rules above (which are unchanged), every `migrate` command except `plan`, and
`python -m backend.auth.bootstrap_admin`, refuse it unless **all** of these are given:

* `BACKEND_ENV=production` in the settings,
* `--production`,
* `--authorize-database netcommand_backend`,
* `--confirm-database netcommand_backend` (also for read-only commands such as `status`).

`--production` with any other database, and `BACKEND_ENV=production` with any other
database, are refused too. The settings themselves refuse `netcommand_backend` without
`BACKEND_ENV=production`, `BACKEND_ENV=production` with a test or other database, and the
production database without `BACKEND_DB_SERVER_UUID`.

**Identity check.** Right after connecting, and before any other statement, the tools run
one read-only `SELECT DATABASE(), @@server_uuid`: the database must be `BACKEND_DB_NAME`
and the server UUID must be `BACKEND_DB_SERVER_UUID` (the DBA reads it once with
`SELECT @@server_uuid;`). This is a safeguard against reaching the wrong server, port,
tunnel or database; it is **not** authentication or proof of identity. It also runs for any
other database when `BACKEND_DB_SERVER_UUID` is set.

**No rollback on production.** `migrate down` is refused on the production database (with
or without `--allow-data-loss`); a production rollback means restoring a verified backup.
`down --dry-run` stays available. Automated tests never connect to any database.

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
  `schema_migrations`. Table-level grants only, so it cannot touch the desktop database's
  application tables (`devices`, `links`, ...); it can create and drop only the backend's
  own tables, including the shared `app_*` tables of Phase C.
  It deliberately has no `DROP` on `audit_log` (removing audit history is an administrator
  step, see *Rolling back*).
* **Runtime account** (`BACKEND_DB_USER`, used by the running backend) needs only:
  * `SELECT`, `INSERT`, `UPDATE` on `users`, `email_challenges`, `sessions`;
  * `SELECT`, `INSERT` on `audit_log` (append-only);
  * `SELECT` on `schema_migrations`;
  * Phase C shared data (see [docs/PHASE_C_SHARED_DATABASE.md](../docs/PHASE_C_SHARED_DATABASE.md)):
    `SELECT`, `INSERT`, `UPDATE` on `app_devices`, `app_device_credentials`, `app_links`,
    `app_findings`, `app_jobs`, `app_job_devices`, `app_device_locks`; `SELECT`, `INSERT`
    only (append-only) on `app_status_events`, `app_config_logs`, `app_job_events`,
    `app_device_backups`.

  It must not have: `DELETE` on any table; `UPDATE` on the append-only `app_*` tables; `UPDATE` on `audit_log`; `DROP`, `ALTER` or
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
GRANT SELECT, CREATE, DROP, REFERENCES ON `netcommand_test`.`app_devices` TO 'netcommand_migrator'@'127.0.0.1';
GRANT SELECT, CREATE, DROP             ON `netcommand_test`.`app_device_credentials` TO 'netcommand_migrator'@'127.0.0.1';
GRANT SELECT, CREATE, DROP             ON `netcommand_test`.`app_links` TO 'netcommand_migrator'@'127.0.0.1';
GRANT SELECT, CREATE, DROP             ON `netcommand_test`.`app_findings` TO 'netcommand_migrator'@'127.0.0.1';
GRANT SELECT, CREATE, DROP             ON `netcommand_test`.`app_status_events` TO 'netcommand_migrator'@'127.0.0.1';
GRANT SELECT, CREATE, DROP             ON `netcommand_test`.`app_config_logs` TO 'netcommand_migrator'@'127.0.0.1';
GRANT SELECT, CREATE, DROP, REFERENCES ON `netcommand_test`.`app_jobs` TO 'netcommand_migrator'@'127.0.0.1';
GRANT SELECT, CREATE, DROP             ON `netcommand_test`.`app_job_devices` TO 'netcommand_migrator'@'127.0.0.1';
GRANT SELECT, CREATE, DROP             ON `netcommand_test`.`app_job_events` TO 'netcommand_migrator'@'127.0.0.1';
GRANT SELECT, CREATE, DROP             ON `netcommand_test`.`app_device_locks` TO 'netcommand_migrator'@'127.0.0.1';
GRANT SELECT, CREATE, DROP             ON `netcommand_test`.`app_device_backups` TO 'netcommand_migrator'@'127.0.0.1';
GRANT SELECT, CREATE, DROP             ON `netcommand_test`.`security_device_login_state` TO 'netcommand_migrator'@'127.0.0.1';
GRANT SELECT, CREATE, DROP             ON `netcommand_test`.`security_lockouts` TO 'netcommand_migrator'@'127.0.0.1';
GRANT LOCK TABLES ON `netcommand\_test`.* TO 'netcommand_migrator'@'127.0.0.1';  -- only works on tables it can SELECT
-- Optional: lets `migrate status` VERIFY the audit triggers. It also lets this
-- account drop them; leave it out to verify as an administrator instead.
-- GRANT TRIGGER ON `netcommand_test`.`audit_log` TO 'netcommand_migrator'@'127.0.0.1';

-- 2) RUNTIME account: what the backend uses. Run AFTER `migrate up` (table
--    grants need the tables). No DELETE anywhere; audit_log and the app_ event,
--    log and backup tables are append-only.
CREATE USER 'netcommand_api'@'127.0.0.1' IDENTIFIED BY '<chosen by the DBA>';
GRANT SELECT, INSERT, UPDATE ON `netcommand_test`.`users` TO 'netcommand_api'@'127.0.0.1';
GRANT SELECT, INSERT, UPDATE ON `netcommand_test`.`email_challenges` TO 'netcommand_api'@'127.0.0.1';
GRANT SELECT, INSERT, UPDATE ON `netcommand_test`.`sessions` TO 'netcommand_api'@'127.0.0.1';
GRANT SELECT, INSERT         ON `netcommand_test`.`audit_log` TO 'netcommand_api'@'127.0.0.1';
GRANT SELECT                 ON `netcommand_test`.`schema_migrations` TO 'netcommand_api'@'127.0.0.1';
GRANT SELECT, INSERT, UPDATE ON `netcommand_test`.`app_devices` TO 'netcommand_api'@'127.0.0.1';
GRANT SELECT, INSERT, UPDATE ON `netcommand_test`.`app_device_credentials` TO 'netcommand_api'@'127.0.0.1';
GRANT SELECT, INSERT, UPDATE ON `netcommand_test`.`app_links` TO 'netcommand_api'@'127.0.0.1';
GRANT SELECT, INSERT, UPDATE ON `netcommand_test`.`app_findings` TO 'netcommand_api'@'127.0.0.1';
GRANT SELECT, INSERT         ON `netcommand_test`.`app_status_events` TO 'netcommand_api'@'127.0.0.1';
GRANT SELECT, INSERT         ON `netcommand_test`.`app_config_logs` TO 'netcommand_api'@'127.0.0.1';
GRANT SELECT, INSERT, UPDATE ON `netcommand_test`.`app_jobs` TO 'netcommand_api'@'127.0.0.1';
GRANT SELECT, INSERT, UPDATE ON `netcommand_test`.`app_job_devices` TO 'netcommand_api'@'127.0.0.1';
GRANT SELECT, INSERT         ON `netcommand_test`.`app_job_events` TO 'netcommand_api'@'127.0.0.1';
GRANT SELECT, INSERT, UPDATE ON `netcommand_test`.`app_device_locks` TO 'netcommand_api'@'127.0.0.1';
GRANT SELECT, INSERT         ON `netcommand_test`.`app_device_backups` TO 'netcommand_api'@'127.0.0.1';
GRANT SELECT, INSERT, UPDATE ON `netcommand_test`.`security_device_login_state` TO 'netcommand_api'@'127.0.0.1';
GRANT SELECT, INSERT         ON `netcommand_test`.`security_lockouts` TO 'netcommand_api'@'127.0.0.1';
```

Grant the runtime account its table privileges after `migrate up` (MySQL needs the tables
to exist for table-level grants without `CREATE`).

## Tests

```powershell
.\venv\Scripts\python.exe -m pytest tests/backend -q
```

They need no database, network or `.env` file.
