# NetCommand backend (Phase 4B skeleton)

The future server for NetCommand: desktop clients → HTTPS → this FastAPI backend → MySQL.
Phase 4B contains only the skeleton: settings, safe logging, and `GET /health`.
There is **no** database access, login, email, or HTTPS yet.

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

## Logging

All log lines pass through a redacting formatter (`backend/logging_config.py`):
passwords, tokens, OTP codes, keys, Authorization headers, Fernet tokens and the exact
values of secret settings are replaced with `[REDACTED]`. Request bodies are never
logged. Validation errors (HTTP 422) do not echo submitted values back.

## Tests

```powershell
.\venv\Scripts\python.exe -m pytest tests/backend -q
```

They need no database, network or `.env` file.
