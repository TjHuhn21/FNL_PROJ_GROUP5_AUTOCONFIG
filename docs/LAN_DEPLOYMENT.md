# NetCommand on the local network (Phase B: HTTPS between laptops)

This guide connects **Laptop 2** (a client) to the NetCommand backend running on
**Laptop 1** (the server), over a phone hotspot or any local network, with HTTPS.

**What Phase B covers.** Only the connection to the backend: signing in, the session, and
account administration travel over HTTPS between the laptops. Device records, topology,
findings, logs and saved device logins are **not** shared through the backend yet (later
phases). Until then, a desktop that cannot reach a NetCommand database itself starts in
*sample mode* (clearly labelled). MySQL stays private on Laptop 1: **do not** open port 3307
to the network to work around this.

Local development does not change: with no settings, the backend still listens on
`http://127.0.0.1:8000` (this computer only) and the desktop still uses that address.

## How the connection is secured

* **HTTPS only for other computers.** The backend refuses to listen on anything but a
  loopback address unless `BACKEND_LAN_MODE=true`, and LAN mode refuses to start without a
  certificate and key. Plain HTTP is never offered to the network. The desktop accepts
  `http://` only for `127.0.0.1` / `localhost`, and never retries an `https://` address over
  `http://`. Both sides require TLS 1.2 or newer.
* **A self-signed certificate, pinned.** `python -m backend.tls_cert` makes `server.crt`
  (public) and `server.key` (secret). Each client is given `server.crt` and trusts **only
  that certificate** (`NETCOMMAND_API_CA_FILE`): not the Windows certificate store, not any
  other certificate. Certificate and host-name verification are always on.
* **The private key never leaves Laptop 1.** It is not in Git (`backend/tls/`, `*.key` and
  `*.pem` are ignored), not in any client package, not in an API response and not in a log.
  The desktop even refuses a trust file that contains a private key.

## The changing hotspot address

A phone hotspot (here a Tecno POVA 5 Pro 5G) gives Laptop 1 an address by DHCP, and it can
change; most phone hotspots offer neither address reservations nor a local DNS server.

The solution: **clients use a NAME, not an address**, and the certificate is made for that
name. The name is checked on every connection (normal HTTPS host-name verification). Only
the name -> address mapping changes when the hotspot changes the address, and that mapping
is local to each client:

1. **Recommended: `NETCOMMAND_API_ADDRESS`** in Laptop 2's `.env`, set to Laptop 1's current
   IPv4 address. The desktop connects to that address but still sends and verifies the
   name from `NETCOMMAND_API_URL` (`netcommand-server`), so a different machine at that
   address is rejected. No administrator rights needed; edit one line when the address
   changes.
2. **Alternative: the hosts file** (`C:\Windows\System32\drivers\etc\hosts`, needs an
   administrator Notepad): `10.167.221.171  netcommand-server`. Then leave
   `NETCOMMAND_API_ADDRESS` empty. Update the line when the address changes.
3. **Laptop 1's Windows computer name** may resolve by itself (LLMNR / mDNS) on some
   networks. Many hotspots block that multicast traffic, so do not rely on it; if you want
   to try it, include the computer name when making the certificate (`--name LAPTOP1`).

**Never** connect to `https://<IP address>:8443` instead: the certificate is deliberately
made for names (plus `127.0.0.1` for Laptop 1 itself), so a bare IP address fails
verification. That is correct behaviour, not something to switch off.

When the address changes, **nothing needs re-pinning**: the certificate stays valid for
the name. Re-pinning (copying a new `server.crt`) is only needed if the certificate is
remade (`--force`), lost, or expires (after 825 days by default).

## Laptop 1 (server): one-time setup

All commands in PowerShell, from the project folder.

1. **Make the certificate** (once):

   ```powershell
   .\venv\Scripts\python.exe -m backend.tls_cert --name netcommand-server
   ```

   It writes `backend\tls\server.crt` and `backend\tls\server.key` and prints the
   certificate's SHA-256 fingerprint. Keep `server.key` on this laptop only. It refuses to
   overwrite existing files unless you add `--force` (then every client needs the new
   `server.crt`).

2. **Configure the backend** in `backend\.env` (not committed; placeholders are in
   `backend\.env.example`):

   ```
   BACKEND_HOST=0.0.0.0
   BACKEND_PORT=8443
   BACKEND_LAN_MODE=true
   BACKEND_TLS_CERT_FILE=backend\tls\server.crt
   BACKEND_TLS_KEY_FILE=backend\tls\server.key
   ```

   (Relative paths are resolved from the folder you start the backend in; absolute paths
   work too.)

3. **Allow TCP 8443 in Windows Firewall, Private networks only.** NetCommand does not change
   firewall settings itself. In an administrator PowerShell:

   ```powershell
   New-NetFirewallRule -DisplayName "NetCommand backend (HTTPS 8443, LAN)" `
     -Direction Inbound -Protocol TCP -LocalPort 8443 -Action Allow `
     -Profile Private -RemoteAddress LocalSubnet
   ```

   Windows often classifies a phone hotspot as **Public**. Set it to Private (Settings >
   Network & internet > Wi-Fi > the hotspot > Network profile type: Private), otherwise the
   rule does not apply. If Windows asks whether Python may use the network the first time
   the backend starts, allow **Private** networks only. **Do not** add any rule for MySQL
   (3307); MySQL should also be configured with `bind-address=127.0.0.1` (its own `my.ini`),
   so it never listens on the network.

4. **Start the backend:**

   ```powershell
   .\venv\Scripts\python.exe -m backend
   ```

   The start-up line shows `bind=0.0.0.0:8443 scheme=https lan_mode=on` (never a path or a
   key). Check it from Laptop 1:

   ```powershell
   .\venv\Scripts\python.exe -c "from desktop_auth.api_client import AuthApiClient as C; print(C('https://localhost:8443', ca_file='backend/tls/server.crt').health())"
   # True
   ```

5. **Laptop 1's own desktop** uses the same backend over HTTPS (LAN mode has one HTTPS
   listener). In the project `.env`:

   ```
   NETCOMMAND_API_URL=https://localhost:8443
   NETCOMMAND_API_CA_FILE=backend\tls\server.crt
   ```

   Then start the desktop as usual: `.\venv\Scripts\python.exe main.py`.

6. **Find Laptop 1's current address** (to give to Laptop 2):

   ```powershell
   Get-NetIPAddress -AddressFamily IPv4 | Where-Object InterfaceAlias -like '*Wi-Fi*' |
     Select-Object IPAddress
   ```

## Laptop 2 (client): setup

1. **Copy `server.crt`** (only that file) from Laptop 1, for example with a USB stick, into
   Laptop 2's project folder, e.g. `certs\server.crt`. Check the fingerprint matches the one
   Laptop 1 printed:

   ```powershell
   .\venv\Scripts\python.exe -c "from backend.tls_cert import fingerprint; print(fingerprint(open('certs/server.crt','rb').read()))"
   ```

2. **Configure the client** in Laptop 2's `.env`:

   ```
   NETCOMMAND_API_URL=https://netcommand-server:8443
   NETCOMMAND_API_CA_FILE=certs\server.crt
   NETCOMMAND_API_ADDRESS=10.167.221.171
   ```

   (Use Laptop 1's current address. Or leave `NETCOMMAND_API_ADDRESS` empty and use the hosts
   file instead, see above.)

3. **Test the connection**, then start NetCommand:

   ```powershell
   Test-NetConnection 10.167.221.171 -Port 8443        # TcpTestSucceeded : True
   .\venv\Scripts\python.exe -c "from desktop_auth.api_client import client_from_environment as c; print(c().health())"
   # True  (uses exactly the .env settings above)
   .\venv\Scripts\python.exe main.py
   ```

## When the hotspot gives Laptop 1 a new address

1. On Laptop 1, read the new address (step 6 above). The backend keeps running (it listens
   on all interfaces).
2. On Laptop 2, change `NETCOMMAND_API_ADDRESS` (or the hosts-file line) and restart the
   desktop. Nothing else changes; the certificate stays valid.

## Error messages on the client

| Message starts with | Meaning |
|---|---|
| `NETCOMMAND_API_URL uses https://, so NETCOMMAND_API_CA_FILE must name...` | the trust file is not configured |
| `The certificate file named by NETCOMMAND_API_CA_FILE was not found.` | wrong path |
| `... contains a PRIVATE KEY` | the server key was copied by mistake: delete it from Laptop 2 |
| `The NetCommand server refused the connection...` | backend not running, wrong port, or the firewall blocks 8443 |
| `The NetCommand server did not answer in time...` | network problem, Public profile, or the hotspot isolates its clients |
| `The NetCommand server name could not be found...` | set `NETCOMMAND_API_ADDRESS` or the hosts file |
| `The NetCommand server's certificate is not the trusted one...` | a different certificate (remade, or another machine): copy the current `server.crt` and compare fingerprints |
| `The NetCommand server's certificate is not valid for the server name...` | the URL uses a name (or IP) the certificate was not made for |
| `A secure (HTTPS) connection ... could not be set up.` | the port does not speak HTTPS (wrong port, or LAN mode not on) |
| sign-in errors (wrong password, code, approval) | the backend's normal messages; nothing changed |

None of them contains a password, code, token, file path or key.

## Local development (unchanged)

```powershell
.\venv\Scripts\python.exe -m backend        # http://127.0.0.1:8000, this computer only
.\venv\Scripts\python.exe main.py           # signs in at http://127.0.0.1:8000
.\venv\Scripts\python.exe main.py --demo    # sample data, no sign-in
```

Direct MySQL developer mode is unchanged: the desktop still uses its own `DB_*` settings and
`db.py` (or `db_fake.py` in demo mode).

## Limitations

* **Sharing records is a later phase.** Phase B secures sign-in and administration only;
  see "What Phase B covers" above.
* **Hotspot client isolation.** Some phone hotspots stop connected devices from talking to
  each other. Then nothing on the laptops can fix it; use another network (for example a
  small router), still with HTTPS.
* **No revocation.** If `server.key` leaks, make a new certificate with `--force` and give
  every client the new `server.crt`; the old one simply stops being trusted.
* **Key protection relies on Windows file permissions** of the user profile; the key is not
  password-protected (the backend starts unattended).
* **API documentation** (`/docs`) is served in `development` and `test` environments; on a
  shared network consider `BACKEND_ENV=production` once the production database is set up.
* Tested with loopback test certificates only; the hotspot itself has not been tested yet.
