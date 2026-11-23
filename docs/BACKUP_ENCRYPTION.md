# Backup encryption

**Status.** Phase 3A added the encryption engine, the key management and two tools.
**Phase 3B: Configure / Apply now writes every new backup ENCRYPTED** (`.ncbak`); it never
writes a plaintext `.txt` backup any more. Existing `.txt` backups are left exactly as they
are (no migration yet).

**Before the first Apply, create the backup key** (once per Windows account):
`python backup_keys.py init --recovery <offline path>` (see *Commands* below). Without a
usable key, Apply refuses to start: nothing is sent to any device.

## How Apply makes a backup (Phase 3B)

```
backup key -> SSH -> privilege 15 -> show running-config -> check it -> encrypt in memory
  -> write ciphertext to .partial -> flush -> read back -> decrypt -> compare with what the
  device sent -> rename to <ip>_<YYYYMMDD_HHMMSS>[_N].ncbak -> only now: configuration commands
```

* **Preflight, before any SSH session:** the Configure page checks the active key before it
  asks for logins or confirmation; the multi-device run checks it again before the first
  device; and `apply_config` loads it before opening each device's SSH session. Any key
  problem (no keyring, an invalid keyring, another Windows account, DPAPI refused, a
  fingerprint mismatch) stops there: no SSH session is opened and nothing is sent.
* **Fail-closed:** an encryption failure, a write or rename failure, a read-back that differs,
  an authentication failure, or a decrypted copy that differs from the device's
  configuration stops that device before any configuration command. There is **no
  plaintext fallback**. Only ciphertext is ever written; the temporary file is removed on
  failure. The console still shows the first lines of the configuration, masked.
* **Several devices:** each device gets its own encrypted backup, verified before its own
  commands; a failed backup stops only that device, and its result has no backup path.
* **Results:** the console, the result message and the configuration log show the backup
  path (`.ncbak`), the key id (`key_id=b1`) and the configuration's SHA-256 (the same value
  that is in the authenticated header). Read a backup with `backup_tool.py verify` or
  `export` (below).

| File | What it does |
|---|---|
| `backup_crypto.py` | the `.ncbak` format: AES-256-GCM encryption, strict parsing and checks |
| `backup_keys.py` | the DPAPI-protected keyring, recovery files, `init` / `verify-recovery` / `import-recovery` / `rotate` / `status` |
| `backup_tool.py` | `verify` and `export` of a `.ncbak` file |

The backup key is **separate** from `FERNET_KEY` (saved device logins, `security.py`),
which is not touched or used.

## The encrypted backup format (`.ncbak`)

```
"NCBAK" | version (1 byte) | header length (4 bytes, big-endian) | header (JSON) | ciphertext + tag
\__________________ associated data: authenticated, not encrypted _______________/
```

* **AES-256-GCM** (the `cryptography` package), 256-bit key, 96-bit nonce, 128-bit tag.
* **Associated data = the exact bytes** of the magic, version, header length and header
  JSON as they are in the file. The header is parsed only to find the key id and nonce,
  never re-serialised before authentication, so changing any byte of it (or of the
  ciphertext or tag) makes decryption fail ("could not be authenticated").
* **Header fields:** `format` (`ncbak`), `alg`, `key_id`, `nonce`, `created_utc`,
  `plaintext_sha256`, `plaintext_size`, and optional non-secret `host`, `source`,
  `privilege`, `app`. Nothing secret is ever put in the header.
* **Device identity (Phase 4A):** new backups also record `serial` (`show version`,
  "Processor board ID"), `platform` (the model on `show version`'s "cisco ... with ...K
  bytes of memory" line, or its "Model number" line), `ios_version` (the version on the
  IOS line of `show version`) and `hostname` (the running configuration's `hostname` line).
  `show version` is read-only; nothing is configured to obtain these. Each field has three
  states: **absent** = not recorded (backups made before Phase 4A), **`null`** = looked for
  but not shown by the device (or `show version` failed; the Apply goes on), or **a string**
  of at most 64 plain characters (letters, digits and `. _ ( ) / + : -`). Values are never
  guessed. These identity values are in the **authenticated but readable** header, so a
  backup can later be matched to a device without decrypting it; the configuration itself
  stays encrypted. `backup_tool.py verify` shows them ("unavailable" / "not recorded").
* **After decryption** the plaintext's SHA-256 and size are compared with the header.
* **Refused before any decryption:** wrong signature, unknown version, header longer than
  4 KiB or empty, invalid or duplicated JSON fields, wrong types, unknown algorithm, a
  nonce that is not 12 bytes, a ciphertext length that does not match the recorded size,
  files over 16 MiB of plaintext, and truncated files.

### Nonces and key rotation limits

Every encryption takes a **fresh 12-byte nonce from `os.urandom`**. With random 96-bit
nonces, one key must not encrypt more than 2^32 messages (NIST SP 800-38D), after which
the chance of a repeated nonce stops being negligible. NetCommand writes one backup per
device per Apply, so this limit is never approached; as an operating rule, **rotate the
backup key once a year, or after 1,000,000 backups, whichever comes first**, and whenever
a key or recovery file may have been exposed.

## Keys

* Each key is **32 random bytes** (`os.urandom`) with an id `b1`, `b2`, ... and a
  **fingerprint** (HMAC-SHA256 of a fixed label with the key, first 128 bits): it
  identifies a key in output and checks without revealing it.
* The keyring is `%LOCALAPPDATA%\NetCommand\keys\backup-keyring.json`, **outside the
  project folder**; `--keyring` or `NETCOMMAND_BACKUP_KEYRING` choose another path.
* Keys are stored **only** as Windows DPAPI blobs in **user scope** (`CryptProtectData`
  without `CRYPTPROTECT_LOCAL_MACHINE`; `CRYPTPROTECT_UI_FORBIDDEN`), with a fixed,
  non-secret entropy label (`NetCommand backup keyring v1`). Only the same Windows account
  can open them. DPAPI output buffers are freed with `LocalFree`; input copies and the
  decrypted key buffer are zeroed first.
* The keyring is validated strictly (exact fields, format/version, unique valid ids and
  fingerprints, valid blobs, the active key present), written atomically (temporary file,
  flush, read back, rename), and checked again before an update replaces it (a change made
  meanwhile is refused). A malformed or unreadable keyring is **never** replaced
  automatically, and no replacement key is ever generated silently.

## Recovery files (`.ncrecovery`)

DPAPI alone is **not** a recovery plan. These all make the DPAPI blobs unreadable:
reinstalling Windows, losing the Windows profile, moving to another computer, or an
administrator forcing a password reset on a local account. Moving or reinstalling
NetCommand, or moving the project folder, does not (the keyring is not in the project).

So every key gets an offline recovery file when it is created:

```
"NCRCV" | version | header length | header JSON | AES-256-GCM(key) + tag
```

* The wrapping key is derived from a **passphrase** (at least 12 characters, Unicode NFC
  normalised) with **scrypt N = 2^17, r = 8, p = 1** (about 128 MiB of memory, well under a
  second on a laptop) and a **16-byte random salt**; a **random 12-byte nonce**.
* The format, version, KDF name and parameters, salt, nonce, key id and fingerprint are
  in the authenticated header. Because scrypt must run before the passphrase can be
  checked, a recovery file may only ask for what NetCommand itself writes, and this is
  checked **before** scrypt runs: **N a power of two from 2^14 to 2^18** (2^17 by default;
  2^18 is about 256 MiB), **r = 8, p = 1**. Anything else is refused as unsupported.
* The passphrase is **never stored**. There is **no plaintext key export**.
* An existing recovery file is never overwritten without `--confirm-overwrite-recovery`,
  and **never** (even with it) when it is the recovery file of a key that is still in the
  keyring: its key id and fingerprint are read from its header (no passphrase needed) and
  compared with the keyring. A file that is not a recognisable recovery file is never
  replaced either. Use a new path for every key (for example `netcommand-b2.ncrecovery`).
* `init` and `rotate` write the new recovery file under a temporary name next to its final
  path, read it back and decrypt it with the passphrase (the recovered key must match byte
  for byte), and only **after the keyring change has succeeded** give it its final name.
  If the keyring change fails, the keyring and any existing recovery file are unchanged.
  If putting the recovery file in place fails, `rotate` puts the keyring back; in the
  unlikely case that this also fails, the error names the verified temporary recovery file
  so it can be moved to safety.

**Keep each recovery file in two separate offline places (for example two USB drives),
and the passphrase somewhere else (a password manager or a sealed note). If both the
DPAPI keyring and every copy of a key's recovery file are lost, the backups made with that
key can never be decrypted.**

## Commands

```powershell
# First key (b1). Asks for a new passphrase twice.
.\venv\Scripts\python.exe backup_keys.py init --recovery E:\netcommand-b1.ncrecovery

# Show key ids, fingerprints and which one is active (no secrets).
.\venv\Scripts\python.exe backup_keys.py status

# Check a recovery file against the keyring (periodically, and after copying it).
.\venv\Scripts\python.exe backup_keys.py verify-recovery --recovery E:\netcommand-b1.ncrecovery

# New active key b2; b1 and every older key stay, so older backups remain readable.
.\venv\Scripts\python.exe backup_keys.py rotate --recovery E:\netcommand-b2.ncrecovery

# After a Windows reinstall / on a new computer: restore keys into this account's DPAPI.
.\venv\Scripts\python.exe backup_keys.py import-recovery --recovery E:\netcommand-b2.ncrecovery
.\venv\Scripts\python.exe backup_keys.py import-recovery --recovery E:\netcommand-b1.ncrecovery

# Check or export one encrypted backup.
.\venv\Scripts\python.exe backup_tool.py verify  backups\10.0.0.2_20261122_150000.ncbak
.\venv\Scripts\python.exe backup_tool.py export  backups\10.0.0.2_20261122_150000.ncbak --to D:\restore\r1.txt
```

`import-recovery` creates a keyring if there is none, adds a key the keyring lacks, or
re-protects a key this account can no longer open (the fingerprint must match). A
different key with the same id is refused. **The first key imported into an empty (new)
keyring automatically becomes the active key**, the one new backups use; later imports
are added without changing the active key unless `--activate` is given. So after losing
the keyring, import the **newest** key's recovery file first (it becomes active), then the
older ones; or import in any order and finish with `--activate` on the newest.

`export` asks you to type `EXPORT PLAINTEXT` after warning that the output is plaintext;
it decrypts and checks the whole backup first, then writes it to a temporary file
`.ncbak-export.<random>.partial` in the destination folder, flushes it, and only then gives
it the destination name (never over an existing file). If the export fails, that temporary
file is removed; if Windows will not let it be removed (for example an antivirus scanner
holds it), the error shows its **exact path** and asks you to delete it. A **crash or power
loss during the write can leave such a `.partial` file with part of the plaintext**:
delete any `.ncbak-export.*.partial` file you find. Delete exported copies when you no
longer need them.

**Deleting is not erasing.** On SSDs and flash drives (and with file-system snapshots,
cloud sync or backup software), a deleted plaintext file can stay recoverable. Export only
to a location you control, preferably an encrypted drive, and never into a synced or shared
folder or the project's Git working tree.

## Recovery procedure (summary)

| Event | What to do |
|---|---|
| NetCommand reinstalled, project folder moved | nothing (keep `%LOCALAPPDATA%\NetCommand`) |
| Windows reinstalled, profile lost, new computer, forced password reset | `import-recovery` the **newest** key's recovery file first (into the empty keyring it becomes active automatically), then each older one; then `status` and `verify-recovery` |
| A recovery file may be exposed | `rotate` (new key and recovery file); keep the old key only for old backups |
| Periodic check | `verify-recovery` for every key's recovery file |

## Backup catalogue and selection (Phase 4B)

**Devices page -> select a device -> Backups...** (roles with the Configure permission:
operator and admin; viewers cannot open it). The window lists encrypted backups, verifies
them and lets you **select one for a future restore**. Selecting only remembers the choice
for this window session; **nothing is restored and nothing is sent to any device**.

**Where Apply writes.** `config.connect.BACKUP_DIR` is now `<project>\backups` whatever
folder NetCommand is started from (it was the relative `backups`, i.e. the same folder for
the usual start from the project folder). Nothing was moved. (A per-user folder such as
`%LOCALAPPDATA%\NetCommand\backups` would start empty while backups are here, so it is
left as a separate migration decision.)

**Folders searched** (top level only, no subfolders; a folder or file that is a symbolic
link or junction is never followed; each folder once):

1. the folder Apply writes to now (`<project>\backups`, or the Mock Lab launcher's
   `mock-lab\backups`);
2. `<project>\backups`;
3. `<project>\mock-lab\backups`;
4. `backups` in the folder NetCommand was started from (older versions wrote there when
   started elsewhere).

Missing or unreadable folders are shown with the reason. Only `*.ncbak` files are listed
(plaintext `.txt` backups are not opened). Files with the same name in different folders
are both listed with their folder; a byte-identical copy is marked "duplicate copy".

**What is shown:** file name and folder, device IP (`host`), time, source, key id, size,
the configuration SHA-256 (shortened in the list), hostname, platform, serial, IOS version,
the verification status and the match with the selected device. Never the configuration.

**Trust.** The readable header is authenticated but not confidential, and it is **not
trusted until the backup is verified**: until then the window says "NOT yet verified" and
the match is marked "(unverified)". **Verify** decrypts the file **in memory** (AES-GCM
tag, SHA-256 and size), resolves its key id in the keyring (older keys after rotation
included) and checks the configuration with Apply's Cisco IOS check. The decrypted bytes are
never written, printed or kept. Statuses: `Verified`, `Verification unavailable` (no usable
keyring, or the key id is not in it), `Verification failed` (tampered, corrupted, hash or
size mismatch, unusable configuration, or the file changed since it was listed), `Invalid`
(not a valid backup file), `Unreadable`. Verification runs in the background.

**Matching** (backup header vs. the selected device). The device records do not store a
serial number or platform, so for now these are unknown on the device side and no backup
can reach "Serial match" yet (a live read-only identity check belongs to the restore phase).

| Check | Rule |
|---|---|
| Serial | both known and equal: "Serial match"; both known and different: **Identity mismatch, selection blocked**; otherwise unknown (never a match) |
| Platform | both known and equal: "Platform match"; both known and different: **Platform mismatch, blocked** (same vendor is not enough) |
| IP address | different: a visible warning; **without a serial match, a different IP blocks selection** (the approved legacy rule), except for a **pending restore candidate** (below) |
| Hostname | different: a warning; a hostname never proves the hardware |
| No identity fields | "Identity not recorded": never a hardware match |

Missing, `null`, malformed or placeholder values (`unavailable`, `unknown`, `n/a`, ...) are
always "unknown".

**Selection** is possible only for a **Verified** backup (this exact file, checked against
its authenticated header) with no blocking mismatch, and only for the Configure permission.
A backup whose hardware identity is not confirmed by serial can be selected for inspection
but is marked as needing the separate **legacy-backup confirmation** (matching IP and the
typed device name) in the future restore workflow; it is never called restore-ready.

**Pending restore candidates (changed IP).** A device that was readdressed keeps its
serial number, but the device records do not store one, so the catalogue cannot confirm
the hardware. A verified backup whose recorded IP differs from the device's can still be
selected when its authenticated header records **both a real serial number and a real
platform** and nothing known about the device contradicts them. It is shown as
"Candidate: live identity check required (IP differs)" and "PENDING RESTORE CANDIDATE, NOT
a verified match", never as a match or restore-ready (`Selection.live_identity_required`).
Selecting it contacts no device and writes nothing. Backups without a serial or platform
(including all backups made before identity was recorded) keep the old rule: a different
IP blocks selection. Serial and platform mismatches block exactly as before.

## Restore preflight (Phase 4E)

`restore_preflight.py`, tested by `tests/test_restore_preflight.py` (Mock Lab only). There
is still **no restore**: no transfer, no `configure replace`, no rollback timer, no save, no
window. The preflight has two stages, and the user decides between them.

**Stage 1 - `run_checks(selection, creds)`, read-only.**

1. *The selected backup again, offline:* the file still exists, is not a link, has the
   SHA-256 recorded at selection (so its authenticated header, including the identity, is
   unchanged); AES-GCM tag, key id, decrypted SHA-256 and size; Apply's configuration
   check; key id, configuration SHA-256 and creation time equal to the selection. The
   decrypted configuration stays in memory; only facts derived from it are kept.
   A selection made for another device address is refused before connecting.
2. *SSH:* one session through Apply's connection code (strict algorithms). SSH protocol 2
   is confirmed from the transport (a device that also accepts SSH-1, banner `SSH-1.99`,
   is a warning); `show privilege` must report level 15.
3. *Live identity:* `show version`, `show inventory` (when the device knows it) and the
   running configuration. **Serial rules:** every `Processor board ID` and every
   **chassis** serial of `show inventory` is read (module serials are ignored); two
   different values in either source, a disagreement between them, an unreadable value or
   no value at all **blocks**. A chassis is an inventory entry whose name or description
   says "chassis", or a bare stack number ("1", "2"). The platform from `show version` is
   cross-checked with the chassis PID.
4. *Matching:* the Phase 4B rules (`backup_catalogue.match`) with the live serial and
   platform: serial or platform mismatch blocks; hostname difference warns; a different IP
   warns with a serial match and blocks without one; a backup without identity is never a
   hardware match and needs the legacy confirmation. **A backup recorded for another IP
   (including every pending candidate) is blocked unless the live serial AND the live
   platform both match it**; `create_safety_backup` checks this again before connecting.
5. *Capabilities (nothing is configured):* no timed rollback already pending
   (`show archive config rollback timer`); an archive path configured (`show archive`,
   running configuration); `configure replace` supported (probe: the incomplete command
   `configure replace`, which IOS answers with `% Incomplete command.` and cannot execute);
   Tcl (enter `tclsh` and `tclquit` at once, writing nothing) or SCP **already** enabled
   (`ip scp server enable` in the configuration; never enabled by NetCommand); free space
   on `flash:` for the file, an archive copy and 64 KiB; a free temporary name
   `flash:nc-restore-<16 hex>.cfg` (`dir`). No safe transfer or rollback method blocks.
6. *Management access in the backup:* the management address (the address NetCommand uses,
   or `management_ip` for NAT/lab setups) on an interface that is not shut down (removed
   or shut while the device has it now blocks; not on the device at all warns); SSH allowed
   on a VTY line (none blocks; no `transport input` line warns); `login local` without any
   local user blocks; the session's account missing, not privilege 15 without an enable
   secret, AAA, `access-class` or a mixed login method warn.

The session is closed before the result is returned. The result has a status per check
and overall - **PASS**, **WARNING**, **BLOCKED** (a safety rule forbids the restore) or
**FAILED** (something could not be done or checked) - the live identity, the backup's
details (never its content), the capabilities, the chosen transfer method and temporary
name, and the phrase the user must type: `RESTORE <ip>`, or `RESTORE LEGACY <ip>` when
the hardware identity is not confirmed by serial.

**Stage 2 - `create_safety_backup(result, typed, creds)`**, only for a PASS/WARNING result
less than 10 minutes old, for the same device address, with the phrase typed exactly.
Otherwise `ConfirmationRefused` is raised and nothing is done (no connection, no file).
It re-verifies the selected backup, reconnects, re-checks privilege 15 and that the same
chassis (serial and platform) answers, then writes an **encrypted** backup of the current
running configuration with Apply's backup code, labelled `purpose: "pre-restore"` in the
authenticated header and named `<ip>_pre-restore_<YYYYMMDD_HHMMSS>.ncbak`. The file is
read back and decrypted in memory and must equal the configuration the device sent; any
failure stops the workflow. **`cancel(result)`** ends it instead. The device is never
changed by either stage.

## Restore engine (Phase 4F)

`restore_engine.restore(preflight_result, creds, timer_minutes=5)`, tested by
`tests/test_restore_engine.py` against the Mock Lab only. No window, no save to the startup
configuration, nothing enables SCP or configures the archive.

**Before anything is sent** the preflight result must be the one stage 2 sealed (an HMAC
with a key that exists only in the running program; any change, a cancel or a second use
breaks it), for this device, at most 10 minutes after its safety backup, confirmed with the
exact phrase; the timer must be 3-10 minutes (default 5). The selected backup is verified
again (file SHA-256, AES-GCM, key id, plaintext SHA-256 and size, configuration check) and
the safety backup is decrypted and checked (label, address, serial, platform, SHA-256).
Both stay in memory.

**Session A** (strict SSH, protocol 2, privilege 15, the preflight's serial and platform):
no pending rollback, an archive path, the running configuration still equal to the safety
backup, the temporary file absent, enough flash. Then the transfer from memory: Tcl through
Netmiko's `InLineTransfer(source_config=...)` or, when `ip scp server enable` is already
configured, `scp putfo` of an in-memory stream (also used when the text cannot go through
Tcl: curly braces, a trailing backslash or non-ASCII). `verify /md5` must give the MD5 of
exactly the bytes sent; otherwise the file is deleted and nothing is replaced.

**`configure replace flash:<file> list force time <minutes>`**. A question (even with
`force`) is never answered: the session is closed. Rejected lines, "Rollback aborted", an
error line or no "Rollback Done" count as a failed (possibly partial) replacement.

**Session B**, a new connection to the same address (same checks as A): the timer must be
pending and the running configuration must equal the backup. Only then `configure
confirm`; the timer must then read "No Rollback Confirmed Change pending" and the running
configuration is compared once more.

**Comparison rules (the approved Phase 4C design).** Both texts must end with a top-level
`end` line (only blank lines may follow it). Then:

* CRLF and CR line ends become LF; trailing whitespace is removed from every line;
* the header block before the first configuration line is skipped: its blank lines and
  `Building configuration...`, `Current configuration : N bytes`, `Using N out of M bytes`
  (IOS prints a blank line between the first two);
* the recognised timestamp lines are skipped: `! Last configuration change at ...`,
  `! NVRAM config last updated at ...`, `! No configuration change since last restart`;
* generated top-level `ntp clock-period <number>` lines are skipped;
* standalone `!` separator lines (only `!`, at any indentation) are skipped.

Every other line is compared exactly and in order: other comment lines, blank lines after
the header (for example inside a banner), indentation and everything up to the final `end`.
Blank lines are skipped only in the header block because IOS's own header contains one;
inside the configuration they can be meaningful (banners), so they count. Reports give only
the number of differing lines and the first line number, never configuration text.

**Rollback.** On any failure after the replacement: `configure revert now` on a session to
the verified device, then a new session must show the safety backup's configuration and no
pending timer. If that cannot be verified while the timer may still run, the engine waits
for the timer (plus 30 s) and checks again. It is never reported as rolled back without that
check. A device that answers with another serial is never sent anything.

**Cleanup.** Only `flash:<temporary file>` is deleted (`delete /force`), then `dir` must not
find it. Archive copies and other files are never touched.

**Results:** SUCCESS (restored, both comparisons equal, confirmed, timer cancelled, file
removed), PARTIAL (all of that but the file could not be removed), FAILED (the device is
verified to be in its original configuration, or nothing was sent), UNKNOWN (anything else;
`manual_actions` says what to do). The result lists the device, backup and safety backup
files, transfer method, comparison, timer state, rollback attempt and verification, and
the cleanup.

**Sessions are always closed by closing the SSH transport.** Netmiko's `disconnect()` sends
a newline, which answers an IOS `[confirm]` question with yes. While a Netmiko call runs, a
watchdog detaches the channel as soon as the transport dies (Netmiko would otherwise wait
its whole read timeout on a closed channel).

## Restore window (Phase 4G)

**Devices page -> Backups... -> select a backup -> Select for restore -> Restore...**
(Configure permission only; viewers cannot open the catalogue, and the window itself refuses
every action without the permission). `gui/restore_window.py` only calls the Phase 4E and
4F functions; every check, the typed confirmation, the seal, the single use and the
rollback stay in `restore_preflight.py` and `restore_engine.py`. The window sends nothing
to a device itself.

1. **Opening** the window connects to nothing and writes nothing. It shows the target
   device and the selected backup (file, folder, creation time, key id, configuration
   SHA-256, verification status) and, for a changed-IP candidate or a legacy backup, what
   that means.
2. **Run Checks** reads (or asks for) the SSH login and runs the read-only preflight on a
   worker thread. Every check is listed with PASS / WARNING / BLOCKED / FAILED and its
   explanation, plus the live identity, the transfer method and, if the restore may go on,
   the exact phrase to type (`RESTORE <ip>`, or `RESTORE LEGACY <ip>`).
3. **Create safety backup and restore** is enabled only for a passing preflight and the
   exact phrase; a final question repeats the device, serial, platform and backup. The
   rollback timer is 3-10 minutes (default 5). Then, on worker threads: the encrypted
   safety backup, and only if it was made and verified, the restore engine.
4. **Progress**: the current stage, the safety-backup path, the rollback timer and the
   engine's log (commands only, never configuration text). **Result**: SUCCESS / FAILED /
   PARTIAL / UNKNOWN with an explanation, both backup paths, the timer state and every
   required manual action (a warning box for anything but SUCCESS).

**Cancelling and closing.** Before the engine starts, Cancel or closing the window ends the
workflow: a running check finishes in the background and changes nothing; a safety backup
being made is completed and the preflight is then cancelled, so no restore can start (the
encrypted safety backup is kept). **Once the engine runs, the window cannot be closed or
cancelled** and nothing is interrupted: the engine always finishes its confirmation or
rollback and the result is shown. Worker results are collected from the application's main
window, so they are handled (and the device released) even after the Restore window was
closed; the Restore window is not a child of the catalogue, so closing the catalogue never
closes it. **Only one check or restore runs per device at a time.** The startup
configuration is never saved.

**NetCommand cannot be closed while a restore runs.** From the moment the safety backup
starts until the restore engine has returned its result, every normal way out of the
workbench is refused with an explanation: the title-bar X (signed in and in sample/demo
mode) and **Sign out**. There is no force-quit. If the **session ends** meanwhile (idle
time-out, time limit, signed out elsewhere, account disabled, role changed), the workbench
is hidden at once, the restore goes on, its result is shown, and NetCommand signs out when
the Restore window is closed. Read-only checks do not hold NetCommand open (ending them
changes nothing). The protection is held until the result has been handled on the window's
thread (recorded in the Restore window, the device released, and any result or recovery
message box dismissed), and released then whatever the outcome (SUCCESS, FAILED, PARTIAL,
UNKNOWN, or an unexpected error, including one in the result handling itself). Ending the process from outside (Task Manager,
Ctrl+C in the console, a Windows shutdown) cannot be prevented; the device's rollback timer
then returns it to its previous configuration, but NetCommand cannot verify or report it.

## Save to Startup (Phase 4H)

A restore never saves. **Save to Startup...** in the Restore window (Configure permission)
is enabled only for a verified **SUCCESS** of that window's own restore: the result sealed
by the engine in this NetCommand session, the configuration verified and confirmed, the
rollback timer verified cancelled, for this device, not saved before. The logic is in
`startup_save.py` (it reuses the restore engine's verified-session, prompt and close
helpers); the window only runs it on worker threads.

**Checks (read-only).** A verified session (SSH 2, privilege 15, the restore's serial and
platform); no pending rollback timer; the running configuration valid and still exactly
the restored one (the engine records a digest of the compared lines when it verifies the
restore; the approved comparison rules decide); the startup configuration valid; the
keyring usable. Then the user types **`SAVE STARTUP <ip>`** (not the restore phrase) and
answers a final question naming the device, serial, platform, restored backup, the
encrypted backup to be made, and that the startup configuration is overwritten and used
after a reload.

**Save (one protected worker).** A new verified session repeats the checks and requires
the startup configuration seen by the checks; the current startup configuration
(`show startup-config`) is saved **encrypted** as `<ip>_pre-save-startup_<time>.ncbak`
(`purpose: pre-save-startup`, `source: show startup-config`, the device identity), read
back, decrypted in memory and compared byte for byte; any failure saves nothing. Then
**`write memory`**. (`copy running-config startup-config` is not used: IOS always asks for
the destination file name, which would need an answer.) A question from `write memory` is
never answered (the session is closed; Netmiko's disconnect is never used). Its text is
never trusted: a NEW verified session reads both configurations again.

**Results.** SUCCESS: the command completed and the startup configuration now equals the
running configuration, which is still the restored one. FAILED: nothing was sent, or the
startup configuration is verified unchanged. UNKNOWN: anything else, including a save that
was interrupted (connection lost, unanswered question) even if the startup configuration
then looks right, a mismatch after the save, or a device that cannot be verified; the
actions name the pre-save-startup backup and say not to reload until resolved. The backup
is kept in every case. Nothing else is changed and the device is never reloaded. While the
save runs NetCommand cannot be closed (the restore workflow's protection and device claim),
and an ended session waits for it and its result.

**Not yet established on real hardware:** the wording of `configure replace` with no file,
of `show archive config rollback timer` and of `show inventory` on the lab's Cisco 1900
router; and for the restore engine the output of `configure replace ... list force time N`
("Rollback Done", rejected-command wording), `verify /md5`, `configure confirm`, whether a
Cisco 1900 generates other lines besides `ntp clock-period` that would make the strict
comparison fail, and the Tcl transfer speed and size limits. For Save to Startup: the exact `write memory`
output ("[OK]"), whether the Cisco 1900 asks the NVRAM-overwrite question (after an IOS
image change) or any other question, and the `show startup-config` header lines. These must
be checked there before NetCommand restores or saves on a real device.

## Limitations of memory protection

NetCommand never writes keys, passphrases or decrypted configurations to logs, messages or
(except an explicit `export`) files, and it zeroes the native buffers it controls: the
copy of a key given to DPAPI and the decrypted key DPAPI returns. It **cannot** reliably
wipe every copy from memory: Python's `bytes` and `str` objects (the key, the passphrase,
the derived wrapping key, the decrypted configuration) cannot be overwritten, the
`cryptography` library and OpenSSL keep their own copies, and Windows may write memory to
the page file or a crash dump. Copies live until Python frees and the system reuses that
memory. Protect the computer itself: a locked screen, an encrypted system drive
(BitLocker) and no untrusted software on the account that runs NetCommand.

## Tests

`tests/test_backup_crypto.py`, `tests/test_backup_keys.py`, `tests/test_backup_tool.py`:
synthetic configurations and throwaway keys only; a fake DPAPI provider for ordinary
tests, and the real Windows DPAPI only on Windows. The real keyring location is never used
by the tests.

## Not done yet (later phases)

* Migrating existing `.txt` backups (dry run first, never deleting originals).
* Aligning the backend's unused `app_device_backups` design with this format.
