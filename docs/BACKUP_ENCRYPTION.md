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
| IP address | different: a visible warning; **without a serial match, a different IP blocks selection** (the approved legacy rule) |
| Hostname | different: a warning; a hostname never proves the hardware |
| No identity fields | "Identity not recorded": never a hardware match |

Missing, `null`, malformed or placeholder values (`unavailable`, `unknown`, `n/a`, ...) are
always "unknown".

**Selection** is possible only for a **Verified** backup (this exact file, checked against
its authenticated header) with no blocking mismatch, and only for the Configure permission.
A backup whose hardware identity is not confirmed by serial can be selected for inspection
but is marked as needing the separate **legacy-backup confirmation** (matching IP and the
typed device name) in the future restore workflow; it is never called restore-ready.

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
