# Security

trug is a local-first iPhone backup tool. It handles two kinds of sensitive
material: **backup keys** (the password that encrypts a device's backups) and
**decrypted backup contents**. This document states how each is handled and what
guarantees the design makes.

## Reporting

This is alpha software. To report a security issue, open a GitHub issue on the
repository (omit any personal data or real backup keys from the report) or
contact the maintainer directly. There is no formal disclosure process yet.

## Backup keys

- **Never on argv.** A backup key is read from the environment
  (`TRUG_BACKUP_PASSWORD`, and `TRUG_BACKUP_NEW_PASSWORD` for
  `encryption enable`/`rotate`) or an interactive no-echo prompt — never from a
  command-line argument, which would be visible to any user via `ps`.
- **Never written to disk or logs.** A backup key lives only in memory for the
  duration of the operation that needs it. It is not persisted, cached, or
  echoed into any log or error message.
- **No-echo prompt fails closed.** The interactive prompt disables terminal echo
  before reading. If echo cannot be disabled, trug **refuses to read the key in
  cleartext** rather than fall back to an echoing read, and tells you to supply
  it via `TRUG_BACKUP_PASSWORD` instead.
- **No-echo entry is unreliable in some terminals — use a standard one.** trug
  disables echo with `tcsetattr`, which is honored by **Terminal.app** and
  **iTerm2**. Some terminals (notably **Warp**) echo and can *munge* keystrokes at
  their own UI layer *above* the TTY, so the characters shown — and the bytes
  trug actually receives — can differ from what you typed by a character or more.
  This is the terminal's behavior, not trug's, and trug cannot detect or correct
  it. **Set a new backup key from Terminal.app or iTerm2, or pass it via
  `TRUG_BACKUP_NEW_PASSWORD` — and never trust a backup key you read off-screen.**
  Setting an unknown backup key locks the device's backups until it is corrected
  (recoverable only via the device's *Reset All Settings*). Setting a *new* key
  (`encryption enable`/`rotate`) asks you to enter it twice and proceeds only on a
  match — this catches a one-off typo, but a terminal that munges *both* entries
  the same way would still pass the check, so the terminal choice above is the
  real guard.
- **Lazy evaluation.** An unencrypted backup never triggers a key prompt: the key
  is read only after the backup is proven encrypted (or, for readability, only on
  the encrypted bytes-source branch). Verifying or browsing a plaintext backup
  with no key configured neither prompts nor hangs.

### Loading the key from the macOS keychain (recommended)

To keep a backup key out of your shell history and out of an interactive prompt,
store it once as a keychain item and load it into the environment for the
duration of a single command. This uses the system keychain as the store of
record; trug still holds the value in memory only.

    # Store the key once. `-w` with no value prompts for it without echoing;
    # nothing is typed on the visible command line.
    security add-generic-password -a "$USER" -s trug-backup-key -w

    # Load it into the environment for one command. The key is resolved by the
    # command substitution at run time, so only the literal text
    # `$(security ...)` — never the key — is written to shell history.
    TRUG_BACKUP_PASSWORD="$(security find-generic-password -a "$USER" -s trug-backup-key -w)" \
      trug backup export <udid> messages --out ~/messages.json

Do **not** inline the key as a literal (`TRUG_BACKUP_PASSWORD=... trug ...`): a
literal value is recorded in your shell history. The command-substitution form
above avoids that; the key is expanded only at execution time.

## Decrypted backup contents

- **Owner-operated decryption only.** Decryption requires the backup key, which
  only the device owner has. trug performs no decryption a user did not
  explicitly request with their own key.
- **Decrypted bytes go only where you ask.** `extract` and `export` write a
  decrypted file only to the `--out` path you specify (they refuse to overwrite
  an existing file, follow a symlink, or clobber a directory unless `--force` is
  given), at `0600` (owner-only) permissions. Decrypted bytes are not written
  anywhere else.
- **Transient decrypted-data locations.** A few operations materialize decrypted
  plaintext to a temporary file in order to open it:
  - **Manifest decryption** (`ManifestReader`) writes the decrypted `Manifest.db`
    to a private temp file to open it as SQLite.
  - **Readability verification** (`BackupVerifier`, `--level readability`) writes
    each checked key database (e.g. `sms.db`, `AddressBook.sqlitedb`) to a private
    temp file to open it and confirm its core tables exist.
  - **Row readers** (`inspect`/`export` of messages, contacts, calls, notes)
    materialize the store's database to a private temp file, open it read-only,
    and remove it.

  Every such temp file is created with `0600` (owner-only) permissions and removed
  on every exit path. The readability check reads only table **names**
  (`sqlite_master`) — never a row or any content — so it surfaces no personal data
  even while a key database is open.
- **No telemetry.** trug sends nothing over the network as part of backup,
  verification, inspection, or export. There is no tracking, analytics, or
  phone-home.

## Privacy invariants (P1–P4)

The inspect/export data paths hold four invariants, in plain language:

- **P1 — no decrypted file survives a normal or handled exit.** Anything trug
  decrypts to open is written `0600` and removed on the way out, on both the
  success and the error path.
- **P2 — a killed run cannot leak to the next one.** A startup scrub clears any
  decrypted temp left behind by a process that was killed before it could clean
  up, so a later run starts from a clean floor.
- **P3 — `inspect` is a capped, redacted preview.** The row cap is applied in the
  SQL query (a large store is never fully read for a preview), and every previewed
  row is truncated and masked on a single rendering path — the table and `--json`
  are redacted identically, with no unmasked back-door.
- **P4 — `export` is the only way row data reaches disk.** Decrypted row data
  reaches disk only through `export`, only to the explicit `--out` path, at
  `0600`, and only with your consent (the command name plus the path). CSV export
  uses this same guarded write path — it is not a second, weaker one.

## Test fixture policy

Tests use two fixture classes, and **neither contains personal data**:

- **Synthetic** fixtures are generated by a fixture builder with a known key and
  known plaintext (schema-only SQLite, fabricated byte strings) — fully
  reproducible, no device, no PII.
- **Real-but-clean** fixtures, where used, are captured from a dedicated throwaway
  device and throwaway Apple ID seeded only with fabricated data, pinned by iOS
  version. They contain no personal data by construction.

No test depends on the presence of personal data, and no real backup key or
personal content is checked into the repository.
