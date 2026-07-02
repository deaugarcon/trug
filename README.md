# trug

Free, open-source local iPhone backup and inspection tool for macOS.
Transparent local backups · readable exports · CLI automation · no license wall.

*Developed under the working title **Tether**; renamed to **trug** for the public
alpha. You may still see "Tether" in older docs and in the backup store path
(`Tether/Backups`).*

**Status: alpha (v0.1.0-alpha).** SP0/SP1 (device detection & pairing), SP2
(local backup: create, list, browse, verify, extract, encryption management),
and SP3/SP3.1 (inspect & export of messages, contacts, call history, and a notes
preview, as JSON or CSV) are in place; **restore is not yet supported.** See
`docs/superpowers/specs/` for the design.

## Install

Install via Homebrew:

    brew install deaugarcon/tap/trug

Or build from source — see **Build (dev)**.

> **macOS 27 beta note:** Command Line Tools 27 beta 2 ships a SwiftPM defect
> (package-manifest linking fails). If you are on the macOS 27 beta, install
> full Xcode 27 beta and make it the active toolchain
> (`sudo xcode-select -s /Applications/Xcode-beta.app/Contents/Developer`)
> before installing.

## Requirements

- **Runs on** macOS 14 (Sonoma) or later.
- **Building from source** needs Xcode 16+ (Swift 6 toolchain) and Homebrew.
  trug links the `libimobiledevice` / `libplist` stack, which
  `./Scripts/build-deps.sh` compiles from pinned source into `Vendor/`; that
  script needs `openssl@3` plus the usual autotools
  (`autoconf automake libtool pkg-config`). Nothing is downloaded at runtime.
- **A USB connection** to the device. USB is the supported path; see
  **Wi-Fi (experimental)** for the current state of network device-info.

## Build (dev)

    brew install autoconf automake libtool pkg-config openssl@3
    ./Scripts/build-deps.sh
    ./Scripts/dev.sh build
    ./Scripts/dev.sh run trug devices list

## CLI

    trug devices list [--json] [--experimental-wifi]
    trug devices info [--udid <udid>] [--json] [--experimental-wifi]
    trug devices pair [--udid <udid>]

    trug backup create [--udid <udid>] [--full] [--verify-level structural|crypto]
    trug backup list [--json]
    trug backup browse <udid> [--domain <domain>] [--json]
    trug backup verify <udid> [--level structural|crypto|readability] [--json]
    trug backup extract <udid> <domain> <relative-path> --out <file> [--force]
    trug backup inspect <udid> <messages|contacts|calls|notes> [--json] [--limit N]
    trug backup export  <udid> <messages|contacts|calls|notes> --out <file> [--format json|csv] [--force]
    trug backup encryption status|enable|disable|rotate [--udid <udid>]

`create` targets the single connected device when `--udid` is omitted; `browse`,
`verify`, `extract`, `inspect`, and `export` operate on the current local backup
for the given `<udid>`.

Example (the UDID and phone numbers below are fictional):

    trug backup inspect 00008120-000A1B2C3D4E5F26 messages --limit 5
    trug backup export  00008120-000A1B2C3D4E5F26 contacts --out ~/contacts.json

### Backup passwords

Backup passwords are read from `TRUG_BACKUP_PASSWORD` (and
`TRUG_BACKUP_NEW_PASSWORD` for `encryption enable`/`rotate`) or an interactive
no-echo prompt — never from a command-line argument. No-echo entry is reliable in
Terminal.app and iTerm2 but **not in Warp** (which can echo/munge the password);
set a new backup password from a standard terminal or via the env var, and never
trust a password you read off-screen. See `SECURITY.md`.

### Exit codes

| Code | Meaning |
|---|---|
| 0 | Success (including an empty device/backup list) |
| 2 | Device not found / ambiguous (pass --udid); or a backup user-input miss: wrong backup password, encrypted backup needs a password, named backup/file absent, refused overwrite, or wrong encryption state |
| 3 | Not paired, or Trust dialog pending |
| 4 | Pairing denied on device |
| 5 | Device is passcode-locked |
| 6 | Backup completed but failed verification |
| 7 | Corrupt or tampered backup (unreadable manifest / malformed file id) |
| 64 | Usage error (bad arguments — e.g. a negative `--limit`, an unknown store or format) |
| 69 | usbmuxd unreachable |
| 70 | Unexpected internal error |

A wrong backup password maps to `2` (a user-input miss), not `7` — `7` is
reserved for a genuinely corrupt backup, so a script can tell "you typed the
wrong password" from "the backup is damaged." A refused overwrite (no `--force`)
by `extract` or `export` is also `2`; a failed write is `70`.
(Insufficient-disk-space and device-locked-during-backup currently surface as
`70`; dedicated codes for them are a proposed-but-unratified change.)

### Output stability

`--json` output is a contract for automation: keys are stable and sorted; fields
may be added in future versions, but existing fields are never renamed or
removed. `inspect --json` and the `export` JSON file follow the same contract.
CSV export follows the same field set and column order but carries no
`schema_version`/`count` header (those are JSON-only); **JSON is the lossless
format** — CSV cannot distinguish an empty string from a missing value.

## Backups

`trug backup create` makes a local backup of the connected device under
`~/Library/Application Support/Tether/Backups/<udid>/`. A backup is staged, then
verified at the chosen level (`--verify-level`, default `structural`), and only
promoted to `current` on success — a failed or interrupted backup never replaces
a previously good one.

**Encryption.** A backup is encrypted only if the device has backup encryption
turned on. Encrypting your backups protects sensitive data (Health, Keychain,
Wi-Fi and saved passwords, call history) that the device only includes in an
**encrypted** backup — turning it on is recommended. Manage it with
`trug backup encryption enable|disable|rotate` (the device prompts you to confirm
the change on its own screen). The password is set on the device; keep it safe —
without it an encrypted backup cannot be read or restored.

**Verify levels.** `structural` checks every manifest row maps to a present
shard; `crypto` additionally proves a sample of encrypted files decrypts;
`readability` opens the key databases (`sms.db`, `AddressBook.sqlitedb`) and
confirms their core tables exist, so downstream tools have something openable.
(`create` verifies at `structural` or `crypto`; `readability` is available on the
standalone `verify` command.)

**Restore is not yet supported.** trug can create, inspect, verify, and extract
files from a backup, but cannot yet restore one to a device.

## Inspect and export

Two commands read structured records — **messages**, **contacts**, **calls**
(call history), and **notes** — out of an existing local backup. They are
deliberately different in what they reveal.

> **`notes` is a title/metadata preview.** It reads `title`, `snippet`,
> `created`, `modified`, and `folder`; the note **body is not included** in this
> release (schema version 1). Full note-body decode is a planned follow-on
> (SP3.2). "Full and unmasked" export therefore means every field the store
> exposes today — which for notes excludes the body.

**`backup inspect <udid> <store>` — redacted, read-only preview.**
Prints a truncated, masked preview to the terminal (or `--json`); it writes
nothing to disk and takes no `--out`. `--limit N` caps the rows previewed
(default 20; a negative value is a usage error, exit 64). Redaction is applied on
the single rendering path, so the table and `--json` are masked identically:

- Message bodies are truncated to **40 characters** (a trailing `…` and
  `"truncated": true` mark a longer body).
- Phone numbers are masked to a `+1*******89` shape (leading digits + last two
  only); emails to `j****@e***.com`; your own messages show `me`.
- Contact names show the first name plus a masked surname (`Ada L*****`).
- Call `address` is masked like a phone number; note `title`/`snippet` are
  truncated to the same 40-character bound.

Example:

    trug backup inspect 00008120-000A1B2C3D4E5F26 messages --limit 5 --json

    {
      "preview": true,
      "rows": [
        {
          "body_preview": "Running late, be there in ten mi…",
          "direction": "received",
          "from": "+1*******89",
          "service": "iMessage",
          "truncated": true,
          "when": "2026-06-01T14:22:05Z"
        }
      ],
      "shown": 1,
      "store": "messages"
    }

**`backup export <udid> <store> --out <file>` — full, unmasked.**
This is the explicit full-data path: it writes the **complete** store, with **no**
truncation and **no** masking. It requires an explicit `--out` path, creates the
file with `0600` (owner-only) permissions, and **refuses to overwrite** an
existing file unless `--force` is given (a refused overwrite is exit 2). The
command name plus the explicit output path are the consent for writing unmasked
personal data; a plaintext-backup export never prompts for a password.

`--format json` (the default) writes a `{store, schema_version, count, rows}`
envelope (`schema_version` is `1`). Message rows carry `body`, `date`, `service`,
`is_from_me`, `sender`, `chat`; contact rows carry `first`, `last`,
`organization`, `primary_phone`, `primary_email`; call rows carry `address`,
`date`, `duration`, `direction`, `call_type`; note rows carry `title`, `snippet`,
`created`, `modified`, `folder`. Example:

    trug backup export 00008120-000A1B2C3D4E5F26 calls --out ~/calls.json

    {
      "count": 1,
      "rows": [
        {
          "address": "+15555550123",
          "call_type": "voice",
          "date": "2026-06-14T18:02:11Z",
          "direction": "outgoing",
          "duration": 372
        }
      ],
      "schema_version": 1,
      "store": "calls"
    }

The command prints only a count and the path to stderr — never row content — so
an export leaves no personal data in your shell history or scrollback.

### CSV export

`--format csv` writes the same field set as a flat, RFC-4180 table (comma
separated, CRLF-terminated, UTF-8 with no BOM) — one header row, one row per
record, columns in the JSON field order. There is no envelope, no
`schema_version`, and no `count` row; the store is implied by the invocation.

    trug backup export 00008120-000A1B2C3D4E5F26 calls --out ~/calls.csv --format csv

    address,date,duration,direction,call_type
    '+15555550123,2026-06-14T18:02:11Z,372,outgoing,voice
    '+15555550188,2026-06-14T09:47:03Z,0,incoming,facetime_audio

Two things to know when opening a CSV:

- **Spreadsheet locale.** The file is comma-separated per RFC 4180. A spreadsheet
  configured for a semicolon (`;`) locale may put every row in one column — use
  its "import" / "text to columns" flow and pick comma as the delimiter.
- **Formula-injection neutralization (intentional).** Any field beginning with
  `=`, `+`, `-`, `@`, or a leading tab/CR/LF is prefixed with a single quote
  (`'`) so a spreadsheet cannot execute it as a formula. That is why the
  `+`-leading phone numbers appear as `'+15555550123` in the output above — the
  apostrophe is added by trug, not part of the stored value. This is deliberate;
  JSON export stays lossless and is unaffected.

## Device support

The backup, inspect, and export paths are validated end-to-end against a real
**iOS 27** device backup. iOS 18-era backups are supported at the format level
(the keybag `VERS 5` lineage carried forward from SP2), but the call-history and
notes readers have **not** been device-validated on iOS 18 in this alpha — the
exact store paths and column spellings for those two stores are confirmed on iOS
27 only here. Treat iOS 18 calls/notes as best-effort until a later release
validates them on hardware.

### Wi-Fi (experimental) — network device-info proof

`--experimental-wifi` is a **network device-info proof**: it demonstrates that a
network lockdownd session can be established and `devices info` succeeds over
Wi-Fi for a USB-paired device. It does **not** claim wireless backup works — that
is SP6 scope. Requires a prior USB pairing and "Show this iPhone when on Wi-Fi"
enabled in Finder. USB is the supported path.

**Proof result (2026-06-10, iPhone Air / iPhone18,4, iOS 27.0, macOS 27 beta):
USB fully verified; Wi-Fi blocked by host-side matching.** The device advertises
`_apple-mobdev2._tcp` correctly (factory MAC, after disabling iOS Private Wi-Fi
Address) and the pairing record stores that same MAC, but this macOS beta's
usbmuxd never surfaced the device to clients — the reference `idevice_id -n`
agrees with trug, and a different previously-paired device *did* transiently
appear over Wi-Fi through the same stack, proving the listing path works. Tracked
for SP6.

**Known limitation:** iOS **Private Wi-Fi Address** (default on) breaks classic
Wi-Fi-sync discovery — the pairing record stores the factory MAC while the device
advertises a per-network private MAC, so usbmuxd cannot match them. SP6 scope:
private-MAC-aware pairing records.

## Privacy

trug is local-first and reads **your own** device backups; it exports the data
you already own, on your machine, to paths you name.

- **No telemetry.** trug sends nothing over the network as part of backup,
  inspection, or export. There is no tracking, analytics, or phone-home.
- **No decrypted data left behind.** The two operations that must materialize a
  decrypted database to open it (manifest decryption and readability
  verification) write it to a `0600` (owner-only) temp file that is removed on
  every exit path, and a startup scrub clears any temp left by a killed run.
- **Guarded writes.** `extract` and `export` write only to your `--out` path,
  at `0600`, and refuse to overwrite an existing file (or follow a symlink, or
  clobber a directory) unless you pass `--force`.

See `SECURITY.md` for the full backup-password and decrypted-content handling.

## License

MIT (trug code). See `NOTICE` for the LGPL-2.1 dynamic-link dependencies.
