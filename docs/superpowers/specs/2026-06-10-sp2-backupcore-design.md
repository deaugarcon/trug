# Tether SP2 — BackupCore Design

**Date:** 2026-06-10
**Status:** Draft for review
**Depends on:** SP0+SP1 (shipped — DeviceCore, LockdownSession, CLI scaffold)
**Platform spec:** `2026-06-10-tether-platform-design.md` (§4 SP2 row)
**Feature reference:** an off-repo feature-survey working note (Part 2a — "Acquiring the backup"; not shipped with this repository)

## 1. Goal

Make Tether actually back up an iPhone, and prove the backup is real. After SP2:

```
tether backup create  [--udid <id>] [--verify-level structural|crypto] [--full]
tether backup list     [--udid <id>] [--json]
tether backup browse   <backup-id> [--domain <d>] [--json]
tether backup verify   <backup-id> [--level structural|crypto|readability]
tether backup extract  <backup-id> <domain> <relative-path> --out <file>
tether backup encryption  status                       [--udid <id>]
tether backup encryption  enable                       [--udid <id>]   # needs NEW password
tether backup encryption  disable                      [--udid <id>]   # needs CURRENT password
tether backup encryption  rotate                       [--udid <id>]   # needs OLD + NEW password
```

`enable`, `disable`, and `rotate` are distinct operations with distinct password requirements (see §6). There is no ambiguous single `on/off` that guesses which password role is meant.

This is the load-bearing sub-project: it acquires the artifact every later feature (exports, restore, spyware scan) reads. Per the reference doc, "get the backup, then parse the datastores" — SP2 is the *get* half plus the cryptographic key to the *parse* half.

## 2. Locked Decisions

| Decision | Choice | Rationale |
|---|---|---|
| MobileBackup2 | **Native Swift port** of the DL* message loop over the C `mobilebackup2` service client | Strongest end-state; verification + progress + cancellation are first-class, not scraped from a subprocess. No GPL `idevicebackup2` linkage |
| Encryption | **Manage + nudge**: `encryption enable\|disable\|rotate\|status`; `create` warns loudly when device is unencrypted | Mirrors iMazing's "encryption unlocks Health/Keychain/calls" stance without silently mutating device state |
| Decryption | **Full keybag + `extract`**: implement PBKDF2→class-key-unwrap→AES now; ship per-file extraction | De-risks the hardest crypto before SP3; `verify --level crypto` gets real teeth |
| History | **Rolling, versioning-ready**: one MB2-native incremental backup per device; layout admits APFS-clone snapshots later without migration | Snapshots are "pure product engineering" (reference doc Part 5) — their own later sub-project |
| Integrity | **Last-verified backup is never mutated in place** — see §4.1. An incremental `create` clones the previous verified backup, mutates the clone, and only promotes it on successful verification | An interrupted backup must never leave the only good copy half-written |
| Storage | `~/Library/Application Support/Tether/Backups/<udid>/` — MobileSync-compatible layout (per platform spec §1) | Format-portable; not Apple's canonical dir (documented) |
| Restore | **Out of scope** — SP5, safety-first | Failure is user-catastrophic |

## 3. Architecture

New package `BackupCore` (depends on `DeviceCore` + `CWrappers`), plus CLI surface in `TetherCLI`. Engine stays UI-free (lint rule extends to `Sources/BackupCore`).

```
TetherCLI  ── backup create|list|browse|verify|extract|encryption
                         │
                    BackupCore
   ┌──────────────────────┼───────────────────────────────┐
   │ MobileBackup2Session  drives the DL* protocol loop:    │
   │                       Hello → version negotiate →      │
   │                       DLMessageDownloadFiles /          │
   │                       UploadFiles / GetFreeDiskSpace /  │
   │                       ContentsOfDirectory / Move /      │
   │                       RemoveItems / CopyItem → progress │
   │ BackupStore           on-disk layout, backup-id naming, │
   │                       list/locate, MobileSync file tree │
   │ ManifestReader        opens Manifest.db (SQLite) +      │
   │                       Manifest.plist/Status/Info;       │
   │                       enumerates Files(fileID,domain,   │
   │                       relativePath,flags,file)          │
   │ Keybag                BackupKeyBag TLV parse → PBKDF2    │
   │                       (DPSL/DPIC double-salt) → KEK →    │
   │                       RFC3394 unwrap class keys          │
   │ BackupDecryptor       per-file AES-CBC decrypt using     │
   │                       the unwrapped class key + per-file │
   │                       key from Manifest.db               │
   │ BackupVerifier        tiered: structural / crypto /      │
   │                       readability                        │
   │ EncryptionControl     MB2 ChangePassword                 │
   │                       (enable/disable/rotate)            │
   └─────────────────────────────────────────────────────────┘
                CWrappers (mobilebackup2_*, afc_* for staging)
```

### Module responsibilities

| Type | Does | Key interface |
|---|---|---|
| `MobileBackup2Session` | Opens the `com.apple.mobilebackup2` service via a `LockdownSession`, negotiates protocol version, runs the message loop, emits `AsyncStream<BackupProgress>`, honors cancellation | `func backup(options:) -> AsyncThrowingStream<BackupProgress, Error>` |
| `BackupStore` | Owns the on-disk root and the §4.1 state machine: clones `current`→`.staging` (APFS `clonefile`/hardlink fallback), tracks `in-progress`/`verified`/`failed`, atomically promotes a verified staging to `current`, prunes failed/superseded generations; lists known backups; resolves a `BackupID` to a `BackupHandle` | `beginStaging() -> StagingHandle`; `promote(_:) throws`; `markFailed(_:)`; `list() -> [BackupSummary]`; `handle(for:) -> BackupHandle` |
| `ManifestReader` | Read-only SQLite/plist access over a `BackupHandle`; enumerates and looks up file records by domain/path; reads `Status.plist` (`IsFullBackup`, `SnapshotState`), `Info.plist`, `Manifest.plist` (`IsEncrypted`, `BackupKeyBag`) | `files(inDomain:) -> [FileRecord]`; `record(domain:path:) -> FileRecord?`; `metadata() -> BackupMetadata` |
| `Keybag` | Parse the TLV keybag; derive KEK from password; unwrap class keys. Pure value-in/value-out — fixture-testable | `init(tlv:) throws`; `unlock(password:) throws -> UnlockedKeybag` |
| `BackupDecryptor` | Given an `UnlockedKeybag` + a `FileRecord`, decrypt that file's bytes (AES-CBC, per-file key unwrapped against its protection class) | `decrypt(_ record:, using:) throws -> Data` |
| `BackupVerifier` | Tiered verification (see §4) | `verify(_ handle:, level:, password:) throws -> VerifyReport` |
| `EncryptionControl` | Reads encryption status via lockdownd; performs `enable`/`disable`/`rotate` via MB2 `ChangePassword` with role-distinct password pairs (§5), rejecting wrong-state requests | `status(udid:)`; `enable(new:udid:)`; `disable(current:udid:)`; `rotate(old:new:udid:)` |

### Design rules carried from SP0/SP1
- CLI-first: every capability is a Core API + CLI command before any GUI.
- Typed errors with recovery (`BackupError`, `KeybagError`, `VerifyError`); C codes never escape `CWrappers`.
- Long ops are `async`, stream progress, cancel cleanly, and never corrupt on-disk state mid-write (see §4.1).
- "Never lie about success": `create` exits 0 only after the requested verify level passes.
- New: **no plaintext secrets at rest** — the backup password is read from env/prompt/stdin, never written to disk or logged; decrypted bytes go only where the user directs (`--out`, stdout).

## 4. Integrity & Verification

### 4.1 Backup-state model (the integrity guarantee)

MobileBackup2 is incremental: it mutates the backup tree in place, transferring only changed files. That is incompatible with "never lose the last good backup" if applied naively to the live store. SP2 therefore models each backup with an explicit state and never lets MB2 write directly over a verified backup.

On-disk layout per device:
```
Backups/<udid>/
  current        → symlink to the live verified backup dir (the MobileSync tree)
  <backupdir>/   one directory per backup generation; contains Status.plist
                 with Tether's state marker + the standard MB2 files
  .staging/      a create-in-progress clone, promoted on success
```

**State machine** (recorded in a Tether-owned `TetherState` key in the backup dir, separate from Apple's `Status.plist` so we never fight MB2 for it):

| State | Meaning | Transition |
|---|---|---|
| `in-progress` | MB2 is actively writing this dir | set when `create` begins on the staging clone |
| `verified` | structural verify passed; safe to use/restore-from | set atomically after verify; `current` symlink repointed here |
| `failed` | create or verify did not complete | set on error/cancel; never promoted; kept for diagnosis, prunable |

**`create` algorithm:**
1. If a `verified` backup exists, clone it into `.staging/` via APFS copy-on-write (`clonefile(2)` — near-instant, no extra space until divergence; falls back to a hardlink tree on non-APFS volumes). If none exists, `.staging/` starts empty (first full backup).
2. Mark `.staging` `in-progress`; point MB2 at it. MB2 does its incremental transfer against the cloned tree.
3. On MB2 `DLMessageDisconnect`, run `structural` verify (plus `crypto` if `--verify-level crypto`) **against the staging tree**.
4. On pass: mark `verified`, atomically repoint `current` to the new dir, then prune older `failed`/superseded dirs per a simple keep-last-verified policy (full retention/snapshots are a later sub-project).
5. On any failure or cancellation: mark `.staging` `failed`, leave `current` untouched. **The previous verified backup is always intact.** The next `create` discards the `failed` staging and re-clones from `current`.

This makes interruption safe by construction: the only directory MB2 ever mutates is a disposable clone, and `current` only ever points at a verified generation. The clone keeps the cost near-zero on APFS (the common case); the hardlink fallback keeps it correct on other filesystems.

### 4.2 Tiered Verification (the differentiator made concrete)

Each tier is a separate, independently runnable check. `create` runs `structural` by default; `--verify-level crypto` adds crypto; `verify` runs any requested tier on an existing backup.

| Tier | Proves | How |
|---|---|---|
| **structural** | Completeness | Every `Files` row's `fileID` maps to a present on-disk shard file (`<id[0:2]>/<fileID>`); sizes consistent with `Manifest.db`; required plists present and parseable; `Status.plist` says the backup finished |
| **crypto** | Decryptability | (1) the keybag unlocks with the supplied password; (2) **`Manifest.db` itself decrypts and opens as valid SQLite** with its expected `Files`/`Properties` tables; (3) a sampled set of protected files (≥1 per protection class present) unwraps + AES-decrypts AND each decrypts to its **expected structural signature** — SQLite header for `.db`/`.sqlitedb`/`.storedata`, bplist/`<?xml` for plists, a known magic for other sampled types. Correct PKCS7 padding alone is *not* sufficient (random keys pad-validate ~0.4% of the time) |
| **readability** | Exportability (SP3 hand-off only) | A **minimal** check, not parsing: the key databases (`sms.db`, `AddressBook.sqlitedb`) decrypt, open as valid SQLite, and contain their expected core tables (`message`/`chat` for sms; `ABPerson` for AddressBook). It confirms SP3's parsers will have something openable — it does **not** read rows, render, or interpret content. Any row-level parsing belongs to SP3 |

`VerifyReport` is structured (counts, per-tier pass/fail, first N failures with file paths) and `--json`-serializable under the SP1 stability contract.

## 5. Data Flow

**`tether backup create --udid X` (encrypted device):**
DeviceCore resolves X → `LockdownSession` → BackupStore clones the current verified backup into `.staging` (§4.1) → `MobileBackup2Session` starts `com.apple.mobilebackup2`, negotiates version → device drives DL* messages; MB2 writes the MobileSync tree **into the `.staging` clone** (incremental: only changed files transfer) → on `DLMessageDisconnect`, BackupVerifier runs `structural` against the staging tree → on pass, BackupStore promotes it (`verified`, repoint `current`) and `create` exits 0; on failure it marks staging `failed` and leaves `current` untouched. Progress (`filesTransferred/total`, bytes, current domain) streams to a CLI progress line. `--verify-level crypto` additionally unlocks the keybag with the password and sample-decrypts before promotion.

**`tether backup extract X HomeDomain Library/SMS/sms.db --out ./sms.db`:**
ManifestReader locates the `FileRecord` → if backup encrypted, Keybag.unlock(password) → BackupDecryptor.decrypt(record) → bytes written to `--out`. No device connection needed (operates on the stored backup). This is the exact path SP3's parsers will call internally.

**`tether backup encryption enable|disable|rotate --udid X`:**
EncryptionControl opens MB2 and sends `ChangePassword` with the role-appropriate password pair:
- `enable` → `(old: nil, new: NEW)` — requires a new password; refuses if already encrypted.
- `disable` → `(old: CURRENT, new: nil)` — requires the current password; refuses if not encrypted.
- `rotate` → `(old: OLD, new: NEW)` — requires both; refuses if not encrypted.

Each then confirms the device reports the expected encryption state. Passwords are sourced from environment (`TETHER_BACKUP_PASSWORD`, and `TETHER_BACKUP_NEW_PASSWORD` for `rotate`) or interactive prompts — **never argv** (visible via `ps`). A wrong current/old password surfaces as `KeybagError.wrongPassword` (exit 2 — a user-input miss, not corruption; see §6), not a silent no-op.

## 6. Error Handling

- `BackupError`: `serviceStartFailed`, `protocolVersionUnsupported(device:)`, `deviceDisconnectedMidBackup`, `insufficientDiskSpace(needed:available:)`, `backupCancelled`, `deviceLocked` (device must be unlocked to back up), each with recovery suggestion.
- `KeybagError`: `wrongPassword`, `unsupportedKeybagVersion(v:)`, `malformedKeybag`. `wrongPassword` is distinguished from `malformedKeybag` so users know whether to re-enter vs file a bug.
- `VerifyError` is non-throwing in normal use — verification *findings* are data in `VerifyReport`; only IO/parse failures throw.
- Cancellation (Ctrl-C / task cancel) during `create` marks the `.staging` clone `failed` and leaves the previous `verified` backup (and the `current` symlink) untouched per §4.1; the next `create` discards the failed staging and re-clones from `current`.
- Exit codes (SHIPPED contract — extends the SP1 table; reconciled to the implementation, which diverged from the original proposal below for device-proven reasons). The mapping is `exitCode(for:)` in `Sources/TetherCLI/OutputFormat.swift`, pinned both directions by `OutputFormatTests`:
  - `2` user-input miss — a wrong backup password (`KeybagError.wrongPassword`), an encrypted backup needing a password (`VerifyError.passwordRequired`), a named-but-absent backup/file, a refused overwrite, or an encryption operation against the wrong on-device state. **C1/D1:** these are NOT corruption or an internal fault; a wrong password was device-proven (live `MBErrorDomain/207`) to belong here, and mapping it to `2` lets a script tell "you typed the wrong password" from "Tether crashed."
  - `6` backup verification failed (`BackupError.verificationFailed`).
  - `7` corrupt/tampered backup (`VerifyError.manifestUnreadable`, `VerifyError.malformedFileID`) — a distinct class from a user-input miss and from an internal fault.
  - `70` internal/unmapped error.
  - **Originally proposed (NOT shipped):** `7 = wrong backup password, 8 = insufficient disk space, 9 = device locked`. `wrongPassword → 7` was REJECTED — it collides with `7 = corrupt backup` and reverses the C1/D1 device-proven contract; `wrongPassword` stays at `2`. `BackupError.insufficientDiskSpace` and `BackupError.deviceLocked` exist in the engine but currently fall through to `70`. **PROPOSED-BUT-UNRATIFIED (open question for Deau):** routing `insufficientDiskSpace → 8` and `deviceLocked → 5` (SP1's passcode-locked code). A public-CLI exit-code addition is Deau-gated, so it is deferred; `unratifiedRoutingsStayAtSeventy` in `OutputFormatTests` pins them at `70` so the routing cannot land silently.

## 7. Testing Strategy

Two fixture classes serve different purposes, and SP2 needs **both** — synthetic proves the algorithm is correct; real-but-clean proves we match Apple's actual on-disk layout, which drifts by iOS version.

| Fixture class | What it proves | Provenance |
|---|---|---|
| **Synthetic** | The *algorithm* is correct (keybag math, AES, manifest parsing) | A fixture-builder script generates a tiny backup with a known password and known plaintext; golden tests assert exact decrypted bytes. Fully reproducible, no device |
| **Real-but-clean** | We match Apple's *actual layout/version* (catches keybag-variant and schema drift the reference doc warns about) | Backups captured from a **dedicated throwaway device + throwaway Apple ID**, seeded only with fabricated data, pinned by iOS version (e.g. `fixtures/real/ios-27.0/`). Contains **no personal data by construction**. Checked in (small) or fetched from a release asset if size demands |

| Layer | Approach |
|---|---|
| `Keybag` / `BackupDecryptor` | Synthetic golden tests for exact bytes; **plus** a real-but-clean encrypted fixture per supported iOS version to catch keybag-variant drift |
| `ManifestReader` | Synthetic `Manifest.db` + plists (known-good and deliberately corrupted); plus a real-but-clean `Manifest.db` to validate against Apple's actual schema |
| `BackupVerifier` | Fixture backups: complete, missing-shard, truncated-file, wrong-password, and a real-but-clean encrypted backup — assert the correct tier fails with the right finding, and that all three tiers pass on a genuine Apple backup |
| `MobileBackup2Session` | Protocol loop tested against a recorded/mock DL* exchange (mock transport from SP1); state-machine transitions unit-tested without a device |
| Device-gated (`TETHER_DEVICE_TESTS=1`) | Real `create` against the connected iPhone: completes, verifies structural, `list` shows it, and `extract` pulls **`Info.plist`** (or another non-personal manifest file guaranteed present in every backup) — assertions check only that a known-shape, non-personal file decrypts/extracts. **No test depends on the presence of personal data.** Run at a device checkpoint, skipped in CI |
| CI | All non-device tests (synthetic + checked-in real-but-clean fixtures) + the no-UI-imports lint extended to `Sources/BackupCore` |

## 8. Risks & Constraints

| Risk | Severity | Mitigation |
|---|---|---|
| Keybag crypto has per-iOS-version variants; getting every one right is the documented "hard part" | High | Synthetic fixtures prove the algorithm; **real-but-clean per-iOS-version fixtures (§7) catch layout/variant drift**; support the current keybag version explicitly and fail loudly (`unsupportedKeybagVersion`) on unknown ones rather than silently mis-decrypting |
| MobileBackup2 is a stateful, chatty protocol; a wrong state transition corrupts the backup | High | Port carefully from the documented `idevicebackup2` state machine; mock-transport state tests before any device run; **MB2 only ever writes a disposable clone, never the verified backup (§4.1)** — corruption cannot reach `current` |
| Backup requires the device unlocked and trusted; long backups can be interrupted | Medium | `deviceLocked` typed error; resumable incremental backups; progress + clean cancellation |
| iOS 17+ moved some services behind RemoteXPC; MB2 itself still works over classic lockdown but verify on iOS 26/27 | Medium | SP1 already talks to iOS 27 over lockdownd; smoke-test `create` on the iOS 27 test device early |
| Disk space: a full first backup can be tens of GB | Medium | `GetFreeDiskSpace` preflight; `insufficientDiskSpace` error before starting |
| Decrypted personal data handling | High | Decrypted bytes only to user-specified `--out`/stdout; password never persisted or logged; documented in `SECURITY.md` |

## 9. Sub-Project Breakdown (for the plan)

Build order within SP2, each a usable increment:

1. **BackupStore state machine (§4.1) + MobileBackup2Session + `backup create` (unencrypted) + structural verify** — the riskiest protocol *and* the integrity guarantee together, since `create` is only correct if it writes a clone and promotes on verify. Ends with a real backup on disk, verified, with the previous generation provably safe across an interrupted run (test: kill mid-backup, assert `current` unchanged).
2. **ManifestReader + `backup list` / `backup browse`** — read/enumerate what we captured.
3. **Keybag + BackupDecryptor + `backup verify --level crypto` + `backup extract`** — the crypto, fixture-driven (synthetic + real-but-clean).
4. **EncryptionControl + `backup encryption status|enable|disable|rotate` + create-time nudge** — device encryption management with role-distinct passwords.
5. **`verify --level readability`** — the minimal SP3 hand-off check (key DBs decrypt + open as SQLite with core tables; no parsing).

## 10. Explicitly Out of Scope (deferred, with destinations)

- **Restore** → SP5 (safety-first design).
- **Datastore parsers / exports** (sms.db→PDF, contacts→vCard, etc.) → SP3. SP2 stops at *decrypted bytes on demand*; SP3 interprets them.
- **Snapshots / versioned history** → later product sub-project (layout is ready for it).
- **Scheduled/automatic wireless backups** → SP6+ (depends on Wi-Fi hardening, still blocked per SP1 findings).
- **WhatsApp and other app-specific schemas** → SP3+ (highest maintenance burden; not foundational).

## 11. Open Questions

None — the six shaping decisions in §2 (MB2 native, manage+nudge encryption, full keybag+extract, rolling versioning-ready history, clone-and-promote integrity, MobileSync-compatible storage; restore out of scope) are all locked.
