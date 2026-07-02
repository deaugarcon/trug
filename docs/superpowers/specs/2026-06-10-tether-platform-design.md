# Tether — Platform Design

**Date:** 2026-06-10 (revised same day: scope narrowed to backup + inspection wedge)
**Status:** Draft for review
**Codename:** Tether (working name; final name chosen before first public release, must not be confusable with the iMazing trademark)

## 1. Vision

A free, open-source **local iPhone backup and inspection tool for macOS**. Not an iMazing clone — the smallest wedge where an open tool is meaningfully better than the commercial incumbents:

1. **Transparent local backups** — backups use a MobileSync-compatible directory schema (the same layout Finder writes), stored under Tether's own folder — documented, verifiable (`tether backup verify`), never a proprietary container. Format-portable: point any MobileSync-compatible tool at the folder and you can walk away from Tether anytime. Note: Tether does **not** write into Apple's canonical `~/Library/Application Support/MobileSync/Backup` location, so backups are portable in format, not auto-discovered by Finder.
2. **Readable exports** — messages, contacts, call logs, notes out of your backups into CSV/JSON/PDF you can actually use.
3. **CLI automation** — every feature scriptable with documented exit codes; cron/launchd-friendly nightly backups.
4. **No license wall** — MIT, free forever, no device-count tiers.

**v1 goals (in priority order)**
- Rock-solid USB device detection and pairing.
- Encrypted backup creation and browsing that never lies about success.
- Readable exports of personal data from those backups.
- Wi-Fi connectivity as a *proof target*: demonstrated working behind an experimental flag, hardened after v1. USB reliability wins every trade-off against it.

**Deferred (explicitly, not abandoned)**
- **Restore** — sequenced after create/browse/export because failure during restore is user-catastrophic. It ships only with its own safety design (preflight checks, explicit confirmation, no silent partial states). See SP5.
- File/photo transfer, app management, scheduled-backup background agent.

**Non-goals**
- Windows/Linux support (macOS only).
- Downloading apps from the App Store (Apple removed this capability industry-wide).
- Music/iTunes library sync.
- Jailbreak tooling or anything requiring exploits.

## 2. Locked Decisions

| Decision | Choice |
|---|---|
| Platform | Native macOS 14+, SwiftUI |
| Protocol layer | `libimobiledevice` + `libplist` + `libusbmuxd` (C), dynamically linked |
| Architecture | CLI-first engine + GUI client over the same core packages |
| Connectivity | USB is the v1 reliability bar; Wi-Fi ships behind an experimental flag as a proof target, hardened post-v1 |
| v1 scope | Backup + inspection: create / browse / verify / export. Restore deferred to SP5; transfer & app management iceboxed |
| Distribution | Open source (MIT for our code); CLI via Homebrew tap; app as signed + notarized DMG with Sparkle auto-updates |
| License posture | MIT for Tether code; LGPL-2.1 dependencies dynamically linked, relinkable, credited in NOTICE |

## 3. System Architecture

```
┌────────────────────┐   ┌────────────────────┐
│  Tether.app        │   │  tether (CLI)      │
│  SwiftUI, macOS 14+│   │  swift-argument-   │
│                    │   │  parser            │
└─────────┬──────────┘   └─────────┬──────────┘
          └──────────┬─────────────┘
              Core engine — SPM packages, no UI imports
┌─────────────────────────────────────────────────────┐
│ DeviceCore    discovery & pairing (USB via usbmuxd; │
│               Wi-Fi via Bonjour, experimental),     │
│               lockdownd sessions, device info       │
│ BackupCore    mobilebackup2: create/browse/verify,  │
│               encrypted-backup keybag handling      │
│ DataKit       parsers over backup artifacts         │
│               (sms.db, contacts, call log, notes)   │
│               → CSV / JSON / PDF exporters          │
└──────────────────────┬──────────────────────────────┘
                libimobiledevice + libplist + libusbmuxd
                (C, dynamically linked — LGPL compliance)
```

Future modules (post-v1, same engine pattern): `RestoreCore` (SP5), `TransferCore`, `AppsCore`, background agent.

### Module responsibilities and dependencies

| Package | Does | Depends on |
|---|---|---|
| `CWrappers` | SPM system-library targets + thin Swift shims over the C libraries; the **only** package that touches C APIs | libimobiledevice et al. |
| `DeviceCore` | Device discovery (USB; Wi-Fi behind flag), pairing records, lockdownd sessions, device info values (model, OS, battery, storage), starting device services; owns the `Device` and `DeviceTransport` abstractions | `CWrappers` |
| `BackupCore` | mobilebackup2 protocol: create backups with progress, Manifest.db browsing, integrity verification, keybag decryption for encrypted backups | `DeviceCore` |
| `DataKit` | Pure parsers over backup artifacts (SQLite/plist fixtures in, structured records out) + CSV/JSON/PDF exporters. **No device dependency** — operates on `BackupCore` output | `BackupCore` (read-only types) |
| `tether` (CLI) | Thin command veneer; every engine feature reachable from the terminal; documented exit codes | all Core packages |
| `Tether.app` | SwiftUI shell; second consumer of the identical engine APIs | all Core packages |

### Design rules

1. **CLI-first contract:** every feature lands as a Core API + CLI command before it gets GUI. The CLI doubles as the integration-test harness against real devices.
2. **No UI imports in Core:** Core packages may not import AppKit/SwiftUI. Enforced by a CI lint step.
3. **Typed errors at the boundary:** C error codes never escape `CWrappers`. Each layer exposes exhaustive Swift error enums with `LocalizedError` recovery suggestions (e.g. `PairingError.trustDialogDismissed` → "Unlock your iPhone and tap Trust").
4. **Async + cancellable:** all long operations are `async`, report progress via `AsyncStream`, and honor task cancellation without corrupting on-disk state.
5. **Transport abstraction:** `DeviceCore` exposes a `DeviceTransport` protocol so unit tests run against a mock transport with recorded protocol exchanges; USB and Wi-Fi are two implementations of the same interface — which is also what keeps Wi-Fi cheap to harden later.
6. **Never lie about success:** a backup either completes and passes structural verification, or it reports exactly what failed. No "completed with warnings" ambiguity. Verification is **tiered**, because each tier proves something different:
   - *structural* — Manifest.db ↔ files on disk agree (presence, sizes). Proves completeness, not decryptability.
   - *crypto* — the keybag unlocks with the supplied password and a sample of protected files decrypts. Proves the backup isn't encrypted garbage.
   - *readability* — DataKit can open the key databases (messages, contacts) extracted from the backup. Proves exportability.
   - *restore preflight* — arrives with SP5; proves restorability claims only to the extent the platform exposes them.
   `tether backup create` exits 0 only after structural verification passes; deeper tiers run on demand via `tether backup verify --level structural|crypto|readability`.

## 4. Sub-Project Decomposition & Build Order

Each sub-project gets its own spec → plan → implementation cycle.

| # | Sub-project | Delivers | Depends on |
|---|---|---|---|
| SP0 | **Foundations** | Repo layout, MIT license + NOTICE, pinned source build of the C libraries (host-arch dylibs for dev/CI; universal arm64+x86_64 + static SSL moves to the SP4 packaging pipeline), GitHub Actions CI | — |
| SP1 | **DeviceCore + `tether devices`** | Reliable USB detection/pairing/info: `tether devices list\|info\|pair`. Wi-Fi proof behind `--experimental-wifi`, defined as: a network lockdownd session is established and `tether devices info` succeeds over Wi-Fi for a USB-paired device — mere Bonjour discovery does not count | SP0 |
| SP2 | **BackupCore + `tether backup`** | Encrypted + unencrypted backup create, browse, verify: `tether backup create\|list\|browse\|verify` | SP1 |
| SP3 | **DataKit + `tether export`** | Messages (with attachments), contacts, call log, notes → CSV/JSON/PDF. **CLI alpha ships here via Homebrew tap** | SP2 |
| SP4 | **GUI v1 → v0.1 DMG release** | SwiftUI app: device sidebar, overview, backup management with progress, export UI; Sparkle; **packaging pipeline owns what SP0 deferred**: universal (arm64 + x86_64) C-dependency builds with static SSL, code signing + notarization; DMG | SP3 |
| SP5 | **Restore (guarded)** | `tether backup restore` + GUI flow, designed safety-first: best-effort preflight report (target device, backup identity, iOS compatibility, estimated payload, destructive vs non-destructive mode, known irreversible effects), explicit typed confirmation, resumable, never silent-partial | SP2 |
| SP6 | **Wi-Fi hardening** | Promote Wi-Fi from experimental flag to supported: reconnection robustness, network lockdownd edge cases, then scheduled wireless backups via LaunchAgent | SP2, SP4 |
| Icebox | TransferCore (files/photos), AppsCore, localization, docs site | Revisit after v0.1 ships and the wedge is validated | — |

## 5. Data Flow Examples

**Nightly automated backup (the CLI wedge):** a user's `launchd` job runs `tether backup create --udid <id> --encrypted`. DeviceCore finds the device over USB, opens a lockdownd session from the stored pairing record; BackupCore streams files into `~/Library/Application Support/Tether/Backups/<udid>/` (MobileSync-compatible layout), then runs structural verification (manifest ↔ disk); exit code 0 only if it passes. `--verify-level crypto` additionally proves the password unlocks the keybag.

**Messages export:** `BackupCore` locates the latest backup → if encrypted, derives keys from the user's backup password via the Manifest keybag → `DataKit` opens the decrypted `sms.db` + attachments → emits structured `Conversation` records → PDF/CSV exporter writes output. No device connection required.

## 6. Error Handling

- Exhaustive error enums per domain (`ConnectionError`, `PairingError`, `BackupError`, `ExportError`), each case carrying context and a recovery suggestion.
- Backups are resumable where the protocol allows (mobilebackup2 supports resuming) and always cancellable without corrupting on-disk state.
- The GUI never shows raw error codes; the CLI exits with documented status codes for scripting.
- Restore (SP5) additionally requires: preflight checks (iOS version compatibility, battery level, free space) and a **best-effort preflight report** — target device, backup identity, estimated payload, destructive vs non-destructive mode, and known irreversible effects. It does not promise to know everything iOS will change; the platform does not expose that. Explicit confirmation is required before any write to the device.

## 7. Testing Strategy

| Layer | Approach |
|---|---|
| Core packages | Swift Testing unit tests against mock `DeviceTransport` with recorded protocol exchanges |
| BackupCore | Verification logic tested against synthetic fixture backups (known-good and deliberately corrupted) with known passwords |
| DataKit | **Synthetic fixtures only**: databases generated by a fixture-builder script, or captured from a dedicated test device seeded with fabricated data — never derived from a real person's device. Golden-file tests for exporters |
| CLI | End-to-end tests gated behind `TETHER_DEVICE_TESTS=1` requiring a real connected device; run manually pre-release, skipped in CI |
| GUI | ViewInspector/snapshot tests for key screens (added in SP4) |
| CI | GitHub Actions macOS runner: build all packages, unit tests, no-UI-imports lint, license/NOTICE check |

## 8. Risks & Constraints

| Risk | Severity | Mitigation |
|---|---|---|
| Apple protocol changes break features each iOS release | High | Track upstream libimobiledevice; pin versions; device-matrix smoke tests before releases; clear messaging when a device's iOS is newer than supported |
| Encrypted-backup keybag crypto is intricate | High | Well-documented by existing open implementations (libimobiledevice's own tooling, MVT); build against fixture backups with known passwords first |
| Restore can brick user data if buggy | High | Deferred to SP5 with its own safety-first design; never ships alongside the first release |
| Wi-Fi pairing requires one initial USB connection (Apple constraint) | Medium | Inherent to platform; Wi-Fi is experimental in v1 anyway; document clearly |
| Wi-Fi reliability (sleep, network changes, flaky lockdownd over TCP) | Medium | Quarantined behind `--experimental-wifi` until SP6 hardening |
| LGPL compliance for shipped dylibs | Low | Dynamic linking, dylibs replaceable in the app bundle, NOTICE file, build scripts published |
| Trademark proximity to "iMazing" | Low | Final name reviewed before v0.1; avoid "amazing"/"mazing" formations |

## 9. Open Questions

None — all v1-shaping decisions are locked in §2. The final product name is intentionally deferred to before the v0.1 release and does not affect architecture.

## 10. Next Step

Write the implementation plan for **SP0 + SP1** (foundations, then reliable `tether devices list|info|pair` over USB against a real iPhone, with the experimental Wi-Fi proof as defined in SP1: network lockdownd session + successful `info`) — the smallest stretch that proves the riskiest plumbing: building/linking the C libraries and talking to a real device.
