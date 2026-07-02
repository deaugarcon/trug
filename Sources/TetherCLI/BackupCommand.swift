import ArgumentParser
import Foundation
import BackupCore
import DeviceCore

struct Backup: ParsableCommand {
    static let configuration = CommandConfiguration(
        abstract: "Create, inspect, and verify device backups.",
        subcommands: [List.self, Browse.self, Create.self, Verify.self, Extract.self, Inspect.self, Export.self, Encryption.self])

    struct List: ParsableCommand {
        static let configuration = CommandConfiguration(abstract: "List backups in the store.")
        @Flag(name: .long, help: "Output JSON instead of a table.")
        var json = false

        // run() is intentionally non-throwing — exitReporting handles engine errors
        // with domain-specific exit codes. Do not convert to `throws`.
        func run() {
            do {
                let store = BackupStore(root: BackupStore.defaultRoot)
                let summaries = try store.listSummaries()
                if json {
                    try printJSON(summaries)
                } else if summaries.isEmpty {
                    print("No backups found.")
                } else {
                    print(TextTable(header: ["UDID", "STATE", "ENCRYPTED", "iOS", "NAME"],
                                    rows: summaries.map {
                                        [$0.id.udid, $0.state.rawValue,
                                         $0.isEncrypted ? "yes" : "no",
                                         $0.productVersion, $0.deviceName]
                                    }).rendered())
                }
            } catch { exitReporting(error) }
        }
    }

    struct Browse: ParsableCommand {
        static let configuration = CommandConfiguration(
            abstract: "List files in a backup, optionally limited to one domain.")
        @Argument(help: "Backup UDID.") var udid: String
        @Option(name: .long, help: "Limit to one domain.") var domain: String?
        @Flag(name: .long, help: "Output JSON instead of a table.") var json = false

        // run() is intentionally non-throwing — exitReporting handles engine errors
        // with domain-specific exit codes. Do not convert to `throws`.
        func run() {
            do {
                let store = BackupStore(root: BackupStore.defaultRoot)
                guard let dir = try store.currentBackupDirectory(for: BackupID(udid: udid)) else {
                    throw VerifyError.backupNotFound(BackupID(udid: udid))
                }
                // Encryption-aware open (checkpoint C run 3): an encrypted backup's Manifest.db is
                // ciphertext, so browsing it through the keybag-less reader hit the not-a-database lie
                // (and the caught error still let the command exit 0). Decrypt via the shared seam; no
                // password -> passwordRequired (exit 2), never the corruption lie.
                // LAZY (Task 14 part D): `open` takes the password as @autoclosure, so PasswordInput.read()
                // is invoked ONLY if the backup is encrypted — browsing a PLAINTEXT backup never prompts.
                let reader = try ManifestReader.open(backupDir: dir.appendingPathComponent(udid),
                                                     udid: udid, password: PasswordInput.read())
                let files = try domain.map { try reader.files(inDomain: $0) } ?? reader.allFiles()
                if json {
                    try printJSON(files.map { ["domain": $0.domain, "path": $0.relativePath] })
                } else if files.isEmpty {
                    print("No files.")
                } else {
                    print(TextTable(header: ["DOMAIN", "PATH"],
                                    rows: files.prefix(1000).map { [$0.domain, $0.relativePath] })
                          .rendered())
                    if files.count > 1000 {
                        print("… \(files.count - 1000) more (use --json for all)")
                    }
                }
            } catch { exitReporting(error) }
        }
    }

    struct Create: ParsableCommand {
        static let configuration = CommandConfiguration(abstract: "Create a backup of a connected device.")
        @Option(name: .long, help: "Target device UDID (optional if exactly one device).")
        var udid: String?
        @Flag(name: .long, help: "Force a full backup instead of incremental.")
        var full = false
        @Option(name: .customLong("verify-level"), help: "structural (default) or crypto.")
        var verifyLevel: String = "structural"

        // run() is intentionally non-throwing — exitReporting handles engine errors
        // with domain-specific exit codes. Do not convert to `throws`.
        func run() {
            do {
                let target = try resolveUDID(udid, includeNetwork: false)
                let store = BackupStore(root: BackupStore.defaultRoot)
                let id = BackupID(udid: target)

                // ONE lockdownd status read, reused for BOTH the plaintext nudge and the WP6.1
                // encryption preflight (Odb R3): two reads could disagree on a state flip and waste a
                // round-trip. `?? false` is the Q2 FAIL-OPEN: a transient status-read failure degrades
                // to "no preflight" — NOT a hard abort of a legitimate backup — and the post-transfer
                // retry below is the backstop (so a wrongly-skipped preflight becomes one-transfer-then
                // -up-to-3-retries, never one-transfer-one-attempt). The nudge and preflight are
                // mutually exclusive by construction: a device is either encrypted-needs-preflight or
                // plaintext-needs-nudge.
                let willEncrypt = (try? EncryptionControl().status(udid: target)) ?? false
                if !willEncrypt {
                    FileHandle.standardError.write(Data(
                        "WARNING: this device's backups are NOT encrypted. Health, Keychain, Wi-Fi passwords, and call history will be missing.\nRun `trug backup encryption enable` to protect them.\n".utf8))
                }

                // WP6.1 PREFLIGHT (F-E1/F-E3, checkpoint-E): resolve the encrypted-backup password
                // BEFORE the ~40min/75GB transfer instead of after it. The decision is the pure
                // `CreatePasswordFlow.decide` guard; env is checked BEFORE the TTY so the supported
                // `TRUG_BACKUP_PASSWORD`-in-CI path still works on a non-TTY (design note #3). The
                // resolved value is held IN MEMORY ONLY (Odb C1 — never env/disk/Keychain/logs) and
                // carried to the FIRST post-transfer verify (A1), so the happy path is one entry.
                // NOTE the rotation nuance: this is RESOLVE only, NO pre-transfer keybag validation —
                // validating the typed password against the cloned (possibly stale) `current` keybag
                // would reject a correct NEW password after a device rotation (Odb F-E1). Authoritative
                // validation stays post-transfer, against the freshly transferred keybag.
                var resolvedPassword: String?
                switch CreatePasswordFlow.decide(willEncrypt: willEncrypt,
                                                 envPresent: PasswordInput.backupPasswordEnvPresent(),
                                                 isTTY: PasswordInput.stdinIsTTY()) {
                case .proceedNoPreflight:
                    resolvedPassword = nil                      // plaintext: verify never pulls it (F2)
                case .proceedWithEnv:
                    resolvedPassword = PasswordInput.read()     // env-first single authoritative value
                case .promptDoubleEntry:
                    resolvedPassword = try PasswordInput.readNewBackupPasswordDoubleEntry()
                case .failFast:
                    // F-E3: encrypted, no env, no TTY — there is no way to resolve a password, so abort
                    // BEFORE any clone/transfer. `passwordRequired` is the user-input (exit-2) class
                    // and its recovery already says "Set TRUG_BACKUP_PASSWORD" — the actionable
                    // fail-fast message (Odb R2), distinct from the retry-exhausted wrong-password story.
                    throw VerifyError.passwordRequired(udid: target)
                }

                // Disk-space preflight BEFORE beginStaging: beginStaging clones `current` first,
                // and on a non-APFS volume that deep copy can fill the disk before the MB2 loop
                // ever negotiates free space with the device (WP1 carry-forward, item 3).
                try store.preflightDiskSpace(for: id)

                let staging = try store.beginStaging(for: id)
                let conn = try DeviceConnection(udid: target)
                let session = MobileBackup2Session(connection: conn)
                // §4.1 integrity glue: a thrown backup marks staging failed and never promotes;
                // promote happens ONLY after a passing verify (else markFailed). Mirrors the
                // gated test's shape exactly (wp2.baton carry-forward (a)).
                do {
                    try session.backup(options: BackupOptions(udid: target, full: full),
                                       into: staging.directory) { progress in
                        FileHandle.standardError.write(Data("\(progress)\n".utf8))
                    }
                } catch {
                    store.markFailed(staging)
                    throw error
                }

                let level = VerifyLevel(rawValue: verifyLevel) ?? .structural
                // §4.1 finalize: verify, then promote on pass — and markFailed on ANY other outcome
                // (a thrown verify/promote OR a failed report), exactly once. Checkpoint B proved a
                // thrown verify previously escaped here with the staging left "in-progress".
                //
                // WP6.1 RETRY (F-E2, option (ii) — binding, artifact CRITICAL SEAM CORRECTION): the
                // bounded retry IS the BODY of this `verifyPassed` closure — NOT a wrapper around
                // `finalize`. `finalize` runs its single `markFailed` on the FIRST throw that escapes
                // this closure, so a wrapper around `finalize` would catch `wrongPassword` only AFTER
                // the staging is already dead (the too-late variant that re-creates the bug). By being
                // the closure body, `verifyWithRetry` re-prompts and re-verifies IN-PLACE and lets a
                // throw escape ONLY after the 3-attempt budget is exhausted — so `finalize` sees exactly
                // ONE outcome: a clean `true` (promote) or one final throw (one markFailed → exit 2).
                // The §4.1 gate's first-escaping-throw semantics are byte-untouched (Odb R4).
                //
                // Attempt #1 uses the preflight-carried password (one happy-path entry, A1); on a
                // wrong/empty-password verify it re-prompts (no env — Q4) and re-verifies, up to 3 TOTAL
                // verify attempts (Q3). The retry is reachable even when preflight was SKIPPED (Q2
                // backstop): `initial` falls back to the lazy `PasswordInput.read()` (env-or-prompt at
                // verify time), so a fail-open status read still degrades to one-transfer-then-retries.
                //
                // LAZY password (surviving F2): `initial` is `@autoclosure` and is forwarded to the
                // verifier's own `@autoclosure` `password:`, so on a PLAINTEXT backup the closure is
                // never pulled — a plaintext create+verify still never prompts, at any level.
                try store.finalize(staging) {
                    try CreatePasswordFlow.verifyWithRetry(
                        maxAttempts: 3,
                        initial: resolvedPassword ?? PasswordInput.read(),
                        prompt: { PasswordInput.readBackupPasswordRetry() },
                        verify: { passwordSource in
                            try BackupVerifier().verify(
                                backupDir: staging.directory, udid: target,
                                level: level, password: passwordSource()).passed
                        })
                }
                print("Backup complete and verified (\(level.rawValue)).")
            } catch { exitReporting(error) }
        }
    }

    struct Verify: ParsableCommand {
        static let configuration = CommandConfiguration(abstract: "Verify an existing backup.")
        @Argument(help: "Backup UDID.") var udid: String
        @Option(name: .long, help: "structural | crypto | readability") var level: String = "structural"
        @Flag(name: .long, help: "Output JSON instead of a table.") var json = false

        // run() is intentionally non-throwing — exitReporting handles engine errors
        // with domain-specific exit codes. Do not convert to `throws`.
        func run() {
            do {
                let store = BackupStore(root: BackupStore.defaultRoot)
                guard let dir = try store.currentBackupDirectory(for: BackupID(udid: udid)) else {
                    throw VerifyError.backupNotFound(BackupID(udid: udid))
                }
                let lvl = VerifyLevel(rawValue: level) ?? .structural
                // LAZY password (Task 14 part D): `verify` takes the password as @autoclosure, so
                // PasswordInput.read() fires ONLY when the verifier actually pulls it — never on a
                // PLAINTEXT backup, at ANY level. structural/crypto pull it only past their encryption
                // gate; readability pulls it only on its encrypted bytes-source branch (a plaintext
                // backup reads each key DB's shard directly — wp6 scope ruling). So verifying a plaintext
                // backup with no env password never prompts/hangs at any level.
                let report = try BackupVerifier().verify(backupDir: dir, udid: udid, level: lvl,
                                                         password: PasswordInput.read())
                if json {
                    try printJSON(report)
                } else {
                    print("\(report.level): \(report.passed ? "PASS" : "FAIL") (\(report.filesChecked) files checked)")
                    // Mark severity so a note on a PASS-with-notes report reads as informational,
                    // not as a failure the user must act on (WP4.2 / C4).
                    for finding in report.findings {
                        let tag = finding.severity == .note ? "note" : "fail"
                        print("  - [\(tag)] \(finding.path): \(finding.problem)")
                    }
                }
                if !report.passed { Foundation.exit(ExitCode.verificationFailed) }
            } catch { exitReporting(error) }
        }
    }

    struct Extract: ParsableCommand {
        static let configuration = CommandConfiguration(abstract: "Extract one file from a backup.")
        @Argument(help: "Backup UDID.") var udid: String
        @Argument(help: "Domain, e.g. RootDomain.") var domain: String
        @Argument(help: "Relative path within the domain.") var path: String
        @Option(name: .long, help: "Output file.") var out: String
        @Flag(name: .long, help: "Overwrite the output file if it already exists.") var force = false

        // run() is intentionally non-throwing — exitReporting handles engine errors
        // with domain-specific exit codes. Do not convert to `throws`.
        func run() {
            do {
                let outURL = URL(fileURLWithPath: out)
                // Refuse to clobber an existing file unless --force: extracted bytes are sensitive
                // (decrypted sms.db etc.) and overwrite is irreversible (Odb F4).
                if !force, FileManager.default.fileExists(atPath: outURL.path) {
                    throw ExtractError.outputExists(out)
                }
                let store = BackupStore(root: BackupStore.defaultRoot)
                guard let dir = try store.currentBackupDirectory(for: BackupID(udid: udid)) else {
                    throw VerifyError.backupNotFound(BackupID(udid: udid))
                }
                let data = try BackupExtractor().extract(udidDir: dir.appendingPathComponent(udid),
                                                         domain: domain, path: path,
                                                         password: PasswordInput.read())
                // Write 0600 through the shared guarded writer: decrypted backup plaintext must not be
                // world-readable (Odb F4). The writer lstat-guards the path so a --force --out that
                // names a DIRECTORY is refused (never recursively deleted) and a symlink --out is never
                // followed off-target (Codex A3, High). See Backup.writeGuardedFile.
                try Backup.writeGuardedFile(data, to: out, force: force)
                print("Extracted \(domain)/\(path) → \(out) (\(data.count) bytes).")
            } catch { exitReporting(error) }
        }
    }

    /// SP3 WP2 — `inspect`: a READ-ONLY, truncated/redacted preview of one store (messages | contacts).
    /// Reuses the gated WP1 `BackupRowReader` byte-for-byte; the privacy-critical truncation + masking
    /// lives entirely in the PURE `InspectRedaction` renderer (the SOLE redaction path for both table
    /// and `--json`, §10.2). The command name IS the read consent (§5.4); no durable artifact is
    /// written (no `--out`, no `createFile`/`write` — Invariant P4). `PasswordInput.read()` is
    /// forwarded DIRECTLY as the reader's `@autoclosure` so a plaintext inspect never prompts (§4).
    struct Inspect: ParsableCommand {
        static let configuration = CommandConfiguration(
            abstract: "Preview one store (messages | contacts | calls | notes) — truncated and redacted, read-only.")

        /// The in-scope stores (§3, SP3.1 §2.1). A parsed enum makes an out-of-scope store
        /// unrepresentable past parse — an unrecognized value is an ArgumentParser usage error, never
        /// an engine error and never an `OutputFormat.swift` exit-code edit (R2).
        enum Store: String, ExpressibleByArgument, CaseIterable {
            case messages, contacts, calls, notes
        }

        @Argument(help: "Backup UDID.") var udid: String
        @Argument(help: "Store to preview: messages | contacts | calls | notes.") var store: Store
        @Flag(name: .long, help: "Output JSON instead of a table.") var json = false
        @Option(name: .long, help: "Max rows to preview (SQL-capped). Default 20.") var limit: Int = 20

        /// HOME of the `--limit` non-negativity contract (constraint b): a negative `--limit` is
        /// rejected at PARSE, so it NEVER reaches the reader's `n >= 0` precondition (which would
        /// mislabel a user typo as a corrupt backup, exit 7). The literal default (20) is itself
        /// non-negative, so the default path can never carry a negative.
        func validate() throws {
            guard limit >= 0 else {
                throw ValidationError("--limit must be non-negative.")
            }
        }

        // run() is intentionally non-throwing — exitReporting handles engine errors
        // with domain-specific exit codes. Do not convert to `throws`.
        func run() {
            do {
                let backupStore = BackupStore(root: BackupStore.defaultRoot)
                guard let dir = try backupStore.currentBackupDirectory(for: BackupID(udid: udid)) else {
                    throw VerifyError.backupNotFound(BackupID(udid: udid))
                }
                let udidDir = dir.appendingPathComponent(udid)
                let reader = BackupRowReader()
                switch store {
                case .messages:
                    // PasswordInput.read() passed DIRECTLY as the @autoclosure (never bound to a
                    // local) so a plaintext inspect never evaluates it — byte-identical to Browse.
                    let rows = try reader.messages(udidDir: udidDir,
                                                   password: PasswordInput.read(), limit: limit)
                    if json {
                        try printJSON(InspectRedaction.messageJSON(rows, limit: limit))
                    } else {
                        renderTable(InspectRedaction.messageTable(rows, limit: limit),
                                    shown: rows.count)
                    }
                case .contacts:
                    let rows = try reader.contacts(udidDir: udidDir,
                                                   password: PasswordInput.read(), limit: limit)
                    if json {
                        try printJSON(InspectRedaction.contactJSON(rows, limit: limit))
                    } else {
                        renderTable(InspectRedaction.contactTable(rows, limit: limit),
                                    shown: rows.count)
                    }
                case .calls:
                    let rows = try reader.calls(udidDir: udidDir,
                                                password: PasswordInput.read(), limit: limit)
                    if json {
                        try printJSON(InspectRedaction.callJSON(rows, limit: limit))
                    } else {
                        renderTable(InspectRedaction.callTable(rows, limit: limit),
                                    shown: rows.count)
                    }
                case .notes:
                    let rows = try reader.notes(udidDir: udidDir,
                                                password: PasswordInput.read(), limit: limit)
                    if json {
                        try printJSON(InspectRedaction.noteJSON(rows, limit: limit))
                    } else {
                        renderTable(InspectRedaction.noteTable(rows, limit: limit),
                                    shown: rows.count)
                    }
                }
            } catch { exitReporting(error) }
        }

        /// Prints the redacted table, plus the export-pointing footer ONLY when the returned count
        /// equals the cap (more rows MAY exist; M2 — no fabricated N).
        private func renderTable(_ table: TextTable, shown: Int) {
            print(table.rendered())
            if let footer = InspectRedaction.moreRowsFooter(shown: shown, cap: limit) {
                print(footer)
            }
        }
    }

    /// SP3 WP3 — `export`: the SOLE disk-write path for SP3 row data (Invariant P4). Given a UDID, a
    /// store selector, and a REQUIRED `--out` path, it decrypts-then-opens via the gated WP1
    /// `BackupRowReader` with `limit: nil` (the FULL store), wraps the FULL UNMASKED rows in the §10.3
    /// `ExportEnvelope`, and writes structured JSON at mode `0600`, no-clobber unless `--force` —
    /// mirroring `Extract`'s discipline byte-for-byte (`--out`/`--force`/no-clobber/0600/`ExtractError`)
    /// by sharing the ONE guarded writer, `Backup.writeGuardedFile`. export is the INVERSE of inspect: it does NOT route through
    /// `InspectRedaction` (masking is a PREVIEW property; export is the explicit full-data path). The
    /// command name + the explicit `--out` path ARE the consent. `PasswordInput.read()` is forwarded
    /// DIRECTLY as the reader's `@autoclosure`, so a plaintext export never prompts (§4).
    struct Export: ParsableCommand {
        static let configuration = CommandConfiguration(
            abstract: "Export one store (messages | contacts | calls | notes) as JSON (default) or CSV — full and unmasked.",
            discussion: """
                Scope: messages, contacts, and calls export their full LOCKED field set. `notes` is a \
                title/metadata PREVIEW — title, snippet, created, modified, and folder; the note BODY is \
                NOT included in schema_version 1 (a planned follow-on, SP3.2, adds the decoded body). So \
                "full and unmasked" means every field the store exposes at v1, which for notes excludes \
                the body.
                """)

        /// The in-scope stores (§3, SP3.1 §2.1). Its OWN enum (a duplicate of `Inspect.Store`, odb
        /// OI2): the gated `Inspect.Store` is left byte-untouched so the diff stays strictly additive.
        /// The grammar (`messages | contacts | calls | notes`, positional) is identical either way. A
        /// parsed enum makes an out-of-scope store unrepresentable past parse — an unrecognized value
        /// is an ArgumentParser usage error, never an engine error and never an `OutputFormat.swift` exit edit.
        enum Store: String, ExpressibleByArgument, CaseIterable {
            case messages, contacts, calls, notes
        }

        /// The output format (§5.1). `json` (default) wraps rows in the `ExportEnvelope`; `csv` writes a
        /// flat RFC-4180 table with NO envelope. EXPORT-ONLY — `inspect` never gains `--format`. A parsed
        /// enum makes an out-of-scope format an ArgumentParser usage error, never an engine exit edit.
        enum Format: String, ExpressibleByArgument, CaseIterable {
            case json, csv
        }

        @Argument(help: "Backup UDID.") var udid: String
        @Argument(help: "Store to export: messages | contacts | calls | notes (notes = title/metadata preview; note body NOT included in v1, see SP3.2).") var store: Store
        @Option(name: .long, help: "Output file.") var out: String
        @Flag(name: .long, help: "Overwrite the output file if it already exists.") var force = false
        @Option(name: .long, help: """
            Output format: json (default) or csv. CSV neutralizes any field beginning with =, +, -, @, \
            or a tab/CR/LF by prefixing it with a ' (an apostrophe) to prevent spreadsheet formula \
            injection (K6) — so a +-leading phone becomes '+…; this is intentional. JSON stays lossless.
            """)
        var format: Format = .json

        // run() is intentionally non-throwing — exitReporting handles engine errors
        // with domain-specific exit codes. Do not convert to `throws`.
        func run() {
            do {
                // No-clobber pre-check FIRST, BEFORE the (expensive) full-store read: a refused export
                // must NOT decrypt a ~369MB store just to refuse the write (fail-fast, mirroring
                // Extract). The authoritative guard is Backup.writeGuardedFile (reached via writeGuarded);
                // performing this fast pre-check here keeps the read off the refusal path. Decrypted row
                // data is sensitive and overwrite is irreversible (Odb F4).
                if !force, FileManager.default.fileExists(atPath: out) {
                    throw ExtractError.outputExists(out)
                }
                let backupStore = BackupStore(root: BackupStore.defaultRoot)
                guard let dir = try backupStore.currentBackupDirectory(for: BackupID(udid: udid)) else {
                    throw VerifyError.backupNotFound(BackupID(udid: udid))
                }
                let udidDir = dir.appendingPathComponent(udid)
                let reader = BackupRowReader()
                // PasswordInput.read() passed DIRECTLY as the @autoclosure (never bound to a local) so
                // a plaintext export never evaluates it — byte-identical to Inspect/Browse. limit: nil =
                // the FULL store (no SQL cap — export is the full-data path, P4). Each case reads its row
                // shape, then `emit` routes json/csv through the one shared 0600 write core + prints the
                // §9-safe count+path line.
                switch store {
                case .messages:
                    let rows = try reader.messages(udidDir: udidDir,
                                                   password: PasswordInput.read(), limit: nil)
                    try Self.emit(rows, store: store.rawValue, format: format, to: out, force: force)
                case .contacts:
                    let rows = try reader.contacts(udidDir: udidDir,
                                                   password: PasswordInput.read(), limit: nil)
                    try Self.emit(rows, store: store.rawValue, format: format, to: out, force: force)
                case .calls:
                    let rows = try reader.calls(udidDir: udidDir,
                                                password: PasswordInput.read(), limit: nil)
                    try Self.emit(rows, store: store.rawValue, format: format, to: out, force: force)
                case .notes:
                    let rows = try reader.notes(udidDir: udidDir,
                                                password: PasswordInput.read(), limit: nil)
                    try Self.emit(rows, store: store.rawValue, format: format, to: out, force: force)
                }
            } catch { exitReporting(error) }
        }

        /// Routes the (full, unmasked) rows to `--format` and prints the §9-safe count+path line. ONE
        /// generic seam over all four stores: `json` wraps in the `ExportEnvelope` (byte-stable — the
        /// JSON path is unchanged); `csv` emits the flat RFC-4180/K6 table (NO envelope, §5.4). Both go
        /// through the SAME `writeGuarded` 0600 disk-write core (one P4 surface). `OutputFormat.swift`
        /// exit codes are untouched — an unknown `--format` is an ArgumentParser usage error, not an
        /// engine exit. `static` so it is unit-testable without driving `run()` (which resolves
        /// `.defaultRoot`).
        static func emit<Row: Encodable & CSVRow>(
            _ rows: [Row], store: String, format: Format, to out: String, force: Bool
        ) throws {
            switch format {
            case .json:
                try writeJSON(ExportEnvelope(store: store, rows: rows), to: out, force: force)
            case .csv:
                try writeCSV(header: Row.csvHeader, rows: rows.map(\.csvFields), to: out, force: force)
            }
            // §9 evidence rule: report the COUNT + the path ONLY, NEVER row content.
            print("Exported \(rows.count) \(store) rows → \(out)")
        }

        /// Encodes the envelope to pretty/sorted JSON FIRST (an encode failure writes nothing), then
        /// writes it through the shared `writeGuarded` core. The `(_ envelope:to:force:)` signature and
        /// the `JSONEncoder(.prettyPrinted,.sortedKeys)` config are PRESERVED byte-for-byte so the JSON
        /// path stays byte-stable and the existing `ExportTests` (G1/G3–G9) remain the regression net.
        static func writeJSON(_ envelope: some Encodable, to out: String, force: Bool) throws {
            let encoder = JSONEncoder()
            encoder.outputFormatting = [.prettyPrinted, .sortedKeys]
            let data = try encoder.encode(envelope)   // encode FIRST — a failure writes nothing
            try writeGuarded(data, to: out, force: force)
        }

        /// Encodes the flat CSV (header + K6-neutralized/RFC-4180 rows, CRLF, UTF-8 no BOM) and writes
        /// it through the SAME `writeGuarded` core as JSON — so CSV is NOT a second disk-write path
        /// (P4). No `ExportEnvelope`, no `schema_version`/`count` (§5.4).
        static func writeCSV(header: [String], rows: [[String?]], to out: String, force: Bool) throws {
            try writeGuarded(CSVEncoder.encode(header: header, rows: rows), to: out, force: force)
        }

        /// The single P4 disk-write core shared by JSON and CSV — it hands the encoded bytes to the ONE
        /// guarded, symlink-safe, file-ONLY writer `Backup.writeGuardedFile`, which owns the no-clobber /
        /// directory-reject / symlink-no-follow guard and the atomic 0600 write (so `export` and
        /// `extract` cannot drift). The caller ENCODES first, so a payload-encode failure never reaches
        /// disk. One guard = one P4 surface for both formats.
        static func writeGuarded(_ data: Data, to out: String, force: Bool) throws {
            try Backup.writeGuardedFile(data, to: out, force: force)
        }
    }

    /// Manage device backup encryption via MB2 ChangePassword (Task 14). Each subcommand reads its
    /// password lazily through PasswordInput (env first, else a no-echo prompt) and is wired to the
    /// audited EncryptionControl — the device must confirm the change (on-device passcode on iOS 13+)
    /// before any subcommand reports success.
    struct Encryption: ParsableCommand {
        static let configuration = CommandConfiguration(
            abstract: "Manage device backup encryption.",
            subcommands: [Status.self, Enable.self, Disable.self, Rotate.self])

        struct Status: ParsableCommand {
            static let configuration = CommandConfiguration(abstract: "Show whether backups are encrypted.")
            @Option(name: .long, help: "Target device UDID (optional if exactly one device).")
            var udid: String?
            func run() {
                do {
                    let target = try resolveUDID(udid, includeNetwork: false)
                    print(try EncryptionControl().status(udid: target) ? "encrypted" : "not encrypted")
                } catch { exitReporting(error) }
            }
        }

        struct Enable: ParsableCommand {
            static let configuration = CommandConfiguration(abstract: "Enable backup encryption with a new password.")
            @Option(name: .long, help: "Target device UDID (optional if exactly one device).")
            var udid: String?
            func run() {
                do {
                    let target = try resolveUDID(udid, includeNetwork: false)
                    // WP6.2 F-E5: the NEW password is resolved with bounded double-entry confirmation
                    // (env-first single-source, interactive double-entry) BEFORE the engine call. The
                    // resolver throws on a budget-exhausted mismatch; resolved eagerly because the
                    // engine's `new:` is a non-throwing @autoclosure (kept byte-untouched).
                    let new = try PasswordInput.readNewWithConfirmation()
                    try EncryptionControl().enable(new: new, udid: target)
                    print("Backup encryption enabled.")
                } catch { exitReporting(error) }
            }
        }

        struct Disable: ParsableCommand {
            static let configuration = CommandConfiguration(abstract: "Disable backup encryption (needs the current password).")
            @Option(name: .long, help: "Target device UDID (optional if exactly one device).")
            var udid: String?
            func run() {
                do {
                    let target = try resolveUDID(udid, includeNetwork: false)
                    try EncryptionControl().disable(current: PasswordInput.read(), udid: target)
                    print("Backup encryption disabled.")
                } catch { exitReporting(error) }
            }
        }

        struct Rotate: ParsableCommand {
            static let configuration = CommandConfiguration(abstract: "Change the backup password (old then new).")
            @Option(name: .long, help: "Target device UDID (optional if exactly one device).")
            var udid: String?
            func run() {
                do {
                    let target = try resolveUDID(udid, includeNetwork: false)
                    // WP6.2 F-E5: only the NEW password gets double-entry confirmation; the OLD password
                    // stays a single `read()` (entering an existing password needs no confirmation — the
                    // rotate itself is the check). Read OLD first, then NEW, so the prompt order matches
                    // "old then new" — OLD ("Backup password: ") then the distinct NEW prompts ("New
                    // backup password: " / "Confirm new backup password: "), three unambiguous reads.
                    // Resolved eagerly (the engine's `new:` is a non-throwing @autoclosure, kept
                    // byte-untouched); the resolver throws on a budget-exhausted mismatch.
                    let old = PasswordInput.read()
                    let new = try PasswordInput.readNewWithConfirmation()
                    try EncryptionControl().rotate(old: old, new: new, udid: target)
                    print("Backup password rotated.")
                } catch { exitReporting(error) }
            }
        }
    }
}

extension Backup {
    /// The ONE guarded, symlink-safe, file-ONLY writer shared by `extract` and `export` (SP3 disk
    /// discipline). It replaces the former `removeItem`-then-`createFile` pattern which — with
    /// `--force` — let a `--out` naming an existing DIRECTORY be recursively deleted (Codex A3, High),
    /// and let `fileExists`/`createFile` FOLLOW a symlink to write off-target. Order (LOCKED):
    ///   1. `lstat` the final path — existence is decided on the ENTRY itself, never a symlink target;
    ///   2. an existing DIRECTORY → refuse regardless of `--force` (`--force` overwrites a file, never a
    ///      tree; the directory and its contents stay intact), reusing `ExtractError.outputExists`;
    ///   3. an existing entry (file OR symlink, incl. a dangling one) with `force == false` → no-clobber
    ///      `ExtractError.outputExists`; the entry is never followed or touched;
    ///   4. an existing entry with `force == true` → `unlink(2)` the ENTRY itself — `unlink` never
    ///      follows a symlink, so a symlink's TARGET is left intact;
    ///   5. `open(O_WRONLY|O_CREAT|O_EXCL|O_NOFOLLOW, 0600)` (exclusive + non-following), pin `0600`
    ///      exactly with `fchmod` (umask-independent), then write ALL bytes (looping on partials/EINTR)
    ///      and `close`. Any open/write/close failure → `ExtractError.writeFailed` and NO partial
    ///      readable 0600 stub survives (the created file is unlinked on failure) — all-or-nothing.
    /// `static` + internal so both nested call sites reach it and it is unit-testable via `@testable`.
    static func writeGuardedFile(_ data: Data, to out: String, force: Bool) throws {
        // 1. lstat — never follow a symlink; the ENTRY at `out` decides existence.
        var info = stat()
        if lstat(out, &info) == 0 {
            // 2. a directory is refused regardless of --force.
            if (info.st_mode & S_IFMT) == S_IFDIR {
                throw ExtractError.outputExists(out)
            }
            // 3. no-clobber unless --force (entry is a file OR a symlink, including dangling).
            guard force else { throw ExtractError.outputExists(out) }
            // 4. --force: remove the entry ITSELF; unlink(2) does not follow a symlink.
            guard unlink(out) == 0 else { throw ExtractError.writeFailed(out) }
        }
        // 5. exclusive, non-following create at 0600, then an all-or-nothing write.
        let fd = open(out, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW, 0o600)
        guard fd >= 0 else { throw ExtractError.writeFailed(out) }
        _ = fchmod(fd, 0o600)   // pin 0600 exactly, independent of umask
        let wroteAll = data.withUnsafeBytes { (raw: UnsafeRawBufferPointer) -> Bool in
            guard let base = raw.baseAddress, raw.count > 0 else { return true }   // empty payload: 0 bytes
            var offset = 0
            while offset < raw.count {
                let n = write(fd, base + offset, raw.count - offset)
                if n < 0 {
                    if errno == EINTR { continue }   // retry an interrupted syscall
                    return false
                }
                if n == 0 { return false }           // no progress — fail rather than spin
                offset += n
            }
            return true
        }
        let closedOK = (close(fd) == 0)
        guard wroteAll, closedOK else {
            unlink(out)   // no partial, readable 0600 stub survives a failed write/close
            throw ExtractError.writeFailed(out)
        }
    }
}

/// Errors specific to the `extract` CLI surface (engine errors come from BackupCore).
enum ExtractError: Error, LocalizedError {
    case outputExists(String)
    case writeFailed(String)

    var errorDescription: String? {
        switch self {
        case .outputExists(let p): "Output file already exists: \(p)."
        case .writeFailed(let p): "Could not write the output file: \(p)."
        }
    }
    var recoverySuggestion: String? {
        switch self {
        case .outputExists: "Choose a different --out path, or pass --force to overwrite."
        case .writeFailed: "Check the output directory exists and is writable."
        }
    }
}
