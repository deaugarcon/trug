import Foundation
import CWrappers

public struct VerifyReport: Sendable, Codable, Equatable {
    public struct Finding: Sendable, Codable, Equatable {
        /// Whether a finding fails the report or is purely informational. A `hard` finding (a missing
        /// shard, a failed decrypt, an unreadable manifest) sets `passed = false`; a `note` records
        /// something worth surfacing that is NOT a defect — e.g. a file that decrypted cleanly (valid
        /// PKCS7 with the per-file key, itself integrity evidence) but whose plaintext type carries no
        /// recognized signature. Conflating the two false-failed real backups (checkpoint C run 3 / C4).
        public enum Severity: String, Sendable, Codable { case hard, note }
        public let path: String
        public let problem: String
        public let severity: Severity
        public init(path: String, problem: String, severity: Severity = .hard) {
            self.path = path; self.problem = problem; self.severity = severity
        }
    }
    public let level: String
    public let passed: Bool
    public let filesChecked: Int
    public let findings: [Finding]
    public init(level: String, passed: Bool, filesChecked: Int, findings: [Finding]) {
        self.level = level; self.passed = passed; self.filesChecked = filesChecked; self.findings = findings
    }

    /// A report passes when it carries no `hard` findings; informational `note`s do not fail it.
    public static func passing(_ findings: [Finding]) -> Bool {
        !findings.contains { $0.severity == .hard }
    }
}

public enum VerifyLevel: String, Sendable, CaseIterable { case structural, crypto, readability }

public struct BackupVerifier {
    public init() {}

    /// Verifies a promoted/staged backup at the requested level.
    ///
    /// Per the WP2 success division: the MB2 session proves "the protocol completed"; the
    /// verifier proves the snapshot is finished AND the requested integrity level holds. A
    /// backup is only promoted after the chosen level passes.
    /// `password` is `@autoclosure`: it is pulled ONLY when actually needed (Task 14 part D / U_god).
    /// Since `PasswordInput.read()` now PROMPTS interactively, evaluating it eagerly would hang an
    /// unencrypted verify on a password the backup doesn't need. For EVERY level the deferred read is
    /// threaded down and evaluated only after `Manifest.plist` proves the backup encrypted (Codex F2):
    /// `crypto`/`readability` are inherently about encryption, but a PLAINTEXT backup run at one of
    /// those levels must report not-applicable HONESTLY rather than prompt/hang for a password it can
    /// never use. The gate is a plist-only `Manifest.plist` read: structural pulls the password only
    /// once `isManifestEncrypted` proves the Manifest.db itself is ciphertext, while crypto/readability
    /// pull it only once `isBackupEncrypted` (the `IsEncrypted` flag) proves there is file ciphertext to
    /// verify — a backup can encrypt file content with a plaintext manifest, so the two seams differ.
    public func verify(backupDir: URL, udid: String, level: VerifyLevel,
                       password: @autoclosure @escaping () -> String?) throws -> VerifyReport {
        let udidDir = backupDir.appendingPathComponent(udid)
        switch level {
        // Forward the deferred read as a closure so each level pulls it only post-encryption-check.
        case .structural: return try structural(udidDir: udidDir, udid: udid, password: password)
        case .crypto: return try crypto(udidDir: udidDir, password: password)            // Task 11
        case .readability: return try readability(udidDir: udidDir, password: password)  // Task 15
        }
    }

    /// A backup-not-encrypted report for a level whose verification is inherently about ciphertext.
    /// Codex F2: `crypto` proves Decryptability, so a PLAINTEXT backup has no ciphertext to verify and
    /// the honest answer is "not applicable" — NOT a silent crypto PASS (which would falsely claim we
    /// verified ciphertext) and NOT a prompt for a password that can never be used. `passed = true`
    /// because there is no crypto FAILURE; the explicit `note` finding records that the level did not
    /// apply, so a reader is never misled into thinking ciphertext was checked. Only `crypto()` uses
    /// this: `readability` proves Exportability and DOES run its table check on a plaintext backup (wp6
    /// scope ruling / Odb L1), so it has no not-applicable arm.
    private func notEncryptedReport(level: VerifyLevel) -> VerifyReport {
        VerifyReport(level: level.rawValue, passed: true, filesChecked: 0,
                     findings: [.init(path: "(encryption)",
                                      problem: "backup is not encrypted; \(level.rawValue) verification is not applicable",
                                      severity: .note)])
    }

    /// Structural-only entry retained for Device Checkpoint A's gated test. Dispatches to the
    /// same `structural(udidDir:udid:password:)` the level API uses, so both paths share one
    /// implementation. It passes no password: this entry exists for the original plaintext-backup
    /// gated test, where the manifest is never encrypted.
    public func verifyStructural(backupDir: URL, udid: String) throws -> VerifyReport {
        try structural(udidDir: backupDir.appendingPathComponent(udid), udid: udid, password: { nil })
    }

    // MARK: - levels

    /// Row↔shard structural check: every `Files` row must have a present shard of the right size,
    /// the snapshot must be `finished`, and the required plists must exist.
    ///
    /// The `SnapshotState == "finished"` gate is ported from `idevicebackup2.c`'s
    /// `mb2_status_check_snapshot_state` — a half-written snapshot is not promotable. A row whose
    /// `fileID` is not strict hex throws `malformedFileID` from `shardURL`; that throw is recorded
    /// as a finding (never `try?`-skipped — wp3.baton Q5 binding) so a tampered manifest cannot
    /// read as a clean backup with one fewer file.
    private func structural(udidDir: URL, udid: String, password: () -> String?) throws -> VerifyReport {
        var findings: [VerifyReport.Finding] = []

        // (1) Snapshot must be finished — a half-written snapshot is structurally incomplete.
        let status = udidDir.appendingPathComponent("Status.plist")
        if !FileManager.default.fileExists(atPath: status.path) {
            findings.append(.init(path: "Status.plist", problem: "missing"))
        } else if let data = try? Data(contentsOf: status),
                  let dict = PlistBridge.foundationObject(fromXML: data) as? [String: Any] {
            let snapshotState = dict["SnapshotState"] as? String
            if snapshotState != "finished" {
                findings.append(.init(path: "Status.plist",
                                      problem: "SnapshotState is \(snapshotState ?? "absent"), expected finished"))
            }
        } else {
            findings.append(.init(path: "Status.plist", problem: "unreadable"))
        }

        // (2) Every Files row must map to a present shard of the right size.
        //     An unopenable Manifest.db is a structural finding, not an exception — verification
        //     findings are data, so a backup missing its manifest reports clearly rather than trapping.
        //
        //     WP4.2 (Checkpoint C run 1): a real encrypted backup encrypts Manifest.db itself, so
        //     opening it as plaintext SQLite yields SQLITE_NOTADB and the not-a-database lie. Detect
        //     encryption by reading Manifest.plist (IsEncrypted + ManifestKey) — NOT by probing
        //     SQLite — and route through the task-#10 decrypt seam.
        //
        //     The keybag is resolved FIRST, OUTSIDE the open's catch, so its preconditions PROPAGATE
        //     rather than degrade into a finding: an encrypted backup with no password throws
        //     `passwordRequired` (user-input class), and a wrong password throws `KeybagError`
        //     .wrongPassword — neither is the not-a-database / re-create lie. A plaintext backup
        //     resolves to a nil keybag and the in-place open is byte-identical to before. Only a
        //     genuine reader-open failure (corrupt/absent manifest) is caught below as a finding.
        let keybag = try resolveKeybagIfEncrypted(udidDir: udidDir, udid: udid, password: password)
        // ^ password() is pulled inside resolveKeybagIfEncrypted ONLY after the Manifest.plist
        //   encryption check passes — a plaintext backup never evaluates it, so no prompt/hang.
        let reader: ManifestReader
        do {
            reader = try keybag.map { try ManifestReader(backupDir: udidDir, unlockedKeybag: $0) }
                ?? ManifestReader(backupDir: udidDir)
        } catch let error as VerifyError {
            findings.append(.init(path: "Manifest.db",
                                  problem: (error as LocalizedError).errorDescription ?? "manifest unreadable"))
            return VerifyReport(level: "structural", passed: false, filesChecked: 0, findings: findings)
        }
        var checked = 0
        for rec in try reader.allFiles() where rec.isFile {
            checked += 1
            let shard: URL
            do {
                shard = try reader.shardURL(for: rec)
            } catch let error as VerifyError {
                // A malformed/tampered fileID — record it, do not skip the row.
                findings.append(.init(path: "\(rec.domain)/\(rec.relativePath)",
                                      problem: (error as LocalizedError).errorDescription ?? "invalid file id"))
                if findings.count >= 50 { break }
                continue
            }
            if !FileManager.default.fileExists(atPath: shard.path) {
                findings.append(.init(path: "\(rec.domain)/\(rec.relativePath)",
                                      problem: "shard file missing (\(rec.fileID))"))
            }
            if findings.count >= 50 { break }   // cap reported findings
        }

        // (3) Required top-level plists: Status.plist and Manifest.plist ONLY.
        //
        // Info.plist is deliberately NOT required (locked decision §16): the device does not send an
        // Info.plist on a full backup and Tether does not synthesize one, so a structurally perfect
        // backup legitimately has none — checkpoint B run 2 lead-verified 78,610 manifest rows ↔
        // 78,610 shards with no Info.plist. Requiring it (the stale Task 9 pseudocode) failed a
        // correct backup. Manifest.db is required implicitly by the ManifestReader open at (2);
        // Manifest.plist carries BackupKeyBag/IsEncrypted, so its absence is a real defect.
        for name in ["Status.plist", "Manifest.plist"]
        where !FileManager.default.fileExists(atPath: udidDir.appendingPathComponent(name).path) {
            findings.append(.init(path: name, problem: "required plist missing"))
        }

        return VerifyReport(level: "structural", passed: findings.isEmpty, filesChecked: checked, findings: findings)
    }

    /// The unlocked keybag needed to read an encrypted backup's manifest, or `nil` for a plaintext
    /// backup. The caller passes the keybag to the task-#10 keybag-aware `ManifestReader`; a `nil`
    /// result means open the manifest in place.
    ///
    /// Encryption is detected from `Manifest.plist` (`IsEncrypted` true AND a `ManifestKey` blob is
    /// present), read as a plist — never by trying to open the ciphertext as SQLite. The throws here
    /// are user-input preconditions and MUST be raised before any manifest open so they propagate
    /// rather than degrade into a structural finding: an encrypted backup with no usable password
    /// throws `passwordRequired`, and a wrong password throws `KeybagError.wrongPassword` (the keybag
    /// is the authority — task #10 item 4). A plaintext backup returns `nil`.
    private func resolveKeybagIfEncrypted(udidDir: URL, udid: String, password: () -> String?) throws -> UnlockedKeybag? {
        guard isManifestEncrypted(udidDir: udidDir) else { return nil }
        // Only NOW pull the password — the backup is proven encrypted, so an interactive prompt is
        // warranted. A plaintext backup returned above without ever evaluating `password`.
        guard let pw = password(), !pw.isEmpty else {
            throw VerifyError.passwordRequired(udid: udid)
        }
        return try Keybag(tlv: try ManifestReader.backupKeybagTLV(in: udidDir)).unlock(password: pw)
    }

    /// True when `Manifest.plist` marks the backup encrypted AND carries the `ManifestKey` blob that
    /// an encrypted `Manifest.db` requires. Reads the plaintext plist only — it never touches the
    /// (possibly ciphertext) `Manifest.db`, so it is safe to call before deciding how to open it.
    private func isManifestEncrypted(udidDir: URL) -> Bool {
        guard let dict = manifestPlist(udidDir: udidDir) else { return false }
        let isEncrypted = (dict["IsEncrypted"] as? Bool) ?? false
        return isEncrypted && dict["ManifestKey"] is Data
    }

    /// True when `Manifest.plist` marks the BACKUP encrypted (the `IsEncrypted` flag alone). This is a
    /// WEAKER question than `isManifestEncrypted`: a backup can encrypt its file CONTENT while leaving
    /// `Manifest.db` itself in plaintext (no `ManifestKey`), so the file-level crypto/readability checks
    /// have ciphertext to verify even though the manifest opens in place. Used by Codex F2 to decide
    /// whether crypto/readability apply BEFORE pulling the password — a plaintext backup (flag false)
    /// returns the honest not-applicable report; the password is never read.
    private func isBackupEncrypted(udidDir: URL) -> Bool {
        (manifestPlist(udidDir: udidDir)?["IsEncrypted"] as? Bool) ?? false
    }

    /// `Manifest.plist` decoded as a dictionary, or `nil` if absent/unreadable. Reads the plaintext
    /// plist only — never the (possibly ciphertext) `Manifest.db`.
    private func manifestPlist(udidDir: URL) -> [String: Any]? {
        guard let data = try? Data(contentsOf: udidDir.appendingPathComponent("Manifest.plist")) else { return nil }
        return (try? PropertyListSerialization.propertyList(from: data, options: [], format: nil)) as? [String: Any]
    }

    /// Crypto-level verification (spec §4.2): the keybag unlocks with the password, the manifest
    /// opens with the expected tables, and one file per present host-unlockable protection class
    /// decrypts. The Apple backup format carries NO per-file MAC — AES-CBC file content is
    /// unauthenticated — so the structural signature is the only available content-integrity check,
    /// and padding success alone is insufficient: a block-aligned tamper preserving valid PKCS7
    /// decrypts cleanly yet loses its leading magic. A sample chosen as checkable-by-extension that
    /// decrypts to NO recognized signature is therefore a HARD failure (tamper/corruption); a sample
    /// with no type expectation that misses a signature is only a note — a clean PKCS7 unpad is itself
    /// integrity evidence and real JSON/text/unknown files must still pass (Codex F3 / C4).
    ///
    /// A wrong password surfaces as a thrown `KeybagError.wrongPassword` (the keybag refuses to
    /// unlock); a missing password and content-shape problems surface as findings.
    ///
    /// `password` is deferred (Codex F2): encryption is checked FIRST from the plaintext `Manifest.plist`
    /// seam, so a PLAINTEXT backup returns the honest not-applicable report WITHOUT ever pulling the
    /// password — verifying an unencrypted backup at `--level crypto` must not prompt/hang.
    private func crypto(udidDir: URL, password: () -> String?) throws -> VerifyReport {
        guard isBackupEncrypted(udidDir: udidDir) else { return notEncryptedReport(level: .crypto) }
        guard let resolved = try resolveEncryptedReader(udidDir: udidDir, password: password) else {
            return VerifyReport(level: "crypto", passed: false, filesChecked: 0,
                                findings: [.init(path: "(password)", problem: "no password supplied")])
        }
        let keybag = resolved.keybag
        let reader = resolved.reader

        var findings: [VerifyReport.Finding] = []
        let decryptor = BackupDecryptor()
        var checked = 0

        // One sample per host-unlockable protection class, PREFERRING a file whose plaintext type is
        // signature-checkable (a .db/.plist/.png/.jpg by extension) so the per-class assertion is
        // strong; only fall back to an arbitrary file if the class has no checkable candidate (C4 (2)).
        // The `checkableByExtension` flag records WHETHER the chosen sample was such a strong pick —
        // it gates the severity of a no-signature result below (Codex F3).
        for sample in selectCryptoSamples(reader: reader, keybag: keybag) {
            let keyed = sample.record
            let protectionClass = keyed.protectionClass ?? 0
            checked += 1
            let path = "\(keyed.domain)/\(keyed.relativePath)"

            let shard: URL
            do { shard = try reader.shardURL(for: keyed) }
            catch let error as VerifyError {
                findings.append(.init(path: path,
                                      problem: (error as LocalizedError).errorDescription ?? "invalid file id"))
                continue
            }
            do {
                let plaintext = try decryptor.decrypt(keyed, shardURL: shard, using: keybag)
                // A clean decrypt (valid PKCS7 unpad with the unwrapped per-file key) is integrity
                // evidence, but it is NOT sufficient on its own: the Apple backup format has no per-file
                // MAC — AES-CBC file content is unauthenticated — so the signature is the only available
                // content-integrity heuristic. A block-aligned tamper preserving valid PKCS7 decrypts
                // cleanly yet destroys the leading magic (Codex F3).
                //
                // Severity therefore depends on the sample's TYPE EXPECTATION:
                //  - chosen as checkable-by-extension (e.g. a .db/.plist) AND no recognized signature
                //    at all -> HARD .failure: the expected magic is gone, a corruption/tamper signal.
                //    (A DIFFERENT-but-recognized signature is NOT a fail — decryption clearly worked,
                //    a mislabeled extension is benign; only NO-signature-at-all trips the failure.)
                //    A legitimately EMPTY checkable file (0-byte .db/.plist, common in iOS backups) is
                //    EXEMPT: empty plaintext from a clean decrypt is legitimately empty, not tamper —
                //    and AES-CBC tampering cannot change ciphertext length, so a multi-block file can
                //    never unpad to empty; only a genuinely empty file reaches this exemption (Odb R1).
                //  - no type expectation (extension not in the checkable set) -> NOTE: refusing real
                //    JSON/text/unknown files here false-failed a valid backup (checkpoint C run 3 / C4).
                if !Self.hasKnownSignature(plaintext) {
                    if sample.checkableByExtension, !plaintext.isEmpty {
                        findings.append(.init(path: path,
                                              problem: "decrypted to unrecognized bytes for a checkable-type file (class \(protectionClass)); the expected container magic is absent — possible corruption or tamper (no per-file MAC, signature is the integrity check)",
                                              severity: .hard))
                    } else {
                        findings.append(.init(path: path,
                                              problem: "decrypted cleanly but carries no recognized signature (class \(protectionClass)); clean PKCS7 unpad is integrity evidence",
                                              severity: .note))
                    }
                }
            } catch {
                findings.append(.init(path: path,
                                      problem: "decrypt failed: \((error as? LocalizedError)?.errorDescription ?? "\(error)")"))
            }
        }

        if checked == 0 {
            findings.append(.init(path: "(files)", problem: "no host-unlockable encrypted files found to verify"))
        }
        return VerifyReport(level: "crypto", passed: VerifyReport.passing(findings),
                            filesChecked: checked, findings: findings)
    }

    /// One crypto sample plus whether it was chosen as signature-checkable by its extension. The flag
    /// gates the severity of a no-signature decrypt: a checkable pick that loses its magic is a hard
    /// failure (tamper/corruption), an unchecked pick is only a note (Codex F3).
    private struct CryptoSample {
        let record: FileRecord
        let checkableByExtension: Bool
    }

    /// Picks one file to crypto-check per host-unlockable protection class. Within a class it PREFERS
    /// a file whose plaintext type is signature-checkable by extension (`.db`/`.sqlite*`/`.plist`/
    /// image), so a clean decrypt can be asserted against a real magic; absent any such file it falls
    /// back to the first file of that class. Each returned sample carries `checkableByExtension` so the
    /// caller knows whether to treat a missing signature as a hard failure (checkable pick) or a note
    /// (no type expectation). Device-only classes (no host class key) are skipped (R3).
    private func selectCryptoSamples(reader: ManifestReader, keybag: UnlockedKeybag) -> [CryptoSample] {
        var chosen: [UInt32: FileRecord] = [:]
        guard let all = try? reader.allFiles() else { return [] }
        for rec in all where rec.isFile {
            guard let keyed = try? reader.recordWithKey(domain: rec.domain, path: rec.relativePath),
                  let protectionClass = keyed.protectionClass,
                  keybag.classKeys[protectionClass] != nil else { continue }
            if let existing = chosen[protectionClass] {
                // Upgrade to a checkable-by-extension file if the current pick is not one.
                if !Self.isSignatureCheckableExtension(existing.relativePath),
                   Self.isSignatureCheckableExtension(keyed.relativePath) {
                    chosen[protectionClass] = keyed
                }
            } else {
                chosen[protectionClass] = keyed
            }
        }
        return chosen.values.map {
            CryptoSample(record: $0, checkableByExtension: Self.isSignatureCheckableExtension($0.relativePath))
        }
    }

    /// True for paths whose extension implies a magic-bearing type the signature check asserts
    /// strongly (SQLite databases, plists, common images) — used only to PREFER a strong sample.
    private static func isSignatureCheckableExtension(_ path: String) -> Bool {
        let lower = path.lowercased()
        return [".db", ".sqlite", ".sqlitedb", ".plist", ".png", ".jpg", ".jpeg"]
            .contains { lower.hasSuffix($0) }
    }

    /// A decrypted backup file carries a recognized structural signature (spec §4.2 / Odb R2). Beyond
    /// the original container magics (SQLite / binary plist / XML plist / PNG / JPEG), it recognizes
    /// the common real-backup types that checkpoint C run 3 proved were being false-failed: GZIP,
    /// HEIC, JSON (`{`/`[` after optional BOM/whitespace), and otherwise-valid printable UTF-8 text.
    /// Conservative by design — a real signature, not "any bytes": random plaintext (a failed decrypt)
    /// is neither a known magic nor valid printable text, so it still misses and fails.
    static func hasKnownSignature(_ data: Data) -> Bool {
        let signatures: [[UInt8]] = [
            Array("SQLite format 3\u{0}".utf8),
            Array("bplist".utf8),
            Array("<?xml".utf8),
            [0x89, 0x50, 0x4E, 0x47],          // PNG
            [0xFF, 0xD8, 0xFF],                // JPEG
            [0x1F, 0x8B],                      // GZIP
        ]
        if signatures.contains(where: { data.starts(with: $0) }) { return true }
        // HEIC/HEIF: `ftyp` brand box at offset 4 (....ftypheic / mif1 / msf1).
        if data.count >= 12, Array(data[4..<8]) == Array("ftyp".utf8) { return true }
        if Self.looksLikeJSON(data) { return true }
        return Self.looksLikePrintableUTF8(data)
    }

    /// Leading `{` or `[` after an optional UTF-8 BOM and whitespace — a JSON object/array.
    private static func looksLikeJSON(_ data: Data) -> Bool {
        var bytes = Array(data.prefix(8))
        if bytes.starts(with: [0xEF, 0xBB, 0xBF]) { bytes.removeFirst(3) }   // strip UTF-8 BOM
        guard let first = bytes.first(where: { !(($0 == 0x20) || ($0 == 0x09) || ($0 == 0x0A) || ($0 == 0x0D)) })
        else { return false }
        return first == UInt8(ascii: "{") || first == UInt8(ascii: "[")
    }

    /// Valid UTF-8 whose decoded prefix is overwhelmingly printable — recognizes plain-text backup
    /// files (`.txt`, `.json`, config/log text) without admitting random decrypt garbage. Empty
    /// plaintext is not "text". A decrypt with the WRONG key yields high-entropy bytes that fail
    /// UTF-8 validation or the printable-ratio gate, so this does not weaken the integrity check.
    private static func looksLikePrintableUTF8(_ data: Data) -> Bool {
        let sample = data.prefix(512)
        guard !sample.isEmpty, let text = String(data: sample, encoding: .utf8) else { return false }
        let scalars = text.unicodeScalars
        guard !scalars.isEmpty else { return false }
        let printable = scalars.reduce(0) { acc, s in
            let ok = s == " " || s == "\t" || s == "\n" || s == "\r"
                || (s.value >= 0x20 && s.value != 0x7F)
            return acc + (ok ? 1 : 0)
        }
        return Double(printable) / Double(scalars.count) >= 0.95
    }

    /// The unlocked keybag plus a keybag-aware `ManifestReader` for an encrypted backup, or `nil` when
    /// no password was supplied. Shared by `crypto` and `readability` so both run the SAME decrypt seam
    /// (unlock the keybag from `Manifest.plist` FIRST — no DB needed — so an encrypted `Manifest.db` is
    /// decrypted before it is opened; real encrypted backups encrypt the manifest too). The caller has
    /// ALREADY proven the backup encrypted via `isBackupEncrypted`, so a missing password is a findable
    /// miss (returned as `nil`) and a WRONG password throws `KeybagError.wrongPassword` from `unlock`.
    private func resolveEncryptedReader(udidDir: URL, password: () -> String?)
        throws -> (keybag: UnlockedKeybag, reader: ManifestReader)? {
        guard let password = password() else { return nil }
        let keybag = try Keybag(tlv: try ManifestReader.backupKeybagTLV(in: udidDir)).unlock(password: password)  // throws wrongPassword
        return (keybag, try ManifestReader(backupDir: udidDir, unlockedKeybag: keybag))
    }

    /// The key databases SP3 reads downstream, with the core tables each must carry. A tables-ONLY
    /// hand-off (spec §4.2): readability proves these DBs decrypt to a real SQLite db with the expected
    /// schema — it never reads a row or interprets content, so it surfaces no personal data.
    private static let readabilityTargets: [(domain: String, path: String, requiredTables: Set<String>)] = [
        ("HomeDomain", "Library/SMS/sms.db", ["message", "chat"]),
        ("HomeDomain", "Library/AddressBook/AddressBook.sqlitedb", ["ABPerson"]),
    ]

    /// Readability-level verification (spec §4.2): a minimal "is this backup EXPORTABLE for SP3" check.
    /// For each key DB that EXISTS in the backup, open it as SQLite and assert the core tables SP3 will
    /// read are PRESENT. It checks table NAMES only (`sqlite_master`) — never a row or any content — so
    /// no personal data is read or surfaced (the privacy hand-off correction).
    ///
    /// SCOPE (wp6 binding ruling): readability runs the table check on BOTH plaintext AND encrypted
    /// backups — SP3 reads `sms.db`/`AddressBook` regardless of encryption, so "is this key DB openable
    /// with its core tables" is meaningful either way. `isBackupEncrypted` selects only the per-file
    /// BYTES-SOURCE; it does NOT short-circuit the level (that early-return was the rejected crypto-mirror
    /// — crypto's "Proves" is Decryptability, which IS not-applicable on plaintext; readability's is
    /// Exportability, which is not). Unlike `crypto`, there is no `notEncryptedReport` arm here.
    ///
    /// F2 (deferred password) is PRESERVED structurally: on a plaintext backup the bytes-source reads the
    /// shard DIRECTLY and the password closure is NEVER evaluated; the password is pulled ONLY in the
    /// encrypted branch, after `isBackupEncrypted` is true. A missing password on an encrypted backup is a
    /// finding (never a force-unwrapped keybag), a wrong one throws `KeybagError.wrongPassword`. An ABSENT
    /// key DB is fine; only a PRESENT DB that fails to open or is missing a core table is a `.hard` finding.
    private func readability(udidDir: URL, password: () -> String?) throws -> VerifyReport {
        // Choose the reader and the per-file bytes-source ONCE, by the plaintext Manifest.plist flag.
        let reader: ManifestReader
        let bytesFor: (FileRecord, URL) throws -> Data
        if isBackupEncrypted(udidDir: udidDir) {
            guard let resolved = try resolveEncryptedReader(udidDir: udidDir, password: password) else {
                return VerifyReport(level: "readability", passed: false, filesChecked: 0,
                                    findings: [.init(path: "(password)", problem: "no password supplied")])
            }
            reader = resolved.reader
            let decryptor = BackupDecryptor()
            bytesFor = { record, shard in try decryptor.decrypt(record, shardURL: shard, using: resolved.keybag) }
        } else {
            // Plaintext backup: read the shard bytes directly. The password closure is NEVER touched here,
            // so an unencrypted readability verify cannot prompt/hang (the surviving F2 invariant).
            reader = try ManifestReader(backupDir: udidDir)
            bytesFor = { _, shard in try Data(contentsOf: shard) }
        }

        var findings: [VerifyReport.Finding] = []
        var checked = 0
        for target in Self.readabilityTargets {
            // Absent key DBs are OK — readability checks only the DBs that EXIST.
            guard let record = try reader.recordWithKey(domain: target.domain, path: target.path)
            else { continue }
            checked += 1
            let path = "\(target.domain)/\(target.path)"

            let shard: URL
            do { shard = try reader.shardURL(for: record) }
            catch let error as VerifyError {
                findings.append(.init(path: path,
                                      problem: (error as LocalizedError).errorDescription ?? "invalid file id"))
                continue
            }
            do {
                let bytes = try bytesFor(record, shard)
                let tables = try openTableNames(bytes: bytes)
                let missing = target.requiredTables.subtracting(tables)
                if !missing.isEmpty {
                    findings.append(.init(path: path,
                                          problem: "missing tables: \(missing.sorted().joined(separator: ", "))"))
                }
            } catch let error as VerifyError {
                // A shard that reads/decrypts cleanly but is NOT a readable SQLite db (tamper/corruption) —
                // a DISTINCT failure from "missing tables" (the bytes are garbage, not a db with a gap).
                // The throw is recorded, never `try?`-swallowed into an empty table set (wp3 Q5 class):
                // swallowing it would mislabel non-database bytes as "missing tables: chat, message".
                findings.append(.init(path: path,
                                      problem: "not a readable SQLite database: \((error as LocalizedError).errorDescription ?? "\(error)")"))
            } catch {
                findings.append(.init(path: path,
                                      problem: "could not read key database: \((error as? LocalizedError)?.errorDescription ?? "\(error)")"))
            }
        }
        return VerifyReport(level: "readability", passed: findings.isEmpty, filesChecked: checked, findings: findings)
    }

    /// Writes key-DB `bytes` to a private temp file, opens it read-only via `SQLiteDB` (`immutable=1`),
    /// and returns its table names. BOTH readability paths funnel through here — the encrypted path passes
    /// DECRYPTED bytes (personal data), the plaintext path passes the raw shard bytes — so neither opens a
    /// backup-resident file in place (which could trip `SQLiteDB`'s `-wal` sidecar guard) and the temp is
    /// always `0600` (owner-only) + removed on every exit path (`defer`), mirroring
    /// `ManifestReader.decryptManifest`. `SQLiteDB` throws `VerifyError.manifestUnreadable` if the bytes
    /// are not a valid SQLite db — that throw PROPAGATES (it is the R2 "not a readable database" signal),
    /// it is never swallowed here.
    private func openTableNames(bytes: Data) throws -> Set<String> {
        let temp = FileManager.default.temporaryDirectory
            .appendingPathComponent("tether-readability-\(UUID().uuidString).db")
        FileManager.default.createFile(atPath: temp.path, contents: nil,
                                       attributes: [.posixPermissions: 0o600])
        defer { try? FileManager.default.removeItem(at: temp) }
        try bytes.write(to: temp)
        return try SQLiteDB(path: temp.path).tableNames()
    }
}
