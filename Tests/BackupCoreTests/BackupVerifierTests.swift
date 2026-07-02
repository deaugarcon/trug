import Testing
import Foundation
@testable import BackupCore

@Suite struct BackupVerifierTests {
    /// A complete unencrypted backup whose `Status.plist` carries `snapshotState`
    /// (or is removed entirely when nil), for exercising the SnapshotState gate.
    private func makeBackup(udid: String, snapshotState: String?) throws -> URL {
        let root = try FixtureBuilder.unencryptedBackup(udid: udid, files: [
            .init(domain: "HomeDomain", path: "a.txt", contents: Data("aaa".utf8)),
        ])
        let status = root.appendingPathComponent(udid).appendingPathComponent("Status.plist")
        if let snapshotState {
            let plist = try PropertyListSerialization.data(
                fromPropertyList: ["IsFullBackup": true, "SnapshotState": snapshotState], format: .xml, options: 0)
            try plist.write(to: status)
        } else {
            try FileManager.default.removeItem(at: status)
        }
        return root
    }

    @Test func passesWhenSnapshotFinished() throws {
        let root = try makeBackup(udid: "U", snapshotState: "finished")
        defer { try? FileManager.default.removeItem(at: root) }
        let report = try BackupVerifier().verifyStructural(backupDir: root, udid: "U")
        #expect(report.passed)
        #expect(report.findings.isEmpty)
    }

    @Test func failsWhenSnapshotNotFinished() throws {
        let root = try makeBackup(udid: "U", snapshotState: "uploading")
        defer { try? FileManager.default.removeItem(at: root) }
        let report = try BackupVerifier().verifyStructural(backupDir: root, udid: "U")
        #expect(!report.passed)
        #expect(report.findings.contains { $0.problem.contains("SnapshotState") })
    }

    @Test func failsWhenStatusMissing() throws {
        let root = try makeBackup(udid: "U", snapshotState: nil)
        defer { try? FileManager.default.removeItem(at: root) }
        let report = try BackupVerifier().verifyStructural(backupDir: root, udid: "U")
        #expect(!report.passed)
        #expect(report.findings.contains { $0.path == "Status.plist" && $0.problem.contains("missing") })
    }

    // MARK: - Task 9: full row↔shard structural verify dispatched by level

    @Test func passesOnCompleteBackup() throws {
        let root = try FixtureBuilder.unencryptedBackup(udid: "U", files: [
            .init(domain: "HomeDomain", path: "a.txt", contents: Data("aaa".utf8)),
        ])
        defer { try? FileManager.default.removeItem(at: root) }
        let report = try BackupVerifier().verify(backupDir: root, udid: "U", level: .structural, password: nil)
        #expect(report.passed)
        #expect(report.findings.isEmpty)
        #expect(report.filesChecked == 1)
    }

    /// Task 14 part D (LAZY password): `verify` takes the password as @autoclosure, so a STRUCTURAL
    /// verify of a PLAINTEXT backup must NEVER evaluate it — otherwise an unencrypted verify with no
    /// env password would fire the interactive no-echo prompt and HANG. The closure records a test
    /// failure if invoked; a pass proves the plaintext structural path never pulls the password.
    @Test func structuralUnencryptedNeverEvaluatesPasswordClosure() throws {
        let root = try FixtureBuilder.unencryptedBackup(udid: "U", files: [
            .init(domain: "HomeDomain", path: "a.txt", contents: Data("aaa".utf8)),
        ])
        defer { try? FileManager.default.removeItem(at: root) }
        let report = try BackupVerifier().verify(
            backupDir: root, udid: "U", level: .structural,
            password: { Issue.record("password closure evaluated on a plaintext structural verify — would prompt/hang"); return nil }())
        #expect(report.passed)
        #expect(report.filesChecked == 1)
    }

    /// Codex F2 (SECURITY): `crypto` evaluated the password EAGERLY, so a PLAINTEXT backup run at
    /// `--level crypto` would fire the interactive no-echo prompt and HANG on a password it can never
    /// use. The fix checks encryption FIRST via the plist-only seam: a plaintext backup must NEVER
    /// evaluate the closure and must return an HONEST not-applicable report (`passed = true`, an
    /// explicit not-encrypted note — NOT a silent crypto PASS claiming ciphertext was verified).
    ///
    /// `.readability` was REMOVED from this test's arguments by the wp6 binding scope ruling: unlike
    /// crypto, readability RUNS its table check on a plaintext backup too (it proves SP3-exportability,
    /// which is meaningful for a plaintext key DB) — so plaintext readability is NOT not-applicable. Its
    /// surviving F2 invariant (the password closure is never pulled on a plaintext backup) moved to
    /// `readabilityPlaintextRunsTableCheckWithoutPullingPassword`.
    @Test func plaintextCryptoIsNotApplicableWithoutPullingPassword() throws {
        let root = try FixtureBuilder.unencryptedBackup(udid: "U", files: [
            .init(domain: "HomeDomain", path: "a.txt", contents: Data("aaa".utf8)),
        ])
        defer { try? FileManager.default.removeItem(at: root) }
        let report = try BackupVerifier().verify(
            backupDir: root, udid: "U", level: .crypto,
            password: { Issue.record("password closure evaluated on a plaintext crypto verify — would prompt/hang"); return nil }())
        #expect(report.passed)                                  // no crypto failure on a plaintext backup
        #expect(report.filesChecked == 0)
        #expect(report.findings.allSatisfy { $0.severity == .note })   // not-applicable, not a defect
        #expect(report.findings.contains { $0.problem.contains("not encrypted") && $0.problem.contains("not applicable") })
    }

    @Test func failsWhenShardMissing() throws {
        let root = try FixtureBuilder.unencryptedBackup(udid: "U", files: [
            .init(domain: "HomeDomain", path: "a.txt", contents: Data("aaa".utf8)),
        ])
        defer { try? FileManager.default.removeItem(at: root) }
        // Delete the shard file behind the row, leaving the manifest row dangling.
        let udidDir = root.appendingPathComponent("U")
        let reader = try ManifestReader(backupDir: udidDir)
        let rec = try #require(try reader.record(domain: "HomeDomain", path: "a.txt"))
        try FileManager.default.removeItem(at: reader.shardURL(for: rec))

        let report = try BackupVerifier().verify(backupDir: root, udid: "U", level: .structural, password: nil)
        #expect(!report.passed)
        #expect(report.findings.contains { $0.problem.contains("missing") })
    }

    /// wp3.baton Q5 BINDING: a `malformedFileID` row must surface as a `VerifyReport` finding,
    /// never be `try?`-skipped — a tampered/corrupt manifest must not read as a clean backup
    /// with one fewer file. The fixture seeds a row whose `fileID` is not strict 40-char hex.
    @Test func recordsMalformedFileIDAsFinding() throws {
        let root = try FixtureBuilder.unencryptedBackupWithMalformedFileID(udid: "U")
        defer { try? FileManager.default.removeItem(at: root) }
        let report = try BackupVerifier().verify(backupDir: root, udid: "U", level: .structural, password: nil)
        #expect(!report.passed)
        #expect(report.findings.contains { $0.problem.contains("invalid file id") })
    }

    /// Checkpoint B run 2 + locked decision §16: a real full backup contains NO Info.plist (the
    /// device does not send one and Tether does not synthesize it). A structurally PERFECT backup
    /// without Info.plist must PASS — Info.plist absence is NOT a finding. This is the regression
    /// lock against the stale Task 9 pseudocode that hard-required Info.plist and failed the
    /// lead-verified 78,610-row device backup.
    @Test func passesWithoutInfoPlist() throws {
        let root = try FixtureBuilder.unencryptedBackup(udid: "U", files: [
            .init(domain: "HomeDomain", path: "a.txt", contents: Data("aaa".utf8)),
        ], omitInfoPlist: true)
        defer { try? FileManager.default.removeItem(at: root) }
        #expect(!FileManager.default.fileExists(atPath: root.appendingPathComponent("U/Info.plist").path),
                "fixture must not contain Info.plist for this regression lock to be non-vacuous")
        let report = try BackupVerifier().verify(backupDir: root, udid: "U", level: .structural, password: nil)
        #expect(report.passed, "findings: \(report.findings)")
        #expect(report.findings.isEmpty)
        #expect(report.filesChecked == 1)
    }

    /// A genuinely-required plist (Manifest.plist) being absent must still FAIL — the required set is
    /// [Status.plist, Manifest.plist] only. Manifest.plist carries BackupKeyBag for encrypted backups
    /// and IsEncrypted/metadata; its absence is a real structural defect, unlike Info.plist's (§16).
    @Test func failsWhenRequiredPlistMissing() throws {
        let root = try FixtureBuilder.unencryptedBackup(udid: "U", files: [
            .init(domain: "HomeDomain", path: "a.txt", contents: Data("aaa".utf8)),
        ])
        defer { try? FileManager.default.removeItem(at: root) }
        try FileManager.default.removeItem(at: root.appendingPathComponent("U/Manifest.plist"))
        let report = try BackupVerifier().verify(backupDir: root, udid: "U", level: .structural, password: nil)
        #expect(!report.passed)
        #expect(report.findings.contains { $0.path == "Manifest.plist" })
    }

    // MARK: - WP4.2 / Checkpoint C run 1: structural verify on an ENCRYPTED backup
    //
    // On real hardware the device encrypts Manifest.db itself. Before this fix, structural opened
    // the ciphertext as SQLite (SQLITE_NOTADB) and reported a corrupt/incomplete backup — the
    // not-a-database/re-create lie. Structural must instead decrypt the manifest through the task-#10
    // seam when a password is available, and emit a precise password-required error when it is not.

    /// WITH the password, structural verify of an encrypted-manifest backup PASSES via the decrypt
    /// seam — the same keybag-aware reader the crypto level uses, with the normal row↔shard check.
    @Test func structuralPassesOnEncryptedBackupWithPassword() throws {
        let (root, udid, password) = try FixtureBuilder.encryptedBackupWithEncryptedManifest()
        defer { try? FileManager.default.removeItem(at: root) }
        let report = try BackupVerifier().verify(backupDir: root, udid: udid, level: .structural, password: password)
        #expect(report.passed, "findings: \(report.findings)")
        #expect(report.findings.isEmpty)
        #expect(report.filesChecked == 1)
    }

    /// WITHOUT a password, structural verify of an encrypted backup must throw the precise
    /// `passwordRequired` error — NEVER the not-a-database / "may be incomplete; re-create it" lie.
    /// The message must point at the password, not at corruption.
    @Test func structuralWithoutPasswordThrowsPasswordRequired() throws {
        let (root, udid, _) = try FixtureBuilder.encryptedBackupWithEncryptedManifest()
        defer { try? FileManager.default.removeItem(at: root) }
        #expect(throws: VerifyError.passwordRequired(udid: udid)) {
            _ = try BackupVerifier().verify(backupDir: root, udid: udid, level: .structural, password: nil)
        }
        // The surfaced message must mention the password and must not allege corruption.
        let error = VerifyError.passwordRequired(udid: udid)
        let text = ((error.errorDescription ?? "") + " " + (error.recoverySuggestion ?? "")).lowercased()
        #expect(text.contains("password"))
        #expect(!text.contains("re-create"))
        #expect(!text.contains("not a database"))
    }

    /// PRODUCTION-SHAPED: the CLI feeds `PasswordInput.read()`, which returns "" (empty string) when
    /// TRUG_BACKUP_PASSWORD is unset — NOT nil. An empty password must take the same `passwordRequired`
    /// arm as nil, never reach the keybag as a (wrong) unlock attempt. This is the exact value the real
    /// `trug backup create/verify` passes on an encrypted backup with no password configured.
    @Test func structuralWithEmptyPasswordThrowsPasswordRequired() throws {
        let (root, udid, _) = try FixtureBuilder.encryptedBackupWithEncryptedManifest()
        defer { try? FileManager.default.removeItem(at: root) }
        #expect(throws: VerifyError.passwordRequired(udid: udid)) {
            _ = try BackupVerifier().verify(backupDir: root, udid: udid, level: .structural, password: "")
        }
    }

    /// A WRONG password during structural verify of an encrypted backup surfaces as `wrongPassword`
    /// (the keybag refuses to unlock) — not as a manifestUnreadable or a false structural finding.
    @Test func structuralWrongPasswordSurfacesWrongPassword() throws {
        let (root, udid, _) = try FixtureBuilder.encryptedBackupWithEncryptedManifest()
        defer { try? FileManager.default.removeItem(at: root) }
        #expect(throws: KeybagError.wrongPassword) {
            _ = try BackupVerifier().verify(backupDir: root, udid: udid, level: .structural, password: "wrong")
        }
    }

    // MARK: - Task 15: readability verify (spec §4.2, tables-only hand-off)
    //
    // Readability proves a backup's key databases open to a real SQLite db carrying the core tables SP3
    // will read — a minimal "is this exportable downstream" check. It asserts table PRESENCE only (the
    // `sqlite_master` names), never a row or any content, so it surfaces no personal data. Per the wp6
    // binding scope ruling it runs the table check on BOTH plaintext AND encrypted backups (SP3 reads
    // sms.db/AddressBook regardless of encryption) — `isBackupEncrypted` selects only the per-file
    // BYTES-SOURCE (direct shard read vs decrypt), it does NOT short-circuit the level. The surviving F2
    // invariant: a plaintext backup NEVER pulls the password (pinned below). Every positive test asserts
    // `filesChecked >= 1` so a not-applicable / no-op path cannot satisfy it (Odb wp6 Strongest objection).

    /// The target path readability checks for SMS — both the plaintext `File` and the encrypted
    /// `ExtraFile` fixtures seed their db at this exact relative path so the lookup finds it.
    private static let smsPath = "Library/SMS/sms.db"

    /// A `Library/SMS/sms.db` ExtraFile whose plaintext is a schema-only SQLite db carrying `tables`,
    /// seeded as an encrypted file under a host-unlockable class so readability decrypts and table-checks
    /// it. Class 3 is host-unlockable in the WP4 oracle keybag (`keybag.known.json`).
    private func encryptedSMSDB(tables: [String]) throws -> FixtureBuilder.ExtraFile {
        FixtureBuilder.ExtraFile(domain: "HomeDomain", relativePath: Self.smsPath,
                                 protectionClass: 3, plaintext: try FixtureBuilder.sqliteBlob(tables: tables))
    }

    /// A plaintext `Library/SMS/sms.db` shard for the unencrypted-backup path — a schema-only SQLite db
    /// written directly as the shard contents (no encryption), so readability reads it via the direct
    /// shard path WITHOUT ever pulling the password.
    private func plaintextSMSDB(tables: [String]) throws -> FixtureBuilder.File {
        FixtureBuilder.File(domain: "HomeDomain", path: Self.smsPath, contents: try FixtureBuilder.sqliteBlob(tables: tables))
    }

    /// HAPPY PATH (non-vacuous): an encrypted backup whose `sms.db` decrypts to a SQLite db with both
    /// required tables (`message`, `chat`) PASSES — and `filesChecked == 1` proves the readability body
    /// actually ran (not the F2 not-applicable arm, which reports `filesChecked == 0`).
    @Test func readabilityPassesWhenKeyDBsOpen() throws {
        let (root, udid, password) = try FixtureBuilder.encryptedBackupWithEncryptedManifest(
            extraFiles: [try encryptedSMSDB(tables: ["message", "chat"])])
        defer { try? FileManager.default.removeItem(at: root) }
        let report = try BackupVerifier().verify(backupDir: root, udid: udid, level: .readability, password: password)
        #expect(report.passed, "findings: \(report.findings)")
        #expect(report.findings.isEmpty)
        #expect(report.filesChecked == 1)
    }

    /// THE DIFFERENTIATOR: an `sms.db` that decrypts cleanly to a VALID SQLite db but is MISSING a core
    /// table (`message`) must FAIL with a `.hard` finding naming the missing table — proving readability
    /// can actually fail. A verifier with only a pass test is unproven (Odb wp6 Q2).
    @Test func readabilityFailsWhenRequiredTableMissing() throws {
        let (root, udid, password) = try FixtureBuilder.encryptedBackupWithEncryptedManifest(
            extraFiles: [try encryptedSMSDB(tables: ["chat"])])   // valid SQLite, but `message` is absent
        defer { try? FileManager.default.removeItem(at: root) }
        let report = try BackupVerifier().verify(backupDir: root, udid: udid, level: .readability, password: password)
        #expect(!report.passed)
        #expect(report.filesChecked == 1)
        #expect(report.findings.contains {
            $0.path.contains("sms.db") && $0.severity == .hard && $0.problem.contains("message")
        }, "findings: \(report.findings)")
    }

    /// Odb wp6 R2: a target shard that decrypts cleanly (valid PKCS7) but whose plaintext is NOT a SQLite
    /// database (tamper/corruption) must surface a DISTINCT "not a readable SQLite database" finding —
    /// NOT a misleading "missing tables: chat, message" (the tables aren't missing; the bytes are garbage).
    /// This forbids `try?`-swallowing the `SQLiteDB` open/read throw (the wp3 Q5 class).
    @Test func readabilityNonSQLiteShardFindsDistinctError() throws {
        // 4 KiB of fixed non-SQLite bytes: a clean decrypt, but no `SQLite format 3\0` header.
        let garbage = FixtureBuilder.ExtraFile(domain: "HomeDomain", relativePath: "Library/SMS/sms.db",
                                               protectionClass: 3, plaintext: Data(repeating: 0xAB, count: 4096))
        let (root, udid, password) = try FixtureBuilder.encryptedBackupWithEncryptedManifest(extraFiles: [garbage])
        defer { try? FileManager.default.removeItem(at: root) }
        let report = try BackupVerifier().verify(backupDir: root, udid: udid, level: .readability, password: password)
        #expect(!report.passed)
        #expect(report.filesChecked == 1)
        #expect(report.findings.contains {
            $0.path.contains("sms.db") && $0.severity == .hard && $0.problem.lowercased().contains("not a readable sqlite")
        }, "findings: \(report.findings)")
        #expect(!report.findings.contains { $0.problem.contains("missing tables") },
                "a non-SQLite shard must not be reported as 'missing tables' — findings: \(report.findings)")
    }

    /// A WRONG password during readability verify surfaces as `wrongPassword` (the keybag refuses to
    /// unlock), mirroring the crypto/structural paths — not a false readability finding.
    @Test func readabilityWrongPasswordSurfacesWrongPassword() throws {
        let (root, udid, _) = try FixtureBuilder.encryptedBackupWithEncryptedManifest(
            extraFiles: [try encryptedSMSDB(tables: ["message", "chat"])])
        defer { try? FileManager.default.removeItem(at: root) }
        #expect(throws: KeybagError.wrongPassword) {
            _ = try BackupVerifier().verify(backupDir: root, udid: udid, level: .readability, password: "wrong")
        }
    }

    /// ABSENT targets are OK, not a failure (plan §1891): an encrypted backup carrying neither `sms.db`
    /// nor `AddressBook.sqlitedb` reports `filesChecked == 0` and PASSES — readability checks only the
    /// key DBs that EXIST. The oracle's mandatory `known.txt` file is not a readability target, so no
    /// target is found here.
    @Test func readabilitySkipsAbsentTargets() throws {
        let (root, udid, password) = try FixtureBuilder.encryptedBackupWithEncryptedManifest()
        defer { try? FileManager.default.removeItem(at: root) }
        let report = try BackupVerifier().verify(backupDir: root, udid: udid, level: .readability, password: password)
        #expect(report.passed, "findings: \(report.findings)")
        #expect(report.filesChecked == 0)
    }

    // MARK: - Task 15: readability on PLAINTEXT backups (wp6 binding scope ruling)
    //
    // The ruling: readability runs the table check on a PLAINTEXT backup too (it proves SP3-exportability,
    // which is meaningful whether or not the backup was encrypted) — `isBackupEncrypted` selects only the
    // per-file bytes-source (direct shard read vs decrypt). The surviving F2 invariant is that a plaintext
    // backup NEVER pulls the password; these tests pin both halves (the table check ran AND no password).

    /// THE RULING'S LOAD-BEARING TEST + the surviving F2 invariant (replaces the `.readability` arm that
    /// was split out of `plaintextCipherLevelNeverEvaluatesPasswordClosure`): an UNENCRYPTED backup whose
    /// `sms.db` shard is a SQLite db with `message`+`chat` PASSES with `filesChecked == 1` — proving the
    /// table check RAN on a plaintext backup — AND the password closure is NEVER evaluated (it reads the
    /// shard directly). The `Issue.record` closure fails the test if the plaintext path pulls the password.
    @Test func readabilityPlaintextRunsTableCheckWithoutPullingPassword() throws {
        let root = try FixtureBuilder.unencryptedBackup(udid: "U", files: [
            try plaintextSMSDB(tables: ["message", "chat"]),
        ])
        defer { try? FileManager.default.removeItem(at: root) }
        let report = try BackupVerifier().verify(
            backupDir: root, udid: "U", level: .readability,
            password: { Issue.record("password closure evaluated on a plaintext readability verify — would prompt/hang"); return nil }())
        #expect(report.passed, "findings: \(report.findings)")     // table check ran and passed
        #expect(report.filesChecked == 1)                          // NOT the not-applicable arm (would be 0)
    }

    /// THE RULING'S WHOLE POINT: a PLAINTEXT `sms.db` that opens but is MISSING a core table must FAIL —
    /// exactly the case the not-applicable mapping would have falsely passed (and SP3 would then choke on
    /// a DB readability claimed nothing about). `!passed` + a `.hard` finding naming the missing table,
    /// still without pulling the password.
    @Test func readabilityFailsOnPlaintextMissingTable() throws {
        let root = try FixtureBuilder.unencryptedBackup(udid: "U", files: [
            try plaintextSMSDB(tables: ["chat"]),   // valid SQLite, but `message` is absent
        ])
        defer { try? FileManager.default.removeItem(at: root) }
        let report = try BackupVerifier().verify(
            backupDir: root, udid: "U", level: .readability,
            password: { Issue.record("password closure evaluated on a plaintext readability verify — would prompt/hang"); return nil }())
        #expect(!report.passed)
        #expect(report.filesChecked == 1)
        #expect(report.findings.contains {
            $0.path.contains("sms.db") && $0.severity == .hard && $0.problem.contains("message")
        }, "findings: \(report.findings)")
    }
}
