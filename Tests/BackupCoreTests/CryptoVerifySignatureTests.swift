import Testing
import Foundation
@testable import BackupCore

/// WP4.2 / Checkpoint C run 3 (C4): crypto verify must not FALSE-FAIL a backup whose files decrypt
/// cleanly but whose plaintext type has no container magic (JSON, plain text). A clean PKCS7 unpad
/// with the unwrapped per-file key is itself integrity evidence; an unrecognized-but-clean type is a
/// NOTE, not a hard failure. A genuinely wrong-key/corrupt shard still fails (decrypt throws).
@Suite struct CryptoVerifySignatureTests {
    // MARK: - hasKnownSignature recognizes the real types it was missing

    @Test func recognizesExpandedSignatures() {
        // JSON object and array (with and without a UTF-8 BOM / leading whitespace).
        #expect(BackupVerifier.hasKnownSignature(Data(#"{"a":1}"#.utf8)))
        #expect(BackupVerifier.hasKnownSignature(Data("  [1,2,3]".utf8)))
        #expect(BackupVerifier.hasKnownSignature(Data([0xEF, 0xBB, 0xBF] + Array(#"{"x":true}"#.utf8))))
        // Plain UTF-8 text.
        #expect(BackupVerifier.hasKnownSignature(Data("hello world\nthis is a log line".utf8)))
        // GZIP and HEIC magics.
        #expect(BackupVerifier.hasKnownSignature(Data([0x1F, 0x8B, 0x08] + Array(repeating: 0, count: 16))))
        #expect(BackupVerifier.hasKnownSignature(Data([0,0,0,0x18] + Array("ftypheic".utf8) + Array(repeating: 0, count: 8))))
        // Existing magics still recognized.
        #expect(BackupVerifier.hasKnownSignature(Data("SQLite format 3\u{0}".utf8)))
        #expect(BackupVerifier.hasKnownSignature(Data("bplist00".utf8)))
    }

    /// CONSERVATIVE: high-entropy bytes (what a WRONG-key decrypt yields) must NOT be mistaken for a
    /// signature — otherwise the integrity check is meaningless. Empty plaintext is not a signature.
    @Test func rejectsHighEntropyAndEmpty() {
        var rng = SystemRandomNumberGenerator()
        let random = Data((0..<256).map { _ in UInt8.random(in: 0...255, using: &rng) })
        // A random buffer should miss every magic and fail the printable-UTF8 gate with overwhelming
        // probability; assert on a fixed non-printable buffer to keep the test deterministic.
        let binary = Data((0..<256).map { UInt8($0 % 256) })   // includes many control bytes
        #expect(!BackupVerifier.hasKnownSignature(binary))
        #expect(!BackupVerifier.hasKnownSignature(Data()))
        _ = random
    }

    // MARK: - end-to-end crypto verify on varied-type files

    /// Crypto verify PASSES on an encrypted backup whose host-unlockable class carries a JSON file
    /// and a plain-text file — pre-C4 these false-failed (no SQLite/plist/image magic). The report
    /// passes; any "no recognized signature" entries are informational notes, never hard failures.
    @Test func cryptoVerifyPassesWithJSONAndTextFiles() throws {
        let (root, udid, password) = try FixtureBuilder.encryptedBackupWithEncryptedManifest(extraFiles: [
            .init(domain: "AppDomain-com.pandora", relativePath: "Documents/lifecycle.json",
                  protectionClass: 4, plaintext: Data(#"{"module":"com.adobe.lifecycle","v":2}"#.utf8)),
            .init(domain: "AppDomain-com.pandora", relativePath: "Documents/notes.txt",
                  protectionClass: 4, plaintext: Data("a plain text note\nsecond line\n".utf8)),
        ])
        defer { try? FileManager.default.removeItem(at: root) }
        let report = try BackupVerifier().verify(backupDir: root, udid: udid, level: .crypto, password: password)
        #expect(report.passed, "findings: \(report.findings)")
        // No HARD findings; the report passed despite any informational notes.
        #expect(!report.findings.contains { $0.severity == .hard })
    }

    /// A cleanly-decrypted file with no recognized signature records a NOTE (informational) and does
    /// NOT fail the report — built by seeding a file whose plaintext is valid-but-unrecognized binary
    /// that still PKCS7-pads cleanly. (Here: a short run of high bytes that is not a magic nor text.)
    @Test func unrecognizedCleanTypeIsNoteNotFailure() throws {
        // 0x80-range bytes: not a magic, not valid printable UTF-8 prefix -> hasKnownSignature false,
        // but it encrypts/decrypts with clean PKCS7, so it must be a NOTE not a hard fail.
        let opaque = Data(repeating: 0xB7, count: 24)
        let (root, udid, password) = try FixtureBuilder.encryptedBackupWithEncryptedManifest(extraFiles: [
            .init(domain: "AppDomain-x", relativePath: "blob.bin", protectionClass: 4, plaintext: opaque),
        ])
        defer { try? FileManager.default.removeItem(at: root) }
        let report = try BackupVerifier().verify(backupDir: root, udid: udid, level: .crypto, password: password)
        #expect(report.passed, "a clean decrypt with no signature must PASS-with-note: \(report.findings)")
        #expect(report.findings.contains { $0.severity == .note })
    }

    /// REAL FAILURE PATH STAYS ARMED (non-vacuous): a corrupt shard (truncated ciphertext that fails
    /// PKCS7 / decrypt) must produce a HARD finding and FAIL the report — the pass-with-note relaxation
    /// must not swallow a genuine decrypt failure.
    @Test func cryptoVerifyFailsOnCorruptShard() throws {
        let (root, udid, password) = try FixtureBuilder.encryptedBackupWithEncryptedManifest()
        defer { try? FileManager.default.removeItem(at: root) }
        let udidDir = root.appendingPathComponent(udid)
        // Corrupt the known file's shard: overwrite with garbage that cannot PKCS7-unpad cleanly.
        let ef = try Fixtures.encryptedFile()
        let id = FixtureBuilder.fileID(domain: ef.domain, path: ef.relativePath)
        let shard = udidDir.appendingPathComponent(String(id.prefix(2))).appendingPathComponent(id)
        try Data(repeating: 0x00, count: 32).write(to: shard)   // 32B of zeros: unpadding fails

        let report = try BackupVerifier().verify(backupDir: root, udid: udid, level: .crypto, password: password)
        #expect(!report.passed, "a corrupt shard must FAIL crypto verify")
        #expect(report.findings.contains { $0.severity == .hard })
    }

    /// CODEX F3/F4 — VALID-PADDING TAMPER on a CHECKABLE-extension file is a HARD failure.
    ///
    /// The Apple backup format has NO per-file MAC (AES-CBC content is unauthenticated), so the
    /// signature check IS the content-integrity check. A block-aligned tamper of the FIRST ciphertext
    /// block destroys the SQLite magic at offset 0 (P[0] randomizes, P[1] bit-flips) while the final
    /// block's PKCS7 padding — derived from the untouched trailing blocks — stays valid, so decrypt
    /// does NOT throw. The pre-fix code demoted the resulting no-signature result to a NOTE and PASSED
    /// a tampered backup. For a file chosen as checkable-by-extension (`.db`), decrypting to NO
    /// recognized signature must be a HARD `.failure` and the report must FAIL — never a note.
    @Test func cryptoVerifyFailsOnValidPaddingTamperOfCheckableFile() throws {
        // A 2-block SQLite plaintext: tampering block 0 destroys the magic but leaves the trailing
        // block's PKCS7 padding intact, so the decrypt succeeds yet carries no recognized signature.
        let sqlitePlaintext = Data("SQLite format 3\u{0}".utf8) + Data(repeating: 0x41, count: 16)
        let (root, udid, password) = try FixtureBuilder.encryptedBackupWithEncryptedManifest(extraFiles: [
            .init(domain: "AppDomain-com.pandora", relativePath: "Library/checkable.db",
                  protectionClass: 4, plaintext: sqlitePlaintext),
        ])
        defer { try? FileManager.default.removeItem(at: root) }
        let udidDir = root.appendingPathComponent(udid)

        // Tamper the FIRST ciphertext block of the .db shard, preserving valid PKCS7 in the last block.
        let xid = FixtureBuilder.fileID(domain: "AppDomain-com.pandora", path: "Library/checkable.db")
        let shard = udidDir.appendingPathComponent(String(xid.prefix(2))).appendingPathComponent(xid)
        var ciphertext = try Data(contentsOf: shard)
        #expect(ciphertext.count >= 48, "need >= 3 blocks so block-0 tamper leaves padding block intact")
        ciphertext[0] ^= 0xFF   // flip a byte in C[0]: P[0] randomizes, P[1] bit-flips, padding untouched
        try ciphertext.write(to: shard)

        let report = try BackupVerifier().verify(backupDir: root, udid: udid, level: .crypto, password: password)
        #expect(!report.passed, "a valid-padding tamper of a checkable file must FAIL crypto verify: \(report.findings)")
        #expect(report.findings.contains { $0.severity == .hard && $0.path.hasSuffix("checkable.db") },
                "the tampered .db must be a HARD finding, not a note: \(report.findings)")
    }

    /// Odb R1 — a legitimately EMPTY checkable file (a 0-byte `.plist`/`.db`, common in iOS backups)
    /// must NOT hard-fail. Empty plaintext from a clean decrypt is legitimately empty (decryption
    /// succeeded to 0 bytes), not a tamper signal — `hasKnownSignature(Data()) == false`, but the
    /// emptiness, not a missing magic, is why. The hard-fail branch exempts empty plaintext. This can't
    /// mask tamper: AES-CBC tampering cannot change ciphertext length, so a multi-block file can never
    /// unpad to empty — only a genuinely empty (single pad-block) file reaches this exemption.
    @Test func emptyCheckableFileDoesNotHardFail() throws {
        let (root, udid, password) = try FixtureBuilder.encryptedBackupWithEncryptedManifest(extraFiles: [
            .init(domain: "AppDomain-com.pandora", relativePath: "Library/empty.plist",
                  protectionClass: 4, plaintext: Data()),
        ])
        defer { try? FileManager.default.removeItem(at: root) }
        let report = try BackupVerifier().verify(backupDir: root, udid: udid, level: .crypto, password: password)
        #expect(report.passed, "an empty checkable file decrypts cleanly to 0 bytes and must PASS: \(report.findings)")
        #expect(!report.findings.contains { $0.severity == .hard },
                "an empty checkable file must not produce a HARD finding: \(report.findings)")
    }
}
