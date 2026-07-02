import Testing
import Foundation
@testable import BackupCore

@Suite struct BackupDecryptorTests {
    /// End-to-end decrypt against the INDEPENDENT oracle's ciphertext: unwrap the per-file key
    /// with the (independently-validated) class key, AES-CBC decrypt with the zero IV, strip
    /// PKCS7, and recover the exact known plaintext the Python/OpenSSL oracle encrypted.
    @Test func decryptsKnownFileToExpectedPlaintext() throws {
        let (root, udid, password) = try FixtureBuilder.encryptedBackupWithKnownFile()
        defer { try? FileManager.default.removeItem(at: root) }
        let udidDir = root.appendingPathComponent(udid)
        let reader = try ManifestReader(backupDir: udidDir)
        let unlocked = try Keybag(tlv: try reader.backupKeybagTLV()).unlock(password: password)
        let rec = try #require(try reader.recordWithKey(domain: "HomeDomain", path: "known.txt"))
        let plaintext = try BackupDecryptor().decrypt(rec, shardURL: reader.shardURL(for: rec), using: unlocked)
        #expect(plaintext == (try Fixtures.encryptedFile().plaintext))
        // The recovered bytes are a real binary plist (the oracle's known plaintext).
        #expect(plaintext.starts(with: Data("bplist".utf8)))
    }

    /// crypto-level verify on the synthetic encrypted backup passes: keybag unlocks, the manifest
    /// opens, and the sampled file's decrypted bytes carry the expected structural signature.
    @Test func cryptoVerifyPassesOnSyntheticEncryptedBackup() throws {
        let (root, udid, password) = try FixtureBuilder.encryptedBackupWithKnownFile()
        defer { try? FileManager.default.removeItem(at: root) }
        let report = try BackupVerifier().verify(backupDir: root, udid: udid, level: .crypto, password: password)
        #expect(report.passed, "findings: \(report.findings)")
    }

    @Test func cryptoVerifyFailsOnWrongPassword() throws {
        let (root, udid, _) = try FixtureBuilder.encryptedBackupWithKnownFile()
        defer { try? FileManager.default.removeItem(at: root) }
        #expect(throws: KeybagError.wrongPassword) {
            _ = try BackupVerifier().verify(backupDir: root, udid: udid, level: .crypto, password: "wrong")
        }
    }

    @Test func cryptoVerifyReportsMissingPassword() throws {
        let (root, udid, _) = try FixtureBuilder.encryptedBackupWithKnownFile()
        defer { try? FileManager.default.removeItem(at: root) }
        let report = try BackupVerifier().verify(backupDir: root, udid: udid, level: .crypto, password: nil)
        #expect(!report.passed)
        #expect(report.findings.contains { $0.problem.contains("password") })
    }

    /// Odb F6: the EncryptionKey blob must be EXACTLY 44 bytes (4B prefix + 40B wrapped key). A
    /// blob of any other length is malformed metadata and must be rejected, not fed to RFC3394.
    @Test func rejectsNon44ByteEncryptionKeyBlob() throws {
        let (root, udid, password) = try FixtureBuilder.encryptedBackupWithKnownFile()
        defer { try? FileManager.default.removeItem(at: root) }
        let udidDir = root.appendingPathComponent(udid)
        let reader = try ManifestReader(backupDir: udidDir)
        let unlocked = try Keybag(tlv: try reader.backupKeybagTLV()).unlock(password: password)
        let good = try #require(try reader.recordWithKey(domain: "HomeDomain", path: "known.txt"))
        // Append a trailing byte → 45 bytes; must be rejected.
        let overLong = FileRecord(fileID: good.fileID, domain: good.domain, relativePath: good.relativePath,
                                  flags: good.flags,
                                  encryptionKeyBlob: (good.encryptionKeyBlob ?? Data()) + Data([0x00]),
                                  protectionClass: good.protectionClass)
        let shard = try reader.shardURL(for: good)
        #expect(throws: BackupDecryptor.DecryptError.noEncryptionMetadata) {
            _ = try BackupDecryptor().decrypt(overLong, shardURL: shard, using: unlocked)
        }
    }
}
