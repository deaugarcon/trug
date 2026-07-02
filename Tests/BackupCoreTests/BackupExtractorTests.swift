import Testing
import Foundation
@testable import BackupCore

@Suite struct BackupExtractorTests {
    @Test func extractsUnencryptedFile() throws {
        let root = try FixtureBuilder.unencryptedBackup(udid: "U", files: [
            .init(domain: "HomeDomain", path: "a.txt", contents: Data("hello".utf8)),
        ])
        defer { try? FileManager.default.removeItem(at: root) }
        let data = try BackupExtractor().extract(udidDir: root.appendingPathComponent("U"),
                                                 domain: "HomeDomain", path: "a.txt", password: "")
        #expect(data == Data("hello".utf8))
    }

    @Test func extractsEncryptedFileViaKeybag() throws {
        let (root, udid, password) = try FixtureBuilder.encryptedBackupWithKnownFile()
        defer { try? FileManager.default.removeItem(at: root) }
        let data = try BackupExtractor().extract(udidDir: root.appendingPathComponent(udid),
                                                 domain: "HomeDomain", path: "known.txt", password: password)
        #expect(data == (try Fixtures.encryptedFile().plaintext))
    }

    /// A missing file in an EXISTING backup is fileNotFoundInBackup, not backupNotFound
    /// (the plan pseudocode used the wrong error — the backup is present).
    @Test func missingFileThrowsFileNotFoundInBackup() throws {
        let root = try FixtureBuilder.unencryptedBackup(udid: "U", files: [
            .init(domain: "HomeDomain", path: "a.txt", contents: Data("hello".utf8)),
        ])
        defer { try? FileManager.default.removeItem(at: root) }
        #expect(throws: VerifyError.fileNotFoundInBackup(domain: "HomeDomain", path: "nope.txt")) {
            _ = try BackupExtractor().extract(udidDir: root.appendingPathComponent("U"),
                                              domain: "HomeDomain", path: "nope.txt", password: "")
        }
    }
}
