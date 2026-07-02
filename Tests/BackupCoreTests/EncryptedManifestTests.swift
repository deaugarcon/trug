import Testing
import Foundation
@testable import BackupCore

/// Task #10: real encrypted backups encrypt Manifest.db itself. ManifestReader must decrypt it
/// (ManifestKey from Manifest.plist, unwrapped via the keybag) before opening it as SQLite.
@Suite struct EncryptedManifestTests {
    @Test func opensEncryptedManifestAndReadsRows() throws {
        let (root, udid, password) = try FixtureBuilder.encryptedBackupWithEncryptedManifest()
        defer { try? FileManager.default.removeItem(at: root) }
        let udidDir = root.appendingPathComponent(udid)
        let keybag = try Keybag(tlv: try ManifestReader.backupKeybagTLV(in: udidDir)).unlock(password: password)
        let reader = try ManifestReader(backupDir: udidDir, unlockedKeybag: keybag)
        // The encrypted manifest decrypted + opened: its one row is visible.
        let rec = try #require(try reader.record(domain: "HomeDomain", path: "known.txt"))
        #expect(rec.isFile)
    }

    @Test func cryptoVerifyPassesOnEncryptedManifestBackup() throws {
        let (root, udid, password) = try FixtureBuilder.encryptedBackupWithEncryptedManifest()
        defer { try? FileManager.default.removeItem(at: root) }
        let report = try BackupVerifier().verify(backupDir: root, udid: udid, level: .crypto, password: password)
        #expect(report.passed, "findings: \(report.findings)")
    }

    // MARK: - WP4.2 / Checkpoint C run 3: per-file metadata is a custom MBFile archive

    /// Crypto verify must SAMPLE >= 1 file on a real-MBFile-shaped backup. Checkpoint C run 3 found
    /// `verify --level crypto` sampling 0 files ("no host-unlockable encrypted files found") because
    /// decodeFileMetadata threw on every real MBFile BLOB and the verifier swallowed it. With the
    /// class-name-mapped decoder, the known file is sampled and its decrypted bytes carry the bplist
    /// signature, so the report passes with filesChecked >= 1 (not a vacuous zero-sample pass).
    @Test func cryptoVerifySamplesMBFileBackedFile() throws {
        let (root, udid, password) = try FixtureBuilder.encryptedBackupWithEncryptedManifest()
        defer { try? FileManager.default.removeItem(at: root) }
        let report = try BackupVerifier().verify(backupDir: root, udid: udid, level: .crypto, password: password)
        #expect(report.passed, "findings: \(report.findings)")
        #expect(report.filesChecked >= 1, "crypto verify must sample at least one MBFile-backed file")
    }

    /// NON-VACUITY LOCK: the fixture BLOB is a real MBFile archive, so the OLD secure decoder
    /// (`unarchivedObject(ofClasses:[NSDictionary,NSString,NSNumber,NSData])`) must FAIL to produce a
    /// usable record from it — proving the new class-name-mapped decoder is genuinely required and
    /// the test is not passing against a plain NSDictionary. If this ever succeeds, the fixture has
    /// regressed to the vacuous shape that hid the checkpoint C run 3 bug.
    @Test func fixtureBlobIsRealMBFileNotPlainDict() throws {
        let ef = try Fixtures.encryptedFile()
        let blob = try FixtureBuilder.mbFileArchive(protectionClass: ef.protectionClass,
                                                    encryptionKeyBlob: ef.encryptionKeyBlob,
                                                    relativePath: ef.relativePath)
        // The old allow-list decoder cannot materialize a [String:Any] with the key fields from a
        // custom-MBFile-root archive: it either throws or returns something that is not the dict.
        let decoded = try? NSKeyedUnarchiver.unarchivedObject(
            ofClasses: [NSDictionary.self, NSString.self, NSNumber.self, NSData.self], from: blob)
        let asDict = decoded as? [String: Any]
        let hasKeyFields = (asDict?["ProtectionClass"] != nil) && (asDict?["EncryptionKey"] != nil)
        #expect(!hasKeyFields, "fixture must be a real MBFile archive the old ofClasses decoder cannot read")
    }

    /// The new decoder recovers the protection class and the 44-byte EncryptionKey blob from the real
    /// MBFile archive, via the full reader path (recordWithKey), so the per-file decrypt has its key.
    @Test func decoderRecoversKeyFromMBFileArchive() throws {
        let (root, udid, password) = try FixtureBuilder.encryptedBackupWithEncryptedManifest()
        defer { try? FileManager.default.removeItem(at: root) }
        let udidDir = root.appendingPathComponent(udid)
        let keybag = try Keybag(tlv: try ManifestReader.backupKeybagTLV(in: udidDir)).unlock(password: password)
        let reader = try ManifestReader(backupDir: udidDir, unlockedKeybag: keybag)
        let ef = try Fixtures.encryptedFile()
        let keyed = try #require(try reader.recordWithKey(domain: ef.domain, path: ef.relativePath))
        #expect(keyed.protectionClass == ef.protectionClass)
        #expect(keyed.encryptionKeyBlob == ef.encryptionKeyBlob)   // 44B: 4B prefix + 40B wrapped
    }

    @Test func extractFromEncryptedManifestBackup() throws {
        let (root, udid, password) = try FixtureBuilder.encryptedBackupWithEncryptedManifest()
        defer { try? FileManager.default.removeItem(at: root) }
        let data = try BackupExtractor().extract(udidDir: root.appendingPathComponent(udid),
                                                 domain: "HomeDomain", path: "known.txt", password: password)
        #expect(data == (try Fixtures.encryptedFile().plaintext))
    }

    /// A wrong password must fail at keybag unlock (wrongPassword), NOT as a manifestUnreadable
    /// from a failed manifest decrypt — the keybag is the authority (task #10 item 4).
    @Test func wrongPasswordFailsWithWrongPasswordNotManifestUnreadable() throws {
        let (root, udid, _) = try FixtureBuilder.encryptedBackupWithEncryptedManifest()
        defer { try? FileManager.default.removeItem(at: root) }
        let udidDir = root.appendingPathComponent(udid)
        #expect(throws: KeybagError.wrongPassword) {
            _ = try Keybag(tlv: try ManifestReader.backupKeybagTLV(in: udidDir)).unlock(password: "wrong")
        }
        // And the end-to-end crypto verify surfaces wrongPassword too (unlock happens before open).
        #expect(throws: KeybagError.wrongPassword) {
            _ = try BackupVerifier().verify(backupDir: root, udid: udid, level: .crypto, password: "wrong")
        }
    }

    /// Task #11: the ManifestKey class prefix is LITTLE-endian. The oracle must emit class 4 as the
    /// bytes 04 00 00 00 — a regression to big-endian (00 00 00 04) keeps the synthetic test green
    /// against a matching BE reader but breaks every real backup. Pin the wire bytes.
    @Test func manifestKeyPrefixIsLittleEndian() throws {
        let blob = try Fixtures.encryptedManifest().manifestKeyBlob
        #expect(Array(blob.prefix(4)) == [0x04, 0x00, 0x00, 0x00],
                "ManifestKey class prefix must be little-endian (04 00 00 00 for class 4)")
    }

    /// Task #11 item 2: the manifest decrypt must NOT require valid PKCS7 — a manifest whose
    /// trailing bytes are zero-padded (not PKCS7) must still open. Success is asserted by the
    /// SQLite open + Files read, never by padding validity (strict PKCS7 = MVT #93/#571 false fails).
    @Test func opensZeroPaddedEncryptedManifest() throws {
        let (root, udid, password) = try FixtureBuilder.encryptedBackupWithEncryptedManifest(padding: .zero)
        defer { try? FileManager.default.removeItem(at: root) }
        let udidDir = root.appendingPathComponent(udid)
        let keybag = try Keybag(tlv: try ManifestReader.backupKeybagTLV(in: udidDir)).unlock(password: password)
        let reader = try ManifestReader(backupDir: udidDir, unlockedKeybag: keybag)
        let rec = try #require(try reader.record(domain: "HomeDomain", path: "known.txt"))
        #expect(rec.isFile)
    }

    /// Checkpoint B: the decrypted-temp path must also handle a WAL-mode plaintext. When the
    /// encrypted Manifest.db decrypts to a WAL-mode db (header 02 02), the temp file the reader
    /// opens is a WAL db with no sidecars — exactly the plaintext-WAL case. The immutable open must
    /// read it identically, so the encrypted-WAL backup's row is visible.
    @Test func opensEncryptedManifestWithWALPlaintext() throws {
        let (root, udid, password) = try FixtureBuilder.encryptedBackupWithEncryptedManifest(walPlaintext: true)
        defer { try? FileManager.default.removeItem(at: root) }
        let udidDir = root.appendingPathComponent(udid)
        let keybag = try Keybag(tlv: try ManifestReader.backupKeybagTLV(in: udidDir)).unlock(password: password)
        let reader = try ManifestReader(backupDir: udidDir, unlockedKeybag: keybag)
        let rec = try #require(try reader.record(domain: "HomeDomain", path: "known.txt"))
        #expect(rec.isFile)
    }

    /// The reader's decode must be LE-sensitive: a ManifestKey whose prefix is the BIG-endian
    /// encoding of class 4 (00 00 00 04) must NOT open — an LE read of those bytes is 0x04000000,
    /// which the keybag has no key for. This fails if the seam ever silently reads big-endian.
    @Test func bigEndianPrefixManifestKeyFailsToOpen() throws {
        let (root, udid, password) = try FixtureBuilder.encryptedBackupWithEncryptedManifest()
        defer { try? FileManager.default.removeItem(at: root) }
        let udidDir = root.appendingPathComponent(udid)

        // Rewrite Manifest.plist's ManifestKey with the SAME wrapped key but a BE class prefix.
        let leBlob = try Fixtures.encryptedManifest().manifestKeyBlob
        let beBlob = Data([0x00, 0x00, 0x00, 0x04]) + leBlob.suffix(from: leBlob.startIndex + 4)
        let plistURL = udidDir.appendingPathComponent("Manifest.plist")
        var plist = try #require(PropertyListSerialization.propertyList(
            from: try Data(contentsOf: plistURL), options: [], format: nil) as? [String: Any])
        plist["ManifestKey"] = beBlob
        try PropertyListSerialization.data(fromPropertyList: plist, format: .xml, options: 0).write(to: plistURL)

        let keybag = try Keybag(tlv: try ManifestReader.backupKeybagTLV(in: udidDir)).unlock(password: password)
        #expect(throws: VerifyError.self) {
            _ = try ManifestReader(backupDir: udidDir, unlockedKeybag: keybag)
        }
    }
}
