import Testing
import Foundation
@testable import BackupCore

@Suite struct ManifestReaderTests {
    @Test func enumeratesFilesInDomain() throws {
        let root = try FixtureBuilder.unencryptedBackup(udid: "U", files: [
            .init(domain: "HomeDomain", path: "Library/SMS/sms.db", contents: Data("db".utf8)),
            .init(domain: "CameraRollDomain", path: "Media/DCIM/IMG_0001.JPG", contents: Data("jpg".utf8)),
        ])
        defer { try? FileManager.default.removeItem(at: root) }
        let reader = try ManifestReader(backupDir: root.appendingPathComponent("U"))
        let home = try reader.files(inDomain: "HomeDomain")
        #expect(home.count == 1)
        #expect(home.first?.relativePath == "Library/SMS/sms.db")
    }

    @Test func locatesRecordByDomainAndPath() throws {
        let root = try FixtureBuilder.unencryptedBackup(udid: "U", files: [
            .init(domain: "HomeDomain", path: "Library/SMS/sms.db", contents: Data("db".utf8)),
        ])
        defer { try? FileManager.default.removeItem(at: root) }
        let reader = try ManifestReader(backupDir: root.appendingPathComponent("U"))
        let rec = try #require(try reader.record(domain: "HomeDomain", path: "Library/SMS/sms.db"))
        #expect(rec.isFile)
    }

    @Test func readsMetadata() throws {
        let root = try FixtureBuilder.unencryptedBackup(udid: "U", files: [])
        defer { try? FileManager.default.removeItem(at: root) }
        let reader = try ManifestReader(backupDir: root.appendingPathComponent("U"))
        let meta = try reader.metadata()
        #expect(meta.isEncrypted == false)
        #expect(meta.productVersion == "27.0")
    }

    @Test func allFilesReturnsEveryRow() throws {
        let root = try FixtureBuilder.unencryptedBackup(udid: "U", files: [
            .init(domain: "HomeDomain", path: "a.db", contents: Data("a".utf8)),
            .init(domain: "CameraRollDomain", path: "b.jpg", contents: Data("b".utf8)),
        ])
        defer { try? FileManager.default.removeItem(at: root) }
        let reader = try ManifestReader(backupDir: root.appendingPathComponent("U"))
        #expect(try reader.allFiles().count == 2)
    }

    @Test func shardURLMatchesFixtureLayout() throws {
        let root = try FixtureBuilder.unencryptedBackup(udid: "U", files: [
            .init(domain: "HomeDomain", path: "Library/SMS/sms.db", contents: Data("db".utf8)),
        ])
        defer { try? FileManager.default.removeItem(at: root) }
        let reader = try ManifestReader(backupDir: root.appendingPathComponent("U"))
        let rec = try #require(try reader.record(domain: "HomeDomain", path: "Library/SMS/sms.db"))
        let shard = try reader.shardURL(for: rec)
        #expect(FileManager.default.fileExists(atPath: shard.path))
    }

    /// Odb WP3 Finding 1 (HIGH): `fileID` is untrusted device data. `shardURL` must reject any
    /// fileID that is not strict 40-char lowercase SHA1 hex, so a crafted manifest cannot steer a
    /// host path out of the backup directory. Each hostile value must throw `malformedFileID` —
    /// fail loudly, never fall through to a path join.
    @Test func shardURLRejectsHostileFileIDs() throws {
        let root = try FixtureBuilder.unencryptedBackup(udid: "U", files: [])
        defer { try? FileManager.default.removeItem(at: root) }
        let reader = try ManifestReader(backupDir: root.appendingPathComponent("U"))
        let hostile = [
            "",                                              // empty → would collapse to backupDir
            "../../../../etc/passwd",                        // traversal
            "/etc/passwd",                                   // absolute
            "a/b/c",                                         // embedded separators reshape the path
            "..",                                            // parent
            String(repeating: "a", count: 39),              // too short
            String(repeating: "a", count: 41),              // too long
            String(repeating: "A", count: 40),              // uppercase (rejected, not normalized)
            "g" + String(repeating: "0", count: 39),        // non-hex char
            String(repeating: "0", count: 20) + "\u{0}" + String(repeating: "0", count: 19), // NUL
        ]
        for value in hostile {
            let rec = FileRecord(fileID: value, domain: "HomeDomain",
                                 relativePath: "x", flags: 1, encryptionKeyBlob: nil)
            #expect(throws: VerifyError.malformedFileID(value),
                    "expected malformedFileID throw for hostile fileID \(value.debugDescription)") {
                try reader.shardURL(for: rec)
            }
        }
    }

    /// A well-formed 40-char lowercase hex fileID is accepted and shards as `<first2>/<fileID>`.
    @Test func shardURLAcceptsWellFormedHex() throws {
        let root = try FixtureBuilder.unencryptedBackup(udid: "U", files: [])
        defer { try? FileManager.default.removeItem(at: root) }
        let reader = try ManifestReader(backupDir: root.appendingPathComponent("U"))
        let id = FixtureBuilder.fileID(domain: "HomeDomain", path: "Library/SMS/sms.db")
        let rec = FileRecord(fileID: id, domain: "HomeDomain", relativePath: "x", flags: 1, encryptionKeyBlob: nil)
        let shard = try reader.shardURL(for: rec)
        #expect(shard.lastPathComponent == id)
        #expect(shard.deletingLastPathComponent().lastPathComponent == String(id.prefix(2)))
    }

    /// Codex WP3 Finding 1 (MEDIUM): a corrupt/hostile `Manifest.db` that errors *mid-iteration*
    /// must not be presented as a complete, smaller backup. The query must demand `SQLITE_DONE`
    /// as the loop terminator and throw `manifestUnreadable` on any other step result — never
    /// silently truncate the enumeration. The fixture enumerates cleanly for the first rows and
    /// then faults on a clobbered page partway through.
    @Test func enumerationThrowsOnMidScanCorruption() throws {
        let root = try FixtureBuilder.backupWithMidScanCorruptManifest(udid: "U")
        defer { try? FileManager.default.removeItem(at: root) }
        let reader = try ManifestReader(backupDir: root.appendingPathComponent("U"))
        #expect(throws: VerifyError.self) {
            _ = try reader.allFiles()
        }
    }

    /// Checkpoint B (real iOS 27 device): the delivered `Manifest.db` is in WAL journal mode
    /// (header bytes 18-19 == 02 02) with NO `-wal`/`-shm` sidecars. A plain `SQLITE_OPEN_READONLY`
    /// open fails `SQLITE_CANTOPEN(14)` — read-only cannot create the `-shm` a WAL db needs. The
    /// reader must open backup-resident dbs via an `immutable=1` URI (which never writes into the
    /// snapshot), so a WAL-mode manifest reads its rows normally.
    @Test func readsWALModeManifest() throws {
        let root = try FixtureBuilder.walModeBackup(udid: "U", files: [
            .init(domain: "HomeDomain", path: "Library/SMS/sms.db", contents: Data("db".utf8)),
            .init(domain: "CameraRollDomain", path: "Media/DCIM/IMG_0001.JPG", contents: Data("jpg".utf8)),
        ])
        defer { try? FileManager.default.removeItem(at: root) }

        // Non-vacuity lock: assert the fixture really IS WAL mode before relying on the open to
        // exercise the immutable=1 path. SQLite header bytes 18 (write version) and 19 (read
        // version) are both 2 for a WAL-mode db (1 == rollback journal). A future fixture refactor
        // that silently produced a rollback-mode db would otherwise pass under any opener, hollowing
        // out this regression lock. (Odb delta review, in-phase should-fix.)
        let manifestBytes = try Data(contentsOf: root.appendingPathComponent("U/Manifest.db"))
        #expect(Array(manifestBytes[18...19]) == [0x02, 0x02],
                "fixture Manifest.db must be WAL mode (header bytes 18-19 == 02 02), not rollback journal")

        let reader = try ManifestReader(backupDir: root.appendingPathComponent("U"))
        #expect(try reader.allFiles().count == 2)
        let rec = try #require(try reader.record(domain: "HomeDomain", path: "Library/SMS/sms.db"))
        #expect(rec.isFile)
    }

    /// `immutable=1` silently IGNORES any `-wal` sidecar content, so reading a backup whose db has a
    /// `Manifest.db-wal` next to it would present a stale snapshot (committed-but-uncheckpointed pages
    /// dropped). Real device delivery checkpoints the WAL and ships no sidecar; a sidecar's presence
    /// is therefore anomalous and must surface `manifestUnreadable`, never a silently-stale read.
    @Test func walSidecarPresenceIsManifestUnreadable() throws {
        let root = try FixtureBuilder.walModeBackup(
            udid: "U",
            files: [.init(domain: "HomeDomain", path: "a.db", contents: Data("a".utf8))],
            retainWALSidecar: true)
        defer { try? FileManager.default.removeItem(at: root) }
        #expect(throws: VerifyError.self) {
            _ = try ManifestReader(backupDir: root.appendingPathComponent("U"))
        }
    }

    /// WP2 baton carry-forward (b) / WP1 deferred item 4: a manifest carrying a
    /// self-referential `file` BLOB must not make enumeration loop or fault.
    /// The flat reader returns each row exactly once and terminates.
    @Test func circularFileIDReferencesDoNotLoop() throws {
        let root = try FixtureBuilder.unencryptedBackup(
            udid: "U",
            files: [.init(domain: "HomeDomain", path: "a.db", contents: Data("a".utf8))],
            circularFileIDs: true)
        defer { try? FileManager.default.removeItem(at: root) }
        let reader = try ManifestReader(backupDir: root.appendingPathComponent("U"))
        let all = try reader.allFiles()
        #expect(all.count == 2)   // the seeded file + the self-referential loop row
        #expect(Set(all.map(\.fileID)).count == all.count)   // no fileID enumerated twice
        let loop = try #require(try reader.record(domain: "HomeDomain", path: "Library/loop.bin"))
        #expect(loop.isFile)
    }
}
