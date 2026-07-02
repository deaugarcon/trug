import Testing
import Foundation
@testable import BackupCore

/// SP3 WP1 — G4 / Invariant P2: the startup scrub removes stale Tether decrypt-temps
/// (`tether-*.db`) and leaves non-Tether files untouched. The scrub is the kill-before-`defer`
/// FLOOR. All planted bytes are FAKE (§9).
@Suite struct TempScrubTests {
    @Test func removesStaleTetherRowsTemp() throws {
        let dir = URL.temporaryTestDir()
        defer { try? FileManager.default.removeItem(at: dir) }

        let staleRows = dir.appendingPathComponent("tether-rows-\(UUID().uuidString).db")
        FileManager.default.createFile(atPath: staleRows.path, contents: Data("fake".utf8),
                                       attributes: [.posixPermissions: 0o600])
        #expect(FileManager.default.fileExists(atPath: staleRows.path))

        TempScrub.run(in: dir)

        #expect(!FileManager.default.fileExists(atPath: staleRows.path))
    }

    /// R-D: the scrub keys on the `tether-` prefix + `.db` suffix, so it must clear BOTH the
    /// reader's `tether-rows-*` and the verifier's `tether-readability-*` residue.
    @Test func removesBothTetherTempFamilies() throws {
        let dir = URL.temporaryTestDir()
        defer { try? FileManager.default.removeItem(at: dir) }

        let rows = dir.appendingPathComponent("tether-rows-x.db")
        let readability = dir.appendingPathComponent("tether-readability-x.db")
        FileManager.default.createFile(atPath: rows.path, contents: Data("a".utf8),
                                       attributes: [.posixPermissions: 0o600])
        FileManager.default.createFile(atPath: readability.path, contents: Data("b".utf8),
                                       attributes: [.posixPermissions: 0o600])

        TempScrub.run(in: dir)

        #expect(!FileManager.default.fileExists(atPath: rows.path))
        #expect(!FileManager.default.fileExists(atPath: readability.path))
    }

    @Test func leavesNonTetherFilesUntouched() throws {
        let dir = URL.temporaryTestDir()
        defer { try? FileManager.default.removeItem(at: dir) }

        // A non-tether file, and a tether-prefixed file with the WRONG suffix — both must survive.
        let keep = dir.appendingPathComponent("important-user.db")
        let wrongSuffix = dir.appendingPathComponent("tether-notes.txt")
        FileManager.default.createFile(atPath: keep.path, contents: Data("keep".utf8))
        FileManager.default.createFile(atPath: wrongSuffix.path, contents: Data("keep".utf8))
        let stale = dir.appendingPathComponent("tether-rows-y.db")
        FileManager.default.createFile(atPath: stale.path, contents: Data("gone".utf8),
                                       attributes: [.posixPermissions: 0o600])

        TempScrub.run(in: dir)

        #expect(FileManager.default.fileExists(atPath: keep.path))
        #expect(FileManager.default.fileExists(atPath: wrongSuffix.path))
        #expect(!FileManager.default.fileExists(atPath: stale.path))
    }

    /// A missing directory must not be fatal — the scrub is a floor, not a gate.
    @Test func missingDirectoryIsNotFatal() {
        let absent = URL.temporaryTestDir().appendingPathComponent("does-not-exist")
        TempScrub.run(in: absent)   // must simply return
    }
}
