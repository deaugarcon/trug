import Testing
import Foundation
@testable import BackupCore

@Suite struct BackupStoreTests {
    func makeStore() -> (BackupStore, URL) {
        let root = URL.temporaryTestDir()
        return (BackupStore(root: root), root)
    }
    let id = BackupID(udid: "TESTUDID")

    @Test func firstStagingStartsEmptyAndPromotes() throws {
        let (store, root) = makeStore()
        defer { try? FileManager.default.removeItem(at: root) }
        let staging = try store.beginStaging(for: id)
        #expect(FileManager.default.fileExists(atPath: staging.directory.path))
        // simulate MB2 writing a file
        try Data("x".utf8).write(to: staging.directory.appendingPathComponent("Status.plist"))
        try store.promote(staging)
        let current = try #require(try store.currentBackupDirectory(for: id))
        #expect(FileManager.default.fileExists(atPath: current.appendingPathComponent("Status.plist").path))
        #expect(store.state(for: id) == .verified)
    }

    @Test func failedStagingLeavesPreviousVerifiedIntact() throws {
        let (store, root) = makeStore()
        defer { try? FileManager.default.removeItem(at: root) }
        // first good backup
        let s1 = try store.beginStaging(for: id)
        try Data("v1".utf8).write(to: s1.directory.appendingPathComponent("marker.txt"))
        try store.promote(s1)
        let firstDir = try #require(try store.currentBackupDirectory(for: id))

        // second backup that fails
        let s2 = try store.beginStaging(for: id)
        try Data("v2-partial".utf8).write(to: s2.directory.appendingPathComponent("marker.txt"))
        store.markFailed(s2)

        // current still points at the first, intact
        let current = try #require(try store.currentBackupDirectory(for: id))
        #expect(current == firstDir)
        #expect(try String(contentsOf: current.appendingPathComponent("marker.txt")) == "v1")
        #expect(store.state(for: id) == .verified)
    }

    @Test func secondStagingClonesFromCurrent() throws {
        let (store, root) = makeStore()
        defer { try? FileManager.default.removeItem(at: root) }
        let s1 = try store.beginStaging(for: id)
        try Data("base".utf8).write(to: s1.directory.appendingPathComponent("keep.txt"))
        try store.promote(s1)

        let s2 = try store.beginStaging(for: id)
        // clone carried the prior file forward (incremental backups rely on this)
        #expect(FileManager.default.fileExists(atPath: s2.directory.appendingPathComponent("keep.txt").path))
    }

    /// Spec §9.1 headline: a process death mid-backup (NO markFailed call) must not touch `current`.
    /// This proves §4.1 across an orphaned staging, not just the graceful markFailed path.
    @Test func orphanedInProgressStagingLeavesCurrentIntact() throws {
        let (store, root) = makeStore()
        defer { try? FileManager.default.removeItem(at: root) }
        // good backup
        let s1 = try store.beginStaging(for: id)
        try Data("good".utf8).write(to: s1.directory.appendingPathComponent("marker.txt"))
        try store.promote(s1)
        let firstDir = try #require(try store.currentBackupDirectory(for: id))

        // simulate process death: a .staging dir left in-progress, NO markFailed, NO promote
        let s2 = try store.beginStaging(for: id)
        try Data("partial".utf8).write(to: s2.directory.appendingPathComponent("marker.txt"))

        // current still points at the good backup, content intact
        let current = try #require(try store.currentBackupDirectory(for: id))
        #expect(current == firstDir)
        #expect(try String(contentsOf: current.appendingPathComponent("marker.txt")) == "good")

        // the next create discards the orphan and re-clones "good" from current
        let s3 = try store.beginStaging(for: id)
        #expect(try String(contentsOf: s3.directory.appendingPathComponent("marker.txt")) == "good")
    }

    /// Reads the raw `TetherState` of a staging directory directly (no public reader exists for an
    /// arbitrary, not-yet-promoted directory — `state(for:)` reads `current`).
    private func rawState(of dir: URL) -> String? {
        try? String(contentsOf: dir.appendingPathComponent("TetherState"))
            .trimmingCharacters(in: .whitespacesAndNewlines)
    }

    /// Checkpoint B (§4.1 glue gap): a verify that THROWS after a successful backup left the staging
    /// "in-progress" on the real device, because the create glue only marked failed for (a) a thrown
    /// backup and (b) report.passed == false — a thrown verify/promote escaped without markFailed.
    /// `finalize` closes that gap: ANY thrown error from the verify-through-promote closure marks the
    /// staging failed before rethrowing. After a throwing verify, TetherState must read "failed".
    @Test func finalizeMarksFailedWhenVerifyThrows() throws {
        let (store, root) = makeStore()
        defer { try? FileManager.default.removeItem(at: root) }
        let staging = try store.beginStaging(for: id)
        #expect(rawState(of: staging.directory) == "in-progress")

        struct StubVerifyError: Error {}
        #expect(throws: StubVerifyError.self) {
            try store.finalize(staging) { throw StubVerifyError() }
        }
        #expect(rawState(of: staging.directory) == "failed", "a thrown verify must leave staging failed (§4.1)")
        // current must not have been created by a failed finalize.
        #expect(try store.currentBackupDirectory(for: id) == nil)
    }

    /// A failed report (passed == false) marks the staging failed exactly once — `finalize` must not
    /// double-mark, and the closure returning `false` is the report-failed arm, not a thrown error.
    @Test func finalizeMarksFailedWhenReportFails() throws {
        let (store, root) = makeStore()
        defer { try? FileManager.default.removeItem(at: root) }
        let staging = try store.beginStaging(for: id)
        #expect(throws: BackupError.verificationFailed) {
            try store.finalize(staging) { false }   // verify ran, report did not pass
        }
        #expect(rawState(of: staging.directory) == "failed")
        #expect(try store.currentBackupDirectory(for: id) == nil)
    }

    /// The happy path: a passing verify (closure returns `true`) promotes the staging — TetherState
    /// "verified" and `current` now resolves. `finalize` must NOT markFailed on success.
    @Test func finalizePromotesWhenVerifyPasses() throws {
        let (store, root) = makeStore()
        defer { try? FileManager.default.removeItem(at: root) }
        let staging = try store.beginStaging(for: id)
        try Data("x".utf8).write(to: staging.directory.appendingPathComponent("Status.plist"))
        try store.finalize(staging) { true }
        #expect(store.state(for: id) == .verified)
        let current = try #require(try store.currentBackupDirectory(for: id))
        #expect(FileManager.default.fileExists(atPath: current.appendingPathComponent("Status.plist").path))
    }

    /// A throw from PROMOTE (not verify) must also markFailed — the checkpoint-B gap covered the
    /// whole verify-through-promote sequence, not just verify. We force a promote failure by deleting
    /// the staging directory out from under `finalize` after the verify closure passes.
    @Test func finalizeMarksFailedWhenPromoteThrows() throws {
        let (store, root) = makeStore()
        defer { try? FileManager.default.removeItem(at: root) }
        let staging = try store.beginStaging(for: id)
        #expect(throws: (any Error).self) {
            try store.finalize(staging) {
                // Verify "passes", but the staging dir vanishes before promote moves it.
                try FileManager.default.removeItem(at: staging.directory)
                return true
            }
        }
        // The staging dir is gone, so markFailed's write is a no-op (try?), but the invariant holds:
        // no promotion happened and `current` was never created.
        #expect(try store.currentBackupDirectory(for: id) == nil)
    }

    @Test func pruneKeepsCurrentAndPreviousGeneration() throws {
        let (store, root) = makeStore()
        defer { try? FileManager.default.removeItem(at: root) }
        for i in 0..<3 {
            let s = try store.beginStaging(for: id)
            try Data("gen\(i)".utf8).write(to: s.directory.appendingPathComponent("g.txt"))
            try store.promote(s)
        }
        // after 3 promotions, exactly 2 generations remain on disk (current + previous)
        let gens = try FileManager.default.contentsOfDirectory(atPath: root.appendingPathComponent(id.udid).path)
            .filter { $0.hasPrefix("backup-") }
        #expect(gens.count == 2)
    }
}
