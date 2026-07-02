import Testing
import Foundation
import BackupCore
@testable import TetherCLI

/// SP3.1 (feat/sp3.1) — the guarded, symlink-safe disk writer shared by `extract` and `export`
/// (ported from feat/sp3 462b3ea; on this branch BOTH the JSON and CSV export paths flow through it
/// via the B5 `writeGuarded` core).
///
/// Codex adversarial review, gate A3 FAIL (High): the former `removeItem`-then-`createFile` write
/// pattern let a `--force` `--out` that names an existing DIRECTORY be recursively deleted, and let
/// the file APIs follow a symlink. These tests lock the corrected behavior:
///   R1 `--force` on an existing NON-EMPTY directory MUST throw and leave the dir + contents intact.
///   R2 no `--force` on a DANGLING symlink MUST throw (no-clobber) and leave the symlink intact.
///   H* the shared `Backup.writeGuardedFile` seam (what BOTH `extract` and `export` call): success,
///      0600, no-clobber, force-overwrite of a plain file, and symlink NO-FOLLOW (target intact).
///   C1 the CSV export path (`writeCSV` → `writeGuarded` → `writeGuardedFile`) shares the SAME guard:
///      `--force` at a directory `--out` is refused, proving CSV is not a second, unguarded surface.
///
/// `extract`'s write path is not driveable at this layer (its `run()` resolves `.defaultRoot` and
/// needs a decrypted backup fixture), so the extract-equivalent behavior is proven on the shared
/// `Backup.writeGuardedFile` helper it calls — byte-identical to the `export` seam.
@Suite struct GuardedWriteTests {

    private static func makeTempDir() throws -> URL {
        let dir = FileManager.default.temporaryDirectory
            .appendingPathComponent("guarded-write-\(UUID().uuidString)", isDirectory: true)
        try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        return dir
    }

    /// Asserts `body` throws `ExtractError.outputExists` SPECIFICALLY — pins the exit-2 no-clobber /
    /// directory-reject contract (Odb F1). `ExtractError` is NOT `Equatable` and its associated path
    /// varies, so the CASE is matched rather than a value: a silent drift to `.writeFailed` (exit 70) —
    /// e.g. if the explicit `S_IFDIR` reject were dropped and a dir + `--force` fell through to a
    /// failing `unlink` — is caught here instead of passing as merely "some ExtractError".
    private static func expectOutputExists(
        _ body: () throws -> Void, sourceLocation: SourceLocation = #_sourceLocation
    ) {
        let error = #expect(throws: ExtractError.self, sourceLocation: sourceLocation, performing: body)
        guard case .outputExists? = error else {
            Issue.record("expected ExtractError.outputExists, got \(String(describing: error))",
                         sourceLocation: sourceLocation)
            return
        }
    }

    // MARK: R1 — --force must NOT recursively delete a directory named by --out

    @Test func forceMustNotDeleteDirectoryAtOutPath() throws {
        let tmp = try Self.makeTempDir()
        defer { try? FileManager.default.removeItem(at: tmp) }

        // A NON-EMPTY directory at the --out path, with a sentinel child that must survive.
        let outDir = tmp.appendingPathComponent("victim-dir", isDirectory: true)
        try FileManager.default.createDirectory(at: outDir, withIntermediateDirectories: true)
        let child = outDir.appendingPathComponent("keep.txt")
        let childBytes = Data("DO NOT DELETE".utf8)
        #expect(FileManager.default.createFile(atPath: child.path, contents: childBytes))

        let env = ExportEnvelope(store: "messages", rows: [MessageRow]())
        // A directory is refused with the no-clobber exit-2 case, NOT a write failure (exit 70).
        Self.expectOutputExists {
            try Backup.Export.writeJSON(env, to: outDir.path, force: true)
        }

        // The directory AND its contents must be intact — --force overwrites a file, never a tree.
        var isDir: ObjCBool = false
        #expect(FileManager.default.fileExists(atPath: outDir.path, isDirectory: &isDir))
        #expect(isDir.boolValue)
        #expect(try Data(contentsOf: child) == childBytes)
    }

    // MARK: R2 — no --force on a DANGLING symlink must no-clobber, not replace the link

    @Test func noForceOnDanglingSymlinkThrowsAndKeepsLink() throws {
        let tmp = try Self.makeTempDir()
        defer { try? FileManager.default.removeItem(at: tmp) }

        let link = tmp.appendingPathComponent("out.json").path
        let missingTarget = tmp.appendingPathComponent("nowhere.json").path
        try FileManager.default.createSymbolicLink(atPath: link, withDestinationPath: missingTarget)

        let env = ExportEnvelope(store: "messages", rows: [MessageRow]())
        // No-clobber on the dangling entry is the exit-2 outputExists case, never writeFailed.
        Self.expectOutputExists {
            try Backup.Export.writeJSON(env, to: link, force: false)
        }

        // The symlink is still a symlink to the same (still-missing) target — not replaced by a file.
        #expect(try FileManager.default.destinationOfSymbolicLink(atPath: link) == missingTarget)
        #expect(!FileManager.default.fileExists(atPath: missingTarget))
    }

    // MARK: H1 — success: a fresh file is created 0600 with the EXACT bytes

    @Test func helperCreatesFileAt0600WithExactBytes() throws {
        let tmp = try Self.makeTempDir()
        defer { try? FileManager.default.removeItem(at: tmp) }
        let out = tmp.appendingPathComponent("out.bin").path
        let bytes = Data("decrypted plaintext".utf8)

        try Backup.writeGuardedFile(bytes, to: out, force: false)

        #expect(try Data(contentsOf: URL(fileURLWithPath: out)) == bytes)
        let perms = try #require(FileManager.default.attributesOfItem(atPath: out)[.posixPermissions] as? NSNumber)
        #expect(perms.int16Value == 0o600)
    }

    // MARK: H2 — the extract-equivalent: --force on a NON-EMPTY directory is refused, tree survives

    /// `extract`'s write path calls this exact helper (its `run()` is not driveable here — it resolves
    /// `.defaultRoot` and needs a decrypted backup fixture), so the directory-reject invariant for
    /// extract is proven directly on the shared seam, mirroring R1 for export.
    @Test func helperRefusesDirectoryWithForceAndKeepsContents() throws {
        let tmp = try Self.makeTempDir()
        defer { try? FileManager.default.removeItem(at: tmp) }
        let outDir = tmp.appendingPathComponent("victim-dir", isDirectory: true)
        try FileManager.default.createDirectory(at: outDir, withIntermediateDirectories: true)
        let child = outDir.appendingPathComponent("keep.txt")
        let childBytes = Data("DO NOT DELETE".utf8)
        #expect(FileManager.default.createFile(atPath: child.path, contents: childBytes))

        // The S_IFDIR reject is the exit-2 outputExists case — a dropped check would surface as
        // writeFailed (exit 70) from the fall-through unlink, which this pin would catch.
        Self.expectOutputExists {
            try Backup.writeGuardedFile(Data("x".utf8), to: outDir.path, force: true)
        }

        var isDir: ObjCBool = false
        #expect(FileManager.default.fileExists(atPath: outDir.path, isDirectory: &isDir))
        #expect(isDir.boolValue)
        #expect(try Data(contentsOf: child) == childBytes)
    }

    // MARK: H3 — no-clobber without --force on a plain file; file UNCHANGED

    @Test func helperRefusesToClobberPlainFileWithoutForce() throws {
        let tmp = try Self.makeTempDir()
        defer { try? FileManager.default.removeItem(at: tmp) }
        let out = tmp.appendingPathComponent("out.bin").path
        let sentinel = Data("PRE-EXISTING".utf8)
        #expect(FileManager.default.createFile(atPath: out, contents: sentinel))

        // No-clobber on an existing plain file is the exit-2 outputExists case.
        Self.expectOutputExists {
            try Backup.writeGuardedFile(Data("NEW".utf8), to: out, force: false)
        }
        #expect(try Data(contentsOf: URL(fileURLWithPath: out)) == sentinel)
    }

    // MARK: H4 — --force overwrites a plain file with the new bytes (still 0600)

    @Test func helperForceOverwritesPlainFile() throws {
        let tmp = try Self.makeTempDir()
        defer { try? FileManager.default.removeItem(at: tmp) }
        let out = tmp.appendingPathComponent("out.bin").path
        #expect(FileManager.default.createFile(atPath: out, contents: Data("STALE".utf8)))

        let fresh = Data("FRESH".utf8)
        try Backup.writeGuardedFile(fresh, to: out, force: true)

        #expect(try Data(contentsOf: URL(fileURLWithPath: out)) == fresh)
        let perms = try #require(FileManager.default.attributesOfItem(atPath: out)[.posixPermissions] as? NSNumber)
        #expect(perms.int16Value == 0o600)
    }

    // MARK: H5 — symlink + no --force: no-clobber throw; link and TARGET both untouched (no-follow)

    @Test func helperNoForceOnSymlinkThrowsAndDoesNotTouchTarget() throws {
        let tmp = try Self.makeTempDir()
        defer { try? FileManager.default.removeItem(at: tmp) }
        let target = tmp.appendingPathComponent("target.txt").path
        let targetBytes = Data("TARGET-KEEP".utf8)
        #expect(FileManager.default.createFile(atPath: target, contents: targetBytes))
        let link = tmp.appendingPathComponent("out.bin").path
        try FileManager.default.createSymbolicLink(atPath: link, withDestinationPath: target)

        // No-clobber on the symlink entry is the exit-2 outputExists case (never follows the link).
        Self.expectOutputExists {
            try Backup.writeGuardedFile(Data("NEW".utf8), to: link, force: false)
        }
        // The symlink is still a symlink to the same target, and the target bytes are unchanged.
        #expect(try FileManager.default.destinationOfSymbolicLink(atPath: link) == target)
        #expect(try Data(contentsOf: URL(fileURLWithPath: target)) == targetBytes)
    }

    // MARK: H6 — symlink + --force: the LINK is replaced by a real file; the TARGET is untouched

    @Test func helperForceReplacesSymlinkItselfNotItsTarget() throws {
        let tmp = try Self.makeTempDir()
        defer { try? FileManager.default.removeItem(at: tmp) }
        let target = tmp.appendingPathComponent("target.txt").path
        let targetBytes = Data("TARGET-KEEP".utf8)
        #expect(FileManager.default.createFile(atPath: target, contents: targetBytes))
        let link = tmp.appendingPathComponent("out.bin").path
        try FileManager.default.createSymbolicLink(atPath: link, withDestinationPath: target)

        let fresh = Data("FRESH".utf8)
        try Backup.writeGuardedFile(fresh, to: link, force: true)

        // `out` is now a REGULAR file (the symlink was unlinked, not followed) holding the new bytes.
        let outType = try #require(FileManager.default.attributesOfItem(atPath: link)[.type] as? FileAttributeType)
        #expect(outType == .typeRegular)
        #expect(try Data(contentsOf: URL(fileURLWithPath: link)) == fresh)
        // The symlink's former TARGET is byte-untouched — the write never followed the link.
        #expect(try Data(contentsOf: URL(fileURLWithPath: target)) == targetBytes)
    }

    // MARK: C1 — the CSV export path shares the SAME guard as JSON (B5 writeGuarded core)

    /// `export --format csv` writes through `writeCSV → writeGuarded → Backup.writeGuardedFile`, the
    /// SAME guard the JSON path uses. Driving `writeCSV` at a directory `--out` with `--force` must be
    /// refused (dir + contents intact), proving CSV is not a second, unguarded disk surface (P4).
    @Test func csvPathRefusesDirectoryWithForceThroughSharedGuard() throws {
        let tmp = try Self.makeTempDir()
        defer { try? FileManager.default.removeItem(at: tmp) }
        let outDir = tmp.appendingPathComponent("victim-dir", isDirectory: true)
        try FileManager.default.createDirectory(at: outDir, withIntermediateDirectories: true)
        let child = outDir.appendingPathComponent("keep.txt")
        let childBytes = Data("DO NOT DELETE".utf8)
        #expect(FileManager.default.createFile(atPath: child.path, contents: childBytes))

        // Same exit-2 dir-reject case as JSON — proves CSV shares the guard, not just some throw.
        Self.expectOutputExists {
            try Backup.Export.writeCSV(header: MessageRow.csvHeader, rows: [], to: outDir.path, force: true)
        }

        // The directory AND its contents survive — the CSV path never recursively deleted the tree.
        var isDir: ObjCBool = false
        #expect(FileManager.default.fileExists(atPath: outDir.path, isDirectory: &isDir))
        #expect(isDir.boolValue)
        #expect(try Data(contentsOf: child) == childBytes)
    }
}
