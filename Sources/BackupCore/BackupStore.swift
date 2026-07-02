import Foundation

/// Handle to an in-progress backup directory between beginStaging() and promote()/markFailed().
public struct StagingHandle: Sendable {
    public let id: BackupID
    public let directory: URL
}

/// Owns the §4.1 on-disk state machine. Never mutates a verified backup in place:
/// create clones `current` → `.staging`, MB2 writes the clone, promote() flips `current`.
public final class BackupStore {
    private let root: URL
    private let fm = FileManager.default

    public init(root: URL) { self.root = root }

    public static var defaultRoot: URL {
        fm_appSupport().appendingPathComponent("Tether/Backups", isDirectory: true)
    }
    private static func fm_appSupport() -> URL {
        FileManager.default.urls(for: .applicationSupportDirectory, in: .userDomainMask)[0]
    }

    private func deviceDir(_ id: BackupID) -> URL { root.appendingPathComponent(id.udid, isDirectory: true) }
    private func stagingDir(_ id: BackupID) -> URL { deviceDir(id).appendingPathComponent(".staging", isDirectory: true) }
    private func currentLink(_ id: BackupID) -> URL { deviceDir(id).appendingPathComponent("current") }
    private func stateFile(_ dir: URL) -> URL { dir.appendingPathComponent("TetherState") }

    /// Disk-space preflight that MUST run before `beginStaging` (WP1 carry-forward, item 3).
    ///
    /// `beginStaging` clones `current` into `.staging` first; on a non-APFS volume that clone is a
    /// deep copy, which can fill the disk before the MB2 loop ever reports free space to the device.
    /// On APFS the clone is copy-on-write (near-free), but we cannot assume the volume is APFS, so
    /// the conservative gate is: free space on the store volume must be at least the current backup's
    /// on-disk size (the worst-case clone cost). Throws `insufficientDiskSpace` otherwise.
    /// A first-ever backup (no `current`) has a clone cost of zero and always passes here — the
    /// MB2 loop's own `GetFreeDiskSpace` handshake still guards the incoming transfer.
    public func preflightDiskSpace(for id: BackupID) throws {
        guard let current = try currentBackupDirectory(for: id) else { return }
        let cloneCost = directorySize(current)
        try fm.createDirectory(at: deviceDir(id), withIntermediateDirectories: true)
        let free = (try? fm.attributesOfFileSystem(forPath: deviceDir(id).path)[.systemFreeSize] as? NSNumber)?
            .uint64Value ?? 0
        guard free >= cloneCost else {
            throw BackupError.insufficientDiskSpace(needed: cloneCost, available: free)
        }
    }

    /// Begins a staging directory: clones the current verified backup if present, else empty.
    public func beginStaging(for id: BackupID) throws -> StagingHandle {
        try fm.createDirectory(at: deviceDir(id), withIntermediateDirectories: true)
        let staging = stagingDir(id)
        if fm.fileExists(atPath: staging.path) { try fm.removeItem(at: staging) }
        if let current = try currentBackupDirectory(for: id) {
            try CloneFile.cloneTree(from: current, to: staging)
        } else {
            try fm.createDirectory(at: staging, withIntermediateDirectories: true)
        }
        try writeState(.inProgress, to: staging)
        return StagingHandle(id: id, directory: staging)
    }

    /// Promotes a verified staging dir to `current` atomically.
    public func promote(_ handle: StagingHandle) throws {
        try writeState(.verified, to: handle.directory)
        // Move staging to a generation dir, then ATOMICALLY repoint `current`.
        let genName = "backup-\(nextGenerationIndex(for: handle.id))"
        let genDir = deviceDir(handle.id).appendingPathComponent(genName, isDirectory: true)
        try fm.moveItem(at: handle.directory, to: genDir)
        try atomicRepointCurrent(handle.id, to: genName)
        pruneOldGenerations(handle.id)   // keeps current + immediately-previous
    }

    public func markFailed(_ handle: StagingHandle) {
        try? writeState(.failed, to: handle.directory)
        // Leave the failed staging in place for diagnosis; next beginStaging() removes it.
    }

    /// §4.1 finalize: runs the caller's verify decision, then promotes ONLY on a passing verify —
    /// and marks the staging failed on ANY other outcome, exactly once.
    ///
    /// `verifyPassed` performs the verification and returns whether the backup may be promoted. The
    /// checkpoint-B gap this closes: the create glue previously marked failed only for a thrown
    /// backup and for `report.passed == false`, so a verify or promote that THREW (e.g. a
    /// `manifestUnreadable` from a WAL-mode Manifest.db) escaped to the CLI error sink with the
    /// staging still "in-progress" — violating §4.1's "any post-backup failure marks staging failed".
    /// Wrapping the whole verify-through-promote sequence here makes the invariant single-sourced and
    /// unit-testable (the CLI `run()` is not), instead of duplicating do/catch arms at the call site.
    ///
    /// Failure modes and their single markFailed:
    ///  - `verifyPassed` throws            → markFailed, rethrow the original error;
    ///  - `verifyPassed` returns `false`   → markFailed, throw `BackupError.verificationFailed`;
    ///  - `promote` throws                 → markFailed, rethrow.
    /// On success (`true` then a clean promote) the staging is `verified` and never marked failed.
    public func finalize(_ handle: StagingHandle, verifyPassed: () throws -> Bool) throws {
        let passed: Bool
        do {
            passed = try verifyPassed()
        } catch {
            markFailed(handle)
            throw error
        }
        guard passed else {
            markFailed(handle)
            throw BackupError.verificationFailed
        }
        do {
            try promote(handle)
        } catch {
            markFailed(handle)
            throw error
        }
    }

    /// The directory `current` points at, if a verified backup exists.
    public func currentBackupDirectory(for id: BackupID) throws -> URL? {
        let link = currentLink(id)
        guard let dest = try? fm.destinationOfSymbolicLink(atPath: link.path) else { return nil }
        let dir = deviceDir(id).appendingPathComponent(dest, isDirectory: true)
        return fm.fileExists(atPath: dir.path) ? dir : nil
    }

    public func state(for id: BackupID) -> BackupState? {
        // `try?` flattens the throwing `URL?` return to a single optional in Swift 6.
        guard let dir = try? currentBackupDirectory(for: id) else { return nil }
        return readState(from: dir)
    }

    /// Summarizes each device's current verified backup for `trug backup list`.
    /// Read-only: enumerates device dirs, reads state + Manifest metadata + on-disk size.
    /// Devices without a current backup (or with an unreadable manifest) are skipped/blank.
    public func listSummaries() throws -> [BackupSummary] {
        guard let udids = try? fm.contentsOfDirectory(atPath: root.path) else { return [] }
        return udids.compactMap { udid in
            let id = BackupID(udid: udid)
            // `try?` flattens the throwing `URL?` return to a single optional in Swift 6.
            guard let dir = try? currentBackupDirectory(for: id) else { return nil }
            let state = readState(from: dir) ?? .failed
            // Read metadata from the PLAINTEXT plists only (no Manifest.db open) so an encrypted
            // backup still lists its device name / iOS version. `list` must stay password-free —
            // opening the keybag-less ManifestReader here would throw on the ciphertext Manifest.db
            // and blank every field (checkpoint C run 3).
            let meta = ManifestReader.metadata(in: dir.appendingPathComponent(udid))
            return BackupSummary(id: id, state: state, isEncrypted: meta.isEncrypted,
                                 deviceName: meta.deviceName, productVersion: meta.productVersion,
                                 sizeBytes: directorySize(dir))
        }
    }

    // MARK: - internals

    private func directorySize(_ url: URL) -> UInt64 {
        var total: UInt64 = 0
        if let enumerator = fm.enumerator(at: url, includingPropertiesForKeys: [.fileSizeKey]) {
            for case let file as URL in enumerator {
                total += UInt64((try? file.resourceValues(forKeys: [.fileSizeKey]).fileSize) ?? 0)
            }
        }
        return total
    }

    private func writeState(_ s: BackupState, to dir: URL) throws {
        try Data(s.rawValue.utf8).write(to: stateFile(dir))
    }
    private func readState(from dir: URL) -> BackupState? {
        guard let raw = try? String(contentsOf: stateFile(dir)).trimmingCharacters(in: .whitespacesAndNewlines)
        else { return nil }
        return BackupState(rawValue: raw)
    }
    private func nextGenerationIndex(for id: BackupID) -> Int {
        let existing = (try? fm.contentsOfDirectory(atPath: deviceDir(id).path)) ?? []
        let indices = existing.compactMap { name -> Int? in
            name.hasPrefix("backup-") ? Int(name.dropFirst("backup-".count)) : nil
        }
        return (indices.max() ?? -1) + 1
    }
    /// Atomically repoints `current` using rename(2): create a temp symlink, then rename it
    /// over `current`. rename(2) replaces the existing symlink in a single syscall — there is
    /// no instant where `current` is absent, even across a crash. (FileManager's
    /// removeItem-then-createSymbolicLink has a two-syscall window that loses `current` on crash.)
    private func atomicRepointCurrent(_ id: BackupID, to genName: String) throws {
        let link = currentLink(id)
        let tmp = deviceDir(id).appendingPathComponent(".current.tmp")
        try? fm.removeItem(at: tmp)
        try fm.createSymbolicLink(atPath: tmp.path, withDestinationPath: genName)
        let rc = tmp.withUnsafeFileSystemRepresentation { t in
            link.withUnsafeFileSystemRepresentation { l in rename(t, l) }
        }
        guard rc == 0 else {
            let err = errno
            try? fm.removeItem(at: tmp)
            throw NSError(domain: NSPOSIXErrorDomain, code: Int(err),
                          userInfo: [NSLocalizedDescriptionKey: "atomic symlink swap failed: \(String(cString: strerror(err)))"])
        }
    }
    /// Retention: keep the current generation AND the immediately-previous one as a fallback
    /// against a false-positive verification, then delete older generations. Deleting the prior
    /// good backup inside the same promote() that created the new one would make a bad verify
    /// unrecoverable. APFS clones make the extra generation near-free.
    private func pruneOldGenerations(_ id: BackupID) {
        let contents = (try? fm.contentsOfDirectory(atPath: deviceDir(id).path)) ?? []
        let gens = contents.filter { $0.hasPrefix("backup-") }
            .compactMap { name -> (name: String, idx: Int)? in
                Int(name.dropFirst("backup-".count)).map { (name, $0) }
            }
            .sorted { $0.idx > $1.idx }   // newest first
        for gen in gens.dropFirst(2) {     // keep current + immediately-previous
            try? fm.removeItem(at: deviceDir(id).appendingPathComponent(gen.name))
        }
    }
}
