import Foundation

/// Removes stale Tether decrypt-temp artifacts (`tether-*.db`) from a temp directory before a
/// read materializes a new one. This is the kill-before-`defer` FLOOR (SP3 spec §5.2, Invariant P2):
/// `BackupRowReader` and `BackupVerifier.openTableNames` each write a `0600` decrypted temp and
/// remove it on `defer`, but `defer` does NOT run if the process is killed (SIGKILL / power loss)
/// between the write and the cleanup. A decrypted temp could then survive across runs. Scrubbing
/// the `tether-` family at the top of every read closes that window for a SUBSEQUENT run.
///
/// SAFETY OF THE UNLINK: removing a temp here is safe even if another in-flight read holds it open.
/// POSIX `unlink` only drops the directory entry; the inode (and its bytes) stay alive until the
/// last open file descriptor is closed, so an in-progress reader finishes reading its already-open
/// fd to completion and the bytes are freed when it closes. This is open-fd survival, NOT a
/// busy/lock check — macOS has no mandatory file locking, so `removeItem` on an in-use temp
/// SUCCEEDS (it makes the entry invisible to a third process), it is not "skipped because locked".
/// The removal is therefore best-effort: a failure on one entry (e.g. a permission quirk) is
/// swallowed per-entry and never aborts a legitimate read — the scrub is a floor, not a gate.
public enum TempScrub {
    /// The temp-name family this scrub owns: a `tether-` prefix and a `.db` suffix. Matches BOTH
    /// the existing `tether-readability-*` temp (`BackupVerifier.openTableNames`) and the new
    /// `tether-rows-*` temp (`BackupRowReader`), so neither tool's residue is left behind.
    static let prefix = "tether-"
    static let suffix = ".db"

    /// Scrubs the system temporary directory — the location every Tether decrypt-temp is written to.
    public static func run() {
        run(in: FileManager.default.temporaryDirectory)
    }

    /// Scrubs `directory` (test seam: point at a controlled temp dir). Removes every entry whose
    /// name has the `tether-` prefix and `.db` suffix, best-effort (`try?` per entry). A non-Tether
    /// file in the same directory is left untouched.
    public static func run(in directory: URL) {
        let fm = FileManager.default
        guard let entries = try? fm.contentsOfDirectory(
            at: directory, includingPropertiesForKeys: nil, options: [.skipsHiddenFiles]) else {
            return   // directory absent or unreadable — nothing to scrub, never fatal
        }
        for entry in entries {
            let name = entry.lastPathComponent
            guard name.hasPrefix(prefix), name.hasSuffix(suffix) else { continue }
            try? fm.removeItem(at: entry)
        }
    }
}
