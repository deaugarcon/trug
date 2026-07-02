import Foundation

enum CloneFile {
    /// Clones a directory tree from `src` to `dst` (which must not exist).
    /// Uses APFS clonefile(2) for instant copy-on-write; falls back to FileManager.copyItem off-APFS.
    static func cloneTree(from src: URL, to dst: URL) throws {
        // Capture errno INSIDE the closure, immediately after the syscall, before the
        // closures unwind or any later call can clobber it.
        let (rc, err): (Int32, Int32) = src.withUnsafeFileSystemRepresentation { s in
            dst.withUnsafeFileSystemRepresentation { d in
                let r = clonefile(s, d, 0)
                return (r, r == 0 ? 0 : errno)
            }
        }
        if rc == 0 { return }
        // ENOTSUP (45) off-APFS, EXDEV (18) cross-device → fall back to a normal copy.
        // NOTE: the fallback is a DEEP COPY, never a hardlink tree. Hardlinks would make the
        // clone share inodes with `current` and reintroduce the in-place-mutation corruption
        // the whole design exists to avoid. Do not "optimize" this to hardlinks.
        if err == ENOTSUP || err == EXDEV {
            try FileManager.default.copyItem(at: src, to: dst)
            return
        }
        throw NSError(domain: NSPOSIXErrorDomain, code: Int(err),
                      userInfo: [NSLocalizedDescriptionKey: "clonefile failed: \(String(cString: strerror(err)))"])
    }
}
