import Foundation
@testable import BackupCore

/// Shared support for the row-reader temp-invariant tests (Invariant P1: no decrypted `tether-rows-*`
/// temp survives a handled exit). The reader materializes a `0600` temp and removes it via `defer`, so
/// a COMPLETED read leaves none.
///
/// De-flake (cross-suite temp race): these `.serialized` suites still run in PARALLEL with the OTHER
/// reader suites in the same test process (each of which materializes its own `tether-rows-*` temp).
/// A naive single `after.subtracting(before)` snapshot can catch a CONCURRENT read's temp that is
/// mid-flight — present for a few ms until its own `defer` fires — and mis-report it as a leak. The
/// helper below SETTLES the delta with bounded polling: a transient concurrent temp clears within the
/// window, while a TRUE leak from the read under test PERSISTS across every poll. The invariant is NOT
/// weakened — a leaked temp is still returned non-empty and the caller's `#expect(...isEmpty)` fails.
enum TempInvariant {
    /// Live `tether-rows-*` temps in the system temp dir (the reader's materialize family).
    static func rowsTemps() -> Set<String> {
        let dir = FileManager.default.temporaryDirectory
        let entries = (try? FileManager.default.contentsOfDirectory(
            at: dir, includingPropertiesForKeys: nil)) ?? []
        return Set(entries.map { $0.lastPathComponent }.filter {
            $0.hasPrefix("\(TempScrub.prefix)rows-") && $0.hasSuffix(TempScrub.suffix)
        })
    }

    /// The set of `tether-rows-*` temps that are NEW since `before` AND still present after a bounded
    /// settle window. Polls up to `maxPolls` times (default ~1s total): a TRANSIENT concurrent temp is
    /// removed by its own `defer` and drops out; a TRUE leak persists and is returned, so the caller's
    /// emptiness assertion still HARD-FAILS on a real leak. Returns as soon as the delta is empty.
    static func newTempsSurviving(since before: Set<String>,
                                  maxPolls: Int = 50,
                                  pollInterval: TimeInterval = 0.02) -> Set<String> {
        var delta = rowsTemps().subtracting(before)
        var polls = 0
        while !delta.isEmpty && polls < maxPolls {
            Thread.sleep(forTimeInterval: pollInterval)   // let a concurrent read's `defer` fire
            delta = rowsTemps().subtracting(before)
            polls += 1
        }
        return delta
    }
}
