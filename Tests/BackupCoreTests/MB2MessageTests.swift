import Testing
import Foundation
@testable import BackupCore

@Suite struct MB2MessageTests {
    @Test func mapsDLMessageToOperation() {
        #expect(MB2Operation(dlMessage: "DLMessageDownloadFiles") == .sendFiles)
        #expect(MB2Operation(dlMessage: "DLMessageUploadFiles") == .receiveFiles)
        #expect(MB2Operation(dlMessage: "DLMessageGetFreeDiskSpace") == .freeDiskSpace)
        #expect(MB2Operation(dlMessage: "DLMessagePurgeDiskSpace") == .purgeDiskSpace)
        #expect(MB2Operation(dlMessage: "DLMessageCreateDirectory") == .createDirectory)
        // The device sends "DLContentsOfDirectory" for list-directory, NOT
        // "DLMessageListDirectory" (verified against idevicebackup2.c main-loop dispatch).
        #expect(MB2Operation(dlMessage: "DLContentsOfDirectory") == .listDirectory)
        #expect(MB2Operation(dlMessage: "DLMessageMoveFiles") == .moveItems)
        #expect(MB2Operation(dlMessage: "DLMessageMoveItems") == .moveItems)
        #expect(MB2Operation(dlMessage: "DLMessageRemoveFiles") == .removeItems)
        #expect(MB2Operation(dlMessage: "DLMessageRemoveItems") == .removeItems)
        #expect(MB2Operation(dlMessage: "DLMessageCopyItem") == .copyItem)
        #expect(MB2Operation(dlMessage: "DLMessageProcessMessage") == .processMessage)
        #expect(MB2Operation(dlMessage: "DLMessageDisconnect") == .disconnect)
        #expect(MB2Operation(dlMessage: "DLMessageNonsense") == nil)
    }
}

/// 3b path-traversal guard — the non-negotiable §4.1 protection. The device's file paths
/// are untrusted; every device-driven host path MUST be confined to backupRoot.
@Suite struct MB2PathGuardTests {
    @Test func acceptsPathInsideRoot() throws {
        let root = URL.temporaryTestDir()
        defer { try? FileManager.default.removeItem(at: root) }
        let resolved = MB2PathGuard.confinedPath(backupRoot: root, deviceRelativePath: "UDID/Manifest.db")
        #expect(resolved != nil)
        #expect(resolved?.path.hasPrefix(root.resolvingSymlinksInPath().path) == true)
    }

    @Test func rejectsDotDotEscape() {
        let root = URL.temporaryTestDir()
        defer { try? FileManager.default.removeItem(at: root) }
        // "../../etc/passwd" must NOT resolve to a path outside backupRoot.
        #expect(MB2PathGuard.confinedPath(backupRoot: root, deviceRelativePath: "../../etc/passwd") == nil)
        #expect(MB2PathGuard.confinedPath(backupRoot: root, deviceRelativePath: "sub/../../escape") == nil)
    }

    @Test func rejectsAbsolutePath() {
        let root = URL.temporaryTestDir()
        defer { try? FileManager.default.removeItem(at: root) }
        #expect(MB2PathGuard.confinedPath(backupRoot: root, deviceRelativePath: "/etc/passwd") == nil)
    }

    /// G3 acceptance bar #1: a REAL symlink inside backupRoot pointing OUTSIDE it, then a device
    /// path that traverses it, must be rejected — the guard must resolve symlinks, not just `..`.
    @Test func rejectsTraversalThroughSymlinkPointingOutside() throws {
        let parent = URL.temporaryTestDir()
        defer { try? FileManager.default.removeItem(at: parent) }
        let root = parent.appendingPathComponent("root")
        let outside = parent.appendingPathComponent("outside")
        try FileManager.default.createDirectory(at: root, withIntermediateDirectories: true)
        try FileManager.default.createDirectory(at: outside, withIntermediateDirectories: true)
        try Data("secret".utf8).write(to: outside.appendingPathComponent("passwd"))
        // root/evil -> ../outside (escapes root once resolved)
        try FileManager.default.createSymbolicLink(at: root.appendingPathComponent("evil"),
                                                   withDestinationURL: outside)
        // A device path through the symlink resolves to <parent>/outside/passwd, outside root → reject.
        #expect(MB2PathGuard.confinedPath(backupRoot: root, deviceRelativePath: "evil/passwd") == nil)
    }

    /// G3 acceptance bar #2: a symlinked INTERMEDIATE component followed by `..` — the ordering
    /// case (lexical `..` collapse vs. symlink resolution) where a naive guard leaks. The guard
    /// must not let `link/../x` smuggle a path outside root when `link` points elsewhere.
    @Test func handlesSymlinkedIntermediateComponentWithDotDot() throws {
        let parent = URL.temporaryTestDir()
        defer { try? FileManager.default.removeItem(at: parent) }
        let root = parent.appendingPathComponent("root")
        let elsewhere = parent.appendingPathComponent("elsewhere")
        try FileManager.default.createDirectory(at: root, withIntermediateDirectories: true)
        try FileManager.default.createDirectory(at: elsewhere.appendingPathComponent("sub"), withIntermediateDirectories: true)
        // root/link -> <parent>/elsewhere ; device path "link/../escape" must NOT land outside root.
        try FileManager.default.createSymbolicLink(at: root.appendingPathComponent("link"),
                                                   withDestinationURL: elsewhere)
        let result = MB2PathGuard.confinedPath(backupRoot: root, deviceRelativePath: "link/../escape")
        // Whatever the collapse/resolve order, the result must either be nil or stay within root.
        let rootResolved = root.resolvingSymlinksInPath().standardizedFileURL.path
        if let result {
            #expect(result.path.hasPrefix(rootResolved + "/") || result.path == rootResolved)
        }
        // The dangerous outcome — landing in <parent>/elsewhere (the symlink target) or at
        // <parent>/escape (a sibling of root) — must NOT happen.
        #expect(result?.path.contains("/elsewhere") != true)
        let escapeSibling = parent.appendingPathComponent("escape").resolvingSymlinksInPath().standardizedFileURL.path
        #expect(result?.path != escapeSibling)
    }

    /// Companion to the above: a symlinked intermediate that points INSIDE root must still be
    /// accepted (proves the guard isn't trivially rejecting every symlinked path).
    @Test func acceptsSymlinkedComponentStayingInsideRoot() throws {
        let root = URL.temporaryTestDir()
        defer { try? FileManager.default.removeItem(at: root) }
        let realSub = root.appendingPathComponent("real")
        try FileManager.default.createDirectory(at: realSub, withIntermediateDirectories: true)
        // root/alias -> root/real (a symlink that stays within root)
        try FileManager.default.createSymbolicLink(at: root.appendingPathComponent("alias"),
                                                   withDestinationURL: realSub)
        let result = MB2PathGuard.confinedPath(backupRoot: root, deviceRelativePath: "alias/file.txt")
        let resolved = try #require(result)
        let rootResolved = root.resolvingSymlinksInPath().standardizedFileURL.path
        #expect(resolved.path.hasPrefix(rootResolved + "/"))
    }

    /// G3 acceptance bar #3 (sequential / TOCTOU-shaped): an EARLIER op lands a symlink inside
    /// backupRoot pointing out, then a LATER op tries to write/move through it. runMessageLoop
    /// processes one message at a time so there's no concurrent race, but this proves the guard
    /// RE-RESOLVES on the later op rather than trusting a path it validated earlier — and that
    /// nothing is written outside backupRoot.
    @Test func reResolvesSymlinkPlantedByEarlierOp() throws {
        let parent = URL.temporaryTestDir()
        defer { try? FileManager.default.removeItem(at: parent) }
        let root = parent.appendingPathComponent("root")
        let outside = parent.appendingPathComponent("outside")
        try FileManager.default.createDirectory(at: root, withIntermediateDirectories: true)
        try FileManager.default.createDirectory(at: outside, withIntermediateDirectories: true)

        // Earlier op result: a symlink now sits INSIDE the staging tree, pointing out of it.
        let planted = root.appendingPathComponent("planted")
        try FileManager.default.createSymbolicLink(at: planted, withDestinationURL: outside)

        // Later op: device asks to write through the planted symlink to escape the root.
        let escapeName = "planted/stolen.txt"
        let result = MB2PathGuard.confinedPath(backupRoot: root, deviceRelativePath: escapeName)
        #expect(result == nil)   // re-resolved per-op → refused

        // Acceptance bar: prove nothing was written outside backupRoot. (The guard returns nil, so
        // a handler would refuse; confirm no file leaked into `outside` via the escape name.)
        #expect(FileManager.default.fileExists(atPath: outside.appendingPathComponent("stolen.txt").path) == false)
    }
}

/// C2: DLMessageProcessMessage is the terminal success/failure signal — ErrorCode==0 is success.
@Suite struct MB2ProcessMessageTests {
    @Test func errorCodeZeroIsSuccess() {
        let outcome = MB2ProcessMessage.outcome(fromMessageDict: ["ErrorCode": 0])
        #expect(outcome == .success)
    }

    @Test func nonZeroErrorCodeIsFailure() {
        let outcome = MB2ProcessMessage.outcome(fromMessageDict: ["ErrorCode": 22, "ErrorDescription": "boom"])
        #expect(outcome == .failure(code: 22, description: "boom"))
    }

    @Test func missingErrorCodeIsFailure() {
        // The C defaults error_code to -1 when ErrorCode is absent; treat absence as failure.
        if case .failure = MB2ProcessMessage.outcome(fromMessageDict: [:]) {} else {
            Issue.record("missing ErrorCode should be a failure")
        }
    }
}

/// Checkpoint-A run-4 bug (MBErrorDomain/205): an ABSENT host file (Status.plist on a first
/// backup) must be reported with CODE_ERROR_LOCAL, never as an empty CODE_SUCCESS data block —
/// otherwise the device parses zero-length data as a plist and refuses the backup.
@Suite struct MB2SendFileFrameTests {
    @Test func absentFileFrameUsesErrorLocalNotSuccess() {
        let frame = MB2.absentFileFrame(description: "No such file or directory")
        // 4-byte big-endian length prefix = description bytes + 1.
        let descLen = "No such file or directory".utf8.count
        let expectedLen = UInt32(descLen + 1)
        let lenBytes = [UInt8](frame.prefix(4))
        let parsedLen = UInt32(lenBytes[0]) << 24 | UInt32(lenBytes[1]) << 16 | UInt32(lenBytes[2]) << 8 | UInt32(lenBytes[3])
        #expect(parsedLen == expectedLen)
        // The 5th byte is the code — MUST be CODE_ERROR_LOCAL (0x06), the regression guard.
        #expect(frame[4] == 0x06)
        #expect(frame[4] != 0x00)   // explicitly NOT CODE_SUCCESS (the 205 bug)
        // Remaining bytes are the description.
        #expect([UInt8](frame.dropFirst(5)) == Array("No such file or directory".utf8))
    }

    @Test func terminatorFrameIsLengthOnePlusCode() {
        let frame = MB2.terminatorFrame(code: 0x00)
        #expect(frame == [0x00, 0x00, 0x00, 0x01, 0x00])   // BE length 1, then CODE_SUCCESS
    }
}

/// Checkpoint-A bug: during the on-device authorization (passcode) wait the device sends nothing,
/// so the receive call returns non-fatal codes. The reference waits through it; we must too. Only
/// MUX/SSL is a real disconnect.
@Suite struct MB2ReceiveDispositionTests {
    @Test func successWithMessageIsMessage() {
        #expect(MB2ReceiveDisposition(resultCode: 0, hasMessage: true) == .message)
    }
    @Test func successWithoutMessageKeepsWaiting() {
        // SUCCESS but no DL* message (dlmessage NULL) — keep waiting, not a disconnect.
        #expect(MB2ReceiveDisposition(resultCode: 0, hasMessage: false) == .keepWaiting)
    }
    @Test func receiveTimeoutKeepsWaiting() {
        #expect(MB2ReceiveDisposition(resultCode: -5, hasMessage: false) == .keepWaiting)  // RECEIVE_TIMEOUT
    }
    @Test func plistErrorDuringAuthWaitKeepsWaiting() {
        // The exact class of code that made us throw at ~15s during the passcode wait.
        #expect(MB2ReceiveDisposition(resultCode: -2, hasMessage: false) == .keepWaiting)  // PLIST_ERROR
        #expect(MB2ReceiveDisposition(resultCode: -7, hasMessage: false) == .keepWaiting)  // REPLY_NOT_OK
    }
    @Test func muxAndSslAreTransportDead() {
        #expect(MB2ReceiveDisposition(resultCode: -3, hasMessage: false) == .transportDead)  // MUX_ERROR
        #expect(MB2ReceiveDisposition(resultCode: -4, hasMessage: false) == .transportDead)  // SSL_ERROR
    }
}

/// G1: the no-progress deadline that bounds a mid-file device wedge.
@Suite struct MB2DeadlineTests {
    /// A mutable clock so tests can advance time deterministically.
    final class Clock: @unchecked Sendable {
        var t: TimeInterval = 0
        func now() -> Date { Date(timeIntervalSince1970: t) }
    }

    @Test func aliveImmediatelyAfterConstruction() throws {
        let clock = Clock()
        let deadline = MB2Deadline(window: 60, now: clock.now)
        try deadline.checkAlive()   // last progress is "now" → alive
    }

    @Test func recordingProgressResetsTheWindow() throws {
        let clock = Clock()
        let deadline = MB2Deadline(window: 60, now: clock.now)
        clock.t = 59
        try deadline.checkAlive()       // 59s < 60s window → alive
        deadline.recordProgress()       // reset at t=59
        clock.t = 118                   // 59s since reset → still alive
        try deadline.checkAlive()
    }

    @Test func throwsAfterWindowElapsesWithoutProgress() {
        let clock = Clock()
        let deadline = MB2Deadline(window: 60, now: clock.now)
        clock.t = 61                    // 61s > 60s window, no progress recorded → stall
        #expect(throws: BackupError.self) { try deadline.checkAlive() }
    }

    /// The backstop Odb asked to evidence: a sustained `keepWaiting` STORM (the fail-open
    /// inversion firing repeatedly post-auth) must make the loop throw deviceDisconnectedMidBackup
    /// once the no-progress window is exceeded — not spin forever.
    @Test func keepWaitingStormPastDeadlineThrows() {
        let clock = Clock()
        let deadline = MB2Deadline(window: 60, now: clock.now)
        // The receiver always says keepWaiting and the clock advances 5s each consult, so progress
        // is never recorded and the window is crossed.
        #expect {
            try deadline.awaitMessage(isCancelled: { false }, next: {
                clock.t += 5
                return .keepWaiting
            })
        } throws: { error in
            if case BackupError.deviceDisconnectedMidBackup = error { return true }
            return false
        }
    }

    /// Positive control: a `keepWaiting` run that delivers a message BEFORE the window returns
    /// cleanly (so the storm test isn't trivially always-throwing).
    @Test func keepWaitingThatResolvesToMessageReturnsCleanly() throws {
        let clock = Clock()
        let deadline = MB2Deadline(window: 60, now: clock.now)
        var consults = 0
        try deadline.awaitMessage(isCancelled: { false }, next: {
            consults += 1
            clock.t += 5
            return consults < 3 ? .keepWaiting : .message   // message at t=15s, within the 60s window
        })
        #expect(consults == 3)
    }

    /// Cancellation during a keepWaiting storm throws backupCancelled (the between-message seam).
    @Test func keepWaitingStormHonorsCancellation() {
        let clock = Clock()
        let deadline = MB2Deadline(window: 600, now: clock.now)   // long window so cancel wins, not deadline
        var consults = 0
        #expect {
            try deadline.awaitMessage(isCancelled: { consults >= 2 }, next: {
                consults += 1
                clock.t += 5
                return .keepWaiting
            })
        } throws: { error in
            if case BackupError.backupCancelled = error { return true }
            return false
        }
    }
}

/// errno → device error code mapping, ported verbatim from idevicebackup2.c errno_to_device_error.
@Suite struct MB2DeviceErrorTests {
    @Test func mapsKnownErrno() {
        #expect(MB2.deviceError(forErrno: ENOENT) == -6)
        #expect(MB2.deviceError(forErrno: EEXIST) == -7)
        #expect(MB2.deviceError(forErrno: ENOSPC) == -15)
        #expect(MB2.deviceError(forErrno: EIO) == -11)
    }
    @Test func mapsUnknownErrnoToMinusOne() {
        #expect(MB2.deviceError(forErrno: EACCES) == -1)
    }

    /// A Cocoa file error wrapping a POSIX errno must map via the underlying errno, not the
    /// Cocoa code (e.g. NSFileWriteOutOfSpaceError=642 is meaningless to errno_to_device_error).
    @Test func extractsUnderlyingPosixErrnoFromCocoaError() {
        let posix = NSError(domain: NSPOSIXErrorDomain, code: Int(ENOSPC), userInfo: nil)
        let cocoa = NSError(domain: NSCocoaErrorDomain, code: 642,
                            userInfo: [NSUnderlyingErrorKey: posix])
        #expect(MB2.deviceError(forError: cocoa) == -15)   // ENOSPC -> -15, not the Cocoa 642
    }

    @Test func fallsBackToMinusOneWhenNoUnderlyingErrno() {
        let cocoa = NSError(domain: NSCocoaErrorDomain, code: 642, userInfo: nil)
        #expect(MB2.deviceError(forError: cocoa) == -1)
    }
}
