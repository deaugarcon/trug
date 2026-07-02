import Foundation

/// Confines an untrusted device-supplied path to within `backupRoot`.
///
/// The reference C (`idevicebackup2.c`) joins device paths to `backup_dir` with zero
/// `..`/absolute/symlink protection. Tether backs up a possibly-compromised phone and
/// promises §4.1, so every device-driven host path is resolved and asserted to stay
/// inside `backupRoot` before any filesystem operation. Returns `nil` if the path would
/// escape — the caller refuses the operation (and sends an error status to the device).
enum MB2PathGuard {
    static func confinedPath(backupRoot: URL, deviceRelativePath: String) -> URL? {
        // Absolute paths from the device are never allowed.
        if deviceRelativePath.hasPrefix("/") { return nil }
        let fm = FileManager.default
        let root = backupRoot.resolvingSymlinksInPath().standardizedFileURL
        let joined = root.appendingPathComponent(deviceRelativePath).standardizedFileURL

        // `resolvingSymlinksInPath()` only resolves symlinks for path components that EXIST on
        // disk. A device can plant a symlink (an earlier op) and then write THROUGH it to a
        // not-yet-existing leaf — the leaf's non-existence leaves the planted symlink unresolved,
        // and a naive full-path resolve would accept the lexical (in-root) path. To close that,
        // resolve symlinks on the DEEPEST EXISTING ANCESTOR, then re-append the non-existent tail.
        let components = joined.pathComponents
        var existingPrefix = URL(fileURLWithPath: "/")
        var tail: [String] = []
        for (i, comp) in components.enumerated() {
            let candidate = i == 0 ? URL(fileURLWithPath: comp)
                                   : existingPrefix.appendingPathComponent(comp)
            if tail.isEmpty && fm.fileExists(atPath: candidate.path) {
                existingPrefix = candidate
            } else {
                tail.append(comp)
            }
        }
        let resolvedPrefix = existingPrefix.resolvingSymlinksInPath().standardizedFileURL
        let resolved = tail.reduce(resolvedPrefix) { $0.appendingPathComponent($1) }
            .standardizedFileURL

        // The resolved path must equal root or sit beneath it (path-component boundary,
        // so "<root>evil" cannot masquerade as inside "<root>").
        let rootPath = root.path
        let resolvedPath = resolved.path
        if resolvedPath == rootPath { return resolved }
        return resolvedPath.hasPrefix(rootPath + "/") ? resolved : nil
    }
}

/// C2: the outcome parsed from a `DLMessageProcessMessage` — the protocol's terminal signal.
/// `ErrorCode == 0` is the only success; absence or non-zero is failure (matches the C, which
/// defaults `error_code` to -1 and sets `operation_ok` only when ErrorCode is 0).
enum MB2ProcessMessage: Equatable {
    case success
    case failure(code: Int, description: String?)

    static func outcome(fromMessageDict dict: [String: Any]) -> MB2ProcessMessage {
        guard let codeValue = dict["ErrorCode"], let code = (codeValue as? NSNumber)?.intValue else {
            return .failure(code: -1, description: dict["ErrorDescription"] as? String)
        }
        if code == 0 { return .success }
        return .failure(code: code, description: dict["ErrorDescription"] as? String)
    }
}

/// Bounds a mid-file device wedge (Odb G1). `mobilebackup2_receive_raw` returns 0 bytes when the
/// device stalls (its underlying `service_receive` has a finite ~30s socket timeout, so it does
/// not block forever), but the receive handler could otherwise retry empty reads indefinitely
/// without the outer loop's deadline ever firing. This tracks the time since the last byte/message
/// of progress and throws `deviceDisconnectedMidBackup` once a stall exceeds `window`, turning a
/// silent mid-file hang into a diagnostic failure.
final class MB2Deadline: @unchecked Sendable {
    private let window: TimeInterval
    private let now: () -> Date
    private var lastProgress: Date

    init(window: TimeInterval, now: @escaping () -> Date = Date.init) {
        self.window = window
        self.now = now
        self.lastProgress = now()
    }

    func recordProgress() { lastProgress = now() }

    /// Throws `BackupError.deviceDisconnectedMidBackup` if more than `window` has elapsed with no progress.
    func checkAlive() throws {
        if now().timeIntervalSince(lastProgress) > window {
            throw BackupError.deviceDisconnectedMidBackup(lastResultCode: nil)
        }
    }

    /// Drives the receive loop's wait-for-message decision against this deadline, device-free.
    /// Each iteration: check cancellation, check the deadline (throws if the no-progress window is
    /// exceeded — this is the backstop against a post-auth `keepWaiting` storm), then take the next
    /// disposition. `.message` returns; `.keepWaiting` loops WITHOUT recording progress (so the
    /// clock keeps advancing toward the deadline); `.transportDead` throws.
    ///
    /// This is exactly the logic `MobileBackup2Session.runMessageLoop` runs for the wait phase,
    /// extracted so the deadline backstop is unit-testable without a device.
    func awaitMessage(isCancelled: () -> Bool, next: () -> MB2ReceiveDisposition) throws {
        while true {
            if isCancelled() { throw BackupError.backupCancelled }
            try checkAlive()
            switch next() {
            case .message:
                recordProgress()
                return
            case .keepWaiting:
                continue   // no progress recorded; the deadline advances toward the window
            case .transportDead:
                throw BackupError.deviceDisconnectedMidBackup(lastResultCode: nil)
            }
        }
    }
}

/// Classifies a `mobilebackup2_receive_message` result so the loop can wait through the on-device
/// authorization (passcode) wait the way the reference `idevicebackup2` does, instead of treating
/// every non-success as a disconnect.
///
/// During the auth wait the device sends nothing, so the receive call returns `RECEIVE_TIMEOUT`
/// (or a transient non-transport code) repeatedly — the reference keeps waiting. Only a genuinely
/// dead transport (`MUX_ERROR` = -3 / `SSL_ERROR` = -4) is fatal. Operates on the raw result code
/// so it is unit-testable without the device or the C module.
enum MB2ReceiveDisposition: Equatable {
    case message        // SUCCESS with a DL* message to process
    case keepWaiting    // timeout or a non-fatal transient — keep looping under the deadline
    case transportDead  // MUX/SSL — the connection is gone

    /// mobilebackup2_error_t raw values (from mobilebackup2.h): SUCCESS=0, MUX_ERROR=-3, SSL_ERROR=-4.
    init(resultCode: Int32, hasMessage: Bool) {
        switch resultCode {
        case 0:   // MOBILEBACKUP2_E_SUCCESS
            self = hasMessage ? .message : .keepWaiting
        case -3, -4:   // MUX_ERROR, SSL_ERROR
            self = .transportDead
        default:
            // RECEIVE_TIMEOUT (-5), PLIST_ERROR (-2), REPLY_NOT_OK (-7), and other non-transport
            // codes are NOT a disconnect during negotiation / the auth wait — keep waiting,
            // bounded by the no-progress deadline so a genuine wedge still fails.
            self = .keepWaiting
        }
    }
}

/// Maps a host `errno` to the device error code the MB2 protocol expects in a status response.
/// Ported verbatim from `idevicebackup2.c`'s `errno_to_device_error`.
enum MB2 {
    static func deviceError(forErrno e: Int32) -> Int32 {
        switch e {
        case ENOENT: return -6
        case EEXIST: return -7
        case ENOTDIR: return -8
        case EISDIR: return -9
        case ELOOP: return -10
        case EIO: return -11
        case ENOSPC: return -15
        default: return -1
        }
    }

    /// Maps a Swift `Error` (typically a `FileManager` Cocoa error) to a device error code.
    ///
    /// `NSError.code` for a Cocoa file error is a Cocoa code (e.g. `NSFileWriteOutOfSpaceError`
    /// = 642), NOT a POSIX errno — feeding it to `deviceError(forErrno:)` mis-maps. Cocoa file
    /// errors carry the real errno in an `NSPOSIXErrorDomain` error under `NSUnderlyingErrorKey`;
    /// extract that. If no POSIX errno is recoverable, fall back to the generic `-1`.
    static func deviceError(forError error: Error) -> Int32 {
        let ns = error as NSError
        if ns.domain == NSPOSIXErrorDomain {
            return deviceError(forErrno: Int32(ns.code))
        }
        if let underlying = ns.userInfo[NSUnderlyingErrorKey] as? NSError,
           underlying.domain == NSPOSIXErrorDomain {
            return deviceError(forErrno: Int32(underlying.code))
        }
        return -1
    }

    // 1-byte transfer framing codes (idevicebackup2.c).
    static let codeSuccess: UInt8 = 0x00
    static let codeErrorLocal: UInt8 = 0x06
    static let codeFileData: UInt8 = 0x0c

    /// Builds the `mb2_handle_send_file` frame for an ABSENT or unreadable file: a 4-byte
    /// big-endian length of (description bytes + 1), then `CODE_ERROR_LOCAL`, then the description.
    /// Getting this wrong (sending CODE_SUCCESS/empty data for an absent file) makes the device try
    /// to parse zero-length data as a plist and refuse the backup (MBErrorDomain/205).
    static func absentFileFrame(description: String) -> [UInt8] {
        let descBytes = Array(description.utf8)
        var frame = [UInt8]()
        frame.append(contentsOf: bigEndianBytes(UInt32(descBytes.count + 1)))
        frame.append(codeErrorLocal)
        frame.append(contentsOf: descBytes)
        return frame
    }

    /// Builds the terminator frame: 4-byte big-endian length 1, then the code byte.
    static func terminatorFrame(code: UInt8) -> [UInt8] {
        bigEndianBytes(UInt32(1)) + [code]
    }

    private static func bigEndianBytes(_ value: UInt32) -> [UInt8] {
        var be = value.bigEndian
        return withUnsafeBytes(of: &be) { Array($0) }
    }
}

/// The wire shape of a `ChangePassword` options dict, as a pure Foundation value so the
/// key-presence discipline is unit-testable without a device or the C plist API.
///
/// Verified against `idevicebackup2.c` `CMD_CHANGEPW` (lines 2379–2449):
///  - `TargetIdentifier` (the device udid) is set FIRST and ALWAYS (line 2381).
///  - `NewPassword` is present only when enabling/rotating (a non-nil new password) — lines 2442-2444.
///  - `OldPassword` is present only when disabling/rotating (a non-nil old password) — lines 2445-2447.
///  - both values are plist STRINGS (`plist_new_string`), never Data.
///  - `MessageName` is NOT a dict key; `mobilebackup2_send_message(..., "ChangePassword", opts)`
///    injects it. Putting it in the dict would be a wire deviation.
/// The "omit-when-nil" rule matters: an empty-string `OldPassword` on an enable is a wire deviation
/// (the reference only sets a key when its value is non-NULL).
enum MB2ChangePassword {
    /// Builds the `[String: String]` options for a ChangePassword, omitting absent password keys.
    /// `old`/`new` carry the enable/disable/rotate mapping the caller chose:
    /// enable → (old: nil, new: pw); disable → (old: pw, new: nil); rotate → (old: a, new: b).
    static func options(targetIdentifier udid: String, old: String?, new: String?) -> [String: String] {
        var dict: [String: String] = ["TargetIdentifier": udid]
        if let new { dict["NewPassword"] = new }
        if let old { dict["OldPassword"] = old }
        return dict
    }
}

/// The MobileBackup2 DL* operations the device can request during a backup.
/// Mapping is taken from the dispatch in `idevicebackup2.c`'s main loop — the C source
/// is the spec for which DL* string maps to which handler.
enum MB2Operation: Equatable {
    case sendFiles, receiveFiles, freeDiskSpace, purgeDiskSpace
    case listDirectory, createDirectory, moveItems, removeItems
    case copyItem, processMessage, disconnect

    init?(dlMessage: String) {
        switch dlMessage {
        case "DLMessageDownloadFiles": self = .sendFiles
        case "DLMessageUploadFiles": self = .receiveFiles
        case "DLMessageGetFreeDiskSpace": self = .freeDiskSpace
        case "DLMessagePurgeDiskSpace": self = .purgeDiskSpace
        // The device sends "DLContentsOfDirectory" (no "Message" infix) for list-directory.
        case "DLContentsOfDirectory": self = .listDirectory
        case "DLMessageCreateDirectory": self = .createDirectory
        case "DLMessageMoveFiles", "DLMessageMoveItems": self = .moveItems
        case "DLMessageRemoveFiles", "DLMessageRemoveItems": self = .removeItems
        case "DLMessageCopyItem": self = .copyItem
        case "DLMessageProcessMessage": self = .processMessage
        case "DLMessageDisconnect": self = .disconnect
        default: return nil
        }
    }
}
