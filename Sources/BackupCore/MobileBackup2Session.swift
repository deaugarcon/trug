import Foundation
import Climobiledevice
import Cplist
import CWrappers
import DeviceCore

public struct BackupOptions: Sendable {
    public let udid: String
    public let full: Bool
    public init(udid: String, full: Bool = false) { self.udid = udid; self.full = full }
}

/// Drives the `com.apple.mobilebackup2` DL* protocol, writing into a staging directory.
///
/// Store-agnostic by design: it takes the staging `backupRoot` URL and never touches the
/// state machine. The caller owns preflight → beginStaging → backup → verify → promote and
/// marks staging failed on a thrown error. `backup()` returns cleanly ONLY when the protocol
/// reports a `DLMessageProcessMessage` with `ErrorCode == 0`; every other terminal condition
/// throws (the §1 "never lie about success" rule). The structural verifier separately proves
/// the snapshot is `finished` before the caller promotes.
///
/// Ported function-by-function from `Vendor/src/libimobiledevice/tools/idevicebackup2.c`.
/// Not thread-safe; create, run, and discard on a single Task.
public final class MobileBackup2Session {
    private let connection: DeviceConnection
    private var client: mobilebackup2_client_t?

    // 1-byte transfer framing codes (idevicebackup2.c).
    private static let codeSuccess: UInt8 = 0x00
    private static let codeErrorLocal: UInt8 = 0x06
    private static let codeErrorRemote: UInt8 = 0x0b
    private static let codeFileData: UInt8 = 0x0c

    /// No-progress deadline DURING TRANSFER: if no byte is transferred and no message processed for
    /// this long, a wedged device is assumed and the backup throws `deviceDisconnectedMidBackup`
    /// (Odb C1/Q-C). Only applies after the device authorizes (first DL* message).
    private let noProgressDeadline: TimeInterval = 60

    /// Authorization deadline BEFORE the first message: the user may be entering their passcode on
    /// the device, which can take minutes. Generous so a slow on-device unlock isn't mistaken for a
    /// dead device; a genuinely disconnected device still surfaces via MUX/SSL → transportDead.
    private let authorizationDeadline: TimeInterval = 300

    public init(connection: DeviceConnection) { self.connection = connection }

    deinit { if let client { mobilebackup2_client_free(client) } }

    /// Runs a full/incremental backup into `backupRoot` (the staging directory).
    /// Streams progress; throws `BackupError` on failure. Honors `Task` cancellation.
    public func backup(options: BackupOptions, into backupRoot: URL,
                       progress: @escaping @Sendable (BackupProgress) -> Void) throws {
        var cli: mobilebackup2_client_t? = nil
        let startResult = mobilebackup2_client_start_service(connection.rawDevice, &cli, "tether")
        guard startResult == MOBILEBACKUP2_E_SUCCESS, let cli else {
            throw BackupError.serviceStartFailed(code: startResult.rawValue)
        }
        self.client = cli

        // Version exchange — local versions {2.0, 2.1}, count is C `char` → Int8 (verified vs header).
        var localVersions: [Double] = [2.0, 2.1]
        var remote: Double = 0
        let vresult = localVersions.withUnsafeMutableBufferPointer {
            mobilebackup2_version_exchange(cli, $0.baseAddress, Int8($0.count), &remote)
        }
        guard vresult == MOBILEBACKUP2_E_SUCCESS else {
            throw BackupError.protocolVersionUnsupported(device: remote > 0 ? String(remote) : "unknown")
        }

        progress(.started)

        // Send the Backup request: target = device udid, source = same udid for a local backup.
        let req = mobilebackup2_send_request(cli, "Backup", options.udid, options.udid, nil)
        guard req == MOBILEBACKUP2_E_SUCCESS else {
            throw BackupError.serviceStartFailed(code: req.rawValue)
        }

        try runMessageLoop(client: cli, backupRoot: backupRoot, progress: progress)
    }

    /// Sends a `ChangePassword` and reads the device's terminal response — enabling, disabling, or
    /// rotating backup encryption. ADDITIVE: a new caller that REUSES the audited `runMessageLoop`
    /// (it does not modify the loop). Ported from `idevicebackup2.c` `CMD_CHANGEPW` (lines 2379–2449)
    /// plus the shared DL receive loop that follows every command (lines 2491–2700).
    ///
    /// The result is ASYNCHRONOUS: `mobilebackup2_send_message` returns immediately and the real
    /// outcome arrives as a terminal `DLMessageProcessMessage` (`ErrorCode == 0` ⇒ success) in the
    /// same loop a backup uses — so a wrong `OldPassword` is a `.failure` the loop turns into a
    /// thrown `backupRefusedByDevice`, never a silently-claimed success (the WP4-class lie Odb flagged).
    /// On iOS 13+ the device may require an on-device passcode confirmation before responding; the
    /// loop's generous pre-first-message authorization deadline (300s) covers that wait unchanged.
    ///
    /// `old`/`new` carry the enable/disable/rotate mapping: enable → (nil, pw); disable → (pw, nil);
    /// rotate → (a, b). The mapping of a failure-with-old-password to `KeybagError.wrongPassword`
    /// is the caller's (EncryptionControl) heuristic — the reference has no dedicated wrong-password
    /// code (Odb Q4), so this transport stays honest and surfaces the raw device failure.
    public func changePassword(udid: String, old: String?, new: String?) throws {
        var cli: mobilebackup2_client_t? = nil
        let startResult = mobilebackup2_client_start_service(connection.rawDevice, &cli, "tether")
        guard startResult == MOBILEBACKUP2_E_SUCCESS, let cli else {
            throw BackupError.serviceStartFailed(code: startResult.rawValue)
        }
        self.client = cli

        // Version exchange is MANDATORY before any command (idevicebackup2.c line 2130); a
        // ChangePassword on a client that has not exchanged versions is a device-side rejection
        // (the checkpoint-A "205" class). Same local versions {2.0, 2.1} as backup().
        var localVersions: [Double] = [2.0, 2.1]
        var remote: Double = 0
        let vresult = localVersions.withUnsafeMutableBufferPointer {
            mobilebackup2_version_exchange(cli, $0.baseAddress, Int8($0.count), &remote)
        }
        guard vresult == MOBILEBACKUP2_E_SUCCESS else {
            throw BackupError.protocolVersionUnsupported(device: remote > 0 ? String(remote) : "unknown")
        }

        // Build the verified wire dict {TargetIdentifier first; NewPassword?/OldPassword? only when
        // non-nil; all string values}. The key-presence discipline is the pure, unit-tested
        // MB2ChangePassword.options; here we just realize it as a C plist.
        let opts = plist_new_dict()
        defer { plist_free(opts) }
        for (key, value) in MB2ChangePassword.options(targetIdentifier: udid, old: old, new: new) {
            plist_dict_set_item(opts, key, plist_new_string(value))
        }
        // MessageName is injected by send_message from the "ChangePassword" argument — not a dict key.
        let sent = mobilebackup2_send_message(cli, "ChangePassword", opts)
        guard sent == MOBILEBACKUP2_E_SUCCESS else {
            throw BackupError.serviceStartFailed(code: sent.rawValue)
        }

        // Read the terminal DLMessageProcessMessage via the SAME audited loop a backup uses. A
        // ChangePassword performs no file transfer, so the loop receives only the terminal message;
        // a throwaway temp dir satisfies the handlers' backupRoot without any file landing in it.
        let scratch = URL(fileURLWithPath: NSTemporaryDirectory(), isDirectory: true)
            .appendingPathComponent("tether-changepw-\(UUID().uuidString)", isDirectory: true)
        try FileManager.default.createDirectory(at: scratch, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: scratch) }
        try runMessageLoop(client: cli, backupRoot: scratch) { _ in }
    }

    /// The DL* loop — ported from idevicebackup2.c main loop (~2503-2765).
    /// Terminal outcome: `.success` only on `DLMessageProcessMessage` ErrorCode==0; otherwise throws.
    private func runMessageLoop(client cli: mobilebackup2_client_t, backupRoot: URL,
                                progress: @escaping @Sendable (BackupProgress) -> Void) throws {
        let handlers = MB2Handlers(client: cli, backupRoot: backupRoot)
        var filesDone = 0
        // Two phases with different patience:
        //  - authorization: before the FIRST DL* message, the user may be entering their passcode
        //    on the device — that can reasonably take minutes. The reference idevicebackup2 has no
        //    limit here; we use a generous authorizationDeadline so we don't bail on a slow unlock.
        //  - transfer: once the first message arrives, the tight no-progress deadline (C1 + G1)
        //    bounds a mid-backup wedge. A received message or byte records progress on it.
        var authorized = false
        let authorizationDeadline = MB2Deadline(window: self.authorizationDeadline)
        let transferDeadline = MB2Deadline(window: noProgressDeadline)

        while true {
            // Hard deadline on total lack of progress — generous before authorization, tight after.
            try (authorized ? transferDeadline : authorizationDeadline).checkAlive()

            var msg: plist_t? = nil
            var dlmessage: UnsafeMutablePointer<CChar>? = nil
            let r = mobilebackup2_receive_message(cli, &msg, &dlmessage)

            // Classify the receive result. The device sends NO messages during the on-device
            // authorization wait (the user must enter their passcode), so the receive call returns
            // RECEIVE_TIMEOUT — or a transient non-fatal code — repeatedly. The reference
            // idevicebackup2 keeps waiting through this; only a dead transport (MUX/SSL) is fatal.
            //
            // These three cases are the same decision rules `MB2Deadline.awaitMessage` models and
            // unit-tests (incl. the keepWaiting-storm → deadline-throw backstop). Keep them in sync:
            // checkAlive-before-consume, no-progress on keepWaiting, throw on transportDead.
            switch MB2ReceiveDisposition(resultCode: r.rawValue, hasMessage: dlmessage != nil) {
            case .message:
                break   // fall through to processing below
            case .keepWaiting:
                // RECEIVE_TIMEOUT or a transient (e.g. PLIST_ERROR) during the auth wait — do NOT
                // treat as a disconnect. This is the between-message cancellation seam; keep
                // looping under the active deadline (checked at the top of the loop).
                if Task.isCancelled { throw BackupError.backupCancelled }
                if let msg { plist_free(msg) }
                if let dlmessage { free(dlmessage) }
                continue
            case .transportDead:
                // MUX_ERROR / SSL_ERROR: the connection is genuinely gone.
                if let msg { plist_free(msg) }
                if let dlmessage { free(dlmessage) }
                throw BackupError.deviceDisconnectedMidBackup(lastResultCode: r.rawValue)
            }
            guard let dlmessage else {
                if let msg { plist_free(msg) }
                throw BackupError.deviceDisconnectedMidBackup(lastResultCode: r.rawValue)
            }
            defer { if let msg { plist_free(msg) }; free(dlmessage) }

            if Task.isCancelled { throw BackupError.backupCancelled }
            // The first DL* message means the device authorized and the transfer has begun;
            // switch from the generous authorization deadline to the tight transfer deadline.
            authorized = true
            transferDeadline.recordProgress()   // a received message counts as progress

            let op = MB2Operation(dlMessage: String(cString: dlmessage))
            switch op {
            case .sendFiles:
                try handlers.sendFiles(message: msg)
            case .receiveFiles:
                let n = try handlers.receiveFiles(message: msg, deadline: transferDeadline)
                filesDone += n
                progress(.transferring(file: "", filesDone: filesDone, filesTotal: filesDone))
            case .listDirectory: handlers.listDirectory(message: msg)
            case .createDirectory: handlers.makeDirectory(message: msg)
            case .moveItems: handlers.moveItems(message: msg)
            case .removeItems: handlers.removeItems(message: msg)
            case .copyItem: handlers.copyItem(message: msg)
            case .freeDiskSpace: handlers.freeDiskSpace()
            case .purgeDiskSpace: handlers.purgeDiskSpace()
            case .processMessage:
                // C2: DLMessageProcessMessage is ALWAYS terminal in the reference (idevicebackup2.c
                // unconditionally `break`s the loop at it). Success only when ErrorCode == 0.
                let dump = handlers.describe(msg)
                switch handlers.processMessageOutcome(msg) {
                case .success:
                    progress(.finished(verified: false))
                    return
                case .failure(let code, let description):
                    let reason = "DLMessageProcessMessage ErrorCode \(code)\(description.map { ": \($0)" } ?? "")"
                    FileHandle.standardError.write(Data("[tether] backup refused — \(reason)\n  message: \(dump)\n".utf8))
                    throw BackupError.backupRefusedByDevice(reason: reason, detail: dump)
                }
            case .disconnect:
                // An early DLMessageDisconnect (before a success ProcessMessage) — the device tore
                // the session down. Capture what accompanied it.
                let dump = handlers.describe(msg)
                FileHandle.standardError.write(Data("[tether] backup refused — early DLMessageDisconnect\n  message: \(dump)\n".utf8))
                throw BackupError.backupRefusedByDevice(reason: "early DLMessageDisconnect", detail: dump)
            case nil:
                continue
            }
        }
    }
}
