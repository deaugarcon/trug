import Foundation

public enum BackupError: Error, LocalizedError, Equatable {
    case serviceStartFailed(code: Int32)
    case protocolVersionUnsupported(device: String)
    /// `lastResultCode` carries the mobilebackup2 receive result that triggered the disconnect,
    /// for diagnostics (e.g. distinguishing a true MUX_ERROR from a transient seen at the seam).
    case deviceDisconnectedMidBackup(lastResultCode: Int32? = nil)
    case insufficientDiskSpace(needed: UInt64, available: UInt64)
    case backupCancelled
    case deviceLocked
    case verificationFailed
    /// The device terminated the backup at the protocol level — either a
    /// `DLMessageProcessMessage` carrying a non-zero `ErrorCode`, or an early
    /// `DLMessageDisconnect`. `detail` carries the dumped message for diagnosis.
    case backupRefusedByDevice(reason: String, detail: String)
    /// `enable` was asked to turn on encryption that is already on (`WillEncrypt == true`).
    /// A dedicated, honest case — NOT `serviceStartFailed(code: 0)`, since code 0 means success
    /// everywhere else in this codebase and would read as a contradiction at the call site / CLI.
    case encryptionAlreadyEnabled
    /// `disable`/`rotate` was asked to act on encryption that is off (`WillEncrypt == false`).
    /// There is no backup password to remove or change when the backup is not encrypted.
    case encryptionNotEnabled

    public var errorDescription: String? {
        switch self {
        case .serviceStartFailed(let c): "Could not start the backup service (mobilebackup2 code \(c))."
        case .protocolVersionUnsupported(let v): "The device's backup protocol (\(v)) is not supported."
        case .deviceDisconnectedMidBackup(let code):
            if let code { "The device disconnected during the backup (mobilebackup2 code \(code))." }
            else { "The device disconnected during the backup." }
        case .insufficientDiskSpace(let n, let a): "Not enough disk space: need \(n) bytes, \(a) available."
        case .backupCancelled: "The backup was cancelled."
        case .deviceLocked: "The device is locked."
        case .verificationFailed: "The backup completed but failed verification."
        case .backupRefusedByDevice(let reason, let detail):
            "The device refused the backup: \(reason). Message: \(detail)"
        case .encryptionAlreadyEnabled: "Backup encryption is already enabled on this device."
        case .encryptionNotEnabled: "Backup encryption is not enabled on this device."
        }
    }

    public var recoverySuggestion: String? {
        switch self {
        case .serviceStartFailed: "Reconnect the device and ensure it is unlocked and trusted, then retry."
        case .protocolVersionUnsupported: "Update Tether; this device's iOS uses a newer backup protocol."
        case .deviceDisconnectedMidBackup: "Reconnect the device; the next backup resumes where it stopped."
        case .insufficientDiskSpace: "Free up disk space and run the backup again."
        case .backupCancelled: "Run `trug backup create` again to retry."
        case .deviceLocked: "Unlock the device, then run the backup again."
        case .verificationFailed: "Run `trug backup verify` for details; the previous backup is unchanged."
        case .backupRefusedByDevice: "Ensure the device is unlocked and trusted; check the message detail for the device's reason."
        case .encryptionAlreadyEnabled: "Use `trug backup encryption rotate` to change the password, or `disable` to turn it off."
        case .encryptionNotEnabled: "Run `trug backup encryption enable` to turn on backup encryption first."
        }
    }
}

public enum KeybagError: Error, LocalizedError, Equatable {
    case wrongPassword
    case unsupportedKeybagVersion(version: Int)
    case malformedKeybag

    public var errorDescription: String? {
        switch self {
        case .wrongPassword: "The backup password is incorrect."
        case .unsupportedKeybagVersion(let v): "Unsupported backup keybag version (\(v))."
        case .malformedKeybag: "The backup keybag is malformed or unreadable."
        }
    }

    public var recoverySuggestion: String? {
        switch self {
        case .wrongPassword: "Re-enter the backup password set on the device."
        case .unsupportedKeybagVersion: "File an issue with your iOS version; Tether needs to add support."
        case .malformedKeybag: "The backup may be corrupt; re-create it with `trug backup create`."
        }
    }
}

/// VerifyError is only thrown for IO/parse failures during verification.
/// Verification *findings* are data in `VerifyReport`, not errors.
public enum VerifyError: Error, LocalizedError, Equatable {
    case backupNotFound(BackupID)
    /// The backup exists, but it has no file at the requested (domain, relativePath). Distinct
    /// from `backupNotFound`: the backup is present and readable; only the named file is absent.
    case fileNotFoundInBackup(domain: String, path: String)
    case manifestUnreadable(reason: String)
    /// A `Manifest.db` row carried a `fileID` that is not a valid 40-char lowercase SHA1 hex.
    /// Refusing to map it to a host path closes the device-driven path-traversal surface.
    case malformedFileID(String)
    /// The backup is encrypted (its `Manifest.db` is ciphertext) but no password was supplied, so
    /// verification cannot decrypt the manifest. Distinct from `manifestUnreadable`: the backup is
    /// NOT corrupt — it just needs a password. Surfacing this instead of a SQLITE_NOTADB parse error
    /// is the whole point of WP4.2 (Checkpoint C run 1): never tell the user to re-create a perfectly
    /// good encrypted backup. Maps to the user-input exit class, not the corrupt-backup class.
    case passwordRequired(udid: String)

    public var errorDescription: String? {
        switch self {
        case .backupNotFound(let id): "No backup found for \(id)."
        case .fileNotFoundInBackup(let domain, let path): "The backup has no file at \(domain)/\(path)."
        case .manifestUnreadable(let r): "Could not read the backup manifest: \(r)."
        case .malformedFileID(let id): "The backup manifest contains an invalid file id (\(id))."
        case .passwordRequired(let udid): "Backup \(udid) is encrypted; a password is required to verify it."
        }
    }
    public var recoverySuggestion: String? {
        switch self {
        case .backupNotFound: "Run `trug backup list` to see available backups."
        case .fileNotFoundInBackup: "Run `trug backup browse <udid>` to see the files in the backup."
        case .manifestUnreadable: "The backup may be incomplete; re-create it."
        case .malformedFileID: "The backup may be corrupt or tampered with; re-create it."
        case .passwordRequired: "Set TRUG_BACKUP_PASSWORD (or use --verify-level crypto with a password)."
        }
    }
}
