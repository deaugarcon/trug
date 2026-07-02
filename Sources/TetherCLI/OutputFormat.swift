import Foundation
import BackupCore
import DeviceCore

enum ExitCode {
    static let deviceNotFound: Int32 = 2
    static let notPaired: Int32 = 3
    static let pairingDenied: Int32 = 4
    static let deviceLocked: Int32 = 5
    static let verificationFailed: Int32 = 6
    static let corruptBackup: Int32 = 7
    static let muxdUnreachable: Int32 = 69
    static let internalError: Int32 = 70
}

/// Maps an engine error to its documented exit code. Pure (no print, no exit) so the mapping is
/// unit-testable on its own — `exitReporting` is the side-effecting wrapper. A regression that moved
/// `passwordRequired` off the user-input class (the C1 contract: an encrypted backup needing a
/// password is NOT corruption) is caught by `OutputFormatTests`, not silently shipped.
func exitCode(for error: Error) -> Int32 {
    switch error {
    case ConnectionError.muxdUnreachable: ExitCode.muxdUnreachable
    case ConnectionError.deviceNotFound,
         ConnectionError.noDeviceConnected,
         ConnectionError.ambiguousDevice: ExitCode.deviceNotFound
    case ConnectionError.notPaired: ExitCode.notPaired
    case PairingError.trustDialogPending: ExitCode.notPaired
    case PairingError.userDenied: ExitCode.pairingDenied
    case PairingError.passwordProtected: ExitCode.deviceLocked
    // A named-but-absent backup or file, a refused overwrite, an encrypted backup with no password
    // supplied, a backup-encryption operation against the wrong on-device state, or a WRONG backup
    // password, is a user-input miss (WP3 Finding 7 / WP4.2 / WP5 Odb F-exit / Checkpoint D D1) —
    // NOT a corrupt-backup or internal fault. Mapping these here lets a script tell "you typed the
    // wrong password / wrong state" from "Tether crashed". `KeybagError.wrongPassword` reaches here
    // from BOTH the crypto verify/browse/extract paths (Keybag.unlock) AND the encryption
    // ChangePassword heuristic (a live device returns MBErrorDomain/207 "Invalid password" — D1).
    // The other KeybagError cases (unsupportedKeybagVersion/malformedKeybag) are NOT user-input and
    // intentionally fall through to the default class.
    case VerifyError.backupNotFound, VerifyError.fileNotFoundInBackup,
         VerifyError.passwordRequired,
         BackupError.encryptionAlreadyEnabled, BackupError.encryptionNotEnabled,
         KeybagError.wrongPassword,
         ExtractError.outputExists: ExitCode.deviceNotFound
    case BackupError.verificationFailed: ExitCode.verificationFailed
    // A corrupt / tampered manifest is a distinct class from an internal fault.
    case VerifyError.manifestUnreadable, VerifyError.malformedFileID: ExitCode.corruptBackup
    default: ExitCode.internalError
    }
}

/// Maps engine errors to stderr text + documented exit codes.
func exitReporting(_ error: Error) -> Never {
    let localized = error as? LocalizedError
    var message = localized?.errorDescription ?? String(describing: error)
    if let recovery = localized?.recoverySuggestion { message += "\n\(recovery)" }
    FileHandle.standardError.write(Data((message + "\n").utf8))
    Foundation.exit(exitCode(for: error))
}

func printJSON(_ value: some Encodable) throws {
    let encoder = JSONEncoder()
    encoder.outputFormatting = [.prettyPrinted, .sortedKeys]
    print(String(decoding: try encoder.encode(value), as: UTF8.self))
}
