import Foundation
import DeviceCore

/// Reads and changes a device's backup-encryption state via the MobileBackup2 `ChangePassword`
/// message (the same mechanism `idevicebackup2 -i changepw/encryption`). `status` reads the
/// lockdownd `WillEncrypt` flag; `enable`/`disable`/`rotate` send a `ChangePassword` and prove the
/// device accepted it by reading the terminal `DLMessageProcessMessage` through the audited
/// `MobileBackup2Session` loop — never claiming success without the device's confirmation.
///
/// Ported from `Vendor/src/libimobiledevice/tools/idevicebackup2.c` `CMD_CHANGEPW` (lines 2379–2449),
/// corrected per `docs/superpowers/sp2/wp5.design.odb.md` (the plan's fire-and-forget pseudocode would
/// have reported success for every call, including a wrong password).
public struct EncryptionControl {
    /// The three encryption operations, used by the pure state-guard so the precondition logic is
    /// testable without a device.
    public enum Operation: Equatable { case enable, disable, rotate }

    /// The decision the state-guard reaches given the current `WillEncrypt` and the requested op:
    /// either proceed with the ChangePassword, or throw a specific honest error.
    public enum Guard: Equatable {
        case proceed
        case alreadyEnabled   // enable when already encrypted → BackupError.encryptionAlreadyEnabled
        case notEnabled       // disable/rotate when not encrypted → BackupError.encryptionNotEnabled
    }

    public init() {}

    /// PURE state-guard: given the device's current `willEncrypt` and the op, decide proceed-vs-throw.
    /// Mirrors idevicebackup2.c's guards: enable requires `!willEncrypt` (line 2383), disable and
    /// rotate require `willEncrypt` (lines 2405, 2424). Factored out (no device) so the precondition
    /// logic is unit-tested directly, the way `MB2ProcessMessage.outcome` is a pure parser.
    public static func decide(op: Operation, willEncrypt: Bool) -> Guard {
        switch op {
        case .enable:           return willEncrypt ? .alreadyEnabled : .proceed
        case .disable, .rotate: return willEncrypt ? .proceed : .notEnabled
        }
    }

    /// Reads whether this device's backups are (or will be) encrypted, via lockdownd domain
    /// `com.apple.mobile.backup` key `WillEncrypt` (idevicebackup2.c lines 2058–2067). A missing key
    /// or a read failure both read as `false` (not encrypted) — the conservative default that lets
    /// `enable` proceed harmlessly; see the R3 caveat in the design note for the post-op-lag nuance.
    public func status(udid: String) throws -> Bool {
        let session = try LockdownSession(udid: udid)
        return (session.value(domain: "com.apple.mobile.backup", key: "WillEncrypt") as? Bool) ?? false
    }

    /// Enables encryption with a new password (device must currently be unencrypted).
    ///
    /// `new` is `@autoclosure`: the state guard (`alreadyEnabled` if the device is already encrypted)
    /// runs FIRST, so an already-encrypted enable throws WITHOUT pulling the password — the CLI's
    /// interactive `PasswordInput.readNew()` prompt fires only once the op is going to proceed (Odb Q1).
    public func enable(new: @autoclosure () -> String, udid: String) throws {
        try guarded(op: .enable, udid: udid)
        try changePassword(old: nil, new: new(), udid: udid)
    }

    /// Disables encryption (device must currently be encrypted; needs the current password).
    ///
    /// `current` is `@autoclosure`: the `notEnabled` guard runs FIRST, so disabling an
    /// already-unencrypted device throws `encryptionNotEnabled` WITHOUT prompting for a password it
    /// would only discard (Odb Q1). The CLI's `PasswordInput.read()` fires only after the guard passes.
    public func disable(current: @autoclosure () -> String, udid: String) throws {
        try guarded(op: .disable, udid: udid)
        try changePassword(old: current(), new: nil, udid: udid)
    }

    /// Rotates the backup password (device must currently be encrypted; needs old + new).
    ///
    /// `old`/`new` are `@autoclosure`: the `notEnabled` guard runs FIRST, so rotating on an
    /// already-unencrypted device throws WITHOUT prompting for the old/new passwords (Odb Q1).
    public func rotate(old: @autoclosure () -> String, new: @autoclosure () -> String, udid: String) throws {
        try guarded(op: .rotate, udid: udid)
        try changePassword(old: old(), new: new(), udid: udid)
    }

    // MARK: - internals

    /// Applies the pure state-guard against the live `status()` and throws the honest error on a
    /// precondition miss. Keeps the device read and the decision separated (the decision is the
    /// unit-tested part; this glue is device-gated).
    private func guarded(op: Operation, udid: String) throws {
        switch EncryptionControl.decide(op: op, willEncrypt: try status(udid: udid)) {
        case .proceed:        return
        case .alreadyEnabled: throw BackupError.encryptionAlreadyEnabled
        case .notEnabled:     throw BackupError.encryptionNotEnabled
        }
    }

    /// Sends the ChangePassword and reads the device's terminal response through the audited
    /// `MobileBackup2Session.changePassword` loop. WRONG-PASSWORD HEURISTIC (Odb Q4): the vendored
    /// source has NO dedicated wrong-password code, so when an `old` password was supplied and the
    /// device refuses the op (`backupRefusedByDevice`), the most likely cause is a wrong old
    /// password — map to `KeybagError.wrongPassword` while preserving the device's raw reason in the
    /// console (the loop already logs the ErrorDescription to stderr). This is a heuristic, not a
    /// protocol fact; the definitive wrong-password outcome is device-surfaced at checkpoint D.
    private func changePassword(old: String?, new: String?, udid: String) throws {
        let connection = try DeviceConnection(udid: udid)
        let session = MobileBackup2Session(connection: connection)
        do {
            try session.changePassword(udid: udid, old: old, new: new)
        } catch let error as BackupError {
            if old != nil, case .backupRefusedByDevice = error {
                throw KeybagError.wrongPassword
            }
            throw error
        }
    }
}
