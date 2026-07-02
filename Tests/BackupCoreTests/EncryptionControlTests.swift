import Testing
import Foundation
@testable import BackupCore

/// Device-free coverage for EncryptionControl. The actual `ChangePassword` send (client +
/// version exchange + receive loop) and the wrong-old-password outcome are device-gated
/// (checkpoint D) — they have no clean host-side signal (Odb Q4) — so they are NOT unit-tested
/// here. What IS testable without a device: the pure state-guard decision and the wire-dict shape.
@Suite struct EncryptionControlGuardTests {
    // enable requires the device be currently UNENCRYPTED (idevicebackup2.c:2383).
    @Test func enableProceedsWhenNotEncrypted() {
        #expect(EncryptionControl.decide(op: .enable, willEncrypt: false) == .proceed)
    }
    @Test func enableRefusesWhenAlreadyEncrypted() {
        #expect(EncryptionControl.decide(op: .enable, willEncrypt: true) == .alreadyEnabled)
    }

    // disable requires the device be currently ENCRYPTED (idevicebackup2.c:2405).
    @Test func disableProceedsWhenEncrypted() {
        #expect(EncryptionControl.decide(op: .disable, willEncrypt: true) == .proceed)
    }
    @Test func disableRefusesWhenNotEncrypted() {
        #expect(EncryptionControl.decide(op: .disable, willEncrypt: false) == .notEnabled)
    }

    // rotate requires the device be currently ENCRYPTED (idevicebackup2.c:2424).
    @Test func rotateProceedsWhenEncrypted() {
        #expect(EncryptionControl.decide(op: .rotate, willEncrypt: true) == .proceed)
    }
    @Test func rotateRefusesWhenNotEncrypted() {
        #expect(EncryptionControl.decide(op: .rotate, willEncrypt: false) == .notEnabled)
    }
}

/// The ChangePassword wire dict shape, verified against idevicebackup2.c:2380-2447. Pure value, no
/// device: TargetIdentifier always; password keys only when non-nil; no MessageName key.
@Suite struct MB2ChangePasswordOptionsTests {
    @Test func enableSetsNewPasswordOnly() {
        let opts = MB2ChangePassword.options(targetIdentifier: "UDID", old: nil, new: "pw")
        #expect(opts["TargetIdentifier"] == "UDID")
        #expect(opts["NewPassword"] == "pw")
        #expect(opts["OldPassword"] == nil)            // omitted, NOT empty-string
        #expect(opts["MessageName"] == nil)            // injected by send_message, never a dict key
    }

    @Test func disableSetsOldPasswordOnly() {
        let opts = MB2ChangePassword.options(targetIdentifier: "UDID", old: "pw", new: nil)
        #expect(opts["TargetIdentifier"] == "UDID")
        #expect(opts["OldPassword"] == "pw")
        #expect(opts["NewPassword"] == nil)            // omitted on a disable
    }

    @Test func rotateSetsBothPasswords() {
        let opts = MB2ChangePassword.options(targetIdentifier: "UDID", old: "a", new: "b")
        #expect(opts["TargetIdentifier"] == "UDID")
        #expect(opts["OldPassword"] == "a")
        #expect(opts["NewPassword"] == "b")
    }

    @Test func targetIdentifierIsAlwaysPresent() {
        // Even a degenerate (no-op) call carries TargetIdentifier — omitting it is a device rejection.
        let opts = MB2ChangePassword.options(targetIdentifier: "UDID", old: nil, new: nil)
        #expect(opts == ["TargetIdentifier": "UDID"])
    }
}

/// The honest encryption error cases (replacing the misleading serviceStartFailed(code:0)) carry
/// real description + recovery, like every other BackupError.
@Suite struct EncryptionErrorTests {
    @Test func encryptionStateErrorsHaveRecovery() {
        let errors: [BackupError] = [.encryptionAlreadyEnabled, .encryptionNotEnabled]
        for e in errors {
            #expect(e.errorDescription?.isEmpty == false)
            #expect(e.recoverySuggestion?.isEmpty == false)
        }
    }
}

/// Odb Q1 (LAZY GUARD-BEFORE-PROMPT): disable/rotate take the password as @autoclosure and run the
/// `status()` state guard BEFORE pulling it — so the interactive PasswordInput prompt never fires for
/// an op the guard is about to refuse. These tests prove the ORDERING device-free: `status()` opens a
/// LockdownSession against a bogus udid (no device → it throws), and the password closure records a
/// failure if invoked. Because the guard/status step runs first and throws, the password is NEVER
/// evaluated. (This proves the host-side ordering; the encryptionNotEnabled outcome against a real
/// not-encrypted device is device-gated — checkpoint D.) Mirrors the browse/verify lazy tests.
@Suite struct EncryptionControlLazyPromptTests {
    private static let bogusUDID = "00000000-0000000000000000"

    @Test func disablePullsPasswordOnlyAfterTheStatusGuard() {
        #expect(throws: (any Error).self) {
            try EncryptionControl().disable(
                current: { Issue.record("password closure evaluated before the status guard — would prompt then discard"); return "" }(),
                udid: Self.bogusUDID)
        }
    }

    @Test func rotatePullsPasswordsOnlyAfterTheStatusGuard() {
        #expect(throws: (any Error).self) {
            try EncryptionControl().rotate(
                old: { Issue.record("old-password closure evaluated before the status guard"); return "" }(),
                new: { Issue.record("new-password closure evaluated before the status guard"); return "" }(),
                udid: Self.bogusUDID)
        }
    }

    @Test func enablePullsPasswordOnlyAfterTheStatusGuard() {
        #expect(throws: (any Error).self) {
            try EncryptionControl().enable(
                new: { Issue.record("new-password closure evaluated before the status guard"); return "" }(),
                udid: Self.bogusUDID)
        }
    }
}
