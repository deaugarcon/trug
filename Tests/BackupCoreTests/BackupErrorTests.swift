import Testing
@testable import BackupCore

@Suite struct BackupErrorTests {
    @Test func backupErrorsHaveRecovery() {
        // KEEP IN SYNC with BackupError cases
        let errors: [BackupError] = [
            .serviceStartFailed(code: -1), .protocolVersionUnsupported(device: "1.0"),
            .deviceDisconnectedMidBackup(lastResultCode: -3), .deviceDisconnectedMidBackup(lastResultCode: nil),
            .insufficientDiskSpace(needed: 10, available: 5),
            .backupCancelled, .deviceLocked, .verificationFailed,
            .backupRefusedByDevice(reason: "ErrorCode 1", detail: "[...]"),
        ]
        for e in errors {
            #expect(e.errorDescription?.isEmpty == false)
            #expect(e.recoverySuggestion?.isEmpty == false)
        }
    }

    @Test func keybagErrorsHaveRecovery() {
        // KEEP IN SYNC with KeybagError cases
        let errors: [KeybagError] = [.wrongPassword, .unsupportedKeybagVersion(version: 9), .malformedKeybag]
        for e in errors {
            #expect(e.errorDescription?.isEmpty == false)
            #expect(e.recoverySuggestion?.isEmpty == false)
        }
    }
}
