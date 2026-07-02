import Testing
@testable import DeviceCore

@Suite struct ErrorMappingTests {
    @Test func connectionErrorsHaveRecoverySuggestions() {
        // KEEP IN SYNC with the enum cases in ConnectionError
        let errors: [ConnectionError] = [
            .muxdUnreachable, .deviceNotFound(udid: "X"), .noDeviceConnected,
            .ambiguousDevice(count: 2), .notPaired(udid: "X"),
            .connectionFailed(code: -3),
        ]
        for error in errors {
            #expect(error.errorDescription?.isEmpty == false)
            #expect(error.recoverySuggestion?.isEmpty == false)
        }
    }

    @Test func pairingErrorsHaveRecoverySuggestions() {
        // KEEP IN SYNC with the enum cases in PairingError
        let errors: [PairingError] = [
            .passwordProtected, .userDenied, .trustDialogPending, .failed(code: -1),
        ]
        for error in errors {
            #expect(error.errorDescription?.isEmpty == false)
            #expect(error.recoverySuggestion?.isEmpty == false)
        }
    }
}
