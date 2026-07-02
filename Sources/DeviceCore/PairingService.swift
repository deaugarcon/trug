import Foundation
import Climobiledevice

public enum PairingService {
    /// Pairs with a USB-connected device. Idempotent: re-pairing succeeds.
    public static func pair(udid: String) throws {
        var dev: idevice_t? = nil
        guard idevice_new_with_options(&dev, udid, IDEVICE_LOOKUP_USBMUX) == IDEVICE_E_SUCCESS,
              let dev else {
            throw ConnectionError.deviceNotFound(udid: udid)
        }
        defer { idevice_free(dev) }

        // Plain client (no handshake): pairing is exactly the unpaired case.
        var cli: lockdownd_client_t? = nil
        let cliResult = lockdownd_client_new(dev, &cli, "tether")
        guard cliResult == LOCKDOWN_E_SUCCESS, let cli else {
            throw ConnectionError.connectionFailed(code: cliResult.rawValue)
        }
        defer { lockdownd_client_free(cli) }

        let result = lockdownd_pair(cli, nil)
        switch result {
        case LOCKDOWN_E_SUCCESS: return
        case LOCKDOWN_E_PASSWORD_PROTECTED: throw PairingError.passwordProtected
        case LOCKDOWN_E_USER_DENIED_PAIRING: throw PairingError.userDenied
        case LOCKDOWN_E_PAIRING_DIALOG_RESPONSE_PENDING: throw PairingError.trustDialogPending
        default: throw PairingError.failed(code: result.rawValue)
        }
    }
}
