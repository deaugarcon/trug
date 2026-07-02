import Foundation
import Climobiledevice

/// Owns a raw libimobiledevice device handle for service clients (MobileBackup2, AFC, …).
///
/// `rawDevice` is exposed for sibling engine packages; it is freed on `deinit` — do not
/// retain it past this object's lifetime.
///
/// - Warning: Any service client built on `rawDevice` (e.g. `MobileBackup2Session`) MUST hold
///   a strong reference to its `DeviceConnection` for as long as it uses the handle. If the
///   connection deinits first, `rawDevice` becomes a freed pointer and the client is a
///   use-after-free. Inject the connection and keep it; never copy out `rawDevice` and outlive it.
/// - Important: Not thread-safe. The underlying C handle is not synchronized.
public final class DeviceConnection {
    public let rawDevice: idevice_t
    public let udid: String

    public init(udid: String, lookupNetwork: Bool = false) throws {
        var dev: idevice_t? = nil
        var options = IDEVICE_LOOKUP_USBMUX.rawValue
        if lookupNetwork { options |= IDEVICE_LOOKUP_NETWORK.rawValue }
        let result = idevice_new_with_options(&dev, udid, idevice_options(rawValue: options))
        guard result == IDEVICE_E_SUCCESS, let dev else {
            // Preserve the C code instead of collapsing every failure into deviceNotFound:
            // a genuinely-absent device is deviceNotFound; anything else keeps its raw code
            // for diagnosis (mirrors LockdownSession's switch-and-fallback).
            switch result {
            case IDEVICE_E_NO_DEVICE:
                throw ConnectionError.deviceNotFound(udid: udid)
            default:
                throw ConnectionError.connectionFailed(code: result.rawValue)
            }
        }
        self.rawDevice = dev
        self.udid = udid
    }

    deinit { idevice_free(rawDevice) }
}
