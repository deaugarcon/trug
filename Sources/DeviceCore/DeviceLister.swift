import Foundation
import Climobiledevice

/// Abstracts usbmuxd device enumeration; USB and Wi-Fi devices share this seam.
public protocol DeviceLister: Sendable {
    /// Lists devices known to usbmuxd. Network devices only when `includeNetwork` is true.
    func list(includeNetwork: Bool) throws -> [DiscoveredDevice]
}

public struct UsbmuxDeviceLister: DeviceLister {
    public init() {}

    public func list(includeNetwork: Bool) throws -> [DiscoveredDevice] {
        var infos: UnsafeMutablePointer<idevice_info_t?>? = nil
        var count: Int32 = 0
        let result = idevice_get_device_list_extended(&infos, &count)
        switch result {
        case IDEVICE_E_SUCCESS:
            break
        case IDEVICE_E_NO_DEVICE:
            // Per the pinned source (Vendor/src/libimobiledevice/src/idevice.c),
            // this function returns IDEVICE_E_NO_DEVICE exactly when the usbmuxd
            // socket connect fails ("ERROR: usbmuxd is not running!"). Zero devices
            // with usbmuxd alive comes back as IDEVICE_E_SUCCESS with count == 0.
            throw ConnectionError.muxdUnreachable
        default:
            throw ConnectionError.connectionFailed(code: result.rawValue)
        }
        // SUCCESS guarantees a non-NULL, NULL-terminated list per the pinned source;
        // guard defensively anyway.
        guard let infos else { throw ConnectionError.muxdUnreachable }
        defer { idevice_device_list_extended_free(infos) }

        return (0..<Int(count)).compactMap { index -> DiscoveredDevice? in
            guard let rawPtr = infos[index] else { return nil }
            let info = rawPtr.pointee
            guard let cUdid = info.udid else { return nil }
            let kind: ConnectionKind = info.conn_type == CONNECTION_NETWORK ? .network : .usb
            if kind == .network && !includeNetwork { return nil }
            return DiscoveredDevice(udid: String(cString: cUdid), connection: kind)
        }
    }
}
