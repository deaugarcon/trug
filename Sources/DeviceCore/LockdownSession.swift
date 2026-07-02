import Foundation
import Climobiledevice
import CWrappers

/// An authenticated lockdownd session with a paired device.
///
/// - Important: Not thread-safe. The underlying C handles are not synchronized.
///   Use from a single `Task` or thread. For concurrent access, wrap in an `actor`.
public final class LockdownSession {
    private let device: idevice_t
    private let client: lockdownd_client_t
    public let udid: String

    public init(udid: String, lookupNetwork: Bool = false) throws {
        var dev: idevice_t? = nil
        var opts = IDEVICE_LOOKUP_USBMUX.rawValue
        if lookupNetwork { opts |= IDEVICE_LOOKUP_NETWORK.rawValue }
        guard idevice_new_with_options(&dev, udid, idevice_options(rawValue: opts)) == IDEVICE_E_SUCCESS,
              let dev else {
            throw ConnectionError.deviceNotFound(udid: udid)
        }
        var cli: lockdownd_client_t? = nil
        let result = lockdownd_client_new_with_handshake(dev, &cli, "tether")
        guard result == LOCKDOWN_E_SUCCESS, let cli else {
            idevice_free(dev)
            switch result {
            case LOCKDOWN_E_INVALID_HOST_ID, LOCKDOWN_E_PAIRING_FAILED:
                throw ConnectionError.notPaired(udid: udid)
            default:
                throw ConnectionError.connectionFailed(code: result.rawValue)
            }
        }
        self.device = dev
        self.client = cli
        self.udid = udid
    }

    deinit {
        lockdownd_client_free(client)
        idevice_free(device)
    }

    /// Reads one lockdownd value; nil domain reads the global domain.
    public func value(domain: String?, key: String?) -> Any? {
        var node: plist_t? = nil
        guard lockdownd_get_value(client, domain, key, &node) == LOCKDOWN_E_SUCCESS,
              let node else { return nil }
        defer { plist_free(node) }
        return PlistBridge.foundationObject(from: node)
    }

    public func info() -> DeviceInfo {
        let global = value(domain: nil, key: nil) as? [String: Any] ?? [:]
        let battery = value(domain: "com.apple.mobile.battery",
                            key: "BatteryCurrentCapacity") as? Int
        let disk = value(domain: "com.apple.disk_usage", key: nil) as? [String: Any] ?? [:]
        // DeviceName, ProductType, ProductVersion, BuildVersion, SerialNumber are
        // mandatory lockdownd fields on all supported iOS versions. "" should never
        // appear from a healthy session; treat it as a read failure if it does.
        return DeviceInfo(
            udid: udid,
            name: global["DeviceName"] as? String ?? "",
            productType: global["ProductType"] as? String ?? "",
            productVersion: global["ProductVersion"] as? String ?? "",
            buildVersion: global["BuildVersion"] as? String ?? "",
            serialNumber: global["SerialNumber"] as? String ?? "",
            batteryPercent: battery,
            totalDiskBytes: (disk["TotalDataCapacity"] as? NSNumber)?.uint64Value,
            freeDiskBytes: (disk["TotalDataAvailable"] as? NSNumber)?.uint64Value)
    }
}
