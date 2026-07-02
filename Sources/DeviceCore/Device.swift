import Foundation

public enum ConnectionKind: String, Sendable, Codable {
    case usb
    case network
}

/// A device visible to usbmuxd, before any lockdown session is opened.
public struct DiscoveredDevice: Sendable, Codable, Equatable {
    public let udid: String
    public let connection: ConnectionKind
    public init(udid: String, connection: ConnectionKind) {
        self.udid = udid
        self.connection = connection
    }
}

/// Values read from a paired device over lockdownd.
public struct DeviceInfo: Sendable, Codable, Equatable {
    public let udid: String
    public let name: String
    public let productType: String       // e.g. "iPhone14,5"
    public let productVersion: String    // e.g. "17.5.1"
    public let buildVersion: String
    public let serialNumber: String
    public let batteryPercent: Int?
    public let totalDiskBytes: UInt64?
    public let freeDiskBytes: UInt64?
    public init(udid: String, name: String, productType: String, productVersion: String,
                buildVersion: String, serialNumber: String, batteryPercent: Int?,
                totalDiskBytes: UInt64?, freeDiskBytes: UInt64?) {
        self.udid = udid; self.name = name; self.productType = productType
        self.productVersion = productVersion; self.buildVersion = buildVersion
        self.serialNumber = serialNumber; self.batteryPercent = batteryPercent
        self.totalDiskBytes = totalDiskBytes; self.freeDiskBytes = freeDiskBytes
    }
}
