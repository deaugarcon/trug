import Testing
@testable import DeviceCore

struct StubLister: DeviceLister {
    let devices: [DiscoveredDevice]
    func list(includeNetwork: Bool) throws -> [DiscoveredDevice] {
        includeNetwork ? devices : devices.filter { $0.connection == .usb }
    }
}

@Suite struct DeviceListerTests {
    @Test func filtersNetworkDevicesByDefault() throws {
        let lister = StubLister(devices: [
            DiscoveredDevice(udid: "A", connection: .usb),
            DiscoveredDevice(udid: "B", connection: .network),
        ])
        #expect(try lister.list(includeNetwork: false).map(\.udid) == ["A"])
        #expect(try lister.list(includeNetwork: true).count == 2)
    }

    @Test func usbmuxListerDoesNotThrow() throws {
        // Smoke test: must not crash whether or not a device is connected.
        let lister = UsbmuxDeviceLister()
        _ = try lister.list(includeNetwork: true)
    }
}
