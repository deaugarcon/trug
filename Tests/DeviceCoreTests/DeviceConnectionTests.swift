import Testing
import Foundation
@testable import DeviceCore

@Suite(.enabled(if: ProcessInfo.processInfo.environment["TRUG_DEVICE_TESTS"] == "1"))
struct DeviceConnectionTests {
    @Test func opensConnectionToFirstDevice() throws {
        let device = try #require(try UsbmuxDeviceLister().list(includeNetwork: false).first)
        let conn = try DeviceConnection(udid: device.udid)
        // The meaningful check is that init did not throw; rawDevice is a non-optional
        // OpaquePointer, so a `!= nil` assertion would be a dead always-true comparison.
        #expect(conn.udid == device.udid)
    }
}

/// Ungated: the bogus-UDID error path needs no device — idevice_new_with_options returns
/// a non-success code regardless of what's plugged in — so CI must exercise it.
@Suite struct DeviceConnectionErrorTests {
    @Test func throwsForBogusUDID() {
        #expect(throws: ConnectionError.self) {
            _ = try DeviceConnection(udid: "BOGUS-UDID-0000")
        }
    }
}
