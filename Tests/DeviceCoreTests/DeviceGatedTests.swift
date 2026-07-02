import Testing
import Foundation
@testable import DeviceCore

/// Real-device tests. Enable with: TRUG_DEVICE_TESTS=1 ./Scripts/dev.sh test
@Suite(.enabled(if: ProcessInfo.processInfo.environment["TRUG_DEVICE_TESTS"] == "1"))
struct DeviceGatedTests {
    @Test func listsAtLeastOneUSBDevice() throws {
        let devices = try UsbmuxDeviceLister().list(includeNetwork: false)
        #expect(!devices.isEmpty)
    }

    @Test func readsInfoFromFirstDevice() throws {
        let device = try #require(try UsbmuxDeviceLister().list(includeNetwork: false).first)
        let info = try LockdownSession(udid: device.udid).info()
        #expect(!info.name.isEmpty)
        #expect(!info.productVersion.isEmpty)
    }
}
