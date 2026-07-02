import Testing
import Foundation
import Cplist
@testable import CWrappers

@Suite struct PlistBridgeTests {
    @Test func roundTripsDictionary() throws {
        let xml = """
        <?xml version="1.0" encoding="UTF-8"?>
        <!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
        <plist version="1.0"><dict>
            <key>DeviceName</key><string>Test iPhone</string>
            <key>BatteryCurrentCapacity</key><integer>87</integer>
        </dict></plist>
        """
        let value = try #require(PlistBridge.foundationObject(fromXML: Data(xml.utf8)) as? [String: Any])
        #expect(value["DeviceName"] as? String == "Test iPhone")
        #expect(value["BatteryCurrentCapacity"] as? Int == 87)
    }

    @Test func roundTripsCNode() throws {
        // Proves dylib linking + loading: constructs a real plist_t via C calls
        let dict = try #require(plist_new_dict())
        defer { plist_free(dict) }
        plist_dict_set_item(dict, "DeviceName", plist_new_string("Test iPhone"))
        let value = try #require(PlistBridge.foundationObject(from: dict) as? [String: Any])
        #expect(value["DeviceName"] as? String == "Test iPhone")
    }
}
