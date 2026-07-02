import ArgumentParser
import DeviceCore

struct Devices: ParsableCommand {
    static let configuration = CommandConfiguration(
        abstract: "Detect, inspect, and pair devices.",
        subcommands: [List.self, Info.self, Pair.self])

    struct List: ParsableCommand {
        static let configuration = CommandConfiguration(abstract: "List connected devices.")
        @Flag(name: .long, help: "Output JSON instead of a table.")
        var json = false
        @Flag(name: .customLong("experimental-wifi"),
              help: "EXPERIMENTAL: include Wi-Fi devices.")
        var experimentalWifi = false

        // run() is intentionally non-throwing — exitReporting handles engine errors
        // with domain-specific exit codes. Do not convert to `throws`.
        func run() {
            do {
                let devices = try UsbmuxDeviceLister().list(includeNetwork: experimentalWifi)
                if json {
                    try printJSON(devices)
                } else if devices.isEmpty {
                    print("No devices found.")
                } else {
                    print(TextTable(header: ["UDID", "CONNECTION"],
                                    rows: devices.map { [$0.udid, $0.connection.rawValue] })
                          .rendered())
                }
            } catch { exitReporting(error) }
        }
    }
}

/// Resolves an explicit UDID, or the single connected device, or fails clearly.
/// Module-internal so `backup create` can reuse the same resolution as `devices`.
func resolveUDID(_ explicit: String?, includeNetwork: Bool) throws -> String {
    if let explicit { return explicit }
    let devices = try UsbmuxDeviceLister().list(includeNetwork: includeNetwork)
    guard let only = devices.first, devices.count == 1 else {
        throw devices.isEmpty
            ? ConnectionError.noDeviceConnected
            : ConnectionError.ambiguousDevice(count: devices.count)
    }
    return only.udid
}

extension Devices {
    struct Info: ParsableCommand {
        static let configuration = CommandConfiguration(abstract: "Show device information.")
        @Option(name: .long, help: "Target device UDID (optional if exactly one device).")
        var udid: String?
        @Flag(name: .long) var json = false
        @Flag(name: .customLong("experimental-wifi"),
              help: "EXPERIMENTAL: allow connecting over Wi-Fi.")
        var experimentalWifi = false

        // run() is intentionally non-throwing — exitReporting handles engine errors
        // with domain-specific exit codes. Do not convert to `throws`.
        func run() {
            do {
                let target = try resolveUDID(udid, includeNetwork: experimentalWifi)
                let info = try LockdownSession(udid: target,
                                               lookupNetwork: experimentalWifi).info()
                if json { try printJSON(info) } else {
                    let osRow = info.productVersion.isEmpty ? "-"
                        : info.buildVersion.isEmpty ? info.productVersion
                        : "\(info.productVersion) (\(info.buildVersion))"
                    print(TextTable(header: ["FIELD", "VALUE"], rows: [
                        ["Name", info.name],
                        ["Model", info.productType],
                        ["iOS", osRow],
                        ["Serial", info.serialNumber],
                        ["Battery", info.batteryPercent.map { "\($0)%" } ?? "-"],
                        ["UDID", info.udid],
                    ]).rendered())
                }
            } catch { exitReporting(error) }
        }
    }

    struct Pair: ParsableCommand {
        static let configuration = CommandConfiguration(abstract: "Pair with a USB device.")
        @Option(name: .long, help: "Target device UDID (optional if exactly one device).")
        var udid: String?

        // run() is intentionally non-throwing — exitReporting handles engine errors
        // with domain-specific exit codes. Do not convert to `throws`.
        func run() {
            do {
                let target = try resolveUDID(udid, includeNetwork: false)
                try PairingService.pair(udid: target)
                print("Paired with \(target).")
            } catch { exitReporting(error) }
        }
    }
}
