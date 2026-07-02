import ArgumentParser

@main
struct Tether: ParsableCommand {
    static let configuration = CommandConfiguration(
        commandName: "trug",
        abstract: "Free, open-source local iPhone backup and inspection tool.",
        version: "0.1.0-alpha",
        subcommands: [Devices.self, Backup.self])
}
