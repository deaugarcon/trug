// swift-tools-version: 6.0
import PackageDescription

let package = Package(
    name: "trug",
    platforms: [.macOS(.v14)],
    products: [
        .library(name: "DeviceCore", targets: ["DeviceCore"]),
        .library(name: "BackupCore", targets: ["BackupCore"]),
        .executable(name: "trug", targets: ["TetherCLI"]),
    ],
    dependencies: [
        .package(url: "https://github.com/apple/swift-argument-parser", from: "1.3.0"),
    ],
    targets: [
        .systemLibrary(name: "Cplist", pkgConfig: "libplist-2.0"),
        .systemLibrary(name: "Climobiledevice", pkgConfig: "libimobiledevice-1.0"),
        .target(name: "CWrappers", dependencies: ["Cplist", "Climobiledevice"]),
        .testTarget(name: "CWrappersTests", dependencies: ["CWrappers"]),
        .target(name: "DeviceCore", dependencies: ["CWrappers"]),
        .testTarget(name: "DeviceCoreTests", dependencies: ["DeviceCore"]),
        .target(name: "BackupCore", dependencies: ["DeviceCore", "CWrappers"],
                linkerSettings: [.linkedLibrary("sqlite3")]),
        .testTarget(name: "BackupCoreTests", dependencies: ["BackupCore"]),
        .executableTarget(
            name: "TetherCLI",
            dependencies: [
                "DeviceCore",
                "BackupCore",
                .product(name: "ArgumentParser", package: "swift-argument-parser"),
            ]
        ),
        .testTarget(name: "TetherCLITests", dependencies: ["TetherCLI"]),
    ]
)
