import Testing
import Foundation
@testable import BackupCore
@testable import DeviceCore

/// End-to-end backup against a real device. Device Checkpoint A — controller-run only,
/// gated behind TRUG_DEVICE_TESTS=1. Demonstrates the caller-owned state-machine flow:
/// beginStaging → session.backup → verifyStructural → promote (only on a passing verify).
@Suite(.enabled(if: ProcessInfo.processInfo.environment["TRUG_DEVICE_TESTS"] == "1"))
struct BackupGatedTests {
    @Test func createsAndVerifiesStructuralBackup() throws {
        let device = try #require(try UsbmuxDeviceLister().list(includeNetwork: false).first)
        let id = BackupID(udid: device.udid)
        let root = URL.temporaryTestDir()
        defer { try? FileManager.default.removeItem(at: root) }
        let store = BackupStore(root: root)
        let staging = try store.beginStaging(for: id)

        let conn = try DeviceConnection(udid: device.udid)
        let session = MobileBackup2Session(connection: conn)
        do {
            try session.backup(options: BackupOptions(udid: device.udid), into: staging.directory) { _ in }
        } catch {
            store.markFailed(staging)
            throw error
        }

        let report = try BackupVerifier().verifyStructural(backupDir: staging.directory, udid: device.udid)
        #expect(report.passed)
        guard report.passed else { store.markFailed(staging); return }

        try store.promote(staging)
        #expect(store.state(for: id) == .verified)
    }

    /// Device Checkpoint C (controller-run): after a backup exists, extract a non-personal,
    /// always-present file (`Info.plist`) and assert the extracted bytes parse as a plist.
    /// No personal-data dependency. Controller-run only — never executed off a device.
    @Test func extractsInfoPlistFromBackup() throws {
        let device = try #require(try UsbmuxDeviceLister().list(includeNetwork: false).first)
        let id = BackupID(udid: device.udid)
        let store = BackupStore(root: BackupStore.defaultRoot)
        let dir = try #require(try store.currentBackupDirectory(for: id))

        let data = try BackupExtractor().extract(udidDir: dir.appendingPathComponent(device.udid),
                                                 domain: "RootDomain", path: "Info.plist",
                                                 password: ProcessInfo.processInfo.environment["TRUG_BACKUP_PASSWORD"] ?? "")
        let parsed = try PropertyListSerialization.propertyList(from: data, options: [], format: nil)
        #expect(parsed is [String: Any])
    }
}

/// Device Checkpoint D (controller-run only — NEVER run off a device, gated by TRUG_DEVICE_TESTS=1):
/// the EncryptionControl round-trip against a THROWAWAY/TEST device — this CHANGES the device's backup
/// password. status → enable → status(true) → rotate → disable → status(false). The wrong-old-password
/// outcome (Odb Q4 heuristic) is verified here too, manually, because it has no clean host-side signal.
/// The controller supplies passwords via TRUG_BACKUP_PASSWORD / TRUG_BACKUP_NEW_PASSWORD.
@Suite(.enabled(if: ProcessInfo.processInfo.environment["TRUG_DEVICE_TESTS"] == "1"))
struct EncryptionControlGatedTests {
    @Test func enableRotateDisableRoundTrip() throws {
        let device = try #require(try UsbmuxDeviceLister().list(includeNetwork: false).first)
        let udid = device.udid
        let control = EncryptionControl()
        // Codex F1 (SECURITY): the passwords MUST come from the environment — there is NO tracked
        // default. A literal fallback ("tether-test-1"/…) would leave a REAL device encrypted with a
        // PUBLIC, source-visible backup password after a mid-test failure. `#require` fails the test
        // cleanly when the controller forgot to supply them, rather than running with known material.
        let pw1 = try #require(ProcessInfo.processInfo.environment["TRUG_BACKUP_PASSWORD"],
                               "set TRUG_BACKUP_PASSWORD — no tracked default for a device round-trip")
        let pw2 = try #require(ProcessInfo.processInfo.environment["TRUG_BACKUP_NEW_PASSWORD"],
                               "set TRUG_BACKUP_NEW_PASSWORD — no tracked default for a device round-trip")

        // Start from a known state: if already encrypted, disable with pw1 first.
        if try control.status(udid: udid) {
            try control.disable(current: pw1, udid: udid)
        }
        #expect(try control.status(udid: udid) == false)

        try control.enable(new: pw1, udid: udid)
        #expect(try control.status(udid: udid) == true)

        try control.rotate(old: pw1, new: pw2, udid: udid)
        #expect(try control.status(udid: udid) == true)

        try control.disable(current: pw2, udid: udid)
        #expect(try control.status(udid: udid) == false)
    }

    /// A wrong old password on a rotate maps to KeybagError.wrongPassword (the Q4 heuristic).
    /// Requires the device to be encrypted with pw1 before running.
    @Test func wrongOldPasswordMapsToWrongPassword() throws {
        let device = try #require(try UsbmuxDeviceLister().list(includeNetwork: false).first)
        let udid = device.udid
        let control = EncryptionControl()
        // Codex F1 (SECURITY): require the env password — no tracked default (see round-trip above).
        let pw1 = try #require(ProcessInfo.processInfo.environment["TRUG_BACKUP_PASSWORD"],
                               "set TRUG_BACKUP_PASSWORD — no tracked default for a device round-trip")

        if try control.status(udid: udid) == false {
            try control.enable(new: pw1, udid: udid)
        }
        #expect(throws: KeybagError.wrongPassword) {
            try control.rotate(old: "definitely-not-the-password", new: "whatever", udid: udid)
        }
    }
}
