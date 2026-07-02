import Foundation

/// Identifies one device's backup within the store. In SP2 this is the device UDID
/// (one rolling backup per device); the type exists so a future snapshot id can extend it.
public struct BackupID: Sendable, Codable, Equatable, CustomStringConvertible {
    public let udid: String
    public init(udid: String) { self.udid = udid }
    public var description: String { udid }
}

public enum BackupState: String, Sendable, Codable {
    case inProgress = "in-progress"
    case verified
    case failed
}

public struct BackupSummary: Sendable, Codable, Equatable {
    public let id: BackupID
    public let state: BackupState
    public let isEncrypted: Bool
    public let deviceName: String
    public let productVersion: String
    public let sizeBytes: UInt64
    public init(id: BackupID, state: BackupState, isEncrypted: Bool,
                deviceName: String, productVersion: String, sizeBytes: UInt64) {
        self.id = id; self.state = state; self.isEncrypted = isEncrypted
        self.deviceName = deviceName; self.productVersion = productVersion; self.sizeBytes = sizeBytes
    }
}

public struct BackupMetadata: Sendable, Equatable {
    public let isEncrypted: Bool
    public let isFullBackup: Bool
    public let deviceName: String
    public let productVersion: String
    public init(isEncrypted: Bool, isFullBackup: Bool, deviceName: String, productVersion: String) {
        self.isEncrypted = isEncrypted; self.isFullBackup = isFullBackup
        self.deviceName = deviceName; self.productVersion = productVersion
    }
}

/// A row from Manifest.db `Files`. `fileID = SHA1(domain + "-" + relativePath)`.
public struct FileRecord: Sendable, Equatable {
    public let fileID: String
    public let domain: String
    public let relativePath: String
    public let flags: Int            // 1 = file, 2 = directory, 4 = symlink
    public let encryptionKeyBlob: Data?   // per-file `EncryptionKey` (44B: 4B prefix + 40B wrapped key); nil if unencrypted
    public let protectionClass: UInt32?   // per-file protection class from the metadata BLOB; nil if unencrypted
    public init(fileID: String, domain: String, relativePath: String, flags: Int,
                encryptionKeyBlob: Data?, protectionClass: UInt32? = nil) {
        self.fileID = fileID; self.domain = domain; self.relativePath = relativePath
        self.flags = flags; self.encryptionKeyBlob = encryptionKeyBlob; self.protectionClass = protectionClass
    }
    public var isFile: Bool { flags == 1 }
}

public enum BackupProgress: Sendable, Equatable {
    case started
    case transferring(file: String, filesDone: Int, filesTotal: Int)
    case verifying
    case finished(verified: Bool)
}
