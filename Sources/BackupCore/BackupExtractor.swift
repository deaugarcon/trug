import Foundation

/// Reads one file's plaintext bytes out of a backup, decrypting if the backup is encrypted.
///
/// Pure engine logic (no CLI, store, or device coupling) so it is unit-testable against a
/// `FixtureBuilder` backup. The CLI `Extract` subcommand is a thin wrapper over this.
public struct BackupExtractor {
    public init() {}

    /// Locates `(domain, path)` in the backup at `udidDir` and returns its plaintext bytes.
    ///
    /// For an encrypted backup the password unlocks the keybag (which also transparently decrypts
    /// an encrypted `Manifest.db`) and the per-file key decrypts the shard; for an unencrypted
    /// backup the shard is read directly — and the password closure is never evaluated.
    /// Throws `VerifyError.fileNotFoundInBackup` when the backup exists but has no such file —
    /// NOT `backupNotFound`, which would wrongly imply the whole backup is missing.
    public func extract(udidDir: URL, domain: String, path: String,
                        password: @autoclosure () -> String) throws -> Data {
        let isEncrypted = (try ManifestReader(backupDir: udidDir).metadata()).isEncrypted
        if isEncrypted {
            let unlocked = try Keybag(tlv: try ManifestReader.backupKeybagTLV(in: udidDir)).unlock(password: password())
            let reader = try ManifestReader(backupDir: udidDir, unlockedKeybag: unlocked)
            guard let record = try reader.recordWithKey(domain: domain, path: path) else {
                throw VerifyError.fileNotFoundInBackup(domain: domain, path: path)
            }
            return try BackupDecryptor().decrypt(record, shardURL: reader.shardURL(for: record), using: unlocked)
        } else {
            let reader = try ManifestReader(backupDir: udidDir)
            guard let record = try reader.record(domain: domain, path: path) else {
                throw VerifyError.fileNotFoundInBackup(domain: domain, path: path)
            }
            return try Data(contentsOf: reader.shardURL(for: record))
        }
    }
}
