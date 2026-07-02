import Foundation
import CryptoKit
import CommonCrypto
import SQLite3
@testable import BackupCore

/// SQLite asks the binder to copy the bound text (vs. assume it stays alive).
private let SQLITE_TRANSIENT = unsafeBitCast(-1, to: sqlite3_destructor_type.self)

/// Builds synthetic, unencrypted MobileSync backups with a known `Manifest.db`
/// and matching shard files, for exercising `ManifestReader` without a device.
enum FixtureBuilder {
    /// One `Files` row plus its shard contents.
    struct File {
        let domain: String
        let path: String
        let contents: Data
        init(domain: String, path: String, contents: Data) {
            self.domain = domain; self.path = path; self.contents = contents
        }
    }

    /// `fileID = SHA1(domain + "-" + relativePath)` per the backup spec (reference doc line 53).
    static func fileID(domain: String, path: String) -> String {
        let digest = Insecure.SHA1.hash(data: Data((domain + "-" + path).utf8))
        return digest.map { String(format: "%02x", $0) }.joined()
    }

    /// Writes a minimal backup tree under a fresh temp dir and returns the *root*
    /// (the dir that contains `<udid>/`). The caller reads via `root/<udid>` and
    /// cleans up `root` (i.e. `returned.deletingLastPathComponent()` from the udid dir).
    @discardableResult
    static func unencryptedBackup(
        udid: String,
        files: [File],
        circularFileIDs: Bool = false,
        omitInfoPlist: Bool = false
    ) throws -> URL {
        let root = URL.temporaryTestDir()
        let dir = root.appendingPathComponent(udid)
        try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)

        try writePlist(["IsFullBackup": true, "SnapshotState": "finished"],
                       to: dir.appendingPathComponent("Status.plist"))
        try writePlist(["IsEncrypted": false],
                       to: dir.appendingPathComponent("Manifest.plist"))
        // Locked decision §16: the device does NOT send Info.plist on a full backup and Tether does
        // not synthesize one. `omitInfoPlist` reproduces that device-shaped tree so structural verify
        // can be proven NOT to require Info.plist (checkpoint B run 2: a perfect backup, no Info.plist).
        if !omitInfoPlist {
            try writePlist(["Device Name": "Test", "Product Version": "27.0"],
                           to: dir.appendingPathComponent("Info.plist"))
        }

        try buildManifest(at: dir.appendingPathComponent("Manifest.db"),
                          in: dir, files: files, circularFileIDs: circularFileIDs)
        return root
    }

    /// A synthetic ENCRYPTED backup whose one file's bytes were encrypted by the independent
    /// oracle (`Scripts/wp4-keybag-oracle.py`): the keybag TLV, per-file ciphertext, NSKeyedArchiver
    /// `Files.file` BLOB ({ProtectionClass, EncryptionKey}), and a plaintext `Manifest.db` (the
    /// documented seam — the encrypted-Manifest.db path is the real-fixture / device-checkpoint-C
    /// authority). Returns `(root, udid, password)`; the caller reads via `root/<udid>`.
    static func encryptedBackupWithKnownFile() throws -> (root: URL, udid: String, password: String) {
        try encryptedBackup(encryptManifest: false)
    }

    /// How the encrypted-Manifest.db fixture pads the plaintext before AES-CBC. Real backups vary;
    /// the reader must NOT require valid PKCS7 (task #11 item 2) — SQLite ignores trailing bytes.
    enum ManifestPadding { case pkcs7, zero }

    /// An additional varied-type encrypted file to seed into the fixture (C4): its `plaintext` is
    /// encrypted with a fresh per-file key wrapped under the host-unlockable `protectionClass` key,
    /// so the crypto verifier samples it and exercises the signature check on a non-plist type.
    struct ExtraFile {
        let domain: String
        let relativePath: String
        let protectionClass: UInt32   // must be a host-unlockable passcode class (e.g. 3 or 4)
        let plaintext: Data
    }

    /// Like `encryptedBackupWithKnownFile`, but `Manifest.db` itself is encrypted (AES-CBC zero IV
    /// under the oracle's manifest key) and `Manifest.plist` carries the `ManifestKey` blob — the
    /// shape a real encrypted backup uses. Exercises the ManifestReader decrypt-then-open seam.
    /// `extraFiles` seeds additional varied-type encrypted files (C4 crypto-verify signature checks).
    static func encryptedBackupWithEncryptedManifest(
        padding: ManifestPadding = .pkcs7, walPlaintext: Bool = false, extraFiles: [ExtraFile] = []
    ) throws -> (root: URL, udid: String, password: String) {
        try encryptedBackup(encryptManifest: true, manifestPadding: padding,
                            walPlaintext: walPlaintext, extraFiles: extraFiles)
    }

    private static func encryptedBackup(
        encryptManifest: Bool, manifestPadding: ManifestPadding = .pkcs7, walPlaintext: Bool = false,
        extraFiles: [ExtraFile] = []
    ) throws -> (root: URL, udid: String, password: String) {
        let udid = "U"
        let ef = try Fixtures.encryptedFile()
        let tlv = try Fixtures.knownKeybagTLV()

        let root = URL.temporaryTestDir()
        let dir = root.appendingPathComponent(udid)
        try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)

        try writePlist(["IsFullBackup": true, "SnapshotState": "finished"],
                       to: dir.appendingPathComponent("Status.plist"))
        var manifestPlist: [String: Any] = ["IsEncrypted": true, "BackupKeyBag": tlv]
        if encryptManifest {
            manifestPlist["ManifestKey"] = try Fixtures.encryptedManifest().manifestKeyBlob
        }
        try writePlist(manifestPlist, to: dir.appendingPathComponent("Manifest.plist"))
        try writePlist(["Device Name": "Test", "Product Version": "27.0"],
                       to: dir.appendingPathComponent("Info.plist"))

        // Shard the oracle's ciphertext under <first2hex>/fileID.
        let id = fileID(domain: ef.domain, path: ef.relativePath)
        let shardDir = dir.appendingPathComponent(String(id.prefix(2)))
        try FileManager.default.createDirectory(at: shardDir, withIntermediateDirectories: true)
        try ef.ciphertext.write(to: shardDir.appendingPathComponent(id))

        // Files.file BLOB: a REAL device-shaped MBFile NSKeyedArchiver archive (custom $classname
        // MBFile root + UID-referenced NSData EncryptionKey), not a plain NSDictionary — so the test
        // exercises the class-name-mapped decoder against the exact shape checkpoint C run 3 found
        // (the old ofClasses decoder fails this BLOB; proven by decodesRealMBFileNotPlainDict).
        let fileBlob = try mbFileArchive(protectionClass: ef.protectionClass,
                                         encryptionKeyBlob: ef.encryptionKeyBlob,
                                         relativePath: ef.relativePath)

        // Build the plaintext Manifest.db to a temp path first. `walPlaintext` makes the plaintext
        // db itself WAL-mode (header 02 02) so the decrypted-temp bytes are a WAL db — the reader's
        // immutable open must read it identically to a plaintext WAL Manifest.db (checkpoint B).
        let plaintextDB = dir.appendingPathComponent("Manifest.plaintext.db")
        var db: OpaquePointer?
        guard sqlite3_open(plaintextDB.path, &db) == SQLITE_OK else {
            throw FixtureError.sqlite("open failed")
        }
        if walPlaintext { try exec(db, "PRAGMA journal_mode=WAL") }
        try exec(db, "CREATE TABLE Files(fileID TEXT PRIMARY KEY, domain TEXT, relativePath TEXT, flags INTEGER, file BLOB)")
        try exec(db, "CREATE TABLE Properties(key TEXT PRIMARY KEY, value BLOB)")
        try insertRow(db, fileID: id, domain: ef.domain, path: ef.relativePath, flags: 1, fileBlob: fileBlob)

        // Seed extra varied-type files (C4): each is encrypted with a fresh per-file key wrapped under
        // its host-unlockable class key, sharded, and given a real MBFile row — so crypto verify
        // samples it and exercises the expanded signature check on a non-plist plaintext.
        let classKeys = try Fixtures.knownPasscodeClassKeys()
        for extra in extraFiles {
            guard let classKey = classKeys[extra.protectionClass] else {
                throw FixtureError.sqlite("extra file class \(extra.protectionClass) is not a host-unlockable passcode class")
            }
            let (encKeyBlob, ciphertext) = try encryptExtraFile(plaintext: extra.plaintext,
                                                                classKey: classKey,
                                                                protectionClass: extra.protectionClass)
            let xid = fileID(domain: extra.domain, path: extra.relativePath)
            let xShardDir = dir.appendingPathComponent(String(xid.prefix(2)))
            try FileManager.default.createDirectory(at: xShardDir, withIntermediateDirectories: true)
            try ciphertext.write(to: xShardDir.appendingPathComponent(xid))
            let xBlob = try mbFileArchive(protectionClass: extra.protectionClass,
                                          encryptionKeyBlob: encKeyBlob, relativePath: extra.relativePath)
            try insertRow(db, fileID: xid, domain: extra.domain, path: extra.relativePath, flags: 1, fileBlob: xBlob)
        }

        if walPlaintext { try exec(db, "PRAGMA wal_checkpoint(TRUNCATE)") }
        sqlite3_close(db)
        if walPlaintext {
            // Fold sidecars away so the encrypted bytes are the self-contained WAL main db.
            try? FileManager.default.removeItem(at: dir.appendingPathComponent("Manifest.plaintext.db-wal"))
            try? FileManager.default.removeItem(at: dir.appendingPathComponent("Manifest.plaintext.db-shm"))
        }

        let manifestDB = dir.appendingPathComponent("Manifest.db")
        if encryptManifest {
            // Encrypt the plaintext DB with the oracle's manifest key (AES-CBC zero IV). Padding
            // mode varies to prove the reader does not require valid PKCS7 (task #11 item 2).
            let plaintextBytes = try Data(contentsOf: plaintextDB)
            let key = try Fixtures.encryptedManifest().manifestKey
            try aesCBCEncryptZeroIV(plaintextBytes, key: key, padding: manifestPadding).write(to: manifestDB)
            try FileManager.default.removeItem(at: plaintextDB)
        } else {
            try FileManager.default.moveItem(at: plaintextDB, to: manifestDB)
        }

        return (root, udid, Fixtures.knownPassword)
    }

    /// Encrypts one extra fixture file the way a real backup does (C4): a fresh per-file key is
    /// AES-256-CBC (zero IV, PKCS7) over the plaintext, RFC3394-wrapped under the class key, and
    /// packed into the 44-byte `EncryptionKey` blob (4B big-endian length prefix + 40B wrapped key,
    /// matching the oracle's framing). Returns `(encryptionKeyBlob, ciphertext)`.
    private static func encryptExtraFile(plaintext: Data, classKey: Data,
                                         protectionClass: UInt32) throws -> (Data, Data) {
        // Deterministic per-file key derived from the path-free plaintext hash, so the fixture is
        // stable across runs without needing a CSPRNG.
        let perFileKey = Data(SHA256.hash(data: plaintext + Data([UInt8(protectionClass)])).prefix(32))
        let ciphertext = try aesCBCEncryptZeroIV(plaintext, key: perFileKey, padding: .pkcs7)
        guard let wrapped = rfc3394Wrap(kek: classKey, key: perFileKey) else {
            throw FixtureError.sqlite("rfc3394 wrap failed for extra file")
        }
        var blob = Data()
        blob.append(contentsOf: withUnsafeBytes(of: UInt32(wrapped.count).bigEndian) { Array($0) })
        blob.append(wrapped)                                    // 4B length prefix + 40B = 44B
        return (blob, ciphertext)
    }

    /// RFC 3394 AES key wrap (the inverse of `Keybag.rfc3394Unwrap`), via CommonCrypto. Wraps a
    /// 32-byte per-file key under the 32-byte class KEK to a 40-byte blob.
    private static func rfc3394Wrap(kek: Data, key: Data) -> Data? {
        var wrappedLen = CCSymmetricWrappedSize(CCWrappingAlgorithm(kCCWRAPAES), key.count)
        var wrapped = Data(count: wrappedLen)
        let status = wrapped.withUnsafeMutableBytes { wp in
            kek.withUnsafeBytes { kp in
                key.withUnsafeBytes { kyp in
                    CCSymmetricKeyWrap(
                        CCWrappingAlgorithm(kCCWRAPAES), CCrfc3394_iv, CCrfc3394_ivLen,
                        kp.baseAddress?.assumingMemoryBound(to: UInt8.self), kek.count,
                        kyp.baseAddress?.assumingMemoryBound(to: UInt8.self), key.count,
                        wp.baseAddress?.assumingMemoryBound(to: UInt8.self), &wrappedLen)
                }
            }
        }
        guard status == kCCSuccess else { return nil }
        return wrapped.prefix(wrappedLen)
    }

    /// AES-256-CBC encrypt with a fixed zero IV, for building an encrypted `Manifest.db` fixture
    /// under the oracle's manifest key. `.pkcs7` pads to a block with the pad byte; `.zero` pads to
    /// a block with zero bytes (a non-PKCS7 trailer the reader must still tolerate — SQLite ignores
    /// it). Either way the buffer is block-aligned for CBC.
    private static func aesCBCEncryptZeroIV(_ plaintext: Data, key: Data, padding: ManifestPadding) throws -> Data {
        let blockSize = kCCBlockSizeAES128
        let remainder = plaintext.count % blockSize
        let padLength = remainder == 0 && padding == .zero ? 0 : blockSize - remainder
        let padByte: UInt8 = padding == .pkcs7 ? UInt8(padLength) : 0
        let padded = plaintext + Data(repeating: padByte, count: padLength)
        let iv = Data(count: blockSize)
        var out = Data(count: padded.count + blockSize)
        let outCapacity = out.count
        var moved = 0
        let status = out.withUnsafeMutableBytes { outPtr in
            padded.withUnsafeBytes { ptPtr in
                key.withUnsafeBytes { keyPtr in
                    iv.withUnsafeBytes { ivPtr in
                        CCCrypt(CCOperation(kCCEncrypt), CCAlgorithm(kCCAlgorithmAES), CCOptions(0),
                                keyPtr.baseAddress, key.count, ivPtr.baseAddress,
                                ptPtr.baseAddress, padded.count,
                                outPtr.baseAddress, outCapacity, &moved)
                    }
                }
            }
        }
        guard status == kCCSuccess else { throw FixtureError.sqlite("manifest encrypt failed (\(status))") }
        return out.prefix(moved)
    }

    /// A backup whose single `Files` row carries a `fileID` that is NOT strict 40-char lowercase
    /// hex, so `ManifestReader.shardURL(for:)` throws `malformedFileID`. Exercises the wp3 Q5
    /// binding: the structural verifier must record that throw as a finding, never `try?`-skip it.
    /// Returns the backup *root* (containing `<udid>/`), like `unencryptedBackup`.
    @discardableResult
    static func unencryptedBackupWithMalformedFileID(udid: String) throws -> URL {
        let root = URL.temporaryTestDir()
        let dir = root.appendingPathComponent(udid)
        try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        try writePlist(["IsFullBackup": true, "SnapshotState": "finished"],
                       to: dir.appendingPathComponent("Status.plist"))
        try writePlist(["IsEncrypted": false], to: dir.appendingPathComponent("Manifest.plist"))
        try writePlist(["Device Name": "Test", "Product Version": "27.0"],
                       to: dir.appendingPathComponent("Info.plist"))

        var db: OpaquePointer?
        guard sqlite3_open(dir.appendingPathComponent("Manifest.db").path, &db) == SQLITE_OK else {
            throw FixtureError.sqlite("open failed")
        }
        defer { sqlite3_close(db) }
        try exec(db, "CREATE TABLE Files(fileID TEXT PRIMARY KEY, domain TEXT, relativePath TEXT, flags INTEGER, file BLOB)")
        // "../../etc/passwd" is neither 40 chars nor [0-9a-f] — shardURL must throw on it.
        try insertRow(db, fileID: "../../etc/passwd", domain: "HomeDomain", path: "a.txt", flags: 1)
        return root
    }

    // MARK: - Manifest.db

    private static func buildManifest(
        at manifest: URL, in dir: URL, files: [File], circularFileIDs: Bool
    ) throws {
        var db: OpaquePointer?
        guard sqlite3_open(manifest.path, &db) == SQLITE_OK else {
            throw FixtureError.sqlite("open failed for \(manifest.path)")
        }
        defer { sqlite3_close(db) }
        try exec(db, "CREATE TABLE Files(fileID TEXT PRIMARY KEY, domain TEXT, relativePath TEXT, flags INTEGER, file BLOB)")

        for f in files {
            let id = fileID(domain: f.domain, path: f.path)
            let shard = dir.appendingPathComponent(String(id.prefix(2)))
            try FileManager.default.createDirectory(at: shard, withIntermediateDirectories: true)
            try f.contents.write(to: shard.appendingPathComponent(id))
            try insertRow(db, fileID: id, domain: f.domain, path: f.path, flags: 1)
        }

        // WP2 baton carry-forward (b)/WP1 item 4: a manifest where a fileID's `file`
        // metadata BLOB names its own fileID as a target — a self-referential cycle.
        // A correct flat reader enumerates rows and never follows the BLOB, so it must
        // terminate. We seed the cycle so a future link-following reader can't silently
        // regress into an infinite walk past this guard.
        if circularFileIDs {
            let selfID = fileID(domain: "HomeDomain", path: "Library/loop.bin")
            let blob = Data(selfID.utf8)   // BLOB points back at this same row
            try insertRow(db, fileID: selfID, domain: "HomeDomain",
                          path: "Library/loop.bin", flags: 1, fileBlob: blob)
        }
    }

    /// Builds a backup whose `Manifest.db` enumerates cleanly for the first rows and then
    /// faults mid-scan: many `Files` rows are written (so the table b-tree spans several pages),
    /// then a later page is overwritten with garbage while page 1 (header + root) stays intact.
    /// `sqlite3_step` yields `SQLITE_ROW` for the early rows and `SQLITE_CORRUPT` once the walk
    /// reaches the clobbered page — exactly the "silently truncated enumeration" failure class.
    /// Returns the backup *root* (containing `<udid>/`), like `unencryptedBackup`.
    @discardableResult
    static func backupWithMidScanCorruptManifest(udid: String, rowCount: Int = 4000) throws -> URL {
        let root = URL.temporaryTestDir()
        let dir = root.appendingPathComponent(udid)
        try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)

        let manifest = dir.appendingPathComponent("Manifest.db")
        var db: OpaquePointer?
        guard sqlite3_open(manifest.path, &db) == SQLITE_OK else {
            throw FixtureError.sqlite("open failed for \(manifest.path)")
        }
        try exec(db, "PRAGMA page_size=4096")
        try exec(db, "CREATE TABLE Files(fileID TEXT PRIMARY KEY, domain TEXT, relativePath TEXT, flags INTEGER, file BLOB)")
        try exec(db, "BEGIN")
        for index in 0..<rowCount {
            let path = "Library/file-\(index).bin"
            try insertRow(db, fileID: fileID(domain: "HomeDomain", path: path),
                          domain: "HomeDomain", path: path, flags: 1)
        }
        try exec(db, "COMMIT")
        sqlite3_close(db)

        // Clobber a page well past page 1 so the header and the b-tree root survive (the open
        // and first steps succeed) but the scan hits garbage partway through.
        let pageSize = 4096
        let handle = try FileHandle(forUpdating: manifest)
        defer { try? handle.close() }
        let size = try handle.seekToEnd()
        let corruptPageStart = UInt64(pageSize * 4)   // page 5
        guard size > corruptPageStart + UInt64(pageSize) else {
            throw FixtureError.sqlite("manifest too small to corrupt deterministically (\(size) bytes)")
        }
        try handle.seek(toOffset: corruptPageStart)
        handle.write(Data(repeating: 0xFF, count: pageSize))
        try handle.synchronize()
        return root
    }

    /// Builds a backup whose `Manifest.db` is in WAL journal mode (header bytes 18-19 == 02 02)
    /// with NO `-wal`/`-shm` sidecars — the exact shape a real iOS 27 device delivers (checkpoint B).
    /// A `SQLITE_OPEN_READONLY` open of such a file fails `SQLITE_CANTOPEN(14)` because read-only
    /// cannot create the `-shm` a WAL db needs; only an `immutable=1` URI open reads it.
    ///
    /// `retainWALSidecar` keeps the (empty, post-checkpoint) `-wal` file in place so the reader's
    /// stale-snapshot guard can be exercised: `immutable=1` silently ignores WAL content, so a
    /// present sidecar must surface `manifestUnreadable` rather than read a stale snapshot.
    /// Returns the backup *root* (containing `<udid>/`), like `unencryptedBackup`.
    @discardableResult
    static func walModeBackup(
        udid: String, files: [File], retainWALSidecar: Bool = false
    ) throws -> URL {
        let root = URL.temporaryTestDir()
        let dir = root.appendingPathComponent(udid)
        try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)

        try writePlist(["IsFullBackup": true, "SnapshotState": "finished"],
                       to: dir.appendingPathComponent("Status.plist"))
        try writePlist(["IsEncrypted": false], to: dir.appendingPathComponent("Manifest.plist"))
        try writePlist(["Device Name": "Test", "Product Version": "27.0"],
                       to: dir.appendingPathComponent("Info.plist"))

        let manifest = dir.appendingPathComponent("Manifest.db")
        try buildWALManifest(at: manifest, in: dir, files: files)
        if !retainWALSidecar {
            // Real device delivery checkpoints the WAL into the main db and ships no sidecars.
            try? FileManager.default.removeItem(at: dir.appendingPathComponent("Manifest.db-wal"))
            try? FileManager.default.removeItem(at: dir.appendingPathComponent("Manifest.db-shm"))
        } else {
            // Keep the -wal in place but drop -shm, so the file the guard checks for exists.
            try? FileManager.default.removeItem(at: dir.appendingPathComponent("Manifest.db-shm"))
            if !FileManager.default.fileExists(atPath: dir.appendingPathComponent("Manifest.db-wal").path) {
                FileManager.default.createFile(
                    atPath: dir.appendingPathComponent("Manifest.db-wal").path, contents: Data())
            }
        }
        return root
    }

    /// Writes a WAL-mode SQLite db (and its shard files) at `manifest`, leaving the db file with
    /// header bytes 18-19 == 02 02. `PRAGMA wal_checkpoint(TRUNCATE)` folds committed pages into the
    /// main file so the post-close db is self-contained once the sidecars are removed by the caller.
    static func buildWALManifest(at manifest: URL, in dir: URL, files: [File]) throws {
        var db: OpaquePointer?
        guard sqlite3_open(manifest.path, &db) == SQLITE_OK else {
            throw FixtureError.sqlite("open failed for \(manifest.path)")
        }
        try exec(db, "PRAGMA journal_mode=WAL")
        try exec(db, "CREATE TABLE Files(fileID TEXT PRIMARY KEY, domain TEXT, relativePath TEXT, flags INTEGER, file BLOB)")
        for f in files {
            let id = fileID(domain: f.domain, path: f.path)
            let shard = dir.appendingPathComponent(String(id.prefix(2)))
            try FileManager.default.createDirectory(at: shard, withIntermediateDirectories: true)
            try f.contents.write(to: shard.appendingPathComponent(id))
            try insertRow(db, fileID: id, domain: f.domain, path: f.path, flags: 1)
        }
        try exec(db, "PRAGMA wal_checkpoint(TRUNCATE)")
        sqlite3_close(db)
    }

    private static func insertRow(
        _ db: OpaquePointer?, fileID: String, domain: String, path: String,
        flags: Int32, fileBlob: Data? = nil
    ) throws {
        var stmt: OpaquePointer?
        guard sqlite3_prepare_v2(db, "INSERT INTO Files VALUES (?,?,?,?,?)", -1, &stmt, nil) == SQLITE_OK else {
            throw FixtureError.sqlite("prepare insert failed")
        }
        defer { sqlite3_finalize(stmt) }
        sqlite3_bind_text(stmt, 1, fileID, -1, SQLITE_TRANSIENT)
        sqlite3_bind_text(stmt, 2, domain, -1, SQLITE_TRANSIENT)
        sqlite3_bind_text(stmt, 3, path, -1, SQLITE_TRANSIENT)
        sqlite3_bind_int(stmt, 4, flags)
        if let fileBlob {
            _ = fileBlob.withUnsafeBytes { sqlite3_bind_blob(stmt, 5, $0.baseAddress, Int32(fileBlob.count), SQLITE_TRANSIENT) }
        } else {
            sqlite3_bind_null(stmt, 5)
        }
        guard sqlite3_step(stmt) == SQLITE_DONE else {
            throw FixtureError.sqlite("step insert failed for \(fileID)")
        }
    }

    private static func exec(_ db: OpaquePointer?, _ sql: String) throws {
        guard sqlite3_exec(db, sql, nil, nil, nil) == SQLITE_OK else {
            throw FixtureError.sqlite("exec failed: \(sql)")
        }
    }

    /// A schema-only SQLite database carrying exactly `tables` (each `CREATE TABLE name(id INTEGER)`)
    /// and NO rows, returned as the file's bytes. Used to seed a readability-target key DB (e.g.
    /// `sms.db` with `message`/`chat`) as an `ExtraFile.plaintext`: the readability verifier asserts
    /// table PRESENCE only (`sqlite_master` names), so a schema-only db with zero personal data is the
    /// correct fixture (privacy policy §7 — no PII, no content). Built the same way `buildManifest`
    /// builds `Manifest.db`, then read back so the bytes can be encrypted into a shard.
    static func sqliteBlob(tables: [String]) throws -> Data {
        let tmp = URL.temporaryTestDir().appendingPathComponent("keydb-\(UUID().uuidString).db")
        defer { try? FileManager.default.removeItem(at: tmp.deletingLastPathComponent()) }
        var db: OpaquePointer?
        guard sqlite3_open(tmp.path, &db) == SQLITE_OK else {
            throw FixtureError.sqlite("open failed for \(tmp.path)")
        }
        for name in tables {
            try exec(db, "CREATE TABLE \(name)(id INTEGER)")   // schema only — no INSERT, no PII
        }
        sqlite3_close(db)
        return try Data(contentsOf: tmp)
    }

    // MARK: - SP3 WP1 row-seeded stores (additive)

    /// One seeded message, mirroring the LOCKED §7 join inputs. All fields are FAKE / invented for
    /// the test (evidence rule §9 — no PII, no real rows).
    struct SeededMessage {
        let body: String?
        let dateAppleEpochNanos: Int   // Apple epoch (ns since 2001-01-01), the modern-iOS unit
        let service: String?
        let isFromMe: Bool
        let senderHandle: String?      // handle.id (nil for a self/no-handle row)
        let chatIdentifier: String?    // chat.chat_identifier (nil if no chat join)
    }

    /// One seeded contact, mirroring the LOCKED §8 option-(a) join inputs. FAKE / invented (§9).
    struct SeededContact {
        let first: String?
        let last: String?
        let organization: String?
        let phone: String?   // becomes an ABMultiValue phone row (property 3) when non-nil
        let email: String?   // becomes an ABMultiValue email row (property 4) when non-nil
    }

    /// One seeded call, mirroring the LOCKED §3.3 `ZCALLRECORD` inputs. FAKE / invented (§9). The
    /// Core Data timestamp is SECONDS since 2001-01-01 (a REAL on device) — NOT the nanoseconds
    /// sms.db uses (§3.4). `dateAppleEpochSeconds == nil` seeds a NULL `ZDATE` (the M1 case). A
    /// non-binary `originated` (e.g. 2) seeds the M2 direction-fallback case; `callType == nil` seeds
    /// a NULL `ZCALLTYPE`. All spellings/codes are the B3 fixture binding — B6 device-verifies truth.
    struct SeededCall {
        let address: String?        // ZCALLRECORD.ZADDRESS (nil seeds NULL)
        let dateAppleEpochSeconds: Int?   // ZDATE, seconds since 2001 (nil seeds NULL — M1)
        let duration: Int           // ZDURATION, seconds
        let originated: Int         // ZORIGINATED raw (0 incoming / 1 outgoing; non-binary → M2 fallback)
        let callType: Int?          // ZCALLTYPE raw code (nil seeds NULL)
    }

    /// One seeded note, mirroring the LOCKED §4.4 preview inputs (`ZICCLOUDSYNCINGOBJECT`). FAKE /
    /// invented (§9). Core Data timestamps are SECONDS since 2001 (§3.4); a nil created/modified seeds
    /// a NULL date (the M1 case), a genuine `0` seeds the real 2001 epoch. `folderName` places the note
    /// in a title-bearing folder row via the `ZFOLDER` self-join (nil → unfiled). `locked` seeds a
    /// `ZISPASSWORDPROTECTED = 1` shape so the B6 locked-note snippet-leak check is fixture-representable.
    struct SeededNote {
        let title: String?
        let snippet: String?
        let createdAppleEpochSeconds: Int?    // ZCREATIONDATE1 (nil seeds NULL — M1)
        let modifiedAppleEpochSeconds: Int?   // ZMODIFICATIONDATE1 (nil seeds NULL — M1)
        let folderName: String?               // resolved via the ZFOLDER self-join (nil → no folder)
        let locked: Bool                      // ZISPASSWORDPROTECTED shape (locked-note B6 check)
    }

    /// Builds a synthetic `sms.db` (`message` + `handle` + `chat` + `chat_message_join`, the §7 join
    /// wired) seeded with `messages`, returned as the store's bytes. Schema column spellings match
    /// `BackupRowReader.Schema`. The property codes / units are the WP1 fixture binding (WP4 rebinds
    /// device truth). ALL rows are seeded/fake (§9).
    static func smsStoreBytes(messages: [SeededMessage]) throws -> Data {
        let tmp = URL.temporaryTestDir().appendingPathComponent("sms-\(UUID().uuidString).db")
        defer { try? FileManager.default.removeItem(at: tmp.deletingLastPathComponent()) }
        var db: OpaquePointer?
        guard sqlite3_open(tmp.path, &db) == SQLITE_OK else {
            throw FixtureError.sqlite("open failed for \(tmp.path)")
        }
        defer { sqlite3_close(db) }
        try exec(db, "CREATE TABLE handle(ROWID INTEGER PRIMARY KEY, id TEXT)")
        try exec(db, "CREATE TABLE chat(ROWID INTEGER PRIMARY KEY, chat_identifier TEXT)")
        try exec(db, """
            CREATE TABLE message(ROWID INTEGER PRIMARY KEY, text TEXT, date INTEGER,
                                 service TEXT, is_from_me INTEGER, handle_id INTEGER)
            """)
        try exec(db, "CREATE TABLE chat_message_join(chat_id INTEGER, message_id INTEGER)")

        // De-duplicate handles and chats so the join keys are stable and FK-shaped.
        var handleRowID: [String: Int] = [:]
        var chatRowID: [String: Int] = [:]
        for (index, m) in messages.enumerated() {
            let messageRowID = index + 1
            var handleKey = 0
            if let sender = m.senderHandle {
                if let existing = handleRowID[sender] {
                    handleKey = existing
                } else {
                    handleKey = handleRowID.count + 1
                    handleRowID[sender] = handleKey
                    try execBind(db, "INSERT INTO handle(ROWID, id) VALUES (?, ?)",
                                 ints: [handleKey], texts: [sender],
                                 intColumns: [0], textColumns: [1])
                }
            }
            try execBind(db, """
                INSERT INTO message(ROWID, text, date, service, is_from_me, handle_id)
                VALUES (?, ?, ?, ?, ?, ?)
                """,
                ints: [messageRowID, m.dateAppleEpochNanos, m.isFromMe ? 1 : 0, handleKey],
                texts: [m.body, m.service],
                intColumns: [0, 2, 4, 5], textColumns: [1, 3])

            if let chatID = m.chatIdentifier {
                let chatKey: Int
                if let existing = chatRowID[chatID] {
                    chatKey = existing
                } else {
                    chatKey = chatRowID.count + 1
                    chatRowID[chatID] = chatKey
                    try execBind(db, "INSERT INTO chat(ROWID, chat_identifier) VALUES (?, ?)",
                                 ints: [chatKey], texts: [chatID],
                                 intColumns: [0], textColumns: [1])
                }
                try execBind(db, "INSERT INTO chat_message_join(chat_id, message_id) VALUES (?, ?)",
                             ints: [chatKey, messageRowID])
            }
        }
        sqlite3_close(db); db = nil
        return try Data(contentsOf: tmp)
    }

    /// Builds a synthetic `AddressBook.sqlitedb` (`ABPerson` + `ABMultiValue`, §8 phone/email join)
    /// seeded with `contacts`, returned as bytes. Phone rows use `property = 3`, email rows
    /// `property = 4` (the WP1 fixture binding matching `BackupRowReader.Schema`). FAKE rows (§9).
    static func addressBookStoreBytes(contacts: [SeededContact]) throws -> Data {
        let tmp = URL.temporaryTestDir().appendingPathComponent("ab-\(UUID().uuidString).db")
        defer { try? FileManager.default.removeItem(at: tmp.deletingLastPathComponent()) }
        var db: OpaquePointer?
        guard sqlite3_open(tmp.path, &db) == SQLITE_OK else {
            throw FixtureError.sqlite("open failed for \(tmp.path)")
        }
        defer { sqlite3_close(db) }
        try exec(db, "CREATE TABLE ABPerson(ROWID INTEGER PRIMARY KEY, First TEXT, Last TEXT, Organization TEXT)")
        try exec(db, """
            CREATE TABLE ABMultiValue(ROWID INTEGER PRIMARY KEY, record_id INTEGER,
                                      property INTEGER, value TEXT)
            """)
        var multiRowID = 0
        for (index, c) in contacts.enumerated() {
            let personRowID = index + 1
            try execBind(db, "INSERT INTO ABPerson(ROWID, First, Last, Organization) VALUES (?, ?, ?, ?)",
                         ints: [personRowID], texts: [c.first, c.last, c.organization],
                         intColumns: [0], textColumns: [1, 2, 3])
            if let phone = c.phone {
                multiRowID += 1
                try execBind(db, "INSERT INTO ABMultiValue(ROWID, record_id, property, value) VALUES (?, ?, ?, ?)",
                             ints: [multiRowID, personRowID, 3], texts: [phone],
                             intColumns: [0, 1, 2], textColumns: [3])
            }
            if let email = c.email {
                multiRowID += 1
                try execBind(db, "INSERT INTO ABMultiValue(ROWID, record_id, property, value) VALUES (?, ?, ?, ?)",
                             ints: [multiRowID, personRowID, 4], texts: [email],
                             intColumns: [0, 1, 2], textColumns: [3])
            }
        }
        sqlite3_close(db); db = nil
        return try Data(contentsOf: tmp)
    }

    /// Builds a synthetic Core Data `CallHistory.storedata` (`ZCALLRECORD`, the §3.3 shape) seeded
    /// with `calls`, returned as the store's bytes. Column spellings match `BackupRowReader.Schema`
    /// (device-verify B6 rebinds truth). `ZDATE`/`ZDURATION` are stored as Core Data REAL (seconds
    /// since 2001) so the reader's `CAST(... AS INTEGER)` + seconds normalizer is exercised on the
    /// real storage class. ALL rows are seeded/fake (§9).
    static func callHistoryStoreBytes(calls: [SeededCall]) throws -> Data {
        let tmp = URL.temporaryTestDir().appendingPathComponent("calls-\(UUID().uuidString).storedata")
        defer { try? FileManager.default.removeItem(at: tmp.deletingLastPathComponent()) }
        var db: OpaquePointer?
        guard sqlite3_open(tmp.path, &db) == SQLITE_OK else {
            throw FixtureError.sqlite("open failed for \(tmp.path)")
        }
        defer { sqlite3_close(db) }
        // ZDATE/ZDURATION are REAL (Core Data NSDate/duration storage class), ZORIGINATED/ZCALLTYPE
        // INTEGER, ZADDRESS TEXT — the shape B3 reads and B6 confirms.
        try exec(db, """
            CREATE TABLE ZCALLRECORD(Z_PK INTEGER PRIMARY KEY, ZADDRESS TEXT,
                                     ZDATE REAL, ZDURATION REAL, ZORIGINATED INTEGER, ZCALLTYPE INTEGER)
            """)
        for (index, c) in calls.enumerated() {
            try insertCall(db, pk: index + 1, address: c.address, dateSeconds: c.dateAppleEpochSeconds,
                           duration: c.duration, originated: c.originated, callType: c.callType)
        }
        sqlite3_close(db); db = nil
        return try Data(contentsOf: tmp)
    }

    /// Inserts one `ZCALLRECORD` row with per-column NULL handling: a nil `address`/`dateSeconds`/
    /// `callType` binds SQL NULL (the M1 NULL-`ZDATE` and NULL-`ZCALLTYPE` cases), `dateSeconds`/
    /// `duration` bind as REAL doubles (Core Data storage class).
    private static func insertCall(
        _ db: OpaquePointer?, pk: Int, address: String?, dateSeconds: Int?,
        duration: Int, originated: Int, callType: Int?
    ) throws {
        var stmt: OpaquePointer?
        guard sqlite3_prepare_v2(db, "INSERT INTO ZCALLRECORD VALUES (?,?,?,?,?,?)", -1, &stmt, nil) == SQLITE_OK else {
            throw FixtureError.sqlite("prepare call insert failed")
        }
        defer { sqlite3_finalize(stmt) }
        sqlite3_bind_int64(stmt, 1, Int64(pk))
        if let address { sqlite3_bind_text(stmt, 2, address, -1, SQLITE_TRANSIENT) } else { sqlite3_bind_null(stmt, 2) }
        if let dateSeconds { sqlite3_bind_double(stmt, 3, Double(dateSeconds)) } else { sqlite3_bind_null(stmt, 3) }
        sqlite3_bind_double(stmt, 4, Double(duration))
        sqlite3_bind_int64(stmt, 5, Int64(originated))
        if let callType { sqlite3_bind_int64(stmt, 6, Int64(callType)) } else { sqlite3_bind_null(stmt, 6) }
        guard sqlite3_step(stmt) == SQLITE_DONE else {
            throw FixtureError.sqlite("step call insert failed for pk \(pk)")
        }
    }

    /// Fixture-local `Z_ENT` codes for the polymorphic `ZICCLOUDSYNCINGOBJECT` rows, MIRRORING the
    /// iOS-27 device layout so the reader must resolve ICNote's code BY NAME from `Z_PRIMARYKEY`
    /// (M1) rather than hardcode an integer: on device ICNote=12 (the real notes) and ICMedia=11 (the
    /// code a hardcoded reader USED to match — NULL-title decoys). Folder/account rows carry titles, so
    /// the discriminator MUST be the entity (Odb H1), NOT `ZTITLE1 IS NOT NULL`.
    static let icNoteEntityCode = 12     // ICNote — the real notes (device: 12, deliberately ≠ 11)
    static let icMediaEntityCode = 11    // ICMedia — NULL-title decoy at the OLD hardcoded code
    static let icFolderEntityCode = 15   // ICFolder — a title-bearing folder (K4 self-join target)
    static let icAccountEntityCode = 14  // ICAccount — a title-bearing account (H1 exclusion target)

    /// Builds a synthetic Core Data `NoteStore.sqlite` (`ZICCLOUDSYNCINGOBJECT` + the `Z_PRIMARYKEY`
    /// entity catalog, the §4.4 shape) seeded with `notes`, returned as the store's bytes. It seeds a
    /// `Z_PRIMARYKEY` mapping (ICNote=12, ICMedia=11, ICFolder=15, ICAccount=14 — the iOS-27 device
    /// layout) so the reader must resolve ICNote's `Z_ENT` BY NAME (M1), NOT by a hardcoded integer.
    /// Per Odb H1 it ALSO seeds **title-bearing FOLDER and ACCOUNT rows** and a **NULL-title MEDIA decoy
    /// at Z_ENT 11** (the code a hardcoded reader matched) so the entity discriminator — NOT
    /// title-nullness — does the filtering; the K4 folder self-join resolves a note's folder NAME from
    /// its folder row's `ZTITLE1`. Dates are stored as REAL seconds so the CAST+seconds normalizer is
    /// exercised on the real Core Data storage class. A `ZICNOTEDATA` body table is seeded schema-only
    /// (NOT read in the alpha — body deferred to SP3.2). ALL rows are seeded/fake (§9).
    static func noteStoreBytes(notes: [SeededNote]) throws -> Data {
        let tmp = URL.temporaryTestDir().appendingPathComponent("notes-\(UUID().uuidString).sqlite")
        defer { try? FileManager.default.removeItem(at: tmp.deletingLastPathComponent()) }
        var db: OpaquePointer?
        guard sqlite3_open(tmp.path, &db) == SQLITE_OK else {
            throw FixtureError.sqlite("open failed for \(tmp.path)")
        }
        defer { sqlite3_close(db) }
        try exec(db, """
            CREATE TABLE ZICCLOUDSYNCINGOBJECT(Z_PK INTEGER PRIMARY KEY, Z_ENT INTEGER,
                ZTITLE1 TEXT, ZSNIPPET TEXT, ZCREATIONDATE1 REAL, ZMODIFICATIONDATE1 REAL,
                ZFOLDER INTEGER, ZISPASSWORDPROTECTED INTEGER)
            """)
        // Body table — the real two-table shape — seeded schema-only; the alpha never reads it.
        try exec(db, "CREATE TABLE ZICNOTEDATA(Z_PK INTEGER PRIMARY KEY, ZNOTE INTEGER, ZDATA BLOB)")
        // The Core Data entity catalog. The reader resolves ICNote's Z_ENT BY NAME from here (M1), so
        // the mapping mirrors the iOS-27 device (ICNote=12, ICMedia=11, …) — deliberately NOT 11.
        try exec(db, "CREATE TABLE Z_PRIMARYKEY(Z_ENT INTEGER PRIMARY KEY, Z_NAME TEXT, Z_SUPER INTEGER, Z_MAX INTEGER)")
        for (name, ent) in [("ICNote", icNoteEntityCode), ("ICMedia", icMediaEntityCode),
                            ("ICFolder", icFolderEntityCode), ("ICAccount", icAccountEntityCode)] {
            try execBind(db, "INSERT INTO Z_PRIMARYKEY(Z_ENT, Z_NAME, Z_SUPER, Z_MAX) VALUES (?, ?, ?, ?)",
                         ints: [ent, 0, 0], texts: [name], intColumns: [0, 2, 3], textColumns: [1])
        }

        var pk = 0

        // 1) A title-bearing FOLDER row per distinct folder name (H1) — the K4 self-join target.
        var folderPK: [String: Int] = [:]
        for name in notes.compactMap(\.folderName) where folderPK[name] == nil {
            pk += 1
            folderPK[name] = pk
            try insertSyncingObject(db, pk: pk, ent: icFolderEntityCode, title: name, snippet: nil,
                                    createdSeconds: nil, modifiedSeconds: nil, folderPK: nil, locked: false)
        }
        // 2) A title-bearing ACCOUNT row (H1) — MUST be excluded by the discriminator despite a title.
        pk += 1
        try insertSyncingObject(db, pk: pk, ent: icAccountEntityCode, title: "Fixture iCloud",
                                snippet: nil, createdSeconds: nil, modifiedSeconds: nil,
                                folderPK: nil, locked: false)
        // 3) A NULL-title MEDIA decoy at Z_ENT 11 (the OLD hardcoded code). A by-name reader excludes it;
        //    a reader hardcoding 11 returns THIS and drops every real note — the device-dead bug (M1).
        pk += 1
        try insertSyncingObject(db, pk: pk, ent: icMediaEntityCode, title: nil, snippet: nil,
                                createdSeconds: nil, modifiedSeconds: nil, folderPK: nil, locked: false)
        // 4) The NOTE rows themselves (Z_ENT = ICNote), each linked to its folder row (if any).
        for n in notes {
            pk += 1
            try insertSyncingObject(db, pk: pk, ent: icNoteEntityCode, title: n.title, snippet: n.snippet,
                                    createdSeconds: n.createdAppleEpochSeconds,
                                    modifiedSeconds: n.modifiedAppleEpochSeconds,
                                    folderPK: n.folderName.flatMap { folderPK[$0] }, locked: n.locked)
        }
        sqlite3_close(db); db = nil
        return try Data(contentsOf: tmp)
    }

    /// Inserts one `ZICCLOUDSYNCINGOBJECT` row with per-column NULL handling: nil title/snippet →
    /// NULL; nil created/modified → NULL (the M1 date case); dates bind as REAL doubles; nil folderPK
    /// → NULL `ZFOLDER` (an unfiled note); `locked` sets `ZISPASSWORDPROTECTED`.
    private static func insertSyncingObject(
        _ db: OpaquePointer?, pk: Int, ent: Int, title: String?, snippet: String?,
        createdSeconds: Int?, modifiedSeconds: Int?, folderPK: Int?, locked: Bool
    ) throws {
        var stmt: OpaquePointer?
        guard sqlite3_prepare_v2(db, "INSERT INTO ZICCLOUDSYNCINGOBJECT VALUES (?,?,?,?,?,?,?,?)", -1, &stmt, nil) == SQLITE_OK else {
            throw FixtureError.sqlite("prepare note insert failed")
        }
        defer { sqlite3_finalize(stmt) }
        sqlite3_bind_int64(stmt, 1, Int64(pk))
        sqlite3_bind_int64(stmt, 2, Int64(ent))
        if let title { sqlite3_bind_text(stmt, 3, title, -1, SQLITE_TRANSIENT) } else { sqlite3_bind_null(stmt, 3) }
        if let snippet { sqlite3_bind_text(stmt, 4, snippet, -1, SQLITE_TRANSIENT) } else { sqlite3_bind_null(stmt, 4) }
        if let createdSeconds { sqlite3_bind_double(stmt, 5, Double(createdSeconds)) } else { sqlite3_bind_null(stmt, 5) }
        if let modifiedSeconds { sqlite3_bind_double(stmt, 6, Double(modifiedSeconds)) } else { sqlite3_bind_null(stmt, 6) }
        if let folderPK { sqlite3_bind_int64(stmt, 7, Int64(folderPK)) } else { sqlite3_bind_null(stmt, 7) }
        sqlite3_bind_int64(stmt, 8, locked ? 1 : 0)
        guard sqlite3_step(stmt) == SQLITE_DONE else {
            throw FixtureError.sqlite("step note insert failed for pk \(pk)")
        }
    }

    /// A small additive bind helper for the SP3 row-seeded stores: positional `?` parameters whose
    /// column types are given by `intColumns` / `textColumns` (1-based positions). When all binds are
    /// ints OR all texts, the column-type arrays may be omitted (inferred from the single array used).
    private static func execBind(
        _ db: OpaquePointer?, _ sql: String,
        ints: [Int] = [], texts: [String?] = [],
        intColumns: [Int]? = nil, textColumns: [Int]? = nil
    ) throws {
        var stmt: OpaquePointer?
        guard sqlite3_prepare_v2(db, sql, -1, &stmt, nil) == SQLITE_OK else {
            throw FixtureError.sqlite("prepare failed: \(sql)")
        }
        defer { sqlite3_finalize(stmt) }
        let intPos = intColumns ?? Array(0..<ints.count)
        let textPos = textColumns ?? Array(0..<texts.count)
        for (i, pos) in intPos.enumerated() {
            sqlite3_bind_int64(stmt, Int32(pos + 1), Int64(ints[i]))
        }
        for (i, pos) in textPos.enumerated() {
            if let value = texts[i] {
                sqlite3_bind_text(stmt, Int32(pos + 1), value, -1, SQLITE_TRANSIENT)
            } else {
                sqlite3_bind_null(stmt, Int32(pos + 1))
            }
        }
        guard sqlite3_step(stmt) == SQLITE_DONE else {
            throw FixtureError.sqlite("step failed: \(sql)")
        }
    }

    /// Shards `storeBytes` into an UNENCRYPTED backup at `(domain, path)` and returns the backup root
    /// (containing `<udid>/`), like `unencryptedBackup`. A convenience wrapper for the SP3 stores.
    @discardableResult
    static func unencryptedBackupWithStore(
        udid: String, domain: String, path: String, storeBytes: Data
    ) throws -> URL {
        try unencryptedBackup(udid: udid, files: [.init(domain: domain, path: path, contents: storeBytes)])
    }

    /// Shards `storeBytes` into an ENCRYPTED backup (encrypted `Manifest.db`) as an `ExtraFile` at
    /// `(domain, path)`, so the row reader exercises the decrypt seam for an encrypted store. Returns
    /// `(root, udid, password)`; the caller reads via `root/<udid>`. Protection class 3 is
    /// host-unlockable from the known password (Fixtures.knownPasscodeClassKeys).
    static func encryptedBackupWithStore(
        domain: String, path: String, storeBytes: Data
    ) throws -> (root: URL, udid: String, password: String) {
        try encryptedBackupWithEncryptedManifest(
            extraFiles: [.init(domain: domain, relativePath: path,
                               protectionClass: 3, plaintext: storeBytes)])
    }

    // MARK: - plists

    private static func writePlist(_ value: [String: Any], to url: URL) throws {
        let data = try PropertyListSerialization.data(fromPropertyList: value, format: .xml, options: 0)
        try data.write(to: url)
    }

    /// Builds a REAL `MBFile`-shaped `NSKeyedArchiver` `Files.file` BLOB — the exact archive a device
    /// emits (checkpoint C run 3, lead-decoded from backup-1), NOT a plain `NSDictionary`.
    ///
    /// Archiving an actual `@objc(MBFile)` `NSCoding` object produces the authentic structure: an
    /// `$objects[1]` root whose `$classname` is `MBFile`, with `ProtectionClass`/`Flags` direct and
    /// `EncryptionKey` a UID -> a separate `NSData` carrying the 44-byte 4B-LE-prefix + 40B-wrapped
    /// key. This is what makes the decoder test non-vacuous: the OLD
    /// `NSKeyedUnarchiver.unarchivedObject(ofClasses:[NSDictionary,...])` THROWS on this BLOB because
    /// `MBFile` is not in the allow-list — only the class-name-mapped decoder reads it.
    static func mbFileArchive(protectionClass: UInt32, encryptionKeyBlob: Data,
                              relativePath: String) throws -> Data {
        let object = MBFileFixture(protectionClass: protectionClass,
                                   encryptionKey: encryptionKeyBlob, relativePath: relativePath)
        return try NSKeyedArchiver.archivedData(withRootObject: object, requiringSecureCoding: false)
    }

    /// A `Files.file` BLOB whose archived root is a class OTHER than `MBFile` — used to prove the
    /// secure decoder (Odb C3b-Sec) does NOT instantiate an arbitrary root: `setClass` only redirects
    /// the `"MBFile"` name, so a different root class is refused under secure coding rather than read.
    static func nonMBFileArchive() throws -> Data {
        try NSKeyedArchiver.archivedData(withRootObject: GadgetFixture(), requiringSecureCoding: false)
    }

    enum FixtureError: Error { case sqlite(String) }
}

/// A device-shaped `MBFile` record, used only to emit a realistic per-file `Files.file` archive.
/// The `@objc(MBFile)` name makes the archive's `$classname` exactly `MBFile`, so a fixture built
/// from it reproduces the real backup's custom-class BLOB that the generic decoder must handle.
@objc(MBFile) private final class MBFileFixture: NSObject, NSCoding {
    let protectionClass: UInt32
    let encryptionKey: Data
    let relativePath: String

    init(protectionClass: UInt32, encryptionKey: Data, relativePath: String) {
        self.protectionClass = protectionClass
        self.encryptionKey = encryptionKey
        self.relativePath = relativePath
    }

    func encode(with coder: NSCoder) {
        coder.encode(Int(protectionClass), forKey: "ProtectionClass")
        coder.encode(4, forKey: "Flags")
        coder.encode(encryptionKey as NSData, forKey: "EncryptionKey")
        coder.encode(relativePath as NSString, forKey: "RelativePath")
        coder.encode(12, forKey: "Size")
    }

    required init?(coder: NSCoder) { return nil }   // emit-only; never decoded by the fixture
}

/// A stand-in for an UNEXPECTED root class — a BLOB archived from this (`$classname = TetherGadget`,
/// not `MBFile`) lets the C3b-Sec test prove the secure decoder refuses to instantiate an arbitrary
/// root: `setClass` redirects only the `"MBFile"` name, so this root is rejected under secure coding.
@objc(TetherGadget) private final class GadgetFixture: NSObject, NSCoding {
    override init() {}
    func encode(with coder: NSCoder) { coder.encode(1, forKey: "x") }
    required init?(coder: NSCoder) { return nil }
}
