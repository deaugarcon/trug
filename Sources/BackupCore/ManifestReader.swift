import Foundation

/// Read-only access to one backup's `Manifest.db` and metadata plists.
/// Operates on the `<udid>` directory inside a backup generation.
public final class ManifestReader {
    private let backupDir: URL
    private let db: SQLiteDB
    /// A decrypted copy of an encrypted `Manifest.db`, removed on deinit; nil for plaintext manifests.
    private let decryptedManifest: URL?

    /// Opens a plaintext `Manifest.db`. Use `init(backupDir:unlockedKeybag:)` for an encrypted backup.
    public init(backupDir: URL) throws {
        self.backupDir = backupDir
        self.db = try SQLiteDB(path: backupDir.appendingPathComponent("Manifest.db").path)
        self.decryptedManifest = nil
    }

    /// Opens a backup's manifest, transparently decrypting `Manifest.db` when the backup is
    /// encrypted (real encrypted backups encrypt the manifest container itself, not just the
    /// per-file data — plan Task 11 Step 6 item 2).
    ///
    /// The seam: read `Manifest.plist`; if `IsEncrypted` and a `ManifestKey` blob is present,
    /// unwrap the manifest key with the supplied unlocked keybag and AES-CBC (zero IV) decrypt
    /// `Manifest.db` to a `0600` temp file that is opened read-only and deleted on deinit. A
    /// plaintext manifest (no `ManifestKey`) is opened in place, identically to `init(backupDir:)`.
    public init(backupDir: URL, unlockedKeybag: UnlockedKeybag) throws {
        self.backupDir = backupDir
        let manifestPlist = Self.plist(in: backupDir, named: "Manifest.plist")
        let isEncrypted = (manifestPlist["IsEncrypted"] as? Bool) ?? false
        if isEncrypted, let manifestKeyBlob = manifestPlist["ManifestKey"] as? Data {
            let temp = try Self.decryptManifest(in: backupDir, manifestKeyBlob: manifestKeyBlob,
                                                keybag: unlockedKeybag)
            self.decryptedManifest = temp
            self.db = try SQLiteDB(path: temp.path)
        } else {
            self.decryptedManifest = nil
            self.db = try SQLiteDB(path: backupDir.appendingPathComponent("Manifest.db").path)
        }
    }

    deinit {
        if let decryptedManifest { try? FileManager.default.removeItem(at: decryptedManifest) }
    }

    /// Opens a backup's manifest, decrypting it when the backup is encrypted — the single seam for
    /// every read command (browse) so an encrypted `Manifest.db` is never read as plaintext SQLite.
    ///
    /// Encryption is detected from `Manifest.plist` (`IsEncrypted` true AND a `ManifestKey` blob is
    /// present), read as a plist, never by probing the ciphertext as SQLite. A plaintext backup opens
    /// in place (behaviorally identical to `init(backupDir:)`). An encrypted backup with a non-empty
    /// password unlocks the keybag (a wrong password throws `KeybagError.wrongPassword`) and opens via
    /// the keybag-aware path; an encrypted backup with no usable password throws
    /// `VerifyError.passwordRequired(udid:)` — NEVER the not-a-database / re-create lie that browsing
    /// an encrypted backup hit before (checkpoint C run 3).
    /// `password` is `@autoclosure`: it is pulled ONLY when the backup is proven encrypted (Task 14
    /// part D / U_god). `PasswordInput.read()` now prompts interactively, so reading it for a
    /// plaintext browse would hang on a password the backup doesn't need; the encryption check at the
    /// guard above runs first and a plaintext backup returns without ever evaluating the closure.
    public static func open(backupDir: URL, udid: String,
                            password: @autoclosure () -> String?) throws -> ManifestReader {
        guard isEncrypted(backupDir: backupDir) else {
            return try ManifestReader(backupDir: backupDir)
        }
        guard let pw = password(), !pw.isEmpty else {
            throw VerifyError.passwordRequired(udid: udid)
        }
        let keybag = try Keybag(tlv: try backupKeybagTLV(in: backupDir)).unlock(password: pw)
        return try ManifestReader(backupDir: backupDir, unlockedKeybag: keybag)
    }

    /// True when `Manifest.plist` marks the backup encrypted AND carries the `ManifestKey` blob an
    /// encrypted `Manifest.db` needs. Reads the plaintext plist only — never touches `Manifest.db`.
    public static func isEncrypted(backupDir: URL) -> Bool {
        let manifest = plist(in: backupDir, named: "Manifest.plist")
        return ((manifest["IsEncrypted"] as? Bool) ?? false) && manifest["ManifestKey"] is Data
    }

    /// Every `Files` row in the given domain.
    public func files(inDomain domain: String) throws -> [FileRecord] {
        var out: [FileRecord] = []
        try db.query("SELECT fileID, domain, relativePath, flags FROM Files WHERE domain = ?",
                     bind: [domain]) { row in
            out.append(record(from: row))
        }
        return out
    }

    /// Every `Files` row in the manifest.
    public func allFiles() throws -> [FileRecord] {
        var out: [FileRecord] = []
        try db.query("SELECT fileID, domain, relativePath, flags FROM Files") { row in
            out.append(record(from: row))
        }
        return out
    }

    /// The row for an exact (domain, relativePath), or nil if absent.
    public func record(domain: String, path: String) throws -> FileRecord? {
        var found: FileRecord?
        try db.query("SELECT fileID, domain, relativePath, flags FROM Files WHERE domain = ? AND relativePath = ?",
                     bind: [domain, path]) { row in
            found = record(from: row)
        }
        return found
    }

    /// Like `record(domain:path:)` but also decodes the `Files.file` metadata BLOB to surface the
    /// per-file wrapped key and protection class, for decrypting an encrypted backup. Returns nil
    /// if the row is absent; throws `manifestUnreadable` if the BLOB is present but undecodable.
    ///
    /// The BLOB is an `NSKeyedArchiver` archive (`$objects`/`$top` indirection — wp4.design.odb.md
    /// A5), so it is decoded with `NSKeyedUnarchiver`, not a flat plist lookup. A row whose archive
    /// carries no `EncryptionKey` (an unencrypted file, a directory, or a symlink) decodes to a
    /// record with a nil key/class — the verifier skips it rather than treating it as a defect.
    public func recordWithKey(domain: String, path: String) throws -> FileRecord? {
        var base: FileRecord?
        var blob: Data?
        try db.query("SELECT fileID, domain, relativePath, flags, file FROM Files WHERE domain = ? AND relativePath = ?",
                     bind: [domain, path]) { row in
            base = record(from: row)
            blob = row.blob(4)
        }
        guard let base else { return nil }
        guard let blob else { return base }
        let (protectionClass, encryptionKey) = try Self.decodeFileMetadata(blob)
        return FileRecord(fileID: base.fileID, domain: base.domain, relativePath: base.relativePath,
                          flags: base.flags, encryptionKeyBlob: encryptionKey, protectionClass: protectionClass)
    }

    /// The backup keybag TLV from `Manifest.plist`'s `BackupKeyBag`, for `Keybag(tlv:)`.
    public func backupKeybagTLV() throws -> Data {
        try Self.backupKeybagTLV(in: backupDir)
    }

    /// Reads the keybag TLV straight from a backup directory's `Manifest.plist`, without an open
    /// `Manifest.db` — needed to unlock the keybag *before* an encrypted manifest can be decrypted.
    public static func backupKeybagTLV(in backupDir: URL) throws -> Data {
        guard let tlv = plist(in: backupDir, named: "Manifest.plist")["BackupKeyBag"] as? Data else {
            throw VerifyError.manifestUnreadable(reason: "Manifest.plist has no BackupKeyBag (is the backup encrypted?)")
        }
        return tlv
    }

    /// Backup-level metadata drawn from the Manifest/Status/Info plists.
    public func metadata() throws -> BackupMetadata {
        Self.metadata(in: backupDir)
    }

    /// Backup-level metadata read straight from a backup directory's PLAINTEXT plists, with no open
    /// `Manifest.db` — so `list` can describe an ENCRYPTED backup (whose `Manifest.db` is ciphertext)
    /// WITHOUT a password. `Manifest.plist` (IsEncrypted), `Status.plist`, and `Info.plist` are all
    /// plaintext on a real encrypted backup; only `Manifest.db` is encrypted. Using the keybag-less
    /// `ManifestReader(backupDir:)` here fails on an encrypted backup (its db open throws) and blanks
    /// every field — checkpoint C run 3 showed encrypted backups listing blank iOS/NAME for exactly
    /// that reason. `list` stays password-free; only browse/verify/extract need the key.
    public static func metadata(in backupDir: URL) -> BackupMetadata {
        let manifest = plist(in: backupDir, named: "Manifest.plist")
        let status = plist(in: backupDir, named: "Status.plist")
        let info = plist(in: backupDir, named: "Info.plist")
        return BackupMetadata(
            isEncrypted: (manifest["IsEncrypted"] as? Bool) ?? false,
            isFullBackup: (status["IsFullBackup"] as? Bool) ?? false,
            deviceName: (info["Device Name"] as? String) ?? "",
            productVersion: (info["Product Version"] as? String) ?? "")
    }

    /// On-disk shard path for a record: `<first 2 hex chars of fileID>/<fileID>`.
    ///
    /// Throws `VerifyError.malformedFileID` unless `fileID` is a strict 40-char lowercase SHA1
    /// hex string — it never falls through to a path join. The `fileID` is read verbatim from a
    /// device-written `Manifest.db`; a crafted value like `"../.."`, an absolute path, or one
    /// containing `/` would otherwise steer this join out of `backupDir` (the read-side twin of
    /// the write-side `MB2PathGuard`). A `[0-9a-f]{40}` value cannot contain `/`, `.`, or NUL by
    /// construction, so the charset+length gate confines the path AND rejects corrupt rows.
    /// Uppercase hex is rejected, not normalized: real iOS fileIDs are lowercase, and a
    /// case-fold would silently launder a corrupt or tampered manifest.
    public func shardURL(for record: FileRecord) throws -> URL {
        guard Self.isValidFileID(record.fileID) else {
            throw VerifyError.malformedFileID(record.fileID)
        }
        return backupDir.appendingPathComponent(String(record.fileID.prefix(2)))
            .appendingPathComponent(record.fileID)
    }

    /// A real iOS backup `fileID` is the lowercase hex of a SHA1 digest: exactly 40 of `[0-9a-f]`.
    static func isValidFileID(_ fileID: String) -> Bool {
        let bytes = fileID.utf8
        guard bytes.count == 40 else { return false }
        return bytes.allSatisfy { (48...57).contains($0) || (97...102).contains($0) }
    }

    // MARK: - internals

    private func record(from row: SQLiteDB.Row) -> FileRecord {
        FileRecord(fileID: row.text(0) ?? "", domain: row.text(1) ?? "",
                   relativePath: row.text(2) ?? "", flags: row.int(3), encryptionKeyBlob: nil)
    }

    /// Decodes a real device `Files.file` BLOB into `(protectionClass?, encryptionKey?)`.
    ///
    /// Checkpoint C run 3 (lead-decoded from backup-1): the BLOB is an `NSKeyedArchiver` bplist whose
    /// root object (`$objects[1]`) is a CUSTOM `MBFile` class — `$classname = MBFile`, with direct
    /// keys `ProtectionClass` (Int), `Flags`, and `EncryptionKey` (a UID -> a separate `NSData`
    /// object whose 44 bytes are the 4B-LE-prefix + 40B-wrapped key, IDENTICAL framing to ManifestKey).
    /// The OLD `unarchivedObject(ofClasses:[NSDictionary,...])` decoder THREW on every real file
    /// because `MBFile` is not in any allow-list — so crypto verify sampled 0 files.
    ///
    /// The fix decodes WITHOUT a registered `MBFile` type: a generic reader class is mapped to the
    /// `"MBFile"` archive class name via `setClass(_:forClassName:)`, so `NSKeyedUnarchiver` resolves
    /// all `$top`/`$objects` UID indirection natively (including the `EncryptionKey` -> `NSData`
    /// reference) and hands back the keyed fields, with no dependency on a concrete `MBFile` class.
    /// A row carrying no `EncryptionKey` (an unencrypted file / directory / symlink) returns nils so
    /// the verifier skips it; a structurally undecodable archive throws `manifestUnreadable`.
    ///
    /// SECURE CODING ON (Odb C3b-Sec): the BLOB is untrusted hostile-device data, so the unarchiver
    /// keeps `requiresSecureCoding` (the default for the secure-coding API) and the root is decoded
    /// class-constrained via `decodeObject(of: MBFileMetadata.self, ...)`. `setClass` only redirects
    /// the `"MBFile"` name to our reader — it does NOT relax secure coding, so the unarchiver still
    /// refuses to instantiate any other arbitrary `NSCoding` class named in `$objects`.
    ///
    /// `internal` (not `private`) so the C3b-Sec test can assert the secure-decode behavior directly.
    static func decodeFileMetadata(_ blob: Data) throws -> (UInt32?, Data?) {
        let unarchiver: NSKeyedUnarchiver
        do {
            unarchiver = try NSKeyedUnarchiver(forReadingFrom: blob)
        } catch {
            throw VerifyError.manifestUnreadable(reason: "file metadata BLOB is not a decodable archive: \(error.localizedDescription)")
        }
        // Map the device's custom MBFile root to our secure reader. Secure coding stays ON.
        unarchiver.setClass(MBFileMetadata.self, forClassName: "MBFile")
        let metadata: MBFileMetadata
        do {
            guard let decoded = try unarchiver.decodeTopLevelObject(of: MBFileMetadata.self,
                                                                    forKey: NSKeyedArchiveRootObjectKey) else {
                throw VerifyError.manifestUnreadable(reason: "file metadata BLOB root is not a readable MBFile record")
            }
            metadata = decoded
        } catch let error as VerifyError {
            throw error
        } catch {
            throw VerifyError.manifestUnreadable(reason: "file metadata BLOB failed secure decode: \(error.localizedDescription)")
        }
        // A directory/symlink/unencrypted row legitimately has no EncryptionKey — return nils, not an
        // error: the verifier and decryptor both skip a keyless record (R3 / spec §4.2).
        guard let key = metadata.encryptionKey, let clas = metadata.protectionClass else {
            return (nil, nil)
        }
        return (clas, key)
    }

    private func plist(at name: String) -> [String: Any] {
        Self.plist(in: backupDir, named: name)
    }

    private static func plist(in backupDir: URL, named name: String) -> [String: Any] {
        guard let data = try? Data(contentsOf: backupDir.appendingPathComponent(name)),
              let object = try? PropertyListSerialization.propertyList(from: data, options: [], format: nil),
              let dict = object as? [String: Any]
        else { return [:] }
        return dict
    }

    /// Decrypts an encrypted `Manifest.db` to a fresh `0600` temp file and returns its URL.
    ///
    /// `ManifestKey` is a 4-byte protection-class prefix followed by the RFC 3394-wrapped manifest
    /// key (the same blob shape as a per-file `EncryptionKey`). Two wire-shape details, pinned by
    /// the Odb ManifestKey spot-check (task #11):
    ///  - the class prefix is **little-endian** (iOSbackup `<l`, dunhamsteve `LittleEndian.Uint32`)
    ///    — the OPPOSITE of the keybag TLV's big-endian integers; a BE read of class 4 yields
    ///    67108864 and selects no key on a real backup;
    ///  - the AES-256-CBC (zero IV) decrypt is **NOT** PKCS7-stripped or size-truncated. References
    ///    disagree benignly on trailing bytes, and a strict PKCS7 check causes false failures on
    ///    real backups (MVT issues #93/#571). The full decrypted buffer is written verbatim; SQLite
    ///    reads by page count from its header and ignores trailing padding. Success is proven by the
    ///    subsequent SQLite open + `Files` read, not by padding validity.
    ///
    /// Throws `manifestUnreadable` only on a structurally malformed `ManifestKey` or a failed key
    /// unwrap (wrong password / corrupt metadata) — never on padding.
    private static func decryptManifest(in backupDir: URL, manifestKeyBlob: Data,
                                        keybag: UnlockedKeybag) throws -> URL {
        // ManifestKey is EXACTLY 44 bytes (4B LE class prefix + 40B wrapped key) — require == 44,
        // not >= 44, so malformed metadata is rejected with a clear signal (Odb F6).
        guard manifestKeyBlob.count == 44 else {
            throw VerifyError.manifestUnreadable(reason: "ManifestKey blob must be 44 bytes, got \(manifestKeyBlob.count)")
        }
        // Little-endian 4-byte class prefix: first byte is least-significant.
        let protectionClass = manifestKeyBlob.prefix(4).reversed().reduce(UInt32(0)) { ($0 << 8) | UInt32($1) }
        let wrappedKey = Data(manifestKeyBlob.suffix(from: manifestKeyBlob.startIndex + 4))
        guard let classKey = keybag.classKeys[protectionClass] else {
            throw VerifyError.manifestUnreadable(reason: "ManifestKey protection class \(protectionClass) is not unlocked by the keybag")
        }
        guard let manifestKey = Keybag.rfc3394Unwrap(kek: classKey, wrapped: wrappedKey) else {
            throw VerifyError.manifestUnreadable(reason: "ManifestKey could not be unwrapped (wrong password or corrupt manifest)")
        }
        let encrypted = try Data(contentsOf: backupDir.appendingPathComponent("Manifest.db"))
        // Full-buffer decrypt, NO PKCS7 strip/throw — SQLite ignores trailing padding bytes.
        let plaintext = try BackupDecryptor.aesCBCDecryptZeroIVRaw(encrypted, key: manifestKey)

        let temp = FileManager.default.temporaryDirectory
            .appendingPathComponent("tether-manifest-\(UUID().uuidString).db")
        FileManager.default.createFile(atPath: temp.path, contents: nil,
                                       attributes: [.posixPermissions: 0o600])
        try plaintext.write(to: temp)
        return temp
    }
}

/// A generic reader for a device `MBFile` keyed archive. `ManifestReader.decodeFileMetadata` maps
/// the archive's `"MBFile"` class name to this type via `NSKeyedUnarchiver.setClass(_:forClassName:)`,
/// so the per-file metadata decodes without depending on Apple's real `MBFile` class. It reads only
/// the two fields the decryptor needs; `EncryptionKey` is the UID-referenced `NSData` whose 44 bytes
/// carry the 4B-LE class prefix + 40B wrapped key. Absent fields stay nil (a keyless directory row).
///
/// Adopts `NSSecureCoding` (Odb C3b-Sec): the per-file BLOB is untrusted hostile-device data, so the
/// unarchiver runs with secure coding ON and every field is decoded class-constrained
/// (`decodeObject(of:forKey:)` / `decodeInteger`). `setClass` redirects the root to this type while
/// secure coding still forbids instantiating any other arbitrary `NSCoding` class in the graph.
///
/// `internal` (not `private`) so the C3b-Sec test can lock `supportsSecureCoding == true` directly —
/// that flag is the security tripwire, distinct from the decoy test that locks root-confinement.
@objc(TetherMBFileMetadata) final class MBFileMetadata: NSObject, NSSecureCoding {
    static var supportsSecureCoding: Bool { true }

    let protectionClass: UInt32?
    let encryptionKey: Data?

    required init?(coder: NSCoder) {
        protectionClass = coder.containsValue(forKey: "ProtectionClass")
            ? UInt32(truncatingIfNeeded: coder.decodeInteger(forKey: "ProtectionClass"))
            : nil
        encryptionKey = coder.decodeObject(of: NSData.self, forKey: "EncryptionKey") as Data?
    }

    // This type is decode-only (it never re-archives a backup record); encode is unreachable.
    func encode(with coder: NSCoder) {}
}
