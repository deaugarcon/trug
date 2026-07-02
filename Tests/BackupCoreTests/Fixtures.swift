import Foundation

/// Loads checked-in WP4 crypto fixtures emitted by `Scripts/wp4-keybag-oracle.py`.
///
/// The keybag TLV and its known-answer class keys are produced by an INDEPENDENT
/// implementation (Python stdlib PBKDF2 + OpenSSL AES, no CommonCrypto) so the Swift
/// `Keybag` under test shares no code with the oracle that built the fixture — a
/// derivation bug cannot hide behind a self-referential fixture (wp4.design.odb.md R1).
enum Fixtures {
    /// Directory holding the emitted fixture, resolved relative to this source file so no
    /// SwiftPM resource bundling (and thus no Package.swift edit) is required.
    static var wp4Dir: URL {
        URL(fileURLWithPath: #filePath)            // Tests/BackupCoreTests/Fixtures.swift
            .deletingLastPathComponent()           // Tests/BackupCoreTests
            .deletingLastPathComponent()           // Tests
            .appendingPathComponent("Fixtures/wp4")
    }

    static let knownPassword = "correct horse battery staple"

    /// The independently-generated synthetic backup keybag TLV.
    static func knownKeybagTLV() throws -> Data {
        try Data(contentsOf: wp4Dir.appendingPathComponent("keybag.tlv"))
    }

    /// Known-answer passcode-wrapped class keys: protection class → expected 32-byte key.
    static func knownPasscodeClassKeys() throws -> [UInt32: Data] {
        let data = try Data(contentsOf: wp4Dir.appendingPathComponent("keybag.known.json"))
        let json = try JSONSerialization.jsonObject(with: data) as? [String: Any]
        let classes = json?["passcode_classes"] as? [String: String] ?? [:]
        var out: [UInt32: Data] = [:]
        for (clas, hex) in classes {
            guard let key = UInt32(clas) else { continue }
            out[key] = Data(hexString: hex)
        }
        return out
    }

    /// Classes the host CANNOT unwrap from the password (device-only); `unlock()` must skip them.
    static func deviceOnlyClasses() throws -> [UInt32] {
        let data = try Data(contentsOf: wp4Dir.appendingPathComponent("keybag.known.json"))
        let json = try JSONSerialization.jsonObject(with: data) as? [String: Any]
        return (json?["device_only_classes"] as? [Int] ?? []).map { UInt32($0) }
    }

    /// The oracle's known encrypted file: the NSKeyedArchiver inputs (protection class + 44-byte
    /// `EncryptionKey` blob), the ciphertext bytes, and the expected plaintext.
    struct EncryptedFile {
        let domain: String
        let relativePath: String
        let protectionClass: UInt32
        let encryptionKeyBlob: Data        // 44B: 4B length prefix + 40B wrapped per-file key
        let ciphertext: Data
        let plaintext: Data
    }

    static func encryptedFile() throws -> EncryptedFile {
        let data = try Data(contentsOf: wp4Dir.appendingPathComponent("keybag.known.json"))
        let json = try JSONSerialization.jsonObject(with: data) as? [String: Any]
        let ef = json?["encrypted_file"] as? [String: Any] ?? [:]
        return EncryptedFile(
            domain: ef["domain"] as? String ?? "",
            relativePath: ef["relative_path"] as? String ?? "",
            protectionClass: UInt32(ef["protection_class"] as? Int ?? 0),
            encryptionKeyBlob: Data(hexString: ef["encryption_key_blob_hex"] as? String ?? ""),
            ciphertext: try Data(contentsOf: wp4Dir.appendingPathComponent("encfile.ciphertext")),
            plaintext: try Data(contentsOf: wp4Dir.appendingPathComponent("encfile.plaintext")))
    }

    /// The oracle's encrypted-Manifest.db material: the `ManifestKey` blob written to Manifest.plist
    /// (4B class prefix + RFC3394-wrapped manifest key) and the raw 32-byte manifest key the fixture
    /// builder encrypts the plaintext Manifest.db with (AES-CBC zero IV).
    struct EncryptedManifest {
        let manifestKeyBlob: Data
        let manifestKey: Data
    }

    static func encryptedManifest() throws -> EncryptedManifest {
        let data = try Data(contentsOf: wp4Dir.appendingPathComponent("keybag.known.json"))
        let json = try JSONSerialization.jsonObject(with: data) as? [String: Any]
        let em = json?["encrypted_manifest"] as? [String: Any] ?? [:]
        return EncryptedManifest(
            manifestKeyBlob: Data(hexString: em["manifest_key_blob_hex"] as? String ?? ""),
            manifestKey: Data(hexString: em["manifest_key_hex"] as? String ?? ""))
    }
}

extension Data {
    /// Decodes a lowercase/uppercase hex string into bytes; ignores malformed input by skipping.
    init(hexString: String) {
        var bytes = [UInt8]()
        var iter = hexString.unicodeScalars.makeIterator()
        func nibble(_ s: Unicode.Scalar?) -> UInt8? {
            guard let s else { return nil }
            switch s {
            case "0"..."9": return UInt8(s.value - 48)
            case "a"..."f": return UInt8(s.value - 97 + 10)
            case "A"..."F": return UInt8(s.value - 65 + 10)
            default: return nil
            }
        }
        while let hi = nibble(iter.next()), let lo = nibble(iter.next()) {
            bytes.append(hi << 4 | lo)
        }
        self = Data(bytes)
    }
}
