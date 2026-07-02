import Foundation
import CommonCrypto

/// Decrypts one backup file's bytes using its protection-class key from an unlocked keybag.
///
/// Per the BINDING corrections in `docs/superpowers/sp2/wp4.design.odb.md`:
/// the per-file wrapped key is `EncryptionKey[4:]` (the first 4 bytes are a length prefix), it
/// is RFC 3394 key-unwrapped with the file's protection-class key, and the shard is AES-256-CBC
/// with a **fixed zero IV** (not derived); the trailing PKCS7 padding is stripped.
public struct BackupDecryptor {
    public init() {}

    public enum DecryptError: Error, LocalizedError, Equatable {
        case noEncryptionMetadata
        case unknownProtectionClass(UInt32)
        case fileKeyUnwrapFailed
        case badPadding

        public var errorDescription: String? {
            switch self {
            case .noEncryptionMetadata: "The backup file has no encryption metadata to decrypt with."
            case .unknownProtectionClass(let c): "The backup file's protection class (\(c)) is not unlocked by this keybag."
            case .fileKeyUnwrapFailed: "The backup file's key could not be unwrapped (wrong class key or corrupt metadata)."
            case .badPadding: "The decrypted backup file has invalid padding (wrong key or corrupt data)."
            }
        }
    }

    public func decrypt(_ record: FileRecord, shardURL: URL, using keybag: UnlockedKeybag) throws -> Data {
        guard let blob = record.encryptionKeyBlob, let protectionClass = record.protectionClass else {
            throw DecryptError.noEncryptionMetadata
        }
        // EncryptionKey is EXACTLY 44 bytes: a 4-byte length prefix + a 40-byte wrapped file key.
        // Require == 44 (not >= 44) so trailing garbage on malformed metadata is rejected with a
        // clear signal rather than feeding an over-long buffer to RFC3394 unwrap (Odb F6).
        guard blob.count == 44 else { throw DecryptError.noEncryptionMetadata }
        let wrappedFileKey = blob.suffix(from: blob.startIndex + 4)

        guard let classKey = keybag.classKeys[protectionClass] else {
            throw DecryptError.unknownProtectionClass(protectionClass)
        }
        guard let fileKey = Keybag.rfc3394Unwrap(kek: classKey, wrapped: Data(wrappedFileKey)) else {
            throw DecryptError.fileKeyUnwrapFailed
        }

        let ciphertext = try Data(contentsOf: shardURL)
        return try Self.aesCBCDecryptZeroIVStripped(ciphertext, key: fileKey)
    }

    /// AES-256-CBC (zero IV) decrypt + PKCS7 strip, for per-file data where the plaintext length is
    /// exact. Throws `DecryptError.badPadding` on a wrong key or corrupt ciphertext.
    static func aesCBCDecryptZeroIVStripped(_ ciphertext: Data, key: Data) throws -> Data {
        try stripPKCS7(aesCBCDecryptZeroIV(ciphertext, key: key))
    }

    /// AES-256-CBC (zero IV) decrypt of the FULL buffer with NO PKCS7 strip — for the encrypted
    /// `Manifest.db` seam (task #11). The references disagree benignly on the manifest's trailing
    /// bytes and a strict PKCS7 check causes false failures on real backups (MVT #93/#571); SQLite
    /// reads by page count from its header and ignores trailing padding, so the raw buffer is
    /// written verbatim and success is asserted by the SQLite open, not by padding validity.
    static func aesCBCDecryptZeroIVRaw(_ ciphertext: Data, key: Data) throws -> Data {
        try aesCBCDecryptZeroIV(ciphertext, key: key)
    }

    // MARK: - crypto

    /// AES-256-CBC decrypt with a fixed all-zero 16-byte IV and NO library padding (caller strips).
    private static func aesCBCDecryptZeroIV(_ ciphertext: Data, key: Data) throws -> Data {
        guard !ciphertext.isEmpty, ciphertext.count % kCCBlockSizeAES128 == 0 else {
            throw DecryptError.badPadding
        }
        let iv = Data(count: kCCBlockSizeAES128)
        let outCapacity = ciphertext.count
        var out = Data(count: outCapacity)
        var moved = 0
        let status = out.withUnsafeMutableBytes { outPtr in
            ciphertext.withUnsafeBytes { ctPtr in
                key.withUnsafeBytes { keyPtr in
                    iv.withUnsafeBytes { ivPtr in
                        CCCrypt(CCOperation(kCCDecrypt), CCAlgorithm(kCCAlgorithmAES),
                                CCOptions(0),   // no kCCOptionPKCS7Padding — strip manually
                                keyPtr.baseAddress, key.count,
                                ivPtr.baseAddress,
                                ctPtr.baseAddress, ciphertext.count,
                                outPtr.baseAddress, outCapacity, &moved)
                    }
                }
            }
        }
        guard status == kCCSuccess else { throw DecryptError.badPadding }
        return out.prefix(moved)
    }

    /// Strips PKCS7 padding, validating the pad byte and trailer.
    private static func stripPKCS7(_ data: Data) throws -> Data {
        guard let pad = data.last, pad >= 1, pad <= UInt8(kCCBlockSizeAES128), Int(pad) <= data.count else {
            throw DecryptError.badPadding
        }
        let trailer = data.suffix(Int(pad))
        guard trailer.allSatisfy({ $0 == pad }) else { throw DecryptError.badPadding }
        return data.prefix(data.count - Int(pad))
    }
}
