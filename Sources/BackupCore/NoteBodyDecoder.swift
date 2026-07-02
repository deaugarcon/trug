import Foundation
import Compression

/// SP3.2 — decodes a note's full plaintext from `ZICNOTEDATA.ZDATA`: a gzip-compressed Apple
/// "note store" protobuf. A single pure `Data -> String?` transform so the whole untrusted-input walk
/// (gzip framing → raw-DEFLATE inflate → protobuf descent → UTF-8) is provable in isolation, the way
/// `InspectRedaction` and `CSVEncoder` are pure.
///
/// TOTALITY (Odb F2, binding): the decoder is fail-closed on EVERY unrecognized shape — a malformed or
/// reserved-flag gzip header, a truncated / over- or under-stated stream, a decompression bomb, or a
/// protobuf shape it does not explicitly handle all yield `nil`, NEVER a partial or best-effort string.
/// It never throws, so a bad row can never abort the reader; blast radius is bounded to "body missing,"
/// never "wrong body." No force-unwrap; every index is bounds-checked.
enum NoteBodyDecoder {
    // device-verify(B6) — Apple "note store" protobuf field numbers, isolated here for a localized
    // B6 rebind (mirrors the Schema Z-spelling isolation). Path: NoteStoreProto.document (2) →
    // Document.note (3) → Note.note_text (2). Confirmed against apple_cloud_notes_parser proto.
    static let documentField = 2
    static let noteField = 3
    static let noteTextField = 2

    // Dual anti-bomb caps (SOLVE §3.2): the compressed cap guards the input size; the decompressed
    // cap guards the gzip ISIZE claim before any buffer is allocated. Per-row and transient — peak
    // memory is min(ISIZE, cap)+1 for one row, freed before the next, NOT cap × N.
    static let maxCompressedBytes = 8 * 1024 * 1024      // 8 MiB
    static let maxDecompressedBytes = 64 * 1024 * 1024   // 64 MiB

    // gzip FLG bits (RFC 1952 §2.3.1). The header parse is flag-DRIVEN — each optional field is skipped
    // by its bit — never a hardcoded 10-byte skip (Odb F2). Any reserved bit set → unrecognized → nil.
    private static let fhcrc: UInt8 = 0x02
    private static let fextra: UInt8 = 0x04
    private static let fname: UInt8 = 0x08
    private static let fcomment: UInt8 = 0x10
    private static let reservedFlags: UInt8 = 0xE0

    /// The single entry point: gzip-compressed note protobuf → decoded plaintext, or `nil` on ANY
    /// unrecognized shape (fail-closed). `""` is a legitimate result (a note with empty text).
    static func decodedText(_ data: Data) -> String? {
        guard data.count <= maxCompressedBytes else { return nil }
        guard let inflated = gunzip(Array(data)) else { return nil }
        // Descend the LOCKED [document, note, note_text] path, taking the first match at each level.
        guard let document = field(inflated, number: documentField),
              let note = field(document, number: noteField),
              let text = field(note, number: noteTextField)
        else { return nil }
        return String(bytes: text, encoding: .utf8)   // invalid UTF-8 → nil (fail-closed)
    }

    // MARK: gzip framing (RFC 1952) + raw-DEFLATE inflate

    /// Parses a single gzip member and inflates its DEFLATE body. Fails closed on bad magic, bad
    /// compression method, reserved flags, an unterminated header field, a missing trailer, or an ISIZE
    /// that does not match the inflated length.
    private static func gunzip(_ bytes: [UInt8]) -> [UInt8]? {
        // Fixed prefix: ID1 ID2 CM FLG MTIME(4) XFL OS = 10 bytes.
        guard bytes.count >= 10,
              bytes[0] == 0x1f, bytes[1] == 0x8b,   // gzip magic
              bytes[2] == 0x08                        // CM = DEFLATE
        else { return nil }
        let flg = bytes[3]
        guard flg & reservedFlags == 0 else { return nil }   // reserved bits must be zero

        var offset = 10
        if flg & fextra != 0 {
            guard offset + 2 <= bytes.count else { return nil }
            let xlen = Int(bytes[offset]) | (Int(bytes[offset + 1]) << 8)   // little-endian
            offset += 2 + xlen
            guard offset <= bytes.count else { return nil }
        }
        if flg & fname != 0 {
            guard let next = skipZeroTerminated(bytes, from: offset) else { return nil }
            offset = next
        }
        if flg & fcomment != 0 {
            guard let next = skipZeroTerminated(bytes, from: offset) else { return nil }
            offset = next
        }
        if flg & fhcrc != 0 {
            offset += 2
            guard offset <= bytes.count else { return nil }
        }

        // Trailer: CRC32(4) + ISIZE(4). The DEFLATE body sits between the header and the trailer.
        guard bytes.count >= offset + 8 else { return nil }
        let bodyEnd = bytes.count - 8
        guard bodyEnd > offset else { return nil }   // a non-empty DEFLATE body is required
        let isize = UInt32(bytes[bodyEnd + 4]) | (UInt32(bytes[bodyEnd + 5]) << 8)
                  | (UInt32(bytes[bodyEnd + 6]) << 16) | (UInt32(bytes[bodyEnd + 7]) << 24)
        guard Int(isize) <= maxDecompressedBytes else { return nil }   // decompressed cap (the claim)

        return inflate(Array(bytes[offset..<bodyEnd]), expectedSize: Int(isize))
    }

    /// Inflates a raw-DEFLATE body via `compression_decode_buffer(COMPRESSION_ZLIB)` (raw DEFLATE on
    /// Apple platforms). The destination is OVER-allocated by one byte over the claimed ISIZE (Odb F3):
    /// a stream whose true output exceeds a lying-small ISIZE fills all `expected+1` bytes and returns
    /// `expected+1 ≠ expected`, so the truncation is caught; an over-stated ISIZE inflates to fewer than
    /// `expected` bytes and is likewise rejected. Only an exact `written == expected` succeeds.
    private static func inflate(_ deflate: [UInt8], expectedSize expected: Int) -> [UInt8]? {
        guard !deflate.isEmpty, expected >= 0 else { return nil }
        let capacity = expected + 1
        var dst = [UInt8](repeating: 0, count: capacity)
        let written = dst.withUnsafeMutableBufferPointer { dstBuf -> Int in
            guard let dstBase = dstBuf.baseAddress else { return -1 }
            return deflate.withUnsafeBufferPointer { srcBuf -> Int in
                guard let srcBase = srcBuf.baseAddress else { return -1 }
                return compression_decode_buffer(dstBase, capacity, srcBase, srcBuf.count, nil, COMPRESSION_ZLIB)
            }
        }
        guard written == expected else { return nil }
        return Array(dst[0..<written])
    }

    /// Advances past a zero-terminated header field (FNAME/FCOMMENT). Returns the index just after the
    /// terminating NUL, or `nil` if the field runs off the end unterminated.
    private static func skipZeroTerminated(_ bytes: [UInt8], from index: Int) -> Int? {
        var i = index
        while i < bytes.count {
            if bytes[i] == 0 { return i + 1 }
            i += 1
        }
        return nil
    }

    // MARK: protobuf walk (length-delimited, first-match, fully bounds-checked)

    /// Returns the payload of the FIRST length-delimited (wire type 2) field whose number is `number`,
    /// or `nil` when it is absent or any framing is malformed. Non-matching fields are skipped by their
    /// wire type; an unknown wire type (groups 3/4, reserved 6/7) fails closed.
    private static func field(_ bytes: [UInt8], number: Int) -> [UInt8]? {
        var i = 0
        while i < bytes.count {
            guard let (tag, afterTag) = readVarint(bytes, at: i) else { return nil }
            i = afterTag
            let fieldNumber = Int(tag >> 3)
            let wireType = tag & 0x7
            switch wireType {
            case 0:   // varint — skip it
                guard let (_, next) = readVarint(bytes, at: i) else { return nil }
                i = next
            case 1:   // 64-bit
                guard i + 8 <= bytes.count else { return nil }
                i += 8
            case 5:   // 32-bit
                guard i + 4 <= bytes.count else { return nil }
                i += 4
            case 2:   // length-delimited
                guard let (length, afterLen) = readVarint(bytes, at: i) else { return nil }
                let start = afterLen
                guard length <= UInt64(bytes.count - start) else { return nil }
                let end = start + Int(length)
                if fieldNumber == number { return Array(bytes[start..<end]) }
                i = end
            default:  // 3, 4 (deprecated groups), 6, 7 (reserved) → fail closed
                return nil
            }
        }
        return nil
    }

    /// Reads a base-128 varint. Returns the value and the index just past it, or `nil` on truncation or
    /// a value wider than 64 bits.
    private static func readVarint(_ bytes: [UInt8], at index: Int) -> (value: UInt64, next: Int)? {
        var result: UInt64 = 0
        var shift: UInt64 = 0
        var i = index
        while i < bytes.count {
            guard shift < 64 else { return nil }   // overflow guard (max 10 groups)
            let byte = bytes[i]
            result |= UInt64(byte & 0x7F) << shift
            i += 1
            if byte & 0x80 == 0 { return (result, i) }
            shift += 7
        }
        return nil   // truncated varint
    }
}
