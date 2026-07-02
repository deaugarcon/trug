import Testing
import Foundation
@testable import BackupCore

/// SP3.2 — the pure `NoteBodyDecoder` (gzip framing → raw-DEFLATE inflate → note-store protobuf walk →
/// UTF-8). Every input is SYNTHETIC (§9): invented note text and hand-assembled protobuf bytes only, no
/// real content. The decoder is a total `Data -> String?`: it NEVER throws and fails closed (→ nil) on
/// every unrecognized shape (Odb F2, binding), so blast radius is bounded to "body missing."
///
/// Gate map (SOLVE §6 decoder tests + Odb F2/F3/F6 bindings):
///   1  round-trip UTF-8 + emoji            6  nil on a well-formed proto missing the [2,3,2] path
///   2  nil on non-gzip / empty input       7  caps by ISIZE claim over the decompressed cap (bomb)
///   3  nil on OVERSTATED ISIZE (truncation) 8 caps by compressed-input size over the compressed cap
///   4  nil on UNDERSTATED ISIZE (F3 +1)     9 returns text, ignores attribute_run, passes U+FFFC (F6)
///   5  nil on a bad proto wire shape       10 empty note_text → "" (decode-success-empty)
///  11  field-path constants are named      12 flag-driven header parse: FEXTRA+FNAME decode (F2)
///  13  fail-closed on reserved FLG bits (F2)
@Suite struct NoteBodyDecoderTests {

    private static func gzOfText(_ text: String, includeAttributeRun: Bool = false) -> Data {
        Data(FixtureBuilder.gzip(FixtureBuilder.noteProtoBytes(text: text, includeAttributeRun: includeAttributeRun)))
    }

    /// Overwrites the 4-byte little-endian ISIZE trailer in place.
    private static func withISIZE(_ gz: [UInt8], _ value: UInt32) -> Data {
        var out = gz
        let n = out.count
        out[n - 4] = UInt8(value & 0xFF); out[n - 3] = UInt8((value >> 8) & 0xFF)
        out[n - 2] = UInt8((value >> 16) & 0xFF); out[n - 1] = UInt8((value >> 24) & 0xFF)
        return Data(out)
    }

    // MARK: 1 — round-trip UTF-8 + emoji

    @Test func decodesRoundTripUTF8AndEmoji() {
        let text = "Café draft — item ✓ 🗒️ ünïcödé lines"
        #expect(NoteBodyDecoder.decodedText(Self.gzOfText(text)) == text)
    }

    // MARK: 2 — nil on non-gzip / empty

    @Test func nilOnNonGzipOrEmptyInput() {
        #expect(NoteBodyDecoder.decodedText(Data([0x00, 0x01, 0x02, 0x03])) == nil)
        #expect(NoteBodyDecoder.decodedText(Data("plainly not gzip".utf8)) == nil)
        #expect(NoteBodyDecoder.decodedText(Data()) == nil)
    }

    // MARK: 3 — nil on OVERSTATED ISIZE (stream ends before the claimed length)

    @Test func nilOnOverstatedISIZE() {
        let gz = FixtureBuilder.gzip(FixtureBuilder.noteProtoBytes(text: "a short synthetic body"))
        // Claim far more than the true inflated length (still under the cap): decode writes the true
        // count ≠ claim → nil.
        #expect(NoteBodyDecoder.decodedText(Self.withISIZE(gz, 4096)) == nil)
    }

    // MARK: 4 — nil on UNDERSTATED ISIZE (the +1 over-allocation truncation guard, Odb F3)

    @Test func nilOnUnderstatedISIZE() {
        let gz = FixtureBuilder.gzip(FixtureBuilder.noteProtoBytes(text: "a reasonably long synthetic note body"))
        // Understate ISIZE to 3: the buffer is expected+1 = 4 bytes; the true output overflows it, decode
        // returns 4 ≠ 3, truncation caught. No partial plaintext escapes.
        #expect(NoteBodyDecoder.decodedText(Self.withISIZE(gz, 3)) == nil)
    }

    // MARK: 5 — nil on a bad proto wire shape

    @Test func nilOnBadProtoWireShape() {
        // Valid gzip whose inflated bytes open with a reserved wire type (7) → the walk fails closed.
        #expect(NoteBodyDecoder.decodedText(Data(FixtureBuilder.gzip([0x07, 0xFF, 0xFF, 0xFF]))) == nil)
    }

    // MARK: 6 — nil on a well-formed proto missing the [2,3,2] leaf

    @Test func nilOnMissingTextPath() {
        // {document=2 {note=3 {attribute_run=5: …}}} — a valid nesting with NO note_text (field 2) leaf.
        // Bytes: 12 06 1A 04 2A 02 08 01 (outer field 2 len6 → field 3 len4 → field 5 len2 → 08 01).
        let proto: [UInt8] = [0x12, 0x06, 0x1A, 0x04, 0x2A, 0x02, 0x08, 0x01]
        #expect(NoteBodyDecoder.decodedText(Data(FixtureBuilder.gzip(proto))) == nil)
    }

    // MARK: 7 — decompressed cap: an ISIZE claim over 64 MiB is rejected before allocation

    @Test func capsByISIZEClaimOverDecompressedCap() {
        let gz = FixtureBuilder.gzip(FixtureBuilder.noteProtoBytes(text: "small"))
        #expect(NoteBodyDecoder.decodedText(Self.withISIZE(gz, UInt32(NoteBodyDecoder.maxDecompressedBytes + 1))) == nil)
    }

    // MARK: 8 — compressed cap: input larger than 8 MiB is rejected outright

    @Test func capsByCompressedInputOverCompressedCap() {
        #expect(NoteBodyDecoder.decodedText(Data(count: NoteBodyDecoder.maxCompressedBytes + 1)) == nil)
    }

    // MARK: 9 — returns text, ignores attribute_run, passes the U+FFFC object placeholder (Odb F6)

    @Test func returnsTextIgnoringAttributeRunsAndPassesObjectPlaceholder() {
        let text = "Before \u{FFFC} after the attachment placeholder"
        #expect(NoteBodyDecoder.decodedText(Self.gzOfText(text, includeAttributeRun: true)) == text)
    }

    // MARK: 10 — empty note_text → "" (decode-success-empty, distinct from nil)

    @Test func emptyNoteTextIsEmptyString() {
        #expect(NoteBodyDecoder.decodedText(Self.gzOfText("")) == "")
    }

    // MARK: 11 — field-path constants are named (device-verify(B6) isolation)

    @Test func fieldPathConstantsAreNamed() {
        #expect(NoteBodyDecoder.documentField == 2)
        #expect(NoteBodyDecoder.noteField == 3)
        #expect(NoteBodyDecoder.noteTextField == 2)
    }

    // MARK: 12 — flag-driven header parse: a member with FEXTRA + FNAME still decodes (Odb F2)

    @Test func decodesGzipWithFEXTRAAndFNAMEHeaderFlags() {
        let text = "flag-driven header body"
        let gz = FixtureBuilder.gzip(FixtureBuilder.noteProtoBytes(text: text),
                                     filename: "note.bin", extra: [0xAA, 0xBB, 0xCC])
        #expect(NoteBodyDecoder.decodedText(Data(gz)) == text)
    }

    // MARK: 13 — fail-closed on reserved FLG bits (an unrecognized header shape, Odb F2)

    @Test func nilOnReservedGzipFlagBits() {
        var gz = FixtureBuilder.gzip(FixtureBuilder.noteProtoBytes(text: "x"))
        gz[3] |= 0x20   // a reserved FLG bit → unrecognized → nil
        #expect(NoteBodyDecoder.decodedText(Data(gz)) == nil)
    }
}
