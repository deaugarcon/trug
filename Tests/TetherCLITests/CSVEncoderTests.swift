import Testing
import Foundation
import BackupCore
@testable import TetherCLI

/// SP3.1 WP-C (B5) — the pure CSVEncoder + CSVRow conformances. RFC-4180 quoting/escaping (§5.3) and
/// K6 formula-injection neutralization (RATIFIED ON). Pure value-to-value transform, provable in
/// isolation. All inputs are SEEDED/FAKE (§9).
@Suite struct CSVEncoderTests {

    /// A single data record's encoded fields — the second `\r\n`-delimited component of `encode`'s
    /// `header\r\nrow\r\n` output. Split on the literal `"\r\n"` SUBSTRING via `components(separatedBy:)`
    /// (NOT Character `drop`: Swift treats `\r\n` as ONE grapheme cluster, so character math miscounts).
    /// A field's own embedded `\r` or `\n` (never a bare `\r\n` here) does not split.
    private static func encodeOneRow(_ fields: [String?]) -> String {
        let text = String(decoding: CSVEncoder.encode(header: ["h"], rows: [fields]), as: UTF8.self)
        let parts = text.components(separatedBy: "\r\n")
        return parts.count > 1 ? parts[1] : ""
    }

    // MARK: RFC-4180 (§5.3)

    @Test func bareFieldIsUnquoted() {
        #expect(Self.encodeOneRow(["plain"]) == "plain")
    }

    @Test func commaForcesQuoting() {
        #expect(Self.encodeOneRow(["a,b"]) == "\"a,b\"")
    }

    @Test func doubleQuoteIsDoubledAndQuoted() {
        // say "hi" → "say ""hi"""
        #expect(Self.encodeOneRow(["say \"hi\""]) == "\"say \"\"hi\"\"\"")
    }

    @Test func embeddedNewlineForcesQuoting() {
        #expect(Self.encodeOneRow(["line1\nline2"]) == "\"line1\nline2\"")
        #expect(Self.encodeOneRow(["a\rb"]) == "\"a\rb\"")
    }

    @Test func recordsAreCRLFTerminatedAndHeaderFirst() {
        let data = CSVEncoder.encode(header: ["x", "y"], rows: [["1", "2"], ["3", "4"]])
        let text = String(decoding: data, as: UTF8.self)
        #expect(text == "x,y\r\n1,2\r\n3,4\r\n")
        #expect(text.hasSuffix("\r\n"))
    }

    @Test func outputHasNoBOM() {
        let data = CSVEncoder.encode(header: ["h"], rows: [["v"]])
        // A UTF-8 BOM is EF BB BF; the output must start with 'h' (0x68), no BOM.
        #expect(Array(data.prefix(3)) != [0xEF, 0xBB, 0xBF])
        #expect(data.first == UInt8(ascii: "h"))
    }

    // MARK: K6 neutralization (RATIFIED ON) — danger set { = + - @ TAB CR LF }, apostrophe prefix

    @Test func leadingDangerCharactersAreNeutralized() {
        // Non-TAB/CR/LF danger leaders: the field is bare after neutralization (no quote trigger).
        #expect(Self.encodeOneRow(["=SUM(A1)"]) == "'=SUM(A1)")
        #expect(Self.encodeOneRow(["+15555550123"]) == "'+15555550123")   // the load-bearing phone case
        #expect(Self.encodeOneRow(["-groceries"]) == "'-groceries")       // dash-leading note (M4)
        #expect(Self.encodeOneRow(["@ada"]) == "'@ada")
    }

    @Test func leadingWhitespaceControlDangerCharsAreNeutralizedThenQuoted() {
        // TAB/CR/LF are in the danger set AND (CR/LF) force quoting; the ' goes BEFORE the char, inside
        // the quotes. A leading TAB: neutralize → "'\t…" → no quote trigger (tab is not , " CR LF).
        #expect(Self.encodeOneRow(["\tcol"]) == "'\tcol")
        // Leading CR: neutralize → "'\rx" then quoting (contains CR) → "'\rx" wrapped.
        #expect(Self.encodeOneRow(["\rx"]) == "\"'\rx\"")
        #expect(Self.encodeOneRow(["\nx"]) == "\"'\nx\"")
    }

    @Test func neutralizeHappensBeforeQuote() {
        // A field that BOTH starts with a danger char AND contains a quote: =a"b
        //   neutralize → '=a"b ; quote (contains ") → double the " and wrap → "'=a""b"
        #expect(Self.encodeOneRow(["=a\"b"]) == "\"'=a\"\"b\"")
    }

    @Test func nonLeadingDangerCharIsNotNeutralized() {
        // A danger char that is NOT first is left alone (only a LEADING trigger is a formula risk).
        #expect(Self.encodeOneRow(["a+b"]) == "a+b")
        #expect(Self.encodeOneRow(["ada@example.org"]) == "ada@example.org")
    }

    // MARK: F1/F2 (Odb B5) — scalar-based checks; grapheme fusion must NOT bypass quote/neutralize

    @Test func embeddedCRLFAdjacencyIsQuoted() {
        // F1: Swift fuses "\r\n" into ONE grapheme, so Character `.contains("\r")`/`.contains("\n")`
        // MISS it — an embedded CRLF would pass UNquoted and inject a new record. Scalar-based quoting
        // must catch it. encodeOneRow can't be used (its own split would break on the embedded CRLF).
        #expect(CSVEncoder.encode(header: ["h"], rows: [["a\r\nb"]])
                == Data("h\r\n\"a\r\nb\"\r\n".utf8))
    }

    @Test func embeddedCRLFPreventsRecordInjection() {
        // F1 end-to-end: a body with CRLF then a formula token. Without scalar quoting, "=cmd|calc"
        // would start a NEW record AND lead with '=' (a formula). Scalar quoting contains it in ONE
        // quoted field — the '=cmd' never begins a record. The field starts with 'h', so the
        // neutralizer correctly does not fire; the injection is stopped by QUOTING, not bypassed.
        #expect(CSVEncoder.encode(header: ["body"], rows: [["hi\r\n=cmd|calc"]])
                == Data("body\r\n\"hi\r\n=cmd|calc\"\r\n".utf8))
    }

    @Test func leadingDangerScalarWithEmbeddedCRLFIsNeutralizedThenQuoted() {
        // Field starts with '=' AND contains CRLF: neutralize (scalar first) → prepend ' ; then quote
        // (scalar CRLF) → wrap. Both scalar-based checks fire.
        #expect(CSVEncoder.encode(header: ["h"], rows: [["=a\r\nb"]])
                == Data("h\r\n\"'=a\r\nb\"\r\n".utf8))
    }

    @Test func leadingDangerScalarFusedWithCombiningMarkIsNeutralized() {
        // F2: '=' + combining acute fuses into one grapheme, so `field.first` != Character("=") and a
        // grapheme-based check MISSES it. Scalar-based neutralize catches the leading '=' scalar.
        #expect(Self.encodeOneRow(["=\u{0301}x"]) == "'=\u{0301}x")
    }

    @Test func internalQuoteFusedWithCombiningMarkIsDoubled() {
        // Same root cause on the ESCAPE step: a '"' fused with a combining mark is one grapheme, so
        // Character-based escaping MISSES it, leaving an unescaped quote inside a quoted field
        // (injection). Scalar-based escape doubles every '"' SCALAR. Field ["]+combining+[x] → the
        // leading quote scalar is doubled inside the wrapping quotes: `"""<combining>x"`.
        #expect(Self.encodeOneRow(["\"\u{0301}x"]) == "\"\"\"\u{0301}x\"")
    }

    // MARK: null-vs-empty (§5.3) — both render as a zero-length field

    @Test func nilAndEmptyBothRenderZeroLength() {
        #expect(Self.encodeOneRow([nil]) == "")
        #expect(Self.encodeOneRow([""]) == "")
        // In a multi-field row both collapse to empty between commas.
        #expect(Self.encodeOneRow(["a", nil, "", "b"]) == "a,,,b")
    }

    // MARK: header row is structural — quoted if needed but NEVER K6-neutralized

    @Test func headerIsNotNeutralized() {
        // A header that happens to begin with a danger char must NOT gain an apostrophe (that would
        // corrupt the column name). The real §5.2 headers are all safe; this pins the design decision.
        let data = CSVEncoder.encode(header: ["=weird", "ok"], rows: [])
        #expect(String(decoding: data, as: UTF8.self) == "=weird,ok\r\n")
    }

    // MARK: Bool rendering via the CSVRow conformance (is_from_me → "true"/"false")

    @Test func messageRowRendersBoolAsLowercaseTrueFalse() {
        let sent = MessageRow(body: "b", date: "d", service: "s",
                              isFromMe: true, sender: nil, chat: "c").csvFields
        let received = MessageRow(body: "b", date: "d", service: "s",
                                  isFromMe: false, sender: nil, chat: "c").csvFields
        // Column order body,date,service,is_from_me,sender,chat → index 3 is is_from_me.
        #expect(sent[3] == "true")
        #expect(received[3] == "false")
    }

    // MARK: CSVRow headers match spec §5.2 column order (== JSON CodingKeys order)

    @Test func csvHeadersMatchSection52Order() {
        #expect(MessageRow.csvHeader == ["body", "date", "service", "is_from_me", "sender", "chat"])
        #expect(ContactRow.csvHeader == ["first", "last", "organization", "primary_phone", "primary_email"])
        #expect(CallRow.csvHeader == ["address", "date", "duration", "direction", "call_type"])
        #expect(NoteRow.csvHeader == ["title", "snippet", "created", "modified", "folder"])
    }

    @Test func callRowRendersDurationAndNilDateFields() {
        let row = CallRow(address: "+15555550188", date: nil, duration: 0,
                          direction: "incoming", callType: nil).csvFields
        // address,date,duration,direction,call_type
        #expect(row == ["+15555550188", nil, "0", "incoming", nil])
    }
}
