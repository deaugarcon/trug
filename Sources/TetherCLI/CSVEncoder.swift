import Foundation
import BackupCore

/// SP3.1 WP-C (B5) — the flat-CSV presentation contract for the four export stores. `CSVRow` lives in
/// TetherCLI (the presentation seam) and the BackupCore row types conform RETROACTIVELY here, so the
/// engine rows stay unedited (engine owns truth; CLI owns presentation) — exactly as `InspectRedaction`
/// does. Because `CSVRow` is declared in THIS module, the conformances raise no Swift-6
/// retroactive-conformance warning (the "0 new warnings" gate holds).
///
/// Column order per store == the JSON `CodingKeys` order == spec §5.2. A future field addition MUST
/// touch both the row's `CodingKeys` and its `csvHeader`/`csvFields`; the per-store golden tests catch
/// any drift.
protocol CSVRow {
    /// The fixed, locked column order (§5.2). Header names are the snake_case field names.
    static var csvHeader: [String] { get }
    /// The row's scalar fields in `csvHeader` order. `nil` → an empty CSV field (the documented
    /// null-vs-empty lossiness, §5.3); `Bool` → lowercase `"true"`/`"false"`; `Int` → its decimal string.
    var csvFields: [String?] { get }
}

// MARK: Retroactive conformances (BackupCore rows unedited)

extension MessageRow: CSVRow {
    static var csvHeader: [String] { ["body", "date", "service", "is_from_me", "sender", "chat"] }
    var csvFields: [String?] { [body, date, service, isFromMe ? "true" : "false", sender, chat] }
}

extension ContactRow: CSVRow {
    static var csvHeader: [String] { ["first", "last", "organization", "primary_phone", "primary_email"] }
    var csvFields: [String?] { [first, last, organization, primaryPhone, primaryEmail] }
}

extension CallRow: CSVRow {
    static var csvHeader: [String] { ["address", "date", "duration", "direction", "call_type"] }
    var csvFields: [String?] { [address, date, String(duration), direction, callType] }
}

extension NoteRow: CSVRow {
    static var csvHeader: [String] { ["title", "snippet", "created", "modified", "folder"] }
    var csvFields: [String?] { [title, snippet, created, modified, folder] }
}

/// A pure, deterministic RFC-4180 CSV encoder with K6 formula-injection neutralization. No I/O, no
/// ArgumentParser — a value-to-value transform so the escaping/neutralization is provable in isolation
/// (the CSV analog of `InspectRedaction`'s purity). Per data field, in this ORDER:
///   1. **K6 neutralize (RATIFIED ON):** if the field is non-empty and its FIRST character is a
///      spreadsheet formula trigger, prepend one apostrophe. Applied BEFORE quoting.
///   2. **RFC-4180 quote:** if the (possibly-mutated) field contains `,` `"` CR or LF, wrap it in
///      double-quotes and double every internal `"`.
/// Records are CRLF-terminated; output is UTF-8 with NO BOM; there is NO envelope (§5.4 — CSV is pure
/// tabular data, no `{store,schema_version,count}`).
enum CSVEncoder {
    /// K6 (RATIFIED) danger set — the OWASP formula-trigger characters, as Unicode SCALARS. A LEADING
    /// one is neutralized. Scalar-typed (not `Character`) so a leading trigger FUSED with a combining
    /// mark — e.g. `"=\u{0301}…"`, whose first grapheme is NOT `Character("=")` — is still caught
    /// (Odb F2): Excel/Sheets decide "is a formula" from the first byte, regardless of grapheme edges.
    static let dangerScalars: Set<Unicode.Scalar> = ["=", "+", "-", "@", "\t", "\r", "\n"]

    /// The K6 neutralizing prefix. Odb B5 ruling: KEEP the apostrophe — a leading tab is itself in the
    /// danger set (a trimming consumer could strip it and re-expose the formula), and `|` is only a DDE
    /// separator after a leading `=` (already neutralized), so it is not a standalone trigger.
    static let neutralizePrefix: Character = "'"

    /// Encodes `header` + `rows` to RFC-4180 CSV bytes. The header row is emitted with RFC-4180 quoting
    /// ONLY — column names are structural and are never K6-neutralized (an apostrophe-prefixed header
    /// would corrupt the column name); the fixed §5.2 names need neither quoting nor neutralization.
    static func encode(header: [String], rows: [[String?]]) -> Data {
        var out = header.map(quote).joined(separator: ",") + "\r\n"
        for row in rows {
            out += row.map(encodeField).joined(separator: ",") + "\r\n"
        }
        return Data(out.utf8)   // UTF-8, no BOM
    }

    /// Encodes one DATA field: nil and "" both render as a zero-length field (null-vs-empty lossiness,
    /// §5.3); otherwise K6-neutralize THEN RFC-4180-quote.
    static func encodeField(_ field: String?) -> String {
        guard let field, !field.isEmpty else { return "" }
        return quote(neutralize(field))
    }

    /// K6: prepend the neutralizing prefix iff the FIRST SCALAR is a formula trigger (scalar-based so a
    /// trigger fused with a combining mark is not missed — Odb F2). A `+`-leading phone/handle (messages
    /// `sender`, contacts `primary_phone`, calls `address`) becomes `'+…`; a `-`/`@`/`=`-leading note
    /// title/snippet becomes `'-…`/`'@…`/`'=…`. INTENTIONAL, ratified mutation (JSON stays lossless).
    static func neutralize(_ field: String) -> String {
        guard let first = field.unicodeScalars.first, dangerScalars.contains(first) else { return field }
        return String(neutralizePrefix) + field
    }

    /// RFC-4180 quoting: wrap in double-quotes iff the field contains a comma, double-quote, CR, or LF —
    /// tested over Unicode SCALARS, NOT Characters, because Swift fuses `"\r\n"` (and a base char + a
    /// combining mark) into ONE grapheme, so a Character `.contains("\r")`/`.contains("\n")` MISSES an
    /// embedded CRLF and would leak a record separator (Odb F1). Every internal double-quote SCALAR is
    /// doubled — also scalar-based, so a combining-fused quote is still escaped. Otherwise emitted bare.
    static func quote(_ field: String) -> String {
        let needsQuoting = field.unicodeScalars.contains {
            $0 == "," || $0 == "\"" || $0 == "\r" || $0 == "\n"
        }
        guard needsQuoting else { return field }
        var quoted = String.UnicodeScalarView()
        quoted.append("\"")
        for scalar in field.unicodeScalars {
            if scalar == "\"" { quoted.append("\"") }   // double every quote SCALAR (grapheme-fusion-safe)
            quoted.append(scalar)
        }
        quoted.append("\"")
        return String(quoted)
    }
}
