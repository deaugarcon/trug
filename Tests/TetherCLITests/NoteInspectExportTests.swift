import Testing
import Foundation
import ArgumentParser
import BackupCore
@testable import TetherCLI

/// SP3.1 WP-B (B4) — `inspect notes` redaction + `export notes` envelope. K3 preview scope: NO body
/// field in schema_version 1. All rows are SEEDED/FAKE (§9): invented titles/snippets/dates only.
///
/// Gate map:
///   E1  §10.2 envelope round-trip ({store, schema_version, count, rows}; keys title/snippet/created/
///       modified/folder — every name matches §4.4, no remap).
///   K3  NO `body` key ever appears in export (preview scope; body deferred to SP3.2).
///   E2  export is FULL + UNMASKED — a >40-char title/snippet appears UNTRUNCATED (inverse of inspect).
///   E3  M1 — nil created/modified export with NO key and NO fabricated 2001 epoch.
///   I3  redact(NoteRow) truncates title+snippet to 40 (K5); created/modified/folder pass; nil → (none).
///   I1  inspect noteTable truncates the over-long title/snippet with an ellipsis.
///   I2  inspect noteJSON is capped + redacted with preview keys.
///   W1  the `notes` selector parses on both inspect and export; it is in Store.allCases.
@Suite struct NoteInspectExportTests {

    // Computed (not stored static) so the non-Sendable NoteRow array is a fresh value per access.
    static var seededNotes: [NoteRow] {
        [
            NoteRow(title: "Groceries", snippet: "milk, eggs, flour",
                    created: "2026-05-30T14:00:00Z", modified: "2026-06-13T08:12:00Z", folder: "Shopping"),
            NoteRow(title: "Trip ideas", snippet: "coast road, ferry timetable",
                    created: "2026-04-02T19:20:00Z", modified: "2026-06-01T21:05:00Z", folder: nil),
        ]
    }

    private static func encode(_ env: some Encodable) throws -> Data {
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.prettyPrinted, .sortedKeys]
        return try encoder.encode(env)
    }

    // MARK: E1 / K3 — §10.2 envelope round-trip, and NO body key

    @Test func notesEnvelopeRoundTripsToSection102SchemaWithNoBody() throws {
        let rows = Self.seededNotes
        let env = ExportEnvelope(store: "notes", rows: rows)
        let data = try Self.encode(env)

        let obj = try #require(try JSONSerialization.jsonObject(with: data) as? [String: Any])
        #expect(Set(obj.keys) == ["store", "schema_version", "count", "rows"])
        #expect(obj["schema_version"] as? Int == 1)
        #expect(obj["count"] as? Int == rows.count)
        #expect(obj["store"] as? String == "notes")

        let rowObjs = try #require(obj["rows"] as? [[String: Any]])
        let first = try #require(rowObjs.first)   // Groceries has a folder → all five keys present
        for key in ["title", "snippet", "created", "modified", "folder"] {
            #expect(first.keys.contains(key))
        }
        // K3: NO body field ships in schema_version 1 — not even a null placeholder, on ANY row.
        for row in rowObjs { #expect(row["body"] == nil) }
        let json = String(decoding: data, as: UTF8.self)
        #expect(!json.contains("\"body\""))

        let decoded = try JSONDecoder().decode(ExportEnvelope<NoteRow>.self, from: data)
        #expect(decoded.store == "notes")
        #expect(decoded.schemaVersion == 1)
        #expect(decoded.rows == rows)
    }

    // MARK: E2 — FULL + UNMASKED (the inverse of inspect): a long title/snippet is NOT truncated

    @Test func exportIsFullAndUntruncatedVerbatim() throws {
        let longTitle = String(repeating: "A", count: 60)
        let longSnippet = String(repeating: "b", count: 60)
        let env = ExportEnvelope(store: "notes", rows: [
            NoteRow(title: longTitle, snippet: longSnippet,
                    created: "2026-01-01T00:00:00Z", modified: "2026-01-01T00:00:00Z", folder: nil),
        ])
        let json = String(decoding: try Self.encode(env), as: UTF8.self)
        #expect(json.contains(longTitle))     // full 60-char title, UNTRUNCATED
        #expect(json.contains(longSnippet))
        #expect(!json.contains("…"))          // no inspect ellipsis in export
    }

    // MARK: E3 — M1: nil created/modified export with no key and no fabricated epoch

    @Test func exportOfNullDateNoteHasNoFabricatedEpoch() throws {
        let row = NoteRow(title: "t", snippet: "s", created: nil, modified: nil, folder: nil)
        let env = ExportEnvelope(store: "notes", rows: [row])
        let data = try Self.encode(env)
        #expect(!String(decoding: data, as: UTF8.self).contains("2001-01-01T00:00:00Z"))

        let decoded = try JSONDecoder().decode(ExportEnvelope<NoteRow>.self, from: data)
        #expect(decoded.rows.first?.created == nil)
        #expect(decoded.rows.first?.modified == nil)
    }

    // MARK: I3 — redact(NoteRow): title+snippet truncated (K5), rest passed; nil → (none)

    @Test func redactTruncatesTitleAndSnippetPassesTheRest() {
        let longTitle = String(repeating: "A", count: 60)
        let longSnippet = String(repeating: "b", count: 60)
        let r = InspectRedaction.redact(NoteRow(
            title: longTitle, snippet: longSnippet,
            created: "2026-05-30T14:00:00Z", modified: "2026-06-13T08:12:00Z", folder: "Work"))
        // K5: truncated to previewBodyMax (40) + ellipsis.
        #expect(r.title.count == InspectRedaction.previewBodyMax + 1)
        #expect(r.title.hasSuffix("…"))
        #expect(r.snippet.count == InspectRedaction.previewBodyMax + 1)
        #expect(r.snippet.hasSuffix("…"))
        #expect(r.created == "2026-05-30T14:00:00Z")   // dates pass through
        #expect(r.folder == "Work")
    }

    @Test func redactNilFieldsRenderNoneNeverEpoch() {
        let r = InspectRedaction.redact(NoteRow(
            title: nil, snippet: nil, created: nil, modified: nil, folder: nil))
        #expect(r.title == "(none)")
        #expect(r.snippet == "(none)")
        #expect(r.created == "(none)")     // M1: nil date → (none), never an epoch
        #expect(r.modified == "(none)")
        #expect(r.folder == "(none)")
    }

    // MARK: I1 — inspect noteTable truncates the over-long title/snippet

    @Test func noteTableTruncatesLongFields() {
        let longTitle = String(repeating: "A", count: 60)
        let table = InspectRedaction.noteTable([
            NoteRow(title: longTitle, snippet: "short", created: "2026-01-01T00:00:00Z",
                    modified: "2026-01-01T00:00:00Z", folder: "Work"),
        ], limit: 20).rendered()
        #expect(table.contains("…"))            // the long title is truncated with an ellipsis
        #expect(!table.contains(longTitle))     // the full 60-char title never appears
        #expect(table.contains("Work"))         // folder passes through
    }

    @Test func noteTableRowsAreFixedArity() {
        let header = InspectRedaction.noteHeader
        let table = InspectRedaction.noteTable(Self.seededNotes, limit: 20)
        for row in table.rows { #expect(row.count == header.count) }
    }

    // MARK: I2 — inspect noteJSON is capped + redacted with preview keys

    @Test func noteJSONIsRedactedWithPreviewKeys() throws {
        let envelope = InspectRedaction.noteJSON(Self.seededNotes, limit: 20)
        #expect(envelope.store == "notes")
        #expect(envelope.preview == true)
        #expect(envelope.shown == Self.seededNotes.count)
        #expect(envelope.total == nil)
        let encoded = String(decoding: try JSONEncoder().encode(envelope), as: UTF8.self)
        #expect(encoded.contains("title"))
        #expect(encoded.contains("snippet"))
        #expect(encoded.contains("folder"))
        #expect(!encoded.contains("\"body\""))   // preview carries no body either
    }

    // MARK: W1 — the `notes` selector parses on inspect + export; it is in Store.allCases

    @Test func notesSelectorParsesOnInspectAndExport() throws {
        let inspect = try Backup.Inspect.parse(["UDID", "notes"])
        #expect(inspect.store == .notes)
        let export = try Backup.Export.parse(["UDID", "notes", "--out", "/tmp/does-not-matter"])
        #expect(export.store == .notes)
    }

    @Test func notesIsAnInScopeStore() {
        #expect(Backup.Inspect.Store.allCases.contains(.notes))
        #expect(Backup.Export.Store.allCases.contains(.notes))
    }
}
