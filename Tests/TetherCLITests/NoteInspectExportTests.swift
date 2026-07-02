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
///   I3  redact(NoteRow) truncates title+snippet+folder to 40 (K5 Deau ruling); created/modified pass; nil → (none).
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

    private static func makeTempDir() throws -> URL {
        let dir = FileManager.default.temporaryDirectory
            .appendingPathComponent("notes-export-\(UUID().uuidString)", isDirectory: true)
        try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        return dir
    }

    // MARK: 16 — §10.2 export JSON is schema_version 2 WITH body, asserted through emit (Odb F4)

    @Test func notesExportJSONIsSchemaVersion2WithBody() throws {
        // SP3.2 (v2 — REWRITTEN from the v1 no-body envelope gate): the notes export JSON is
        // schema_version 2 and carries `body`. Routed through `Backup.Export.emit` so the version is
        // asserted on the REAL emit path (the type-carried `ExportSchemaVersioned`), not a
        // direct-construct default. A decoded body ships verbatim; a nil body OMITS the key
        // (M1-parallel); a locked note's withheld body ships as "" (present-empty, M2-parallel).
        let rows = [
            NoteRow(title: "Has body", snippet: "s", created: "2026-01-01T00:00:00Z",
                    modified: "2026-01-01T00:00:00Z", folder: nil, body: "decoded note text"),
            NoteRow(title: "No body", snippet: "s", created: "2026-01-01T00:00:00Z",
                    modified: "2026-01-01T00:00:00Z", folder: nil, body: nil),
            NoteRow(title: "Locked", snippet: "", created: "2026-01-01T00:00:00Z",
                    modified: "2026-01-01T00:00:00Z", folder: nil, body: ""),
        ]
        let dir = try Self.makeTempDir()
        defer { try? FileManager.default.removeItem(at: dir) }
        let out = dir.appendingPathComponent("notes.json").path
        try Backup.Export.emit(rows, store: "notes", format: .json, to: out, force: false)

        let data = try Data(contentsOf: URL(fileURLWithPath: out))
        let obj = try #require(try JSONSerialization.jsonObject(with: data) as? [String: Any])
        #expect(Set(obj.keys) == ["store", "schema_version", "count", "rows"])
        #expect(obj["schema_version"] as? Int == 2)        // notes bumped to v2 THROUGH emit
        #expect(obj["store"] as? String == "notes")
        #expect(obj["count"] as? Int == rows.count)

        let rowObjs = try #require(obj["rows"] as? [[String: Any]])
        #expect(rowObjs[0]["body"] as? String == "decoded note text")   // decoded body ships verbatim
        #expect(rowObjs[1].keys.contains("body") == false)              // nil body → key OMITTED (M1)
        #expect(rowObjs[2]["body"] as? String == "")                    // locked withhold → present "" (M2)

        let decoded = try JSONDecoder().decode(ExportEnvelope<NoteRow>.self, from: data)
        #expect(decoded.schemaVersion == 2)
        #expect(decoded.rows == rows)
    }

    // MARK: 17 — non-notes stores stay schema_version 1 through the SAME emit path

    @Test func nonNotesExportStaysSchemaVersion1() throws {
        // messages/contacts/calls keep schema_version 1 (byte-stable goldens); only notes bumps. Proven
        // on the emit path so the per-store version carrier is exercised, not assumed.
        let messages = [
            MessageRow(body: "hi", date: "2026-01-01T00:00:00Z", service: "SMS",
                       isFromMe: false, sender: nil, chat: "c"),
        ]
        let dir = try Self.makeTempDir()
        defer { try? FileManager.default.removeItem(at: dir) }
        let out = dir.appendingPathComponent("messages.json").path
        try Backup.Export.emit(messages, store: "messages", format: .json, to: out, force: false)

        let obj = try #require(try JSONSerialization.jsonObject(
            with: Data(contentsOf: URL(fileURLWithPath: out))) as? [String: Any])
        #expect(obj["schema_version"] as? Int == 1)
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

    // MARK: K5 (Deau ruling) — folder truncates symmetrically with title/snippet

    @Test func redactTruncatesLongFolderSymmetricallyWithTitleAndSnippet() {
        // K5: folder truncates at previewBodyMax (40), grapheme-safe, with a trailing `…`, via the SAME
        // redactBody path title/snippet use — no separate truncated flag (RedactedNote records note-field
        // truncation solely by the `…` in the string). A folder of ≤ 40 passes through unchanged; the
        // 40-char boundary yields NO ellipsis (exactly as title/snippet).
        let longFolder = String(repeating: "F", count: 60)
        let r = InspectRedaction.redact(NoteRow(
            title: "t", snippet: "s", created: "2026-01-01T00:00:00Z",
            modified: "2026-01-01T00:00:00Z", folder: longFolder))
        #expect(r.folder == String(longFolder.prefix(InspectRedaction.previewBodyMax)) + "…")
        #expect(r.folder.count == InspectRedaction.previewBodyMax + 1)   // 40 kept + `…`
        #expect(r.folder.hasSuffix("…"))

        let exact40 = String(repeating: "G", count: InspectRedaction.previewBodyMax)
        let atBoundary = InspectRedaction.redact(NoteRow(
            title: "t", snippet: "s", created: nil, modified: nil, folder: exact40))
        #expect(atBoundary.folder == exact40)             // ≤ 40 unchanged
        #expect(!atBoundary.folder.hasSuffix("…"))        // no ellipsis at the boundary
    }

    @Test func noteTableAndJSONTruncateLongFolder() throws {
        // Both render paths consume the SAME redact() output, so the long folder truncates in the table
        // AND the --json envelope; the full folder appears in NEITHER. title/snippet are short here so the
        // only `…` source is the folder.
        let longFolder = String(repeating: "F", count: 60)
        let truncated = String(longFolder.prefix(InspectRedaction.previewBodyMax)) + "…"
        let rows = [
            NoteRow(title: "t", snippet: "s", created: "2026-01-01T00:00:00Z",
                    modified: "2026-01-01T00:00:00Z", folder: longFolder),
        ]
        let table = InspectRedaction.noteTable(rows, limit: 20).rendered()
        #expect(table.contains("…"))
        #expect(!table.contains(longFolder))

        let json = String(decoding: try JSONEncoder().encode(InspectRedaction.noteJSON(rows, limit: 20)), as: UTF8.self)
        #expect(json.contains(truncated))
        #expect(!json.contains(longFolder))
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

    // MARK: 19 — EXPORT-ONLY body policy (SOLVE §4): inspect carries NO body column, even with a body

    @Test func notesInspectHasNoBodyColumn() throws {
        // The body is disclosed ONLY on the consented export path. The inspect redaction projection has
        // no body field, so neither the table nor the --json envelope carries one — even when the
        // underlying NoteRow has a fully populated (sensitive) body. Reads InspectRedaction only; the
        // inspect no-body invariant stays byte-stable.
        let rows = [
            NoteRow(title: "t", snippet: "s", created: "2026-01-01T00:00:00Z",
                    modified: "2026-01-01T00:00:00Z", folder: "F", body: "sensitive decoded body"),
        ]
        #expect(!InspectRedaction.noteHeader.contains("body"))
        let table = InspectRedaction.noteTable(rows, limit: 20).rendered()
        #expect(!table.contains("sensitive decoded body"))
        let json = String(decoding: try JSONEncoder().encode(InspectRedaction.noteJSON(rows, limit: 20)), as: UTF8.self)
        #expect(!json.contains("\"body\""))
        #expect(!json.contains("sensitive decoded body"))
    }

    // MARK: 20 — a locked note's body is not disclosed in the export FILE (withheld "" ships faithfully)

    @Test func lockedNoteBodyNotDisclosedInExportFile() throws {
        // The reader withholds a locked note's body as "" at the SQL/marshal layer (proven in
        // NoteRowReaderTests); emit serializes that faithfully — the export file shows the locked note's
        // body as "" (present-empty), never a value. A sibling unlocked note's body ships in full, so the
        // "" is a deliberate withhold, not a blanket omission.
        let rows = [
            NoteRow(title: "Locked", snippet: "", created: "2026-01-01T00:00:00Z",
                    modified: "2026-01-01T00:00:00Z", folder: nil, body: ""),
            NoteRow(title: "Open", snippet: "s", created: "2026-01-01T00:00:00Z",
                    modified: "2026-01-01T00:00:00Z", folder: nil, body: "open note plaintext"),
        ]
        let dir = try Self.makeTempDir()
        defer { try? FileManager.default.removeItem(at: dir) }
        let out = dir.appendingPathComponent("notes.json").path
        try Backup.Export.emit(rows, store: "notes", format: .json, to: out, force: false)

        let decoded = try JSONDecoder().decode(ExportEnvelope<NoteRow>.self,
                                               from: Data(contentsOf: URL(fileURLWithPath: out)))
        #expect(decoded.schemaVersion == 2)
        #expect(decoded.rows[0].body == "")                     // locked → withheld ""
        #expect(decoded.rows[1].body == "open note plaintext")  // unlocked → full body
    }
}
