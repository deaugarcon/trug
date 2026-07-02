import Testing
import Foundation
import ArgumentParser
import BackupCore
@testable import TetherCLI

/// SP3.1 WP-A (B3) — `inspect calls` redaction + `export calls` envelope. All rows are SEEDED/FAKE
/// (evidence rule §9): invented NANP 555 numbers and fabricated dates/durations only. inspect is the
/// redacted preview; export is the FULL + UNMASKED inverse (never routed through InspectRedaction).
///
/// Gate map:
///   E1  §10.1 envelope round-trip ({store, schema_version, count, rows}; call_type snake_case key).
///   E2  export is FULL + UNMASKED — the seeded address appears VERBATIM (no +1*******89 mask).
///   E3  M1 — a nil date exports with NO "date" key and NO fabricated 2001 epoch.
///   I1  inspect callTable is redacted — the address is masked, never raw.
///   I2  inspect callJSON is capped + redacted with preview keys; raw address absent.
///   I3  redact(CallRow) masks address, passes duration/direction/call_type; nil date → (none) (M1).
///   W1  the `calls` selector parses on both inspect and export; it is in Store.allCases.
@Suite struct CallInspectExportTests {

    // Computed (not stored static) so the non-Sendable CallRow array is a fresh value per access.
    static var seededCalls: [CallRow] {
        [
            CallRow(address: "+15555550189", date: "2026-06-14T18:02:11Z", duration: 372,
                    direction: "outgoing", callType: "voice"),
            CallRow(address: "+15555550188", date: "2026-06-14T09:47:03Z", duration: 0,
                    direction: "incoming", callType: "facetime_video"),
        ]
    }

    private static func encode(_ env: some Encodable) throws -> Data {
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.prettyPrinted, .sortedKeys]
        return try encoder.encode(env)
    }

    // MARK: E1 — §10.1 envelope round-trip

    @Test func callsEnvelopeRoundTripsToSection101Schema() throws {
        let rows = Self.seededCalls
        let env = ExportEnvelope(store: "calls", rows: rows)
        let data = try Self.encode(env)

        let obj = try #require(try JSONSerialization.jsonObject(with: data) as? [String: Any])
        #expect(Set(obj.keys) == ["store", "schema_version", "count", "rows"])
        #expect(obj["schema_version"] as? Int == 1)
        #expect(obj["count"] as? Int == rows.count)
        #expect(obj["store"] as? String == "calls")

        // Row carries the §10.1 snake_case key call_type (NOT callType) + the rest.
        let rowObjs = try #require(obj["rows"] as? [[String: Any]])
        #expect(rowObjs.count == rows.count)
        let first = try #require(rowObjs.first)
        #expect(first["call_type"] != nil)
        #expect(first["callType"] == nil)
        for key in ["address", "date", "duration", "direction", "call_type"] {
            #expect(first.keys.contains(key))
        }

        // Decode round-trip recovers the seeded rows byte-for-byte.
        let decoded = try JSONDecoder().decode(ExportEnvelope<CallRow>.self, from: data)
        #expect(decoded.store == "calls")
        #expect(decoded.schemaVersion == 1)
        #expect(decoded.count == rows.count)
        #expect(decoded.rows == rows)
    }

    // MARK: E2 — FULL + UNMASKED (the inverse of inspect)

    @Test func exportIsFullAndUnmaskedVerbatim() throws {
        let env = ExportEnvelope(store: "calls", rows: Self.seededCalls)
        let json = String(decoding: try Self.encode(env), as: UTF8.self)
        // The full address appears VERBATIM (no +1*******89 mask); call_type is present unmasked.
        #expect(json.contains("+15555550189"))
        #expect(!json.contains("*******"))
        #expect(json.contains("facetime_video"))
    }

    // MARK: E3 — M1: a nil date exports with no "date" key and no fabricated epoch

    @Test func exportOfNullDateCallHasNoFabricatedEpoch() throws {
        let row = CallRow(address: "+15555550199", date: nil, duration: 10,
                          direction: "incoming", callType: nil)
        let env = ExportEnvelope(store: "calls", rows: [row])
        let data = try Self.encode(env)
        let json = String(decoding: data, as: UTF8.self)
        // The fabricated 2001 epoch NEVER appears; the optional date/call_type keys are simply omitted.
        #expect(!json.contains("2001-01-01T00:00:00Z"))

        // Round-trip preserves the nil date (missing key decodes to nil, not the epoch).
        let decoded = try JSONDecoder().decode(ExportEnvelope<CallRow>.self, from: data)
        #expect(decoded.rows.first?.date == nil)
        #expect(decoded.rows.first?.callType == nil)
    }

    // MARK: I3 — redact(CallRow): address masked, rest passed through; nil date → (none)

    @Test func redactMasksAddressAndPassesTheRest() {
        let r = InspectRedaction.redact(Self.seededCalls[0])
        #expect(r.address != "+15555550189")   // masked, never raw
        #expect(r.address.contains("*"))
        #expect(r.when == "2026-06-14T18:02:11Z")   // date passes through
        #expect(r.duration == "372")
        #expect(r.direction == "outgoing")
        #expect(r.callType == "voice")
    }

    @Test func redactNilDateRendersNoneNeverEpoch() {
        // M1 at the CLI layer: a nil date renders (none), never a fabricated epoch string.
        let r = InspectRedaction.redact(CallRow(address: nil, date: nil, duration: 0,
                                                direction: "incoming", callType: nil))
        #expect(r.when == "(none)")
        #expect(r.address == "(none)")        // nil address → (none)
        #expect(r.callType == "(none)")       // nil call_type → (none)
    }

    // MARK: I1 — inspect callTable is redacted (no raw seeds)

    @Test func callTableRendersMaskedNeverRaw() {
        let table = InspectRedaction.callTable(Self.seededCalls, limit: 20).rendered()
        #expect(!table.contains("+15555550189"))   // masked, never the raw address
        #expect(!table.contains("+15555550188"))
        #expect(table.contains("outgoing"))         // non-sensitive fields pass through
    }

    // odb R-new-1 — every redacted row is fixed-arity matching the header (TextTable traps otherwise).
    @Test func callTableRowsAreFixedArity() {
        let header = InspectRedaction.callHeader
        let table = InspectRedaction.callTable(Self.seededCalls, limit: 20)
        for row in table.rows { #expect(row.count == header.count) }
    }

    // MARK: I2 — inspect callJSON is capped + redacted with preview keys

    @Test func callJSONIsRedactedWithPreviewKeys() throws {
        let envelope = InspectRedaction.callJSON(Self.seededCalls, limit: 20)
        #expect(envelope.store == "calls")
        #expect(envelope.preview == true)
        #expect(envelope.shown == Self.seededCalls.count)
        #expect(envelope.total == nil)   // OI1: no fabricated total
        let encoded = String(decoding: try JSONEncoder().encode(envelope), as: UTF8.self)
        #expect(!encoded.contains("+15555550189"))   // raw address absent
        #expect(encoded.contains("call_type"))       // snake_case preview key present
        #expect(encoded.contains("direction"))
    }

    // MARK: W1 — the `calls` selector parses on inspect + export; it is in Store.allCases

    @Test func callsSelectorParsesOnInspectAndExport() throws {
        let inspect = try Backup.Inspect.parse(["UDID", "calls"])
        #expect(inspect.store == .calls)
        let export = try Backup.Export.parse(["UDID", "calls", "--out", "/tmp/does-not-matter"])
        #expect(export.store == .calls)
    }

    @Test func callsIsAnInScopeStore() {
        #expect(Backup.Inspect.Store.allCases.contains(.calls))
        #expect(Backup.Export.Store.allCases.contains(.calls))
    }
}
