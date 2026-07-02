import Foundation

/// The SP3 §10.3 export envelope: a generic Encodable wrapper around the reader's already-§10.3-Codable
/// rows. `MessageRow`/`ContactRow` (BackupCore) carry the §10.3 snake_case `CodingKeys`
/// (`is_from_me`/`primary_phone`/`primary_email`), so encoding `[MessageRow]`/`[ContactRow]` directly
/// emits the locked row schema byte-for-byte — NO presentation wrapper, NO key remap. The envelope adds
/// only the store-independent `{store, schema_version, count, rows}` header.
///
/// `count` is DERIVED from `rows.count` in the initializer, so it can never disagree with `rows`
/// (impossible-state-unrepresentable). Rows pass through VERBATIM — NO redaction, NO truncation:
/// `export` is the explicit full-data path (Invariant P4); masking is an `inspect`-only preview
/// property and this envelope never touches `InspectRedaction`.
struct ExportEnvelope<Row: Encodable>: Encodable {
    let store: String
    let schemaVersion: Int
    let count: Int
    let rows: [Row]

    /// §10.3 spells the version key `schema_version`; the rest already match.
    enum CodingKeys: String, CodingKey {
        case store
        case schemaVersion = "schema_version"
        case count
        case rows
    }

    /// `count` is derived from `rows.count` so the two can never disagree. `schemaVersion` defaults to
    /// the current SP3-owned schema integer (1) — the forward-evolution marker for downstream readers.
    init(store: String, schemaVersion: Int = 1, rows: [Row]) {
        self.store = store
        self.schemaVersion = schemaVersion
        self.count = rows.count
        self.rows = rows
    }
}

/// Decodable conformance for the round-trip TESTS only (the production path is encode-only). Mirrors
/// the same §10.3 keys so a decoded envelope recovers `{store, schema_version, count, rows}`.
extension ExportEnvelope: Decodable where Row: Decodable {
    init(from decoder: Decoder) throws {
        let c = try decoder.container(keyedBy: CodingKeys.self)
        self.store = try c.decode(String.self, forKey: .store)
        self.schemaVersion = try c.decode(Int.self, forKey: .schemaVersion)
        self.count = try c.decode(Int.self, forKey: .count)
        self.rows = try c.decode([Row].self, forKey: .rows)
    }
}
