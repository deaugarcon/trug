import Foundation
import SQLite3

/// SQLite asks the binder to copy bound text rather than assume the buffer outlives the step.
private let SQLITE_TRANSIENT = unsafeBitCast(-1, to: sqlite3_destructor_type.self)

/// Minimal read-only SQLite wrapper: open, prepare, step, typed column access.
/// Scoped to what `ManifestReader` needs against a backup's `Manifest.db` —
/// `SELECT … FROM Files` and the table-name probe used by readability verify.
///
/// IMMUTABLE-ONLY: the initializer opens via an `immutable=1` URI, which is correct ONLY for a
/// backup-resident db that must never be written (see `init`). A future feature that needs a
/// WRITABLE SQLite db must NOT reuse this initializer — `immutable=1` would silently drop writes
/// and ignore any WAL. Add a separate writable path rather than relaxing this one. (Odb R2.)
final class SQLiteDB {
    private var handle: OpaquePointer?

    /// Opens a backup-resident SQLite db read-only via an `immutable=1` URI.
    ///
    /// A real iOS 27 device delivers `Manifest.db` in WAL journal mode (header bytes 18-19 == 02 02)
    /// with no `-wal`/`-shm` sidecars (checkpoint B). A plain `SQLITE_OPEN_READONLY` open of such a
    /// file fails `SQLITE_CANTOPEN(14)`: read-only cannot create the `-shm` shared-memory file a WAL
    /// db needs. `immutable=1` tells SQLite the file will not change underneath it, so it reads the
    /// main db pages directly without ever touching the WAL machinery — and, crucially, never WRITES
    /// into the backup (an `-shm` creation would mutate the snapshot we are only meant to read).
    /// `immutable=1` is therefore the only correct mode for a backup-resident db.
    ///
    /// GUARD: because `immutable=1` silently IGNORES any `-wal` sidecar content, a `<db>-wal` sitting
    /// next to the file would mean committed-but-uncheckpointed pages are dropped — a stale snapshot.
    /// Real device delivery checkpoints the WAL and ships no sidecar, so a present `-wal` is anomalous
    /// and is surfaced as `manifestUnreadable` rather than read silently stale.
    init(path: String) throws {
        let walSidecar = path + "-wal"
        if FileManager.default.fileExists(atPath: walSidecar) {
            throw VerifyError.manifestUnreadable(reason:
                "a write-ahead-log sidecar exists next to \(path); immutable=1 would ignore it and read a stale snapshot")
        }
        guard let uri = Self.immutableURI(forPath: path) else {
            throw VerifyError.manifestUnreadable(reason: "could not form a file: URI for \(path)")
        }
        guard sqlite3_open_v2(uri, &handle, SQLITE_OPEN_READONLY | SQLITE_OPEN_URI, nil) == SQLITE_OK else {
            let message = handle.map { String(cString: sqlite3_errmsg($0)) } ?? "unknown error"
            sqlite3_close(handle)   // open_v2 may hand back a handle even on failure
            handle = nil
            throw VerifyError.manifestUnreadable(reason: "sqlite3_open failed for \(path): \(message)")
        }
    }

    /// Builds a `file:` URI with `immutable=1&mode=ro` from a filesystem path. The path is
    /// percent-encoded so spaces ("Application Support") and other URI-reserved characters in a
    /// backup root survive intact; the `?` query separator is appended after encoding so the query
    /// keys are not themselves encoded.
    static func immutableURI(forPath path: String) -> String? {
        // Encode everything that is not unreserved/path-safe. `/` is kept so the path structure
        // survives; `?`, `#`, `&`, space, etc. are encoded so they cannot be read as URI syntax.
        var allowed = CharacterSet.alphanumerics
        allowed.insert(charactersIn: "/-._~")
        guard let encoded = path.addingPercentEncoding(withAllowedCharacters: allowed) else { return nil }
        return "file:\(encoded)?immutable=1&mode=ro"
    }

    deinit { sqlite3_close(handle) }

    /// Runs `sql`, invoking `row` once per result row. Text binds are positional, 1-based.
    func query(_ sql: String, bind: [String] = [], _ row: (Row) -> Void) throws {
        var stmt: OpaquePointer?
        guard sqlite3_prepare_v2(handle, sql, -1, &stmt, nil) == SQLITE_OK else {
            let message = handle.map { String(cString: sqlite3_errmsg($0)) } ?? "unknown error"
            throw VerifyError.manifestUnreadable(reason: "prepare failed (\(message)): \(sql)")
        }
        defer { sqlite3_finalize(stmt) }
        for (i, value) in bind.enumerated() {
            sqlite3_bind_text(stmt, Int32(i + 1), value, -1, SQLITE_TRANSIENT)
        }
        // Iterate until the step result stops being a row, then demand that the loop ended
        // because the result set was exhausted (SQLITE_DONE) — not because a corrupt/hostile
        // Manifest.db errored mid-iteration. Treating a non-DONE terminator as "no more rows"
        // would present a silently truncated enumeration as a complete, smaller backup.
        var result = sqlite3_step(stmt)
        while result == SQLITE_ROW {
            row(Row(stmt: stmt))
            result = sqlite3_step(stmt)
        }
        guard result == SQLITE_DONE else {
            let message = handle.map { String(cString: sqlite3_errmsg($0)) } ?? "unknown error"
            throw VerifyError.manifestUnreadable(reason: "step failed mid-iteration (code \(result): \(message)): \(sql)")
        }
    }

    /// Table names in the database — used by readability verification.
    func tableNames() throws -> Set<String> {
        var names = Set<String>()
        try query("SELECT name FROM sqlite_master WHERE type='table'") { row in
            if let name = row.text(0) { names.insert(name) }
        }
        return names
    }

    /// Typed accessors over the current step's columns. Valid only inside the `query` callback.
    struct Row {
        let stmt: OpaquePointer?
        func text(_ i: Int32) -> String? { sqlite3_column_text(stmt, i).map { String(cString: $0) } }
        func int(_ i: Int32) -> Int { Int(sqlite3_column_int64(stmt, i)) }
        func blob(_ i: Int32) -> Data? {
            guard let pointer = sqlite3_column_blob(stmt, i) else { return nil }
            return Data(bytes: pointer, count: Int(sqlite3_column_bytes(stmt, i)))
        }
    }
}
