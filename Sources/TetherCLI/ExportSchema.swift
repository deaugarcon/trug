import Foundation
import BackupCore

/// SP3.2 — the per-store export `schema_version`, carried at the TYPE so a store's version is a
/// compile-time property rather than an emit-site literal (impossible-states-unrepresentable). Declared
/// in TetherCLI (the presentation seam) with RETROACTIVE conformances, so the BackupCore rows stay
/// unedited — exactly as `CSVRow` does. Because the protocol is declared in THIS module, the
/// conformances raise no Swift-6 retroactive-conformance warning (the "0 new warnings" gate holds).
protocol ExportSchemaVersioned {
    /// The §10.2/§10.3 `schema_version` for this row's export envelope.
    static var exportSchemaVersion: Int { get }
}

/// The SP3-era default is v1. messages/contacts/calls keep it (their goldens stay byte-stable); only
/// notes overrides. A new store adding a schema-affecting field bumps its own type, nothing else.
extension ExportSchemaVersioned {
    static var exportSchemaVersion: Int { 1 }
}

extension MessageRow: ExportSchemaVersioned {}
extension ContactRow: ExportSchemaVersioned {}
extension CallRow: ExportSchemaVersioned {}

/// SP3.2 bumps NOTES to v2: the envelope now carries the decoded `body`. The version exists precisely
/// so a downstream consumer detects the schema change from the SP3.1 preview (v1, no body) to the
/// SP3.2 body (v2) — spec §10.2/§10.3.
extension NoteRow: ExportSchemaVersioned {
    static var exportSchemaVersion: Int { 2 }
}
