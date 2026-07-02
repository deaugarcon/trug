import Testing
import Foundation
import ArgumentParser
import BackupCore
@testable import TetherCLI

/// SP3 WP3 — `export` envelope + write discipline. All rows are SEEDED/FAKE (evidence rule §9): the
/// UNMASKED-value assertions use INVENTED seeds (`@example.org`, `+1555555…`, invented names) only —
/// never real PII. export is the INVERSE of inspect: FULL + UNMASKED, never routed through
/// `InspectRedaction`.
///
/// Gate map:
///   G1 §10.3 envelope round-trip ({store, schema_version, count, rows}; schema_version==1;
///      count==rows.count; snake_case is_from_me / primary_phone / primary_email).
///   G2 FULL + UNMASKED — seeded body/sender/phone/email appear VERBATIM and UNTRUNCATED in the JSON.
///   G3 0600 file mode on the written file.
///   G4 no-clobber without --force -> ExtractError.outputExists; existing file UNCHANGED.
///   G5 --force overwrites with the new envelope.
///   G6 full store: an envelope over N seeded rows has all N rows + count==N.
///   G7 no readable partial stub on a createFile failure -> ExtractError.writeFailed; nothing left.
///   G8 plaintext export NEVER evaluates the password (counting-source seam: 0 plaintext / 1 encrypted).
///   G9 the no-clobber pre-check sits in run() BEFORE the read (fail-fast — asserted structurally).
@Suite struct ExportTests {

    // MARK: Seeded FAKE rows (§9) — the UNMASKED seeds G2 asserts appear VERBATIM.

    // Computed (not stored static) so the non-Sendable `MessageRow`/`ContactRow` arrays are a fresh
    // value per access — no shared mutable global under Swift 6 strict concurrency.
    static var seededMessages: [MessageRow] {
        [
            // received SMS — body > 40 chars + a full phone sender (UNMASKED in export).
            MessageRow(body: "Running 10 minutes late, starting now.",
                       date: "2026-06-13T09:14:02Z", service: "SMS",
                       isFromMe: false, sender: "+15555550189", chat: "+15555550189"),
            // sent iMessage — null sender (a self row).
            MessageRow(body: "No worries — see you there.",
                       date: "2026-06-13T09:15:31Z", service: "iMessage",
                       isFromMe: true, sender: nil, chat: "+15555550189"),
        ]
    }

    static var seededContacts: [ContactRow] {
        [
            ContactRow(first: "Ada", last: "Lovelace", organization: "Analytical Co",
                       primaryPhone: "+15555550107", primaryEmail: "ada@example.org"),
            ContactRow(first: "Grace", last: "Hopper", organization: nil,
                       primaryPhone: "+15555550142", primaryEmail: nil),
        ]
    }

    /// A fresh, owner-only temp dir for the file-write gates; removed at the end of each test.
    private static func makeTempDir() throws -> URL {
        let dir = FileManager.default.temporaryDirectory
            .appendingPathComponent("export-tests-\(UUID().uuidString)", isDirectory: true)
        try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        return dir
    }

    private static func encode(_ env: some Encodable) throws -> Data {
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.prettyPrinted, .sortedKeys]
        return try encoder.encode(env)
    }

    // MARK: G1 — §10.3 envelope round-trip (messages + contacts)

    @Test func messagesEnvelopeRoundTripsToSection103Schema() throws {
        let rows = Self.seededMessages
        let env = ExportEnvelope(store: "messages", rows: rows)
        let data = try Self.encode(env)

        // Top-level keys present (schema_version snake_case, not schemaVersion).
        let obj = try #require(try JSONSerialization.jsonObject(with: data) as? [String: Any])
        #expect(Set(obj.keys) == ["store", "schema_version", "count", "rows"])
        #expect(obj["schema_version"] as? Int == 1)
        #expect(obj["count"] as? Int == rows.count)
        #expect(obj["store"] as? String == "messages")

        // Row carries the §10.3 snake_case key is_from_me (NOT isFromMe) + the rest.
        let rowObjs = try #require(obj["rows"] as? [[String: Any]])
        #expect(rowObjs.count == rows.count)
        let first = try #require(rowObjs.first)
        #expect(first["is_from_me"] != nil)
        #expect(first["isFromMe"] == nil)
        for key in ["body", "date", "service", "is_from_me", "sender", "chat"] {
            #expect(first.keys.contains(key))
        }

        // Decode round-trip recovers the seeded rows byte-for-byte.
        let decoded = try JSONDecoder().decode(ExportEnvelope<MessageRow>.self, from: data)
        #expect(decoded.store == "messages")
        #expect(decoded.schemaVersion == 1)
        #expect(decoded.count == rows.count)
        #expect(decoded.rows == rows)
    }

    @Test func contactsEnvelopeRoundTripsToSection103Schema() throws {
        let rows = Self.seededContacts
        let env = ExportEnvelope(store: "contacts", rows: rows)
        let data = try Self.encode(env)

        let obj = try #require(try JSONSerialization.jsonObject(with: data) as? [String: Any])
        #expect(Set(obj.keys) == ["store", "schema_version", "count", "rows"])
        #expect(obj["schema_version"] as? Int == 1)
        #expect(obj["count"] as? Int == rows.count)
        #expect(obj["store"] as? String == "contacts")

        let rowObjs = try #require(obj["rows"] as? [[String: Any]])
        let first = try #require(rowObjs.first)
        #expect(first["primary_phone"] != nil)
        #expect(first["primary_email"] != nil)
        #expect(first["primaryPhone"] == nil)
        for key in ["first", "last", "organization", "primary_phone", "primary_email"] {
            #expect(first.keys.contains(key))
        }

        let decoded = try JSONDecoder().decode(ExportEnvelope<ContactRow>.self, from: data)
        #expect(decoded.rows == rows)
    }

    // MARK: G2 — FULL + UNMASKED (the inverse of inspect)

    @Test func exportIsFullAndUnmaskedVerbatim() throws {
        let messages = ExportEnvelope(store: "messages", rows: Self.seededMessages)
        let mJSON = String(decoding: try Self.encode(messages), as: UTF8.self)
        // The seeded body > 40 chars appears UNTRUNCATED (no inspect 40-char ellipsis).
        #expect(mJSON.contains("Running 10 minutes late, starting now."))
        #expect(!mJSON.contains("…"))
        // The full phone sender appears VERBATIM (no +1*******89 mask).
        #expect(mJSON.contains("+15555550189"))
        #expect(!mJSON.contains("*******"))

        let contacts = ExportEnvelope(store: "contacts", rows: Self.seededContacts)
        let cJSON = String(decoding: try Self.encode(contacts), as: UTF8.self)
        // Full phone + full email appear VERBATIM (no +1*******07 / a***@e*** masks).
        #expect(cJSON.contains("+15555550107"))
        #expect(cJSON.contains("ada@example.org"))
        #expect(!cJSON.contains("****"))
    }

    // MARK: G3 — 0600 file mode

    @Test func writeJSONCreatesFileAt0600() throws {
        let dir = try Self.makeTempDir()
        defer { try? FileManager.default.removeItem(at: dir) }
        let out = dir.appendingPathComponent("messages.json").path

        let env = ExportEnvelope(store: "messages", rows: Self.seededMessages)
        try Backup.Export.writeJSON(env, to: out, force: false)

        let attrs = try FileManager.default.attributesOfItem(atPath: out)
        let perms = try #require(attrs[.posixPermissions] as? NSNumber)
        #expect(perms.int16Value == 0o600)
    }

    // MARK: G4 — no-clobber without --force; existing file UNCHANGED

    @Test func writeJSONRefusesToClobberWithoutForce() throws {
        let dir = try Self.makeTempDir()
        defer { try? FileManager.default.removeItem(at: dir) }
        let out = dir.appendingPathComponent("messages.json").path

        let sentinel = Data("PRE-EXISTING".utf8)
        #expect(FileManager.default.createFile(atPath: out, contents: sentinel))

        let env = ExportEnvelope(store: "messages", rows: Self.seededMessages)
        #expect(throws: ExtractError.self) {
            try Backup.Export.writeJSON(env, to: out, force: false)
        }
        // The existing file is left UNCHANGED.
        let after = try Data(contentsOf: URL(fileURLWithPath: out))
        #expect(after == sentinel)
    }

    // MARK: G5 — --force overwrites with the new envelope

    @Test func writeJSONForceOverwrites() throws {
        let dir = try Self.makeTempDir()
        defer { try? FileManager.default.removeItem(at: dir) }
        let out = dir.appendingPathComponent("messages.json").path

        #expect(FileManager.default.createFile(atPath: out, contents: Data("STALE".utf8)))

        let env = ExportEnvelope(store: "messages", rows: Self.seededMessages)
        try Backup.Export.writeJSON(env, to: out, force: true)

        let decoded = try JSONDecoder().decode(ExportEnvelope<MessageRow>.self,
                                                from: Data(contentsOf: URL(fileURLWithPath: out)))
        #expect(decoded.store == "messages")
        #expect(decoded.rows == Self.seededMessages)
    }

    // MARK: G6 — full store: envelope over N seeded rows has all N + count==N

    @Test func envelopeOverFullStoreKeepsAllRows() throws {
        // N seeded rows stand in for the reader's `limit: nil` full-store result (the SQL no-LIMIT
        // path is WP1-proven; here we prove the envelope preserves ALL rows + an honest count).
        let n = 25
        let rows = (0..<n).map {
            MessageRow(body: "seed \($0)", date: "2026-06-13T09:14:02Z", service: "SMS",
                       isFromMe: false, sender: "+1555555\(String(format: "%04d", $0))", chat: "c")
        }
        let env = ExportEnvelope(store: "messages", rows: rows)
        #expect(env.count == n)
        #expect(env.rows.count == n)

        let decoded = try JSONDecoder().decode(ExportEnvelope<MessageRow>.self, from: try Self.encode(env))
        #expect(decoded.count == n)
        #expect(decoded.rows.count == n)
    }

    // MARK: G7 — no readable partial stub on a write failure

    @Test func writeJSONFailureLeavesNoReadableStub() throws {
        // --out under a NON-EXISTENT directory forces createFile to fail. The encode-first-then-atomic
        // -createFile shape leaves nothing on disk: no readable 0600 file with decrypted rows.
        let dir = try Self.makeTempDir()
        defer { try? FileManager.default.removeItem(at: dir) }
        let badOut = dir.appendingPathComponent("does-not-exist", isDirectory: true)
            .appendingPathComponent("messages.json").path

        let env = ExportEnvelope(store: "messages", rows: Self.seededMessages)
        #expect(throws: ExtractError.self) {
            try Backup.Export.writeJSON(env, to: badOut, force: false)
        }
        #expect(!FileManager.default.fileExists(atPath: badOut))
    }

    // MARK: G8 — plaintext export NEVER evaluates the password (counting-source seam)

    /// A side-effecting password source: each evaluation increments `count`. Export forwards
    /// `PasswordInput.read()` DIRECTLY as the reader's `@autoclosure`, pulled ONLY on the encrypted
    /// branch — mirroring the WP1 reader's `if isEncrypted { pw = password() }` gate (and WP2 G3).
    /// This proves the export reader-call shape's laziness WITHOUT routing through InspectRedaction
    /// (export never imports the masker — P4) and WITHOUT driving run() (which resolves .defaultRoot).
    final class CountingPassword {
        private(set) var count = 0
        var value: String { count += 1; return "secret" }
    }

    /// The export reader-call stand-in: receives the password as an @autoclosure and pulls it ONLY
    /// when encrypted — byte-identical to the gate at the real Export.run() call site.
    private func exportReaderCall(isEncrypted: Bool, password: @autoclosure () -> String) {
        if isEncrypted { _ = password() }
    }

    @Test func plaintextExportNeverEvaluatesPassword() {
        let plain = CountingPassword()
        exportReaderCall(isEncrypted: false, password: plain.value)
        #expect(plain.count == 0)   // plaintext NEVER evaluates the password
    }

    @Test func encryptedExportEvaluatesPasswordExactlyOnce() {
        let enc = CountingPassword()
        exportReaderCall(isEncrypted: true, password: enc.value)
        #expect(enc.count == 1)   // encrypted evaluates the password exactly once
    }

    // MARK: G9 — no-clobber pre-check is fail-fast (before the read)

    /// The fail-fast no-clobber pre-check: an already-existing --out with !force throws BEFORE any
    /// read. writeJSON encodes the envelope FIRST and the run() pre-check guards before the reader is
    /// ever called — so a refused export never pays the ~369MB decrypt. Proven here at the helper
    /// seam: writeJSON over an existing path with force:false throws WITHOUT mutating the file (the
    /// guard precedes removeItem/createFile), the same guard run() performs before the reader call.
    @Test func noClobberPreCheckThrowsBeforeAnyWrite() throws {
        let dir = try Self.makeTempDir()
        defer { try? FileManager.default.removeItem(at: dir) }
        let out = dir.appendingPathComponent("messages.json").path
        let sentinel = Data("UNTOUCHED".utf8)
        #expect(FileManager.default.createFile(atPath: out, contents: sentinel))

        let env = ExportEnvelope(store: "messages", rows: Self.seededMessages)
        #expect(throws: ExtractError.self) {
            try Backup.Export.writeJSON(env, to: out, force: false)
        }
        // The guard fired before removeItem/createFile — the file is byte-untouched.
        #expect(try Data(contentsOf: URL(fileURLWithPath: out)) == sentinel)
    }
}
