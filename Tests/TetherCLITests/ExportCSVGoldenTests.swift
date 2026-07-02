import Testing
import Foundation
import ArgumentParser
import BackupCore
@testable import TetherCLI

/// SP3.1 WP-C (B5) — byte-exact CSV goldens per store + the shared 0600 write core. Goldens are built
/// IN-TEST as `Data` with explicit `\r\n` (Odb M3): NO checked-in `.csv` files, so no `core.autocrlf`/
/// git-EOL normalization can silently break the byte comparison. All rows are SEEDED/FAKE (§9): invented
/// 555 numbers, names, and note text only.
///
/// LOAD-BEARING, INTENTIONAL (K6 RATIFIED): every `+`-leading phone/address becomes `'+…`, and a
/// `-`/`@`-leading note title/snippet becomes `'-…`/`'@…`. These apostrophes are the ratified
/// formula-injection neutralization — NOT a bug. Do NOT "fix" them; JSON stays the lossless format.
@Suite struct ExportCSVGoldenTests {

    // Computed (fresh non-Sendable value per access).
    static var seededMessages: [MessageRow] {
        [
            MessageRow(body: "Running late, now", date: "2026-06-13T09:14:02Z", service: "SMS",
                       isFromMe: false, sender: "+15555550189", chat: "+15555550189"),
            MessageRow(body: "No worries", date: "2026-06-13T09:15:31Z", service: "iMessage",
                       isFromMe: true, sender: nil, chat: "+15555550189"),
        ]
    }
    static var seededContacts: [ContactRow] {
        [
            ContactRow(first: "Ada", last: "Lovelace", organization: "Analytical, Co",
                       primaryPhone: "+15555550107", primaryEmail: "ada@example.org"),
            ContactRow(first: "Grace", last: "Hopper", organization: nil,
                       primaryPhone: "+15555550142", primaryEmail: nil),
        ]
    }
    static var seededCalls: [CallRow] {
        [
            CallRow(address: "+15555550123", date: "2026-06-14T18:02:11Z", duration: 372,
                    direction: "outgoing", callType: "voice"),
            CallRow(address: "+15555550188", date: nil, duration: 0, direction: "incoming", callType: nil),
        ]
    }
    static var seededNotes: [NoteRow] {
        [
            // dash-leading title (M4) + comma-containing snippet.
            NoteRow(title: "- shopping list", snippet: "milk, eggs",
                    created: "2026-05-30T14:00:00Z", modified: "2026-06-13T08:12:00Z", folder: "Shopping"),
            // @-leading title (M4) + quote-containing snippet + nil folder.
            NoteRow(title: "@mentions", snippet: "say \"hi\"",
                    created: "2026-04-02T19:20:00Z", modified: "2026-06-01T21:05:00Z", folder: nil),
        ]
    }

    /// Builds the expected CSV bytes with explicit CRLF terminators (M3: in-test Data literal).
    private static func golden(_ lines: [String]) -> Data {
        Data(lines.map { $0 + "\r\n" }.joined().utf8)
    }

    private static func makeTempDir() throws -> URL {
        let dir = FileManager.default.temporaryDirectory
            .appendingPathComponent("csv-golden-\(UUID().uuidString)", isDirectory: true)
        try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        return dir
    }

    private static func encodeCSV(_ rows: [some CSVRow]) -> Data {
        CSVEncoder.encode(header: type(of: rows[0]).csvHeader, rows: rows.map(\.csvFields))
    }

    // MARK: byte-exact goldens per store

    @Test func messagesGoldenIsByteExact() {
        let expected = Self.golden([
            "body,date,service,is_from_me,sender,chat",
            "\"Running late, now\",2026-06-13T09:14:02Z,SMS,false,'+15555550189,'+15555550189",
            "No worries,2026-06-13T09:15:31Z,iMessage,true,,'+15555550189",
        ])
        #expect(Self.encodeCSV(Self.seededMessages) == expected)
    }

    @Test func contactsGoldenIsByteExact() {
        let expected = Self.golden([
            "first,last,organization,primary_phone,primary_email",
            "Ada,Lovelace,\"Analytical, Co\",'+15555550107,ada@example.org",
            "Grace,Hopper,,'+15555550142,",
        ])
        #expect(Self.encodeCSV(Self.seededContacts) == expected)
    }

    @Test func callsGoldenIsByteExact() {
        let expected = Self.golden([
            "address,date,duration,direction,call_type",
            "'+15555550123,2026-06-14T18:02:11Z,372,outgoing,voice",
            "'+15555550188,,0,incoming,",
        ])
        #expect(Self.encodeCSV(Self.seededCalls) == expected)
    }

    @Test func notesGoldenIsByteExactWithDashAndAtLeadingNeutralized() {
        // M4: the dash- and @-leading titles are neutralized to '-… / '@…; the comma snippet is quoted;
        // the quote snippet is doubled+quoted. This is the ratified K6 mutation, not corruption.
        let expected = Self.golden([
            "title,snippet,created,modified,folder",
            "'- shopping list,\"milk, eggs\",2026-05-30T14:00:00Z,2026-06-13T08:12:00Z,Shopping",
            "'@mentions,\"say \"\"hi\"\"\",2026-04-02T19:20:00Z,2026-06-01T21:05:00Z,",
        ])
        #expect(Self.encodeCSV(Self.seededNotes) == expected)
    }

    // MARK: --format csv writes 0600, no-clobber, --force (shared writeGuarded core)

    @Test func writeCSVCreatesFileAt0600() throws {
        let dir = try Self.makeTempDir()
        defer { try? FileManager.default.removeItem(at: dir) }
        let out = dir.appendingPathComponent("calls.csv").path
        try Backup.Export.writeCSV(header: CallRow.csvHeader,
                                   rows: Self.seededCalls.map(\.csvFields), to: out, force: false)
        let attrs = try FileManager.default.attributesOfItem(atPath: out)
        #expect((attrs[.posixPermissions] as? NSNumber)?.int16Value == 0o600)
        // The written bytes are the byte-exact golden.
        #expect(try Data(contentsOf: URL(fileURLWithPath: out)) == Self.encodeCSV(Self.seededCalls))
    }

    @Test func writeCSVRefusesToClobberWithoutForce() throws {
        let dir = try Self.makeTempDir()
        defer { try? FileManager.default.removeItem(at: dir) }
        let out = dir.appendingPathComponent("calls.csv").path
        let sentinel = Data("PRE-EXISTING".utf8)
        #expect(FileManager.default.createFile(atPath: out, contents: sentinel))

        #expect(throws: ExtractError.self) {
            try Backup.Export.writeCSV(header: CallRow.csvHeader,
                                       rows: Self.seededCalls.map(\.csvFields), to: out, force: false)
        }
        #expect(try Data(contentsOf: URL(fileURLWithPath: out)) == sentinel)   // untouched
    }

    @Test func writeCSVForceOverwrites() throws {
        let dir = try Self.makeTempDir()
        defer { try? FileManager.default.removeItem(at: dir) }
        let out = dir.appendingPathComponent("calls.csv").path
        #expect(FileManager.default.createFile(atPath: out, contents: Data("STALE".utf8)))

        try Backup.Export.writeCSV(header: CallRow.csvHeader,
                                   rows: Self.seededCalls.map(\.csvFields), to: out, force: true)
        #expect(try Data(contentsOf: URL(fileURLWithPath: out)) == Self.encodeCSV(Self.seededCalls))
    }

    @Test func writeCSVFailureLeavesNoReadableStub() throws {
        let dir = try Self.makeTempDir()
        defer { try? FileManager.default.removeItem(at: dir) }
        let badOut = dir.appendingPathComponent("nope", isDirectory: true)
            .appendingPathComponent("calls.csv").path
        #expect(throws: ExtractError.self) {
            try Backup.Export.writeCSV(header: CallRow.csvHeader,
                                       rows: Self.seededCalls.map(\.csvFields), to: badOut, force: false)
        }
        #expect(!FileManager.default.fileExists(atPath: badOut))
    }

    // MARK: JSON path stays byte-stable through the refactor (regression net)

    @Test func jsonPathIsByteStableAfterRefactor() throws {
        // writeJSON must still produce EXACTLY pretty+sorted ExportEnvelope bytes — the P4 refactor
        // (writeJSON = encode + writeGuarded) did not change the JSON output.
        let dir = try Self.makeTempDir()
        defer { try? FileManager.default.removeItem(at: dir) }
        let out = dir.appendingPathComponent("messages.json").path

        let env = ExportEnvelope(store: "messages", rows: Self.seededMessages)
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.prettyPrinted, .sortedKeys]
        let expected = try encoder.encode(env)

        try Backup.Export.writeJSON(env, to: out, force: false)
        #expect(try Data(contentsOf: URL(fileURLWithPath: out)) == expected)
    }

    // MARK: emit routes json vs csv to the same disk core

    @Test func emitRoutesCsvAndJsonToTheSameCore() throws {
        let dir = try Self.makeTempDir()
        defer { try? FileManager.default.removeItem(at: dir) }

        let csvOut = dir.appendingPathComponent("calls.csv").path
        try Backup.Export.emit(Self.seededCalls, store: "calls", format: .csv, to: csvOut, force: false)
        #expect(try Data(contentsOf: URL(fileURLWithPath: csvOut)) == Self.encodeCSV(Self.seededCalls))
        #expect((try FileManager.default.attributesOfItem(atPath: csvOut)[.posixPermissions]
                 as? NSNumber)?.int16Value == 0o600)

        let jsonOut = dir.appendingPathComponent("calls.json").path
        try Backup.Export.emit(Self.seededCalls, store: "calls", format: .json, to: jsonOut, force: false)
        let decoded = try JSONDecoder().decode(ExportEnvelope<CallRow>.self,
                                               from: Data(contentsOf: URL(fileURLWithPath: jsonOut)))
        #expect(decoded.store == "calls")
        #expect(decoded.rows == Self.seededCalls)
    }
}
