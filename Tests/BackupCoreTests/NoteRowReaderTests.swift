import Testing
import Foundation
@testable import BackupCore

/// SP3.1 WP-B (B4) — notes reader (K3 title/metadata preview scope; NO body). All rows are
/// SEEDED/FAKE (evidence rule §9): invented titles/snippets/dates only. No real note appears.
///
/// Gate map (SOLVE §E B4 + §G H1 + lead consistency reqs):
///   G1  notes() join → count + seeded-row equality, ordered by ZMODIFICATIONDATE1 DESC.
///   H1  the discriminator resolves ICNote's Z_ENT BY NAME from Z_PRIMARYKEY (M1) — title-bearing
///       FOLDER/ACCOUNT and NULL-title MEDIA rows are EXCLUDED (Odb H1: NOT ZTITLE1 IS NOT NULL). This
///       is the non-vacuous discriminator gate; the by-name resolution is the device-portability fix.
///   K4  folder self-join resolves the folder NAME; an unfiled note → folder nil.
///   M1d NULL ZCREATIONDATE1/ZMODIFICATIONDATE1 → nil (never a fabricated epoch); genuine 0 → epoch.
///   B6  a locked note's (ZISPASSWORDPROTECTED=1) ZSNIPPET is WITHHELD at the SQL layer regardless of
///       stored bytes; its title stays listable (M2 defensive hardening).
///   P3  SQL-layer cap (limit:2 over >2 rows; limit:nil = full).
///   P1  encrypted read reaches the same rows; plaintext never evaluates the password.
@Suite struct NoteRowReaderTests {

    // MARK: Seeded FAKE rows (§9)

    /// Three FAKE notes: two in the "Shopping" folder (one most-recently modified), and one unfiled
    /// (NULL ZFOLDER → folder nil). Dates are seconds-since-2001. The builder ALSO seeds a title-bearing
    /// folder row ("Shopping") and a title-bearing account row ("Fixture iCloud") — H1's exclusion targets.
    static let seededNotes: [FixtureBuilder.SeededNote] = [
        .init(title: "Groceries", snippet: "milk, eggs, flour",
              createdAppleEpochSeconds: 100, modifiedAppleEpochSeconds: 300,
              folderName: "Shopping", locked: false),
        .init(title: "Trip ideas", snippet: "coast road, ferry timetable",
              createdAppleEpochSeconds: 50, modifiedAppleEpochSeconds: 200,
              folderName: "Shopping", locked: false),
        .init(title: "Random thought", snippet: "remember to call the plumber",
              createdAppleEpochSeconds: 10, modifiedAppleEpochSeconds: 100,
              folderName: nil, locked: false),
    ]

    static let notesDomain = "AppDomainGroup-group.com.apple.notes"
    static let notesPath = "NoteStore.sqlite"

    private static func seededBackupRoot(_ notes: [FixtureBuilder.SeededNote]) throws -> URL {
        let bytes = try FixtureBuilder.noteStoreBytes(notes: notes)
        return try FixtureBuilder.unencryptedBackupWithStore(
            udid: "U", domain: notesDomain, path: notesPath, storeBytes: bytes)
    }

    // MARK: G1 — notes join (count + seeded equality, ordered ZMODIFICATIONDATE1 DESC)

    @Test func notesJoinReturnsSeededRows() throws {
        let root = try Self.seededBackupRoot(Self.seededNotes)
        defer { try? FileManager.default.removeItem(at: root) }

        let rows = try BackupRowReader().notes(
            udidDir: root.appendingPathComponent("U"), password: "", limit: nil)

        #expect(rows.count == Self.seededNotes.count)
        // Ordered by ZMODIFICATIONDATE1 DESC — Groceries (modified 300) is first.
        #expect(rows[0] == NoteRow(
            title: "Groceries", snippet: "milk, eggs, flour",
            created: CoreDataDateNormalizer.normalize(appleEpochSeconds: 100),
            modified: CoreDataDateNormalizer.normalize(appleEpochSeconds: 300),
            folder: "Shopping"))
        #expect(rows[1].title == "Trip ideas")
        #expect(rows[1].folder == "Shopping")
        // The unfiled note comes last (modified 100) and has NO folder.
        #expect(rows[2].title == "Random thought")
        #expect(rows[2].folder == nil)
    }

    // MARK: H1 — the discriminator is Z_ENT; title-bearing folders + accounts are EXCLUDED

    @Test func discriminatorExcludesTitleBearingFoldersAndAccounts() throws {
        let root = try Self.seededBackupRoot(Self.seededNotes)
        defer { try? FileManager.default.removeItem(at: root) }

        let rows = try BackupRowReader().notes(
            udidDir: root.appendingPathComponent("U"), password: "", limit: nil)

        // Only the NOTE rows return — the title-bearing folder + account rows are filtered by Z_ENT,
        // NOT by title-nullness (which would leak folders/accounts as notes — the H1 trap).
        #expect(rows.count == Self.seededNotes.count)
        let titles = rows.compactMap(\.title)
        #expect(!titles.contains("Fixture iCloud"))   // the account row (has a title) is NOT a note
        #expect(!titles.contains("Shopping"))         // the folder row (has a title) is NOT a note
        // "Shopping" still legitimately appears as a FOLDER NAME (the K4 join), just never as a note.
        #expect(rows.contains { $0.folder == "Shopping" })
    }

    // MARK: M1 — ICNote entity resolved BY NAME (Z_PRIMARYKEY), NOT a hardcoded code; MEDIA decoy excluded

    @Test func icNoteEntityResolvedByNameExcludesMediaDecoy() throws {
        // The fixture mirrors the iOS-27 device: Z_PRIMARYKEY maps ICNote→12 (the real notes) and
        // ICMedia→11 (a NULL-title decoy at the code the reader USED to hardcode). A reader that
        // hardcodes 11 returns ONLY the decoy and drops every real note (the fixture-green/device-dead
        // trap); the by-name resolution returns exactly the real notes and excludes the decoy.
        let root = try Self.seededBackupRoot(Self.seededNotes)
        defer { try? FileManager.default.removeItem(at: root) }

        let rows = try BackupRowReader().notes(
            udidDir: root.appendingPathComponent("U"), password: "", limit: nil)

        #expect(rows.count == Self.seededNotes.count)               // all real notes, no decoy leak
        #expect(rows.allSatisfy { $0.title != nil })                // the NULL-title MEDIA decoy is absent
        #expect(Set(rows.compactMap(\.title)) == Set(Self.seededNotes.compactMap(\.title)))
    }

    // MARK: K4 — folder self-join resolves the name; unfiled note → nil

    @Test func folderSelfJoinResolvesNameAndNilWhenUnfiled() throws {
        let root = try Self.seededBackupRoot(Self.seededNotes)
        defer { try? FileManager.default.removeItem(at: root) }

        let rows = try BackupRowReader().notes(
            udidDir: root.appendingPathComponent("U"), password: "", limit: nil)
        // Filed notes resolve the folder name; the unfiled note (NULL ZFOLDER) LEFT-JOINs to nil.
        #expect(rows.filter { $0.folder == "Shopping" }.count == 2)
        #expect(rows.filter { $0.folder == nil }.count == 1)
    }

    // MARK: M1 — note dates: NULL → nil (never fabricated epoch); genuine 0 → epoch

    @Test func nullNoteDatesSurfaceAsNilNeverFabricateEpoch() throws {
        let root = try Self.seededBackupRoot([
            .init(title: "No dates", snippet: "s", createdAppleEpochSeconds: nil,
                  modifiedAppleEpochSeconds: nil, folderName: nil, locked: false),
        ])
        defer { try? FileManager.default.removeItem(at: root) }

        let rows = try BackupRowReader().notes(
            udidDir: root.appendingPathComponent("U"), password: "", limit: nil)
        #expect(rows.count == 1)
        #expect(rows[0].created == nil)                        // surfaced as nil
        #expect(rows[0].modified == nil)
        #expect(rows[0].created != "2001-01-01T00:00:00Z")    // NOT the fabricated epoch
        #expect(rows[0].title == "No dates")                  // the rest of the row is still read
    }

    @Test func genuineZeroNoteDatesSurfaceEpochNotNil() throws {
        // The OTHER half of the M1 discriminator (parity with B3 Q1): a genuine stored 0 is the real
        // 2001 epoch, NOT nil — guards against a future refactor treating 0 as a missing sentinel.
        let root = try Self.seededBackupRoot([
            .init(title: "Epoch note", snippet: "s", createdAppleEpochSeconds: 0,
                  modifiedAppleEpochSeconds: 0, folderName: nil, locked: false),
        ])
        defer { try? FileManager.default.removeItem(at: root) }

        let rows = try BackupRowReader().notes(
            udidDir: root.appendingPathComponent("U"), password: "", limit: nil)
        #expect(rows.count == 1)
        #expect(rows[0].created == "2001-01-01T00:00:00Z")   // real epoch, NOT nil
        #expect(rows[0].modified == "2001-01-01T00:00:00Z")
    }

    // Normalizer-level both-halves pin (shared CoreDataDateNormalizer, same as B3 — restated for notes).
    @Test func coreDataDateNormalizerZeroAndNullHalvesForNotes() {
        #expect(CoreDataDateNormalizer.normalize(appleEpochSeconds: 0) == "2001-01-01T00:00:00Z")
        #expect(CoreDataDateNormalizer.normalize(appleEpochSeconds: nil) == nil)
    }

    // MARK: B6 — locked-note snippet withholding (fixture-representable; device-verify)

    @Test func lockedNoteSnippetWithheldInFixtureB6MustConfirmOnDevice() throws {
        // The fixture models the SAFE device behavior: a password-protected note's ZSNIPPET is
        // withheld (empty). device-verify(B6): confirm the real device does NOT retain pre-lock
        // plaintext in ZSNIPPET; if it can, notesSelect needs a `ZISPASSWORDPROTECTED = 0` predicate.
        let root = try Self.seededBackupRoot([
            .init(title: "Locked note", snippet: "", createdAppleEpochSeconds: 100,
                  modifiedAppleEpochSeconds: 100, folderName: nil, locked: true),
        ])
        defer { try? FileManager.default.removeItem(at: root) }

        let rows = try BackupRowReader().notes(
            udidDir: root.appendingPathComponent("U"), password: "", limit: nil)
        #expect(rows.count == 1)
        #expect(rows[0].snippet == "")   // snippet withheld in the fixture (B6 confirms on device)
    }

    @Test func lockedNoteWithStoredSnippetIsWithheld() throws {
        // The UNSAFE device case B6 flagged: a password-protected note whose ZSNIPPET still holds
        // pre-lock plaintext (iOS 27 measured empty, but other devices/iOS majors are unmeasured). The
        // reader must WITHHOLD the snippet at the SQL layer regardless of the stored bytes, while the
        // title stays listable. A reader without the ZISPASSWORDPROTECTED guard would leak the snippet.
        let root = try Self.seededBackupRoot([
            .init(title: "Locked with snippet", snippet: "pre-lock preview text",
                  createdAppleEpochSeconds: 100, modifiedAppleEpochSeconds: 100,
                  folderName: nil, locked: true),
        ])
        defer { try? FileManager.default.removeItem(at: root) }

        let rows = try BackupRowReader().notes(
            udidDir: root.appendingPathComponent("U"), password: "", limit: nil)
        #expect(rows.count == 1)
        #expect(rows[0].title == "Locked with snippet")     // the title is legitimately listable
        #expect(rows[0].snippet == "")                      // snippet WITHHELD despite stored bytes
        #expect(rows[0].snippet != "pre-lock preview text") // the stored plaintext never leaks
    }

    // MARK: P3 — SQL-layer cap

    @Test func limitCapsAtSQLLayer() throws {
        #expect(Self.seededNotes.count > 2)
        let root = try Self.seededBackupRoot(Self.seededNotes)
        defer { try? FileManager.default.removeItem(at: root) }

        let capped = try BackupRowReader().notes(
            udidDir: root.appendingPathComponent("U"), password: "", limit: 2)
        #expect(capped.count == 2)

        let all = try BackupRowReader().notes(
            udidDir: root.appendingPathComponent("U"), password: "", limit: nil)
        #expect(all.count == Self.seededNotes.count)
    }

    @Test func limitIsInTheSQLString() {
        let cappedSQL = BackupRowReader.Schema.notesSelect(limit: 2)
        let fullSQL = BackupRowReader.Schema.notesSelect(limit: nil)
        #expect(cappedSQL.contains("LIMIT 2"))
        #expect(!fullSQL.contains("LIMIT"))
        // The H1 discriminator resolves ICNote's entity code BY NAME from Z_PRIMARYKEY (M1) — not a
        // hardcoded integer, not title-nullness. This is the device-portability fix.
        #expect(cappedSQL.contains("o.Z_ENT = (SELECT Z_ENT FROM Z_PRIMARYKEY WHERE Z_NAME = 'ICNote')"))
        #expect(!cappedSQL.contains("ZTITLE1 IS NOT NULL"))
        // M2: a locked note's snippet is WITHHELD at the SQL layer (ZISPASSWORDPROTECTED guard).
        #expect(cappedSQL.contains("CASE WHEN o.ZISPASSWORDPROTECTED = 1 THEN '' ELSE o.ZSNIPPET END"))
        // The seconds normalizer's CAST lock is visible (same as calls).
        #expect(cappedSQL.contains("CAST(o.ZCREATIONDATE1 AS INTEGER)"))
    }

    // MARK: P1 — encrypted read + lazy password

    @Test func encryptedFixtureReadReachesSameRows() throws {
        let bytes = try FixtureBuilder.noteStoreBytes(notes: Self.seededNotes)
        let (root, udid, password) = try FixtureBuilder.encryptedBackupWithStore(
            domain: Self.notesDomain, path: Self.notesPath, storeBytes: bytes)
        defer { try? FileManager.default.removeItem(at: root) }

        let rows = try BackupRowReader().notes(
            udidDir: root.appendingPathComponent(udid), password: password, limit: nil)
        #expect(rows.count == Self.seededNotes.count)
        #expect(rows[0].title == "Groceries")
    }

    /// A side-effecting password source: proves a plaintext notes read never evaluates the password and
    /// the encrypted path evaluates it exactly once — identical to the messages/calls laziness contract.
    final class CountingPassword {
        private(set) var count = 0
        let secret: String
        init(secret: String) { self.secret = secret }
        var value: String { count += 1; return secret }
    }

    @Test func plaintextReadNeverEvaluatesPassword() throws {
        let root = try Self.seededBackupRoot(Self.seededNotes)
        defer { try? FileManager.default.removeItem(at: root) }

        let plaintextPw = CountingPassword(secret: "should-never-be-read")
        let plaintextRows = try BackupRowReader().notes(
            udidDir: root.appendingPathComponent("U"), password: plaintextPw.value, limit: nil)
        #expect(plaintextRows.count == Self.seededNotes.count)
        #expect(plaintextPw.count == 0)   // NEVER evaluated on the plaintext path

        let bytes = try FixtureBuilder.noteStoreBytes(notes: Self.seededNotes)
        let (encRoot, udid, password) = try FixtureBuilder.encryptedBackupWithStore(
            domain: Self.notesDomain, path: Self.notesPath, storeBytes: bytes)
        defer { try? FileManager.default.removeItem(at: encRoot) }

        let encryptedPw = CountingPassword(secret: password)
        let encryptedRows = try BackupRowReader().notes(
            udidDir: encRoot.appendingPathComponent(udid), password: encryptedPw.value, limit: nil)
        #expect(encryptedRows.count == Self.seededNotes.count)
        #expect(encryptedPw.count == 1)   // evaluated exactly once on the encrypted path
    }
}

/// P1 for notes — no decrypted `tether-rows-*` temp survives a handled exit. SERIALIZED (WP1 pattern).
@Suite(.serialized) struct NoteRowReaderTempInvariantTests {
    @Test func noTempSurvivesNormalRead() throws {
        let bytes = try FixtureBuilder.noteStoreBytes(notes: NoteRowReaderTests.seededNotes)
        let root = try FixtureBuilder.unencryptedBackupWithStore(
            udid: "U", domain: NoteRowReaderTests.notesDomain,
            path: NoteRowReaderTests.notesPath, storeBytes: bytes)
        defer { try? FileManager.default.removeItem(at: root) }

        let before = TempInvariant.rowsTemps()
        _ = try BackupRowReader().notes(
            udidDir: root.appendingPathComponent("U"), password: "", limit: nil)
        // Settle the delta (bounded poll) so a concurrent suite's mid-flight temp clears; a true leak persists.
        #expect(TempInvariant.newTempsSurviving(since: before).isEmpty)
    }
}
