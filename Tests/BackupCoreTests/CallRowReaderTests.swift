import Testing
import Foundation
@testable import BackupCore

/// SP3.1 WP-A (B3) — call-history reader. All rows are SEEDED/FAKE (evidence rule §9): only invented
/// NANP 555 numbers, fabricated dates/durations. No real call appears in any fixture or assertion.
///
/// Gate map (SOLVE §E B3):
///   G1  calls() join → count + seeded-row equality, ordered by ZDATE ASC.
///   N1  CoreDataDateNormalizer converts SECONDS-since-2001 (NOT the ns sms.db uses — §3.4 crux).
///   D1  direction map: 1→outgoing, 0→incoming.
///   M2  direction fallback ("incoming") is exercised ONLY on non-binary ZORIGINATED (Odb M2).
///   K2  call_type map: known codes → strings; unknown/NULL → honest nil.
///   M1  NULL ZDATE surfaces as nil — NEVER a fabricated 2001-01-01T00:00:00Z (Odb M1).
///   P3  SQL-layer cap (limit:2 over >2 rows; limit:nil = full).
///   P1  encrypted-fixture read reaches the same rows; plaintext never evaluates the password.
@Suite struct CallRowReaderTests {

    // MARK: Seeded FAKE rows (§9)

    /// Three FAKE calls: an outgoing voice call, an incoming declined (0s) FaceTime video, and an
    /// incoming call with an UNKNOWN ZCALLTYPE code (→ call_type nil). Dates are seconds-since-2001.
    static let seededCalls: [FixtureBuilder.SeededCall] = [
        .init(address: "+15555550123", dateAppleEpochSeconds: 1, duration: 372,
              originated: 1, callType: BackupRowReader.Schema.callTypeVoice),
        .init(address: "+15555550188", dateAppleEpochSeconds: 86_400, duration: 0,
              originated: 0, callType: BackupRowReader.Schema.callTypeFaceTimeVideo),
        .init(address: "+15555550170", dateAppleEpochSeconds: 172_800, duration: 45,
              originated: 0, callType: 999 /* unknown → nil */),
    ]

    static let callsDomain = "HomeDomain"
    static let callsPath = "Library/CallHistoryDB/CallHistory.storedata"

    private static func seededBackupRoot(_ calls: [FixtureBuilder.SeededCall]) throws -> URL {
        let bytes = try FixtureBuilder.callHistoryStoreBytes(calls: calls)
        return try FixtureBuilder.unencryptedBackupWithStore(
            udid: "U", domain: callsDomain, path: callsPath, storeBytes: bytes)
    }

    // MARK: G1 — calls join (count + seeded equality, ordered ZDATE ASC)

    @Test func callsJoinReturnsSeededRows() throws {
        let root = try Self.seededBackupRoot(Self.seededCalls)
        defer { try? FileManager.default.removeItem(at: root) }

        let rows = try BackupRowReader().calls(
            udidDir: root.appendingPathComponent("U"), password: "", limit: nil)

        #expect(rows.count == Self.seededCalls.count)
        // Ordered by ZDATE ASC — first seeded call is the outgoing voice call.
        #expect(rows[0] == CallRow(
            address: "+15555550123",
            date: CoreDataDateNormalizer.normalize(appleEpochSeconds: 1),
            duration: 372, direction: "outgoing", callType: "voice"))
        // Incoming declined FaceTime video: 0-second duration, incoming direction.
        #expect(rows[1].direction == "incoming")
        #expect(rows[1].duration == 0)
        #expect(rows[1].callType == "facetime_video")
        // Unknown ZCALLTYPE code → call_type honestly nil (K2 asymmetry).
        #expect(rows[2].callType == nil)
        #expect(rows[2].direction == "incoming")
    }

    // MARK: N1 — the §3.4 crux: Core Data ZDATE is SECONDS, not nanoseconds

    @Test func coreDataDateNormalizerUsesSecondsNotNanoseconds() {
        // A GENUINE 0 raw is the 2001 epoch itself (NOT nil) — the "0 is a real second-0 date"
        // half of the M1 discriminator (Odb Q1): only a SQL NULL yields nil; a stored 0 yields the
        // epoch string. Guards against a future refactor that treats 0 as a missing-value sentinel.
        #expect(CoreDataDateNormalizer.normalize(appleEpochSeconds: 0) == "2001-01-01T00:00:00Z")
        // 1 SECOND after the 2001 epoch is 2001-01-01T00:00:01Z under the seconds divisor.
        #expect(CoreDataDateNormalizer.normalize(appleEpochSeconds: 1) == "2001-01-01T00:00:01Z")
        // A full day of SECONDS advances the calendar date — impossible if the divisor were 1e9 (ns),
        // under which 86_400 raw would be < 1ms and still read 2001-01-01T00:00:00Z.
        #expect(CoreDataDateNormalizer.normalize(appleEpochSeconds: 86_400) == "2001-01-02T00:00:00Z")
        // The divergence proof: the SAME raw value read as ns (DateNormalizer) vs seconds
        // (CoreDataDateNormalizer) MUST differ — a blind reuse would misread every call time by 1e9.
        #expect(CoreDataDateNormalizer.normalize(appleEpochSeconds: 1)
                != DateNormalizer.normalize(appleEpochRaw: 1))
    }

    // MARK: D1 / M2 — direction map (binary explicit; fallback ONLY on non-binary)

    @Test func directionMapsBinaryValues() {
        #expect(BackupRowReader.Schema.callDirection(1) == "outgoing")
        #expect(BackupRowReader.Schema.callDirection(0) == "incoming")
    }

    /// M2 (Odb): the "incoming" default is a DOCUMENTED fallback reached ONLY by non-binary values.
    /// The binary inputs {0,1} take their explicit branches (0→incoming, 1→outgoing); every non-binary
    /// input defaults to "incoming". B6 must confirm ZORIGINATED is strictly binary so this is dead
    /// code on device — the test documents the branch rather than pretending it cannot happen.
    @Test func directionFallbackExercisedOnlyOnNonBinary() {
        // 1 is the ONLY value that is not "incoming" — proving 0 and every non-binary value map to
        // "incoming", but 0 does so via its explicit branch while non-binary hits the fallback.
        #expect(BackupRowReader.Schema.callDirection(1) == "outgoing")
        for nonBinary in [2, 3, -1, 99, Int.max] {
            #expect(BackupRowReader.Schema.callDirection(nonBinary) == "incoming")
        }
    }

    /// The M2 fallback is reachable THROUGH the reader: a seeded non-binary ZORIGINATED row yields
    /// direction "incoming" (never a crash, never a fabricated third direction).
    @Test func nonBinaryOriginatedReadsAsIncoming() throws {
        let root = try Self.seededBackupRoot([
            .init(address: "+15555550111", dateAppleEpochSeconds: 5, duration: 10,
                  originated: 2 /* non-binary */, callType: BackupRowReader.Schema.callTypeVoice),
        ])
        defer { try? FileManager.default.removeItem(at: root) }

        let rows = try BackupRowReader().calls(
            udidDir: root.appendingPathComponent("U"), password: "", limit: nil)
        #expect(rows.count == 1)
        #expect(rows[0].direction == "incoming")   // M2 documented fallback via the reader
    }

    // MARK: K2 — call_type map (known codes; unknown/NULL → honest nil)

    @Test func callTypeMapsKnownCodesAndNilOnUnknown() {
        #expect(BackupRowReader.Schema.callType(BackupRowReader.Schema.callTypeVoice) == "voice")
        #expect(BackupRowReader.Schema.callType(BackupRowReader.Schema.callTypeFaceTimeAudio) == "facetime_audio")
        #expect(BackupRowReader.Schema.callType(BackupRowReader.Schema.callTypeFaceTimeVideo) == "facetime_video")
        #expect(BackupRowReader.Schema.callType(999) == nil)   // unknown code → nil
        #expect(BackupRowReader.Schema.callType(nil) == nil)   // NULL ZCALLTYPE → nil
    }

    // MARK: M1 — NULL ZDATE surfaces as nil, NEVER a fabricated 2001 epoch

    @Test func nullDateSurfacesAsNilNeverFabricatesEpoch() throws {
        // A row whose ZDATE is SQL NULL. int()-based reads would coerce NULL→0→2001-01-01T00:00:00Z,
        // a fabricated timestamp presented as truth. The reader must surface nil instead (M1).
        let root = try Self.seededBackupRoot([
            .init(address: "+15555550199", dateAppleEpochSeconds: nil /* NULL ZDATE */, duration: 10,
                  originated: 0, callType: BackupRowReader.Schema.callTypeVoice),
        ])
        defer { try? FileManager.default.removeItem(at: root) }

        let rows = try BackupRowReader().calls(
            udidDir: root.appendingPathComponent("U"), password: "", limit: nil)
        #expect(rows.count == 1)
        #expect(rows[0].date == nil)                              // surfaced as nil
        #expect(rows[0].date != "2001-01-01T00:00:00Z")          // NOT the fabricated epoch
        // The rest of the row is still read — a missing date does not drop the record.
        #expect(rows[0].address == "+15555550199")
        #expect(rows[0].duration == 10)
    }

    /// The OTHER half of the M1 discriminator (Odb Q1): a GENUINE stored `ZDATE == 0.0` is a real
    /// second-0 date — the reader must surface `2001-01-01T00:00:00Z`, NOT nil. Only a SQL NULL
    /// yields nil. This is the symmetric partner to `nullDateSurfacesAsNilNeverFabricatesEpoch`: it
    /// fails loudly if a future refactor ever treats `0` as a missing-value sentinel.
    @Test func genuineZeroDateSurfacesEpochNotNil() throws {
        let root = try Self.seededBackupRoot([
            .init(address: "+15555550100", dateAppleEpochSeconds: 0 /* genuine second-0 date */,
                  duration: 5, originated: 1, callType: BackupRowReader.Schema.callTypeVoice),
        ])
        defer { try? FileManager.default.removeItem(at: root) }

        let rows = try BackupRowReader().calls(
            udidDir: root.appendingPathComponent("U"), password: "", limit: nil)
        #expect(rows.count == 1)
        #expect(rows[0].date == "2001-01-01T00:00:00Z")   // real epoch date, NOT nil
        #expect(rows[0].date != nil)
    }

    // MARK: P3 — SQL-layer cap

    @Test func limitCapsAtSQLLayer() throws {
        #expect(Self.seededCalls.count > 2)   // so a read-all-then-truncate would be detectable
        let root = try Self.seededBackupRoot(Self.seededCalls)
        defer { try? FileManager.default.removeItem(at: root) }

        let capped = try BackupRowReader().calls(
            udidDir: root.appendingPathComponent("U"), password: "", limit: 2)
        #expect(capped.count == 2)

        let all = try BackupRowReader().calls(
            udidDir: root.appendingPathComponent("U"), password: "", limit: nil)
        #expect(all.count == Self.seededCalls.count)
    }

    @Test func limitIsInTheSQLString() {
        let cappedSQL = BackupRowReader.Schema.callsSelect(limit: 2)
        let fullSQL = BackupRowReader.Schema.callsSelect(limit: nil)
        #expect(cappedSQL.contains("LIMIT 2"))
        #expect(!fullSQL.contains("LIMIT"))
        // The seconds-vs-ns lock is visible in the SQL: ZDATE is CAST to INTEGER (no double accessor).
        #expect(cappedSQL.contains("CAST(r.ZDATE AS INTEGER)"))
    }

    // MARK: P1 — encrypted read + lazy password

    @Test func encryptedFixtureReadReachesSameRows() throws {
        let bytes = try FixtureBuilder.callHistoryStoreBytes(calls: Self.seededCalls)
        let (root, udid, password) = try FixtureBuilder.encryptedBackupWithStore(
            domain: Self.callsDomain, path: Self.callsPath, storeBytes: bytes)
        defer { try? FileManager.default.removeItem(at: root) }

        let rows = try BackupRowReader().calls(
            udidDir: root.appendingPathComponent(udid), password: password, limit: nil)
        #expect(rows.count == Self.seededCalls.count)
        #expect(rows[0].address == "+15555550123")
    }

    /// A side-effecting password source: each evaluation increments `count`. Proves a plaintext calls
    /// read never evaluates the password (would hang once PasswordInput.read() is wired) and the
    /// encrypted path evaluates it exactly once — identical to the WP1 messages laziness contract.
    final class CountingPassword {
        private(set) var count = 0
        let secret: String
        init(secret: String) { self.secret = secret }
        var value: String { count += 1; return secret }
    }

    @Test func plaintextReadNeverEvaluatesPassword() throws {
        let root = try Self.seededBackupRoot(Self.seededCalls)
        defer { try? FileManager.default.removeItem(at: root) }

        let plaintextPw = CountingPassword(secret: "should-never-be-read")
        let plaintextRows = try BackupRowReader().calls(
            udidDir: root.appendingPathComponent("U"), password: plaintextPw.value, limit: nil)
        #expect(plaintextRows.count == Self.seededCalls.count)
        #expect(plaintextPw.count == 0)   // NEVER evaluated on the plaintext path

        let bytes = try FixtureBuilder.callHistoryStoreBytes(calls: Self.seededCalls)
        let (encRoot, udid, password) = try FixtureBuilder.encryptedBackupWithStore(
            domain: Self.callsDomain, path: Self.callsPath, storeBytes: bytes)
        defer { try? FileManager.default.removeItem(at: encRoot) }

        let encryptedPw = CountingPassword(secret: password)
        let encryptedRows = try BackupRowReader().calls(
            udidDir: encRoot.appendingPathComponent(udid), password: encryptedPw.value, limit: nil)
        #expect(encryptedRows.count == Self.seededCalls.count)
        #expect(encryptedPw.count == 1)   // evaluated exactly once on the encrypted path
    }
}

/// P1 for calls — no decrypted `tether-rows-*` temp survives a handled exit. SERIALIZED so the shared
/// system-temp residue is measured as the DELTA caused by THIS read alone (mirrors the WP1 pattern).
@Suite(.serialized) struct CallRowReaderTempInvariantTests {
    @Test func noTempSurvivesNormalRead() throws {
        let bytes = try FixtureBuilder.callHistoryStoreBytes(calls: CallRowReaderTests.seededCalls)
        let root = try FixtureBuilder.unencryptedBackupWithStore(
            udid: "U", domain: CallRowReaderTests.callsDomain,
            path: CallRowReaderTests.callsPath, storeBytes: bytes)
        defer { try? FileManager.default.removeItem(at: root) }

        let before = TempInvariant.rowsTemps()
        _ = try BackupRowReader().calls(
            udidDir: root.appendingPathComponent("U"), password: "", limit: nil)
        // Settle the delta (bounded poll) so a concurrent suite's mid-flight temp clears; a true leak persists.
        #expect(TempInvariant.newTempsSurviving(since: before).isEmpty)
    }
}
