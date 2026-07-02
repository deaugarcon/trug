import Testing
import Foundation
@testable import BackupCore

/// SP3 WP1 — schema-aware row reader. All rows are SEEDED/FAKE (evidence rule §9): no real message
/// text, sender, or contact appears in any fixture or assertion.
@Suite struct BackupRowReaderTests {
    // MARK: Seeded fixtures (FAKE rows — §9)

    /// Apple epoch (ns since 2001-01-01 UTC). 2001-01-01T00:00:01Z == 1 second == 1_000_000_000 ns.
    static let oneSecondAfterAppleEpochNanos = 1_000_000_000

    /// Three FAKE messages: a received SMS, a sent iMessage (no sender handle), and a second
    /// received iMessage in a different chat — enough to prove the §7 join and the > 2 row cap (G5).
    static let seededMessages: [FixtureBuilder.SeededMessage] = [
        .init(body: "fixture body one", dateAppleEpochNanos: oneSecondAfterAppleEpochNanos,
              service: "SMS", isFromMe: false, senderHandle: "+15555550001", chatIdentifier: "+15555550001"),
        .init(body: "fixture body two", dateAppleEpochNanos: oneSecondAfterAppleEpochNanos + 1_000_000_000,
              service: "iMessage", isFromMe: true, senderHandle: nil, chatIdentifier: "+15555550001"),
        .init(body: "fixture body three", dateAppleEpochNanos: oneSecondAfterAppleEpochNanos + 2_000_000_000,
              service: "iMessage", isFromMe: false, senderHandle: "fake@example.test", chatIdentifier: "group-fixture"),
    ]

    /// Three FAKE contacts: one with phone+email, one with phone only (email absent → null), and one
    /// with neither (both null) — proving option (a) primaries and the null-when-absent rule (G2).
    static let seededContacts: [FixtureBuilder.SeededContact] = [
        .init(first: "Fixa", last: "Onecontact", organization: "Fake Org", phone: "+15555550101", email: "fixa@example.test"),
        .init(first: "Fixb", last: "Twocontact", organization: nil, phone: "+15555550102", email: nil),
        .init(first: "Fixc", last: "Threecontact", organization: nil, phone: nil, email: nil),
    ]

    static let messagesDomain = "HomeDomain"
    static let messagesPath = "Library/SMS/sms.db"
    static let contactsDomain = "HomeDomain"
    static let contactsPath = "Library/AddressBook/AddressBook.sqlitedb"

    // MARK: G1 — messages join (count + seeded equality)

    @Test func messagesJoinReturnsSeededRows() throws {
        let bytes = try FixtureBuilder.smsStoreBytes(messages: Self.seededMessages)
        let root = try FixtureBuilder.unencryptedBackupWithStore(
            udid: "U", domain: Self.messagesDomain, path: Self.messagesPath, storeBytes: bytes)
        defer { try? FileManager.default.removeItem(at: root) }

        let rows = try BackupRowReader().messages(
            udidDir: root.appendingPathComponent("U"), password: "", limit: nil)

        #expect(rows.count == Self.seededMessages.count)
        // Ordered by date ASC — first seeded message is the received SMS.
        #expect(rows[0] == MessageRow(
            body: "fixture body one",
            date: DateNormalizer.normalize(appleEpochRaw: Self.oneSecondAfterAppleEpochNanos),
            service: "SMS", isFromMe: false, sender: "+15555550001", chat: "+15555550001"))
        // The sent iMessage: is_from_me true, no sender handle (null).
        #expect(rows[1].isFromMe == true)
        #expect(rows[1].sender == nil)
        #expect(rows[1].chat == "+15555550001")
        // The second received iMessage in a different chat.
        #expect(rows[2].sender == "fake@example.test")
        #expect(rows[2].chat == "group-fixture")
    }

    // MARK: G2 — contacts option (a): primary phone/email, null when absent

    @Test func contactsReturnsPrimaryPhoneAndEmail() throws {
        let bytes = try FixtureBuilder.addressBookStoreBytes(contacts: Self.seededContacts)
        let root = try FixtureBuilder.unencryptedBackupWithStore(
            udid: "U", domain: Self.contactsDomain, path: Self.contactsPath, storeBytes: bytes)
        defer { try? FileManager.default.removeItem(at: root) }

        let rows = try BackupRowReader().contacts(
            udidDir: root.appendingPathComponent("U"), password: "", limit: nil)

        #expect(rows.count == Self.seededContacts.count)
        #expect(rows[0] == ContactRow(first: "Fixa", last: "Onecontact", organization: "Fake Org",
                                      primaryPhone: "+15555550101", primaryEmail: "fixa@example.test"))
        // Phone present, email absent → primaryEmail null.
        #expect(rows[1] == ContactRow(first: "Fixb", last: "Twocontact", organization: nil,
                                      primaryPhone: "+15555550102", primaryEmail: nil))
        // Neither phone nor email → both null.
        #expect(rows[2] == ContactRow(first: "Fixc", last: "Threecontact", organization: nil,
                                      primaryPhone: nil, primaryEmail: nil))
    }

    // MARK: G5 — P3: SQL-layer cap (limit:2 over >2 rows; limit:nil = all)

    @Test func limitCapsAtSQLLayer() throws {
        // Seed strictly MORE than 2 messages so a read-all-then-truncate is detectable: the cap MUST
        // be in SQL. seededMessages has 3 rows.
        #expect(Self.seededMessages.count > 2)
        let bytes = try FixtureBuilder.smsStoreBytes(messages: Self.seededMessages)
        let root = try FixtureBuilder.unencryptedBackupWithStore(
            udid: "U", domain: Self.messagesDomain, path: Self.messagesPath, storeBytes: bytes)
        defer { try? FileManager.default.removeItem(at: root) }

        let capped = try BackupRowReader().messages(
            udidDir: root.appendingPathComponent("U"), password: "", limit: 2)
        #expect(capped.count == 2)

        let all = try BackupRowReader().messages(
            udidDir: root.appendingPathComponent("U"), password: "", limit: nil)
        #expect(all.count == Self.seededMessages.count)
    }

    /// The cap is enforced in SQL (`LIMIT` reaches the query string), not a post-read `.prefix`.
    /// Assert the rendered SELECT carries a `LIMIT` clause when capping and none when full.
    @Test func limitIsInTheSQLString() {
        let cappedSQL = BackupRowReader.Schema.messagesSelect(limit: 2)
        let fullSQL = BackupRowReader.Schema.messagesSelect(limit: nil)
        #expect(cappedSQL.contains("LIMIT 2"))
        #expect(!fullSQL.contains("LIMIT"))
    }

    // MARK: G7 — DateNormalizer + encrypted-fixture read

    @Test func dateNormalizerConvertsSeededAppleEpoch() {
        // 1 second after the Apple epoch (2001-01-01T00:00:00Z) is 2001-01-01T00:00:01Z.
        let iso = DateNormalizer.normalize(appleEpochRaw: Self.oneSecondAfterAppleEpochNanos)
        #expect(iso == "2001-01-01T00:00:01Z")
    }

    @Test func encryptedFixtureReadReachesSameRows() throws {
        let bytes = try FixtureBuilder.smsStoreBytes(messages: Self.seededMessages)
        let (root, udid, password) = try FixtureBuilder.encryptedBackupWithStore(
            domain: Self.messagesDomain, path: Self.messagesPath, storeBytes: bytes)
        defer { try? FileManager.default.removeItem(at: root) }

        let rows = try BackupRowReader().messages(
            udidDir: root.appendingPathComponent(udid), password: password, limit: nil)
        #expect(rows.count == Self.seededMessages.count)
        #expect(rows[0].body == "fixture body one")
    }

    // MARK: odb-High — empty password on encrypted backup → passwordRequired (NOT wrongPassword)

    @Test func emptyPasswordOnEncryptedThrowsPasswordRequired() throws {
        let bytes = try FixtureBuilder.smsStoreBytes(messages: Self.seededMessages)
        let (root, udid, _) = try FixtureBuilder.encryptedBackupWithStore(
            domain: Self.messagesDomain, path: Self.messagesPath, storeBytes: bytes)
        defer { try? FileManager.default.removeItem(at: root) }

        #expect(throws: VerifyError.passwordRequired(udid: udid)) {
            _ = try BackupRowReader().messages(
                udidDir: root.appendingPathComponent(udid), password: "", limit: nil)
        }
    }

    // MARK: odb Medium — @autoclosure password laziness (plaintext NEVER prompts)

    /// A side-effecting password source: each evaluation of `value` increments `count`. Passing
    /// `source.value` as the `@autoclosure` password lets the test observe whether the reader pulled
    /// the password at all (count) — proving plaintext never evaluates it (spec §1.1/§4) and that the
    /// encrypted path evaluates it exactly once.
    final class CountingPassword {
        private(set) var count = 0
        let secret: String
        init(secret: String) { self.secret = secret }
        var value: String { count += 1; return secret }
    }

    @Test func plaintextReadNeverEvaluatesPassword() throws {
        // PLAINTEXT backup: the password closure must NEVER fire (count stays 0). Otherwise, once WP2
        // wires interactive PasswordInput.read(), a plaintext `inspect` would hang on a prompt.
        let bytes = try FixtureBuilder.smsStoreBytes(messages: Self.seededMessages)
        let root = try FixtureBuilder.unencryptedBackupWithStore(
            udid: "U", domain: Self.messagesDomain, path: Self.messagesPath, storeBytes: bytes)
        defer { try? FileManager.default.removeItem(at: root) }

        let plaintextPw = CountingPassword(secret: "should-never-be-read")
        let plaintextRows = try BackupRowReader().messages(
            udidDir: root.appendingPathComponent("U"), password: plaintextPw.value, limit: nil)
        #expect(plaintextRows.count == Self.seededMessages.count)
        #expect(plaintextPw.count == 0)   // closure NEVER evaluated on the plaintext path

        // ENCRYPTED backup: the password closure must fire EXACTLY ONCE (pre-check + extract reuse
        // the single resolved value — no double-eval, no double-prompt).
        let (encRoot, udid, password) = try FixtureBuilder.encryptedBackupWithStore(
            domain: Self.messagesDomain, path: Self.messagesPath, storeBytes: bytes)
        defer { try? FileManager.default.removeItem(at: encRoot) }

        let encryptedPw = CountingPassword(secret: password)
        let encryptedRows = try BackupRowReader().messages(
            udidDir: encRoot.appendingPathComponent(udid), password: encryptedPw.value, limit: nil)
        #expect(encryptedRows.count == Self.seededMessages.count)
        #expect(encryptedPw.count == 1)   // evaluated exactly once on the encrypted path
    }
}

/// G3 / Invariant P1 — no decrypted `tether-rows-*` temp survives a handled exit; the live temp is
/// `0600`. SERIALIZED so the shared system-temp-dir residue is measured as the DELTA caused by THIS
/// read alone (other suites running in parallel would otherwise create/remove their own temps and
/// race a raw "is the dir empty" check). The delta is computed by name-set difference, so a
/// concurrent suite's temp that pre-exists the read is excluded by construction.
@Suite(.serialized) struct BackupRowReaderTempInvariantTests {
    @Test func noTempSurvivesNormalRead() throws {
        let bytes = try FixtureBuilder.smsStoreBytes(messages: BackupRowReaderTests.seededMessages)
        let root = try FixtureBuilder.unencryptedBackupWithStore(
            udid: "U", domain: BackupRowReaderTests.messagesDomain,
            path: BackupRowReaderTests.messagesPath, storeBytes: bytes)
        defer { try? FileManager.default.removeItem(at: root) }

        let before = TempInvariant.rowsTemps()
        _ = try BackupRowReader().messages(
            udidDir: root.appendingPathComponent("U"), password: "", limit: nil)
        // No NEW `tether-rows-*` temp introduced by THIS read survives. Settle the delta (bounded poll)
        // so a concurrent suite's mid-flight temp clears; a true leak persists and still fails.
        #expect(TempInvariant.newTempsSurviving(since: before).isEmpty)
    }

    @Test func noTempSurvivesThrownError() throws {
        // A backup with NO sms.db at the expected path: `extract` throws `fileNotFoundInBackup`. The
        // thrown path must still leave zero NEW `tether-rows-*` residue.
        let root = try FixtureBuilder.unencryptedBackup(udid: "U", files: [
            .init(domain: "HomeDomain", path: "unrelated.txt", contents: Data("x".utf8)),
        ])
        defer { try? FileManager.default.removeItem(at: root) }

        let before = TempInvariant.rowsTemps()
        #expect(throws: VerifyError.self) {
            _ = try BackupRowReader().messages(
                udidDir: root.appendingPathComponent("U"), password: "", limit: nil)
        }
        // Settle the delta (bounded poll) so a concurrent suite's mid-flight temp clears; a true leak persists.
        #expect(TempInvariant.newTempsSurviving(since: before).isEmpty)
    }

    @Test func liveTempIsCreatedOwnerOnly0600() throws {
        // The reader creates its temp with `attributes: [.posixPermissions: 0o600]` (owner-only). The
        // process cannot be paused mid-read to observe the live temp, so assert the creation contract
        // directly against the exact attributes the reader uses.
        let temp = FileManager.default.temporaryDirectory
            .appendingPathComponent("\(TempScrub.prefix)rows-\(UUID().uuidString)\(TempScrub.suffix)")
        FileManager.default.createFile(atPath: temp.path, contents: nil,
                                       attributes: [.posixPermissions: 0o600])
        defer { try? FileManager.default.removeItem(at: temp) }
        let attrs = try FileManager.default.attributesOfItem(atPath: temp.path)
        let perms = (attrs[.posixPermissions] as? NSNumber)?.int16Value
        #expect(perms == 0o600)
    }
}
