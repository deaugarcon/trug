import Foundation

/// A single message row, joined per the LOCKED §7 minimum (`body` + `date` + `service` +
/// `is_from_me`, plus `sender` from `handle` and `chat` context). Field names/types match the
/// SP3 spec §10.3 export schema EXACTLY so WP3's encoder can emit this struct unchanged.
public struct MessageRow: Codable, Equatable {
    public let body: String?
    public let date: String          // normalized ISO-8601 (see DateNormalizer)
    public let service: String?
    public let isFromMe: Bool
    public let sender: String?
    public let chat: String?

    /// §10.3 uses snake_case `is_from_me`; the rest are already lowercase. Mapping it here keeps the
    /// Swift property camelCase while the encoded JSON matches the locked schema byte-for-byte.
    enum CodingKeys: String, CodingKey {
        case body, date, service
        case isFromMe = "is_from_me"
        case sender, chat
    }

    public init(body: String?, date: String, service: String?,
                isFromMe: Bool, sender: String?, chat: String?) {
        self.body = body; self.date = date; self.service = service
        self.isFromMe = isFromMe; self.sender = sender; self.chat = chat
    }
}

/// A single contact row, joined per the LOCKED §8 option (a): name fields plus a primary phone and
/// a primary email (first by stable `ROWID`, null when absent). Field names/types match §10.3.
public struct ContactRow: Codable, Equatable {
    public let first: String?
    public let last: String?
    public let organization: String?
    public let primaryPhone: String?
    public let primaryEmail: String?

    enum CodingKeys: String, CodingKey {
        case first, last, organization
        case primaryPhone = "primary_phone"
        case primaryEmail = "primary_email"
    }

    public init(first: String?, last: String?, organization: String?,
                primaryPhone: String?, primaryEmail: String?) {
        self.first = first; self.last = last; self.organization = organization
        self.primaryPhone = primaryPhone; self.primaryEmail = primaryEmail
    }
}

/// A single call-history row, joined per the LOCKED SP3.1 §3.3 minimum (`address` + `date` +
/// `duration` + `direction`) plus the K2-ratified `call_type`. Field names/types match the SP3.1
/// §10.1 export schema so the WP3 `ExportEnvelope` emits this struct unchanged.
///
/// `date` is OPTIONAL by deliberate marshal contract (Odb M1): a NULL `ZDATE` surfaces as `nil`
/// rather than a FABRICATED `2001-01-01T00:00:00Z` epoch. `CoreDataDateNormalizer` never invents a
/// timestamp from a missing value, so a corrupt/absent date is visible, not silently wrong. (This
/// is the "surface as nil" arm of the M1 disposition; the SOLVE's non-optional `date` is superseded
/// here because a non-optional String cannot represent "no timestamp" without lying.)
public struct CallRow: Codable, Equatable {
    public let address: String?      // ZCALLRECORD.ZADDRESS — remote party phone/handle
    public let date: String?         // ISO-8601 via CoreDataDateNormalizer (SECONDS); nil on NULL ZDATE (M1)
    public let duration: Int         // ZDURATION — call length in whole seconds
    public let direction: String     // "outgoing" | "incoming" (from ZORIGINATED)
    public let callType: String?     // "voice" | "facetime_audio" | "facetime_video" (K2); nil when unknown/absent

    /// §10.1 spells the type key `call_type`; the rest already match the schema.
    enum CodingKeys: String, CodingKey {
        case address, date, duration, direction
        case callType = "call_type"
    }

    public init(address: String?, date: String?, duration: Int,
                direction: String, callType: String?) {
        self.address = address; self.date = date; self.duration = duration
        self.direction = direction; self.callType = callType
    }
}

/// A single note row, per the LOCKED SP3.1 §4.4 minimum plus the K4-ratified `folder`. This is the
/// K3-RATIFIED **title/metadata preview scope**: `ZSNIPPET` is Apple's own PLAINTEXT preview, so the
/// record is decode-free. There is deliberately **NO `body` field in schema_version 1** — not even a
/// `null` placeholder — because advertising a `body` key the reader cannot populate would over-claim
/// preview scope (the full gzip-protobuf body is a named SP3.2 follow-on that bumps schema_version → 2).
/// Field names already match §4.4, so no `CodingKeys` remap.
///
/// `created`/`modified` are OPTIONAL by the same M1 marshal contract as `CallRow.date` (Odb M1, §G):
/// a NULL `ZCREATIONDATE1`/`ZMODIFICATIONDATE1` surfaces as `nil` (key omitted), NEVER a fabricated
/// `2001-01-01T00:00:00Z`; a genuine stored `0` IS the real 2001 epoch. This deviates from the SOLVE
/// §B.1 sketch's non-optional dates exactly as B3's `date` did, under the same §G disposition.
public struct NoteRow: Codable, Equatable {
    public let title: String?       // ZTITLE1
    public let snippet: String?     // ZSNIPPET — Apple's own PLAINTEXT preview (no protobuf decode)
    public let created: String?     // ISO-8601 via CoreDataDateNormalizer (SECONDS); nil on NULL (M1)
    public let modified: String?    // ISO-8601 via CoreDataDateNormalizer (SECONDS); nil on NULL (M1)
    public let folder: String?      // K4 — folder name via the ZFOLDER self-join; nil when unfiled

    public init(title: String?, snippet: String?, created: String?,
                modified: String?, folder: String?) {
        self.title = title; self.snippet = snippet; self.created = created
        self.modified = modified; self.folder = folder
    }
}

/// Schema-aware row reader for the two in-scope SP3 stores (`sms.db`, `AddressBook.sqlitedb`).
///
/// REUSES the proven decrypt-then-open seam byte-for-byte: `BackupExtractor.extract` for the
/// plaintext store bytes, the `BackupVerifier.openTableNames` 0600-temp + `defer`-remove shape to
/// materialize them, and `SQLiteDB(immutable=1)` to read. No seam file is edited and `immutable=1`
/// is not relaxed — every query is a `SELECT` over the immutable temp.
///
/// `limit: nil` reads the FULL store (the export path); `limit: N` applies a SQL-layer `LIMIT N`
/// (the inspect cap, Invariant P3) — the cap is in the query, never a read-all-then-truncate.
public struct BackupRowReader {
    public init() {}

    // MARK: Public surface

    /// Reads message rows from `HomeDomain/Library/SMS/sms.db` per the LOCKED §7 join.
    public func messages(udidDir: URL, password: @autoclosure () -> String, limit: Int?) throws -> [MessageRow] {
        let sql = Self.Schema.messagesSelect(limit: try Self.validatedLimit(limit))
        // Forward the closure LAZILY (`password()` inside another `@autoclosure`) so a plaintext
        // read never evaluates it — see `read`.
        return try read(udidDir: udidDir, password: password(),
                        domain: Self.Schema.messagesDomain, path: Self.Schema.messagesPath,
                        sql: sql) { row in
            MessageRow(
                body: row.text(0),
                date: DateNormalizer.normalize(appleEpochRaw: row.int(1)),
                service: row.text(2),
                isFromMe: row.int(3) != 0,
                sender: row.text(4),
                chat: row.text(5))
        }
    }

    /// Reads contact rows from `HomeDomain/Library/AddressBook/AddressBook.sqlitedb` per §8 option (a).
    public func contacts(udidDir: URL, password: @autoclosure () -> String, limit: Int?) throws -> [ContactRow] {
        let sql = Self.Schema.contactsSelect(limit: try Self.validatedLimit(limit))
        // Forward the closure LAZILY (`password()` inside another `@autoclosure`) so a plaintext
        // read never evaluates it — see `read`.
        return try read(udidDir: udidDir, password: password(),
                        domain: Self.Schema.contactsDomain, path: Self.Schema.contactsPath,
                        sql: sql) { row in
            ContactRow(
                first: row.text(0),
                last: row.text(1),
                organization: row.text(2),
                primaryPhone: row.text(3),
                primaryEmail: row.text(4))
        }
    }

    /// Reads call rows from `HomeDomain/Library/CallHistoryDB/CallHistory.storedata` (Core Data) per
    /// the LOCKED §3.3 minimum. REUSES the generic `read<Row>` verbatim, so P1/P2/P4 hold by
    /// construction — this adds no new decrypt/materialize path. The one genuine novelty is the date
    /// unit: Core Data `ZDATE` is SECONDS since 2001 (`CoreDataDateNormalizer`), NOT the nanoseconds
    /// `sms.db` uses — reusing `DateNormalizer` here would misread every call time by 1e9 (§3.4).
    public func calls(udidDir: URL, password: @autoclosure () -> String, limit: Int?) throws -> [CallRow] {
        let sql = Self.Schema.callsSelect(limit: try Self.validatedLimit(limit))
        // Forward the closure LAZILY (`password()` inside another `@autoclosure`) so a plaintext
        // read never evaluates it — see `read`.
        return try read(udidDir: udidDir, password: password(),
                        domain: Self.Schema.callsDomain, path: Self.Schema.callsPath,
                        sql: sql) { row in
            // ZDATE/ZCALLTYPE are read via `text(i)` so a SQL NULL is distinguishable (nil) from a
            // genuine 0 — `int(i)` maps both to 0, which for ZDATE would forge the 2001 epoch (M1).
            CallRow(
                address: row.text(0),
                date: CoreDataDateNormalizer.normalize(appleEpochSeconds: row.text(1).flatMap { Int($0) }),
                duration: row.int(2),
                direction: Self.Schema.callDirection(row.int(3)),
                callType: Self.Schema.callType(row.text(4).flatMap { Int($0) }))
        }
    }

    /// Reads note rows from `AppDomainGroup-group.com.apple.notes/NoteStore.sqlite` (Core Data) per the
    /// LOCKED §4.4 preview minimum + K4 `folder`. REUSES the generic `read<Row>` verbatim (P1/P2/P4 by
    /// construction) and the SAME `CoreDataDateNormalizer` (seconds since 2001) B3 introduced — both
    /// stores are Core Data. This is the K3 title/metadata preview: no `ZICNOTEDATA` body decode.
    public func notes(udidDir: URL, password: @autoclosure () -> String, limit: Int?) throws -> [NoteRow] {
        let sql = Self.Schema.notesSelect(limit: try Self.validatedLimit(limit))
        // Forward the closure LAZILY (`password()` inside another `@autoclosure`) so a plaintext
        // read never evaluates it — see `read`.
        return try read(udidDir: udidDir, password: password(),
                        domain: Self.Schema.notesDomain, path: Self.Schema.notesPath,
                        sql: sql) { row in
            // created/modified read via `text(i)` over the CAST columns so a SQL NULL surfaces nil
            // (M1) — `int(i)` would coerce NULL→0 and forge the 2001 epoch.
            NoteRow(
                title: row.text(0),
                snippet: row.text(1),
                created: CoreDataDateNormalizer.normalize(appleEpochSeconds: row.text(2).flatMap { Int($0) }),
                modified: CoreDataDateNormalizer.normalize(appleEpochSeconds: row.text(3).flatMap { Int($0) }),
                folder: row.text(4))
        }
    }

    // MARK: Materialize + read (mirrors BackupVerifier.openTableNames)

    /// Validates `limit` once and renders it injection-safe: a `LIMIT` literal can only ever be a
    /// non-negative `Int` (an `Int` cannot carry SQL syntax). `nil` means "no LIMIT" (full store).
    /// A negative limit is a programmer error (the CLI clamps `--limit` at WP2), surfaced as
    /// `manifestUnreadable` rather than reaching SQL.
    private static func validatedLimit(_ limit: Int?) throws -> Int? {
        guard let n = limit else { return nil }
        guard n >= 0 else {
            throw VerifyError.manifestUnreadable(reason: "row limit must be non-negative, got \(n)")
        }
        return n
    }

    /// The shared flow for both stores: pre-check → resolve password ONCE (only when encrypted) →
    /// extract → 0600 temp + `defer`-remove → `SQLiteDB(immutable=1)` → run `sql` → marshal.
    private func read<Row>(udidDir: URL, password: @autoclosure () -> String,
                           domain: String, path: String, sql: String,
                           marshal: (SQLiteDB.Row) -> Row) throws -> [Row] {
        // P2 floor: clear any kill-before-`defer` residue from a prior run BEFORE materializing.
        TempScrub.run()

        // Resolve the password LAZILY and EXACTLY ONCE, and ONLY on the encrypted path. A plaintext
        // backup must NEVER evaluate the closure (spec §1.1/§4: "plaintext never prompts") — once WP2
        // wires interactive `PasswordInput.read()`, evaluating it eagerly would HANG a plaintext
        // `inspect` on a prompt that must not fire. Mirrors `ManifestReader.open:61-66`: the
        // encryption check runs first, gated entirely behind `isEncrypted`.
        let pw: String
        if ManifestReader.isEncrypted(backupDir: udidDir) {
            pw = password()            // pulled exactly once, only here, only when encrypted

            // [odb High] `BackupExtractor.extract` calls `Keybag.unlock` directly — it does NOT route
            // through `ManifestReader.open`, so an empty password on an encrypted backup would throw
            // `KeybagError.wrongPassword` (the corrupt-data exit class), NOT the spec-LOCKED user-input
            // class. Pre-check here so an empty-password encrypted read surfaces
            // `VerifyError.passwordRequired` instead. Reuses the existing static + existing case; no
            // new error case, no seam edit.
            if pw.isEmpty {
                throw VerifyError.passwordRequired(udid: udidDir.lastPathComponent)
            }
        } else {
            pw = ""                    // plaintext: the closure is never evaluated; extract ignores pw
        }

        let bytes = try BackupExtractor().extract(udidDir: udidDir, domain: domain, path: path, password: pw)

        let temp = FileManager.default.temporaryDirectory
            .appendingPathComponent("\(TempScrub.prefix)rows-\(UUID().uuidString)\(TempScrub.suffix)")
        FileManager.default.createFile(atPath: temp.path, contents: nil,
                                       attributes: [.posixPermissions: 0o600])   // 0600 owner-only
        defer { try? FileManager.default.removeItem(at: temp) }                  // removed on every handled exit
        try bytes.write(to: temp)

        var out: [Row] = []
        try SQLiteDB(path: temp.path).query(sql) { row in
            out.append(marshal(row))
        }
        return out
    }

    // MARK: Schema (device-uncertain spellings isolated for WP4)

    /// EVERY device-uncertain column/table spelling and property code lives here so WP4 can rebind
    /// the verified device schema WITHOUT reshaping the reader. The minimum FIELDS are LOCKED
    /// (spec §7/§8); only the exact spellings are WP4-deferred. These are all compile-time constants
    /// — NEVER user input — so the only dynamic SQL fragment anywhere is a validated non-negative
    /// Int `LIMIT` (see `validatedLimit`).
    enum Schema {
        // --- Messages store (HomeDomain/Library/SMS/sms.db) ---
        static let messagesDomain = "HomeDomain"               // WP4-verify
        static let messagesPath = "Library/SMS/sms.db"         // WP4-verify

        /// The LOCKED §7 join. Column order MUST match the marshalling in `messages(...)`:
        /// 0 body, 1 date, 2 service, 3 is_from_me, 4 sender, 5 chat.
        static func messagesSelect(limit: Int?) -> String {
            // Columns (WP4-verify each spelling): message.text/date/service/is_from_me/handle_id,
            // handle.ROWID/id, chat.chat_identifier, chat_message_join.message_id/chat_id.
            let base = """
            SELECT m.text, m.date, m.service, m.is_from_me, h.id AS sender, c.chat_identifier
            FROM message AS m
            LEFT JOIN handle AS h            ON m.handle_id = h.ROWID
            LEFT JOIN chat_message_join AS j ON j.message_id = m.ROWID
            LEFT JOIN chat AS c              ON c.ROWID = j.chat_id
            ORDER BY m.date ASC, m.ROWID ASC
            """
            return limitClause(base, limit)
        }

        // --- Contacts store (HomeDomain/Library/AddressBook/AddressBook.sqlitedb) ---
        static let contactsDomain = "HomeDomain"                              // WP4-verify
        static let contactsPath = "Library/AddressBook/AddressBook.sqlitedb"  // WP4-verify

        /// `ABMultiValue.property` codes that identify a phone vs an email value. The real device
        /// codes are WP4-device-verified and may differ across iOS majors; the FixtureBuilder seeds
        /// these same codes so WP1 is fixture-green and WP4 rebinds here only.
        static let phoneProperty = 3   // WP4-verify
        static let emailProperty = 4   // WP4-verify

        /// The LOCKED §8 option-(a) join. Column order MUST match the marshalling in `contacts(...)`:
        /// 0 first, 1 last, 2 organization, 3 primary_phone, 4 primary_email. "primary" = first by
        /// stable ROWID (§8.3).
        static func contactsSelect(limit: Int?) -> String {
            // Columns (WP4-verify each spelling): ABPerson.ROWID/First/Last/Organization,
            // ABMultiValue.record_id/value/property/ROWID.
            let base = """
            SELECT p.First, p.Last, p.Organization,
                   (SELECT v.value FROM ABMultiValue v
                     WHERE v.record_id = p.ROWID AND v.property = \(phoneProperty)
                     ORDER BY v.ROWID ASC LIMIT 1) AS primary_phone,
                   (SELECT v.value FROM ABMultiValue v
                     WHERE v.record_id = p.ROWID AND v.property = \(emailProperty)
                     ORDER BY v.ROWID ASC LIMIT 1) AS primary_email
            FROM ABPerson AS p
            ORDER BY p.ROWID ASC
            """
            return limitClause(base, limit)
        }

        // --- Calls store (HomeDomain/Library/CallHistoryDB/CallHistory.storedata — Core Data) ---
        static let callsDomain = "HomeDomain"                                  // device-verify(B6)
        static let callsPath = "Library/CallHistoryDB/CallHistory.storedata"   // device-verify(B6)

        /// `ZCALLTYPE` flag codes that discriminate voice vs FaceTime (K2). The real device codes are
        /// device-verify(B6) and may differ across iOS majors; the FixtureBuilder seeds these SAME
        /// codes so B3 is fixture-green and B6 rebinds here only.
        static let callTypeVoice = 1           // device-verify(B6)
        static let callTypeFaceTimeAudio = 8   // device-verify(B6)
        static let callTypeFaceTimeVideo = 16  // device-verify(B6)

        /// The LOCKED §3.3 call SELECT. Column order MUST match the marshalling in `calls(...)`:
        /// 0 ZADDRESS, 1 CAST(ZDATE AS INTEGER), 2 CAST(ZDURATION AS INTEGER), 3 ZORIGINATED, 4 ZCALLTYPE.
        static func callsSelect(limit: Int?) -> String {
            // ZDATE/ZDURATION are Core Data REAL (seconds since 2001). CAST to INTEGER so an integer
            // value reaches int()/text() and the whole-second truncation is EXPLICIT at the SQL layer
            // — no dependence on accessor coercion, and no SQLiteDB `double` accessor is added (A3).
            // Every Z-spelling is device-verify(B6), isolated here for a localized B6 rebind.
            let base = """
            SELECT r.ZADDRESS,
                   CAST(r.ZDATE AS INTEGER)     AS date_s,
                   CAST(r.ZDURATION AS INTEGER) AS duration_s,
                   r.ZORIGINATED,
                   r.ZCALLTYPE
            FROM ZCALLRECORD AS r
            ORDER BY r.ZDATE ASC, r.Z_PK ASC
            """
            return limitClause(base, limit)
        }

        /// Maps a raw `ZORIGINATED` to the LOCKED §3.3 direction string: `1` outgoing, `0` incoming
        /// (both device-verify(B6)). M2: a non-binary/impossible value falls back to `"incoming"` — a
        /// DOCUMENTED fallback, NOT a spelling to rebind. The fallback is reachable ONLY by non-binary
        /// inputs; `0`/`1` take their explicit branches. B6 must confirm `ZORIGINATED` is strictly
        /// binary {0,1} and always populated, which makes this fallback dead code on real device rows.
        static func callDirection(_ originated: Int) -> String {
            switch originated {
            case 1: return "outgoing"
            case 0: return "incoming"
            default: return "incoming"   // M2 documented fallback — non-binary only
            }
        }

        /// Maps a raw `ZCALLTYPE` to the K2 `call_type` string, or `nil` when absent/unknown. Unlike
        /// `direction`, an unknown/NULL call_type honestly returns `nil` (the asymmetry is intentional
        /// — Odb M2: a fifth "unknown" direction is unrepresentable under the §3.3 lock, but call_type
        /// is already nullable so it need not fabricate a value).
        static func callType(_ raw: Int?) -> String? {
            guard let raw else { return nil }
            switch raw {
            case callTypeVoice: return "voice"
            case callTypeFaceTimeAudio: return "facetime_audio"
            case callTypeFaceTimeVideo: return "facetime_video"
            default: return nil          // unknown code → honest nil
            }
        }

        // --- Notes store (AppDomainGroup-group.com.apple.notes/NoteStore.sqlite — Core Data) ---
        static let notesDomain = "AppDomainGroup-group.com.apple.notes"   // device-verify(B6)
        static let notesPath = "NoteStore.sqlite"                         // device-verify(B6)

        /// The LOCKED §4.4 preview SELECT + K4 folder self-join. Column order MUST match `notes(...)`:
        /// 0 ZTITLE1, 1 ZSNIPPET, 2 CAST(ZCREATIONDATE1 AS INTEGER), 3 CAST(ZMODIFICATIONDATE1 AS INTEGER),
        /// 4 f.ZTITLE1 (folder name). Dates are Core Data REAL seconds — CAST AS INTEGER (same as calls)
        /// and read via text() so a NULL date surfaces nil, never a forged epoch (M1).
        static func notesSelect(limit: Int?) -> String {
            // Discriminator (Odb H1): the NOTE entity is resolved AT RUNTIME BY NAME from the Core Data
            // `Z_PRIMARYKEY` catalog — NOT a hardcoded integer, NOT `ZTITLE1 IS NOT NULL`. Core Data
            // assigns `Z_ENT` codes at store-creation and they are NOT stable across devices/iOS majors:
            // device-verify(B6) measured ICNote=12 and ICMedia=11 on iOS 27, so the previously-hardcoded
            // 11 returned MEDIA rows and dropped EVERY real note (the fixture-green/device-dead trap).
            // Folders and accounts DO carry titles (the K4 join reads `f.ZTITLE1`), so a title-nullness
            // filter would emit them AS notes — hence an entity discriminator, resolved by the stable
            // Core Data class NAME 'ICNote'. The literal is a fixed class name (no user input), so the
            // scalar subquery is injection-safe; a missing ICNote row makes it NULL → 0 rows (fail-safe,
            // never junk). The self-join resolves a note's folder NAME from its ZFOLDER FK; a NULL
            // ZFOLDER LEFT-JOINs to nothing → folder nil.
            // device-verify(B6) — LOCKED notes: their ZSNIPPET is WITHHELD at the SQL layer (M2, below)
            // regardless of stored bytes; locked notes are NOT excluded (their titles are listable).
            // Every Z-spelling is device-verify(B6), isolated here for a localized B6 rebind.
            let base = """
            SELECT o.ZTITLE1,
                   CASE WHEN o.ZISPASSWORDPROTECTED = 1 THEN '' ELSE o.ZSNIPPET END AS ZSNIPPET,
                   CAST(o.ZCREATIONDATE1 AS INTEGER)     AS created_s,
                   CAST(o.ZMODIFICATIONDATE1 AS INTEGER) AS modified_s,
                   f.ZTITLE1 AS folder
            FROM ZICCLOUDSYNCINGOBJECT AS o
            LEFT JOIN ZICCLOUDSYNCINGOBJECT AS f ON o.ZFOLDER = f.Z_PK
            WHERE o.Z_ENT = (SELECT Z_ENT FROM Z_PRIMARYKEY WHERE Z_NAME = 'ICNote')
            ORDER BY o.ZMODIFICATIONDATE1 DESC, o.Z_PK ASC
            """
            return limitClause(base, limit)
        }

        /// Appends a `LIMIT N` clause when capping (inspect) and nothing when full (export). `limit`
        /// is already validated non-negative by `validatedLimit`, so interpolating it is injection-safe.
        private static func limitClause(_ base: String, _ limit: Int?) -> String {
            guard let n = limit else { return base }
            return base + "\nLIMIT \(n)"
        }
    }
}

/// Converts a raw `message.date` (Apple Core Data epoch: nanoseconds since 2001-01-01 UTC on modern
/// iOS) to an ISO-8601 UTC string. The epoch BASE and the UNIT (ns vs s) are WP4-device-verified —
/// the unit divisor is isolated here so WP4 can confirm or rebind it without touching the reader.
enum DateNormalizer {
    /// Seconds between the Unix epoch (1970-01-01) and the Apple/Core-Data epoch (2001-01-01 UTC).
    private static let appleEpochOffsetSeconds: Double = 978_307_200   // WP4-verify (base)

    /// Divisor from the raw stored unit to seconds. Modern iOS stores `message.date` in NANOSECONDS.
    private static let nanosecondsPerSecond: Double = 1_000_000_000    // WP4-verify (unit)

    static func normalize(appleEpochRaw raw: Int) -> String {
        let appleSeconds = Double(raw) / nanosecondsPerSecond
        let unixSeconds = appleSeconds + appleEpochOffsetSeconds
        // `ISO8601FormatStyle` is a Sendable value type (vs the non-Sendable `ISO8601DateFormatter`),
        // so it is safe as a stateless local under Swift 6 strict concurrency. The field set is PINNED
        // explicitly (date year/month/day + time + timeZone, UTC, `-`/`:` separators, `T` between
        // date and time) so the exported `date` is stable regardless of any future Foundation default
        // — `2001-01-01T00:00:01Z`. [odb Low]
        let style = Date.ISO8601FormatStyle(timeZone: TimeZone(identifier: "UTC") ?? .gmt)
            .year().month().day()
            .dateTimeSeparator(.standard)   // `T`
            .time(includingFractionalSeconds: false)
            .timeZone(separator: .omitted)  // trailing `Z`, no colon
        return Date(timeIntervalSince1970: unixSeconds).formatted(style)
    }
}

/// Converts a raw Core Data timestamp (`ZDATE`/`ZCREATIONDATE1`/…) to an ISO-8601 UTC string. Core
/// Data stores `NSDate` as `timeIntervalSinceReferenceDate` — **SECONDS** since 2001-01-01 UTC — so
/// the unit divisor is `1`, NOT the `1e9` nanosecond divisor `DateNormalizer` uses for `sms.db`
/// (§3.4). This is a SEPARATE sibling to `DateNormalizer`, never an edit of it: the ns divisor stays
/// byte-unchanged for messages while the seconds divisor is isolated here for a localized B6 rebind.
/// Named for Core Data (not "Call") because both Core Data stores — calls now, notes at B4 — share
/// this seconds base.
enum CoreDataDateNormalizer {
    /// Seconds between the Unix epoch (1970-01-01) and the Apple/Core-Data epoch (2001-01-01 UTC).
    private static let appleEpochOffsetSeconds: Double = 978_307_200   // device-verify(B6) base

    /// Divisor from the raw stored unit to seconds. Core Data `NSDate` is already in SECONDS.
    private static let unitDivisor: Double = 1                          // device-verify(B6) unit (SECONDS)

    /// Returns `nil` for a NULL/absent raw timestamp (Odb M1): a missing `ZDATE` must NOT become a
    /// fabricated `2001-01-01T00:00:00Z`. A present value normalizes exactly like `DateNormalizer`
    /// but with the seconds divisor.
    static func normalize(appleEpochSeconds raw: Int?) -> String? {
        guard let raw else { return nil }
        let appleSeconds = Double(raw) / unitDivisor
        let unixSeconds = appleSeconds + appleEpochOffsetSeconds
        // Same PINNED field set as DateNormalizer (UTC, `-`/`:` separators, `T`, trailing `Z`, no
        // fractional seconds) so the exported `date` is stable regardless of any Foundation default.
        let style = Date.ISO8601FormatStyle(timeZone: TimeZone(identifier: "UTC") ?? .gmt)
            .year().month().day()
            .dateTimeSeparator(.standard)   // `T`
            .time(includingFractionalSeconds: false)
            .timeZone(separator: .omitted)  // trailing `Z`, no colon
        return Date(timeIntervalSince1970: unixSeconds).formatted(style)
    }
}
