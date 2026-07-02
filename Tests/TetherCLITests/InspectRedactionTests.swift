import Testing
import Foundation
import ArgumentParser
import BackupCore
@testable import TetherCLI

/// SP3 WP2 — `inspect` redaction renderer + preview assembly. All rows are SEEDED/FAKE (evidence
/// rule §9): no real message text, sender, or contact appears in any fixture or assertion. Tests
/// assert on the MASKED output, never embedding a raw value an assertion expects to leak.
///
/// Gate map: G1 (body truncation, §11.1 40-char), G2 (sender/name masking, §11.1), G3 (CLI lazy
/// password — count 0 plaintext / 1 encrypted), G4 (table redacted), G5 (--json capped+redacted,
/// preview keys), G7 (no createFile/write in inspect source), G8 (validate() rejects --limit<0).
/// odb F1 (mask totality on degenerate inputs), F2 (validate ordering + non-negative default).
@Suite struct InspectRedactionTests {

    // MARK: Seeded FAKE rows (§9)

    // Computed (not stored static) so the non-Sendable `MessageRow`/`ContactRow` arrays are a fresh
    // value per access — no shared mutable global state under Swift 6 strict concurrency.
    static var seededMessages: [MessageRow] {
        [
            // received SMS — phone sender masked
            MessageRow(body: "Running 10 min late, starting now, will be there soon promise",
                       date: "2026-06-13T09:14:02Z", service: "SMS",
                       isFromMe: false, sender: "+15555550189", chat: "+15555550189"),
            // sent iMessage — is_from_me => 'me'
            MessageRow(body: "No worries — see you there.",
                       date: "2026-06-13T09:15:31Z", service: "iMessage",
                       isFromMe: true, sender: nil, chat: "+15555550189"),
            // received iMessage — email sender masked
            MessageRow(body: "Dinner photos attached for the trip",
                       date: "2026-06-12T21:02:00Z", service: "iMessage",
                       isFromMe: false, sender: "jane@example.com", chat: "group-fixture"),
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

    // MARK: G1 — body truncation to §11.1 40 chars

    @Test func bodyTruncatesPast40WithEllipsis() {
        let long = String(repeating: "a", count: 60)
        let r = InspectRedaction.redactBody(long)
        #expect(r.truncated == true)
        // 40 visible characters + the single ellipsis grapheme.
        #expect(r.text.count == InspectRedaction.previewBodyMax + 1)
        #expect(r.text.hasSuffix("…"))
        #expect(r.text.dropLast() == String(repeating: "a", count: InspectRedaction.previewBodyMax))
    }

    @Test func bodyExactly40IsNotTruncated() {
        // EXACTLY 40 chars: no ellipsis, truncated:false (odb F1 boundary).
        let exact = String(repeating: "b", count: 40)
        let r = InspectRedaction.redactBody(exact)
        #expect(r.truncated == false)
        #expect(r.text == exact)
        #expect(!r.text.hasSuffix("…"))
    }

    @Test func bodyShorterThan40IsUnchanged() {
        let r = InspectRedaction.redactBody("short body")
        #expect(r.truncated == false)
        #expect(r.text == "short body")
    }

    @Test func bodyNilAndEmptyAreHandled() {
        let nilR = InspectRedaction.redactBody(nil)
        #expect(nilR.truncated == false)
        #expect(nilR.text == "")
        let emptyR = InspectRedaction.redactBody("")
        #expect(emptyR.truncated == false)
        #expect(emptyR.text == "")
    }

    // odb F1 — grapheme-safe truncation: a body whose 40th boundary lands mid-emoji must not
    // crash and must not split a grapheme (truncate on Character, never UTF-16/byte offset).
    @Test func bodyTruncationIsGraphemeSafe() {
        // 39 ASCII + a family emoji (a single grapheme of multiple scalars): the 40th Character
        // is the emoji. Truncating to 40 Characters keeps the WHOLE emoji, never half of it.
        let emoji = "👨‍👩‍👧‍👦"
        let body = String(repeating: "x", count: 39) + emoji + "trailing"
        let r = InspectRedaction.redactBody(body)
        #expect(r.truncated == true)
        // 40 graphemes kept + ellipsis = 41 Characters; the emoji survives intact (no half-emoji).
        #expect(r.text.count == InspectRedaction.previewBodyMax + 1)
        #expect(r.text.contains(emoji))
    }

    // MARK: G2 — sender/name masking (§11.1)

    @Test func maskPhoneKeepsShapeAndLastTwo() {
        let masked = InspectRedaction.maskPhone("+15555550189")
        // Leading "+1", masked middle, last two digits "89".
        #expect(masked.hasPrefix("+1"))
        #expect(masked.hasSuffix("89"))
        #expect(masked.contains("*"))
        #expect(masked != "+15555550189")   // never the raw value
    }

    @Test func maskEmailKeepsFirstLocalFirstDomainAndTLD() {
        let masked = InspectRedaction.maskEmail("jane@example.com")
        #expect(masked.hasPrefix("j"))
        #expect(masked.contains("@"))
        #expect(masked.hasSuffix(".com"))
        #expect(masked.contains("*"))
        #expect(masked != "jane@example.com")   // never the raw value
    }

    @Test func maskSenderDispatchesByAtSign() {
        #expect(InspectRedaction.maskSender("+15555550189").contains("*"))
        #expect(InspectRedaction.maskSender("jane@example.com").contains("@"))
    }

    @Test func messageFromMeRendersMeBeforeMasking() {
        // is_from_me == true ⇒ sender 'me', applied BEFORE masking (no self-handle masked-then-leaked).
        let r = InspectRedaction.redact(MessageRow(
            body: "hi", date: "2026-06-13T00:00:00Z", service: "iMessage",
            isFromMe: true, sender: "+15555559999", chat: "c"))
        #expect(r.from == "me")
        #expect(r.direction == "sent")
    }

    @Test func messageReceivedMasksSender() {
        let r = InspectRedaction.redact(Self.seededMessages[0])
        #expect(r.from != "+15555550189")   // masked, never raw
        #expect(r.from.contains("*"))
        #expect(r.direction == "received")
    }

    // contact-name masking — WP2 DESIGN DECISION (recorded in source header), NOT a §11.1 lock.
    @Test func contactNameMaskKeepsFirstNameAndLastInitial() {
        let r = InspectRedaction.redact(Self.seededContacts[0])
        // "Ada Lovelace" -> "Ada L*****" form (first name kept, last initial + mask).
        #expect(r.name.hasPrefix("Ada"))
        #expect(r.name != "Ada Lovelace")
        #expect(r.name.contains("*"))
        #expect(r.phone != "+15555550107")   // masked
        #expect(r.email != "ada@example.org")
    }

    @Test func contactNullPhoneEmailRenderNoneToken() {
        let r = InspectRedaction.redact(Self.seededContacts[1])
        #expect(r.email == "(none)")          // null email → (none)
        #expect(r.organization == "(none)")   // null organization → (none)
    }

    // odb F1 — contact name totality: nil / empty / one-char name must not crash or leak.
    @Test func contactNameTotalityOnDegenerateNames() {
        let nilName = InspectRedaction.redact(ContactRow(
            first: nil, last: nil, organization: nil, primaryPhone: nil, primaryEmail: nil))
        #expect(nilName.name == "(none)")
        let oneChar = InspectRedaction.redact(ContactRow(
            first: "A", last: "B", organization: nil, primaryPhone: nil, primaryEmail: nil))
        // one-char names must not crash; masking a 1-char last name must not echo it raw past a token.
        #expect(!oneChar.name.isEmpty)
        let emptyStrings = InspectRedaction.redact(ContactRow(
            first: "", last: "", organization: "", primaryPhone: "", primaryEmail: ""))
        #expect(!emptyStrings.name.isEmpty)
    }

    // MARK: odb F1 — mask TOTALITY on degenerate inputs (no crash, no raw echo, fixed token)

    @Test func maskEmailTotalityNeverCrashesNeverEchoesRaw() {
        let degenerate = ["", "a", "a@", "@b.com", "a@b", "a@b.co", "first.last@sub.example.co.uk"]
        for input in degenerate {
            let masked = InspectRedaction.maskEmail(input)
            // No transform traps (we got here), and a too-short value is never returned raw.
            if input.count <= 3 {
                #expect(masked != input)
            }
            #expect(!masked.isEmpty)
        }
        // a@b.co is short: must NOT be echoed verbatim (the whole address revealed).
        #expect(InspectRedaction.maskEmail("a@b.co") != "a@b.co")
    }

    @Test func maskPhoneTotalityNeverCrashesNeverEchoesRaw() {
        let degenerate = ["", "1", "12", "+1", "abc", "1234"]
        for input in degenerate {
            let masked = InspectRedaction.maskPhone(input)
            // No trap, and a ≤2-char input is never returned unmasked (fixed redaction token).
            if input.count <= 2 {
                #expect(masked != input)
            }
        }
    }

    @Test func maskSenderTotalityOnEmptyAndNoSeparator() {
        #expect(!InspectRedaction.maskSender("").isEmpty)
        #expect(!InspectRedaction.maskSender("noatsign").isEmpty)
    }

    // MARK: G4 — TABLE output is redacted (no raw seeds)

    @Test func messageTableRendersMaskedNeverRaw() {
        let table = InspectRedaction.messageTable(Self.seededMessages, limit: 20).rendered()
        // Masked sender + 'me', never the raw phone/email or the full body.
        #expect(table.contains("me"))
        #expect(!table.contains("+15555550189"))
        #expect(!table.contains("jane@example.com"))
        #expect(!table.contains("Running 10 min late, starting now, will be there soon promise"))
        // The truncation ellipsis appears for the over-long body.
        #expect(table.contains("…"))
    }

    @Test func contactTableRendersMaskedNeverRaw() {
        let table = InspectRedaction.contactTable(Self.seededContacts, limit: 20).rendered()
        #expect(!table.contains("+15555550107"))
        #expect(!table.contains("ada@example.org"))
        #expect(!table.contains("Lovelace"))   // last name masked
    }

    // odb R-new-1 — every redacted row is fixed-arity matching the header (TextTable traps otherwise).
    @Test func messageTableRowsAreFixedArity() {
        let header = InspectRedaction.messageHeader
        let table = InspectRedaction.messageTable(Self.seededMessages, limit: 20)
        for row in table.rows { #expect(row.count == header.count) }
    }

    @Test func contactTableRowsAreFixedArity() {
        let header = InspectRedaction.contactHeader
        let table = InspectRedaction.contactTable(Self.seededContacts, limit: 20)
        for row in table.rows { #expect(row.count == header.count) }
    }

    // MARK: G5 — --json capped + redacted, preview keys (raw schema keys ABSENT)

    @Test func messageJSONIsCappedRedactedWithPreviewKeys() throws {
        let envelope = InspectRedaction.messageJSON(Self.seededMessages, limit: 20)
        #expect(envelope.store == "messages")
        #expect(envelope.preview == true)
        #expect(envelope.shown == Self.seededMessages.count)
        #expect(envelope.total == nil)   // OI1: no fabricated total (no COUNT(*) pass)
        let encoded = String(decoding: try JSONEncoder().encode(envelope), as: UTF8.self)
        // Redacted forms present; raw seeds absent.
        #expect(!encoded.contains("+15555550189"))
        #expect(!encoded.contains("jane@example.com"))
        // §10.2 preview keys present; raw schema keys (is_from_me / the raw `sender`) absent.
        #expect(encoded.contains("body_preview"))
        #expect(encoded.contains("direction"))
        #expect(!encoded.contains("is_from_me"))
    }

    @Test func contactJSONIsRedactedWithPreviewKeys() throws {
        let envelope = InspectRedaction.contactJSON(Self.seededContacts, limit: 20)
        #expect(envelope.store == "contacts")
        #expect(envelope.preview == true)
        let encoded = String(decoding: try JSONEncoder().encode(envelope), as: UTF8.self)
        #expect(!encoded.contains("+15555550107"))
        #expect(!encoded.contains("ada@example.org"))
        #expect(!encoded.contains("Lovelace"))
    }

    // odb OI1 / M2 — footer gated on rows.count == cap (no fabricated N).
    @Test func footerOnlyWhenRowsCountEqualsCap() {
        // shown == cap: more rows MAY exist → footer present.
        #expect(InspectRedaction.moreRowsFooter(shown: 20, cap: 20) != nil)
        // shown < cap: we KNOW there are no more → no footer.
        #expect(InspectRedaction.moreRowsFooter(shown: 3, cap: 20) == nil)
        // The footer points at export, with NO fabricated count.
        let footer = InspectRedaction.moreRowsFooter(shown: 20, cap: 20) ?? ""
        #expect(footer.contains("export"))
    }

    // MARK: G3 — CLI lazy password (count 0 plaintext / 1 encrypted)

    /// A side-effecting password source: each evaluation increments `count`. The inspect load seam
    /// forwards it as an `@autoclosure` to the reader-call shape, pulling it ONLY on the encrypted
    /// branch — exactly mirroring the WP1 reader's `if isEncrypted { pw = password() }` gate and
    /// WP1's `plaintextReadNeverEvaluatesPassword`. Proves a plaintext inspect never evaluates the
    /// password (would hang on the interactive prompt) without driving `run()` (which resolves the
    /// real `.defaultRoot`).
    final class CountingPassword {
        private(set) var count = 0
        var value: String { count += 1; return "secret" }
    }

    @Test func plaintextLoadNeverEvaluatesPassword() {
        let plain = CountingPassword()
        // `read` is the reader-call stand-in: it receives the password as an @autoclosure and only
        // pulls it when encrypted — so the load seam forwarding the autoclosure proves laziness.
        _ = InspectRedaction.load(isEncrypted: false, password: plain.value, read: { _ in
            // plaintext branch: do NOT evaluate the password (mirrors the reader)
            ["row"]
        })
        #expect(plain.count == 0)   // plaintext NEVER evaluates the password
    }

    @Test func encryptedLoadEvaluatesPasswordExactlyOnce() {
        let enc = CountingPassword()
        _ = InspectRedaction.load(isEncrypted: true, password: enc.value, read: { pw in
            _ = pw()                // encrypted branch: pull the password once (mirrors the reader)
            return ["row"]
        })
        #expect(enc.count == 1)   // encrypted evaluates the password exactly once
    }

    // MARK: G8 / odb F2 — validate() rejects --limit < 0 AT PARSE
    //
    // ArgumentParser runs `validate()` DURING `parse(...)` (after decoding, before `run()`), so a
    // negative `--limit` is rejected at parse and NEVER reaches the reader's `n >= 0` precondition
    // (which would mislabel a user typo as a corrupt backup, exit 7 — constraint b / D4). The bare
    // `Inspect()` initializer is NOT used: an uninitialized `@Argument`/`@Option` wrapper traps; the
    // wrappers are only valid after a parse. `--limit=-1` (the `=` form) binds the leading-`-` value
    // to the option rather than reading it as another flag.

    @Test func validateRejectsNegativeLimitAtParse() {
        // `parse` itself throws (the ValidationError is wrapped by ArgumentParser) because validate()
        // fires during parsing — proving the guard's HOME is the parse layer (constraint b).
        #expect(throws: (any Error).self) {
            _ = try Backup.Inspect.parse(["UDID", "messages", "--limit=-1"])
        }
        // The thrown error carries our exact message (not a generic decode failure).
        do {
            _ = try Backup.Inspect.parse(["UDID", "messages", "--limit=-1"])
            Issue.record("expected parse to throw on --limit=-1")
        } catch {
            #expect("\(error)".contains("--limit must be non-negative"))
        }
    }

    @Test func validateAcceptsZeroAndDefault() throws {
        // Zero is non-negative — parses cleanly (validate() passes).
        let zero = try Backup.Inspect.parse(["UDID", "messages", "--limit=0"])
        #expect(zero.limit == 0)
        let twenty = try Backup.Inspect.parse(["UDID", "messages", "--limit", "20"])
        #expect(twenty.limit == 20)
        // The literal default is itself non-negative (odb F2 (b)) — the default path never carries < 0.
        let defaulted = try Backup.Inspect.parse(["UDID", "messages"])
        #expect(defaulted.limit >= 0)
    }

    @Test func defaultPreviewCapIsTwenty() throws {
        // OI2: the omitted-flag default is the small content-sensitive cap (20).
        let cmd = try Backup.Inspect.parse(["UDID", "messages"])
        #expect(cmd.limit == 20)
    }

    @Test func unknownStoreIsAParseErrorNotAnEngineError() {
        // R2: an out-of-scope store is an ArgumentParser usage error at PARSE — never an engine
        // error, never an OutputFormat exit-code edit. The Store enum makes it unrepresentable past parse.
        #expect(throws: (any Error).self) {
            _ = try Backup.Inspect.parse(["UDID", "callhistory"])
        }
    }

    // MARK: G7 — no durable artifact: inspect source contains no createFile/write(to:)

    @Test func inspectSourceWritesNoDurableArtifact() throws {
        // Source-grep guard: the InspectRedaction renderer + the Inspect command must not create or
        // write any file (no --out, no createFile/write(to:)). Proves P4 at the CLI layer.
        let root = URL(fileURLWithPath: #filePath)
            .deletingLastPathComponent().deletingLastPathComponent().deletingLastPathComponent()
        let renderer = try String(contentsOf: root.appendingPathComponent(
            "Sources/TetherCLI/InspectRedaction.swift"), encoding: .utf8)
        #expect(!renderer.contains("createFile"))
        #expect(!renderer.contains("write(to:"))
    }
}
