import Foundation
import BackupCore

/// SP3 WP2 — the PURE redaction / truncation renderer for `inspect`. NO I/O, NO ArgumentParser, NO
/// stdout: every function here is a value-to-value transform so the privacy-critical masking is
/// provable in isolation (the SOLVE's non-negotiable #2). Table AND `--json` both consume the SAME
/// `redact(_:)` output — one redaction path, so a masked table with an unmasked `--json` is
/// impossible by construction (§10.2 back-door closed).
///
/// ## Privacy contract (§11.1 RATIFIED, LOCKED — WP2 enforces, must not widen)
/// - Body → `previewBodyMax` (40) characters + a trailing `…` when longer; `truncated:true` in JSON.
/// - Sender phone → `+1*******89` shape (leading prefix + last two, middle masked).
/// - Sender email → `j****@e***.com` shape (first local char + first domain char + TLD).
/// - `is_from_me == true` → sender rendered `me` BEFORE masking (no self-handle masked-then-leaked).
///
/// ## odb F1 — mask TOTALITY (the privacy contract). Every transform is TOTAL and fail-safe:
/// a value too short to mask meaningfully emits a FIXED redaction token (`redactedToken`), NEVER the
/// raw value; truncation is grapheme-safe (`Character` indexing, never UTF-16/byte offsets); no
/// force-unwrap, no `split(...)[1]`.
///
/// ## WP2 DESIGN DECISION (recorded, NOT a §11.1 lock)
/// Contact-name masking ("Ada Lovelace" → "Ada L*****") and the `(none)` token for null
/// phone/email/organization are a WP2 presentation call. §11.1 ratified ONLY body/sender/is_from_me;
/// the §10.1 `Ada L*****` form is illustrative. The algorithm is defined explicitly below
/// (first name kept, last name first-char + mask; `(none)` for null/empty) so U_god has a concrete
/// contract to check, rather than meth inventing it implicitly under TDD.
enum InspectRedaction {

    // MARK: Named bounds (one greppable line each — cannot drift)

    /// §11.1 RATIFIED body character cap. A single named constant so the bound cannot drift.
    static let previewBodyMax = 40

    /// The fail-safe fixed redaction token for a value too short to mask without revealing it.
    static let redactedToken = "•••"

    /// The token for a null / empty field (§10.1 `(none)`).
    static let noneToken = "(none)"

    // MARK: Pure display models

    struct RedactedBody: Equatable {
        let text: String
        let truncated: Bool
    }

    /// A redacted message row for table + JSON. `from` is already `me` or a masked handle.
    struct RedactedMessage: Encodable, Equatable {
        let when: String
        let from: String
        let direction: String      // "sent" | "received" (derived from is_from_me; raw key ABSENT)
        let service: String
        let bodyPreview: String
        let truncated: Bool

        enum CodingKeys: String, CodingKey {
            case when, from, direction, service
            case bodyPreview = "body_preview"
            case truncated
        }
    }

    /// A redacted contact row for table + JSON.
    struct RedactedContact: Encodable, Equatable {
        let name: String
        let organization: String
        let phone: String
        let email: String
    }

    /// A redacted call row for table + JSON (K5): `address` masked via `maskPhone`; `when` is the
    /// pass-through date (or `(none)` when the reader surfaced a nil date — M1, never a fabricated
    /// epoch); `duration`/`direction`/`callType` pass through (K5 masks only the address).
    struct RedactedCall: Encodable, Equatable {
        let when: String
        let address: String
        let duration: String
        let direction: String
        let callType: String

        enum CodingKeys: String, CodingKey {
            case when, address, duration, direction
            case callType = "call_type"
        }
    }

    /// A redacted note row for table + JSON (K5): `title`, `snippet`, AND `folder` truncated to
    /// `previewBodyMax` (40) via `redactBody` (folder truncation is the Deau K5 ruling); `created`/
    /// `modified` pass through. A nil/empty field → `(none)`; a nil date (M1) → `(none)` (NEVER a
    /// fabricated epoch). No `body` field exists (export-only body policy).
    struct RedactedNote: Encodable, Equatable {
        let title: String
        let snippet: String
        let created: String
        let modified: String
        let folder: String
    }

    // MARK: Body truncation (grapheme-safe — odb F1)

    /// Truncates a body to `previewBodyMax` GRAPHEMES (never UTF-16/byte offsets), appending `…` only
    /// when the body is strictly longer. A body of EXACTLY `previewBodyMax` is returned unchanged with
    /// `truncated:false` (no ellipsis at the boundary). `nil`/empty → empty, not truncated.
    static func redactBody(_ body: String?) -> RedactedBody {
        guard let body, !body.isEmpty else { return RedactedBody(text: "", truncated: false) }
        // `count` and `prefix` operate on `Character` (extended grapheme clusters), so a multibyte
        // emoji is one unit and is never split mid-grapheme.
        guard body.count > previewBodyMax else { return RedactedBody(text: body, truncated: false) }
        let kept = String(body.prefix(previewBodyMax))
        return RedactedBody(text: kept + "…", truncated: true)
    }

    // MARK: Sender masking (§11.1) — total, fail-safe (odb F1)

    /// Masks a phone to the `+1*******89` shape: keep everything up to the last two digits, mask the
    /// middle, keep the last two. A value too short to mask without revealing it → `redactedToken`.
    static func maskPhone(_ phone: String) -> String {
        // Keep at most a 2-char leading prefix + the last 2 chars; mask the middle. Too short to
        // mask meaningfully (≤ 4 chars where prefix+suffix would cover the whole value) → token.
        let chars = Array(phone)
        guard chars.count >= 5 else { return redactedToken }
        let prefixLen = chars.first == "+" ? 2 : 1
        let lead = String(chars.prefix(prefixLen))
        let tail = String(chars.suffix(2))
        let maskedCount = chars.count - prefixLen - 2
        guard maskedCount >= 1 else { return redactedToken }
        return lead + String(repeating: "*", count: maskedCount) + tail
    }

    /// Masks an email to the `j****@e***.com` shape: first local char + masked, first domain char +
    /// masked + the TLD. Totally fail-safe: no `@` separator, empty, or too-short → `redactedToken`
    /// (NEVER the raw value). No unguarded `split("@")[1]`.
    static func maskEmail(_ email: String) -> String {
        guard let atIndex = email.firstIndex(of: "@") else { return redactedToken }
        let local = String(email[email.startIndex..<atIndex])
        let domainFull = String(email[email.index(after: atIndex)...])
        guard let firstLocal = local.first, let firstDomain = domainFull.first else {
            return redactedToken
        }
        // Split the domain into name + TLD on the LAST dot; no dot → mask the whole domain (no TLD
        // to reveal). This keeps `j****@e***.com` while never echoing a dotless / too-short domain.
        let tld: String
        let domainName: String
        if let lastDot = domainFull.lastIndex(of: "."), lastDot != domainFull.startIndex {
            tld = String(domainFull[lastDot...])         // includes the leading dot, e.g. ".com"
            domainName = String(domainFull[domainFull.startIndex..<lastDot])
        } else {
            tld = ""
            domainName = domainFull
        }
        let localMaskCount = max(local.count - 1, 1)
        let domainMaskCount = max(domainName.count - 1, 1)
        return "\(firstLocal)\(String(repeating: "*", count: localMaskCount))@" +
               "\(firstDomain)\(String(repeating: "*", count: domainMaskCount))\(tld)"
    }

    /// Dispatches a sender handle to phone- or email-masking by the presence of `@`.
    static func maskSender(_ sender: String) -> String {
        sender.contains("@") ? maskEmail(sender) : maskPhone(sender)
    }

    // MARK: Contact-name masking (WP2 DESIGN DECISION — recorded above, not §11.1)

    /// "Ada Lovelace" → "Ada L*****". First name kept; last name → first char + mask. A nil/empty
    /// name → `noneToken`. A one-char last name → first char + a single mask char (never echoed raw
    /// past a token). Totally fail-safe (odb F1).
    static func maskName(first: String?, last: String?) -> String {
        let f = (first ?? "").trimmingCharacters(in: .whitespaces)
        let l = (last ?? "").trimmingCharacters(in: .whitespaces)
        let maskedLast: String
        if let firstChar = l.first {
            maskedLast = String(firstChar) + String(repeating: "*", count: max(l.count - 1, 1))
        } else {
            maskedLast = ""
        }
        let joined = [f, maskedLast].filter { !$0.isEmpty }.joined(separator: " ")
        return joined.isEmpty ? noneToken : joined
    }

    // MARK: Row redaction — the SOLE path (table + JSON both call this)

    /// Redacts a message row. `is_from_me → 'me'` is applied BEFORE masking, so a self-handle is
    /// never masked-then-leaked.
    static func redact(_ row: MessageRow) -> RedactedMessage {
        let from: String
        if row.isFromMe {
            from = "me"                                   // BEFORE masking — no self-handle leak
        } else if let sender = row.sender, !sender.isEmpty {
            from = maskSender(sender)
        } else {
            from = noneToken
        }
        let body = redactBody(row.body)
        return RedactedMessage(
            when: row.date,
            from: from,
            direction: row.isFromMe ? "sent" : "received",
            service: row.service ?? "",
            bodyPreview: body.text,
            truncated: body.truncated)
    }

    /// Redacts a contact row: name masked (WP2 call), phone/email masked, `(none)` for null.
    static func redact(_ row: ContactRow) -> RedactedContact {
        let phone: String
        if let p = row.primaryPhone, !p.isEmpty { phone = maskPhone(p) } else { phone = noneToken }
        let email: String
        if let e = row.primaryEmail, !e.isEmpty { email = maskEmail(e) } else { email = noneToken }
        let org = (row.organization?.isEmpty == false) ? (row.organization ?? noneToken) : noneToken
        return RedactedContact(
            name: maskName(first: row.first, last: row.last),
            organization: org,
            phone: phone,
            email: email)
    }

    /// Redacts a call row (K5): the `address` is masked with the §11.1 phone mask; `when`/`duration`/
    /// `direction`/`call_type` pass through. A nil address → `(none)`; a nil date (M1) → `(none)`
    /// (NEVER a fabricated epoch); a nil call_type → `(none)`.
    static func redact(_ row: CallRow) -> RedactedCall {
        let address: String
        if let a = row.address, !a.isEmpty { address = maskPhone(a) } else { address = noneToken }
        return RedactedCall(
            when: row.date ?? noneToken,
            address: address,
            duration: String(row.duration),
            direction: row.direction,
            callType: row.callType ?? noneToken)
    }

    /// Redacts a note row (K5): `title`, `snippet`, AND `folder` are truncated to `previewBodyMax` (40)
    /// via `redactBody` (grapheme-safe, ellipsis when longer) — the folder truncation is the Deau K5
    /// ruling, symmetric with title/snippet (same path, no separate truncated flag). `created`/`modified`
    /// pass through. A nil/empty title/snippet/folder → `(none)`; a nil date (M1) → `(none)`, NEVER a
    /// forged epoch.
    static func redact(_ row: NoteRow) -> RedactedNote {
        let title = redactBody(row.title).text
        let snippet = redactBody(row.snippet).text
        let folder = redactBody(row.folder).text
        return RedactedNote(
            title: title.isEmpty ? noneToken : title,
            snippet: snippet.isEmpty ? noneToken : snippet,
            created: row.created ?? noneToken,
            modified: row.modified ?? noneToken,
            folder: folder.isEmpty ? noneToken : folder)
    }

    // MARK: Table assembly (default output)

    static let messageHeader = ["WHEN", "FROM", "DIR", "SVC", "BODY"]
    static let contactHeader = ["NAME", "ORG", "PHONE", "EMAIL"]
    static let callHeader = ["WHEN", "ADDRESS", "DUR", "DIR", "TYPE"]
    static let noteHeader = ["TITLE", "SNIPPET", "CREATED", "MODIFIED", "FOLDER"]

    /// Builds the messages preview TABLE from the (already SQL-capped) rows. Every row is fixed-arity
    /// matching `messageHeader` so `TextTable` never traps on a ragged row (odb R-new-1).
    static func messageTable(_ rows: [MessageRow], limit: Int) -> TextTable {
        TextTable(header: messageHeader, rows: rows.map { row in
            let r = redact(row)
            return [r.when, r.from, r.direction, r.service, r.bodyPreview]
        })
    }

    static func contactTable(_ rows: [ContactRow], limit: Int) -> TextTable {
        TextTable(header: contactHeader, rows: rows.map { row in
            let r = redact(row)
            return [r.name, r.organization, r.phone, r.email]
        })
    }

    /// Builds the calls preview TABLE from the (already SQL-capped) rows. Fixed-arity per row matching
    /// `callHeader` so `TextTable` never traps on a ragged row (odb R-new-1).
    static func callTable(_ rows: [CallRow], limit: Int) -> TextTable {
        TextTable(header: callHeader, rows: rows.map { row in
            let r = redact(row)
            return [r.when, r.address, r.duration, r.direction, r.callType]
        })
    }

    /// Builds the notes preview TABLE from the (already SQL-capped) rows. Fixed-arity per row matching
    /// `noteHeader` so `TextTable` never traps on a ragged row (odb R-new-1).
    static func noteTable(_ rows: [NoteRow], limit: Int) -> TextTable {
        TextTable(header: noteHeader, rows: rows.map { row in
            let r = redact(row)
            return [r.title, r.snippet, r.created, r.modified, r.folder]
        })
    }

    /// The footer that points the user at `export`. Gated on `shown == cap` (odb M2): when fewer rows
    /// than the cap came back we KNOW there are no more, so no footer; only at the cap can more exist.
    /// No fabricated N (the capped read returns no full count; OI1).
    static func moreRowsFooter(shown: Int, cap: Int) -> String? {
        guard shown == cap else { return nil }
        return "… more rows (use `export` for the full store)"
    }

    // MARK: --json envelope assembly (capped + redacted — §10.2)

    /// The `--json` preview envelope: `{store, preview:true, shown, total, rows}`. `total` is always
    /// `nil` (omitted) — the capped read returns no full count and WP2 adds no `COUNT(*)` pass (OI1).
    struct MessageEnvelope: Encodable {
        let store: String
        let preview: Bool
        let shown: Int
        let total: Int?
        let rows: [RedactedMessage]
    }

    struct ContactEnvelope: Encodable {
        let store: String
        let preview: Bool
        let shown: Int
        let total: Int?
        let rows: [RedactedContact]
    }

    static func messageJSON(_ rows: [MessageRow], limit: Int) -> MessageEnvelope {
        let redacted = rows.map(redact)
        return MessageEnvelope(store: "messages", preview: true,
                               shown: redacted.count, total: nil, rows: redacted)
    }

    static func contactJSON(_ rows: [ContactRow], limit: Int) -> ContactEnvelope {
        let redacted = rows.map(redact)
        return ContactEnvelope(store: "contacts", preview: true,
                               shown: redacted.count, total: nil, rows: redacted)
    }

    struct CallEnvelope: Encodable {
        let store: String
        let preview: Bool
        let shown: Int
        let total: Int?
        let rows: [RedactedCall]
    }

    static func callJSON(_ rows: [CallRow], limit: Int) -> CallEnvelope {
        let redacted = rows.map(redact)
        return CallEnvelope(store: "calls", preview: true,
                            shown: redacted.count, total: nil, rows: redacted)
    }

    struct NoteEnvelope: Encodable {
        let store: String
        let preview: Bool
        let shown: Int
        let total: Int?
        let rows: [RedactedNote]
    }

    static func noteJSON(_ rows: [NoteRow], limit: Int) -> NoteEnvelope {
        let redacted = rows.map(redact)
        return NoteEnvelope(store: "notes", preview: true,
                            shown: redacted.count, total: nil, rows: redacted)
    }

    // MARK: Lazy-password load seam (G3 / constraint a)

    /// The pure load seam that proves the `@autoclosure` password is forwarded LAZILY: `password` is
    /// an `@autoclosure` carried into `read` UNEVALUATED (as a thunk), exactly as `Inspect.run()`
    /// forwards `PasswordInput.read()` into `reader.messages/contacts(...)`. `read` is the
    /// reader-call stand-in: it receives the still-unevaluated thunk and — like the WP1 reader's
    /// `if isEncrypted { pw = password() }` gate — pulls it ONLY on the encrypted branch. A plaintext
    /// load therefore never evaluates the password, so a plaintext `inspect` never prompts. Mirrors
    /// WP1's `plaintextReadNeverEvaluatesPassword` on a CLI-layer seam, without driving `run()`
    /// (which resolves the real `.defaultRoot`). `isEncrypted` is in the signature so the seam
    /// documents the branch the reader gates on, even though the gate itself lives in the reader.
    static func load<Row>(isEncrypted: Bool,
                          password: @autoclosure @escaping () -> String,
                          read: (@escaping () -> String) throws -> [Row]) rethrows -> [Row] {
        _ = isEncrypted   // the reader (here, the injected `read`) owns the `if isEncrypted` gate
        // Forward the closure LAZILY (the `@autoclosure` `password` thunk itself, unevaluated) so the
        // read never evaluates it unless it chooses to — in spirit to the WP1 reader's lazy forward.
        return try read(password)
    }
}
