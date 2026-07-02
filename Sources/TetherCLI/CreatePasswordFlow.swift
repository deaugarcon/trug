import Foundation
import BackupCore

/// WP6.1 (checkpoint-E): the create-time password flow as PURE / INJECTABLE seams, so the
/// sequencing that burned two ~75GB transfers is provable WITHOUT a device and WITHOUT process exit
/// (Odb Q1, gate-blocking). `Backup.Create.run()` is a thin caller over these — it owns the device
/// reads and the terminal `exit`; this owns the decisions and the loops.
///
/// Design placement (Odb RULING, binding): the bounded RETRY lives HERE in `TetherCLI`, lexically
/// OUTSIDE `BackupStore.finalize` — the §4.1 promote-only-on-verified gate sees an already-proven
/// password and is byte-untouched (option (ii), not (i): no retry/attempt parameter was pushed into
/// `BackupVerifier` or `BackupCore`).
enum CreatePasswordFlow {

    /// What the create orchestration must do for the encrypted-password BEFORE the transfer, given the
    /// device's `WillEncrypt`, whether `TRUG_BACKUP_PASSWORD` is set, and whether stdin is a TTY.
    ///
    /// Mirrors the proven-testable `EncryptionControl.decide(op:willEncrypt:)` pure-guard pattern: a
    /// total function over the three observable inputs, returning one of four outcomes — no IO, no
    /// device, no exit. The env check PRECEDES the TTY check (design note #3): a non-TTY run WITH the
    /// env set is the supported CI path and must NOT fail-fast.
    enum PreflightDecision: Equatable {
        /// Plaintext device (`WillEncrypt == false`): no preflight, no prompt, no fail-fast. The
        /// surviving F2 invariant — a plaintext create never resolves a password it cannot use.
        case proceedNoPreflight
        /// Encrypted + env present: resolve from `TRUG_BACKUP_PASSWORD`, no double-entry (a single
        /// authoritative value has nothing to double-enter).
        case proceedWithEnv
        /// Encrypted + no env + interactive TTY: prompt with double-entry (read twice, compare).
        case promptDoubleEntry
        /// Encrypted + no env + NON-TTY: abort BEFORE the transfer (F-E3) — there is no way to resolve
        /// a password and no point transferring 75GB only to fail at verify.
        case failFast
    }

    /// Pure preflight guard. `envPresent` is "the env var is set to a non-empty value"; `isTTY` is the
    /// same `tcgetattr(STDIN)`-succeeds probe `PasswordInput.readNoEcho` already relies on.
    static func decide(willEncrypt: Bool, envPresent: Bool, isTTY: Bool) -> PreflightDecision {
        guard willEncrypt else { return .proceedNoPreflight }
        if envPresent { return .proceedWithEnv }     // env BEFORE TTY (note #3) — CI path stays alive
        return isTTY ? .promptDoubleEntry : .failFast
    }

    /// Double-entry resolve (F-E1): read the password twice, accept only on a match, re-ask on a
    /// mismatch — BOUNDED to `maxAttempts` PAIRS so a pathological stdin (a TTY for read 1, broken to
    /// EOF for read 2) cannot spin forever (C2 / R1). On budget exhaustion, throws
    /// `KeybagError.wrongPassword` (the user-input / exit-2 class) — the "entered incorrectly" story,
    /// distinct from the fail-fast "set TRUG_BACKUP_PASSWORD" story.
    ///
    /// `readOnce` is injected so a test drives N reads with no terminal; production passes a no-echo
    /// reader. The two reads of a pair are independent so each is a fresh no-echo prompt.
    static func doubleEntry(maxAttempts: Int, readOnce: () -> String) throws -> String {
        for _ in 0..<max(1, maxAttempts) {
            let first = readOnce()
            let second = readOnce()
            if first == second { return first }
        }
        throw KeybagError.wrongPassword
    }

    /// Bounded verify-retry (F-E2, option (ii)) — the BODY of the `verifyPassed` closure that
    /// `Create.run()` hands to `BackupStore.finalize` (artifact CRITICAL SEAM CORRECTION, binding):
    /// the loop lives INSIDE that closure, NOT in a wrapper around `finalize`. `finalize` runs
    /// `markFailed` on the FIRST throw that escapes `verifyPassed`, so a wrapper-around-finalize would
    /// catch `wrongPassword` only AFTER the staging is already dead (the too-late variant that
    /// re-creates the bug). By being the closure body, this loop re-prompts and re-verifies in-place
    /// and lets a throw escape ONLY after the budget is exhausted — `finalize` sees exactly ONE
    /// outcome: a clean `true` (promote) or a single final throw (one `markFailed`, exit 2). The §4.1
    /// gate's first-escaping-throw semantics are byte-untouched.
    ///
    /// Runs `verify` against `initial` (the preflight-resolved password — the happy path is ONE entry,
    /// A1), and on a RETRYABLE password miss re-prompts and re-verifies, up to `maxAttempts` TOTAL
    /// verifies (Q3: 3 total, NOT preflight + 3). Verify runs exactly ONCE on success. Returns the
    /// verify's `passed` result so it IS a `() throws -> Bool` for `finalize`.
    ///
    /// Retryable = a password the user can fix: `KeybagError.wrongPassword` (a typo) or
    /// `VerifyError.passwordRequired` (a mistyped-to-empty entry, design line 100). Any OTHER thrown
    /// error (a corrupt manifest, an IO fault) is NOT a password miss and propagates IMMEDIATELY — the
    /// retry must never paper over a genuine integrity fault. On budget exhaustion the LAST password
    /// error propagates so `finalize`'s catch runs its single `markFailed` and `exitReporting` maps it
    /// to the exit-2 user-input class.
    ///
    /// `initial` is `@autoclosure` AND is forwarded to `verify` as a DEFERRED closure — never
    /// materialized by this loop. This preserves the surviving F2 invariant end-to-end: the verifier
    /// itself takes the password as `@autoclosure` and pulls it only once it proves the backup
    /// encrypted, so a PLAINTEXT create whose `verify` never touches the password never evaluates the
    /// `PasswordInput.read()` fallback that seeds `initial` — no prompt, no hang. If this loop pulled
    /// `initial()` eagerly to hand `verify` a `String`, that laziness would be lost (the bug a
    /// plaintext-survivor test catches). `prompt` is the RETRY reader (no env — the env value already
    /// failed or is absent, Q4). On the FIRST attempt `verify` gets the lazy `initial`; on a retry it
    /// gets the (eagerly-read) re-prompt value. All injected so a test drives wrong-then-right with no
    /// device, no terminal.
    @discardableResult
    static func verifyWithRetry(maxAttempts: Int,
                                initial: @autoclosure @escaping () -> String,
                                prompt: () -> String,
                                verify: (@escaping () -> String) throws -> Bool) throws -> Bool {
        var passwordSource: () -> String = initial   // lazy on attempt #1 (F2-preserving)
        var attempt = 1
        while true {
            do {
                return try verify(passwordSource)
            } catch let error where isRetryablePasswordError(error) {
                guard attempt < max(1, maxAttempts) else { throw error }   // exhausted -> last error
                attempt += 1
                let reentered = prompt()                                   // re-prompt, no env (Q4)
                passwordSource = { reentered }                            // retry value is eager
            }
        }
    }

    /// A password miss the user can correct by re-typing: a wrong password, or an empty entry that
    /// surfaced as `passwordRequired`. Anything else (corrupt/unreadable manifest, etc.) is NOT
    /// retryable and must propagate unswallowed.
    static func isRetryablePasswordError(_ error: Error) -> Bool {
        if case KeybagError.wrongPassword = error { return true }
        if case VerifyError.passwordRequired = error { return true }
        return false
    }
}
