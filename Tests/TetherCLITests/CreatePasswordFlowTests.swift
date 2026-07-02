import Testing
import BackupCore
@testable import TetherCLI

/// WP6.1 (checkpoint-E): the create-time password flow — preflight resolve, double-entry, bounded
/// retry, and non-TTY fail-fast — pinned through the PURE / INJECTABLE seams the design mandates
/// (Odb Q1, gate-blocking). Every case here runs WITHOUT a device and WITHOUT process exit: the
/// terminal `Backup.Create.run()` is a thin caller over these seams, so the sequencing logic that
/// burned two ~75GB transfers is provable off-hardware.
@Suite struct CreatePasswordFlowTests {

    // MARK: - Preflight decision (pure) — design test matrix line 98

    /// A plaintext device needs no preflight at all: no prompt, no fail-fast (the surviving F2
    /// invariant — preflight only resolves when WillEncrypt).
    @Test func plaintextDeviceProceedsWithNoPreflight() {
        #expect(CreatePasswordFlow.decide(willEncrypt: false, envPresent: false, isTTY: true) == .proceedNoPreflight)
        #expect(CreatePasswordFlow.decide(willEncrypt: false, envPresent: true, isTTY: false) == .proceedNoPreflight)
    }

    /// Encrypted device + env present -> use the env value, NO double-entry (env is a single
    /// authoritative value; double-prompting it is meaningless — design F-E1).
    @Test func encryptedWithEnvProceedsWithEnvNoDoubleEntry() {
        #expect(CreatePasswordFlow.decide(willEncrypt: true, envPresent: true, isTTY: true) == .proceedWithEnv)
        #expect(CreatePasswordFlow.decide(willEncrypt: true, envPresent: true, isTTY: false) == .proceedWithEnv)
    }

    /// Encrypted device + no env + interactive TTY -> double-entry prompt.
    @Test func encryptedNoEnvTTYPromptsDoubleEntry() {
        #expect(CreatePasswordFlow.decide(willEncrypt: true, envPresent: false, isTTY: true) == .promptDoubleEntry)
    }

    /// Encrypted device + no env + NON-TTY -> fail-fast (F-E3). The env check MUST precede the TTY
    /// check: this is reached only because env is absent.
    @Test func encryptedNoEnvNonTTYFailsFast() {
        #expect(CreatePasswordFlow.decide(willEncrypt: true, envPresent: false, isTTY: false) == .failFast)
    }

    /// THE env-before-TTY guard (design note #3 / matrix line 103): a NON-TTY run WITH the env set is
    /// the supported CI path and MUST NOT fail-fast — it proceeds with env. A regression that fails-fast
    /// on `!isatty` alone (dropping the env precedence) turns this RED.
    @Test func nonTTYWithEnvIsTheSupportedCIPathNotFailFast() {
        #expect(CreatePasswordFlow.decide(willEncrypt: true, envPresent: true, isTTY: false) != .failFast)
        #expect(CreatePasswordFlow.decide(willEncrypt: true, envPresent: true, isTTY: false) == .proceedWithEnv)
    }

    // MARK: - Double-entry (pure, bounded) — design test matrix line 99 / C2

    /// Two equal reads accept on the first pass.
    @Test func doubleEntryAcceptsMatchingFirstPair() throws {
        var reads = ["hunter2", "hunter2"].makeIterator()
        let value = try CreatePasswordFlow.doubleEntry(maxAttempts: 3) { reads.next() ?? "" }
        #expect(value == "hunter2")
    }

    /// A mismatch re-asks; a later matching pair is accepted (design: "two mismatches then a match ->
    /// accept on the match").
    @Test func doubleEntryReAsksOnMismatchThenAcceptsMatch() throws {
        // pass 1: "a" vs "b" (mismatch) -> re-ask; pass 2: "c" vs "c" (match) -> accept.
        var reads = ["a", "b", "c", "c"].makeIterator()
        let value = try CreatePasswordFlow.doubleEntry(maxAttempts: 3) { reads.next() ?? "" }
        #expect(value == "c")
    }

    /// The mismatch re-ask is BOUNDED (C2 / R1): a stdin that mismatches forever aborts at the budget
    /// with the wrong-password (exit-2) class — it never spins `while true`.
    @Test func doubleEntryBudgetExhaustionAborts() {
        var reads = ["a", "b", "c", "d", "e", "f", "g", "h"].makeIterator()  // never two-in-a-row equal
        #expect(throws: KeybagError.wrongPassword) {
            _ = try CreatePasswordFlow.doubleEntry(maxAttempts: 3) { reads.next() ?? "" }
        }
    }

    // MARK: - Bounded retry (injected prompt + injected verify) — matrix line 100

    /// Happy path: the carried (preflight-resolved) password verifies on attempt #1 — verify runs
    /// EXACTLY ONCE on success, the prompt is NEVER consulted (no re-entry on the happy path / A1), and
    /// the retry RETURNS the verify's `passed` (`true`) so it IS the `() throws -> Bool` for `finalize`.
    /// `verify` pulls the password via the injected source closure (the same lazy seam the real
    /// verifier uses — F2-preserving).
    @Test func retrySucceedsOnFirstAttemptWithoutPrompting() throws {
        var verifyCalls = 0
        var promptCalls = 0
        let passed = try CreatePasswordFlow.verifyWithRetry(
            maxAttempts: 3,
            initial: "correct",
            prompt: { promptCalls += 1; return "unused" },
            verify: { source in verifyCalls += 1; if source() != "correct" { throw KeybagError.wrongPassword }; return true })
        #expect(passed)
        #expect(verifyCalls == 1)
        #expect(promptCalls == 0)
    }

    /// Wrong-then-right: attempt #1 (carried) is wrong -> re-prompt -> attempt #2 passes. Verify runs
    /// only on failure; success ends the loop and returns `true`.
    @Test func retryWrongThenRightSucceeds() throws {
        var verifyCalls = 0
        var promptCalls = 0
        let passed = try CreatePasswordFlow.verifyWithRetry(
            maxAttempts: 3,
            initial: "typo",
            prompt: { promptCalls += 1; return "correct" },
            verify: { source in verifyCalls += 1; if source() != "correct" { throw KeybagError.wrongPassword }; return true })
        #expect(passed)
        #expect(verifyCalls == 2)   // attempt #1 (typo) + attempt #2 (re-prompted, correct)
        #expect(promptCalls == 1)   // exactly one re-prompt
    }

    /// A correct password whose verify returns `false` (a NON-password defect — e.g. a missing shard)
    /// is NOT retried: `false` is a clean result, not a retryable throw, so it returns straight to
    /// `finalize` (which maps it to `verificationFailed` + markFailed). The retry must never re-prompt
    /// on a password-correct-but-backup-bad outcome.
    @Test func retryReturnsFalseWithoutRetryingOnNonPasswordDefect() throws {
        var verifyCalls = 0
        var promptCalls = 0
        let passed = try CreatePasswordFlow.verifyWithRetry(
            maxAttempts: 3,
            initial: "correct",
            prompt: { promptCalls += 1; return "x" },
            verify: { _ in verifyCalls += 1; return false })   // password fine, backup defective
        #expect(!passed)
        #expect(verifyCalls == 1)   // no retry on a clean false
        #expect(promptCalls == 0)
    }

    /// Three wrong entries exhaust the budget and propagate the LAST error (exit-2 class). The total
    /// verify count is 3 (Q3: "3 total verify attempts", NOT preflight + 3).
    @Test func retryExhaustionPropagatesLastErrorAfterThreeAttempts() {
        var verifyCalls = 0
        #expect(throws: KeybagError.wrongPassword) {
            _ = try CreatePasswordFlow.verifyWithRetry(
                maxAttempts: 3,
                initial: "wrong1",
                prompt: { "wrongN" },
                verify: { _ in verifyCalls += 1; throw KeybagError.wrongPassword })
        }
        #expect(verifyCalls == 3)   // attempt #1 (initial) + 2 re-prompts = 3 total
    }

    /// An empty entry surfaces as `VerifyError.passwordRequired` from the verify closure (the
    /// mistyped-to-empty case) and is treated as RETRYABLE just like wrongPassword (design line 100).
    @Test func retryTreatsPasswordRequiredAsRetryable() throws {
        var verifyCalls = 0
        let passed = try CreatePasswordFlow.verifyWithRetry(
            maxAttempts: 3,
            initial: "",
            prompt: { "correct" },
            verify: { source in
                verifyCalls += 1
                let pw = source()
                if pw.isEmpty { throw VerifyError.passwordRequired(udid: "U") }
                if pw != "correct" { throw KeybagError.wrongPassword }
                return true
            })
        #expect(passed)
        #expect(verifyCalls == 2)
    }

    /// A NON-password error (e.g. a corrupt manifest mid-verify) is NOT retryable — it propagates
    /// immediately without burning the budget or re-prompting. The retry is for password misses only;
    /// it must never paper over a genuine integrity fault.
    @Test func retryDoesNotSwallowNonPasswordErrors() {
        var verifyCalls = 0
        var promptCalls = 0
        #expect(throws: VerifyError.manifestUnreadable(reason: "x")) {
            _ = try CreatePasswordFlow.verifyWithRetry(
                maxAttempts: 3,
                initial: "correct",
                prompt: { promptCalls += 1; return "x" },
                verify: { _ in verifyCalls += 1; throw VerifyError.manifestUnreadable(reason: "x") })
        }
        #expect(verifyCalls == 1)   // thrown on the first attempt, no retry
        #expect(promptCalls == 0)
    }

    // MARK: - F2 survivor (the password is never pulled when verify does not use it) — matrix line 102

    /// THE surviving F2 invariant at the retry seam: on a PLAINTEXT-shaped create, `verify` succeeds
    /// WITHOUT consulting the password, so the lazy `initial` closure is NEVER evaluated — a plaintext
    /// create+verify still never prompts/hangs for a password it cannot use. `initial` is `@autoclosure`
    /// exactly so the `PasswordInput.read()` fallback that seeds it in `run()` is not pulled here.
    @Test func plaintextVerifyNeverPullsTheInitialPassword() throws {
        var initialPulled = false
        var promptCalls = 0
        let passed = try CreatePasswordFlow.verifyWithRetry(
            maxAttempts: 3,
            initial: { initialPulled = true; return "should-not-be-read" }(),
            prompt: { promptCalls += 1; return "x" },
            verify: { _ in true })   // plaintext: passes WITHOUT calling source() — password never pulled
        #expect(passed)
        #expect(initialPulled == false)   // the lazy password was never evaluated
        #expect(promptCalls == 0)
    }

    /// The retryability classifier is the load-bearing seam between "user can re-type this" and "this
    /// is a real fault." Pins both arms so a future broadening (e.g. retrying a corrupt manifest) or
    /// narrowing (dropping passwordRequired) turns RED.
    @Test func retryabilityClassifierIsExactlyThePasswordMisses() {
        #expect(CreatePasswordFlow.isRetryablePasswordError(KeybagError.wrongPassword))
        #expect(CreatePasswordFlow.isRetryablePasswordError(VerifyError.passwordRequired(udid: "U")))
        #expect(!CreatePasswordFlow.isRetryablePasswordError(VerifyError.manifestUnreadable(reason: "x")))
        #expect(!CreatePasswordFlow.isRetryablePasswordError(KeybagError.malformedKeybag))
        #expect(!CreatePasswordFlow.isRetryablePasswordError(BackupError.verificationFailed))
    }
}
