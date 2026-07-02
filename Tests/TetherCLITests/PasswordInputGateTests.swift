import Testing
import BackupCore
@testable import TetherCLI

/// WP6.2 (checkpoint-E F-E5): the NEW-password resolve gate for `encryption enable`/`rotate`.
/// `PasswordInput.readNew()` was SINGLE-entry — a one-char munge set an unknown device backup
/// password with no confirmation, a lockout recoverable only via the device's Reset All Settings
/// (it materialized at checkpoint E). The fix routes the new-password resolve through the WP6.1
/// `CreatePasswordFlow.doubleEntry` seam, but ONLY interactively — the env source stays single-source.
///
/// The pure decision (env-present → single read; env-absent + TTY → double-entry; env-absent +
/// non-TTY → single read) is `newPasswordGate`, unit-tested here device-free exactly like WP6.1's
/// `CreatePasswordFlow.decide`. The double-entry compare/bound is ALREADY proven in
/// `CreatePasswordFlowTests` (the seam is REUSED, not re-written) — not duplicated here.
@Suite struct PasswordInputGateTests {

    // MARK: - Env/TTY gate (pure, NEW) — Odb test matrix line 122

    /// THE env single-source guard (Odb R1/Q1, gate-blocking): with `TRUG_BACKUP_NEW_PASSWORD`
    /// set, the resolve is a SINGLE read — NO double-entry — for BOTH a TTY and a non-TTY (the CI
    /// path). A set env is one authoritative value; double-prompting it is meaningless and would
    /// hang/mismatch in CI. A naive "wrap readNew in doubleEntry" regression (dropping the env gate)
    /// turns this RED — and it is the one silent regression no existing test catches.
    @Test func envPresentResolvesSingleSourceNoDoubleEntry() {
        #expect(PasswordInput.newPasswordGate(envPresent: true, isTTY: true) == .useEnv)
        #expect(PasswordInput.newPasswordGate(envPresent: true, isTTY: false) == .useEnv)
    }

    /// Env absent + interactive TTY → double-entry (the F-E5 fix: read twice, confirm).
    @Test func envAbsentTTYUsesDoubleEntry() {
        #expect(PasswordInput.newPasswordGate(envPresent: false, isTTY: true) == .doubleEntry)
    }

    /// Env absent + NON-TTY (a pipe, no env) → a SINGLE no-echo read (Odb A2/Q4). enable/rotate have
    /// nothing to abort (unlike create's failFast before a 75GB transfer), so the non-TTY-no-env path
    /// degrades to one read — NOT a double-entry that would EOF-mismatch on the second read, and NOT
    /// a fail-fast. This matches `readNew()`'s current non-TTY behavior byte-for-byte.
    @Test func envAbsentNonTTYUsesSingleRead() {
        #expect(PasswordInput.newPasswordGate(envPresent: false, isTTY: false) == .singleRead)
    }

    /// The env check PRECEDES the TTY check (mirrors WP6.1 design note #3): env-present + non-TTY is
    /// the supported CI path and MUST resolve to `useEnv`, never `singleRead`/`doubleEntry`. A
    /// regression that checks TTY before env would mis-route the CI path.
    @Test func envPrecedesTTYForTheCIPath() {
        #expect(PasswordInput.newPasswordGate(envPresent: true, isTTY: false) == .useEnv)
        #expect(PasswordInput.newPasswordGate(envPresent: true, isTTY: false) != .doubleEntry)
        #expect(PasswordInput.newPasswordGate(envPresent: true, isTTY: false) != .singleRead)
    }

    /// The gate has EXACTLY three outcomes — there is NO `failFast` case (Odb A2: enable/rotate
    /// always need a value if they reach the resolve; there is no transfer to abort). Pins the case
    /// space so a future `failFast` (wrongly copied from `CreatePasswordFlow.decide`) turns RED.
    @Test func gateHasNoFailFastOutcome() {
        let outcomes: [PasswordInput.NewPasswordSource] = [
            PasswordInput.newPasswordGate(envPresent: true, isTTY: true),
            PasswordInput.newPasswordGate(envPresent: true, isTTY: false),
            PasswordInput.newPasswordGate(envPresent: false, isTTY: true),
            PasswordInput.newPasswordGate(envPresent: false, isTTY: false),
        ]
        // Every outcome is one of the three valid sources; none is an abort.
        for outcome in outcomes {
            #expect(outcome == .useEnv || outcome == .doubleEntry || outcome == .singleRead)
        }
    }

    // MARK: - Resolver read-count contract (the SOLE env-drop guard) — Odb R1/Q1, U_god note #0

    /// THE gate-blocking guard (team-lead correction 2026-06-13): with `TRUG_BACKUP_NEW_PASSWORD`
    /// set, the resolve consumes the env value with EXACTLY ZERO interactive reads — the double-entry
    /// confirm pass is NEVER invoked. This is the env-dropping-swap regression NO existing test catches
    /// (`EncryptionControlGatedTests` passes a string literal at the engine layer, is device-gated, and
    /// bypasses `PasswordInput` entirely). Driving the pure `resolveNewPassword` with a counting reader
    /// proves the `.useEnv` arm is single-source: the returned value is the env value, and `readOnce`
    /// fired 0 times. A naive "wrap readNew in doubleEntry" (dropping the env gate) makes this RED.
    @Test func envSourceConsumesZeroInteractiveReads() throws {
        var reads = 0
        let resolved = try PasswordInput.resolveNewPassword(
            source: .useEnv,
            envValue: "from-env",
            readOnce: { _ in reads += 1; return "should-never-be-read" })
        #expect(resolved == "from-env")
        #expect(reads == 0)   // env is single-source — NO interactive read, NO confirm pass
    }

    /// The interactive arm reads TWICE (a pair) and confirms: a matching pair accepts the entered
    /// value, and the confirm read uses the `confirming: true` prompt selector. Proves `.doubleEntry`
    /// routes through the WP6.1 `CreatePasswordFlow.doubleEntry` seam (the compare/bound is already
    /// covered there — not duplicated; this pins the WIRING and the read count).
    @Test func doubleEntryArmReadsTwiceAndConfirms() throws {
        var prompts: [Bool] = []      // records the `confirming` flag of each read, in order
        let resolved = try PasswordInput.resolveNewPassword(
            source: .doubleEntry,
            envValue: "ignored-when-not-useEnv",
            readOnce: { confirming in prompts.append(confirming); return "match" })
        #expect(resolved == "match")
        #expect(prompts == [false, true])   // first read = new prompt, second = confirm prompt
    }

    /// The non-TTY pipe arm reads EXACTLY ONCE (no second read to confirm against — a double-entry
    /// would EOF-mismatch on a pipe). The single read uses the non-confirm prompt. Pins Odb A2/Q4.
    @Test func singleReadArmReadsExactlyOnce() throws {
        var prompts: [Bool] = []
        let resolved = try PasswordInput.resolveNewPassword(
            source: .singleRead,
            envValue: "ignored-when-not-useEnv",
            readOnce: { confirming in prompts.append(confirming); return "piped" })
        #expect(resolved == "piped")
        #expect(prompts == [false])   // exactly one read, the non-confirm prompt — never a confirm pass
    }

    /// The interactive arm is BOUNDED at 3 (reused C2): a forever-mismatching reader aborts at the
    /// budget with the exit-2 wrong-password class — it never spins. (The full compare/bound matrix
    /// lives in CreatePasswordFlowTests:50–72; this pins that `.doubleEntry` inherits the bound via
    /// the reused seam, not a forked loop.)
    @Test func doubleEntryArmIsBoundedThroughTheReusedSeam() {
        var values = ["a", "b", "c", "d", "e", "f", "g", "h"].makeIterator()   // never two-in-a-row equal
        #expect(throws: KeybagError.wrongPassword) {
            _ = try PasswordInput.resolveNewPassword(
                source: .doubleEntry,
                envValue: "ignored",
                readOnce: { _ in values.next() ?? "z" })
        }
    }
}
