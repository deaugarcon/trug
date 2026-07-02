import Foundation

/// Reads a backup password for encrypted-backup operations.
///
/// Source order (Task 14): the environment variable FIRST (`TRUG_BACKUP_PASSWORD` /
/// `TRUG_BACKUP_NEW_PASSWORD`), else an interactive prompt with terminal echo DISABLED so the
/// password is never shown. The password is NEVER read from argv (it would leak into the process
/// list / shell history). The prompt is written to STDERR so stdout stays clean for piping
/// (`trug backup browse … | …`), and the typed value is returned without a trailing newline.
///
/// Callers must invoke `read()`/`readNew()` LAZILY (the engine seams take `@autoclosure`): the
/// prompt fires only once a backup is proven encrypted, so an unencrypted op never blocks on a
/// password it does not need.
enum PasswordInput {
    /// The current backup password: `TRUG_BACKUP_PASSWORD` env, else a no-echo prompt.
    static func read(prompt: String = "Backup password: ",
                     env: String = "TRUG_BACKUP_PASSWORD") -> String {
        if let value = ProcessInfo.processInfo.environment[env], !value.isEmpty { return value }
        FileHandle.standardError.write(Data(prompt.utf8))
        return readNoEcho()
    }

    /// A new backup password (for enable/rotate): `TRUG_BACKUP_NEW_PASSWORD` env, else a no-echo prompt.
    static func readNew() -> String {
        read(prompt: "New backup password: ", env: "TRUG_BACKUP_NEW_PASSWORD")
    }

    /// How `readNewWithConfirmation` resolves a NEW backup password (WP6.2 F-E5). Three outcomes,
    /// mirroring WP6.1's `proceedWithEnv`/`promptDoubleEntry` split but WITHOUT a `failFast` case:
    /// `decide`'s fail-fast has no meaning for enable/rotate (they have no transfer to abort — if they
    /// reach the resolve they NEED a value, Odb A2), so the non-interactive degrade is a single read.
    enum NewPasswordSource: Equatable {
        /// `TRUG_BACKUP_NEW_PASSWORD` is set: one authoritative value, no confirmation to double-enter.
        case useEnv
        /// No env + interactive TTY: read twice and confirm (the F-E5 lockout guard).
        case doubleEntry
        /// No env + non-TTY (a pipe): a single no-echo read — there is no second read to confirm against.
        case singleRead
    }

    /// Pure new-password resolve gate. The env check PRECEDES the TTY check (WP6.1 design note #3): an
    /// env-present run resolves from the env on BOTH a TTY and a non-TTY (the supported CI path), so a
    /// set `TRUG_BACKUP_NEW_PASSWORD` is NEVER double-prompted. Unit-tested device-free exactly like
    /// `CreatePasswordFlow.decide`; the process-coupled glue (env read + `tcgetattr` + `readNoEcho`)
    /// stays in `readNewWithConfirmation`.
    static func newPasswordGate(envPresent: Bool, isTTY: Bool) -> NewPasswordSource {
        if envPresent { return .useEnv }      // env BEFORE TTY — CI path is single-source, never confirmed
        return isTTY ? .doubleEntry : .singleRead
    }

    /// Resolves a NEW backup password for `encryption enable`/`rotate` WITH bounded double-entry
    /// confirmation (WP6.2 F-E5). A NEW password is write-once with no recovery oracle: a one-char
    /// munge sets an unknown device backup password (a lockout recoverable only via the device's Reset
    /// All Settings — it materialized at checkpoint E). The double-entry catches a transient typo; the
    /// SECURITY.md Warp note covers the systematic-munge case double-entry cannot.
    ///
    /// Env-first single-source, double-entry interactive-only (Odb ruling b): `TRUG_BACKUP_NEW_PASSWORD`
    /// is one authoritative value with nothing to confirm, so it resolves with a SINGLE read; the
    /// confirmation runs only on the env-absent interactive branch. The interactive arm REUSES the
    /// WP6.1 seam (`CreatePasswordFlow.doubleEntry`, bound 3) verbatim — one double-entry implementation
    /// across create and enable/rotate — and every read goes through `readNoEcho` so the F3
    /// fail-closed + no-echo guarantee holds on the confirm read too. On a budget-exhausted mismatch
    /// `doubleEntry` throws `KeybagError.wrongPassword` (the exit-2 user-input class, unchanged).
    static func readNewWithConfirmation() throws -> String {
        try resolveNewPassword(source: newPasswordGate(envPresent: backupPasswordEnvPresent(env: "TRUG_BACKUP_NEW_PASSWORD"),
                                                       isTTY: stdinIsTTY()),
                               envValue: ProcessInfo.processInfo.environment["TRUG_BACKUP_NEW_PASSWORD"] ?? "",
                               readOnce: { Self.promptedNoEchoRead(confirming: $0) })
    }

    /// Pure dispatch over the `NewPasswordSource` decision — the testable heart of
    /// `readNewWithConfirmation`, separated from the process-coupled glue (env read, `tcgetattr`,
    /// `readNoEcho`) so the read-count contract is provable device-free (Odb R1/Q1 — the SOLE guard
    /// against the silent env-dropping regression no existing test catches):
    ///  - `.useEnv` consumes the authoritative `envValue` with ZERO interactive reads (single-source;
    ///    the double-entry confirm pass is NEVER invoked for a set env).
    ///  - `.doubleEntry` runs the WP6.1 `CreatePasswordFlow.doubleEntry` seam (bound 3, reused
    ///    verbatim) over `readOnce` — two reads per pass, re-ask on mismatch, throw on exhaustion.
    ///  - `.singleRead` consumes exactly ONE `readOnce` (a pipe has no second read to confirm against).
    ///
    /// `readOnce(confirm:)` is injected: production passes the no-echo terminal reader; a test passes a
    /// counting closure to prove the per-source read count. `confirm` selects the prompt (false = the
    /// new-password prompt, true = the confirm prompt) so the interactive arm's two reads are distinct.
    static func resolveNewPassword(source: NewPasswordSource,
                                   envValue: String,
                                   readOnce: (_ confirming: Bool) -> String) throws -> String {
        switch source {
        case .useEnv:
            // Env precedence, unchanged from `read()`: a set, non-empty env value is authoritative.
            // ZERO interactive reads — the single-source guarantee (Q1).
            return envValue
        case .doubleEntry:
            var first = true
            return try CreatePasswordFlow.doubleEntry(maxAttempts: 3) {
                let confirming = !first
                first = false
                return readOnce(confirming)
            }
        case .singleRead:
            // Non-TTY, no env (a pipe): no second read to confirm against, so a single read — matches
            // `readNew()`'s current non-TTY behavior (Odb A2/Q4). NOT a fail-fast: nothing to abort.
            return readOnce(false)
        }
    }

    /// The production interactive reader for `resolveNewPassword`: writes the new-password (or confirm)
    /// prompt to stderr and reads through `readNoEcho` — so the F3 fail-closed + no-echo guarantee
    /// holds on EVERY read including the confirm (Odb ruling d / R2). The double-entry confirmation
    /// catches a transient typo; the SECURITY.md Warp note covers the systematic-munge case it cannot.
    private static func promptedNoEchoRead(confirming: Bool) -> String {
        let prompt = confirming ? "Confirm new backup password: " : "New backup password: "
        FileHandle.standardError.write(Data(prompt.utf8))
        return readNoEcho()
    }

    /// Whether `TRUG_BACKUP_PASSWORD` is set to a non-empty value — the `envPresent` input to the
    /// WP6.1 preflight guard (`CreatePasswordFlow.decide`). Mirrors the env precedence in `read()`:
    /// an empty env value is treated as absent (it would never satisfy `read()`'s `!value.isEmpty`).
    static func backupPasswordEnvPresent(env: String = "TRUG_BACKUP_PASSWORD") -> Bool {
        if let value = ProcessInfo.processInfo.environment[env] { return !value.isEmpty }
        return false
    }

    /// Whether stdin is an interactive terminal — the `isTTY` input to the WP6.1 preflight guard.
    /// Uses the SAME `tcgetattr(STDIN)`-succeeds probe `readNoEcho` relies on, so the fail-fast
    /// decision and the no-echo read agree on what "a terminal" means (design note #3).
    static func stdinIsTTY() -> Bool {
        var t = termios()
        return tcgetattr(STDIN_FILENO, &t) == 0
    }

    /// WP6.1 F-E1 double-entry resolve for an INTERACTIVE create: read the password twice with echo
    /// disabled, accept only on a match, re-ask on a mismatch — bounded by `CreatePasswordFlow`
    /// (C2/R1). NO env read here: the caller has ALREADY decided this is the env-absent interactive
    /// branch (`decide` returned `.promptDoubleEntry`), so re-consulting env would contradict the
    /// guard. Each read is a fresh no-echo prompt; the "confirm" prompt makes the double-entry explicit.
    static func readNewBackupPasswordDoubleEntry() throws -> String {
        var first = true
        return try CreatePasswordFlow.doubleEntry(maxAttempts: 3) {
            let prompt = first ? "Backup password: " : "Confirm backup password: "
            first.toggle()
            FileHandle.standardError.write(Data(prompt.utf8))
            return readNoEcho()
        }
    }

    /// WP6.1 F-E2 RETRY prompt: a single no-echo read that BYPASSES the env var (Q4 — the env value
    /// already failed or is absent, so re-reading it would loop on the same wrong value). Used only on
    /// a re-prompt after a wrong-password verify; the happy path never reaches it.
    static func readBackupPasswordRetry() -> String {
        FileHandle.standardError.write(Data("Re-enter backup password: ".utf8))
        return readNoEcho()
    }

    /// Reads one line with terminal echo disabled, restoring the original terminal state on every
    /// exit path.
    ///
    /// Two distinct cases (Codex F3):
    ///  - stdin is NOT a TTY (e.g. a pipe): `tcgetattr` fails, termios is a no-op, and the line is read
    ///    normally. There is no echo to leak on a pipe, and the env-var path above already covers
    ///    non-interactive use, so this is the documented SAFE fallback.
    ///  - stdin IS a TTY but disabling echo FAILS (`tcsetattr` returns non-zero): reading now would
    ///    echo the password in CLEARTEXT. We FAIL CLOSED — surface a clear stderr error and exit
    ///    non-zero BEFORE any `readLine`, so the password is never typed with echo on. Previously the
    ///    `tcsetattr` result was discarded, which left echo on (fail-OPEN).
    private static func readNoEcho() -> String {
        let fd = STDIN_FILENO
        var original = termios()
        let isTTY = tcgetattr(fd, &original) == 0
        if isTTY {
            var noEcho = original
            noEcho.c_lflag &= ~tcflag_t(ECHO)
            guard tcsetattr(fd, TCSANOW, &noEcho) == 0 else {
                FileHandle.standardError.write(Data(
                    "error: could not disable terminal echo; refusing to read the backup password in cleartext.\nSupply it via TRUG_BACKUP_PASSWORD instead.\n".utf8))
                exit(1)
            }
        }
        // Restore echo and emit the newline the user's (suppressed) Return did not show.
        defer {
            if isTTY {
                var restore = original
                _ = tcsetattr(fd, TCSANOW, &restore)
                FileHandle.standardError.write(Data("\n".utf8))
            }
        }
        return readLine(strippingNewline: true) ?? ""
    }
}
