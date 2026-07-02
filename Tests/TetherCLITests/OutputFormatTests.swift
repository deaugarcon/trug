import Testing
import BackupCore
@testable import TetherCLI

/// Pins the engine-error -> exit-code mapping (`exitCode(for:)`) so a regression that silently
/// reclassifies an error stays RED, not green. The load-bearing case is the C1 contract:
/// `passwordRequired` must map to the user-input class (2), NEVER the corrupt-backup class (7) —
/// an encrypted backup that simply needs a password is not corruption.
@Suite struct OutputFormatTests {
    /// THE C1 contract: an encrypted backup needing a password is a user-input miss (exit 2), not a
    /// corrupt/internal fault. Without this pin, moving passwordRequired to 7 or 70 stays green.
    @Test func passwordRequiredMapsToUserInputClass() {
        #expect(exitCode(for: VerifyError.passwordRequired(udid: "U")) == 2)
    }

    /// A named-but-absent backup/file and a refused overwrite are user-input misses (exit 2).
    @Test func userInputMissesMapToTwo() {
        #expect(exitCode(for: VerifyError.backupNotFound(BackupID(udid: "U"))) == 2)
        #expect(exitCode(for: VerifyError.fileNotFoundInBackup(domain: "D", path: "p")) == 2)
        #expect(exitCode(for: ExtractError.outputExists("/tmp/out")) == 2)
    }

    /// An encryption operation against the wrong on-device state is a user-input miss (exit 2), NOT
    /// an internal fault (70) — a script must tell "wrong encryption state" from "Tether crashed"
    /// (WP5 Odb F-exit). Without this pin, the two cases silently fall back to 70.
    @Test func encryptionStateErrorsMapToTwo() {
        #expect(exitCode(for: BackupError.encryptionAlreadyEnabled) == 2)
        #expect(exitCode(for: BackupError.encryptionNotEnabled) == 2)
    }

    /// A WRONG backup password is a user-input miss (exit 2), not an internal fault (70) — checkpoint
    /// D D1: the live device returned MBErrorDomain/207 "Invalid password" and Tether surfaced the
    /// honest message, but exit 70 told scripts "Tether crashed". This reaches exitCode from both the
    /// crypto verify/browse/extract paths and the encryption ChangePassword heuristic. The OTHER
    /// KeybagError cases are NOT user-input and must stay OFF the exit-2 arm (pinned here too, so a
    /// future over-broadening of the mapping is caught RED).
    @Test func wrongPasswordMapsToTwoButOtherKeybagErrorsDoNot() {
        #expect(exitCode(for: KeybagError.wrongPassword) == 2)
        #expect(exitCode(for: KeybagError.unsupportedKeybagVersion(version: 9)) != 2)
        #expect(exitCode(for: KeybagError.malformedKeybag) != 2)
    }

    /// A corrupt / tampered manifest is its own class (exit 7), distinct from a user-input miss and
    /// from an internal fault — the very class the C1 fix stopped mislabeling encrypted backups as.
    @Test func corruptManifestMapsToSeven() {
        #expect(exitCode(for: VerifyError.manifestUnreadable(reason: "x")) == 7)
        #expect(exitCode(for: VerifyError.malformedFileID("zz")) == 7)
    }

    /// A failed verification report surfaces as the verification-failed class (exit 6).
    @Test func verificationFailedMapsToSix() {
        #expect(exitCode(for: BackupError.verificationFailed) == 6)
    }

    /// An error the mapping does not name falls through to the internal-error class (exit 70).
    @Test func unknownErrorMapsToSeventy() {
        struct Unmapped: Error {}
        #expect(exitCode(for: Unmapped()) == 70)
    }

    /// Task 16 — the SHIPPED SP2 backup exit-code table, pinned in FULL so the contract cannot drift
    /// silently. The plan/spec proposed `7 = wrong backup password, 8 = insufficient disk space,
    /// 9 = device locked`; the SHIPPED contract diverged for device-proven reasons (C1/D1) and WINS.
    /// This pins both the mapped classes AND the deliberate non-mappings.
    @Test func shippedBackupExitTableIsStable() {
        // User-input misses → 2 (C1/D1: a wrong password or wrong on-device state is not corruption).
        #expect(exitCode(for: VerifyError.passwordRequired(udid: "U")) == 2)
        #expect(exitCode(for: KeybagError.wrongPassword) == 2)
        #expect(exitCode(for: VerifyError.backupNotFound(BackupID(udid: "U"))) == 2)
        #expect(exitCode(for: VerifyError.fileNotFoundInBackup(domain: "D", path: "p")) == 2)
        #expect(exitCode(for: ExtractError.outputExists("/tmp/out")) == 2)
        #expect(exitCode(for: BackupError.encryptionAlreadyEnabled) == 2)
        #expect(exitCode(for: BackupError.encryptionNotEnabled) == 2)
        // Verification-failed → 6; corrupt/tampered manifest → 7 (distinct from user-input and internal).
        #expect(exitCode(for: BackupError.verificationFailed) == 6)
        #expect(exitCode(for: VerifyError.manifestUnreadable(reason: "x")) == 7)
        #expect(exitCode(for: VerifyError.malformedFileID("zz")) == 7)
    }

    /// Task 16 — DELIBERATE NON-MAPPINGS (negative pins). `BackupError.insufficientDiskSpace` and
    /// `BackupError.deviceLocked` exist in the engine but are intentionally NOT routed to dedicated
    /// codes for SP2 — they fall through to the internal-error class (70). The plan/spec's proposed
    /// `insufficientDiskSpace → 8` / `deviceLocked → 5` routing is a PUBLIC-CLI contract change that is
    /// Deau-gated (proposed-but-unratified, recorded in spec §6), NOT a lead/Meth decision. This pin
    /// keeps them at 70 so the routing cannot be added silently green — adding it must turn this test
    /// RED and force the Deau decision into the open.
    @Test func unratifiedRoutingsStayAtSeventy() {
        #expect(exitCode(for: BackupError.insufficientDiskSpace(needed: 10, available: 1)) == 70)
        #expect(exitCode(for: BackupError.insufficientDiskSpace(needed: 10, available: 1)) != 8)
        #expect(exitCode(for: BackupError.deviceLocked) == 70)
        #expect(exitCode(for: BackupError.deviceLocked) != 5)
    }
}
