import Testing
import Foundation
@testable import BackupCore

@Suite struct KeybagTests {
    @Test func unlocksWithCorrectPassword() throws {
        let tlv = try Fixtures.knownKeybagTLV()
        let kb = try Keybag(tlv: tlv)
        let unlocked = try kb.unlock(password: Fixtures.knownPassword)
        #expect(unlocked.classKeys.isEmpty == false)
    }

    /// Cross-validation against the INDEPENDENT oracle: every passcode-wrapped class key the
    /// Swift parser recovers must equal, byte-for-byte, the key the Python/OpenSSL oracle wrapped.
    /// This is the non-self-referential oracle check (wp4.design.odb.md R1 / gate criterion).
    @Test func recoveredClassKeysMatchIndependentOracle() throws {
        let tlv = try Fixtures.knownKeybagTLV()
        let unlocked = try Keybag(tlv: tlv).unlock(password: Fixtures.knownPassword)
        let expected = try Fixtures.knownPasscodeClassKeys()
        #expect(expected.isEmpty == false)
        for (clas, key) in expected {
            #expect(unlocked.classKeys[clas] == key,
                    "class \(clas) key must match the independent oracle byte-for-byte")
        }
    }

    /// Device-only classes (WRAP without the passcode bit) cannot be unwrapped from the password
    /// and MUST be skipped, not unwrapped or thrown on (wp4.design.odb.md R3).
    @Test func skipsDeviceOnlyClasses() throws {
        let tlv = try Fixtures.knownKeybagTLV()
        let unlocked = try Keybag(tlv: tlv).unlock(password: Fixtures.knownPassword)
        for clas in try Fixtures.deviceOnlyClasses() {
            #expect(unlocked.classKeys[clas] == nil,
                    "device-only class \(clas) must not appear in host-unwrapped class keys")
        }
    }

    @Test func rejectsWrongPassword() throws {
        let tlv = try Fixtures.knownKeybagTLV()
        let kb = try Keybag(tlv: tlv)
        #expect(throws: KeybagError.wrongPassword) {
            _ = try kb.unlock(password: "definitely-not-the-password")
        }
    }

    @Test func rejectsMalformedTLV() throws {
        // Truncated mid-length-field — not a parseable TLV stream.
        #expect(throws: KeybagError.self) {
            _ = try Keybag(tlv: Data([0x56, 0x45, 0x52, 0x53, 0x00, 0x00]))
        }
    }

    /// Odb G1: a hostile keybag with an oversized ITER must be rejected FAST at init, not run
    /// through PBKDF2 (which would wedge for minutes-to-hours). Patch the fixture TLV's ITER to
    /// 0xFFFFFFFF and assert init throws malformedKeybag — without the bound this test would hang.
    @Test func rejectsOversizedIterFast() throws {
        let tlv = try Self.patchedKeybag(tag: "ITER", value: 0xFFFFFFFF)
        #expect(throws: KeybagError.malformedKeybag) {
            _ = try Keybag(tlv: Data(tlv))
        }
    }

    // MARK: - WP4.2 / Checkpoint C run 2: real iOS 27 keybag is VERS 5

    /// Overwrites the 4-byte big-endian payload of a single-occurrence header tag in the known
    /// keybag TLV, leaving every other byte (and thus the known-answer class keys) untouched. Real
    /// iOS 27 keeps the IDENTICAL VERS-3/4 wire format at VERS 5, so flipping only VERS models the
    /// device keybag exactly: if VERS 5 unlocks here it unlocks the real one (lead's TLV parse).
    static func patchedKeybag(tag: String, value: UInt32) throws -> [UInt8] {
        var tlv = Array(try Fixtures.knownKeybagTLV())
        let tagBytes: [UInt8] = Array(tag.utf8)
        let idx = try #require((0...(tlv.count - 12)).first { i in Array(tlv[i..<i+4]) == tagBytes })
        let payloadStart = idx + 8   // 4B tag + 4B length
        tlv[payloadStart + 0] = UInt8((value >> 24) & 0xFF)
        tlv[payloadStart + 1] = UInt8((value >> 16) & 0xFF)
        tlv[payloadStart + 2] = UInt8((value >> 8) & 0xFF)
        tlv[payloadStart + 3] = UInt8(value & 0xFF)
        return tlv
    }

    /// A VERS-5 keybag (real iOS 27) must parse and unlock identically to VERS 3/4 — same wire
    /// format, same class keys. Built by patching only the VERS field of the known fixture, so the
    /// recovered keys must still match the independent oracle byte-for-byte.
    @Test func unlocksVers5Keybag() throws {
        let tlv = try Self.patchedKeybag(tag: "VERS", value: 5)
        let unlocked = try Keybag(tlv: Data(tlv)).unlock(password: Fixtures.knownPassword)
        let expected = try Fixtures.knownPasscodeClassKeys()
        #expect(expected.isEmpty == false)
        for (clas, key) in expected {
            #expect(unlocked.classKeys[clas] == key,
                    "VERS 5 must recover the same class \(clas) key as the oracle (identical wire format)")
        }
    }

    /// The version gate stays armed: a genuinely-unknown version (6) must still be REJECTED with
    /// the precise unsupportedKeybagVersion — accepting VERS 5 must not blanket-accept any version.
    @Test func rejectsUnknownKeybagVersion() throws {
        let tlv = try Self.patchedKeybag(tag: "VERS", value: 6)
        #expect(throws: KeybagError.unsupportedKeybagVersion(version: 6)) {
            _ = try Keybag(tlv: Data(tlv))
        }
    }

    /// The real iOS 27 keybag's DPIC is EXACTLY 10,000,000. The round-count ceiling must ADMIT that
    /// value (the comparison is <=, not <) or the real keybag dies at init as malformedKeybag. Patch
    /// DPIC to the real value and assert init succeeds (parse only — no PBKDF2 run needed).
    @Test func admitsRealDpicValue() throws {
        let tlv = try Self.patchedKeybag(tag: "DPIC", value: 10_000_000)
        #expect(throws: Never.self) {
            _ = try Keybag(tlv: Data(tlv))   // parse + bound check; must not throw
        }
    }

    /// The DoS bound stays meaningful: a DPIC just above the ceiling must still be rejected FAST at
    /// init (never run through PBKDF2). With the ceiling at 50,000,000, 50,000,001 must fail.
    @Test func rejectsDpicAboveCeilingFast() throws {
        let tlv = try Self.patchedKeybag(tag: "DPIC", value: 50_000_001)
        #expect(throws: KeybagError.malformedKeybag) {
            _ = try Keybag(tlv: Data(tlv))
        }
    }
}
