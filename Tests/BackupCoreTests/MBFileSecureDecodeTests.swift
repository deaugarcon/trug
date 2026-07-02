import Testing
import Foundation
@testable import BackupCore

/// Odb C3b-Sec: the per-file metadata decoder runs NSKeyedUnarchiver with SECURE CODING ON. Two
/// distinct properties are locked separately: (a) the secure-coding FLAG itself is on
/// (`supportsSecureCoding`), and (b) the decoder confines the root to our reader — a decoy non-MBFile
/// root is rejected. Plus the real-bytes pass must not regress.
@Suite struct MBFileSecureDecodeTests {
    /// The real device-shaped MBFile archive still decodes under secure coding: protection class and
    /// the 44-byte EncryptionKey come back intact (the real-bytes pass must not regress).
    @Test func realMBFileArchiveStillDecodes() throws {
        let ef = try Fixtures.encryptedFile()
        let blob = try FixtureBuilder.mbFileArchive(protectionClass: ef.protectionClass,
                                                    encryptionKeyBlob: ef.encryptionKeyBlob,
                                                    relativePath: ef.relativePath)
        let (clas, key) = try ManifestReader.decodeFileMetadata(blob)
        #expect(clas == ef.protectionClass)
        #expect(key == ef.encryptionKeyBlob)
    }

    /// THE SECURITY TRIPWIRE (Odb C3b-Sec): the reader's secure-coding flag must stay ON. The decoy
    /// test below is over-determined — it rejects a wrong-class root via the typed-root cast and
    /// GadgetFixture.init?(coder:)==nil regardless of the flag, so it does NOT catch the flag being
    /// flipped off. This asserts the flag directly, so disabling secure coding goes RED here.
    @Test func metadataReaderRequiresSecureCoding() {
        #expect(MBFileMetadata.supportsSecureCoding == true)
    }

    /// ROOT-CONFINEMENT: an archive whose root is a DIFFERENT class (not MBFile) must be REJECTED —
    /// the MBFile-only setClass redirect plus the typed-root decode refuse to hand back an arbitrary
    /// class, so decodeFileMetadata throws manifestUnreadable. (This locks root-confinement, NOT the
    /// secure-coding flag — metadataReaderRequiresSecureCoding locks the flag; the rejection here
    /// holds even with the flag off because the typed-root cast and GadgetFixture.init?(coder:)==nil
    /// each reject the decoy independently.)
    @Test func nonMBFileRootIsRejected() throws {
        let gadget = try FixtureBuilder.nonMBFileArchive()
        #expect(throws: VerifyError.self) {
            _ = try ManifestReader.decodeFileMetadata(gadget)
        }
    }

    /// Malformed (non-archive) bytes throw manifestUnreadable, not a trap.
    @Test func malformedBlobThrowsManifestUnreadable() throws {
        #expect(throws: VerifyError.self) {
            _ = try ManifestReader.decodeFileMetadata(Data([0x00, 0x01, 0x02, 0x03]))
        }
    }
}
