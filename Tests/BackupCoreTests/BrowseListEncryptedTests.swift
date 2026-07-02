import Testing
import Foundation
@testable import BackupCore

/// WP4.2 / Checkpoint C run 3: `browse` and `list` must handle an ENCRYPTED backup. browse decrypts
/// the manifest through the keybag (or fails with a precise password error, never the corruption
/// lie); list reads device metadata from the PLAINTEXT plists with NO password. These exercise the
/// engine seams the CLI commands call (ManifestReader.open / ManifestReader.metadata(in:)), which
/// are unit-testable without the real store the commands bind to.
@Suite struct BrowseListEncryptedTests {
    // MARK: - browse (ManifestReader.open)

    /// With the password, browsing an encrypted backup enumerates its files via the decrypt seam —
    /// the same keybag-aware reader the verifier uses. (Pre-fix: keybag-less open hit NOTADB.)
    @Test func browseEnumeratesEncryptedBackupWithPassword() throws {
        let (root, udid, password) = try FixtureBuilder.encryptedBackupWithEncryptedManifest()
        defer { try? FileManager.default.removeItem(at: root) }
        let reader = try ManifestReader.open(backupDir: root.appendingPathComponent(udid),
                                             udid: udid, password: password)
        let files = try reader.allFiles()
        #expect(files.contains { $0.relativePath == "known.txt" })
    }

    /// Without a password, browsing an encrypted backup throws the precise passwordRequired — NEVER
    /// the not-a-database / "may be incomplete; re-create it" lie. (Empty string = the CLI feed.)
    @Test func browseWithoutPasswordThrowsPasswordRequired() throws {
        let (root, udid, _) = try FixtureBuilder.encryptedBackupWithEncryptedManifest()
        defer { try? FileManager.default.removeItem(at: root) }
        let udidDir = root.appendingPathComponent(udid)
        for pw in [nil, ""] as [String?] {
            #expect(throws: VerifyError.passwordRequired(udid: udid)) {
                _ = try ManifestReader.open(backupDir: udidDir, udid: udid, password: pw)
            }
        }
    }

    /// A wrong password surfaces as wrongPassword (keybag is the authority), not a corruption finding.
    @Test func browseWrongPasswordSurfacesWrongPassword() throws {
        let (root, udid, _) = try FixtureBuilder.encryptedBackupWithEncryptedManifest()
        defer { try? FileManager.default.removeItem(at: root) }
        #expect(throws: KeybagError.wrongPassword) {
            _ = try ManifestReader.open(backupDir: root.appendingPathComponent(udid),
                                        udid: udid, password: "wrong")
        }
    }

    /// An UNENCRYPTED backup opens byte-identically through the shared seam (no password needed) and
    /// enumerates its files — the plaintext path must be unchanged.
    @Test func browseUnencryptedIsPasswordFree() throws {
        let root = try FixtureBuilder.unencryptedBackup(udid: "U", files: [
            .init(domain: "HomeDomain", path: "a.txt", contents: Data("aaa".utf8)),
        ])
        defer { try? FileManager.default.removeItem(at: root) }
        let reader = try ManifestReader.open(backupDir: root.appendingPathComponent("U"),
                                             udid: "U", password: nil)
        #expect(try reader.allFiles().contains { $0.relativePath == "a.txt" })
    }

    /// Task 14 part D (LAZY password): `open` takes the password as @autoclosure, so on a PLAINTEXT
    /// backup the closure must NEVER be evaluated — otherwise an unencrypted browse with no env
    /// password would fire the interactive no-echo prompt and HANG. The closure here records a test
    /// failure if it is ever invoked; a passing test proves the plaintext browse never pulls it.
    @Test func browseUnencryptedNeverEvaluatesPasswordClosure() throws {
        let root = try FixtureBuilder.unencryptedBackup(udid: "U", files: [
            .init(domain: "HomeDomain", path: "a.txt", contents: Data("aaa".utf8)),
        ])
        defer { try? FileManager.default.removeItem(at: root) }
        let reader = try ManifestReader.open(
            backupDir: root.appendingPathComponent("U"), udid: "U",
            password: { Issue.record("password closure evaluated on a plaintext backup — would prompt/hang"); return nil }())
        #expect(try reader.allFiles().contains { $0.relativePath == "a.txt" })
    }

    // MARK: - list (ManifestReader.metadata(in:))

    /// `list` must describe an ENCRYPTED backup WITHOUT a password: IsEncrypted and the device
    /// name / iOS version live in the PLAINTEXT Manifest.plist/Info.plist, not in the ciphertext
    /// Manifest.db. Pre-fix, list built a keybag-less ManifestReader whose db open threw, blanking
    /// every field (checkpoint C run 3 showed blank iOS/NAME).
    @Test func listReadsEncryptedMetadataWithoutPassword() throws {
        let (root, udid, _) = try FixtureBuilder.encryptedBackupWithEncryptedManifest()
        defer { try? FileManager.default.removeItem(at: root) }
        let meta = ManifestReader.metadata(in: root.appendingPathComponent(udid))
        #expect(meta.isEncrypted)
        #expect(meta.deviceName == "Test")
        #expect(meta.productVersion == "27.0")
    }
}
