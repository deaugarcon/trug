import Testing
import Foundation
@testable import BackupCore

@Suite struct CloneFileTests {
    @Test func clonesDirectoryTreeContents() throws {
        let tmp = URL.temporaryTestDir()
        defer { try? FileManager.default.removeItem(at: tmp) }
        let src = tmp.appendingPathComponent("src")
        let dst = tmp.appendingPathComponent("dst")
        try FileManager.default.createDirectory(at: src.appendingPathComponent("sub"), withIntermediateDirectories: true)
        try Data("hello".utf8).write(to: src.appendingPathComponent("a.txt"))
        try Data("world".utf8).write(to: src.appendingPathComponent("sub/b.txt"))

        try CloneFile.cloneTree(from: src, to: dst)

        #expect(try String(contentsOf: dst.appendingPathComponent("a.txt")) == "hello")
        #expect(try String(contentsOf: dst.appendingPathComponent("sub/b.txt")) == "world")
    }

    @Test func modifyingCloneDoesNotAffectSource() throws {
        let tmp = URL.temporaryTestDir()
        defer { try? FileManager.default.removeItem(at: tmp) }
        let src = tmp.appendingPathComponent("src")
        let dst = tmp.appendingPathComponent("dst")
        try FileManager.default.createDirectory(at: src, withIntermediateDirectories: true)
        try Data("original".utf8).write(to: src.appendingPathComponent("f.txt"))

        try CloneFile.cloneTree(from: src, to: dst)
        try Data("changed".utf8).write(to: dst.appendingPathComponent("f.txt"))

        #expect(try String(contentsOf: src.appendingPathComponent("f.txt")) == "original")
    }
}

extension URL {
    static func temporaryTestDir() -> URL {
        let u = FileManager.default.temporaryDirectory
            .appendingPathComponent("tether-test-\(UInt64.random(in: 0..<UInt64.max))")
        try? FileManager.default.createDirectory(at: u, withIntermediateDirectories: true)
        return u
    }
}
