import Testing
@testable import BackupCore

@Suite struct SmokeTest {
    @Test func packageCompiles() { #expect(Bool(true)) }
}
