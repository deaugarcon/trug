import Testing
@testable import TetherCLI

@Suite struct TableFormatterTests {
    @Test func rendersAlignedColumns() {
        let table = TextTable(header: ["UDID", "CONNECTION"],
                              rows: [["abc", "usb"], ["a-longer-udid", "network"]])
        let lines = table.rendered().split(separator: "\n").map(String.init)
        #expect(lines[0] == "UDID           CONNECTION")
        #expect(lines[1] == "abc            usb       ")
        #expect(lines[2] == "a-longer-udid  network   ")
    }
}
