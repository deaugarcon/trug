import Foundation

struct TextTable: Sendable {
    let header: [String]
    let rows: [[String]]

    func rendered() -> String {
        let all = [header] + rows
        let widths = header.indices.map { col in
            all.map { $0[col].count }.max() ?? 0
        }
        func line(_ cells: [String]) -> String {
            cells.enumerated()
                .map { $0.element.padding(toLength: widths[$0.offset], withPad: " ", startingAt: 0) }
                .joined(separator: "  ")
        }
        return all.map(line).joined(separator: "\n")
    }
}
