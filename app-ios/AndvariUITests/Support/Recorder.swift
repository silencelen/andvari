import Foundation
import XCTest

/// What the job reads afterwards: one entry per test with its status, failure text and the screenshots it took.
/// Written to `UITEST_OUT_DIR/uitest-summary.json` after every test, so a run that dies keeps what it had.
final class Recorder: NSObject, XCTestObservation {
    static let shared = Recorder()

    private struct Entry: Codable {
        var test: String
        var status: String
        var message: String?
        var seconds: Double
        var screenshots: [String]
    }

    private var entries: [Entry] = []
    private var failures: [String: [String]] = [:]
    private var skips: [String: String] = [:]
    private var shots: [String: [String]] = [:]
    private var registered = false

    /// The directory on the Mac that runs the simulator. A simulator process can write there.
    static var outDirectory: URL? {
        guard let path = ProcessInfo.processInfo.environment["UITEST_OUT_DIR"], !path.isEmpty else { return nil }
        return URL(fileURLWithPath: path, isDirectory: true)
    }

    func register() {
        guard !registered else { return }
        registered = true
        XCTestObservationCenter.shared.addTestObserver(self)
    }

    static func name(of test: XCTestCase) -> String {
        // "-[T1AppFlowTests test01_FirstLaunch]" -> "T1AppFlowTests.test01_FirstLaunch"
        test.name
            .trimmingCharacters(in: CharacterSet(charactersIn: "-[]"))
            .replacingOccurrences(of: " ", with: ".")
    }

    func noteScreenshot(_ file: String, for test: XCTestCase) {
        shots[Recorder.name(of: test), default: []].append(file)
    }

    func noteSkip(_ reason: String, for test: XCTestCase) {
        skips[Recorder.name(of: test)] = reason
    }

    func testCase(_ testCase: XCTestCase, didRecord issue: XCTIssue) {
        var text = issue.compactDescription
        if let location = issue.sourceCodeContext.location {
            text += " (\(location.fileURL.lastPathComponent):\(location.lineNumber))"
        }
        failures[Recorder.name(of: testCase), default: []].append(text)
    }

    func testCaseDidFinish(_ testCase: XCTestCase) {
        let name = Recorder.name(of: testCase)
        let run = testCase.testRun
        let status: String
        var message: String?
        if run?.hasBeenSkipped == true {
            status = "skipped"
            message = skips[name] ?? "skipped"
        } else if run?.hasSucceeded == true {
            status = "passed"
        } else {
            status = "failed"
            message = failures[name]?.joined(separator: "\n") ?? "failed"
        }
        entries.append(Entry(test: name, status: status, message: message, seconds: run?.totalDuration ?? 0, screenshots: shots[name] ?? []))
        write()
    }

    private func write() {
        guard let directory = Recorder.outDirectory else { return }
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.prettyPrinted, .sortedKeys, .withoutEscapingSlashes]
        guard let data = try? encoder.encode(entries) else { return }
        try? FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
        try? data.write(to: directory.appendingPathComponent("uitest-summary.json"), options: .atomic)
    }
}
