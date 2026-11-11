import XCTest

/// What the tests need to know about the job's backend. The workflow passes these as TEST_RUNNER_ variables; the
/// defaults are the values in app-ios/uitest/env.sh.
enum Fixture {
    private static func value(_ name: String, _ fallback: String) -> String {
        guard let value = ProcessInfo.processInfo.environment[name], !value.isEmpty else { return fallback }
        return value
    }

    static let serverOrigin = value("UITEST_SERVER_ORIGIN", "http://127.0.0.1:8087")
    static let email = value("UITEST_EMAIL", "uitest@andvari-uitest.test")
    static let password = value("UITEST_PASSWORD", "correct horse battery staple uitest 1")
    static let siteOrigin = value("UITEST_SITE_ORIGIN", "https://site.andvari-uitest.test:8443")
    static let siteHost = value("UITEST_SITE_HOST", "site.andvari-uitest.test")
    static let httpOrigin = value("UITEST_HTTP_ORIGIN", "http://plainhttp-uitest.test:8081")

    /// The seeded logins (tools/uitest-seed).
    static let siteItem = "UITest Site"
    static let siteUser = "alice"
    static let sitePassword = "alice-Passw0rd-site"
    static let httpItem = "UITest Plain HTTP"
    static let seededNames = ["UITest Site", "UITest Site second", "UITest Plain HTTP", "Example Mail", "No Address", "UITest Note"]
}

/// A test is a list of named steps. Every step ends with a screenshot, kept in the result bundle and written as
/// `<Class>.<test>__NN_<step>.png` beside the summary, so a reader without a simulator can see each one.
class UITestCase: XCTestCase {
    static let bundleID = "com.silencelen.andvari"

    let app = XCUIApplication(bundleIdentifier: UITestCase.bundleID)
    let springboard = XCUIApplication(bundleIdentifier: "com.apple.springboard")
    private var stepNumber = 0

    override class func setUp() {
        super.setUp()
        Recorder.shared.register()
    }

    override func setUp() {
        super.setUp()
        continueAfterFailure = false
        stepNumber = 0
    }

    override func tearDown() {
        // Whatever is on screen when the test ends, pass or fail.
        shot("end")
        super.tearDown()
    }

    // MARK: - Steps and screenshots

    func step(_ name: String, _ body: () throws -> Void) rethrows {
        try XCTContext.runActivity(named: name) { _ in
            do {
                try body()
            } catch {
                shot(name + "-failed")
                throw error
            }
            shot(name)
        }
    }

    func shot(_ name: String) {
        stepNumber += 1
        let safe = name.map { $0.isLetter || $0.isNumber || $0 == "-" ? $0 : "-" }
        let file = String(format: "%@__%02d_%@.png", Recorder.name(of: self), stepNumber, String(safe))
        let screenshot = XCUIScreen.main.screenshot()
        let attachment = XCTAttachment(screenshot: screenshot)
        attachment.name = file
        attachment.lifetime = .keepAlways
        add(attachment)
        if let directory = Recorder.outDirectory {
            let folder = directory.appendingPathComponent("screenshots", isDirectory: true)
            try? FileManager.default.createDirectory(at: folder, withIntermediateDirectories: true)
            if (try? screenshot.pngRepresentation.write(to: folder.appendingPathComponent(file))) != nil {
                Recorder.shared.noteScreenshot(file, for: self)
            }
        }
    }

    /// Leave the test present but skipped, with the reason in the summary.
    func skip(_ reason: String) throws -> Never {
        Recorder.shared.noteSkip(reason, for: self)
        shot("skipped")
        throw XCTSkip(reason)
    }

    /// The UI tree of an app, as text, in the result bundle and beside the screenshots: what a failed query saw.
    func dumpTree(_ application: XCUIApplication, as name: String) {
        let text = application.debugDescription
        let attachment = XCTAttachment(string: text)
        attachment.name = name + ".txt"
        attachment.lifetime = .keepAlways
        add(attachment)
        if let directory = Recorder.outDirectory {
            let folder = directory.appendingPathComponent("trees", isDirectory: true)
            try? FileManager.default.createDirectory(at: folder, withIntermediateDirectories: true)
            let file = Recorder.name(of: self) + "__" + name + ".txt"
            try? text.write(to: folder.appendingPathComponent(file), atomically: true, encoding: .utf8)
        }
    }

    // MARK: - Finding and waiting

    /// Any element with this accessibility identifier, whatever its type.
    func element(_ identifier: String, in application: XCUIApplication? = nil) -> XCUIElement {
        (application ?? app).descendants(matching: .any).matching(identifier: identifier).firstMatch
    }

    /// Wait for [condition], answering the system's own alerts meanwhile.
    @discardableResult
    func waitUntil(_ timeout: TimeInterval = 20, _ condition: () -> Bool) -> Bool {
        let deadline = Date().addingTimeInterval(timeout)
        while true {
            if condition() { return true }
            if Date() >= deadline { return false }
            answerSystemAlerts()
            Thread.sleep(forTimeInterval: 0.3)
        }
    }

    func require(_ element: XCUIElement, _ what: String, timeout: TimeInterval = 20, file: StaticString = #filePath, line: UInt = #line) {
        if !waitUntil(timeout, { element.exists }) {
            dumpTree(app, as: "missing-" + String(what.map { $0.isLetter || $0.isNumber ? $0 : "-" }))
            XCTFail("\(what) did not appear within \(Int(timeout)) s", file: file, line: line)
        }
    }

    /// iOS asks things of its own over the app: to save the password just typed, and to allow Face ID.
    func answerSystemAlerts() {
        let notNow = springboard.buttons["Not Now"]
        if notNow.exists {
            notNow.tap()
            return
        }
        let alert = springboard.alerts.firstMatch
        if alert.exists {
            for title in ["OK", "Allow", "Not Now"] where alert.buttons[title].exists {
                alert.buttons[title].tap()
                return
            }
        }
    }

    // MARK: - Typing

    func enter(_ text: String, into field: XCUIElement, what: String, file: StaticString = #filePath, line: UInt = #line) {
        require(field, what, file: file, line: line)
        field.tap()
        // The keyboard takes a moment to belong to the field.
        Thread.sleep(forTimeInterval: 0.6)
        field.typeText(text)
    }
}
