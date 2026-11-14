import CryptoKit
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
    static let otherOrigin = value("UITEST_OTHER_ORIGIN", "https://other-uitest.test:8443")
    static let otherHost = value("UITEST_OTHER_HOST", "other-uitest.test")
    static let secondItem = "UITest Site second"
    static let secondUser = "alice.second"
    static let secondPassword = "second-Passw0rd-site"
    static let cardItem = "UITest Card"

    /// The seeded logins (tools/uitest-seed).
    static let siteItem = "UITest Site"
    static let siteUser = "alice"
    static let sitePassword = "alice-Passw0rd-site"
    static let httpItem = "UITest Plain HTTP"
    static let seededNames = ["UITest Site", "UITest Site second", "UITest Plain HTTP", "Example Mail", "No Address", "UITest Note", "UITest Card"]

    /// The first 16 hex digits of a value's SHA-256: how the test site's page shows what a form submitted
    /// (app-ios/uitest/serve-site.py), so a test compares it with the seeded value without the page showing the value.
    static func digest(_ value: String) -> String {
        String(SHA256.hash(data: Data(value.utf8)).map { String(format: "%02x", $0) }.joined().prefix(16))
    }
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
        dismissLeftoverSystemSheets()
        super.tearDown()
    }

    /// A provider chooser or a provider's list that a failed test left open covers the next test's screen, and a
    /// tap meant for the screen under it lands on the sheet. Close them; this never fails a test.
    func dismissLeftoverSystemSheets() {
        for application in [app, XCUIApplication(bundleIdentifier: "com.apple.mobilesafari")] where application.state == .runningForeground {
            let chooser = application.buttons["andvari"]
            let cancel = application.buttons.matching(NSPredicate(format: "label == 'Cancel'")).firstMatch
            if chooser.exists && application.buttons["Passwords"].exists && cancel.exists {
                tapWhereItIs(cancel, in: application)
                Thread.sleep(forTimeInterval: 1)
            }
            if application.staticTexts["AutoFill Password"].exists || application.navigationBars["andvari"].exists {
                let close = application.buttons.matching(NSPredicate(format: "label IN {'Close', 'Cancel'}")).firstMatch
                if close.exists {
                    tapWhereItIs(close, in: application)
                    Thread.sleep(forTimeInterval: 1)
                }
            }
        }
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

    /// Tap where [element] is now, without failing the test if it went away in the meantime (a retry button that
    /// the thing it retries has just replaced). The tap lands on the app's own coordinates.
    func tapWhereItIs(_ element: XCUIElement, in application: XCUIApplication) {
        guard element.exists else { return }
        let frame = element.frame
        guard !frame.isEmpty else { return }
        application.coordinate(withNormalizedOffset: .zero).withOffset(CGVector(dx: frame.midX, dy: frame.midY)).tap()
    }

    /// iOS asks things of its own over the app: to save the password just typed, and to allow Face ID.
    func answerSystemAlerts() {
        let notNow = springboard.buttons["Not Now"]
        if notNow.exists {
            tapWhereItIs(notNow, in: springboard)
            return
        }
        // iOS's own offer to keep the master password just typed ("Save Password?", the Passwords app's) is drawn
        // in the app's window, over the screen the test wants next.
        if app.state == .runningForeground {
            let inApp = app.alerts.buttons["Not Now"].firstMatch
            let loose = app.buttons.matching(NSPredicate(format: "label == 'Not Now'")).firstMatch
            if inApp.exists {
                tapWhereItIs(inApp, in: app)
                return
            }
            if loose.exists && app.staticTexts["Save Password?"].exists {
                tapWhereItIs(loose, in: app)
                return
            }
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

    /// Empty a field that already holds text (an AutoFill fill, an earlier try), so what is typed next is all it holds.
    func clearField(_ field: XCUIElement) {
        guard let value = field.value as? String, !value.isEmpty, value != field.placeholderValue else { return }
        field.tap()
        Thread.sleep(forTimeInterval: 0.6)
        field.typeText(String(repeating: XCUIKeyboardKey.delete.rawValue, count: value.count + 2))
    }

    func enter(_ text: String, into field: XCUIElement, what: String, file: StaticString = #filePath, line: UInt = #line) {
        require(field, what, file: file, line: line)
        // On a slow runner the field exists before it can be touched (a sheet still arriving, the cover still leaving).
        _ = waitUntil(15) { field.isHittable }
        // The keyboard takes a moment to belong to the field, longer the first time a simulator shows one; a tap
        // that lands while something else still has the focus is tried again.
        for _ in 0..<3 {
            field.tap()
            if waitUntil(5, { self.hasKeyboardFocus(field) }) { break }
        }
        if !hasKeyboardFocus(field) {
            dumpTree(app, as: "no-keyboard-focus")
            XCTFail("\(what) never took the keyboard", file: file, line: line)
        }
        field.typeText(text)
    }

    /// Scroll [application]'s list until [element] sits in the middle part of the screen, clear of the bars above and
    /// the floating search bar below: a row partly behind one of them is "hittable" and still takes no tap. A row the
    /// list has not built yet is taken to be further down.
    @discardableResult
    func scrollToComfort(_ element: XCUIElement, in application: XCUIApplication? = nil, tries: Int = 12) -> Bool {
        let application = application ?? app
        let height = application.windows.firstMatch.frame.height
        let at = { (y: CGFloat) in application.coordinate(withNormalizedOffset: CGVector(dx: 0.5, dy: y)) }
        for _ in 0..<tries {
            if element.exists {
                let frame = element.frame
                if frame.minY > height * 0.18 && frame.maxY < height * 0.8 && element.isHittable { return true }
                // Above the comfortable band: drag the list down; below it: drag it up. A third of a screen at a time.
                if frame.minY <= height * 0.18 {
                    drag(at(0.45), to: at(0.75))
                } else {
                    drag(at(0.7), to: at(0.4))
                }
            } else {
                drag(at(0.7), to: at(0.4))
            }
            Thread.sleep(forTimeInterval: 0.6)
        }
        return element.exists && element.isHittable
    }

    /// A slow drag that holds at its end, so the list stops where the finger does instead of coasting on.
    private func drag(_ from: XCUICoordinate, to: XCUICoordinate) {
        from.press(forDuration: 0.1, thenDragTo: to, withVelocity: .slow, thenHoldForDuration: 0.2)
    }

    /// Whether [element] holds the keyboard (XCUITest's own attribute, as its tree dumps show it).
    func hasKeyboardFocus(_ element: XCUIElement) -> Bool {
        element.exists && ((element.value(forKey: "hasKeyboardFocus") as? Bool) ?? false)
    }
}
