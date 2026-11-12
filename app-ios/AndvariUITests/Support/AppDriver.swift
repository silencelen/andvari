import XCTest

/// The screens of the app, as the tests tell them apart.
enum AppScreen: String {
    case chooseServer
    case welcome
    case unlock
    case vault
}

extension UITestCase {
    var serverField: XCUIElement { app.textFields["field.server"] }
    var emailField: XCUIElement { app.textFields["field.email"] }
    var masterPasswordField: XCUIElement { app.secureTextFields["field.master-password"] }
    var unlockButton: XCUIElement { app.buttons["button.unlock"] }
    var signInButton: XCUIElement { app.buttons["button.sign-in"] }
    var settingsButton: XCUIElement { app.buttons["vault.settings"] }
    var quickUnlockSwitch: XCUIElement { app.switches["settings.quick-unlock"] }

    func vaultRow(_ name: String) -> XCUIElement { element("vault.item." + name) }

    /// Which screen is up, or nil while it is loading or showing something else.
    func currentScreen() -> AppScreen? {
        if settingsButton.exists { return .vault }
        if unlockButton.exists { return .unlock }
        if signInButton.exists { return .welcome }
        if serverField.exists { return .chooseServer }
        return nil
    }

    @discardableResult
    func waitForScreen(_ timeout: TimeInterval = 60, file: StaticString = #filePath, line: UInt = #line) -> AppScreen {
        var seen: AppScreen?
        if !waitUntil(timeout, { seen = currentScreen(); return seen != nil }) {
            dumpTree(app, as: "no-screen")
            XCTFail("the app showed none of its screens within \(Int(timeout)) s", file: file, line: line)
        }
        return seen ?? .chooseServer
    }

    func expectScreen(_ wanted: AppScreen, timeout: TimeInterval = 60, file: StaticString = #filePath, line: UInt = #line) {
        if !waitUntil(timeout, { currentScreen() == wanted }) {
            dumpTree(app, as: "not-" + wanted.rawValue)
            XCTFail("expected the \(wanted.rawValue) screen, found \(currentScreen()?.rawValue ?? "none of the known screens")", file: file, line: line)
        }
    }

    func launchApp() {
        app.launch()
    }

    /// Choose the job's server and pass the Trust Gate.
    func chooseServer() {
        enter(Fixture.serverOrigin + "\n", into: serverField, what: "the server field")
        let origin = element("gate.origin")
        require(origin, "the Trust Gate")
        XCTAssertEqual(origin.value as? String, Fixture.serverOrigin, "the Trust Gate must show the origin that was typed")
        app.buttons["button.connect"].tap()
        expectScreen(.welcome)
    }

    func typeSignIn() {
        enter(Fixture.email, into: emailField, what: "the email field")
        enter(Fixture.password + "\n", into: masterPasswordField, what: "the master password field")
    }

    func typeUnlock() {
        enter(Fixture.password + "\n", into: masterPasswordField, what: "the master password field")
    }

    /// From wherever the app is after a launch to the unlocked vault, by typing: the path of someone without Face ID.
    func reachVault() {
        switch waitForScreen() {
        case .chooseServer:
            chooseServer()
            typeSignIn()
        case .welcome:
            typeSignIn()
        case .unlock:
            typeUnlock()
        case .vault:
            break
        }
        expectScreen(.vault, timeout: 60)
        require(vaultRow(Fixture.siteItem), "the seeded login in the list", timeout: 30)
    }

    func openSettings() {
        settingsButton.tap()
        require(element("settings.sign-out"), "the settings sheet")
    }

    /// Sign out from the vault through Settings.
    func signOutFromVault() {
        openSettings()
        element("settings.sign-out").tap()
        confirmSignOut()
    }

    func confirmSignOut() {
        // The confirmation repeats the title of the button that raised it; the dialog's own has no identifier.
        let confirm = app.buttons.matching(NSPredicate(format: "label == 'Sign out' AND identifier == ''")).firstMatch
        if !waitUntil(8, { confirm.exists && confirm.isHittable }) {
            dumpTree(app, as: "no-sign-out-confirmation")
            XCTFail("the sign-out confirmation did not appear")
        }
        confirm.tap()
        expectScreen(.welcome)
    }

    /// The switch's own control: a tap on the middle of a labelled row does not always reach it.
    func setQuickUnlockSwitch(_ on: Bool) {
        let toggle = quickUnlockSwitch
        require(toggle, "the Face ID switch")
        guard isOn(toggle) != on else { return }
        flip(toggle)
    }

    func isOn(_ toggle: XCUIElement) -> Bool {
        (toggle.value as? String) == "1"
    }

    /// Show a matching face for a while, for a prompt whose end the tests cannot see directly.
    func matchFace(for seconds: TimeInterval) {
        let deadline = Date().addingTimeInterval(seconds)
        Thread.sleep(forTimeInterval: 1.5)
        while Date() < deadline {
            answerSystemAlerts()
            Biometrics.match()
            Thread.sleep(forTimeInterval: 1.5)
        }
    }

    /// Show the simulator a matching face until [done], as a person would keep looking at the phone.
    @discardableResult
    func matchFaceUntil(_ timeout: TimeInterval = 20, _ done: () -> Bool) -> Bool {
        let deadline = Date().addingTimeInterval(timeout)
        Thread.sleep(forTimeInterval: 1.5)
        while Date() < deadline {
            if done() { return true }
            answerSystemAlerts()
            Biometrics.match()
            Thread.sleep(forTimeInterval: 1.5)
        }
        return done()
    }
}
