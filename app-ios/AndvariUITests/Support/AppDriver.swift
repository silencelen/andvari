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

    /// A new app process. Its first screen is never the unlocked vault.
    func launchApp() {
        app.launch()
    }

    /// The app in front again, in the process it has: what a person does from the app switcher. It comes back
    /// locked, because the vault locks whenever the app leaves the screen.
    func bringAppForward() {
        app.activate()
        if !waitUntil(15, { self.app.state == .runningForeground }) {
            // A process iOS ended in the background starts again.
            app.launch()
        }
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
        confirmPersonalVaultIfAsked()
    }

    /// Open an item's detail from the vault list, scrolling the list to its row.
    func openItem(_ name: String) {
        let row = vaultRow(name)
        for _ in 0..<3 where !(row.exists && row.isHittable) { app.swipeDown() }
        for _ in 0..<5 where !(row.exists && row.isHittable) { app.swipeUp() }
        require(row, "the row of \(name)")
        row.tap()
        require(element("detail.username"), "the detail of \(name)")
    }

    /// Search the vault list for [text]; the rows that stay are the matches.
    func searchVault(_ text: String) {
        let search = app.searchFields.firstMatch
        if !search.exists { app.swipeDown() }
        enter(text, into: search, what: "the search field")
    }

    /// Leave the search, whichever way this iOS offers it.
    func endSearch() {
        let cancel = app.buttons["Cancel"].firstMatch
        let clear = app.searchFields.firstMatch.buttons.firstMatch
        if cancel.exists && cancel.isHittable {
            cancel.tap()
        } else if clear.exists && clear.isHittable {
            clear.tap()
        }
        let keyboardDone = app.keyboards.buttons.matching(NSPredicate(format: "label == 'search' OR label == 'Search' OR label == 'done' OR label == 'Done'")).firstMatch
        if app.keyboards.firstMatch.exists && keyboardDone.exists { keyboardDone.tap() }
    }

    /// A vault row whose text (name, then username) contains [text].
    func vaultRowContaining(_ text: String) -> XCUIElement {
        app.descendants(matching: .any).matching(NSPredicate(format: "identifier BEGINSWITH 'vault.item.' AND label CONTAINS %@", text)).firstMatch
    }

    /// The "Saved … from AutoFill" list and every "Logins not saved yet" row with its reason, for a failure message.
    func saveListsSummary() -> String {
        var parts: [String] = []
        let applied = app.staticTexts.matching(NSPredicate(format: "label BEGINSWITH 'Saved ' AND label ENDSWITH ' from AutoFill'")).firstMatch
        parts.append(applied.exists ? applied.label : "no saved list")
        for cell in app.cells.containing(.button, identifier: "pending.save").allElementsBoundByIndex.prefix(5) {
            parts.append("not saved: " + cell.staticTexts.allElementsBoundByIndex.map(\.label).joined(separator: " / "))
        }
        return parts.joined(separator: "; ")
    }

    // MARK: - The personal vault

    /// The notice a device shows until it has confirmed the account's personal vault. The seeding tool enrolled the
    /// account elsewhere, so this simulator is always such a device after it signs in.
    var personalVaultNotice: XCUIElement {
        app.staticTexts.matching(NSPredicate(format: "label BEGINSWITH 'Confirm your personal vault on this device' OR label BEGINSWITH 'The server says your personal vault is'")).firstMatch
    }

    /// Its one answer: "Use Personal", offered once the app has looked up who else holds the vault.
    var usePersonalVaultButton: XCUIElement {
        app.buttons.matching(NSPredicate(format: "label BEGINSWITH 'Use '")).firstMatch
    }

    /// Confirm the personal vault when the device asks, as a person would: new items have nowhere to go until then.
    func confirmPersonalVaultIfAsked() {
        guard waitUntil(4, { self.personalVaultNotice.exists }) else { return }
        require(usePersonalVaultButton, "the notice's Use button", timeout: 20)
        usePersonalVaultButton.tap()
        if !waitUntil(15, { !self.personalVaultNotice.exists }) {
            dumpTree(app, as: "personal-vault-still-asked")
            XCTFail("the personal-vault notice stayed after Use")
        }
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
