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
        let search = app.searchFields.firstMatch
        let look: () -> Bool = {
            seen = self.currentScreen()
            // A search left open (an earlier test's) hides the vault's bar, and with it every mark of the screen.
            if seen == nil && self.safelyHittable(search) { self.endSearch() }
            return seen != nil
        }
        // A sheet an earlier test left open (it stopped halfway) hides the screen under it: start the app again, which
        // comes up locked, rather than fail every test after it.
        let first = min(20, timeout)
        if waitUntil(first, look) { return seen ?? .chooseServer }
        dumpTree(app, as: "no-screen-so-relaunched")
        app.terminate()
        app.launch()
        if !waitUntil(max(timeout - first, 20), look) {
            dumpTree(app, as: "no-screen")
            XCTFail("the app showed none of its screens within \(Int(timeout)) s, nor after it was started again", file: file, line: line)
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
        dismissLeftoverSystemSheets()
    }

    /// iOS asks which provider's list to open when two are on: choose andvari, and make sure the choice took. A tap
    /// while the chooser is still sliding in is lost, so it is tried again.
    func chooseAndvariProvider(in application: XCUIApplication) {
        let chooser = application.buttons["andvari"]
        require(chooser, "andvari in the provider chooser", timeout: 8)
        for _ in 0..<3 {
            Thread.sleep(forTimeInterval: 0.8)
            tapWhereItIs(chooser, in: application)
            if waitUntil(4, { !chooser.exists }) { return }
        }
        dumpTree(application, as: "provider-chooser-stayed")
        XCTFail("the provider chooser did not take the choice of andvari")
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
        require(masterPasswordField, "the master password field")
        clearField(masterPasswordField)
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
        // From the top of the list, where the rows the test looks for are built first.
        if !row.exists { app.swipeDown(); app.swipeDown() }
        if !scrollToComfort(row) {
            dumpTree(app, as: "no-row-\(name)")
            XCTFail("the row of \(name) could not be brought on screen")
        }
        row.tap()
        require(element("detail.username"), "the detail of \(name)")
    }

    /// Search the vault list for [text]; the rows that stay are the matches.
    func searchVault(_ text: String) {
        let search = app.searchFields.firstMatch
        if !search.exists { app.swipeDown() }
        enter(text, into: search, what: "the search field")
    }

    /// Leave the search, whichever way this iOS offers it: the round close button beside iOS 26's search bar, or an
    /// older Cancel. The clear-text button inside the field only empties it: the search stays open, with its keyboard,
    /// and the vault's bar stays hidden.
    func endSearch() {
        let close = app.buttons.matching(NSPredicate(format: "label == 'close' OR label == 'Close' OR label == 'Cancel'")).firstMatch
        if self.safelyHittable(close) {
            close.tap()
        } else {
            let keyboardDone = app.keyboards.buttons.matching(NSPredicate(format: "label == 'search' OR label == 'Search' OR label == 'done' OR label == 'Done'")).firstMatch
            if app.keyboards.firstMatch.exists && keyboardDone.exists && keyboardDone.isEnabled { keyboardDone.tap() }
        }
        _ = waitUntil(5) { !self.app.keyboards.firstMatch.exists }
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
        // Its Done is always at the top; the sheet is longer than the screen, and a list only holds the rows near it.
        require(element("settings.done"), "the settings sheet")
    }

    /// A control further down the settings sheet, scrolled to.
    func settingsControl(_ identifier: String, _ what: String) -> XCUIElement {
        let control = element(identifier)
        if !scrollToComfort(control) {
            dumpTree(app, as: "no-settings-control")
            XCTFail("\(what) could not be brought on screen")
        }
        return control
    }

    /// Sign out from the vault through Settings.
    func signOutFromVault() {
        openSettings()
        settingsControl("settings.sign-out", "Sign out in Settings").tap()
        confirmSignOut()
    }

    func confirmSignOut() {
        // The confirmation repeats the title of the button that raised it; the dialog's own has no identifier.
        let confirm = app.buttons.matching(NSPredicate(format: "label == 'Sign out' AND identifier == ''")).firstMatch
        if !waitUntil(8, { self.safelyHittable(confirm) }) {
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
