import XCTest

/// The vault's own screens, as several test classes drive them: the add menu and its editors, an item's detail, a
/// dialog's button, the shared vaults.
extension UITestCase {
    /// The app started again and unlocked as the seeded account: it comes up locked, with nothing an earlier test left
    /// open over the vault, and signed in again if an earlier class left it signed out.
    func freshVault() {
        app.terminate()
        launchApp()
        reachVaultAnyWay()
    }

    // MARK: - Editors

    /// The add menu's [kind]: "New login", "New card" or "New note". iOS's own "Save Password?" for the master password
    /// just typed at the unlock can come up over the vault a moment later and take the tap meant for the add menu: it
    /// is answered, and the menu opened again.
    func openNewItemEditor(_ kind: String) {
        let entry = app.buttons[kind]
        for _ in 0..<3 where !entry.exists {
            answerSystemAlerts()
            app.buttons["vault.new-item"].tap()
            _ = waitUntil(4, { entry.exists })
        }
        require(entry, "\(kind) in the add menu", timeout: 5)
        entry.tap()
    }

    /// Scroll an editor's form up until [element] can be tapped: above the keyboard when one is up, clear of the bars
    /// otherwise. The drag is made in the upper part of the screen, which a keyboard never covers: one that starts on
    /// the keyboard types, or moves the cursor.
    @discardableResult
    func scrollFormTo(_ element: XCUIElement, tries: Int = 14) -> Bool {
        let from = app.coordinate(withNormalizedOffset: CGVector(dx: 0.5, dy: 0.4))
        let to = app.coordinate(withNormalizedOffset: CGVector(dx: 0.5, dy: 0.2))
        let inReach: () -> Bool = {
            guard element.exists, let frame = try? element.snapshot().frame else { return false }
            let keyboard = self.app.keyboards.firstMatch
            var lowest = Screen.bounds.height * 0.85
            if keyboard.exists, let top = try? keyboard.snapshot().frame.minY, top > 0 { lowest = top - 4 }
            return frame.minY > Screen.bounds.height * 0.12 && frame.maxY < lowest && self.safelyHittable(element)
        }
        for _ in 0..<tries {
            if inReach() { return true }
            from.press(forDuration: 0.1, thenDragTo: to, withVelocity: .slow, thenHoldForDuration: 0.2)
            Thread.sleep(forTimeInterval: 0.6)
        }
        return inReach()
    }

    /// A secret field of an editor, by its label: a secure field while hidden, a text field once shown.
    func secretEntry(_ label: String) -> XCUIElement {
        let hidden = app.secureTextFields[label]
        return hidden.exists ? hidden : app.textFields[label]
    }

    /// The Show or Hide button in the same row as [field]: an editor has one for each secret field.
    func eyeButton(beside field: XCUIElement) -> XCUIElement? {
        guard field.exists, let frame = try? field.snapshot().frame else { return nil }
        let eyes = app.buttons.matching(NSPredicate(format: "label == 'Show' OR label == 'Hide'"))
        for index in 0..<eyes.count {
            let eye = eyes.element(boundBy: index)
            guard eye.exists, let at = try? eye.snapshot().frame else { continue }
            if at.midY > frame.minY - 8 && at.midY < frame.maxY + 8 { return eye }
        }
        return nil
    }

    /// What the secret field [label] of the open editor holds, read after its Show: shown, it is a plain text field
    /// whose value is its text.
    func shownEntry(_ label: String) -> String {
        let hidden = app.secureTextFields[label]
        if hidden.exists {
            guard let eye = eyeButton(beside: hidden) else {
                dumpTree(app, as: "no-show-button")
                XCTFail("the \(label) field has no Show button beside it")
                return ""
            }
            tapWhereItIs(eye, in: app)
        }
        let shown = app.textFields[label]
        var value: String?
        _ = waitUntil(8) {
            guard shown.exists, let text = shown.value as? String else { return false }
            value = text == shown.placeholderValue ? "" : text
            return true
        }
        guard let value else {
            dumpTree(app, as: "secret-not-shown")
            XCTFail("the \(label) field did not show what it holds")
            return ""
        }
        return value
    }

    // MARK: - An item's detail

    /// Open an item of any kind from the vault list, scrolling the list to its row (openItem is for logins: it waits
    /// for the username).
    func openAnyItem(_ name: String) {
        let row = vaultRow(name)
        // From the top of the list, where the rows the test looks for are built first.
        if !row.exists { app.swipeDown(); app.swipeDown() }
        if !scrollToComfort(row) {
            dumpTree(app, as: "no-row-\(name)")
            XCTFail("the row of \(name) could not be brought on screen")
        }
        row.tap()
        require(app.navigationBars[name], "the detail of \(name)")
    }

    /// The password of the login [name], read from its detail opened afresh and revealed; the detail stays open.
    func revealedPassword(of name: String) -> String {
        openItem(name)
        let reveal = element("detail.reveal-password")
        require(reveal, "the password of \(name)", timeout: 15)
        reveal.tap()
        var value = ""
        _ = waitUntil(10) {
            value = (self.element("detail.password").value as? String) ?? ""
            return !value.isEmpty && !value.contains("•")
        }
        return value
    }

    /// A hidden row of the open detail ("detail.card number"), shown with its button ("Show card number") and read.
    func revealedDetail(_ identifier: String, show: String) -> String {
        let row = element(identifier)
        require(row, "the row \(identifier)", timeout: 15)
        scrollToComfort(row)
        if (row.value as? String) == "Hidden" {
            let button = app.buttons[show]
            require(button, "the button \(show)")
            button.tap()
        }
        var value = ""
        _ = waitUntil(10) {
            value = (row.value as? String) ?? ""
            return !value.isEmpty && value != "Hidden"
        }
        return value
    }

    /// Whether the open detail's note (a note's text, a login's or a card's notes) reads [text] once shown.
    func detailNotesRead(_ text: String) -> Bool {
        let show = app.buttons["Show"]
        if !scrollToComfort(show) {
            dumpTree(app, as: "no-notes-show")
            return false
        }
        show.tap()
        let shown = app.staticTexts.matching(NSPredicate(format: "label == %@", text)).firstMatch
        if waitUntil(10, { shown.exists }) { return true }
        dumpTree(app, as: "notes-read-differently")
        return false
    }

    /// The lines on screen that contain any of [parts], for a failure message that says what the app said.
    func screenWords(containing parts: [String]) -> String {
        let predicate = NSCompoundPredicate(orPredicateWithSubpredicates: parts.map { NSPredicate(format: "label CONTAINS[c] %@", $0) })
        let texts = app.staticTexts.matching(predicate)
        var lines: [String] = []
        for index in 0..<min(texts.count, 8) {
            let line = texts.element(boundBy: index).label
            if !lines.contains(line) { lines.append(line) }
        }
        return lines.isEmpty ? "nothing about it" : lines.joined(separator: " | ")
    }

    // MARK: - Dialogs

    /// Tap the button [label] of the dialog titled [title]. The rows behind a dialog can carry the same word (each trash
    /// row has its own Delete forever), so it is the one that can be tapped while the dialog is up, nearest below its
    /// title.
    func confirm(_ label: String, inDialog title: String) {
        let heading = app.staticTexts[title]
        require(heading, "the dialog “\(title)”", timeout: 5)
        let buttons = app.buttons.matching(NSPredicate(format: "label == %@", label))
        var target: XCUIElement?
        _ = waitUntil(5) {
            let top = heading.frame.minY
            target = buttons.allElementsBoundByIndex
                .filter { self.safelyHittable($0) && $0.frame.minY > top }
                .min { $0.frame.minY < $1.frame.minY }
            return target != nil
        }
        guard let target else {
            dumpTree(app, as: "no-confirm-\(label)")
            XCTFail("the dialog “\(title)” has no \(label) to tap")
            return
        }
        target.tap()
    }

    // MARK: - The list and the shared vaults

    /// Pull the vault list down from its top: a sync.
    func refreshVault() {
        for _ in 0..<2 where !(self.safelyHittable(settingsButton)) { app.navigationBars.buttons.firstMatch.tap() }
        for _ in 0..<2 {
            let start = app.coordinate(withNormalizedOffset: CGVector(dx: 0.5, dy: 0.3))
            start.press(forDuration: 0.1, thenDragTo: app.coordinate(withNormalizedOffset: CGVector(dx: 0.5, dy: 0.85)), withVelocity: .slow, thenHoldForDuration: 0.5)
            Thread.sleep(forTimeInterval: 2)
        }
    }

    func openSharedVaults() {
        openSettings()
        let link = app.buttons["Shared vaults"]
        scrollToComfort(link)
        link.tap()
        require(app.navigationBars["Shared vaults"], "the shared vaults")
    }

    func closeSharedVaults() {
        app.navigationBars.buttons.firstMatch.tap()
        let done = element("settings.done")
        require(done, "Settings' Done")
        done.tap()
    }

    /// Settings, on its first screen, closed and opened again: its list then stands at its top. A list builds only the
    /// rows near what it shows, so a row far above where it stands cannot be scrolled to by name.
    func reopenSettings() {
        let done = element("settings.done")
        if done.exists {
            done.tap()
            _ = waitUntil(10) { !done.exists }
        }
        _ = waitUntil(10) { self.safelyHittable(self.settingsButton) }
        openSettings()
    }
}
