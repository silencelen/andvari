import XCTest

/// What landed in the app after the first suite: two-step sign-in, the trash, item history, moving and copying between
/// vaults, lifecycle notices, the extension's card test pages (extension/test-pages/), and what the simulator cannot
/// show. Runs after T3, so AutoFill, the Safari extension and Face ID are already on.
final class T4VaultFeatureTests: UITestCase {
    private let stamp = Int(Date().timeIntervalSince1970) % 100000

    /// Two-step setup survives a trip to another app: the app locks on the way out, and after the unlock it opens the
    /// confirm step again with the same key. The code an authenticator would show then turns it on; a later one off.
    func test01_TwoStepSetupSurvivesATripAway() {
        step("vault") {
            bringAppForward()
            reachVaultAnyWay()
        }
        let keyText = app.staticTexts.matching(NSPredicate(format: "label MATCHES '^[A-Z2-7]{4}( [A-Z2-7]{1,4})+$'")).firstMatch
        var key = ""
        step("setup-started") {
            openSettings()
            let link = app.buttons["Two-step sign-in"]
            require(link, "Two-step sign-in in Settings")
            link.tap()
            let password = app.secureTextFields["Master password"]
            enter(Fixture.password, into: password, what: "the master password for two-step setup")
            app.buttons["Turn on"].tap()
            require(keyText, "the setup key", timeout: 20)
            key = keyText.label.replacingOccurrences(of: " ", with: "")
            require(app.buttons["Confirm"], "the confirm step")
        }
        step("away-in-the-settings-app") {
            settingsApp.launch()
            Thread.sleep(forTimeInterval: 2)
        }
        step("back-on-the-confirm-step-with-the-same-key") {
            bringAppForward()
            reachVaultAnyWay()
            require(keyText, "the setup key after the trip", timeout: 20)
            XCTAssertEqual(keyText.label.replacingOccurrences(of: " ", with: ""), key, "the setup key changed across the trip")
            require(app.buttons["Confirm"], "the confirm step after the trip")
        }
        step("confirmed-with-the-authenticator-code") {
            // A code taken at the very end of its 30 seconds may expire on the way.
            if Authenticator.secondsLeft < 6 { Thread.sleep(forTimeInterval: Double(Authenticator.secondsLeft + 1)) }
            guard let code = Authenticator.code(base32: key) else {
                XCTFail("the setup key \(key) is not base32")
                return
            }
            enter(code, into: app.textFields["6-digit code"], what: "the code field")
            app.buttons["Confirm"].tap()
            XCTAssertTrue(waitUntil(15) { self.app.staticTexts["On"].exists }, "two-step sign-in did not turn on")
        }
        step("turned-off-with-a-later-code") {
            // A code is accepted once: the next 30 seconds' code turns it off.
            Thread.sleep(forTimeInterval: Double(Authenticator.secondsLeft + 1))
            guard let code = Authenticator.code(base32: key) else { return }
            enter(code, into: app.textFields["6-digit code"], what: "the code field")
            app.buttons["Turn off"].tap()
            XCTAssertTrue(waitUntil(15) { self.app.staticTexts["Off"].exists }, "two-step sign-in did not turn off")
            app.buttons["Done"].firstMatch.tap()
        }
    }

    /// Delete a login, find it in the trash, restore it; delete it again and delete it forever.
    func test02_TrashRestoreAndDeleteForever() {
        let name = "Trash Me \(stamp)"
        step("login-added") {
            bringAppForward()
            reachVaultAnyWay()
            addLogin(name, user: "tom")
        }
        step("deleted") {
            deleteLogin(name)
        }
        step("in-the-trash") {
            openTrash()
            require(trashRow(name), "\(name) in the trash", timeout: 20)
        }
        step("restored") {
            trashRow(name).buttons["Restore"].tap()
            XCTAssertTrue(waitUntil(15) { !self.trashRow(name).exists }, "the restored login is still in the trash")
            closeTrash()
            XCTAssertTrue(waitUntil(15) { self.vaultRow(name).exists }, "the restored login is not back in the vault")
        }
        step("deleted-forever") {
            deleteLogin(name)
            openTrash()
            require(trashRow(name), "\(name) in the trash again", timeout: 20)
            trashRow(name).buttons["Delete forever"].tap()
            let confirm = app.buttons.matching(NSPredicate(format: "label == 'Delete forever' AND identifier == ''"))
            XCTAssertTrue(waitUntil(5) { confirm.count >= 2 }, "Delete forever asked for no confirmation")
            confirm.element(boundBy: confirm.count - 1).tap()
            XCTAssertTrue(waitUntil(15) { !self.trashRow(name).exists }, "the login is still in the trash after Delete forever")
            closeTrash()
            XCTAssertFalse(vaultRow(name).exists, "the login deleted forever is in the vault")
        }
    }

    /// Change a login's password, find the earlier version in its history, and restore it.
    func test03_ItemHistoryRestoresAVersion() {
        let name = "History Me \(stamp)"
        step("login-added") {
            bringAppForward()
            reachVaultAnyWay()
            addLogin(name, user: "hana", password: "First-Passw0rd")
        }
        step("password-changed") {
            openItem(name)
            app.buttons["Edit"].tap()
            let password = app.secureTextFields["Password"]
            require(password, "the editor's password field")
            clearField(password)
            password.typeText("Second-Passw0rd")
            app.buttons["Save"].tap()
            element("detail.reveal-password").tap()
            XCTAssertTrue(waitUntil(10) { (self.element("detail.password").value as? String) == "Second-Passw0rd" }, "the new password was not saved")
        }
        step("earlier-version-listed") {
            let show = app.buttons["Show earlier versions"]
            scrollToComfort(show)
            show.tap()
            let restore = app.buttons.matching(NSPredicate(format: "label == 'Restore'")).firstMatch
            require(restore, "an earlier version with Restore", timeout: 20)
            scrollToComfort(restore)
        }
        step("version-restored") {
            app.buttons.matching(NSPredicate(format: "label == 'Restore'")).firstMatch.tap()
            let confirm = app.buttons.matching(NSPredicate(format: "label == 'Restore' AND identifier == ''"))
            XCTAssertTrue(waitUntil(5) { confirm.count >= 2 }, "Restore asked for no confirmation")
            confirm.element(boundBy: confirm.count - 1).tap()
            Thread.sleep(forTimeInterval: 3)
            // A password shown before the restore stays as it was shown: read it again from a fresh detail.
            app.navigationBars.buttons.firstMatch.tap()
            openItem(name)
            element("detail.reveal-password").tap()
            XCTAssertTrue(waitUntil(15) { (self.element("detail.password").value as? String) == "First-Passw0rd" }, "the restored version's password is not back, the login holds \(String(describing: self.element("detail.password").value))")
            app.navigationBars.buttons.firstMatch.tap()
        }
    }

    /// Create a shared vault, copy one login into it (both copies remain) and move another (it leaves the personal vault).
    func test04_MoveAndCopyToASharedVault() {
        let vault = "Shared \(stamp)"
        let copied = "Copy Me \(stamp)"
        let moved = "Move Me \(stamp)"
        step("shared-vault-created") {
            bringAppForward()
            reachVaultAnyWay()
            openSharedVaults()
            app.buttons["New shared vault…"].tap()
            let field = app.alerts.textFields.firstMatch
            require(field, "the new vault's name field")
            field.typeText(vault)
            app.alerts.buttons["Create"].tap()
            require(containing(vault, in: app), "\(vault) in the list of vaults", timeout: 20)
            closeSharedVaults()
        }
        step("logins-added") {
            addLogin(copied, user: "cora")
            addLogin(moved, user: "mo")
        }
        step("copied") {
            moveOrCopy(copied, to: vault, move: false)
            XCTAssertTrue(waitUntil(15) { self.app.descendants(matching: .any).matching(identifier: "vault.item." + copied).count == 2 }, "the copy did not appear beside the original")
        }
        step("moved") {
            moveOrCopy(moved, to: vault, move: true)
            XCTAssertTrue(waitUntil(15) { self.app.descendants(matching: .any).matching(identifier: "vault.item." + moved).count == 1 }, "the moved login is not there once")
            // Moved out of the personal vault: from where it is now, the personal vault is a place to go.
            openItem(moved)
            let button = app.buttons.matching(NSPredicate(format: "label BEGINSWITH 'Move or copy' OR label BEGINSWITH 'Copy to another vault'")).firstMatch
            scrollToComfort(button)
            button.tap()
            XCTAssertTrue(waitUntil(10) { self.app.buttons["Personal"].exists }, "the moved login is still in the personal vault")
            XCTAssertFalse(app.buttons["\(vault) (shared)"].exists, "the moved login's own vault is offered as a target")
            app.buttons["Cancel"].tap()
            app.navigationBars.buttons.firstMatch.tap()
        }
    }

    /// Another device of the account deletes a shared vault this device holds, then restores it: each shows here as a
    /// notice at the top of the vault after a sync, and each notice goes when dismissed.
    func test05_LifecycleNoticesForASharedVault() {
        let vault = "Lifecycle \(stamp)"
        step("vault-created-elsewhere-and-synced-here") {
            XCTAssertNil(OtherDevice.vault("create", vault), "the other device could not create the vault")
            bringAppForward()
            reachVaultAnyWay()
            openSharedVaults()
            let listed = containing(vault, in: app)
            if !waitUntil(10, { listed.exists }) {
                // The list is what the last sync knew: pull to sync, and look again.
                closeSharedVaults()
                refreshVault()
                openSharedVaults()
            }
            require(listed, "\(vault) on this device", timeout: 20)
            closeSharedVaults()
        }
        let deletedNotice = app.staticTexts.matching(NSPredicate(format: "label BEGINSWITH %@", "“\(vault)” was deleted by its owner.")).firstMatch
        step("deleted-elsewhere") {
            XCTAssertNil(OtherDevice.vault("delete", vault), "the other device could not delete the vault")
            refreshVault()
            if !waitUntil(20, { deletedNotice.exists }) {
                dumpTree(app, as: "no-deleted-notice")
                XCTFail("no notice that \(vault) was deleted")
            }
        }
        step("deleted-notice-dismissed") {
            dismissNotice(deletedNotice)
        }
        let restoredNotice = app.staticTexts["“\(vault)” was restored."]
        step("restored-elsewhere") {
            XCTAssertNil(OtherDevice.vault("restore", vault), "the other device could not restore the vault")
            refreshVault()
            if !waitUntil(20, { restoredNotice.exists }) {
                dumpTree(app, as: "no-restored-notice")
                XCTFail("no notice that \(vault) was restored")
            }
            dismissNotice(restoredNotice)
        }
    }

    /// card-skimmer.html: an invisible card form the page's script focused. Fill refuses with nothing tapped and
    /// with only the visible email tapped, and the skimmer's own debug line stays empty.
    func test06_CardSkimmerPageGetsNothing() {
        step("provider-and-extension-on") {
            requireAutoFillProvider()
            requireSafariExtension()
        }
        step("page") {
            openInSafari(Fixture.siteOrigin + "/test-pages/card-skimmer.html", heading: "Checkout")
        }
        let tapFirst = safari.webViews.staticTexts.matching(NSPredicate(format: "label CONTAINS 'Tap the card number field on the page first'")).firstMatch
        step("refused-with-nothing-tapped") {
            fillCardFromPopup()
            XCTAssertTrue(waitUntil(8) { tapFirst.exists }, "the popup did not refuse a card fill with nothing tapped. It says: \(popupDetails())")
        }
        step("refused-with-the-email-tapped") {
            closePopup()
            let email = safari.webViews.textFields.firstMatch
            require(email, "the page's email field")
            email.tap()
            fillCardFromPopup()
            XCTAssertTrue(waitUntil(8) { tapFirst.exists }, "the popup did not refuse a card fill with only the email tapped")
        }
        step("skimmer-got-nothing") {
            closePopup()
            let got = safari.webViews.staticTexts.matching(NSPredicate(format: "label CONTAINS 'cardnumber=' OR label CONTAINS 'cvc=' OR label CONTAINS 'exp-month=' OR label CONTAINS 'ccname=' OR label CONTAINS 'postal='")).firstMatch
            XCTAssertFalse(got.exists, "the skimmer form received: \(got.exists ? got.label : "")")
        }
    }

    /// card-two-forms.html: the fill uses the form of the field tapped, not the page's richest form.
    func test07_CardTwoFormsFillsOnlyTheTappedForm() {
        step("provider-and-extension-on") {
            requireAutoFillProvider()
            requireSafariExtension()
        }
        let codes = { self.safari.webViews.textFields.matching(NSPredicate(format: "label == 'Security code'")) }
        let number = { self.safari.webViews.textFields["Card number"] }
        step("saved-card-code-tapped-and-filled") {
            openInSafari(Fixture.siteOrigin + "/test-pages/card-two-forms.html", heading: "Two card forms")
            let saved = codes().element(boundBy: 0)
            require(saved, "the saved card's security code")
            saved.tap()
            fillCardFromPopup()
            closePopup()
            XCTAssertEqual(digits(codes().element(boundBy: 0)), Fixture.cardCode, "the saved card's code was not filled")
            XCTAssertEqual(digits(number()), "", "the new-card form was filled from the saved card's field")
            XCTAssertEqual(digits(codes().element(boundBy: 1)), "", "the new card's code was filled from the saved card's field")
        }
        step("new-card-number-tapped-and-filled") {
            openInSafari(Fixture.siteOrigin + "/test-pages/card-two-forms.html", heading: "Two card forms")
            require(number(), "the new card's number")
            number().tap()
            fillCardFromPopup()
            closePopup()
            XCTAssertEqual(digits(number()), Fixture.cardNumber, "the new card's number was not filled")
            XCTAssertEqual(digits(codes().element(boundBy: 1)), Fixture.cardCode, "the new card's code was not filled")
            XCTAssertEqual(digits(codes().element(boundBy: 0)), "", "the saved card's code was filled from the new card's field")
        }
    }

    /// card-inner-scroll.html: a card form low in a modal that scrolls on its own. Filled once scrolled into view; with
    /// the form scrolled away again, a fill writes nothing and says the field can't be seen.
    func test08_CardInnerScrollFillsOnceInView() {
        step("provider-and-extension-on") {
            requireAutoFillProvider()
            requireSafariExtension()
        }
        let number = safari.webViews.textFields["Card number"]
        step("form-scrolled-into-view-and-filled") {
            openInSafari(Fixture.siteOrigin + "/test-pages/card-inner-scroll.html", heading: "Checkout")
            XCTAssertTrue(scrollToComfort(number, in: safari, tries: 16), "the card form could not be scrolled into view inside the modal")
            number.tap()
            fillCardFromPopup()
            closePopup()
            XCTAssertEqual(digits(number), Fixture.cardNumber, "the card number was not filled once in view")
        }
        let unseen = safari.webViews.staticTexts.matching(NSPredicate(format: "label CONTAINS \"can't be seen\" OR label CONTAINS \"can’t be seen\"")).firstMatch
        step("scrolled-away-fills-nothing") {
            // Back to the top of the modal: the field tapped is out of view.
            let title = safari.webViews.staticTexts["Checkout"]
            XCTAssertTrue(scrollToComfort(title, in: safari, tries: 16), "the modal could not be scrolled back up")
            fillCardFromPopup()
            XCTAssertTrue(waitUntil(8) { unseen.exists }, "the popup did not say the field can't be seen. It says: \(popupDetails())")
        }
    }

    /// Settings has the switch for other apps' keyboards, off by default. Whether a third-party keyboard is then kept out
    /// cannot be shown: the simulator has none installed, and the suite would have to ship a keyboard extension in an
    /// app of its own to add one.
    func test09_ThirdPartyKeyboardSwitch() throws {
        step("switch-off-by-default") {
            bringAppForward()
            reachVaultAnyWay()
            openSettings()
            let toggle = app.switches["Allow third-party keyboards"]
            scrollToComfort(toggle)
            require(toggle, "the third-party keyboard switch")
            XCTAssertFalse(isOn(toggle), "other apps' keyboards are allowed by default")
            element("settings.done").tap()
        }
        try skip("The iOS simulator has no third-party keyboard installed, and the suite cannot add one without shipping a keyboard extension in an app of its own, so whether andvari keeps such a keyboard out of its fields cannot be shown here. The switch itself is checked above: present, and off by default.")
    }

    /// A read-only member's item offers Copy only. Not reachable here: the iOS app has no way yet to accept a vault
    /// another member shares (no invitation or identity-check screen), so no vault this account only reads can be opened.
    func test10_ReadOnlyVaultItemOffersCopyOnly() throws {
        try skip("The iOS app cannot yet accept a shared vault from another member: there is no invitation or identity-code check screen, and a grant from someone this device has not verified is not adopted by itself. So no vault this account only reads can be opened on the simulator, and the Copy-only offer of its items cannot be shown. The seed tool can make the share once the app can accept it.")
    }

    // MARK: - Helpers

    private func digits(_ field: XCUIElement) -> String {
        ((field.value as? String) ?? "").filter(\.isNumber)
    }

    private func addLogin(_ name: String, user: String, password: String? = nil) {
        app.buttons["vault.new-item"].tap()
        let newLogin = app.buttons["New login"]
        require(newLogin, "New login in the add menu", timeout: 5)
        newLogin.tap()
        enter(name, into: app.textFields["Name"], what: "the Name field")
        enter(user, into: app.textFields["Username"], what: "the Username field")
        if let password {
            enter(password, into: app.secureTextFields["Password"], what: "the Password field")
        }
        app.buttons["Save"].tap()
        if !waitUntil(15, { self.vaultRow(name).exists }) {
            dumpTree(app, as: "login-not-added")
            XCTFail("\(name) was not added")
        }
    }

    private func deleteLogin(_ name: String) {
        openItem(name)
        app.buttons["Edit"].tap()
        let delete = app.buttons["Delete login"]
        require(delete, "Delete login in the editor")
        scrollToComfort(delete)
        delete.tap()
        let confirm = app.buttons.matching(NSPredicate(format: "label == 'Delete' AND identifier == ''")).firstMatch
        require(confirm, "the delete confirmation", timeout: 5)
        confirm.tap()
        if !waitUntil(15, { !self.vaultRow(name).exists }) {
            dumpTree(app, as: "login-not-deleted")
            XCTFail("\(name) is still in the vault after Delete")
        }
    }

    /// The trash's row for [name]: a row with the name and a Restore button (the vault list behind has no Restore).
    private func trashRow(_ name: String) -> XCUIElement {
        app.cells.containing(NSPredicate(format: "label CONTAINS %@", name)).containing(.button, identifier: "Restore").firstMatch
    }

    private func openTrash() {
        openSettings()
        let link = app.buttons["Trash"]
        scrollToComfort(link)
        link.tap()
        require(app.navigationBars["Trash"], "the trash")
    }

    private func closeTrash() {
        app.navigationBars.buttons.firstMatch.tap()
        let done = element("settings.done")
        require(done, "Settings' Done")
        done.tap()
    }

    private func openSharedVaults() {
        openSettings()
        let link = app.buttons["Shared vaults"]
        scrollToComfort(link)
        link.tap()
        require(app.navigationBars["Shared vaults"], "the shared vaults")
    }

    private func closeSharedVaults() {
        app.navigationBars.buttons.firstMatch.tap()
        let done = element("settings.done")
        require(done, "Settings' Done")
        done.tap()
    }

    private func moveOrCopy(_ name: String, to vault: String, move: Bool) {
        openItem(name)
        let button = app.buttons.matching(NSPredicate(format: "label BEGINSWITH 'Move or copy' OR label BEGINSWITH 'Copy to another vault'")).firstMatch
        require(button, "Move or copy in the item")
        scrollToComfort(button)
        button.tap()
        require(app.navigationBars["Move or copy"], "the move or copy sheet")
        let segment = app.buttons[move ? "Move" : "Copy"].firstMatch
        if segment.exists { segment.tap() }
        app.buttons["\(vault) (shared)"].tap()
        // The toolbar's button carries the same word as the segment: the one in the navigation bar runs it.
        app.navigationBars["Move or copy"].buttons[move ? "Move" : "Copy"].tap()
        XCTAssertTrue(waitUntil(20) { !self.app.navigationBars["Move or copy"].exists }, "the move or copy did not finish")
        if app.navigationBars.buttons.firstMatch.exists && !settingsButton.exists {
            app.navigationBars.buttons.firstMatch.tap()
        }
        _ = waitUntil(10) { self.settingsButton.exists }
    }

    /// Pull the vault list down from its top: a sync.
    private func refreshVault() {
        for _ in 0..<2 where !(settingsButton.exists && settingsButton.isHittable) { app.navigationBars.buttons.firstMatch.tap() }
        for _ in 0..<2 {
            let start = app.coordinate(withNormalizedOffset: CGVector(dx: 0.5, dy: 0.3))
            start.press(forDuration: 0.1, thenDragTo: app.coordinate(withNormalizedOffset: CGVector(dx: 0.5, dy: 0.85)), withVelocity: .slow, thenHoldForDuration: 0.5)
            Thread.sleep(forTimeInterval: 2)
        }
    }

    private func dismissNotice(_ notice: XCUIElement) {
        let row = app.cells.containing(NSPredicate(format: "label == %@", notice.label)).firstMatch
        row.buttons["Dismiss"].tap()
        XCTAssertTrue(waitUntil(10) { !notice.exists }, "the notice stayed after Dismiss")
    }

    /// Open the popup, unlock it, and tap Fill on the seeded card's row.
    private func fillCardFromPopup() {
        let fill = safari.webViews.buttons.matching(NSPredicate(format: "label BEGINSWITH 'Fill this card'")).firstMatch
        if !openPopup(until: { fill.exists }) {
            XCTFail("the popup offered no card to fill. It says: \(popupDetails())")
            return
        }
        scrollToComfort(fill, in: safari)
        fill.tap()
        Thread.sleep(forTimeInterval: 2)
    }
}
