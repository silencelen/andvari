import XCTest

/// andvari as part of iOS: the AutoFill provider and the Safari extension. Each one is its own test. A step the
/// simulator cannot do is a skip with the reason, never a pass.
final class T3SystemIntegrationTests: UITestCase {
    /// Turn andvari on as an AutoFill provider in Settings, the only place iOS lets it be turned on.
    func test01_EnableAutoFillProviderInSettings() throws {
        step("app-ready") {
            prepareAppForFilling()
        }
        var found = false
        step("autofill-settings") {
            found = openAutoFillSettings()
        }
        if !found {
            try skip("The simulator's Settings app has no AutoFill & Passwords screen to turn a provider on in.")
        }
        step("andvari-switch-on") {
            let toggle = autoFillProviderSwitch
            require(toggle, "the andvari switch under AutoFill From")
            if !isOn(toggle) {
                flip(toggle)
                Thread.sleep(forTimeInterval: 2)
                shot("after-flip")
                dumpTree(settingsApp, as: "settings-after-flip")
                answerSystemAlerts()
            }
            XCTAssertTrue(waitUntil(5) { self.isOn(self.autoFillProviderSwitch) }, "the andvari switch did not stay on")
        }
        step("suggestions-published") {
            settingsApp.terminate()
            relaunchAndUnlock()
            SystemState.providerEnabled = true
        }
    }

    /// Safari on the https test site: the keyboard offers the seeded login, Face ID, and both fields are filled.
    func test02_SafariQuickTypeFill() {
        step("provider-on") {
            requireAutoFillProvider()
        }
        step("page-with-username-focused") {
            if !openUntilFillOffered(Fixture.siteOrigin + "/login.html", heading: "Sign in", field: "Username") {
                dumpEverything("username-focused")
                XCTFail("Safari did not offer andvari's login for \(Fixture.siteHost) in three tries")
            }
        }
        let username = webField("Username")
        step("offer-names-site-login-and-andvari") {
            require(fillOfferButton, "Safari's offer to fill from andvari")
            let text = containing("saved in", in: safari).label
            XCTAssertTrue(text.contains(Fixture.siteHost) && text.contains(Fixture.siteUser) && text.contains("andvari"), "the offer reads: \(text)")
        }
        step("fill-tapped") {
            closeSafariTips()
            fillOfferButton.tap()
            Thread.sleep(forTimeInterval: 1.5)
            dumpEverything("fill-tapped")
        }
        step("filled") {
            // A first-run tip of Safari's can take the first tap; the offer is then still there.
            if fillOfferButton.exists && fillOfferButton.isHittable {
                fillOfferButton.tap()
            }
            XCTAssertTrue(matchFaceUntil(25) { (username.value as? String) == Fixture.siteUser }, "the username was not filled, it holds \(String(describing: username.value))")
            let password = safari.webViews.secureTextFields["Password"]
            XCTAssertFalse(((password.value as? String) ?? "").isEmpty, "the password was not filled")
        }
    }

    /// The password list: the key button above the keyboard opens andvari's own sheet, Face ID, the list with this
    /// site's logins first, and a tap on one fills.
    func test03_SafariCredentialListSheet() {
        step("provider-on") {
            requireAutoFillProvider()
        }
        step("page") {
            openInSafari(Fixture.siteOrigin + "/login.html", heading: "Sign in")
        }
        let username = webField("Username")
        step("username-focused") {
            require(username, "the page's username field")
            focus(username, heading: "Sign in")
        }
        step("offer-closed") {
            closeFillOffer()
            if !safari.keyboards.firstMatch.exists {
                username.tap()
                Thread.sleep(forTimeInterval: 2)
                closeFillOffer()
            }
            XCTAssertTrue(waitUntil(5) { self.safari.keyboards.firstMatch.exists }, "no keyboard after the offer was closed")
        }
        step("passwords-key") {
            let key = safari.buttons["Passwords"]
            require(key, "the Passwords key above the keyboard", timeout: 5)
            key.tap()
        }
        step("andvari-chosen") {
            // With two providers on, iOS asks which one's list to open.
            chooseAndvariProvider(in: safari)
            dumpEverything("after-choosing-andvari")
        }
        step("list-after-face-id") {
            let header = "For this site"
            let shown = matchFaceUntil(25) { self.labelled(header, in: self.safari).exists || self.labelled(header, in: self.springboard).exists }
            dumpEverything("list")
            XCTAssertTrue(shown, "andvari's list of logins did not appear")
        }
        step("row-fills") {
            let row = [safari, springboard].map { self.labelled("UITest Site second", in: $0) }.first { $0.exists }
            guard let row else {
                XCTFail("the list does not show the second login for this site")
                return
            }
            row.tap()
            XCTAssertTrue(waitUntil(15) { (username.value as? String) == "alice.second" }, "the chosen login was not filled, the field holds \(String(describing: username.value))")
        }
    }

    /// The one-time code field: iOS offers andvari's code for this site and fills six digits.
    func test04_SafariOneTimeCode() {
        step("provider-on") {
            requireAutoFillProvider()
        }
        step("page") {
            openInSafari(Fixture.siteOrigin + "/totp.html", heading: "One-time code")
        }
        let code = webField("Verification code")
        step("code-focused") {
            require(code, "the page's code field")
            focus(code, heading: "One-time code")
            dumpEverything("code-focused")
        }
        step("code-offered-by-andvari") {
            let suggestion = safari.descendants(matching: .any).matching(NSPredicate(format: "label CONTAINS[c] 'code' AND label CONTAINS[c] 'andvari'")).firstMatch
            require(suggestion, "andvari's code above the keyboard", timeout: 8)
            suggestion.tap()
        }
        step("code-filled-and-right") {
            // Safari submits a form once its code is filled, so the page that follows is where the code is read.
            let shown = safari.webViews.staticTexts.matching(NSPredicate(format: "label BEGINSWITH 'Code: '")).firstMatch
            XCTAssertTrue(matchFaceUntil(30) { shown.exists }, "no code reached the site")
            let filled = String(shown.label.dropFirst("Code: ".count))
            XCTAssertTrue(expectedOneTimeCodes().contains(filled), "the site received \(filled), which is not the code for the seeded secret now")
        }
    }

    /// A plain-http page is offered the login saved as http and not the https site's.
    func test05_SafariPlainHttpPage() throws {
        step("provider-on") {
            requireAutoFillProvider()
        }
        step("page") {
            openInSafari(Fixture.httpOrigin + "/login.html", heading: "Sign in")
        }
        let username = webField("Username")
        step("username-focused") {
            require(username, "the page's username field")
            focus(username, heading: "Sign in")
            Thread.sleep(forTimeInterval: 2)
            dumpEverything("http-username-focused")
        }
        let offer = containing("saved in", in: safari)
        step("https-login-not-offered") {
            XCTAssertFalse(offer.exists && offer.label.contains("“\(Fixture.siteUser)”"), "the https site's login was offered on a plain-http page")
        }
        if !offer.exists && !safari.buttons["Passwords"].exists {
            try skip("Safari in the iOS \(systemVersion.major).\(systemVersion.minor) simulator offers nothing from an AutoFill provider on a plain-http page: no offer sheet and no Passwords key above the keyboard (see the screenshot). The login saved for the http address is in the system's store like the others, so the rule that only it is offered here cannot be shown either way.")
        }
        step("the-http-login-is-offered") {
            XCTAssertTrue(offer.exists && offer.label.contains("“bob”"), "the login saved for the http address was not the one offered")
        }
    }

    /// iOS 26.2 and later: submitting a new login makes iOS offer to save it to andvari, and the app saves it by
    /// itself at its next unlock, under "Saved 1 login from AutoFill", into the personal vault.
    func test06_NativeSavePrompt() throws {
        if !systemAtLeast(26, 2) {
            try skip("The save request (SupportsSavePasswordCredentials) needs iOS 26.2; this simulator runs \(systemVersion.major).\(systemVersion.minor).")
        }
        let user = "saved\(Int(Date().timeIntervalSince1970) % 100000)"
        step("provider-on-and-no-saved-list") {
            requireAutoFillProvider()
            bringAppForward()
            reachVaultAnyWay()
            dismissSavedList()
        }
        step("save-offered-and-taken") {
            XCTAssertTrue(submitLoginAndSaveToAndvari(page: "signup.html", heading: "Sign up", user: user, password: "Saved-Passw0rd-1", passwordLabel: "New password", submit: "Create account"), "iOS did not offer to save the new login to andvari")
        }
        let header = app.staticTexts["Saved 1 login from AutoFill"]
        step("saved-by-itself-at-unlock") {
            bringAppForward()
            reachVaultAnyWay()
            if !waitUntil(15, { header.exists }) {
                dumpTree(app, as: "no-saved-list")
                XCTFail("the app did not list the login as saved from AutoFill: \(saveListsSummary())")
            }
            let row = app.cells.containing(NSPredicate(format: "label == %@", user)).firstMatch
            require(row, "the saved login's row", timeout: 5)
            XCTAssertTrue(row.staticTexts["Added as a new login"].exists, "the row does not say the login was added")
            XCTAssertTrue(row.staticTexts["In Personal"].exists, "the row does not say the login is in the personal vault")
        }
        step("in-the-vault") {
            dismissSavedList()
            XCTAssertFalse(header.exists, "Done did not dismiss the list")
            searchVault(user)
            XCTAssertTrue(waitUntil(10) { self.vaultRowContaining(user).exists }, "the saved login is not in the vault list")
            endSearch()
        }
    }

    /// Settings > Apps > Safari > Extensions: turn the andvari web extension on and let it run on websites.
    func test07_EnableSafariExtensionInSettings() {
        enableSafariExtension()
    }

    /// The extension's popup in Safari: Face ID once it has painted, this site's logins listed for it, a tap fills,
    /// and the unlock outlives the popup: opened again at once, it lists without Face ID.
    func test08_SafariExtensionPopupFill() {
        step("provider-and-extension-on") {
            requireAutoFillProvider()
            requireSafariExtension()
        }
        step("page") {
            openInSafari(Fixture.siteOrigin + "/login.html", heading: "Sign in")
        }
        let row = popupLoginRow(Fixture.siteItem, Fixture.siteUser)
        step("popup-lists-this-sites-login") {
            if !openPopup(until: { row.exists }) {
                XCTFail("the popup listed no login for this site after Face ID. The popup says: \(popupDetails())")
            }
            XCTAssertTrue(listedForThisSite(row), "\(Fixture.siteItem) is not listed under \"This site\": row \(row.frame), headings \(popupHeading("This site").frame) and \(popupHeading("All logins").frame)")
            XCTAssertTrue(listedForThisSite(popupLoginRow(Fixture.secondItem, Fixture.secondUser)), "\(Fixture.secondItem) is not listed under \"This site\"")
            XCTAssertFalse(listedForThisSite(popupLoginRow(Fixture.httpItem, "bob")), "a login for another site is listed under \"This site\"")
        }
        step("fill-from-popup") {
            row.tap()
            // The row opens the login; its Fill button is further down the sheet, and a tap scrolls to it.
            let fill = safari.webViews.buttons.matching(NSPredicate(format: "label == 'Fill' OR label BEGINSWITH 'Fill '")).firstMatch
            require(fill, "the Fill button of the login in the popup", timeout: 8)
            fill.tap()
            let username = webField("Username")
            if !matchFaceUntil(25, { (username.value as? String) == Fixture.siteUser }) {
                XCTFail("the popup did not fill the page, the field holds \(String(describing: username.value)). The popup says: \(popupDetails())")
            }
        }
        step("unlock-outlives-the-popup") {
            // No face is shown this time: a list that needs Face ID again does not appear.
            let listed = openPopup(until: { row.exists }, timeout: 12, showFace: false)
            if !listed {
                let details = popupDetails()
                _ = matchFaceUntil(20) { row.exists }
                XCTFail("opened again within 90 s of the unlock, the popup asked for Face ID again. The popup says: \(details)")
            }
        }
    }

    /// AutoFill in an app that has no website: andvari's own unlock field. The key above the keyboard opens the
    /// provider's list with every login, and choosing one puts its password in the field.
    func test09_AppFieldCredentialList() {
        step("provider-on") {
            requireAutoFillProvider()
        }
        step("unlock-screen") {
            bringAppForward()
            if currentScreen() == .vault {
                app.buttons["vault.lock"].tap()
            }
            expectScreen(.unlock)
            // The screen asks for a face by itself, which makes it busy; the system's sheet only offers Cancel once a
            // face has failed. Wait for that prompt first, so the test does not type under it.
            _ = waitUntil(6) { !self.element("unlock.sign-out").isEnabled || self.faceIDCancel != nil }
            let refused = refuseFaceID(until: { self.faceIDCancel == nil && self.element("unlock.sign-out").isEnabled && self.masterPasswordField.isHittable })
            XCTAssertTrue(refused, "the Face ID prompt is still up")
        }
        step("field-focused") {
            masterPasswordField.tap()
            Thread.sleep(forTimeInterval: 3)
            dumpTree(app, as: "app-field-focused")
        }
        step("passwords-key") {
            let key = app.descendants(matching: .any).matching(NSPredicate(format: "label CONTAINS[c] 'Passwords' OR label CONTAINS[c] 'AutoFill'")).firstMatch
            require(key, "the Passwords key above the keyboard", timeout: 5)
            key.tap()
            // With two providers on, iOS asks which one's list to open.
            chooseAndvariProvider(in: app)
        }
        step("list-after-face-id") {
            let row = { [self] in [app, springboard].map { self.labelled("No Address", in: $0) }.first { $0.exists } }
            let shown = matchFaceUntil(25) { row() != nil }
            dumpTree(app, as: "app-list")
            XCTAssertTrue(shown, "andvari's list of logins did not appear over the app")
            row()?.tap()
        }
        step("field-filled") {
            XCTAssertTrue(waitUntil(10) { !((self.masterPasswordField.value as? String) ?? "").isEmpty && (self.masterPasswordField.value as? String) != "Master password" }, "the field was not filled")
        }
    }

    /// What the owner checks by hand: two changed passwords and one new login saved from Safari are applied by the
    /// app at its next unlock and listed; the list is still there after a lock; a changed login shows its new
    /// password and the old one under "Previous passwords"; Undo takes one back; Undo all takes back the rest.
    func test10_SavedListPersistsUndoAndHistory() throws {
        if !systemAtLeast(26, 2) {
            try skip("The save request (SupportsSavePasswordCredentials) needs iOS 26.2; this simulator runs \(systemVersion.major).\(systemVersion.minor).")
        }
        let newUser = "carol\(Int(Date().timeIntervalSince1970) % 100000)"
        step("provider-on-and-no-saved-list") {
            requireAutoFillProvider()
            bringAppForward()
            reachVaultAnyWay()
            dismissSavedList()
        }
        step("three-saves-from-safari") {
            XCTAssertTrue(submitLoginAndSaveToAndvari(page: "login.html", heading: "Sign in", user: Fixture.siteUser, password: "Changed-Passw0rd-A", passwordLabel: "Password", submit: "Sign in"), "iOS did not offer to update \(Fixture.siteUser)'s password in andvari")
            XCTAssertTrue(submitLoginAndSaveToAndvari(page: "login.html", heading: "Sign in", user: Fixture.secondUser, password: "Changed-Passw0rd-B", passwordLabel: "Password", submit: "Sign in"), "iOS did not offer to update \(Fixture.secondUser)'s password in andvari")
            XCTAssertTrue(submitLoginAndSaveToAndvari(page: "login.html", heading: "Sign in", user: newUser, password: "New-Passw0rd-C", passwordLabel: "Password", submit: "Sign in"), "iOS did not offer to save \(newUser)'s login to andvari")
        }
        let three = app.staticTexts["Saved 3 logins from AutoFill"]
        let two = app.staticTexts["Saved 2 logins from AutoFill"]
        let anyList = app.staticTexts.matching(NSPredicate(format: "label BEGINSWITH 'Saved ' AND label ENDSWITH ' from AutoFill'")).firstMatch
        step("all-three-applied-at-unlock") {
            bringAppForward()
            reachVaultAnyWay()
            if !waitUntil(15, { three.exists }) {
                dumpTree(app, as: "not-three-saved")
                XCTFail("the app did not list three logins saved from AutoFill: \(saveListsSummary())")
            }
            let changed = app.cells.containing(NSPredicate(format: "label == %@", Fixture.secondUser)).firstMatch
            XCTAssertTrue(changed.staticTexts["New password for \(Fixture.secondItem). The old one is in its history."].exists, "the row of the changed login does not say what happened")
        }
        step("list-survives-a-lock") {
            app.buttons["vault.lock"].tap()
            expectScreen(.unlock)
            reachVaultAnyWay()
            XCTAssertTrue(waitUntil(10) { three.exists }, "the saved list was gone after a lock and unlock")
        }
        step("new-and-previous-password-in-the-login") {
            openItem(Fixture.secondItem)
            element("detail.reveal-password").tap()
            XCTAssertTrue(waitUntil(5) { (self.element("detail.password").value as? String) == "Changed-Passw0rd-B" }, "the login does not hold the saved password")
            let previous = app.staticTexts["Previous passwords"]
            for _ in 0..<3 where !previous.exists { app.swipeUp() }
            require(previous, "the login's previous passwords", timeout: 5)
            app.buttons["Show"].firstMatch.tap()
            XCTAssertTrue(waitUntil(5) { self.app.staticTexts[Fixture.secondPassword].exists }, "the previous password shown is not the seeded one")
            app.navigationBars.buttons.firstMatch.tap()
            // The list keeps its place; the saved logins are at its top.
            for _ in 0..<4 where !(anyList.exists && anyList.isHittable) { app.swipeDown() }
            require(anyList, "the saved list", timeout: 10)
        }
        step("undo-one") {
            let added = app.cells.containing(NSPredicate(format: "label == %@", newUser)).firstMatch
            require(added, "the new login's row in the saved list", timeout: 5)
            added.buttons["Undo"].tap()
            if !waitUntil(10, { two.exists }) {
                dumpTree(app, as: "after-undo")
                XCTFail("after one Undo the list does not read two saved logins: \(saveListsSummary())")
            }
        }
        step("undo-all") {
            let all = app.buttons["Undo all"]
            require(all, "Undo all", timeout: 5)
            all.tap()
            if !waitUntil(10, { !anyList.exists }) {
                dumpTree(app, as: "after-undo-all")
                XCTFail("the saved list is still there after Undo all: \(anyList.label)")
            }
        }
        step("everything-as-it-was") {
            openItem(Fixture.secondItem)
            element("detail.reveal-password").tap()
            XCTAssertTrue(waitUntil(5) { (self.element("detail.password").value as? String) == Fixture.secondPassword }, "Undo all did not put the seeded password back, the login holds \(String(describing: self.element("detail.password").value))")
            app.swipeUp()
            XCTAssertFalse(app.staticTexts["Previous passwords"].exists, "the undone password is still in the login's history")
            app.navigationBars.buttons.firstMatch.tap()
            openItem(Fixture.siteItem)
            element("detail.reveal-password").tap()
            XCTAssertTrue(waitUntil(5) { (self.element("detail.password").value as? String) == Fixture.sitePassword }, "Undo all did not put \(Fixture.siteUser)'s password back")
            app.navigationBars.buttons.firstMatch.tap()
            searchVault(newUser)
            Thread.sleep(forTimeInterval: 2)
            XCTAssertFalse(vaultRowContaining(newUser).exists, "the login that Undo took back is still in the vault")
            endSearch()
        }
    }

    /// The popup lists the vault's cards, and the popup sits in the middle of its sheet: its page's root fills the
    /// sheet's width, and a card's row is centred in it.
    func test11_PopupListsCardsAndIsCentred() {
        step("provider-and-extension-on") {
            requireAutoFillProvider()
            requireSafariExtension()
        }
        step("page") {
            openInSafari(Fixture.siteOrigin + "/login.html", heading: "Sign in")
        }
        let card = safari.webViews.staticTexts[Fixture.cardItem]
        step("popup-lists-the-card") {
            let row = popupLoginRow(Fixture.siteItem, Fixture.siteUser)
            if !openPopup(until: { row.exists }) {
                XCTFail("the popup did not unlock. The popup says: \(popupDetails())")
                return
            }
            XCTAssertTrue(popupHeading("Cards").exists, "the popup has no Cards heading")
            for _ in 0..<3 where !(card.exists && card.isHittable) { popupWebView.swipeUp() }
            XCTAssertTrue(card.exists, "the popup does not list the seeded card")
            XCTAssertTrue(safari.webViews.staticTexts["Visa ••1111"].exists, "the card's row does not show its masked number")
        }
        step("centred") {
            let window = safari.windows.firstMatch.frame
            let sheet = popupWebView.frame
            dumpTree(safari, as: "popup-layout")
            XCTAssertEqual(sheet.midX, window.midX, accuracy: 3, "the popup's sheet is not centred on the screen: \(sheet) in \(window)")
            guard let root = popupRoot() else {
                XCTFail("the popup page's root element was not found")
                return
            }
            XCTAssertEqual(root.frame.midX, sheet.midX, accuracy: 3, "the popup page's root is not centred in its sheet: \(root.frame) in \(sheet)")
            XCTAssertGreaterThanOrEqual(root.frame.width, sheet.width - 6, "the popup page's root does not fill its sheet: \(root.frame) in \(sheet)")
            guard let box = popupRowBox(Fixture.cardItem) else {
                XCTFail("the card's row was not found")
                return
            }
            XCTAssertEqual(box.frame.midX, sheet.midX, accuracy: 3, "the card's row is not centred in the sheet: \(box.frame) in \(sheet)")
        }
    }

    /// A login saved for one site, chosen in the popup on another: nothing is filled until a second tap on a
    /// confirmation that names both sites.
    func test12_PopupCrossSiteFillAsksFirst() {
        step("provider-and-extension-on") {
            requireAutoFillProvider()
            requireSafariExtension()
        }
        step("other-site") {
            openInSafari(Fixture.otherOrigin + "/login.html", heading: "Sign in")
        }
        let row = popupLoginRow(Fixture.siteItem, Fixture.siteUser)
        step("popup-lists-it-for-another-site") {
            if !openPopup(until: { row.exists }) {
                XCTFail("the popup did not unlock. The popup says: \(popupDetails())")
                return
            }
            XCTAssertFalse(listedForThisSite(row), "a login for \(Fixture.siteHost) is listed under \"This site\" on \(Fixture.otherHost)")
        }
        let username = webField("Username")
        let warning = safari.webViews.staticTexts.matching(NSPredicate(format: "label CONTAINS 'is saved for' AND label CONTAINS %@ AND label CONTAINS %@", Fixture.siteHost, Fixture.otherHost)).firstMatch
        step("confirmation-names-both-sites") {
            row.tap()
            // The row opens the login; its Fill button is further down the sheet, and a tap scrolls to it.
            let fill = safari.webViews.buttons.matching(NSPredicate(format: "label == 'Fill' OR label BEGINSWITH 'Fill '")).firstMatch
            require(fill, "the Fill button of the login in the popup", timeout: 8)
            fill.tap()
            if !waitUntil(8, { warning.exists }) {
                dumpTree(safari, as: "no-cross-site-confirmation")
                XCTFail("no confirmation naming \(Fixture.siteHost) and \(Fixture.otherHost) appeared")
            }
            XCTAssertTrue(((username.value as? String) ?? "").isEmpty, "the page was filled before the confirmation was answered")
        }
        step("filled-after-the-second-tap") {
            safari.webViews.buttons["Fill on \(Fixture.otherHost)"].tap()
            XCTAssertTrue(matchFaceUntil(25) { (username.value as? String) == Fixture.siteUser }, "the confirmed fill did not reach the page, the field holds \(String(describing: username.value))")
        }
    }
}
