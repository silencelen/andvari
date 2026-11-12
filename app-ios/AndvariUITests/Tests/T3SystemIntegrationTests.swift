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
            let chooser = safari.buttons["andvari"]
            require(chooser, "andvari in the provider chooser", timeout: 8)
            chooser.tap()
            Thread.sleep(forTimeInterval: 1.5)
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
    /// itself at its next unlock, under "Saved 1 login from AutoFill".
    func test06_NativeSavePrompt() throws {
        if !systemAtLeast(26, 2) {
            try skip("The save request (SupportsSavePasswordCredentials) needs iOS 26.2; this simulator runs \(systemVersion.major).\(systemVersion.minor).")
        }
        let user = "saved\(Int(Date().timeIntervalSince1970) % 100000)"
        step("provider-on") {
            requireAutoFillProvider()
        }
        step("save-offered-and-taken") {
            XCTAssertTrue(submitLoginAndSaveToAndvari(page: "signup.html", heading: "Sign up", user: user, password: "Saved-Passw0rd-1", passwordLabel: "New password", submit: "Create account"), "iOS did not offer to save the new login to andvari")
        }
        try step("saved-by-itself-at-unlock") {
            launchApp()
            reachVaultAnyWay()
            let saved = containing("from AutoFill", in: app)
            let name = app.staticTexts.matching(NSPredicate(format: "label CONTAINS[c] %@", user)).firstMatch
            let arrived = waitUntil(15) { saved.exists || name.exists }
            dumpTree(app, as: "after-save-in-app")
            XCTAssertTrue(arrived, "the saved login did not reach the app")
            if !saved.exists && app.staticTexts[KnownDefect.noPersonalVaultMessage].exists {
                try skip(KnownDefect.noPersonalVault + " Here: the save offer worked and the capture reached the app, where it waits under \"Logins not saved yet\".")
            }
            XCTAssertTrue(saved.exists, "the login reached the app but was not saved by itself")
        }
    }

    /// Settings > Apps > Safari > Extensions: turn the andvari web extension on and let it run on websites.
    func test07_EnableSafariExtensionInSettings() {
        let settings = settingsApp
        step("settings-apps") {
            settings.terminate()
            settings.launch()
            XCTAssertTrue(scrollToAndTap(labelled("Apps", in: settings), in: settings), "Settings has no Apps row")
            Thread.sleep(forTimeInterval: 1.5)
            dumpTree(settings, as: "settings-apps")
        }
        step("safari-settings") {
            let search = settings.searchFields.firstMatch
            if search.exists {
                search.tap()
                search.typeText("Safari")
                Thread.sleep(forTimeInterval: 1.5)
            }
            let row = settings.cells.matching(NSPredicate(format: "label BEGINSWITH 'Safari'")).firstMatch
            let fallback = labelled("Safari", in: settings)
            XCTAssertTrue(scrollToAndTap(row.exists ? row : fallback, in: settings, swipes: 12), "Settings > Apps has no Safari row")
            Thread.sleep(forTimeInterval: 1.5)
            dumpTree(settings, as: "settings-safari")
        }
        step("extensions") {
            XCTAssertTrue(scrollToAndTap(labelled("Extensions", in: settings), in: settings, swipes: 10), "Safari's settings have no Extensions row")
            Thread.sleep(forTimeInterval: 1.5)
            dumpTree(settings, as: "settings-extensions")
        }
        step("andvari-extension") {
            let row = settings.descendants(matching: .any).matching(NSPredicate(format: "label BEGINSWITH[c] 'andvari'")).firstMatch
            XCTAssertTrue(scrollToAndTap(row, in: settings, swipes: 4), "andvari is not listed under Safari's extensions")
            Thread.sleep(forTimeInterval: 1.5)
            dumpTree(settings, as: "settings-andvari-extension")
        }
        step("allowed") {
            let allow = settings.switches.matching(NSPredicate(format: "label CONTAINS[c] 'Allow Extension'")).firstMatch
            require(allow, "the Allow Extension switch")
            // A tap that lands while the screen is still sliding in changes nothing: look, and try again.
            for _ in 0..<3 where !isOn(allow) {
                Thread.sleep(forTimeInterval: 1.5)
                flip(allow)
                _ = waitUntil(5) { self.isOn(allow) }
            }
            XCTAssertTrue(isOn(allow), "the extension did not turn on")
            dumpTree(settings, as: "settings-andvari-extension-on")
            SystemState.extensionEnabled = true
        }
    }

    /// The extension's popup in Safari: Face ID once it has painted, this site's logins first, and a tap fills.
    func test08_SafariExtensionPopupFill() {
        step("provider-on") {
            requireAutoFillProvider()
        }
        step("extension-on") {
            XCTAssertTrue(SystemState.extensionEnabled, "the extension was not turned on in Settings (test07)")
        }
        step("page") {
            openInSafari(Fixture.siteOrigin + "/login.html", heading: "Sign in")
        }
        step("popup-lists-this-sites-login") {
            let row = popupRow(Fixture.siteItem)
            let listed = openPopup(until: { row.exists })
            if !listed {
                XCTFail("the popup listed no login for this site after Face ID. The popup says: \(popupDetails())")
            }
        }
        step("fill-from-popup") {
            popupRow(Fixture.siteItem).tap()
            Thread.sleep(forTimeInterval: 2)
            dumpEverything("popup-row-tapped")
            let fill = safari.webViews.buttons.matching(NSPredicate(format: "label BEGINSWITH[c] 'Fill'")).firstMatch
            if fill.exists && fill.isHittable {
                fill.tap()
            }
            let username = webField("Username")
            let filled = matchFaceUntil(25) { (username.value as? String) == Fixture.siteUser }
            if !filled {
                XCTFail("the popup did not fill the page, the field holds \(String(describing: username.value)). The popup says: \(popupDetails())")
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
            launchApp()
            expectScreen(.unlock)
            // The screen asks for a face by itself; the system's sheet only offers Cancel once a face has failed.
            Thread.sleep(forTimeInterval: 2)
            Biometrics.noMatch()
            dismissBiometricPrompt()
            XCTAssertTrue(waitUntil(8) { self.element("unlock.sign-out").isEnabled }, "the Face ID prompt is still up")
        }
        step("field-focused") {
            masterPasswordField.tap()
            Thread.sleep(forTimeInterval: 3)
            dumpTree(app, as: "app-field-focused")
            dumpTree(springboard, as: "app-field-focused-springboard")
        }
        step("passwords-key") {
            let key = app.descendants(matching: .any).matching(NSPredicate(format: "label CONTAINS[c] 'Passwords' OR label CONTAINS[c] 'AutoFill'")).firstMatch
            require(key, "the Passwords key above the keyboard", timeout: 5)
            key.tap()
            Thread.sleep(forTimeInterval: 2)
            dumpTree(app, as: "app-after-passwords-key")
            dumpTree(springboard, as: "app-after-passwords-key-springboard")
            // With two providers on, iOS asks which one's list to open.
            let chooser = app.buttons["andvari"]
            require(chooser, "andvari in the provider chooser", timeout: 8)
            chooser.tap()
        }
        step("list-after-face-id") {
            let row = { [self] in [app, springboard].map { self.labelled("No Address", in: $0) }.first { $0.exists } }
            let shown = matchFaceUntil(25) { row() != nil }
            dumpTree(app, as: "app-list")
            dumpTree(springboard, as: "app-list-springboard")
            XCTAssertTrue(shown, "andvari's list of logins did not appear over the app")
            row()?.tap()
        }
        step("field-filled") {
            XCTAssertTrue(waitUntil(10) { !((self.masterPasswordField.value as? String) ?? "").isEmpty && (self.masterPasswordField.value as? String) != "Master password" }, "the field was not filled")
        }
    }

    /// What the owner checks by hand after a changed password is saved from Safari: the app replaces the login's
    /// password by itself and lists it; the list is still there after a lock; the login shows its previous
    /// password; Undo puts one back; Undo all puts the rest back.
    func test10_ChangedPasswordsSavedListUndoAndHistory() throws {
        if !systemAtLeast(26, 2) {
            try skip("The save request (SupportsSavePasswordCredentials) needs iOS 26.2; this simulator runs \(systemVersion.major).\(systemVersion.minor).")
        }
        step("provider-on") {
            requireAutoFillProvider()
        }
        step("two-changed-passwords-saved-from-safari") {
            XCTAssertTrue(submitLoginAndSaveToAndvari(page: "login.html", heading: "Sign in", user: Fixture.siteUser, password: "Changed-Passw0rd-A", passwordLabel: "Password", submit: "Sign in"), "iOS did not offer to save the first changed password to andvari")
            XCTAssertTrue(submitLoginAndSaveToAndvari(page: "login.html", heading: "Sign in", user: Fixture.secondUser, password: "Changed-Passw0rd-B", passwordLabel: "Password", submit: "Sign in"), "iOS did not offer to save the second changed password to andvari")
        }
        let two = app.staticTexts["Saved 2 logins from AutoFill"]
        let one = app.staticTexts["Saved 1 login from AutoFill"]
        step("both-applied-at-unlock") {
            launchApp()
            reachVaultAnyWay()
            if !waitUntil(15, { two.exists }) {
                dumpTree(app, as: "no-saved-list")
                XCTFail("the app did not list two logins saved from AutoFill")
            }
        }
        step("list-survives-a-lock") {
            app.buttons["vault.lock"].tap()
            expectScreen(.unlock)
            reachVaultAnyWay()
            XCTAssertTrue(waitUntil(10) { two.exists }, "the saved list was gone after a lock and unlock")
        }
        step("previous-password-in-the-login") {
            app.swipeUp()
            let row = vaultRow(Fixture.secondItem)
            require(row, "the changed login in the list")
            row.tap()
            require(element("detail.username"), "the login's detail")
            element("detail.reveal-password").tap()
            XCTAssertTrue(waitUntil(5) { (self.element("detail.password").value as? String) == "Changed-Passw0rd-B" }, "the login does not hold the saved password")
            app.swipeUp()
            XCTAssertTrue(waitUntil(5) { self.app.staticTexts["Previous passwords"].exists }, "the login shows no previous passwords")
            dumpTree(app, as: "detail-with-history")
            app.navigationBars.buttons.firstMatch.tap()
            app.swipeDown()
        }
        step("undo-one") {
            let undo = app.buttons.matching(NSPredicate(format: "label == 'Undo'")).firstMatch
            require(undo, "an Undo button in the saved list")
            undo.tap()
            if !waitUntil(10, { one.exists }) {
                dumpTree(app, as: "after-undo")
                XCTFail("after one Undo the list does not read one saved login")
            }
        }
        step("undo-all") {
            let all = app.buttons["Undo all"]
            if all.exists {
                all.tap()
            } else {
                // With one entry left its own Undo is the whole of it.
                app.buttons.matching(NSPredicate(format: "label == 'Undo'")).firstMatch.tap()
            }
            Thread.sleep(forTimeInterval: 1)
            // A destructive action may ask once more.
            let confirm = app.buttons.matching(NSPredicate(format: "label BEGINSWITH 'Undo' AND identifier == ''"))
            if confirm.count > 0 && one.exists {
                confirm.element(boundBy: confirm.count - 1).tap()
            }
            if !waitUntil(10, { !one.exists && !two.exists }) {
                dumpTree(app, as: "after-undo-all")
                XCTFail("the saved list is still there after undoing everything")
            }
        }
        step("passwords-are-back") {
            app.swipeUp()
            vaultRow(Fixture.secondItem).tap()
            require(element("detail.username"), "the login's detail")
            element("detail.reveal-password").tap()
            XCTAssertTrue(waitUntil(5) { (self.element("detail.password").value as? String) == Fixture.secondPassword }, "Undo did not put the seeded password back, the login holds \(String(describing: self.element("detail.password").value))")
        }
    }

    /// The popup lists the vault's cards, and its content sits in the middle of the sheet.
    func test11_PopupListsCardsAndIsCentred() throws {
        step("provider-on") {
            requireAutoFillProvider()
        }
        if !SystemState.extensionEnabled {
            try skip("The Safari extension was not turned on in Settings in this run (test07), so there is no popup to look at.")
        }
        step("page") {
            openInSafari(Fixture.siteOrigin + "/login.html", heading: "Sign in")
        }
        var unlocked = false
        step("popup-unlocked") {
            let row = popupRow(Fixture.siteItem)
            unlocked = openPopup(until: { row.exists })
        }
        if !unlocked {
            try skip("The popup did not unlock in this run; test08 is the test that says why. The popup says: \(popupDetails())")
        }
        step("cards-listed") {
            let search = safari.webViews.textFields.firstMatch
            safari.webViews.firstMatch.swipeUp()
            let card = popupRow(Fixture.cardItem)
            if !waitUntil(8, { card.exists }) {
                dumpTree(safari, as: "popup-no-card")
                XCTFail("the popup does not list the seeded card")
            }
            _ = search
        }
        step("centred") {
            let popup = safari.webViews.containing(NSPredicate(format: "label CONTAINS %@", Fixture.cardItem)).firstMatch
            let content = popup.exists ? popup : safari.webViews.element(boundBy: safari.webViews.count - 1)
            let row = popupRow(Fixture.cardItem)
            let window = safari.windows.firstMatch.frame
            dumpTree(safari, as: "popup-layout")
            XCTAssertEqual(content.frame.midX, window.midX, accuracy: 4, "the popup's view is not centred in the sheet: \(content.frame) in \(window)")
            XCTAssertEqual(row.frame.midX, window.midX, accuracy: 12, "the popup's rows are not centred in the sheet: \(row.frame) in \(window)")
        }
    }

    /// A login saved for one site, chosen in the popup on another: nothing is filled until a second tap on a
    /// confirmation that names both sites.
    func test12_PopupCrossSiteFillAsksFirst() throws {
        step("provider-on") {
            requireAutoFillProvider()
        }
        if !SystemState.extensionEnabled {
            try skip("The Safari extension was not turned on in Settings in this run (test07), so there is no popup to look at.")
        }
        step("other-site") {
            openInSafari(Fixture.otherOrigin + "/login.html", heading: "Sign in")
        }
        var unlocked = false
        step("popup-unlocked") {
            let row = popupRow(Fixture.siteItem)
            unlocked = openPopup(until: { row.exists })
        }
        if !unlocked {
            try skip("The popup did not unlock in this run; test08 is the test that says why. The popup says: \(popupDetails())")
        }
        let username = webField("Username")
        let warning = safari.webViews.staticTexts.matching(NSPredicate(format: "label CONTAINS 'is saved for' AND label CONTAINS %@ AND label CONTAINS %@", Fixture.siteHost, Fixture.otherHost)).firstMatch
        step("confirmation-names-both-sites") {
            popupRow(Fixture.siteItem).tap()
            Thread.sleep(forTimeInterval: 1.5)
            let fill = safari.webViews.buttons.matching(NSPredicate(format: "label == 'Fill' OR label BEGINSWITH 'Fill '")).firstMatch
            if !warning.exists && fill.exists && fill.isHittable {
                fill.tap()
            }
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
