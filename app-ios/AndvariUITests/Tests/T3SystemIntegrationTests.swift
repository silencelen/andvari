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
        step("page") {
            openInSafari(Fixture.siteOrigin + "/login.html", heading: "Sign in")
        }
        let username = webField("Username")
        step("username-focused") {
            require(username, "the page's username field")
            focus(username, heading: "Sign in")
            dumpEverything("username-focused")
        }
        step("offer-names-site-login-and-andvari") {
            require(fillOfferButton, "Safari's offer to fill from andvari")
            let text = containing("saved in", in: safari).label
            XCTAssertTrue(text.contains(Fixture.siteHost) && text.contains(Fixture.siteUser) && text.contains("andvari"), "the offer reads: \(text)")
        }
        step("fill-tapped") {
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

    /// iOS 26.2 and later: submitting a new login makes iOS offer to save it to andvari, and the app has it at its
    /// next unlock.
    func test06_NativeSavePrompt() throws {
        if !systemAtLeast(26, 2) {
            try skip("The save request (SupportsSavePasswordCredentials) needs iOS 26.2; this simulator runs \(systemVersion.major).\(systemVersion.minor).")
        }
        let user = "saved\(Int(Date().timeIntervalSince1970) % 100000)"
        step("provider-on") {
            requireAutoFillProvider()
        }
        step("page") {
            openInSafari(Fixture.siteOrigin + "/signup.html", heading: "Sign up")
        }
        step("form-typed") {
            let username = webField("Username")
            require(username, "the page's username field")
            focus(username, heading: "Sign up")
            username.typeText(user)
            let password = safari.webViews.secureTextFields["New password"]
            password.tap()
            Thread.sleep(forTimeInterval: 2)
            shot("strong-password-offer")
            // iOS offers a password of its own, to be saved in andvari; a person with their own closes that.
            closeFillOffer()
            if !safari.keyboards.firstMatch.exists {
                password.tap()
                Thread.sleep(forTimeInterval: 1.5)
                closeFillOffer()
            }
            password.typeText("Saved-Passw0rd-1")
        }
        step("save-offered-with-andvari") {
            safari.webViews.buttons["Create account"].tap()
            let alert = safari.alerts["Save Password?"]
            if !waitUntil(10, { alert.exists }) {
                dumpEverything("no-save-alert")
                XCTFail("iOS did not offer to save the new login")
            }
            XCTAssertTrue(alert.buttons["andvari"].exists, "andvari is not among the places to save to")
        }
        step("saved-to-andvari") {
            safari.alerts["Save Password?"].buttons["andvari"].tap()
            Thread.sleep(forTimeInterval: 4)
            dumpEverything("after-save")
        }
        step("arrives-in-the-app") {
            app.terminate()
            launchApp()
            reachVaultAnyWay()
            let saved = containing("from AutoFill", in: app)
            let row = app.descendants(matching: .any).matching(NSPredicate(format: "label CONTAINS[c] %@", user)).firstMatch
            let arrived = waitUntil(15) { row.exists }
            dumpTree(app, as: "after-save-in-app")
            XCTAssertTrue(arrived, "the saved login did not reach the app")
            // The design saves a new login by itself and lists it under "Saved … from AutoFill". When the app holds it
            // back instead, the row says why; that sentence is the failure.
            if !saved.exists {
                let reason = app.staticTexts.matching(NSPredicate(format: "label CONTAINS[c] 'vault' OR label CONTAINS[c] 'offline' OR label CONTAINS[c] 'changed'")).firstMatch
                XCTFail("the login reached the app but was not saved by itself; it is listed under \"Logins not saved yet\" with: \(reason.exists ? reason.label : "no reason shown")")
            }
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
            if !isOn(allow) {
                flip(allow)
                Thread.sleep(forTimeInterval: 1.5)
            }
            XCTAssertTrue(isOn(allow), "the extension did not turn on")
            dumpTree(settings, as: "settings-andvari-extension-on")
            SystemState.extensionEnabled = true
        }
    }

    /// The extension's popup in Safari: Face ID as it opens, this site's logins first, and a tap fills the page.
    func test08_SafariExtensionPopupFill() {
        step("provider-on") {
            requireAutoFillProvider()
        }
        step("extension-on") {
            XCTAssertTrue(SystemState.extensionEnabled, "the extension was not turned on in Settings (test07)")
        }
        step("page") {
            openInSafari(Fixture.siteOrigin + "/login.html", heading: "Sign in")
            // With the extension on, the page's field takes focus and Safari's offer covers the toolbar.
            _ = waitUntil(5) { self.fillOfferButton.exists }
            closeFillOffer()
            dumpTree(safari, as: "page-with-extension")
        }
        step("site-permission") {
            // The extension asks to see this site: a banner with Review, then how long to allow it.
            let review = safari.buttons["Review"]
            if waitUntil(4, { review.exists }) {
                review.tap()
                Thread.sleep(forTimeInterval: 2)
                dumpEverything("permission-review")
                let choices = safari.buttons.matching(NSPredicate(format: "label BEGINSWITH 'Always Allow'"))
                if choices.count > 0 {
                    choices.element(boundBy: 0).tap()
                    Thread.sleep(forTimeInterval: 2)
                    dumpEverything("permission-allowed")
                    let second = safari.buttons.matching(NSPredicate(format: "label BEGINSWITH 'Always Allow'"))
                    if second.count > 0 && second.element(boundBy: 0).isHittable {
                        second.element(boundBy: 0).tap()
                        Thread.sleep(forTimeInterval: 2)
                    }
                }
            }
            _ = waitUntil(3) { self.fillOfferButton.exists }
            closeFillOffer()
        }
        step("page-menu") {
            let menu = safari.buttons["PageFormatMenuButton"]
            if !waitUntil(10, { menu.exists && menu.isHittable }) {
                // A keyboard hides the toolbar.
                safari.webViews.staticTexts["Sign in"].firstMatch.tap()
                closeFillOffer()
            }
            if !waitUntil(10, { menu.exists && menu.isHittable }) {
                dumpTree(safari, as: "no-page-menu")
                XCTFail("Safari's page menu button is not reachable")
            }
            menu.tap()
            Thread.sleep(forTimeInterval: 2)
            dumpEverything("page-menu")
        }
        step("andvari-in-menu") {
            var entry = safari.descendants(matching: .any).matching(NSPredicate(format: "label BEGINSWITH[c] 'andvari'")).firstMatch
            if !entry.exists {
                // The extensions may sit one level down.
                for title in ["Manage Extensions", "Extensions"] where labelled(title, in: safari).exists {
                    labelled(title, in: safari).tap()
                    Thread.sleep(forTimeInterval: 1.5)
                    dumpEverything("extensions-menu")
                    break
                }
                entry = safari.descendants(matching: .any).matching(NSPredicate(format: "label BEGINSWITH[c] 'andvari'")).firstMatch
            }
            require(entry, "andvari in Safari's page menu", timeout: 5)
            entry.tap()
            Thread.sleep(forTimeInterval: 3)
            dumpEverything("popup-opening")
        }
        step("popup-lists-this-site") {
            let site = containing("This site", in: safari)
            let allow = safari.buttons["Allow for One Day"]
            let unlock = safari.buttons.matching(NSPredicate(format: "label BEGINSWITH 'Unlock with'")).firstMatch
            var tappedUnlock = false
            let listed = matchFaceUntil(40) {
                // Safari asks, per site, whether the extension may see it; the popup waits behind that.
                if allow.exists && allow.isHittable {
                    self.shot("extension-asks-for-a-site")
                    allow.tap()
                    return false
                }
                if !site.exists && !tappedUnlock && unlock.exists && unlock.isHittable {
                    tappedUnlock = true
                    unlock.tap()
                }
                return site.exists
            }
            dumpEverything("popup")
            XCTAssertTrue(listed, "the popup did not list this site's logins after Face ID")
        }
        step("fill-from-popup") {
            let row = safari.descendants(matching: .any).matching(NSPredicate(format: "label CONTAINS %@", Fixture.siteItem)).firstMatch
            require(row, "the seeded login in the popup", timeout: 5)
            row.tap()
            Thread.sleep(forTimeInterval: 2)
            dumpEverything("popup-row-tapped")
            // The detail has a Fill button; a second Face ID may be asked when the handler's process was ended.
            let fill = safari.buttons.matching(NSPredicate(format: "label BEGINSWITH[c] 'Fill'")).firstMatch
            if fill.exists {
                fill.tap()
            }
            let username = webField("Username")
            XCTAssertTrue(matchFaceUntil(20) { (username.value as? String) == Fixture.siteUser }, "the popup did not fill the page, the field holds \(String(describing: username.value))")
        }
    }

    /// AutoFill in an app that has no website: andvari's own unlock field. The key above the keyboard opens the
    /// provider's list with every login, and choosing one puts its password in the field.
    func test09_AppFieldCredentialList() {
        step("provider-on") {
            requireAutoFillProvider()
        }
        step("unlock-screen") {
            app.terminate()
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
}
