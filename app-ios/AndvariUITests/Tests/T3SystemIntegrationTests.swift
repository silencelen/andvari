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
            username.tap()
            Thread.sleep(forTimeInterval: 3)
            dumpEverything("username-focused")
        }
        step("suggestion-tapped") {
            guard let suggestion = offered(Fixture.siteUser) else {
                XCTFail("the keyboard offered no andvari login for \(Fixture.siteHost)")
                return
            }
            suggestion.tap()
            Thread.sleep(forTimeInterval: 1.5)
            dumpEverything("suggestion-tapped")
        }
        step("filled") {
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
            username.tap()
            Thread.sleep(forTimeInterval: 3)
        }
        step("passwords-key") {
            guard let key = offered("Passwords") ?? offered("AutoFill") ?? offered("Password") else {
                dumpEverything("no-passwords-key")
                XCTFail("the keyboard has no Passwords key to open the list with")
                return
            }
            key.tap()
            Thread.sleep(forTimeInterval: 2)
            dumpEverything("after-passwords-key")
            // With more than one provider iOS asks which one.
            if let chooser = offered("andvari") {
                chooser.tap()
                Thread.sleep(forTimeInterval: 1.5)
                dumpEverything("after-choosing-andvari")
            }
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
            code.tap()
            Thread.sleep(forTimeInterval: 3)
            dumpEverything("code-focused")
        }
        step("code-offered") {
            guard let suggestion = offered("andvari") ?? offered(Fixture.siteUser) ?? offered("code") else {
                XCTFail("the keyboard offered no one-time code from andvari")
                return
            }
            suggestion.tap()
            Thread.sleep(forTimeInterval: 1.5)
            dumpEverything("code-tapped")
        }
        step("code-filled") {
            XCTAssertTrue(matchFaceUntil(25) { ((code.value as? String) ?? "").range(of: #"^\d{6}$"#, options: .regularExpression) != nil }, "no six-digit code was filled, the field holds \(String(describing: code.value))")
        }
    }

    /// A plain-http page is offered the login saved as http and not the https site's.
    func test05_SafariPlainHttpPage() {
        step("provider-on") {
            requireAutoFillProvider()
        }
        step("page") {
            openInSafari(Fixture.httpOrigin + "/login.html", heading: "Sign in")
        }
        let username = webField("Username")
        step("username-focused") {
            require(username, "the page's username field")
            username.tap()
            Thread.sleep(forTimeInterval: 3)
            dumpEverything("http-username-focused")
        }
        step("only-the-http-login") {
            XCTAssertNil(offered(Fixture.siteUser), "the https site's login was offered on a plain-http page")
            XCTAssertNotNil(offered("bob"), "the login saved for the http address was not offered")
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
            username.tap()
            Thread.sleep(forTimeInterval: 1)
            username.typeText(user)
            let password = safari.webViews.secureTextFields["New password"]
            password.tap()
            Thread.sleep(forTimeInterval: 2)
            dumpEverything("new-password-focused")
            // iOS may put its own strong password in the field; typing over it is what a person with their own does.
            if let own = offered("Choose My Own Password") ?? offered("Other Options") {
                own.tap()
                Thread.sleep(forTimeInterval: 1)
            }
            password.typeText("Saved-Passw0rd-1")
        }
        step("submitted") {
            safari.webViews.buttons["Create account"].tap()
            Thread.sleep(forTimeInterval: 3)
            dumpEverything("after-submit")
        }
        step("save-offered") {
            guard let save = offered("Save Password") ?? offered("Save") else {
                XCTFail("iOS did not offer to save the new login")
                return
            }
            save.tap()
            Thread.sleep(forTimeInterval: 3)
            dumpEverything("after-save")
        }
        step("arrives-in-the-app") {
            app.terminate()
            launchApp()
            reachVaultAnyWay()
            let saved = containing("from AutoFill", in: app)
            let row = app.descendants(matching: .any).matching(NSPredicate(format: "label CONTAINS[c] %@", user)).firstMatch
            if !waitUntil(15, { saved.exists || row.exists }) {
                dumpTree(app, as: "no-saved-login")
                XCTFail("the saved login did not arrive in the app")
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
}
