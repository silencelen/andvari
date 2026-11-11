import XCTest

/// andvari as part of iOS: the AutoFill provider and the Safari extension. Each step that the simulator cannot do
/// is a skip with the reason, never a pass.
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
                toggle.tap()
                // Turning a provider on may ask to confirm, or to turn off another.
                Thread.sleep(forTimeInterval: 2)
                shot("after-tap")
                dumpTree(settingsApp, as: "settings-after-tap")
                answerSystemAlerts()
            }
            XCTAssertTrue(waitUntil(5) { self.isOn(self.autoFillProviderSwitch) }, "the andvari switch did not stay on")
        }
        step("suggestions-published") {
            relaunchAndUnlock()
        }
    }

    /// Safari on the test site: what the keyboard offers for the username field.
    func test02_SafariQuickTypeFill() throws {
        step("page") {
            openInSafari(Fixture.siteOrigin + "/login.html", heading: "Sign in")
        }
        let username = safari.webViews.textFields["Username"]
        step("username-focused") {
            require(username, "the page's username field")
            username.tap()
            Thread.sleep(forTimeInterval: 2.5)
            dumpKeyboardArea("safari-username-focused")
        }
        let suggestion = safari.descendants(matching: .any).matching(NSPredicate(format: "label CONTAINS[c] %@ AND NOT (label CONTAINS[c] 'Username')", Fixture.siteUser)).firstMatch
        if !suggestion.exists {
            XCTFail("the keyboard offered no andvari login for \(Fixture.siteHost)")
            return
        }
        step("suggestion-tapped") {
            suggestion.tap()
            Thread.sleep(forTimeInterval: 1.5)
            dumpTree(springboard, as: "after-suggestion-springboard")
        }
        step("filled") {
            XCTAssertTrue(matchFaceUntil(25) { (username.value as? String) == Fixture.siteUser }, "the username was not filled, it holds \(String(describing: username.value))")
            let password = safari.webViews.secureTextFields["Password"]
            XCTAssertFalse(((password.value as? String) ?? "").isEmpty, "the password was not filled")
        }
    }
}
