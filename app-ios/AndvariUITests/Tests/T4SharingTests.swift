import XCTest

/// Shared vaults on the simulator, against the throwaway server (app-ios/uitest/README.md), as far as one account can
/// take them by itself. It runs last: the vault it makes stays on the server.
final class T4SharingTests: UITestCase {
    /// A vault made here is on this account's own record: its screen asks no "You own" question and its members screen
    /// offers adding someone. The people this account verified start empty, and an address the server doesn't know is
    /// said so, with nothing recorded.
    func test01_SharedVaultMembersAndVerifiedPeople() {
        launchApp()
        step("vault") {
            reachVault()
        }
        step("shared-vaults") {
            openSettings()
            settingsControl("Shared vaults", "Shared vaults in Settings").tap()
            require(app.buttons["New shared vault…"], "New shared vault in Shared vaults", timeout: 30)
        }
        step("created") {
            app.buttons["New shared vault…"].tap()
            enter("Family", into: app.alerts.textFields.firstMatch, what: "the new vault's name")
            app.alerts.buttons["Create"].tap()
            require(app.staticTexts["Family"], "the new vault in the list", timeout: 30)
            shot("created")
        }
        step("its-screen") {
            app.staticTexts["Family"].tap()
            require(app.buttons["Members"], "Members on the vault's screen", timeout: 20)
            XCTAssertFalse(app.staticTexts["You own “Family”?"].exists, "made here, so on this account's own record")
            shot("vault-screen")
        }
        step("members") {
            app.buttons["Members"].tap()
            require(app.textFields["field.member-email"], "the add-a-member field", timeout: 30)
            require(app.staticTexts["UI test (you)"], "this account, listed as the owner", timeout: 10)
            XCTAssertFalse(app.staticTexts["You own “Family”?"].exists)
            shot("members")
        }
        step("back-to-settings") {
            // One screen at a time, each arrival checked before the next tap: a tap that lands mid-transition would
            // reach the bar underneath.
            for title in ["Family", "Shared vaults", "Settings"] {
                app.navigationBars.buttons.element(boundBy: 0).tap()
                require(app.navigationBars[title], "back on \(title)", timeout: 15)
            }
            require(element("settings.done"), "the settings sheet", timeout: 10)
        }
        step("verified-people") {
            settingsControl("People you verified", "People you verified in Settings").tap()
            require(app.staticTexts["Nobody yet."], "the empty list of people verified", timeout: 30)
            enter("nobody@andvari-uitest.test", into: app.textFields["field.person-email"], what: "the address to look up")
            app.buttons["Look up and verify"].tap()
            require(app.staticTexts["No active account has that email."], "the server's answer for an unknown address", timeout: 30)
            XCTAssertTrue(app.staticTexts["Nobody yet."].exists, "nothing was recorded")
            shot("verified-people")
        }
    }
}
