import XCTest

/// Shared vaults and vault health on the simulator, against the throwaway server (app-ios/uitest/README.md), as far as
/// one account can take them by itself. It runs last: the vault it makes, and the verdict it records, stay on the server.
final class T4SharingTests: UITestCase {
    /// A vault made here is on this account's own record: its screen asks no "You own" question and its members screen
    /// offers adding someone. The people this account verified start empty, and an address the server doesn't know is
    /// said so, with nothing recorded.
    func test01_SharedVaultMembersAndVerifiedPeople() {
        launchApp()
        step("vault") {
            // The tests before this one turn Face ID on: the unlock screen then asks for a face before the password.
            reachVaultAnyWay()
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
            // Settings again from its top: the list still stands where Shared vaults was, below the rows near the top,
            // and a list builds only the rows near what it shows.
            element("settings.done").tap()
            require(vaultRow(Fixture.siteItem), "the vault list", timeout: 15)
            openSettings()
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

    /// Vault health counts the logins, and a check run records only what the person says: "It worked" on the first
    /// login, then Stop. No breach check here: it would depend on the breach service the server relays to.
    func test02_VaultHealthRecordsACheck() {
        launchApp()
        step("vault") {
            reachVaultAnyWay()
        }
        step("health") {
            openSettings()
            settingsControl("Vault health", "Vault health in Settings").tap()
            let logins = app.descendants(matching: .any).matching(NSPredicate(format: "label BEGINSWITH 'Logins: '")).firstMatch
            require(logins, "the Logins count", timeout: 30)
            shot("health")
        }
        step("run") {
            app.buttons["Checked"].tap()
            let start = app.buttons.matching(NSPredicate(format: "label BEGINSWITH 'Check the '")).firstMatch
            require(start, "the button that checks the never-checked logins", timeout: 15)
            start.tap()
            require(app.navigationBars.matching(NSPredicate(format: "identifier BEGINSWITH 'Check 1 of '")).firstMatch, "the run on its first login", timeout: 15)
            shot("run")
            app.buttons["It worked"].tap()
            require(app.navigationBars.matching(NSPredicate(format: "identifier BEGINSWITH 'Check 2 of '")).firstMatch, "the run on its second login", timeout: 30)
            app.buttons["Stop"].tap()
        }
        step("recorded") {
            let recorded = app.descendants(matching: .any).matching(NSPredicate(format: "label CONTAINS 'Checked recently: it worked'")).firstMatch
            if !scrollToComfort(recorded) {
                dumpTree(app, as: "no-recorded-check")
                XCTFail("the login checked does not show the verdict")
            }
            shot("recorded")
        }
    }
}
