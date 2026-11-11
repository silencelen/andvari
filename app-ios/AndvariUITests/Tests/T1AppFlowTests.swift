import XCTest

/// The everyday app, in the order a person meets it. The tests run in name order and each one starts from
/// whatever the one before left: a relaunch always comes back locked, so every test proves its own way in.
final class T1AppFlowTests: UITestCase {
    /// First launch of a fresh install: no server is assumed, the Trust Gate shows the raw origin, sign-in lands
    /// in the vault with the seeded logins.
    func test01_FirstLaunchChooseServerSignIn() {
        launchApp()
        step("first-launch") {
            let screen = waitForScreen()
            XCTAssertEqual(screen, .chooseServer, "a fresh install must ask for a server before anything else")
        }
        step("server-typed") {
            enter(Fixture.serverOrigin, into: serverField, what: "the server field")
        }
        step("trust-gate") {
            serverField.typeText("\n")
            let origin = element("gate.origin")
            require(origin, "the Trust Gate")
            XCTAssertEqual(origin.value as? String, Fixture.serverOrigin)
        }
        step("welcome") {
            app.buttons["button.connect"].tap()
            expectScreen(.welcome)
            XCTAssertEqual(element("welcome.server").value as? String, Fixture.serverOrigin)
        }
        step("credentials-typed") {
            enter(Fixture.email, into: emailField, what: "the email field")
            enter(Fixture.password, into: masterPasswordField, what: "the master password field")
        }
        step("vault-list") {
            masterPasswordField.typeText("\n")
            expectScreen(.vault, timeout: 60)
            for name in Fixture.seededNames {
                require(vaultRow(name), "the seeded item \(name)", timeout: 30)
            }
        }
    }

    /// A wrong master password is refused in place and the right one still works.
    func test02_WrongPasswordThenUnlock() {
        launchApp()
        step("locked-after-relaunch") {
            expectScreen(.unlock)
            XCTAssertEqual(element("unlock.account").label, Fixture.email)
        }
        step("wrong-password-refused") {
            enter("not the password\n", into: masterPasswordField, what: "the master password field")
            Thread.sleep(forTimeInterval: 3)
            XCTAssertEqual(currentScreen(), .unlock, "a wrong password must not open the vault")
        }
        step("unlocked") {
            typeUnlock()
            expectScreen(.vault, timeout: 60)
        }
    }

    /// Leaving the app locks the vault: it comes back at the unlock screen.
    func test03_BackgroundLocks() {
        launchApp()
        step("vault") {
            reachVault()
        }
        step("home-screen") {
            XCUIDevice.shared.press(.home)
            Thread.sleep(forTimeInterval: 2)
        }
        step("locked-on-return") {
            app.activate()
            expectScreen(.unlock)
        }
        step("unlocked-again") {
            typeUnlock()
            expectScreen(.vault, timeout: 60)
        }
    }

    /// The Lock button in the vault's toolbar.
    func test04_LockButton() {
        launchApp()
        step("vault") {
            reachVault()
        }
        step("locked") {
            app.buttons["vault.lock"].tap()
            expectScreen(.unlock)
        }
    }

    /// An item's detail: the username, a hidden password that can be revealed, a running one-time code, the address.
    func test05_ItemDetail() {
        launchApp()
        step("vault") {
            reachVault()
        }
        step("detail") {
            vaultRow(Fixture.siteItem).tap()
            let username = element("detail.username")
            require(username, "the username row")
            XCTAssertEqual(username.value as? String, Fixture.siteUser)
            XCTAssertEqual(element("detail.password").value as? String, "Hidden")
        }
        step("password-revealed") {
            element("detail.reveal-password").tap()
            XCTAssertTrue(waitUntil(5) { (self.element("detail.password").value as? String) == Fixture.sitePassword }, "the revealed password is the seeded one")
        }
        step("one-time-code") {
            let code = element("detail.one-time-code")
            require(code, "the one-time code row")
            XCTAssertTrue(waitUntil(5) { ((code.value as? String) ?? "").range(of: #"^\d{6}, \d+ seconds left$"#, options: .regularExpression) != nil }, "a six-digit code with its time left, got \(String(describing: code.value))")
        }
        step("back-to-list") {
            app.navigationBars.buttons.firstMatch.tap()
            require(vaultRow(Fixture.siteItem), "the list")
        }
    }

    /// Search narrows the list.
    func test06_Search() {
        launchApp()
        step("vault") {
            reachVault()
        }
        step("search") {
            let search = app.searchFields.firstMatch
            if !search.exists {
                app.swipeDown()
            }
            enter("Plain", into: search, what: "the search field")
            XCTAssertTrue(waitUntil(10) { self.vaultRow(Fixture.httpItem).exists && !self.vaultRow(Fixture.siteItem).exists }, "only the matching login stays listed")
        }
    }

    /// Sign out from Settings: back at sign-in for the same server, and a relaunch stays signed out.
    func test07_SignOut() {
        launchApp()
        step("vault") {
            reachVault()
        }
        step("settings") {
            openSettings()
        }
        step("signed-out") {
            element("settings.sign-out").tap()
            confirmSignOut()
            XCTAssertEqual(element("welcome.server").value as? String, Fixture.serverOrigin)
        }
        step("still-signed-out-after-relaunch") {
            app.terminate()
            launchApp()
            expectScreen(.welcome)
        }
    }
}
