import XCTest

/// Deleting an account that owns a shared vault someone else still uses. The preview names the vault and offers no
/// confirmation while it stands; once the vault is deleted in Shared vaults the account can be deleted, the app stands
/// on the server screen, and nothing of the account is left on the device, in a new process either. The account is a
/// throwaway one the seed tool makes for this test (tools/uitest-seed `share`): it owns a vault the seeded account
/// reads. Runs last: it signs the seeded account out, and in again at its end.
final class T9DeletionBlockerTests: UITestCase {
    private let stamp = Int(Date().timeIntervalSince1970) % 100000

    func test01_SharedVaultBlocksDeletionUntilItIsDeleted() {
        let owner = "owner-\(stamp)@andvari-uitest.test"
        let ownerPassword = "correct horse owner staple \(stamp)"
        let vault = "Owned \(stamp)"
        let item = "Owned Login \(stamp)"
        let blocker = "You own “\(vault)”, and 1 other person still uses it. Delete it, or make one of them its owner, first (Shared vaults)."
        let goes = app.staticTexts.matching(NSPredicate(format: "label BEGINSWITH 'Your account, and its sign-in on every device'")).firstMatch

        step("owner-shares-a-vault-elsewhere") {
            XCTAssertNil(
                OtherDevice.shareReadOnly(vault: vault, item: item, ownerEmail: owner, ownerPassword: ownerPassword),
                "the owner's account and the vault it shares with the seeded account could not be made"
            )
        }
        // What the device keeps while nobody is signed in, before the owner's account ever touches it.
        var before: Set<String> = []
        step("seeded-account-signed-out") {
            freshVault()
            signOutFromVault()
            before = Set(LocalState.accountFiles())
        }
        step("owner-signed-in") {
            clearField(emailField)
            enter(owner, into: emailField, what: "the email field")
            // The master password a key at a time, as a person types it: the sign-in takes it only as it is.
            let typed = typeKeyByKey(ownerPassword, into: masterPasswordField, what: "the sign-in screen's master password field")
            XCTAssertEqual(typed, ownerPassword.count, "the sign-in screen's master password field let go of the keyboard after \(typed) of \(ownerPassword.count) characters")
            masterPasswordField.typeText("\n")
            expectScreen(.vault, timeout: 90)
            confirmPersonalVaultIfAsked()
            require(vaultRow(item), "the owner's login in the vault it shares", timeout: 30)
        }
        step("preview-names-the-vault-and-takes-no-confirmation") {
            openSettings()
            settingsControl("settings.delete-account", "Delete account in Settings").tap()
            require(goes, "what deleting takes, from the server's preview", timeout: 30)
            if !scrollToComfort(app.staticTexts[blocker]) {
                dumpTree(app, as: "no-blocker")
                XCTFail("the preview does not say what stands in the way (\(blocker)). It says: \(deletionWords())")
            }
            let again = app.buttons["Check again"]
            XCTAssertTrue(scrollToComfort(again), "the preview offers no Check again")
            XCTAssertFalse(app.textFields["field.delete-email"].exists, "the preview takes the address while a vault stands in the way")
            XCTAssertFalse(element("button.delete-account").exists, "the preview offers Delete account while a vault stands in the way")
        }
        step("vault-deleted-in-shared-vaults") {
            // Out of Settings and in again: its list stands far below Shared vaults, and builds only the rows near it.
            app.navigationBars.buttons.element(boundBy: 0).tap()
            let done = element("settings.done")
            require(done, "Settings", timeout: 15)
            done.tap()
            _ = waitUntil(10) { !done.exists }
            openSharedVaults()
            let row = app.staticTexts[vault]
            require(row, "\(vault) among the shared vaults", timeout: 30)
            row.tap()
            require(app.buttons["Members"], "the vault's own screen", timeout: 20)
            confirmOwnershipIfAsked(of: vault, password: ownerPassword)
            let name = app.textFields["Type “\(vault)” to delete it"]
            if !scrollToComfort(name) {
                dumpTree(app, as: "no-delete-vault-field")
                XCTFail("the vault's screen has no field to type its name into: \(sharedVaultWords())")
            }
            // Return puts the keyboard away: Delete vault is under it.
            enter(vault + "\n", into: name, what: "the vault's name, typed to delete it")
            _ = waitUntil(5) { !self.app.keyboards.firstMatch.exists }
            let delete = app.buttons["Delete vault"]
            if !scrollToComfort(delete) {
                dumpTree(app, as: "no-delete-vault")
                XCTFail("Delete vault could not be brought on screen")
            }
            XCTAssertTrue(delete.isEnabled, "Delete vault is not offered for the name typed")
            delete.tap()
            // The vault's screen closes by itself once the vault is gone.
            require(app.navigationBars["Shared vaults"], "the shared vaults again", timeout: 30)
            if !waitUntil(20, { !row.exists }) {
                dumpTree(app, as: "vault-not-deleted")
                XCTFail("\(vault) is still among the vaults after Delete vault: \(sharedVaultWords())")
            }
            closeSharedVaults()
        }
        step("preview-takes-the-confirmation") {
            _ = waitUntil(10) { self.safelyHittable(self.settingsButton) }
            openSettings()
            settingsControl("settings.delete-account", "Delete account in Settings").tap()
            require(goes, "what deleting takes, from the server's preview", timeout: 30)
            if !scrollToComfort(app.textFields["field.delete-email"]) {
                dumpTree(app, as: "still-blocked")
                XCTFail("the preview takes no confirmation after the vault was deleted. It says: \(deletionWords())")
            }
            XCTAssertFalse(app.staticTexts[blocker].exists, "the preview still names the vault that was deleted")
        }
        step("confirmed") {
            enter(owner, into: app.textFields["field.delete-email"], what: "the address to confirm")
            let password = app.secureTextFields["field.delete-password"]
            let typed = typeKeyByKey(ownerPassword, into: password, what: "the master password that confirms the deletion")
            XCTAssertEqual(typed, ownerPassword.count, "the deletion's master password field let go of the keyboard after \(typed) of \(ownerPassword.count) characters")
            // Return puts the keyboard away: the button is under it.
            password.typeText("\n")
            _ = waitUntil(5) { !self.app.keyboards.firstMatch.exists }
            let delete = element("button.delete-account")
            require(delete, "Delete account", timeout: 10)
            if !scrollToComfort(delete) {
                dumpTree(app, as: "no-delete-button")
                XCTFail("the Delete account button could not be brought on screen")
            }
            delete.tap()
            // The confirmation repeats the button's title; its own button has no identifier.
            let confirm = app.buttons.matching(NSPredicate(format: "label == 'Delete account' AND identifier == ''")).firstMatch
            if !waitUntil(10, { self.safelyHittable(confirm) }) {
                dumpTree(app, as: "no-delete-confirmation")
                XCTFail("the confirmation did not appear. The screen says: \(deletionWords())")
            }
            confirm.tap()
        }
        step("on-the-server-screen") {
            if !waitUntil(90, { self.currentScreen() == .chooseServer }) {
                dumpTree(app, as: "not-deleted")
                XCTFail("the app is not on the server screen 90 s after Delete account. The screen says: \(deletionWords())")
            }
            let said = app.staticTexts["The account \(owner) was deleted, with everything this iPhone kept for it."]
            let seen = waitUntil(3) { said.exists }
            XCTContext.runActivity(named: seen ? "the server screen says the account was deleted" : "the server screen shows no notice of the deletion") { _ in }
        }
        step("nothing-left-in-a-new-process") {
            app.terminate()
            launchApp()
            XCTAssertEqual(waitForScreen(), .chooseServer, "a new process of the app does not start on the server screen")
            let files = LocalState.accountFiles()
            XCTAssertEqual(files.filter { !before.contains($0) }, [], "the deleted account left files on the device")
            XCTAssertEqual(files.filter { $0.contains("/vault-") }, [], "a vault cache is still on the device")
            XCTAssertNil(LocalState.signedInEmail(), "the snapshot the extensions read is still on the device")
        }
        step("seeded-account-in-again-without-the-vault") {
            reachVault()
            XCTAssertFalse(vaultRow(item).exists, "the login of the vault its owner deleted is still in the seeded account's vault")
        }
    }

    // MARK: - Helpers

    /// "You own “…”?": a vault made on another device of the account is on the account's own record, so its screen
    /// here does not ask. Should it ask, the master password answers, as the screen says.
    private func confirmOwnershipIfAsked(of vault: String, password: String) {
        let ask = app.buttons["Confirm I own “\(vault)”…"]
        guard waitUntil(3, { ask.exists }) else { return }
        XCTContext.runActivity(named: "the vault's screen asked the owner to confirm it owns “\(vault)”") { _ in }
        scrollToComfort(ask)
        ask.tap()
        let field = app.secureTextFields["Master password (required)"]
        enter(password + "\n", into: field, what: "the master password that confirms the ownership")
        _ = waitUntil(5) { !self.app.keyboards.firstMatch.exists }
        let confirm = app.buttons["Confirm"]
        scrollToComfort(confirm)
        confirm.tap()
        if !waitUntil(30, { !field.exists && !ask.exists }) {
            dumpTree(app, as: "ownership-not-confirmed")
            XCTFail("the ownership of \(vault) was not confirmed: \(sharedVaultWords())")
        }
    }

    /// What the Delete account screen says, for a failure message.
    private func deletionWords() -> String {
        screenWords(containing: ["You own", "only admin", "can't", "didn't", "isn't", "wrong", "Try again", "stands"])
    }

    private func sharedVaultWords() -> String {
        screenWords(containing: ["You own", "reports you", "can't", "couldn't", "Try again", "Deleted"])
    }
}
