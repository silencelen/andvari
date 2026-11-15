import XCTest

/// Deleting an account on the simulator, against the throwaway server (app-ios/uitest/README.md): the seed tool made a
/// second, empty account for this test to delete. It runs last: it signs the seeded account out first.
final class T5AccountDeletionTests: UITestCase {
    /// Settings › Delete account shows what goes, takes the address and the master password, asks once more, and the
    /// deleted account leaves the app on the server screen.
    func test01_DeleteAnAccount() {
        launchApp()
        step("signed-out") {
            reachVaultAnyWay()
            signOutFromVault()
        }
        step("throwaway-signed-in") {
            enter(Fixture.throwawayEmail, into: emailField, what: "the email field")
            enter(Fixture.throwawayPassword + "\n", into: masterPasswordField, what: "the master password field")
            expectScreen(.vault, timeout: 60)
            confirmPersonalVaultIfAsked()
        }
        step("preview") {
            openSettings()
            settingsControl("settings.delete-account", "Delete account in Settings").tap()
            let goes = app.staticTexts.matching(NSPredicate(format: "label BEGINSWITH 'Your account, and its sign-in on every device'")).firstMatch
            require(goes, "what deleting takes, from the server's preview", timeout: 30)
            shot("preview")
        }
        step("confirmed") {
            enter(Fixture.throwawayEmail, into: app.textFields["field.delete-email"], what: "the address to confirm")
            enter(Fixture.throwawayPassword, into: app.secureTextFields["field.delete-password"], what: "the master password")
            let delete = element("button.delete-account")
            require(delete, "Delete account", timeout: 10)
            if !scrollToComfort(delete) {
                dumpTree(app, as: "no-delete-button")
                XCTFail("the Delete account button could not be brought on screen")
            }
            delete.tap()
            // The confirmation repeats the button's title; its own button has no identifier.
            let confirm = app.buttons.matching(NSPredicate(format: "label == 'Delete account' AND identifier == ''")).firstMatch
            if !waitUntil(10, { confirm.exists && confirm.isHittable }) {
                dumpTree(app, as: "no-delete-confirmation")
                XCTFail("the confirmation did not appear")
            }
            confirm.tap()
        }
        step("deleted") {
            expectScreen(.chooseServer, timeout: 90)
            shot("deleted")
        }
    }
}
