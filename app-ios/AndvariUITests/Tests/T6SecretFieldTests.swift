import XCTest

/// Every field of the app that takes a secret, typed a key at a time as a person types, and read back: the login
/// editor's password, one-time code key and notes, the card editor's number, security code and notes, a note's text,
/// the recovery phrase and the unlock screen's master password. What is typed has what a keyboard likes to rewrite (a
/// misspelt word, two hyphens, straight quotes, a small letter at the start), so a field that lets the keyboard correct
/// it fails here too. The last test enrolls a new account in the app and recovers it, for the fields only those screens
/// have: the enrolment's master password and its confirmation, the recovery phrase typed back, and the new master
/// password and its confirmation after a recovery. The master password fields of sign-in, two-step sign-in, account
/// deletion and a backup are typed the same way where their own tests use them (T9, T4 test07, T8).
final class T6SecretFieldTests: UITestCase {
    private let stamp = Int(Date().timeIntervalSince1970) % 100000

    /// A login: the password and the one-time code's key, each hidden while typed and read back with its Show; the
    /// notes; then saved, and read again from the item (the code is the one an authenticator gives for the key).
    func test01_LoginEditorSecretsTypedAKeyAtATime() {
        let name = "Typed Login \(stamp)"
        let password = "Typ3d--pass'w0rd\"1"
        let key = "JBSWY3DPEHPK3PXP"
        let notes = "teh notes -- it's \"q\"\nline two"
        step("new-login-editor") {
            freshVault()
            openNewItemEditor("New login")
            enter(name, into: app.textFields["Name"], what: "the Name field")
            enter("tess", into: app.textFields["Username"], what: "the Username field")
        }
        step("password-typed") {
            let kept = typeKeyByKey(password, into: app.secureTextFields["Password"], what: "the editor's Password field")
            XCTAssertEqual(kept, password.count, "the Password field let go of the keyboard after \(kept) of \(password.count) characters")
            XCTAssertEqual(shownEntry("Password"), password, "the Password field does not hold what was typed")
        }
        step("code-key-typed") {
            let field = app.secureTextFields["Secret or otpauth:// link"]
            scrollFormTo(field)
            let kept = typeKeyByKey(key, into: field, what: "the one-time code's key field")
            XCTAssertEqual(kept, key.count, "the one-time code's key field let go of the keyboard after \(kept) of \(key.count) characters")
            XCTAssertEqual(shownEntry("Secret or otpauth:// link"), key, "the one-time code's key field does not hold what was typed")
        }
        step("notes-typed") {
            let field = app.textViews["Notes"]
            scrollFormTo(field)
            let kept = typeKeyByKey(notes, into: field, what: "the Notes field")
            XCTAssertEqual(kept, notes.count, "the Notes field let go of the keyboard after \(kept) of \(notes.count) characters")
            XCTAssertEqual(field.value as? String, notes, "the Notes field does not hold what was typed")
        }
        step("saved-and-read-back") {
            saveEditor("New login")
            XCTAssertEqual(revealedPassword(of: name), password, "the password was not saved as typed")
            let code = element("detail.one-time-code")
            require(code, "the one-time code row")
            // The code of the 30 seconds now, or of the ones either side when the clock has just turned.
            let now = Date()
            let expected = [now.addingTimeInterval(-30), now, now.addingTimeInterval(30)].compactMap { Authenticator.code(base32: key, at: $0) }
            XCTAssertTrue(
                waitUntil(5) { expected.contains(String(((code.value as? String) ?? "").prefix(6))) },
                "the item's one-time code \(String(describing: code.value)) is not the code of the key typed (\(expected.joined(separator: ", ")))"
            )
            XCTAssertTrue(detailNotesRead(notes), "the notes were not saved as typed")
            app.navigationBars.buttons.firstMatch.tap()
        }
    }

    /// A card: the number and the security code on the number pad, each read back with its Show; the notes; then saved,
    /// and read again from the item.
    func test02_CardEditorSecretsTypedAKeyAtATime() {
        let name = "Typed Card \(stamp)"
        // A card network's test number: it passes the check digit and belongs to no one.
        let number = "5555555555554444"
        let code = "737"
        let notes = "teh pin -- 12"
        step("new-card-editor") {
            freshVault()
            openNewItemEditor("New card")
            enter(name, into: app.textFields["Name"], what: "the Name field")
        }
        step("number-typed") {
            let kept = typeKeyByKey(number, into: app.secureTextFields["Card number"], what: "the Card number field")
            XCTAssertEqual(kept, number.count, "the Card number field let go of the keyboard after \(kept) of \(number.count) digits")
            XCTAssertEqual(shownEntry("Card number").filter(\.isNumber), number, "the Card number field does not hold what was typed")
        }
        step("expiry-typed") {
            enter("11", into: app.textFields["Month (MM)"], what: "the Month field")
            enter("2032", into: app.textFields["Year (YYYY)"], what: "the Year field")
        }
        step("code-typed") {
            let field = app.secureTextFields["Security code"]
            scrollFormTo(field)
            let kept = typeKeyByKey(code, into: field, what: "the Security code field")
            XCTAssertEqual(kept, code.count, "the Security code field let go of the keyboard after \(kept) of \(code.count) digits")
            XCTAssertEqual(shownEntry("Security code"), code, "the Security code field does not hold what was typed")
        }
        step("notes-typed") {
            let field = app.textViews["Notes"]
            scrollFormTo(field)
            let kept = typeKeyByKey(notes, into: field, what: "the Notes field")
            XCTAssertEqual(kept, notes.count, "the Notes field let go of the keyboard after \(kept) of \(notes.count) characters")
            XCTAssertEqual(field.value as? String, notes, "the Notes field does not hold what was typed")
        }
        step("saved-and-read-back") {
            saveEditor("New card")
            openAnyItem(name)
            XCTAssertEqual(revealedDetail("detail.card number", show: "Show card number").filter(\.isNumber), number, "the card number was not saved as typed")
            XCTAssertEqual(revealedDetail("detail.security code", show: "Show security code"), code, "the security code was not saved as typed")
            XCTAssertTrue(detailNotesRead(notes), "the notes were not saved as typed")
            app.navigationBars.buttons.firstMatch.tap()
        }
    }

    /// A note's text, two lines of it: read back from the field, then from the saved note.
    func test03_NoteTextTypedAKeyAtATime() {
        let name = "Typed Note \(stamp)"
        let text = "teh note -- it's \"q\"\nline two"
        step("new-note-editor") {
            freshVault()
            openNewItemEditor("New note")
            enter(name, into: app.textFields["Name"], what: "the Name field")
        }
        step("note-typed") {
            let field = app.textViews["Note"]
            let kept = typeKeyByKey(text, into: field, what: "the Note field")
            XCTAssertEqual(kept, text.count, "the Note field let go of the keyboard after \(kept) of \(text.count) characters")
            XCTAssertEqual(field.value as? String, text, "the Note field does not hold what was typed")
        }
        step("saved-and-read-back") {
            saveEditor("New note")
            openAnyItem(name)
            XCTAssertTrue(detailNotesRead(text), "the note was not saved as typed")
            app.navigationBars.buttons.firstMatch.tap()
        }
    }

    /// The recovery phrase on "Forgot your master password?": hidden while typed, the same characters once shown. The
    /// phrase is not sent: it is not this account's.
    func test04_RecoveryPhraseTypedAKeyAtATime() {
        // The shape of a phrase: letters of both cases, digits, hyphens (two in a row) and underscores.
        let phrase = "Q2Fu-dF9i_ZS1h--bHRlcmVk_0aW5n"
        step("unlock-screen") {
            freshVault()
            app.buttons["vault.lock"].tap()
            settleUnlockScreenForTyping()
        }
        step("recover-screen") {
            let forgot = app.buttons.matching(NSPredicate(format: "label == 'Forgot your master password?'")).firstMatch
            require(forgot, "Forgot your master password? on the unlock screen")
            if !safelyHittable(forgot) { app.swipeUp() }
            forgot.tap()
            require(app.staticTexts["Reset your master password"], "the recover screen")
        }
        step("phrase-typed-and-shown") {
            let field = app.secureTextFields["Recovery phrase"]
            let kept = typeKeyByKey(phrase, into: field, what: "the Recovery phrase field")
            XCTAssertEqual(kept, phrase.count, "the Recovery phrase field let go of the keyboard after \(kept) of \(phrase.count) characters")
            XCTAssertEqual(shownEntry("Recovery phrase"), phrase, "the Recovery phrase field does not hold what was typed")
        }
        step("cancelled") {
            let cancel = app.buttons["Cancel"]
            if safelyHittable(cancel) {
                cancel.tap()
                expectScreen(.unlock)
            }
        }
    }

    /// The unlock screen's master password, typed a key at a time: one dot a character, and it opens the vault.
    func test05_MasterPasswordTypedAKeyAtATimeUnlocks() {
        step("unlock-screen") {
            freshVault()
            app.buttons["vault.lock"].tap()
            settleUnlockScreenForTyping()
        }
        step("typed-and-unlocked") {
            let field = masterPasswordField
            let count = Fixture.password.count
            let kept = typeKeyByKey(Fixture.password, into: field, what: "the unlock screen's master password field")
            XCTAssertEqual(kept, count, "the master password field let go of the keyboard after \(kept) of \(count) characters")
            if let dots = hiddenLength(of: field) {
                XCTAssertEqual(dots, count, "the master password field shows \(dots) dots for \(count) characters typed")
            }
            field.typeText("\n")
            expectScreen(.vault, timeout: 60)
        }
    }

    /// A new account enrolled in the app with an invite, and then recovered: the enrolment's master password and its
    /// confirmation, the recovery phrase typed back, the same phrase typed to recover, and the new master password and
    /// its confirmation, each a key at a time. What was typed is known by what it opens: the phrase typed back is the
    /// one shown, the phrase typed to recover is taken, and the new master password signs in.
    func test06_EnrolmentAndRecoveryFieldsTypedAKeyAtATime() {
        let email = "enrol-\(stamp)@andvari-uitest.test"
        let password = "correct horse enrol staple \(stamp)"
        let renewed = "correct horse renewed staple \(stamp)"
        var code = ""
        var phrase = ""
        step("invited-elsewhere") {
            let invite = OtherDevice.invite(email)
            XCTAssertNil(invite.problem, "the invite could not be made")
            code = invite.code ?? ""
            XCTAssertFalse(code.isEmpty, "the invite has no code")
        }
        step("enrolment-form") {
            freshVault()
            signOutFromVault()
            let tab = app.buttons["Enroll"]
            require(tab, "Enroll on the sign-in screen")
            tab.tap()
            enter(code, into: app.textFields["field.invite"], what: "the Invite field")
            enter(email, into: emailField, what: "the Email field")
        }
        step("master-password-typed-twice") {
            let first = masterPasswordField
            let again = app.secureTextFields["field.confirm-password"]
            scrollFormTo(first)
            var typed = typeKeyByKey(password, into: first, what: "the enrolment's master password field")
            XCTAssertEqual(typed, password.count, "the enrolment's master password field let go of the keyboard after \(typed) of \(password.count) characters")
            if let dots = hiddenLength(of: first) {
                XCTAssertEqual(dots, password.count, "the enrolment's master password field shows \(dots) dots for \(password.count) characters typed")
            }
            scrollFormTo(again)
            typed = typeKeyByKey(password, into: again, what: "the enrolment's Confirm password field")
            XCTAssertEqual(typed, password.count, "the enrolment's Confirm password field let go of the keyboard after \(typed) of \(password.count) characters")
            // Done puts the keyboard away.
            again.typeText("\n")
            _ = waitUntil(5) { !self.app.keyboards.firstMatch.exists }
            XCTAssertFalse(app.staticTexts["The passwords don't match."].exists, "the two passwords, typed the same, are said to differ")
        }
        step("vault-created") {
            // No printed recovery sheet: the form asks for a tick that says so.
            let waiver = app.descendants(matching: .any).matching(NSPredicate(format: "label CONTAINS 'I understand that if I lose my master password'"))
            let create = element("button.create-vault")
            _ = scrollToComfort(create, lowest: 0.93)
            guard let tick = firstHittable(waiver) else {
                dumpTree(app, as: "no-waiver")
                XCTFail("the enrolment form has no tick for enrolling without a recovery sheet")
                return
            }
            tick.tap()
            if !waitUntil(5, { create.exists && create.isEnabled }) {
                dumpTree(app, as: "create-vault-not-offered")
                XCTFail("Create vault is not offered. The form says: \(enrolmentWords())")
            }
            _ = scrollToComfort(create, lowest: 0.93)
            create.tap()
            if !waitUntil(180, { self.app.staticTexts["Save your recovery phrase"].exists }) {
                dumpTree(app, as: "not-enrolled")
                XCTFail("the recovery phrase was not shown within 180 s of Create vault. The form says: \(enrolmentWords())")
            }
        }
        step("phrase-typed-back") {
            phrase = shownRecoveryPhrase()
            XCTAssertGreaterThanOrEqual(phrase.count, 40, "the screen shows no recovery phrase to type back")
            let field = app.secureTextFields["Type it back"]
            scrollFormTo(field)
            let typed = typeKeyByKey(phrase, into: field, what: "the Type it back field")
            XCTAssertEqual(typed, phrase.count, "the Type it back field let go of the keyboard after \(typed) of \(phrase.count) characters")
            XCTAssertEqual(shownEntry("Type it back"), phrase, "the Type it back field does not hold what was typed")
            let saved = app.buttons["I've saved it"]
            scrollFormTo(saved)
            saved.tap()
            if !waitUntil(90, { self.currentScreen() == .vault }) {
                dumpTree(app, as: "phrase-not-confirmed")
                XCTFail("the vault did not open after the phrase was typed back: \(enrolmentWords())")
            }
        }
        step("signed-out") {
            signOutFromVault()
        }
        step("phrase-typed-to-recover") {
            let forgot = app.buttons.matching(NSPredicate(format: "label == 'Forgot your master password?'")).firstMatch
            require(forgot, "Forgot your master password? on the sign-in screen")
            if !safelyHittable(forgot) { app.swipeUp() }
            forgot.tap()
            require(app.staticTexts["Reset your master password"], "the recover screen")
            let address = app.textFields["field.email"]
            clearField(address)
            enter(email, into: address, what: "the recover screen's Email field")
            let field = app.secureTextFields["Recovery phrase"]
            let typed = typeKeyByKey(phrase, into: field, what: "the Recovery phrase field")
            XCTAssertEqual(typed, phrase.count, "the Recovery phrase field let go of the keyboard after \(typed) of \(phrase.count) characters")
            // Go sends it: the next step comes only for the account's own phrase.
            field.typeText("\n")
            if !waitUntil(90, { self.app.secureTextFields["field.new-master-password"].exists }) {
                dumpTree(app, as: "phrase-not-taken")
                XCTFail("the phrase typed was not taken: \(enrolmentWords())")
            }
        }
        step("new-master-password-typed-twice") {
            let first = app.secureTextFields["field.new-master-password"]
            let again = app.secureTextFields["field.type-it-again"]
            var typed = typeKeyByKey(renewed, into: first, what: "the New master password field")
            XCTAssertEqual(typed, renewed.count, "the New master password field let go of the keyboard after \(typed) of \(renewed.count) characters")
            scrollFormTo(again)
            typed = typeKeyByKey(renewed, into: again, what: "the Type it again field")
            XCTAssertEqual(typed, renewed.count, "the Type it again field let go of the keyboard after \(typed) of \(renewed.count) characters")
            XCTAssertFalse(app.staticTexts["The two don't match yet."].exists, "the two new passwords, typed the same, are said to differ")
            // Go resets the master password.
            again.typeText("\n")
            if !waitUntil(150, { self.currentScreen() == .welcome }) {
                dumpTree(app, as: "not-reset")
                XCTFail("the app is not back on the sign-in screen 150 s after the reset: \(enrolmentWords())")
            }
            let said = app.staticTexts.matching(NSPredicate(format: "label BEGINSWITH 'Master password reset'")).firstMatch
            note(waitUntil(3) { said.exists } ? "after the reset the app says: \(said.label)" : "after the reset the sign-in screen shows no notice")
        }
        step("signed-in-with-the-new-password") {
            clearField(emailField)
            enter(email, into: emailField, what: "the email field")
            enter(renewed + "\n", into: masterPasswordField, what: "the master password field")
            // A recovery uses the phrase up: the sign-in after it may first show a new one to save.
            let again = app.staticTexts["Save your recovery phrase"]
            if !waitUntil(150, { self.currentScreen() == .vault || again.exists }) {
                dumpTree(app, as: "new-password-not-taken")
                XCTFail("the new master password did not sign in: \(enrolmentWords())")
            }
            if again.exists {
                note("the sign-in after the recovery showed a new recovery phrase to save before the vault")
                let fresh = shownRecoveryPhrase()
                let field = app.secureTextFields["Type it back"]
                scrollFormTo(field)
                enter(fresh, into: field, what: "the Type it back field")
                let saved = app.buttons["I've saved it"]
                scrollFormTo(saved)
                saved.tap()
                expectScreen(.vault, timeout: 90)
            }
            signOutFromVault()
        }
    }

    // MARK: - Helpers

    /// The recovery phrase the screen shows once: one run of letters, digits, hyphens and underscores.
    private func shownRecoveryPhrase() -> String {
        let shown = app.staticTexts.matching(NSPredicate(format: "label MATCHES %@", "^[A-Za-z0-9_-]{40,}$")).firstMatch
        if !waitUntil(30, { shown.exists }) {
            dumpTree(app, as: "no-recovery-phrase")
            return ""
        }
        return shown.label
    }

    /// What the enrolment and recovery screens say when they refuse, for a failure message.
    private func enrolmentWords() -> String {
        screenWords(containing: ["stronger", "invite", "couldn't", "can't", "doesn't", "don't match", "expired", "Try again", "wrong", "Timed out", "Checking"])
    }
}
