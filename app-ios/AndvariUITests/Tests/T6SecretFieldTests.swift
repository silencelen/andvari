import XCTest

/// Every field of the app that takes a secret, typed a key at a time as a person types, and read back: the login
/// editor's password, one-time code key and notes, the card editor's number, security code and notes, a note's text,
/// the recovery phrase and the unlock screen's master password. What is typed has what a keyboard likes to rewrite (a
/// misspelt word, two hyphens, straight quotes, a small letter at the start), so a field that lets the keyboard correct
/// it fails here too. The master password fields of sign-in, two-step sign-in, account deletion and a backup are typed
/// the same way where their own tests use them (T9, T4 test07, T8). Not typed here: the enrolment screens (their
/// master password, and the recovery phrase typed back), which need an invite and are being rebuilt, and the new master
/// password after a recovery, which needs the account's phrase and the seed tool throws that away.
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
            app.buttons["Save"].tap()
            require(vaultRow(name), "\(name) in the vault", timeout: 20)
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
            app.buttons["Save"].tap()
            require(vaultRow(name), "\(name) in the vault", timeout: 20)
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
            app.buttons["Save"].tap()
            require(vaultRow(name), "\(name) in the vault", timeout: 20)
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
}
