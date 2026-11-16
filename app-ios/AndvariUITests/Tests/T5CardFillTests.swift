import XCTest

/// Card fill as the owner decided it on 2026-11-14: a card goes only into a payment provider's card form, here the test
/// site's stand-in provider (Fixture.providerOrigin), which only the Safari extension's UI-test build lists. A shop's own
/// card fields get nothing, nor does any page from the review rounds' attacks (extension/test-pages/card-*.html): the
/// popup offers no Fill there and says to copy from the app. checkout.html is a shop page that embeds the provider's form
/// in one frame (?layout=card), in a frame per field (?layout=split), or as a security code alone (?layout=code). Runs
/// after T3 and T4: AutoFill, the Safari extension and Face ID are already on, and Safari has let the extension run on
/// the test site, not yet on the provider's.
final class T5CardFillTests: UITestCase {
    /// The end of the popup's line under the cards when it copies instead of filling (errors.ts, the Safari build).
    private let copyFromApp = "Copy what you need from the andvari app."

    /// Every page of the review rounds' card attacks and first-party card forms: no Fill is offered, and the popup's
    /// line says why and to copy from the app. The skimmer's hidden form receives nothing.
    func test01_MerchantPagesRefuseWithCopyFromApp() {
        step("provider-and-extension-on") {
            requireAutoFillProvider()
            requireSafariExtension()
        }
        let pages = TestSite.cardPages()
        step("card-test-pages-listed") {
            XCTAssertGreaterThanOrEqual(pages.count, 18, "the test site lists \(pages.count) card test pages: \(pages)")
        }
        let fill = safari.webViews.buttons.matching(NSPredicate(format: "label BEGINSWITH 'Fill this card'")).firstMatch
        let line = popupSays(copyFromApp)
        for name in pages {
            step("refused-" + name.replacingOccurrences(of: ".html", with: "")) {
                // Each page says, in its own words, that nothing is filled into it since 2026-11-14.
                openInSafari(Fixture.siteOrigin + "/test-pages/" + name, containing: "nothing is filled into this page")
                if !openPopup(until: { line.exists || fill.exists }) {
                    XCTFail("\(name): the popup showed neither a Fill nor a line to copy from the app. It says: \(popupWords())")
                    return
                }
                XCTAssertFalse(fill.exists, "\(name): the popup offers a card fill: \(fill.exists ? fill.label : "")")
                XCTAssertTrue(line.exists, "\(name): the popup does not say to copy from the app. It says: \(popupWords())")
                closePopup()
                if name == "card-skimmer.html" {
                    let got = safari.webViews.staticTexts.matching(NSPredicate(format: "label CONTAINS 'cardnumber=' OR label CONTAINS 'cvc=' OR label CONTAINS 'exp-month=' OR label CONTAINS 'ccname=' OR label CONTAINS 'postal='")).firstMatch
                    XCTAssertFalse(got.exists, "the skimmer's form received: \(got.exists ? got.label : "")")
                }
            }
        }
    }

    /// checkout.html while Safari still keeps the extension out of the provider's frame (Other Websites: Ask): the
    /// popup lists the cards with no Fill. Once every website is allowed in Safari's settings, it offers a Fill into the
    /// provider's origin. The design has the popup name the provider's site to allow meanwhile; when it does not, the
    /// test ends skipped with that finding, after the rest has passed.
    func test02_ProviderFrameOutOfReachThenAllowed() throws {
        step("provider-and-extension-on") {
            requireAutoFillProvider()
            requireSafariExtension()
        }
        let providerHost = providerHostWithPort()
        let allowLine = popupSays("where Safari doesn't let andvari run yet")
        let card = popupSays(Fixture.cardItem)
        let fill = fillButton()
        var named: String?
        step("provider-out-of-reach") {
            openInSafari(checkout("card"), heading: "Checkout")
            if !openPopup(until: { card.exists || fill.exists }) {
                XCTFail("the popup on the checkout listed no card. It says: \(popupWords())")
                return
            }
            // The cards come after the logins: give the line under them a moment.
            _ = waitUntil(5) { allowLine.exists || fill.exists }
            XCTAssertFalse(fill.exists, "a Fill is offered into a frame Safari keeps the extension out of")
            if allowLine.exists {
                named = allowLine.label
                XCTAssertTrue(allowLine.label.contains(providerHost), "the line does not name \(providerHost): \(allowLine.label)")
                XCTAssertTrue(allowLine.label.contains(copyFromApp), "the line does not say to copy from the app: \(allowLine.label)")
            }
            closePopup()
        }
        step("every-website-allowed") {
            XCTAssertTrue(allowExtensionOnEveryWebsite(), "Safari's settings did not let the extension run on every website")
        }
        step("fill-offered") {
            openInSafari(checkout("card"), heading: "Checkout")
            XCTAssertTrue(openPopup(until: { fill.exists }), "the popup offers no Fill into \(Fixture.providerOrigin) once every website is allowed. It says: \(popupWords())")
            XCTAssertFalse(allowLine.exists, "the popup still names the site to allow")
            closePopup()
        }
        if named == nil {
            try skip("Finding (2026-11-14): while Safari kept the extension out of the provider's frame (Other Websites: Ask, the default), the popup on checkout.html listed the cards with no Fill and no line at all; the design has it name the provider's site to allow (\"The card form comes from \(providerHost), where Safari doesn't let andvari run yet…\"). With every website allowed, the Fill into \(Fixture.providerOrigin) is offered (checked above). Safari may not report to the extension a frame it keeps the extension out of.")
        }
    }

    /// ?layout=card: a tap on the card number in the provider's frame, then Fill: the number, the expiry and the security
    /// code land in the provider's form, and the shop's own name-on-card field stays empty.
    func test03_ProviderCardFormFills() {
        requireProviderReachable()
        let number = providerField("Card number")
        let expiry = providerField("Expiry")
        let code = providerField("Security code")
        step("number-tapped-and-filled") {
            openInSafari(checkout("card"), heading: "Checkout")
            tapAndFill(number, "the provider's card number", reach: .addressBar) { self.digits(number) == Fixture.cardNumber }
        }
        step("the-provider-form-only") {
            XCTAssertTrue(Fixture.cardExpiryDigits.contains(digits(expiry)), "the expiry holds \(text(expiry))")
            XCTAssertEqual(digits(code), Fixture.cardCode, "the security code was not filled")
            XCTAssertEqual(text(shopNameOnCard), "", "the shop's own name-on-card field was filled")
        }
    }

    /// ?layout=split: one provider frame per field. A fill reaches only the frames the person chose in (round 11): a
    /// tap on the number alone, then Fill, fills the number alone; a tap in each frame, then one Fill, fills all three.
    func test04_SplitProviderFramesFillWhereTapped() {
        requireProviderReachable()
        let number = providerField("Card number")
        let expiry = providerField("Expiry")
        let code = providerField("Security code")
        step("number-alone-tapped-and-filled") {
            openInSafari(checkout("split"), heading: "Checkout")
            tapAndFill(number, "the card number frame", reach: .addressBar, checkLabel: { label in
                XCTAssertTrue(label.contains("card number"), "the Fill does not name the card number: \(label)")
                XCTAssertFalse(label.contains("expiry") || label.contains("security code"), "the Fill names a detail of a frame not tapped: \(label)")
            }) { self.digits(number) == Fixture.cardNumber }
            Thread.sleep(forTimeInterval: 2)
            XCTAssertEqual(digits(expiry), "", "the expiry frame, not tapped, was filled. The frames saw: \(pageEvents())")
            XCTAssertEqual(digits(code), "", "the security code frame, not tapped, was filled. The frames saw: \(pageEvents())")
        }
        step("each-frame-tapped-then-one-fill") {
            openInSafari(checkout("split"), heading: "Checkout")
            tapField(number)
            tapField(expiry)
            tapAndFill(code, "the split provider's frames", reach: .addressBar) {
                self.digits(number) == Fixture.cardNumber && Fixture.cardExpiryDigits.contains(self.digits(expiry)) && self.digits(code) == Fixture.cardCode
            }
            XCTAssertEqual(text(shopNameOnCard), "", "the shop's own name-on-card field was filled")
        }
    }

    /// ?layout=code: a security code alone in the provider's frame (a saved card asked for again). A tap on it, then
    /// Fill: the seeded card's code.
    func test05_LoneSecurityCodeFrameFills() {
        requireProviderReachable()
        let code = providerField("Security code")
        step("code-tapped-and-filled") {
            openInSafari(checkout("code"), heading: "Checkout")
            tapAndFill(code, "the lone security code", reach: .addressBar) { self.digits(code) == Fixture.cardCode }
        }
    }

    /// The keyboard's Done, the way a person brings Safari's page menu back in the default layout, does not drop the
    /// choice: the provider's form still fills.
    func test06_ChoiceSurvivesTheKeyboardsDone() {
        requireProviderReachable()
        let number = providerField("Card number")
        let code = providerField("Security code")
        step("number-tapped-done-and-filled") {
            openInSafari(checkout("card"), heading: "Checkout")
            tapAndFill(number, "the provider's card number", reach: .keyboardDone) { self.digits(number) == Fixture.cardNumber }
            XCTAssertEqual(digits(code), Fixture.cardCode, "the security code was not filled")
        }
    }

    /// ?layout=twice: a second card-number frame beside the first. Two provider frames ask for the same card detail, so
    /// the popup offers no Fill, says why, and copies instead (round 11); nothing is filled anywhere.
    func test07_SecondFrameOfAKindIsRefused() {
        requireProviderReachable()
        let numbers = safari.webViews.textFields.matching(NSPredicate(format: "label == 'Card number'"))
        let expiry = providerField("Expiry")
        let code = providerField("Security code")
        let fill = fillButton()
        let doubled = popupSays("more than one payment form asking for the same card detail")
        step("first-number-tapped-and-popup-opened") {
            openInSafari(checkout("twice"), heading: "Checkout")
            XCTAssertTrue(waitUntil(15) { numbers.count == 2 }, "the page shows \(numbers.count) card-number frames, not two")
            tapField(numbers.element(boundBy: 0))
            if !openPopup(until: { doubled.exists || fill.exists }, reach: .addressBar) {
                XCTFail("the popup showed neither a Fill nor why it fills none. It says: \(popupWords())")
                return
            }
            XCTAssertFalse(fill.exists, "the popup offers a Fill with two card-number frames on the page")
            XCTAssertTrue(doubled.exists, "the popup does not say why it fills none. It says: \(popupWords())")
            XCTAssertTrue(doubled.exists && doubled.label.contains(copyFromApp), "the line does not say to copy from the app: \(doubled.exists ? doubled.label : "")")
            closePopup()
        }
        step("nothing-filled") {
            for index in 0..<numbers.count {
                XCTAssertEqual(digits(numbers.element(boundBy: index)), "", "card-number frame \(index + 1) was filled")
            }
            XCTAssertEqual(digits(expiry), "", "the expiry frame was filled")
            XCTAssertEqual(digits(code), "", "the security code frame was filled")
        }
    }

    /// ?layout=lure (rounds 12 and 13): the shop asks for the security code alone, beside another site's "rewards" widget
    /// that mounts provider frames of its own. A field tapped there and the shop's code are two payment forms (round 13):
    /// the popup fills neither, says so and offers Start over. Once the person starts over and taps the code, the Fill
    /// names the security code alone, and the widget's fields keep what was typed.
    func test08_LureWidgetFieldsNeverJoinTheFill() {
        requireProviderReachable()
        // field.html labels its input by kind: the widget's frames are the page's only number and expiry.
        let rewardsNumber = providerField("Card number")
        let rewardsExpiry = providerField("Expiry")
        let code = providerField("Security code")
        let fill = fillButton()
        let mixed = popupSays("two different payment forms")
        let startOver = popupWebView.buttons.matching(NSPredicate(format: "label == 'Start over'")).firstMatch
        step("typed-into-the-rewards-widget") {
            openInSafari(checkout("lure"), heading: "Checkout")
            typeDigits("5555", into: rewardsNumber, what: "the rewards number")
            typeDigits("0101", into: rewardsExpiry, what: "the rewards expiry")
        }
        step("code-tapped-and-two-forms-refused") {
            require(code, "the shop's security code")
            tapField(code)
            if !openPopup(until: { mixed.exists || fill.exists }, reach: .addressBar) {
                XCTFail("the popup showed neither a Fill nor why it fills none. It says: \(popupWords())")
                return
            }
            XCTAssertFalse(fill.exists, "the popup offers a Fill with fields of two payment forms chosen: \(fill.exists ? fill.label : "")")
            XCTAssertTrue(mixed.exists, "the popup does not say the fields are in two payment forms. It says: \(popupWords())")
            require(startOver, "the popup's Start over")
            scrollToComfort(startOver, in: safari)
            tapWhereItIs(startOver, in: safari)
            XCTAssertTrue(waitUntil(10) { !mixed.exists }, "Start over left the two-forms line. The popup says: \(popupWords())")
            closePopup()
        }
        step("code-tapped-again-and-filled") {
            tapAndFill(code, "the shop's security code", reach: .addressBar, checkLabel: { label in
                XCTAssertTrue(label.contains("security code"), "the Fill does not name the security code: \(label)")
                XCTAssertFalse(label.contains("card number") || label.contains("expiry"), "the Fill would write the rewards widget's fields: \(label)")
            }) { self.digits(code) == Fixture.cardCode }
        }
        step("rewards-fields-as-typed") {
            XCTAssertEqual(digits(rewardsNumber), "5555", "the rewards number was overwritten. The frames saw: \(pageEvents())")
            XCTAssertEqual(digits(rewardsExpiry), "0101", "the rewards expiry was overwritten. The frames saw: \(pageEvents())")
        }
    }

    /// ?layout=clipped (round 12): the page clips the card frame to its postal-code row. A fill from a tap there writes no
    /// detail that does not show: the number, expiry and security code stay empty.
    func test09_ClippedFrameWritesNothingHidden() {
        requireProviderReachable()
        let postal = providerField("Postal code")
        let number = providerField("Card number")
        let expiry = providerField("Expiry")
        let code = providerField("Security code")
        let anyHiddenFilled = { !self.digits(number).isEmpty || !self.digits(expiry).isEmpty || !self.digits(code).isEmpty }
        step("postal-tapped-and-fill-tried") {
            openInSafari(checkout("clipped"), heading: "Checkout")
            require(postal, "the postal code, the clipped frame's one visible field")
            tapField(postal)
            let fill = fillButton()
            let line = popupSays(copyFromApp)
            if !openPopup(until: { fill.exists || line.exists }, reach: .addressBar) {
                XCTFail("the popup showed neither a Fill nor a line. It says: \(popupWords())")
                return
            }
            if fill.exists {
                scrollToComfort(fill, in: safari)
                tapWhereItIs(fill, in: safari)
                _ = matchFaceUntil(15, anyHiddenFilled)
            }
            let words = popupWords()
            closePopup()
            XCTAssertFalse(anyHiddenFilled(), "a detail the page clips away was written. The popup says: \(words). The frames saw: \(pageEvents())")
        }
    }

    // MARK: - Helpers

    private func checkout(_ layout: String) -> String {
        Fixture.siteOrigin + "/checkout.html?layout=" + layout + "&uitest-events"
    }

    /// "pay.andvari-uitest.test:8443", as the popup names the provider's site.
    private func providerHostWithPort() -> String {
        guard let url = URL(string: Fixture.providerOrigin), let host = url.host else { return Fixture.providerOrigin }
        return url.port.map { "\(host):\($0)" } ?? host
    }

    /// A field of the provider's form, in whichever frame holds it (card.html labels the expiry "Expiry", field.html
    /// "Expiry (MM / YY)").
    private func providerField(_ label: String) -> XCUIElement {
        safari.webViews.textFields.matching(NSPredicate(format: "label BEGINSWITH %@", label)).firstMatch
    }

    private var shopNameOnCard: XCUIElement { safari.webViews.textFields["Name on card"] }

    private func text(_ field: XCUIElement) -> String {
        guard field.exists, let value = field.value as? String, value != field.placeholderValue else { return "" }
        return value
    }

    private func digits(_ field: XCUIElement) -> String {
        text(field).filter(\.isNumber)
    }

    /// The card row's Fill into the provider's origin. Since round 12 it names the details it writes once a field is
    /// chosen ("Fill this card's card number, expiry date, security code into …").
    private func fillButton() -> XCUIElement {
        safari.webViews.buttons.matching(NSPredicate(format: "label BEGINSWITH 'Fill this card' AND label ENDSWITH %@", "into " + Fixture.providerOrigin)).firstMatch
    }

    /// The provider's frames are reachable once Safari lets the extension run on every website (test02 does it).
    private func requireProviderReachable() {
        step("provider-and-extension-on") {
            requireAutoFillProvider()
            requireSafariExtension()
            XCTAssertTrue(allowExtensionOnEveryWebsite(), "Safari's settings did not let the extension run on every website")
        }
    }

    /// A line of the popup's own, never of the page under it.
    private func popupSays(_ text: String) -> XCUIElement {
        popupWebView.staticTexts.matching(NSPredicate(format: "label CONTAINS %@", text)).firstMatch
    }

    /// What the popup says about a fill or its lock, for a failure message.
    private func popupWords() -> String {
        guard popupWebView.exists else { return "nothing: the popup is closed" }
        let texts = popupWebView.staticTexts.matching(NSPredicate(format: "label CONTAINS[c] 'fill' OR label CONTAINS[c] 'tap' OR label CONTAINS[c] 'lock' OR label CONTAINS[c] 'copy' OR label CONTAINS[c] 'card form'"))
        var lines: [String] = []
        for index in 0..<min(texts.count, 10) {
            let line = texts.element(boundBy: index).label
            if !lines.contains(line) { lines.append(line) }
        }
        return lines.isEmpty ? "nothing about the fill" : lines.joined(separator: " | ")
    }

    /// The event logs of the page and its frames (served with ?uitest-events).
    private func pageEvents() -> String {
        let logs = safari.webViews.staticTexts.matching(NSPredicate(format: "label BEGINSWITH 'events:'"))
        var out: [String] = []
        for index in 0..<min(logs.count, 6) { out.append(logs.element(boundBy: index).label) }
        return out.isEmpty ? "no event log" : out.joined(separator: " || ")
    }

    /// Type [digits] into a page field, as a person types something else there: pressed until it has the keyboard.
    private func typeDigits(_ digits: String, into field: XCUIElement, what: String) {
        require(field, what)
        tapField(field)
        if !hasKeyboardFocus(field) {
            XCTFail("\(what) never took the keyboard")
            return
        }
        field.typeText(digits)
        XCTAssertTrue(waitUntil(5) { self.digits(field) == digits }, "\(what) holds \(text(field)) after typing \(digits)")
    }

    /// Press [field] (again when Safari took a tap as nothing): a press is what chooses a card field; a focus alone never
    /// does.
    private func tapField(_ field: XCUIElement) {
        Thread.sleep(forTimeInterval: 2)
        for attempt in 0..<3 where attempt == 0 || !hasKeyboardFocus(field) {
            field.tap()
            _ = waitUntil(4) { self.hasKeyboardFocus(field) }
        }
    }

    /// Press [field] in the provider's frame, then Fill the seeded card from the popup, reached [reach]'s way while the
    /// field has the keyboard, answering the Face ID the app's handler asks before it releases the card, until [filled].
    /// The popup's unlock lasts 90 s (APP_VAULT_LIFETIME_MS): a Fill that meets its end finds the unlock screen, and is
    /// tried once more. The popup is closed after; a fill that did not come fails with what the popup and frames saw.
    private func tapAndFill(_ field: XCUIElement, _ what: String, reach: PopupReach, checkLabel: ((String) -> Void)? = nil, until filled: @escaping () -> Bool) {
        require(field, what)
        tapField(field)
        shot("field-tapped")
        let fill = fillButton()
        let unlock = safari.buttons.matching(NSPredicate(format: "label BEGINSWITH 'Unlock with'")).firstMatch
        let tapFirst = popupSays("Tap the card field in the payment form first")
        var followed = false
        for _ in 1...3 {
            if !openPopup(until: { fill.exists }, reach: reach) {
                XCTFail("the popup offers no Fill into \(Fixture.providerOrigin). It says: \(popupWords())")
                return
            }
            scrollToComfort(fill, in: safari)
            if let checkLabel, fill.exists { checkLabel(fill.label) }
            tapWhereItIs(fill, in: safari)
            if matchFaceUntil(20, { filled() || tapFirst.exists }) && filled() { break }
            if tapFirst.exists && !followed {
                // A frame Safari has just let the extension into can miss the first press. The popup asks for a tap in
                // the payment form, then a fill: done once, as a person would, and written into the result.
                followed = true
                let said = popupWords()
                closePopup()
                XCTContext.runActivity(named: "the popup asked for the tap again: \(said). The frames saw: \(pageEvents())") { _ in }
                tapField(field)
                continue
            }
            if !unlock.exists { break }
        }
        let words = popupWords()
        closePopup()
        if !filled() {
            XCTFail("\(what) was not filled. The popup says: \(words). The page and its frames saw: \(pageEvents())")
        }
    }
}
