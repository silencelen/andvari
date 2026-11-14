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

    /// checkout.html while Safari still keeps the extension out of the provider's frame (Other Websites: Ask): the popup
    /// names the provider's site to allow and copies instead. Once every website is allowed in Safari's settings, it
    /// offers a Fill into the provider's origin.
    func test02_ProviderFrameNamesTheSiteToAllow() {
        step("provider-and-extension-on") {
            requireAutoFillProvider()
            requireSafariExtension()
        }
        let providerHost = providerHostWithPort()
        let allowLine = popupSays("where Safari doesn't let andvari run yet")
        let fill = fillButton()
        step("provider-site-to-allow") {
            openInSafari(checkout("card"), heading: "Checkout")
            if !openPopup(until: { allowLine.exists || fill.exists }) {
                XCTFail("the popup on the checkout showed neither a Fill nor the site to allow. It says: \(popupWords())")
                return
            }
            if allowLine.exists {
                XCTAssertTrue(allowLine.label.contains(providerHost), "the line does not name \(providerHost): \(allowLine.label)")
                XCTAssertTrue(allowLine.label.contains(copyFromApp), "the line does not say to copy from the app: \(allowLine.label)")
                XCTAssertFalse(fill.exists, "a Fill is offered beside the line")
            } else {
                // Safari already lets the extension into the provider's frame: nothing to ask, so nothing to check here.
                XCTContext.runActivity(named: "Safari already allowed \(providerHost)") { _ in }
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

    /// ?layout=split: one provider frame per field. A tap on the number, then Fill: each sibling frame receives its own
    /// field, the number, the expiry and the security code.
    func test04_SplitProviderFramesFillEachItsOwn() {
        requireProviderReachable()
        let number = providerField("Card number")
        let expiry = providerField("Expiry")
        let code = providerField("Security code")
        step("number-tapped-and-filled") {
            openInSafari(checkout("split"), heading: "Checkout")
            tapAndFill(number, "the card number frame", reach: .addressBar) { self.digits(number) == Fixture.cardNumber }
        }
        step("each-sibling-its-own-field") {
            XCTAssertTrue(waitUntil(10) { Fixture.cardExpiryDigits.contains(self.digits(expiry)) }, "the expiry frame holds \(text(expiry)). The frames saw: \(pageEvents())")
            XCTAssertTrue(waitUntil(10) { self.digits(code) == Fixture.cardCode }, "the security code frame holds \(text(code)). The frames saw: \(pageEvents())")
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

    /// ?layout=twice: a second card-number frame beside the first. Two candidates for one field kind: a fill guesses
    /// between them never, so nothing is filled anywhere.
    func test07_SecondFrameOfAKindIsRefused() throws {
        if Fixture.siblingRule == "frame-tree" {
            try skip("Waits for the sibling rule coming on ios-ui (2026-11-14): split-field frames matched by location.ancestorOrigins with exactly one frame per field kind, two candidates for a kind refused. The extension built here still finds siblings by the frame tree (webNavigation in its manifest), where each frame of a kind receives it.")
        }
        requireProviderReachable()
        let numbers = safari.webViews.textFields.matching(NSPredicate(format: "label == 'Card number'"))
        let expiry = providerField("Expiry")
        let code = providerField("Security code")
        let anyFilled = { !self.digits(numbers.element(boundBy: 0)).isEmpty || !self.digits(numbers.element(boundBy: 1)).isEmpty || !self.digits(expiry).isEmpty || !self.digits(code).isEmpty }
        step("first-number-tapped-and-fill-tried") {
            openInSafari(checkout("twice"), heading: "Checkout")
            XCTAssertTrue(waitUntil(15) { numbers.count == 2 }, "the page shows \(numbers.count) card-number frames, not two")
            let first = numbers.element(boundBy: 0)
            tapField(first)
            let fill = fillButton()
            XCTAssertTrue(openPopup(until: { fill.exists }, reach: .addressBar), "the popup offers no Fill into \(Fixture.providerOrigin). It says: \(popupWords())")
            scrollToComfort(fill, in: safari)
            tapWhereItIs(fill, in: safari)
            _ = matchFaceUntil(15, anyFilled)
            let words = popupWords()
            closePopup()
            XCTAssertFalse(anyFilled(), "a field was filled with two card-number frames on the page. The popup says: \(words). The frames saw: \(pageEvents())")
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

    private func fillButton() -> XCUIElement {
        safari.webViews.buttons["Fill this card into \(Fixture.providerOrigin)"]
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
    private func tapAndFill(_ field: XCUIElement, _ what: String, reach: PopupReach, until filled: @escaping () -> Bool) {
        require(field, what)
        tapField(field)
        shot("field-tapped")
        let fill = fillButton()
        let unlock = safari.buttons.matching(NSPredicate(format: "label BEGINSWITH 'Unlock with'")).firstMatch
        for attempt in 1...2 {
            if !openPopup(until: { fill.exists }, reach: reach) {
                XCTFail("the popup offers no Fill into \(Fixture.providerOrigin). It says: \(popupWords())")
                return
            }
            scrollToComfort(fill, in: safari)
            tapWhereItIs(fill, in: safari)
            if matchFaceUntil(20, filled) { break }
            if attempt == 2 || !unlock.exists { break }
        }
        let words = popupWords()
        closePopup()
        if !filled() {
            XCTFail("\(what) was not filled. The popup says: \(words). The page and its frames saw: \(pageEvents())")
        }
    }
}
