import CryptoKit
import XCTest

/// iOS itself: Settings, Safari, and the pieces of the keyboard that belong to AutoFill.
extension UITestCase {
    var settingsApp: XCUIApplication { XCUIApplication(bundleIdentifier: "com.apple.Preferences") }
    var safari: XCUIApplication { XCUIApplication(bundleIdentifier: "com.apple.mobilesafari") }

    /// "26.2" as (26, 2).
    var systemVersion: (major: Int, minor: Int) {
        let version = ProcessInfo.processInfo.operatingSystemVersion
        return (version.majorVersion, version.minorVersion)
    }

    func systemAtLeast(_ major: Int, _ minor: Int) -> Bool {
        let now = systemVersion
        return now.major > major || (now.major == major && now.minor >= minor)
    }

    /// The first element of [application] whose label is exactly [label], whatever its type.
    func labelled(_ label: String, in application: XCUIApplication) -> XCUIElement {
        application.descendants(matching: .any).matching(NSPredicate(format: "label == %@", label)).firstMatch
    }

    /// The first element of [application] whose label contains [text], whatever its type.
    func containing(_ text: String, in application: XCUIApplication) -> XCUIElement {
        application.descendants(matching: .any).matching(NSPredicate(format: "label CONTAINS[c] %@", text)).firstMatch
    }

    /// Scroll a list until the element can be tapped, then tap it. False when it never shows.
    @discardableResult
    func scrollToAndTap(_ element: XCUIElement, in application: XCUIApplication, swipes: Int = 8) -> Bool {
        for _ in 0..<swipes {
            if element.exists && element.isHittable {
                element.tap()
                return true
            }
            application.swipeUp()
            Thread.sleep(forTimeInterval: 0.4)
        }
        if element.exists && element.isHittable {
            element.tap()
            return true
        }
        return false
    }

    /// From the unlock screen to the vault with a face when Face ID is on, with the password otherwise.
    func reachVaultAnyWay() {
        switch waitForScreen() {
        case .unlock:
            // The prompt comes up by itself when Face ID is on; give the button a moment to show which it is.
            Thread.sleep(forTimeInterval: 1)
            if element("unlock.biometric").exists {
                if !matchFaceUntil(20, { self.currentScreen() == .vault }) {
                    dismissBiometricPrompt()
                    typeUnlock()
                }
            } else {
                typeUnlock()
            }
            expectScreen(.vault, timeout: 60)
            require(vaultRow(Fixture.siteItem), "the seeded login in the list", timeout: 30)
        default:
            reachVault()
        }
    }

    /// The system's Face ID sheet, when a face did not match: give up on it.
    func dismissBiometricPrompt() {
        let cancel = springboard.buttons.matching(identifier: "com.apple.localauthentication.ax.authentication.button.cancel").firstMatch
        if waitUntil(5, { cancel.exists }) {
            cancel.tap()
            Thread.sleep(forTimeInterval: 1)
        }
    }

    /// Flip a Settings-style switch row: the row's label takes a tap without changing anything, its inner control does.
    func flip(_ toggle: XCUIElement) {
        let inner = toggle.switches.firstMatch
        if inner.exists {
            inner.tap()
        } else {
            toggle.coordinate(withNormalizedOffset: CGVector(dx: 0.92, dy: 0.5)).tap()
        }
    }

    /// The app signed in, Face ID on, and unlocked once since: what both extensions need before they can fill.
    func prepareAppForFilling() {
        XCTAssertTrue(Biometrics.setEnrolled(true), "the simulator's Face ID could not be enrolled")
        launchApp()
        reachVaultAnyWay()
        openSettings()
        if !isOn(quickUnlockSwitch) {
            setQuickUnlockSwitch(true)
            matchFace(for: 8)
            XCTAssertTrue(isOn(quickUnlockSwitch), "Face ID did not turn on in the app")
        }
        element("settings.done").tap()
        require(vaultRow(Fixture.siteItem), "the vault list")
    }

    /// A new app process, unlocked: the system's suggestions are rebuilt from the vault it shows.
    func relaunchAndUnlock() {
        app.terminate()
        launchApp()
        reachVaultAnyWay()
        // The identity store is written off the main thread.
        Thread.sleep(forTimeInterval: 3)
    }

    // MARK: - Settings

    /// Settings > General > AutoFill & Passwords, the screen with one switch per provider. False when the
    /// simulator's Settings has no such screen.
    func openAutoFillSettings() -> Bool {
        let settings = settingsApp
        settings.terminate()
        settings.launch()
        _ = waitUntil(15) { settings.staticTexts["General"].exists || settings.buttons["General"].exists || settings.cells["General"].exists }
        shot("settings-root")
        dumpTree(settings, as: "settings-root")
        guard scrollToAndTap(labelled("General", in: settings), in: settings) else { return false }
        Thread.sleep(forTimeInterval: 1)
        shot("settings-general")
        dumpTree(settings, as: "settings-general")
        for title in ["AutoFill & Passwords", "Autofill & Passwords", "Passwords"] {
            let row = labelled(title, in: settings)
            if scrollToAndTap(row, in: settings, swipes: 4) {
                Thread.sleep(forTimeInterval: 1.5)
                shot("settings-autofill")
                dumpTree(settings, as: "settings-autofill")
                return true
            }
        }
        return false
    }

    /// The provider switch for andvari on the AutoFill screen.
    var autoFillProviderSwitch: XCUIElement {
        settingsApp.switches.matching(NSPredicate(format: "label CONTAINS[c] 'andvari'")).firstMatch
    }

    // MARK: - Safari

    /// Open [url] in a fresh Safari and wait for the page's heading.
    func openInSafari(_ url: String, heading: String) {
        let browser = safari
        browser.terminate()
        XCUIDevice.shared.system.open(URL(string: url)!)
        let shown = { browser.webViews.staticTexts[heading].exists }
        if waitUntil(20, shown) { return }
        // A Safari that was not running may come up on its start page and drop the address: type it, as a person would.
        let address = browser.textFields["TabBarItemTitle"]
        if address.exists {
            address.tap()
            Thread.sleep(forTimeInterval: 1)
            browser.typeText(url + "\n")
        }
        if !waitUntil(40, shown) {
            dumpTree(browser, as: "safari-no-page")
            XCTFail("Safari did not show \(url)")
        }
    }

    /// Safari's own offer for a field it recognises: a sheet naming the site, the login and the provider.
    var fillOfferButton: XCUIElement { safari.buttons["FillPasswordButton"] }

    /// Close Safari's offer sheet, leaving the keyboard and its AutoFill keys.
    func closeFillOffer() {
        let close = safari.buttons["xmark"]
        if close.exists {
            close.tap()
            Thread.sleep(forTimeInterval: 1)
        }
    }

    /// The AutoFill row above the keyboard, as text, for a reader working out what iOS offered.
    func dumpKeyboardArea(_ name: String) {
        dumpTree(safari, as: name)
    }

    // MARK: - Shared setup for the AutoFill tests

    /// andvari turned on under AutoFill From, with the app unlocked since, so its suggestions are in the system's
    /// store. Done once per run; a test that needs it and cannot have it fails with the reason, it does not pass.
    func requireAutoFillProvider() {
        if SystemState.providerEnabled { return }
        prepareAppForFilling()
        XCTAssertTrue(openAutoFillSettings(), "Settings has no AutoFill & Passwords screen")
        let toggle = autoFillProviderSwitch
        require(toggle, "the andvari switch under AutoFill From")
        if !isOn(toggle) {
            flip(toggle)
            Thread.sleep(forTimeInterval: 2)
            answerSystemAlerts()
        }
        XCTAssertTrue(waitUntil(5) { self.isOn(self.autoFillProviderSwitch) }, "andvari could not be turned on as an AutoFill provider")
        settingsApp.terminate()
        relaunchAndUnlock()
        SystemState.providerEnabled = true
    }

    /// Everything on screen that is not the page: Safari's own tree and SpringBoard's, where system sheets live.
    func dumpEverything(_ name: String) {
        dumpTree(safari, as: name + "-safari")
        dumpTree(springboard, as: name + "-springboard")
    }

    /// An element anywhere in Safari or SpringBoard whose label contains [text] and that is not part of the page.
    func offered(_ text: String) -> XCUIElement? {
        for application in [safari, springboard] {
            let matches = application.descendants(matching: .any).matching(NSPredicate(format: "label CONTAINS[c] %@", text))
            for index in 0..<min(matches.count, 8) {
                let candidate = matches.element(boundBy: index)
                // The page's own fields carry the word too ("Username"); what iOS offers sits in the lower half.
                if candidate.exists && candidate.isHittable && candidate.frame.minY > application.frame.height * 0.45 {
                    return candidate
                }
            }
        }
        return nil
    }

    /// Whether iOS has reacted to a focused field: Safari's offer, or a keyboard.
    var fieldHasInput: Bool { fillOfferButton.exists || safari.keyboards.firstMatch.exists }

    /// Tap a page's field until iOS reacts. A Safari that has just started sometimes takes the first tap as focus
    /// only, with neither a keyboard nor an offer.
    func focus(_ field: XCUIElement, heading: String) {
        field.tap()
        if waitUntil(4, { self.fieldHasInput }) { return }
        safari.webViews.staticTexts[heading].firstMatch.tap()
        Thread.sleep(forTimeInterval: 1)
        field.tap()
        _ = waitUntil(5) { self.fieldHasInput }
    }

    /// The codes RFC 6238 gives for the seeded secret around now (one step either side).
    func expectedOneTimeCodes() -> [String] {
        let key = SymmetricKey(data: Data("12345678901234567890".utf8))
        let step = UInt64(Date().timeIntervalSince1970) / 30
        return [step - 1, step, step + 1].map { counter in
            var bigEndian = counter.bigEndian
            let mac = Array(HMAC<Insecure.SHA1>.authenticationCode(for: Data(bytes: &bigEndian, count: 8), using: key))
            let offset = Int(mac[19] & 0x0f)
            let binary = (UInt32(mac[offset] & 0x7f) << 24) | (UInt32(mac[offset + 1]) << 16) | (UInt32(mac[offset + 2]) << 8) | UInt32(mac[offset + 3])
            return String(format: "%06d", binary % 1_000_000)
        }
    }

    func webField(_ label: String) -> XCUIElement {
        let text = safari.webViews.textFields[label]
        return text.exists ? text : safari.webViews.secureTextFields[label]
    }
}

/// What earlier tests of this run already set up.
enum SystemState {
    static var providerEnabled = false
    static var extensionEnabled = false
}
