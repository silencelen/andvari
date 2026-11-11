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
        for candidate in [springboard, XCUIApplication(bundleIdentifier: "com.apple.CoreAuthUI")] {
            for title in ["Cancel", "Use master password"] where candidate.buttons[title].exists {
                candidate.buttons[title].tap()
                return
            }
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

    /// Open [url] in Safari and wait for the page's heading.
    func openInSafari(_ url: String, heading: String) {
        let browser = safari
        XCUIDevice.shared.system.open(URL(string: url)!)
        if !waitUntil(30, {
            // Safari's first run may put a sheet of its own over the page.
            for title in ["Continue", "Not Now", "Close"] where browser.buttons[title].exists && !browser.webViews.staticTexts[heading].exists {
                browser.buttons[title].tap()
            }
            return browser.webViews.staticTexts[heading].exists
        }) {
            dumpTree(browser, as: "safari-no-page")
            XCTFail("Safari did not show \(url)")
        }
    }

    /// The AutoFill row above the keyboard, as text, for a reader working out what iOS offered.
    func dumpKeyboardArea(_ name: String) {
        dumpTree(safari, as: name)
    }
}
