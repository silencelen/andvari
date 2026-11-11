import XCTest

/// Face ID. The simulator's biometric is a switch (Biometrics.swift) and it has no Secure Enclave, so these prove
/// the app's flow around quick unlock, not the hardware protection of the key (app-ios/uitest/README.md).
final class T2QuickUnlockTests: UITestCase {
    override func setUp() {
        super.setUp()
        XCTAssertTrue(Biometrics.setEnrolled(true), "the simulator's Face ID could not be enrolled")
    }

    /// Turn Face ID on in Settings. The prompt needs a matching face.
    func test01_EnableQuickUnlock() {
        launchApp()
        step("vault") {
            reachVault()
        }
        step("settings") {
            openSettings()
            require(quickUnlockSwitch, "the Face ID switch")
            XCTAssertTrue(quickUnlockSwitch.isEnabled, "the Face ID switch is disabled: \(quickUnlockMessage())")
        }
        step("face-id-on") {
            setQuickUnlockSwitch(true)
            // The switch flips at once and falls back if enrolling fails, so its position is read after the prompt.
            matchFace(for: 8)
            XCTAssertTrue(isOn(quickUnlockSwitch), "Face ID did not turn on: \(quickUnlockMessage())")
        }
        step("locked-offers-face-id") {
            element("settings.lock").tap()
            expectScreen(.unlock)
            require(element("unlock.biometric"), "the Unlock with Face ID button")
        }
        step("vault-by-face") {
            XCTAssertTrue(matchFaceUntil(25) { self.currentScreen() == .vault }, "a matching face did not open the vault")
        }
    }

    /// Lock, and the unlock screen offers Face ID by itself; a matching face opens the vault with no password.
    func test02_UnlockWithFaceID() {
        launchApp()
        step("unlock-screen-offers-face-id") {
            expectScreen(.unlock)
            require(element("unlock.biometric"), "the Unlock with Face ID button")
        }
        step("vault-by-face") {
            XCTAssertTrue(matchFaceUntil(25) { self.currentScreen() == .vault }, "a matching face did not open the vault")
            require(vaultRow(Fixture.siteItem), "the seeded login in the list")
        }
    }

    /// A face that does not match never opens the vault, and the master password still does.
    func test03_NonMatchingFaceStaysLocked() {
        launchApp()
        step("unlock-screen") {
            expectScreen(.unlock)
            require(element("unlock.biometric"), "the Unlock with Face ID button")
        }
        step("no-match-stays-locked") {
            Thread.sleep(forTimeInterval: 2)
            Biometrics.noMatch()
            Thread.sleep(forTimeInterval: 3)
            XCTAssertNotEqual(currentScreen(), .vault, "a non-matching face opened the vault")
            shot("face-not-recognized")
            dismissBiometricPrompt()
        }
        step("password-still-works") {
            expectScreen(.unlock)
            typeUnlock()
            expectScreen(.vault, timeout: 60)
        }
    }

    /// Background and return: Face ID is offered again and opens the vault.
    func test04_BackgroundThenFaceID() {
        launchApp()
        step("vault-by-face") {
            expectScreen(.unlock)
            XCTAssertTrue(matchFaceUntil(25) { self.currentScreen() == .vault }, "a matching face did not open the vault")
        }
        step("home-screen") {
            XCUIDevice.shared.press(.home)
            Thread.sleep(forTimeInterval: 2)
        }
        step("vault-by-face-on-return") {
            app.activate()
            XCTAssertTrue(matchFaceUntil(25) { self.currentScreen() == .vault }, "a matching face did not open the vault after a return")
        }
    }

    /// Turning the switch off removes the offer.
    func test05_DisableQuickUnlock() {
        launchApp()
        step("vault") {
            expectScreen(.unlock)
            XCTAssertTrue(matchFaceUntil(25) { self.currentScreen() == .vault }, "a matching face did not open the vault")
        }
        step("face-id-off") {
            openSettings()
            setQuickUnlockSwitch(false)
            XCTAssertTrue(waitUntil(5) { !self.isOn(self.quickUnlockSwitch) }, "the switch stayed on")
        }
        step("no-offer-when-locked") {
            element("settings.lock").tap()
            expectScreen(.unlock)
            XCTAssertFalse(element("unlock.biometric").exists, "Face ID is still offered after it was turned off")
        }
    }

    private func quickUnlockMessage() -> String {
        let message = element("settings.quick-unlock-message")
        return message.exists ? message.label : "no message shown"
    }
}
