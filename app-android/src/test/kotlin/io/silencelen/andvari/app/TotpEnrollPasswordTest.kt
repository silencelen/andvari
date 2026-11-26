package io.silencelen.andvari.app

import java.io.File
import kotlin.test.Test
import kotlin.test.assertFalse
import kotlin.test.assertTrue

/**
 * Security review 2026-10 (server F4, client half): the server refuses a FIRST TOTP enrollment
 * from a session whose password login is older than its fresh-login window unless the setup body
 * carries `currentAuthKey`. The phone enrolls from Settings, typically long after sign-in, so the
 * Enable step must ask for the master password and enroll through core's
 * `AndvariApi.totpSetupWithPassword` (end-to-end in the server suite's TotpEnrollClientTest).
 *
 * Source pins in the RegressionPins0262Test idiom — the wiring lives in a composable and a
 * ViewModel closure this pure-JVM suite cannot render. Comments are stripped so prose can't
 * satisfy a pin.
 */
class TotpEnrollPasswordTest {
    private fun code(name: String): String = File("src/main/kotlin/io/silencelen/andvari/app/$name").readText()
        .replace(Regex("/\\*.*?\\*/", RegexOption.DOT_MATCHES_ALL), "")
        .lines().joinToString("\n") { it.substringBefore("//") }

    private val vmCode = code("AndvariViewModel.kt")

    @Test
    fun theViewModelEnrollsWithThePasswordProof() {
        assertTrue(vmCode.contains("fun totpBegin(password: String)"), "totpBegin must take the master password")
        assertTrue(vmCode.contains("totpSetupWithPassword(password, requireNotNull(account)"), "enrollment must send the password proof")
        assertFalse(vmCode.contains("api!!.totpSetup()"), "the bare setup call is refused by the server outside the fresh-login window")
    }

    /**
     * The code-only "turn off" call refuses without sending anything since two-step sign-in's off step needs the
     * master password too. Nothing on the phone called the old view model's wrapper of it; it is gone, and the new
     * path turns two-step off through `turnOffTwoStepWithPassword` (SettingsAndQuickUnlockTest).
     */
    @Test
    fun theOldViewModelNoLongerOffersTheCodeOnlyTurnOff() {
        assertFalse(vmCode.contains("fun totpDisable("), "the old code-only turn-off wrapper must be gone")
        assertFalse(Regex("""\.totpDisable\(\s*code\s*\)""").containsMatchIn(vmCode), "nothing may call the code-only turn-off")
    }

    // theEnableStepAsksForTheMasterPassword pinned the old Settings screen, deleted in the overhaul. The new path's two-step
    // setup asks for the password first (trust/SettingsScreens.kt, SettingsAndQuickUnlockTest).
}
