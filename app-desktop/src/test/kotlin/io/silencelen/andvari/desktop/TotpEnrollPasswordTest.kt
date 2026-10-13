package io.silencelen.andvari.desktop

import java.io.File
import kotlin.test.Test
import kotlin.test.assertFalse
import kotlin.test.assertTrue

/**
 * Security review 2026-10 (server F4, client half): the server refuses a FIRST TOTP enrollment
 * from a session whose password login is older than its fresh-login window unless the setup body
 * carries `currentAuthKey`. The desktop enrolls from Settings, typically long after sign-in, so
 * the Enable step must ask for the master password and enroll through core's
 * `AndvariApi.totpSetupWithPassword` (end-to-end in the server suite's TotpEnrollClientTest).
 * Source pins in the SurfacePinsTest idiom; comments stripped so prose can't satisfy a pin.
 */
class TotpEnrollPasswordTest {
    private fun code(relative: String): String =
        (listOf(File(relative), File("app-desktop/$relative")).firstOrNull { it.isFile } ?: error("could not locate $relative"))
            .readText()
            .replace(Regex("/\\*.*?\\*/", RegexOption.DOT_MATCHES_ALL), "")
            .lines().joinToString("\n") { it.substringBefore("//") }

    private val state = code("src/main/kotlin/io/silencelen/andvari/desktop/DesktopState.kt")
    private val ui = code("src/main/kotlin/io/silencelen/andvari/desktop/Ui.kt")

    @Test
    fun theStateEnrollsWithThePasswordProof() {
        assertTrue(state.contains("fun beginTotpSetup(password: String)"), "beginTotpSetup must take the master password")
        // A9 (M-1): the proof is the account's fenced in-session derivation (KDF fence + the session's salt).
        assertTrue(state.contains("totpSetupWithPassword(password, requireNotNull(account)"), "enrollment must send the password proof through the fenced derivation")
        assertFalse(state.contains("api!!.totpSetup()"), "the bare setup call is refused by the server outside the fresh-login window")
    }

    @Test
    fun theEnableStepAsksForTheMasterPassword() {
        val enable = ui.indexOf("{ Text(\"Enable\") }")
        assertTrue(enable > -1, "the Enable button moved — update the pin")
        val before = ui.substring(maxOf(0, enable - 1200), enable)
        assertTrue(before.contains("Secret(\"Master password\""), "Enable must sit under a master-password field")
        assertTrue(before.contains("state.beginTotpSetup(totpPassword)"), "Enable must hand the typed password to the state")
    }
}
