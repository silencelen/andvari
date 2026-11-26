package io.silencelen.andvari.app

import java.io.File
import kotlin.test.Test
import kotlin.test.assertFalse
import kotlin.test.assertTrue

/**
 * Audit 2026-09-13 H129 — the pre-unlock family is width-capped (owner decision: 480dp, centred).
 *
 * Android's auth and recovery screens were full-bleed `fillMaxSize().padding(24.dp)` columns of
 * `fillMaxWidth` fields with no cap anywhere, while web pins its auth card at 440px and desktop
 * bounds its tree at 760dp. The manifest handles the fold posture in-process, so the SAME
 * composable renders on the cover screen and the ~7.6" inner display: unfolded, the sign-in and
 * master-password fields became one ~800dp line, and the recovery-phrase type-back — a
 * transcription task — became a single very long line to track across.
 *
 * A source pin, in the house `SurfaceCopyPinsTest` idiom: this module has no Compose test runtime,
 * and what must not regress is that every screen in the family goes through the ONE shell. A new
 * pre-unlock screen written as a bare full-bleed column is exactly the drift this catches.
 */
class AuthWidthCapTest {

    private val main = File("src/main/kotlin/io/silencelen/andvari/app/MainActivity.kt").readText()

    private val code = main
        .replace(Regex("/\\*.*?\\*/", RegexOption.DOT_MATCHES_ALL), "")
        .lines().joinToString("\n") { it.substringBefore("//") }

    /** The body of a top-level composable, from its signature to the next declaration. */
    private fun body(fn: String): String {
        val at = code.indexOf("fun $fn(")
        assertTrue(at > 0, "could not find $fn in MainActivity.kt")
        val rest = code.substring(at)
        val end = rest.indexOf("\n@Composable")
        return if (end > 0) rest.substring(0, end) else rest
    }

    /** The cap itself: one shell, one number, centred, and still scrollable (Cut F). */
    @Test
    fun theAuthShellCapsTheWidthAndKeepsTheColumnScrollable() {
        assertTrue(code.contains("private val AUTH_MAX_WIDTH = 480.dp"), "the owner's 480dp cap")
        val shell = body("AuthColumn")
        assertTrue(shell.contains("Box(Modifier.fillMaxSize(), contentAlignment = Alignment.TopCenter)"), "centred, not left-hugged, on a wide display")
        assertTrue(shell.contains("widthIn(max = AUTH_MAX_WIDTH)"), "the cap must be applied, not merely declared")
        assertTrue(shell.contains("verticalScroll(rememberScrollState())"), "Cut F: the IME must never strand the button off-screen")
    }

    // everyPreUnlockScreenUsesTheSharedShell went with the old pre-unlock family (WelcomeScreen, PendingReconcileScreen,
    // RecoverySetupScreen, RecoveryCaptureScreen, UnlockScreen, RecoverScreen). The new path's
    // screens are pinned to the same shell by trust/TrustAuthWidthTest.
}
