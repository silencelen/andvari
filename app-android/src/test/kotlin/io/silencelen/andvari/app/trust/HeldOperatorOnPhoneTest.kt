package io.silencelen.andvari.app.trust

import io.silencelen.andvari.core.app.AppPhase
import io.silencelen.andvari.core.app.AppPlatform
import io.silencelen.andvari.core.app.CopyKey
import io.silencelen.andvari.core.app.EntryScreen
import io.silencelen.andvari.core.app.FirstRunNotice
import io.silencelen.andvari.core.app.fake.FakeScene
import io.silencelen.andvari.core.app.fake.FakeScenes
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import java.io.File
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertIs
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue

/**
 * An account a hand-over made its server's operator, on a phone (decided on 2026-11-16, design §9.1): the phone stops
 * using it at once, keeps its copy locked, and the person removes it. The first screen says so for as long as it
 * stands, and only the confirmation of "remove it from this phone" removes the copy.
 */
class HeldOperatorOnPhoneTest {
    private fun src(name: String) = File("src/main/kotlin/io/silencelen/andvari/app/trust/$name").readText()

    @Test
    fun theFirstScreenSaysTheAccountIsHeldUntilThePersonRemovesIt() {
        val api = FakeScenes.onPlatform(AppPlatform.ANDROID, FakeScene.VAULTS)
        val m = TrustModel(api, CoroutineScope(Dispatchers.Unconfined), BuildConstants.JOIN_BASE, { 0L })
        m.onSnapshot(api.snapshot)
        assertEquals(AppPhase.UNLOCKED, api.snapshot.phase)

        api.script.handoverMadeThisAccountTheOperator()
        m.onSnapshot(api.snapshot)
        // Stopped at once: no open account, the first screen with the notice and the held account.
        assertNull(api.snapshot.account)
        var first = assertIs<EntryScreen.FirstRun>(api.snapshot.entry)
        assertEquals(FirstRunNotice.OPERATOR_NEEDS_COMPUTER, first.notice)
        val held = assertNotNull(first.heldAsOperator)
        assertEquals(FakeScenes.EMAIL, held.email)
        assertEquals(CopyKey.OPERATOR_HELD_ON_PHONE, held.line.key)
        assertEquals(CopyKey.OPERATOR_HELD_REMOVE_UNKNOWN, held.removeLine.key, "stopped while it could not count what was not sent")

        // Dismissing the notice leaves the held account on the screen: it stands until the person removes it.
        m.act { entry.dismissNotice(first) }
        first = assertIs<EntryScreen.FirstRun>(api.snapshot.entry)
        assertNull(first.notice)
        val still = assertNotNull(first.heldAsOperator)

        // The confirmation's call removes this phone's copy; the first screen is then as for no account.
        removeHeldOperator(m, still)
        first = assertIs<EntryScreen.FirstRun>(api.snapshot.entry)
        assertNull(first.heldAsOperator)
    }

    @Test
    fun theCardIsOnTheFirstScreenAndOnlyItsConfirmationRemovesTheAccount() {
        val entry = src("EntryScreens.kt")
        val firstRun = entry.substringAfter("internal fun FirstRunScreen(").substringBefore("\n}\n")
        assertTrue("screen.heldAsOperator?.let { held ->\n            HeldOperatorCard(model, s, held)" in firstRun)
        val card = entry.substringAfter("internal fun HeldOperatorCard(").substringBefore("\n}\n")
        assertTrue("Say(held.line)" in card, "the shared code's line, as information")
        assertTrue("text = { Say(held.removeLine) }" in card, "what is lost is said before the removal")
        assertTrue("onClick = { asking = true }" in card, "the button only asks")
        assertEquals(1, Regex("removeHeldOperator\\(").findAll(card).count(), "the confirmation is the one place it is removed")
        assertTrue("dismissNotice" !in card, "the line has no dismiss")
        assertEquals(1, Regex("removeHeldOperatorAccount\\(").findAll(File("src/main/kotlin").walkTopDown().filter { it.isFile && it.extension == "kt" }.joinToString("") { it.readText() }).count())
    }
}
