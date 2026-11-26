package io.silencelen.andvari.desktop.trust

import androidx.compose.material3.MaterialTheme
import androidx.compose.runtime.CompositionLocalProvider
import androidx.compose.ui.ImageComposeScene
import androidx.compose.ui.input.key.Key
import androidx.compose.ui.input.key.KeyEvent
import androidx.compose.ui.input.key.KeyEventType
import androidx.compose.ui.unit.Density
import io.silencelen.andvari.core.app.ActionResult
import io.silencelen.andvari.core.app.AppPhase
import io.silencelen.andvari.core.app.CopyKey
import io.silencelen.andvari.core.app.LoginInput
import io.silencelen.andvari.core.app.PolicyWipeNotice
import io.silencelen.andvari.core.app.VaultActionResult
import io.silencelen.andvari.core.app.content.VaultSyncState
import io.silencelen.andvari.core.app.fake.FakeDesktopAppApi
import io.silencelen.andvari.core.app.fake.FakeScene
import io.silencelen.andvari.core.app.fake.FakeScenes
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.runBlocking
import java.io.File
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertIs
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertSame
import kotlin.test.assertTrue

/**
 * Under a server's policy that forbids a copy of the vault on devices, over the fake, by key: the notice after the shared
 * code removed this computer's copy (its lines exactly as handed, kept until dismissed, only the notice on show); the
 * line while the copy is being removed, with Save and "New" still offered; and the question before quitting while changes
 * wait in memory only.
 */
class PolicyWipeDrawnTest {
    private fun model(api: FakeDesktopAppApi): TrustModel =
        TrustModel(api, CoroutineScope(Dispatchers.Unconfined), { 0L }).also { it.onSnapshot(api.snapshot) }

    private fun unlocked(api: FakeDesktopAppApi, m: TrustModel) {
        m.run({ unlock(assertNotNull(snapshot.locked), FakeScenes.PASSWORD) })
        m.onSnapshot(api.snapshot)
        assertEquals(AppPhase.UNLOCKED, api.snapshot.phase)
    }

    /** The whole window's column ([TrustApp]), with the focus walk and the notice's drawings recorded. */
    @OptIn(androidx.compose.ui.InternalComposeUiApi::class)
    private class Window(m: TrustModel) {
        val focus = ArrayList<String>()
        val drawn = ArrayList<Triple<PolicyWipeNotice, List<String>, AppPhase>>()
        private var t = 0L
        private val scene = ImageComposeScene(600, 2400, Density(1f)) {
            CompositionLocalProvider(
                LocalFocusLog provides focus,
                LocalPolicyWipeDrawn provides { n, lines, phase -> drawn += Triple(n, lines.map { it.shown() }, phase) },
            ) { MaterialTheme { TrustApp(m, null, "log") } }
        }

        fun render() {
            repeat(2) {
                t += 50_000_000L
                scene.render(t)
            }
        }

        init {
            render()
        }

        private fun press(key: Key) {
            scene.sendKeyEvent(KeyEvent(key, KeyEventType.KeyDown))
            scene.sendKeyEvent(KeyEvent(key, KeyEventType.KeyUp))
            render()
        }

        fun tabUntil(words: String, most: Int = 60) {
            repeat(most) {
                if (focus.lastOrNull() == words) return
                press(Key.Tab)
            }
            assertEquals(words, focus.lastOrNull(), focus.toString())
        }

        fun enter() = press(Key.Enter)

        fun close() = scene.close()
    }

    private fun shown(notice: PolicyWipeNotice): List<String> = notice.lines.map { UiText.of(it).shown() }

    // ---- the notice ----

    @Test
    fun theNoticeSaysTheSharedCodesLinesInOrderInEveryPhaseAndGoesOnlyByItsDismiss() {
        val api = FakeScenes.desktopAt(FakeScene.LOCKED)
        val m = model(api)
        api.script.policyCopyRemoved(notSent = 2, unsure = 1, unfinishedMoves = 1)
        val notice = assertNotNull(api.snapshot.policyWipe)
        assertEquals(
            listOf(CopyKey.POLICY_COPY_REMOVED_LOST, CopyKey.POLICY_COPY_REMOVED_UNSURE_ONE, CopyKey.POLICY_COPY_REMOVED_MOVE_UNFINISHED_ONE),
            notice.lines.map { it.key },
        )
        assertEquals(shown(notice), policyWipeLines(notice).map { it.shown() }, "the lines exactly as handed, in order, and nothing else")
        val w = Window(m)
        try {
            assertEquals(Triple(notice, shown(notice), AppPhase.LOCKED), w.drawn.last(), "drawn above the lock screen")
            // An unlock and a lock do not take it.
            unlocked(api, m)
            w.render()
            assertSame(notice, api.snapshot.policyWipe)
            assertEquals(AppPhase.UNLOCKED, w.drawn.last().third, "drawn above the open vault")
            assertSame(notice, w.drawn.last().first)
            m.lockNow()
            m.onSnapshot(api.snapshot)
            w.render()
            assertSame(notice, api.snapshot.policyWipe)
            assertEquals(AppPhase.LOCKED, w.drawn.last().third)
            // Only its dismiss, from the keyboard as from a click.
            w.drawn.clear()
            w.tabUntil(UiText.ph(Placeholder.DISMISS).shown())
            w.enter()
            assertNull(api.snapshot.policyWipe)
            w.render()
            assertTrue(w.drawn.isEmpty(), "not drawn again")
        } finally {
            w.close()
        }
    }

    @Test
    fun aKnownNumberIsNeverHiddenAndEachCombinationIsDrawnAsHanded() {
        val api = FakeScenes.desktopAt(FakeScene.LOCKED)
        model(api)
        val cases = listOf(
            Triple(3, 0, true) to listOf(CopyKey.POLICY_COPY_REMOVED_AT_LEAST_LOST),
            Triple(3, 2, true) to listOf(CopyKey.POLICY_COPY_REMOVED_AT_LEAST_LOST, CopyKey.POLICY_COPY_REMOVED_UNSURE),
            Triple(0, 0, true) to listOf(CopyKey.POLICY_COPY_REMOVED_CANNOT_TELL),
            Triple(1, 0, false) to listOf(CopyKey.POLICY_COPY_REMOVED_ONE_LOST),
            Triple(0, 4, false) to listOf(CopyKey.POLICY_COPY_REMOVED_NONE_KNOWN_LOST, CopyKey.POLICY_COPY_REMOVED_UNSURE),
            Triple(0, 0, false) to listOf(CopyKey.POLICY_COPY_REMOVED_NOTHING_LOST),
        )
        for ((n, keys) in cases) {
            api.script.policyCopyRemoved(notSent = n.first, unsure = n.second, cannotTell = n.third)
            val notice = assertNotNull(api.snapshot.policyWipe)
            assertEquals(keys, notice.lines.map { it.key }, n.toString())
            assertEquals(notice.lines.map { UiText.of(it).shown() }, policyWipeLines(notice).map { it.shown() }, n.toString())
        }
    }

    @Test
    fun insideAnAccountAnotherAccountsNoticeIsNeitherDrawnNorDismissedAndTheDesktopKeepsNone() {
        val api = FakeScenes.desktopAt(FakeScene.LOCKED)
        val m = model(api)
        unlocked(api, m)
        api.script.policyCopyRemoved(notSent = 1, userId = "someone-else")
        assertNull(api.snapshot.policyWipe, "the shared code hands none inside another account")
        val w = Window(m)
        try {
            assertTrue(w.drawn.isEmpty())
        } finally {
            w.close()
        }
        // The bar reads the snapshot only: no notice of its own, no cache across accounts.
        val bar = File("src/main/kotlin/io/silencelen/andvari/desktop/trust/TrustApp.kt").readText().substringAfter("private fun PolicyWipeBar(").substringBefore("\n}\n")
        assertTrue(bar.contains("val notice = s.policyWipe ?: return"))
        assertTrue(bar.contains("model.api.dismissPolicyWipe(notice)"))
    }

    // ---- while the copy is being removed ----

    @Test
    fun whileTheCopyIsBeingRemovedTheRemovalsLineStandsWhereStoppedWouldAndSaveStaysOffered() {
        val api = FakeScenes.desktopAt(FakeScene.LOCKED)
        val m = model(api)
        unlocked(api, m)
        val fake = assertNotNull(api.fakeContent)
        val c = assertNotNull(m.content.value)
        fake.removingForPolicy(true)
        val line = assertNotNull(c.state.removingLine)
        assertFalse(c.state.serverStopped)
        assertTrue(c.state.sync != VaultSyncState.STOPPED)
        assertEquals(line, assertIs<UiText.Plain>(syncLine(c.state)).text, "the shared code's line, never \"stopped\"")
        assertTrue(canSaveState(c.state), "Save and the edit controls stay offered")
        // A save meanwhile is refused with the shared code's own sentence for that refusal (since the policy keys work,
        // apart from the state's line), which the editor says in place as handed.
        val r = assertIs<ActionResult.Failed>(runBlocking { c.saveLogin(null, LoginInput("Bank", "me", "pw", emptyList(), "", "", false), null) })
        assertEquals(r.message, sentence(r))
        assertTrue(r.message != UiText.ph(Placeholder.SYNC_STOPPED).shown())
        // A shared vault's change refused meanwhile says the removal's line, not a general failure.
        assertEquals(UiText.of(CopyKey.SAVE_COPY_BEING_REMOVED).shown(), UiText.forResult(VaultActionResult.REMOVING_COPY, 0)?.shown())
        fake.removingForPolicy(false)
        assertNull(c.state.removingLine)
        assertFalse(syncLine(c.state).let { it is UiText.Plain && it.text == line })
    }

    @Test
    fun aNewItemsEditorSaysTheRemovalsLineWhereNoVaultIsOfferedAndKeepsWhatWasTypedAcrossANewContent() {
        val src = File("src/main/kotlin/io/silencelen/andvari/desktop/trust/VaultItemsScreens.kt").readText()
        val editor = src.substringAfter("private fun ItemEditor(").substringBefore("\n}\n")
        assertTrue(editor.contains("if (e.itemId == null && choices.isEmpty()) state.removingLine?.let { Say(UiText.Plain(it)) }"))
        val section = src.substringAfter("internal fun VaultItemsSection(").substringBefore("\n}\n")
        // Held above the content, keyed by the unlock: a content composed again keeps the editor and its draft.
        assertTrue(section.indexOf("var editing by remember(unlocks)") in 0 until section.indexOf("val c = content ?: return"))
        assertFalse(src.contains("remember(c, key) { mutableStateOf(d?.name"), "nothing typed is keyed by the content")
    }

    // ---- quitting while changes wait in memory only ----

    @Test
    fun quittingAsksFirstWithTheNumberOrWithoutOneAndNeverWhenNothingWaits() {
        val api = FakeScenes.desktopAt(FakeScene.LOCKED)
        val m = model(api)
        var quits = 0
        m.quit = { quits++ }
        api.script.waitingInMemory = 3
        m.askBeforeQuit()
        assertEquals(0, quits, "not ended unasked")
        val ask = assertNotNull(m.quitAsked.value)
        assertEquals(3, ask.waiting)
        assertEquals(listOf("3"), assertIs<UiText.Ph>(quitQuestionLine(ask)).args)
        assertEquals(Placeholder.QUIT_WAITING, assertIs<UiText.Ph>(quitQuestionLine(ask)).placeholder)
        m.stayAfterQuestion()
        assertNull(m.quitAsked.value)
        assertEquals(0, quits)
        // Cannot be told (locked, with kept records sealed): asked without a number.
        api.script.waitingInMemory = null
        m.askBeforeQuit()
        assertEquals(Placeholder.QUIT_WAITING_UNKNOWN, assertIs<UiText.Ph>(quitQuestionLine(assertNotNull(m.quitAsked.value))).placeholder)
        // From the window: "Quit anyway" by the keyboard ends the app.
        val w = Window(m)
        try {
            w.tabUntil(UiText.ph(Placeholder.QUIT_WAITING_ANYWAY).shown())
            w.enter()
        } finally {
            w.close()
        }
        assertEquals(1, quits)
        assertNull(m.quitAsked.value)
        // Nothing waits: no question, the app ends at once.
        api.script.waitingInMemory = 0
        m.askBeforeQuit()
        assertEquals(2, quits)
        assertNull(m.quitAsked.value)
        // The window's close and the menu's Quit both ask first.
        val main = File("src/main/kotlin/io/silencelen/andvari/desktop/Main.kt").readText().substringAfter("private fun ApplicationScope.AppWindow(")
        assertTrue(main.contains("onClose = { if (model == null) exitApplication() else model.askBeforeQuit() }"))
        assertTrue(main.contains("Item(\"Quit\", shortcut = KeyShortcut(Key.Q, ctrl = true)) { if (model == null) exitApplication() else model.askBeforeQuit() }"))
        assertTrue(main.contains("model?.quit = ::exitApplication"))
    }

    @Test
    fun afterTheFakesCopyWentTheQuitQuestionCountsWhatWaitsInMemory() {
        val api = FakeScenes.desktopAt(FakeScene.LOCKED)
        val m = model(api)
        unlocked(api, m)
        api.script.policyCopyRemoved(notSent = 0)
        val c = assertNotNull(m.content.value)
        assertNotNull(api.fakeContent).setOffline(true)
        assertEquals(ActionResult.Ok, runBlocking { c.saveLogin(null, LoginInput("Bank", "me", "pw", emptyList(), "", "", false), c.vaultsForNewItems().first().vaultId) })
        assertEquals(1, api.waitingInMemory(), "the save waits in memory only")
        var quits = 0
        m.quit = { quits++ }
        m.askBeforeQuit()
        assertEquals(0, quits)
        assertEquals(1, assertNotNull(m.quitAsked.value).waiting)
    }
}
