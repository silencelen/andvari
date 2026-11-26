package io.silencelen.andvari.app.trust

import io.silencelen.andvari.core.app.AppPhase
import io.silencelen.andvari.core.app.AppPlatform
import io.silencelen.andvari.core.app.CopyKey
import io.silencelen.andvari.core.app.EntryScreen
import io.silencelen.andvari.core.app.fake.FakeScene
import io.silencelen.andvari.core.app.fake.FakeScenes
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import java.io.File
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertIs
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue

/**
 * What the shared code offers now, used where it applies: live updates told that the network is
 * back, alone; the first screen's own notice for a deletion whose outcome is unknown; the move's "starts fresh".
 */
class SharedCodeOffersTest {
    private val scope = CoroutineScope(Dispatchers.Unconfined)

    private fun src(name: String) = File("src/main/kotlin/io/silencelen/andvari/app/trust/$name").readText()

    @Test
    fun aNetworksReturnTellsLiveUpdatesAloneThroughTheSharedCodesOwnCall() {
        val api = FakeScenes.onPlatform(AppPlatform.ANDROID, FakeScene.VAULTS)
        val m = TrustModel(api, scope, BuildConstants.JOIN_BASE, { 0L })
        m.onSnapshot(api.snapshot)
        assertEquals(AppPhase.UNLOCKED, api.snapshot.phase)
        val before = api.networkReturns
        m.networkReturned()
        assertEquals(before + 1, api.networkReturns, "the bell is told")
        // Locked, it does nothing (the shared code's rule), and nothing throws.
        m.act { lock() }
        m.networkReturned()
        assertEquals(before + 1, api.networkReturns)
        assertTrue(src("TrustSeam.kt").contains("model.networkReturned()"))
    }

    @Test
    fun theFirstScreenSaysTheSharedCodesUnknownDeletionNoticeAndNeverTheAppsBesideIt() {
        val api = FakeScenes.onPlatform(AppPlatform.ANDROID, FakeScene.VAULTS)
        val m = TrustModel(api, scope, BuildConstants.JOIN_BASE, { 0L })
        m.onSnapshot(api.snapshot)
        api.script.deletionOutcomeUnknown = true
        api.script.sessionEndedByServer()
        api.signInAgain(assertNotNull(api.snapshot.locked))
        m.onSnapshot(api.snapshot)
        val first = assertIs<EntryScreen.FirstRun>(api.snapshot.entry)
        val notice = assertNotNull(first.deletionOutcomeUnknown, "the shared code gives its notice")
        for (appToo in listOf(false, true)) {
            val line = assertNotNull(deletionUnknownLine(first, appCannotTell = appToo))
            assertTrue(line.dismissable)
            assertEquals(UiText.of(notice.line).shown(), line.text.shown(), "the shared code's words, once")
            assertTrue(line.text.shown().contains(notice.email))
        }
        // Its dismiss is the shared code's.
        m.act { entry.dismissNotice(first) }
        val after = assertIs<EntryScreen.FirstRun>(api.snapshot.entry)
        assertNull(after.deletionOutcomeUnknown)
        // Where the shared code says nothing, the app's own line stays (not dismissable), and nothing at all otherwise.
        assertEquals(Placeholder.DELETION_CANNOT_TELL, assertIs<UiText.Ph>(assertNotNull(deletionUnknownLine(after, appCannotTell = true)).text).placeholder)
        assertFalse(deletionUnknownLine(after, appCannotTell = true)!!.dismissable)
        assertNull(deletionUnknownLine(after, appCannotTell = false))
    }

    @Test
    fun aMoveThatStartsFreshSaysTheSharedCodesSentenceBeforeItStarts() {
        val code = src("VaultScreens.kt")
        assertTrue(code.contains("screen.startsFresh?.let { out += UiText.of(it) }"))
        // The line is the shared code's key, shown as a placeholder exactly while that key awaits its words.
        assertEquals(CopyKey.MOVE_STARTS_FRESH.awaitingOwner, UiText.of(CopyKey.MOVE_STARTS_FRESH).isPlaceholder)
    }
}
