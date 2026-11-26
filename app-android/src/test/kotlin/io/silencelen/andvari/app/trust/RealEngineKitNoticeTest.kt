package io.silencelen.andvari.app.trust

import io.silencelen.andvari.core.app.AppPhase
import io.silencelen.andvari.core.app.AppPlatform
import io.silencelen.andvari.core.app.CopyKey
import io.silencelen.andvari.core.app.EntryScreen
import io.silencelen.andvari.core.app.engine.AppEngine
import io.silencelen.andvari.core.app.engine.EngineAppApi
import io.silencelen.andvari.core.client.MemoryDeviceState
import io.silencelen.andvari.core.client.session.WireTransport
import io.silencelen.andvari.core.crypto.createCryptoProvider
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertIs
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertSame
import kotlin.test.assertTrue

/**
 * The app's own model over the shared code's REAL implementation ([EngineAppApi] over [AppEngine]), as the desktop's
 * tests do: this phone's device state at rest says a kit of a committed change was on show when the app was closed (the
 * engine's own mark, which holds nothing of the kit). The start says the kit is gone; a lock, the idle clock, the
 * background and the return leave the notice; the first screen offers the way out its line names; only the dismiss takes
 * it, and a later start says nothing.
 *
 * The transport here refuses every server, so nothing is sent anywhere. The kit shown after a late refusal, over the
 * shared code's own test server, is walked in [SharedTestServerWalksTest].
 */
class RealEngineKitNoticeTest {
    private val noServer = WireTransport { origin, _ -> throw IllegalStateException("no server in this test: $origin") }

    private fun engine(state: MemoryDeviceState): EngineAppApi = EngineAppApi(
        AppEngine(
            AppPlatform.ANDROID, "Pixel", noServer, state, MemoryDeviceState(), createCryptoProvider(), { 1_700_000_000_000L },
            baked = null, storeBuild = false, stores = null, main = Dispatchers.Unconfined, work = Dispatchers.Unconfined,
        ),
    )

    @Test
    fun aKitOnShowAtTheCloseIsSaidGoneAtTheStartThroughALockUntilTheDismiss() {
        val state = MemoryDeviceState()
        // As the engine writes it when such a kit comes on show (after a recovery; another account was kept here).
        state.set(KIT_ON_SHOW_KEY, "recovery|${CopyKey.KIT_RECOVERED_NOT_KEPT.name}|ada@example.com")
        var now = 0L
        val api = engine(state)
        val m = TrustModel(api, CoroutineScope(Dispatchers.Unconfined), BuildConstants.JOIN_BASE, { now })
        m.start()
        m.onSnapshot(api.snapshot)
        assertEquals(AppPhase.ENTRY, api.snapshot.phase)
        assertIs<EntryScreen.FirstRun>(api.snapshot.entry)
        val notice = assertNotNull(api.snapshot.kitWiped, "the start says the kit is gone")
        assertEquals("ada@example.com", notice.email)
        assertEquals(CopyKey.KIT_WIPED_AFTER_RECOVERY_NOT_HERE, notice.line)
        // The reason line under the notice, never the kit's own line (which says to save the kit), and its way out.
        assertEquals(CopyKey.KIT_NOT_HERE_WHY_ANOTHER_KEPT, notice.whyHere)
        assertEquals(io.silencelen.andvari.core.app.KeptWayOut.SIGN_OUT_KEPT_ACCOUNT, notice.wayOut)
        assertEquals(
            listOf(UiText.of(CopyKey.KIT_WIPED_AFTER_RECOVERY_NOT_HERE).shown(), UiText.of(CopyKey.KIT_NOT_HERE_WHY_ANOTHER_KEPT).shown()),
            kitWipedLines(notice).map { it.shown() },
        )
        // The notice's own way out names a kept session that this phone does not keep now (only the mark at rest was
        // written here): the first screen does not offer it (it offered the sign-out of an account that is not there).
        assertEquals(WayOut.KEPT_SIGN_OUT, wayOutOf(notice.wayOut))
        assertNull(api.snapshot.keptSignedOut)
        assertNull(kitWipedWayOut(notice, m.saidOn(api.snapshot)?.result, api.snapshot), "no kept session it named: no way out")

        // Nothing but the dismiss takes it: a lock, the idle clock, the background, the return.
        m.act { lock() }
        now += 3_600_000
        m.tick()
        m.backgrounded()
        m.returnedToForeground()
        m.onSnapshot(api.snapshot)
        assertSame(notice, api.snapshot.kitWiped)
        assertTrue(m.wentWrong.value == null, "nothing went wrong on the way")

        // A second start of the app (the process ended) says it again, from the same mark.
        val again = engine(state)
        again.start()
        val second = assertNotNull(again.snapshot.kitWiped)
        assertEquals(notice.line, second.line)

        // The dismiss, from the app's own Close, takes it and its mark.
        m.dismissKitWiped(notice)
        assertNull(api.snapshot.kitWiped)
        val third = engine(state)
        third.start()
        assertNull(third.snapshot.kitWiped, "a later start says nothing")
    }

    private companion object {
        /** The shared code's key for the mark (`EngineAppApi.KIT_ON_SHOW_KEY`), written as the engine writes it. */
        const val KIT_ON_SHOW_KEY = "ovh.kit.notkept.onshow"
    }
}
