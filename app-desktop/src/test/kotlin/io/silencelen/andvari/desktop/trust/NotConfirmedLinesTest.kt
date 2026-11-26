package io.silencelen.andvari.desktop.trust

import io.silencelen.andvari.core.app.AppPhase
import io.silencelen.andvari.core.app.CopyKey
import io.silencelen.andvari.core.app.fake.FakeScene
import io.silencelen.andvari.core.app.fake.FakeScenes
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertIs
import kotlin.test.assertNotNull
import kotlin.test.assertNull

/**
 * The desktop's own two lines about work a session's end cut short: where this computer could not confirm the session in
 * time, each says that end as the shared code hands it, never that the server signed this computer out. By key.
 */
class NotConfirmedLinesTest {
    private fun models() = FakeScenes.desktopAt(FakeScene.LOCKED).let { api ->
        api to TrustModel(api, CoroutineScope(Dispatchers.Unconfined), { 0L }).also { it.onSnapshot(api.snapshot) }
    }

    @Test
    fun workOvertakenByAnUnconfirmedEndSaysThatEndNeverTheServers() {
        val (api, m) = models()
        val s = api.snapshot
        val locked = assertNotNull(s.locked)
        val serverEnded = rebuilt(s, "locked" to rebuilt(locked, "signedOutByServer" to true))
        assertEquals(Placeholder.SERVER_ENDED_BEFORE_DONE, assertIs<UiText.Ph>(m.overtookWords(serverEnded, serverEnded)).placeholder)
        val notConfirmed = rebuilt(s, "locked" to rebuilt(locked, "signedOutByServer" to true, "sessionNotConfirmed" to true))
        val said = assertIs<UiText.Ph>(m.overtookWords(notConfirmed, notConfirmed))
        assertEquals(Placeholder.NOT_CONFIRMED_BEFORE_DONE, said.placeholder)
        assertEquals(listOf(UiText.of(CopyKey.SESSION_NOT_CONFIRMED).shown()), said.args, "the shared code's own line for that end")
        // Asked with the copy open, overtaken at the lock screen of that end: the lock screen's line.
        m.run({ unlock(assertNotNull(snapshot.locked), FakeScenes.PASSWORD) })
        val open = api.snapshot
        assertEquals(AppPhase.UNLOCKED, open.phase)
        val account = assertNotNull(open.account)
        val before = rebuilt(open, "account" to rebuilt(account, "signedOutByServer" to true, "sessionNotConfirmed" to true, "endLine" to CopyKey.SESSION_NOT_CONFIRMED_COPY_OPEN))
        assertEquals(listOf(UiText.of(CopyKey.SESSION_NOT_CONFIRMED).shown()), assertIs<UiText.Ph>(m.overtookWords(before, notConfirmed)).args)
        // Still on the open copy's screen: the open copy's line.
        val stillOpen = assertIs<UiText.Ph>(m.overtookWords(before, before))
        assertEquals(Placeholder.NOT_CONFIRMED_BEFORE_DONE, stillOpen.placeholder)
        assertEquals(listOf(UiText.of(CopyKey.SESSION_NOT_CONFIRMED_COPY_OPEN).shown()), stillOpen.args)
        assertNull(m.notConfirmedEnd(serverEnded, serverEnded))
    }

    @Test
    fun aChangeCutByAnUnconfirmedEndSaysThatEndNeverTheServers() {
        val (api, m) = models()
        val s = api.snapshot
        val locked = assertNotNull(s.locked)
        assertEquals(Placeholder.CHANGE_CUT_BY_LOCK, assertIs<UiText.Ph>(m.changeCutLine(s)).placeholder)
        val serverEnded = rebuilt(s, "locked" to rebuilt(locked, "signedOutByServer" to true))
        assertEquals(Placeholder.CHANGE_CUT_BY_SERVER_END, assertIs<UiText.Ph>(m.changeCutLine(serverEnded)).placeholder)
        val notConfirmed = rebuilt(s, "locked" to rebuilt(locked, "signedOutByServer" to true, "sessionNotConfirmed" to true))
        val cut = assertIs<UiText.Ph>(m.changeCutLine(notConfirmed))
        assertEquals(Placeholder.CHANGE_CUT_BY_NOT_CONFIRMED, cut.placeholder)
        assertEquals(listOf(UiText.of(CopyKey.SESSION_NOT_CONFIRMED).shown()), cut.args)
    }
}
