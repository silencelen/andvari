package io.silencelen.andvari.desktop.trust

import io.silencelen.andvari.core.app.AppPhase
import io.silencelen.andvari.core.app.OperatorResult
import io.silencelen.andvari.core.app.fake.FakeScene
import io.silencelen.andvari.core.app.fake.FakeScenes
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import java.io.File
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertIs
import kotlin.test.assertNotNull
import kotlin.test.assertTrue

/**
 * "andvari locked before this was done" only where a lock did it (the reader of 2026-11-17): the same throw and the same
 * STALE come when the server ends the session, and on the first screen there is nothing to unlock.
 */
class OvertookWhereTest {
    private val dir = "src/main/kotlin/io/silencelen/andvari/desktop/trust/"
    private fun body(file: String, head: String) = File(dir + file).readText().substringAfter(head).substringBefore("\n}\n")
    private fun saidPh(m: TrustModel): Placeholder = assertIs<UiText.Ph>(assertNotNull(m.said.value).text).placeholder

    @Test
    fun aLockSaysTheLockAndAServerEndSaysItself() {
        // A lock by hand: the lock's line.
        val api = FakeScenes.desktopAt(FakeScene.VAULTS)
        val m = TrustModel(api, CoroutineScope(Dispatchers.Unconfined), { 0L })
        m.onSnapshot(api.snapshot)
        m.lockOvertook()
        assertEquals(AppPhase.LOCKED, api.snapshot.phase)
        assertEquals(Placeholder.LOCK_OVERTOOK, saidPh(m))

        // The server ended the session while the vault was open: not a lock of andvari's (said as itself whether the
        // vault is still on show read-only or at the lock screen).
        val ended = FakeScenes.desktopAt(FakeScene.VAULTS)
        val e = TrustModel(ended, CoroutineScope(Dispatchers.Unconfined), { 0L })
        e.onSnapshot(ended.snapshot)
        ended.script.sessionEndedByServer()
        e.onSnapshot(ended.snapshot)
        assertTrue(ended.snapshot.account?.signedOutByServer == true || ended.snapshot.locked?.signedOutByServer == true)
        e.lockOvertook()
        assertEquals(Placeholder.SERVER_ENDED_BEFORE_DONE, saidPh(e))
        // And at its lock screen, with the vault locked.
        if (ended.snapshot.phase == AppPhase.UNLOCKED) ended.lock()
        assertEquals(AppPhase.LOCKED, ended.snapshot.phase)
        assertTrue(assertNotNull(ended.snapshot.locked).signedOutByServer)
        e.lockOvertook()
        assertEquals(Placeholder.SERVER_ENDED_BEFORE_DONE, saidPh(e))

        // On the first screen there is nothing to unlock.
        e.signInAgain()
        e.onSnapshot(ended.snapshot)
        assertEquals(AppPhase.ENTRY, ended.snapshot.phase)
        e.lockOvertook()
        assertEquals(Placeholder.STOPPED_BEFORE_DONE, saidPh(e))
    }

    /**
     * Each place that reached the lock's line, settled from the code: the app's own work that the person did not ask for
     * (the re-read after a device link was approved, the cancel of a link left on show, which the lock cancels itself)
     * says nothing of its own; an answer done before its handling met the wiped keys is said as done; a change cut by
     * the content's close says to check; the shared code's own work that faulted says so as itself.
     */
    @Test
    fun eachPlaceSaysWhatIsSoThere() {
        assertTrue(body("TrustModel.kt", "    private fun devicesFollowTheLink(").contains("launchOvertakable(::lockedQuietly, fault) { api.devices.openDevices() }"))
        assertTrue(body("TrustModel.kt", "    fun leftDeviceLink(").contains("launchOvertakable(::lockedQuietly, fault) { api.devices.cancelDeviceLink() }"))
        assertTrue(body("TrustModel.kt", "    private fun lockedQuietly(").substringBefore("\n    }\n").let { "api.lock()" in it && "saidFlow" !in it })
        val launch = body("TrustModel.kt", "    private fun <R : IntentResult> launchIntent(")
        assertTrue(launch.contains("Overtaken.act({ if (r.done) doneAsTheKeysWent(r) else lockOvertook() }, fault) { answered(place, r, words, after) }"))
        assertTrue(body("TrustModel.kt", "    private fun doneAsTheKeysWent(").contains("doneUnderLockWords(r)"))
        val closed = body("TrustModel.kt", "    private fun contentClosed(").substringBefore("\n    }\n")
        // Its line is the lock's, the server's end, or an unconfirmed session's end as the shared code says it.
        assertTrue(closed.contains("changeCutLine(s)"))
        val cut = body("TrustModel.kt", "    internal fun changeCutLine(").substringBefore("\n    }\n")
        assertTrue(cut.contains("Placeholder.CHANGE_CUT_BY_SERVER_END") && cut.contains("Placeholder.CHANGE_CUT_BY_LOCK") && cut.contains("Placeholder.CHANGE_CUT_BY_NOT_CONFIRMED"))
        assertTrue(!closed.contains("LOCK_OVERTOOK") && !cut.contains("LOCK_OVERTOOK"))
        assertTrue(body("TrustModel.kt", "    fun faultedInBackground(").contains("faulted(t, null, background = true)"))
        // Finishing the server's set-up: a session that had ended is no "answer of the server's".
        assertEquals(Placeholder.OP_SETUP_NOT_FINISHED, assertIs<UiText.Ph>(assertNotNull(setupWords(OperatorResult.FAILED, 0))).placeholder)
        assertEquals(Placeholder.OP_NOT_TAKEN, assertIs<UiText.Ph>(assertNotNull(operatorWords(OperatorResult.FAILED, 0))).placeholder, "elsewhere the list's own line")
    }
}
