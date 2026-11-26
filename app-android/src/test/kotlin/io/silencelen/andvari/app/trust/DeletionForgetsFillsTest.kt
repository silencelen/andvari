package io.silencelen.andvari.app.trust

import io.silencelen.andvari.app.autofill.AutofillDebugLog
import io.silencelen.andvari.core.app.AppPhase
import io.silencelen.andvari.core.app.AppPlatform
import io.silencelen.andvari.core.app.DeletionResult
import io.silencelen.andvari.core.app.EntryScreen
import io.silencelen.andvari.core.app.PlainResult
import io.silencelen.andvari.core.app.fake.FakeAppApi
import io.silencelen.andvari.core.app.fake.FakeScene
import io.silencelen.andvari.core.app.fake.FakeScenes
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import java.io.File
import java.nio.file.Files
import kotlin.test.AfterTest
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertIs
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue

/**
 * An account deletion leaves the phone as a fresh install, so what the autofill status screen recorded of the last fills
 * (the calling app's package and the page's host) goes with it, and so do the ring of fill events and the debug toggle:
 * they say which apps and sites the deleted account filled on. The same at the forgetting of an account whose deletion
 * got no answer. A sign-out and "Forget this server" leave them, as the released app does.
 */
class DeletionForgetsFillsTest {
    private val dir: File = Files.createTempDirectory("andvari-fills").toFile()

    /** The phone's records, with the fill records in [dir] as the phone keeps them in its files folder. */
    private inner class Records : AutofillRecords {
        var cleared = 0
        var kept: String? = null
        override fun clear() { cleared++; kept = null }
        override fun owner(): String? = kept
        override fun setOwner(accountId: String) { kept = accountId }
        override fun forgetFills() = AutofillDebugLog.forgetIn(dir)
    }

    private val records = Records()

    @AfterTest
    fun toggleOff() = AutofillDebugLog.armCacheUntil(0L)

    private fun at(scene: FakeScene): Pair<FakeAppApi, TrustModel> {
        val api = FakeScenes.onPlatform(AppPlatform.ANDROID, scene)
        val m = TrustModel(api, CoroutineScope(Dispatchers.Unconfined), BuildConstants.JOIN_BASE, { 0L }, autofillRecords = records)
        m.onSnapshot(api.snapshot)
        return api to m
    }

    private fun TrustModel.delete(api: FakeAppApi) {
        val screen = assertNotNull(assertNotNull(api.snapshot.account).deletion)
        runIn(DELETION_SECTION, { settings.deleteAccount(screen, FakeScenes.EMAIL, FakeScenes.PASSWORD, null) }, { deletionWords(it, 0) }) { deletionAnswered(it) }
        onSnapshot(api.snapshot)
    }

    /** Two fills recorded with the debug toggle on: the last fill's summary and a ring of two. */
    private fun recordFills() {
        AutofillDebugLog.armCacheUntil(System.currentTimeMillis() + AutofillDebugLog.DEBUG_WINDOW_MS)
        for (pkg in listOf("com.android.chrome", "com.example.bank")) {
            val event = AutofillDebugLog.FillEvent(
                ts = 1L, origin = "service", reason = AutofillDebugLog.FillReason.DATASETS.name, detail = "1", pkg = pkg,
                fields = listOf(AutofillDebugLog.FieldSummary(kind = "PASSWORD", host = "bank.example")),
            )
            AutofillDebugLog.recordIn(dir, event) { AutofillDebugLog.armedByCache() }
        }
        AutofillDebugLog.awaitWrites()
        assertEquals("com.example.bank", AutofillDebugLog.lastEventIn(dir)?.pkg, "the last fill is recorded")
        assertEquals(2, AutofillDebugLog.ringFileIn(dir).readLines().count { it.isNotBlank() }, "the ring holds both")
        assertTrue(AutofillDebugLog.armedByCache())
    }

    private fun assertFillsGone(at: String) {
        AutofillDebugLog.awaitWrites()
        assertNull(AutofillDebugLog.lastEventIn(dir), "$at: the last fill's app and host")
        assertFalse(AutofillDebugLog.ringFileIn(dir).exists(), "$at: the ring of fill events")
        assertFalse(AutofillDebugLog.armedByCache(), "$at: the debug toggle")
        // A start reads the files folder afresh: nothing of them is there.
        assertEquals(emptyList(), dir.list()!!.toList(), "$at: nothing left in the files folder")
    }

    @Test
    fun aConfirmedDeletionForgetsTheLastFillsTheRingAndTheToggle() {
        val (api, m) = at(FakeScene.DELETION)
        recordFills()
        m.delete(api)
        assertEquals(AppPhase.ENTRY, api.snapshot.phase)
        assertNotNull(assertIs<EntryScreen.FirstRun>(api.snapshot.entry).accountDeleted, "the deletion was confirmed")
        assertFillsGone("after a confirmed deletion")
    }

    @Test
    fun forgettingAnAccountWhoseDeletionGotNoAnswerForgetsThemToo() {
        val (api, m) = at(FakeScene.DELETION)
        api.script.deletionAnswerLost = true
        recordFills()
        m.delete(api)
        assertTrue(assertNotNull(assertNotNull(api.snapshot.account).deletion).outcomeUnknown)
        AutofillDebugLog.awaitWrites()
        assertNotNull(AutofillDebugLog.lastEventIn(dir), "an answer nobody can tell yet forgets nothing")
        assertTrue(AutofillDebugLog.ringFileIn(dir).exists())
        val clearedBefore = records.cleared
        m.askToForgetUnknownDeletion()
        assertNotNull(m.forgetUnknownAsked.value, "the offer's second step")
        m.forgetUnknownDeletion()
        m.onSnapshot(api.snapshot)
        assertEquals(AppPhase.ENTRY, api.snapshot.phase, "the account is forgotten on this phone")
        assertFillsGone("after forgetting the account")
        assertEquals(clearedBefore + 1, records.cleared, "the trusted browsers and remembered apps go too, as at a deletion")
    }

    @Test
    fun aSignOutAndForgetThisServerLeaveThem() {
        val (_, m) = at(FakeScene.DELETION)
        recordFills()
        m.personEnded(PlainResult.DONE)
        AutofillDebugLog.awaitWrites()
        assertEquals("com.example.bank", AutofillDebugLog.lastEventIn(dir)?.pkg, "a sign-out or a forgotten server keeps the last fill")
        assertTrue(AutofillDebugLog.ringFileIn(dir).exists())
        assertTrue(AutofillDebugLog.armedByCache())
        m.personEnded(DeletionResult.OUTCOME_UNKNOWN)
        AutofillDebugLog.awaitWrites()
        assertNotNull(AutofillDebugLog.lastEventIn(dir), "nor does a deletion nobody can tell yet")
    }

    @Test
    fun thePhonesRecordsForgetTheFilesAndTheStoredToggle() {
        val src = File("src/main/kotlin/io/silencelen/andvari/app/trust/TrustSeam.kt").readText()
        assertTrue(src.contains("override fun forgetFills() = io.silencelen.andvari.app.autofill.AutofillDebugLog.forget(app)"))
        val log = File("src/main/kotlin/io/silencelen/andvari/app/autofill/AutofillDebugLog.kt").readText()
        val forget = log.substringAfter("fun forget(context: Context) {").substringBefore("\n    }\n")
        // The stored toggle is removed at once (a start after the deletion reads it off), then the files.
        assertTrue(forget.indexOf("debugPrefs(app).edit().remove(K_DEBUG_UNTIL).commit()") in 0 until forget.indexOf("forgetIn(app.filesDir)"), forget)
    }
}
