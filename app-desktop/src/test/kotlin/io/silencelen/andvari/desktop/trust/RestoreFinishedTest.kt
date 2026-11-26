package io.silencelen.andvari.desktop.trust

import io.silencelen.andvari.core.model.wire.QuotaMeter
import io.silencelen.andvari.core.model.wire.QuotaUse
import kotlinx.coroutines.runBlocking
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertNotNull
import kotlin.test.assertTrue

/**
 * A restore whose every item is in the account is finished, and its record says so when its file is opened again; a run
 * that the room check ends writes no record and starts nothing (decided on 23 November 2026). The line of the question
 * before a sign-out stays wherever this computer's record does not show the restore as finished.
 */
internal class RestoreFinishedTest : RestoreTestKit() {
    private val line get() = ph(Placeholder.RESTORE_UNFINISHED_AT_SIGN_OUT)

    @Test
    fun theAnswerToTheLastBatchLostThenTheSameFileOpenedAgainFinishesTheRestoreWithoutAPress() {
        val w = world("finished-last-unheard")
        keepOn(w)
        val bytes = backup(201, familyItems = 0)
        val f = flow(w, bytes)
        open(f)
        w.server.beforePush = { n -> if (n == 2) w.server.loseNextAnswer = true }
        runBlocking { f.confirm() }
        w.server.beforePush = null
        assertEquals(RestoreFlow.Stage.STOPPED, f.views.value.stage)
        // Before the file is opened again, this computer's record does not show the restore as finished: the line stays.
        has(question(w), line)
        val pushes = w.server.pushes
        // The page left; the same file chosen again.
        val again = flow(w, bytes)
        open(again)
        val p = assertNotNull(again.views.value.preview)
        val lines = page(w, again)
        println("FINISHED|last unheard preview=$lines question=${question(w)}")
        assertEquals(201, personalItems(w))
        assertEquals(0, p.vaults.sumOf { it.left })
        assertTrue(w.server.pushes <= pushes + 1, "at most the preview's sync sent what the stopped run left queued; nothing of the restore")
        assertTrue(p.vaults.first { it.personal }.restoredAt != null, "the record says the vault's restore ended")
        assertFalse(line in question(w), "nothing of the restore is left: ${question(w)}")
    }

    @Test
    fun aRunTheRoomCheckEndsWritesNoRecordAndTheQuestionDrawsNoLine() {
        val w = world("finished-no-room")
        keepOn(w)
        w.server.quota = QuotaUse(QuotaMeter(0, 1L shl 40), QuotaMeter(0, 2), QuotaMeter(0, 10), QuotaMeter(0, 10))
        val f = flow(w, backup(3, familyItems = 0))
        open(f)
        runBlocking { f.confirm() }
        println("FINISHED|no room stage=${f.views.value.stage} noRoom=${f.views.value.noRoom?.size} records=${restoreFiles(w).map { it.name }} unfinished=${w.api.restores.unfinishedRestore()}")
        assertEquals(RestoreFlow.Stage.PREVIEW, f.views.value.stage)
        assertNotNull(f.views.value.noRoom)
        assertEquals(0, w.server.pushes)
        assertEquals(emptyList(), restoreFiles(w).map { it.name }, "no record lies on the computer")
        assertFalse(line in question(w))
    }

    @Test
    fun theLineStaysAfterAStopInTheMiddleOfAVault() {
        val w = world("finished-middle")
        keepOn(w)
        val bytes = backup(401, familyItems = 0)
        stopAfter(w, bytes, taken = 1)
        has(question(w), line)
        // Opened again (its sync sends the batch the stop left queued): an item is left, nothing ends, the line stays.
        val again = flow(w, bytes)
        open(again)
        assertTrue(assertNotNull(again.views.value.preview).vaults.sumOf { it.left } > 0)
        has(question(w), line)
    }

    @Test
    fun theLineStaysWhileItemsTheServerRefusedAreLeftAlsoWhenTheFileIsOpenedAgain() {
        val w = world("finished-refused")
        val bytes = backup(3, familyItems = 0)
        w.server.rejectFirst = true
        val f = flow(w, bytes)
        open(f)
        runBlocking { f.confirm() }
        assertEquals(RestoreFlow.Stage.ENDED, f.views.value.stage)
        has(question(w), line)
        val again = flow(w, bytes)
        open(again)
        assertEquals(1, assertNotNull(again.views.value.preview).vaults.sumOf { it.left })
        has(question(w), line)
    }
}
