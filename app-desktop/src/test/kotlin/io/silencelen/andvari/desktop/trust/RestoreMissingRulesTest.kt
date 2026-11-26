package io.silencelen.andvari.desktop.trust

import io.silencelen.andvari.core.client.restore.RestoreOpening
import io.silencelen.andvari.core.client.restore.RestoreResult
import kotlinx.coroutines.runBlocking
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertIs
import kotlin.test.assertNotNull
import kotlin.test.assertTrue

/**
 * Two rules of the shared restore that no test held: the files taken off are reported only for the vaults a run stored
 * into or ended, and a run whose choice holds nothing sends nothing, writes no record and starts nothing.
 */
internal class RestoreMissingRulesTest : RestoreTestKit() {
    @Test
    fun tryAgainThatStoresNothingAndEndsNoVaultReportsNoFilesTakenOff() {
        val w = world("rules-stripped-narrow")
        // Items 2 and 3 name attached files the backup does not hold; "A" is refused for good, on every run.
        val bytes = withoutFiles(3, named = setOf(2, 3))
        w.server.rejectFirst = true
        val f = flow(w, bytes)
        open(f)
        runBlocking { f.confirm() }
        assertEquals(RestoreFlow.Stage.ENDED, f.views.value.stage)
        val first = assertNotNull(f.views.value.done)
        assertEquals(2, first.stored)
        assertEquals(2, first.stripped, "the run that stored them says the files taken off")
        has(page(w, f), ph(Placeholder.RESTORE_DONE_STRIPPED, "2"), "Try again")
        // Try again: "A" is refused again; nothing is stored and the vault, ended by the first run, is not ended again.
        runBlocking { f.tryAgain() }
        assertEquals(RestoreFlow.Stage.ENDED, f.views.value.stage)
        val again = assertNotNull(f.views.value.done)
        assertEquals(0, again.stored)
        assertEquals(1, again.refused.size)
        assertEquals(0, again.stripped)
        val end = page(w, f)
        println("RULES|try again end=$end")
        assertFalse(end.any { it == ph(Placeholder.RESTORE_DONE_STRIPPED, "2") }, "no files taken off in a run that stored nothing: $end")
        assertTrue(end.none { line -> (1..3).any { line == ph(Placeholder.RESTORE_DONE_STRIPPED, it.toString()) } }, "$end")
        assertEquals(2, personalItems(w))
    }

    @Test
    fun aRunWhoseChoiceHoldsNothingSendsNothingWritesNoRecordAndStartsNothing() {
        // The record at rest, so that a record written would be a file of this computer.
        val w = atRest("rules-empty-choice")
        val bytes = backup(3, familyItems = 2)
        val api = w.api.restores
        val file = assertIs<RestoreOpening.Opened>(runBlocking { api.open(pass.toCharArray(), bytes) }).file
        val preview = assertNotNull(runBlocking { api.preview(file) })
        val pushes = w.server.pushes
        val r = assertIs<RestoreResult.Done>(runBlocking { api.restore(file, preview.choose(emptySet())) { } })
        assertEquals(0, r.vaults)
        assertEquals(0, r.stored)
        assertEquals(pushes, w.server.pushes, "nothing sent")
        assertEquals(emptyList(), restoreFiles(w).map { it.name }, "no record written")
        assertFalse(api.unfinishedRestore(), "nothing started")
        // Again through the call that chooses by the description now, with ids the file does not hold.
        val again = assertIs<RestoreResult.Done>(assertNotNull(runBlocking { api.restoreAgain(file, setOf("not a vault of the file")) { } }))
        assertEquals(0, again.vaults)
        assertEquals(pushes, w.server.pushes)
        assertEquals(emptyList(), restoreFiles(w).map { it.name })
        assertEquals(0, personalItems(w))
    }
}
