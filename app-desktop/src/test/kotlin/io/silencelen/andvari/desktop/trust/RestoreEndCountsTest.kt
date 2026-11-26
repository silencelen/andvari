package io.silencelen.andvari.desktop.trust

import kotlinx.coroutines.runBlocking
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse

/**
 * Every number at the end of a restore counts what the server kept, each thing once (decided on 23 November 2026): the
 * attached files restored are those of the items this run stored, each once; the files taken off are those of the
 * vaults this run stored into or brought to their end.
 */
internal class RestoreEndCountsTest : RestoreTestKit() {
    private fun filesLine(n: Int) = ph(if (n == 1) Placeholder.RESTORE_DONE_FILES_ONE else Placeholder.RESTORE_DONE_FILES, n.toString())

    private fun strippedLine(n: Int) = ph(Placeholder.RESTORE_DONE_STRIPPED, n.toString())

    private fun anyFilesLine(lines: List<String>) = lines.filter { l -> (1..500).any { l == filesLine(it) } }

    @Test
    fun theFileOfAnItemTheServerRefusedIsNotCountedAndIsCountedOnceWhenTheItemArrives() {
        val w = world("counts-refused-file")
        // 201 items; "A", the first, carries the one attached file of the backup. The server refuses "A".
        val f = flow(w, backup(201, familyItems = 0))
        open(f)
        w.server.rejectFirst = true
        runBlocking { f.confirm() }
        assertEquals(RestoreFlow.Stage.ENDED, f.views.value.stage)
        val end = page(w, f)
        println("COUNTS|refused end=$end uploads=${w.server.uploads.size} withFile=${w.server.items.count { it.attachmentIds.isNotEmpty() }}")
        assertEquals(0, w.server.items.count { it.attachmentIds.isNotEmpty() }, "the account holds no item with a file")
        assertEquals(emptyList(), anyFilesLine(end), "no attached file was restored: $end")
        // Try again: "A" arrives now, with its file, which is counted now and only now.
        w.server.rejectFirst = false
        runBlocking { f.tryAgain() }
        val again = page(w, f)
        println("COUNTS|refused then taken end=$again")
        assertEquals(1, w.server.items.count { it.attachmentIds.isNotEmpty() })
        assertEquals(listOf(filesLine(1)), anyFilesLine(again))
    }

    @Test
    fun aBatchSentAgainOnlyForTheRecordCountsNoneOfItsFiles() {
        val w = world("counts-sent-again")
        val bytes = backup(201, familyItems = 0)
        val f = flow(w, bytes)
        open(f)
        // The server takes the first batch ("A" with its file among them) and its answer is lost: the run stops.
        w.server.beforePush = { n -> if (n == 1) w.server.loseNextAnswer = true }
        runBlocking { f.confirm() }
        w.server.beforePush = null
        assertEquals(RestoreFlow.Stage.STOPPED, f.views.value.stage)
        // The same file again: its preview's sync sends what the stopped run left queued; one item is left.
        val again = flow(w, bytes)
        open(again)
        runBlocking { again.confirm() }
        val end = page(w, again)
        println("COUNTS|sent again end=$end account=${personalItems(w)} withFile=${w.server.items.count { it.attachmentIds.isNotEmpty() }}")
        assertEquals(201, personalItems(w))
        has(end, ph(Placeholder.RESTORE_DONE_ONE, "1", "1"))
        assertEquals(emptyList(), anyFilesLine(end), "the file of \"A\" was stored by the first run, not by this one: $end")
    }

    @Test
    fun aRefusedItemIsNotInTheFilesTakenOffAndIsCountedOnceWhenTaken() {
        val w = world("counts-stripped-refused")
        // 201 items made without their files; "A" (first) and "Item 201" each name one.
        val bytes = withoutFiles(201, setOf(1, 201))
        val f = flow(w, bytes)
        open(f)
        w.server.rejectFirst = true
        runBlocking { f.confirm() }
        val first = page(w, f)
        // "A" was refused: only the file of "Item 201" was taken off.
        has(first, strippedLine(1))
        w.server.rejectFirst = false
        runBlocking { f.tryAgain() }
        val second = page(w, f)
        has(second, strippedLine(2))
        assertEquals(201, personalItems(w))
        println("COUNTS|stripped first=$first second=$second")
    }
}
