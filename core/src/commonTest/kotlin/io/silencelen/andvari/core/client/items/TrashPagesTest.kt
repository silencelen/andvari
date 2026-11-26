package io.silencelen.andvari.core.client.items

import io.silencelen.andvari.core.client.net.NoAnswerKind
import io.silencelen.andvari.core.client.net.WireResult
import io.silencelen.andvari.core.model.wire.DeletedItem
import io.silencelen.andvari.core.model.wire.WireError
import kotlinx.coroutines.runBlocking
import kotlin.test.Test
import kotlin.test.assertEquals

/**
 * The deleted-items list in pages (spec 03 §5.1): the server answers at most 65,536 rows a page, newest
 * first, and the next page after `<deletedAt>:<itemId>` of the last row. The engine reads every page, keeps one entry
 * per item with its newest deletion time, has a list only once the last page arrived, fails the whole read on a refused
 * or unanswered page (unknown, never a shorter list), and stops at [ItemEngine.TRASH_MAX_PAGES]. Engine-18: a page of
 * more than 65,536 rows, rows out of order, or a page that does not start strictly after the cursor fails the read, and a
 * row of a vault this account may not read is left out.
 */
class TrashPagesTest {
    private val full = ItemTransport.TRASH_PAGE_ROWS

    private fun id(n: Int) = n.toString(16).padStart(8, '0') + "-0000-4000-8000-000000000000"

    /** [count] rows, newest first, deleted at [top] down to `top - count + 1`. */
    private fun page(r: ItemRig, count: Int, top: Long, first: Int = 0) = (0 until count).map { DeletedItem(id(first + it), r.personal, top - it) }

    @Test
    fun everyPageIsRead_afterTheLastRowOfTheOneBefore_newestFirst() = runBlocking<Unit> {
        val r = ItemRig()
        for (n in 0 until full + 3) r.server.itemRows[id(n)] = r.tombstone(id(n), r.personal, 1_000_000L - n)
        val got = r.engine.deletedItems().ok()
        assertEquals(full + 3, got.size, "the rows past the first page are listed too")
        assertEquals(listOf(null, "${1_000_000L - full + 1}:${id(full - 1)}"), r.server.trashAfters)
        assertEquals(id(0), got.first().itemId)
        assertEquals(id(full + 2), got.last().itemId)
    }

    @Test
    fun oneEntryPerItem_withItsNewestDeletion() = runBlocking<Unit> {
        val r = ItemRig()
        val first = page(r, full, 10_000_000L)
        r.server.trashPages = { after ->
            if (after == null) WireResult.Ok(first, 200)
            // A row of the first page again, with an older time, in its place in the order (below the cursor). An item
            // deleted again between the two reads would be above the cursor, which the order check refuses (below).
            else WireResult.Ok(listOf(DeletedItem(id(full + 1), r.personal, 2), DeletedItem(id(5), r.personal, 1)), 200)
        }
        val got = r.engine.deletedItems().ok()
        assertEquals(full + 1, got.size)
        assertEquals(1, got.count { it.itemId == id(5) })
        assertEquals(10_000_000L - 5, got.single { it.itemId == id(5) }.deletedAt, "the newest deletion is kept")
        assertEquals(id(0), got.first().itemId, "newest first")
    }

    /** Engine-17's rule: the server's page is at most 65,536 rows; one more is a lie, never read as a full page. */
    @Test
    fun aPageOfMoreThanTheStatedRows_failsTheRead() = runBlocking<Unit> {
        val r = ItemRig()
        r.server.trashPages = { after -> WireResult.Ok(if (after == null) page(r, full + 1, 10_000_000L) else emptyList(), 200) }
        assertEquals(ItemFailure.Corrupt(ItemTransport.TRASH_INCOMPLETE), r.engine.deletedItems().failure())
        assertEquals(listOf<String?>(null), r.server.trashAfters, "nothing is asked after a page that is too long")
    }

    /**
     * Engine-17's rule against a looping cursor: rows strictly descending in `(deletedAt, itemId)`, and the first row of
     * a later page strictly after the cursor's row. A page that goes back up, repeats a row, or starts at or above the
     * cursor fails the read; a row at the cursor's time with a lower id is in order.
     */
    @Test
    fun rowsOutOfOrder_orAPageThatStartsAtOrAboveTheCursor_failTheRead() = runBlocking<Unit> {
        val r = ItemRig()
        val incomplete = ItemFailure.Corrupt(ItemTransport.TRASH_INCOMPLETE)
        r.server.trashPages = { WireResult.Ok(listOf(DeletedItem(id(1), r.personal, 5), DeletedItem(id(2), r.personal, 6)), 200) }
        assertEquals(incomplete, r.engine.deletedItems().failure(), "a page that goes back up")
        r.server.trashPages = { WireResult.Ok(listOf(DeletedItem(id(1), r.personal, 5), DeletedItem(id(1), r.personal, 5)), 200) }
        assertEquals(incomplete, r.engine.deletedItems().failure(), "a row twice")
        r.server.trashPages = { WireResult.Ok(listOf(DeletedItem(id(1), r.personal, 5), DeletedItem(id(2), r.personal, 5)), 200) }
        assertEquals(incomplete, r.engine.deletedItems().failure(), "a higher id at the same time")

        val first = page(r, full, 10_000_000L)
        val cursorAt = 10_000_000L - full + 1
        for ((why, second) in listOf(
            "the cursor's own row first" to DeletedItem(id(full - 1), r.personal, cursorAt),
            "a row above the cursor first" to DeletedItem(id(full + 7), r.personal, cursorAt + 100),
            "the cursor's time with a higher id first" to DeletedItem(id(full + 7), r.personal, cursorAt),
        )) {
            r.server.trashAfters.clear()
            r.server.trashPages = { after -> WireResult.Ok(if (after == null) first else listOf(second, DeletedItem(id(full + 8), r.personal, 1)), 200) }
            assertEquals(incomplete, r.engine.deletedItems().failure(), why)
            assertEquals(2, r.server.trashAfters.size, why)
        }
        val lower = "0000fffe-0000-4000-8000-000000000001" // below the cursor's id(full - 1), and on no page before
        r.server.trashPages = { after -> WireResult.Ok(if (after == null) first else listOf(DeletedItem(lower, r.personal, cursorAt)), 200) }
        assertEquals(full + 1, r.engine.deletedItems().ok().size, "the cursor's time with a lower id is in order")
    }

    /**
     * A page of another account's rows: a row of a vault this account may not read is never shown as the person's own
     * trash. It is left out, not a failure (it is also what a vault shared a moment ago looks like until it is adopted).
     */
    @Test
    fun aRowOfAVaultThisAccountMayNotRead_isLeftOut() = runBlocking<Unit> {
        val r = ItemRig()
        val elsewhere = "cccccccc-cccc-4ccc-8ccc-cccccccccccc"
        r.server.trashPages = { WireResult.Ok(listOf(DeletedItem(id(1), elsewhere, 9), DeletedItem(id(2), r.personal, 8), DeletedItem(id(3), elsewhere, 7)), 200) }
        assertEquals(listOf(id(2)), r.engine.deletedItems().ok().map { it.itemId })
    }

    @Test
    fun aRefusedOrUnansweredLaterPage_failsTheWholeRead() = runBlocking<Unit> {
        val r = ItemRig()
        val first = page(r, full, 10_000_000L)
        r.server.trashPages = { after -> if (after == null) WireResult.Ok(first, 200) else WireResult.Refused(400, WireError("bad_request", "bad_request")) }
        assertEquals(ItemFailure.Refused("bad_request", 400), r.engine.deletedItems().failure())
        r.server.trashPages = { after -> if (after == null) WireResult.Ok(first, 200) else WireResult.NoAnswer(NoAnswerKind.TRANSPORT) }
        assertEquals(ItemFailure.Unreachable(NoAnswerKind.TRANSPORT), r.engine.deletedItems().failure())
    }

    @Test
    fun aServerThatNeverEndsItsList_isReadAtMostSoManyPages() = runBlocking<Unit> {
        val r = ItemRig()
        var pages = 0
        r.server.trashPages = { WireResult.Ok(page(r, full, 1_000_000_000L - pages * full.toLong(), pages++ * full), 200) }
        assertEquals(ItemFailure.Corrupt(ItemTransport.TRASH_INCOMPLETE), r.engine.deletedItems().failure())
        assertEquals(ItemEngine.TRASH_MAX_PAGES, r.server.trashAfters.size)
    }

    @Test
    fun aFullPageThatDoesNotMoveOn_orNamesNoNextRow_failsTheRead() = runBlocking<Unit> {
        val r = ItemRig()
        val same = page(r, full, 10_000_000L)
        r.server.trashPages = { WireResult.Ok(same, 200) }
        assertEquals(ItemFailure.Corrupt(ItemTransport.TRASH_INCOMPLETE), r.engine.deletedItems().failure())
        assertEquals(2, r.server.trashAfters.size, "the same page twice: the read stops")

        r.server.trashAfters.clear()
        r.server.trashPages = { WireResult.Ok(page(r, full - 1, 10_000_000L) + DeletedItem("not-a-uuid", r.personal, 1), 200) }
        assertEquals(ItemFailure.Corrupt(ItemTransport.TRASH_INCOMPLETE), r.engine.deletedItems().failure())
        assertEquals(1, r.server.trashAfters.size)
    }
}
