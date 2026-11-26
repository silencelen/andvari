package io.silencelen.andvari.hostile

import io.silencelen.andvari.cli.Host
import io.silencelen.andvari.cli.e2e.doc
import io.silencelen.andvari.cli.e2e.synced
import io.silencelen.andvari.core.client.DeletedItemView
import io.silencelen.andvari.core.client.items.ItemEngine
import io.silencelen.andvari.core.client.items.ItemFailure
import io.silencelen.andvari.core.client.items.ItemResult
import io.silencelen.andvari.core.client.items.ItemTransport
import io.silencelen.andvari.core.model.wire.DeletedItem
import io.silencelen.andvari.core.model.wire.DeletedItemsResponse
import io.silencelen.andvari.core.model.wire.WireJson
import io.silencelen.andvari.core.model.wire.WireRoute
import io.silencelen.andvari.hostile.proxy.Resp
import java.net.URLDecoder
import java.util.UUID
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertIs
import kotlin.test.assertNotNull
import kotlin.test.assertTrue

/**
 * The deleted-items list in pages (spec 03 §5.1; `ItemEngine.trashRows` in core), lied to: a page that loops, a list
 * that never ends, and a page of another account's rows. The device asks for at most [ItemEngine.TRASH_MAX_PAGES] pages
 * of at most [ItemTransport.TRASH_PAGE_ROWS] rows, has a list only once the last page arrived, fails the whole read when
 * any page breaks the rules (rows strictly descending, the first strictly after the cursor), and never shows a row of a
 * vault the account may not read as its own.
 */
class TrashPagesTest {
    private val full = ItemTransport.TRASH_PAGE_ROWS
    private val incomplete = ItemResult.Failed(ItemFailure.Corrupt(ItemTransport.TRASH_INCOMPLETE))
    private val newestFirst = compareByDescending<DeletedItem> { it.deletedAt }.thenByDescending { it.itemId }

    private fun page(rows: List<DeletedItem>): Resp =
        Resp(200, mapOf("Content-Type" to "application/json"), WireJson.json.encodeToString(DeletedItemsResponse.serializer(), DeletedItemsResponse(rows)).encodeToByteArray())

    private fun served(r: Resp): List<DeletedItem> = WireJson.json.decodeFromString(DeletedItemsResponse.serializer(), r.text).items

    /** [n] rows of new items in [vaultId], deleted at [top] and one millisecond earlier each: strictly descending. */
    private fun filler(vaultId: String, n: Int, top: Long): List<DeletedItem> = List(n) { DeletedItem(UUID.randomUUID().toString(), vaultId, top - it) }

    /** A member [tag] with two items of their personal vault deleted; the ids of the two. */
    private suspend fun World.trashed(tag: String): Pair<Host, Set<String>> {
        val h = member(tag)
        val a = account(h)
        a.synced()
        val v = assertNotNull(a.personalVaultId)
        val ids = listOf("one", "two").map { n ->
            val (saved, err) = a.putItem(v, doc("$tag $n"))
            assertEquals(null, err, "$tag saves $n")
            saved!!.itemId
        }
        a.synced()
        for (id in ids) assertEquals(null, a.deleteItem(id).second, "$tag deletes $id")
        a.synced()
        return h to ids.toSet()
    }

    private suspend fun World.trash(h: Host): ItemResult<List<DeletedItemView>> = account(h).items.deletedItems()

    private suspend fun World.trashIds(h: Host): Set<String> =
        assertIs<ItemResult.Ok<List<DeletedItemView>>>(trash(h), "the trash reads").value.map { it.itemId }.toSet()

    /**
     * The real first page, made full: served again for the cursor; then a second page that starts above the cursor; then
     * one that brings back a row of the first page among new rows. Each fails the whole read at the second request, and
     * nothing of either page is shown; the honest trash then reads.
     */
    @Test fun aTrashPageThatLoopsFailsTheWholeRead() = world {
        operator()
        val (ah, mine) = trashed("alice")
        assertEquals(mine, trashIds(ah), "the honest trash: one page, no cursor")
        val v = account(ah).personalVaultId!!
        var first: List<DeletedItem>? = null
        fun firstOf(x: io.silencelen.andvari.hostile.proxy.Ctx): List<DeletedItem> =
            first ?: served(x.forward()).let { real -> real + filler(v, full - real.size, real.last().deletedAt - 1) }.also { first = it }

        val lies: List<Pair<String, (List<DeletedItem>) -> List<DeletedItem>>> = listOf(
            "the first page again" to { f -> f },
            "a page that starts above the cursor" to { f -> listOf(DeletedItem(UUID.randomUUID().toString(), v, f.first().deletedAt + 1)) },
            "a row of the first page again, among new rows" to { f -> filler(v, 3, f.last().deletedAt - 1) + f[0] },
        )
        for ((why, second) in lies) {
            proxy.honest()
            proxy.on(WireRoute.ITEMS_DELETED, "alice") { x -> if (x.req.queryParam("after") == null) page(firstOf(x)) else page(second(first!!)) }
            val mark = proxy.mark()
            assertEquals(incomplete, trash(ah), why)
            assertEquals(2, sent(ah, WireRoute.ITEMS_DELETED, mark).size, "$why: the loop is seen on the second page")
        }
        proxy.honest()
        assertEquals(mine, trashIds(ah), "the honest trash again")
        assertTrue(sent(ah, WireRoute.ITEM_RESTORE).isEmpty() && sent(ah, WireRoute.ITEM_PURGE).isEmpty(), "nothing restored or purged")
    }

    /**
     * Every page full of new rows, each page below the one before: the device asks for exactly
     * [ItemEngine.TRASH_MAX_PAGES] pages, each after the last row of the page before, shows no trash, and the honest trash
     * then reads. A page of one row more than [ItemTransport.TRASH_PAGE_ROWS] is refused at once.
     */
    @Test fun aTrashListThatNeverEndsStopsAtTheStatedNumberOfPages() = world {
        operator()
        val (ah, mine) = trashed("alice")
        val v = account(ah).personalVaultId!!
        var top = 1_790_000_000_000L
        proxy.on(WireRoute.ITEMS_DELETED, "alice") { _ -> page(filler(v, full, top).also { top -= full }) }
        val mark = proxy.mark()
        assertEquals(incomplete, trash(ah))
        val asked = proxy.log().drop(mark).filter { it.req.route == WireRoute.ITEMS_DELETED }
        assertEquals(ItemEngine.TRASH_MAX_PAGES, asked.size, "the stated number of pages, then it stops")
        for ((i, x) in asked.withIndex()) {
            val after = x.req.queryParam("after")?.let { URLDecoder.decode(it, Charsets.UTF_8) }
            if (i == 0) assertEquals(null, after) else served(asked[i - 1].served!!).last().let { assertEquals("${it.deletedAt}:${it.itemId}", after, "page $i") }
        }

        proxy.honest()
        proxy.on(WireRoute.ITEMS_DELETED, "alice") { _ -> page(filler(v, full + 1, top)) }
        val once = proxy.mark()
        assertEquals(incomplete, trash(ah), "a page of one row too many")
        assertEquals(1, sent(ah, WireRoute.ITEMS_DELETED, once).size)

        proxy.honest()
        assertEquals(mine, trashIds(ah), "the honest trash again")
    }

    /**
     * Bob's own deleted items served as Alice's page, whole or mixed into hers in their place in the order: none of
     * Bob's rows is ever shown in Alice's trash (a row of a vault she may not read is left out), and her own rows are.
     */
    @Test fun aTrashPageOfAnotherAccountsRowsIsNeverShownAsTheAccountsOwn() = world {
        operator()
        val (ah, mine) = trashed("alice")
        val (bh, bobs) = trashed("bob")
        assertEquals(bobs, trashIds(bh))
        val bobsPage = served(proxy.last(WireRoute.ITEMS_DELETED, "bob")!!.served!!)
        assertEquals(bobs, bobsPage.map { it.itemId }.toSet())

        proxy.on(WireRoute.ITEMS_DELETED, "alice") { _ -> page(bobsPage) }
        assertEquals(emptySet(), trashIds(ah), "Bob's whole page as Alice's: none of it is hers")

        proxy.honest()
        proxy.on(WireRoute.ITEMS_DELETED, "alice") { x -> page((served(x.forward()) + bobsPage).sortedWith(newestFirst)) }
        assertEquals(mine, trashIds(ah), "Bob's rows mixed into hers: only hers are shown")
    }
}
