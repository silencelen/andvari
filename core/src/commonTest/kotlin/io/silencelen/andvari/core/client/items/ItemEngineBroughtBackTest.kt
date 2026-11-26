package io.silencelen.andvari.core.client.items

import io.silencelen.andvari.core.app.content.ContentCopy
import kotlinx.coroutines.runBlocking
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertTrue

/**
 * A change of this device that brings back an item deleted elsewhere (spec 03 §5: the server answers the put with the
 * deletion's mark, every time, and keeps the item as the change made it): no "(conflict)" copy of the very item that
 * came back, and it is said once, in one notice per vault. The general rule for an edit that meets a deletion is the
 * server's and is not touched here.
 */
class ItemEngineBroughtBackTest {
    /** Saved here, then deleted elsewhere (the server holds its deletion; this device has not seen it), then edited here. */
    private fun ItemRig.editOverADeletion(): String = runBlocking {
        server.echo = true
        server.journal = true
        val id = engine.save(null, doc, personal).ok().itemId
        server.itemRows[id] = tombstone(id, personal, ++server.rev)
        engine.save(id, doc.copy(name = "Router (edited)"), personal).ok()
        id
    }

    private fun ItemRig.copies(id: String) = server.pushes.flatten().filter { it.itemId != id }

    private fun ItemRig.broughtBack() = engine.notices().filter { it.kind == ItemNotice.ITEM_BROUGHT_BACK }

    @Test fun anEditOverADeletionElsewhereMakesNoCopyAndIsSaidOnce() = runBlocking<Unit> {
        val r = ItemRig()
        r.server.marksBroughtBack = false
        val id = r.editOverADeletion()
        assertTrue(r.engine.sync() is ItemResult.Ok)
        assertTrue(r.copies(id).isEmpty(), "no copy of the item that came back: ${r.copies(id)}")
        assertEquals(listOf("Router (edited)"), r.engine.items().map { it.doc.name }, "the item is back once, as the change made it")
        val notice = r.broughtBack().single()
        assertEquals(1, notice.count)
        assertEquals("Router (edited)", notice.itemName)
        assertEquals(r.personal, notice.vaultId)
        // A line of its own (never the general "something changed"), naming the item; not a warning.
        val (line, warning) = ContentCopy.notice(notice)
        assertTrue("Router (edited)" in line, line)
        assertFalse(line == ContentCopy.notice(notice.copy(kind = "unknown-kind")).first)
        assertFalse(warning)
    }

    /**
     * An older server stored the row it brought back with the conflict mark: the mark is cleared and nothing is copied,
     * because this device's own put brought it back and displaced no version. Said once.
     */
    @Test fun aMarkAnOlderServerSetOnTheItemThatCameBackMakesNoCopy() = runBlocking<Unit> {
        val r = ItemRig()
        val id = r.editOverADeletion()
        assertTrue(r.engine.sync() is ItemResult.Ok)
        assertTrue(r.copies(id).none { r.pushedDoc(it).name.contains("(conflict") }, "no conflict copy: ${r.copies(id).map { r.pushedDoc(it).name }}")
        assertFalse(r.server.itemRows.getValue(id).conflict, "the mark was cleared")
        assertEquals(1, r.engine.items().size)
        assertEquals(1, r.broughtBack().size)
    }

    /** Two changes in one vault that each brought an item back: one notice, which counts them. */
    @Test fun twoItemsBroughtBackInOneVaultAreOneNoticeThatCountsThem() = runBlocking<Unit> {
        val r = ItemRig()
        r.server.marksBroughtBack = false
        r.editOverADeletion()
        val second = r.engine.save(null, r.doc.copy(name = "Printer"), r.personal).ok().itemId
        r.server.itemRows[second] = r.tombstone(second, r.personal, ++r.server.rev)
        r.engine.save(second, r.doc.copy(name = "Printer (edited)"), r.personal).ok()
        val notice = r.broughtBack().single()
        assertEquals(2, notice.count)
        assertEquals(null, notice.itemName)
    }
}
