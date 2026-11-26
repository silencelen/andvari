package io.silencelen.andvari.core.client.items

import io.silencelen.andvari.core.app.ActionResult
import io.silencelen.andvari.core.app.AttachmentRules
import io.silencelen.andvari.core.app.content.ContentHost
import io.silencelen.andvari.core.app.content.EngineVaultContent
import io.silencelen.andvari.core.client.InMemoryVaultCache
import io.silencelen.andvari.core.client.ItemDoc
import io.silencelen.andvari.core.client.LoginData
import io.silencelen.andvari.core.crypto.KdfParams
import io.silencelen.andvari.core.model.wire.ItemVersion
import io.silencelen.andvari.core.model.wire.SyncItem
import kotlinx.coroutines.runBlocking
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue

/**
 * Opening the trash without one call per item: the device keeps the last envelope of an item it held when the tombstone
 * is applied, opens the trash's rows from it with no call, and reads only what it never held, a bounded number, newest
 * first. The kept envelopes go when the item is restored or purged, when its vault goes, and with the account's cache.
 */
class TrashKeptTest {
    private fun doc(i: Int) = ItemDoc(type = "login", name = "Site $i", login = LoginData(username = "user$i", password = "made-up-$i"))

    /** Deliver [rows] on a pull past every cursor so far, and store them as the server's. */
    private fun deliver(r: ItemRig, rows: List<SyncItem>) {
        rows.forEach { r.server.itemRows[it.itemId] = it }
        r.server.rev += 10_000
        r.server.queue.add(r.response(r.server.rev, items = rows))
        runBlocking { r.engine.sync().ok() }
    }

    /** [count] items this device held, then deleted on the server (by another device) and pulled as tombstones. */
    private fun heldThenDeleted(r: ItemRig, count: Int, vaultId: String = r.personal, key: ByteArray = r.personalKey): List<String> {
        val ids = (0 until count).map { r.id() }
        deliver(r, ids.mapIndexed { i, id -> r.itemRow(id, vaultId, key, doc(i), rev = r.server.rev + 1 + i) })
        deliver(r, ids.mapIndexed { i, id -> r.tombstone(id, vaultId, r.server.rev + 1 + i) })
        return ids
    }

    /** [count] items deleted on the server that this device never held: tombstones, with their last version kept there. */
    private fun neverHeld(r: ItemRig, count: Int): List<String> {
        val ids = (0 until count).map { r.id() }
        val base = r.server.rev
        ids.forEachIndexed { i, id ->
            val row = r.itemRow(id, r.personal, r.personalKey, doc(i), rev = base + 1 + i)
            r.server.versions[id] = mutableListOf(ItemVersion(row.rev, row.blob!!, row.formatVersion, base + 1 + i))
        }
        deliver(r, ids.mapIndexed { i, id -> r.tombstone(id, r.personal, base + 1000 + i) })
        return ids
    }

    private fun kept(r: ItemRig, itemId: String): String? = r.cache.clientState(ItemStore.TRASH_PREFIX + itemId)

    private fun ItemEngine.keptIds(r: ItemRig): List<String> = ItemStore(r.cache).trashedIds()

    @Test
    fun aTrashOf300ItemsThisDeviceHeld_opensWithOneCall_andNoneAnItemsHistory() = runBlocking<Unit> {
        val r = ItemRig()
        val ids = heldThenDeleted(r, 300)
        val calls = r.server.calls
        val rows = r.engine.deletedItems().ok()
        assertEquals(1, r.server.calls - calls, "one page of the list, and nothing per row (it was 301 calls)")
        assertTrue(r.server.versionsRead.isEmpty())
        assertEquals(300, rows.size)
        assertTrue(rows.all { it.doc != null && !it.notRead })
        assertEquals("Site 299", rows.first().doc?.name, "newest deletion first, named from what this device held")
        assertEquals(ids.toSet(), rows.mapTo(HashSet()) { it.itemId })
    }

    @Test
    fun aTrashOf300ItemsNeverHeld_readsTheNewest20_andSaysTheRestAreNotReadYet() = runBlocking<Unit> {
        val r = ItemRig()
        neverHeld(r, 300)
        val calls = r.server.calls
        val rows = r.engine.deletedItems().ok()
        assertEquals(1 + ItemEngine.TRASH_FETCH_MAX, r.server.calls - calls, "one page and at most 20 rows read (it was 301)")
        assertEquals((299 downTo 280).map { "Site $it" }, rows.take(20).map { it.doc?.name }, "the newest first")
        assertTrue(rows.drop(20).all { it.doc == null && it.notRead }, "the rest say they are not read yet")

        // Each opening reads further; what was read stays read.
        val again = r.engine.deletedItems().ok()
        assertEquals(2 * (1 + ItemEngine.TRASH_FETCH_MAX), r.server.calls - calls)
        assertEquals(40, again.count { it.doc != null })
    }

    @Test
    fun aRowThisDeviceNeverHeld_isReadWhenItIsRestored_andComesBack() = runBlocking<Unit> {
        val r = ItemRig()
        val ids = neverHeld(r, 30)
        r.server.echo = true
        val c = EngineVaultContent(r.engine, r.crypto, Host(r))
        assertEquals(ActionResult.Ok, c.openTrash())
        val oldest = ids.first()
        val row = c.state.trash!!.single { it.itemId == oldest }
        assertTrue(row.notReadYet)
        assertNull(row.name)
        assertTrue(row.canRestore, "it can be restored: the restore reads it first")
        val reads = r.server.versionsRead.size
        assertEquals(ActionResult.Ok, c.restoreFromTrash(oldest))
        assertEquals(reads + 1, r.server.versionsRead.size, "one read, for this row")
        val (restoredId, upload) = r.server.restored.single()
        assertEquals(oldest, restoredId)
        assertEquals("Site 0", r.pushedDoc(io.silencelen.andvari.core.model.wire.Mutation("m", "put", oldest, r.personal, 0, upload)).name)
        assertEquals("Site 0", c.state.items.single { it.itemId == oldest }.name, "live again")
    }

    @Test
    fun theKeptEnvelopeGoes_whenTheItemIsPurged_orRestored() = runBlocking<Unit> {
        val r = ItemRig()
        val (a, b) = heldThenDeleted(r, 2)
        assertNotNull(kept(r, a))
        assertNotNull(kept(r, b))
        r.engine.purgeDeleted(a, r.personal).ok()
        assertNull(kept(r, a), "purged")
        r.engine.restoreDeleted(b, r.personal, doc(1)).ok()
        assertNull(kept(r, b), "restored")
        assertTrue(r.engine.keptIds(r).isEmpty())
    }

    @Test
    fun theKeptEnvelopesGo_whenTheirVaultGoes() = runBlocking<Unit> {
        val r = ItemRig()
        r.openShared()
        val mine = heldThenDeleted(r, 1).single()
        val theirs = heldThenDeleted(r, 2, r.shared, r.sharedKey)
        theirs.forEach { assertNotNull(kept(r, it)) }
        r.keys.onServed = { report -> if (r.shared in report.lostAccess) r.keys.depart(r.shared, VaultDeparture.REMOVED) }
        r.server.queue.add(r.response(r.server.rev + 5000, removed = listOf(r.shared)))
        r.engine.sync().ok()
        theirs.forEach { assertNull(kept(r, it), "the vault went") }
        assertNotNull(kept(r, mine), "the personal vault's stay")
    }

    @Test
    fun theKeptEnvelopesArePruned_againstAWholeReadOfTheTrash() = runBlocking<Unit> {
        val r = ItemRig()
        val (a, b) = heldThenDeleted(r, 2)
        // Purged on another device: the server no longer lists it.
        r.server.itemRows.remove(a)
        r.engine.deletedItems().ok()
        assertNull(kept(r, a))
        assertNotNull(kept(r, b))
    }

    @Test
    fun theKeptEnvelopesLiveInTheAccountsCacheOnly_soTheyGoWithIt() = runBlocking<Unit> {
        val cache = InMemoryVaultCache()
        val r = ItemRig(cache)
        val ids = heldThenDeleted(r, 3)
        assertEquals(ids, r.engine.keptIds(r))
        // The account leaves the device: its cache is deleted (a sign-out, a removal). The same account on a new
        // cache (the same server and keys) holds nothing of the trash, and reads its rows from the server again.
        val fresh = ItemRig(InMemoryVaultCache())
        fresh.server.itemRows.putAll(r.server.itemRows)
        fresh.server.versions.putAll(r.server.versions)
        assertTrue(fresh.engine.keptIds(fresh).isEmpty())
        val calls = fresh.server.versionsRead.size
        fresh.engine.deletedItems().ok()
        assertEquals(calls + 3, fresh.server.versionsRead.size)
    }

    @Test
    fun theKeptEnvelopesAreCapped_theOldestKeptGoingFirst() = runBlocking<Unit> {
        val r = ItemRig()
        val first = heldThenDeleted(r, 3)
        val more = heldThenDeleted(r, ItemStore.TRASH_KEEP_MAX)
        assertEquals(ItemStore.TRASH_KEEP_MAX, r.engine.keptIds(r).size)
        first.forEach { assertNull(kept(r, it)) }
        assertNotNull(kept(r, more.last()))
        assertFalse(r.engine.keptIds(r).any { it in first })
    }

    @Test
    fun theFakePlaysARowNotReadYet_asTheEngineDoes() = runBlocking<Unit> {
        val c = io.silencelen.andvari.core.app.content.FakeVaultContent()
        val id = c.seedDeleted(io.silencelen.andvari.core.app.content.FakeVaultContent.PERSONAL_VAULT_ID, "Old bank", "ana", 3, notReadYet = true)
        assertEquals(ActionResult.Ok, c.openTrash())
        val row = c.state.trash!!.single()
        assertTrue(row.notReadYet)
        assertNull(row.name)
        assertTrue(row.canRestore)
        assertEquals(0, c.trashDocReads)
        assertEquals(ActionResult.Ok, c.restoreFromTrash(id))
        assertEquals(1, c.trashDocReads)
        assertEquals("Old bank", c.state.items.single().name)
    }

    private class Host(val r: ItemRig) : ContentHost {
        override fun wallMs(): Long = r.now
        override fun attachmentLimits() = AttachmentRules.limits(null, null)
        override fun origin(): String = "https://vault.example.com"
        override fun userId(): String = r.userId
        override fun accountId(): String = "0123456789abcdef0123456789abcdef"
        override fun backupKdfParams(): KdfParams? = null
    }
}
