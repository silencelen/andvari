package io.silencelen.andvari.core.client.items

import kotlinx.coroutines.runBlocking
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertIs
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue

/** The item engine against its two seams: what it asks of the key source, what it tells it, and what it refuses. */
class ItemEngineSeamTest {
    @Test
    fun aSaveIntoThePersonalVault_roundTripsThroughTheTransport() = runBlocking<Unit> {
        val r = ItemRig()
        val saved = r.engine.save(null, r.doc).ok()
        assertEquals(Written.APPLIED, saved.outcome)
        val m = r.server.pushes.single().single()
        assertEquals(r.personal, m.vaultId, "a new item with no destination goes to the genesis personal vault")
        assertEquals("Router", r.pushedDoc(m).name)
        assertNull(ItemCodec.logHeadOf(r.pushedDoc(m)), "an item in the personal vault carries no log head")
        // The reconcile pull delivers the stored row; the working set shows it.
        r.serve(r.server.itemRows.getValue(saved.itemId))
        r.engine.sync().ok()
        assertEquals("Router", r.engine.item(saved.itemId)?.doc?.name)
    }

    @Test
    fun noPersonalVault_meansNoDefaultDestination() = runBlocking<Unit> {
        val r = ItemRig()
        r.keys.personalVaultId = null
        r.keys.open.remove(r.personal)
        assertEquals(ItemFailure.NotAllowed(ItemRefusal.NO_PERSONAL_VAULT), r.engine.save(null, r.doc).failure())
        assertTrue(r.server.pushes.isEmpty())
        assertTrue(r.engine.vaults().isEmpty(), "the served `personal` label opens nothing")
    }

    @Test
    fun theTrustEngineHearsOfAPullBeforeAnyOfItsItemsIsRead_andOfTheHeadsTheyCarry() = runBlocking<Unit> {
        val r = ItemRig()
        val head = LogHeadStamp(4, "cd".repeat(32))
        val id = r.id()
        val row = r.itemRow(id, r.shared, r.sharedKey, ItemCodec.stamped(r.doc, head))
        // The key source opens the vault only when it is told of the served rows, as the vault-log engine would.
        r.keys.onServed = { report -> if (report.vaults.any { it.vaultId == r.shared }) r.keys.put(r.shared, r.sharedKey, "writer") }
        r.keys.trail.clear()
        r.server.queue.add(r.response(9, vaults = listOf(r.vaultRow(r.shared, r.sharedKey, "shared", "Family", head = io.silencelen.andvari.core.model.wire.SyncLogHead(4, head.hash))), grants = listOf(r.grantRow(r.shared)), items = listOf(row)))
        r.engine.sync().ok()

        val report = r.keys.reports.last()
        assertEquals(4, report.vaults.single().logHead?.seq, "the served head rides the report as served")
        assertEquals(r.shared, report.grants.single().vaultId)
        assertTrue(r.keys.trail.indexOf("served") < r.keys.trail.indexOf("key:${r.shared}"), "served() comes before the shared key is asked for: ${r.keys.trail}")
        assertEquals(listOf(Triple(r.shared, 4L, head.hash)), r.keys.heads, "the item's head is reported as a hint")
        assertEquals("Router", r.engine.item(id)?.doc?.name)
        assertEquals(listOf("personal", "shared"), r.engine.vaults().map { it.type })
    }

    @Test
    fun aVaultTheKeySourceDoesNotList_staysCiphertext_untilItOpens() = runBlocking<Unit> {
        val r = ItemRig()
        val id = r.id()
        r.server.queue.add(r.response(9, vaults = listOf(r.vaultRow(r.shared, r.sharedKey, "shared", "Family")), grants = listOf(r.grantRow(r.shared)), items = listOf(r.itemRow(id, r.shared, r.sharedKey))))
        r.engine.sync().ok()
        assertNull(r.engine.item(id), "not accepted: nothing is decrypted")
        assertEquals(listOf("personal"), r.engine.vaults().map { it.type })
        assertTrue(id in r.engine.liveItemIds(), "the envelope is kept: its rev passed the cursor")

        // The person accepts (the vault-log engine adopts the key); the next cycle reads the rows it already holds.
        r.keys.put(r.shared, r.sharedKey, "reader")
        r.engine.sync().ok()
        assertEquals("Router", r.engine.item(id)?.doc?.name)
        assertEquals(false, r.engine.vaults().single { it.type == "shared" }.writable, "a reader reads and does not write")
    }

    @Test
    fun aWriteToASharedVaultCarriesItsVerifiedHead_andACopyToPersonalDropsIt() = runBlocking<Unit> {
        val r = ItemRig()
        r.openShared(head = LogHeadStamp(3, "ab".repeat(32)))
        val saved = r.engine.save(null, r.doc, vaultId = r.shared).ok()
        val m = r.server.pushes.last().single()
        val head = assertNotNull(ItemCodec.logHeadOf(r.pushedDoc(m, r.sharedKey)), "spec 02 §3: a writer stamps the verified head")
        assertEquals(3, head.seq)
        assertEquals("ab".repeat(32), head.hash)

        r.serve(r.server.itemRows.getValue(saved.itemId))
        r.engine.sync().ok()
        val plan = r.engine.planMove(saved.itemId, r.personal, deleteSource = false).ok()
        r.engine.runMove(plan, finalSync = false).ok()
        val copy = r.server.pushes.last().single()
        assertEquals(r.personal, copy.vaultId)
        assertNull(ItemCodec.logHeadOf(r.pushedDoc(copy)), "the copy's old head named another vault's log")
    }

    @Test
    fun nothingIsSealedOrSentToAVaultThatIsNotVerified_orByAReader() = runBlocking<Unit> {
        val r = ItemRig(io.silencelen.andvari.core.client.InMemoryVaultCache())
        val id = r.id()
        r.openShared(items = listOf(r.itemRow(id, r.shared, r.sharedKey)))
        for (standing in listOf(VaultStanding.FROZEN, VaultStanding.FAILED, VaultStanding.WITHHELD)) {
            r.keys.open.getValue(r.shared).standing = standing
            val pushes = r.server.pushes.size
            assertEquals(ItemFailure.NotAllowed(ItemRefusal.VAULT_READ_ONLY), r.engine.save(id, r.doc.copy(name = "edited"), vaultId = r.shared).failure(), "$standing")
            assertEquals(ItemFailure.NotAllowed(ItemRefusal.VAULT_READ_ONLY), r.engine.save(null, r.doc, vaultId = r.shared).failure(), "$standing")
            assertEquals(ItemFailure.NotAllowed(ItemRefusal.VAULT_READ_ONLY), r.engine.remove(id).failure(), "$standing")
            assertEquals(pushes, r.server.pushes.size, "$standing: nothing was sent")
            assertEquals("Router", r.engine.item(id)?.doc?.name, "$standing: what is held stays readable")
            // Copying OUT stays allowed (design §3.6): it writes only under the destination's key.
            val plan = r.engine.planMove(id, r.personal, deleteSource = false).ok()
            r.engine.runMove(plan, finalSync = false).ok()
            assertEquals(r.personal, r.server.pushes.last().single().vaultId)
            // A MOVE out is a write to the source: refused.
            assertEquals(ItemFailure.NotAllowed(ItemRefusal.VAULT_READ_ONLY), r.engine.runMove(r.engine.planMove(id, r.personal, deleteSource = true).ok()).failure())
        }
        r.keys.open.getValue(r.shared).standing = VaultStanding.VERIFIED
        r.keys.open.getValue(r.shared).role = VaultAccess.ROLE_READER
        assertEquals(ItemFailure.NotAllowed(ItemRefusal.VAULT_READ_ONLY), r.engine.save(id, r.doc, vaultId = r.shared).failure())
    }

    @Test
    fun aKeyTheSourceDoesNotOffer_isNeverUsed() = runBlocking<Unit> {
        val r = ItemRig()
        val id = r.id()
        r.openShared(items = listOf(r.itemRow(id, r.shared, r.sharedKey)))
        r.keys.open.remove(r.shared)
        assertIs<ItemFailure.NotAllowed>(r.engine.save(null, r.doc, vaultId = r.shared).failure())
        assertEquals(ItemFailure.NotAllowed(ItemRefusal.VAULT_NOT_OPEN), r.engine.save(null, r.doc, vaultId = r.shared).failure())
        assertTrue(r.engine.vaults().none { it.vaultId == r.shared })
    }
}
