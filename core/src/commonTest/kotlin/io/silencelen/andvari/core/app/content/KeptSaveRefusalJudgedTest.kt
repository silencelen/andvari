package io.silencelen.andvari.core.app.content

import io.silencelen.andvari.core.app.ActionResult
import io.silencelen.andvari.core.app.AttachmentRules
import io.silencelen.andvari.core.app.InMemoryBlobs
import io.silencelen.andvari.core.app.InMemoryFillSnapshots
import io.silencelen.andvari.core.app.InMemorySaveQueue
import io.silencelen.andvari.core.app.LoginInput
import io.silencelen.andvari.core.client.VaultCache
import io.silencelen.andvari.core.client.items.DurableCache
import io.silencelen.andvari.core.client.items.ItemFailure
import io.silencelen.andvari.core.client.items.ItemRig
import io.silencelen.andvari.core.client.onboard.OpenedAccount
import io.silencelen.andvari.core.crypto.Bytes
import io.silencelen.andvari.core.crypto.KdfParams
import io.silencelen.andvari.core.trust.GenesisFields
import io.silencelen.andvari.core.trust.VerifiedGenesis
import kotlinx.coroutines.runBlocking
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNotNull
import kotlin.test.assertTrue

/**
 * Two saves with files of one item, both kept until their change lands. The first one's queued change is refused for
 * good by a drain that a save of another item makes; the second one's change still waits in the queue at the next sync.
 * The refusal is not taken from the list there (the first save cannot be judged while a change of its item waits); once
 * the second one's change has landed, the first one is judged by that refusal: let go and said, with what was lost.
 * Over the real item engine, on a copy kept at rest.
 */
class KeptSaveRefusalJudgedTest {
    private class Stores {
        val moves = InMemoryFillSnapshots()
        val keptSaves = InMemoryFillSnapshots()
        val files = InMemoryBlobs()
        val applied = InMemoryFillSnapshots()
        val queue = InMemorySaveQueue()
    }

    private fun unlock(r: ItemRig): OpenedAccount {
        val seed = ByteArray(32) { 4 }
        val identity = r.crypto.boxKeypairFromSeed(seed)
        val genesis = VerifiedGenesis(GenesisFields(r.userId, Bytes.toB64(identity.publicKey), "instance", r.personal, 0), "00".repeat(32))
        return OpenedAccount(r.userId, ByteArray(32) { 1 }, identity, r.crypto.signKeypairFromSeed(seed), genesis, r.personal, ByteArray(32) { 7 })
    }

    private class TestHost(val r: ItemRig) : ContentHost {
        override fun wallMs(): Long = r.now
        override fun attachmentLimits() = AttachmentRules.limits(null, null)
        override fun origin(): String = "https://vault.example.com"
        override fun userId(): String = r.userId
        override fun accountId(): String = "0123456789abcdef0123456789abcdef"
        override fun backupKdfParams(): KdfParams? = null
        override fun offlineCacheAllowed(): Boolean = true
    }

    private fun login(name: String) = LoginInput(name, "me", "pw", listOf("https://example.com"), "", "", false)

    @Test
    fun aRefusalForGoodWaitsUntilEveryKeptSaveOfItsItemIsJudged() = runBlocking<Unit> {
        val cache: VaultCache = DurableCache()
        val r = ItemRig(cache)
        r.server.echo = true
        r.server.journal = true
        val s = Stores()
        val c = EngineVaultContent(r.engine, r.crypto, TestHost(r), ContentKeeping(unlock(r), s.moves, s.keptSaves, s.files, s.applied, s.queue))
        assertEquals(ActionResult.Ok, c.saveLogin(null, login("Passport"), null))
        val id = c.state.items.single { it.name == "Passport" }.itemId
        assertTrue(r.server.itemRows[id]?.deleted == false, "the item is on the server")

        // The first save with a file: the server answers "for now", so its change waits and the save stays kept.
        c.openAttachmentDraft(id)
        assertEquals(ActionResult.Ok, c.addAttachment("first.pdf", "one".encodeToByteArray()))
        r.server.refuseWith = 503 to "unavailable"
        assertEquals(ActionResult.Ok, c.saveLogin(id, login("Passport"), null))
        assertEquals(1, cache.pending().size)
        assertNotNull(s.keptSaves.bytes)

        // A save of another item drains the queue: the server refuses the first save's change for good.
        r.server.refuseWith = null
        r.server.rejectItems[id] = "item_too_large"
        assertEquals(ActionResult.Ok, c.saveLogin(null, login("Bank"), null))
        assertTrue(cache.pending().none { it.itemId == id }, "the refused change left the queue")
        r.server.rejectItems.remove(id)

        // The second save with a file of the same item, whose change waits ("for now") at the next sync.
        c.openAttachmentDraft(id)
        assertEquals(ActionResult.Ok, c.addAttachment("second.pdf", "two".encodeToByteArray()))
        r.server.refuseWith = 503 to "unavailable"
        assertEquals(ActionResult.Ok, c.saveLogin(id, login("Passport"), null))
        assertTrue(cache.pending().any { it.itemId == id }, "the second change waits")
        // The sync completes, but its push is answered with no result for that change: it still waits.
        r.server.refuseWith = null
        r.server.emptyResultsVaults += r.personal
        assertEquals(ActionResult.Ok, c.syncQuietly())
        r.server.emptyResultsVaults.clear()
        assertTrue(cache.pending().any { it.itemId == id }, "and still waits after the sync")
        val lost = ContentCopy.forFailure(ItemFailure.Refused("item_too_large", 400), ContentCopy.During.SAVE)
        val givenUp = ContentCopy.keptSaveGivenUp("Passport", newItem = false, files = 1, why = lost)
        println("after the sync with the second change waiting: notice ${c.state.notice}, kept ${s.keptSaves.bytes?.size}")
        assertTrue(c.state.notice != givenUp, "not judged while a change of its item waits")

        // The second change lands: the first save is judged now by the refusal, let go and said.
        assertEquals(ActionResult.Ok, c.syncQuietly())
        println("after the second change landed: notice ${c.state.notice}, kept ${s.keptSaves.bytes?.size}, files ${s.files.ids()}")
        assertTrue(cache.pending().isEmpty())
        assertEquals(givenUp, c.state.notice, "the first save is let go and said, with what was lost")
        assertEquals(null, s.keptSaves.bytes, "nothing stays kept")
        assertTrue(s.files.ids().isEmpty(), "and no file set aside")
        c.close()
    }
}
