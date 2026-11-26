package io.silencelen.andvari.core.app.content

import io.silencelen.andvari.core.app.ActionResult
import io.silencelen.andvari.core.app.AttachmentRules
import io.silencelen.andvari.core.app.InMemoryBlobs
import io.silencelen.andvari.core.app.InMemoryFillSnapshots
import io.silencelen.andvari.core.app.InMemorySaveQueue
import io.silencelen.andvari.core.app.LoginInput
import io.silencelen.andvari.core.client.ItemDoc
import io.silencelen.andvari.core.client.items.DurableCache
import io.silencelen.andvari.core.client.items.ItemFailure
import io.silencelen.andvari.core.client.items.ItemRig
import io.silencelen.andvari.core.client.onboard.OpenedAccount
import io.silencelen.andvari.core.crypto.Bytes
import io.silencelen.andvari.core.crypto.KdfParams
import io.silencelen.andvari.core.trust.GenesisFields
import io.silencelen.andvari.core.trust.VerifiedGenesis
import kotlinx.coroutines.runBlocking
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue

/**
 * A refusal for good of a kept save's queued change survives a lock and a restart until every kept save of its item was
 * judged by it: it is kept with the kept save's own record at rest. The walk of [KeptSaveRefusalJudgedTest] (two saves
 * with files of one item; the first one's change refused for good; the second one's change waiting at the next sync,
 * then landing), with the content closed and made again at one of its steps. Over the real item engine, on a copy kept
 * at rest.
 */
class KeptRefusalAcrossLockTest {
    private class Stores {
        val moves = InMemoryFillSnapshots()
        val keptSaves = InMemoryFillSnapshots()
        val files = InMemoryBlobs()
        val applied = InMemoryFillSnapshots()
        val queue = InMemorySaveQueue()
    }

    /** One unlock of the same account: the same keys, a new object. */
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

    private fun content(r: ItemRig, s: Stores, restarted: Boolean): EngineVaultContent {
        val engine = if (restarted) r.restarted() else r.engine
        return EngineVaultContent(engine, r.crypto, TestHost(r), ContentKeeping(unlock(r), s.moves, s.keptSaves, s.files, s.applied, s.queue))
    }

    /** Where the content is closed and made again. */
    private enum class Cut { AFTER_THE_REFUSAL, BEFORE_THE_LANDING }

    private fun walk(cut: Cut, restarted: Boolean) = runBlocking<Unit> {
        val cache = DurableCache()
        val r = ItemRig(cache)
        r.server.echo = true
        r.server.journal = true
        val s = Stores()
        var c = content(r, s, restarted = false)
        assertEquals(ActionResult.Ok, c.saveLogin(null, login("Passport"), null))
        val id = c.state.items.single { it.name == "Passport" }.itemId

        // 1. The first save with a file: the server answers "for now", so its change waits and the save stays kept.
        c.openAttachmentDraft(id)
        assertEquals(ActionResult.Ok, c.addAttachment("first.pdf", "one".encodeToByteArray()))
        r.server.refuseWith = 503 to "unavailable"
        assertEquals(ActionResult.Ok, c.saveLogin(id, login("Passport"), null))
        assertNotNull(s.keptSaves.bytes)

        // 2. A save of another item drains the queue: the server refuses the first save's change for good.
        r.server.refuseWith = null
        r.server.rejectItems[id] = "item_too_large"
        assertEquals(ActionResult.Ok, c.saveLogin(null, login("Bank"), null))
        assertTrue(cache.pending().none { it.itemId == id }, "the refused change left the queue")
        r.server.rejectItems.remove(id)

        if (cut == Cut.AFTER_THE_REFUSAL) {
            c.close()
            c = content(r, s, restarted)
        }

        // 3. The second save with a file of the same item, whose change waits.
        c.openAttachmentDraft(id)
        assertEquals(ActionResult.Ok, c.addAttachment("second.pdf", "two".encodeToByteArray()))
        r.server.refuseWith = 503 to "unavailable"
        assertEquals(ActionResult.Ok, c.saveLogin(id, login("Passport"), null))
        assertTrue(cache.pending().any { it.itemId == id }, "the second change waits")

        // 4. A sync whose push is answered with no result for that change: it still waits.
        r.server.refuseWith = null
        r.server.emptyResultsVaults += r.personal
        assertEquals(ActionResult.Ok, c.syncQuietly())
        r.server.emptyResultsVaults.clear()
        assertTrue(cache.pending().any { it.itemId == id }, "and still waits after the sync")
        val lost = ContentCopy.forFailure(ItemFailure.Refused("item_too_large", 400), ContentCopy.During.SAVE)
        val givenUp = ContentCopy.keptSaveGivenUp("Passport", newItem = false, files = 1, why = lost)
        assertTrue(c.state.notice != givenUp, "not judged while a change of its item waits")

        if (cut == Cut.BEFORE_THE_LANDING) {
            c.close()
            c = content(r, s, restarted)
        }

        // 5. The second change lands: the first save is judged by the refusal, let go and said.
        assertEquals(ActionResult.Ok, c.syncQuietly())
        println("cut $cut, restarted $restarted: notice ${c.state.notice}, kept ${s.keptSaves.bytes?.size}, files ${s.files.ids()}")
        assertTrue(cache.pending().isEmpty())
        assertEquals(givenUp, c.state.notice, "the first save is let go and said, with what was lost")
        assertNull(s.keptSaves.bytes, "nothing stays kept")
        assertTrue(s.files.ids().isEmpty(), "and no file set aside")
        c.close()
    }

    @Test
    fun aLockBeforeTheLaterSaveLands_losesNoRefusal() = walk(Cut.BEFORE_THE_LANDING, restarted = false)

    @Test
    fun aRestartBeforeTheLaterSaveLands_losesNoRefusal() = walk(Cut.BEFORE_THE_LANDING, restarted = true)

    @Test
    fun aRestartRightAfterTheRefusal_losesNoRefusal() = walk(Cut.AFTER_THE_REFUSAL, restarted = true)

    private val json = Json { ignoreUnknownKeys = true; encodeDefaults = true }

    /** What is written at rest for a refusal: its reason and status, nothing else; a record without it reads as before. */
    @Test
    fun theRefusalAtRestHoldsOnlyItsReason_andAnOlderRecordReadsAsBefore() {
        val doc = ItemDoc(type = "login", name = "Passport")
        val waiting = KeptSave("s", "i", "i", "v", 3, doc, listOf("f"), queuedAt = 4)
        val marked = waiting.refusedWith(ItemFailure.Refused("item_too_large", 400))
        assertNotNull(marked)
        val written = json.parseToJsonElement(json.encodeToString(KeptSave.serializer(), marked)).jsonObject
        val refusal = written["refusal"]!!.jsonObject
        assertEquals(setOf("reason", "status"), refusal.keys, "the reason and its status only: no name, no content")
        assertEquals("item_too_large", refusal["reason"]!!.jsonPrimitive.content)
        assertEquals(ItemFailure.Refused("item_too_large", 400), marked.refusal!!.failure())
        assertEquals(ItemFailure.Denied(1), waiting.refusedWith(ItemFailure.Denied(1))!!.refusal!!.failure())
        assertNull(waiting.refusedWith(ItemFailure.Halted), "only a refusal for good is kept")
        assertNull(marked.judged().refusal)

        // A record of an older build, without the field: read as before, with no refusal.
        val older = JsonObject(written.filterKeys { it != "refusal" })
        val read = json.decodeFromString(KeptSave.serializer(), older.toString())
        assertNull(read.refusal)
        assertEquals(listOf("s", "i", "i", "v"), listOf(read.id, read.itemId, read.newItemId, read.vaultId))
        assertEquals(4L, read.queuedAt)
        assertEquals(listOf("f"), read.newFiles)
    }
}
