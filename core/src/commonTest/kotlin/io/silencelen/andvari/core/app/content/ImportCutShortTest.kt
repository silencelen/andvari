package io.silencelen.andvari.core.app.content

import io.silencelen.andvari.core.app.ActionResult
import io.silencelen.andvari.core.app.AttachmentRules
import io.silencelen.andvari.core.app.CopyKey
import io.silencelen.andvari.core.app.ImportCopy
import io.silencelen.andvari.core.app.InMemoryBlobs
import io.silencelen.andvari.core.app.InMemoryFillSnapshots
import io.silencelen.andvari.core.app.InMemorySaveQueue
import io.silencelen.andvari.core.client.InMemoryVaultCache
import io.silencelen.andvari.core.client.VaultCache
import io.silencelen.andvari.core.client.items.DurableCache
import io.silencelen.andvari.core.client.items.ItemResult
import io.silencelen.andvari.core.client.items.ItemRig
import io.silencelen.andvari.core.client.items.LockedBeforeKept
import io.silencelen.andvari.core.client.items.Written
import io.silencelen.andvari.core.client.onboard.OpenedAccount
import io.silencelen.andvari.core.crypto.Bytes
import io.silencelen.andvari.core.crypto.KdfParams
import io.silencelen.andvari.core.crypto.KeysGoneException
import io.silencelen.andvari.core.trust.GenesisFields
import io.silencelen.andvari.core.trust.VerifiedGenesis
import kotlinx.coroutines.runBlocking
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertIs
import kotlin.test.assertNull
import kotlin.test.assertTrue
import kotlin.test.fail

/**
 * An import cut short follows the rule of a single save (the rule of 2026-11-17): on a copy kept only in memory nothing
 * of it stays queued behind a line that says it stopped, and the line says how many items were saved and how many were
 * not; those are not sent later behind the person's back, and a Retry imports them without making duplicates. On a copy
 * kept at rest the import is kept: the rest of it waits on this device, counted, and the line says so and when it goes.
 *
 * Every case runs the real item engine under the real content, with an import of 450 rows: the server takes the first
 * batch of 200, and the second push is the one that gets no answer, is refused, or is overtaken by a lock.
 */
class ImportCutShortTest {
    private class TestHost(val r: ItemRig) : ContentHost {
        override fun wallMs(): Long = r.now
        override fun attachmentLimits() = AttachmentRules.limits(null, null)
        override fun origin(): String = "https://vault.example.com"
        override fun userId(): String = r.userId
        override fun accountId(): String = "0123456789abcdef0123456789abcdef"
        override fun backupKdfParams(): KdfParams? = null
        override fun offlineCacheAllowed(): Boolean = true
    }

    private fun unlock(r: ItemRig): OpenedAccount {
        val seed = ByteArray(32) { 4 }
        val identity = r.crypto.boxKeypairFromSeed(seed)
        val genesis = VerifiedGenesis(GenesisFields(r.userId, Bytes.toB64(identity.publicKey), "instance", r.personal, 0), "00".repeat(32))
        return OpenedAccount(r.userId, ByteArray(32) { 1 }, identity, r.crypto.signKeypairFromSeed(seed), genesis, r.personal, ByteArray(32) { 7 })
    }

    private fun content(r: ItemRig): EngineVaultContent {
        r.server.echo = true
        r.server.journal = true
        val m = InMemoryFillSnapshots()
        return EngineVaultContent(r.engine, r.crypto, TestHost(r), ContentKeeping(unlock(r), m, InMemoryFillSnapshots(), InMemoryBlobs(), InMemoryFillSnapshots(), InMemorySaveQueue(), InMemoryFillSnapshots()))
    }

    private val rows = (1..450).joinToString("") { "Site $it,https://s$it.test,user$it,pw$it,\n" }

    /** What the app interface counts at a sign-out from the item engine's cache. */
    private fun unsent(cache: VaultCache) = cache.pending().size + cache.stagedDenied().size + cache.heldVaults().size

    /**
     * The import planned and confirmed; [atSecondPush] runs as the second push arrives, before it is answered. Answers
     * the content, with the import's line read off its state.
     */
    private suspend fun cutShort(cache: VaultCache, atSecondPush: (ItemRig) -> Unit): Pair<ItemRig, EngineVaultContent> {
        val r = ItemRig(cache)
        val c = content(r)
        c.syncQuietly()
        assertEquals(ActionResult.Ok, c.importCsv("name,url,username,password,note\n$rows".encodeToByteArray()))
        var pushes = 0
        r.server.hold = { route -> if (route == "push" && ++pushes == 2) atSecondPush(r) }
        assertEquals(ActionResult.Ok, c.confirmImport())
        r.server.hold = null
        return r to c
    }

    private fun EngineVaultContent.importLine(): String = state.csvImport?.error ?: fail("the import says nothing")

    private fun EngineVaultContent.names(): Set<String> = state.items.map { it.name }.toSet()

    @Test
    fun noAnswerInTheMiddle_onACopyInMemory_saysHowManyWereSavedAndNot_keepsNothing_andRetryImportsTheRestOnce() = runBlocking<Unit> {
        val cache = InMemoryVaultCache()
        val (r, c) = cutShort(cache) { it.server.offline = true }

        assertEquals(ContentCopy.importStopped(200, 250, null), c.importLine())
        assertTrue(c.importLine().endsWith(CopyKey.IMPORT_RETRY_THE_REST.fill(emptyList())), c.importLine())
        assertTrue(c.state.csvImport!!.retryable)
        assertFalse(c.state.csvImport!!.kept, "nothing was kept: the import stopped")
        assertEquals(0, unsent(cache), "nothing waits behind the line")

        // The server answers again: nothing the line called not saved goes by itself.
        r.server.offline = false
        val before = r.server.pushes.size
        assertEquals(ActionResult.Ok, c.syncQuietly())
        assertEquals(before, r.server.pushes.size, "nothing is sent behind the person's back")
        assertEquals(200, c.state.items.size, "the ones the line called saved")

        // The person's own Retry imports the rest, and nothing twice.
        assertEquals(ActionResult.Ok, c.confirmImport())
        assertEquals(null, c.state.csvImport?.error)
        assertEquals(450, r.server.itemRows.size)
        assertEquals((1..450).map { "Site $it" }.toSet(), c.names())
        assertEquals(450, c.state.items.size, "no duplicates")
    }

    @Test
    fun noAnswerInTheMiddle_onACopyKeptAtRest_keepsTheRest_countsIt_saysItIsKept_andSendsItWhenTheServerAnswers() = runBlocking<Unit> {
        val cache = DurableCache()
        val (r, c) = cutShort(cache) { it.server.offline = true }

        assertEquals(ContentCopy.importKept(250, Written.QUEUED), c.importLine())
        assertEquals(CopyKey.IMPORT_KEPT_MANY.fill(listOf("250")), c.importLine())
        assertFalse(c.state.csvImport!!.retryable, "nothing is left for a Retry to do")
        assertTrue(c.state.csvImport!!.kept, "kept, not failed: the view says so for the apps to draw")
        assertEquals(250, unsent(cache), "the rest waits on this device, counted")
        assertEquals(250, c.state.items.size, "the kept ones show at once, as a queued save does; the sent ones come with the next pull")

        r.server.offline = false
        assertEquals(ActionResult.Ok, c.syncQuietly())
        assertEquals(0, unsent(cache))
        assertEquals(450, r.server.itemRows.size)
        assertEquals(450, c.state.items.size)
    }

    @Test
    fun aRefusalForNowInTheMiddle_onACopyKeptAtRest_keepsTheRest_andSaysWhenItGoes() = runBlocking<Unit> {
        for ((status, how) in listOf(401 to Written.KEPT_SESSION_ENDED, 429 to Written.KEPT_TOO_MANY_REQUESTS, 503 to Written.KEPT_SERVER_FAULT)) {
            val cache = DurableCache()
            val (r, c) = cutShort(cache) { it.server.refuseWith = status to "refused_$status" }
            assertEquals(ContentCopy.importKept(250, how), c.importLine(), "$status")
            assertTrue(c.state.csvImport!!.kept, "$status")
            val key =if (status == 401) CopyKey.IMPORT_KEPT_UNTIL_SIGN_IN_MANY else CopyKey.IMPORT_KEPT_MANY
            assertEquals(key.fill(listOf("250")), c.importLine(), "$status")
            assertEquals(250, unsent(cache), "$status")

            r.server.refuseWith = null
            assertEquals(ActionResult.Ok, c.syncQuietly(), "$status")
            assertEquals(0, unsent(cache), "$status")
            assertEquals(450, r.server.itemRows.size, "$status")
        }
    }

    @Test
    fun aRefusalInTheMiddle_onACopyInMemory_keepsNothing_andSaysHowManyWereSavedAndNot() = runBlocking<Unit> {
        for (status in listOf(401, 429, 503)) {
            val cache = InMemoryVaultCache()
            val (r, c) = cutShort(cache) { it.server.refuseWith = status to "refused_$status" }
            val retryable = status != 401
            val why = if (retryable) null else ContentCopy.SESSION_EXPIRED
            assertEquals(ContentCopy.importStopped(200, 250, why), c.importLine(), "$status")
            assertEquals(retryable, c.state.csvImport!!.retryable, "$status")
            assertFalse(c.state.csvImport!!.kept, "$status")
            assertEquals(0, unsent(cache), "$status")

            r.server.refuseWith = null
            val before = r.server.pushes.size
            assertEquals(ActionResult.Ok, c.syncQuietly(), "$status")
            assertEquals(before, r.server.pushes.size, "$status: nothing is sent later")
            assertEquals(200, r.server.itemRows.size, "$status")
        }
    }

    /** Every batch landed and only the final pull got no answer: the import is done, never "interrupted". */
    @Test
    fun anImportWhoseBatchesAllLanded_isDone_whenOnlyTheFinalPullGetsNoAnswer() = runBlocking<Unit> {
        val r = ItemRig(InMemoryVaultCache())
        val c = content(r)
        c.syncQuietly()
        assertEquals(ActionResult.Ok, c.importCsv("name,url,username,password,note\n$rows".encodeToByteArray()))
        var pushes = 0
        r.server.hold = { route -> if (route == "push" && ++pushes == 3) r.server.offlineAfterNextPush = true }
        assertEquals(ActionResult.Ok, c.confirmImport())
        r.server.hold = null
        assertEquals(3, r.server.pushes.size, "the three batches landed")
        val view = c.state.csvImport!!
        assertNull(view.error, view.error)
        assertEquals(450, r.server.itemRows.size)
        // The check's probe P3: done, while the list shows none of them yet. The line says when they show, and not to
        // import the file again before then (it would add them twice), never only "Added".
        assertEquals(0, c.state.items.size)
        assertEquals(ContentCopy.importDoneListedLater(450, view.vaultName), view.done)
        assertEquals(ContentCopy.fillNames(CopyKey.IMPORT_DONE_LISTED_LATER, ContentCopy.Slot("450", false), ContentCopy.Slot(view.vaultName, true)), view.done)
        r.server.offline = false
        assertEquals(ActionResult.Ok, c.syncQuietly())
        assertEquals(450, c.state.items.size, "the next sync shows them")
    }

    /** An import whose last pull was answered shows its items at once, and its line is the plain done line. */
    @Test
    fun anImportWhoseItemsTheListShows_saysThePlainDoneLine() = runBlocking<Unit> {
        val r = ItemRig(InMemoryVaultCache())
        val c = content(r)
        c.syncQuietly()
        assertEquals(ActionResult.Ok, c.importCsv("name,url,username,password,note\nSite 1,https://s1.test,user1,pw1,\n".encodeToByteArray()))
        assertEquals(ActionResult.Ok, c.confirmImport())
        val view = c.state.csvImport!!
        assertEquals(1, c.state.items.size)
        assertEquals(io.silencelen.andvari.core.app.ImportCopy.done(1, view.vaultName), view.done)
        // One item done but not yet listed has its own key, in the singular.
        assertEquals(ContentCopy.fillNames(CopyKey.IMPORT_DONE_LISTED_LATER_ONE, ContentCopy.Slot("Personal", true)), ContentCopy.importDoneListedLater(1, "Personal"))
    }

    @Test
    fun noAnswerAtTheFirstPush_onACopyInMemory_isTheLineItWasBefore_withNothingSaved_andNothingKept() = runBlocking<Unit> {
        val cache = InMemoryVaultCache()
        val r = ItemRig(cache)
        val c = content(r)
        c.syncQuietly()
        assertEquals(ActionResult.Ok, c.importCsv("name,url,username,password,note\n$rows".encodeToByteArray()))
        r.server.hold = { route -> if (route == "push") r.server.offline = true }
        assertEquals(ActionResult.Ok, c.confirmImport())
        assertEquals(ImportCopy.INTERRUPTED, c.importLine())
        assertEquals(0, unsent(cache), "the first batch does not wait in memory behind the line")
    }

    /**
     * A lock in the middle: three rows of about 2 MiB go in two pushes under the 6 MiB cap; the lock lands while the first
     * is on its way. On a copy in memory the row still waiting goes with the lock and is said as not saved; on a copy
     * kept at rest it is kept, and the import counts as kept whole.
     */
    @Test
    fun aLockInTheMiddle_saysWhatIsInMemoryAsNotSaved_andKeepsWhatIsAtRest() = runBlocking<Unit> {
        for (durable in listOf(false, true)) {
            val cache: VaultCache = if (durable) DurableCache() else InMemoryVaultCache()
            val r = ItemRig(cache)
            val items = (1..3).map { r.planned("big $it", noteBytes = 2 * 1024 * 1024) }
            r.server.hold = { route -> if (route == "push") r.keys.locked = true }
            val thrown = try {
                r.engine.importAll(items)
                fail("durable=$durable: the lock is the lock's own result")
            } catch (e: KeysGoneException) {
                e
            }
            assertEquals(1, r.server.pushes.size, "durable=$durable")
            if (durable) {
                assertFalse(thrown is LockedBeforeKept, "every item was kept")
                assertEquals(1, cache.pending().size, "the row that waits is kept, and goes after the next unlock")
            } else {
                assertEquals(2, assertIs<LockedBeforeKept>(thrown).kept, "two saved, one not")
                assertEquals(0, cache.pending().size, "nothing waits in memory to be sent unsaid")
            }
        }
    }

    /**
     * The check's probe P4, on a copy in memory: two items whose joint push the server refuses as too large. The engine
     * splits the batch, the first item lands on its own, and the lock comes as it goes: one item saved and one not, and
     * the lines for exactly one saved item say so in the singular.
     */
    @Test
    fun aLockAfterASplitBatch_savesExactlyOneItem_andItsLineIsInTheSingular() = runBlocking<Unit> {
        val cache = InMemoryVaultCache()
        val r = ItemRig(cache)
        val items = (1..2).map { r.planned("big $it", noteBytes = 2000) }
        r.server.refuseBodyOverBytes = 4000
        var pushes = 0
        r.server.hold = { route -> if (route == "push" && ++pushes == 2) r.keys.locked = true }
        val thrown = try {
            r.engine.importAll(items)
            fail("the lock is the lock's own result")
        } catch (e: KeysGoneException) {
            e
        }
        assertEquals(1, r.server.itemRows.size, "the first item landed on its own")
        assertEquals(1, assertIs<LockedBeforeKept>(thrown).kept, "one saved, one not")
        assertEquals(0, cache.pending().size)

        assertEquals(ContentCopy.fillNames(CopyKey.LOCK_CUT_IMPORT_KEPT_ONE_LOST_ONE), ContentCopy.unsavedAtLock(emptyList(), 1, 1))
        assertEquals(
            ContentCopy.fillNames(CopyKey.LOCK_CUT_IMPORT_KEPT_ONE_LOST_MANY, ContentCopy.Slot("4", false)),
            ContentCopy.unsavedAtLock(emptyList(), 1, 4),
        )
    }

    /** The engine's own account of an import cut short, as the content hears it. */
    @Test
    fun theEngineTellsWhatTheImportCameTo() = runBlocking<Unit> {
        for (durable in listOf(false, true)) {
            val cache: VaultCache = if (durable) DurableCache() else InMemoryVaultCache()
            val r = ItemRig(cache)
            val items = (1..450).map { r.planned("n$it") }
            var pushes = 0
            r.server.hold = { route -> if (route == "push" && ++pushes == 2) r.server.offline = true }
            var heard: io.silencelen.andvari.core.client.items.ImportStopped? = null
            assertIs<ItemResult.Failed>(r.engine.importAll(items, onStopped = { heard = it }))
            val st = heard ?: fail("durable=$durable: nothing was heard")
            assertEquals(200, st.saved, "durable=$durable")
            assertEquals(if (durable) 250 else 0, st.keptToSend, "durable=$durable")
            assertEquals(if (durable) 0 else 250, st.notSaved, "durable=$durable")
            assertEquals(if (durable) Written.QUEUED else null, st.kept, "durable=$durable")
            assertEquals(st.keptToSend, cache.pending().size, "durable=$durable")
        }
    }
}
