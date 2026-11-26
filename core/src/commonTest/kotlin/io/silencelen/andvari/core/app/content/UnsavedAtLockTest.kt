package io.silencelen.andvari.core.app.content

import io.silencelen.andvari.core.app.ActionResult
import io.silencelen.andvari.core.app.CopyKey
import io.silencelen.andvari.core.app.AttachmentRules
import io.silencelen.andvari.core.app.BlobStore
import io.silencelen.andvari.core.app.FillSnapshotStore
import io.silencelen.andvari.core.app.InMemoryBlobs
import io.silencelen.andvari.core.app.InMemoryFillSnapshots
import io.silencelen.andvari.core.app.InMemorySaveQueue
import io.silencelen.andvari.core.app.LoginInput
import io.silencelen.andvari.core.client.items.DurableCache
import io.silencelen.andvari.core.client.items.ItemEngine
import io.silencelen.andvari.core.client.items.ItemRig
import io.silencelen.andvari.core.client.onboard.OpenedAccount
import io.silencelen.andvari.core.crypto.Bytes
import io.silencelen.andvari.core.crypto.KdfParams
import io.silencelen.andvari.core.trust.GenesisFields
import io.silencelen.andvari.core.trust.VerifiedGenesis
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.launch
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.yield
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNull
import kotlin.test.assertTrue

/**
 * What the key fix left (keys-1, item 4, "Not done: telling the person"): a change a lock overtook before this device
 * kept it is neither kept nor lost silently. The next unlock's content says which item was not saved (by name, never a
 * secret of it), and how many items of an import were and were not; the note lives in this process's memory only,
 * nothing about it is written anywhere, it is said once, and it is gone with the process.
 */
class UnsavedAtLockTest {
    private class Disk : KeptStorage {
        val records = HashMap<String, InMemoryFillSnapshots>()
        val blobSets = HashMap<String, InMemoryBlobs>()
        override fun record(name: String): FillSnapshotStore = records.getOrPut(name) { InMemoryFillSnapshots() }
        override fun blobs(name: String): BlobStore = blobSets.getOrPut(name) { InMemoryBlobs() }
        fun holds(): List<String> = records.filterValues { it.bytes != null }.keys.sorted() + blobSets.filterValues { it.ids().isNotEmpty() }.keys.sorted()
    }

    private class TestHost(val r: ItemRig) : ContentHost {
        override fun wallMs(): Long = r.now
        override fun attachmentLimits() = AttachmentRules.limits(null, null)
        override fun origin(): String = ORIGIN
        override fun userId(): String = r.userId
        override fun accountId(): String = "0123456789abcdef0123456789abcdef"
        override fun backupKdfParams(): KdfParams? = null
    }

    private fun unlock(r: ItemRig): OpenedAccount {
        val seed = ByteArray(32) { 4 }
        val identity = r.crypto.boxKeypairFromSeed(seed)
        val genesis = VerifiedGenesis(GenesisFields(r.userId, Bytes.toB64(identity.publicKey), "instance", r.personal, 0), "00".repeat(32))
        return OpenedAccount(r.userId, ByteArray(32) { 1 }, identity, r.crypto.signKeypairFromSeed(seed), genesis, r.personal, ByteArray(32) { 7 })
    }

    private class Process(val r: ItemRig) {
        val disk = Disk()
        val queue = InMemorySaveQueue()
        val stores = ContentStores(r.crypto, disk, queue)
    }

    private fun content(p: Process, engine: ItemEngine, account: OpenedAccount): EngineVaultContent {
        p.r.server.echo = true
        return EngineVaultContent(engine, p.r.crypto, TestHost(p.r), p.stores.keeping(account, ORIGIN, offlineCacheAllowed = true))
    }

    /** The lock as the app interface runs it: the content closes, then the engine, then the account's keys go. */
    private fun lock(c: EngineVaultContent, engine: ItemEngine, account: OpenedAccount) {
        c.close()
        engine.close()
        account.wipe()
    }

    private fun login(name: String) = LoginInput(name, "me", "a-secret-pw", listOf("https://example.com"), "", "", false)

    @Test
    fun aSaveALockOvertookBeforeItsSeal_isNamedAtTheNextUnlock_andNothingOfItIsOnDisk() = runBlocking<Unit> {
        val r = ItemRig(DurableCache())
        val p = Process(r)
        val first = unlock(r)
        val c = content(p, r.engine, first)
        // A sync holds the engine while its pull waits on the network; the save waits behind it.
        val pullEntered = CompletableDeferred<Unit>()
        val pullRelease = CompletableDeferred<Unit>()
        r.server.pullEntered = pullEntered
        r.server.pullRelease = pullRelease
        val sync = launch { c.refresh() }
        pullEntered.await()
        var answer: ActionResult? = null
        val save = launch { answer = c.saveLogin(null, login("Bank of Springfield"), null) }
        yield()
        val pushesBefore = r.server.pushes.size
        lock(c, r.engine, first)
        pullRelease.complete(Unit)
        sync.join()
        save.join()

        assertEquals(ActionResult.NotDone(null), answer, "a lock is not a failure of the save")
        assertEquals(pushesBefore, r.server.pushes.size, "nothing was sent")
        assertTrue(r.cache.pending().isEmpty(), "nothing was queued")
        assertEquals(emptyList(), p.disk.holds(), "nothing about it is written in the kept records")
        assertTrue(p.queue.entries().isEmpty())

        // The next unlock says it, once, by name and never with its secret.
        val second = unlock(r)
        val engine2 = r.restarted()
        val c2 = content(p, engine2, second)
        val said = c2.state.notice
        assertEquals(ContentCopy.unsavedAtLock(listOf("Bank of Springfield"), 0, 0), said)
        assertTrue(said!!.contains("“Bank of Springfield”") && !said.contains("a-secret-pw"), said)
        lock(c2, engine2, second)
        val third = unlock(r)
        val c3 = content(p, r.restarted(), third)
        assertNull(c3.state.notice, "said once")
    }

    @Test
    fun theNoteIsTheAccountsOwn_andGoneWithTheProcess() = runBlocking<Unit> {
        val r = ItemRig(DurableCache())
        val p = Process(r)
        val first = unlock(r)
        val c = content(p, r.engine, first)
        lock(c, r.engine, first)
        // A save asked for once the content closed: its screen is going.
        assertEquals(ActionResult.NotDone(null), c.saveLogin(null, login("Locker"), null))

        // The account at another server, in the same process, sees nothing of it.
        val elsewhere = EngineVaultContent(r.restarted(), r.crypto, TestHost(r), p.stores.keeping(unlock(r), "https://other.example.com", true))
        assertNull(elsewhere.state.notice)

        // A new process (the app was closed) has none.
        val fresh = Process(r)
        assertNull(content(fresh, r.restarted(), unlock(r)).state.notice, "gone when the app is")

        // The same process, the same account: said.
        assertEquals(ContentCopy.unsavedAtLock(listOf("Locker"), 0, 0), content(p, r.restarted(), unlock(r)).state.notice)
    }

    /** Changes are counted by item, not by name: two items with the same name, or with none, are two; one item twice is one. */
    @Test
    fun twoItemsOfTheSameNameAreTwoChanges_andOneItemSavedTwiceIsOne() = runBlocking<Unit> {
        val r = ItemRig(DurableCache())
        val p = Process(r)
        val first = unlock(r)
        val c = content(p, r.engine, first)
        assertEquals(ActionResult.Ok, c.saveLogin(null, login("Bank"), null))
        assertEquals(ActionResult.Ok, c.saveLogin(null, login("Bank"), null))
        val (one, two) = c.state.items.map { it.itemId }
        lock(c, r.engine, first)
        // Saves asked for once the content closed: the first item twice, the second once.
        c.saveLogin(one, login("Bank"), null)
        c.saveLogin(one, login("Bank"), null)
        c.saveLogin(two, login("Bank"), null)
        val next = content(p, r.restarted(), unlock(r))
        assertEquals(ContentCopy.unsavedAtLock(listOf("Bank", "Bank"), 0, 0), next.state.notice)
        assertEquals(CopyKey.UNSAVED_AT_LOCK_TWO.fill(listOf("Bank", "Bank")), next.state.notice)
        assertEquals(2, next.state.lockCut.size)
    }

    @Test
    fun anImportWhoseLaterBatchesALockStopped_saysHowManyWereSavedAndHowManyNot() = runBlocking<Unit> {
        val r = ItemRig(DurableCache())
        val p = Process(r)
        val first = unlock(r)
        val c = content(p, r.engine, first)
        val rows = (1..251).joinToString("") { "Site $it,https://s$it.test,user$it,pw$it,\n" }
        assertEquals(ActionResult.Ok, c.importCsv("name,url,username,password,note\n$rows".encodeToByteArray()))
        // The first batch of 200 is on its way when the lock lands.
        val pushEntered = CompletableDeferred<Unit>()
        val pushRelease = CompletableDeferred<Unit>()
        r.server.pushEntered = pushEntered
        r.server.pushRelease = pushRelease
        var answer: ActionResult? = null
        val import = launch { answer = c.confirmImport() }
        pushEntered.await()
        lock(c, r.engine, first)
        pushRelease.complete(Unit)
        import.join()

        assertEquals(ActionResult.NotDone(null), answer)
        assertEquals(listOf(200), r.server.pushes.map { it.size }, "the later batch was never sealed or sent")
        assertEquals(emptyList(), p.disk.holds())

        val c2 = content(p, r.restarted(), unlock(r))
        assertEquals(ContentCopy.unsavedAtLock(emptyList(), 200, 51), c2.state.notice)
        assertTrue(c2.state.notice!!.contains("200 items were saved and 51 were not"), c2.state.notice)
    }

    private companion object {
        const val ORIGIN = "https://vault.example.com"
    }
}
