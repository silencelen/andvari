package io.silencelen.andvari.core.app.content

import io.silencelen.andvari.core.app.BlobStore
import io.silencelen.andvari.core.app.FillSnapshotStore
import io.silencelen.andvari.core.app.InMemoryBlobs
import io.silencelen.andvari.core.app.InMemoryFillSnapshots
import io.silencelen.andvari.core.app.InMemorySaveQueue
import io.silencelen.andvari.core.client.items.CopyDeletion
import io.silencelen.andvari.core.client.items.ItemCacheNames
import io.silencelen.andvari.core.client.onboard.OpenedAccount
import io.silencelen.andvari.core.crypto.Bytes
import io.silencelen.andvari.core.crypto.createCryptoProvider
import io.silencelen.andvari.core.trust.GenesisFields
import io.silencelen.andvari.core.trust.VerifiedGenesis
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertNotEquals
import kotlin.test.assertNull
import kotlin.test.assertTrue

/** The life of the offline cache and of the content's kept records: where they live under the policy, and when they go. */
class ContentStoresTest {
    private val crypto = createCryptoProvider()
    private val origin = "https://vault.example.com"

    private class Disk : KeptStorage {
        val records = HashMap<String, InMemoryFillSnapshots>()
        val blobSets = HashMap<String, InMemoryBlobs>()
        override fun record(name: String): FillSnapshotStore = records.getOrPut(name) { InMemoryFillSnapshots() }
        override fun blobs(name: String): BlobStore = blobSets.getOrPut(name) { InMemoryBlobs() }
        fun holds(): List<String> = records.filterValues { it.bytes != null }.keys.sorted() + blobSets.filterValues { it.ids().isNotEmpty() }.keys.sorted()
    }

    private fun account(userId: String): OpenedAccount {
        val seed = ByteArray(32) { 4 }
        val identity = crypto.boxKeypairFromSeed(seed)
        val personal = "44444444-4444-4444-8444-444444444444"
        val genesis = VerifiedGenesis(GenesisFields(userId, Bytes.toB64(identity.publicKey), "instance", personal, 0), "00".repeat(32))
        return OpenedAccount(userId, ByteArray(32) { 1 }, identity, crypto.signKeypairFromSeed(seed), genesis, personal, ByteArray(32) { 7 })
    }

    private val alice = "55555555-5555-4555-8555-555555555555"
    private val bob = "66666666-6666-4666-8666-666666666666"

    private fun keep(k: ContentKeeping) {
        k.moves.write(byteArrayOf(1))
        k.keptSaves.write(byteArrayOf(2))
        k.files.put("f", byteArrayOf(3))
        k.applied.write(byteArrayOf(4))
    }

    @Test
    fun allowed_theRecordsAreFilesUnderTheAccountsOwnNames_andADropDeletesThem() {
        val disk = Disk()
        val queue = InMemorySaveQueue()
        val stores = ContentStores(crypto, disk, queue)
        keep(stores.keeping(account(alice), origin, offlineCacheAllowed = true))
        queue.add("q1", byteArrayOf(9))
        val prefix = ItemCacheNames.keptPrefix(crypto, origin, alice)
        assertEquals(
            listOf("$prefix-applied-saves", "$prefix-kept-saves", "$prefix-moves", "$prefix-files"), disk.holds(),
        )
        assertFalse(stores.inMemory(origin, alice))

        // A lock and an unlock: the same files, still there.
        assertContentEquals(byteArrayOf(1), stores.keeping(account(alice), origin, true).moves.read())

        stores.drop(origin, alice, CopyDeletion.SIGNED_OUT)
        assertEquals(emptyList(), disk.holds())
        assertTrue(queue.entries().isEmpty(), "the extensions' queue is emptied")
    }

    @Test
    fun forbidden_whatWasOnDiskStaysUntilCounted_andTheRecordsLiveInMemoryAcrossALock() {
        val disk = Disk()
        val stores = ContentStores(crypto, disk)
        keep(stores.keeping(account(alice), origin, offlineCacheAllowed = true))
        val before = disk.holds()
        assertTrue(before.isNotEmpty())

        // The policy now forbids keeping anything: nothing is removed before it is counted (decided on 2026-11-17). The
        // files stay as they are, unread by this opening, for the policy's run; this opening's records are in memory.
        val k = stores.keeping(account(alice), origin, offlineCacheAllowed = false)
        assertEquals(before, disk.holds(), "nothing on disk is removed by the composition")
        assertContentEquals(byteArrayOf(2), disk.record(ItemCacheNames.keptPrefix(crypto, origin, alice) + ContentStores.KEPT_SAVES).read(), "the kept save is still there")
        assertTrue(stores.inMemory(origin, alice))
        keep(k)
        assertEquals(before, disk.holds(), "nothing more is written to disk under a forbidding policy")

        // A lock and an unlock: the same records, still in memory.
        assertContentEquals(byteArrayOf(2), stores.keeping(account(alice), origin, false).keptSaves.read())
        // Allowed again later in the process: what was kept under the forbidding policy never reaches the disk.
        assertContentEquals(byteArrayOf(2), stores.keeping(account(alice), origin, true).keptSaves.read())
        assertEquals(before, disk.holds())

        stores.drop(origin, alice, CopyDeletion.FORGOT_SERVER)
        assertEquals(emptyList(), disk.holds(), "the drop (the run's wipe, or the person's own end) removes what was on disk")
        assertFalse(stores.inMemory(origin, alice))
        assertNull(stores.keeping(account(alice), origin, false).keptSaves.read(), "a drop leaves nothing in memory")
    }

    /**
     * The switch that keeps data on the device turned off (the desktop's "Keep me signed in"): the platform's storage
     * carries what it holds into memory and keeps it there (a record whose delete clears memory too, as the desktop's
     * does). Before, the composition that followed called the storage's delete for every record, which wiped what the
     * switch had just carried to memory: a save a lock cut short was lost with it. Now the composition removes nothing.
     */
    @Test
    fun theSwitchOffCarriesToMemoryAndTheCompositionThatFollowsKeepsIt() {
        class OptIn : FillSnapshotStore {
            var bytes: ByteArray? = null
            override fun read(): ByteArray? = bytes
            override fun write(bytes: ByteArray): Boolean { this.bytes = bytes; return true }
            override fun delete() { bytes = null }
        }
        val records = HashMap<String, OptIn>()
        val storage = object : KeptStorage {
            override fun record(name: String): FillSnapshotStore = records.getOrPut(name) { OptIn() }
            override fun blobs(name: String): BlobStore = InMemoryBlobs()
        }
        val stores = ContentStores(crypto, storage)
        stores.keeping(account(alice), origin, offlineCacheAllowed = true).keptSaves.write(byteArrayOf(5))
        // The switch goes off: the platform's records now hold it in memory only (here: the same record object).
        val k = stores.keeping(account(alice), origin, offlineCacheAllowed = false)
        assertContentEquals(byteArrayOf(5), records.getValue(ItemCacheNames.keptPrefix(crypto, origin, alice) + ContentStores.KEPT_SAVES).bytes, "not deleted")
        assertNull(k.keptSaves.read(), "this opening keeps its own records in memory")
    }

    @Test
    fun noDisk_isMemoryOnly() {
        val stores = ContentStores(crypto, null)
        keep(stores.keeping(account(alice), origin, offlineCacheAllowed = true))
        assertTrue(stores.inMemory(origin, alice))
    }

    @Test
    fun twoAccounts_orOneAtTwoServers_neverShareARecord_andADropTakesOnlyItsOwn() {
        val disk = Disk()
        val stores = ContentStores(crypto, disk)
        keep(stores.keeping(account(alice), origin, true))
        assertNull(stores.keeping(account(bob), origin, true).moves.read())
        assertNull(stores.keeping(account(alice), "https://other.example.com", true).moves.read())
        assertNotEquals(ItemCacheNames.keptPrefix(crypto, origin, alice), ItemCacheNames.keptPrefix(crypto, origin, bob))

        keep(stores.keeping(account(bob), origin, true))
        stores.drop(origin, alice, CopyDeletion.ACCOUNT_DELETED)
        assertNull(stores.keeping(account(alice), origin, true).moves.read())
        assertContentEquals(byteArrayOf(1), stores.keeping(account(bob), origin, true).moves.read())
    }

    @Test
    fun aFollowedMove_carriesTheKeptRecords_onDiskAndInMemory_andNeverOverwrites() {
        val moved = "https://new.example.com"
        val disk = Disk()
        val stores = ContentStores(crypto, disk)
        keep(stores.keeping(account(alice), origin, true))
        assertTrue(stores.carry(origin, moved, alice))
        val there = stores.keeping(account(alice), moved, true)
        assertContentEquals(byteArrayOf(1), there.moves.read())
        assertContentEquals(byteArrayOf(2), there.keptSaves.read())
        assertContentEquals(byteArrayOf(3), there.files.get("f"))
        assertContentEquals(byteArrayOf(4), there.applied.read())
        assertNull(stores.keeping(account(alice), origin, true).moves.read(), "nothing is left at the old name")

        // A name already taken at the new address is never replaced: the carry stops, and the old records stay.
        keep(stores.keeping(account(alice), origin, true))
        assertFalse(stores.carry(origin, moved, alice))
        assertContentEquals(byteArrayOf(1), stores.keeping(account(alice), origin, true).moves.read())

        // Held in memory (a forbidding policy): re-filed under the new name.
        val memory = ContentStores(crypto, null)
        keep(memory.keeping(account(bob), origin, false))
        assertTrue(memory.carry(origin, moved, bob))
        assertTrue(memory.inMemory(moved, bob) && !memory.inMemory(origin, bob))
        assertContentEquals(byteArrayOf(2), memory.keeping(account(bob), moved, false).keptSaves.read())
    }

    @Test
    fun aFollowedMove_carriesTheCacheFiles_toTheNewNames() {
        val moved = "https://new.example.com"
        val renames = ArrayList<Pair<String, String>>()
        assertTrue(ItemCacheNames.carry(crypto, origin, moved, alice) { a, b -> renames += a to b; true })
        assertEquals(ItemCacheNames.files(crypto, origin, alice).zip(ItemCacheNames.files(crypto, moved, alice)), renames)
        assertFalse(ItemCacheNames.carry(crypto, origin, moved, alice) { a, _ -> !a.endsWith("-wal") })
    }

    @Test
    fun theCacheDeletion_triesEveryFileOfTheNamespace_andSaysWhetherAllWent() {
        val removed = ArrayList<String>()
        assertTrue(ItemCacheNames.delete(crypto, origin, alice, CopyDeletion.SIGNED_OUT) { removed += it; true })
        val db = ItemCacheNames.fileName(crypto, origin, alice)
        assertEquals(listOf(db, "$db-wal", "$db-shm", "$db-journal"), removed)

        removed.clear()
        // One file that will not go, and one that throws: every other file is still tried, and the answer is false.
        val ok = ItemCacheNames.delete(crypto, origin, alice, CopyDeletion.POLICY_FORBIDS_OFFLINE_COPY) {
            removed += it
            when {
                it.endsWith("-wal") -> false
                it.endsWith("-shm") -> error("disk")
                else -> true
            }
        }
        assertFalse(ok)
        assertEquals(4, removed.size)
        // The cache file's name is as it was (a renamed cache would strand every existing file).
        assertTrue(db.startsWith("vault-") && db.endsWith(".db") && db.length == "vault-".length + 32 + 3)
    }
}
