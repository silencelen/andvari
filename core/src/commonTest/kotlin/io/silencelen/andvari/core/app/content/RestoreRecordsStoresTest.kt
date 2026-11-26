package io.silencelen.andvari.core.app.content

import io.silencelen.andvari.core.app.BlobStore
import io.silencelen.andvari.core.app.FillSnapshotStore
import io.silencelen.andvari.core.app.InMemoryBlobs
import io.silencelen.andvari.core.app.InMemoryFillSnapshots
import io.silencelen.andvari.core.client.items.CopyDeletion
import io.silencelen.andvari.core.client.items.ItemCacheNames
import io.silencelen.andvari.core.crypto.createCryptoProvider
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertNotNull
import kotlin.test.assertNull

/**
 * Where the records of a backup restore live on a device: among the account's kept records, a file while the policy
 * allows a copy, memory otherwise; gone with the account's records; carried with a followed move; and a name that is not
 * a restore record's is refused before anything is read or written.
 */
class RestoreRecordsStoresTest {
    private val crypto = createCryptoProvider()
    private val origin = "https://vault.example.com"
    private val alice = "55555555-5555-4555-8555-555555555555"
    private val name = "restore-0b0b0b0b-0b0b-4b0b-8b0b-0b0b0b0b0b0b-0123456789abcdef-0123456789abcdef0123456789abcdef"

    private class Disk : KeptStorage {
        val records = HashMap<String, InMemoryFillSnapshots>()
        override fun record(name: String): FillSnapshotStore = records.getOrPut(name) { InMemoryFillSnapshots() }
        override fun blobs(name: String): BlobStore = InMemoryBlobs()
        fun holds(): List<String> = records.filterValues { it.bytes != null }.keys.sorted()
    }

    private fun file(at: String = origin) = ItemCacheNames.keptPrefix(crypto, at, alice) + ContentStores.RESTORES

    @Test
    fun allowedTheRecordsAreOneFileOfTheAccountAndASignOutDeletesIt() {
        val disk = Disk()
        val stores = ContentStores(crypto, disk)
        val r = stores.restoreRecords(origin, alice, offlineCacheAllowed = true)
        r.replace(name, "{\"plan\":1}")
        r.replace("$name-x", "{\"plan\":2}")
        assertEquals(listOf(file()), disk.holds())
        assertEquals("{\"plan\":1}", stores.restoreRecords(origin, alice, true).read(name), "read back by another opening")
        r.remove("$name-x")
        assertNull(r.read("$name-x"))
        assertEquals("{\"plan\":1}", r.read(name))
        stores.drop(origin, alice, CopyDeletion.SIGNED_OUT)
        assertEquals(emptyList(), disk.holds(), "gone with the account's records")
        assertNull(stores.restoreRecords(origin, alice, true).read(name))
    }

    @Test
    fun forbiddenTheRecordsStayInMemoryOnlyAndAPolicyWipeKeepsThemThere() {
        val disk = Disk()
        val stores = ContentStores(crypto, disk)
        stores.restoreRecords(origin, alice, offlineCacheAllowed = false).replace(name, "{}")
        assertEquals(emptyList(), disk.holds(), "nothing at rest")
        assertEquals("{}", stores.restoreRecords(origin, alice, offlineCacheAllowed = false).read(name), "kept across a lock, in this process")
        assertEquals("{}", stores.restoreRecords(origin, alice, offlineCacheAllowed = true).read(name), "read from memory once the policy allows")
        assertEquals(emptyList(), disk.holds(), "a read writes nothing")
        stores.drop(origin, alice, CopyDeletion.POLICY_FORBIDS_OFFLINE_COPY)
        assertEquals("{}", stores.restoreRecords(origin, alice, false).read(name), "a policy's wipe keeps them in memory")
        assertEquals(emptyList(), disk.holds())
        stores.drop(origin, alice, CopyDeletion.SIGNED_OUT)
        assertNull(stores.restoreRecords(origin, alice, false).read(name), "a sign-out takes them")
    }

    @Test
    fun aPolicyWipeMovesTheRecordsOfTheFileIntoMemoryAndLeavesNoFile() {
        val disk = Disk()
        val stores = ContentStores(crypto, disk)
        val r = stores.restoreRecords(origin, alice, offlineCacheAllowed = true)
        r.replace(name, "{\"plan\":1}")
        r.replace("$name-x", "{\"plan\":2}")
        assertEquals(listOf(file()), disk.holds())
        stores.drop(origin, alice, CopyDeletion.POLICY_FORBIDS_OFFLINE_COPY)
        assertEquals(emptyList(), disk.holds(), "no file of the restore's records after the wipe")
        val held = stores.restoreRecords(origin, alice, offlineCacheAllowed = false)
        assertEquals("{\"plan\":1}", held.read(name), "moved into memory")
        assertEquals("{\"plan\":2}", held.read("$name-x"))
        held.replace(name, "{\"plan\":3}")
        assertEquals(emptyList(), disk.holds(), "and kept there while the policy forbids")
        assertEquals("{\"plan\":3}", held.read(name))
    }

    @Test
    fun thePlaceIsAskedAtEachWriteAndAWipeIsNeverFollowedByAWriteToTheFile() {
        val disk = Disk()
        val stores = ContentStores(crypto, disk)
        var allowed = true
        val r = stores.restoreRecords(origin, alice) { allowed }
        r.replace(name, "{\"step\":1}")
        assertEquals(listOf(file()), disk.holds(), "allowed: a file")
        // A policy that forbids a copy arrives, and its wipe runs; the same records go on.
        allowed = false
        stores.drop(origin, alice, CopyDeletion.POLICY_FORBIDS_OFFLINE_COPY)
        r.replace(name, "{\"step\":2}")
        assertEquals(emptyList(), disk.holds(), "nothing written to the disk once the policy forbids")
        assertEquals("{\"step\":2}", r.read(name))
        // Allowed again: the next write takes the record to the file, and memory lets go of it.
        allowed = true
        assertEquals("{\"step\":2}", r.read(name), "memory first")
        r.replace("$name-x", "{}")
        assertEquals("{\"step\":2}", r.read(name), "memory's copy is still the one read")
        r.replace(name, "{\"step\":3}")
        allowed = false
        assertEquals("{\"step\":3}", r.read(name), "read from the file: memory no longer holds it")
        assertEquals("{\"step\":3}", stores.restoreRecords(origin, alice, true).read(name))
    }

    @Test
    fun aFollowedMoveCarriesTheRecords() {
        val disk = Disk()
        val stores = ContentStores(crypto, disk)
        stores.restoreRecords(origin, alice, true).replace(name, "{}")
        val to = "https://new.example.com"
        stores.carry(origin, to, alice)
        assertEquals(listOf(file(to)), disk.holds())
        assertEquals("{}", stores.restoreRecords(to, alice, true).read(name))
    }

    @Test
    fun aNameThatIsNoRestoreRecordsIsRefusedBeforeAnythingIsReadOrWritten() {
        val disk = Disk()
        val stores = ContentStores(crypto, disk)
        val r = stores.restoreRecords(origin, alice, true)
        for (bad in listOf("../x", "restore-A", "a/b", "a\\b", "x".repeat(200), "")) {
            assertFailsWith<IllegalArgumentException>(bad) { r.replace(bad, "{}") }
            assertFailsWith<IllegalArgumentException>(bad) { r.read(bad) }
        }
        assertEquals(emptyList(), disk.holds())
    }

    @Test
    fun aRecordThatCannotBeReadIsNeverTakenAsEmpty() {
        val disk = Disk()
        val stores = ContentStores(crypto, disk)
        assertNotNull(disk.record(file())).write("not json".encodeToByteArray())
        assertFailsWith<IllegalStateException> { stores.restoreRecords(origin, alice, true).read(name) }
    }
}
