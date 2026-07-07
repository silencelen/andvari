package io.silencelen.andvari.core.client

import io.silencelen.andvari.core.model.Mutation
import io.silencelen.andvari.core.model.WireGrant
import io.silencelen.andvari.core.model.WireItem
import io.silencelen.andvari.core.model.WireVault
import java.io.File
import java.nio.file.Files
import kotlin.test.AfterTest
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNull
import kotlin.test.assertTrue

/**
 * The VaultCache behavioral contract, run against BOTH impls (InMemory + the durable
 * SQLite impl) so they can never diverge. Durable-only properties (survive close/reopen)
 * are in [SqliteVaultCacheTest].
 */
abstract class VaultCacheContractTest {
    abstract fun newCache(): VaultCache

    private fun wire(id: String, vaultId: String, rev: Long, conflict: Boolean = false, deleted: Boolean = false) =
        WireItem(id, vaultId, rev, 1000, 2000, deleted, conflict, 1, listOf("att-$id"), "blob-$id")

    private fun vitem(id: String, vaultId: String, rev: Long) =
        VaultItem(id, vaultId, rev, 2000, ItemDoc(type = "note", name = "n-$id"))

    @Test fun cursorDefaultsToZero_andRoundTrips() {
        val c = newCache()
        assertEquals(0L, c.cursor())
        c.setCursor(42); assertEquals(42L, c.cursor())
    }

    @Test fun itemUpsertGetAllDelete() {
        val c = newCache()
        c.upsertItem(wire("a", "v1", 1), vitem("a", "v1", 1))
        c.upsertItem(wire("b", "v1", 2), vitem("b", "v1", 2))
        assertEquals(2, c.allItems().size)
        assertEquals("n-a", c.getItem("a")!!.doc.name)
        c.deleteItem("a")
        assertNull(c.getItem("a"))
        assertTrue(c.envelopes().none { it.itemId == "a" })
    }

    @Test fun upsertItemWithNullView_persistsEnvelopeButHidesFromWorkingSet() {
        val c = newCache()
        c.upsertItem(wire("x", "v1", 5), null) // undecryptable envelope
        assertNull(c.getItem("x"))
        assertTrue(c.allItems().isEmpty())
        val env = c.envelopes().single { it.itemId == "x" }
        assertEquals("v1", env.vaultId); assertEquals(5L, env.rev)
        assertEquals(listOf("att-x"), env.attachmentIds); assertEquals("blob-x", env.blob)
    }

    @Test fun envelopesRoundTripEveryField() {
        val c = newCache()
        val w = WireItem("i", "v9", 7, 111, 222, deleted = false, conflict = true, formatVersion = 1, attachmentIds = listOf("p", "q"), blob = "B")
        c.upsertItem(w, vitem("i", "v9", 7))
        assertEquals(w, c.envelopes().single { it.itemId == "i" })
    }

    @Test fun grantsAndVaultsUpsertList() {
        val c = newCache()
        c.upsertGrant(WireGrant("v1", "u", "owner", "wv", 3, null))
        c.upsertGrant(WireGrant("v2", "u", "writer", "", 4, "sealed"))
        c.upsertVault(WireVault("v1", "personal", 3, "meta1", 100))
        assertEquals(2, c.grants().size)
        assertEquals("sealed", c.grants().single { it.vaultId == "v2" }.sealedVk)
        assertEquals("meta1", c.vaults().single { it.vaultId == "v1" }.metaBlob)
    }

    @Test fun dropVaultPurgesGrantVaultAndItems() {
        val c = newCache()
        c.upsertGrant(WireGrant("v1", "u", "owner", "wv", 1, null))
        c.upsertVault(WireVault("v1", "shared", 1, "m", 1))
        c.upsertItem(wire("a", "v1", 2), vitem("a", "v1", 2))
        c.upsertItem(wire("b", "v2", 3), vitem("b", "v2", 3))
        c.dropVault("v1")
        assertTrue(c.grants().none { it.vaultId == "v1" })
        assertTrue(c.vaults().none { it.vaultId == "v1" })
        assertNull(c.getItem("a"))
        assertTrue(c.envelopes().none { it.vaultId == "v1" })
        assertEquals("b", c.getItem("b")!!.itemId) // other vault untouched
    }

    @Test fun queueFifoAcrossInterleavedEnqueueDequeue() {
        val c = newCache()
        fun m(id: String, vault: String = "v1") = Mutation(id, "put", "item-$id", vault, 0, null)
        c.enqueue(m("1")); c.enqueue(m("2")); c.enqueue(m("3"))
        assertEquals(listOf("1", "2", "3"), c.pending().map { it.mutationId })
        c.dequeue("2")
        assertEquals(listOf("1", "3"), c.pending().map { it.mutationId })
        c.enqueue(m("4"))
        assertEquals(listOf("1", "3", "4"), c.pending().map { it.mutationId })
    }

    @Test fun dropPendingRemovesOnlyMatchingVault() {
        val c = newCache()
        c.enqueue(Mutation("a", "put", "i1", "v1", 0, null))
        c.enqueue(Mutation("b", "put", "i2", "v2", 0, null))
        c.enqueue(Mutation("c", "put", "i3", "v1", 0, null))
        c.dropPending("v1")
        assertEquals(listOf("b"), c.pending().map { it.mutationId })
    }

    @Test fun clearResetsRowsAndCursorButPreservesQueue() {
        val c = newCache()
        c.upsertItem(wire("a", "v1", 1), vitem("a", "v1", 1))
        c.upsertGrant(WireGrant("v1", "u", "owner", "wv", 1, null))
        c.upsertVault(WireVault("v1", "personal", 1, "m", 1))
        c.setCursor(99)
        c.enqueue(Mutation("q", "put", "i", "v1", 0, null))
        c.clear()
        assertEquals(0L, c.cursor())
        assertTrue(c.allItems().isEmpty() && c.grants().isEmpty() && c.vaults().isEmpty() && c.envelopes().isEmpty())
        assertEquals(listOf("q"), c.pending().map { it.mutationId }) // queue survives a 410 resync
    }
}

class InMemoryVaultCacheTest : VaultCacheContractTest() {
    override fun newCache(): VaultCache = InMemoryVaultCache()
}

class SqliteVaultCacheTest : VaultCacheContractTest() {
    private val tmp: File = Files.createTempDirectory("andvari-cache").toFile()
    override fun newCache(): VaultCache = sqliteVaultCache(File(tmp, "vault-${System.nanoTime()}.db").absolutePath, "u")

    @AfterTest fun cleanup() { tmp.deleteRecursively() }

    /** Durable-only: everything survives close + reopen of the same file. */
    @Test fun survivesCloseAndReopen() {
        val path = File(tmp, "persist.db").absolutePath
        val c1 = sqliteVaultCache(path, "user-1")
        c1.setCursor(1234)
        c1.upsertItem(WireItem("a", "v1", 5, 1, 2, false, false, 1, listOf("x"), "blobA"), VaultItem("a", "v1", 5, 2, ItemDoc("note", "keep")))
        c1.upsertItem(WireItem("u", "v1", 6, 1, 2, false, false, 1, emptyList(), "blobU"), null) // undecryptable
        c1.upsertGrant(WireGrant("v1", "user-1", "owner", "wv", 5, null))
        c1.upsertVault(WireVault("v1", "personal", 5, "m", 1))
        c1.enqueue(Mutation("q1", "put", "i", "v1", 0, null))
        c1.close()

        val c2 = sqliteVaultCache(path, "user-1")
        assertEquals(1234L, c2.cursor())
        assertEquals(2, c2.envelopes().size) // both the decryptable and the null-view envelope
        assertEquals("blobA", c2.envelopes().single { it.itemId == "a" }.blob)
        assertEquals(1, c2.grants().size)
        assertEquals(1, c2.vaults().size)
        assertEquals(listOf("q1"), c2.pending().map { it.mutationId })
        c2.close()
    }

    /** Opening the same file under a DIFFERENT account wipes everything (defense in depth). */
    @Test fun differentAccountWipesFile() {
        val path = File(tmp, "shared.db").absolutePath
        val a = sqliteVaultCache(path, "alice")
        a.upsertGrant(WireGrant("v1", "alice", "owner", "wv", 1, null))
        a.enqueue(Mutation("q", "put", "i", "v1", 0, null))
        a.close()
        val b = sqliteVaultCache(path, "bob")
        assertTrue(b.grants().isEmpty() && b.pending().isEmpty())
        b.close()
    }
}
