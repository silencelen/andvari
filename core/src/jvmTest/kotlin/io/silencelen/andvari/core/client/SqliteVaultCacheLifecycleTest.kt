package io.silencelen.andvari.core.client

import io.silencelen.andvari.core.model.Mutation
import io.silencelen.andvari.core.model.PendingTransfer
import io.silencelen.andvari.core.model.TransferRecord
import io.silencelen.andvari.core.model.WireGrant
import io.silencelen.andvari.core.model.WireItem
import io.silencelen.andvari.core.model.WireVault
import kotlinx.serialization.json.Json
import java.io.File
import java.nio.file.Files
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertNull
import kotlin.test.assertTrue

/**
 * The v1→v2 cache migration + the 0.5.0 lifecycle persistence (#8): this migration first
 * executes IN PRODUCTION on fielded phones' populated v1 databases, so it is exercised
 * here against a hand-built v1 schema with real rows — plus HeldVaultRecord round-trip,
 * the staged-denied queue state, clear()-preserves-safety-state, and the account-mismatch
 * full wipe.
 */
class SqliteVaultCacheLifecycleTest {
    private val tmp = Files.createTempDirectory("andvari-cache-v2").toFile()
    private val json = Json { ignoreUnknownKeys = true; encodeDefaults = true }

    private fun newPath(): String = File(tmp, "vault-${System.nanoTime()}.db").absolutePath

    private fun mutation(id: String, vaultId: String) = Mutation(id, "delete", "item-$id", vaultId, 3, null)

    private val wireItem = WireItem("i1", "v1", 7, 100, 200, deleted = false, conflict = true, formatVersion = 1, attachmentIds = listOf("a1"), blob = "BLOB")
    private val wireGrant = WireGrant("v1", "u1", "writer", "", 3, "SEALED")
    private val wireVault = WireVault("v1", "shared", 2, "META", 50)

    /** Hand-build a POPULATED v1-schema db — byte-for-byte the pre-0.5.0 layout. */
    private fun buildV1Db(path: String, userId: String) {
        val db = openSqlBox(path)
        db.tx {
            db.exec("CREATE TABLE kv(key TEXT PRIMARY KEY, value TEXT NOT NULL)")
            db.exec(
                """CREATE TABLE items(itemId TEXT PRIMARY KEY, vaultId TEXT NOT NULL,
                   rev INTEGER NOT NULL, createdAt INTEGER NOT NULL, updatedAt INTEGER NOT NULL,
                   deleted INTEGER NOT NULL, conflict INTEGER NOT NULL, formatVersion INTEGER NOT NULL,
                   attachmentIds TEXT NOT NULL, blob TEXT)""",
            )
            db.exec("CREATE INDEX items_vault ON items(vaultId)")
            db.exec(
                """CREATE TABLE grants(vaultId TEXT PRIMARY KEY, userId TEXT NOT NULL,
                   role TEXT NOT NULL, wrappedVk TEXT NOT NULL, rev INTEGER NOT NULL, sealedVk TEXT)""",
            )
            db.exec(
                """CREATE TABLE vaults(vaultId TEXT PRIMARY KEY, type TEXT NOT NULL,
                   rev INTEGER NOT NULL, metaBlob TEXT NOT NULL, createdAt INTEGER NOT NULL)""",
            )
            db.exec(
                """CREATE TABLE queue(seq INTEGER PRIMARY KEY AUTOINCREMENT,
                   mutationId TEXT NOT NULL UNIQUE, vaultId TEXT NOT NULL, json TEXT NOT NULL)""",
            )
            db.exec("INSERT INTO kv(key,value) VALUES('userId',?)", userId)
            db.exec("INSERT INTO kv(key,value) VALUES('cursor','42')")
            db.exec(
                "INSERT INTO items(itemId,vaultId,rev,createdAt,updatedAt,deleted,conflict,formatVersion,attachmentIds,blob) VALUES(?,?,?,?,?,?,?,?,?,?)",
                wireItem.itemId, wireItem.vaultId, wireItem.rev, wireItem.createdAt, wireItem.updatedAt, 0, 1, wireItem.formatVersion, """["a1"]""", wireItem.blob,
            )
            db.exec("INSERT INTO grants(vaultId,userId,role,wrappedVk,rev,sealedVk) VALUES(?,?,?,?,?,?)", wireGrant.vaultId, wireGrant.userId, wireGrant.role, wireGrant.wrappedVk, wireGrant.rev, wireGrant.sealedVk)
            db.exec("INSERT INTO vaults(vaultId,type,rev,metaBlob,createdAt) VALUES(?,?,?,?,?)", wireVault.vaultId, wireVault.type, wireVault.rev, wireVault.metaBlob, wireVault.createdAt)
            val m = mutation("m1", "v1")
            db.exec("INSERT INTO queue(mutationId,vaultId,json) VALUES(?,?,?)", m.mutationId, m.vaultId, json.encodeToString(Mutation.serializer(), m))
        }
        db.userVersion = 1
        db.close()
    }

    @Test
    fun v1ToV2MigrationPreservesEveryRowAndAddsEmptyLifecycleState() {
        val path = newPath()
        buildV1Db(path, "u1")

        val cache = sqliteVaultCache(path, "u1")
        // Every v1 row intact:
        assertEquals(42L, cache.cursor())
        assertEquals(wireItem, cache.envelopes().single())
        assertEquals(wireGrant, cache.grants().single())
        assertEquals(wireVault, cache.vaults().single())
        assertEquals(listOf(mutation("m1", "v1")), cache.pending()) // a v1 queue row is NOT staged
        // New lifecycle state present and empty:
        assertTrue(cache.heldVaults().isEmpty())
        assertTrue(cache.stagedDenied().isEmpty())
        assertFalse(cache.isConsumedDeleteId("any"))
        assertEquals(0L, cache.lastVerifiedTransferSeq("v1"))
        // The staged-denied state works on the migrated queue table (column was ALTERed in):
        cache.markStagedDenied("m1")
        assertTrue(cache.pending().isEmpty())
        assertEquals(listOf(mutation("m1", "v1")), cache.stagedDenied())
        cache.close()

        val raw = openSqlBox(path)
        assertEquals(2, raw.userVersion)
        raw.close()
    }

    @Test
    fun heldVaultRecordRoundTripsDurably() {
        val path = newPath()
        val record = HeldVaultRecord(
            vault = wireVault.copy(
                pendingTransfer = PendingTransfer("u2", "offer-1", "PROOF", 123L, 4L),
                lastTransfer = TransferRecord("offer-0", "u1", "ACCEPT", 3L, "ab".repeat(32)),
                restoreProof = "RESTORE", deleteId = "del-0",
            ),
            grant = wireGrant,
            items = listOf(wireItem, wireItem.copy(itemId = "i2", blob = null, deleted = true)),
            reason = "deleted",
            verified = true,
            purgeAt = 999L,
            deleteId = "del-1",
            parked = listOf(mutation("m1", "v1"), mutation("m2", "v1")),
            expungeAt = 888L,
        )
        val cache = sqliteVaultCache(path, "u1")
        cache.putHeld(record)
        cache.addConsumedDeleteId("del-1")
        cache.setLastVerifiedTransferSeq("v1", 4)
        cache.close()

        val reopened = sqliteVaultCache(path, "u1") // "process restart"
        assertEquals(record, reopened.getHeld("v1"))
        assertEquals(listOf(record), reopened.heldVaults())
        assertTrue(reopened.isConsumedDeleteId("del-1"))
        assertEquals(4L, reopened.lastVerifiedTransferSeq("v1"))
        reopened.removeHeld("v1")
        assertNull(reopened.getHeld("v1"))
        reopened.close()
    }

    @Test
    fun stagedDeniedStateSurvivesReopen_andReenqueueResetsIt() {
        val path = newPath()
        val cache = sqliteVaultCache(path, "u1")
        cache.enqueue(mutation("m1", "v1"))
        cache.enqueue(mutation("m2", "v2"))
        cache.markStagedDenied("m1")
        cache.close()

        val reopened = sqliteVaultCache(path, "u1")
        assertEquals(listOf(mutation("m2", "v2")), reopened.pending()) // staged row never re-pushed blindly
        assertEquals(listOf(mutation("m1", "v1")), reopened.stagedDenied()) // …but survives death (F21)
        // Re-enqueue (reinstate replay) returns the row to the pushable state.
        reopened.enqueue(mutation("m1", "v1"))
        assertEquals(2, reopened.pending().size)
        assertTrue(reopened.stagedDenied().isEmpty())
        // dropPending removes rows in EITHER state.
        reopened.markStagedDenied("m1")
        reopened.dropPending("v1")
        assertTrue(reopened.stagedDenied().isEmpty())
        assertEquals(listOf(mutation("m2", "v2")), reopened.pending())
        reopened.close()
    }

    @Test
    fun clearPreservesLifecycleSafetyState() {
        val path = newPath()
        val cache = sqliteVaultCache(path, "u1")
        cache.setCursor(9)
        cache.upsertVault(wireVault)
        cache.upsertGrant(wireGrant)
        cache.upsertItem(wireItem, null)
        cache.enqueue(mutation("m1", "v1"))
        cache.markStagedDenied("m1")
        cache.putHeld(HeldVaultRecord(wireVault, wireGrant, emptyList(), "removed", false, null, null, emptyList(), 777L))
        cache.addConsumedDeleteId("del-1")
        cache.setLastVerifiedTransferSeq("v1", 2)

        cache.clear() // the 410-resync wipe

        // Rows + cursor gone…
        assertEquals(0L, cache.cursor())
        assertTrue(cache.envelopes().isEmpty() && cache.grants().isEmpty() && cache.vaults().isEmpty())
        // …but every piece of safety state survives (like the queue always has).
        assertEquals(listOf(mutation("m1", "v1")), cache.stagedDenied())
        assertEquals("v1", cache.heldVaults().single().vault.vaultId)
        assertTrue(cache.isConsumedDeleteId("del-1"))
        assertEquals(2L, cache.lastVerifiedTransferSeq("v1"))
        cache.close()
    }

    @Test
    fun accountMismatchWipesEverythingIncludingLifecycleState() {
        val path = newPath()
        val cache = sqliteVaultCache(path, "u1")
        cache.setCursor(9)
        cache.upsertVault(wireVault)
        cache.enqueue(mutation("m1", "v1"))
        cache.putHeld(HeldVaultRecord(wireVault, wireGrant, emptyList(), "removed", false, null, null, emptyList(), 777L))
        cache.addConsumedDeleteId("del-1")
        cache.setLastVerifiedTransferSeq("v1", 2)
        cache.close()

        val other = sqliteVaultCache(path, "u2") // different account → full wipe
        assertEquals(0L, other.cursor())
        assertTrue(other.vaults().isEmpty())
        assertTrue(other.pending().isEmpty() && other.stagedDenied().isEmpty())
        assertTrue(other.heldVaults().isEmpty())
        assertFalse(other.isConsumedDeleteId("del-1"))
        assertEquals(0L, other.lastVerifiedTransferSeq("v1"))
        other.close()
    }
}
