package io.silencelen.andvari.server

import java.io.File
import java.sql.Connection
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue

/**
 * The use-and-limits sums (spec 03 §14.4:`Quotas.ownedBytes`, `ownedItems`, `vaultBytes`, `vaultItems`) read only the
 * covering index `items(vaultId, deleted, blobSize)`, never the item rows with their ciphertext. Measured on one
 * database before (the index dropped) and after (the index as the baseline has it); the timings are printed, the
 * query plans asserted.
 */
class ItemsUseIndexTest {
    private val owner = "owner-0"
    private val vaults = 20
    private val perVault = 1_000
    private val blob = "A".repeat(2_048)

    private fun fill(c: Connection) {
        c.exec(
            """INSERT INTO users(userId,email,displayName,kdfSalt,kdfParams,verifier,wrappedUvk,identityPub,encryptedIdentitySeed,genesis,personalVaultId,role,createdAt,registeredVia)
               VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
            owner, "o@example.com", "O", "AAAA", "{}", "v", "AAAA", "AAAA", "AAAA", "AAAA", "v-0", "member", 1L, "enrol",
        )
        c.prepareStatement("INSERT INTO items(itemId,vaultId,rev,createdAt,updatedAt,deleted,formatVersion,blob,blobSize) VALUES(?,?,?,?,?,?,2,?,?)").use { ps ->
            for (v in 0 until vaults) {
                c.exec("INSERT INTO vaults(vaultId,type,rev,metaBlob,createdAt) VALUES(?,?,0,'AAAA',1)", "v-$v", if (v == 0) "personal" else "shared")
                c.exec("INSERT INTO grants(vaultId,userId,role,addedAt,wrappedVk,rev) VALUES(?,?,'owner',1,'AAAA',0)", "v-$v", owner)
                for (i in 0 until perVault) {
                    val deleted = i % 4 == 0
                    ps.setString(1, "i-$v-$i"); ps.setString(2, "v-$v"); ps.setLong(3, i.toLong()); ps.setLong(4, 1); ps.setLong(5, 1)
                    ps.setInt(6, if (deleted) 1 else 0)
                    if (deleted) ps.setNull(7, java.sql.Types.VARCHAR) else ps.setString(7, blob)
                    ps.setLong(8, if (deleted) 0 else blob.length.toLong())
                    ps.addBatch()
                }
                ps.executeBatch()
            }
        }
    }

    private fun plan(c: Connection, sql: String, vararg args: Any?): String =
        c.queryAll("EXPLAIN QUERY PLAN $sql", *args) { it.getString("detail") }.joinToString(" | ")

    /** Median microseconds of one call over [n] calls, and the last result. */
    private fun time(n: Int, f: () -> Long): Pair<Long, Long> {
        var r = 0L
        val us = (0 until n).map { val t = System.nanoTime(); r = f(); (System.nanoTime() - t) / 1_000 }.sorted()
        return us[n / 2] to r
    }

    @Test
    fun theUseSumsReadOnlyTheCoveringIndex_measuredBeforeAndAfter() {
        val path = File(TestKit.tempDir(), "andvari.db").path
        Db(path, durable = false).use { db ->
            db.tx { fill(it) }
            val bytesSql = "SELECT COALESCE(SUM(blobSize),0) FROM items WHERE vaultId=? AND deleted=0"
            fun measure(label: String): List<Long> = db.read { c ->
                c.createStatement().use { it.execute("ANALYZE") }
                val owned = time(41) { Quotas.ownedBytes(c, owner) }
                val items = time(41) { Quotas.ownedItems(c, owner) }
                val one = time(201) { Quotas.vaultBytes(c, "v-3") }
                println(
                    "[measure] $label: ownedBytes ${owned.first} us, ownedItems ${items.first} us, vaultBytes ${one.first} us " +
                        "(median; $vaults vaults × $perVault items of ${blob.length} B, a quarter deleted); plan: ${plan(c, bytesSql, "v-3")}",
                )
                listOf(owned.second, items.second, one.second)
            }
            val after = measure("with the index")
            assertTrue("COVERING INDEX idx_items_vault_live_size" in db.read { plan(it, bytesSql, "v-3") })
            assertTrue("COVERING INDEX idx_items_vault_live_size" in db.read { plan(it, "SELECT COUNT(*) FROM items WHERE vaultId=? AND deleted=0", "v-3") })
            db.tx { it.exec("DROP INDEX idx_items_vault_live_size") }
            val before = measure("without the index")
            assertTrue("idx_items_vault_live_size" !in db.read { plan(it, bytesSql, "v-3") })
            assertEquals(before, after)
            val live = perVault - perVault / 4
            assertEquals(listOf(vaults.toLong() * live * blob.length, vaults.toLong() * live, live.toLong() * blob.length), after)
        }
        // The next start puts the dropped index back (the start-up step, spec 02 §5.1).
        Db(path, durable = false).use { db -> assertEquals(listOf("created index idx_items_vault_live_size"), db.addedAtStart) }
    }
}
