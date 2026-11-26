package io.silencelen.andvari.server

import io.ktor.client.statement.bodyAsText
import io.ktor.http.HttpMethod
import io.ktor.server.testing.testApplication
import io.silencelen.andvari.core.model.wire.AccountSummary
import io.silencelen.andvari.core.model.wire.WireJson
import kotlinx.serialization.builtins.ListSerializer
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue

/**
 * The server's cost of the meters: the operator's accounts list computes every account's meters, which
 * are aggregates over its items. In one hold of the database lock that was about 310 ms for 300 accounts of 300 items
 * and about 850 ms at 1,000 items each (measured on this build), and every other request waited. The list now holds the
 * lock once per account, so another request is served while a list is being read.
 */
class AccountsListLockTest {
    private fun seed(s: Services, accounts: Int, itemsEach: Int, blobChars: Int) {
        val blob = "A".repeat(blobChars)
        s.db.tx { c ->
            repeat(accounts) { n ->
                val u = uuid(); val v = uuid()
                c.exec(
                    """INSERT INTO users(userId,email,displayName,kdfSalt,kdfParams,verifier,wrappedUvk,identityPub,encryptedIdentitySeed,genesis,personalVaultId,role,createdAt,registeredVia)
                       VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                    u, "u$n@example.com", "User $n", "AAAA", encodeParams(TestKit.FAST_KDF), "x", "AAAA", "AAAA", "AAAA", "AAAA", v, "member", 1_800_000_000_000L + n, "enrol",
                )
                c.exec("INSERT INTO vaults(vaultId,type,rev,metaBlob,createdAt) VALUES(?,?,?,?,?)", v, "personal", 1, "AAAA", 1_800_000_000_000L)
                c.exec("INSERT INTO grants(vaultId,userId,role,addedAt,wrappedVk,rev) VALUES(?,?,?,?,?,?)", v, u, "owner", 1_800_000_000_000L, "AAAA", 1)
                repeat(2) { d -> c.exec("INSERT INTO devices(deviceId,userId,platform,name,how,createdAt,lastSeenAt) VALUES(?,?,?,?,?,?,?)", uuid(), u, "linux", "d$d", "registered", 1L, 2L) }
                repeat(itemsEach) { i ->
                    c.exec(
                        "INSERT INTO items(itemId,vaultId,rev,createdAt,updatedAt,formatVersion,blob,blobSize) VALUES(?,?,?,?,?,?,?,?)",
                        uuid(), v, i + 1L, 1L, 1L, 2, blob, blobChars.toLong(),
                    )
                }
            }
        }
    }

    @Test
    fun anotherRequestIsServed_whileTheListIsRead() = testApplication {
        val s = TestKit.services()
        application { andvariModule(s) }
        val c = client
        val op = Flow.finishSetup(c, s)
        seed(s, 6, 20, 100)
        val other = Executors.newSingleThreadExecutor()
        var between = 0
        val served = ArrayList<Boolean>()
        try {
            // Between two rows of the list, another request's read of the database gets the lock at once.
            s.raceHook = { p ->
                if (p == "accounts.betweenRows" && between++ == 3) {
                    served += runCatching { other.submit<Long> { s.db.read { it.count("SELECT COUNT(*) FROM users") } }.get(5, TimeUnit.SECONDS) }.isSuccess
                }
            }
            val r = c.call(HttpMethod.Get, "/api/v1/admin/accounts", token = op.token)
            assertEquals(200, r.status.value, r.bodyAsText())
            val rows = WireJson.json.decodeFromString(ListSerializer(AccountSummary.serializer()), r.bodyAsText())
            assertEquals(7, rows.size)
            assertTrue(rows.filter { it.userId != op.userId }.all { it.itemCount == 20L && it.quota!!.accountBytes.used == 2_000L })
            assertEquals(listOf(true), served, "the other request was served while the list was read")
        } finally {
            s.raceHook = null
            other.shutdownNow()
        }
    }

    /** The measurement behind the change, printed (`ACCOUNTS-LIST-LOCK`): the whole list, and the longest hold of the lock. */
    @Test
    fun measure_theLongestHoldIsOneAccount() {
        val s = TestKit.services()
        try {
            seed(s, 300, 300, 1_500)
            val holds = ArrayList<Long>()
            var last = 0L
            s.raceHook = { p -> if (p == "accounts.betweenRows") { val t = System.nanoTime(); if (last != 0L) holds += t - last; last = t } }
            OperatorRules.summaries(s, s.clock.now()) // warm
            holds.clear(); last = 0L
            val t0 = System.nanoTime()
            val rows = OperatorRules.summaries(s, s.clock.now())
            val totalMs = (System.nanoTime() - t0) / 1_000_000
            val maxHoldMs = holds.max() / 1_000_000.0
            println("ACCOUNTS-LIST-LOCK accounts=300 itemsEach=300 blobChars=1500 listMs=$totalMs longestHoldMs=$maxHoldMs medianHoldMs=${holds.sorted()[holds.size / 2] / 1_000_000.0}")
            assertEquals(300, rows.size)
        } finally {
            s.raceHook = null
            s.close()
        }
    }
}
