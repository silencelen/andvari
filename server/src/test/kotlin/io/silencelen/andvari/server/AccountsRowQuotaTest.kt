package io.silencelen.andvari.server

import io.ktor.client.HttpClient
import io.ktor.client.statement.bodyAsText
import io.ktor.http.HttpMethod
import io.ktor.server.testing.testApplication
import io.silencelen.andvari.core.model.wire.AccountSummary
import io.silencelen.andvari.core.model.wire.MutationStatus
import io.silencelen.andvari.core.model.wire.QuotaMeter
import io.silencelen.andvari.core.model.wire.QuotaUse
import io.silencelen.andvari.core.model.wire.WireJson
import io.silencelen.andvari.core.trust.LogEntry
import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.jsonObject
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue

/**
 * The operator's accounts list carries each account's meters (spec 03 §7.1, §14.4): the same `quota` object the account
 * itself reads on `GET /sync`, so the console shows use against the limit in force, and the row predicts the same checks.
 */
class AccountsRowQuotaTest {
    /** Every row of `GET /admin/accounts`, by userId: the summary as an old client decodes it, and the row's `quota`. */
    private suspend fun HttpClient.rows(op: Me): Map<String, Pair<AccountSummary, QuotaUse>> {
        val r = call(HttpMethod.Get, "/api/v1/admin/accounts", token = op.token)
        assertEquals(200, r.status.value, r.bodyAsText())
        return WireJson.json.parseToJsonElement(r.bodyAsText()).jsonArray.associate { e ->
            val row = WireJson.json.decodeFromJsonElement(AccountSummary.serializer(), e)
            row.userId to (row to WireJson.json.decodeFromJsonElement(QuotaUse.serializer(), e.jsonObject["quota"] ?: error("no quota on the row")))
        }
    }

    @Test
    fun eachRowCarriesTheMetersItsAccountIsTold_atEachStepToAndPastEachLimit() = testApplication {
        val clock = MutableClock()
        val s = TestKit.services(clock = clock)
        application { andvariModule(s) }
        val c = client
        val op = Flow.finishSetup(c, s)
        val a = Flow.member(c, s, "a@example.com")
        val b = Flow.member(c, s, "b@example.com")

        /** The row of each of [who] equals what that account is told, and the old fields agree with it. */
        suspend fun same(vararg who: Me): Map<String, QuotaUse> {
            val rows = c.rows(op)
            return who.associate { m ->
                val (row, q) = rows.getValue(m.userId)
                assertEquals(c.meters(m), q, "the row of ${m.email}")
                assertEquals(q.accountBytes.used, row.usedBytes); assertEquals(q.items.used, row.itemCount)
                m.userId to q
            }
        }
        val defaults = QuotaUse(QuotaMeter(0, 104_857_600), QuotaMeter(0, 5_000), QuotaMeter(0, 50), QuotaMeter(0, 20))
        val start = same(op, a, b)
        assertEquals(setOf(defaults), start.values.toSet())

        fun put(bytes: String, items: String, vaults: String, links: String) =
            """{"accountBytes":$bytes,"items":$items,"ownedSharedVaults":$vaults,"openLinks":$links,"currentAuthKey":"${op.authKey}"}"""
        assertEquals(200, c.call(HttpMethod.Put, "/api/v1/admin/accounts/${a.userId}/quota", put("14", "2", "1", "1"), op.token).status.value)
        assertEquals(QuotaUse(QuotaMeter(0, 14), QuotaMeter(0, 2), QuotaMeter(0, 1), QuotaMeter(0, 1)), same(a, b)[a.userId])

        // Owned shared vaults: to the limit, then refused.
        SharedVault(c, s, a).create()
        assertEquals(QuotaMeter(1, 1), same(a)[a.userId]!!.ownedSharedVaults)
        val second = SharedVault(c, s, a)
        val g = second.append(a, LogEntry.Genesis(second.vaultId, a.userId, second.at, a.identity.identityPubB64, "a".repeat(64)), ""","metaBlob":"AAAA","wrappedVk":"AAAA"""")
        assertEquals(413, g.status.value); assertTrue(g.bodyAsText().contains("\"quota\":\"ownedSharedVaults\""))

        // Bytes: a push that lands on the limit, then one byte past it.
        assertEquals(MutationStatus.APPLIED, c.putItem(a, a.personalVaultId, blob = "A".repeat(14)).status)
        assertEquals(QuotaMeter(14, 14), same(a)[a.userId]!!.accountBytes)
        assertEquals("quota_exceeded", c.putItem(a, a.personalVaultId, blob = "A").reason)

        // Items: bytes back to the default, then to the limit and past it.
        assertEquals(200, c.call(HttpMethod.Put, "/api/v1/admin/accounts/${a.userId}/quota", put("null", "2", "1", "1"), op.token).status.value)
        assertEquals(QuotaMeter(14, 104_857_600), same(a)[a.userId]!!.accountBytes)
        assertEquals(MutationStatus.APPLIED, c.putItem(a, a.personalVaultId).status)
        assertEquals(QuotaMeter(2, 2), same(a)[a.userId]!!.items)
        assertEquals("quota_exceeded", c.putItem(a, a.personalVaultId).reason)

        // Open links: to the limit, then refused; at its expiry the row drops it as the account's own answer does.
        val link = """{"linkId":"${b16()}","kind":"connect","offer":"AAAAAAAAAAAA","expiresAt":${clock.now() + 60_000}}"""
        assertEquals(201, c.call(HttpMethod.Post, "/api/v1/links", link, a.token).status.value)
        assertEquals(QuotaMeter(1, 1), same(a)[a.userId]!!.openLinks)
        val more = c.call(HttpMethod.Post, "/api/v1/links", """{"linkId":"${b16()}","kind":"connect","offer":"AAAAAAAAAAAA","expiresAt":${clock.now() + 60_000}}""", a.token)
        assertEquals(413, more.status.value)
        clock.advance(60_000)
        assertEquals(QuotaMeter(0, 1), same(a)[a.userId]!!.openLinks)

        // Nothing of a's shows on anyone else's row.
        val end = same(op, a, b)
        assertEquals(defaults, end[b.userId]); assertEquals(defaults, end[op.userId])
    }
}
