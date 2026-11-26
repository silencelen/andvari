package io.silencelen.andvari.server

import io.ktor.client.HttpClient
import io.ktor.client.statement.bodyAsText
import io.ktor.http.HttpMethod
import io.ktor.server.testing.testApplication
import io.silencelen.andvari.core.model.wire.MutationStatus
import io.silencelen.andvari.core.model.wire.PushResponse
import io.silencelen.andvari.core.model.wire.QuotaMeter
import io.silencelen.andvari.core.model.wire.QuotaUse
import io.silencelen.andvari.core.model.wire.SyncResponse
import io.silencelen.andvari.core.model.wire.WireJson
import io.silencelen.andvari.core.trust.LogEntry
import kotlinx.serialization.json.jsonObject
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue

/**
 * An account's own meters on `GET /sync` (spec 03 §4, §14.4 "What an account is told"): for each limited thing, the
 * `used` it is told plus what it adds predicts the quota check exactly (a step that lands on the limit is accepted, one
 * that passes it by one is refused); an operator's change shows at the next read; no other account's use appears.
 */
class QuotaUseTest {
    private val defaults = QuotaUse(QuotaMeter(0, 104_857_600), QuotaMeter(0, 5_000), QuotaMeter(0, 50), QuotaMeter(0, 20))

    private fun limit(s: Services, who: Me, column: String, value: Int?) {
        // What `andvari admin quota` writes (the operator's route is exercised in operatorsChange…).
        s.db.tx { it.exec("UPDATE users SET $column=? WHERE userId=?", value?.toLong(), who.userId) }
    }

    private fun blob(n: Int) = "A".repeat(n)

    private suspend fun HttpClient.restore(me: Me, itemId: String, blob: String) =
        call(HttpMethod.Post, "/api/v1/items/$itemId/restore", """{"formatVersion":2,"attachmentIds":[],"blob":"$blob"}""", me.token)

    private suspend fun HttpClient.newLink(me: Me, expiresAt: Long) =
        call(HttpMethod.Post, "/api/v1/links", """{"linkId":"${b16()}","kind":"connect","offer":"AAAAAAAAAAAA","expiresAt":$expiresAt}""", me.token)

    @Test
    fun accountBytes_theToldUsePredictsPushRestoreAndUpload_atTheLimit() = testApplication {
        val s = TestKit.services()
        application { andvariModule(s) }
        val c = client
        Flow.finishSetup(c, s)
        val a = Flow.member(c, s, "a@example.com")
        val pv = a.personalVaultId
        assertEquals(defaults, c.meters(a))

        // Item bytes are the blob's length.
        val firstId = uuid()
        val first = c.putItem(a, pv, firstId, blob = blob(8))
        assertEquals(QuotaMeter(8, 104_857_600), c.meters(a).accountBytes)

        // A push: room 7, an 8-byte item is refused; room 8, it lands exactly on the limit; then one byte more is refused.
        limit(s, a, "quotaAccountBytes", 8 + 7)
        assertEquals(QuotaMeter(8, 15), c.meters(a).accountBytes)
        val over = c.putItem(a, pv, blob = blob(8))
        assertEquals(MutationStatus.REJECTED, over.status); assertEquals("quota_exceeded", over.reason)
        limit(s, a, "quotaAccountBytes", 8 + 8)
        assertEquals(MutationStatus.APPLIED, c.putItem(a, pv, blob = blob(8)).status)
        assertEquals(QuotaMeter(16, 16), c.meters(a).accountBytes)
        assertEquals("quota_exceeded", c.putItem(a, pv, blob = blob(1)).reason)

        // An update counts only its growth.
        limit(s, a, "quotaAccountBytes", 16 + 2)
        assertEquals("quota_exceeded", c.putItem(a, pv, firstId, blob = blob(11), base = first.newItemRev!!).reason)
        val grown = c.putItem(a, pv, firstId, blob = blob(10), base = first.newItemRev!!)
        assertEquals(MutationStatus.APPLIED, grown.status)
        assertEquals(QuotaMeter(18, 18), c.meters(a).accountBytes)

        // An upload counts its stored size: the body less its 24-byte header.
        limit(s, a, "quotaAccountBytes", 18 + 63)
        val up1 = c.upload(a.token, uuid(), pv, uuid(), attachmentBytes(64))
        assertEquals(413, up1.status.value, up1.bodyAsText()); assertTrue(up1.bodyAsText().contains("\"quota\":\"accountBytes\""))
        assertEquals(QuotaMeter(18, 81), c.meters(a).accountBytes)
        limit(s, a, "quotaAccountBytes", 18 + 64)
        assertEquals(200, c.upload(a.token, uuid(), pv, uuid(), attachmentBytes(64)).status.value)
        assertEquals(QuotaMeter(82, 82), c.meters(a).accountBytes)
        assertEquals(413, c.upload(a.token, uuid(), pv, uuid(), attachmentBytes(1)).status.value)

        // A tombstone counts nothing; a restore counts its blob.
        assertEquals(MutationStatus.APPLIED, c.deleteItem(a, pv, firstId, grown.newItemRev!!).status)
        assertEquals(QuotaMeter(72, 82), c.meters(a).accountBytes)
        limit(s, a, "quotaAccountBytes", 72 + 9)
        val r1 = c.restore(a, firstId, blob(10))
        assertEquals(413, r1.status.value, r1.bodyAsText()); assertTrue(r1.bodyAsText().contains("\"quota\":\"accountBytes\""))
        limit(s, a, "quotaAccountBytes", 72 + 10)
        assertEquals(200, c.restore(a, firstId, blob(10)).status.value)
        assertEquals(QuotaMeter(82, 82), c.meters(a).accountBytes)

        // One push batch: each mutation sees the ones before it, so "used plus everything I add" is the test.
        limit(s, a, "quotaAccountBytes", 82 + 10)
        val batch = """{"mutations":[""" + listOf(6, 4, 1).joinToString(",") { n ->
            """{"mutationId":"${uuid()}","op":"put","itemId":"${uuid()}","vaultId":"$pv","baseItemRev":0,"item":{"formatVersion":2,"attachmentIds":[],"blob":"${blob(n)}"}}"""
        } + "]}"
        val pr = WireJson.json.decodeFromString(PushResponse.serializer(), c.call(HttpMethod.Post, "/api/v1/sync/push", batch, a.token).bodyAsText())
        assertEquals(listOf(MutationStatus.APPLIED, MutationStatus.APPLIED, MutationStatus.REJECTED), pr.results.map { it.status })
        assertEquals(QuotaMeter(92, 92), c.meters(a).accountBytes)
    }

    @Test
    fun items_theToldUsePredictsThePush_andASharedVaultsContentCountsOnItsOwnerOnly() = testApplication {
        val clock = MutableClock()
        val s = TestKit.services(clock = clock)
        application { andvariModule(s) }
        val c = client
        Flow.finishSetup(c, s)
        val a = Flow.member(c, s, "a@example.com")
        val b = Flow.member(c, s, "b@example.com")
        c.putItem(a, a.personalVaultId); c.putItem(a, a.personalVaultId)
        assertEquals(QuotaMeter(2, 5_000), c.meters(a).items)

        limit(s, a, "quotaItems", 3)
        assertEquals(MutationStatus.APPLIED, c.putItem(a, a.personalVaultId).status)
        assertEquals(QuotaMeter(3, 3), c.meters(a).items)
        val full = c.putItem(a, a.personalVaultId)
        assertEquals(MutationStatus.REJECTED, full.status); assertEquals("quota_exceeded", full.reason)

        // b writes into a's shared vault: a's meters, never b's. b's own meters say nothing about a's room.
        val v = SharedVault(c, s, a).create()
        v.add(b)
        val bBefore = c.meters(b)
        assertEquals(defaults, bBefore)
        assertEquals("quota_exceeded", c.putItem(b, v.vaultId, blob = blob(5)).reason)
        limit(s, a, "quotaItems", 4)
        assertEquals(MutationStatus.APPLIED, c.putItem(b, v.vaultId, blob = blob(5)).status)
        val am = c.meters(a)
        assertEquals(QuotaMeter(4, 4), am.items)
        assertEquals(QuotaMeter(17, 104_857_600), am.accountBytes)
        assertEquals(QuotaMeter(1, 50), am.ownedSharedVaults)
        assertEquals(bBefore, c.meters(b))
    }

    @Test
    fun ownedSharedVaults_theToldUsePredictsGenesisAndAccept_andAVaultInGraceStillCounts() = testApplication {
        val clock = MutableClock()
        val s = TestKit.services(clock = clock)
        application { andvariModule(s) }
        val c = client
        Flow.finishSetup(c, s)
        val a = Flow.member(c, s, "a@example.com")
        val b = Flow.member(c, s, "b@example.com")

        // Genesis: the personal vault is not counted; one below the limit is accepted, at the limit refused.
        limit(s, a, "quotaOwnedSharedVaults", 1)
        assertEquals(QuotaMeter(0, 1), c.meters(a).ownedSharedVaults)
        val v = SharedVault(c, s, a).create()
        assertEquals(QuotaMeter(1, 1), c.meters(a).ownedSharedVaults)
        val second = SharedVault(c, s, a)
        val g = second.append(a, LogEntry.Genesis(second.vaultId, a.userId, second.at, a.identity.identityPubB64, "a".repeat(64)), ""","metaBlob":"AAAA","wrappedVk":"AAAA"""")
        assertEquals(413, g.status.value, g.bodyAsText()); assertTrue(g.bodyAsText().contains("\"quota\":\"ownedSharedVaults\""))

        // Accept: the vault's whole content moves onto the new owner, each meter checked as "used + the vault's".
        v.add(b)
        assertEquals(MutationStatus.APPLIED, c.putItem(a, v.vaultId, blob = blob(30)).status)
        val offerId = b16()
        v.ok(a, LogEntry.Offer(v.vaultId, v.next, v.head, a.userId, v.at, b.userId, b.identity.identityPubB64, offerId, clock.now() + 60_000))
        suspend fun accept() = v.append(b, LogEntry.Accept(v.vaultId, v.next, v.head, b.userId, v.at, offerId), ""","wrappedVk":"AAAA"""")
        limit(s, b, "quotaOwnedSharedVaults", 0)
        assertTrue(accept().bodyAsText().contains("\"quota\":\"ownedSharedVaults\""))
        limit(s, b, "quotaOwnedSharedVaults", 1)
        c.putItem(b, b.personalVaultId, blob = blob(7))
        assertEquals(QuotaMeter(7, 104_857_600), c.meters(b).accountBytes)
        limit(s, b, "quotaAccountBytes", 7 + 29)
        assertTrue(accept().bodyAsText().contains("\"quota\":\"accountBytes\""))
        limit(s, b, "quotaAccountBytes", 7 + 30)
        limit(s, b, "quotaItems", 1)
        assertTrue(accept().bodyAsText().contains("\"quota\":\"items\""))
        limit(s, b, "quotaItems", 2)
        v.ok(b, LogEntry.Accept(v.vaultId, v.next, v.head, b.userId, v.at, offerId), ""","wrappedVk":"AAAA"""")
        assertEquals(QuotaUse(QuotaMeter(37, 37), QuotaMeter(2, 2), QuotaMeter(1, 1), QuotaMeter(0, 20)), c.meters(b))
        assertEquals(QuotaUse(QuotaMeter(0, 104_857_600), QuotaMeter(0, 5_000), QuotaMeter(0, 1), QuotaMeter(0, 20)), c.meters(a))

        // A vault deleted into its grace still counts, with its content, until it is purged.
        val gone = SharedVault(c, s, a).create()
        c.putItem(a, gone.vaultId, blob = blob(9))
        gone.ok(a, LogEntry.Delete(gone.vaultId, gone.next, gone.head, a.userId, gone.at, b16()))
        val after = c.meters(a)
        assertEquals(QuotaMeter(1, 1), after.ownedSharedVaults)
        assertEquals(QuotaMeter(9, 104_857_600), after.accountBytes)
        assertEquals(QuotaMeter(1, 5_000), after.items)
    }

    @Test
    fun openLinks_theToldUsePredictsTheCreate_andAnExpiredLinkStopsCounting() = testApplication {
        val clock = MutableClock()
        val s = TestKit.services(clock = clock)
        application { andvariModule(s) }
        val c = client
        Flow.finishSetup(c, s)
        val a = Flow.member(c, s, "a@example.com")
        limit(s, a, "quotaOpenLinks", 2)
        assertEquals(201, c.newLink(a, clock.now() + 60_000).status.value)
        assertEquals(QuotaMeter(1, 2), c.meters(a).openLinks)
        assertEquals(201, c.newLink(a, clock.now() + 120_000).status.value)
        assertEquals(QuotaMeter(2, 2), c.meters(a).openLinks)
        val full = c.newLink(a, clock.now() + 60_000)
        assertEquals(413, full.status.value); assertTrue(full.bodyAsText().contains("\"quota\":\"openLinks\""))
        // At its expiry a link stops counting, with no request from anyone.
        clock.advance(60_000)
        assertEquals(QuotaMeter(1, 2), c.meters(a).openLinks)
        assertEquals(201, c.newLink(a, clock.now() + 60_000).status.value)
        assertEquals(QuotaMeter(2, 2), c.meters(a).openLinks)
    }

    @Test
    fun operatorsChangeShowsAtTheNextRead_everyAnswerCarriesIt_andNoOtherAccountsUseAppears() = testApplication {
        val s = TestKit.services()
        application { andvariModule(s) }
        val c = client
        val op = Flow.finishSetup(c, s)
        val a = Flow.member(c, s, "a@example.com")
        val b = Flow.member(c, s, "b@example.com")
        c.putItem(a, a.personalVaultId, blob = blob(12))
        SharedVault(c, s, a).create()
        assertEquals(201, c.newLink(a, s.clock.now() + 60_000).status.value)
        assertEquals(QuotaUse(QuotaMeter(12, 104_857_600), QuotaMeter(1, 5_000), QuotaMeter(1, 50), QuotaMeter(1, 20)), c.meters(a))
        assertEquals(defaults, c.meters(b))
        assertEquals(defaults, c.meters(op))

        // The operator's per-account override, then back to the default.
        fun put(v: String) = """{"accountBytes":$v,"items":null,"ownedSharedVaults":${if (v == "null") "null" else "2"},"openLinks":null,"currentAuthKey":"${op.authKey}"}"""
        assertEquals(200, c.call(HttpMethod.Put, "/api/v1/admin/accounts/${a.userId}/quota", put("1000"), op.token).status.value)
        assertEquals(QuotaUse(QuotaMeter(12, 1_000), QuotaMeter(1, 5_000), QuotaMeter(1, 2), QuotaMeter(1, 20)), c.meters(a))
        assertEquals(defaults, c.meters(b))
        assertEquals(200, c.call(HttpMethod.Put, "/api/v1/admin/accounts/${a.userId}/quota", put("null"), op.token).status.value)
        assertEquals(QuotaMeter(12, 104_857_600), c.meters(a).accountBytes)

        // A change of the instance default shows for every account without an override.
        s.db.tx { s.policy.storeOn(it, s.policy.get().copy(quotaDefaults = s.policy.get().quotaDefaults.copy(items = 7))) }
        assertEquals(QuotaMeter(1, 7), c.meters(a).items)
        assertEquals(QuotaMeter(0, 7), c.meters(b).items)

        // A delta answer carries the meters too, and the object stays within its stated bound.
        val full = c.call(HttpMethod.Get, "/api/v1/sync?since=0", token = a.token).bodyAsText()
        val rev = WireJson.json.decodeFromString(SyncResponse.serializer(), full).rev
        assertEquals(c.meters(a), c.meters(a, since = rev))
        val m = Long.MAX_VALUE
        val widest = ",\"quota\":" + WireJson.json.encodeToString(QuotaUse.serializer(), QuotaUse(QuotaMeter(m, m), QuotaMeter(m, m), QuotaMeter(m, m), QuotaMeter(m, m)))
        assertEquals(QuotaUses.MAX_JSON_BYTES, widest.length)
    }
}

/** The caller's own meters, as `GET /sync` answers them (spec 03 §4). */
suspend fun HttpClient.meters(me: Me, since: Long = 0): QuotaUse {
    val r = call(HttpMethod.Get, "/api/v1/sync?since=$since", token = me.token)
    assertEquals(200, r.status.value, r.bodyAsText())
    val quota = WireJson.json.parseToJsonElement(r.bodyAsText()).jsonObject["quota"] ?: error("no quota in the /sync answer")
    return WireJson.json.decodeFromJsonElement(QuotaUse.serializer(), quota)
}
