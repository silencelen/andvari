package io.silencelen.andvari.server

import io.ktor.client.HttpClient
import io.ktor.client.statement.HttpResponse
import io.ktor.client.statement.bodyAsText
import io.ktor.http.HttpMethod
import io.ktor.server.testing.testApplication
import io.silencelen.andvari.core.crypto.Bytes
import io.silencelen.andvari.core.model.wire.LogAppendResponse
import io.silencelen.andvari.core.model.wire.LogHead
import io.silencelen.andvari.core.model.wire.LogPage
import io.silencelen.andvari.core.model.wire.WireJson
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import kotlinx.serialization.json.long
import io.silencelen.andvari.core.trust.LogEntry
import io.silencelen.andvari.core.trust.MemberRole
import io.silencelen.andvari.core.trust.VaultLog
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNotNull

/** A shared vault's life after its grace ends (spec 03 §10.3 step 5, §11.1): the purge is final. */
class VaultLifecycleTest {
    private val crypto = TestKit.crypto
    private fun b16() = Bytes.toB64(crypto.randomBytes(16))
    private fun sign(me: Me, e: LogEntry): String = Bytes.toB64(VaultLog.sign(crypto, me.identity.sign, e))

    private suspend fun HttpClient.append(me: Me, vaultId: String, frame: String, side: String = ""): HttpResponse =
        call(HttpMethod.Post, "/api/v1/vaults/$vaultId/log", """{"entry":"$frame"$side}""", me.token)

    private suspend fun HttpResponse.head(): LogAppendResponse {
        assertEquals(200, status.value, bodyAsText())
        return WireJson.json.decodeFromString(LogAppendResponse.serializer(), bodyAsText())
    }

    private fun JsonObject.grace(): Pair<Long, Long>? = (this["deleted"] as? JsonObject)?.let {
        it["deletedAt"]!!.jsonPrimitive.long to it["purgeAt"]!!.jsonPrimitive.long
    }

    private suspend fun HttpResponse.json(): JsonObject {
        assertEquals(200, status.value, bodyAsText())
        return WireJson.json.parseToJsonElement(bodyAsText()).jsonObject
    }

    private fun JsonObject.logHead() = WireJson.json.decodeFromJsonElement(LogHead.serializer(), this["head"]!!)

    /**
     * A deleted vault's grace end is the server's stored `purgeAt` (spec 03 §10.3, §10.6, §11.2): the
     * append answer of the `delete`, every later answer while the vault is in grace, the log fetch of the
     * members who see the delete and the deleted-vaults list all carry the same `{deletedAt, purgeAt}`;
     * an account cut off before the delete, a live vault and a restored one carry no `deleted` at all.
     */
    @Test
    fun theGraceEnd_isSentWhereAClientLearnsOfTheDelete() = testApplication {
        val clock = MutableClock(1_800_000_000_000L)
        val s = TestKit.services(clock = clock)
        application { andvariModule(s) }
        val c = client
        Flow.finishSetup(c, s)
        val a = Flow.member(c, s, "a@example.com")
        val b = Flow.member(c, s, "b@example.com")
        val d = Flow.member(c, s, "d@example.com")
        s.db.tx { writeConnection(it, a.userId, b.userId, clock.now()); writeConnection(it, a.userId, d.userId, clock.now()) }
        val vaultId = uuid()
        val t = clock.now()
        val g = c.append(a, vaultId, sign(a, LogEntry.Genesis(vaultId, a.userId, t, a.identity.identityPubB64, "a".repeat(64))), ""","metaBlob":"AAAA","wrappedVk":"AAAA"""").json()
        assertEquals(null, g["deleted"], "a live vault's answer has no deleted")
        var h = g.logHead()
        h = c.append(a, vaultId, sign(a, LogEntry.Add(vaultId, h.seq + 1, h.hash, a.userId, t, b.userId, b.identity.identityPubB64, MemberRole.WRITER, b16())), ""","grant":"AAAA"""").json().logHead()
        h = c.append(a, vaultId, sign(a, LogEntry.Add(vaultId, h.seq + 1, h.hash, a.userId, t, d.userId, d.identity.identityPubB64, MemberRole.READER, b16())), ""","grant":"AAAA"""").json().logHead()
        h = c.append(a, vaultId, sign(a, LogEntry.Remove(vaultId, h.seq + 1, h.hash, a.userId, t, d.userId))).json().logHead()
        assertEquals(null, c.call(HttpMethod.Get, "/api/v1/vaults/$vaultId/log", token = b.token).json()["deleted"], "no deleted before the delete")

        // The delete, a while later: the grace runs from the server's time of the append.
        clock.advance(20 * 60_000L)
        val deletedAt = clock.now()
        val expected = deletedAt to deletedAt + 7 * Clock.DAY_MS
        assertEquals(7 * Clock.DAY_MS, s.config.vaultGraceMs)
        val deleteId = b16()
        val deleteFrame = sign(a, LogEntry.Delete(vaultId, h.seq + 1, h.hash, a.userId, clock.now(), deleteId))
        val del = c.append(a, vaultId, deleteFrame).json()
        assertEquals(expected, del.grace(), "the delete's own answer")
        h = del.logHead()
        assertEquals(expected, s.db.read { db -> db.queryOne("SELECT deletedAt,purgeAt FROM vaults WHERE vaultId=?", vaultId) { it.getLong(1) to it.getLong(2) } })

        // A member who sees the delete learns the same time from the log fetch; the removed one learns nothing.
        clock.advance(60_000L)
        assertEquals(expected, c.call(HttpMethod.Get, "/api/v1/vaults/$vaultId/log", token = b.token).json().grace(), "member's log fetch")
        assertEquals(expected, c.call(HttpMethod.Get, "/api/v1/vaults/$vaultId/log?after=1", token = a.token).json().grace(), "owner's later page")
        val cut = c.call(HttpMethod.Get, "/api/v1/vaults/$vaultId/log", token = d.token).json()
        assertEquals(3L, cut.logHead().seq)
        assertEquals(null, cut["deleted"], "an account cut off before the delete")
        // The deleted-vaults list gives the same purgeAt.
        val listed = WireJson.json.parseToJsonElement(c.call(HttpMethod.Get, "/api/v1/vaults/deleted", token = a.token).bodyAsText()).jsonArray.single().jsonObject
        assertEquals(expected, listed["deletedAt"]!!.jsonPrimitive.long to listed["purgeAt"]!!.jsonPrimitive.long)

        // A leave during the grace and a retry of the delete answer it too: the time does not move.
        clock.advance(60_000L)
        val leave = c.append(b, vaultId, sign(b, LogEntry.Leave(vaultId, h.seq + 1, h.hash, b.userId, clock.now()))).json()
        assertEquals(expected, leave.grace(), "a leave in grace")
        h = leave.logHead()
        assertEquals(expected, c.append(a, vaultId, deleteFrame).json().grace(), "a retried delete")

        // A restore ends the grace: no deleted any more.
        val restore = c.append(a, vaultId, sign(a, LogEntry.Restore(vaultId, h.seq + 1, h.hash, a.userId, clock.now(), deleteId))).json()
        assertEquals(null, restore["deleted"])
        assertEquals(null, c.call(HttpMethod.Get, "/api/v1/vaults/$vaultId/log", token = a.token).json()["deleted"])
        // Core's wire types still decode both answers (the field is additive).
        WireJson.json.decodeFromString(LogAppendResponse.serializer(), del.toString())
        WireJson.json.decodeFromString(LogPage.serializer(), c.call(HttpMethod.Get, "/api/v1/vaults/$vaultId/log", token = b.token).bodyAsText())
    }

    @Test
    fun purgedVault_refusesEveryLaterEntry_andItsTombstoneStays() = testApplication {
        val clock = MutableClock(1_800_000_000_000L)
        val s = TestKit.services(clock = clock)
        application { andvariModule(s) }
        val c = client
        Flow.finishSetup(c, s)
        val a = Flow.member(c, s, "a@example.com")
        val b = Flow.member(c, s, "b@example.com")
        s.db.tx { writeConnection(it, a.userId, b.userId, clock.now()) }
        val vaultId = uuid()
        val t = clock.now()
        var h = c.append(a, vaultId, sign(a, LogEntry.Genesis(vaultId, a.userId, t, a.identity.identityPubB64, "a".repeat(64))), ""","metaBlob":"AAAA","wrappedVk":"AAAA"""").head().head
        h = c.append(a, vaultId, sign(a, LogEntry.Add(vaultId, h.seq + 1, h.hash, a.userId, t, b.userId, b.identity.identityPubB64, MemberRole.WRITER, b16())), ""","grant":"AAAA"""").head().head
        val deleteId = b16()
        h = c.append(a, vaultId, sign(a, LogEntry.Delete(vaultId, h.seq + 1, h.hash, a.userId, t, deleteId))).head().head
        // The grace ends and the janitor purges the vault.
        clock.advance((s.config.vaultGraceDays + 1) * Clock.DAY_MS)
        val tokA = s.db.tx { db -> s.sessions.issue(db, a.userId, a.deviceId, "linux", passwordLogin = true).accessToken }
        val tokB = s.db.tx { db -> s.sessions.issue(db, b.userId, b.deviceId, "linux", passwordLogin = true).accessToken }
        assertEquals(1L, s.janitor.purgeDueVaults(clock.now()))
        val a2 = Me(a.email, a.userId, a.identity).also { it.session = a.session!!.copy(accessToken = tokA) }
        val b2 = Me(b.email, b.userId, b.identity).also { it.session = b.session!!.copy(accessToken = tokB) }
        val at = clock.now()
        // The owner's restore after the purge is refused: no grant comes back, nothing is written.
        val restore = c.append(a2, vaultId, sign(a2, LogEntry.Restore(vaultId, h.seq + 1, h.hash, a.userId, at, deleteId)))
        assertEquals(403, restore.status.value, restore.bodyAsText())
        assertEquals("no_grant", restore.errorCode())
        // So is a member's leave, and the owner's second delete.
        assertEquals("no_grant", c.append(b2, vaultId, sign(b2, LogEntry.Leave(vaultId, h.seq + 1, h.hash, b.userId, at))).errorCode())
        assertEquals("no_grant", c.append(a2, vaultId, sign(a2, LogEntry.Delete(vaultId, h.seq + 1, h.hash, a.userId, at, b16()))).errorCode())
        s.db.read { db ->
            assertEquals(h.seq, db.queryOne("SELECT MAX(seq) FROM vault_log WHERE vaultId=?", vaultId) { it.getLong(1) })
            assertEquals(0L, db.count("SELECT COUNT(*) FROM grants WHERE vaultId=? AND revokedAt IS NULL", vaultId))
            assertEquals(0L, db.count("SELECT COUNT(*) FROM grants WHERE vaultId=? AND wrappedVk<>''", vaultId))
            assertNotNull(db.queryOne("SELECT purgedAt FROM vaults WHERE vaultId=?", vaultId) { it.longOrNull("purgedAt") })
            assertEquals(null, db.queryOne("SELECT deletedAt FROM vaults WHERE vaultId=? AND deletedAt IS NULL", vaultId) { 1 })
        }
        // Both former members still read the tombstoned log, marked purged.
        for (tok in listOf(tokA, tokB)) {
            val page = WireJson.json.decodeFromString(LogPage.serializer(), c.call(HttpMethod.Get, "/api/v1/vaults/$vaultId/log", token = tok).bodyAsText())
            assertEquals(h.seq, page.head.seq)
            assertNotNull(page.purged)
        }
        // A byte-identical retry of the delete still answers with the head, as any retry does.
        assertEquals(200, c.append(a2, vaultId, sign(a2, LogEntry.Delete(vaultId, 2, s.db.read { db -> VaultLogs.headAt(db, vaultId, 1)!!.hash }, a.userId, t, deleteId))).status.value)
        // A year after the purge the log rows go; the vault id is never reused.
        clock.advance(Janitor.TOMBSTONE_LOG_RETENTION_MS + Clock.DAY_MS)
        s.janitor.sweep(clock.now())
        assertEquals(0L, s.db.read { it.count("SELECT COUNT(*) FROM vault_log WHERE vaultId=?", vaultId) })
        val tokA3 = s.db.tx { db -> s.sessions.issue(db, a.userId, a.deviceId, "linux", passwordLogin = true).accessToken }
        val a3 = Me(a.email, a.userId, a.identity).also { it.session = a.session!!.copy(accessToken = tokA3) }
        assertEquals("vault_id_taken", c.append(a3, vaultId, sign(a3, LogEntry.Genesis(vaultId, a.userId, clock.now(), a.identity.identityPubB64, "a".repeat(64))), ""","metaBlob":"AAAA","wrappedVk":"AAAA"""").errorCode())
    }
}
