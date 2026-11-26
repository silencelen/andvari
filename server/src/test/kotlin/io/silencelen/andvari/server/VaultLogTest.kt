package io.silencelen.andvari.server

import io.ktor.client.HttpClient
import io.ktor.client.statement.bodyAsText
import io.ktor.http.HttpMethod
import io.ktor.server.testing.testApplication
import io.silencelen.andvari.core.crypto.Bytes
import io.silencelen.andvari.core.model.wire.LogAppendResponse
import io.silencelen.andvari.core.model.wire.LogPage
import io.silencelen.andvari.core.model.wire.PushResponse
import io.silencelen.andvari.core.model.wire.SyncResponse
import io.silencelen.andvari.core.model.wire.WireJson
import io.silencelen.andvari.core.trust.LogEntry
import io.silencelen.andvari.core.trust.MemberRole
import io.silencelen.andvari.core.trust.VaultLog
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNotNull
import kotlin.test.assertTrue

/** The vault log routes (spec 03 §10, §11) against the shared verifier, and the data routes around them. */
class VaultLogTest {
    private val crypto = TestKit.crypto
    private fun b16() = Bytes.toB64(crypto.randomBytes(16))

    private class Log(val vaultId: String) {
        var seq = -1L
        var head = "0".repeat(64)
        var at = 1_800_000_000_000L
    }

    private fun sign(me: Me, e: LogEntry): String = Bytes.toB64(VaultLog.sign(crypto, me.identity.sign, e))

    private suspend fun HttpClient.post(me: Me, log: Log, frame: String, side: String = ""): io.ktor.client.statement.HttpResponse =
        call(HttpMethod.Post, "/api/v1/vaults/${log.vaultId}/log", """{"entry":"$frame"$side}""", me.token)

    private suspend fun HttpClient.ok(me: Me, log: Log, frame: String, side: String = ""): LogAppendResponse {
        val r = post(me, log, frame, side)
        assertEquals(200, r.status.value, r.bodyAsText())
        return WireJson.json.decodeFromString(LogAppendResponse.serializer(), r.bodyAsText()).also { log.seq = it.head.seq; log.head = it.head.hash; log.at = it.head.at }
    }

    private fun next(l: Log) = l.seq + 1

    @Test
    fun genesisAddLeaveDeleteRestore_accessRules_andTheData() = testApplication {
        val clock = MutableClock(1_800_000_000_000L)
        val s = TestKit.services(clock = clock)
        application { andvariModule(s) }
        val c = client
        Flow.finishSetup(c, s)
        val a = Flow.member(c, s, "a@example.com")
        val b = Flow.member(c, s, "b@example.com")
        val x = Flow.member(c, s, "x@example.com")
        val log = Log(uuid())
        val t = clock.now()
        val g = sign(a, LogEntry.Genesis(log.vaultId, a.userId, t, a.identity.identityPubB64, "a".repeat(64)))
        val r0 = c.ok(a, log, g, ""","metaBlob":"AAAA","wrappedVk":"AAAA"""")
        assertEquals(0, r0.head.seq)
        // The vault id is spent.
        assertEquals("vault_id_taken", c.post(x, Log(log.vaultId), sign(x, LogEntry.Genesis(log.vaultId, x.userId, t, x.identity.identityPubB64, "b".repeat(64))), ""","metaBlob":"AAAA","wrappedVk":"AAAA"""").errorCode())
        // A side field the kind does not take, and a missing one.
        assertEquals("bad_grant", c.post(a, log, sign(a, LogEntry.Add(log.vaultId, 1, log.head, a.userId, t, b.userId, b.identity.identityPubB64, MemberRole.WRITER, b16()))).errorCode())
        // add needs a connections row.
        val add = sign(a, LogEntry.Add(log.vaultId, 1, log.head, a.userId, t, b.userId, b.identity.identityPubB64, MemberRole.WRITER, b16()))
        assertEquals("not_connected", c.post(a, log, add, ""","grant":"AAAA"""").errorCode())
        s.db.tx { writeConnection(it, a.userId, b.userId, t) }
        c.ok(a, log, add, ""","grant":"AAAA"""")
        // A byte-identical retry answers 200 and changes nothing.
        val before = s.db.read { it.count("SELECT COUNT(*) FROM vault_log") }
        c.ok(a, log, add, ""","grant":"AAAA"""")
        assertEquals(before, s.db.read { it.count("SELECT COUNT(*) FROM vault_log") })
        // Non-members learn nothing; members cannot do the owner's part; a stale position carries the head.
        val stranger = sign(x, LogEntry.Leave(log.vaultId, next(log), log.head, x.userId, t))
        val nf = c.post(x, log, stranger)
        assertEquals("no_grant", nf.errorCode()); assertTrue(!nf.bodyAsText().contains("\"seq\""))
        assertEquals("no_grant", c.call(HttpMethod.Get, "/api/v1/vaults/${log.vaultId}/log", token = x.token).errorCode())
        assertEquals("not_vault_owner", c.post(b, log, sign(b, LogEntry.Remove(log.vaultId, next(log), log.head, b.userId, t, a.userId))).errorCode())
        val moved = c.post(a, log, sign(a, LogEntry.Delete(log.vaultId, 1, "0".repeat(64), a.userId, t, b16())))
        assertEquals("log_head_moved", moved.errorCode()); assertTrue(moved.bodyAsText().contains("\"seq\":1"))
        // The signer must be the caller.
        assertEquals("bad_signer", c.post(a, log, sign(b, LogEntry.Leave(log.vaultId, next(log), log.head, b.userId, t))).errorCode())
        // The `at` ceiling is the server's.
        assertEquals("at_ahead", c.post(a, log, sign(a, LogEntry.Delete(log.vaultId, next(log), log.head, a.userId, t + 11 * 60_000, b16()))).errorCode())
        // The verifier's own verdicts: removing the owner is a precondition failure.
        assertEquals("precondition", c.post(a, log, sign(a, LogEntry.Remove(log.vaultId, next(log), log.head, a.userId, t, a.userId))).errorCode())

        // The member sees the vault and its grant; it writes items into it.
        val sync = WireJson.json.decodeFromString(SyncResponse.serializer(), c.call(HttpMethod.Get, "/api/v1/sync?since=0", token = b.token).bodyAsText())
        val v = sync.vaults.single { it.vaultId == log.vaultId }
        assertEquals(1, v.logHead!!.seq)
        assertEquals("AAAA", sync.grants.single { it.vaultId == log.vaultId }.signedGrant)
        val itemId = uuid()
        val push = """{"mutations":[{"mutationId":"${uuid()}","op":"put","itemId":"$itemId","vaultId":"${log.vaultId}","baseItemRev":0,"item":{"formatVersion":2,"attachmentIds":[],"blob":"QUJD"}}]}"""
        val pr = WireJson.json.decodeFromString(PushResponse.serializer(), c.call(HttpMethod.Post, "/api/v1/sync/push", push, b.token).bodyAsText())
        assertEquals("applied", pr.results.single().status)
        // The owner's quota governs writes to its vault.
        s.db.tx { it.exec("UPDATE users SET quotaAccountBytes=10 WHERE userId=?", a.userId) }
        val push2 = """{"mutations":[{"mutationId":"${uuid()}","op":"put","itemId":"${uuid()}","vaultId":"${log.vaultId}","baseItemRev":0,"item":{"formatVersion":2,"attachmentIds":[],"blob":"QUJDREVGR0hJSktMTU5P"}}]}"""
        val pr2 = WireJson.json.decodeFromString(PushResponse.serializer(), c.call(HttpMethod.Post, "/api/v1/sync/push", push2, b.token).bodyAsText())
        assertEquals("rejected", pr2.results.single().status); assertEquals("quota_exceeded", pr2.results.single().reason)

        // Delete, then the member leaves during the grace; restore re-grants nobody who left.
        val deleteId = b16()
        c.ok(a, log, sign(a, LogEntry.Delete(log.vaultId, next(log), log.head, a.userId, t, deleteId)))
        assertTrue(c.call(HttpMethod.Get, "/api/v1/vaults/deleted", token = a.token).bodyAsText().contains(deleteId))
        // While deleted, every member still reads the whole log.
        val page = WireJson.json.decodeFromString(LogPage.serializer(), c.call(HttpMethod.Get, "/api/v1/vaults/${log.vaultId}/log", token = b.token).bodyAsText())
        assertEquals(3, page.entries.size)
        val leave = sign(b, LogEntry.Leave(log.vaultId, next(log), log.head, b.userId, t))
        c.ok(b, log, leave)
        // The retry of a leave whose own effect revoked the grant is still 200.
        c.ok(b, log, leave)
        c.ok(a, log, sign(a, LogEntry.Restore(log.vaultId, next(log), log.head, a.userId, t, deleteId)))
        assertEquals(null, s.db.read { db -> db.queryOne("SELECT revokedAt FROM grants WHERE vaultId=? AND userId=?", log.vaultId, a.userId) { it.longOrNull("revokedAt") } })
        assertNotNull(s.db.read { db -> db.queryOne("SELECT revokedAt FROM grants WHERE vaultId=? AND userId=?", log.vaultId, b.userId) { it.longOrNull("revokedAt") } })
        // The member who left reads up to and including its leave, and nothing after.
        val cut = WireJson.json.decodeFromString(LogPage.serializer(), c.call(HttpMethod.Get, "/api/v1/vaults/${log.vaultId}/log?after=0", token = b.token).bodyAsText())
        assertEquals(3, cut.entries.size)
        assertEquals(3, cut.head.seq)
        assertEquals("bad_after", c.call(HttpMethod.Get, "/api/v1/vaults/${log.vaultId}/log?after=01", token = a.token).errorCode())
        val bSync = WireJson.json.decodeFromString(SyncResponse.serializer(), c.call(HttpMethod.Get, "/api/v1/sync?since=0", token = b.token).bodyAsText())
        assertTrue(bSync.removedGrantsInfo.any { it.vaultId == log.vaultId && it.reason == "left" })
    }

    @Test
    fun personalVault_hasNoLog_andSelfWrapAndRenameRules() = testApplication {
        val clock = MutableClock(1_800_000_000_000L)
        val s = TestKit.services(clock = clock)
        application { andvariModule(s) }
        val c = client
        Flow.finishSetup(c, s)
        val a = Flow.member(c, s, "a@example.com")
        val pv = Log(a.personalVaultId)
        pv.seq = 0
        assertEquals("not_shared_vault", c.post(a, pv, sign(a, LogEntry.Delete(a.personalVaultId, 1, "0".repeat(64), a.userId, clock.now(), b16()))).errorCode())
        assertEquals("owner_wrap_immutable", c.call(HttpMethod.Put, "/api/v1/vaults/${a.personalVaultId}/grant/self-wrap", """{"wrappedVk":"AAAA"}""", a.token).errorCode())
        assertEquals("not_shared_vault", c.call(HttpMethod.Put, "/api/v1/vaults/${a.personalVaultId}/meta", """{"metaBlob":"AAAA"}""", a.token).errorCode())
        assertEquals("not_vault_owner", c.call(HttpMethod.Put, "/api/v1/vaults/${uuid()}/meta", """{"metaBlob":"AAAA"}""", a.token).errorCode())
    }
}
