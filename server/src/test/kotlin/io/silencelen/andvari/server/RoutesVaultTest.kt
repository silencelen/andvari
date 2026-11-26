package io.silencelen.andvari.server

import io.ktor.client.statement.bodyAsText
import io.ktor.http.HttpMethod
import io.ktor.server.testing.testApplication
import io.silencelen.andvari.core.crypto.Bytes
import io.silencelen.andvari.core.model.wire.VaultMemberSummary
import io.silencelen.andvari.core.model.wire.WireJson
import io.silencelen.andvari.core.trust.LogEntry
import io.silencelen.andvari.core.trust.MemberRole
import kotlinx.serialization.builtins.ListSerializer
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue

/** Index rows 46, 48 and 50 (spec 03 §10.3, §10.4, §10.7, §11.3): the refusals the other files leave. */
class RoutesVaultTest {
    private val post = HttpMethod.Post
    private val get = HttpMethod.Get
    private val put = HttpMethod.Put

    /** The statement bytes of a signed log entry (header 5, signer key 32, signature 64, then the statement). */
    private fun statementOf(frameB64: String): String = Bytes.fromB64(frameB64).let { it.copyOfRange(101, it.size).decodeToString() }

    @Test
    fun row46_theFrameVerdicts_wrongVault_memberLimit_offerExpired() = testApplication {
        val clock = MutableClock(1_800_000_000_000L)
        val s = TestKit.services(clock = clock)
        application { andvariModule(s) }
        val c = client
        Flow.finishSetup(c, s)
        val owner = Flow.member(c, s, "owner@example.com")
        val m = Flow.member(c, s, "m@example.com")
        val v = SharedVault(c, s, owner).create()
        v.add(m, MemberRole.WRITER)
        val canonical = statementOf(v.sign(m, LogEntry.Leave(v.vaultId, v.next, v.head, m.userId, v.at)))
        suspend fun raw(st: String) = c.call(post, "/api/v1/vaults/${v.vaultId}/log", """{"entry":"${Bytes.toB64(m.identity.frame(3, st))}"}""", m.token)
        for ((code, st) in listOf(
            "non_canonical" to canonical.replaceFirst("{", "{ "),
            "non_canonical" to canonical.replace("\"kind\":\"leave\"", "\"kind\":\"leave\",\"extra\":1"),
            "bad_statement" to canonical.replace("\"v\":2", "\"v\":3"),
            "bad_statement" to canonical.replace("\"seq\":${v.next}", "\"seq\":0"),
        )) {
            val r = raw(st)
            assertEquals(400, r.status.value, "$code: $st ${r.bodyAsText()}"); assertEquals(code, r.errorCode(), st)
        }
        // A statement that is not JSON is still a frame (non_canonical); bytes that are not a frame are bad_frame.
        assertEquals("non_canonical", raw("not json").errorCode())
        assertEquals("bad_frame", c.call(post, "/api/v1/vaults/${v.vaultId}/log", """{"entry":"AAAAAAAA"}""", m.token).errorCode())
        // wrong_vault: a well-formed entry for another vault, posted to this one.
        val elsewhere = v.sign(m, LogEntry.Leave(uuid(), v.next, v.head, m.userId, v.at))
        val wv = c.call(post, "/api/v1/vaults/${v.vaultId}/log", """{"entry":"$elsewhere"}""", m.token)
        assertEquals(400, wv.status.value); assertEquals("wrong_vault", wv.errorCode())
        // The frame is checked before the signer: m's malformed frame signed by another key is still non_canonical.
        assertEquals("non_canonical", c.call(post, "/api/v1/vaults/${v.vaultId}/log", """{"entry":"${Bytes.toB64(TestKit.Identity().frame(3, canonical.replaceFirst("{", "{ ")))}"}""", m.token).errorCode())

        // member_limit: an account that is not active, and one already in 500 shared vaults.
        val off = Flow.member(c, s, "off@example.com")
        s.db.tx { writeConnection(it, owner.userId, off.userId, clock.now()) }
        s.db.tx { it.exec("UPDATE users SET status='disabled', disabledAt=1 WHERE userId=?", off.userId) }
        val addOff = v.append(owner, LogEntry.Add(v.vaultId, v.next, v.head, owner.userId, v.at, off.userId, off.identity.identityPubB64, MemberRole.READER, b16()), ""","grant":"AAAA"""")
        assertEquals(409, addOff.status.value, addOff.bodyAsText()); assertEquals("member_limit", addOff.errorCode())
        val full = Flow.member(c, s, "full@example.com")
        val seeded = List(VaultLogs.MEMBERSHIP_LIMIT) { uuid() }
        s.db.tx { db ->
            writeConnection(db, owner.userId, full.userId, clock.now())
            for (vid in seeded) {
                db.exec("INSERT INTO vaults(vaultId,type,rev,metaBlob,createdAt) VALUES(?,?,?,?,?)", vid, "shared", 1, "AAAA", 1)
                db.exec("INSERT INTO grants(vaultId,userId,role,addedAt,wrappedVk,rev) VALUES(?,?,'writer',1,'',1)", vid, full.userId)
            }
        }
        val addFull = v.append(owner, LogEntry.Add(v.vaultId, v.next, v.head, owner.userId, v.at, full.userId, full.identity.identityPubB64, MemberRole.READER, b16()), ""","grant":"AAAA"""")
        assertEquals(409, addFull.status.value, addFull.bodyAsText()); assertEquals("member_limit", addFull.errorCode())
        // One membership fewer and the add lands.
        assertEquals(1, s.db.tx { it.exec("DELETE FROM grants WHERE userId=? AND vaultId=?", full.userId, seeded.first()) })
        v.ok(owner, LogEntry.Add(v.vaultId, v.next, v.head, owner.userId, v.at, full.userId, full.identity.identityPubB64, MemberRole.READER, b16()), ""","grant":"AAAA"""")

        // offer_expired: the target accepts at the offer's expiry, by the server's clock.
        val offerId = b16()
        v.ok(owner, LogEntry.Offer(v.vaultId, v.next, v.head, owner.userId, v.at, m.userId, m.identity.identityPubB64, offerId, clock.now() + 60_000))
        clock.advance(60_000)
        val late = v.append(m, LogEntry.Accept(v.vaultId, v.next, v.head, m.userId, v.at, offerId), ""","wrappedVk":"AAAA"""")
        assertEquals(409, late.status.value, late.bodyAsText()); assertEquals("offer_expired", late.errorCode())
        // A fresh offer accepted in time hands the vault over.
        v.ok(owner, LogEntry.Cancel(v.vaultId, v.next, v.head, owner.userId, v.at, offerId))
        val offer2 = b16()
        v.ok(owner, LogEntry.Offer(v.vaultId, v.next, v.head, owner.userId, v.at, m.userId, m.identity.identityPubB64, offer2, clock.now() + 60_000))
        clock.advance(59_999)
        v.ok(m, LogEntry.Accept(v.vaultId, v.next, v.head, m.userId, v.at, offer2), ""","wrappedVk":"AAAA"""")
        assertEquals("owner", s.db.read { it.queryOne("SELECT role FROM grants WHERE vaultId=? AND userId=?", v.vaultId, m.userId) { r -> r.getString(1) } })
    }

    @Test
    fun row48_members_theServersView() = testApplication {
        val clock = MutableClock(1_800_000_000_000L)
        val s = TestKit.services(clock = clock)
        application { andvariModule(s) }
        val c = client
        Flow.finishSetup(c, s)
        val owner = Flow.member(c, s, "owner@example.com")
        val r = Flow.member(c, s, "r@example.com")
        val v = SharedVault(c, s, owner).create()
        v.add(r, MemberRole.READER)
        val resp = c.call(get, "/api/v1/vaults/${v.vaultId}/members", token = r.token)
        assertEquals(200, resp.status.value, resp.bodyAsText())
        val list = WireJson.json.decodeFromString(ListSerializer(VaultMemberSummary.serializer()), resp.bodyAsText())
        assertEquals(mapOf(owner.userId to "owner", r.userId to "reader"), list.associate { it.userId to it.role })
        assertEquals(r.identity.identityPubB64, list.single { it.userId == r.userId }.identityPub)
        assertEquals("r@example.com", list.single { it.userId == r.userId }.email)
        assertEquals("no_grant", c.call(get, "/api/v1/vaults/not-a-uuid/members", token = r.token).errorCode())
        // A disabled member is surfaced with its status.
        s.db.tx { it.exec("UPDATE users SET status='disabled', disabledAt=1 WHERE userId=?", r.userId) }
        val after = WireJson.json.decodeFromString(ListSerializer(VaultMemberSummary.serializer()), c.call(get, "/api/v1/vaults/${v.vaultId}/members", token = owner.token).bodyAsText())
        assertEquals("disabled", after.single { it.userId == r.userId }.status)
    }

    @Test
    fun row50_rename_success_staleMeta_vaultDeleted() = testApplication {
        val clock = MutableClock(1_800_000_000_000L)
        val s = TestKit.services(clock = clock)
        application { andvariModule(s) }
        val c = client
        Flow.finishSetup(c, s)
        val owner = Flow.member(c, s, "owner@example.com")
        val v = SharedVault(c, s, owner).create()
        val rev0 = s.db.read { it.queryOne("SELECT rev FROM vaults WHERE vaultId=?", v.vaultId) { r -> r.getLong(1) } }!!
        val ok = c.call(put, "/api/v1/vaults/${v.vaultId}/meta", """{"metaBlob":"TkVX","baseVaultRev":$rev0}""", owner.token)
        assertEquals(200, ok.status.value, ok.bodyAsText())
        val rev1 = Regex("\"rev\":(\\d+)").find(ok.bodyAsText())!!.groupValues[1].toLong()
        assertTrue(rev1 > rev0)
        assertEquals("TkVX", s.db.read { it.queryOne("SELECT metaBlob FROM vaults WHERE vaultId=?", v.vaultId) { r -> r.getString(1) } })
        val stale = c.call(put, "/api/v1/vaults/${v.vaultId}/meta", """{"metaBlob":"T0xE","baseVaultRev":$rev0}""", owner.token)
        assertEquals(409, stale.status.value); assertEquals("stale_meta", stale.errorCode())
        // Without a base rev it is last-writer-wins.
        assertEquals(200, c.call(put, "/api/v1/vaults/${v.vaultId}/meta", """{"metaBlob":"QU5Z"}""", owner.token).status.value)
        v.ok(owner, LogEntry.Delete(v.vaultId, v.next, v.head, owner.userId, v.at, b16()))
        val deleted = c.call(put, "/api/v1/vaults/${v.vaultId}/meta", """{"metaBlob":"QU5Z"}""", owner.token)
        assertEquals(400, deleted.status.value, deleted.bodyAsText()); assertEquals("vault_deleted", deleted.errorCode())
    }
}
