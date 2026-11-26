package io.silencelen.andvari.server

import io.ktor.client.statement.bodyAsText
import io.ktor.http.HttpMethod
import io.ktor.server.testing.testApplication
import io.silencelen.andvari.core.crypto.Bytes
import io.silencelen.andvari.core.model.wire.RegisterAuth
import kotlinx.coroutines.async
import kotlinx.coroutines.awaitAll
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue

/** Links and connections (spec 03 §15). */
class LinksTest {
    private fun id() = Bytes.toB64(TestKit.crypto.randomBytes(16))
    private fun create(linkId: String, kind: String, expiresAt: Long, tokenHash: String? = null) =
        """{"linkId":"$linkId","kind":"$kind","offer":"AAAAAAAAAAAA","expiresAt":$expiresAt${tokenHash?.let { ",\"tokenHash\":\"$it\"" } ?: ""}}"""

    @Test
    fun connect_create_fetch_answer_reveal_inbox_ack() = testApplication {
        val clock = MutableClock()
        val s = TestKit.services(clock = clock)
        application { andvariModule(s) }
        val c = client
        Flow.finishSetup(c, s)
        val a = Flow.member(c, s, "a@example.com")
        val b = Flow.member(c, s, "b@example.com")
        val linkId = id()
        val exp = clock.now() + 3_600_000
        val created = c.call(HttpMethod.Post, "/api/v1/links", create(linkId, "connect", exp), a.token)
        assertEquals(201, created.status.value, created.bodyAsText())
        assertEquals("""{"expiresAt":$exp,"ttlMs":3600000}""", created.bodyAsText())
        assertEquals("link_id_taken", c.call(HttpMethod.Post, "/api/v1/links", create(linkId, "connect", exp), a.token).errorCode())
        val open = c.call(HttpMethod.Get, "/api/v1/links/$linkId").bodyAsText()
        assertEquals(
            """{"kind":"connect","offer":"AAAAAAAAAAAA","expiresAt":$exp,"state":"open","creatorUserId":"${a.userId}","creatorIdentityPub":"${a.identity.identityPubB64}","reveal":null}""",
            open,
        )
        assertEquals("cannot_target_self", c.call(HttpMethod.Post, "/api/v1/links/$linkId/answer", """{"answer":"BBBB"}""", a.token).errorCode())
        assertEquals(200, c.call(HttpMethod.Post, "/api/v1/links/$linkId/answer", """{"answer":"BBBB"}""", b.token).status.value)
        assertEquals("link_used", c.call(HttpMethod.Post, "/api/v1/links/$linkId/answer", """{"answer":"CCCC"}""", b.token).errorCode())
        assertEquals(1L, s.db.read { it.count("SELECT COUNT(*) FROM connections") })
        assertEquals("""{"kind":"connect","state":"answered","reveal":null}""", c.call(HttpMethod.Get, "/api/v1/links/$linkId").bodyAsText())
        // The inbox, the reveal (once, creator only), the ack.
        assertTrue(c.call(HttpMethod.Get, "/api/v1/links/answers", token = a.token).bodyAsText().contains("\"answererUserId\":\"${b.userId}\""))
        val nonce = Bytes.toB64(ByteArray(32) { 1 })
        assertEquals("link_unknown", c.call(HttpMethod.Post, "/api/v1/links/$linkId/reveal", """{"nonce":"$nonce"}""", b.token).errorCode())
        assertEquals(200, c.call(HttpMethod.Post, "/api/v1/links/$linkId/reveal", """{"nonce":"$nonce"}""", a.token).status.value)
        assertEquals("link_state", c.call(HttpMethod.Post, "/api/v1/links/$linkId/reveal", """{"nonce":"$nonce"}""", a.token).errorCode())
        assertTrue(c.call(HttpMethod.Get, "/api/v1/links/$linkId").bodyAsText().contains("\"reveal\":\"$nonce\""))
        assertEquals(200, c.call(HttpMethod.Post, "/api/v1/links/$linkId/ack", token = a.token).status.value)
        assertEquals(200, c.call(HttpMethod.Post, "/api/v1/links/$linkId/ack", token = a.token).status.value)
        assertEquals("[]", c.call(HttpMethod.Get, "/api/v1/links/answers", token = a.token).bodyAsText())
        assertEquals("link_state", c.call(HttpMethod.Delete, "/api/v1/links/$linkId", token = a.token).errorCode())
    }

    @Test
    fun create_rules_expiry_kind_tokenHash_who_quota_and_fetchStates() = testApplication {
        val clock = MutableClock()
        val s = TestKit.services(TestKit.config(kind = "public"), clock)
        application { andvariModule(s) }
        val c = client
        val op = Flow.finishSetup(c, s)
        val a = Flow.member(c, s, "a@example.com")
        val t = clock.now()
        assertEquals("bad_kind", c.call(HttpMethod.Post, "/api/v1/links", create(id(), "enrol", t + 60_000), a.token).errorCode())
        assertEquals("bad_expiry", c.call(HttpMethod.Post, "/api/v1/links", create(id(), "connect", t), a.token).errorCode())
        assertEquals("bad_expiry", c.call(HttpMethod.Post, "/api/v1/links", create(id(), "connect", t + 7 * Clock.DAY_MS + 10 * 60_000 + 1), a.token).errorCode())
        assertEquals(201, c.call(HttpMethod.Post, "/api/v1/links", create(id(), "connect", t + 7 * Clock.DAY_MS + 10 * 60_000), a.token).status.value)
        assertEquals("bad_token_hash", c.call(HttpMethod.Post, "/api/v1/links", create(id(), "register", t + 60_000), op.token).errorCode())
        val th = Bytes.toB64(ByteArray(32))
        // On a public instance register links are the operator's.
        assertEquals("not_operator", c.call(HttpMethod.Post, "/api/v1/links", create(id(), "register", t + 60_000, th), a.token).errorCode())
        assertEquals(201, c.call(HttpMethod.Post, "/api/v1/links", create(id(), "register", t + 60_000, th), op.token).status.value)
        // Quota: 20 open links by default.
        s.db.tx { it.exec("UPDATE users SET quotaOpenLinks=1 WHERE userId=?", a.userId) }
        val q = c.call(HttpMethod.Post, "/api/v1/links", create(id(), "connect", t + 60_000), a.token)
        assertEquals(413, q.status.value)
        assertTrue(q.bodyAsText().contains("\"quota\":\"openLinks\""))
        // Fetch: expired is 410, revoked and unknown are 404.
        val shortId = id()
        s.db.tx { it.exec("UPDATE users SET quotaOpenLinks=NULL WHERE userId=?", a.userId) }
        assertEquals(201, c.call(HttpMethod.Post, "/api/v1/links", create(shortId, "connect", t + 60_000), a.token).status.value)
        val revokeId = id()
        assertEquals(201, c.call(HttpMethod.Post, "/api/v1/links", create(revokeId, "connect", t + 60_000), a.token).status.value)
        assertEquals(200, c.call(HttpMethod.Delete, "/api/v1/links/$revokeId", token = a.token).status.value)
        assertEquals(404, c.call(HttpMethod.Get, "/api/v1/links/$revokeId").status.value)
        assertEquals(404, c.call(HttpMethod.Get, "/api/v1/links/${id()}").status.value)
        clock.advance(61_000)
        assertEquals("link_expired", c.call(HttpMethod.Get, "/api/v1/links/$shortId").errorCode())
    }

    /** Index row 54: two answers to one link at once. The first wins; the other is `409 link_used`; one connection. */
    @Test
    fun twoAnswersAtOnce_oneWins_oneConnection() = testApplication {
        val clock = MutableClock()
        val s = TestKit.services(clock = clock)
        application { andvariModule(s) }
        val c = client
        Flow.finishSetup(c, s)
        val a = Flow.member(c, s, "a@example.com")
        val answerers = (1..4).map { Flow.member(c, s, "b$it@example.com") }
        val linkId = id()
        assertEquals(201, c.call(HttpMethod.Post, "/api/v1/links", create(linkId, "connect", clock.now() + 3_600_000), a.token).status.value)
        val answers = kotlinx.coroutines.coroutineScope {
            answerers.map { b -> async { b to c.call(HttpMethod.Post, "/api/v1/links/$linkId/answer", """{"answer":"${Bytes.toB64(b.userId.encodeToByteArray())}"}""", b.token) } }.awaitAll()
        }
        val won = answers.filter { it.second.status.value == 200 }
        assertEquals(1, won.size, answers.map { it.second.status.value }.toString())
        for ((_, r) in answers - won.toSet()) {
            assertEquals(409, r.status.value)
            assertEquals("link_used", r.errorCode())
        }
        val winner = won.single().first
        assertEquals(1L, s.db.read { it.count("SELECT COUNT(*) FROM connections WHERE a=? OR b=?", a.userId, a.userId) })
        val (x, y) = listOf(a.userId, winner.userId).sorted()
        assertEquals(1L, s.db.read { it.count("SELECT COUNT(*) FROM connections WHERE a=? AND b=?", x, y) })
        // The creator's inbox holds the winner's answer, and only it.
        val inbox = c.call(HttpMethod.Get, "/api/v1/links/answers", token = a.token).bodyAsText()
        assertTrue(inbox.contains(winner.userId))
        assertEquals(1, Regex("\"linkId\"").findAll(inbox).count())
        assertEquals(1L, s.db.read { it.count("SELECT COUNT(*) FROM audit WHERE type='link_answer'") })
    }

    /** Disabling an account revokes its open register links. */
    @Test
    fun aDisabledAccountsRegisterLink_registersNoOne() = testApplication {
        val clock = MutableClock()
        val s = TestKit.services(clock = clock)
        application { andvariModule(s) }
        val c = client
        Flow.finishSetup(c, s)
        val a = Flow.member(c, s, "a@example.com")
        val (linkId, _, token) = HostLinks.clientView(TestKit.crypto.randomBytes(32))
        assertEquals(201, c.call(HttpMethod.Post, "/api/v1/links", create(linkId, "register", clock.now() + 3_600_000, ServerCrypto.hashToken(token)), a.token).status.value)
        s.db.tx { Accounts(s).disable(it, a.userId, "other", null, null) }
        val r = c.call(HttpMethod.Post, "/api/v1/auth/register", Me("new@example.com").register(s, RegisterAuth.Link(linkId, token, "AAAAAAAA")))
        assertEquals(404, r.status.value, r.bodyAsText()); assertEquals("link_unknown", r.errorCode())
        // Re-enabling does not bring the link back.
        s.db.tx { Accounts(s).enable(it, a.userId, null, null) }
        assertEquals("link_unknown", c.call(HttpMethod.Post, "/api/v1/auth/register", Me("new2@example.com").register(s, RegisterAuth.Link(linkId, token, "AAAAAAAA"))).errorCode())
    }

    @Test
    fun registerLink_registersAndConnects() = testApplication {
        val clock = MutableClock()
        val s = TestKit.services(clock = clock)
        application { andvariModule(s) }
        val c = client
        Flow.finishSetup(c, s)
        val a = Flow.member(c, s, "a@example.com")
        // The creator derives the token from s; the server only sees its hash.
        val secret = TestKit.crypto.randomBytes(32)
        val (linkId, _, token) = HostLinks.clientView(secret)
        assertEquals(201, c.call(HttpMethod.Post, "/api/v1/links", create(linkId, "register", clock.now() + 3_600_000, ServerCrypto.hashToken(token)), a.token).status.value)
        val n = Me("new@example.com")
        Flow.register(c, s, n, RegisterAuth.Link(linkId, token, "AAAAAAAA"))
        val (x, y) = listOf(a.userId, n.userId).sorted()
        assertEquals(1L, s.db.read { it.count("SELECT COUNT(*) FROM connections WHERE a=? AND b=?", x, y) })
        assertTrue(c.call(HttpMethod.Get, "/api/v1/links/answers", token = a.token).bodyAsText().contains(n.userId))
    }
}
