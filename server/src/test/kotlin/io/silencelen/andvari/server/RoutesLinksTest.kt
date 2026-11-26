package io.silencelen.andvari.server

import io.ktor.client.HttpClient
import io.ktor.client.statement.bodyAsText
import io.ktor.http.HttpMethod
import io.ktor.server.testing.testApplication
import io.silencelen.andvari.core.model.wire.TotpSetupResponse
import io.silencelen.andvari.core.model.wire.WireJson
import kotlin.test.Test
import kotlin.test.assertEquals

/** Index rows 54, 57 and 61–66 (spec 03 §15.4, §15.6, §16.4–§16.6): the refusals the other files leave. */
class RoutesLinksTest {
    private val post = HttpMethod.Post
    private val name = Grammar.nameOf("Pixel 9")!!
    private fun create(linkId: String, kind: String, expiresAt: Long, tokenHash: String? = null) =
        """{"linkId":"$linkId","kind":"$kind","offer":"AAAAAAAAAAAA","expiresAt":$expiresAt${tokenHash?.let { ",\"tokenHash\":\"$it\"" } ?: ""}}"""

    @Test
    fun rows54and57_answerRefusals_andAnAckBeforeTheAnswer() = testApplication {
        val clock = MutableClock()
        val s = TestKit.services(clock = clock)
        application { andvariModule(s) }
        val c = client
        Flow.finishSetup(c, s)
        val a = Flow.member(c, s, "a@example.com")
        val b = Flow.member(c, s, "b@example.com")
        suspend fun answer(id: String) = c.call(post, "/api/v1/links/$id/answer", """{"answer":"QkJCQg"}""", b.token)
        val unknown = answer(b16())
        assertEquals(404, unknown.status.value); assertEquals("link_unknown", unknown.errorCode())
        // A register link is answered by registering, never by this route.
        val reg = b16()
        assertEquals(201, c.call(post, "/api/v1/links", create(reg, "register", clock.now() + 60_000, b32()), a.token).status.value)
        val km = answer(reg)
        assertEquals(409, km.status.value); assertEquals("kind_mismatch", km.errorCode())
        // Open, then expired.
        val conn = b16()
        assertEquals(201, c.call(post, "/api/v1/links", create(conn, "connect", clock.now() + 60_000), a.token).status.value)
        val early = c.call(post, "/api/v1/links/$conn/ack", token = a.token)
        assertEquals(409, early.status.value); assertEquals("link_state", early.errorCode())
        clock.advance(60_000)
        val exp = answer(conn)
        assertEquals(410, exp.status.value); assertEquals("link_expired", exp.errorCode())
        // A revoked link is unknown.
        val rev = b16()
        assertEquals(201, c.call(post, "/api/v1/links", create(rev, "connect", clock.now() + 60_000), a.token).status.value)
        assertEquals(200, c.call(HttpMethod.Delete, "/api/v1/links/$rev", token = a.token).status.value)
        assertEquals("link_unknown", answer(rev).errorCode())
        assertEquals(0L, s.db.read { it.count("SELECT COUNT(*) FROM connections WHERE a=? OR b=?", a.userId, a.userId) })
    }

    /** E's link driven to [upTo]: "claimed", "nonce", "revealed" or "approved". Returns (linkId, proof). */
    private suspend fun drive(c: HttpClient, s: Services, e: Me, upTo: String): Pair<String, String> {
        val linkId = b16(); val proof = b32()
        assertEquals(201, c.call(post, "/api/v1/device-links", """{"linkId":"$linkId","expiresAt":${s.clock.now() + 60_000}}""", e.token).status.value)
        assertEquals(200, c.call(post, "/api/v1/device-links/$linkId/claim", """{"nPub":"${b32()}","name":"$name","platform":"android","commitN":"${"c".repeat(64)}","mac":"${b32()}"}""").status.value)
        if (upTo == "claimed") return linkId to proof
        assertEquals(200, c.call(post, "/api/v1/device-links/$linkId/nonce", """{"nonceE":"${b32()}","proofHash":"${sha256Hex(proof)}"}""", e.token).status.value)
        if (upTo == "nonce") return linkId to proof
        assertEquals(200, c.call(post, "/api/v1/device-links/$linkId/reveal", """{"nonceN":"${b32()}","proof":"$proof"}""").status.value)
        if (upTo == "revealed") return linkId to proof
        assertEquals(200, c.call(post, "/api/v1/device-links/$linkId/approve", """{"outer":"QUFB","inner":"QUFB","approveMac":"${b32()}"}""", e.token).status.value)
        return linkId to proof
    }

    private fun approve() = """{"outer":"QUFB","inner":"QUFB","approveMac":"${b32()}"}"""

    @Test
    fun rows61to66_unknownIds_expiry_wrongProof_wrongState() = testApplication {
        val clock = MutableClock()
        val s = TestKit.services(clock = clock)
        application { andvariModule(s) }
        val c = client
        Flow.finishSetup(c, s)
        val e = Flow.member(c, s, "e@example.com")
        val none = b16()
        val claim = """{"nPub":"${b32()}","name":"$name","platform":"android","commitN":"${"c".repeat(64)}","mac":"${b32()}"}"""
        c.expectAll(listOf(
            Expect("61 claim unknown", post, "/api/v1/device-links/$none/claim", null, 404, "link_unknown", claim),
            Expect("63 poll unknown", post, "/api/v1/device-links/$none/poll", null, 404, "link_unknown", """{"proof":"${b32()}"}"""),
            Expect("64 reveal unknown", post, "/api/v1/device-links/$none/reveal", null, 404, "link_unknown", """{"nonceN":"${b32()}","proof":"${b32()}"}"""),
            Expect("66 pickup unknown", post, "/api/v1/device-links/$none/pickup", null, 404, "link_unknown", """{"proof":"${b32()}","authKey":"${e.authKey}","device":{"deviceSecret":"${b32()}"}}"""),
            Expect("61 claim, malformed id", post, "/api/v1/device-links/not-an-id/claim", null, 404, "link_unknown", claim),
        ))
        // Wrong proof on reveal and pickup.
        val (l1, _) = drive(c, s, e, "nonce")
        assertEquals("bad_proof", c.call(post, "/api/v1/device-links/$l1/reveal", """{"nonceN":"${b32()}","proof":"${b32()}"}""").errorCode())
        // Approve before the reveal is link_state.
        assertEquals("link_state", c.call(post, "/api/v1/device-links/$l1/approve", approve(), e.token).errorCode())
        val (l2, p2) = drive(c, s, e, "approved")
        assertEquals("bad_proof", c.call(post, "/api/v1/device-links/$l2/pickup", """{"proof":"${b32()}","authKey":"${e.authKey}","device":{"deviceSecret":"${b32()}"}}""").errorCode())
        // A second approval is link_state.
        assertEquals("link_state", c.call(post, "/api/v1/device-links/$l2/approve", approve(), e.token).errorCode())
        // Every later state expires five minutes after it was entered: approved here.
        clock.advance(DeviceLinks.STATE_TTL_MS)
        c.expectAll(listOf(
            Expect("63 poll expired", post, "/api/v1/device-links/$l2/poll", null, 410, "link_expired", """{"proof":"$p2"}"""),
            Expect("66 pickup expired", post, "/api/v1/device-links/$l2/pickup", null, 410, "link_expired", """{"proof":"$p2","authKey":"${e.authKey}","device":{"deviceSecret":"${b32()}"}}"""),
        ))
        // Claimed, then expired: nonce and reveal; revealed, then expired: approve.
        val (l3, p3) = drive(c, s, e, "claimed")
        clock.advance(DeviceLinks.STATE_TTL_MS)
        assertEquals("link_expired", c.call(post, "/api/v1/device-links/$l3/nonce", """{"nonceE":"${b32()}","proofHash":"${sha256Hex(p3)}"}""", e.token).errorCode())
        assertEquals("link_expired", c.call(post, "/api/v1/device-links/$l3/reveal", """{"nonceN":"${b32()}","proof":"$p3"}""").errorCode())
        val (l4, _) = drive(c, s, e, "revealed")
        clock.advance(DeviceLinks.STATE_TTL_MS - 1)
        assertEquals(200, c.call(HttpMethod.Get, "/api/v1/device-links/$l4", token = e.token).status.value, "one millisecond before the deadline")
        clock.advance(1)
        val late = c.call(post, "/api/v1/device-links/$l4/approve", approve(), e.token)
        assertEquals(410, late.status.value, late.bodyAsText()); assertEquals("link_expired", late.errorCode())
    }

    @Test
    fun row66_pickup_withTwoStep_asksForTheCode() = testApplication {
        val clock = MutableClock()
        val s = TestKit.services(clock = clock)
        application { andvariModule(s) }
        val c = client
        Flow.finishSetup(c, s)
        val e = Flow.member(c, s, "e@example.com")
        val secret = WireJson.json.decodeFromString(TotpSetupResponse.serializer(), c.call(post, "/api/v1/account/totp/setup", """{"currentAuthKey":"${e.authKey}"}""", e.token).bodyAsText()).secretBase32
        assertEquals(200, c.call(post, "/api/v1/account/totp/confirm", """{"code":"${Flow.totp(secret, clock.now())}"}""", e.token).status.value)
        clock.advance(30_000)
        val (l, p) = drive(c, s, e, "approved")
        val body = { totp: String? -> """{"proof":"$p","authKey":"${e.authKey}"${totp?.let { ",\"totp\":\"$it\"" } ?: ""},"device":{"deviceSecret":"${b32()}"}}""" }
        val ask = c.call(post, "/api/v1/device-links/$l/pickup", body(null))
        assertEquals(401, ask.status.value); assertEquals("totp_required", ask.errorCode())
        val code = Flow.totp(secret, clock.now())
        assertEquals("invalid_credentials", c.call(post, "/api/v1/device-links/$l/pickup", body(if (code == "000000") "111111" else "000000")).errorCode())
        val ok = c.call(post, "/api/v1/device-links/$l/pickup", body(code))
        assertEquals(200, ok.status.value, ok.bodyAsText())
    }
}
