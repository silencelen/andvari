package io.silencelen.andvari.server

import io.ktor.client.HttpClient
import io.ktor.client.statement.HttpResponse
import io.ktor.client.statement.bodyAsText
import io.ktor.http.HttpMethod
import io.ktor.server.testing.testApplication
import io.silencelen.andvari.core.crypto.Bytes
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue

/**
 * A device link at a person's pace (spec 03 §16, §0.2), on a driven clock, both sides asking the server every two
 * seconds while they wait, as the command-line tool and the apps do: the existing device reads the link
 * (`GET /device-links/{id}`, its own budget of 60 a minute), the new device polls it (`POST …/poll`, 60 a minute per
 * address, shared with the reveal). The new device asks from one fixed address, as it would behind a home network.
 * Neither side is ever refused as too many; what bounds a person's pace is the link's own timer (five minutes in each
 * state), which ends a link left longer as `410 link_expired`, never as `429`.
 */
class DeviceLinkPaceTest {
    private val post = HttpMethod.Post
    private fun b32() = Bytes.toB64(TestKit.crypto.randomBytes(32))
    private val newDeviceIp = "10.44.44.44"

    /** One link from E's creation to N's showing of the code, with both sides asking every two seconds; the link's id and N's proof. */
    private suspend fun showCode(c: HttpClient, clock: MutableClock, e: Me, seen: MutableList<Int>): Pair<String, String> {
        val linkId = Bytes.toB64(TestKit.crypto.randomBytes(16))
        suspend fun track(r: HttpResponse): HttpResponse = r.also { seen += it.status.value }
        assertEquals(201, track(c.call(post, "/api/v1/device-links", """{"linkId":"$linkId","expiresAt":${clock.now() + 300_000}}""", e.token)).status.value)
        // The person carries the link to the new device for twenty seconds; E reads the link every two.
        repeat(10) { clock.advance(2_000); assertEquals(200, track(c.call(HttpMethod.Get, "/api/v1/device-links/$linkId", token = e.token)).status.value) }
        val proof = b32()
        val claim = """{"nPub":"${b32()}","name":"${Grammar.nameOf("Pixel 9")!!}","platform":"android","commitN":"${"c".repeat(64)}","mac":"${b32()}"}"""
        assertEquals(200, track(c.call(post, "/api/v1/device-links/$linkId/claim", claim, ip = newDeviceIp)).status.value)
        clock.advance(2_000)
        assertEquals(200, track(c.call(post, "/api/v1/device-links/$linkId/poll", """{"proof":"$proof"}""", ip = newDeviceIp)).status.value)
        assertTrue(track(c.call(HttpMethod.Get, "/api/v1/device-links/$linkId", token = e.token)).bodyAsText().contains("\"claim\""))
        assertEquals(200, track(c.call(post, "/api/v1/device-links/$linkId/nonce", """{"nonceE":"${b32()}","proofHash":"${sha256Hex(proof)}"}""", e.token)).status.value)
        clock.advance(2_000)
        assertTrue(track(c.call(post, "/api/v1/device-links/$linkId/poll", """{"proof":"$proof"}""", ip = newDeviceIp)).bodyAsText().contains("nonceE"))
        assertEquals(200, track(c.call(post, "/api/v1/device-links/$linkId/reveal", """{"nonceN":"${b32()}","proof":"$proof"}""", ip = newDeviceIp)).status.value)
        return linkId to proof
    }

    /** The person takes [ms] to type the code: both sides ask every two seconds meanwhile; the statuses they got. */
    private suspend fun wait(c: HttpClient, clock: MutableClock, e: Me, linkId: String, proof: String, ms: Long, seen: MutableList<Int>) {
        var waited = 0L
        while (waited < ms) {
            clock.advance(2_000); waited += 2_000
            seen += c.call(post, "/api/v1/device-links/$linkId/poll", """{"proof":"$proof"}""", ip = newDeviceIp).status.value
            seen += c.call(HttpMethod.Get, "/api/v1/device-links/$linkId", token = e.token).status.value
        }
    }

    @Test
    fun anApprovalAfterThreeMinutes_withBothSidesAskingEveryTwoSeconds_isNeverRefused() = testApplication {
        val clock = MutableClock()
        val s = TestKit.services(clock = clock)
        application { andvariModule(s) }
        val c = client
        Flow.finishSetup(c, s)
        val e = Flow.member(c, s, "e@example.com")
        val seen = ArrayList<Int>()
        val (linkId, proof) = showCode(c, clock, e, seen)
        wait(c, clock, e, linkId, proof, 3 * 60_000L, seen)
        assertEquals(200, c.call(post, "/api/v1/device-links/$linkId/approve", """{"outer":"QUFBQUFB","inner":"SU5ORVJJ","approveMac":"${b32()}"}""", e.token).status.value)
        clock.advance(2_000)
        assertTrue(c.call(post, "/api/v1/device-links/$linkId/poll", """{"proof":"$proof"}""", ip = newDeviceIp).bodyAsText().contains("\"outer\""))
        val pk = c.call(post, "/api/v1/device-links/$linkId/pickup", """{"proof":"$proof","authKey":"${e.authKey}","device":{"deviceSecret":"${b32()}"}}""", ip = newDeviceIp)
        assertEquals(200, pk.status.value, pk.bodyAsText())
        assertTrue(seen.size > 180, "both sides asked all along")
        assertEquals(setOf(200, 201), seen.toSet(), "no request of the link was refused")
    }

    @Test
    fun aPersonWhoTakesTenMinutes_losesTheLinkToItsTimer_neverToALimit() = testApplication {
        val clock = MutableClock()
        val s = TestKit.services(clock = clock)
        application { andvariModule(s) }
        val c = client
        Flow.finishSetup(c, s)
        val e = Flow.member(c, s, "e@example.com")
        val seen = ArrayList<Int>()
        val (linkId, proof) = showCode(c, clock, e, seen)
        // Up to the revealed state's five minutes, every answer is served.
        wait(c, clock, e, linkId, proof, 5 * 60_000L - 2_000, seen)
        assertEquals(setOf(200, 201), seen.toSet())
        // From then on the link is gone, for both sides, as expired; no request is ever refused as too many.
        seen.clear()
        wait(c, clock, e, linkId, proof, 5 * 60_000L, seen)
        assertEquals(setOf(410), seen.toSet())
        assertEquals("link_expired", c.call(post, "/api/v1/device-links/$linkId/approve", """{"outer":"QUFBQUFB","inner":"SU5ORVJJ","approveMac":"${b32()}"}""", e.token).errorCode())
    }
}
