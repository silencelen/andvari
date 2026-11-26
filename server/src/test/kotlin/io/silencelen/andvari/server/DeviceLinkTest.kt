package io.silencelen.andvari.server

import io.ktor.client.statement.bodyAsText
import io.ktor.http.HttpMethod
import io.ktor.server.testing.testApplication
import io.silencelen.andvari.core.crypto.Bytes
import io.silencelen.andvari.core.model.wire.Device
import io.silencelen.andvari.core.model.wire.DeviceLinkPickupResponse
import io.silencelen.andvari.core.model.wire.WireJson
import kotlinx.serialization.builtins.ListSerializer
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue

/** Device links and the devices list (spec 03 §16). */
class DeviceLinkTest {
    private fun b32() = Bytes.toB64(TestKit.crypto.randomBytes(32))
    private fun id() = Bytes.toB64(TestKit.crypto.randomBytes(16))
    private val name = Grammar.nameOf("Pixel 9")!!

    @Test
    fun fullPairing_thenPickupWithThePassword() = testApplication {
        val clock = MutableClock()
        val s = TestKit.services(clock = clock)
        application { andvariModule(s) }
        val c = client
        Flow.finishSetup(c, s)
        val e = Flow.member(c, s, "e@example.com")
        val linkId = id()
        val cr = c.call(HttpMethod.Post, "/api/v1/device-links", """{"linkId":"$linkId","expiresAt":${clock.now() + 3_600_000}}""", e.token)
        assertEquals(201, cr.status.value, cr.bodyAsText())
        assertTrue(cr.bodyAsText().contains("\"ttlMs\":300000"), "the server caps the open state at 5 minutes")
        val proof = b32()
        val claim = """{"nPub":"${b32()}","name":"$name","platform":"android","commitN":"${"c".repeat(64)}","mac":"${b32()}"}"""
        assertEquals(200, c.call(HttpMethod.Post, "/api/v1/device-links/$linkId/claim", claim).status.value)
        assertEquals("link_claimed", c.call(HttpMethod.Post, "/api/v1/device-links/$linkId/claim", claim).errorCode())
        // Before E's nonce, the poll shows only the state; and reveal is out of order.
        assertEquals("""{"state":"claimed"}""", c.call(HttpMethod.Post, "/api/v1/device-links/$linkId/poll", """{"proof":"$proof"}""").bodyAsText())
        assertEquals("link_state", c.call(HttpMethod.Post, "/api/v1/device-links/$linkId/reveal", """{"nonceN":"${b32()}","proof":"$proof"}""").errorCode())
        val nonceE = b32()
        assertEquals(200, c.call(HttpMethod.Post, "/api/v1/device-links/$linkId/nonce", """{"nonceE":"$nonceE","proofHash":"${sha256Hex(proof)}"}""", e.token).status.value)
        assertEquals("link_state", c.call(HttpMethod.Post, "/api/v1/device-links/$linkId/nonce", """{"nonceE":"$nonceE","proofHash":"${sha256Hex(proof)}"}""", e.token).errorCode())
        assertEquals("bad_proof", c.call(HttpMethod.Post, "/api/v1/device-links/$linkId/poll", """{"proof":"${b32()}"}""").errorCode())
        assertTrue(c.call(HttpMethod.Post, "/api/v1/device-links/$linkId/poll", """{"proof":"$proof"}""").bodyAsText().contains(nonceE))
        assertEquals(200, c.call(HttpMethod.Post, "/api/v1/device-links/$linkId/reveal", """{"nonceN":"${b32()}","proof":"$proof"}""").status.value)
        assertTrue(c.call(HttpMethod.Get, "/api/v1/device-links/$linkId", token = e.token).bodyAsText().contains("\"state\":\"revealed\""))
        assertEquals("link_state", c.call(HttpMethod.Post, "/api/v1/device-links/$linkId/pickup", """{"proof":"$proof","authKey":"${e.authKey}","device":{"deviceSecret":"${b32()}"}}""").errorCode())
        assertEquals(200, c.call(HttpMethod.Post, "/api/v1/device-links/$linkId/approve", """{"outer":"QUFBQUFB","inner":"SU5ORVJJ","approveMac":"${b32()}"}""", e.token).status.value)
        assertTrue(c.call(HttpMethod.Post, "/api/v1/device-links/$linkId/poll", """{"proof":"$proof"}""").bodyAsText().contains("\"outer\":\"QUFBQUFB\""))
        // A wrong password is the uniform 401; the right one picks up, once.
        assertEquals("invalid_credentials", c.call(HttpMethod.Post, "/api/v1/device-links/$linkId/pickup", """{"proof":"$proof","authKey":"${b32()}","device":{"deviceSecret":"${b32()}"}}""").errorCode())
        // requireLink does not apply to a linked device.
        s.db.tx { it.exec("UPDATE users SET requireLink=1 WHERE userId=?", e.userId) }
        val secret = b32()
        val pk = c.call(HttpMethod.Post, "/api/v1/device-links/$linkId/pickup", """{"proof":"$proof","authKey":"${e.authKey}","device":{"deviceSecret":"$secret"}}""")
        assertEquals(200, pk.status.value, pk.bodyAsText())
        val got = WireJson.json.decodeFromString(DeviceLinkPickupResponse.serializer(), pk.bodyAsText())
        assertEquals("SU5ORVJJ", got.inner)
        // The session is a login's SessionResponse: role, the two-step flags and the account keys inside it.
        assertEquals("member", got.session.role); assertEquals(false, got.session.totpEnrolled); assertEquals(false, got.session.mustEnrollTotp)
        assertEquals(e.userId, got.session.userId); assertTrue(!got.session.accountKeys.genesis.isNullOrEmpty())
        assertEquals(404, c.call(HttpMethod.Post, "/api/v1/device-links/$linkId/pickup", """{"proof":"$proof","authKey":"${e.authKey}","device":{"deviceSecret":"$secret"}}""").status.value)
        val devices = WireJson.json.decodeFromString(ListSerializer(Device.serializer()), c.call(HttpMethod.Get, "/api/v1/account/devices", token = e.token).bodyAsText())
        val linked = devices.single { it.deviceId == got.session.deviceId }
        assertEquals("linked", linked.how); assertEquals("Pixel 9", linked.name); assertEquals(e.deviceId, linked.linkedFrom); assertTrue(linked.live)
        assertTrue(devices.single { it.deviceId == e.deviceId }.current)
        // The linked device is a known device: it logs in under requireLink.
        assertEquals(200, c.call(HttpMethod.Post, "/api/v1/auth/login", e.loginBody(deviceId = got.session.deviceId, secret = secret)).status.value)
        // Revoke clears it as a known device.
        assertEquals("cannot_target_self", c.call(HttpMethod.Post, "/api/v1/account/devices/${e.deviceId}/revoke", """{"currentAuthKey":"${e.authKey}"}""", e.token).errorCode())
        assertEquals("no_such_device", c.call(HttpMethod.Post, "/api/v1/account/devices/${uuid()}/revoke", """{"currentAuthKey":"${e.authKey}"}""", e.token).errorCode())
        assertEquals(200, c.call(HttpMethod.Post, "/api/v1/account/devices/${got.session.deviceId}/revoke", """{"currentAuthKey":"${e.authKey}"}""", e.token).status.value)
        assertEquals("link_required", c.call(HttpMethod.Post, "/api/v1/auth/login", e.loginBody(deviceId = got.session.deviceId, secret = secret)).errorCode())
        assertTrue(Flow.sink(s).map { it.first }.containsAll(listOf("new_device", "device_removed")))
    }

    @Test
    fun viewNonceApprove_onlyByTheDeviceThatCreatedTheLink() = testApplication {
        val clock = MutableClock()
        val s = TestKit.services(clock = clock)
        application { andvariModule(s) }
        val c = client
        Flow.finishSetup(c, s)
        val e = Flow.member(c, s, "e@example.com")
        // A second signed-in device of the same account.
        val e2 = WireJson.json.decodeFromString(io.silencelen.andvari.core.model.wire.SessionResponse.serializer(), c.call(HttpMethod.Post, "/api/v1/auth/login", e.loginBody()).bodyAsText())
        val linkId = id()
        assertEquals(201, c.call(HttpMethod.Post, "/api/v1/device-links", """{"linkId":"$linkId","expiresAt":${clock.now() + 60_000}}""", e.token).status.value)
        val proof = b32()
        assertEquals(200, c.call(HttpMethod.Post, "/api/v1/device-links/$linkId/claim", """{"nPub":"${b32()}","name":"$name","platform":"android","commitN":"${"c".repeat(64)}","mac":"${b32()}"}""").status.value)
        // Spec 03 §16.3 and §16.5: the view and the nonce are the creating device's too; the account's other
        // device sees no such link, and its nonce changes nothing.
        val view = c.call(HttpMethod.Get, "/api/v1/device-links/$linkId", token = e2.accessToken)
        assertEquals(404, view.status.value, view.bodyAsText()); assertEquals("link_unknown", view.errorCode())
        val nonce = c.call(HttpMethod.Post, "/api/v1/device-links/$linkId/nonce", """{"nonceE":"${b32()}","proofHash":"${sha256Hex(b32())}"}""", e2.accessToken)
        assertEquals(404, nonce.status.value, nonce.bodyAsText()); assertEquals("link_unknown", nonce.errorCode())
        assertTrue(!c.call(HttpMethod.Get, "/api/v1/device-links/$linkId", token = e.token).bodyAsText().contains("nonceE"), "the refused nonce changed nothing")
        assertEquals(200, c.call(HttpMethod.Post, "/api/v1/device-links/$linkId/nonce", """{"nonceE":"${b32()}","proofHash":"${sha256Hex(proof)}"}""", e.token).status.value)
        assertEquals(200, c.call(HttpMethod.Post, "/api/v1/device-links/$linkId/reveal", """{"nonceN":"${b32()}","proof":"$proof"}""").status.value)
        val approve = """{"outer":"QUFBQUFB","inner":"SU5ORVJJ","approveMac":"${b32()}"}"""
        val other = c.call(HttpMethod.Post, "/api/v1/device-links/$linkId/approve", approve, e2.accessToken)
        assertEquals(404, other.status.value, other.bodyAsText())
        assertEquals("link_unknown", other.errorCode())
        assertTrue(c.call(HttpMethod.Get, "/api/v1/device-links/$linkId", token = e.token).bodyAsText().contains("\"state\":\"revealed\""), "the refused approval changed nothing")
        assertEquals(200, c.call(HttpMethod.Post, "/api/v1/device-links/$linkId/approve", approve, e.token).status.value)
    }

    @Test
    fun timers_replacement_cancel() = testApplication {
        val clock = MutableClock()
        val s = TestKit.services(clock = clock)
        application { andvariModule(s) }
        val c = client
        Flow.finishSetup(c, s)
        val e = Flow.member(c, s, "e@example.com")
        val other = Flow.member(c, s, "o@example.com")
        val l1 = id(); val l2 = id()
        assertEquals("bad_expiry", c.call(HttpMethod.Post, "/api/v1/device-links", """{"linkId":"$l1","expiresAt":${clock.now()}}""", e.token).errorCode())
        c.call(HttpMethod.Post, "/api/v1/device-links", """{"linkId":"$l1","expiresAt":${clock.now() + 60_000}}""", e.token)
        c.call(HttpMethod.Post, "/api/v1/device-links", """{"linkId":"$l2","expiresAt":${clock.now() + 60_000}}""", e.token)
        // A new link replaces the open one.
        assertEquals(404, c.call(HttpMethod.Get, "/api/v1/device-links/$l1", token = e.token).status.value)
        assertEquals(404, c.call(HttpMethod.Get, "/api/v1/device-links/$l2", token = other.token).status.value)
        clock.advance(61_000)
        assertEquals("link_expired", c.call(HttpMethod.Get, "/api/v1/device-links/$l2", token = e.token).errorCode())
        assertEquals("link_expired", c.call(HttpMethod.Post, "/api/v1/device-links/$l2/claim", """{"nPub":"${b32()}","name":"$name","platform":"ios","commitN":"${"a".repeat(64)}","mac":"${b32()}"}""").errorCode())
        assertEquals(200, c.call(HttpMethod.Delete, "/api/v1/device-links/$l2", token = e.token).status.value)
        assertEquals(404, c.call(HttpMethod.Delete, "/api/v1/device-links/$l2", token = e.token).status.value)
        // require-link needs the password.
        assertEquals("reauth_failed", c.call(HttpMethod.Put, "/api/v1/account/require-link", """{"enabled":true,"currentAuthKey":"${b32()}"}""", e.token).errorCode())
        assertEquals(200, c.call(HttpMethod.Put, "/api/v1/account/require-link", """{"enabled":true,"currentAuthKey":"${e.authKey}"}""", e.token).status.value)
    }
}
