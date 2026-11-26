package io.silencelen.andvari.server

import io.ktor.client.HttpClient
import io.ktor.client.statement.bodyAsText
import io.ktor.http.HttpMethod
import io.ktor.server.testing.testApplication
import io.silencelen.andvari.core.crypto.Bytes
import kotlinx.coroutines.async
import kotlinx.coroutines.awaitAll
import kotlinx.coroutines.coroutineScope
import kotlin.test.Test
import kotlin.test.assertEquals

/**
 * Device-link pickup against concurrent account changes (spec 03 §16.6): the pickup's transaction re-checks
 * what its password gate checked, like login; revoking the device that created or approved a link cancels it.
 */
class DeviceLinkRaceTest {
    private fun b32() = Bytes.toB64(TestKit.crypto.randomBytes(32))
    private fun id() = Bytes.toB64(TestKit.crypto.randomBytes(16))
    private val name = Grammar.nameOf("Pixel 9")!!

    /** Drive a fresh link of [e] to `approved`, approved by [approver] (E by default): (linkId, proof). */
    private suspend fun approved(c: HttpClient, s: Services, e: Me, approverToken: String = e.token): Pair<String, String> {
        val linkId = id()
        assertEquals(201, c.call(HttpMethod.Post, "/api/v1/device-links", """{"linkId":"$linkId","expiresAt":${s.clock.now() + 60_000}}""", e.token).status.value)
        val proof = b32()
        assertEquals(200, c.call(HttpMethod.Post, "/api/v1/device-links/$linkId/claim", """{"nPub":"${b32()}","name":"$name","platform":"android","commitN":"${"c".repeat(64)}","mac":"${b32()}"}""").status.value)
        assertEquals(200, c.call(HttpMethod.Post, "/api/v1/device-links/$linkId/nonce", """{"nonceE":"${b32()}","proofHash":"${sha256Hex(proof)}"}""", e.token).status.value)
        assertEquals(200, c.call(HttpMethod.Post, "/api/v1/device-links/$linkId/reveal", """{"nonceN":"${b32()}","proof":"$proof"}""").status.value)
        assertEquals(200, c.call(HttpMethod.Post, "/api/v1/device-links/$linkId/approve", """{"outer":"QUFBQUFB","inner":"SU5ORVJJ","approveMac":"${b32()}"}""", approverToken).status.value)
        return linkId to proof
    }

    private fun pickup(e: Me, proof: String) = """{"proof":"$proof","authKey":"${e.authKey}","device":{"deviceSecret":"${b32()}"}}"""

    private fun devices(s: Services, e: Me) = s.db.read { it.count("SELECT COUNT(*) FROM devices WHERE userId=?", e.userId) }

    private val OPERATOR_KEY = HashMap<Services, String>()

    private fun app(block: suspend (HttpClient, Services, Me) -> Unit) = testApplication {
        val s = TestKit.services()
        application { andvariModule(s) }
        OPERATOR_KEY[s] = Flow.finishSetup(client, s).authKey
        block(client, s, Flow.member(client, s, "e@example.com"))
    }

    @Test
    fun pickup_racingAPasswordChange_mintsNothing() = app { c, s, e ->
        val (linkId, proof) = approved(c, s, e)
        val before = devices(s, e)
        // The password changes after the gate verified the old one, before the pickup's transaction.
        s.raceHook = { point -> if (point == "pickup.afterGate") s.db.tx { it.exec("UPDATE users SET verifier=? WHERE userId=?", ServerCrypto.hashVerifier(b32()), e.userId) } }
        val r = c.call(HttpMethod.Post, "/api/v1/device-links/$linkId/pickup", pickup(e, proof))
        assertEquals(401, r.status.value, r.bodyAsText())
        assertEquals("invalid_credentials", r.errorCode())
        assertEquals(before, devices(s, e))
        assertEquals(1L, s.db.read { it.count("SELECT COUNT(*) FROM audit WHERE type='device_link_pickup_denied' AND meta='credential_changed'") })
    }

    @Test
    fun pickup_racingAnAccountDisable_mintsNothing() = app { c, s, e ->
        val (linkId, proof) = approved(c, s, e)
        val before = devices(s, e)
        s.raceHook = { point -> if (point == "pickup.afterGate") s.db.tx { it.exec("UPDATE users SET status='disabled', disabledAt=1 WHERE userId=?", e.userId) } }
        assertEquals("invalid_credentials", c.call(HttpMethod.Post, "/api/v1/device-links/$linkId/pickup", pickup(e, proof)).errorCode())
        assertEquals(before, devices(s, e))
    }

    @Test
    fun pickup_racingTheRevokeOfTheApprovingDevice_mintsNothing() = app { c, s, e ->
        val (linkId, proof) = approved(c, s, e)
        val before = devices(s, e)
        s.raceHook = { point -> if (point == "pickup.afterGate") s.db.tx { s.sessions.revokeDevice(it, e.deviceId) } }
        assertEquals("link_unknown", c.call(HttpMethod.Post, "/api/v1/device-links/$linkId/pickup", pickup(e, proof)).errorCode())
        assertEquals(before, devices(s, e))
    }

    @Test
    fun pickup_refusesALinkWhoseApproverIsRevoked_evenIfTheRowSurvived() = app { c, s, e ->
        val (linkId, proof) = approved(c, s, e)
        // A revoke that left the row behind (only the device flag is set): the pickup's own check still holds.
        s.db.tx { it.exec("UPDATE devices SET revokedAt=1 WHERE deviceId=?", e.deviceId) }
        assertEquals("link_unknown", c.call(HttpMethod.Post, "/api/v1/device-links/$linkId/pickup", pickup(e, proof)).errorCode())
    }

    @Test
    fun revokingTheCreatingAndApprovingDevice_fromAnotherDevice_cancelsTheLink() = app { c, s, e ->
        // Only the creating device approves (§16.6), so approvedBy is E's device; a second device of the account revokes it.
        val second = WireJsonSession.parse(c.call(HttpMethod.Post, "/api/v1/auth/login", e.loginBody()).bodyAsText())
        val (linkId, proof) = approved(c, s, e)
        assertEquals(e.deviceId, s.db.read { db -> db.queryOne("SELECT approvedBy FROM device_links WHERE linkId=?", linkId) { it.getString(1) } })
        assertEquals(200, c.call(HttpMethod.Post, "/api/v1/account/devices/${e.deviceId}/revoke", """{"currentAuthKey":"${e.authKey}"}""", second.first).status.value)
        assertEquals("link_unknown", c.call(HttpMethod.Post, "/api/v1/device-links/$linkId/poll", """{"proof":"$proof"}""").errorCode())
        assertEquals("link_unknown", c.call(HttpMethod.Post, "/api/v1/device-links/$linkId/pickup", pickup(e, proof)).errorCode())
    }

    @Test
    fun revokingTheCreatingDevice_byTheOperator_cancelsItsLink() = app { c, s, e ->
        val op = s.db.read { it.queryOne("SELECT userId FROM users WHERE role='operator'") { r -> r.getString(1) } }!!
        val opDevice = s.db.read { it.queryOne("SELECT deviceId FROM devices WHERE userId=?", op) { r -> r.getString(1) } }!!
        val opToken = s.db.tx { s.sessions.issue(it, op, opDevice, "linux", passwordLogin = true).accessToken }
        val (linkId, proof) = approved(c, s, e)
        assertEquals(200, c.call(HttpMethod.Post, "/api/v1/admin/devices/${e.deviceId}/revoke", """{"currentAuthKey":"${OPERATOR_KEY.getValue(s)}"}""", opToken).status.value)
        assertEquals(0L, s.db.read { it.count("SELECT COUNT(*) FROM device_links WHERE linkId=?", linkId) })
        assertEquals("link_unknown", c.call(HttpMethod.Post, "/api/v1/device-links/$linkId/pickup", pickup(e, proof)).errorCode())
    }

    @Test
    fun twoClaimsAtOnce_oneWins() = app { c, s, e ->
        val linkId = id()
        assertEquals(201, c.call(HttpMethod.Post, "/api/v1/device-links", """{"linkId":"$linkId","expiresAt":${s.clock.now() + 60_000}}""", e.token).status.value)
        val codes = coroutineScope {
            (1..6).map {
                async { c.call(HttpMethod.Post, "/api/v1/device-links/$linkId/claim", """{"nPub":"${b32()}","name":"$name","platform":"android","commitN":"${"c".repeat(64)}","mac":"${b32()}"}""").status.value }
            }.awaitAll()
        }
        assertEquals(1, codes.count { it == 200 }, codes.toString())
        assertEquals(5, codes.count { it == 409 }, codes.toString())
    }

    @Test
    fun twoPickupsAtOnce_oneSession() = app { c, s, e ->
        val (linkId, proof) = approved(c, s, e)
        val before = devices(s, e)
        val codes = coroutineScope { (1..3).map { async { c.call(HttpMethod.Post, "/api/v1/device-links/$linkId/pickup", pickup(e, proof)).status.value } }.awaitAll() }
        assertEquals(1, codes.count { it == 200 }, codes.toString())
        assertEquals(before + 1, devices(s, e))
    }
}

/** (accessToken, deviceId) of a SessionResponse body. */
object WireJsonSession {
    fun parse(body: String): Pair<String, String> {
        val r = io.silencelen.andvari.core.model.wire.WireJson.json.decodeFromString(io.silencelen.andvari.core.model.wire.SessionResponse.serializer(), body)
        return r.accessToken to r.deviceId
    }
}
