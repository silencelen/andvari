package io.silencelen.andvari.server

import io.ktor.client.statement.bodyAsText
import io.ktor.http.HttpMethod
import io.ktor.server.testing.testApplication
import io.silencelen.andvari.core.crypto.Bytes
import io.silencelen.andvari.core.model.wire.DeviceLinkPickupResponse
import io.silencelen.andvari.core.model.wire.RecoveryVerifyResponse
import io.silencelen.andvari.core.model.wire.SessionResponse
import io.silencelen.andvari.core.model.wire.WireJson
import kotlin.test.Test
import kotlin.test.assertEquals

/**
 * The kind of a device row decides everywhere a session is made, not the caller's word (decided on 2026-11-17): a
 * session made on a row made as `web` is a web session, which every operator route refuses, whatever the request's
 * `X-Andvari-Client` header says. The sign-in read the row since the day before; a registration, a recovery's commit and
 * a link's pickup still marked the session by the header (`linux` here, the tests' default), so a browser's row held a
 * session that was not a web one. The assisted recovery's commit is in `AssistedRecoveryTest`.
 */
class RowKindDecidesTest {
    private val post = HttpMethod.Post
    private fun b32() = Bytes.toB64(TestKit.crypto.randomBytes(32))
    private fun id() = Bytes.toB64(TestKit.crypto.randomBytes(16))

    private fun platformOf(s: Services, accessToken: String): String? =
        s.db.read { c -> c.queryOne("SELECT clientPlatform FROM sessions WHERE accessHash=?", ServerCrypto.hashToken(accessToken)) { it.getString(1) } }

    private fun rowOf(s: Services, deviceId: String): String? =
        s.db.read { c -> c.queryOne("SELECT platform FROM devices WHERE deviceId=?", deviceId) { it.getString(1) } }

    @Test
    fun aRegistrationOnABrowsersRow_makesAWebSession_whateverTheHeader() = testApplication {
        val s = TestKit.services()
        application { andvariModule(s) }
        Flow.finishSetup(client, s)
        val me = Flow.member(client, s, "me@example.com", platform = "web")
        assertEquals("web", rowOf(s, me.deviceId))
        assertEquals("web", platformOf(s, me.token))
        // An app's row keeps the header's platform.
        val app = Flow.member(client, s, "app@example.com")
        assertEquals("linux", platformOf(s, app.token))
    }

    @Test
    fun aKitRecoverysCommitOnABrowsersRow_makesAWebSession() = testApplication {
        val s = TestKit.services()
        application { andvariModule(s) }
        Flow.finishSetup(client, s)
        val me = Flow.member(client, s, "me@example.com")
        val ticket = WireJson.json.decodeFromString(
            RecoveryVerifyResponse.serializer(),
            client.call(post, "/api/v1/recovery/self/verify", """{"email":"${me.email}","recoveryAuthKey":"${me.recoveryAuthKey}"}""").bodyAsText(),
        ).recoveryTicket
        val r = client.call(
            post, "/api/v1/recovery/self/commit",
            """{"recoveryTicket":"$ticket","newAuthKey":"${b32()}","newKdfSalt":"${Bytes.toB64(ByteArray(16) { 4 })}","newKdfParams":{"v":1,"alg":"argon2id13","ops":1,"memBytes":8388608},""" +
                """"newWrappedUvk":"AAAA","newMemberRecovery":{"recoveryWrappedUvk":"AAAA","recoveryAuthKey":"${b32()}"},""" +
                """"device":{"platform":"web","name":"browser","deviceSecret":"${b32()}"}}""",
        )
        assertEquals(200, r.status.value, r.bodyAsText())
        val session = WireJson.json.decodeFromString(SessionResponse.serializer(), r.bodyAsText())
        assertEquals("web", rowOf(s, session.deviceId))
        assertEquals("web", platformOf(s, session.accessToken))
    }

    @Test
    fun aLinksPickupOnABrowsersRow_makesAWebSession() = testApplication {
        val clock = MutableClock()
        val s = TestKit.services(clock = clock)
        application { andvariModule(s) }
        val c = client
        Flow.finishSetup(c, s)
        val e = Flow.member(c, s, "e@example.com")
        val linkId = id()
        assertEquals(201, c.call(post, "/api/v1/device-links", """{"linkId":"$linkId","expiresAt":${clock.now() + 3_600_000}}""", e.token).status.value)
        val proof = b32()
        assertEquals(200, c.call(post, "/api/v1/device-links/$linkId/claim", """{"nPub":"${b32()}","name":"${Grammar.nameOf("Browser")!!}","platform":"web","commitN":"${"c".repeat(64)}","mac":"${b32()}"}""").status.value)
        assertEquals(200, c.call(post, "/api/v1/device-links/$linkId/nonce", """{"nonceE":"${b32()}","proofHash":"${sha256Hex(proof)}"}""", e.token).status.value)
        assertEquals(200, c.call(post, "/api/v1/device-links/$linkId/reveal", """{"nonceN":"${b32()}","proof":"$proof"}""").status.value)
        assertEquals(200, c.call(post, "/api/v1/device-links/$linkId/approve", """{"outer":"QUFBQUFB","inner":"SU5ORVJJ","approveMac":"${b32()}"}""", e.token).status.value)
        val pk = c.call(post, "/api/v1/device-links/$linkId/pickup", """{"proof":"$proof","authKey":"${e.authKey}","device":{"deviceSecret":"${b32()}"}}""")
        assertEquals(200, pk.status.value, pk.bodyAsText())
        val session = WireJson.json.decodeFromString(DeviceLinkPickupResponse.serializer(), pk.bodyAsText()).session
        assertEquals("web", rowOf(s, session.deviceId))
        assertEquals("web", platformOf(s, session.accessToken))
    }
}
