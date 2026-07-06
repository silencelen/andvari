package io.silencelen.andvari.server

import io.ktor.client.request.get
import io.ktor.client.request.header
import io.ktor.client.request.post
import io.ktor.client.request.put
import io.ktor.client.request.setBody
import io.ktor.client.statement.bodyAsText
import io.ktor.http.ContentType
import io.ktor.http.HttpStatusCode
import io.ktor.http.contentType
import io.ktor.server.testing.testApplication
import io.silencelen.andvari.core.crypto.Bytes
import io.silencelen.andvari.core.model.DeviceInfo
import io.silencelen.andvari.core.model.LoginRequest
import io.silencelen.andvari.core.model.PreloginRequest
import io.silencelen.andvari.core.model.PreloginResponse
import io.silencelen.andvari.core.model.RefreshRequest
import io.silencelen.andvari.core.model.SessionResponse
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue

/**
 * P4 password change (spec 03 §3): verifier/salt/params/wrappedUvk swap in one shot,
 * every session except the caller revoked, and the SAME UVK survives the rotation.
 */
class PasswordChangeTest : P4TestSupport() {

    @Test
    fun passwordChange_swapsCreds_revokesOtherSessions_freshDeviceDecrypts() = testApplication {
        application { andvariModule(buildServices(config(), Notifier())) }
        val client = jsonClient(this)

        val vc = VirtualClient("pw@x.com", "original password value")
        val sessionA = client.register(vc, bootstrapToken)
        val itemId = vc.newItemId()
        client.push(vc, putMutation(vc, itemId, """{"type":"login","name":"Bank","login":{"password":"hunter2"}}""", 0))

        // A second device/session (B) performs the change; A must die, B must survive.
        val loginB = client.post("/api/v1/auth/login") {
            contentType(ContentType.Application.Json); header("X-Andvari-Client", "test/1.0.0")
            setBody(LoginRequest(vc.email, vc.authKey, DeviceInfo("test", "device-b")))
        }
        assertEquals(HttpStatusCode.OK, loginB.status, loginB.bodyAsText())
        val sessionB = json.decodeFromString(SessionResponse.serializer(), loginB.bodyAsText())

        val newPassword = "rotated password value 2"
        val change = vc.buildPasswordChange(newPassword)

        // Wrong current authKey → 401.
        val bad = client.put("/api/v1/account/password") {
            contentType(ContentType.Application.Json); authed(sessionB.accessToken)
            setBody(change.copy(currentAuthKey = Bytes.toB64(crypto.randomBytes(32))))
        }
        assertEquals(HttpStatusCode.Unauthorized, bad.status)

        val ok = client.put("/api/v1/account/password") {
            contentType(ContentType.Application.Json); authed(sessionB.accessToken)
            setBody(change)
        }
        assertEquals(HttpStatusCode.OK, ok.status, ok.bodyAsText())

        // Session A (the register session) is revoked: refresh and access both dead…
        val refreshA = client.post("/api/v1/auth/refresh") {
            contentType(ContentType.Application.Json)
            setBody(RefreshRequest(sessionA.refreshToken))
        }
        assertEquals(HttpStatusCode.Unauthorized, refreshA.status, "the old refresh token must be revoked")
        assertEquals(HttpStatusCode.Unauthorized, client.get("/api/v1/sync?since=0") { authed(sessionA.accessToken) }.status)
        // …while the calling session (B) stays authorized.
        assertEquals(HttpStatusCode.OK, client.get("/api/v1/sync?since=0") { authed(sessionB.accessToken) }.status)

        // A fresh device holding ONLY the new password: prelogin → login → unlock → decrypt.
        val pre = client.post("/api/v1/auth/prelogin") {
            contentType(ContentType.Application.Json)
            setBody(PreloginRequest(vc.email))
        }
        val preResp = json.decodeFromString(PreloginResponse.serializer(), pre.bodyAsText())
        assertEquals(change.newKdfSalt, preResp.kdfSalt, "prelogin must serve the rotated salt")

        val fresh = VirtualClient(vc.email, newPassword)
        fresh.userId = vc.userId
        fresh.personalVaultId = vc.personalVaultId
        val freshLogin = client.post("/api/v1/auth/login") {
            contentType(ContentType.Application.Json); header("X-Andvari-Client", "test/1.0.0")
            setBody(LoginRequest(vc.email, fresh.authKeyWith(preResp.kdfSalt, preResp.kdfParams), DeviceInfo("test", "fresh")))
        }
        assertEquals(HttpStatusCode.OK, freshLogin.status, freshLogin.bodyAsText())
        val freshSession = json.decodeFromString(SessionResponse.serializer(), freshLogin.bodyAsText())
        fresh.accessToken = freshSession.accessToken

        val snap = client.sync(fresh)
        fresh.unlockFromServer(freshSession.accountKeys, snap.grants.single { it.vaultId == fresh.personalVaultId }.wrappedVk)
        assertTrue(
            fresh.decItem(itemId, snap.items.single { it.itemId == itemId }.blob!!).contains("hunter2"),
            "the SAME UVK re-wrapped under the new password must still decrypt existing items",
        )

        // The old password no longer logs in.
        val old = client.post("/api/v1/auth/login") {
            contentType(ContentType.Application.Json); header("X-Andvari-Client", "test/1.0.0")
            setBody(LoginRequest(vc.email, vc.authKeyWith(preResp.kdfSalt, preResp.kdfParams), DeviceInfo("test", "stale")))
        }
        assertEquals(HttpStatusCode.Unauthorized, old.status)
    }
}
