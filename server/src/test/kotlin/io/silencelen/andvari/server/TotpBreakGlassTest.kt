package io.silencelen.andvari.server

import io.ktor.client.HttpClient
import io.ktor.client.request.header
import io.ktor.client.request.post
import io.ktor.client.request.setBody
import io.ktor.client.statement.HttpResponse
import io.ktor.client.statement.bodyAsText
import io.ktor.http.ContentType
import io.ktor.http.HttpHeaders
import io.ktor.http.HttpStatusCode
import io.ktor.http.contentType
import io.ktor.server.testing.testApplication
import io.silencelen.andvari.core.model.DeviceInfo
import io.silencelen.andvari.core.model.LoginRequest
import io.silencelen.andvari.core.model.RefreshRequest
import io.silencelen.andvari.core.model.SessionResponse
import io.silencelen.andvari.core.model.TotpCodeRequest
import io.silencelen.andvari.core.model.TotpSetupResponse
import io.silencelen.andvari.core.model.TotpStatus
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue

/**
 * P4 break-glass hardening (spec 03 §2): logins via the PUBLIC origin require
 * server-TOTP with single-use (replay-protected) codes, and public refresh is off.
 */
class TotpBreakGlassTest : P4TestSupport() {

    private val publicHost = "public.test"

    /** A login as seen from the public (break-glass) origin: the Host header carries the public hostname. */
    private suspend fun HttpClient.publicLogin(vc: VirtualClient, code: String? = null): HttpResponse =
        post("/api/v1/auth/login") {
            contentType(ContentType.Application.Json)
            header("X-Andvari-Client", "test/1.0.0")
            header(HttpHeaders.Host, publicHost)
            setBody(LoginRequest(vc.email, vc.authKey, DeviceInfo("test", "break-glass"), totp = code))
        }

    private suspend fun HttpClient.internalLogin(vc: VirtualClient): HttpResponse =
        post("/api/v1/auth/login") {
            contentType(ContentType.Application.Json)
            header("X-Andvari-Client", "test/1.0.0")
            setBody(LoginRequest(vc.email, vc.authKey, DeviceInfo("test", "lan")))
        }

    /** A 6-digit code that is provably not valid for any step near now. */
    private fun wrongCode(secretBase32: String): String {
        val valid = (-2L..2L).map { totpCode(secretBase32, it) }.toSet()
        return (0..999_999).asSequence().map { it.toString().padStart(6, '0') }.first { it !in valid }
    }

    @Test
    fun publicOrigin_requiresEnrollment_andRefreshIsDisabled() = testApplication {
        application { andvariModule(buildServices(config(publicHostname = publicHost), Notifier())) }
        val client = jsonClient(this)
        val vc = VirtualClient("bg1@x.com", "break glass password one")
        client.register(vc, bootstrapToken)

        // Correct password but no TOTP enrolled → the public origin refuses outright.
        val denied = client.publicLogin(vc)
        assertEquals(HttpStatusCode.Forbidden, denied.status)
        assertEquals("public_login_requires_totp", errorOf(denied))

        // Refresh via the public origin is disabled even for a valid token…
        val publicRefresh = client.post("/api/v1/auth/refresh") {
            contentType(ContentType.Application.Json)
            header(HttpHeaders.Host, publicHost)
            setBody(RefreshRequest(vc.refreshToken))
        }
        assertEquals(HttpStatusCode.Forbidden, publicRefresh.status)
        assertEquals("public_refresh_disabled", errorOf(publicRefresh))

        // …and was NOT consumed by the refusal: the internal origin still rotates it.
        val internalRefresh = client.post("/api/v1/auth/refresh") {
            contentType(ContentType.Application.Json)
            setBody(RefreshRequest(vc.refreshToken))
        }
        assertEquals(HttpStatusCode.OK, internalRefresh.status, internalRefresh.bodyAsText())

        // The internal origin is untouched by the TOTP gate.
        val internal = client.internalLogin(vc)
        assertEquals(HttpStatusCode.OK, internal.status, internal.bodyAsText())
    }

    @Test
    fun enrollment_publicLogin_andCodeReplayRejection() = testApplication {
        application { andvariModule(buildServices(config(publicHostname = publicHost), Notifier())) }
        val client = jsonClient(this)
        val vc = VirtualClient("bg2@x.com", "break glass password two")
        client.register(vc, bootstrapToken)

        assertEquals(TotpStatus(enrolled = false, pendingSetup = false), client.totpStatus(vc))

        val setupResp = client.post("/api/v1/account/totp/setup") { authed(vc) }
        assertEquals(HttpStatusCode.OK, setupResp.status, setupResp.bodyAsText())
        val setup = json.decodeFromString(TotpSetupResponse.serializer(), setupResp.bodyAsText())
        assertTrue(setup.otpauthUri.contains("secret=${setup.secretBase32}"), "otpauth URI must carry the secret")
        assertEquals(TotpStatus(enrolled = false, pendingSetup = true), client.totpStatus(vc))

        // Confirm with the current code — enrollment promotes the secret AND consumes this step.
        val confirmCode = totpCode(setup.secretBase32)
        val confirm = client.post("/api/v1/account/totp/confirm") {
            contentType(ContentType.Application.Json); authed(vc)
            setBody(TotpCodeRequest(confirmCode))
        }
        assertEquals(HttpStatusCode.OK, confirm.status, confirm.bodyAsText())
        assertEquals(TotpStatus(enrolled = true, pendingSetup = false), client.totpStatus(vc))

        // Enrolled but the code is missing → 401 totp_required.
        val missing = client.publicLogin(vc)
        assertEquals(HttpStatusCode.Unauthorized, missing.status)
        assertEquals("totp_required", errorOf(missing))

        // Wrong code → 401.
        assertEquals(HttpStatusCode.Unauthorized, client.publicLogin(vc, wrongCode(setup.secretBase32)).status)

        // REPLAY: the code the confirm consumed cannot log in within the same step.
        assertEquals(HttpStatusCode.Unauthorized, client.publicLogin(vc, confirmCode).status)

        // The NEXT step's code sits inside the ±1 window and is unused → success.
        val nextCode = totpCode(setup.secretBase32, stepOffset = 1)
        val ok = client.publicLogin(vc, nextCode)
        assertEquals(HttpStatusCode.OK, ok.status, ok.bodyAsText())
        assertTrue(json.decodeFromString(SessionResponse.serializer(), ok.bodyAsText()).totpEnrolled)

        // REPLAY: a code that already logged in must fail the second time.
        assertEquals(HttpStatusCode.Unauthorized, client.publicLogin(vc, nextCode).status)

        // Non-public login still needs no TOTP even when enrolled.
        val internal = client.internalLogin(vc)
        assertEquals(HttpStatusCode.OK, internal.status, internal.bodyAsText())
    }
}
