package io.silencelen.andvari.server

import io.ktor.client.HttpClient
import io.ktor.client.request.post
import io.ktor.client.request.setBody
import io.ktor.client.statement.HttpResponse
import io.ktor.client.statement.bodyAsText
import io.ktor.http.ContentType
import io.ktor.http.HttpStatusCode
import io.ktor.http.contentType
import io.ktor.server.testing.testApplication
import io.silencelen.andvari.core.model.TotpCodeRequest
import io.silencelen.andvari.core.model.TotpSetupResponse
import io.silencelen.andvari.core.model.TotpStatus
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue

/**
 * Security review 2026-10 (server F4): a FIRST TOTP enrollment used to need nothing but a bearer
 * access token. Whoever held a member's token — a compromised client, a leaked log — could enroll
 * a second factor they own, and every later login on every origin then needed their code. No API
 * path, the member's or an admin's, can remove a factor without a code from it, so the member was
 * locked out for good once their refresh chain lapsed.
 *
 * A first enrollment now needs proof the caller knows the password: a `currentAuthKey` in the
 * setup body (verified like a password change), OR a session minted by a password login within
 * [TOTP_ENROLL_FRESH_LOGIN_MS] — the "just signed in" window every fielded client's enrollment
 * flow already falls inside, since they send no body. The §2.6 restricted session (instance
 * requires TOTP, member not enrolled) stays exempt: it exists only to be enrolled.
 */
class TotpEnrollReauthTest : P4TestSupport() {

    private suspend fun HttpClient.setup(vc: VirtualClient, body: String? = null): HttpResponse =
        post("/api/v1/account/totp/setup") {
            authed(vc)
            if (body != null) { contentType(ContentType.Application.Json); setBody(body) }
        }

    /** Push this user's device logins back past the freshness window — a session that has been
     *  refreshed for hours since the password was last typed. */
    private fun ageLogins(services: Services, vc: VirtualClient) {
        services.repo.db.tx { c -> c.exec("UPDATE devices SET createdAt=? WHERE userId=?", now() - 3_600_000, vc.userId) }
    }

    @Test
    fun staleSession_withoutPassword_cannotEnrollAFirstFactor() = testApplication {
        val services = buildServices(config(), Notifier())
        application { andvariModule(services) }
        val client = jsonClient(this)
        val vc = VirtualClient("stale@x.com", "stale session password")
        client.register(vc, bootstrapToken)
        ageLogins(services, vc)

        val resp = client.setup(vc)
        assertEquals(HttpStatusCode.Forbidden, resp.status, resp.bodyAsText())
        assertEquals("reauth_required", errorOf(resp))
        assertEquals(TotpStatus(enrolled = false, pendingSetup = false), client.totpStatus(vc), "nothing may be staged")
    }

    @Test
    fun staleSession_wrongPassword_isRefusedAndAudited() = testApplication {
        val services = buildServices(config(), Notifier())
        application { andvariModule(services) }
        val client = jsonClient(this)
        val vc = VirtualClient("wrongpw@x.com", "the real password here")
        client.register(vc, bootstrapToken) // bootstrap ⇒ admin, so it can read its own audit rows
        ageLogins(services, vc)

        val other = VirtualClient("wrongpw@x.com", "a guessed password here")
        val resp = client.setup(vc, """{"currentAuthKey":"${other.authKey}"}""")
        assertEquals(HttpStatusCode.Forbidden, resp.status, resp.bodyAsText())
        assertEquals("reauth_failed", errorOf(resp))
        assertEquals(TotpStatus(enrolled = false, pendingSetup = false), client.totpStatus(vc))
        assertEquals(1, client.auditRows(vc, "totp_setup_reauth_fail").size)
    }

    @Test
    fun staleSession_withPassword_enrolls() = testApplication {
        val services = buildServices(config(), Notifier())
        application { andvariModule(services) }
        val client = jsonClient(this)
        val vc = VirtualClient("withpw@x.com", "password proves presence")
        client.register(vc, bootstrapToken)
        ageLogins(services, vc)

        val resp = client.setup(vc, """{"currentAuthKey":"${vc.authKey}"}""")
        assertEquals(HttpStatusCode.OK, resp.status, resp.bodyAsText())
        val setup = json.decodeFromString(TotpSetupResponse.serializer(), resp.bodyAsText())
        val confirm = client.post("/api/v1/account/totp/confirm") {
            contentType(ContentType.Application.Json); authed(vc)
            setBody(TotpCodeRequest(totpCode(setup.secretBase32)))
        }
        assertEquals(HttpStatusCode.OK, confirm.status, confirm.bodyAsText())
        assertEquals(TotpStatus(enrolled = true, pendingSetup = false), client.totpStatus(vc))
    }

    @Test
    fun freshLogin_withoutBody_stillEnrolls_theFieldedWireShape() = testApplication {
        application { andvariModule(buildServices(config(), Notifier())) }
        val client = jsonClient(this)
        val vc = VirtualClient("fresh@x.com", "just signed in password")
        client.register(vc, bootstrapToken)

        val resp = client.setup(vc)
        assertEquals(HttpStatusCode.OK, resp.status, resp.bodyAsText())
        assertTrue(client.totpStatus(vc).pendingSetup)
    }

    @Test
    fun restrictedSession_isExempt_evenWhenStale() = testApplication {
        val base = config()
        val cfg = Config(
            host = base.host, port = 0, dbPath = base.dbPath, blobDir = base.blobDir, webDir = null,
            recoveryPublicKey = base.recoveryPublicKey, recoveryFingerprint = base.recoveryFingerprint,
            enumSecret = base.enumSecret, publicHostname = null, bootstrapToken = bootstrapToken,
            totpRequired = true,
        )
        val services = buildServices(cfg, Notifier())
        application { andvariModule(services) }
        val client = jsonClient(this)
        val vc = VirtualClient("restricted@x.com", "restricted session password")
        val s = client.register(vc, bootstrapToken)
        assertTrue(s.mustEnrollTotp)
        ageLogins(services, vc)

        val resp = client.setup(vc)
        assertEquals(HttpStatusCode.OK, resp.status, resp.bodyAsText())
    }
}
