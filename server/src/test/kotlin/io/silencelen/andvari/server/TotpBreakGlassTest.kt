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

    // §2.5 flattened the login bucket to 5/min per IP (origin-independent), so multi-login tests
    // stamp a distinct forwarded IP per attempt (testApplication's peer is loopback → XFF trusted).
    private var ipCounter = 0
    private fun nextIp() = "198.51.100.${++ipCounter}"

    /** A login as seen from the public (break-glass) origin: the Host header carries the public hostname. */
    private suspend fun HttpClient.publicLogin(vc: VirtualClient, code: String? = null): HttpResponse =
        post("/api/v1/auth/login") {
            contentType(ContentType.Application.Json)
            header("X-Andvari-Client", "test/1.0.0")
            header(HttpHeaders.Host, publicHost)
            header("X-Forwarded-For", nextIp())
            setBody(LoginRequest(vc.email, vc.authKey, DeviceInfo("test", "break-glass"), totp = code))
        }

    private suspend fun HttpClient.internalLogin(vc: VirtualClient, code: String? = null): HttpResponse =
        post("/api/v1/auth/login") {
            contentType(ContentType.Application.Json)
            header("X-Andvari-Client", "test/1.0.0")
            header("X-Forwarded-For", nextIp())
            setBody(LoginRequest(vc.email, vc.authKey, DeviceInfo("test", "lan"), totp = code))
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

        // §2.6 row 1 (multi-tenant design 2026-07-15): an ENROLLED secret is now verified on EVERY
        // origin — an internal login without a code gets the reactive 401 totp_required, exactly like
        // the public origin. (The success-with-code internal path is locked in
        // MultiTenantEndpointTest.enrolledTotp_enforcedOnEveryOrigin — both valid window steps are
        // already consumed at this point in THIS test.)
        val internal = client.internalLogin(vc)
        assertEquals(HttpStatusCode.Unauthorized, internal.status, internal.bodyAsText())
        assertEquals("totp_required", errorOf(internal))
    }

    /**
     * bug-server--0: setup on an ALREADY-ENROLLED account is a rotation and must prove the CURRENT
     * factor first — otherwise a hijacked session could stage its own secret, confirm it with a code
     * it controls, and then totpDisable with that code, bypassing the guard totpDisable enforces.
     * The rotation code rides the same guarded totpLastStep consume as login, so it cannot be
     * replayed; the completed rotation audits as totp_rotate, never masquerading as totp_enroll.
     */
    @Test
    fun setupWhileEnrolled_requiresCurrentCode_thenRotates() = testApplication {
        application { andvariModule(buildServices(config(publicHostname = publicHost), Notifier())) }
        val client = jsonClient(this)
        val vc = VirtualClient("bg3@x.com", "break glass password three")
        client.register(vc, bootstrapToken) // bootstrap invite → admin (auditRows below)

        // Fresh enrollment: no body, exactly the fielded wire shape.
        val setup1 = json.decodeFromString(
            TotpSetupResponse.serializer(),
            client.post("/api/v1/account/totp/setup") { authed(vc) }.bodyAsText(),
        )
        val confirm1 = client.post("/api/v1/account/totp/confirm") {
            contentType(ContentType.Application.Json); authed(vc)
            setBody(TotpCodeRequest(totpCode(setup1.secretBase32)))
        }
        assertEquals(HttpStatusCode.OK, confirm1.status, confirm1.bodyAsText())

        // Enrolled + no current code → refused, and nothing was staged (pendingSetup stays false).
        val noCode = client.post("/api/v1/account/totp/setup") { authed(vc) }
        assertEquals(HttpStatusCode.BadRequest, noCode.status, noCode.bodyAsText())
        assertEquals("totp_code_required", errorOf(noCode))
        assertEquals(TotpStatus(enrolled = true, pendingSetup = false), client.totpStatus(vc))

        // Enrolled + a WRONG current code → refused.
        val badCode = client.post("/api/v1/account/totp/setup") {
            contentType(ContentType.Application.Json); authed(vc)
            setBody(TotpCodeRequest(wrongCode(setup1.secretBase32)))
        }
        assertEquals(HttpStatusCode.BadRequest, badCode.status)
        assertEquals("bad_totp_code", errorOf(badCode))

        // Enrolled + a valid unused current code → rotation stages a FRESH secret…
        val rotCode = totpCode(setup1.secretBase32, stepOffset = 1) // confirm consumed the current step
        val rotResp = client.post("/api/v1/account/totp/setup") {
            contentType(ContentType.Application.Json); authed(vc)
            setBody(TotpCodeRequest(rotCode))
        }
        assertEquals(HttpStatusCode.OK, rotResp.status, rotResp.bodyAsText())
        val setup2 = json.decodeFromString(TotpSetupResponse.serializer(), rotResp.bodyAsText())
        assertTrue(setup2.secretBase32 != setup1.secretBase32, "a rotation must mint a new secret")

        // REPLAY: the consumed rotation code cannot authorize a second setup.
        val replay = client.post("/api/v1/account/totp/setup") {
            contentType(ContentType.Application.Json); authed(vc)
            setBody(TotpCodeRequest(rotCode))
        }
        assertEquals(HttpStatusCode.BadRequest, replay.status)
        assertEquals("bad_totp_code", errorOf(replay))

        // Confirm with the NEW secret's code completes the rotation.
        val confirm2 = client.post("/api/v1/account/totp/confirm") {
            contentType(ContentType.Application.Json); authed(vc)
            setBody(TotpCodeRequest(totpCode(setup2.secretBase32)))
        }
        assertEquals(HttpStatusCode.OK, confirm2.status, confirm2.bodyAsText())
        assertEquals(TotpStatus(enrolled = true, pendingSetup = false), client.totpStatus(vc))

        // The OLD secret is dead; the NEW one logs in (its current step was consumed by confirm2).
        assertEquals(HttpStatusCode.Unauthorized, client.publicLogin(vc, totpCode(setup1.secretBase32, stepOffset = 1)).status)
        val ok = client.publicLogin(vc, totpCode(setup2.secretBase32, stepOffset = 1))
        assertEquals(HttpStatusCode.OK, ok.status, ok.bodyAsText())

        // Audit: one first-time enroll, one rotation — the rotation never hides as totp_enroll.
        assertEquals(1, client.auditRows(vc, "totp_enroll").size)
        assertEquals(1, client.auditRows(vc, "totp_rotate").size)

        // F02: the two rejected setups above (the wrong code, then the replayed rotation code — a
        // consumed step fails the window check, so both land as "setup") each left a totp_verify_fail
        // row. Before this the only TOTP rows were successes, so a grind against the factor showed up
        // in GET /admin/audit as nothing at all. The refused-no-code attempt writes none: it never
        // presented a code to check.
        assertEquals(listOf("setup", "setup"), client.auditRows(vc, "totp_verify_fail").map { it.meta })
    }

    /**
     * F02: every TOTP route verifies a 6-digit code, and until F02 none of them carried a bucket —
     * ~333k expected requests to guess a factor, free and unlogged, off a session an attacker already
     * holds (the exact threat the rotation gate above was added for). Every rejected code is audited.
     *
     * Server review 2026-08-13: F02's first cut keyed one bucket per ROUTE, which handed the LIVE
     * secret 10 guesses a minute — /disable and an ENROLLED /setup both check it, at 5/min each. The
     * key is now cut by the secret a call checks, so both spend one `totp_verify:<userId>` budget and
     * the live factor faces the 5/min the finding asked for.
     */
    @Test
    fun liveSecretGuesses_shareOneBudget_acrossDisableAndRotation() = testApplication {
        application { andvariModule(buildServices(config(publicHostname = publicHost), Notifier())) }
        val client = jsonClient(this)
        val vc = VirtualClient("bg4@x.com", "break glass password four")
        client.register(vc, bootstrapToken) // bootstrap invite → admin (auditRows below)

        // Enroll first. A FIRST setup verifies nothing and confirm checks the pending secret, so
        // neither touches the live-secret budget this test then spends.
        val setup = json.decodeFromString(
            TotpSetupResponse.serializer(),
            client.post("/api/v1/account/totp/setup") { authed(vc) }.bodyAsText(),
        )
        val confirm = client.post("/api/v1/account/totp/confirm") {
            contentType(ContentType.Application.Json); authed(vc)
            setBody(TotpCodeRequest(totpCode(setup.secretBase32)))
        }
        assertEquals(HttpStatusCode.OK, confirm.status, confirm.bodyAsText())

        // Five guesses against the live factor are each refused on the code…
        val wrong = wrongCode(setup.secretBase32)
        suspend fun disableAttempt() = client.post("/api/v1/account/totp/disable") {
            contentType(ContentType.Application.Json); authed(vc)
            setBody(TotpCodeRequest(wrong))
        }
        repeat(5) { n ->
            val r = disableAttempt()
            assertEquals(HttpStatusCode.BadRequest, r.status, "guess ${n + 1} is under the bucket")
            assertEquals("bad_totp_code", errorOf(r))
        }
        // …and the 6th inside the same minute never reaches the verify at all.
        val sixth = disableAttempt()
        assertEquals(HttpStatusCode.TooManyRequests, sixth.status, sixth.bodyAsText())
        assertEquals("rate_limited", errorOf(sixth))

        // The factor stands (a bucketed attempt changes no state) and the grind is VISIBLE: five
        // rows, one per code actually checked — the 429 left none because it never got that far.
        assertEquals(TotpStatus(enrolled = true, pendingSetup = false), client.totpStatus(vc))
        val misses = client.auditRows(vc, "totp_verify_fail")
        assertEquals(5, misses.size)
        assertTrue(misses.all { it.userId == vc.userId && it.meta == "disable" }, "each miss names the route it hit")

        // THE FIX: a rotation carrying a VALID current code is refused too, because it would check
        // the same secret the five guesses above were spent on. With a per-route key this call
        // succeeded — five fresh guesses, on the same factor, inside the same minute.
        val rotate = client.post("/api/v1/account/totp/setup") {
            contentType(ContentType.Application.Json); authed(vc)
            setBody(TotpCodeRequest(totpCode(setup.secretBase32, stepOffset = 1))) // confirm consumed the current step
        }
        assertEquals(HttpStatusCode.TooManyRequests, rotate.status, rotate.bodyAsText())
        assertEquals("rate_limited", errorOf(rotate))
    }

    /**
     * The usability half of that split, and the reason a single shared key was not the answer: the
     * PENDING secret is one the server just handed this caller, so confirming it is not guessing
     * surface and keeps its own budget. A rotation already staged therefore stays finishable in a
     * minute whose live-secret budget is gone. The arithmetic also proves the budget really is
     * shared rather than renamed: the staging setup + four disable misses = five.
     */
    @Test
    fun stagedRotation_stillConfirms_whenTheLiveSecretBudgetIsSpent() = testApplication {
        application { andvariModule(buildServices(config(publicHostname = publicHost), Notifier())) }
        val client = jsonClient(this)
        val vc = VirtualClient("bg5@x.com", "break glass password five")
        client.register(vc, bootstrapToken)

        val setup1 = json.decodeFromString(
            TotpSetupResponse.serializer(),
            client.post("/api/v1/account/totp/setup") { authed(vc) }.bodyAsText(),
        )
        val confirm1 = client.post("/api/v1/account/totp/confirm") {
            contentType(ContentType.Application.Json); authed(vc)
            setBody(TotpCodeRequest(totpCode(setup1.secretBase32)))
        }
        assertEquals(HttpStatusCode.OK, confirm1.status, confirm1.bodyAsText())

        // Stage the rotation: this verifies the LIVE secret, so it spends 1 of the 5.
        val rotResp = client.post("/api/v1/account/totp/setup") {
            contentType(ContentType.Application.Json); authed(vc)
            setBody(TotpCodeRequest(totpCode(setup1.secretBase32, stepOffset = 1))) // confirm consumed the current step
        }
        assertEquals(HttpStatusCode.OK, rotResp.status, rotResp.bodyAsText())
        val setup2 = json.decodeFromString(TotpSetupResponse.serializer(), rotResp.bodyAsText())

        // Four more live-secret attempts exhaust the shared budget…
        val wrong = wrongCode(setup1.secretBase32)
        suspend fun disableAttempt() = client.post("/api/v1/account/totp/disable") {
            contentType(ContentType.Application.Json); authed(vc)
            setBody(TotpCodeRequest(wrong))
        }
        repeat(4) { n ->
            val r = disableAttempt()
            assertEquals(HttpStatusCode.BadRequest, r.status, "guess ${n + 1} shares the budget with the staging setup")
            assertEquals("bad_totp_code", errorOf(r))
        }
        val spent = disableAttempt()
        assertEquals(HttpStatusCode.TooManyRequests, spent.status, spent.bodyAsText())

        // …and the staged rotation still completes: /confirm holds its own key.
        val confirm2 = client.post("/api/v1/account/totp/confirm") {
            contentType(ContentType.Application.Json); authed(vc)
            setBody(TotpCodeRequest(totpCode(setup2.secretBase32)))
        }
        assertEquals(HttpStatusCode.OK, confirm2.status, confirm2.bodyAsText())
        assertEquals(TotpStatus(enrolled = true, pendingSetup = false), client.totpStatus(vc))
        assertEquals(1, client.auditRows(vc, "totp_rotate").size)
    }
}
