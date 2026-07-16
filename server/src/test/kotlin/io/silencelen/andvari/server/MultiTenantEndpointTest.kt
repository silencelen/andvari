package io.silencelen.andvari.server

import io.ktor.client.HttpClient
import io.ktor.client.plugins.contentnegotiation.ContentNegotiation
import io.ktor.client.plugins.websocket.WebSockets
import io.ktor.client.plugins.websocket.webSocket
import io.ktor.client.request.get
import io.ktor.client.request.header
import io.ktor.client.request.post
import io.ktor.client.request.put
import io.ktor.client.request.setBody
import io.ktor.client.statement.HttpResponse
import io.ktor.client.statement.bodyAsText
import io.ktor.http.ContentType
import io.ktor.http.HttpHeaders
import io.ktor.http.HttpStatusCode
import io.ktor.http.contentType
import io.ktor.serialization.kotlinx.json.json
import io.ktor.server.testing.testApplication
import io.ktor.websocket.CloseReason
import io.silencelen.andvari.core.crypto.Bytes
import io.silencelen.andvari.core.model.ClientPolicy
import io.silencelen.andvari.core.model.DeviceInfo
import io.silencelen.andvari.core.model.LoginRequest
import io.silencelen.andvari.core.model.RecoveryVerifyRequest
import io.silencelen.andvari.core.model.RefreshRequest
import io.silencelen.andvari.core.model.SessionResponse
import io.silencelen.andvari.core.model.TotpCodeRequest
import io.silencelen.andvari.core.model.TotpSetupResponse
import java.io.File
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue

/**
 * Multi-tenant / endpoint-agnostic pivot, SERVER lanes (design 2026-07-15):
 *   §2.2 operator policy overlay (per-origin `closed`, decorative identity fields, tighten-only
 *        offlineCacheAllowed floor) + the widened admin-PUT strip (lossless round-trip),
 *   §2.6 TOTP as per-instance policy (the login matrix + the restricted session),
 *   §2.5 origin-decoupled flat login bucket + email-keyed exponential backoff (login + recovery),
 *   §7.2 isPublicOrigin exact-host match + HSTS forceHsts re-home,
 *   §3   canonicalOrigin (deprecated inviteBaseUrl alias, https-for-non-local rule),
 *   §2.1 env parsing + boot lint,
 *   §8.1 the /selfhost route registered before the SPA fallback.
 * House style: VirtualClient does the real client crypto; helpers from P4TestSupport.
 */
class MultiTenantEndpointTest : P4TestSupport() {

    /** [P4TestSupport.config] + the §2.1 operator-stance knobs (all defaulted to today's behavior). */
    private fun tenantConfig(
        publicHostname: String? = null,
        signupMode: String = "invite-only",
        totpRequired: Boolean = false,
        instanceName: String? = null,
        canonicalOrigin: String? = null,
        selfHostDocsUrl: String? = null,
        offlineCacheAllowedFloor: Boolean = true,
        forceHsts: Boolean = false,
        loginRatePerMin: Int = 5,
        webDir: String? = null,
    ) = Config(
        host = "127.0.0.1", port = 0,
        dbPath = File(tmpDir, "mt-${System.nanoTime()}.db").absolutePath,
        blobDir = File(tmpDir, "mt-blobs-${System.nanoTime()}").absolutePath, webDir = webDir,
        recoveryPublicKey = recovery.publicKey, recoveryFingerprint = fingerprint,
        enumSecret = ByteArray(32) { 7 }, publicHostname = publicHostname, bootstrapToken = bootstrapToken,
        signupMode = signupMode, totpRequired = totpRequired, instanceName = instanceName,
        canonicalOrigin = canonicalOrigin, selfHostDocsUrl = selfHostDocsUrl,
        offlineCacheAllowedFloor = offlineCacheAllowedFloor, forceHsts = forceHsts, loginRatePerMin = loginRatePerMin,
    )

    // §2.5 flattened the login bucket to 5/min/IP, so multi-attempt tests stamp distinct forwarded
    // IPs (testApplication's peer is loopback → XFF trusted); the 203.0.113/24 pool is reserved for
    // "same source" assertions.
    private var ipCounter = 0
    private fun nextIp() = "198.51.100.${++ipCounter}"

    private suspend fun HttpClient.loginRaw(
        email: String,
        authKey: String,
        code: String? = null,
        ip: String? = null,
        host: String? = null,
    ): HttpResponse = post("/api/v1/auth/login") {
        contentType(ContentType.Application.Json)
        header("X-Andvari-Client", "test/1.0.0")
        if (ip != null) header("X-Forwarded-For", ip)
        if (host != null) header(HttpHeaders.Host, host)
        setBody(LoginRequest(email, authKey, DeviceInfo("test", "mt"), totp = code))
    }

    private fun policyOf(body: String): ClientPolicy = json.decodeFromString(ClientPolicy.serializer(), body)

    // ---- §2.2: operator overlay + per-origin `closed` + tighten-only floor ----

    @Test
    fun clientPolicy_operatorOverlay_andPerOriginClosed() = testApplication {
        val publicHost = "public.test"
        application {
            andvariModule(
                buildServices(
                    tenantConfig(
                        publicHostname = publicHost, signupMode = "landing",
                        instanceName = "andvari (test)", canonicalOrigin = "https://pm.example.com",
                    ),
                    Notifier(),
                ),
            )
        }
        val client = jsonClient(this)

        // Private origin: the env stance verbatim, identity fields declared, selfHostDocsUrl derived.
        val p = policyOf(client.get("/api/v1/client-policy").bodyAsText())
        assertEquals("landing", p.signupMode)
        assertEquals(false, p.totpRequired)
        assertEquals("andvari (test)", p.instanceName)
        assertEquals("https://pm.example.com", p.canonicalOrigin)
        assertEquals("https://pm.example.com/selfhost", p.selfHostDocsUrl)
        assertTrue(p.offlineCacheAllowed, "floor true + stored true stays true")

        // Break-glass twin origin: ALWAYS signupMode="closed" (§2.2) — no client hostname sniffing.
        val pub = policyOf(client.get("/api/v1/client-policy") { header(HttpHeaders.Host, publicHost) }.bodyAsText())
        assertEquals("closed", pub.signupMode)
        assertEquals("andvari (test)", pub.instanceName, "only signupMode forks per-origin")
    }

    @Test
    fun clientPolicy_offlineCacheFloor_isTightenOnly() = testApplication {
        // Env floor FALSE forces the declared value false even though the stored/admin value is true.
        application { andvariModule(buildServices(tenantConfig(offlineCacheAllowedFloor = false), Notifier())) }
        val client = jsonClient(this)
        val p = policyOf(client.get("/api/v1/client-policy").bodyAsText())
        assertFalse(p.offlineCacheAllowed, "env floor is tighten-only: false wins over the stored true")
    }

    @Test
    fun adminPolicyPut_stripsOverlay_operatorStanceNeverClobbered() = testApplication {
        val services = buildServices(
            tenantConfig(signupMode = "landing", instanceName = "ref", canonicalOrigin = "https://pm.example.com", totpRequired = false),
            Notifier(),
        )
        application { andvariModule(services) }
        val client = jsonClient(this)
        val admin = VirtualClient("stripadmin@x.com", "policy strip admin password")
        client.register(admin, bootstrapToken)

        // An OLD admin client GETs the policy (overlay values included) and PUTs the whole object
        // back with one edited field — exactly the lossless round-trip §2.2 requires.
        val got = policyOf(client.get("/api/v1/admin/policy") { authed(admin) }.bodyAsText())
        assertEquals("landing", got.signupMode, "admin GET shows the resolved overlay")
        val put = client.put("/api/v1/admin/policy") {
            contentType(ContentType.Application.Json); authed(admin)
            setBody(got.copy(autoLockSeconds = 222))
        }
        assertEquals(HttpStatusCode.OK, put.status, put.bodyAsText())

        // The stored JSON kept the admin edit but NONE of the overlay values.
        val storedJson = services.repo.policyJson()
        assertNotNull(storedJson)
        assertTrue("\"autoLockSeconds\":222" in storedJson, "the admin's real edit persists: $storedJson")
        assertFalse("landing" in storedJson, "operator signupMode must never persist via an admin PUT: $storedJson")
        assertFalse("pm.example.com" in storedJson, "canonicalOrigin/selfHostDocsUrl must be stripped: $storedJson")
        assertFalse("\"ref\"" in storedJson, "instanceName must be stripped: $storedJson")

        // Reads still declare the operator stance + the admin edit — nothing clobbered either way.
        val after = policyOf(client.get("/api/v1/client-policy").bodyAsText())
        assertEquals("landing", after.signupMode)
        assertEquals(222, after.autoLockSeconds)

        // offlineCacheAllowed stays the ADMIN-settable knob (floor true leaves it in charge).
        client.put("/api/v1/admin/policy") {
            contentType(ContentType.Application.Json); authed(admin)
            setBody(got.copy(offlineCacheAllowed = false))
        }
        assertFalse(policyOf(client.get("/api/v1/client-policy").bodyAsText()).offlineCacheAllowed)
        client.put("/api/v1/admin/policy") {
            contentType(ContentType.Application.Json); authed(admin)
            setBody(got.copy(offlineCacheAllowed = true))
        }
        assertTrue(policyOf(client.get("/api/v1/client-policy").bodyAsText()).offlineCacheAllowed)
    }

    @Test
    fun clientPolicy_perIpRateBucket() = testApplication {
        application { andvariModule(buildServices(tenantConfig(), Notifier())) }
        val client = jsonClient(this)
        repeat(60) {
            assertEquals(HttpStatusCode.OK, client.get("/api/v1/client-policy").status, "fetch ${it + 1} of 60 must pass")
        }
        val over = client.get("/api/v1/client-policy")
        assertEquals(HttpStatusCode.TooManyRequests, over.status, "the 61st same-IP fetch in a minute must be bucketed")
        assertEquals("rate_limited", errorOf(over))
    }

    // ---- §2.6: the TOTP matrix ----

    /** Row 1: an ENROLLED secret is verified on EVERY origin (was public-origin-only). */
    @Test
    fun enrolledTotp_enforcedOnEveryOrigin() = testApplication {
        application { andvariModule(buildServices(tenantConfig(), Notifier())) }
        val client = jsonClient(this)
        val vc = VirtualClient("row1@x.com", "row one enrolled password")
        client.register(vc, bootstrapToken)

        val setup = json.decodeFromString(
            TotpSetupResponse.serializer(),
            client.post("/api/v1/account/totp/setup") { authed(vc) }.bodyAsText(),
        )
        val confirmCode = totpCode(setup.secretBase32)
        assertEquals(
            HttpStatusCode.OK,
            client.post("/api/v1/account/totp/confirm") {
                contentType(ContentType.Application.Json); authed(vc); setBody(TotpCodeRequest(confirmCode))
            }.status,
        )

        // Internal (non-public) origin, no code → the reactive 401 totp_required.
        val missing = client.loginRaw(vc.email, vc.authKey)
        assertEquals(HttpStatusCode.Unauthorized, missing.status)
        assertEquals("totp_required", errorOf(missing))

        // Wrong code → 401. ("12345" is 5 digits — deterministically unequal to any 6-digit code,
        // no wrongCode() search needed.)
        assertEquals(HttpStatusCode.Unauthorized, client.loginRaw(vc.email, vc.authKey, code = "12345").status)

        // Fresh (unconsumed) step inside the ±1 window → 200, and the session is NOT restricted.
        val code = totpCode(setup.secretBase32, stepOffset = 1)
        val ok = client.loginRaw(vc.email, vc.authKey, code = code)
        assertEquals(HttpStatusCode.OK, ok.status, ok.bodyAsText())
        val session = json.decodeFromString(SessionResponse.serializer(), ok.bodyAsText())
        assertTrue(session.totpEnrolled)
        assertFalse(session.mustEnrollTotp)

        // The anti-replay consume guards the internal origin too.
        assertEquals(HttpStatusCode.Unauthorized, client.loginRaw(vc.email, vc.authKey, code = code).status)
    }

    /** Row 4: totpRequired + not enrolled + private origin → RESTRICTED session until enrollment. */
    @Test
    fun totpRequired_notEnrolled_restrictedSession_untilEnrolled() = testApplication {
        application { andvariModule(buildServices(tenantConfig(totpRequired = true), Notifier())) }
        val ws = createClient { install(ContentNegotiation) { json(json) }; install(WebSockets) }
        val vc = VirtualClient("row4@x.com", "row four restricted password")

        // Register succeeds (invite gate unchanged) and announces the restriction.
        val reg = ws.register(vc, bootstrapToken)
        assertTrue(reg.mustEnrollTotp, "register under instance totpRequired must mark the session restricted")

        // Every authed route except setup/confirm + logout answers 403 totp_enrollment_required —
        // the TOTP status GET and disable included (strict §2.6 allowlist).
        for (probe in listOf("/api/v1/sync?since=0", "/api/v1/account/keys", "/api/v1/account/totp")) {
            val r = ws.get(probe) { authed(vc) }
            assertEquals(HttpStatusCode.Forbidden, r.status, "$probe must be restricted: ${r.bodyAsText()}")
            assertEquals("totp_enrollment_required", errorOf(r))
        }
        val ticket = ws.post("/api/v1/events/ticket") { authed(vc) }
        assertEquals(HttpStatusCode.Forbidden, ticket.status)
        assertEquals("totp_enrollment_required", errorOf(ticket))
        // The WS upgrade's Bearer path mirrors the refusal (it bypasses requirePrincipal).
        ws.webSocket("/api/v1/events", request = { authed(vc) }) {
            assertEquals(CloseReason.Codes.VIOLATED_POLICY.code, closeReason.await()?.code, "restricted session must not hold a dirty-bell socket")
        }

        // Logout IS allowed from a restricted session…
        assertEquals(HttpStatusCode.OK, ws.post("/api/v1/auth/logout") { authed(vc) }.status)
        // …and a fresh password-only login SUCCEEDS into a restricted session (row 4: never a 401).
        val relogin = ws.loginRaw(vc.email, vc.authKey)
        assertEquals(HttpStatusCode.OK, relogin.status, relogin.bodyAsText())
        val restricted = json.decodeFromString(SessionResponse.serializer(), relogin.bodyAsText())
        assertTrue(restricted.mustEnrollTotp)
        vc.accessToken = restricted.accessToken

        // The enrollment pair is reachable; confirming lifts the restriction on the SAME session.
        val setup = json.decodeFromString(
            TotpSetupResponse.serializer(),
            ws.post("/api/v1/account/totp/setup") { authed(vc) }.also {
                assertEquals(HttpStatusCode.OK, it.status, it.bodyAsText())
            }.bodyAsText(),
        )
        assertEquals(
            HttpStatusCode.OK,
            ws.post("/api/v1/account/totp/confirm") {
                contentType(ContentType.Application.Json); authed(vc); setBody(TotpCodeRequest(totpCode(setup.secretBase32)))
            }.status,
        )
        val sync = ws.get("/api/v1/sync?since=0") { authed(vc) }
        assertEquals(HttpStatusCode.OK, sync.status, "the SAME token must work once enrolled: ${sync.bodyAsText()}")

        // Post-enrollment logins are row 1: code required, and the session is unrestricted.
        val enrolledLogin = ws.loginRaw(vc.email, vc.authKey, code = totpCode(setup.secretBase32, stepOffset = 1))
        assertEquals(HttpStatusCode.OK, enrolledLogin.status, enrolledLogin.bodyAsText())
        assertFalse(json.decodeFromString(SessionResponse.serializer(), enrolledLogin.bodyAsText()).mustEnrollTotp)
    }

    /** Row 5: totpRequired + not enrolled + PUBLIC origin → 403, no restricted-session hatch. */
    @Test
    fun totpRequired_notEnrolled_publicOrigin_stillRefused() = testApplication {
        val publicHost = "public.test"
        application { andvariModule(buildServices(tenantConfig(publicHostname = publicHost, totpRequired = true), Notifier())) }
        val client = jsonClient(this)
        val vc = VirtualClient("row5@x.com", "row five public password")
        client.register(vc, bootstrapToken)

        val denied = client.loginRaw(vc.email, vc.authKey, host = publicHost)
        assertEquals(HttpStatusCode.Forbidden, denied.status)
        assertEquals("public_login_requires_totp", errorOf(denied))
    }

    // ---- §2.5: flat login bucket + email-keyed backoff ----

    @Test
    fun loginRateLimit_flatFivePerIp_originIndependent() = testApplication {
        application { andvariModule(buildServices(tenantConfig(), Notifier())) }
        val client = jsonClient(this)
        val key = Bytes.toB64(ByteArray(32) { 3 })
        // 5 attempts from ONE IP (alternating emails so the email backoff never engages) → 401s.
        repeat(5) { n ->
            val r = client.loginRaw("ghost${n % 2}@gone.test", key, ip = "203.0.113.50")
            assertEquals(HttpStatusCode.Unauthorized, r.status, "attempt ${n + 1} is under the bucket")
        }
        // The 6th is refused — the PRIVATE origin no longer gets the old 10/min relaxation (B1-3).
        val sixth = client.loginRaw("ghost-c@gone.test", key, ip = "203.0.113.50")
        assertEquals(HttpStatusCode.TooManyRequests, sixth.status)
        assertEquals("rate_limited", errorOf(sixth))
    }

    @Test
    fun loginRateLimit_perMinIsConfigurable() = testApplication {
        application { andvariModule(buildServices(tenantConfig(loginRatePerMin = 2), Notifier())) }
        val client = jsonClient(this)
        val key = Bytes.toB64(ByteArray(32) { 3 })
        repeat(2) { assertEquals(HttpStatusCode.Unauthorized, client.loginRaw("g$it@gone.test", key, ip = "203.0.113.60").status) }
        assertEquals(HttpStatusCode.TooManyRequests, client.loginRaw("g9@gone.test", key, ip = "203.0.113.60").status)
    }

    /**
     * Per-account backoff (§2.5): 5 consecutive failures lock the EMAIL (not the IP) for 2^0=1 s;
     * a success resets the counter. Real and never-registered emails behave byte-identically — the
     * throttle must not be an account oracle (the fake-salt discipline extended).
     */
    @Test
    fun emailBackoff_locksAfterFiveFailures_identicallyForRealAndGhostEmails() = testApplication {
        application { andvariModule(buildServices(tenantConfig(), Notifier())) }
        val client = jsonClient(this)
        val vc = VirtualClient("real@backoff.test", "real backoff account password")
        client.register(vc, bootstrapToken)
        val wrongKey = Bytes.toB64(ByteArray(32) { 9 })

        for (email in listOf("real@backoff.test", "ghost@backoff.test")) {
            repeat(5) { n ->
                val r = client.loginRaw(email, wrongKey, ip = nextIp())
                assertEquals(HttpStatusCode.Unauthorized, r.status, "$email failure ${n + 1} stays a uniform 401")
                assertEquals("invalid_credentials", errorOf(r))
            }
            // 6th attempt from a FRESH IP: blocked by the email lock, not the IP bucket — and the
            // block shape is identical whether the account exists or not.
            val blocked = client.loginRaw(email, wrongKey, ip = nextIp())
            assertEquals(HttpStatusCode.TooManyRequests, blocked.status, "$email must be email-locked after 5 failures")
            assertEquals("rate_limited", errorOf(blocked))
        }

        // The 5th-failure lock is 2^0 = 1 s; a blocked attempt does not extend it.
        Thread.sleep(1200)
        val ok = client.loginRaw(vc.email, vc.authKey, ip = nextIp())
        assertEquals(HttpStatusCode.OK, ok.status, "after the lock lapses the correct password logs in: ${ok.bodyAsText()}")
        // Success RESET the consecutive-failure count: one new failure is a 401, not a re-lock.
        assertEquals(HttpStatusCode.Unauthorized, client.loginRaw(vc.email, wrongKey, ip = nextIp()).status)
        assertEquals(HttpStatusCode.Unauthorized, client.loginRaw(vc.email, wrongKey, ip = nextIp()).status)
    }

    /** §F.8 (review 2026-07-16 D1): recovery verify has NO per-account backoff — only the per-IP 5/min.
     *  A targeted victim (attacker knows their email) must NEVER be locked out of the last-resort recovery
     *  path. Rotating IPs past the per-IP bucket, many wrong verifies at the victim's email stay a uniform
     *  401 — a per-account lockout would 429 here. (The 256-bit recovery secret makes per-IP sufficient.) */
    @Test
    fun recoveryVerify_noPerAccountLockout() = testApplication {
        application { andvariModule(buildServices(tenantConfig(), Notifier())) }
        val client = jsonClient(this)
        val vc = VirtualClient("rec@backoff.test", "recovery backoff password")
        client.register(vc, bootstrapToken)
        val wrongSecret = Bytes.toB64(ByteArray(32) { 4 })
        repeat(12) { n -> // well past login's threshold of 5 — proves no per-account counter exists here
            val r = client.post("/api/v1/recovery/self/verify") {
                contentType(ContentType.Application.Json)
                header("X-Forwarded-For", nextIp()) // fresh IP each time → the per-IP 5/min never trips
                setBody(RecoveryVerifyRequest("rec@backoff.test", wrongSecret))
            }
            assertEquals(HttpStatusCode.Unauthorized, r.status, "wrong recovery verify #${n + 1} must stay 401 — no per-account lockout (§F.8)")
        }
    }

    // ---- §7.2: isPublicOrigin exact-host match + HSTS re-home ----

    @Test
    fun isPublicOrigin_exactHostMatch_craftedHostsStayPrivate() = testApplication {
        val publicHost = "pm.example.com"
        application { andvariModule(buildServices(tenantConfig(publicHostname = publicHost), Notifier())) }
        val client = jsonClient(this)

        // /auth/refresh is the régime probe: public origin → 403 before the body is even read;
        // private origin → 401 invalid_refresh for a garbage token.
        suspend fun refreshVia(host: String): HttpResponse = client.post("/api/v1/auth/refresh") {
            contentType(ContentType.Application.Json)
            header(HttpHeaders.Host, host)
            setBody(RefreshRequest("zz"))
        }
        assertEquals("public_refresh_disabled", errorOf(refreshVia(publicHost).also { assertEquals(HttpStatusCode.Forbidden, it.status) }))
        // :port strips before comparing — the proxied Host may legitimately carry one.
        assertEquals(HttpStatusCode.Forbidden, refreshVia("$publicHost:8443").status)
        // Crafted Hosts that CONTAIN the public hostname must not select the public régime (§7.2).
        assertEquals(HttpStatusCode.Unauthorized, refreshVia("evil-$publicHost").status)
        assertEquals(HttpStatusCode.Unauthorized, refreshVia("$publicHost.evil.com").status)
        // A trailing FQDN root dot must NOT dodge the régime into the private path (review F1).
        assertEquals(HttpStatusCode.Forbidden, refreshVia("$publicHost.").status)

        // HSTS follows the same exact-match authority.
        assertNotNull(client.get("/api/v1/client-policy") { header(HttpHeaders.Host, publicHost) }.headers["Strict-Transport-Security"])
        assertNull(client.get("/api/v1/client-policy") { header(HttpHeaders.Host, "evil-$publicHost") }.headers["Strict-Transport-Security"])
    }

    @Test
    fun hsts_forceHsts_emitsOnEveryOrigin() = testApplication {
        application { andvariModule(buildServices(tenantConfig(forceHsts = true), Notifier())) }
        val client = jsonClient(this)
        val r = client.get("/api/v1/client-policy")
        assertEquals("max-age=31536000; includeSubDomains", r.headers["Strict-Transport-Security"],
            "ANDVARI_FORCE_HSTS=1 must emit HSTS without a public hostname (§7.2 re-home)")
    }

    // ---- §3: canonicalOrigin resolution + validation ----

    @Test
    fun canonicalOrigin_aliasFallback_andSelfHostDocsDefault() {
        fun cfg(canonical: String? = null, invite: String? = null, docs: String? = null, public: String? = null) = Config(
            host = "127.0.0.1", port = 0, dbPath = File(tmpDir, "co.db").absolutePath,
            blobDir = File(tmpDir, "co-blobs").absolutePath, webDir = null,
            recoveryPublicKey = ByteArray(0), recoveryFingerprint = "", enumSecret = ByteArray(32) { 9 },
            publicHostname = public, bootstrapToken = null,
            inviteBaseUrl = invite, canonicalOrigin = canonical, selfHostDocsUrl = docs,
        )

        // New var authoritative; docs URL derives from it.
        val c1 = cfg(canonical = "https://pm.example.com")
        assertEquals("https://pm.example.com", c1.canonicalOrigin)
        assertEquals("https://pm.example.com/selfhost", c1.selfHostDocsUrl)
        assertNull(c1.canonicalOriginIssue())

        // Deprecated alias honored when the new var is absent; explicit values win.
        val c2 = cfg(invite = "https://legacy.example.com")
        assertEquals("https://legacy.example.com", c2.canonicalOrigin)
        assertEquals("https://legacy.example.com/selfhost", c2.selfHostDocsUrl)
        assertEquals("https://new.example.com", cfg(canonical = "https://new.example.com", invite = "https://legacy.example.com").canonicalOrigin)
        assertEquals("https://docs.example.com/guide", cfg(canonical = "https://pm.example.com", docs = "https://docs.example.com/guide").selfHostDocsUrl)

        // Unset ⇒ the fail-safe issue (email invites inert), and no derived docs URL.
        assertNull(cfg().canonicalOrigin)
        assertNull(cfg().selfHostDocsUrl)
        assertTrue(cfg().canonicalOriginIssue()!!.contains("unset"))

        // NEW https rule (§3): http:// is refused for non-local hosts (enroll links are bearer
        // credentials) but allowed for loopback/RFC1918/.local dev parity.
        assertTrue(cfg(canonical = "http://pm.example.com").canonicalOriginIssue()!!.contains("https"), "public http must be refused")
        for (devOk in listOf(
            "http://localhost:8080", "http://127.0.0.1:8080", "http://192.168.7.50:8080",
            "http://10.1.2.3:8080", "http://172.16.0.5:8080", "http://vault.local:8080",
        )) assertNull(cfg(canonical = devOk).canonicalOriginIssue(), "dev/LAN origin must stay allowed: $devOk")
        assertTrue(cfg(canonical = "http://172.15.0.5:8080").canonicalOriginIssue() != null, "172.15/16 is NOT RFC1918")
        // F2: a routable DNS name that merely PREFIX-matches a private range is NOT local → https required.
        for (fakeLocal in listOf("http://10.evil.com", "http://192.168.evil.com", "http://127.evil.com", "http://172.16.evil.com"))
            assertTrue(cfg(canonical = fakeLocal).canonicalOriginIssue()!!.contains("https"), "prefix-not-literal must be refused: $fakeLocal")

        // A5 stays, topology-conditional, with the reworded break-glass message; the default-port
        // and round-trip checks stay too (EmailInviteTest pins the full typo matrix via the alias).
        val a5 = cfg(canonical = "https://pub.example.com", public = "pub.example.com").canonicalOriginIssue()
        assertTrue(a5 != null && "break-glass" in a5, "A5 message must name the break-glass origin: $a5")
        assertNull(cfg(canonical = "https://primary.example.com", public = "pub.example.com").canonicalOriginIssue())
        assertTrue(cfg(canonical = "https://pm.example.com:443").canonicalOriginIssue()!!.contains(":443"))
    }

    // ---- §2.1: env parsing + boot lint ----

    @Test
    fun fromEnv_readsInstanceStance_defaultsAreDeployInert() {
        val secret = Bytes.toB64(ByteArray(32) { 1 })
        fun envOf(vararg pairs: Pair<String, String>): (String) -> String? {
            val m = mapOf("ANDVARI_ENUM_SECRET" to secret, *pairs)
            return { name -> m[name] }
        }

        // Nothing set → today's behavior exactly (the deploy-inert pin).
        val d = Config.fromEnv(envOf())
        assertEquals("invite-only", d.signupMode)
        assertFalse(d.totpRequired)
        assertNull(d.instanceName)
        assertNull(d.canonicalOrigin)
        assertNull(d.selfHostDocsUrl)
        assertTrue(d.offlineCacheAllowedFloor)
        assertFalse(d.forceHsts)
        assertEquals(5, d.loginRatePerMin)

        val c = Config.fromEnv(
            envOf(
                "ANDVARI_SIGNUP_MODE" to "landing",
                "ANDVARI_TOTP_REQUIRED" to "1",
                "ANDVARI_INSTANCE_NAME" to "andvari (reference instance)",
                "ANDVARI_CANONICAL_ORIGIN" to "https://andvari.example.com",
                "ANDVARI_OFFLINE_CACHE_ALLOWED" to "0",
                "ANDVARI_FORCE_HSTS" to "true",
                "ANDVARI_LOGIN_RATE_PER_MIN" to "7",
            ),
        )
        assertEquals("landing", c.signupMode)
        assertTrue(c.totpRequired)
        assertEquals("andvari (reference instance)", c.instanceName)
        assertEquals("https://andvari.example.com", c.canonicalOrigin)
        assertEquals("https://andvari.example.com/selfhost", c.selfHostDocsUrl)
        assertFalse(c.offlineCacheAllowedFloor)
        assertTrue(c.forceHsts)
        assertEquals(7, c.loginRatePerMin)

        // §7.3: `open` boot-coerces to landing (reserved — never silently open an unwired door);
        // unknown values coerce to the conservative default; garbage numerics fall back too.
        assertEquals("landing", Config.fromEnv(envOf("ANDVARI_SIGNUP_MODE" to "open")).signupMode)
        assertEquals("invite-only", Config.fromEnv(envOf("ANDVARI_SIGNUP_MODE" to "frobnicate")).signupMode)
        assertEquals(5, Config.fromEnv(envOf("ANDVARI_LOGIN_RATE_PER_MIN" to "abc")).loginRatePerMin)
        assertEquals(5, Config.fromEnv(envOf("ANDVARI_LOGIN_RATE_PER_MIN" to "0")).loginRatePerMin)

        // Deprecated alias flows through to the resolved origin.
        assertEquals(
            "https://legacy.example.com",
            Config.fromEnv(envOf("ANDVARI_INVITE_BASE_URL" to "https://legacy.example.com")).canonicalOrigin,
        )
    }

    @Test
    fun envLint_flagsUnknownAndInvalid_notesCoercionsAndDeprecation() {
        // Clean env: no problems, no notes.
        val clean = Config.envLint(
            mapOf(
                "ANDVARI_SIGNUP_MODE" to "landing",
                "ANDVARI_CANONICAL_ORIGIN" to "https://pm.example.com",
                "ANDVARI_TOTP_REQUIRED" to "false",
                "PATH" to "/usr/bin", // non-ANDVARI keys are ignored
            ),
        )
        assertTrue(clean.problems.isEmpty(), "clean env must lint clean: ${clean.problems}")
        assertTrue(clean.notes.isEmpty(), clean.notes.toString())

        // Problems (strict boot refuses): unknown var, bad bool, bad enum, bad number, bad origin.
        val bad = Config.envLint(
            mapOf(
                "ANDVARI_SINGUP_MODE" to "landing", // the B2-1 typo class this exists for
                "ANDVARI_TOTP_REQUIRED" to "yes",
                "ANDVARI_SIGNUP_MODE" to "frobnicate",
                "ANDVARI_LOGIN_RATE_PER_MIN" to "many",
                "ANDVARI_CANONICAL_ORIGIN" to "https://pm.example.com:443",
            ),
        )
        assertEquals(5, bad.problems.size, bad.problems.toString())
        assertTrue(bad.problems.any { "ANDVARI_SINGUP_MODE" in it })
        assertTrue(bad.problems.any { "ANDVARI_TOTP_REQUIRED" in it })
        assertTrue(bad.problems.any { "frobnicate" in it })
        assertTrue(bad.problems.any { "ANDVARI_LOGIN_RATE_PER_MIN" in it })
        assertTrue(bad.problems.any { ":443" in it })

        // Notes (warn, never fatal): the reserved `open` coercion + the deprecated alias in use.
        val notes = Config.envLint(
            mapOf(
                "ANDVARI_SIGNUP_MODE" to "open",
                "ANDVARI_INVITE_BASE_URL" to "https://legacy.example.com",
            ),
        )
        assertTrue(notes.problems.isEmpty(), notes.problems.toString())
        assertTrue(notes.notes.any { "open" in it && "landing" in it })
        assertTrue(notes.notes.any { "deprecated" in it })
    }

    // ---- §8.1: /selfhost is a real route, registered before the SPA fallback ----

    @Test
    fun selfhost_servedBeforeSpaFallback_withDownloadableArtifacts() = testApplication {
        val webDir = File(tmpDir, "web-${System.nanoTime()}").apply { mkdirs() }
        File(webDir, "index.html").writeText("<!doctype html><title>SPA-INDEX-SENTINEL</title>")
        application { andvariModule(buildServices(tenantConfig(webDir = webDir.absolutePath), Notifier())) }
        val client = jsonClient(this)

        // The SPA catch-all swallows arbitrary paths…
        assertTrue("SPA-INDEX-SENTINEL" in client.get("/some/random/path").bodyAsText())

        // …but /selfhost is its own page (the B2-4 dead-end this route exists to fix).
        val page = client.get("/selfhost")
        assertEquals(HttpStatusCode.OK, page.status)
        assertTrue(page.headers["Content-Type"]!!.startsWith("text/html"))
        val html = page.bodyAsText()
        assertFalse("SPA-INDEX-SENTINEL" in html, "/selfhost must never fall through to index.html")
        assertTrue("Self-hosting andvari" in html, "the bundled guide renders")
        // The renderer is escape-first: document content can never smuggle live markup.
        assertTrue("&lt;script&gt;" in html)
        assertFalse("<script>alert" in html)

        // The three deploy artifacts download (fixture copies on the test classpath).
        for (name in listOf("docker-compose.yml", "andvari.env.template", "bringup.sh")) {
            val r = client.get("/selfhost/$name")
            assertEquals(HttpStatusCode.OK, r.status, "$name must be downloadable")
            assertTrue("test fixture" in r.bodyAsText(), "$name serves the bundled bytes")
            assertTrue(r.headers["Content-Disposition"]!!.contains(name))
        }
        // Anything off the fixed allowlist is a 404, not a probe surface.
        assertEquals(HttpStatusCode.NotFound, client.get("/selfhost/evil.txt").status)
    }

    @Test
    fun selfhost_registeredEvenWithoutWebDir() = testApplication {
        application { andvariModule(buildServices(tenantConfig(), Notifier())) }
        val client = jsonClient(this)
        val page = client.get("/selfhost")
        assertEquals(HttpStatusCode.OK, page.status, "selfHostDocsUrl must resolve on every instance (§8.1)")
        assertTrue("Self-hosting andvari" in page.bodyAsText())
    }

    /** The markdown renderer is escape-first and scheme-pins links (defense for the bundled page). */
    @Test
    fun selfhostMarkdown_escapesHtml_andPinsLinkSchemes() {
        val html = SelfHost.renderMarkdown(
            """
            # Title
            <img src=x onerror=alert(1)> and [ok](https://example.com) and [bad](javascript:alert(1))

            ```
            <script>in-fence</script>
            ```
            """.trimIndent(),
        )
        assertTrue("<h1>Title</h1>" in html)
        assertTrue("&lt;img src=x onerror=alert(1)&gt;" in html)
        assertTrue("<a href=\"https://example.com\">ok</a>" in html)
        // The javascript: pseudo-link stays inert ESCAPED TEXT — it never becomes an href.
        assertFalse("href=\"javascript:" in html, "non-http(s) schemes must never become hrefs")
        assertTrue("[bad](javascript:alert(1))" in html, "the rejected link renders as plain text")
        assertTrue("&lt;script&gt;in-fence&lt;/script&gt;" in html)
        assertFalse("<script>" in html)
    }
}
