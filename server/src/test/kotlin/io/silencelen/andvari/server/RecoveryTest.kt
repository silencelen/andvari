package io.silencelen.andvari.server

import io.ktor.client.HttpClient
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
import io.ktor.server.testing.testApplication
import io.silencelen.andvari.core.crypto.Bytes
import io.silencelen.andvari.core.crypto.KdfParams
import io.silencelen.andvari.core.model.AccountKeys
import io.silencelen.andvari.core.model.AdminUserSummary
import io.silencelen.andvari.core.model.DeviceInfo
import io.silencelen.andvari.core.model.InviteRequest
import io.silencelen.andvari.core.model.InviteResponse
import io.silencelen.andvari.core.model.LoginRequest
import io.silencelen.andvari.core.model.PreloginRequest
import io.silencelen.andvari.core.model.PreloginResponse
import io.silencelen.andvari.core.model.RecoveryCommitRequest
import io.silencelen.andvari.core.model.RecoverySelfConfirmRequest
import io.silencelen.andvari.core.model.RecoverySelfSetupRequest
import io.silencelen.andvari.core.model.RecoverySelfSetupResponse
import io.silencelen.andvari.core.model.RecoveryVerifyRequest
import io.silencelen.andvari.core.model.RecoveryUpload
import io.silencelen.andvari.core.model.RecoveryVerifyResponse
import io.silencelen.andvari.core.model.RegisterRequest
import io.silencelen.andvari.core.model.SessionResponse
import kotlinx.serialization.builtins.ListSerializer
import java.io.File
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue

/**
 * Per-member self-service recovery + escrow opt-out (design 2026-07-12 §F). Exercises the §F.4
 * register truth-table, the §F.3 two-phase verify→commit protocol, §F.5 anti-enumeration, the
 * dedicated-reset guards (non-active refusal, KDF floor, session revocation, NO active/mustChange
 * flip), the authenticated self-setup reauth (§F.3.3 / §F.2 migration nudge), the public-origin
 * refusal, and single-use ticket replay — same house style as the other server integration tests.
 * Also the confirm piece-binding contract (design 2026-07-13): R1 bound / R2 unbound-device-scoped /
 * R3 no-row, reset-on-rotate (leg ii), the register-returned recoveryPieceId, the setup route's JSON
 * response, the empty/malformed confirm-body parse rule, and the v8 escrowPolicy reconciliation.
 */
class RecoveryTest : P4TestSupport() {

    private val publicHost = "public.test"

    /** A floored server (production KDF floor) to exercise the commit-path requireKdfFloor gate. */
    private fun flooredConfig() = Config(
        host = "127.0.0.1", port = 0,
        dbPath = File(tmpDir, "rec-floor-${System.nanoTime()}.db").absolutePath,
        blobDir = File(tmpDir, "blobs-${System.nanoTime()}").absolutePath, webDir = null,
        recoveryPublicKey = recovery.publicKey, recoveryFingerprint = fingerprint,
        enumSecret = ByteArray(32) { 7 }, publicHostname = null, bootstrapToken = bootstrapToken,
        minKdfMemBytes = 64L * 1024 * 1024, minKdfOps = 3,
    )

    private suspend fun HttpClient.createInvite(admin: VirtualClient, email: String, escrowPolicy: String = "required"): String {
        val resp = post("/api/v1/admin/users") {
            contentType(ContentType.Application.Json); authed(admin)
            setBody(InviteRequest(email, escrowPolicy = escrowPolicy))
        }
        assertEquals(HttpStatusCode.OK, resp.status, resp.bodyAsText())
        return json.decodeFromString(InviteResponse.serializer(), resp.bodyAsText()).inviteToken
    }

    private suspend fun HttpClient.rawRegister(req: RegisterRequest, host: String? = null): HttpResponse =
        post("/api/v1/auth/register") {
            contentType(ContentType.Application.Json); header("X-Andvari-Client", "test/1.0.0")
            if (host != null) header(HttpHeaders.Host, host)
            setBody(req)
        }

    private suspend fun HttpClient.verify(email: String, recoveryAuthKey: String, host: String? = null): HttpResponse =
        post("/api/v1/recovery/self/verify") {
            contentType(ContentType.Application.Json); header("X-Andvari-Client", "test/1.0.0")
            if (host != null) header(HttpHeaders.Host, host)
            setBody(RecoveryVerifyRequest(email, recoveryAuthKey))
        }

    private suspend fun HttpClient.commit(body: RecoveryCommitRequest, host: String? = null): HttpResponse =
        post("/api/v1/recovery/self/commit") {
            contentType(ContentType.Application.Json); header("X-Andvari-Client", "test/1.0.0")
            if (host != null) header(HttpHeaders.Host, host)
            setBody(body)
        }

    private suspend fun HttpClient.accountKeys(vc: VirtualClient): AccountKeys {
        val resp = get("/api/v1/account/keys") { authed(vc) }
        assertEquals(HttpStatusCode.OK, resp.status, resp.bodyAsText())
        return json.decodeFromString(AccountKeys.serializer(), resp.bodyAsText())
    }

    /** §F.9 capture-confirmation POST. [pieceId] = null posts NO body and NO content-type — the exact
     *  fielded 0.15/0.16 wire shape (R2, device-scoped); non-null posts the bound
     *  RecoverySelfConfirmRequest (R1). [accessToken] selects the confirming DEVICE (defaults to the
     *  register session). A session suffices — no key material moves. */
    private suspend fun HttpClient.confirm(
        vc: VirtualClient,
        pieceId: String? = null,
        accessToken: String = vc.accessToken,
        host: String? = null,
    ): HttpResponse =
        post("/api/v1/recovery/self/confirm") {
            authed(accessToken)
            if (host != null) header(HttpHeaders.Host, host)
            if (pieceId != null) { contentType(ContentType.Application.Json); setBody(RecoverySelfConfirmRequest(pieceId)) }
        }

    /** PUT /recovery/self-setup (fresh piece + currentAuthKey reauth) → the parsed JSON response.
     *  [accessToken] selects the committing DEVICE — the server stamps it as the row's setupDeviceId. */
    private suspend fun HttpClient.selfSetup(vc: VirtualClient, accessToken: String = vc.accessToken): RecoverySelfSetupResponse {
        val resp = put("/api/v1/recovery/self-setup") {
            contentType(ContentType.Application.Json); authed(accessToken)
            setBody(vc.buildRecoverySelfSetup())
        }
        assertEquals(HttpStatusCode.OK, resp.status, resp.bodyAsText())
        return json.decodeFromString(RecoverySelfSetupResponse.serializer(), resp.bodyAsText())
    }

    /** A full fresh-device login (prelogin → derive authKey → login) → the SessionResponse. */
    private suspend fun HttpClient.freshLogin(vc: VirtualClient): SessionResponse {
        val pre = json.decodeFromString(
            PreloginResponse.serializer(),
            post("/api/v1/auth/prelogin") { contentType(ContentType.Application.Json); setBody(PreloginRequest(vc.email)) }.bodyAsText(),
        )
        val resp = post("/api/v1/auth/login") {
            contentType(ContentType.Application.Json); header("X-Andvari-Client", "test/1.0.0")
            setBody(LoginRequest(vc.email, vc.authKeyWith(pre.kdfSalt, pre.kdfParams), DeviceInfo("test", "relogin")))
        }
        assertEquals(HttpStatusCode.OK, resp.status, resp.bodyAsText())
        return json.decodeFromString(SessionResponse.serializer(), resp.bodyAsText())
    }

    // ---- §F.4 register truth-table: required / waived / neither ----
    @Test
    fun registerGate_required_waived_neither() = testApplication {
        application { andvariModule(buildServices(config(), Notifier())) }
        val client = jsonClient(this)
        val admin = VirtualClient("adm-gate@x.com", "admin gate password one")
        client.register(admin, bootstrapToken) // required + escrow + memberRecovery → 200 (bootstrap)

        // required invite, escrow + memberRecovery present → 200
        val reqTok = client.createInvite(admin, "req@x.com")
        val reqVc = VirtualClient("req@x.com", "req password one")
        assertEquals(HttpStatusCode.OK, client.rawRegister(reqVc.buildRegister(reqTok, recovery.publicKey, fingerprint)).status)

        // required invite, escrow OMITTED → escrow_required
        val reqTok2 = client.createInvite(admin, "req2@x.com")
        val reqVc2 = VirtualClient("req2@x.com", "req2 password one")
        val noEscrow = client.rawRegister(reqVc2.buildRegister(reqTok2, recovery.publicKey, fingerprint, includeEscrow = false))
        assertEquals(HttpStatusCode.BadRequest, noEscrow.status)
        assertEquals("escrow_required", errorOf(noEscrow))

        // waived invite, escrow OMITTED → 200 (member has only the self-service piece)
        val wTok = client.createInvite(admin, "waived@x.com", escrowPolicy = "waived")
        val wVc = VirtualClient("waived@x.com", "waived password one")
        assertEquals(HttpStatusCode.OK, client.rawRegister(wVc.buildRegister(wTok, recovery.publicKey, fingerprint, includeEscrow = false)).status)

        // waived invite, escrow PRESENT → escrow_not_allowed_when_waived
        val wTok2 = client.createInvite(admin, "waived2@x.com", escrowPolicy = "waived")
        val wVc2 = VirtualClient("waived2@x.com", "waived2 password one")
        val waivedEscrow = client.rawRegister(wVc2.buildRegister(wTok2, recovery.publicKey, fingerprint, includeEscrow = true))
        assertEquals(HttpStatusCode.BadRequest, waivedEscrow.status)
        assertEquals("escrow_not_allowed_when_waived", errorOf(waivedEscrow))

        // neither: memberRecovery OMITTED → recovery_required, regardless of escrow posture
        val nTok = client.createInvite(admin, "none@x.com")
        val nVc = VirtualClient("none@x.com", "none password one")
        val noRec = client.rawRegister(nVc.buildRegister(nTok, recovery.publicKey, fingerprint, includeMemberRecovery = false))
        assertEquals(HttpStatusCode.BadRequest, noRec.status)
        assertEquals("recovery_required", errorOf(noRec))

        // …even on a waived invite (the mandatory-recovery check precedes the escrow polarity gate)
        val nwTok = client.createInvite(admin, "nonewaived@x.com", escrowPolicy = "waived")
        val nwVc = VirtualClient("nonewaived@x.com", "none waived password one")
        val noRecW = client.rawRegister(nwVc.buildRegister(nwTok, recovery.publicKey, fingerprint, includeEscrow = false, includeMemberRecovery = false))
        assertEquals(HttpStatusCode.BadRequest, noRecW.status)
        assertEquals("recovery_required", errorOf(noRecW))
    }

    // ---- §F.3 two-phase verify→commit happy path + session revocation + no mustChange + ticket single-use ----
    @Test
    fun recovery_verifyCommit_resetsPassword_revokesSessions_ticketSingleUse() = testApplication {
        application { andvariModule(buildServices(config(), Notifier())) }
        val client = jsonClient(this)
        val admin = VirtualClient("adm-flow@x.com", "admin flow password one")
        client.register(admin, bootstrapToken)
        val tok = client.createInvite(admin, "flow@x.com")
        val vc = VirtualClient("flow@x.com", "original flow password one")
        client.register(vc, tok) // has a live session + a member_recovery row

        // phase 1: verify with the recovery secret's auth half
        val vresp = client.verify(vc.email, vc.recoveryAuthKey)
        assertEquals(HttpStatusCode.OK, vresp.status, vresp.bodyAsText())
        val verify = json.decodeFromString(RecoveryVerifyResponse.serializer(), vresp.bodyAsText())
        assertEquals(vc.userId, verify.userId, "response MUST carry userId (needed for Ad.recovery / Ad.idkey)")
        assertEquals(Bytes.toB64(vc.identityPub), verify.identityPub, "identityPub feeds the pubkey hard-fail")

        // phase 2: commit a brand-new password (client opened the SAME UVK and re-wrapped it)
        val commit = vc.buildRecoveryCommit(verify, "brand new flow password two")
        assertEquals(HttpStatusCode.OK, client.commit(commit).status)

        // the register-time session was revoked by the reset
        assertEquals(HttpStatusCode.Unauthorized, client.get("/api/v1/account/keys") { authed(vc) }.status)

        // login with the NEW password succeeds, and mustChangePassword is FALSE (the user chose it)
        val newClient = VirtualClient(vc.email, "brand new flow password two")
        val preResp = client.post("/api/v1/auth/prelogin") {
            contentType(ContentType.Application.Json); setBody(PreloginRequest(vc.email))
        }
        val pre = json.decodeFromString(PreloginResponse.serializer(), preResp.bodyAsText())
        val newAuthKey = newClient.authKeyWith(pre.kdfSalt, pre.kdfParams)
        val login = client.post("/api/v1/auth/login") {
            contentType(ContentType.Application.Json); header("X-Andvari-Client", "test/1.0.0")
            setBody(LoginRequest(vc.email, newAuthKey, DeviceInfo("test", "post-recovery")))
        }
        assertEquals(HttpStatusCode.OK, login.status, login.bodyAsText())
        assertFalse(json.decodeFromString(SessionResponse.serializer(), login.bodyAsText()).mustChangePassword)

        // the OLD password no longer authenticates
        val oldAuthKey = vc.authKeyWith(pre.kdfSalt, pre.kdfParams)
        val oldLogin = client.post("/api/v1/auth/login") {
            contentType(ContentType.Application.Json); header("X-Andvari-Client", "test/1.0.0")
            setBody(LoginRequest(vc.email, oldAuthKey, DeviceInfo("test", "old")))
        }
        assertEquals(HttpStatusCode.Unauthorized, oldLogin.status)

        // single-use ticket: replaying the consumed ticket is rejected
        val replay = client.commit(vc.buildRecoveryCommit(verify, "yet another password three"))
        assertEquals(HttpStatusCode.Unauthorized, replay.status)
        assertEquals("invalid_ticket", errorOf(replay))
    }

    // ---- §F.5 anti-enumeration: unknown email / known-no-row / wrong-key are all a uniform 401 ----
    @Test
    fun recovery_verify_antiEnum_uniform401() = testApplication {
        val services = buildServices(config(), Notifier())
        application { andvariModule(services) }
        val client = jsonClient(this)
        val admin = VirtualClient("adm-enum@x.com", "admin enum password one")
        client.register(admin, bootstrapToken) // admin has a member_recovery row

        val randomAuthKey = Bytes.toB64(crypto.randomBytes(32))

        // (1) unknown email → 401
        val unknown = client.verify("nobody@x.com", randomAuthKey)
        // (2) known email, WRONG recovery auth key → 401
        val wrongKey = client.verify(admin.email, randomAuthKey)
        // (3) known email, NO member_recovery row (delete it to simulate a legacy/pre-migration account) → 401
        services.repo.db.tx { c -> c.exec("DELETE FROM member_recovery WHERE userId=?", admin.userId) }
        val noRow = client.verify(admin.email, admin.recoveryAuthKey) // even the CORRECT key can't match a missing row

        assertEquals(HttpStatusCode.Unauthorized, unknown.status)
        assertEquals(HttpStatusCode.Unauthorized, wrongKey.status)
        assertEquals(HttpStatusCode.Unauthorized, noRow.status)
        // shape-uniform: identical error body across all three states
        assertEquals(errorOf(unknown), errorOf(wrongKey))
        assertEquals(errorOf(unknown), errorOf(noRow))
    }

    // ---- commit refuses a non-active account (recovery_account_not_active); does NOT reactivate it ----
    @Test
    fun recovery_commit_refusesDisabledAccount() = testApplication {
        val services = buildServices(config(), Notifier())
        application { andvariModule(services) }
        val client = jsonClient(this)
        val admin = VirtualClient("adm-dis@x.com", "admin disable password one")
        client.register(admin, bootstrapToken)
        val tok = client.createInvite(admin, "victim@x.com")
        val vc = VirtualClient("victim@x.com", "victim password one")
        client.register(vc, tok)

        // mint a ticket while still active…
        val verify = json.decodeFromString(RecoveryVerifyResponse.serializer(), client.verify(vc.email, vc.recoveryAuthKey).bodyAsText())
        // …then the admin disables the account (TOCTOU belt)…
        services.admin.disableUser(vc.userId, admin.userId)
        // …so the commit is refused, and NEVER silently reactivates the account.
        val commit = client.commit(vc.buildRecoveryCommit(verify, "attempted new password two"))
        assertEquals(HttpStatusCode.BadRequest, commit.status)
        assertEquals("recovery_account_not_active", errorOf(commit))
        // still disabled: even the ORIGINAL password can't log in
        val pre = json.decodeFromString(
            PreloginResponse.serializer(),
            client.post("/api/v1/auth/prelogin") { contentType(ContentType.Application.Json); setBody(PreloginRequest(vc.email)) }.bodyAsText(),
        )
        val login = client.post("/api/v1/auth/login") {
            contentType(ContentType.Application.Json); header("X-Andvari-Client", "test/1.0.0")
            setBody(LoginRequest(vc.email, vc.authKeyWith(pre.kdfSalt, pre.kdfParams), DeviceInfo("test", "x")))
        }
        assertEquals(HttpStatusCode.Unauthorized, login.status)
    }

    // ---- commit enforces the KDF floor on the NEW params (spec 01 §9 / §F.3.2) ----
    @Test
    fun recovery_commit_enforcesKdfFloor() = testApplication {
        application { andvariModule(buildServices(flooredConfig(), Notifier())) }
        val client = jsonClient(this)
        // strong params clear the production floor at register…
        val vc = VirtualClient("floor@x.com", "floor password one", fast = false)
        client.register(vc, bootstrapToken)
        val verify = json.decodeFromString(RecoveryVerifyResponse.serializer(), client.verify(vc.email, vc.recoveryAuthKey).bodyAsText())
        // …but a commit that downgrades below the floor is refused.
        val weak = vc.buildRecoveryCommit(verify, "floor password two").copy(newKdfParams = KdfParams(ops = 1, memBytes = 8 * 1024 * 1024))
        val resp = client.commit(weak)
        assertEquals(HttpStatusCode.BadRequest, resp.status)
        assertEquals("kdf_too_weak", errorOf(resp))
    }

    // ---- L1: admin recovery enforces the SAME KDF floor as register/change/self-commit (spec 05 T1/T8) ----
    @Test
    fun adminRecovery_enforcesKdfFloor() = testApplication {
        application { andvariModule(buildServices(flooredConfig(), Notifier())) }
        val client = jsonClient(this)
        val admin = VirtualClient("adm-rec@x.com", "admin recovery password one", fast = false)
        client.register(admin, bootstrapToken)

        suspend fun postRecovery(p: KdfParams): HttpResponse = client.post("/api/v1/admin/recovery") {
            contentType(ContentType.Application.Json); authed(admin)
            setBody(RecoveryUpload(admin.userId, "AA", "AA", "AA", p))
        }

        // A sub-floor bundle is refused BEFORE the user lookup / verifier write — the floor is line 1
        // of applyRecovery, closing the one password-set path that previously skipped it.
        val weak = postRecovery(KdfParams(ops = 1, memBytes = 8 * 1024 * 1024))
        assertEquals(HttpStatusCode.BadRequest, weak.status)
        assertEquals("kdf_too_weak", errorOf(weak))

        // recovery-cli's real output is KdfParams.DEFAULT (at-floor) — it clears the inclusive floor.
        val ok = postRecovery(KdfParams.DEFAULT)
        assertEquals(HttpStatusCode.OK, ok.status, ok.bodyAsText())
    }

    // ---- §F.3.3 self-setup: requires a fresh currentAuthKey reauth; clears the migration nudge ----
    @Test
    fun recovery_selfSetup_requiresReauth_andClearsSetupNeeded() = testApplication {
        val services = buildServices(config(), Notifier())
        application { andvariModule(services) }
        val client = jsonClient(this)
        val admin = VirtualClient("adm-setup@x.com", "admin setup password one")
        client.register(admin, bootstrapToken)
        val tok = client.createInvite(admin, "migrant@x.com")
        val vc = VirtualClient("migrant@x.com", "migrant password one")
        client.register(vc, tok)

        // simulate a legacy account (no member_recovery row) → the migration nudge fires
        services.repo.db.tx { c -> c.exec("DELETE FROM member_recovery WHERE userId=?", vc.userId) }
        assertTrue(client.accountKeys(vc).recoverySetupNeeded, "no row ⇒ recoverySetupNeeded=true")

        // wrong currentAuthKey → 401 (a quick-unlock session without the password is refused here)
        val bad = client.put("/api/v1/recovery/self-setup") {
            contentType(ContentType.Application.Json); authed(vc)
            setBody(RecoverySelfSetupRequest(Bytes.toB64(crypto.randomBytes(32)), vc.buildMemberRecovery()))
        }
        assertEquals(HttpStatusCode.Unauthorized, bad.status)

        // correct currentAuthKey → 200, and the nudge clears
        val ok = client.put("/api/v1/recovery/self-setup") {
            contentType(ContentType.Application.Json); authed(vc)
            setBody(vc.buildRecoverySelfSetup())
        }
        assertEquals(HttpStatusCode.OK, ok.status, ok.bodyAsText())
        assertFalse(client.accountKeys(vc).recoverySetupNeeded, "after self-setup ⇒ recoverySetupNeeded=false")

        // and the freshly-set piece actually works end-to-end (verify succeeds)
        assertEquals(HttpStatusCode.OK, client.verify(vc.email, vc.recoveryAuthKey).status)
    }

    // ---- all three recovery endpoints refuse the public break-glass origin ----
    @Test
    fun recovery_publicOrigin_refusedOnAllThree() = testApplication {
        application { andvariModule(buildServices(config(publicHostname = publicHost), Notifier())) }
        val client = jsonClient(this)
        val admin = VirtualClient("adm-pub@x.com", "admin public password one")
        client.register(admin, bootstrapToken)
        val tok = client.createInvite(admin, "pub@x.com")
        val vc = VirtualClient("pub@x.com", "pub password one")
        client.register(vc, tok)
        // The enrolled piece — captured now because buildRecoverySelfSetup() below regenerates it.
        val recoveryAuthKey = vc.recoveryAuthKey

        val v = client.verify(vc.email, recoveryAuthKey, host = publicHost)
        assertEquals(HttpStatusCode.Forbidden, v.status)
        assertEquals("recovery_public_disabled", errorOf(v))

        val c = client.commit(RecoveryCommitRequest("ticket", "a", "s", KdfParams(), "w"), host = publicHost)
        assertEquals(HttpStatusCode.Forbidden, c.status)
        assertEquals("recovery_public_disabled", errorOf(c))

        val s = client.put("/api/v1/recovery/self-setup") {
            contentType(ContentType.Application.Json); header(HttpHeaders.Host, publicHost); authed(vc)
            setBody(vc.buildRecoverySelfSetup())
        }
        assertEquals(HttpStatusCode.Forbidden, s.status)
        assertEquals("recovery_public_disabled", errorOf(s))

        // the internal origin still works (control) — verify with the ORIGINAL enrolled piece succeeds
        assertEquals(HttpStatusCode.OK, client.verify(vc.email, recoveryAuthKey).status)
    }

    // ---- §F.9 capture confirmation: register leaves recoveryConfirmed=false on BOTH surfaces ----
    @Test
    fun register_leavesRecoveryConfirmedFalse() = testApplication {
        application { andvariModule(buildServices(config(), Notifier())) }
        val client = jsonClient(this)
        val admin = VirtualClient("adm-conf@x.com", "admin confirm password one")
        // the register RESPONSE's bundled accountKeys reads back false (capture not yet confirmed)…
        assertFalse(client.register(admin, bootstrapToken).accountKeys.recoveryConfirmed)
        val tok = client.createInvite(admin, "conf@x.com")
        val vc = VirtualClient("conf@x.com", "conf password one")
        assertFalse(client.register(vc, tok).accountKeys.recoveryConfirmed)
        // …and so does a subsequent GET /account/keys (the sole builder, so the two can't drift).
        assertFalse(client.accountKeys(vc).recoveryConfirmed)
    }

    // ---- §F.9: AccountKeys.recoveryConfirmed is false for a fresh account AND a migration (no-row) one ----
    @Test
    fun accountKeys_recoveryConfirmed_falseForFreshAndMigration() = testApplication {
        val services = buildServices(config(), Notifier())
        application { andvariModule(services) }
        val client = jsonClient(this)
        val admin = VirtualClient("adm-mig@x.com", "admin migration password one")
        client.register(admin, bootstrapToken)
        val tok = client.createInvite(admin, "mig@x.com")
        val vc = VirtualClient("mig@x.com", "mig password one")
        client.register(vc, tok)

        // fresh account: has a member_recovery row but capture unconfirmed → confirmed=false, setup NOT needed
        val fresh = client.accountKeys(vc)
        assertFalse(fresh.recoveryConfirmed, "fresh register ⇒ recoveryConfirmed=false")
        assertFalse(fresh.recoverySetupNeeded, "fresh register HAS a member_recovery row ⇒ setup not needed")

        // simulate a legacy/migration account (no member_recovery row): still confirmed=false, nudge fires
        services.repo.db.tx { c -> c.exec("DELETE FROM member_recovery WHERE userId=?", vc.userId) }
        val migration = client.accountKeys(vc)
        assertFalse(migration.recoveryConfirmed, "migration account ⇒ recoveryConfirmed=false")
        assertTrue(migration.recoverySetupNeeded, "no row ⇒ recoverySetupNeeded=true (informational nudge)")
    }

    // ---- §F.9: POST /recovery/self/confirm flips the durable flag, reflected on next keys AND login ----
    @Test
    fun recovery_selfConfirm_setsConfirmed_reflectedOnKeysAndLogin() = testApplication {
        application { andvariModule(buildServices(config(), Notifier())) }
        val client = jsonClient(this)
        val admin = VirtualClient("adm-set@x.com", "admin setflag password one")
        client.register(admin, bootstrapToken)
        val tok = client.createInvite(admin, "set@x.com")
        val vc = VirtualClient("set@x.com", "set password one")
        client.register(vc, tok)
        assertFalse(client.accountKeys(vc).recoveryConfirmed, "precondition: unconfirmed")

        // confirm (authenticated, no body — the fielded wire shape; rides R2 device-scoped acceptance,
        // and this IS the register session whose register stamped setupDeviceId) → 200 "ok"
        val resp = client.confirm(vc)
        assertEquals(HttpStatusCode.OK, resp.status, resp.bodyAsText())
        assertEquals("ok", resp.bodyAsText())

        // reflected on GET /account/keys…
        assertTrue(client.accountKeys(vc).recoveryConfirmed, "after confirm ⇒ recoveryConfirmed=true on keys")
        // …and cross-device: a brand-new login's bundled accountKeys carries it too (durable, server-side)
        assertTrue(client.freshLogin(vc).accountKeys.recoveryConfirmed, "after confirm ⇒ true on a fresh login")
        // idempotent: a second confirm is still 200
        assertEquals(HttpStatusCode.OK, client.confirm(vc).status)
    }

    // ---- §F.9: /recovery/self/confirm refuses the public break-glass origin (like the other recovery routes) ----
    @Test
    fun recovery_selfConfirm_refusedOnPublicOrigin() = testApplication {
        application { andvariModule(buildServices(config(publicHostname = publicHost), Notifier())) }
        val client = jsonClient(this)
        val admin = VirtualClient("adm-cpub@x.com", "admin confirm public password one")
        client.register(admin, bootstrapToken)
        val tok = client.createInvite(admin, "cpub@x.com")
        val vc = VirtualClient("cpub@x.com", "cpub password one")
        client.register(vc, tok)

        val pub = client.confirm(vc, host = publicHost)
        assertEquals(HttpStatusCode.Forbidden, pub.status)
        assertEquals("recovery_public_disabled", errorOf(pub))
        // the flag was NOT set (refused before the handler ran); the internal origin still works (control)
        assertFalse(client.accountKeys(vc).recoveryConfirmed)
        assertEquals(HttpStatusCode.OK, client.confirm(vc).status)
        assertTrue(client.accountKeys(vc).recoveryConfirmed)
    }

    // ---- §F.9 (round-3): self-setup COMMITS/rotates the piece but MUST NOT confirm capture — the block-path
    //      gate calls it on mount, before the type-back, so confirming here would mark an interrupted reveal
    //      "captured". recoveryConfirmed is flipped ONLY by /recovery/self/confirm after the demonstrated type-back.
    @Test
    fun recovery_selfSetup_commits_butDoesNotConfirm() = testApplication {
        val services = buildServices(config(), Notifier())
        application { andvariModule(services) }
        val client = jsonClient(this)
        val admin = VirtualClient("adm-ssc@x.com", "admin selfsetup confirm password one")
        client.register(admin, bootstrapToken)
        val tok = client.createInvite(admin, "ssc@x.com")
        val vc = VirtualClient("ssc@x.com", "ssc password one")
        client.register(vc, tok)
        // fresh register: piece committed but capture unconfirmed
        assertFalse(client.accountKeys(vc).recoveryConfirmed)

        // an authenticated self-setup (fresh currentAuthKey) commits/rotates the piece …
        val ok = client.put("/api/v1/recovery/self-setup") {
            contentType(ContentType.Application.Json); authed(vc)
            setBody(vc.buildRecoverySelfSetup())
        }
        assertEquals(HttpStatusCode.OK, ok.status, ok.bodyAsText())
        val afterSetup = client.accountKeys(vc)
        // … but MUST NOT flip recoveryConfirmed (the revealed phrase has not been captured yet) …
        assertFalse(afterSetup.recoveryConfirmed, "self-setup commits the row but must NOT confirm capture")
        assertFalse(afterSetup.recoverySetupNeeded, "self-setup (re)wrote the row ⇒ setup not needed")
        // … only the explicit type-back confirm flips it.
        assertEquals(HttpStatusCode.OK, client.confirm(vc).status)
        assertTrue(client.accountKeys(vc).recoveryConfirmed, "confirm after capture ⇒ recoveryConfirmed=true")

        // Piece-binding leg (ii), reset-on-rotate (design 2026-07-13 §2.1): a LATER setup rotates the
        // piece, so it must also CLEAR the previously-true flag — the confirmation attested a phrase the
        // rotation just killed, and the flag always describes the CURRENT piece.
        client.selfSetup(vc)
        assertFalse(client.accountKeys(vc).recoveryConfirmed, "setup rotates the piece ⇒ clears recoveryConfirmed")
    }

    // ---- design 2026-07-13 piece binding: R1 bound confirm attests the CURRENT piece ----
    @Test
    fun recovery_confirm_bound_setsConfirmed() = testApplication {
        application { andvariModule(buildServices(config(), Notifier())) }
        val client = jsonClient(this)
        val admin = VirtualClient("adm-b1@x.com", "admin bound one password")
        client.register(admin, bootstrapToken)
        val tok = client.createInvite(admin, "b1@x.com")
        val vc = VirtualClient("b1@x.com", "b1 password one")
        client.register(vc, tok)

        val pieceId = assertNotNull(client.selfSetup(vc).pieceId)
        val resp = client.confirm(vc, pieceId)
        assertEquals(HttpStatusCode.OK, resp.status, resp.bodyAsText())
        assertTrue(client.accountKeys(vc).recoveryConfirmed, "bound confirm of the current piece ⇒ flag flips")
    }

    // ---- THE repro (design 2026-07-13 §0 ordering 1): two devices interleave setup/confirm — the
    //      loser's confirm must NEVER attest the winner's (uncaptured-by-the-loser) piece ----
    @Test
    fun recovery_twoDevice_interleaving_confirmNeverAttestsOtherPiece() = testApplication {
        application { andvariModule(buildServices(config(), Notifier())) }
        val client = jsonClient(this)
        val admin = VirtualClient("adm-2d@x.com", "admin two device password")
        client.register(admin, bootstrapToken)
        val tok = client.createInvite(admin, "2d@x.com")
        val vc = VirtualClient("2d@x.com", "2d password one")
        client.register(vc, tok)

        // device A = the register session; device B = a second device (fresh full login)
        val deviceA = vc.accessToken
        val deviceB = client.freshLogin(vc).accessToken
        val idA = assertNotNull(client.selfSetup(vc, accessToken = deviceA).pieceId)
        val idB = assertNotNull(client.selfSetup(vc, accessToken = deviceB).pieceId) // rotates A's piece away

        // A type-backs the phrase IT revealed — but the server row is now B's piece: refused, flag untouched
        val stale = client.confirm(vc, idA, accessToken = deviceA)
        assertEquals(HttpStatusCode.Conflict, stale.status, stale.bodyAsText())
        assertEquals("recovery_piece_stale", errorOf(stale))
        assertFalse(client.accountKeys(vc).recoveryConfirmed, "a confirm must never attest a rotated-away piece")

        // B's confirm names the CURRENT piece: accepted
        assertEquals(HttpStatusCode.OK, client.confirm(vc, idB, accessToken = deviceB).status)
        assertTrue(client.accountKeys(vc).recoveryConfirmed)
    }

    // ---- same-device rotation: a bound confirm of the SUPERSEDED id is stale, of the current one accepted ----
    @Test
    fun recovery_confirm_staleAfterRotation_409() = testApplication {
        application { andvariModule(buildServices(config(), Notifier())) }
        val client = jsonClient(this)
        val admin = VirtualClient("adm-rot@x.com", "admin rotation password one")
        client.register(admin, bootstrapToken)
        val tok = client.createInvite(admin, "rot@x.com")
        val vc = VirtualClient("rot@x.com", "rot password one")
        client.register(vc, tok)

        val id1 = assertNotNull(client.selfSetup(vc).pieceId)
        val id2 = assertNotNull(client.selfSetup(vc).pieceId) // same device — still rotates id1 away
        val stale = client.confirm(vc, id1)
        assertEquals(HttpStatusCode.Conflict, stale.status, stale.bodyAsText())
        assertEquals("recovery_piece_stale", errorOf(stale))
        assertFalse(client.accountKeys(vc).recoveryConfirmed)
        assertEquals(HttpStatusCode.OK, client.confirm(vc, id2).status)
        assertTrue(client.accountKeys(vc).recoveryConfirmed)
    }

    // ---- leg (ii) reset-on-rotate: a setup after a confirm drops the flag back to false, durably ----
    @Test
    fun recovery_setup_rotation_clearsConfirmed() = testApplication {
        application { andvariModule(buildServices(config(), Notifier())) }
        val client = jsonClient(this)
        val admin = VirtualClient("adm-clr@x.com", "admin clear password one")
        client.register(admin, bootstrapToken)
        val tok = client.createInvite(admin, "clr@x.com")
        val vc = VirtualClient("clr@x.com", "clr password one")
        client.register(vc, tok)

        val id1 = assertNotNull(client.selfSetup(vc).pieceId)
        assertEquals(HttpStatusCode.OK, client.confirm(vc, id1).status)
        assertTrue(client.accountKeys(vc).recoveryConfirmed, "precondition: confirmed")

        client.selfSetup(vc) // rotation ⇒ the confirmed phrase is dead ⇒ flag must drop
        assertFalse(client.accountKeys(vc).recoveryConfirmed, "rotation clears recoveryConfirmed on keys")
        assertFalse(client.freshLogin(vc).accountKeys.recoveryConfirmed, "…and on a brand-new login (durable)")
    }

    // ---- R2: a body-less (fielded-native) confirm from the device whose setup committed the row is accepted ----
    @Test
    fun recovery_confirm_unbound_sameDevice_accepted() = testApplication {
        application { andvariModule(buildServices(config(), Notifier())) }
        val client = jsonClient(this)
        val admin = VirtualClient("adm-ub@x.com", "admin unbound password one")
        client.register(admin, bootstrapToken)
        val tok = client.createInvite(admin, "ub@x.com")
        val vc = VirtualClient("ub@x.com", "ub password one")
        client.register(vc, tok)

        client.selfSetup(vc) // the register session's device commits (and stamps) the current row
        val resp = client.confirm(vc) // body-less from that SAME device
        assertEquals(HttpStatusCode.OK, resp.status, resp.bodyAsText())
        assertTrue(client.accountKeys(vc).recoveryConfirmed)
        // audited as the legacy acceptance — distinct from the bound recovery_self_confirm type
        val rows = client.auditRows(admin, "recovery_self_confirm_unbound")
        assertTrue(rows.any { it.userId == vc.userId }, "unbound acceptance must audit recovery_self_confirm_unbound")
    }

    // ---- R2 rejection: after a FOREIGN device rotated the piece, a body-less confirm is stale ----
    @Test
    fun recovery_confirm_unbound_afterForeignRotation_409() = testApplication {
        application { andvariModule(buildServices(config(), Notifier())) }
        val client = jsonClient(this)
        val admin = VirtualClient("adm-fr@x.com", "admin foreign password one")
        client.register(admin, bootstrapToken)
        val tok = client.createInvite(admin, "fr@x.com")
        val vc = VirtualClient("fr@x.com", "fr password one")
        client.register(vc, tok)

        val deviceB = client.freshLogin(vc).accessToken
        client.selfSetup(vc) // device A commits…
        client.selfSetup(vc, accessToken = deviceB) // …then device B rotates (foreign to A)

        val stale = client.confirm(vc) // body-less as A: the current row is B's
        assertEquals(HttpStatusCode.Conflict, stale.status, stale.bodyAsText())
        assertEquals("recovery_piece_stale", errorOf(stale))
        val staleRows = client.auditRows(admin, "recovery_self_confirm_stale")
        assertTrue(staleRows.any { it.userId == vc.userId && it.meta == "unbound" }, "rejected legacy confirm audits meta=unbound")

        assertEquals(HttpStatusCode.OK, client.confirm(vc, accessToken = deviceB).status) // body-less as B: same-device
        assertTrue(client.accountKeys(vc).recoveryConfirmed)
    }

    // ---- migration compat: a pre-v8 row (both columns NULL, no backfill) accepts a body-less confirm ----
    @Test
    fun recovery_confirm_unbound_preV8Row_accepted() = testApplication {
        val services = buildServices(config(), Notifier())
        application { andvariModule(services) }
        val client = jsonClient(this)
        val admin = VirtualClient("adm-v7@x.com", "admin prev8 password one")
        client.register(admin, bootstrapToken)
        val tok = client.createInvite(admin, "v7@x.com")
        val vc = VirtualClient("v7@x.com", "v7 password one")
        client.register(vc, tok)

        // simulate a row the v8 migration inherited: no pieceId, no setupDeviceId
        services.repo.db.tx { c -> c.exec("UPDATE member_recovery SET pieceId=NULL, setupDeviceId=NULL WHERE userId=?", vc.userId) }
        // NULL setupDeviceId accepts ANY device (a pre-v8 piece predates the columns) — use a second
        // device to prove the acceptance is the NULL arm, not the same-device arm.
        val deviceB = client.freshLogin(vc).accessToken
        val resp = client.confirm(vc, accessToken = deviceB)
        assertEquals(HttpStatusCode.OK, resp.status, resp.bodyAsText())
        assertTrue(client.accountKeys(vc).recoveryConfirmed)
    }

    // ---- a BOUND confirm can never match a NULL-id (pre-v8) row ----
    @Test
    fun recovery_confirm_boundAgainstPreV8Row_409() = testApplication {
        val services = buildServices(config(), Notifier())
        application { andvariModule(services) }
        val client = jsonClient(this)
        val admin = VirtualClient("adm-bn@x.com", "admin boundnull password one")
        client.register(admin, bootstrapToken)
        val tok = client.createInvite(admin, "bn@x.com")
        val vc = VirtualClient("bn@x.com", "bn password one")
        client.register(vc, tok)

        services.repo.db.tx { c -> c.exec("UPDATE member_recovery SET pieceId=NULL, setupDeviceId=NULL WHERE userId=?", vc.userId) }
        val resp = client.confirm(vc, "any-claimed-piece-id")
        assertEquals(HttpStatusCode.Conflict, resp.status, resp.bodyAsText())
        assertEquals("recovery_piece_stale", errorOf(resp))
        assertFalse(client.accountKeys(vc).recoveryConfirmed, "a bound confirm never matches a NULL-id row")
    }

    // ---- §2.3: register returns the committed piece's id; the enroll path's bound confirm accepts it ----
    @Test
    fun recovery_register_returnsPieceId_boundEnrollConfirm() = testApplication {
        application { andvariModule(buildServices(config(), Notifier())) }
        val client = jsonClient(this)
        val admin = VirtualClient("adm-rp@x.com", "admin regpiece password one")
        client.register(admin, bootstrapToken)
        val tok = client.createInvite(admin, "rp@x.com")
        val vc = VirtualClient("rp@x.com", "rp password one")

        val session = client.register(vc, tok)
        val pieceId = assertNotNull(session.recoveryPieceId, "register response must carry the committed piece's id")
        // §1.3: ONLY register populates it — a login leaves it null
        assertNull(client.freshLogin(vc).recoveryPieceId, "login must NOT hand out the current piece's id")
        // the enroll happy-path: bound confirm with the register-returned id, from the register session
        assertEquals(HttpStatusCode.OK, client.confirm(vc, pieceId).status)
        assertTrue(client.accountKeys(vc).recoveryConfirmed)
    }

    // ---- §1.4: the exact fielded wire shape (POST, no body, no content-type) parses as pieceId=null ----
    @Test
    fun recovery_confirm_emptyBody_noContentType_parses() = testApplication {
        application { andvariModule(buildServices(config(), Notifier())) }
        val client = jsonClient(this)
        val admin = VirtualClient("adm-eb@x.com", "admin emptybody password one")
        client.register(admin, bootstrapToken)
        val tok = client.createInvite(admin, "eb@x.com")
        val vc = VirtualClient("eb@x.com", "eb password one")
        client.register(vc, tok)

        val resp = client.confirm(vc) // the helper posts NO body and NO content-type
        assertEquals(HttpStatusCode.OK, resp.status, resp.bodyAsText()) // not 400/500 — legacy shape must keep working
        assertEquals("ok", resp.bodyAsText(), "confirm response body unchanged for fielded clients")
    }

    // ---- §1.4: a non-blank garbage body is 400 bad_request and must not touch the flag ----
    @Test
    fun recovery_confirm_malformedBody_400() = testApplication {
        application { andvariModule(buildServices(config(), Notifier())) }
        val client = jsonClient(this)
        val admin = VirtualClient("adm-mb@x.com", "admin malformed password one")
        client.register(admin, bootstrapToken)
        val tok = client.createInvite(admin, "mb@x.com")
        val vc = VirtualClient("mb@x.com", "mb password one")
        client.register(vc, tok)

        val resp = client.post("/api/v1/recovery/self/confirm") {
            authed(vc); contentType(ContentType.Application.Json); setBody("{not json")
        }
        assertEquals(HttpStatusCode.BadRequest, resp.status, resp.bodyAsText())
        assertEquals("bad_request", errorOf(resp))
        assertFalse(client.accountKeys(vc).recoveryConfirmed, "a malformed body must not touch the flag")
    }

    // ---- §2.1: the setup route's JSON response carries the id the next bound confirm accepts ----
    @Test
    fun recovery_selfSetup_responseCarriesPieceId() = testApplication {
        application { andvariModule(buildServices(config(), Notifier())) }
        val client = jsonClient(this)
        val admin = VirtualClient("adm-sr@x.com", "admin setupresp password one")
        client.register(admin, bootstrapToken)
        val tok = client.createInvite(admin, "sr@x.com")
        val vc = VirtualClient("sr@x.com", "sr password one")
        client.register(vc, tok)

        val setup = client.selfSetup(vc)
        val pieceId = assertNotNull(setup.pieceId, "setup response must carry the fresh pieceId (was the text \"ok\")")
        assertEquals(HttpStatusCode.OK, client.confirm(vc, pieceId).status, "the returned id is exactly what the next bound confirm accepts")
        assertTrue(client.accountKeys(vc).recoveryConfirmed)
    }

    // ---- R3: an account whose member_recovery row is gone gets a clean 409, never a 500 ----
    @Test
    fun recovery_confirm_noRow_409() = testApplication {
        val services = buildServices(config(), Notifier())
        application { andvariModule(services) }
        val client = jsonClient(this)
        val admin = VirtualClient("adm-nr@x.com", "admin norow password one")
        client.register(admin, bootstrapToken)
        val tok = client.createInvite(admin, "nr@x.com")
        val vc = VirtualClient("nr@x.com", "nr password one")
        client.register(vc, tok)

        services.repo.db.tx { c -> c.exec("DELETE FROM member_recovery WHERE userId=?", vc.userId) }
        val resp = client.confirm(vc)
        assertEquals(HttpStatusCode.Conflict, resp.status, "no row ⇒ 409, never a 500")
        assertEquals("recovery_piece_stale", errorOf(resp))
        assertFalse(client.accountKeys(vc).recoveryConfirmed)
    }

    // ---- §F.4 (v8): AdminUserSummary.escrowPolicy reconciliation — the persisted invite posture ----
    @Test
    fun adminUsers_escrowPolicy_reflectsInvitePosture() = testApplication {
        val services = buildServices(config(), Notifier())
        application { andvariModule(services) }
        val client = jsonClient(this)
        val admin = VirtualClient("adm-pol@x.com", "admin policy password one")
        client.register(admin, bootstrapToken) // the bootstrap invite row defaults to 'required'

        val reqTok = client.createInvite(admin, "polreq@x.com") // InviteRequest defaults to "required"
        val reqVc = VirtualClient("polreq@x.com", "polreq password one")
        client.register(reqVc, reqTok)

        val wTok = client.createInvite(admin, "polwaived@x.com", escrowPolicy = "waived")
        val wVc = VirtualClient("polwaived@x.com", "polwaived password one")
        assertEquals(HttpStatusCode.OK, client.rawRegister(wVc.buildRegister(wTok, recovery.publicKey, fingerprint, includeEscrow = false)).status)

        // simulate a pre-v8 account: the column is NULL (no backfill) → posture unknown/legacy
        services.repo.db.tx { c -> c.exec("UPDATE users SET escrowPolicy=NULL WHERE userId=?", admin.userId) }

        val resp = client.get("/api/v1/admin/users") { authed(admin) }
        assertEquals(HttpStatusCode.OK, resp.status, resp.bodyAsText())
        val users = json.decodeFromString(ListSerializer(AdminUserSummary.serializer()), resp.bodyAsText())
        assertEquals("required", users.first { it.email == "polreq@x.com" }.escrowPolicy, "required invite ⇒ persisted posture 'required'")
        assertEquals("waived", users.first { it.email == "polwaived@x.com" }.escrowPolicy, "waived invite ⇒ persisted posture 'waived'")
        assertNull(users.first { it.email == admin.email }.escrowPolicy, "pre-v8 user (no backfill) ⇒ null posture")
    }
}
