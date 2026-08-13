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
import io.silencelen.andvari.core.crypto.Escrow
import io.silencelen.andvari.core.model.EscrowUpload
import io.silencelen.andvari.core.model.InviteRequest
import io.silencelen.andvari.core.model.InviteResponse
import kotlin.test.Test
import kotlin.test.assertEquals

/**
 * Structural escrow-blob gate (requireEscrowBlob) on BOTH ingestion points: register
 * and PUT /escrow/self. The server can't open the blob (sealed to the OFFLINE recovery
 * key — a cryptographic server-side canary is impossible by design); this pins the
 * garbage filter AND that well-formed blobs from a conforming client still pass,
 * so fielded 0.3.0 clients are unaffected.
 */
class EscrowValidationTest : P4TestSupport() {

    private suspend fun io.ktor.client.HttpClient.escrowSelf(vc: VirtualClient, upload: EscrowUpload) =
        put("/api/v1/escrow/self") {
            contentType(ContentType.Application.Json)
            authed(vc)
            setBody(upload)
        }

    @Test
    fun escrowSelf_acceptsConformingBlob_rejectsGarbage() = testApplication {
        application { andvariModule(buildServices(config(), Notifier())) }
        val client = jsonClient(this)
        val vc = VirtualClient("esc@x.com", "escrow gate password 1")
        client.register(vc, bootstrapToken)

        // A real client re-upload (what a future UVK change would send): passes.
        val valid = EscrowUpload(Bytes.toB64(Escrow.sealUvk(crypto, recovery.publicKey, vc.userId, vc.uvk)), fingerprint)
        assertEquals(HttpStatusCode.OK, client.escrowSelf(vc, valid).status)

        // Not base64url at all.
        val notB64 = client.escrowSelf(vc, EscrowUpload("this is not base64!!!", fingerprint))
        assertEquals(HttpStatusCode.BadRequest, notB64.status)
        assertEquals("bad_escrow_blob", errorOf(notB64))

        // Valid base64url but far below any possible sealed payload (truncated blob).
        val tooShort = client.escrowSelf(vc, EscrowUpload(Bytes.toB64(ByteArray(32)), fingerprint))
        assertEquals(HttpStatusCode.BadRequest, tooShort.status)
        assertEquals("bad_escrow_blob", errorOf(tooShort))

        // Empty string.
        val empty = client.escrowSelf(vc, EscrowUpload("", fingerprint))
        assertEquals(HttpStatusCode.BadRequest, empty.status)

        // Absurdly oversized "blob" — not something Escrow.sealUvk can ever emit.
        val tooBig = client.escrowSelf(vc, EscrowUpload(Bytes.toB64(ByteArray(4096)), fingerprint))
        assertEquals(HttpStatusCode.BadRequest, tooBig.status)
        assertEquals("bad_escrow_blob", errorOf(tooBig))

        // Fingerprint pin still checked first — unchanged ordering.
        val wrongFp = client.escrowSelf(vc, EscrowUpload(valid.sealed, "0".repeat(64)))
        assertEquals(HttpStatusCode.BadRequest, wrongFp.status)
        assertEquals("escrow_fingerprint_mismatch", errorOf(wrongFp))

        // The stored blob is still the valid one (garbage never replaced it): admin fetch + offline open.
        val sealed = client.get("/api/v1/admin/users/${vc.userId}/escrow") { authed(vc) }.bodyAsText()
        val payload = Escrow.open(crypto, recovery.publicKey, recovery.privateKey, Bytes.fromB64(sealed))
        assertEquals(vc.userId, payload.userId)
    }

    @Test
    fun freshEnrollIsNotEscrowStale_andReportsCurrentFingerprint() = testApplication {
        application { andvariModule(buildServices(config(), Notifier())) }
        val client = jsonClient(this)
        val vc = VirtualClient("stale@x.com", "escrow stale password 1")
        val session = client.register(vc, bootstrapToken)
        // F57: a fresh account's escrow is sealed to the CURRENT org recovery key → NOT stale;
        // the client is handed the current fingerprint (escrowFingerprint) so it can detect a
        // future re-ceremony (escrowStale flips true only once the org key rotates) and drive
        // the re-seal-on-unlock prompt.
        assertEquals(false, session.accountKeys.escrowStale, "fresh enroll must not be escrow-stale")
        assertEquals(fingerprint, session.accountKeys.escrowFingerprint)
    }

    @Test
    fun register_rejectsGarbageEscrow_withoutConsumingInvite() = testApplication {
        application { andvariModule(buildServices(config(), Notifier())) }
        val client = jsonClient(this)
        val admin = VirtualClient("adm-esc@x.com", "escrow admin password 1")
        client.register(admin, bootstrapToken)

        val inviteResp = client.post("/api/v1/admin/users") {
            contentType(ContentType.Application.Json)
            authed(admin)
            setBody(InviteRequest("fresh-esc@x.com"))
        }
        assertEquals(HttpStatusCode.OK, inviteResp.status, inviteResp.bodyAsText())
        val invite = json.decodeFromString(InviteResponse.serializer(), inviteResp.bodyAsText())

        val vc = VirtualClient("fresh-esc@x.com", "escrow fresh password 1")
        val good = vc.buildRegister(invite.inviteToken, recovery.publicKey, fingerprint)

        // Same request, escrow blob replaced with junk → clean 400, nothing persisted.
        val garbage = client.post("/api/v1/auth/register") {
            contentType(ContentType.Application.Json)
            header("X-Andvari-Client", "test/1.0.0")
            setBody(good.copy(escrow = EscrowUpload(Bytes.toB64(ByteArray(8)), fingerprint)))
        }
        assertEquals(HttpStatusCode.BadRequest, garbage.status)
        assertEquals("bad_escrow_blob", errorOf(garbage))

        // The invite survived the rejected attempt: the untouched request now succeeds.
        val ok = client.post("/api/v1/auth/register") {
            contentType(ContentType.Application.Json)
            header("X-Andvari-Client", "test/1.0.0")
            setBody(good)
        }
        assertEquals(HttpStatusCode.OK, ok.status, ok.bodyAsText())
    }

    /**
     * F19: the §F.4 escrow-polarity gate is TOTAL across BOTH ingestion points. Register already
     * refused a blob on a `waived` invite; PUT /escrow/self read no user row at all, so the member
     * the design guarantees has NO admin backstop could hand itself an escrow row with one blob
     * carrying the org fingerprint — which /recovery-pubkey serves to anybody. The Admin console
     * then reads "admin backstop" over a users.escrowPolicy still saying `waived`: a coverage lie
     * discovered only when a real recovery ceremony meets an unopenable blob.
     */
    @Test
    fun escrowSelf_waivedAccount_cannotPlantABackstop() = testApplication {
        application { andvariModule(buildServices(config(), Notifier())) }
        val client = jsonClient(this)
        val admin = VirtualClient("adm-waive@x.com", "escrow waive admin 1")
        client.register(admin, bootstrapToken)

        val inviteResp = client.post("/api/v1/admin/users") {
            contentType(ContentType.Application.Json)
            authed(admin)
            setBody(InviteRequest("waived-esc@x.com", escrowPolicy = "waived"))
        }
        assertEquals(HttpStatusCode.OK, inviteResp.status, inviteResp.bodyAsText())
        val invite = json.decodeFromString(InviteResponse.serializer(), inviteResp.bodyAsText())

        // Enroll under the waived invite (escrow omitted — the only shape register accepts there).
        val waived = VirtualClient("waived-esc@x.com", "escrow waive member 1")
        val registerResp = client.post("/api/v1/auth/register") {
            contentType(ContentType.Application.Json)
            header("X-Andvari-Client", "test/1.0.0")
            setBody(waived.buildRegister(invite.inviteToken, recovery.publicKey, fingerprint, includeEscrow = false))
        }
        assertEquals(HttpStatusCode.OK, registerResp.status, registerResp.bodyAsText())
        val session = json.decodeFromString(
            io.silencelen.andvari.core.model.SessionResponse.serializer(),
            registerResp.bodyAsText(),
        )
        waived.userId = session.userId; waived.accessToken = session.accessToken

        // A perfectly-formed blob sealed to the REAL org key, with the REAL public fingerprint —
        // everything the old route checked — is refused on the persisted posture alone.
        val real = EscrowUpload(Bytes.toB64(Escrow.sealUvk(crypto, recovery.publicKey, waived.userId, waived.uvk)), fingerprint)
        val refused = client.escrowSelf(waived, real)
        assertEquals(HttpStatusCode.BadRequest, refused.status, refused.bodyAsText())
        assertEquals("escrow_not_allowed_when_waived", errorOf(refused))

        // Nothing was persisted: the admin fetch still finds no backstop for this member.
        assertEquals(
            HttpStatusCode.NotFound,
            client.get("/api/v1/admin/users/${waived.userId}/escrow") { authed(admin) }.status,
            "a waived account must have no escrow row after the refused upload",
        )

        // The gate is polarity-only: a `required` account (the admin itself) still uploads.
        assertEquals(HttpStatusCode.OK, client.escrowSelf(admin, EscrowUpload(Bytes.toB64(Escrow.sealUvk(crypto, recovery.publicKey, admin.userId, admin.uvk)), fingerprint)).status)
    }

    /**
     * F19 (second leg): with NO org recovery key, config.recoveryFingerprint is "" — so a body
     * carrying an empty fingerprint passed the compare and the route happily stored escrow rows
     * nothing can ever open. This was the one escrow path without an escrowConfigured guard; it now
     * answers the same 503 escrow_not_configured the pubkey route does. Reached the way a real
     * instance reaches it: members enroll under a configured instance, THEN the operator drops the
     * key from the env (register itself refuses on an unconfigured instance, so this is the only
     * way an account and an unconfigured server ever coexist).
     */
    @Test
    fun escrowSelf_keyDroppedFromEnv_refusesEmptyFingerprintBlobs() {
        val configured = config()
        val vc = VirtualClient("esc-unconf@x.com", "escrow unconfigured pw 1")
        testApplication {
            application { andvariModule(buildServices(configured, Notifier())) }
            jsonClient(this).register(vc, bootstrapToken)
        }
        testApplication {
            application { andvariModule(buildServices(config(escrowConfigured = false, dbPath = configured.dbPath), Notifier())) }
            val client = jsonClient(this)
            val resp = client.escrowSelf(vc, EscrowUpload(Bytes.toB64(Escrow.sealUvk(crypto, recovery.publicKey, vc.userId, vc.uvk)), ""))
            assertEquals(HttpStatusCode.ServiceUnavailable, resp.status, resp.bodyAsText())
            assertEquals("escrow_not_configured", errorOf(resp))
        }
    }

    /**
     * bug-server--9: on an instance with no org recovery key, /recovery-pubkey answered a BARE
     * STRING body with its 503. Every consumer decodes ApiError, so the named cause was lost —
     * core's errorFrom fell back to "http_503" and the web enroll helper substituted a generic
     * code of its own, leaving a self-hoster with an opaque failure mid-enrollment. The success
     * body stays bare base64: only the failure joins the taxonomy.
     */
    @Test
    fun recoveryPubkey_unconfiguredInstance_answersTheHouseApiError() = testApplication {
        application { andvariModule(buildServices(config(escrowConfigured = false), Notifier())) }
        val client = jsonClient(this)

        val resp = client.get("/api/v1/recovery-pubkey")
        assertEquals(HttpStatusCode.ServiceUnavailable, resp.status)
        assertEquals("escrow_not_configured", errorOf(resp))
    }

    @Test
    fun recoveryPubkey_configuredInstance_stillServesBareBase64() = testApplication {
        application { andvariModule(buildServices(config(), Notifier())) }
        val client = jsonClient(this)

        val resp = client.get("/api/v1/recovery-pubkey")
        assertEquals(HttpStatusCode.OK, resp.status)
        assertEquals(Bytes.toB64(recovery.publicKey), resp.bodyAsText().trim())
    }
}
