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
}
