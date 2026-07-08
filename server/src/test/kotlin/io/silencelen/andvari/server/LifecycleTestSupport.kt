package io.silencelen.andvari.server

import io.ktor.client.HttpClient
import io.ktor.client.request.delete
import io.ktor.client.request.get
import io.ktor.client.request.post
import io.ktor.client.request.put
import io.ktor.client.request.setBody
import io.ktor.client.statement.HttpResponse
import io.ktor.client.statement.bodyAsText
import io.ktor.http.ContentType
import io.ktor.http.HttpStatusCode
import io.ktor.http.contentType
import io.silencelen.andvari.core.crypto.Bytes
import io.silencelen.andvari.core.model.CreateVaultRequest
import io.silencelen.andvari.core.model.DeletedVaultSummary
import io.silencelen.andvari.core.model.InviteRequest
import io.silencelen.andvari.core.model.InviteResponse
import io.silencelen.andvari.core.model.TransferAcceptRequest
import io.silencelen.andvari.core.model.TransferOfferRequest
import io.silencelen.andvari.core.model.UserLookupRequest
import io.silencelen.andvari.core.model.UserLookupResponse
import io.silencelen.andvari.core.model.VaultDeleteRequest
import io.silencelen.andvari.core.model.VaultMemberAdd
import io.silencelen.andvari.core.model.VaultMemberRemoveRequest
import io.silencelen.andvari.core.model.VaultMetaUpdateRequest
import io.silencelen.andvari.core.model.VaultRestoreRequest
import kotlinx.serialization.builtins.ListSerializer
import kotlin.test.assertEquals

/**
 * Shared scaffolding for the vault-lifecycle (spec 03 §11 "Skipti") server tests —
 * HTTP helpers for every §10/§11 route so the op tests, the concurrency matrix, and
 * the mixed-fleet narrative all drive the same wire shapes a real client would.
 */
abstract class LifecycleTestSupport : P4TestSupport() {

    // ---- §10 sharing routes ----

    protected suspend fun HttpClient.createVault(vc: VirtualClient, req: CreateVaultRequest): HttpResponse =
        post("/api/v1/vaults") { authed(vc); contentType(ContentType.Application.Json); setBody(req) }

    /** Admin invites + enrolls a second, non-admin user against the running server. */
    protected suspend fun HttpClient.enrollSecond(admin: VirtualClient, email: String, pw: String): VirtualClient {
        val inv = post("/api/v1/admin/users") {
            authed(admin); contentType(ContentType.Application.Json); setBody(InviteRequest(email, isAdmin = false))
        }
        assertEquals(HttpStatusCode.OK, inv.status, inv.bodyAsText())
        val token = json.decodeFromString(InviteResponse.serializer(), inv.bodyAsText()).inviteToken
        val vc = VirtualClient(email, pw, fast = true)
        register(vc, token)
        return vc
    }

    /** lookup → seal VK to the member identity → POST members (the real add flow). */
    protected suspend fun HttpClient.addMember(
        owner: VirtualClient,
        handle: VirtualClient.SharedVaultHandle,
        member: VirtualClient,
        role: String,
    ): HttpResponse {
        val lr = post("/api/v1/users/lookup") {
            authed(owner); contentType(ContentType.Application.Json); setBody(UserLookupRequest(member.email))
        }
        assertEquals(HttpStatusCode.OK, lr.status, lr.bodyAsText())
        val info = json.decodeFromString(UserLookupResponse.serializer(), lr.bodyAsText())
        val sealed = owner.sealVkFor(Bytes.fromB64(info.identityPub), handle.vaultId, handle.vk)
        return post("/api/v1/vaults/${handle.vaultId}/members") {
            authed(owner); contentType(ContentType.Application.Json); setBody(VaultMemberAdd(member.userId, role, sealed))
        }
    }

    /** Member opens its sealed grant from a fresh sync → the shared VK. */
    protected suspend fun HttpClient.openMemberVk(member: VirtualClient, vaultId: String): ByteArray {
        val grant = sync(member).grants.single { it.vaultId == vaultId }
        return member.openSharedGrant(vaultId, grant.sealedVk!!)
    }

    protected suspend fun HttpClient.removeMember(
        vc: VirtualClient,
        vaultId: String,
        userId: String,
        body: VaultMemberRemoveRequest? = null,
    ): HttpResponse = delete("/api/v1/vaults/$vaultId/members/$userId") {
        authed(vc)
        if (body != null) { contentType(ContentType.Application.Json); setBody(body) }
    }

    // ---- §11 lifecycle routes ----

    protected suspend fun HttpClient.vaultDelete(vc: VirtualClient, vaultId: String, deleteId: String, proof: String): HttpResponse =
        post("/api/v1/vaults/$vaultId/delete") {
            authed(vc); contentType(ContentType.Application.Json); setBody(VaultDeleteRequest(deleteId, proof))
        }

    protected suspend fun HttpClient.vaultRestore(vc: VirtualClient, vaultId: String, deleteId: String, proof: String): HttpResponse =
        post("/api/v1/vaults/$vaultId/restore") {
            authed(vc); contentType(ContentType.Application.Json); setBody(VaultRestoreRequest(deleteId, proof))
        }

    protected suspend fun HttpClient.deletedVaults(vc: VirtualClient): List<DeletedVaultSummary> {
        val resp = get("/api/v1/vaults/deleted") { authed(vc) }
        assertEquals(HttpStatusCode.OK, resp.status, resp.bodyAsText())
        return json.decodeFromString(ListSerializer(DeletedVaultSummary.serializer()), resp.bodyAsText())
    }

    protected suspend fun HttpClient.vaultLeave(vc: VirtualClient, vaultId: String): HttpResponse =
        post("/api/v1/vaults/$vaultId/leave") { authed(vc) }

    protected suspend fun HttpClient.transferOffer(vc: VirtualClient, vaultId: String, req: TransferOfferRequest): HttpResponse =
        post("/api/v1/vaults/$vaultId/transfer") {
            authed(vc); contentType(ContentType.Application.Json); setBody(req)
        }

    protected suspend fun HttpClient.transferCancel(vc: VirtualClient, vaultId: String): HttpResponse =
        delete("/api/v1/vaults/$vaultId/transfer") { authed(vc) }

    protected suspend fun HttpClient.transferAccept(vc: VirtualClient, vaultId: String, req: TransferAcceptRequest): HttpResponse =
        post("/api/v1/vaults/$vaultId/transfer/accept") {
            authed(vc); contentType(ContentType.Application.Json); setBody(req)
        }

    protected suspend fun HttpClient.putVaultMeta(vc: VirtualClient, vaultId: String, req: VaultMetaUpdateRequest): HttpResponse =
        put("/api/v1/vaults/$vaultId/meta") {
            authed(vc); contentType(ContentType.Application.Json); setBody(req)
        }

    /** Owner mints deleteId + delete proof (the real 0.5.0 client flow) and deletes. */
    protected suspend fun HttpClient.deleteWithProof(
        owner: VirtualClient,
        handle: VirtualClient.SharedVaultHandle,
        deleteId: String = uuid(),
    ): Pair<String, String> {
        val proof = owner.mintDeleteProof(handle.vaultId, handle.vk, deleteId)
        val resp = vaultDelete(owner, handle.vaultId, deleteId, proof)
        assertEquals(HttpStatusCode.OK, resp.status, resp.bodyAsText())
        return deleteId to proof
    }

    /** Full offer flow: mint proof for seq = transferSeq+1 and POST it. */
    protected suspend fun HttpClient.offerWithProof(
        owner: VirtualClient,
        handle: VirtualClient.SharedVaultHandle,
        target: VirtualClient,
        seq: Long,
        offerId: String = uuid(),
        expiresAt: Long = now() + 14 * Service.DAY_MS,
    ): Triple<String, Long, HttpResponse> {
        val proof = owner.mintOfferProof(handle.vaultId, handle.vk, offerId, target.userId, expiresAt, seq)
        val resp = transferOffer(owner, handle.vaultId, TransferOfferRequest(target.userId, offerId, expiresAt, proof))
        return Triple(offerId, expiresAt, resp)
    }
}
