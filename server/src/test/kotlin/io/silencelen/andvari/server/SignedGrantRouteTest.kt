package io.silencelen.andvari.server

import io.ktor.client.HttpClient
import io.ktor.client.request.get
import io.ktor.client.request.post
import io.ktor.client.request.put
import io.ktor.client.request.setBody
import io.ktor.client.statement.HttpResponse
import io.ktor.client.statement.bodyAsText
import io.ktor.http.ContentType
import io.ktor.http.HttpStatusCode
import io.ktor.http.contentType
import io.ktor.server.testing.testApplication
import io.silencelen.andvari.core.crypto.Bytes
import io.silencelen.andvari.core.model.CreateVaultRequest
import io.silencelen.andvari.core.model.GrantReissueRequest
import io.silencelen.andvari.core.model.InviteRequest
import io.silencelen.andvari.core.model.InviteResponse
import io.silencelen.andvari.core.model.SelfWrapRequest
import io.silencelen.andvari.core.model.VaultMemberAdd
import io.silencelen.andvari.core.model.VaultMemberSummary
import kotlinx.serialization.builtins.ListSerializer
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNull
import kotlin.test.assertTrue

/**
 * Grant v2 on the wire (security review 2026-10, root cause A §1.5, §8.2 step 4, branch A6). The server stores
 * the opaque `signedGrant` beside the dual-sent v1 `sealedVk` and delivers both; it cannot open or check either.
 * What it enforces: the owner alone re-issues a member's grant (`PUT /vaults/{id}/members/{userId}/grant`), only
 * onto an active non-owner grant, size-capped and audited; and `GET /members` carries the `legacyGrant` HINT
 * (no v2 grant and no self-wrap on the row) so the owner's client knows whom to re-issue to.
 */
class SignedGrantRouteTest : P4TestSupport() {

    private suspend fun HttpClient.createVault(vc: VirtualClient, req: CreateVaultRequest): HttpResponse =
        post("/api/v1/vaults") { authed(vc); contentType(ContentType.Application.Json); setBody(req) }

    private suspend fun HttpClient.enrollSecond(admin: VirtualClient, email: String, pw: String): VirtualClient {
        val inv = post("/api/v1/admin/users") {
            authed(admin); contentType(ContentType.Application.Json); setBody(InviteRequest(email, isAdmin = false))
        }
        assertEquals(HttpStatusCode.OK, inv.status, inv.bodyAsText())
        val vc = VirtualClient(email, pw, fast = true)
        register(vc, json.decodeFromString(InviteResponse.serializer(), inv.bodyAsText()).inviteToken)
        return vc
    }

    private suspend fun HttpClient.add(owner: VirtualClient, vaultId: String, req: VaultMemberAdd): HttpResponse =
        post("/api/v1/vaults/$vaultId/members") { authed(owner); contentType(ContentType.Application.Json); setBody(req) }

    private suspend fun HttpClient.reissue(vc: VirtualClient, vaultId: String, userId: String, signedGrant: String): HttpResponse =
        put("/api/v1/vaults/$vaultId/members/$userId/grant") { authed(vc); contentType(ContentType.Application.Json); setBody(GrantReissueRequest(signedGrant)) }

    private suspend fun HttpClient.members(vc: VirtualClient, vaultId: String): List<VaultMemberSummary> =
        json.decodeFromString(ListSerializer(VaultMemberSummary.serializer()), get("/api/v1/vaults/$vaultId/members") { authed(vc) }.bodyAsText())

    // Opaque stand-ins: the server never opens a grant, so any well-formed base64url works.
    private val v2a = Bytes.toB64(ByteArray(420) { 2 })
    private val v2b = Bytes.toB64(ByteArray(420) { 3 })

    @Test
    fun theV2GrantRidesBesideTheV1SealAndOnlyTheOwnerReissues() = testApplication {
        application { andvariModule(buildServices(config(), Notifier())) }
        val client = jsonClient(this)
        val owner = VirtualClient("sg-owner@x.com", "signed grant owner password one", fast = true)
        client.register(owner, bootstrapToken)
        val bob = client.enrollSecond(owner, "sg-bob@x.com", "signed grant bob password two")
        val carol = client.enrollSecond(owner, "sg-carol@x.com", "signed grant carol password three")
        val (createReq, handle) = owner.buildCreateSharedVault()
        assertEquals(HttpStatusCode.Created, client.createVault(owner, createReq).status)

        // Bob: an N owner dual-sends. Carol: an N-1 owner client sends v1 only (still accepted in-window).
        val bobSeal = owner.sealVkFor(bob.identityPub, handle.vaultId, handle.vk)
        assertEquals(HttpStatusCode.Created, client.add(owner, handle.vaultId, VaultMemberAdd(bob.userId, "writer", bobSeal, v2a)).status)
        val carolSeal = owner.sealVkFor(carol.identityPub, handle.vaultId, handle.vk)
        assertEquals(HttpStatusCode.Created, client.add(owner, handle.vaultId, VaultMemberAdd(carol.userId, "reader", carolSeal)).status)

        val bobRow = client.sync(bob).grants.single { it.vaultId == handle.vaultId }
        assertEquals(v2a, bobRow.signedGrant)
        assertEquals(bobSeal, bobRow.sealedVk, "dual-sent in-window")
        assertNull(client.sync(carol).grants.single { it.vaultId == handle.vaultId }.signedGrant)

        // The legacyGrant hint: carol has neither a v2 grant nor a self-wrap; bob has a v2 grant; the owner never.
        val hints = client.members(owner, handle.vaultId).associate { it.userId to it.legacyGrant }
        assertEquals(true, hints[carol.userId])
        assertEquals(false, hints[bob.userId])
        assertEquals(false, hints[owner.userId])

        // Re-issue: only the owner, only onto an active non-owner grant, size-capped.
        assertEquals(HttpStatusCode.Forbidden, client.reissue(bob, handle.vaultId, carol.userId, v2b).status)
        assertEquals(HttpStatusCode.BadRequest, client.reissue(owner, handle.vaultId, owner.userId, v2b).status)
        assertEquals(HttpStatusCode.BadRequest, client.reissue(owner, handle.vaultId, carol.userId, Bytes.toB64(ByteArray(3000) { 1 })).status)
        assertEquals(HttpStatusCode.BadRequest, client.reissue(owner, handle.vaultId, carol.userId, "!!").status)
        val before = client.sync(carol)
        val ok = client.reissue(owner, handle.vaultId, carol.userId, v2b)
        assertEquals(HttpStatusCode.OK, ok.status, ok.bodyAsText())
        val carolRow = client.sync(carol, before.rev).grants.single { it.vaultId == handle.vaultId }
        assertEquals(v2b, carolRow.signedGrant, "re-delivered to the member by a grant rev bump")
        assertEquals(carolSeal, carolRow.sealedVk, "the v1 seal is kept")
        assertEquals("reader", carolRow.role, "a re-issue never changes the role")
        assertEquals(false, client.members(owner, handle.vaultId).single { it.userId == carol.userId }.legacyGrant)
        assertTrue(client.auditRows(owner, "vault_grant_reissue").any { it.userId == owner.userId })

        // A self-wrap also clears the hint (the member's devices no longer need any grant).
        val dave = client.enrollSecond(owner, "sg-dave@x.com", "signed grant dave password four")
        client.add(owner, handle.vaultId, VaultMemberAdd(dave.userId, "writer", owner.sealVkFor(dave.identityPub, handle.vaultId, handle.vk)))
        assertEquals(true, client.members(owner, handle.vaultId).single { it.userId == dave.userId }.legacyGrant)
        val sw = client.put("/api/v1/vaults/${handle.vaultId}/grant/self-wrap") {
            authed(dave); contentType(ContentType.Application.Json); setBody(SelfWrapRequest(dave.wrapVkUnderOwnUvk(handle.vaultId, handle.vk)))
        }
        assertEquals(HttpStatusCode.OK, sw.status)
        assertEquals(false, client.members(owner, handle.vaultId).single { it.userId == dave.userId }.legacyGrant)

        // An oversized or malformed signedGrant on add is refused before any row is written.
        val erin = client.enrollSecond(owner, "sg-erin@x.com", "signed grant erin password five")
        val erinSeal = owner.sealVkFor(erin.identityPub, handle.vaultId, handle.vk)
        assertEquals(HttpStatusCode.BadRequest, client.add(owner, handle.vaultId, VaultMemberAdd(erin.userId, "writer", erinSeal, Bytes.toB64(ByteArray(3000) { 1 }))).status)
        assertTrue(client.members(owner, handle.vaultId).none { it.userId == erin.userId })
    }
}
