package io.silencelen.andvari.server

import io.ktor.client.HttpClient
import io.ktor.client.request.delete
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
import io.silencelen.andvari.core.model.InviteRequest
import io.silencelen.andvari.core.model.InviteResponse
import io.silencelen.andvari.core.model.SelfWrapRequest
import io.silencelen.andvari.core.model.UserLookupRequest
import io.silencelen.andvari.core.model.UserLookupResponse
import io.silencelen.andvari.core.model.VaultMemberAdd
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue

/**
 * `PUT /api/v1/vaults/{id}/grant/self-wrap` (security review 2026-10, root cause A §3.2): a member
 * stores `Envelope(UVK, VK, Ad.vk(vaultId, userId))` on its OWN active grant so every device of
 * that member reads the VK from the UVK wrap instead of the server-mintable seal. The server cannot
 * check the wrap (it is ciphertext under a key it never sees); what it enforces is WHO may write
 * WHICH row: the caller's own active non-owner grant only, ≤ 1 KiB, audited, and the write is
 * re-delivered to the caller's devices by a grant rev bump.
 */
class GrantSelfWrapTest : P4TestSupport() {

    private suspend fun HttpClient.createVault(vc: VirtualClient, req: CreateVaultRequest): HttpResponse =
        post("/api/v1/vaults") { authed(vc); contentType(ContentType.Application.Json); setBody(req) }

    private suspend fun HttpClient.selfWrap(vc: VirtualClient, vaultId: String, wrappedVk: String): HttpResponse =
        put("/api/v1/vaults/$vaultId/grant/self-wrap") { authed(vc); contentType(ContentType.Application.Json); setBody(SelfWrapRequest(wrappedVk)) }

    private suspend fun HttpClient.enrollSecond(admin: VirtualClient, email: String, pw: String): VirtualClient {
        val inv = post("/api/v1/admin/users") {
            authed(admin); contentType(ContentType.Application.Json); setBody(InviteRequest(email, isAdmin = false))
        }
        assertEquals(HttpStatusCode.OK, inv.status, inv.bodyAsText())
        val vc = VirtualClient(email, pw, fast = true)
        register(vc, json.decodeFromString(InviteResponse.serializer(), inv.bodyAsText()).inviteToken)
        return vc
    }

    private suspend fun HttpClient.addMember(owner: VirtualClient, vaultId: String, vk: ByteArray, member: VirtualClient, email: String) {
        val info = json.decodeFromString(
            UserLookupResponse.serializer(),
            post("/api/v1/users/lookup") { authed(owner); contentType(ContentType.Application.Json); setBody(UserLookupRequest(email)) }.bodyAsText(),
        )
        val sealed = owner.sealVkFor(Bytes.fromB64(info.identityPub), vaultId, vk)
        val resp = post("/api/v1/vaults/$vaultId/members") {
            authed(owner); contentType(ContentType.Application.Json); setBody(VaultMemberAdd(member.userId, "writer", sealed))
        }
        assertEquals(HttpStatusCode.Created, resp.status, resp.bodyAsText())
    }

    @Test
    fun aMemberStoresItsOwnWrapAndEveryDeviceReceivesIt() = testApplication {
        application { andvariModule(buildServices(config(), Notifier())) }
        val client = jsonClient(this)
        val owner = VirtualClient("sw-owner@x.com", "self wrap owner password one", fast = true)
        client.register(owner, bootstrapToken)
        val bob = client.enrollSecond(owner, "sw-bob@x.com", "self wrap bob password two")
        val (createReq, handle) = owner.buildCreateSharedVault()
        assertEquals(HttpStatusCode.Created, client.createVault(owner, createReq).status)
        client.addMember(owner, handle.vaultId, handle.vk, bob, "sw-bob@x.com")

        val before = client.sync(bob)
        val sealedRow = before.grants.single { it.vaultId == handle.vaultId }
        val vk = bob.openSharedGrant(handle.vaultId, sealedRow.sealedVk!!)
        val wrap = bob.wrapVkUnderOwnUvk(handle.vaultId, vk)

        val resp = client.selfWrap(bob, handle.vaultId, wrap)
        assertEquals(HttpStatusCode.OK, resp.status, resp.bodyAsText())

        // A pull from the old cursor re-delivers the row (grant rev bumped) with the wrap; seal retained.
        val row = client.sync(bob, before.rev).grants.single { it.vaultId == handle.vaultId }
        assertEquals(wrap, row.wrappedVk)
        assertEquals(sealedRow.sealedVk, row.sealedVk, "the v1 seal is kept for older clients")
        assertEquals("writer", row.role, "the self-wrap never changes the role")
        assertTrue(row.rev > sealedRow.rev)
        assertTrue(bob.openOwnGrant(handle.vaultId, row.wrappedVk).contentEquals(handle.vk))

        // Idempotent: the same wrap again is a no-op (no rev churn).
        val again = client.selfWrap(bob, handle.vaultId, wrap)
        assertEquals(HttpStatusCode.OK, again.status)
        assertTrue(client.sync(bob, client.sync(bob).rev).grants.none { it.vaultId == handle.vaultId })

        assertTrue(client.auditRows(owner, "vault_grant_self_wrap").any { it.userId == bob.userId })
        // The owner's own row is untouched by a member's self-wrap.
        assertEquals(createReq.wrappedVk, client.sync(owner).grants.single { it.vaultId == handle.vaultId }.wrappedVk)
    }

    @Test
    fun onlyTheCallersOwnActiveMemberGrantAndOnlyASmallWrap() = testApplication {
        application { andvariModule(buildServices(config(), Notifier())) }
        val client = jsonClient(this)
        val owner = VirtualClient("sw2-owner@x.com", "self wrap owner password three", fast = true)
        client.register(owner, bootstrapToken)
        val bob = client.enrollSecond(owner, "sw2-bob@x.com", "self wrap bob password four")
        val eve = client.enrollSecond(owner, "sw2-eve@x.com", "self wrap eve password five")
        val (createReq, handle) = owner.buildCreateSharedVault()
        client.createVault(owner, createReq)
        client.addMember(owner, handle.vaultId, handle.vk, bob, "sw2-bob@x.com")
        val wrap = bob.wrapVkUnderOwnUvk(handle.vaultId, handle.vk)

        // A non-member cannot write a wrap onto a vault it has no grant for.
        assertEquals(HttpStatusCode.Forbidden, client.selfWrap(eve, handle.vaultId, eve.wrapVkUnderOwnUvk(handle.vaultId, handle.vk)).status)
        // The owner's wrap is bound into transfer accept proofs: this route never rewrites it.
        val ownerResp = client.selfWrap(owner, handle.vaultId, owner.wrapVkUnderOwnUvk(handle.vaultId, handle.vk))
        assertEquals(HttpStatusCode.Forbidden, ownerResp.status, ownerResp.bodyAsText())
        assertEquals(createReq.wrappedVk, client.sync(owner).grants.single { it.vaultId == handle.vaultId }.wrappedVk)
        // A personal vault's row is an owner row too.
        assertEquals(HttpStatusCode.Forbidden, client.selfWrap(bob, bob.personalVaultId, wrap).status)

        // Size bound: > 1 KiB, or not base64url, is refused before any row is touched.
        val big = Bytes.toB64(ByteArray(2048) { 1 })
        assertEquals(HttpStatusCode.BadRequest, client.selfWrap(bob, handle.vaultId, big).status)
        assertEquals(HttpStatusCode.BadRequest, client.selfWrap(bob, handle.vaultId, "!!").status)
        assertEquals(HttpStatusCode.BadRequest, client.selfWrap(bob, handle.vaultId, "").status)

        // A removed member's grant is no longer theirs to write.
        val rm = client.delete("/api/v1/vaults/${handle.vaultId}/members/${bob.userId}") { authed(owner) }
        assertEquals(HttpStatusCode.OK, rm.status, rm.bodyAsText())
        assertEquals(HttpStatusCode.Forbidden, client.selfWrap(bob, handle.vaultId, wrap).status)
    }
}
