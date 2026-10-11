package io.silencelen.andvari.server

import io.ktor.client.request.post
import io.ktor.client.request.setBody
import io.ktor.http.ContentType
import io.ktor.http.HttpStatusCode
import io.ktor.http.contentType
import io.ktor.server.testing.testApplication
import io.ktor.http.content.OutgoingContent
import io.ktor.utils.io.ByteWriteChannel
import io.ktor.utils.io.writeFully
import io.silencelen.andvari.core.crypto.LifecycleProof
import io.silencelen.andvari.core.model.VaultLeaveRequest
import io.silencelen.andvari.core.model.VaultMemberRemoveRequest
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNull

/**
 * Removal proofs v2 on the server (security review 2026-10, root cause A §6.2, branch A7). The server cannot verify a
 * proof (no VK): it STORES the v2 fields on the revoked grant row, RELAYS `{proofV, issuedAt}` in removedGrantsInfo
 * for `removed` and `left` alike, refuses a nonce it already stored for the vault (hygiene, honest server only), and
 * still accepts the empty leave body of older clients while the compatibility window is open.
 */
class RemovalProofV2ServerTest : LifecycleTestSupport() {

    @Test
    fun aV2RemovalIsStoredAndRelayedAndItsNonceIsSingleUse() = testApplication {
        val services = buildServices(config(), Notifier())
        application { andvariModule(services) }
        val client = jsonClient(this)
        val owner = VirtualClient("owner@x.com", "owner a7 password one", fast = true)
        client.register(owner, bootstrapToken)
        val bob = client.enrollSecond(owner, "bob@x.com", "bob a7 password two")
        val (createReq, handle) = owner.buildCreateSharedVault()
        client.createVault(owner, createReq)
        client.addMember(owner, handle, bob, "writer")
        val cursor = client.sync(bob).rev

        val key = LifecycleProof.lifecycleKey(crypto, handle.vk)
        val nonce = LifecycleProof.newNonce(crypto)
        val at = System.currentTimeMillis()
        val proof = LifecycleProof.removeV2(crypto, key, handle.vaultId, bob.userId, nonce, at)
        val body = VaultMemberRemoveRequest(proof = proof, nonce = nonce, proofV = 2, issuedAt = at)
        assertEquals(HttpStatusCode.OK, client.removeMember(owner, handle.vaultId, bob.userId, body).status)

        val info = client.sync(bob, cursor).removedGrantsInfo.single { it.vaultId == handle.vaultId }
        assertEquals("removed", info.reason)
        assertEquals(2, info.proofV)
        assertEquals(at, info.issuedAt)
        assertEquals(nonce, info.removeNonce)
        assertEquals(proof, info.removeProof)

        // Re-add, then try to store the SAME nonce again for this vault: refused (409 nonce_reused).
        assertEquals(HttpStatusCode.Created, client.addMember(owner, handle, bob, "writer").status)
        val again = client.removeMember(owner, handle.vaultId, bob.userId, body)
        assertEquals(HttpStatusCode.Conflict, again.status)
        assertEquals("nonce_reused", errorOf(again))
        // The re-add cleared the stored proof fields on the live grant row.
        assertEquals("writer", client.sync(bob).grants.single { it.vaultId == handle.vaultId }.role)
    }

    @Test
    fun aV2LeaveIsStoredAndRelayedOnTheLeftRow() = testApplication {
        val services = buildServices(config(), Notifier())
        application { andvariModule(services) }
        val client = jsonClient(this)
        val owner = VirtualClient("owner@x.com", "owner a7 password one", fast = true)
        client.register(owner, bootstrapToken)
        val bob = client.enrollSecond(owner, "bob@x.com", "bob a7 password two")
        val (createReq, handle) = owner.buildCreateSharedVault()
        client.createVault(owner, createReq)
        client.addMember(owner, handle, bob, "writer")
        val cursor = client.sync(bob).rev

        val key = LifecycleProof.lifecycleKey(crypto, handle.vk)
        val nonce = LifecycleProof.newNonce(crypto)
        val at = System.currentTimeMillis()
        val proof = LifecycleProof.leave(crypto, key, handle.vaultId, bob.userId, nonce, at)
        assertEquals(HttpStatusCode.OK, client.vaultLeave(bob, handle.vaultId, VaultLeaveRequest(2, proof, nonce, at)).status)

        val info = client.sync(bob, cursor).removedGrantsInfo.single { it.vaultId == handle.vaultId }
        assertEquals("left", info.reason)
        assertEquals(2, info.proofV)
        assertEquals(at, info.issuedAt)
        assertEquals(nonce, info.removeNonce)
        assertEquals(proof, info.removeProof)
    }

    @Test
    fun anOlderClientsEmptyLeaveIsStillAcceptedAndRelaysNoProof() = testApplication {
        val services = buildServices(config(), Notifier())
        application { andvariModule(services) }
        val client = jsonClient(this)
        val owner = VirtualClient("owner@x.com", "owner a7 password one", fast = true)
        client.register(owner, bootstrapToken)
        val bob = client.enrollSecond(owner, "bob@x.com", "bob a7 password two")
        val (createReq, handle) = owner.buildCreateSharedVault()
        client.createVault(owner, createReq)
        client.addMember(owner, handle, bob, "writer")
        val cursor = client.sync(bob).rev
        // The pre-A7 web client posts `{}`.
        val r = client.post("/api/v1/vaults/${handle.vaultId}/leave") {
            authed(bob)
            contentType(ContentType.Application.Json); setBody("{}")
        }
        assertEquals(HttpStatusCode.OK, r.status)
        val info = client.sync(bob, cursor).removedGrantsInfo.single { it.vaultId == handle.vaultId }
        assertEquals("left", info.reason)
        assertNull(info.proofV)
        assertNull(info.removeProof)
    }

    @Test
    fun malformedV2BodiesAreRefused() = testApplication {
        val services = buildServices(config(), Notifier())
        application { andvariModule(services) }
        val client = jsonClient(this)
        val owner = VirtualClient("owner@x.com", "owner a7 password one", fast = true)
        client.register(owner, bootstrapToken)
        val bob = client.enrollSecond(owner, "bob@x.com", "bob a7 password two")
        val (createReq, handle) = owner.buildCreateSharedVault()
        client.createVault(owner, createReq)
        client.addMember(owner, handle, bob, "writer")
        val proof = LifecycleProof.removeV2(crypto, LifecycleProof.lifecycleKey(crypto, handle.vk), handle.vaultId, bob.userId, LifecycleProof.newNonce(crypto), 1)
        // A UUID is a v1 nonce, not a v2 one; a v2 body needs issuedAt; an unknown version is refused.
        for ((b, code) in listOf(
            VaultMemberRemoveRequest(proof, uuid(), 2, System.currentTimeMillis()) to "bad_nonce",
            VaultMemberRemoveRequest(proof, LifecycleProof.newNonce(crypto), 2, null) to "bad_proof",
            VaultMemberRemoveRequest(proof, LifecycleProof.newNonce(crypto), 3, 1) to "bad_proof_version",
        )) {
            val r = client.removeMember(owner, handle.vaultId, bob.userId, b)
            assertEquals(HttpStatusCode.BadRequest, r.status, code)
            assertEquals(code, errorOf(r))
        }
        val badLeave = client.vaultLeave(bob, handle.vaultId, VaultLeaveRequest(1, proof, uuid(), null))
        assertEquals(HttpStatusCode.BadRequest, badLeave.status)
        assertEquals("bad_proof_version", errorOf(badLeave))
    }

    /** A7 review LOW-5: a CHUNKED leave body (no Content-Length) is parsed too, never silently dropped. */
    @Test
    fun aChunkedV2LeaveBodyIsStoredAndRelayed() = testApplication {
        val services = buildServices(config(), Notifier())
        application { andvariModule(services) }
        val client = jsonClient(this)
        val owner = VirtualClient("owner@x.com", "owner a7 password one", fast = true)
        client.register(owner, bootstrapToken)
        val bob = client.enrollSecond(owner, "bob@x.com", "bob a7 password two")
        val (createReq, handle) = owner.buildCreateSharedVault()
        client.createVault(owner, createReq)
        client.addMember(owner, handle, bob, "writer")
        val cursor = client.sync(bob).rev
        val key = LifecycleProof.lifecycleKey(crypto, handle.vk)
        val nonce = LifecycleProof.newNonce(crypto)
        val at = System.currentTimeMillis()
        val proof = LifecycleProof.leave(crypto, key, handle.vaultId, bob.userId, nonce, at)
        val bytes = """{"proofV":2,"proof":"$proof","nonce":"$nonce","issuedAt":$at}""".encodeToByteArray()
        val r = client.post("/api/v1/vaults/${handle.vaultId}/leave") {
            authed(bob)
            setBody(object : OutgoingContent.WriteChannelContent() {
                override val contentType = ContentType.Application.Json
                override suspend fun writeTo(channel: ByteWriteChannel) { channel.writeFully(bytes) }
            })
        }
        assertEquals(HttpStatusCode.OK, r.status)
        val info = client.sync(bob, cursor).removedGrantsInfo.single { it.vaultId == handle.vaultId }
        assertEquals(2, info.proofV)
        assertEquals(nonce, info.removeNonce)
    }

    /** A7 review LOW-5: a removal that revokes nothing (target not an active member) never claims the nonce, so the
     *  same nonce is still usable for the real removal later. */
    @Test
    fun aRemovalOfANonMemberDoesNotClaimTheNonce() = testApplication {
        val services = buildServices(config(), Notifier())
        application { andvariModule(services) }
        val client = jsonClient(this)
        val owner = VirtualClient("owner@x.com", "owner a7 password one", fast = true)
        client.register(owner, bootstrapToken)
        val bob = client.enrollSecond(owner, "bob@x.com", "bob a7 password two")
        val (createReq, handle) = owner.buildCreateSharedVault()
        client.createVault(owner, createReq)
        client.addMember(owner, handle, bob, "writer")
        assertEquals(HttpStatusCode.OK, client.removeMember(owner, handle.vaultId, bob.userId).status) // bare: revoked
        val key = LifecycleProof.lifecycleKey(crypto, handle.vk)
        val nonce = LifecycleProof.newNonce(crypto)
        val at = System.currentTimeMillis()
        val body = VaultMemberRemoveRequest(LifecycleProof.removeV2(crypto, key, handle.vaultId, bob.userId, nonce, at), nonce, 2, at)
        assertEquals(HttpStatusCode.NotFound, client.removeMember(owner, handle.vaultId, bob.userId, body).status)
        assertEquals(HttpStatusCode.Created, client.addMember(owner, handle, bob, "writer").status)
        assertEquals(HttpStatusCode.OK, client.removeMember(owner, handle.vaultId, bob.userId, body).status, "the nonce was never claimed")
    }
}
