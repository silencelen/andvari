package io.silencelen.andvari.server

import io.ktor.client.statement.bodyAsText
import io.ktor.http.HttpStatusCode
import io.ktor.server.testing.testApplication
import io.silencelen.andvari.core.model.Mutation
import io.silencelen.andvari.core.model.TransferAcceptRequest
import io.silencelen.andvari.core.model.VaultMetaUpdateRequest
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue

/**
 * Mixed-fleet matrix (design §10): one server, three client GENERATIONS driven through
 * delete → offline-denial → restore → replay → leave → re-add → transfer → rename.
 *
 * The generations are behavioral shapes over the same wire (this is a server test —
 * what differs is which response fields each generation acts on):
 *  - owner  ~ 0.5   — mints lifecycle proofs, reads removedGrantsInfo;
 *  - m4     ~ 0.4.0 — durable queue; acts on removedGrants only, ignores the additive
 *    fields (kotlinx ignoreUnknownKeys — the response parses fine with them present);
 *  - m2     ~ 0.2.x MSI — ignores removedGrants entirely, keeps pushing stale edits
 *    (incl. the personal-vault re-encrypt) until relaunch.
 *
 * Every §11 route is retried twice somewhere in the narrative (idempotency pinning).
 */
class LifecycleFleetTest : LifecycleTestSupport() {

    @Test
    fun mixedFleet_deleteRestoreLeaveTransferRename_withOfflineQueuedEdits() = testApplication {
        val services = buildServices(config(), Notifier())
        application { andvariModule(services) }
        val client = jsonClient(this)

        // ---- fixture: owner (0.5) + m4 (0.4-shaped) + m2 (0.2-shaped), populated vault ----
        val owner = VirtualClient("owner@x.com", "owner fleet password one", fast = true)
        client.register(owner, bootstrapToken)
        val m4 = client.enrollSecond(owner, "m4@x.com", "m4 fleet password two")
        val m2 = client.enrollSecond(owner, "m2@x.com", "m2 fleet password tre")

        val (createReq, handle) = owner.buildCreateSharedVault()
        assertEquals(HttpStatusCode.Created, client.createVault(owner, createReq).status)
        client.addMember(owner, handle, m4, "writer")
        client.addMember(owner, handle, m2, "writer")
        val m4Vk = client.openMemberVk(m4, handle.vaultId)
        val m2Vk = client.openMemberVk(m2, handle.vaultId)

        val sharedItem = owner.newItemId()
        client.push(owner, Mutation(uuid(), "put", sharedItem, handle.vaultId, 0, owner.encItemIn(handle.vaultId, handle.vk, sharedItem, """{"name":"wifi"}""")))
        val m4Item = m4.newItemId()
        client.push(m4, Mutation(uuid(), "put", m4Item, handle.vaultId, 0, m4.encItemIn(handle.vaultId, m4Vk, m4Item, """{"name":"m4-item"}""")))

        // m2 goes OFFLINE holding a queued (unpushed) edit against the shared item. Its
        // mutationId is FIXED — a durable client queue replays the SAME id, so this is the
        // exact id that must NOT be frozen as 'denied' by the dedup cache (DATA-LOSS #2).
        val m2Cursor = client.sync(m2).rev
        val m2QueuedBase = client.sync(m2).items.single { it.itemId == sharedItem }.rev
        val m2QueuedBlob = m2.encItemIn(handle.vaultId, m2Vk, sharedItem, """{"name":"wifi","note":"m2 offline edit"}""")
        val m2ParkedMutationId = uuid()

        // ---- DELETE (retry-twice: idempotent by deleteId) ----
        val (deleteId, deleteProof) = client.deleteWithProof(owner, handle)
        assertEquals(HttpStatusCode.OK, client.vaultDelete(owner, handle.vaultId, deleteId, deleteProof).status)

        // 0.4-shaped m4 pulls: removedGrants (its purge trigger) + the additive info it
        // ignores — but which a 0.5 device verifies under its held VK before attributing.
        val m4AfterDelete = client.sync(m4)
        assertTrue(m4AfterDelete.removedGrants.contains(handle.vaultId))
        val info = m4AfterDelete.removedGrantsInfo.single { it.vaultId == handle.vaultId }
        assertEquals("deleted", info.reason)
        assertTrue(m4.verifyDeleteProof(handle.vaultId, m4Vk, info.deleteId!!, info.deleteProof!!))
        assertTrue(m4AfterDelete.items.none { it.vaultId == handle.vaultId }, "no ciphertext delivered during grace")

        // 0.2-shaped m2 reconnects and flushes its queue: per-mutation denied (200 —
        // never a thrown 4xx, the queue dequeues), audited with the deleted: prefix. The
        // denied result must NOT be cached (DATA-LOSS #2) — see the SAME-id replay below.
        val m2Flush = client.push(m2, Mutation(m2ParkedMutationId, "put", sharedItem, handle.vaultId, m2QueuedBase, m2QueuedBlob))
        assertEquals("denied", m2Flush.results[0].status)
        // …and its MSI-style personal-vault re-encrypt of the same item hits the
        // vault_mismatch fence (existing row retained) — denied, not resurrected.
        val m2Teleport = client.push(m2, Mutation(uuid(), "put", sharedItem, m2.personalVaultId, 0, m2.encItem(sharedItem, """{"name":"teleported"}""")))
        assertEquals("denied", m2Teleport.results[0].status)
        assertTrue(client.sync(m2).items.none { it.itemId == sharedItem })

        // ---- RESTORE (retry-twice: idempotent by the stored restoreProof) ----
        val restoreProof = owner.mintRestoreProof(handle.vaultId, handle.vk, deleteId)
        assertEquals(HttpStatusCode.OK, client.vaultRestore(owner, handle.vaultId, deleteId, restoreProof).status)
        assertEquals(HttpStatusCode.OK, client.vaultRestore(owner, handle.vaultId, deleteId, restoreProof).status)

        // m2's cursor STRADDLES delete+restore: removedGrants never fires for it
        // (revokedAt back to NULL); the vault + grant + all items are re-delivered.
        val m2AfterRestore = client.sync(m2, m2Cursor)
        assertFalse(m2AfterRestore.removedGrants.contains(handle.vaultId))
        assertTrue(m2AfterRestore.vaults.any { it.vaultId == handle.vaultId })
        assertTrue(m2AfterRestore.items.any { it.itemId == sharedItem })

        // A 0.5 client REPLAYS its parked mutation after restore with the EXACT SAME
        // mutationId it was denied under during grace (DATA-LOSS #2). Because a 'denied'
        // result is never cached, the replay re-evaluates against the now-active grant and
        // APPLIES — the design's "restore brings back members' in-flight edits" holds.
        // baseRev is still valid: items were untouched during grace.
        val replay = client.push(m2, Mutation(m2ParkedMutationId, "put", sharedItem, handle.vaultId, m2QueuedBase, m2QueuedBlob))
        assertEquals("applied", replay.results[0].status, "parked mutation must APPLY on replay after restore — denied results are not cached")
        assertTrue(owner.decItemIn(handle.vaultId, handle.vk, sharedItem, client.sync(owner).items.single { it.itemId == sharedItem }.blob!!).contains("m2 offline edit"))

        // ---- LEAVE (retry-twice: idempotent by reason) + re-add resurrects ----
        assertEquals(HttpStatusCode.OK, client.vaultLeave(m4, handle.vaultId).status)
        assertEquals(HttpStatusCode.OK, client.vaultLeave(m4, handle.vaultId).status)
        val m4AfterLeave = client.sync(m4)
        assertTrue(m4AfterLeave.removedGrants.contains(handle.vaultId))
        assertEquals("left", m4AfterLeave.removedGrantsInfo.single { it.vaultId == handle.vaultId }.reason)
        // Keys were kept: re-add resurrects the grant (writer again).
        assertEquals(HttpStatusCode.Created, client.addMember(owner, handle, m4, "writer").status)
        assertEquals("writer", client.sync(m4).grants.single { it.vaultId == handle.vaultId }.role)

        // ---- TRANSFER owner → m4 (offer retried twice = overwrite-with-cancel-audit;
        //      accept retried twice = idempotent) ----
        val (offerId, _, offer1) = client.offerWithProof(owner, handle, m4, seq = 1)
        assertEquals(HttpStatusCode.Created, offer1.status, offer1.bodyAsText())
        // Offer retry (same offerId): one pending max — the overwrite audits a cancel first.
        val (_, _, offer2) = client.offerWithProof(owner, handle, m4, seq = 1, offerId = offerId)
        assertEquals(HttpStatusCode.Created, offer2.status)
        assertTrue(client.auditRows(owner, "vault_transfer_cancel").any { it.meta == "${handle.vaultId}:superseded" })

        // The pending offer reaches every member on the vault row; the 0.2-shape simply
        // never acts on the unknown field (it still parses the row fine).
        val m2Pending = client.sync(m2).vaults.single { it.vaultId == handle.vaultId }.pendingTransfer
        assertNotNull(m2Pending)
        assertEquals(m4.userId, m2Pending.toUserId)

        // m4 verifies the offer proof under ITS held VK before consenting (0.5 duty).
        val offerOk = io.silencelen.andvari.core.crypto.LifecycleProof.verify(
            m4.mintOfferProof(handle.vaultId, m4Vk, m2Pending.offerId, m4.userId, m2Pending.expiresAt, m2Pending.seq),
            m2Pending.proof,
        )
        assertTrue(offerOk, "offer proof verifies under the member-held VK")

        val wrapped = m4.wrapVkUnderOwnUvk(handle.vaultId, m4Vk)
        val acceptProof = m4.mintAcceptProof(handle.vaultId, m4Vk, offerId, m4.userId, 1, wrapped)
        assertEquals(HttpStatusCode.OK, client.transferAccept(m4, handle.vaultId, TransferAcceptRequest(offerId, wrapped, acceptProof)).status)
        assertEquals(HttpStatusCode.OK, client.transferAccept(m4, handle.vaultId, TransferAcceptRequest(offerId, wrapped, acceptProof)).status)

        // Post-transfer state: m4 owner (posted wrap + RETAINED sealedVk), ex-owner writer
        // who can still push (the fielded-MSI writer-powers residual, pinned here).
        val m4Grant = client.sync(m4).grants.single { it.vaultId == handle.vaultId }
        assertEquals("owner", m4Grant.role)
        assertNotNull(m4Grant.sealedVk)
        val exOwnerItem = owner.newItemId()
        assertEquals(
            "applied",
            client.push(owner, Mutation(uuid(), "put", exOwnerItem, handle.vaultId, 0, owner.encItemIn(handle.vaultId, handle.vk, exOwnerItem, """{"name":"ex-owner-writes"}"""))).results[0].status,
        )
        // …and MSI item-DELETE ops with the true vaultId still apply (design §10 pin).
        val delRev = client.sync(owner).items.single { it.itemId == exOwnerItem }.rev
        assertEquals("applied", client.push(owner, Mutation(uuid(), "delete", exOwnerItem, handle.vaultId, delRev, null)).results[0].status)

        // Old owner can no longer run lifecycle ops (delete now 403s as non-owner).
        val exDelete = client.vaultDelete(owner, handle.vaultId, uuid(), owner.mintDeleteProof(handle.vaultId, handle.vk, uuid()))
        assertEquals(HttpStatusCode.Forbidden, exDelete.status)

        // ---- RENAME by the NEW owner (retry-twice: second write with a fresh base rev) ----
        val newMeta = m4.sealVaultMeta(handle.vaultId, m4Vk, """{"name":"Family","metaV":2}""")
        val curRev = client.sync(m4).vaults.single { it.vaultId == handle.vaultId }.rev
        assertEquals(HttpStatusCode.OK, client.putVaultMeta(m4, handle.vaultId, VaultMetaUpdateRequest(newMeta, curRev)).status)
        // Stale retry with the old base rev → 409 (no silent last-write-wins)…
        val stale = client.putVaultMeta(m4, handle.vaultId, VaultMetaUpdateRequest(newMeta, curRev))
        assertEquals(HttpStatusCode.Conflict, stale.status)
        assertEquals("stale_meta", errorOf(stale))
        // …and the guard-free retry converges.
        assertEquals(HttpStatusCode.OK, client.putVaultMeta(m4, handle.vaultId, VaultMetaUpdateRequest(newMeta)).status)

        // Every fielded generation re-receives the vault row and re-decrypts the new name
        // with the VK it already holds (zero client change — the 0.2 shape shows no names
        // at all, a no-op).
        val m2Delivered = client.sync(m2).vaults.single { it.vaultId == handle.vaultId }
        assertTrue(m2.openVaultMeta(handle.vaultId, m2Vk, m2Delivered.metaBlob).contains("Family"))
        assertNull(m2Delivered.pendingTransfer, "accept cleared the pending offer for every member")
        assertEquals(m4.userId, m2Delivered.lastTransfer?.newOwnerUserId)

        // ---- transfer-cancel retry-twice rider (fresh offer by the new owner) ----
        val (o2, _, freshOffer) = client.offerWithProof(m4, handle, m2, seq = 2)
        assertEquals(HttpStatusCode.Created, freshOffer.status)
        assertEquals(o2, client.sync(owner).vaults.single { it.vaultId == handle.vaultId }.pendingTransfer?.offerId)
        assertEquals(HttpStatusCode.OK, client.transferCancel(m4, handle.vaultId).status)
        assertEquals(HttpStatusCode.OK, client.transferCancel(m4, handle.vaultId).status)
        assertNull(client.sync(owner).vaults.single { it.vaultId == handle.vaultId }.pendingTransfer)
    }
}
