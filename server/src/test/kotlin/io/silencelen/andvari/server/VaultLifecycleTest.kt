package io.silencelen.andvari.server

import io.ktor.client.request.delete
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
import io.ktor.utils.io.ByteReadChannel
import io.silencelen.andvari.core.model.Mutation
import io.silencelen.andvari.core.model.TransferAcceptRequest
import io.silencelen.andvari.core.model.TransferOfferRequest
import io.silencelen.andvari.core.model.VaultDeleteResponse
import io.silencelen.andvari.core.model.VaultMemberRemoveRequest
import io.silencelen.andvari.core.model.VaultMetaUpdateRequest
import java.io.File
import java.sql.DriverManager
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue

/**
 * Vault lifecycle (spec 03 §11, design 2026-07-07 "Skipti"): per-op semantics, the §4
 * concurrency matrix as named tests, the public-origin regression sweep over every
 * §10/§11 route, the MSI-shaped skeletal-fence proof, the janitor (purge + expiry +
 * dry-run + restore-vs-purge fence), rate-bucket separation, and the v3→v4 migration.
 */
class VaultLifecycleTest : LifecycleTestSupport() {

    // ---- DELETE: soft delete, per-member revocation, operation-identity idempotency ----

    @Test
    fun delete_softDeletes_idempotentByDeleteId_and409OnMismatch() = testApplication {
        val services = buildServices(config(), Notifier())
        application { andvariModule(services) }
        val client = jsonClient(this)
        val owner = VirtualClient("owner@x.com", "owner delete password one", fast = true)
        client.register(owner, bootstrapToken)
        val bob = client.enrollSecond(owner, "bob@x.com", "bob delete password two")

        val (createReq, handle) = owner.buildCreateSharedVault()
        client.createVault(owner, createReq)
        client.addMember(owner, handle, bob, "writer")
        val item = owner.newItemId()
        client.push(owner, Mutation(uuid(), "put", item, handle.vaultId, 0, owner.encItemIn(handle.vaultId, handle.vk, item, """{"name":"wifi"}""")))

        val deleteId = uuid()
        val proof = owner.mintDeleteProof(handle.vaultId, handle.vk, deleteId)
        val r1 = client.vaultDelete(owner, handle.vaultId, deleteId, proof)
        assertEquals(HttpStatusCode.OK, r1.status, r1.bodyAsText())
        val d1 = json.decodeFromString(VaultDeleteResponse.serializer(), r1.bodyAsText())
        assertTrue(d1.purgeAt > now(), "grace window in the future")

        // Retry with the SAME deleteId → idempotent 200, same purgeAt (double-delete race).
        val r2 = client.vaultDelete(owner, handle.vaultId, deleteId, proof)
        assertEquals(HttpStatusCode.OK, r2.status)
        assertEquals(d1.purgeAt, json.decodeFromString(VaultDeleteResponse.serializer(), r2.bodyAsText()).purgeAt)

        // A DIFFERENT deleteId against the tombstone → 409 vault_state_changed, never a
        // fresh delete (stale retry racing a restore — operation-identity idempotency).
        val r3 = client.vaultDelete(owner, handle.vaultId, uuid(), owner.mintDeleteProof(handle.vaultId, handle.vk, uuid()))
        assertEquals(HttpStatusCode.Conflict, r3.status)
        assertEquals("vault_state_changed", errorOf(r3))

        // During grace: rows intact server-side, but grants revoked → items unreachable.
        val bobSync = client.sync(bob)
        assertTrue(bobSync.removedGrants.contains(handle.vaultId))
        assertTrue(bobSync.items.none { it.vaultId == handle.vaultId })
        // Audit carries the pre-captured member count.
        assertTrue(client.auditRows(owner, "vault_delete").any { it.meta == "${handle.vaultId}:members=2" })
        // Outsider (no grant row at all) gets the uniform 403 — no tombstone existence oracle.
        val eve = client.enrollSecond(owner, "eve@x.com", "eve delete password tre")
        val r4 = client.vaultDelete(eve, handle.vaultId, uuid(), owner.mintDeleteProof(handle.vaultId, handle.vk, uuid()))
        assertEquals(HttpStatusCode.Forbidden, r4.status)
        assertEquals("not_vault_owner", errorOf(r4))
    }

    // ---- removedGrantsInfo: reason from the caller's OWN grant + verifiable proofs ----

    @Test
    fun delete_emitsRemovedGrantsInfo_reasonFromOwnGrant_withVerifiableProofs() = testApplication {
        val services = buildServices(config(), Notifier())
        application { andvariModule(services) }
        val client = jsonClient(this)
        val owner = VirtualClient("owner@x.com", "owner info password one", fast = true)
        client.register(owner, bootstrapToken)
        val bob = client.enrollSecond(owner, "bob@x.com", "bob info password two")
        val carol = client.enrollSecond(owner, "carol@x.com", "carol info password tre")

        val (createReq, handle) = owner.buildCreateSharedVault()
        client.createVault(owner, createReq)
        client.addMember(owner, handle, bob, "writer")
        client.addMember(owner, handle, carol, "writer")
        val bobVk = client.openMemberVk(bob, handle.vaultId)
        val carolCursor = client.sync(carol).rev

        // Owner removes carol WITH a removal proof BEFORE the delete.
        val nonce = uuid()
        val removeProof = owner.mintRemoveProof(handle.vaultId, handle.vk, carol.userId, nonce)
        assertEquals(
            HttpStatusCode.OK,
            client.removeMember(owner, handle.vaultId, carol.userId, VaultMemberRemoveRequest(removeProof, nonce)).status,
        )
        // Then deletes the vault.
        val (deleteId, _) = client.deleteWithProof(owner, handle)

        // Carol (removed pre-delete) sees reason='removed' — never 'deleted' (no mislabel) —
        // with the relayed removal proof her 0.5.0 client verifies under her held VK.
        val carolInfo = client.sync(carol, carolCursor).removedGrantsInfo.single { it.vaultId == handle.vaultId }
        assertEquals("removed", carolInfo.reason)
        assertNull(carolInfo.deleteProof, "tombstone fields ride only reason='deleted'")
        assertEquals(nonce, carolInfo.removeNonce)
        // Carol still holds the VK she was granted while a member — that is what her
        // 0.5.0 client verifies the relayed removal proof against.
        assertTrue(carol.verifyRemoveProof(handle.vaultId, handle.vk, carol.userId, carolInfo.removeNonce!!, carolInfo.removeProof!!))

        // Bob sees reason='deleted' with tombstone fields + a deleteProof that verifies.
        val bobInfo = client.sync(bob).removedGrantsInfo.single { it.vaultId == handle.vaultId }
        assertEquals("deleted", bobInfo.reason)
        assertEquals(deleteId, bobInfo.deleteId)
        assertNotNull(bobInfo.deletedAt); assertNotNull(bobInfo.purgeAt)
        assertTrue(bob.verifyDeleteProof(handle.vaultId, bobVk, bobInfo.deleteId!!, bobInfo.deleteProof!!))
    }

    // ---- RESTORE: scope rule, idempotency, vault_gone past grace ----

    @Test
    fun restore_resurrectsOnlyVaultDeleteRevocations_idempotent() = testApplication {
        val services = buildServices(config(), Notifier())
        application { andvariModule(services) }
        val client = jsonClient(this)
        val owner = VirtualClient("owner@x.com", "owner restore password one", fast = true)
        client.register(owner, bootstrapToken)
        val bob = client.enrollSecond(owner, "bob@x.com", "bob restore password two")
        val carol = client.enrollSecond(owner, "carol@x.com", "carol restore password tre")

        val (createReq, handle) = owner.buildCreateSharedVault()
        client.createVault(owner, createReq)
        client.addMember(owner, handle, bob, "writer")
        client.addMember(owner, handle, carol, "reader")
        val item = owner.newItemId()
        client.push(owner, Mutation(uuid(), "put", item, handle.vaultId, 0, owner.encItemIn(handle.vaultId, handle.vk, item, """{"name":"wifi"}""")))
        val bobCursor = client.sync(bob).rev

        // carol removed BEFORE the delete — restore must NOT resurrect her.
        client.removeMember(owner, handle.vaultId, carol.userId)
        val (deleteId, _) = client.deleteWithProof(owner, handle)

        val restoreProof = owner.mintRestoreProof(handle.vaultId, handle.vk, deleteId)
        val r1 = client.vaultRestore(owner, handle.vaultId, deleteId, restoreProof)
        assertEquals(HttpStatusCode.OK, r1.status, r1.bodyAsText())
        // Retry → idempotent 200 (same operation identity: the stored restoreProof matches).
        assertEquals(HttpStatusCode.OK, client.vaultRestore(owner, handle.vaultId, deleteId, restoreProof).status)
        // A different deleteId against the live vault → 409 (stale restore retry).
        val r3 = client.vaultRestore(owner, handle.vaultId, uuid(), owner.mintRestoreProof(handle.vaultId, handle.vk, uuid()))
        assertEquals(HttpStatusCode.Conflict, r3.status)
        assertEquals("vault_state_changed", errorOf(r3))

        // Bob is back with the vault + items via the proven backfill; his cursor straddled
        // delete+restore so removedGrants does NOT fire (revokedAt back to NULL).
        val bobSync = client.sync(bob, bobCursor)
        assertFalse(bobSync.removedGrants.contains(handle.vaultId))
        assertEquals("writer", bobSync.grants.single { it.vaultId == handle.vaultId }.role)
        assertTrue(bobSync.items.any { it.itemId == item })
        // #4: the restored LIVE vault row carries the consumed-deleteId marker
        // (restoreProof + deleteId), so a device offline across the whole delete→restore
        // cycle verifies restore(VK,vaultId,deleteId)==restoreProof and marks it consumed —
        // a later replayed old tombstone bearing that deleteId is then rejected as stale.
        val restoredVault = bobSync.vaults.single { it.vaultId == handle.vaultId }
        assertEquals(deleteId, restoredVault.deleteId)
        assertEquals(restoreProof, restoredVault.restoreProof)
        assertTrue(
            io.silencelen.andvari.core.crypto.LifecycleProof.verify(
                bob.mintRestoreProof(handle.vaultId, handle.vk, restoredVault.deleteId!!), restoredVault.restoreProof!!,
            ),
            "restoreProof on the live vault verifies under a member-held VK",
        )
        // Bob can write again.
        val newItem = bob.newItemId()
        val bobVk = client.openMemberVk(bob, handle.vaultId)
        assertEquals("applied", client.push(bob, Mutation(uuid(), "put", newItem, handle.vaultId, 0, bob.encItemIn(handle.vaultId, bobVk, newItem, """{"name":"back"}"""))).results[0].status)

        // carol stays removed: no active grant, writes denied.
        val carolSync = client.sync(carol)
        assertTrue(carolSync.grants.none { it.vaultId == handle.vaultId })
        // Members list: owner + bob only.
        val members = services.repo.db.read { c ->
            c.queryAll("SELECT userId FROM grants WHERE vaultId=? AND revokedAt IS NULL", handle.vaultId) { it.getString(1) }
        }.toSet()
        assertEquals(setOf(owner.userId, bob.userId), members)
    }

    // ---- DATA-LOSS #1: a consumed deleteId must NOT re-delete a restored vault ----

    @Test
    fun delete_consumedDeleteIdAfterRestore_409_neverReDeletes() = testApplication {
        val services = buildServices(config(), Notifier())
        application { andvariModule(services) }
        val client = jsonClient(this)
        val owner = VirtualClient("owner@x.com", "owner consume password one", fast = true)
        client.register(owner, bootstrapToken)
        val bob = client.enrollSecond(owner, "bob@x.com", "bob consume password two")

        val (createReq, handle) = owner.buildCreateSharedVault()
        client.createVault(owner, createReq)
        client.addMember(owner, handle, bob, "writer")

        // delete d1 → restore(d1).
        val d1 = uuid()
        val d1Proof = owner.mintDeleteProof(handle.vaultId, handle.vk, d1)
        assertEquals(HttpStatusCode.OK, client.vaultDelete(owner, handle.vaultId, d1, d1Proof).status)
        assertEquals(HttpStatusCode.OK, client.vaultRestore(owner, handle.vaultId, d1, owner.mintRestoreProof(handle.vaultId, handle.vk, d1)).status)

        // A stale delete retry bearing the ALREADY-CONSUMED d1 arrives on the now-live vault.
        // It must NOT fall through into a fresh delete (which would undo the restore and
        // re-revoke every member) — 409 vault_state_changed.
        val replay = client.vaultDelete(owner, handle.vaultId, d1, d1Proof)
        assertEquals(HttpStatusCode.Conflict, replay.status)
        assertEquals("vault_state_changed", errorOf(replay))

        // The vault is still LIVE and members intact — no re-revocation happened.
        services.repo.db.read { c ->
            assertNull(c.queryOne("SELECT deletedAt FROM vaults WHERE vaultId=?", handle.vaultId) { rs -> rs.getLong(1).let { if (rs.wasNull()) null else it } })
            val active = c.queryAll("SELECT userId FROM grants WHERE vaultId=? AND revokedAt IS NULL", handle.vaultId) { it.getString(1) }.toSet()
            assertEquals(setOf(owner.userId, bob.userId), active)
        }
        // Bob still holds a live writer grant and can write.
        val bobVk = client.openMemberVk(bob, handle.vaultId)
        val item = bob.newItemId()
        assertEquals("applied", client.push(bob, Mutation(uuid(), "put", item, handle.vaultId, 0, bob.encItemIn(handle.vaultId, bobVk, item, """{"name":"still-here"}"""))).results[0].status)

        // A GENUINELY new delete (fresh deleteId ≠ consumed) still works — the fence only
        // blocks the consumed id, not a legitimate re-delete.
        val d2 = uuid()
        assertEquals(HttpStatusCode.OK, client.vaultDelete(owner, handle.vaultId, d2, owner.mintDeleteProof(handle.vaultId, handle.vk, d2)).status)
        assertTrue(client.sync(bob).removedGrants.contains(handle.vaultId))
    }

    // ---- #6: guard-order — an ex-member gets the SAME 403 whether the vault is live or in grace ----

    @Test
    fun guardOrder_exMemberGetsUniform403_liveOrInGrace_noStateOracle() = testApplication {
        val services = buildServices(config(), Notifier())
        application { andvariModule(services) }
        val client = jsonClient(this)
        val owner = VirtualClient("owner@x.com", "owner oracle password one", fast = true)
        client.register(owner, bootstrapToken)
        val bob = client.enrollSecond(owner, "bob@x.com", "bob oracle password two")

        val (createReq, handle) = owner.buildCreateSharedVault()
        client.createVault(owner, createReq)
        client.addMember(owner, handle, bob, "writer")
        // bob is REMOVED (member_remove) before any delete — an ex-member/outsider now.
        client.removeMember(owner, handle.vaultId, bob.userId)

        fun offerResp() = TransferOfferRequest(owner.userId, uuid(), now() + Service.DAY_MS, "cHJvb2Y")
        // On a LIVE vault: offer/cancel/accept by the ex-member → uniform 403.
        val liveOffer = client.transferOffer(bob, handle.vaultId, offerResp())
        val liveCancel = client.transferCancel(bob, handle.vaultId)
        val liveAccept = client.transferAccept(bob, handle.vaultId, TransferAcceptRequest(uuid(), "d3JhcA", "cHJvb2Y"))
        assertEquals(HttpStatusCode.Forbidden, liveOffer.status); assertEquals("not_vault_owner", errorOf(liveOffer))
        assertEquals(HttpStatusCode.Forbidden, liveCancel.status); assertEquals("no_grant", errorOf(liveCancel))
        assertEquals(HttpStatusCode.Forbidden, liveAccept.status); assertEquals("no_grant", errorOf(liveAccept))

        // Owner deletes the vault → it enters grace.
        client.deleteWithProof(owner, handle)

        // The SAME ex-member on the now-in-grace vault gets the SAME status+error for each
        // route (bob's grant is still member_remove-revoked — the delete only touched active
        // grants). No live↔grace state-transition oracle.
        val graceOffer = client.transferOffer(bob, handle.vaultId, offerResp())
        val graceCancel = client.transferCancel(bob, handle.vaultId)
        val graceAccept = client.transferAccept(bob, handle.vaultId, TransferAcceptRequest(uuid(), "d3JhcA", "cHJvb2Y"))
        assertEquals(HttpStatusCode.Forbidden, graceOffer.status); assertEquals("not_vault_owner", errorOf(graceOffer))
        assertEquals(HttpStatusCode.Forbidden, graceCancel.status); assertEquals("no_grant", errorOf(graceCancel))
        assertEquals(HttpStatusCode.Forbidden, graceAccept.status); assertEquals("no_grant", errorOf(graceAccept))

        // The grant-holder-at-delete owner, by contrast, DOES get the meaningful vault_deleted.
        val ownerOffer = client.transferOffer(owner, handle.vaultId, TransferOfferRequest(bob.userId, uuid(), now() + Service.DAY_MS, "cHJvb2Y"))
        assertEquals(HttpStatusCode.Conflict, ownerOffer.status)
        assertEquals("vault_deleted", errorOf(ownerOffer))
    }

    // ---- #5: a malformed removal-proof body → 400 (never a silent proofless 200) ----

    @Test
    fun removeMember_malformedProofBody_400_absentBodyStaysProofless() = testApplication {
        val services = buildServices(config(), Notifier())
        application { andvariModule(services) }
        val client = jsonClient(this)
        val owner = VirtualClient("owner@x.com", "owner malformed password one", fast = true)
        client.register(owner, bootstrapToken)
        val bob = client.enrollSecond(owner, "bob@x.com", "bob malformed password two")
        val carol = client.enrollSecond(owner, "carol@x.com", "carol malformed password tre")

        val (createReq, handle) = owner.buildCreateSharedVault()
        client.createVault(owner, createReq)
        client.addMember(owner, handle, bob, "writer")
        client.addMember(owner, handle, carol, "writer")

        // A PRESENT-but-unparseable JSON body → 400 bad_request (the client learns the proof
        // did NOT land and can retry) — never a silent proofless 200.
        val bad = client.delete("/api/v1/vaults/${handle.vaultId}/members/${bob.userId}") {
            authed(owner); contentType(ContentType.Application.Json); setBody("{not json")
        }
        assertEquals(HttpStatusCode.BadRequest, bad.status, bad.bodyAsText())
        assertEquals("bad_request", errorOf(bad))
        // bob still a member (the malformed remove did nothing).
        assertTrue(client.sync(bob).grants.any { it.vaultId == handle.vaultId })

        // An ABSENT body (0.4.0 shape: no Content-Length) → proofless removal, 200.
        val absent = client.removeMember(owner, handle.vaultId, carol.userId)
        assertEquals(HttpStatusCode.OK, absent.status, absent.bodyAsText())
        val carolInfo = client.sync(carol).removedGrantsInfo.single { it.vaultId == handle.vaultId }
        assertEquals("removed", carolInfo.reason)
        assertNull(carolInfo.removeProof, "no proof was sent → none relayed")
    }

    // ---- GET /vaults/deleted: owner's own in-grace vaults; ZK chain intact ----

    @Test
    fun deletedList_ownersInGraceVaultsOnly_zkRoundTrip() = testApplication {
        val services = buildServices(config(), Notifier())
        application { andvariModule(services) }
        val client = jsonClient(this)
        val owner = VirtualClient("owner@x.com", "owner list password one", fast = true)
        client.register(owner, bootstrapToken)
        val bob = client.enrollSecond(owner, "bob@x.com", "bob list password two")

        val (createReq, handle) = owner.buildCreateSharedVault()
        client.createVault(owner, createReq)
        client.addMember(owner, handle, bob, "writer")
        assertTrue(client.deletedVaults(owner).isEmpty())

        val (deleteId, _) = client.deleteWithProof(owner, handle)
        val row = client.deletedVaults(owner).single()
        assertEquals(handle.vaultId, row.vaultId)
        assertEquals(deleteId, row.deleteId)
        // The listed wrappedVk re-opens under the owner's UVK and decrypts the name —
        // exactly what Recently-deleted renders (ciphertext the owner already owned).
        val vk = owner.openOwnGrant(handle.vaultId, row.wrappedVk)
        assertTrue(owner.openVaultMeta(handle.vaultId, vk, row.metaBlob).contains("Shared"))
        // A non-owner member sees nothing.
        assertTrue(client.deletedVaults(bob).isEmpty())
        // After restore the list is empty again.
        client.vaultRestore(owner, handle.vaultId, deleteId, owner.mintRestoreProof(handle.vaultId, handle.vk, deleteId))
        assertTrue(client.deletedVaults(owner).isEmpty())
    }

    // ---- LEAVE: non-owner only, idempotent by reason, re-add resurrects ----

    @Test
    fun leave_nonOwnerIdempotent_ownerBlocked_reAddResurrects() = testApplication {
        val services = buildServices(config(), Notifier())
        application { andvariModule(services) }
        val client = jsonClient(this)
        val owner = VirtualClient("owner@x.com", "owner leave password one", fast = true)
        client.register(owner, bootstrapToken)
        val bob = client.enrollSecond(owner, "bob@x.com", "bob leave password two")

        val (createReq, handle) = owner.buildCreateSharedVault()
        client.createVault(owner, createReq)
        client.addMember(owner, handle, bob, "writer")
        val cursor = client.sync(bob).rev

        // Owner cannot leave — transfer or delete are the only exits.
        val ownerLeave = client.vaultLeave(owner, handle.vaultId)
        assertEquals(HttpStatusCode.BadRequest, ownerLeave.status)
        assertEquals("owner_must_transfer_or_delete", errorOf(ownerLeave))

        assertEquals(HttpStatusCode.OK, client.vaultLeave(bob, handle.vaultId).status)
        // leave-retry race: idempotent by reason.
        assertEquals(HttpStatusCode.OK, client.vaultLeave(bob, handle.vaultId).status)

        // Bob's own pull carries removedGrants + reason='left' for his other devices.
        val bobSync = client.sync(bob, cursor)
        assertTrue(bobSync.removedGrants.contains(handle.vaultId))
        assertEquals("left", bobSync.removedGrantsInfo.single { it.vaultId == handle.vaultId }.reason)
        assertTrue(client.auditRows(owner, "vault_member_leave").any { it.meta == "${handle.vaultId}:${bob.userId}" })

        // Keys were kept: the owner re-adds bob and the grant resurrects.
        assertEquals(HttpStatusCode.Created, client.addMember(owner, handle, bob, "writer").status)
        assertEquals("writer", client.sync(bob).grants.single { it.vaultId == handle.vaultId }.role)

        // An outsider (never a member) gets the uniform 403.
        val eve = client.enrollSecond(owner, "eve@x.com", "eve leave password tre")
        val r = client.vaultLeave(eve, handle.vaultId)
        assertEquals(HttpStatusCode.Forbidden, r.status)
        assertEquals("no_grant", errorOf(r))
    }

    // ---- TRANSFER: offer → accept flips roles; sealedVk retained; idempotent accept ----

    @Test
    fun transfer_offerAcceptFlipsRoles_retainsSealedVk_idempotentAccept() = testApplication {
        val services = buildServices(config(), Notifier())
        application { andvariModule(services) }
        val client = jsonClient(this)
        val owner = VirtualClient("owner@x.com", "owner transfer password one", fast = true)
        client.register(owner, bootstrapToken)
        val bob = client.enrollSecond(owner, "bob@x.com", "bob transfer password two")

        val (createReq, handle) = owner.buildCreateSharedVault()
        client.createVault(owner, createReq)
        client.addMember(owner, handle, bob, "writer")
        val bobVk = client.openMemberVk(bob, handle.vaultId)
        assertTrue(bobVk.contentEquals(handle.vk))

        val (offerId, expiresAt, offerResp) = client.offerWithProof(owner, handle, bob, seq = 1)
        assertEquals(HttpStatusCode.Created, offerResp.status, offerResp.bodyAsText())

        // The pending offer rides the vault row to EVERY member (banner delivery).
        val pending = client.sync(bob).vaults.single { it.vaultId == handle.vaultId }.pendingTransfer
        assertNotNull(pending)
        assertEquals(bob.userId, pending.toUserId)
        assertEquals(offerId, pending.offerId)
        assertEquals(1L, pending.seq)
        assertEquals(expiresAt, pending.expiresAt)

        // Bob accepts: re-wraps VK under his OWN UVK (the vault-creation construction),
        // acceptProof binds sha256(wrappedVk) + seq.
        val wrapped = bob.wrapVkUnderOwnUvk(handle.vaultId, bobVk)
        val acceptProof = bob.mintAcceptProof(handle.vaultId, bobVk, offerId, bob.userId, 1, wrapped)
        val a1 = client.transferAccept(bob, handle.vaultId, TransferAcceptRequest(offerId, wrapped, acceptProof))
        assertEquals(HttpStatusCode.OK, a1.status, a1.bodyAsText())
        val revAfterAccept = services.repo.db.read { services.repo.currentRev(it) }
        // Idempotent retry (lost response, IDENTICAL wrappedVk) → 200, still owner, and
        // TRULY read-only: no grant/vault rev churn (#8). Only a genuine self-heal re-wrap
        // (a different wrappedVk) would bump revs.
        assertEquals(HttpStatusCode.OK, client.transferAccept(bob, handle.vaultId, TransferAcceptRequest(offerId, wrapped, acceptProof)).status)
        assertEquals(revAfterAccept, services.repo.db.read { services.repo.currentRev(it) }, "idempotent accept retry must not churn revs")

        // Roles flipped atomically; the ex-owner keeps wrappedVk (R7: access continuous);
        // the new owner's grant carries the posted wrappedVk AND the RETAINED sealedVk
        // (the exactly-one rule is relaxed post-transfer — keyless-owner fallback).
        val bobGrant = client.sync(bob).grants.single { it.vaultId == handle.vaultId }
        assertEquals("owner", bobGrant.role)
        assertEquals(wrapped, bobGrant.wrappedVk)
        assertNotNull(bobGrant.sealedVk, "sealedVk retained as fallback key material")
        assertTrue(bob.openOwnGrant(handle.vaultId, bobGrant.wrappedVk).contentEquals(handle.vk))
        val ownerGrant = client.sync(owner).grants.single { it.vaultId == handle.vaultId }
        assertEquals("writer", ownerGrant.role)
        assertTrue(owner.openOwnGrant(handle.vaultId, ownerGrant.wrappedVk).contentEquals(handle.vk))

        // lastTransfer is delivered (seq-chained acceptProof for member verification);
        // pending cleared.
        val vaultRow = client.sync(owner).vaults.single { it.vaultId == handle.vaultId }
        assertNull(vaultRow.pendingTransfer)
        val record = vaultRow.lastTransfer
        assertNotNull(record)
        assertEquals(offerId, record.offerId)
        assertEquals(bob.userId, record.newOwnerUserId)
        assertEquals(1L, record.seq)
        assertEquals(acceptProof, record.acceptProof)
        // #3: wrapHash = hexLower(sha256(utf8(new owner's stored wrappedVk))) — the exact
        // binding the accept-proof domain needs. The ex-owner (a member holding VK) verifies
        // the acceptProof from ONLY the delivered wrapHash, so a server-side wrap swap or
        // role rewrite is detectable by every keyholder without ever seeing the wrappedVk.
        assertNotNull(record.wrapHash)
        assertEquals(sha256HexUtf8(wrapped), record.wrapHash)
        assertTrue(
            owner.verifyAcceptProofFromWrapHash(handle.vaultId, handle.vk, record.offerId, record.newOwnerUserId, record.seq, record.wrapHash!!, record.acceptProof),
            "another member verifies the accept-proof from wrapHash under its held VK",
        )

        // Powers flipped: ex-owner is a legitimate writer (can push), cannot manage.
        val it2 = owner.newItemId()
        assertEquals("applied", client.push(owner, Mutation(uuid(), "put", it2, handle.vaultId, 0, owner.encItemIn(handle.vaultId, handle.vk, it2, """{"name":"still-writer"}"""))).results[0].status)
        assertEquals(HttpStatusCode.Forbidden, client.removeMember(owner, handle.vaultId, bob.userId).status)
        // New owner manages members (rename works too — separate test).
        val carol = client.enrollSecond(owner, "carol@x.com", "carol transfer password tre")
        assertEquals(HttpStatusCode.Created, client.addMember(bob, handle, carol, "reader").status)
        assertTrue(client.auditRows(owner, "vault_transfer_accept").any { it.meta == "${handle.vaultId}:${owner.userId}:${bob.userId}" })
    }

    // ---- TRANSFER: cancel/decline, cleared on member ops, grant-predates-offer belt ----

    @Test
    fun transfer_cancelDecline_clearedOnMemberOps_andPredatesOfferBelt() = testApplication {
        val services = buildServices(config(), Notifier())
        application { andvariModule(services) }
        val client = jsonClient(this)
        val owner = VirtualClient("owner@x.com", "owner cancel password one", fast = true)
        client.register(owner, bootstrapToken)
        val bob = client.enrollSecond(owner, "bob@x.com", "bob cancel password two")

        val (createReq, handle) = owner.buildCreateSharedVault()
        client.createVault(owner, createReq)
        client.addMember(owner, handle, bob, "writer")
        val bobVk = client.openMemberVk(bob, handle.vaultId)

        // Owner cancel.
        client.offerWithProof(owner, handle, bob, seq = 1)
        assertEquals(HttpStatusCode.OK, client.transferCancel(owner, handle.vaultId).status)
        // cancel-retry → idempotent 200 (nothing pending).
        assertEquals(HttpStatusCode.OK, client.transferCancel(owner, handle.vaultId).status)
        assertNull(client.sync(bob).vaults.single { it.vaultId == handle.vaultId }.pendingTransfer)

        // Target decline.
        val (o2, _, _) = client.offerWithProof(owner, handle, bob, seq = 1)
        assertEquals(HttpStatusCode.OK, client.transferCancel(bob, handle.vaultId).status)
        // accept-vs-cancel: a late accept re-checks in-tx → transfer_not_pending.
        val wrapped = bob.wrapVkUnderOwnUvk(handle.vaultId, bobVk)
        val lateAccept = client.transferAccept(bob, handle.vaultId, TransferAcceptRequest(o2, wrapped, bob.mintAcceptProof(handle.vaultId, bobVk, o2, bob.userId, 1, wrapped)))
        assertEquals(HttpStatusCode.Conflict, lateAccept.status)
        assertEquals("transfer_not_pending", errorOf(lateAccept))

        // Role-changing the target clears the pending offer.
        client.offerWithProof(owner, handle, bob, seq = 1)
        client.put("/api/v1/vaults/${handle.vaultId}/members/${bob.userId}") {
            authed(owner); contentType(ContentType.Application.Json)
            setBody(io.silencelen.andvari.core.model.VaultMemberRole("reader"))
        }
        assertNull(client.sync(bob).vaults.single { it.vaultId == handle.vaultId }.pendingTransfer)

        // Removing the target clears it too.
        client.put("/api/v1/vaults/${handle.vaultId}/members/${bob.userId}") {
            authed(owner); contentType(ContentType.Application.Json)
            setBody(io.silencelen.andvari.core.model.VaultMemberRole("writer"))
        }
        val (o4, _, _) = client.offerWithProof(owner, handle, bob, seq = 1)
        client.removeMember(owner, handle.vaultId, bob.userId)
        assertNull(client.sync(owner).vaults.single { it.vaultId == handle.vaultId }.pendingTransfer)

        // Belt: re-add bob, then resurrect the OLD pending fields directly in the DB
        // (simulating a pending that somehow survived a remove→re-add) — accept must
        // refuse because the grant's addedAt postdates pendingOfferSetAt.
        client.addMember(owner, handle, bob, "writer")
        val bobVk2 = client.openMemberVk(bob, handle.vaultId)
        services.repo.db.tx { c ->
            c.exec(
                "UPDATE vaults SET pendingOwnerId=?, pendingOfferId=?, pendingOfferProof='x', pendingOfferExpiresAt=?, pendingOfferSetAt=? WHERE vaultId=?",
                bob.userId, o4, now() + 7 * Service.DAY_MS, now() - 60 * 60_000, handle.vaultId,
            )
        }
        val wrapped2 = bob.wrapVkUnderOwnUvk(handle.vaultId, bobVk2)
        val beltAccept = client.transferAccept(bob, handle.vaultId, TransferAcceptRequest(o4, wrapped2, bob.mintAcceptProof(handle.vaultId, bobVk2, o4, bob.userId, 1, wrapped2)))
        assertEquals(HttpStatusCode.Conflict, beltAccept.status)
        assertEquals("transfer_not_pending", errorOf(beltAccept))

        // Target leaving clears a pending offer (fresh offer first).
        services.repo.db.tx { c -> c.exec("UPDATE vaults SET pendingOwnerId=NULL, pendingOfferId=NULL, pendingOfferProof=NULL, pendingOfferExpiresAt=NULL, pendingOfferSetAt=NULL WHERE vaultId=?", handle.vaultId) }
        client.offerWithProof(owner, handle, bob, seq = 1)
        client.vaultLeave(bob, handle.vaultId)
        assertNull(client.sync(owner).vaults.single { it.vaultId == handle.vaultId }.pendingTransfer)
        assertTrue(client.auditRows(owner, "vault_transfer_cancel").any { it.meta == "${handle.vaultId}:target_left" })

        // Offer validation: target must be an active member, not self, sane expiry.
        val eve = client.enrollSecond(owner, "eve@x.com", "eve cancel password tre")
        val badTarget = client.transferOffer(owner, handle.vaultId, TransferOfferRequest(eve.userId, uuid(), now() + Service.DAY_MS, owner.mintDeleteProof(handle.vaultId, handle.vk, uuid())))
        assertEquals(HttpStatusCode.NotFound, badTarget.status)
        assertEquals("not_a_member", errorOf(badTarget))
        val selfOffer = client.transferOffer(owner, handle.vaultId, TransferOfferRequest(owner.userId, uuid(), now() + Service.DAY_MS, "cHJvb2Y"))
        assertEquals(HttpStatusCode.BadRequest, selfOffer.status)
        val staleExpiry = client.transferOffer(owner, handle.vaultId, TransferOfferRequest(bob.userId, uuid(), now() - 1000, "cHJvb2Y"))
        assertEquals(HttpStatusCode.BadRequest, staleExpiry.status)
        assertEquals("bad_expiry", errorOf(staleExpiry))
    }

    // ---- janitor: transfer-offer expiry (accept-vs-expire) ----

    @Test
    fun janitor_expiresTransferOffers_acceptAfterExpiryRefused() = testApplication {
        val services = buildServices(config(), Notifier())
        application { andvariModule(services) }
        val client = jsonClient(this)
        val owner = VirtualClient("owner@x.com", "owner expire password one", fast = true)
        client.register(owner, bootstrapToken)
        val bob = client.enrollSecond(owner, "bob@x.com", "bob expire password two")

        val (createReq, handle) = owner.buildCreateSharedVault()
        client.createVault(owner, createReq)
        client.addMember(owner, handle, bob, "writer")
        val bobVk = client.openMemberVk(bob, handle.vaultId)
        val (offerId, _, _) = client.offerWithProof(owner, handle, bob, seq = 1)

        // Sweep before expiry: nothing happens.
        assertTrue(services.janitor.sweep(now()).expiredOffers.isEmpty())
        // Sweep past the 14d TTL: offer expires, vault rev bumps (banner clears), audited.
        val res = services.janitor.sweep(now() + 15 * Service.DAY_MS)
        assertEquals(listOf(handle.vaultId), res.expiredOffers)
        assertNull(client.sync(bob).vaults.single { it.vaultId == handle.vaultId }.pendingTransfer)
        assertTrue(client.auditRows(owner, "vault_transfer_expire").any { it.meta == "${handle.vaultId}:${bob.userId}" })

        // accept-vs-expire: the late accept re-checks in-tx → transfer_not_pending.
        val wrapped = bob.wrapVkUnderOwnUvk(handle.vaultId, bobVk)
        val late = client.transferAccept(bob, handle.vaultId, TransferAcceptRequest(offerId, wrapped, bob.mintAcceptProof(handle.vaultId, bobVk, offerId, bob.userId, 1, wrapped)))
        assertEquals(HttpStatusCode.Conflict, late.status)
        assertEquals("transfer_not_pending", errorOf(late))
    }

    // ---- RENAME: metaBlob rewrite, stale guard, size cap, authz ----

    @Test
    fun rename_updatesMetaBlob_staleGuard_sizeCap_authz() = testApplication {
        val services = buildServices(config(), Notifier())
        application { andvariModule(services) }
        val client = jsonClient(this)
        val owner = VirtualClient("owner@x.com", "owner rename password one", fast = true)
        client.register(owner, bootstrapToken)
        val bob = client.enrollSecond(owner, "bob@x.com", "bob rename password two")

        val (createReq, handle) = owner.buildCreateSharedVault()
        client.createVault(owner, createReq)
        client.addMember(owner, handle, bob, "writer")
        val baseRev = client.sync(owner).vaults.single { it.vaultId == handle.vaultId }.rev

        val renamed = owner.sealVaultMeta(handle.vaultId, handle.vk, """{"name":"Family","metaV":2}""")
        val r1 = client.putVaultMeta(owner, handle.vaultId, VaultMetaUpdateRequest(renamed, baseRev))
        assertEquals(HttpStatusCode.OK, r1.status, r1.bodyAsText())

        // Every member re-receives the vault row and re-decrypts the new name (zero client change).
        val bobVk = client.openMemberVk(bob, handle.vaultId)
        val delivered = client.sync(bob).vaults.single { it.vaultId == handle.vaultId }
        assertTrue(bob.openVaultMeta(handle.vaultId, bobVk, delivered.metaBlob).contains("Family"))

        // Stale tab: baseVaultRev below the current rev → 409 stale_meta, no silent LWW.
        val stale = client.putVaultMeta(owner, handle.vaultId, VaultMetaUpdateRequest(renamed, baseRev))
        assertEquals(HttpStatusCode.Conflict, stale.status)
        assertEquals("stale_meta", errorOf(stale))
        // Without the optional guard the write is accepted (retry-twice semantics).
        assertEquals(HttpStatusCode.OK, client.putVaultMeta(owner, handle.vaultId, VaultMetaUpdateRequest(renamed)).status)

        // Size cap ≤ 4 KiB b64; non-owner → 403; audit is ids-only.
        assertEquals(HttpStatusCode.BadRequest, client.putVaultMeta(owner, handle.vaultId, VaultMetaUpdateRequest("A".repeat(9000))).status)
        assertEquals(HttpStatusCode.Forbidden, client.putVaultMeta(bob, handle.vaultId, VaultMetaUpdateRequest(renamed)).status)
        assertTrue(client.auditRows(owner, "vault_rename").all { it.meta == handle.vaultId })
    }

    // ---- §4 matrix: push-vs-delete (denied + `deleted:` audit prefix, never a throw) ----

    @Test
    fun race_pushVsDelete_perMutationDeniedWithDeletedPrefix() = testApplication {
        val services = buildServices(config(), Notifier())
        application { andvariModule(services) }
        val client = jsonClient(this)
        val owner = VirtualClient("owner@x.com", "owner pushrace password one", fast = true)
        client.register(owner, bootstrapToken)
        val bob = client.enrollSecond(owner, "bob@x.com", "bob pushrace password two")

        val (createReq, handle) = owner.buildCreateSharedVault()
        client.createVault(owner, createReq)
        client.addMember(owner, handle, bob, "writer")
        val bobVk = client.openMemberVk(bob, handle.vaultId)
        client.deleteWithProof(owner, handle)

        // The queued edit lands AFTER the delete: per-mutation denied inside a 200 push —
        // the batch is never thrown, so old clients dequeue instead of wedging.
        val itemId = bob.newItemId()
        val resp = client.push(bob, Mutation(uuid(), "put", itemId, handle.vaultId, 0, bob.encItemIn(handle.vaultId, bobVk, itemId, """{"name":"late"}""")))
        assertEquals("denied", resp.results[0].status)
        // Lifecycle fallout is excluded from intrusion review by the `deleted:` meta prefix.
        assertTrue(client.auditRows(owner, "push_denied").any { it.meta == "deleted:${handle.vaultId}:$itemId" })
    }

    // ---- §4 matrix: attachment-upload-vs-delete (the in-tx grantRole re-check) ----

    @Test
    fun race_attachmentUploadVsDelete_refusedInCommitTx() = testApplication {
        val services = buildServices(config(), Notifier())
        application { andvariModule(services) }
        val client = jsonClient(this)
        val owner = VirtualClient("owner@x.com", "owner attrace password one", fast = true)
        client.register(owner, bootstrapToken)
        val bob = client.enrollSecond(owner, "bob@x.com", "bob attrace password two")

        val (createReq, handle) = owner.buildCreateSharedVault()
        client.createVault(owner, createReq)
        client.addMember(owner, handle, bob, "writer")
        client.deleteWithProof(owner, handle)

        // Call the store DIRECTLY (bypassing the route pre-check) — this models a body
        // that finished streaming after the delete revoked the grant. The commit tx
        // re-checks grantRole and refuses: no post-revocation ciphertext lands.
        val attId = uuid()
        val body = ByteArray(64) { 1 } // header(24) + >STREAM_ABYTES ciphertext
        val thrown = runCatching {
            services.service.attachments.store(bob.userId, attId, bob.newItemId(), handle.vaultId, ByteReadChannel(body), services.service.policy())
        }.exceptionOrNull()
        assertTrue(thrown is Forbidden && thrown.reason == "no_grant", "expected in-tx no_grant, got $thrown")
        assertFalse(services.service.attachments.file(attId).isFile, "no blob file committed")
        assertNull(services.repo.db.read { c -> services.service.attachments.rowById(c, attId) }, "no row committed")
    }

    // ---- §4 matrix: add-member-vs-delete, rename-vs-delete, offer-after-delete ----

    @Test
    fun race_memberOpsAfterDelete_refusedPerMatrix() = testApplication {
        val services = buildServices(config(), Notifier())
        application { andvariModule(services) }
        val client = jsonClient(this)
        val owner = VirtualClient("owner@x.com", "owner oprace password one", fast = true)
        client.register(owner, bootstrapToken)
        val bob = client.enrollSecond(owner, "bob@x.com", "bob oprace password two")
        val carol = client.enrollSecond(owner, "carol@x.com", "carol oprace password tre")

        val (createReq, handle) = owner.buildCreateSharedVault()
        client.createVault(owner, createReq)
        client.addMember(owner, handle, bob, "writer")
        client.deleteWithProof(owner, handle)

        // add-member-vs-delete: the ex-owner's grant is revoked → requireOwnerOfShared 403.
        assertEquals(HttpStatusCode.Forbidden, client.addMember(owner, handle, carol, "writer").status)
        // rename-vs-delete: same guard → 403 (design matrix pins 403, not vault_deleted).
        assertEquals(HttpStatusCode.Forbidden, client.putVaultMeta(owner, handle.vaultId, VaultMetaUpdateRequest(owner.sealVaultMeta(handle.vaultId, handle.vk, """{"name":"x"}"""))).status)
        // offer-after-delete: grant-holders get the deleted special case (409 vault_deleted)…
        val offer = client.transferOffer(owner, handle.vaultId, TransferOfferRequest(bob.userId, uuid(), now() + Service.DAY_MS, "cHJvb2Y"))
        assertEquals(HttpStatusCode.Conflict, offer.status)
        assertEquals("vault_deleted", errorOf(offer))
        // …while true outsiders get the uniform 403 (no tombstone existence oracle).
        val outsider = client.transferOffer(carol, handle.vaultId, TransferOfferRequest(bob.userId, uuid(), now() + Service.DAY_MS, "cHJvb2Y"))
        assertEquals(HttpStatusCode.Forbidden, outsider.status)
        assertEquals("not_vault_owner", errorOf(outsider))
    }

    // ---- janitor purge: skeletal tombstones, key blanking, no rev bump, file unlink ----

    @Test
    fun janitor_purge_skeletalTombstones_blanksAllKeyMaterial_noRevBump() = testApplication {
        val services = buildServices(config(), Notifier())
        application { andvariModule(services) }
        val client = jsonClient(this)
        val owner = VirtualClient("owner@x.com", "owner purge password one", fast = true)
        client.register(owner, bootstrapToken)
        val bob = client.enrollSecond(owner, "bob@x.com", "bob purge password two")
        val carol = client.enrollSecond(owner, "carol@x.com", "carol purge password tre")

        val (createReq, handle) = owner.buildCreateSharedVault()
        client.createVault(owner, createReq)
        client.addMember(owner, handle, bob, "writer")
        client.addMember(owner, handle, carol, "writer")
        // carol removed pre-delete: her blanked sealedVk is the "previously-revoked" case.
        client.removeMember(owner, handle.vaultId, carol.userId)

        // An item with an attachment + an archived version (overwrite) — all must purge.
        val itemId = owner.newItemId()
        val attId = uuid()
        assertEquals(HttpStatusCode.OK, client.uploadAttachment(owner, attId, itemId, ByteArray(64) { 1 }, handle.vaultId).status)
        val p1 = client.push(owner, Mutation(uuid(), "put", itemId, handle.vaultId, 0, owner.encItemIn(handle.vaultId, handle.vk, itemId, """{"name":"v1"}""").copy(attachmentIds = listOf(attId))))
        client.push(owner, Mutation(uuid(), "put", itemId, handle.vaultId, p1.results[0].newItemRev!!, owner.encItemIn(handle.vaultId, handle.vk, itemId, """{"name":"v2"}""").copy(attachmentIds = listOf(attId))))
        assertTrue(services.service.attachments.file(attId).isFile)

        client.deleteWithProof(owner, handle)
        val revBefore = services.repo.db.read { services.repo.currentRev(it) }

        // Not yet due → sweep is a no-op. Due (grace passed) → purge.
        assertTrue(services.janitor.sweep(now()).purgedVaults.isEmpty())
        assertEquals(listOf(handle.vaultId), services.janitor.sweep(now() + 8 * Service.DAY_MS).purgedVaults)
        // Purge retry: already stamped → no double purge.
        assertTrue(services.janitor.sweep(now() + 9 * Service.DAY_MS).purgedVaults.isEmpty())

        services.repo.db.read { c ->
            // Item rows reduced to permanent skeletal tombstones — retained, ciphertext-free.
            val item = c.queryOne("SELECT deleted, blob, blobSize, attachmentIds FROM items WHERE itemId=?", itemId) { rs ->
                listOf(rs.getInt(1).toString(), rs.getString(2) ?: "NULL", rs.getLong(3).toString(), rs.getString(4))
            }!!
            assertEquals(listOf("1", "NULL", "0", "[]"), item)
            // item_versions + attachment rows destroyed.
            assertEquals(0, c.queryOne("SELECT COUNT(*) FROM item_versions WHERE itemId=?", itemId) { it.getInt(1) })
            assertEquals(0, c.queryOne("SELECT COUNT(*) FROM attachments WHERE vaultId=?", handle.vaultId) { it.getInt(1) })
            // ALL grants' key material blanked — active-at-delete AND previously-revoked:
            // wrappedVk='' (the NOT NULL sentinel), sealedVk=NULL. Rows retained.
            val grants = c.queryAll("SELECT wrappedVk, sealedVk FROM grants WHERE vaultId=?", handle.vaultId) { rs ->
                rs.getString(1) to rs.getString(2)
            }
            assertEquals(3, grants.size, "grant rows retained forever")
            assertTrue(grants.all { it.first == "" && it.second == null })
            // Vault tombstone: metaBlob blanked, purgedAt stamped, row retained.
            val v = c.queryOne("SELECT metaBlob, purgedAt FROM vaults WHERE vaultId=?", handle.vaultId) { rs ->
                rs.getString(1) to rs.getLong(2)
            }!!
            assertEquals("", v.first)
            assertTrue(v.second > 0)
        }
        // NO rev bump: purge is invisible to sync (revoked members receive nothing).
        assertEquals(revBefore, services.repo.db.read { services.repo.currentRev(it) })
        // Blob file unlinked post-commit.
        assertFalse(services.service.attachments.file(attId).isFile)
        // Audited with userId=null (machine action).
        assertTrue(client.auditRows(owner, "vault_purge").any { it.meta == handle.vaultId && it.userId == null })
        // vaultId never recycled: re-creating it is refused (AD binding + dedup depend on it).
        val recreate = client.createVault(owner, io.silencelen.andvari.core.model.CreateVaultRequest(handle.vaultId, createReq.metaBlob, createReq.wrappedVk))
        assertEquals(HttpStatusCode.BadRequest, recreate.status)
        assertEquals("vault_id_taken", errorOf(recreate))
        // Restore past grace → 410 vault_gone.
        val gone = client.vaultRestore(owner, handle.vaultId, uuid(), owner.mintRestoreProof(handle.vaultId, handle.vk, uuid()))
        assertEquals(HttpStatusCode.Gone, gone.status)
        assertEquals("vault_gone", errorOf(gone))
    }

    // ---- (d) MSI-shaped: edit-after-purge hits the skeletal vault_mismatch fence ----

    @Test
    fun msiShaped_editAfterPurge_deniedBySkeletalFence_neverResurrected() = testApplication {
        val services = buildServices(config(), Notifier())
        application { andvariModule(services) }
        val client = jsonClient(this)
        val owner = VirtualClient("owner@x.com", "owner msi password one", fast = true)
        client.register(owner, bootstrapToken)

        val (createReq, handle) = owner.buildCreateSharedVault()
        client.createVault(owner, createReq)
        val itemId = owner.newItemId()
        client.push(owner, Mutation(uuid(), "put", itemId, handle.vaultId, 0, owner.encItemIn(handle.vaultId, handle.vk, itemId, """{"name":"shared-secret"}""")))

        client.deleteWithProof(owner, handle)
        assertEquals(listOf(handle.vaultId), services.janitor.sweep(now() + 8 * Service.DAY_MS).purgedVaults)

        // The 0.2.x MSI re-encrypts a stale shared item under the PERSONAL vault and
        // pushes it weeks later. The skeletal row keeps `existing != null` forever, so
        // the vault_mismatch fence fires: per-mutation denied, item NEVER re-INSERTed
        // into the personal vault (the resurrection hole stays closed by retained rows).
        val teleport = Mutation(uuid(), "put", itemId, owner.personalVaultId, 0, owner.encItem(itemId, """{"name":"resurrected"}"""))
        assertEquals("denied", client.push(owner, teleport).results[0].status)
        assertTrue(client.auditRows(owner, "push_denied").any { it.meta == "vault_mismatch:${owner.personalVaultId}:$itemId" })
        assertTrue(client.sync(owner).items.none { it.itemId == itemId }, "skeletal tombstone never delivered, never resurrected")

        // Same stale session pushing with the TRUE vaultId: no grant → denied with the
        // deleted: prefix (routine lifecycle fallout, not an intrusion event).
        val direct = Mutation(uuid(), "put", itemId, handle.vaultId, 0, owner.encItemIn(handle.vaultId, handle.vk, itemId, """{"name":"still-there?"}"""))
        assertEquals("denied", client.push(owner, direct).results[0].status)
        assertTrue(client.auditRows(owner, "push_denied").any { it.meta == "deleted:${handle.vaultId}:$itemId" })
        // The skeletal row is still ciphertext-free.
        services.repo.db.read { c ->
            assertNull(c.queryOne("SELECT blob FROM items WHERE itemId=?", itemId) { it.getString(1) })
        }
    }

    // ---- janitor: restore-vs-purge fence + dry-run mode ----

    @Test
    fun janitor_restoreVsPurgeFence_andDryRun() = testApplication {
        val services = buildServices(config(), Notifier())
        application { andvariModule(services) }
        val client = jsonClient(this)
        val owner = VirtualClient("owner@x.com", "owner fence password one", fast = true)
        client.register(owner, bootstrapToken)

        val (createReq, handle) = owner.buildCreateSharedVault()
        client.createVault(owner, createReq)
        val itemId = owner.newItemId()
        client.push(owner, Mutation(uuid(), "put", itemId, handle.vaultId, 0, owner.encItemIn(handle.vaultId, handle.vk, itemId, """{"name":"keep"}""")))
        val (deleteId, _) = client.deleteWithProof(owner, handle)

        // Restore wins, then the fence: purgeVault re-checks deletedAt/purgeAt IN-TX and
        // must skip a restored vault even when handed a stale "due" verdict.
        assertEquals(HttpStatusCode.OK, client.vaultRestore(owner, handle.vaultId, deleteId, owner.mintRestoreProof(handle.vaultId, handle.vk, deleteId)).status)
        assertFalse(services.janitor.purgeVault(handle.vaultId, now() + 8 * Service.DAY_MS), "fence skips the restored vault")
        services.repo.db.read { c ->
            assertNotNull(c.queryOne("SELECT blob FROM items WHERE itemId=?", itemId) { it.getString(1) }, "ciphertext intact")
        }

        // Dry-run: a due vault is logged, not purged; a due offer is logged, not expired.
        val dryServices = buildServices(config(janitorDryRun = true), Notifier())
        // (fresh DB) — register + delete a vault there, then sweep past grace.
        testDryRun(dryServices)
    }

    private fun testDryRun(services: Services) = kotlinx.coroutines.runBlocking {
        val repo = services.repo
        // Minimal direct fixture: a shared vault row + one grant, already tombstoned.
        val vaultId = uuid()
        repo.db.tx { c ->
            val vr = repo.nextRev(c, "vault", vaultId, vaultId)
            c.exec(
                "INSERT INTO vaults(vaultId,type,rev,metaBlob,createdAt,deletedAt,purgeAt,deleteId) VALUES(?,?,?,?,?,?,?,?)",
                vaultId, "shared", vr, "bWV0YQ", now(), now() - 8 * Service.DAY_MS, now() - Service.DAY_MS, uuid(),
            )
        }
        val res = services.janitor.sweep(now())
        assertTrue(res.dryRun)
        assertTrue(res.purgedVaults.isEmpty(), "dry-run destroys nothing")
        repo.db.read { c ->
            assertNull(c.queryOne("SELECT purgedAt FROM vaults WHERE vaultId=?", vaultId) { rs -> rs.getLong(1).let { if (rs.wasNull()) null else it } })
        }
    }

    // ---- (c) public break-glass origin refuses EVERY §10/§11 route (incl. the F23 GET) ----

    @Test
    fun publicOrigin_refusesEverySharingAndLifecycleRoute() = testApplication {
        val public = "andvari.example.com"
        application { andvariModule(buildServices(config(publicHostname = public), Notifier())) }
        val client = jsonClient(this)
        val owner = VirtualClient("owner@x.com", "owner public password one", fast = true)
        client.register(owner, bootstrapToken)
        val v = uuid(); val u = uuid()

        data class Route(val name: String, val call: suspend () -> io.ktor.client.statement.HttpResponse)
        val routes = listOf(
            // §10 sharing (the members GET is the F23 patch — it used to be missing).
            Route("POST /vaults") { client.post("/api/v1/vaults") { authed(owner); header("Host", public); contentType(ContentType.Application.Json); setBody(owner.buildCreateSharedVault().first) } },
            Route("POST /users/lookup") { client.post("/api/v1/users/lookup") { authed(owner); header("Host", public); contentType(ContentType.Application.Json); setBody(io.silencelen.andvari.core.model.UserLookupRequest("a@x.com")) } },
            Route("GET /vaults/{id}/members (F23)") { client.get("/api/v1/vaults/$v/members") { authed(owner); header("Host", public) } },
            Route("POST /vaults/{id}/members") { client.post("/api/v1/vaults/$v/members") { authed(owner); header("Host", public); contentType(ContentType.Application.Json); setBody(io.silencelen.andvari.core.model.VaultMemberAdd(u, "reader", "c2Vhb")) } },
            Route("PUT /vaults/{id}/members/{u}") { client.put("/api/v1/vaults/$v/members/$u") { authed(owner); header("Host", public); contentType(ContentType.Application.Json); setBody(io.silencelen.andvari.core.model.VaultMemberRole("reader")) } },
            Route("DELETE /vaults/{id}/members/{u}") { client.delete("/api/v1/vaults/$v/members/$u") { authed(owner); header("Host", public) } },
            // §11 lifecycle.
            Route("POST delete") { client.post("/api/v1/vaults/$v/delete") { authed(owner); header("Host", public); contentType(ContentType.Application.Json); setBody(io.silencelen.andvari.core.model.VaultDeleteRequest(uuid(), "cHJvb2Y")) } },
            Route("POST restore") { client.post("/api/v1/vaults/$v/restore") { authed(owner); header("Host", public); contentType(ContentType.Application.Json); setBody(io.silencelen.andvari.core.model.VaultRestoreRequest(uuid(), "cHJvb2Y")) } },
            Route("GET /vaults/deleted") { client.get("/api/v1/vaults/deleted") { authed(owner); header("Host", public) } },
            Route("POST leave") { client.post("/api/v1/vaults/$v/leave") { authed(owner); header("Host", public) } },
            Route("POST transfer") { client.post("/api/v1/vaults/$v/transfer") { authed(owner); header("Host", public); contentType(ContentType.Application.Json); setBody(TransferOfferRequest(u, uuid(), now() + Service.DAY_MS, "cHJvb2Y")) } },
            Route("DELETE transfer") { client.delete("/api/v1/vaults/$v/transfer") { authed(owner); header("Host", public) } },
            Route("POST transfer/accept") { client.post("/api/v1/vaults/$v/transfer/accept") { authed(owner); header("Host", public); contentType(ContentType.Application.Json); setBody(TransferAcceptRequest(uuid(), "d3JhcA", "cHJvb2Y")) } },
            Route("PUT meta") { client.put("/api/v1/vaults/$v/meta") { authed(owner); header("Host", public); contentType(ContentType.Application.Json); setBody(VaultMetaUpdateRequest("bWV0YQ")) } },
        )
        for (route in routes) {
            val resp = route.call()
            assertEquals(HttpStatusCode.Forbidden, resp.status, "${route.name}: expected public-origin refusal, got ${resp.status} ${resp.bodyAsText()}")
            assertEquals("sharing_public_disabled", errorOf(resp), route.name)
        }
    }

    // ---- rate buckets: restore is never blocked by the delete spree it undoes ----

    @Test
    fun rateBuckets_destructiveExhaustionDoesNotBlockRecovery() = testApplication {
        application { andvariModule(buildServices(config(), Notifier())) }
        val client = jsonClient(this)
        val owner = VirtualClient("owner@x.com", "owner bucket password one", fast = true)
        client.register(owner, bootstrapToken)

        val (createReq, handle) = owner.buildCreateSharedVault()
        client.createVault(owner, createReq)
        val (deleteId, _) = client.deleteWithProof(owner, handle)

        // Exhaust vault_destructive (10/h): the first delete + 9 idempotent replays.
        val proof = owner.mintDeleteProof(handle.vaultId, handle.vk, deleteId)
        repeat(9) { assertEquals(HttpStatusCode.OK, client.vaultDelete(owner, handle.vaultId, deleteId, proof).status) }
        val eleventh = client.vaultDelete(owner, handle.vaultId, deleteId, proof)
        assertEquals(HttpStatusCode.TooManyRequests, eleventh.status)

        // The undo still works: restore rides the separate vault_recovery bucket (30/h).
        val restore = client.vaultRestore(owner, handle.vaultId, deleteId, owner.mintRestoreProof(handle.vaultId, handle.vk, deleteId))
        assertEquals(HttpStatusCode.OK, restore.status, restore.bodyAsText())
    }

    // ---- members GET carries the additive account status (F22 rider) ----

    @Test
    fun memberSummary_carriesAccountStatus() = testApplication {
        application { andvariModule(buildServices(config(), Notifier())) }
        val client = jsonClient(this)
        val owner = VirtualClient("owner@x.com", "owner status password one", fast = true)
        client.register(owner, bootstrapToken)
        val bob = client.enrollSecond(owner, "bob@x.com", "bob status password two")

        val (createReq, handle) = owner.buildCreateSharedVault()
        client.createVault(owner, createReq)
        client.addMember(owner, handle, bob, "writer")

        val disable = client.post("/api/v1/admin/users/${bob.userId}/disable") { authed(owner) }
        assertEquals(HttpStatusCode.OK, disable.status, disable.bodyAsText())

        val resp = client.get("/api/v1/vaults/${handle.vaultId}/members") { authed(owner) }
        assertEquals(HttpStatusCode.OK, resp.status)
        val members = json.decodeFromString(
            kotlinx.serialization.builtins.ListSerializer(io.silencelen.andvari.core.model.VaultMemberSummary.serializer()),
            resp.bodyAsText(),
        )
        assertEquals("active", members.single { it.userId == owner.userId }.status)
        assertEquals("disabled", members.single { it.userId == bob.userId }.status)
    }

    // ---- v3 → v4 migration on a live-shaped DB: 16 additive ALTERs, idempotent ----

    @Test
    fun migration_v3ToV4_additiveAndIdempotent() {
        val dbFile = File(tmpDir, "v3fixture-${System.nanoTime()}.db")
        // Hand-build a v3-shaped DB: meta(schemaVersion=3), v1 vaults + items, v3 grants
        // (items because the v5 tombstone index is created on it).
        DriverManager.getConnection("jdbc:sqlite:${dbFile.absolutePath}").use { c ->
            c.createStatement().use { st ->
                st.executeUpdate("CREATE TABLE meta(key TEXT PRIMARY KEY, value TEXT NOT NULL)")
                st.executeUpdate("CREATE TABLE vaults(vaultId TEXT PRIMARY KEY, type TEXT NOT NULL, rev INTEGER NOT NULL, metaBlob TEXT NOT NULL, createdAt INTEGER NOT NULL)")
                st.executeUpdate(
                    """CREATE TABLE grants(vaultId TEXT NOT NULL, userId TEXT NOT NULL, role TEXT NOT NULL,
                       wrappedVk TEXT NOT NULL, rev INTEGER NOT NULL, revokedAt INTEGER, sealedVk TEXT, addedAt INTEGER, PRIMARY KEY(vaultId,userId))""",
                )
                st.executeUpdate(
                    """CREATE TABLE items(itemId TEXT PRIMARY KEY, vaultId TEXT NOT NULL, rev INTEGER NOT NULL,
                       createdAt INTEGER NOT NULL, updatedAt INTEGER NOT NULL, deleted INTEGER NOT NULL DEFAULT 0,
                       conflict INTEGER NOT NULL DEFAULT 0, formatVersion INTEGER NOT NULL,
                       attachmentIds TEXT NOT NULL DEFAULT '[]', blob TEXT, blobSize INTEGER NOT NULL DEFAULT 0)""",
                )
                st.executeUpdate("INSERT INTO vaults(vaultId,type,rev,metaBlob,createdAt) VALUES('v','shared',1,'m',1)")
                st.executeUpdate("INSERT INTO grants(vaultId,userId,role,wrappedVk,rev) VALUES('v','u','owner','wv',1)")
                st.executeUpdate("INSERT INTO meta(key,value) VALUES('schemaVersion','3')")
                st.executeUpdate("INSERT INTO meta(key,value) VALUES('oldestRetainedRev','0')")
            }
        }

        Db(dbFile.absolutePath).use { db ->
            db.read { c ->
                assertEquals("5", c.queryOne("SELECT value FROM meta WHERE key='schemaVersion'") { it.getString(1) })
                // Pre-v4 rows read back NULL lifecycle state, transferSeq=0.
                val v = c.queryOne("SELECT deletedAt, purgeAt, purgedAt, deleteId, transferSeq, pendingOfferId FROM vaults WHERE vaultId='v'") { rs ->
                    listOf(rs.getObject(1), rs.getObject(2), rs.getObject(3), rs.getObject(4), rs.getLong(5), rs.getObject(6))
                }!!
                assertEquals(listOf(null, null, null, null, 0L, null), v)
                assertNull(c.queryOne("SELECT revokedReason FROM grants WHERE userId='u'") { it.getString(1) })
                // The partial purge index exists; so does the v5 tombstone index (F56).
                assertNotNull(c.queryOne("SELECT name FROM sqlite_master WHERE type='index' AND name='idx_vaults_purge'") { it.getString(1) })
                assertNotNull(c.queryOne("SELECT name FROM sqlite_master WHERE type='index' AND name='idx_items_deleted_updated'") { it.getString(1) })
                // 410 machinery untouched.
                assertEquals("0", c.queryOne("SELECT value FROM meta WHERE key='oldestRetainedRev'") { it.getString(1) })
            }
        }
        // Re-opening is idempotent (already migrated — the ALTERs do not re-run).
        Db(dbFile.absolutePath).use { db ->
            assertEquals("5", db.read { c -> c.queryOne("SELECT value FROM meta WHERE key='schemaVersion'") { it.getString(1) } })
        }
    }
}
