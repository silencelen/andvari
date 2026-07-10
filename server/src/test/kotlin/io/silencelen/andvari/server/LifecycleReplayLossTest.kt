package io.silencelen.andvari.server

import io.ktor.server.testing.testApplication
import io.silencelen.andvari.core.client.Account
import io.silencelen.andvari.core.client.AndvariApi
import io.silencelen.andvari.core.client.InMemoryVaultCache
import io.silencelen.andvari.core.client.ItemDoc
import io.silencelen.andvari.core.client.SyncEngine
import io.silencelen.andvari.core.crypto.Bytes
import io.silencelen.andvari.core.crypto.Escrow
import io.silencelen.andvari.core.crypto.createCryptoProvider
import io.silencelen.andvari.core.model.VaultMemberAdd
import java.io.File
import java.nio.file.Files
import kotlin.test.AfterTest
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue

/**
 * **LC-1** (v5 recon, P2 — the one place the new lifecycle code introduced a LOSS path):
 * a re-delete during restore-replay must not destroy a member's parked offline edit.
 *
 * **The bug.** `flushQueue` took a fast path on any denial of a REPLAYED mutation —
 * `replayedMutationIds.remove(...)` → calm notice → `cache.dequeue(...)` — on the assumption that
 * a denial could only mean "the vault is live again and my role changed". A denial equally means
 * "the vault went in-grace AGAIN", and dropping it there destroyed the very edit F21's replay
 * exists to protect: it survived the first delete, then vanished on the second. Every denial now
 * STAGES instead, and `surfaceStagedDenials` takes the verdict from the vault's ACTUAL fate after
 * a fresh pull — held → re-park; live → durable drop (calm notice for a replay, thrown denial
 * otherwise). The decision moved from provenance (was it a replay?) to state (is the vault held?).
 *
 * **On coverage, honestly.** The loss needed a RACE: [SyncEngine] flushes immediately after a
 * reinstate (`if (reinstated.isNotEmpty()) runCatching { flushQueue() }`), so in any deterministic
 * ordering the replay lands while the vault is live. The window opened only when the owner
 * re-deleted between that reinstate and its flush, or when that flush failed (offline) and the
 * vault was deleted before the retry. Injecting either from `testApplication` needs a seam the
 * engine does not expose, so these tests do NOT reproduce the race. They pin the two behaviours the
 * fix now derives from vault state — which is exactly what closes the window, since no denial can
 * dequeue a mutation before a pull has re-established the vault's fate:
 *   1. a denial while the vault is HELD parks the edit, and a restore replays it end-to-end;
 *   2. a REPLAYED edit refused on a LIVE vault is dropped calmly, never thrown at the caller.
 */
class LifecycleReplayLossTest {
    private val crypto = createCryptoProvider()
    private val recovery = crypto.boxKeypairFromSeed(crypto.randomBytes(32))
    private val fingerprint = Escrow.fingerprint(crypto, recovery.publicKey)
    private val bootstrap = "lc1-bootstrap"
    private val tmp = Files.createTempDirectory("andvari-lc1").toFile()

    private fun config() = Config(
        host = "127.0.0.1", port = 0,
        dbPath = File(tmp, "lc1-${System.nanoTime()}.db").absolutePath,
        blobDir = File(tmp, "blobs").absolutePath, webDir = null,
        recoveryPublicKey = recovery.publicKey, recoveryFingerprint = fingerprint,
        enumSecret = ByteArray(32) { 7 }, publicHostname = null, bootstrapToken = bootstrap,
    )

    @AfterTest fun cleanup() { tmp.deleteRecursively() }

    private suspend fun enroll(api: AndvariApi, email: String, password: String, invite: String): Account {
        val policy = api.clientPolicy()
        val recoveryPub = Bytes.fromB64(api.recoveryPubkey())
        val (req, account) = Account.enroll(
            invite, email, email.substringBefore('@'), password,
            policy.kdfParams, recoveryPub, policy.recoveryFingerprint, "device", crypto,
        )
        api.register(req)
        return account
    }

    /** LC-1 (1): a denial while the vault is HELD parks the edit; a restore replays it. */
    @Test
    fun deniedEdit_isParkedWhileHeld_andReplaysOnRestore() = testApplication {
        val services = buildServices(config(), Notifier())
        application { andvariModule(services) }

        val apiOwner = AndvariApi("", createClient { })
        val owner = enroll(apiOwner, "own@lc1.com", "owner lifecycle password one", bootstrap)
        val engineOwner = SyncEngine(apiOwner, owner, InMemoryVaultCache())
        engineOwner.sync()

        val invite = services.admin.createInvite("kid@lc1.com", isAdmin = false, byUserId = owner.userId).second
        val apiMember = AndvariApi("", createClient { })
        val member = enroll(apiMember, "kid@lc1.com", "member lifecycle password two", invite)
        val cacheMember = InMemoryVaultCache()
        val engineMember = SyncEngine(apiMember, member, cacheMember)
        engineMember.sync()

        val nv = owner.buildCreateSharedVault("Family")
        apiOwner.createVault(nv.request)
        engineOwner.sync()
        engineOwner.save(null, ItemDoc(type = "login", name = "wifi"), vaultId = nv.vaultId)
        val info = apiOwner.lookupUser("kid@lc1.com")
        apiOwner.addVaultMember(
            nv.vaultId,
            VaultMemberAdd(member.userId, "writer", owner.wrapVkForMember(Bytes.fromB64(info.identityPub), nv.vaultId)),
        )
        engineMember.sync()
        val item = engineMember.items().single { it.doc.name == "wifi" }

        // Owner deletes; the member edits anyway — the write is denied, then PARKED (F21).
        engineOwner.deleteSharedVault(nv.vaultId)
        runCatching { engineMember.save(item.itemId, item.doc.copy(name = "wifi-edited-by-kid")) }
        engineMember.sync()
        val held = assertNotNull(cacheMember.getHeld(nv.vaultId), "the deleted vault moves to holding")
        assertEquals(1, held.parked.size, "F21: the member's offline edit is parked, never dropped")
        val parkedId = held.parked.single().mutationId

        // Owner restores: the parked edit replays with its ORIGINAL mutationId and lands.
        val deleted = engineOwner.listDeleted().single { it.vaultId == nv.vaultId }
        engineOwner.restoreSharedVault(nv.vaultId, deleted.deleteId)
        engineMember.sync()
        assertNull(cacheMember.getHeld(nv.vaultId), "restore clears the holding record")
        assertTrue(cacheMember.pending().none { it.mutationId == parkedId }, "the replay was pushed, not left queued")

        engineOwner.sync()
        assertTrue(
            engineOwner.items().any { it.doc.name == "wifi-edited-by-kid" },
            "the member's edit survived delete → restore and applied on replay",
        )
    }

    /**
     * LC-1 (2): a REPLAYED edit refused on a vault that is LIVE again — the member was demoted
     * across the grace window — drains into the calm "recovered edits refused" notice. It must be
     * dropped WITHOUT throwing at the caller (a first-hand denial still throws; a replay never
     * does). This is the branch the old fast-path served, and the fix must keep serving it now that
     * the verdict is taken in `surfaceStagedDenials`.
     */
    @Test
    fun replayedEdit_refusedOnLiveVault_isCalmlyDropped_notThrown() = testApplication {
        val services = buildServices(config(), Notifier())
        application { andvariModule(services) }

        val apiOwner = AndvariApi("", createClient { })
        val owner = enroll(apiOwner, "own2@lc1.com", "owner lifecycle password three", bootstrap)
        val engineOwner = SyncEngine(apiOwner, owner, InMemoryVaultCache())
        engineOwner.sync()

        val invite = services.admin.createInvite("kid2@lc1.com", isAdmin = false, byUserId = owner.userId).second
        val apiMember = AndvariApi("", createClient { })
        val member = enroll(apiMember, "kid2@lc1.com", "member lifecycle password four", invite)
        val cacheMember = InMemoryVaultCache()
        val engineMember = SyncEngine(apiMember, member, cacheMember)
        engineMember.sync()

        val nv = owner.buildCreateSharedVault("Family")
        apiOwner.createVault(nv.request)
        engineOwner.sync()
        engineOwner.save(null, ItemDoc(type = "login", name = "wifi"), vaultId = nv.vaultId)
        val info = apiOwner.lookupUser("kid2@lc1.com")
        val sealed = owner.wrapVkForMember(Bytes.fromB64(info.identityPub), nv.vaultId)
        apiOwner.addVaultMember(nv.vaultId, VaultMemberAdd(member.userId, "writer", sealed))
        engineMember.sync()
        val item = engineMember.items().single { it.doc.name == "wifi" }

        // Delete → the member's edit parks.
        engineOwner.deleteSharedVault(nv.vaultId)
        runCatching { engineMember.save(item.itemId, item.doc.copy(name = "wifi-edited-by-kid")) }
        engineMember.sync()
        val parkedId = assertNotNull(cacheMember.getHeld(nv.vaultId)).parked.single().mutationId

        // Restore, but demote the member to READER before they sync: the replay is refused on a
        // LIVE vault — a legitimate refusal, and a calm one (never an exception at the caller).
        val deleted = engineOwner.listDeleted().single { it.vaultId == nv.vaultId }
        engineOwner.restoreSharedVault(nv.vaultId, deleted.deleteId)
        apiOwner.setVaultMemberRole(nv.vaultId, member.userId, "reader")

        engineMember.sync() // MUST NOT throw: a refused REPLAY is a notice, not a caller-facing error
        engineMember.sync() // the classifying pull has now completed — the verdict settles

        assertNull(cacheMember.getHeld(nv.vaultId), "the vault is live again — nothing to hold")
        assertTrue(
            cacheMember.pending().none { it.mutationId == parkedId },
            "a replay refused on a live vault is durably dropped (calm notice), never retried forever",
        )
        engineOwner.sync()
        assertTrue(
            engineOwner.items().none { it.doc.name == "wifi-edited-by-kid" },
            "the demoted member's edit was correctly refused",
        )
    }
}
