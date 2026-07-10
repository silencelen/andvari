package io.silencelen.andvari.core.client

import io.silencelen.andvari.core.crypto.Attachments
import io.silencelen.andvari.core.crypto.Bytes
import io.silencelen.andvari.core.crypto.CryptoException
import io.silencelen.andvari.core.crypto.LifecycleProof
import io.silencelen.andvari.core.model.Mutation
import io.silencelen.andvari.core.model.PushRequest
import io.silencelen.andvari.core.model.PendingTransfer
import io.silencelen.andvari.core.model.RemovedGrantInfo
import io.silencelen.andvari.core.model.TransferAcceptRequest
import io.silencelen.andvari.core.model.TransferOfferRequest
import io.silencelen.andvari.core.model.VaultDeleteRequest
import io.silencelen.andvari.core.model.VaultMetaUpdateRequest
import io.silencelen.andvari.core.model.VaultRestoreRequest
import io.silencelen.andvari.core.model.WireItem
import io.silencelen.andvari.core.model.WireVault
import io.silencelen.andvari.core.model.WireGrant
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock

/** A newly attached file awaiting upload: the doc's AttachmentRef + plaintext bytes. */
class PendingUpload(val ref: AttachmentRef, val data: ByteArray)

/** A vault we hold the key for — for pickers, badges, and the sharing screens. */
data class VaultInfo(
    val vaultId: String,
    val type: String,
    val name: String,
    val role: String?,
)

/**
 * A lifecycle notice the UI renders (spec 03 §11 / design §11). Fired ONLY for vaults held
 * locally before the pull — never on since=0 / fresh-device pulls. Attribution ("by its
 * owner") is EARNED by a verified proof; unverified events get calm/anomaly wording.
 */
data class LifecycleNotice(
    val id: String,
    val vaultId: String,
    val vaultName: String,
    val kind: String, // deleted | removed | left | anomaly | restored | transfer-complete | transfer-anomaly
    /** verified delete: the server-erase deadline (for the "kept sealed until…" line). */
    val purgeAt: Long? = null,
    /** verified delete: N of the member's edits parked for replay on restore (F21). */
    val parkedCount: Int? = null,
    /** transfer-complete/-anomaly: who now owns the vault, and whether that is us. */
    val newOwnerUserId: String? = null,
    val becameMine: Boolean = false,
)

/** A restorable in-grace deleted vault (GET /vaults/deleted), name decrypted locally. */
data class DeletedVaultInfo(
    val vaultId: String,
    val name: String,
    val deletedAt: Long,
    val purgeAt: Long,
    val deleteId: String,
)

/** A verified incoming ownership offer TO this user — the accept consent screen renders
 *  only after the offer proof verifies under the held VK (spec 03 §11). */
data class IncomingTransfer(
    val vaultId: String,
    val vaultName: String,
    val offerId: String,
    val seq: Long,
    val expiresAt: Long,
)

/** One holding-area entry for the "Recently removed" surface (name re-derived, never stored). */
data class HeldVaultInfo(
    val vaultId: String,
    val name: String,
    val reason: String,
    val verified: Boolean,
    val purgeAt: Long?,
    val expungeAt: Long,
)

/** One attachment of a move/copy gesture: fresh id + fresh fileKey minted at gesture time. */
data class GestureAttachment(
    val oldId: String,
    val newId: String,
    val newFileKey: String,
    val name: String,
    val size: Long,
)

/** A move/copy gesture (F19, design §8). Minted ONCE (fresh newItemId + per-attachment fresh
 *  fileKeys); a RETRY of the SAME gesture converges via server mutation-dedup — never a fresh
 *  gesture, which would collide-or-duplicate. [sourceRev] is the rev of the content copied,
 *  so the delete leg's baseItemRev catches a source that changed mid-move. */
data class MoveGesture(
    val gestureId: String,
    val sourceItemId: String,
    val sourceVaultId: String,
    val sourceRev: Long,
    val targetVaultId: String,
    val newItemId: String,
    val del: Boolean, // true = move (copy then delete source); false = copy only
    val attachments: List<GestureAttachment>,
)

/** F19: the target vault denied the copy — source untouched, gesture aborted (design §8). */
class CopyDeniedException :
    ApiException(403, "copy_denied", "The copy to the target vault was denied — you may not have write access there.")

/** F19: the source changed since we read it — the move is aborted, nothing deleted (design §8). */
class ItemChangedException :
    ApiException(409, "item_changed", "This item changed while moving — review and retry.")

/**
 * Client sync engine (sibling of web/src/vault/store.ts). Pulls deltas since the
 * cursor, decrypts into the cache, materializes conflict copies client-side (the
 * server can't re-encrypt — spec 03 §5), and pushes mutations with stable ids. The
 * offline queue in [VaultCache] makes pushes crash-durable and retry-idempotent.
 *
 * 0.5.0 adds the shared-vault lifecycle (spec 03 §11): proof-verified tri-state
 * handling of removedGrants with a holding area (durable where the cache is), parked
 * denied mutations replayed on restore (F21), verified transfer offers/completions,
 * delete/restore/leave/transfer/rename actions, and the F19 move/copy gesture engine.
 */
class SyncEngine(
    private val api: AndvariApi,
    private val account: Account,
    private val cache: VaultCache,
) {
    private companion object {
        const val SERVER_BATCH_MAX = 200 // server rejects a push batch larger than this (Service.push)
        const val DAY_MS = 86_400_000L
    }

    // ---- vault lifecycle state (spec 03 §11); session-scoped — the durable halves
    // (holding area, consumed deleteIds, verified transfer seqs, STAGED-DENIED queue rows)
    // live in [VaultCache].
    /** Notices awaiting the UI banner. */
    private val noticeList = mutableListOf<LifecycleNotice>()
    /** Vaults this device just deleted/left — drop them cleanly on the reconcile pull (no
     *  banner). One-shot AND scoped to the action's own reconcile (removed in a finally
     *  there), so a failed reconcile can never leave a stale entry that would misread a
     *  LATER genuine removal as self-initiated and bypass the holding area. */
    private val suppressDrop = mutableSetOf<String>()

    /** One denied mutation awaiting its park-vs-genuine verdict. [stagedBefore] is the
     *  pull-start counter at staging time: only a pull that STARTED later may classify it.
     *  [wasReplay] marks an edit that was itself a restore-replay (F21), so a GENUINE denial
     *  of it drains into the calm "recovered edits refused" notice instead of throwing.
     *  Not durable: a restart reloads it as false (LC-1 comment on [hydrate]) — that costs a
     *  harsher notice at worst, never the edit. */
    private class StagedDenial(val mutation: Mutation, val stagedBefore: Long, val wasReplay: Boolean = false)

    /** Denied mutations staged between flush and the fresh pull that reveals their vault's
     *  fate (F21). In-memory INDEX only — the durable truth is the queue's staged-denied
     *  state ([VaultCache.markStagedDenied]), reloaded here by [hydrate] after a restart. */
    private val preParkedByVault = mutableMapOf<String, MutableList<StagedDenial>>()

    /**
     * Serializes every flush→pull→classify cycle. Without it, a concurrent caller's pull —
     * whose snapshot may PREDATE a vault's deletion — could classify another cycle's staged
     * denial as "genuine" off stale state and drop a parkable edit. The epoch guard below
     * ([pullStartCounter]/[freshestCompletedPullStart]) is the belt for the same hazard.
     */
    private val syncMutex = Mutex()
    /** Monotonic id handed to each pull as it STARTS. */
    private var pullStartCounter = 0L
    /** The largest start-id among COMPLETED pulls — "a pull started at X has finished". */
    private var freshestCompletedPullStart = 0L

    /** mutationIds re-enqueued by a reinstate replay: a denial of one of these on a LIVE
     *  vault is a calm one-time notice ("recovered edits couldn't be applied"), never a
     *  thrown sync failure — the member's role may simply have changed across the grace. */
    private val replayedMutationIds = mutableSetOf<String>()
    /** vaultId → count of replayed mutations denied this cycle (drained into a notice). */
    private val replayDeniedByVault = mutableMapOf<String, Int>()

    /** Verified incoming ownership offers TO us, recomputed every pull from vault rows. */
    private val incomingByVault = mutableMapOf<String, IncomingTransfer>()
    /** Bulk-copy gestures memoized per (source vault | item | target) so a RETRY after a
     *  mid-run failure reuses the SAME gestureId/newItemId/fileKeys (design §8). */
    private val bulkGestures = mutableMapOf<String, MoveGesture>()

    fun items(): List<VaultItem> = cache.allItems().sortedBy { it.doc.name.lowercase() }
    fun item(itemId: String): VaultItem? = cache.getItem(itemId)

    // ---- read-only cache pass-throughs (F82) ----
    // The spec 07 export planner and the F20 undecryptable-grant count enumerate raw wire
    // rows. Exposing them here keeps [cache] private — the natives used to carry the
    // engine's own cache instance for these reads, a close-ordering hazard.

    /** Persisted item envelopes (ciphertext rows), tombstones included. */
    fun envelopes(): List<WireItem> = cache.envelopes()

    /** Persisted vault rows as delivered — [vaultInfos] is the decrypted/filtered view. */
    fun vaultRows(): List<WireVault> = cache.vaults()

    /** Persisted grant rows as delivered, openable or not (a sealed grant still counts). */
    fun grants(): List<WireGrant> = cache.grants()

    /**
     * Guided importers (design 2026-07-09, amendment A8): the PERSONAL vault's light
     * projections for the vault-aware import plan — the one engine-owned entry point all
     * native clients use, so no call site ever maps raw item lists (the web twin is
     * `store.importProjections()`). Callers gate on the personal vault being present/
     * hydrated FIRST (refuse-not-degrade); an empty working set here plans as if the
     * vault were empty, which is only correct once that gate has passed.
     */
    fun importProjections(): CsvImport.ImportProjections =
        CsvImport.projections(items().filter { it.vaultId == account.personalVaultId }.map { it.doc })

    /**
     * Item history (feature): fetch this item's archived versions (server keeps the last 10) and
     * decrypt each under the held VK, newest rev first. Versions that don't decrypt — e.g. sealed
     * under a superseded VK after a rotation — are dropped (bounded history, resets at VK rotation;
     * see the design doc). Restore a chosen version with [save] — an ordinary put over the live item.
     */
    suspend fun itemVersions(itemId: String, vaultId: String): List<DecryptedItemVersion> =
        api.itemVersions(itemId).mapNotNull { v ->
            runCatching { DecryptedItemVersion(v.rev, v.archivedAt, account.decryptItemVersion(vaultId, itemId, v)) }.getOrNull()
        }

    /**
     * Item undelete (feature): the user's tombstoned items, each named from its last archived version
     * (a tombstone's own blob is null). doc=null when there's no readable version → surfaced unnamed
     * but restorable by identity. Restore a chosen one with [restoreDeleted].
     */
    suspend fun deletedItems(): List<DeletedItemView> =
        api.deletedItems().map { d ->
            val doc = runCatching {
                api.itemVersions(d.itemId).firstOrNull()?.let { account.decryptItemVersion(d.vaultId, d.itemId, it) }
            }.getOrNull()
            DeletedItemView(d.itemId, d.vaultId, d.deletedAt, doc)
        }

    /**
     * Item undelete (feature): restore a tombstoned item by re-encrypting the chosen doc under the
     * current VK and POSTing to the dedicated restore route, then sync so it reappears live. Attachment
     * refs are DROPPED — a deleted item's attachment blobs were hard-unlinked at tombstone (design doc).
     */
    suspend fun restoreDeleted(itemId: String, vaultId: String, doc: ItemDoc) {
        api.restoreItem(itemId, account.encryptItem(vaultId, itemId, doc.copy(attachments = emptyList())))
        sync()
    }

    /** Item undelete (F49): "Delete forever" — hard-delete a tombstoned item + its versions server-side. */
    suspend fun purgeDeleted(itemId: String) {
        api.purgeItem(itemId)
    }

    /** Vaults whose key we hold, personal first then shared by name (mirrors web vaults()). */
    fun vaultInfos(): List<VaultInfo> = cache.vaults()
        .filter { account.hasVault(it.vaultId) }
        .map { v ->
            val name = account.decryptVaultName(v.vaultId, v.metaBlob)
            VaultInfo(
                vaultId = v.vaultId,
                type = v.type,
                name = if (!name.isNullOrEmpty() && name != "(vault)") name else if (v.type == "personal") "Personal" else "Shared",
                role = account.roleFor(v.vaultId),
            )
        }
        .sortedWith(compareBy({ it.type != "personal" }, { it.name.lowercase() }))

    /**
     * Held envelopes this build cannot decrypt because their formatVersion is newer than
     * [Account.ITEM_FORMAT_VERSION] (fail-closed, spec 02 §3) — items that exist but
     * silently vanish from [items]. Excludes tombstones and vaults whose VK is missing
     * (those aren't an app-version problem). Drives the "N items need an app update"
     * banner on the native clients.
     */
    fun needsUpdateCount(): Int = cache.envelopes().count {
        !it.deleted && account.hasVault(it.vaultId) && it.formatVersion > Account.ITEM_FORMAT_VERSION
    }

    /**
     * Push any queued mutations first (crash recovery), then pull deltas, THEN surface
     * denied writes — a denied flush must never abort the pull that delivers
     * `removedGrants` (F21, spec 03 §4): the purge/notice and the denied verdict land in
     * ONE cycle, and denials whose vault the pull revealed as in-grace are PARKED
     * (replayable on restore), not surfaced as failures.
     *
     * The whole cycle is [syncMutex]-serialized: concurrent callers (the 5-min poll, a
     * user refresh, a save's reconcile) must never interleave, or one cycle's stale pull
     * could classify another cycle's staged denial (see [surfaceStagedDenials]).
     */
    suspend fun sync() = syncMutex.withLock {
        pruneHolding()
        flushQueue()
        pull()
        surfaceStagedDenials()
    }

    /**
     * Rebuild the account + decrypted working set from the durable cache — called once
     * after Account.unlock, before the first sync(). Grants/vaults are pull DELTAS
     * (spec 03 §4): once the cursor moved past them they never re-send, so cold start
     * MUST reconstruct keys purely from persisted rows. Undecryptable envelopes are
     * retried here on every launch (e.g. after an upgrade or a later-opened grant).
     */
    fun hydrate() {
        for (g in cache.grants()) {
            runCatching { account.addGrant(g) } // role applies unconditionally; key opens if missing
        }
        for (v in cache.vaults()) {
            if (v.type == "personal" && account.hasVault(v.vaultId)) account.setPersonalVault(v.vaultId)
        }
        for (w in cache.envelopes()) {
            if (w.deleted || !account.hasVault(w.vaultId)) continue
            runCatching {
                cache.upsertItem(w, VaultItem(w.itemId, w.vaultId, w.rev, w.updatedAt, account.decryptItem(w)))
            }
        }
        // Reload durably staged denials (F21): a process death between a denial and the
        // pull that classifies it must not destroy the edit. stagedBefore=0 → the first
        // completed pull after this restart is fresh enough to classify them.
        // LC-1: `wasReplay` is an in-memory nicety (it only picks the NOTICE wording for a
        // genuine refusal), so reloading it as false is safe — the park-vs-drop verdict is
        // taken from the vault's held state, never from this flag. Worst case after a crash:
        // a recovered edit refused on a live vault surfaces as a normal denial, not a calm one.
        for (m in cache.stagedDenied()) {
            preParkedByVault.getOrPut(m.vaultId) { mutableListOf() }.add(StagedDenial(m, 0))
        }
    }

    /** Close the underlying cache (must precede deleting its DB file — Windows file locks). */
    fun close() = cache.close()

    private suspend fun pull() {
        // Epoch guard (#0 belt): stamp the START of this pull before anything is fetched.
        // surfaceStagedDenials only classifies denials staged BEFORE a completed pull's
        // start — i.e. verdicts always come from a snapshot fetched after the denial.
        val myStart = ++pullStartCounter
        val since = cache.cursor()
        // Capture the vaults we HOLD THE KEY FOR before applying this pull, with their
        // decrypted names (spec 03 §11: notices fire ONLY for locally-held vaults, and the
        // pre-purge name drives the copy). Empty on a since=0 / fresh-device pull.
        val prePullNames = HashMap<String, String>()
        for (v in cache.vaults()) {
            if (account.hasVault(v.vaultId)) prePullNames[v.vaultId] = account.decryptVaultName(v.vaultId, v.metaBlob) ?: "(vault)"
        }
        var resyncing = false
        val resp = try {
            api.sync(since)
        } catch (e: ApiException) {
            if (e.status == 410) {
                // Fetch the replacement snapshot FIRST; the durable cache is wiped only
                // once the full response is in hand (a failed fetch must not leave an
                // empty cache behind — that would regress offline durability).
                resyncing = true
                api.sync(0)
            } else throw e
        }

        // Rollback guards BEFORE anything is applied (spec 05 T1: warn, never delete or
        // overwrite local newer state; spec 03 §4). A non-full response below our cursor,
        // or an unsolicited full snapshot, is a server rollback / replay signal.
        if (!resp.full && resp.rev < since) {
            throw ApiException(409, "rev_regression", "server rev went backwards — possible rollback; local state kept")
        }
        if (resp.full && since > 0 && !resyncing) {
            throw ApiException(409, "rev_regression", "unsolicited full snapshot — possible rollback; local state kept")
        }

        val reinstated: List<ReinstatedVault>
        try {
            reinstated = applyPull(resp, resyncing, since, prePullNames)
        } catch (t: Throwable) {
            // The DB tx rolled back to a consistent state, but the in-memory working set +
            // Account key map were mutated eagerly. Rebuild them from the (rolled-back)
            // durable rows so the live session matches disk (data is intact; the next sync
            // re-applies the delta since the cursor also rolled back).
            runCatching { cache.evictDecrypted(); hydrate() }
            throw t
        }

        if (myStart > freshestCompletedPullStart) freshestCompletedPullStart = myStart

        // Reinstate replay (spec 03 §11 / #3): the parked mutations were durably
        // RE-ENQUEUED inside the pull tx (crash-safe — death here replays them on the next
        // launch); flush them now through the ordinary queue path with their ORIGINAL
        // mutationIds (server dedup + the never-cache-denied rule make this converge).
        for (r in reinstated) {
            pushNotice(LifecycleNotice(account.newItemId(), r.vaultId, r.cachedName, "restored"))
        }
        if (reinstated.isNotEmpty()) {
            runCatching { flushQueue() } // offline replay failure ≠ pull failure; rows stay queued
        }
        drainReplayDenied()

        materializeOutstandingConflicts()
    }

    private class ReinstatedVault(val vaultId: String, val cachedName: String)

    /** Replayed-then-denied edits (#6): the vault is live again but our role no longer
     *  allows the write (e.g. re-added as reader) — a calm one-time notice, never a thrown
     *  sync failure, and the rows were already durably dropped in [flushQueue]. */
    private fun drainReplayDenied() {
        if (replayDeniedByVault.isEmpty()) return
        for ((vid, n) in replayDeniedByVault) {
            val name = cache.vaults().find { it.vaultId == vid }
                ?.let { account.decryptVaultName(vid, it.metaBlob) } ?: "(vault)"
            pushNotice(LifecycleNotice(account.newItemId(), vid, name, "replay-denied", parkedCount = n))
        }
        replayDeniedByVault.clear()
    }

    private fun applyPull(
        resp: io.silencelen.andvari.core.model.SyncResponse,
        resyncing: Boolean,
        since: Long,
        prePullNames: Map<String, String>,
    ): List<ReinstatedVault> {
        val reinstated = mutableListOf<ReinstatedVault>()
        cache.atomically {
            if (resyncing) cache.clear() // resets cursor + rows; PRESERVES the queue + holding area (spec 03 §4/§11)
            // A LIVE grant re-arriving for a vault in the holding area is a reinstate
            // signal (restore / owner re-add) — collected here, acted on after items apply.
            val reinstatedIds = mutableSetOf<String>()
            for (grant in resp.grants) {
                // Persist UNCONDITIONALLY (ciphertext rows; deltas never re-send) — the
                // in-memory key-open below may fail/skip, hydrate() retries from disk.
                cache.upsertGrant(grant)
                // addGrant applies role changes even when the VK is already held (a role
                // change re-delivers the grant precisely for this).
                runCatching {
                    account.addGrant(grant)
                    if (cache.getHeld(grant.vaultId) != null) reinstatedIds.add(grant.vaultId)
                }
            }
            for (vault in resp.vaults) {
                cache.upsertVault(vault)
                if (vault.type == "personal" && account.hasVault(vault.vaultId)) account.setPersonalVault(vault.vaultId)
                // Consumed-deleteId marker (spec 03 §11): a live vault that WAS restored
                // carries restoreProof over the deleteId it undid. Verifying it durably
                // marks the deleteId consumed, so a later replayed old tombstone bearing it
                // is recognized as stale — even on a device offline across the whole
                // delete→restore cycle.
                val rp = vault.restoreProof
                val did = vault.deleteId
                if (rp != null && did != null && account.hasVault(vault.vaultId)) {
                    runCatching {
                        val key = account.lifecycleKeyFor(vault.vaultId)
                        val expected = LifecycleProof.restore(account.cryptoProvider(), key, vault.vaultId, did)
                        if (LifecycleProof.verify(expected, rp)) cache.addConsumedDeleteId(did)
                    }
                }
                // Transfer state: recompute the verified incoming offer + surface a
                // completion notice for a newly-seen accepted transfer.
                runCatching {
                    applyTransferState(vault, noticeable = prePullNames.containsKey(vault.vaultId) && since > 0 && !resyncing)
                }
            }
            for (item in resp.items) {
                if (item.deleted) {
                    cache.deleteItem(item.itemId)
                    continue
                }
                // Envelope persists even when the VK is missing or decrypt fails — the
                // rev has passed the cursor and will never re-send; hydrate() retries.
                val decrypted = if (account.hasVault(item.vaultId)) {
                    runCatching {
                        VaultItem(item.itemId, item.vaultId, item.rev, item.updatedAt, account.decryptItem(item))
                    }.getOrNull()
                } else null
                cache.upsertItem(item, decrypted)
            }
            // Reinstate (spec 03 §11): runs AFTER items apply so the backfill row wins and
            // the held-ciphertext rehydration below only fills gaps.
            for (vaultId in reinstatedIds) {
                val held = cache.getHeld(vaultId) ?: continue
                // Durable-first (#3): the parked mutations re-enter the crash-durable queue
                // BEFORE the holding record is dropped — all inside this tx, so a process
                // death anywhere after commit still replays them (ordinary flushQueue path,
                // ORIGINAL mutationIds preserved).
                for (m in held.parked) {
                    cache.enqueue(m)
                    replayedMutationIds.add(m.mutationId) // a denial of these is a calm notice (#6)
                }
                cache.removeHeld(vaultId)
                held.deleteId?.let { cache.addConsumedDeleteId(it) }
                // Belt: rehydrate any held ciphertext item the backfill did not re-deliver.
                for (wi in held.items) {
                    if (cache.getItem(wi.itemId) != null) continue
                    runCatching {
                        cache.upsertItem(wi, VaultItem(wi.itemId, vaultId, wi.rev, wi.updatedAt, account.decryptItem(wi)))
                    }
                }
                val name = prePullNames[vaultId]
                    ?: held.grant?.let { account.peekVaultName(it, held.vault.metaBlob) }
                    ?: "(vault)"
                reinstated.add(ReinstatedVault(vaultId, name))
            }
            // Revoked memberships (spec 03 §11 tri-state). F21: this MUST NOT throw — a bad
            // proof or holding failure can never abort the pull that delivered removedGrants.
            val infoByVault = HashMap<String, RemovedGrantInfo>()
            for (info in resp.removedGrantsInfo) infoByVault[info.vaultId] = info
            for (vaultId in resp.removedGrants) {
                runCatching {
                    handleRemovedGrant(vaultId, infoByVault[vaultId], prePullNames[vaultId], since, resyncing)
                }.onFailure {
                    hardDropLocal(vaultId) // still ensure the vault leaves the live view
                }
            }
            cache.setCursor(resp.rev)
        }
        return reinstated
    }

    // ==== vault lifecycle: sync-time handling (spec 03 §11) ====

    /**
     * One removedGrants entry, tri-state (spec 03 §4/§11):
     *  - vault NOT held before the pull → unverifiable / unknown → silent no-op (no banner);
     *  - a replayed tombstone whose deleteId is already consumed → recognized, kept live, no warn;
     *  - this device initiated the delete/leave → drop cleanly, no banner;
     *  - held VK → verify the relayed proof: VALID → soft-hide + attributed notice; INVALID or a
     *    bare revocation → soft-hide + anomaly warning; 'left' → soft-hide + calm "you left".
     * Never hard-purges before purgeAt even on a valid proof (bounds tombstone-replay to a
     * self-healing ≤7d soft-hide). The vault always leaves the LIVE view; holding retains it.
     */
    private fun handleRemovedGrant(
        vaultId: String,
        info: RemovedGrantInfo?,
        cachedName: String?,
        since: Long,
        resyncing: Boolean,
    ) {
        // One-shot self-initiation marker (#4): consumed on the FIRST removedGrant processed
        // for this vault, no matter which branch runs below — a stale entry must never
        // linger to misread a LATER genuine removal as self-initiated and bypass holding.
        val selfInitiated = suppressDrop.remove(vaultId)

        // A stale/replayed tombstone of an already-restored vault: keep it live, do not re-warn.
        val deleteId = info?.deleteId
        if (info?.reason == "deleted" && deleteId != null && cache.isConsumedDeleteId(deleteId)) return

        // Unverifiable: the VK was not held before this pull (fresh device, hidden grant, or a
        // since=0 / resync pull) → silent no-op. Drop any stray unusable row.
        if (cachedName == null || since == 0L || resyncing) {
            hardDropLocal(vaultId)
            return
        }

        // This device initiated the delete/leave — drop cleanly, no banner (design §4/§13).
        if (selfInitiated) {
            hardDropLocal(vaultId)
            return
        }

        val reason = info?.reason ?: "removed"
        val verdict = when {
            reason == "left" -> "left"
            verifyRemoval(vaultId, reason, info) -> "valid"
            else -> "anomaly"
        }

        // Snapshot ciphertext + move to holding BEFORE forgetting the VK.
        val parkedCount = moveToHolding(vaultId, reason, info, verdict == "valid", cachedName)

        when {
            verdict == "left" -> pushNotice(LifecycleNotice(account.newItemId(), vaultId, cachedName, "left"))
            verdict == "anomaly" -> pushNotice(LifecycleNotice(account.newItemId(), vaultId, cachedName, "anomaly"))
            reason == "deleted" -> pushNotice(
                LifecycleNotice(
                    account.newItemId(), vaultId, cachedName, "deleted",
                    purgeAt = info?.purgeAt, parkedCount = parkedCount.takeIf { it > 0 },
                ),
            )
            else -> pushNotice(LifecycleNotice(account.newItemId(), vaultId, cachedName, "removed"))
        }
    }

    /** Verify the relayed removal/delete proof under the still-held VK (spec 03 §11). */
    private fun verifyRemoval(vaultId: String, reason: String, info: RemovedGrantInfo?): Boolean {
        if (info == null) return false // a bare revocation of a held vault is never "valid"
        return runCatching {
            val key = account.lifecycleKeyFor(vaultId)
            val crypto = account.cryptoProvider()
            if (reason == "deleted") {
                val proof = info.deleteProof ?: return false
                val id = info.deleteId ?: return false
                LifecycleProof.verify(LifecycleProof.delete(crypto, key, vaultId, id), proof)
            } else {
                // 'removed' / 'transferred': verify the optional removal proof over (vaultId, me, nonce).
                val proof = info.removeProof ?: return false
                val nonce = info.removeNonce ?: return false
                LifecycleProof.verify(LifecycleProof.remove(crypto, key, vaultId, account.userId, nonce), proof)
            }
        }.getOrDefault(false)
    }

    /**
     * Move a removed vault's rows into the ciphertext-only holding area (design §6), then
     * drop it from the live view. Parked = this cycle's staged denials (F21) + any not-yet-
     * flushed queued mutations for the vault (they would only be denied) + anything already
     * held. Returns the parked count for the notice. The item snapshot reuses the cache's
     * ciphertext envelopes verbatim — nothing is re-encrypted, nothing plaintext at rest.
     */
    private fun moveToHolding(
        vaultId: String,
        reason: String,
        info: RemovedGrantInfo?,
        verifiedDelete: Boolean,
        @Suppress("UNUSED_PARAMETER") cachedName: String,
    ): Int {
        val items = cache.envelopes().filter { it.vaultId == vaultId && !it.deleted }
        val staged = preParkedByVault.remove(vaultId)?.map { it.mutation } ?: emptyList()
        val queued = cache.pending().filter { it.vaultId == vaultId }
        val parked = ((cache.getHeld(vaultId)?.parked ?: emptyList()) + staged + queued).distinctBy { it.mutationId }
        // Verified deletes expunge at purgeAt (the server erases then); everything else at +30d.
        val expungeAt = if (verifiedDelete && reason == "deleted" && info?.purgeAt != null) info.purgeAt else nowMs() + 30 * DAY_MS
        cache.putHeld(
            HeldVaultRecord(
                vault = cache.vaults().find { it.vaultId == vaultId } ?: WireVault(vaultId, "shared", 0, "", 0),
                grant = cache.grants().find { it.vaultId == vaultId }, // retained (normative, design §6)
                items = items,
                reason = reason,
                verified = verifiedDelete,
                purgeAt = info?.purgeAt,
                deleteId = info?.deleteId,
                parked = parked,
                expungeAt = expungeAt,
            ),
        )
        hardDropLocal(vaultId)
        return parked.size
    }

    /** Drop a vault from the LIVE view: rows, queued mutations, key/role, incoming offer. */
    private fun hardDropLocal(vaultId: String) {
        cache.dropVault(vaultId)
        cache.dropPending(vaultId)
        account.removeVault(vaultId)
        incomingByVault.remove(vaultId)
    }

    /** Expunge holding-area entries past their deadline (purgeAt / +30d, design §6). */
    private fun pruneHolding() {
        val now = nowMs()
        for (h in cache.heldVaults()) if (h.expungeAt <= now) cache.removeHeld(h.vault.vaultId)
    }

    /**
     * Recompute transfer state for one vault row (spec 03 §11). A pending offer TO us
     * surfaces ONLY after its proof verifies under the held VK, is unexpired, and its seq
     * beats the last VERIFIED one (replay floor). A completed transfer is verified via the
     * relayed wrapHash; only a VERIFIED completion advances the seen-seq chain — an
     * unverifiable row must not suppress the notice when the genuine wrapHash arrives on a
     * later pull, nor (via a fabricated huge seq) mute future offers. A verified completion
     * also retracts any earlier transfer-anomaly warning for the vault.
     */
    private fun applyTransferState(vault: WireVault, noticeable: Boolean) {
        val vaultId = vault.vaultId
        if (!account.hasVault(vaultId)) return
        // Incoming offer: recomputed each pull, so a cancel/expiry/re-designate (all
        // re-deliver the row) clears a stale banner.
        incomingByVault.remove(vaultId)
        val crypto = account.cryptoProvider()
        val seenSeq = cache.lastVerifiedTransferSeq(vaultId)
        val pt = vault.pendingTransfer
        if (pt != null && pt.toUserId == account.userId && pt.expiresAt > nowMs() && pt.seq > seenSeq) {
            runCatching {
                val key = account.lifecycleKeyFor(vaultId)
                val expected = LifecycleProof.offer(crypto, key, vaultId, pt.offerId, pt.toUserId, pt.expiresAt, pt.seq)
                if (LifecycleProof.verify(expected, pt.proof)) {
                    incomingByVault[vaultId] = IncomingTransfer(
                        vaultId = vaultId,
                        vaultName = account.decryptVaultName(vaultId, vault.metaBlob) ?: "(vault)",
                        offerId = pt.offerId,
                        seq = pt.seq,
                        expiresAt = pt.expiresAt,
                    )
                }
            } // no key / bad proof — no consent screen (spec 03 §11)
        }
        val lt = vault.lastTransfer
        if (lt != null && lt.seq > seenSeq) {
            val wrapHash = lt.wrapHash
            val verified = wrapHash != null && runCatching {
                val key = account.lifecycleKeyFor(vaultId)
                val expected = LifecycleProof.acceptFromHash(crypto, key, vaultId, lt.offerId, lt.newOwnerUserId, lt.seq, wrapHash)
                LifecycleProof.verify(expected, lt.acceptProof)
            }.getOrDefault(false)
            val name = account.decryptVaultName(vaultId, vault.metaBlob) ?: "(vault)"
            if (verified) {
                cache.setLastVerifiedTransferSeq(vaultId, lt.seq)
                // A verified completion supersedes any earlier unverified-sighting warning.
                noticeList.removeAll { it.vaultId == vaultId && it.kind == "transfer-anomaly" }
                if (noticeable) {
                    pushNotice(
                        LifecycleNotice(
                            account.newItemId(), vaultId, name, "transfer-complete",
                            newOwnerUserId = lt.newOwnerUserId, becameMine = lt.newOwnerUserId == account.userId,
                        ),
                    )
                }
            } else if (noticeable) {
                // Invalid proof / missing wrapHash on a locally-held vault: retain-and-warn
                // (design §4 TRANSFER 5) — the ownership change couldn't be verified.
                pushNotice(LifecycleNotice(account.newItemId(), vaultId, name, "transfer-anomaly", newOwnerUserId = lt.newOwnerUserId))
            }
        }
    }

    private fun pushNotice(n: LifecycleNotice) {
        // Collapse a repeat notice for the same vault+kind (idempotent re-pulls).
        noticeList.removeAll { it.vaultId == n.vaultId && it.kind == n.kind }
        noticeList.add(n)
    }

    // ==== vault lifecycle: read surfaces ====

    /** The pending lifecycle notices for the UI banner (spec 03 §11). */
    fun notices(): List<LifecycleNotice> = noticeList.toList()

    fun dismissNotice(id: String) {
        noticeList.removeAll { it.id == id }
    }

    fun clearNotices() = noticeList.clear()

    /** Vaults soft-hidden in the holding area (the "Recently removed" surface). The name is
     *  re-derived from the retained grant + metaBlob on each read — never persisted. */
    fun heldVaultInfos(): List<HeldVaultInfo> {
        pruneHolding()
        return cache.heldVaults().map { h ->
            HeldVaultInfo(
                vaultId = h.vault.vaultId,
                name = h.grant?.let { account.peekVaultName(it, h.vault.metaBlob) } ?: "(vault)",
                reason = h.reason,
                verified = h.verified,
                purgeAt = h.purgeAt,
                expungeAt = h.expungeAt,
            )
        }
    }

    /** Verified incoming ownership offers TO us — the accept consent screen renders per entry. */
    fun incomingTransfers(): List<IncomingTransfer> = incomingByVault.values.toList()

    /** The pending offer on a vault (for the owner's "Ownership offer to …" chip), or null. */
    fun pendingTransferFor(vaultId: String): PendingTransfer? =
        cache.vaults().find { it.vaultId == vaultId }?.pendingTransfer

    // ==== vault lifecycle: actions (spec 03 §11) ====

    /**
     * Reconcile sync after a lifecycle op COMMITTED server-side (#1). Transport/offline
     * failures are swallowed — the op itself succeeded, a later sync trues up ([onFailure]
     * lets the caller clean its local view first). But a genuine-denial ApiException from
     * the same cycle is real user-facing information about a DIFFERENT edit being dropped
     * (e.g. a queued reader edit on an unrelated vault) — it must propagate, never be
     * silently swallowed with the edit.
     */
    private suspend fun reconcileSync(onFailure: (() -> Unit)? = null) {
        try {
            sync()
        } catch (e: Throwable) {
            onFailure?.invoke()
            if (e is ApiException && e.code == "denied") throw e
        }
    }

    /** DELETE (soft, 7d grace). Mints a fresh deleteId + delete proof under the held VK.
     *  This device initiated it, so the reconcile pull drops the vault cleanly (no banner);
     *  the owner restores it from Recently deleted. Returns the server-erase deadline. */
    suspend fun deleteSharedVault(vaultId: String): Long {
        val deleteId = account.newItemId()
        val key = account.lifecycleKeyFor(vaultId)
        val proof = LifecycleProof.delete(account.cryptoProvider(), key, vaultId, deleteId)
        val resp = api.deleteVault(vaultId, VaultDeleteRequest(deleteId, proof))
        suppressDrop.add(vaultId)
        try {
            reconcileSync(onFailure = { hardDropLocal(vaultId) })
        } finally {
            suppressDrop.remove(vaultId) // #4: never outlives the action's own reconcile
        }
        return resp.purgeAt
    }

    /** The caller's own in-grace deleted vaults — re-opens each VK from the wrappedVk it
     *  already owned so the name shows AND restore can mint its proof (ZK-clean). */
    suspend fun listDeleted(): List<DeletedVaultInfo> = api.deletedVaults().map { d ->
        var name = "(vault)"
        runCatching {
            account.addGrant(WireGrant(d.vaultId, account.userId, "owner", d.wrappedVk, 0, null))
            name = account.decryptVaultName(d.vaultId, d.metaBlob) ?: "(vault)"
        } // can't open — placeholder; restore will fail loudly if truly lost
        DeletedVaultInfo(d.vaultId, name, d.deletedAt, d.purgeAt, d.deleteId)
    }

    /** RESTORE (within grace). Requires the VK held (listDeleted re-opened it). */
    suspend fun restoreSharedVault(vaultId: String, deleteId: String) {
        val key = account.lifecycleKeyFor(vaultId)
        val proof = LifecycleProof.restore(account.cryptoProvider(), key, vaultId, deleteId)
        api.restoreVault(vaultId, VaultRestoreRequest(deleteId, proof))
        cache.addConsumedDeleteId(deleteId)
        reconcileSync() // restore committed; a failed reconcile trues up later
    }

    /** LEAVE (self-removal). This device initiated it → drop cleanly (no "you left" banner here). */
    suspend fun leaveSharedVault(vaultId: String) {
        api.leaveVault(vaultId)
        suppressDrop.add(vaultId)
        try {
            reconcileSync(onFailure = { hardDropLocal(vaultId) })
        } finally {
            suppressDrop.remove(vaultId) // #4: never outlives the action's own reconcile
        }
    }

    /** TRANSFER offer. seq = the vault's last completed transfer seq + 1 (= transferSeq+1). */
    suspend fun offerTransfer(vaultId: String, toUserId: String) {
        val seq = (cache.vaults().find { it.vaultId == vaultId }?.lastTransfer?.seq ?: 0L) + 1
        val offerId = account.newItemId()
        val expiresAt = nowMs() + 14 * DAY_MS
        val key = account.lifecycleKeyFor(vaultId)
        val proof = LifecycleProof.offer(account.cryptoProvider(), key, vaultId, offerId, toUserId, expiresAt, seq)
        api.offerTransfer(vaultId, TransferOfferRequest(toUserId, offerId, expiresAt, proof))
        reconcileSync()
    }

    /** TRANSFER cancel (owner) or decline (target). */
    suspend fun cancelTransfer(vaultId: String) {
        api.cancelTransfer(vaultId)
        incomingByVault.remove(vaultId)
        reconcileSync()
    }

    /**
     * TRANSFER accept (design §4 TRANSFER 3). Re-verifies the offer proof under the held VK
     * BEFORE acting, mints + round-trip-verifies the owner wrap (same construction as vault
     * creation), and posts acceptProof over sha256(wrappedVk). Fails loudly rather than
     * post an unopenable wrap.
     */
    suspend fun acceptTransfer(vaultId: String) {
        val pt = cache.vaults().find { it.vaultId == vaultId }?.pendingTransfer
        if (pt == null || pt.toUserId != account.userId) {
            throw ApiException(409, "transfer_not_pending", "no ownership offer pending for you")
        }
        if (pt.expiresAt <= nowMs()) throw ApiException(409, "transfer_not_pending", "this ownership offer has expired")
        val key = account.lifecycleKeyFor(vaultId)
        val crypto = account.cryptoProvider()
        val expected = LifecycleProof.offer(crypto, key, vaultId, pt.offerId, pt.toUserId, pt.expiresAt, pt.seq)
        if (!LifecycleProof.verify(expected, pt.proof)) {
            throw ApiException(400, "not_transfer_target", "the offer could not be verified with the vault's key")
        }
        val wrappedVk = account.buildOwnerWrap(vaultId) // throws if it fails round-trip
        val proof = LifecycleProof.accept(crypto, key, vaultId, pt.offerId, account.userId, pt.seq, wrappedVk)
        api.acceptTransfer(vaultId, TransferAcceptRequest(pt.offerId, wrappedVk, proof))
        incomingByVault.remove(vaultId)
        reconcileSync()
    }

    /** RENAME. Read-modify-write metaBlob (name only, unknown fields preserved, metaV bumped),
     *  with the current vault rev as the stale-write guard. A 409 stale_meta (a concurrent
     *  change) auto-resyncs and retries ONCE on top of the fresh row (never a silent
     *  last-write-wins). */
    suspend fun renameVault(vaultId: String, newName: String, retry: Boolean = true) {
        val vault = cache.vaults().find { it.vaultId == vaultId } ?: throw CryptoException("vault not found")
        val metaBlob = account.buildRenameMeta(vaultId, vault.metaBlob, newName)
        try {
            api.updateVaultMeta(vaultId, VaultMetaUpdateRequest(metaBlob, vault.rev))
        } catch (e: ApiException) {
            if (retry && e.code == "stale_meta") {
                sync() // pull the newer row, then rebuild the rename on top of it
                return renameVault(vaultId, newName, retry = false)
            }
            throw e
        }
        reconcileSync()
    }

    // ==== F19: move / copy an item into another vault (design §8) ====

    /** Mint a move/copy gesture: fresh newItemId + per-attachment fresh fileKeys, captured
     *  ONCE. A retry MUST reuse the SAME gesture (server dedup converges); a new deliberate
     *  copy gets a fresh one. [del]=true = move (copy then delete source); false = copy. */
    fun newMoveGesture(itemId: String, targetVaultId: String, del: Boolean): MoveGesture {
        val src = cache.getItem(itemId) ?: throw CryptoException("the item to move is no longer here")
        return MoveGesture(
            gestureId = account.newItemId(),
            sourceItemId = itemId,
            sourceVaultId = src.vaultId,
            sourceRev = src.rev, // the rev of the content copied — the delete leg's stale-write guard
            targetVaultId = targetVaultId,
            newItemId = account.newItemId(),
            del = del,
            attachments = src.doc.attachments.map {
                GestureAttachment(
                    oldId = it.id,
                    newId = account.newItemId(),
                    newFileKey = Bytes.toB64(account.newFileKey()), // FRESH — breaks the sha256(ciphertext) linkage
                    name = it.name,
                    size = it.size,
                )
            },
        )
    }

    /** UUIDv4-shaped id from sha256("gesture|gestureId|leg") — a retry of the same gesture
     *  replays the same mutationIds (server dedup key = deviceId+mutationId). Shaping is the
     *  ONE shared [Bytes.uuidV4FromBytes] (also behind ConflictCopy + Account ids). */
    private fun gestureMutationId(gestureId: String, leg: String): String =
        Bytes.uuidV4FromBytes(account.cryptoProvider().sha256("gesture|$gestureId|$leg".encodeToByteArray()))

    /**
     * Run a move/copy gesture (design §8 safe shape): COPY LEG FIRST (fresh ids, attachments
     * re-encrypted under fresh fileKeys), wait for a POSITIVE `applied`/`conflict`, THEN —
     * for a move — delete the SOURCE with the baseRev of the content actually copied. Copy
     * denied → [CopyDeniedException], source untouched. A missing/unknown copy status is NOT
     * a durable copy — abort with the source untouched. Delete conflict (source changed) →
     * resync + [ItemChangedException], never a blind retry. Idempotent per gesture
     * (mutationIds derive from gestureId; the server replays stored results verbatim).
     * Pushed DIRECTLY (never queued): the gate must inspect this leg's own result.
     */
    suspend fun runGesture(g: MoveGesture, onProgress: ((done: Int, total: Int) -> Unit)? = null, finalSync: Boolean = true) {
        val src = cache.getItem(g.sourceItemId)
            ?: throw CryptoException("The item to move is no longer here — it may have changed or been removed.")

        // --- COPY LEG ---
        var newDoc = src.doc
        if (g.attachments.isNotEmpty()) {
            val newRefs = ArrayList<AttachmentRef>(g.attachments.size)
            var done = 0
            onProgress?.invoke(0, g.attachments.size)
            for (a in g.attachments) {
                val srcRef = src.doc.attachments.find { it.id == a.oldId }
                    ?: throw CryptoException("an attachment vanished from the source item")
                val plain = downloadAttachment(srcRef)
                val enc = Attachments.encrypt(account.cryptoProvider(), Bytes.fromB64(a.newFileKey), plain)
                try {
                    api.uploadAttachment(a.newId, g.newItemId, g.targetVaultId, enc.header + enc.ciphertext)
                } catch (e: ApiException) {
                    // Gesture RETRY (memo reused while the source rev is unchanged): this
                    // attempt's re-encryption carries a fresh random secretstream header, so a
                    // copy leg that partially landed before the failure now trips the server's
                    // sha-matched dedup on its own once-minted id. Ours-by-construction: skip.
                    if (e.code != "attachment_id_taken") throw e
                }
                newRefs.add(AttachmentRef(id = a.newId, name = a.name, size = a.size, fileKey = a.newFileKey))
                onProgress?.invoke(++done, g.attachments.size)
            }
            newDoc = newDoc.copy(attachments = newRefs)
        }
        val upload = account.encryptItem(g.targetVaultId, g.newItemId, newDoc)
        val copyResp = api.push(
            PushRequest(listOf(Mutation(gestureMutationId(g.gestureId, "copy"), "put", g.newItemId, g.targetVaultId, 0, upload))),
        )
        val copyResult = copyResp.results.firstOrNull()
        if (copyResult?.status == "denied") throw CopyDeniedException() // ABORT — source untouched
        // POSITIVE confirmation required (design §8): only `applied`, or `conflict` (put-over-
        // existing on a crash-window retry: our copy won, content is present), may proceed to
        // the delete leg. A missing result or an unknown/future status is NOT a durable copy.
        if (copyResult?.status != "applied" && copyResult?.status != "conflict") {
            throw ApiException(0, "copy_unconfirmed", "The copy could not be confirmed — nothing was moved. Try again.")
        }
        if (account.hasVault(g.targetVaultId)) {
            val now = nowMs()
            val wire = WireItem(
                itemId = g.newItemId, vaultId = g.targetVaultId, rev = copyResult.newItemRev ?: 1,
                createdAt = now, updatedAt = now, deleted = false, conflict = false,
                formatVersion = upload.formatVersion, attachmentIds = upload.attachmentIds, blob = upload.blob,
            )
            cache.upsertItem(wire, VaultItem(g.newItemId, g.targetVaultId, wire.rev, now, newDoc))
        }

        // --- DELETE LEG (move only) ---
        if (g.del) {
            val delResp = api.push(
                PushRequest(listOf(Mutation(gestureMutationId(g.gestureId, "delete"), "delete", g.sourceItemId, g.sourceVaultId, g.sourceRev, null))),
            )
            when (delResp.results.firstOrNull()?.status) {
                "conflict" -> {
                    // Resync so the user sees the newer source; a genuine-denial the resync
                    // surfaces (an UNRELATED dropped edit, #1) rides along as suppressed —
                    // the item-changed verdict stays the primary error.
                    val changed = ItemChangedException()
                    try {
                        sync()
                    } catch (e: Throwable) {
                        if (e is ApiException && e.code == "denied") changed.addSuppressed(e)
                    }
                    throw changed
                }
                "denied" -> throw ApiException(403, "denied", "The source item could not be deleted — your access may have changed. The copy was made.")
                else -> cache.deleteItem(g.sourceItemId)
            }
        }

        if (finalSync) {
            reconcileSync() // move/copy committed; offline reconcile trues up later; genuine denials surface (#1)
        }
    }

    /**
     * Bulk "copy all to Personal" (design §8) — the delete dialog's rescue step. COPY LEGS
     * ONLY: originals are NEVER deleted (abort mid-bulk is non-destructive; the vault delete
     * itself ends access, and grace-retains the originals so a restore genuinely returns
     * everything). Gestures are memoized per source item, so a RETRY after a mid-run failure
     * reuses the same ids and converges on server dedup instead of double-writing.
     */
    suspend fun copyAllToPersonal(vaultId: String, onProgress: ((done: Int, total: Int) -> Unit)? = null): Int {
        val items = cache.allItems().filter { it.vaultId == vaultId }
        var copied = 0
        for (it in items) {
            val gKey = "$vaultId|${it.itemId}|${account.personalVaultId}"
            var g = bulkGestures[gKey]
            if (g == null || g.sourceRev != it.rev) {
                // New gesture only for a first attempt or when the source content changed
                // since the memoized attempt (a different rev IS different content).
                g = newMoveGesture(it.itemId, account.personalVaultId, del = false)
                bulkGestures[gKey] = g
            }
            runGesture(g, onProgress = null, finalSync = false)
            copied++
            onProgress?.invoke(copied, items.size)
        }
        reconcileSync()
        return copied
    }

    // ==== conflict materialization (spec 03 §5) ====

    /**
     * Conflict copies derive from PERSISTED state, not a transient in-loop list: a crash
     * between cursor-advance and materialization must not bury a displaced version
     * forever (spec 03 §5). The copy's itemId is deterministic over (itemId, rev) so
     * concurrent/restarted materializers converge on one copy; an already-present copy
     * means someone (possibly us, pre-crash) materialized — skip, the flag-clear is
     * theirs to land.
     */
    private suspend fun materializeOutstandingConflicts() {
        val envelopes = cache.envelopes()
        val known = envelopes.mapTo(HashSet()) { it.itemId }
        for (item in envelopes) {
            if (!item.conflict || item.deleted) continue
            // A reader must not materialize (its push would be denied, spec 03 §5) — the
            // flag waits for a writer/owner on some other device.
            if (account.roleFor(item.vaultId) == "reader") continue
            val winner = cache.getItem(item.itemId) ?: continue // undecryptable → wait
            val copyId = deterministicCopyId(item.itemId, item.rev)
            // PDD-1: the CORRECT copy is built from the DISPLACED (losing) value by the pushing
            // client (materializeConflictFromServerItem); this path is the FALLBACK + flag
            // clearer. If the copy is already present (push side, a peer, or a prior pass), skip
            // re-creating it and just clear the flag with the live winner. If it is absent (the
            // conflict was caused by a client that didn't materialize) preserve at least the
            // winner so clearing the flag doesn't erase the only trace.
            val mutations = mutableListOf<Mutation>()
            if (copyId !in known && cache.getItem(copyId) == null) {
                val copyDoc = winner.doc.copy(name = "${winner.doc.name} (conflict ${isoDate(item.updatedAt)})")
                mutations += putMutation(copyId, item.vaultId, copyDoc, 0)
            }
            mutations += putMutation(item.itemId, item.vaultId, winner.doc, winner.rev) // clears the flag
            push(mutations)
        }
    }

    /**
     * Materialize the conflict copy from the server-returned LOSING version (spec 03 §5, PDD-1).
     * The pushing client is the ONLY party that receives the displaced value (MutationResult
     * .serverItem); the pull side sees only the winner. Creates just the copy — the conflict
     * flag is cleared by [materializeOutstandingConflicts] on the reconcile pull, which holds
     * the live winner. The copy id is deterministic over (itemId, winnerRev), the same
     * derivation the pull side uses, so an already-present copy is a no-op.
     */
    private suspend fun materializeConflictFromServerItem(losing: WireItem, winnerRev: Long) {
        if (account.roleFor(losing.vaultId) == "reader") return // a reader's push would be denied
        val losingDoc = runCatching { account.decryptItem(losing) }.getOrNull() ?: return // held key → skip
        val copyId = deterministicCopyId(losing.itemId, winnerRev)
        if (cache.getItem(copyId) != null) return // already materialized
        val copyDoc = losingDoc.copy(name = "${losingDoc.name} (conflict ${isoDate(losing.updatedAt)})")
        push(listOf(putMutation(copyId, losing.vaultId, copyDoc, 0)))
    }

    /** UUIDv4-shaped id derived from sha256("conflict|itemId|rev") — stable across retries.
     *  Delegates to the vector-pinned shared derivation (spec/test-vectors/conflictcopy.json). */
    private fun deterministicCopyId(itemId: String, rev: Long): String =
        ConflictCopy.id(account.cryptoProvider(), itemId, rev)

    fun putMutation(itemId: String, vaultId: String, doc: ItemDoc, baseItemRev: Long): Mutation =
        Mutation(
            mutationId = account.newItemId(),
            op = "put",
            itemId = itemId,
            vaultId = vaultId,
            baseItemRev = baseItemRev,
            item = account.encryptItem(vaultId, itemId, doc),
        )

    fun deleteMutation(itemId: String, vaultId: String, baseItemRev: Long): Mutation =
        Mutation(account.newItemId(), "delete", itemId, vaultId, baseItemRev, null)

    /** Create or update an item, then reconcile. New items go to [vaultId] (default personal). */
    suspend fun save(itemId: String?, doc: ItemDoc, vaultId: String? = null) = saveWithUploads(itemId, doc, emptyList(), vaultId)

    /**
     * Blob-first save (spec 02 §6): encrypt + upload every new attachment under the
     * (possibly fresh) itemId, THEN push the item that references them. An EXISTING item
     * never changes vaults (its blob AD binds to the vault; the server enforces
     * vault_mismatch) — edits always target the item's own vault, wherever it lives.
     *
     * F21: a save denied because its vault just went in-grace (an owner's accidental
     * delete) is PARKED for replay on restore — [surfaceStagedDenials] runs after the
     * reconcile pull, whose verdict is guaranteed fresh: the whole flush→pull→classify
     * cycle is [syncMutex]-serialized against every other caller, and the epoch guard
     * additionally refuses to classify off any pull that started before the denial
     * (the native equivalent of the web store's second-sync review fix).
     *
     * F71: [onProgress] mirrors [runGesture]'s per-upload (done, total) callback — fires
     * only when there are uploads. Call sites MUST pass it NAMED: a trailing lambda binds
     * to the LAST parameter, which stops being onProgress the day one is appended (the
     * exact runGesture mistake that shipped once).
     */
    suspend fun saveWithUploads(
        itemId: String?,
        doc: ItemDoc,
        uploads: List<PendingUpload>,
        vaultId: String? = null,
        onProgress: ((done: Int, total: Int) -> Unit)? = null,
        newItemId: String? = null,
    ) {
        // [newItemId] (F71 review): a RETRY of a failed NEW-item save must reuse the id the
        // first attempt minted — attachments committed by that attempt are bound to it, and
        // a fresh mint would trip the push's attachment_mismatch validation forever. Used
        // only when [itemId] is null (an edit's identity is the itemId); callers keep one
        // draft id per editor session and clear it on success/cancel.
        val existing = itemId?.let { cache.getItem(it) }
        // Save guard (design §6): an edit to an itemId we no longer hold must NOT silently
        // teleport into the personal vault — the item's vault may have been deleted or its
        // grant revoked mid-edit. Fail loudly; the server-side skeletal fence is the belt.
        if (itemId != null && existing == null) {
            throw ApiException(409, "vault_state_changed", "This item is no longer here — it may have been removed or its vault deleted.")
        }
        val effectiveVault = existing?.vaultId ?: vaultId ?: account.personalVaultId
        val id = itemId ?: newItemId ?: account.newItemId()
        if (uploads.isNotEmpty()) {
            var done = 0
            onProgress?.invoke(0, uploads.size)
            for (u in uploads) {
                val enc = Attachments.encrypt(account.cryptoProvider(), Bytes.fromB64(u.ref.fileKey), u.data)
                try {
                    api.uploadAttachment(u.ref.id, id, effectiveVault, enc.header + enc.ciphertext)
                } catch (e: ApiException) {
                    // Retry after a PARTIAL failure (F71: the editor stays open and the user
                    // re-clicks Save with the same once-minted refs): this attempt re-encrypted
                    // from plaintext, and secretstream's random header makes the bytes differ
                    // from what the earlier attempt committed — the server's sha-matched dedup
                    // then refuses the id. The id is a UUID this editor session minted, so
                    // "taken" can only mean OUR earlier attempt landed: continue, don't wedge.
                    if (e.code != "attachment_id_taken") throw e
                }
                onProgress?.invoke(++done, uploads.size)
            }
        }
        syncMutex.withLock {
            push(listOf(putMutation(id, effectiveVault, doc, existing?.rev ?: 0)))
            pull()
            surfaceStagedDenials()
        }
    }

    /**
     * Bulk import into the personal vault (spec 06): chunked pushes at the server batch
     * cap, one pull at the end. Each [PlannedItem] carries an itemId minted at plan time,
     * and the push mutationId is derived from it, so re-running the SAME plan after an
     * interruption replays idempotently (server key = deviceId+mutationId) instead of
     * duplicating. With the durable cache (spec 02 §8) the queue also survives a crash.
     */
    suspend fun importAll(
        items: List<CsvImport.PlannedItem>,
        onProgress: ((done: Int, total: Int) -> Unit)? = null,
    ) = syncMutex.withLock {
        val vaultId = account.personalVaultId
        var done = 0
        for (chunk in items.chunked(SERVER_BATCH_MAX)) {
            push(chunk.map {
                Mutation(
                    mutationId = it.itemId, // stable id → idempotent retry of the same plan
                    op = "put", itemId = it.itemId, vaultId = vaultId, baseItemRev = 0,
                    item = account.encryptItem(vaultId, it.itemId, it.doc),
                )
            })
            done += chunk.size
            onProgress?.invoke(done, items.size)
        }
        pull()
        surfaceStagedDenials()
    }

    /** Download + decrypt one attachment (hard failure on any corruption, spec 02 §6). */
    suspend fun downloadAttachment(ref: AttachmentRef): ByteArray {
        val bytes = api.downloadAttachment(ref.id)
        if (bytes.size <= Attachments.HEADER_BYTES) throw CryptoException("attachment response truncated")
        return Attachments.decrypt(
            account.cryptoProvider(),
            Bytes.fromB64(ref.fileKey),
            bytes.copyOfRange(0, Attachments.HEADER_BYTES),
            bytes.copyOfRange(Attachments.HEADER_BYTES, bytes.size),
        )
    }

    suspend fun remove(itemId: String) {
        val existing = cache.getItem(itemId) ?: return
        syncMutex.withLock {
            push(listOf(deleteMutation(itemId, existing.vaultId, existing.rev)))
            pull()
            surfaceStagedDenials()
        }
    }

    /** Enqueue durably, attempt to send; a failure leaves it queued for flushQueue(). */
    private suspend fun push(mutations: List<Mutation>) {
        mutations.forEach { cache.enqueue(it) }
        flushQueue()
    }

    /**
     * Drain the queue in server-cap-sized batches. A `denied` mutation is durably marked
     * STAGED-DENIED (#2 — it survives process death; [VaultCache.pending] stops returning
     * it so it is never blindly re-pushed) and indexed in [preParkedByVault]: the following
     * fresh pull either folds it into the holding area (its vault went in-grace → PARKED
     * for restore replay, F21) or [surfaceStagedDenials] concludes a genuine permission
     * denial and durably drops it. A denial of a reinstate-REPLAYED mutation on a live
     * vault is a calm notice instead (#6). NEVER throws for denied — a denied flush must
     * not abort the pull that delivers removedGrants.
     */
    private suspend fun flushQueue(): Int {
        var deniedCount = 0
        val displaced = mutableListOf<Pair<WireItem, Long>>() // PDD-1: (losing serverItem, winner newRev)
        while (true) {
            val chunk = cache.pending().take(SERVER_BATCH_MAX)
            if (chunk.isEmpty()) break
            val resp = api.push(PushRequest(chunk))
            val byId = resp.results.associateBy { it.mutationId }
            var progressed = false
            for (m in chunk) {
                val r = byId[m.mutationId] ?: continue
                val wasReplay = replayedMutationIds.remove(m.mutationId)
                if (r.status == "denied") {
                    deniedCount++
                    // LC-1 (P2, data loss): a REPLAYED edit used to be dequeued right here, on the
                    // assumption that a denial could only mean "the vault is live again and my role
                    // changed". But a denial equally means "the vault went in-grace AGAIN" — an
                    // owner re-deleting during (or just after) the restore. Dropping it then
                    // destroyed the member's parked offline edit and defeated the very F21
                    // protection the replay exists to provide. Every denial — replayed or not —
                    // now stages and lets surfaceStagedDenials decide against the vault's ACTUAL
                    // fate after a fresh pull: held → re-park (survives the next restore);
                    // live → durable drop (calm notice for a replay, thrown denial otherwise).
                    cache.markStagedDenied(m.mutationId)
                    preParkedByVault.getOrPut(m.vaultId) { mutableListOf() }.add(StagedDenial(m, pullStartCounter, wasReplay))
                } else {
                    // PDD-1: on a conflicting PUT the server keeps OUR value live (LWW) and
                    // returns the DISPLACED (losing) version as serverItem. Capture it and
                    // materialize the conflict copy from THAT after the drain (spec 03 §5) — the
                    // pull side sees only the winner and would copy the wrong (surviving) value.
                    // Guard on op=="put": a DELETE that loses to a newer edit (edit-beats-delete)
                    // ALSO returns conflict+serverItem, but there serverItem is the SURVIVING
                    // winner, not a losing value — materializing it would spawn a spurious copy.
                    val si = r.serverItem
                    val nr = r.newItemRev
                    if (r.status == "conflict" && m.op == "put" && si != null && nr != null) displaced += si to nr
                    // Any other definitive outcome removes it (idempotent replay returns
                    // the original result).
                    cache.dequeue(m.mutationId)
                }
                progressed = true
            }
            if (!progressed) break // defensive: no results matched (server returns one per mutation)
        }
        // Materialize AFTER draining — a re-entrant push here recurses into flushQueue; each
        // copy is a fresh item (baseRev 0) that applies cleanly, so the recursion is bounded.
        for ((losing, winnerRev) in displaced) materializeConflictFromServerItem(losing, winnerRev)
        return deniedCount
    }

    /**
     * After the pull: staged denials whose vault landed in the holding area were parked
     * (folded in by [moveToHolding]; late arrivals for an already-held vault append here) —
     * those are NOT failures, the deletion notice explains them. Anything else is a genuine
     * permission denial and surfaces exactly like the pre-0.5.0 behavior, just AFTER the
     * pull (F21). Epoch guard (#0): an entry may be classified ONLY once a pull that
     * STARTED after it was staged has completed — a verdict must never come from a stale
     * snapshot that predates the denial (a too-fresh entry stays durably staged for the
     * next cycle).
     */
    private fun surfaceStagedDenials() {
        if (preParkedByVault.isEmpty()) return
        var genuine = 0
        val iter = preParkedByVault.entries.iterator()
        while (iter.hasNext()) {
            val (vaultId, entries) = iter.next()
            val (ripe, tooFresh) = entries.partition { freshestCompletedPullStart > it.stagedBefore }
            if (ripe.isEmpty()) continue
            val held = cache.getHeld(vaultId)
            if (held != null) {
                cache.atomically {
                    cache.putHeld(held.copy(parked = (held.parked + ripe.map { it.mutation }).distinctBy { it.mutationId }))
                    ripe.forEach { cache.dequeue(it.mutation.mutationId) } // queue → held.parked, atomically
                }
            } else {
                // Vault is LIVE: a genuine refusal. LC-1 — a replayed edit refused here (the
                // member's role changed across the grace) stays a CALM notice, never a throw;
                // only a first-hand denial is escalated to the caller.
                val (replays, firstHand) = ripe.partition { it.wasReplay }
                if (replays.isNotEmpty()) {
                    replayDeniedByVault[vaultId] = (replayDeniedByVault[vaultId] ?: 0) + replays.size
                }
                genuine += firstHand.size
                ripe.forEach { cache.dequeue(it.mutation.mutationId) } // definitive durable drop
            }
            if (tooFresh.isEmpty()) {
                iter.remove()
            } else {
                entries.clear()
                entries.addAll(tooFresh)
            }
        }
        // LC-1: the calm "recovered edits refused" notices are now MINTED here (the verdict moved
        // out of flushQueue), and pull()'s drain already ran before this — so drain again, and do
        // it BEFORE the throw below: a first-hand denial must not swallow the replay notices.
        drainReplayDenied()
        if (genuine > 0) throw ApiException(403, "denied", "write denied for $genuine mutation(s)")
    }

    private fun nowMs(): Long = kotlinx.datetime.Clock.System.now().toEpochMilliseconds()

    private fun isoDate(epochMillis: Long): String {
        val instant = kotlinx.datetime.Instant.fromEpochMilliseconds(epochMillis)
        return instant.toString().substring(0, 10)
    }
}
