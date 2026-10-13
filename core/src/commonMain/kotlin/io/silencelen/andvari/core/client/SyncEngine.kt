package io.silencelen.andvari.core.client

import io.silencelen.andvari.core.crypto.Attachments
import io.silencelen.andvari.core.crypto.Bytes
import io.silencelen.andvari.core.crypto.CryptoException
import io.silencelen.andvari.core.crypto.GrantPin
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
import io.silencelen.andvari.core.model.GrantReissueRequest
import io.silencelen.andvari.core.model.UserLookupResponse
import io.silencelen.andvari.core.model.VaultMemberAdd
import io.silencelen.andvari.core.model.VaultMemberSummary
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import kotlinx.io.IOException

/** A newly attached file awaiting upload: the doc's AttachmentRef + plaintext bytes. */
class PendingUpload(val ref: AttachmentRef, val data: ByteArray)

/**
 * How a save/remove ended (audit 2026-09-13 H18 — the web store's success-as-QUEUED twin).
 * [APPLIED]: the server answered and the reconcile pull ran (or the write landed and only
 * the reconcile pull failed — a later sync trues up; the write itself is safe). [QUEUED]: the
 * server was unreachable, the mutation sits in a DURABLE queue ([VaultCache.durable]) and
 * [SyncEngine.items] already projects it, so the editor may close exactly like the online
 * path — the user must not be left with an open editor and a sentence that says "queued"
 * while the list shows nothing (re-saving lands duplicates: G23's half-landed state). A
 * non-durable engine never returns QUEUED: it throws the transport failure instead.
 */
enum class SaveOutcome { APPLIED, QUEUED }

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
    /** deleted | removed | left | anomaly | restored | added | transfer-complete |
     *  transfer-anomaly | replay-denied | write-rejected. `added` (H71) and `write-rejected`
     *  (H03/H19) are the web store's twins: "You were added to X" for a genuinely new
     *  non-owner grant, and "N offline changes to X couldn't be applied — <reason>" for
     *  queue rows the server definitively refused and the drain durably dropped.
     *  `vk-mismatch` / `key-unreadable` (security review 2026-10, root cause A §3.1): a grant row
     *  carried a seal whose key differs from our own UVK wrap (ours was kept), or our UVK wrap is
     *  present and does not open (no seal fallback; the vault stays keyless).
     *  `wrong-vault` (root cause A §5.1 INV-HOME, branch A1b): the server sent an item under another vault than the
     *  one this device holds it in (or a conflict row that disagrees about its vault); the row was NOT applied. One
     *  per pull; [vaultId] is the first offending row's vault and [parkedCount] how many rows were refused. */
    val kind: String,
    /** verified delete: the server-erase deadline (for the "kept sealed until…" line). */
    val purgeAt: Long? = null,
    /** verified delete: N of the member's edits parked for replay on restore (F21).
     *  Doubles as the count for "replay-denied" and "write-rejected". */
    val parkedCount: Int? = null,
    /** write-rejected: the server's refusal reason for the (first) dropped row —
     *  `unknown_attachment` / `attachment_mismatch` (the referenced attachment is gone),
     *  `item_attachment_quota` / `body_too_large` (too large), else unspecified. Picks the
     *  explanation clause in [HouseholdCopy.writeRejectedNotice]. */
    val reason: String? = null,
    /** transfer-complete/-anomaly: who now owns the vault, and whether that is us. */
    val newOwnerUserId: String? = null,
    val becameMine: Boolean = false,
    /** `added` from a VERIFIED v2 grant (root cause A §1.6): the label of the PINNED contact who signed it, for
     *  "You were added to <vault> by <contact>". Null for a legacy add (no sender was authenticated). */
    val byLabel: String? = null,
)

/** §1.6: a v2 grant from someone this account has not verified (or not on this device). The vault is NOT
 *  adopted and its name is not shown (it would decrypt under a key nobody authenticated). [fromUserId] is
 *  unverified routing data: whom the human should verify. */
data class PendingInvitation(val vaultId: String, val fromUserId: String, val grantIdB64: String)

/** §8.2 "Review your shared vaults": a vault readable only through a v1 seal nobody vouched for yet. The name
 *  decrypts under that unauthenticated key, so the card badges it "not yet verified". */
data class LegacyVaultReview(val vaultId: String, val name: String?, val itemCount: Int)

/** The owner's add-member flow refused a member who is not pinned (or not current) on this device (§1.5):
 *  run "Verify a household member" first. */
class MemberNotVerifiedException(val userId: String) :
    Exception("verify this member before sharing with them (their identity code is not confirmed on this device)")

/** A6b: an owner-only signing action on a vault this account has no evidence of owning (the server's `role=owner`
 *  label is not evidence). The UI asks "You own <vault>?" ([SyncEngine.confirmOwnership]) first. */
class OwnershipNotConfirmedException(val vaultId: String) :
    Exception("confirm that you own this vault first (this device has no record that you created it or accepted it)")

/** A6b review MEDIUM-1: the vault's key reached this device as a MEMBER; claiming it needs the human's explicit
 *  "This vault's owner transferred it to me" on top of the password. */
class OwnershipTransferAckRequiredException(val vaultId: String) :
    Exception("this device received this vault as a member: confirm that its owner transferred it to you")

/**
 * What "You own <vault>?" shows (A6b review MEDIUM-1), like A5b's personal-vault choice. [reportedOwner],
 * [lastTransferTo]/[lastTransferSeq], [coHolders] and [origin] are AS REPORTED BY THE SERVER; [receivedAsMember] is
 * this device's own record that it first got the key as a member (then the dialog asks for the transfer acknowledgement).
 */
data class OwnershipClaim(
    val vaultId: String,
    val vaultName: String?,
    val reportedOwner: CoHolder?,
    val lastTransferTo: CoHolder?,
    val lastTransferSeq: Long?,
    val coHolders: List<CoHolder>,
    val origin: PersonalChoiceInfo.Origin,
    val receivedAsMember: Boolean,
)

/** A6b: a re-issue with no human confirmation and no matching issued-grants record. */
class ReissueNotAuthorizedException(val vaultId: String, val userId: String) :
    Exception("re-sharing this vault with this member needs your confirmation")

/** A6b: the master password given for a reauth does not open this account's key. */
class ReauthFailedException : Exception("that master password isn't right")

/**
 * A6b carry-forward (A1b): the reauth could not be checked because this session unlocked with a salt the account no
 * longer has (a password change or a KDF upgrade since this unlock). The message is the copy; web twin
 * `ReauthStaleSessionError`, byte-identical.
 */
class ReauthStaleSessionException : Exception(HouseholdCopy.REAUTH_STALE_SESSION)

/**
 * One row of the "Legacy grants" list (§8.2 step 4, A6b). Everything but [verifiedLabel] and [pinState] is what the
 * SERVER reports: the list itself comes from the server, so the owner confirms each row ("Re-share <vault> with
 * <member>?"), and only that confirmation signs.
 */
data class LegacyGrantRow(
    val vaultId: String,
    /** Decrypted under the held key (null when it does not decrypt). */
    val vaultName: String?,
    val userId: String,
    /** Server-reported. */
    val displayName: String,
    /** Server-reported. */
    val email: String,
    /** The key the server serves for the member; must equal the pin for a confirmation. */
    val identityPub: String,
    /** The label of this device's CURRENT pin for the member (a human verified it); null when not pinned here. */
    val verifiedLabel: String?,
    val pinState: SyncEngine.MemberPinState,
    /** False when this account has no evidence of owning the vault yet ("You own <vault>?" first). */
    val ownershipConfirmed: Boolean,
)

/** A5b review LOW-1/LOW-2 (closed in A6): what "Use the new personal vault" would mean, loaded BEFORE it is
 *  offered. The co-holder lists and origin are what the SERVER reports. */
data class PersonalChangeDetails(
    val currentVaultId: String,
    val currentName: String?,
    val servedVaultId: String,
    val servedName: String?,
    /** Who else the server reports holding the NEW vault (the lookup must succeed for "Use new" to be offered). */
    val servedCoHolders: List<CoHolder>,
    val servedOrigin: PersonalChoiceInfo.Origin,
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
    /** ux-error--4: where anti-replay diagnostics go. Defaults to [CoreLog.Silent] — a host
     *  that wires nothing behaves exactly as before. */
    private val log: CoreLog = CoreLog.Silent,
    /**
     * Where the personal wrap this device last authenticated, and the vault id it pinned, are kept (security
     * review 2026-10, root cause A, A5b, M-1). Native hosts pass a [FileDeviceState] in the (origin, user)
     * namespace, which no cache policy or purge removes; null falls back to [VaultCache.clientState], which
     * is only as durable as the cache.
     */
    private val deviceState: DeviceState? = null,
) {
    companion object {
        const val SERVER_BATCH_MAX = 200 // server rejects a push batch larger than this (Service.push)
        /**
         * H19 (audit 2026-09-13): the server refuses a POST /sync/push body over 8 MiB
         * (App.kt BODY_CAP_PUSH_BYTES) with a pre-handler 413 — nothing in the batch is
         * applied, and before this bound a durably-queued 200-row import chunk whose
         * ciphertext summed past the cap was re-sent by EVERY later sync until sign-out.
         * The drain now also bounds a batch by its approximate encoded size: rows are added
         * while the running total stays under this (well below the server's cap — base64
         * blobs plus JSON framing are counted, the rest of the envelope is small), and a
         * single row is always sent alone. A lone row that STILL exceeds the cap is the
         * one poison shape that remains, and [flushQueue]'s whole-batch-refusal path drops
         * it durably with a notice instead of wedging the queue.
         */
        const val PUSH_BODY_SOFT_CAP_BYTES = 6L * 1024 * 1024
        const val DAY_MS = 86_400_000L
        /** The name every surface shows when a vault's own name is unavailable (undecryptable
         *  meta, or a row we hold no VK for). Web twin: the same literal in store.ts, which
         *  also carries [vaultInfos]'s sentinel compare against it — so a vault a user
         *  genuinely NAMED "(vault)" is relabelled Personal/Shared on both engines alike.
         *  Dropping that sentinel is a two-engine change; the constant is not. */
        const val VAULT_NAME_FALLBACK = "(vault)"

        // Root cause A §8.2 (branch A6), in the cache's client state (which survives a resync).
        /** v1-only vault keys this device vouches for, as `vaultId|sha256(VK)|frozen|confirmed` lines (pre-upgrade
         *  evidence, or the human's Accept): the vouch covers that exact key, not whatever the server serves next. */
        internal const val LEGACY_AUTHORIZED_KEY = "grant.legacy.authorized"
        /** Set once the §8.2 freeze ran (or was ruled out) on this cache: later v1 grants are never frozen. */
        internal const val FREEZE_DONE_KEY = "grant.freeze.done"
        /** grantIds of pending invitations the human declined. */
        internal const val DECLINED_KEY = "grant.declined"
        /** [LifecycleNotice.reason] on a `left` notice whose leave carried no proof (in-window, §8.6): the copy adds
         *  "Didn't do this? Tell your admin". */
        const val LEFT_UNPROVEN = "unproven"
        /** [LifecycleNotice.reason] on a `replay-denied` notice raised by a consumed removal nonce (§6.3 step 5), as
         *  opposed to the recovered-edits refusal that kind also covers. */
        const val REMOVAL_REPLAY = "removal"
        /** [LifecycleNotice.reason] on a `removed` / `left` notice whose nonce another of this user's devices already
         *  consumed (found only in account state, A7 review MEDIUM-2): calm, "already recorded on another device". */
        const val ALREADY_RECORDED = "already-recorded"
        /** [LifecycleNotice.reason] on a `removed` notice attributed by a v1 (legacy) proof, in-window (A7 review LOW-3). */
        const val REMOVED_LEGACY = "legacy"
        /** Branch A7: the per-vault held-key memory, `vaultId|sha256(VK)` lines, stored beside the vouches. */
        internal const val HELD_KEYS_KEY = "grant.held.keys"

        /** A6b review MEDIUM-1: vaults this device first adopted a key for as a MEMBER (durable provenance). */
        internal const val MEMBER_GRANTED_KEY = "grant.member.granted"
    }

    // ---- vault lifecycle state (spec 03 §11); session-scoped — the durable halves
    // (holding area, consumed deleteIds, verified transfer seqs, STAGED-DENIED queue rows)
    // live in [VaultCache].
    /** Notices awaiting the UI banner. */
    private val noticeList = mutableListOf<LifecycleNotice>()
    /** "kind|vaultId" key anomalies already surfaced this engine (root cause A §3.1: show once). */
    private val keyAnomaliesShown = mutableSetOf<String>()
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

    /** H71: vaults an "added" notice already fired for — once per engine lifetime, so an
     *  idempotent re-delivery of the same grant never re-announces (web `addedNoticed`). */
    private val addedNoticed = mutableSetOf<String>()
    /** H71: "added" notices minted INSIDE the pull tx, emitted only after it commits. */
    private val pendingAddedNotices = mutableListOf<LifecycleNotice>()

    /** H03/H19: queue rows the server DEFINITIVELY refused this drain (per-row `rejected`,
     *  or a whole-batch 400/413 isolated to one row by bisection) — durably dropped in
     *  [flushQueue]; keyed by mutationId → reason so a direct save can learn its own
     *  fate and throw the honest editor error, and grouped per vault for the notice. */
    private val rejectedMutationIds = mutableMapOf<String, String>()
    private val rejectedByVault = mutableMapOf<String, MutableList<String>>()

    /** H18: decrypted view of a QUEUED put, keyed by mutationId — memoized because
     *  [items] is a hot read and the queue's ciphertext would otherwise be re-opened on
     *  every list refresh. Pruned to the live queue on each read; never persisted. */
    private val pendingDocCache = mutableMapOf<String, VaultItem?>()

    /**
     * The live working set: the cache's server-confirmed items OVERLAID with the outbound
     * queue (H18, audit 2026-09-13 — the web store's optimistic apply + `pendingSyncItemIds`
     * twin). Before this the natives fed their list from the cache alone, so an offline save
     * the copy called "queued" was invisible until it flushed: the user re-created the entry
     * or re-tapped Save, and the queue then landed both. A queued put replaces (or adds) the
     * row with the queued doc; a queued delete hides the row. Rows are keyed by itemId, later
     * queue entries win (FIFO ⇒ the newest edit of an item is what the user last saved).
     * The overlay reads the cache's own rev for an edited item (the reconcile pull trues it
     * up), rev 0 for a brand-new one, and stamps updatedAt with the local clock (R36; web
     * parity). Never fed to [saveWithUploads]'s base-rev read — that consults the cache, or
     * (H37) the base the item's own queued burst was minted against, so LWW stays
     * server-relative and a projected rev can never masquerade as one the server issued.
     */
    fun items(): List<VaultItem> = overlayPending(cache.allItems()).sortedBy { it.doc.name.lowercase() }
    fun item(itemId: String): VaultItem? {
        val base = cache.getItem(itemId)
        val overlay = overlayPending(listOfNotNull(base), only = itemId)
        return overlay.firstOrNull()
    }

    /** H18: itemIds with a queued (unflushed) put or delete — the list's "pending sync" mark. */
    fun pendingSyncItemIds(): Set<String> = cache.pending().mapTo(LinkedHashSet()) { it.itemId }
    fun hasPendingSync(itemId: String): Boolean = cache.pending().any { it.itemId == itemId }

    private fun overlayPending(base: List<VaultItem>, only: String? = null): List<VaultItem> {
        val pending = cache.pending()
        if (pending.isEmpty()) { pendingDocCache.clear(); return base }
        val live = pending.mapTo(HashSet()) { it.mutationId }
        pendingDocCache.keys.retainAll(live)
        val byId = LinkedHashMap<String, VaultItem>(base.size)
        for (it in base) byId[it.itemId] = it
        for (m in pending) {
            if (only != null && m.itemId != only) continue
            when (m.op) {
                "delete" -> byId.remove(m.itemId)
                "put" -> {
                    val decrypted = pendingDocCache.getOrPut(m.mutationId) {
                        val up = m.item ?: return@getOrPut null
                        if (!account.hasVault(m.vaultId)) return@getOrPut null
                        val prior = byId[m.itemId] ?: cache.getItem(m.itemId)
                        runCatching {
                            // R36: updatedAt is the LOCAL clock at first projection (≈ the commit —
                            // save() refreshes at once), the way web's queued write stamps it. The
                            // old `prior?.updatedAt ?: 0` gave a brand-new offline item the epoch
                            // ("last changed: 56 years ago", ranked worst-stale) and a queued edit
                            // its pre-edit time. Cached per mutationId, so the stamp is stable until
                            // the server's own time replaces it on the reconcile pull. `rev` stays
                            // the prior rev: LWW must remain server-relative (pinned).
                            val wire = WireItem(m.itemId, m.vaultId, prior?.rev ?: 0, 0, nowMs(), false, false, up.formatVersion, up.attachmentIds, up.blob)
                            VaultItem(m.itemId, m.vaultId, wire.rev, wire.updatedAt, account.decryptItem(wire))
                        }.getOrNull()
                    }
                    if (decrypted != null) byId[m.itemId] = decrypted
                }
            }
        }
        return byId.values.toList()
    }

    // ---- read-only cache pass-throughs (F82) ----
    // The spec 07 export planner and the F20 undecryptable-grant count enumerate raw wire
    // rows. Exposing them here keeps [cache] private — the natives used to carry the
    // engine's own cache instance for these reads, a close-ordering hazard.

    /** Persisted item envelopes (ciphertext rows), tombstones included. */
    fun envelopes(): List<WireItem> = cache.envelopes()

    /**
     * The usage-ledger prune keep-set after a landed full sync (audit G04, corrected by H36):
     * every live envelope's id, DECRYPTABLE OR NOT. Built from [envelopes], never from [items] —
     * [items] is the working set and silently omits a newer-formatVersion envelope and every
     * item in a vault whose key has not arrived; pruning against it erased those live items'
     * usage on every sync of the older device. The rule and its twins are on
     * [UsageLedger.liveItemIds]; this is the engine-level accessor the natives hand to
     * `UsageRecorderCore.flushWithPrune`.
     */
    fun liveItemIds(): Set<String> = UsageLedger.liveItemIds(cache.envelopes())

    /** Persisted vault rows as delivered — [vaultInfos] is the decrypted/filtered view. */
    fun vaultRows(): List<WireVault> = cache.vaults()

    /** Persisted grant rows as delivered, openable or not (a sealed grant still counts). */
    fun grants(): List<WireGrant> = cache.grants()

    /**
     * Guided importers (design 2026-07-09, amendment A8): the DESTINATION vault's light
     * projections for the vault-aware import plan — the one engine-owned entry point all
     * native clients use, so no call site ever maps raw item lists (the web twin is
     * `store.importProjections()`). Callers gate on the vault being present/hydrated
     * FIRST (refuse-not-degrade); an empty working set here plans as if the vault were
     * empty, which is only correct once that gate has passed.
     *
     * S2 (owner dev-note 2026-07-10): [vaultId] is the import destination — null keeps
     * the personal-vault behavior. The SAME vaultId MUST feed [importAll], or the F75
     * dedupe fingerprints against one vault while the rows land in another.
     */
    fun importProjections(vaultId: String? = null): CsvImport.ImportProjections {
        val target = vaultId ?: account.personalVaultId
        return CsvImport.projections(items().filter { it.vaultId == target }.map { it.doc })
    }

    /**
     * Item history (feature): fetch this item's archived versions (server keeps the last 10) and
     * decrypt each under the held VK, newest rev first. Versions that don't decrypt — e.g. sealed
     * under a superseded VK after a rotation — are dropped (bounded history, resets at VK rotation;
     * see the design doc). Restore a chosen version with [save] — an ordinary put over the live item.
     */
    /**
     * H03 (audit 2026-09-13): the doc to put when the user restores an archived [version] of
     * [itemId] — every attachment ref the LIVE item no longer carries is stripped. A history
     * version is verbatim ciphertext from its day; an attachment removed since (and swept
     * server-side) makes a verbatim put a `rejected` row (spec 03 §5) — and, on a pre-H03
     * server, the batch-wide 400 that wedged the queue. The Trash restore already strips ALL
     * refs (the delete dropped the rows); history keeps the ones that still exist. Web twin:
     * Vault.tsx History.restore. Falls back to the version as-is when the live item is gone
     * (the save guard reports that case itself).
     */
    fun versionDocForRestore(itemId: String, version: ItemDoc): ItemDoc {
        val live = item(itemId)?.doc ?: return version
        val liveIds = live.attachments.mapTo(HashSet()) { it.id }
        return version.copy(attachments = version.attachments.filter { it.id in liveIds })
    }

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
        // INV-SEAL (a): the doc was decrypted from this item's archived envelope under [vaultId]; INV-HOME: only at home.
        api.restoreItem(itemId, sealFor(SealProvenance.Envelope(vaultId), itemId, doc.copy(attachments = emptyList())))
        sync()
    }

    /** Item undelete (F49): "Delete forever" — hard-delete a tombstoned item + its versions server-side. */
    suspend fun purgeDeleted(itemId: String) {
        api.purgeItem(itemId)
    }

    /**
     * Vaults whose key we hold, personal first then shared by name (mirrors web vaults()).
     *
     * [VaultInfo.type] is DERIVED, not copied (security review 2026-10, root cause A §4.3): "personal"
     * iff the vault is [Account.personalVaultId], which only a UVK-authenticated personal wrap sets: one the
     * server served, one this device cached, or one minted from the human's confirmed choice (there is no
     * automatic migration pick any more). The server's plaintext `type` label is ignored for every decision this feeds:
     * the default destination, the "(shared)" tag, copy-to-Personal, the import target and the sort.
     */
    fun vaultInfos(): List<VaultInfo> = cache.vaults()
        .filter { account.hasVault(it.vaultId) }
        .map { v ->
            val name = account.decryptVaultName(v.vaultId, v.metaBlob)
            val personal = v.vaultId == account.personalVaultId
            VaultInfo(
                vaultId = v.vaultId,
                type = if (personal) "personal" else "shared",
                name = if (!name.isNullOrEmpty() && name != VAULT_NAME_FALLBACK) name else if (personal) "Personal" else "Shared",
                role = account.roleFor(v.vaultId),
            )
        }
        .sortedWith(compareBy({ it.type != "personal" }, { it.name.lowercase() }))

    // ---- personal vault identity + account state (security review 2026-10, root cause A §4, §8.5) ----

    /** The account-state blob (contact pins). Refreshed best-effort on every [sync]. */
    val accountState: AccountStateSync = AccountStateSync(api, account, cache, deviceState = deviceState)

    init {
        // Root cause A §1.4 step 7: the grant verifier picks the pin by the sender the statement NAMES, from this
        // account's human-verified contacts, and learns whether that pin is current on this device (L-3).
        account.grantPins = { uid ->
            accountState.doc.contact(uid)?.let { c ->
                runCatching { GrantPin(Bytes.fromB64(c.identityPub), accountState.isCurrent(c)) }.getOrNull()
            }
        }
        for (entry in persistedSet(LEGACY_AUTHORIZED_KEY)) {
            val parts = entry.split('|')
            val tag = parts.getOrNull(1) ?: continue // bound to the exact key vouched for; no tag, no vouch
            account.authorizeLegacyKey(parts[0], tag, frozen = parts.getOrNull(2) == "frozen")
        }
        loadHeldKeys()
    }

    // ---- per-vault held-key memory (security review 2026-10, root cause A, branch A7; R15(g)) ----

    /** Push the persisted held-key tags into the account (the durable record wins). */
    private fun loadHeldKeys() {
        for (entry in persistedSet(HELD_KEYS_KEY)) {
            val parts = entry.split('|')
            if (parts.size == 2) account.rememberHeldKey(parts[0], parts[1])
        }
    }

    /** Persist the tag of every vault the account adopted a key for and this device has no tag for yet. A recorded
     *  tag is never overwritten here; only [hardDropLocal] removes one, with the vault. */
    private fun persistHeldKeys() {
        val persisted = persistedSet(HELD_KEYS_KEY)
        val known = persisted.mapTo(HashSet()) { it.substringBefore('|') }
        val added = account.heldKeyTagsSnapshot().filterKeys { it !in known }.map { (v, t) -> "$v|$t" }
        if (added.isNotEmpty()) persistSet(HELD_KEYS_KEY, persisted + added)
        persistMemberGranted()
    }

    // ---- removal proofs v2 (security review 2026-10, root cause A §6; branch A7) ----

    /**
     * §6.3 `liveSince`: stamp every vault this device now holds a key for, outside the holding area, that has no
     * stamp yet, with the DEVICE clock. Cleared when the vault leaves the live view ([hardDropLocal]), so a re-add
     * this device sees moves it past every proof minted before the re-add. Never set from a server value.
     */
    private fun markLiveVaults() {
        val now = nowMs()
        for (v in cache.vaults()) {
            val id = v.vaultId
            if (!account.hasVault(id) || cache.getHeld(id) != null || cache.liveSince(id) != null) continue
            cache.setLiveSince(id, now)
        }
        for (g in cache.grants()) {
            val id = g.vaultId
            if (!account.hasVault(id) || cache.getHeld(id) != null || cache.liveSince(id) != null) continue
            cache.setLiveSince(id, now)
        }
    }

    /** §6.3 step 5: THIS device's consumed nonces for [vaultId]. */
    private fun consumedFor(vaultId: String): Set<String> = cache.consumedNonces()[vaultId].orEmpty().mapTo(HashSet()) { it.nonce }

    /** A7 review MEDIUM-2: the account state's consumed nonces for [vaultId] (other devices of this user). */
    private fun accountConsumedFor(vaultId: String): Set<String> = accountState.doc.consumedNonces[vaultId].orEmpty().mapTo(HashSet()) { it.nonce }

    /** Called after a personal wrap is stored server-side, so a native host can update its cached
     *  `AccountKeys` (an offline cold start then knows the personal vault without the network). */
    var onPersonalWrapStored: ((io.silencelen.andvari.core.model.PersonalWrap) -> Unit)? = null

    /** Non-null while the human must answer "Which vault is your Personal vault?" (no wrap anywhere). */
    var personalVaultChoices: List<PersonalVaultMigration.Candidate>? = null
        private set

    private val lastPersonalKey = "personal.last"
    private val wrapCacheKey = "personal.wrap"
    private val wrapJson = kotlinx.serialization.json.Json { ignoreUnknownKeys = true }

    // A5b M-1: the device's personal memory lives in [deviceState] when the host gives one (it outlives the
    // cache); it is mirrored into the cache's client state so a host without one behaves as before.
    private fun personalGet(key: String): String? = deviceState?.get(key) ?: cache.clientState(key)
    private fun personalSet(key: String, value: String?) {
        deviceState?.set(key, value)
        cache.setClientState(key, value)
    }

    /** The wrap this device cached the last time it authenticated one (UVK-sealed; null if none). */
    private fun cachedPersonalWrap(): io.silencelen.andvari.core.model.PersonalWrap? = personalGet(wrapCacheKey)?.let {
        runCatching { wrapJson.decodeFromString(io.silencelen.andvari.core.model.PersonalWrap.serializer(), it) }.getOrNull()
    }

    private fun rememberPersonalWrap(wrap: io.silencelen.andvari.core.model.PersonalWrap) {
        personalSet(wrapCacheKey, wrapJson.encodeToString(io.silencelen.andvari.core.model.PersonalWrap.serializer(), wrap))
        personalSet(lastPersonalKey, wrap.vaultId)
    }

    /** The question's choices, from the cached rows and this client's own key provenance. The server's
     *  `type` label and `role` are not read. */
    fun personalCandidates(): List<PersonalVaultMigration.Candidate> {
        val grants = cache.grants().associateBy { it.vaultId }
        val counts = items().groupingBy { it.vaultId }.eachCount()
        return cache.vaults().filter { account.hasVault(it.vaultId) }.map { v ->
            val g = grants[v.vaultId]
            PersonalVaultMigration.Candidate(
                vaultId = v.vaultId,
                // Our OWN row, key from our UVK wrap, and no seal anywhere on the row.
                ownUvkWrap = account.keyFromOwnUvkWrap(v.vaultId) && g != null && g.userId == account.userId &&
                    g.sealedVk.isNullOrEmpty(),
                name = account.decryptVaultName(v.vaultId, v.metaBlob),
                itemCount = counts[v.vaultId] ?: 0,
            )
        }
    }

    /**
     * Root cause A §4.3 as amended by the A5 review (H-1) and re-review (A5b), local only, never minting:
     *  - CONFIRMED (a served wrap opened): if this device cached a wrap for a DIFFERENT vault, the device does
     *    not switch: the cached wrap stays in force and the change waits for the human
     *    ([Account.PersonalStatus.CHANGED], [personalChange]; also covers an older wrap replayed, L-2).
     *    Otherwise cache the served wrap (it is UVK-sealed) and remember its vault;
     *  - ABSENT with a cached wrap: the server WITHHELD it, an anomaly; the cached wrap stands; no question;
     *  - ABSENT with nothing cached: ask the human ([personalVaultChoices]); nothing is picked;
     *  - UNREADABLE with a cached wrap that opens: the junk does not discard it
     *    ([Account.PersonalStatus.UNREADABLE_CACHED], L-1);
     *  - UNREADABLE with nothing usable cached: no personal vault; only a re-designation replaces it.
     */
    private fun decidePersonalLocally() {
        val cached = cachedPersonalWrap()
        when (account.personalStatus) {
            Account.PersonalStatus.CONFIRMED -> {
                personalVaultChoices = null
                if (cached != null && account.holdPersonalChange(cached)) return
                account.personalWrap?.let { rememberPersonalWrap(it) }
            }
            Account.PersonalStatus.WITHHELD, Account.PersonalStatus.CHANGED, Account.PersonalStatus.UNREADABLE_CACHED ->
                personalVaultChoices = null
            Account.PersonalStatus.UNREADABLE -> {
                if (cached != null) account.applyCachedPersonalWrap(cached)
                personalVaultChoices = if (account.personalStatus == Account.PersonalStatus.UNREADABLE_CACHED) null else emptyList()
            }
            Account.PersonalStatus.ABSENT -> {
                if (cached != null) {
                    account.applyCachedPersonalWrap(cached)
                    personalVaultChoices = if (account.personalStatus == Account.PersonalStatus.WITHHELD) null else emptyList()
                    return
                }
                personalVaultChoices = PersonalVaultMigration.choices(personalCandidates(), personalGet(lastPersonalKey))
            }
        }
    }

    // ---- A5b (M-2): an informed, confirmed choice ----

    private val coHoldersByVault = HashMap<String, List<CoHolder>>()
    private var pendingProposal: PersonalVaultProposal? = null

    /** The vault this device already had as personal: its cached wrap, else the last one it used (L-1). */
    fun devicePersonalVaultId(): String? = cachedPersonalWrap()?.vaultId ?: personalGet(lastPersonalKey)

    private fun originOf(vaultId: String): PersonalChoiceInfo.Origin =
        if (cache.vaults().firstOrNull { it.vaultId == vaultId }?.lastTransfer?.newOwnerUserId == account.userId) {
            PersonalChoiceInfo.Origin.RECEIVED_BY_TRANSFER
        } else PersonalChoiceInfo.Origin.CREATED

    /** One vault as the question and the Settings list show it. [PersonalChoiceInfo.coHolders] is null until
     *  [refreshPersonalChoiceDetails] (or a proposal) loaded it. */
    fun personalChoiceInfo(vaultId: String): PersonalChoiceInfo {
        val row = cache.vaults().firstOrNull { it.vaultId == vaultId }
        return PersonalChoiceInfo(
            vaultId = vaultId,
            name = row?.let { account.decryptVaultName(vaultId, it.metaBlob) }?.takeIf { it != VAULT_NAME_FALLBACK },
            itemCount = items().count { it.vaultId == vaultId },
            origin = originOf(vaultId),
            coHolders = coHoldersByVault[vaultId],
            onThisDevice = vaultId == devicePersonalVaultId(),
        )
    }

    private suspend fun loadCoHolders(vaultId: String): List<CoHolder> {
        val list = api.vaultMembers(vaultId).filter { it.userId != account.userId }
            .map { CoHolder(it.userId, it.displayName, it.email, it.role) }
        coHoldersByVault[vaultId] = list
        return list
    }

    /** Best effort: load who else holds each of [vaultIds] for the lists (an unreachable server leaves null). */
    suspend fun refreshPersonalChoiceDetails(vaultIds: Collection<String>) {
        for (id in vaultIds) runCatching { loadCoHolders(id) }
    }

    /**
     * Step 1 of a designation (the first-time question, a Settings re-designation, or keeping the current vault
     * over a [PersonalChange]): describe the chosen vault for the confirmation. Mints NOTHING and sends nothing
     * but the member lookup. Refuses a vault not keyed from our own UVK wrap, and fails if the co-holders cannot
     * be loaded: the confirmation must be able to name them. Supersedes any earlier proposal.
     */
    suspend fun proposePersonalVault(vaultId: String): PersonalVaultProposal {
        pendingProposal = null
        if (!account.keyFromOwnUvkWrap(vaultId)) throw CryptoException("vault $vaultId is not wrapped under this account's key")
        val coHolders = loadCoHolders(vaultId)
        val info = personalChoiceInfo(vaultId)
        return PersonalVaultProposal(vaultId, info.name, info.origin, coHolders, account.personalVaultId.ifEmpty { null })
            .also { pendingProposal = it }
    }

    /** Drop a proposal the human cancelled. */
    fun cancelPersonalProposal() { pendingProposal = null }

    /**
     * Step 2: the human confirmed [proposal] (after reading its name and co-holders). Only the pending proposal
     * this engine issued is accepted, once; anything else throws [IllegalStateException] and mints nothing.
     * [currentAuthKey] (from a FRESH full-password entry) is required by the server to REPLACE an existing
     * wrap (re-designation, Q9); a first designation may omit it.
     */
    suspend fun confirmPersonalVault(proposal: PersonalVaultProposal, currentAuthKey: String?) {
        check(proposal === pendingProposal) { "that personal-vault choice was not confirmed here (or is stale)" }
        pendingProposal = null
        val wrap = account.buildPersonalWrap(proposal.vaultId)
        api.putPersonalWrap(io.silencelen.andvari.core.model.PersonalWrapPut(wrap.vaultId, wrap.wrappedVk, currentAuthKey))
        rememberPersonalWrap(wrap) // before applying, so the new wrap is never mistaken for a change
        account.applyPersonalWrap(wrap)
        decidePersonalLocally() // clears the question
        onPersonalWrapStored?.invoke(wrap)
    }

    /** Vaults a re-designation may offer: held, and keyed from our own UVK wrap (never a seal). */
    fun redesignationChoices(): List<VaultInfo> = vaultInfos().filter { account.keyFromOwnUvkWrap(it.vaultId) }

    /**
     * Settings → "This is my personal vault" (owner decision Q9), confirmed: re-designation with a FRESH
     * master-password reauth. The authKey is derived here from [password] and the account's own salt/params,
     * and the server refuses the replacement without it.
     */
    suspend fun redesignatePersonalVault(proposal: PersonalVaultProposal, password: String) {
        check(proposal === pendingProposal) { "that personal-vault choice was not confirmed here (or is stale)" }
        val keys = api.accountKeys()
        val authKey = kotlinx.coroutines.withContext(kotlinx.coroutines.Dispatchers.Default) {
            Account.deriveAuthKey(password, keys.kdfSalt, keys.kdfParams, account.cryptoProvider())
        }
        confirmPersonalVault(proposal, authKey)
    }

    /** Non-null while a served wrap names another vault than this device's and the human has not decided. */
    fun personalChange(): PersonalChange? {
        if (account.personalStatus != Account.PersonalStatus.CHANGED) return null
        val served = account.pendingPersonalChange ?: return null
        return PersonalChange(account.personalVaultId, served.vaultId)
    }

    /**
     * The human confirmed the change named by [personalChange]: the served wrap (authenticated under our UVK)
     * is now in force and cached. Mints nothing. Keeping the current vault instead is a re-designation
     * ([proposePersonalVault] + [redesignatePersonalVault]), which replaces the server's copy.
     */
    fun acceptPersonalChange() {
        val change = personalChange()
        check(change != null && personalChangeDescribed == change.servedVaultId) {
            "\"Use the new personal vault\" is offered only after its co-holders were loaded (describePersonalChange)"
        }
        personalChangeDescribed = null
        account.acceptPersonalChange()
        account.personalWrap?.let { rememberPersonalWrap(it) } // before deciding, or it would read as a change again
        decidePersonalLocally()
    }

    // ---- signed grants (security review 2026-10, root cause A §1.4–§1.6, §3.2, §8.2; branch A6) ----

    private fun persistedSet(key: String): Set<String> =
        cache.clientState(key)?.split('\n')?.filter { it.isNotEmpty() }?.toSet() ?: emptySet()

    private fun persistSet(key: String, set: Set<String>) {
        cache.setClientState(key, if (set.isEmpty()) null else set.sorted().joinToString("\n"))
    }

    /**
     * §8.2 step 3, once per cache: a v1-only key is FROZEN (self-wrapped silently) when this cache already held
     * the vault's grant row AND an item that decrypted under it before this release ran here. The server would
     * have had to forge the grant before the upgrade: the trust-on-first-use the household already had. Every
     * v1-only vault that arrives later is legacy-read-only until the human accepts it (or the owner re-issues).
     */
    private fun freezeOnce(decryptedVaults: Set<String>) {
        if (cache.clientState(FREEZE_DONE_KEY) != null) return
        val evidence = cache.grants()
            .filter { g ->
                g.userId == account.userId && g.vaultId in decryptedVaults &&
                    account.keySource(g.vaultId) == Account.KeySource.LEGACY_SEAL
            }
            .map { it.vaultId }
        for (id in evidence) vouchLegacy(id, frozen = true)
        cache.setClientState(FREEZE_DONE_KEY, "1")
    }

    /** Persist and apply a §8.2 vouch for the key [vaultId] holds NOW (bound to that key's tag). */
    private fun vouchLegacy(vaultId: String, frozen: Boolean) {
        val tag = account.legacyKeyTag(vaultId) ?: return
        val others = persistedSet(LEGACY_AUTHORIZED_KEY).filterNot { it.startsWith("$vaultId|") }
        persistSet(LEGACY_AUTHORIZED_KEY, (others + "$vaultId|$tag|${if (frozen) "frozen" else "confirmed"}").toSet())
        account.authorizeLegacyKey(vaultId, tag, frozen)
    }

    /** Re-run §1.4 for cached rows whose key is not held (pending, refused) or held only from a v1 seal; decrypt
     *  the cached items of any vault that became readable. */
    private fun reevaluateGrants() {
        val newlyHeld = HashSet<String>()
        for (g in cache.grants()) {
            if (g.userId != account.userId) continue
            val held = account.hasVault(g.vaultId)
            val retry = !held || (account.keySource(g.vaultId) == Account.KeySource.LEGACY_SEAL && !g.signedGrant.isNullOrEmpty())
            if (!retry || cache.getHeld(g.vaultId) != null) continue
            runCatching { account.addGrant(g) }
            if (!held && account.hasVault(g.vaultId)) newlyHeld.add(g.vaultId)
        }
        if (newlyHeld.isEmpty()) return
        for (w in cache.envelopes()) {
            if (w.deleted || w.vaultId !in newlyHeld) continue
            runCatching { cache.upsertItem(w, VaultItem(w.itemId, w.vaultId, w.rev, w.updatedAt, account.decryptItem(w))) }
        }
    }

    /** §1.4 anomalies, once per vault per engine ("the server may be misbehaving — tell your admin"). */
    private fun surfaceGrantStates() {
        for ((vaultId, verdict) in account.grantAnomalies()) {
            if (!keyAnomaliesShown.add("grant-anomaly|$vaultId|${verdict.code}")) continue
            pushNotice(LifecycleNotice(account.newItemId(), vaultId, "", "grant-anomaly", reason = verdict.code))
        }
    }

    private val selfWrapsPosted = mutableSetOf<String>()

    /** §3.2: post the member self-wrap for every held key [Account.selfWrapAuthorized] vouches for. Best effort. */
    private suspend fun postAuthorizedSelfWraps() {
        for (g in cache.grants()) postSelfWrapIfAuthorized(g)
    }

    private suspend fun postSelfWrapIfAuthorized(g: WireGrant): Boolean {
        if (g.vaultId in selfWrapsPosted || !account.needsSelfWrap(g) || !account.selfWrapAuthorized(g.vaultId)) return false
        return runCatching {
            api.putGrantSelfWrap(g.vaultId, io.silencelen.andvari.core.model.SelfWrapRequest(account.buildSelfWrap(g.vaultId)))
            selfWrapsPosted.add(g.vaultId)
        }.isSuccess
    }

    /** Pending invitations the human has not declined. */
    fun pendingInvitations(): List<PendingInvitation> {
        val declined = persistedSet(DECLINED_KEY)
        // A vault held only through an unvouched legacy seal whose row now carries a pending v2 grant is listed
        // too: verifying the sender confirms the key (it is off the review card, A6 review LOW-2).
        return account.pendingGrants().filter {
            it.grantIdB64 !in declined && (!account.hasVault(it.vaultId) || account.isLegacyReadOnly(it.vaultId))
        }
            .map { PendingInvitation(it.vaultId, it.fromUserId, it.grantIdB64) }
    }

    /** Who the SERVER says sent [inv] (display name + the key a human must verify). Untrusted. */
    suspend fun invitationSender(inv: PendingInvitation): UserLookupResponse = api.userIdentity(inv.fromUserId)

    /**
     * Accept [inv] (§1.6): run the verification ceremony for its sender (the human TYPED the sender's 32-hex code,
     * read from THEIR screen), then re-run §1.4. True only when the grant now verifies and the vault is adopted.
     * A wrong code pins nothing and adopts nothing.
     */
    suspend fun acceptInvitation(inv: PendingInvitation, typedCode: String): Boolean {
        val served = api.userIdentity(inv.fromUserId)
        if (served.userId != inv.fromUserId) return false
        verifyMemberTyped(served, typedCode) ?: return false
        return afterInvitationPin(inv)
    }

    /** As [acceptInvitation], with a scan of the sender's identity QR (full-length compare). */
    suspend fun acceptInvitationQr(inv: PendingInvitation, qrPayload: String): Boolean {
        val served = api.userIdentity(inv.fromUserId)
        if (served.userId != inv.fromUserId) return false
        verifyMemberQr(served, qrPayload) ?: return false
        return afterInvitationPin(inv)
    }

    private suspend fun afterInvitationPin(inv: PendingInvitation): Boolean {
        reevaluateGrants()
        surfaceGrantStates()
        val adopted = account.hasVault(inv.vaultId) && account.keySource(inv.vaultId) == Account.KeySource.SIGNED_GRANT
        if (adopted) cache.grants().firstOrNull { it.vaultId == inv.vaultId }?.let { postSelfWrapIfAuthorized(it) }
        return adopted
    }

    /** "Decline": hide [inv] on this device (by grantId, so a re-issued grant asks again). */
    fun declineInvitation(inv: PendingInvitation) {
        persistSet(DECLINED_KEY, persistedSet(DECLINED_KEY) + inv.grantIdB64)
    }

    /** §8.2 "Review your shared vaults": the vaults readable only through an unconfirmed v1 seal. */
    fun legacyReviewVaults(): List<LegacyVaultReview> {
        // A6 review LOW-2: vaults whose v2 field failed or awaits verification are not offered for trust on first use.
        val ids = (account.legacyReadOnlyVaultIds() - account.grantAnomalies().keys - account.pendingGrants().map { it.vaultId }.toSet())
            .filterNot { account.heldKeyContradictsVouch(it) }.toSet() // round 3: the vouch gate
        if (ids.isEmpty()) return emptyList()
        val counts = items().groupingBy { it.vaultId }.eachCount()
        return cache.vaults().filter { it.vaultId in ids }.map { v ->
            LegacyVaultReview(v.vaultId, account.decryptVaultName(v.vaultId, v.metaBlob)?.takeIf { it != VAULT_NAME_FALLBACK }, counts[v.vaultId] ?: 0)
        }.sortedBy { it.vaultId }
    }

    /** The owner the SERVER reports for [vaultId] (the review card labels it as server-reported). */
    suspend fun reportedOwner(vaultId: String): CoHolder? =
        api.vaultMembers(vaultId).firstOrNull { it.role == "owner" }?.let { CoHolder(it.userId, it.displayName, it.email, it.role) }

    /**
     * The human pressed "Accept" on the review card (Q7, trust on first use): this device vouches for the v1-only
     * key of [vaultId]. Persisted, the read-only state lifts, and the self-wrap is posted.
     */
    suspend fun acceptLegacyVault(vaultId: String) {
        check(account.isLegacyReadOnly(vaultId)) { "vault $vaultId is not awaiting review" }
        // A6 review LOW-2: a row whose v2 field failed or awaits verification is never an "Accept anyway".
        check(!account.heldKeyContradictsVouch(vaultId)) { "vault $vaultId holds a key this device's earlier vouch contradicts" }
        check(vaultId !in account.grantAnomalies() && account.pendingGrants().none { it.vaultId == vaultId }) {
            "vault $vaultId has a grant that failed verification or awaits it; it cannot be accepted on trust"
        }
        vouchLegacy(vaultId, frozen = false)
        cache.grants().firstOrNull { it.vaultId == vaultId }?.let { postSelfWrapIfAuthorized(it) }
    }

    // ---- owner side (§1.5, §8.2 step 4) ----

    /** How a served identity relates to this device's pins, for the add-member flow (§1.5, §7.2). */
    enum class MemberPinState {
        /** Pinned, current on this device, and the served key is the pinned key: no fingerprint step. */
        PINNED,

        /** Pinned, but the server now serves ANOTHER key for them: refuse, and verify again in person. */
        KEY_CHANGED,

        /** Not pinned here (or the pin is not current on this device, L-3): run the verification ceremony. */
        NEEDS_VERIFICATION,
    }

    fun memberPinState(served: UserLookupResponse): MemberPinState = memberPinState(served.userId, served.identityPub)

    fun memberPinState(userId: String, servedIdentityPub: String): MemberPinState {
        val pin = accountState.currentPin(userId) ?: return MemberPinState.NEEDS_VERIFICATION
        return when (ContactPin.pinState(accountState.doc, ServedIdentity(userId, servedIdentityPub))) {
            ContactPin.PinState.PINNED_MATCH -> if (pin.userId == userId) MemberPinState.PINNED else MemberPinState.NEEDS_VERIFICATION
            ContactPin.PinState.PINNED_MISMATCH -> MemberPinState.KEY_CHANGED
            ContactPin.PinState.UNPINNED -> MemberPinState.NEEDS_VERIFICATION
        }
    }

    // ---- grant authority (security review 2026-10, root cause A, branch A6b) ----
    //
    // THE INVARIANT: this client never signs or seals a vault key to a user unless (a) a human on this device
    // confirmed that (vault, user) pair now ([addVaultMember] from the add-member screen, [confirmReissue] from the
    // "Legacy grants" list), or (b) the pair is in this account's UVK-authenticated issued-grants record for the SAME
    // identity key ([reissueGrant]). And no owner-only signing action (add member, re-issue, transfer offer) runs on
    // the strength of the server's `role=owner` label: it needs this account's own owned-vaults record ([ownsVault]),
    // written at creation, at transfer accept, or by a password-reauthed "You own <vault>?" ([confirmOwnership]).
    // The server's member list and `legacyGrant` flag only decide what is SHOWN.

    /** True when this account's own evidence (account state, UVK-authenticated) says it owns [vaultId]. */
    fun ownsVault(vaultId: String): Boolean = accountState.owns(vaultId)

    /**
     * The server reports this account as [vaultId]'s owner, but this account has no evidence of it: the vault was
     * created before A6b, or on a device whose record never synced. The first owner action asks "You own <vault>?".
     */
    fun ownershipNeedsConfirmation(vaultId: String): Boolean =
        account.hasVault(vaultId) && account.serverRoleFor(vaultId) == "owner" && !ownsVault(vaultId) &&
            vaultId != account.personalVaultId

    private fun requireOwned(vaultId: String) {
        if (!ownsVault(vaultId)) throw OwnershipNotConfirmedException(vaultId)
    }

    private var pendingOwnershipClaim: OwnershipClaim? = null

    /** A6b review MEDIUM-1: this device first adopted [vaultId]'s key as a MEMBER (a seal, a v2 grant, a non-owner
     *  row), now or in an earlier session (the durable record; the in-memory bit is rebuilt from served rows). */
    fun receivedAsMember(vaultId: String): Boolean =
        account.keyArrivedByMemberGrant(vaultId) || vaultId in persistedSet(MEMBER_GRANTED_KEY) ||
            accountState.doc.receivedAsMember(vaultId)

    private fun persistMemberGranted() {
        val persisted = persistedSet(MEMBER_GRANTED_KEY)
        val added = cache.vaults().map { it.vaultId }.filter { it !in persisted && account.keyArrivedByMemberGrant(it) }
        if (added.isNotEmpty()) persistSet(MEMBER_GRANTED_KEY, persisted + added)
    }

    /**
     * A6b carry-forward LOW-R (A1b): every vault THIS device recorded as received-as-member joins the account state too
     * (UVK-sealed, union-merged, add-only), so a fresh device of the same account whose first served row is
     * owner-shaped still asks for the transfer acknowledgement. Best effort: a failed write is retried next sync.
     */
    private suspend fun flushMemberReceived() {
        val local = persistedSet(MEMBER_GRANTED_KEY).filter { !accountState.doc.receivedAsMember(it) }
        if (local.isEmpty()) return
        val at = nowMs()
        runCatching { accountState.update { d -> AccountState.withMemberReceived(d, local, at) } }
    }

    /**
     * Step 1 of "You own <vault>?" (A6b review MEDIUM-1): what the confirmation must show, loaded BEFORE it is offered.
     * Everything but [OwnershipClaim.receivedAsMember] is what the SERVER reports (who it lists as owner, its last
     * completed transfer, the co-holders); it informs, it decides nothing. Mints nothing. Refuses a vault whose key
     * does not come from this account's own UVK wrap, and THROWS when the members cannot be loaded (the dialog must
     * name them). Supersedes any earlier claim.
     */
    suspend fun describeOwnership(vaultId: String): OwnershipClaim {
        pendingOwnershipClaim = null
        if (!account.hasVault(vaultId) || !account.keyFromOwnUvkWrap(vaultId) || account.isLegacyReadOnly(vaultId) ||
            account.heldKeyContradictsVouch(vaultId)
        ) throw VaultKeyNotVerifiedException(vaultId)
        val members = api.vaultMembers(vaultId).map { CoHolder(it.userId, it.displayName, it.email, it.role) }
        val row = cache.vaults().firstOrNull { it.vaultId == vaultId }
        val lt = row?.lastTransfer
        return OwnershipClaim(
            vaultId = vaultId,
            vaultName = row?.let { account.decryptVaultName(vaultId, it.metaBlob) }?.takeIf { it != VAULT_NAME_FALLBACK },
            reportedOwner = members.firstOrNull { it.role == "owner" },
            lastTransferTo = lt?.let { t -> members.firstOrNull { it.userId == t.newOwnerUserId } ?: CoHolder(t.newOwnerUserId, "", "", "") },
            lastTransferSeq = lt?.seq,
            coHolders = members.filter { it.userId != account.userId },
            origin = originOf(vaultId),
            receivedAsMember = receivedAsMember(vaultId),
        ).also { pendingOwnershipClaim = it }
    }

    /** Drop a claim the human cancelled. */
    fun cancelOwnershipClaim() { pendingOwnershipClaim = null }

    /**
     * Step 2, "You own <vault>?" confirmed (A6b): only the claim this engine described ([describeOwnership]) and still
     * holds; a fresh master-password reauth checked on this device against the UVK this session holds
     * ([Account.verifyPassword]); and, for a vault this device received as a MEMBER, the human's explicit second
     * acknowledgement [transferredToMe] ("This vault's owner transferred it to me": a genuine owner whose vault was
     * transferred to them before A6b is in exactly this state, so it is not refused outright). Records [vaultId] as owned.
     */
    suspend fun confirmOwnership(claim: OwnershipClaim, password: String, transferredToMe: Boolean = false) {
        check(claim === pendingOwnershipClaim) { "that ownership confirmation was not described here (or is stale)" }
        val vaultId = claim.vaultId
        if (!account.hasVault(vaultId) || !account.keyFromOwnUvkWrap(vaultId) || account.isLegacyReadOnly(vaultId) ||
            account.heldKeyContradictsVouch(vaultId)
        ) throw VaultKeyNotVerifiedException(vaultId)
        if (receivedAsMember(vaultId) && !transferredToMe) throw OwnershipTransferAckRequiredException(vaultId)
        val keys = api.accountKeys()
        // A6b carry-forward (A1b): a salt this session did not unlock with (a password change or KDF upgrade since) can
        // never verify; say how to recover instead of "that master password isn't right".
        if (!account.sessionSaltCurrent(keys)) throw ReauthStaleSessionException()
        val ok = kotlinx.coroutines.withContext(kotlinx.coroutines.Dispatchers.Default) { account.verifyPassword(password, keys) }
        if (!ok) throw ReauthFailedException()
        pendingOwnershipClaim = null
        accountState.update { AccountState.withOwned(it, vaultId, nowMs()) }
    }

    /** Create a shared vault (owner): this account's own evidence that it owns it is recorded at once. */
    suspend fun createSharedVault(name: String): String {
        val nv = account.buildCreateSharedVault(name)
        try {
            api.createVault(nv.request)
        } catch (e: Throwable) {
            account.removeVault(nv.vaultId) // roll back the optimistic local registration
            throw e
        }
        runCatching { accountState.update { AccountState.withOwned(it, nv.vaultId, nowMs()) } }
        reconcileSync()
        return nv.vaultId
    }

    private fun keyHash(identityPubB64: String): String = Bytes.toHexLower(account.cryptoProvider().sha256(Bytes.fromB64(identityPubB64)))

    private suspend fun recordIssued(vaultId: String, pin: Contact) {
        runCatching { accountState.update { AccountState.withIssued(it, vaultId, pin.userId, keyHash(pin.identityPub), nowMs()) } }
    }

    /**
     * Add [userId] to [vaultId] (owner, §1.5). A human picked this vault and this member on the add-member screen
     * (rule a). Only a vault this account OWNS by its own evidence ([OwnershipNotConfirmedException] otherwise) and a
     * member PINNED and current on this device ([MemberNotVerifiedException] otherwise); the v2 grant and, in the
     * compatibility window, the dual-sent v1 seal are both sealed to the PIN key. The pair is then recorded.
     */
    suspend fun addVaultMember(vaultId: String, userId: String, role: String) {
        requireOwned(vaultId)
        val pin = accountState.currentPin(userId) ?: throw MemberNotVerifiedException(userId)
        val signed = account.buildSignedGrant(vaultId, pin)
        val sealed = account.wrapVkForMember(Bytes.fromB64(pin.identityPub), vaultId)
        api.addVaultMember(vaultId, VaultMemberAdd(userId, role, sealed, signed))
        recordIssued(vaultId, pin)
    }

    private suspend fun postReissue(vaultId: String, pin: Contact) {
        api.reissueGrant(vaultId, pin.userId, GrantReissueRequest(account.buildSignedGrant(vaultId, pin)))
        recordIssued(vaultId, pin)
    }

    /**
     * §8.2 step 4 WITHOUT a prompt (rule b only): re-issue [userId]'s grant for [vaultId] as v2 with the SAME key, when
     * this account owns the vault by its own evidence and the pair is in its issued-grants record for the key now
     * pinned. Anything else throws ([ReissueNotAuthorizedException]): it needs [confirmReissue].
     */
    suspend fun reissueGrant(vaultId: String, userId: String) {
        requireOwned(vaultId)
        val pin = accountState.currentPin(userId) ?: throw MemberNotVerifiedException(userId)
        val rec = accountState.issued(vaultId, userId)
        if (rec == null || rec.keyHash != keyHash(pin.identityPub)) throw ReissueNotAuthorizedException(vaultId, userId)
        postReissue(vaultId, pin)
    }

    private val legacyRowsByVault = HashMap<String, List<LegacyGrantRow>>()

    /** Vaults a verified transfer moved away from this account during a pull; tombstoned at the end of [sync]. */
    private val ownershipReleases = LinkedHashSet<String>()

    private suspend fun flushOwnershipReleases() {
        if (ownershipReleases.isEmpty()) return
        val ids = ownershipReleases.toList()
        ownershipReleases.clear()
        runCatching { accountState.update { d -> ids.fold(d) { acc, id -> AccountState.withoutOwned(acc, id, nowMs()) } } }
    }

    /**
     * The "Legacy grants" list for [vaultId] (§8.2 step 4, A6b): the members the SERVER lists as still holding only a
     * v1 grant (a hint), each with the vault name and, when pinned and current here, the member's VERIFIED label.
     * Loading it re-issues, without a prompt, only the pairs in this account's issued-grants record for the same key
     * (rule b); every other row waits for the owner's per-row confirmation ([confirmReissue]). Never called by
     * [sync]. Throws when the member list cannot be loaded.
     */
    suspend fun loadLegacyGrants(vaultId: String): List<LegacyGrantRow> {
        legacyRowsByVault.remove(vaultId)
        if (!account.hasVault(vaultId) || account.isLegacyReadOnly(vaultId)) return emptyList()
        val members = api.vaultMembers(vaultId)
        val name = cache.vaults().firstOrNull { it.vaultId == vaultId }?.let { account.decryptVaultName(vaultId, it.metaBlob) }
            ?.takeIf { it != VAULT_NAME_FALLBACK }
        val owned = ownsVault(vaultId)
        val rows = mutableListOf<LegacyGrantRow>()
        for (m in members) {
            if (m.legacyGrant != true || m.role == "owner" || m.userId == account.userId) continue
            val state = memberPinState(m.userId, m.identityPub)
            val pin = accountState.currentPin(m.userId)
            if (owned && state == MemberPinState.PINNED && pin != null && accountState.issued(vaultId, m.userId)?.keyHash == keyHash(pin.identityPub)) {
                if (runCatching { postReissue(vaultId, pin) }.isSuccess) continue
            }
            rows.add(LegacyGrantRow(vaultId, name, m.userId, m.displayName, m.email, m.identityPub, pin?.label?.takeIf { state == MemberPinState.PINNED }, state, owned))
        }
        legacyRowsByVault[vaultId] = rows
        return rows
    }

    /** The rows the last [loadLegacyGrants] for [vaultId] returned (empty until one ran). */
    fun legacyGrantRows(vaultId: String): List<LegacyGrantRow> = legacyRowsByVault[vaultId].orEmpty()

    /**
     * The owner tapped "Re-share <vault> with <member>" on [row] (rule a). Only a row this engine itself offered in
     * the current list is accepted, once; the vault must be owned by this account's evidence and the member pinned
     * and current here with the key the row shows. Signs and seals to the PIN key, then records the pair.
     */
    suspend fun confirmReissue(row: LegacyGrantRow) {
        val offered = legacyRowsByVault[row.vaultId].orEmpty()
        check(offered.any { it === row }) { "that re-share was not offered here (or the list is stale)" }
        requireOwned(row.vaultId)
        val pin = accountState.currentPin(row.userId) ?: throw MemberNotVerifiedException(row.userId)
        if (memberPinState(row.userId, row.identityPub) != MemberPinState.PINNED) throw MemberNotVerifiedException(row.userId)
        postReissue(row.vaultId, pin)
        legacyRowsByVault[row.vaultId] = offered.filterNot { it === row }
    }

    // ---- A5b review LOW-1 / LOW-2: "Use the new personal vault" only once its co-holders loaded ----

    private var personalChangeDescribed: String? = null

    /**
     * Load what "Use the new personal vault" would mean: the new vault's co-holders (as the server reports them)
     * and origin. THROWS when the member lookup fails, and then [acceptPersonalChange] stays refused: the human
     * may only switch to a vault whose co-holders they were shown. Keeping the current vault needs nothing.
     */
    suspend fun describePersonalChange(): PersonalChangeDetails {
        personalChangeDescribed = null
        val change = personalChange() ?: throw IllegalStateException("no personal-vault change is pending")
        val coHolders = loadCoHolders(change.servedVaultId)
        val nameOf = { id: String ->
            cache.vaults().firstOrNull { it.vaultId == id }?.let { account.decryptVaultName(id, it.metaBlob) }?.takeIf { it != VAULT_NAME_FALLBACK }
        }
        personalChangeDescribed = change.servedVaultId
        return PersonalChangeDetails(change.currentVaultId, nameOf(change.currentVaultId), change.servedVaultId, nameOf(change.servedVaultId), coHolders, originOf(change.servedVaultId))
    }

    // ---- "Verify a household member" (root cause A §7.2), shared by the native screens ----

    /** This account's identity QR payload, over the SEED-DERIVED key (never a server value). */
    fun identityQrPayload(): String = IdentityQr.compose(account.cryptoProvider(), account.userId, account.identityPub)

    /** Find a member by email. The returned key is UNTRUSTED until [verifyMemberTyped]/[verifyMemberQr]. */
    suspend fun lookupMember(email: String): io.silencelen.andvari.core.model.UserLookupResponse = api.lookupUser(email)

    /**
     * Pin [served] iff the human-typed [typed] (their 32 hex, read from THEIR screen) matches SHA-256 of the
     * key the server serves for them. Null (nothing pinned) on a mismatch.
     */
    suspend fun verifyMemberTyped(served: io.silencelen.andvari.core.model.UserLookupResponse, typed: String): Contact? {
        val c = ContactPin.fromTyped(account.cryptoProvider(), typed, ServedIdentity(served.userId, served.identityPub), served.displayName, nowMs()) ?: return null
        accountState.pin(c)
        return c
    }

    /** Pin [served] iff a scanned identity QR matches the served key at FULL length. */
    suspend fun verifyMemberQr(served: io.silencelen.andvari.core.model.UserLookupResponse, qrPayload: String): Contact? {
        val c = ContactPin.fromQr(account.cryptoProvider(), qrPayload, ServedIdentity(served.userId, served.identityPub), served.displayName, nowMs()) ?: return null
        accountState.pin(c)
        return c
    }

    /** One-tap pin from a members list (§8.2 step 6): the same typed comparison, against the key the member row
     *  carries. Nothing is pinned on a mismatch. */
    suspend fun verifyMemberTyped(member: VaultMemberSummary, typed: String): Contact? =
        verifyMemberTyped(UserLookupResponse(member.userId, member.displayName, member.identityPub), typed)

    /** Remove a pin (tombstoned). */
    suspend fun unpinMember(userId: String) = accountState.unpin(userId)

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
        rejectedMutationIds.clear() // H03: per-row verdicts are consumed by the save that sent them; a background cycle starts clean
        flushQueue()
        pull()
        surfaceStagedDenials()
        // Root cause A §4.3 (A5 review H-1): local, never mints. §4.2: best effort, never fails the sync.
        decidePersonalLocally()
        runCatching { accountState.refresh() }
        // Root cause A (branch A6). Pins may have changed: re-run §1.4 for rows not yet adopted (pending
        // invitations, legacy keys an owner re-issued). Then the member self-wrap (§3.2), minted ONLY for a key
        // from a verified v2 grant or a v1 key this device froze or the human confirmed (never for a key only an
        // unconfirmed v1 seal vouches for: the A1 laundering bug). The owner's §8.2 step 4 re-issue is NOT run here
        // (A6b): it needs the owner's confirmation, or the issued-grants record, through the "Legacy grants" list.
        reevaluateGrants()
        persistHeldKeys()
        markLiveVaults()
        surfaceGrantStates()
        postAuthorizedSelfWraps()
        flushOwnershipReleases()
        flushMemberReceived()
    }

    /**
     * Rebuild the account + decrypted working set from the durable cache — called once
     * after Account.unlock, before the first sync(). Grants/vaults are pull DELTAS
     * (spec 03 §4): once the cursor moved past them they never re-send, so cold start
     * MUST reconstruct keys purely from persisted rows. Undecryptable envelopes are
     * retried here on every launch (e.g. after an upgrade or a later-opened grant).
     */
    fun hydrate() {
        loadHeldKeys() // A7: the durable record first (a rolled-back pull re-hydrates through here too)
        for (g in cache.grants()) {
            runCatching { account.addGrant(g) } // role applies unconditionally; key opens if missing
        }
        // Root cause A §4.3 (A5 H-1, A5b): the served personal wrap was judged at unlock; here it is checked
        // against the wrap this device cached (withheld, junk, or naming another vault). With no wrap anywhere
        // the human is asked; nothing is picked automatically and the server's `type` label is not an input.
        decidePersonalLocally()
        val decryptedVaults = HashSet<String>()
        for (w in cache.envelopes()) {
            // INV-HOME (A1b): rebuild/confirm the home from the cached rows (an upgraded cache records its homes here);
            // a cached row that contradicts a recorded home is quarantined, never decrypted into the working set.
            if (!admitHome(w)) {
                cache.deleteItem(w.itemId)
                continue
            }
            if (w.deleted || !account.hasVault(w.vaultId)) continue
            runCatching {
                cache.upsertItem(w, VaultItem(w.itemId, w.vaultId, w.rev, w.updatedAt, account.decryptItem(w)))
                decryptedVaults.add(w.vaultId)
            }
        }
        freezeOnce(decryptedVaults)
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
        // Rebuild incoming-transfer state (spec 03 §11): a pending-offer row is NOT
        // re-delivered while the offer merely pends (only cancel/expiry/re-designate/
        // accept re-deliver it), so the verified consent surface must be recomputed from
        // the cached rows or a restart mid-offer loses the offer until the owner acts.
        // noticeable=false: rebuilding must never re-fire completion/anomaly notices for
        // rows already seen before the restart. Idempotent per row (it starts by clearing
        // the vault's entry), and a verified-completion sighting still advances the
        // durable seq floor — an apply-time verification skip is retried here.
        for (v in cache.vaults()) {
            runCatching { applyTransferState(v, noticeable = false) }
        }
        persistHeldKeys()
        markLiveVaults()
        surfaceKeyAnomalies()
    }

    /** Close the underlying cache (must precede deleting its DB file — Windows file locks). */
    fun close() = cache.close()

    private suspend fun pull() {
        // §8.2 (A6 re-review LOW-D): evidence is what THIS cache held before the upgrade. Every pull (sync, an
        // import, a write's reconcile) marks the freeze as done FIRST, so if no hydrate looked at the cache, nothing
        // this engine pulls from now on can count as pre-upgrade evidence.
        if (cache.clientState(FREEZE_DONE_KEY) == null) cache.setClientState(FREEZE_DONE_KEY, "1")
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
            if (account.hasVault(v.vaultId)) prePullNames[v.vaultId] = account.decryptVaultName(v.vaultId, v.metaBlob) ?: VAULT_NAME_FALLBACK
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
            pendingAddedNotices.clear() // H71: nothing this tx minted is true after the rollback
            wrongVault = ItemHome.Tally() // the refused rows rolled back with the tx; the next pull refuses them again
            throw t
        }

        if (myStart > freshestCompletedPullStart) freshestCompletedPullStart = myStart

        // H71: "You were added to X" — minted inside the tx (the name decrypts under the
        // freshly-opened key there), surfaced only now that the tx committed, so a rolled-
        // back pull never announces a grant the cache does not hold.
        for (n in pendingAddedNotices) pushNotice(n)
        pendingAddedNotices.clear()

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
        surfaceKeyAnomalies()
        surfaceWrongVault()
    }

    /**
     * INV-HOME (security review 2026-10, root cause A §5.1; branch A1b): admit one served or cached row against
     * `home(itemId)`. The first row for an itemId records its home; a later row (live or tombstone) under another
     * vault is NOT applied: it is quarantined and counted for this pull's single "wrong vault" anomaly.
     */
    private fun admitHome(item: WireItem): Boolean =
        when (ItemHome.admit(cache.itemHome(item.itemId), item.vaultId)) {
            ItemHome.Admit.NEW_HOME -> {
                cache.setItemHome(item.itemId, item.vaultId)
                true
            }
            ItemHome.Admit.HOME -> true
            ItemHome.Admit.QUARANTINE -> {
                cache.quarantine(item)
                wrongVault.note(item.vaultId)
                false
            }
        }

    /** INV-HOME / INV-CONFLICT: this pull's refusals, as ONE "the server sent an item under the wrong vault" notice. */
    private var wrongVault = ItemHome.Tally()

    private fun surfaceWrongVault() {
        val t = wrongVault
        wrongVault = ItemHome.Tally()
        if (t.anomalies() == 0) return
        pushNotice(LifecycleNotice(account.newItemId(), t.firstVaultId ?: "", "", "wrong-vault", parkedCount = t.refused))
    }

    /** Rows refused by INV-HOME on this device (ciphertext, never applied), for diagnosis. */
    fun quarantinedItems(): List<WireItem> = cache.quarantined()

    /**
     * INV-SEAL (root cause A §5.1; branch A1b): the ONE item seal for a push. [provenance] names where the plaintext
     * came from, and so the only vault it may be sealed under; the item must live there (its home), or have no home yet
     * (a fresh id: a copy, an import row, a new item), which this seal then records. [Account.sealItem] adds
     * INV-WRITE-KEY. A refusal throws [ItemChangedVaultsException]; nothing is re-targeted.
     */
    private fun sealFor(provenance: SealProvenance, itemId: String, doc: ItemDoc): io.silencelen.andvari.core.model.ItemUpload {
        val home = cache.itemHome(itemId)
        if (ItemHome.seal(home, provenance.vaultId) == ItemHome.Seal.REFUSE) throw ItemChangedVaultsException()
        val upload = account.sealItem(provenance, itemId, doc)
        if (home == null) cache.setItemHome(itemId, provenance.vaultId)
        return upload
    }

    /**
     * Canonical-key precedence, the surfacing half (security review 2026-10, root cause A §3.1):
     * [Account.addGrant] already kept our own UVK-wrapped key and refused the seal, or refused a
     * damaged wrap outright; this turns those verdicts into the house "server may be misbehaving"
     * signal, ONCE per vault per engine. The key verdicts are rebuilt from the cached rows on
     * every hydrate, so a server that keeps serving the bad row is reported again next session.
     */
    private fun surfaceKeyAnomalies() {
        for (vaultId in account.vkMismatchVaultIds()) {
            if (!keyAnomaliesShown.add("vk-mismatch|$vaultId")) continue
            val name = cache.vaults().firstOrNull { it.vaultId == vaultId }
                ?.let { account.decryptVaultName(vaultId, it.metaBlob) } ?: VAULT_NAME_FALLBACK
            pushNotice(LifecycleNotice(account.newItemId(), vaultId, name, "vk-mismatch"))
        }
        for (vaultId in account.keyUnreadableVaultIds()) {
            if (!keyAnomaliesShown.add("key-unreadable|$vaultId")) continue
            // No key, so the name cannot be decrypted: the copy falls back to "a vault".
            pushNotice(LifecycleNotice(account.newItemId(), vaultId, "", "key-unreadable"))
        }
    }

    private class ReinstatedVault(val vaultId: String, val cachedName: String)

    /** Replayed-then-denied edits (#6): the vault is live again but our role no longer
     *  allows the write (e.g. re-added as reader) — a calm one-time notice, never a thrown
     *  sync failure, and the rows were already durably dropped in [flushQueue]. */
    private fun drainReplayDenied() {
        if (replayDeniedByVault.isEmpty()) return
        for ((vid, n) in replayDeniedByVault) {
            val name = cache.vaults().find { it.vaultId == vid }
                ?.let { account.decryptVaultName(vid, it.metaBlob) } ?: VAULT_NAME_FALLBACK
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
            val newlyAdded = mutableSetOf<String>() // H71: grants for vaults not held before this pull
            for (grant in resp.grants) {
                // Persist UNCONDITIONALLY (ciphertext rows; deltas never re-send) — the
                // in-memory key-open below may fail/skip, hydrate() retries from disk.
                cache.upsertGrant(grant)
                val heldBefore = account.hasVault(grant.vaultId) // BEFORE addGrant opens the key
                // addGrant applies role changes even when the VK is already held (a role
                // change re-delivers the grant precisely for this).
                runCatching {
                    account.addGrant(grant)
                    if (cache.getHeld(grant.vaultId) != null) reinstatedIds.add(grant.vaultId)
                    else if (!heldBefore && since > 0 && !resyncing) newlyAdded.add(grant.vaultId) // a genuine add
                }
            }
            for (delivered in resp.vaults) {
                // spec 02 §4 warn-and-keep-newer: a delivered metaBlob whose metaV
                // regressed keeps the newer local blob (rev/lifecycle fields still apply).
                val vault = keepNewerMeta(delivered)
                cache.upsertVault(vault)
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
            // H71 (web F20 twin, store.ts newlyAdded): a calm "you were added to <vault>" notice
            // for each vault whose key we did NOT hold before this pull but now do. Never on a
            // since=0 / resync pull (newlyAdded is empty then — notices fire only for verifiable
            // NEW state), never for a reinstated (restored / re-added held) vault (that path
            // emits "restored"), never for a personal vault, never for a vault we OWN (an owner
            // grant is our OWN wrappedVk, so a second device of this account sees a vault it just
            // created as a brand-new grant — "you were added" would be a lie there; ownership
            // handed TO us arrives on a vault we already held and emits transfer-complete), and
            // once per vault for the engine's lifetime. Computed AFTER vaults apply so the name
            // decrypts under the freshly-opened key. Transparency for honest servers only — a
            // lying server can equally omit the grant; this is not an F16 defense.
            for (vaultId in newlyAdded) {
                if (vaultId in reinstatedIds || vaultId in addedNoticed) continue
                val v = cache.vaults().find { it.vaultId == vaultId } ?: continue
                if (vaultId == account.personalVaultId || !account.hasVault(vaultId)) continue
                if (account.roleFor(vaultId) == "owner") continue
                addedNoticed.add(vaultId)
                val name = account.decryptVaultName(vaultId, v.metaBlob) ?: VAULT_NAME_FALLBACK
                // §1.6: a verified grant names the PINNED contact who signed it; a legacy add names no one.
                val by = account.signedGrantSender(vaultId)?.let { accountState.doc.contact(it)?.label }
                pendingAddedNotices.add(LifecycleNotice(account.newItemId(), vaultId, name, "added", byLabel = by))
            }
            for (item in resp.items) {
                // INV-HOME first: a row under another vault than this item's home is not applied at all (not even a
                // tombstone), and never reaches the cache, the working set, export or autofill.
                if (!admitHome(item)) continue
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
                    if (cache.getItem(wi.itemId) != null || !admitHome(wi)) continue
                    runCatching {
                        cache.upsertItem(wi, VaultItem(wi.itemId, vaultId, wi.rev, wi.updatedAt, account.decryptItem(wi)))
                    }
                }
                val name = prePullNames[vaultId]
                    ?: held.grant?.let { account.peekVaultName(it, held.vault.metaBlob) }
                    ?: VAULT_NAME_FALLBACK
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
            markLiveVaults()
            persistHeldKeys()
            cache.setCursor(resp.rev)
        }
        return reinstated
    }

    // ==== vault lifecycle: sync-time handling (spec 03 §11) ====

    /**
     * spec 02 §4 warn-and-keep-newer: the metaBlob plaintext carries the monotonic `metaV`
     * counter (bumped by every rename write), and a DELIVERED blob whose counter regresses
     * below the locally-held one is a replayed/rolled-back row — warn and keep the newer
     * local blob, never silently apply (the metaBlob-level sibling of [pull]'s rev rollback
     * guards; an absent or non-integral metaV reads as 0, the pre-rename floor, matching
     * [Account.buildRenameMeta] — see [metaV]). Comparable only when the VK is held, a previous row
     * exists (never on a since=0 / resync pull — the cache was just cleared), and BOTH
     * blobs decrypt; anything unverifiable applies the delivered row as-is (this guard is
     * anti-replay, not availability). ONLY the metaBlob is kept — rev and the lifecycle
     * fields always apply. Web twin: store.ts keepNewerMeta.
     */
    private fun keepNewerMeta(delivered: WireVault): WireVault {
        if (!account.hasVault(delivered.vaultId)) return delivered
        val held = cache.vaults().find { it.vaultId == delivered.vaultId } ?: return delivered
        if (held.metaBlob == delivered.metaBlob) return delivered
        return runCatching {
            val heldV = metaV(held)
            val deliveredV = metaV(delivered)
            if (deliveredV < heldV) {
                log.warn(
                    CoreLog.EVENT_VAULT_META_REPLAY,
                    "vault ${delivered.vaultId} delivered metaV $deliveredV regressed below held $heldV" +
                        " — replayed metaBlob; keeping the newer local one",
                )
                delivered.copy(metaBlob = held.metaBlob)
            } else delivered
        }.getOrDefault(delivered)
    }

    /** The row's plaintext `metaV` (spec 02 §4): counts ONLY as a non-negative integer ≤ 2^53
     *  (JS Number.MAX_SAFE_INTEGER), else 0 — via the SINGLE [Account.parseMetaV] rule that must
     *  read identically on every client (the same read [Account.buildRenameMeta] uses), or one
     *  impl pins while another applies, forking the fleet in exactly the adversarial anti-replay
     *  path this guard exists for. Web twin: store.ts metaVOf (Number.isSafeInteger). */
    private fun metaV(v: WireVault): Long {
        val meta = account.decryptVaultMeta(v.vaultId, v.metaBlob)
        val p = meta["metaV"] as? kotlinx.serialization.json.JsonPrimitive ?: return 0L
        if (p.isString) return 0L // "999999" is not a counter
        return Account.parseMetaV(p.content)
    }

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
            hardDropLocal(vaultId, forgetKeyMemory = selfInitiated)
            return
        }

        // This device initiated the delete/leave — drop cleanly, no banner (design §4/§13). The user's own action is
        // the one drop that clears this device's key memory for the vault (A7 review MEDIUM-1).
        if (selfInitiated) {
            hardDropLocal(vaultId, forgetKeyMemory = true)
            return
        }

        val reason = info?.reason ?: "removed"
        if (reason == "removed" || reason == "left") {
            handleRemovalOrLeave(vaultId, reason, info, cachedName)
            return
        }
        val verdict = if (verifyRemoval(vaultId, reason, info)) "valid" else "anomaly"

        // Snapshot ciphertext + move to holding BEFORE forgetting the VK.
        val parkedCount = moveToHolding(vaultId, reason, info, verdict == "valid")

        when {
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

    /**
     * `removed` / `left` on a vault this device held, not self-initiated (security review 2026-10, root cause A §6.3,
     * §8.6; branch A7). [io.silencelen.andvari.core.crypto.RemovalProof.decide] runs the verification order against
     * the held VK, this device's `liveSince` and the consumed set (device ∪ account state); its verdict picks the
     * banner. A valid verdict's `(vaultId, nonce, issuedAt)` is consumed in the SAME transaction that moves the vault
     * to the holding area (this runs inside [applyPull]'s [VaultCache.atomically]). The data handling is the same for
     * every verdict: holding area, 30 days.
     */
    private fun handleRemovalOrLeave(vaultId: String, reason: String, info: RemovedGrantInfo?, cachedName: String) {
        val decision = runCatching {
            io.silencelen.andvari.core.crypto.RemovalProof.decide(
                crypto = account.cryptoProvider(),
                lifecycleKey = account.lifecycleKeyFor(vaultId),
                vaultId = vaultId,
                myUserId = account.userId,
                reason = reason,
                proofV = info?.proofV,
                proof = info?.removeProof,
                nonce = info?.removeNonce,
                issuedAt = info?.issuedAt,
                consumed = consumedFor(vaultId),
                consumedAccount = accountConsumedFor(vaultId),
                liveSince = cache.liveSince(vaultId),
                now = nowMs(),
            )
        }.getOrElse { io.silencelen.andvari.core.crypto.RemovalProof.Decision(io.silencelen.andvari.core.crypto.RemovalProof.Verdict.ANOMALY, "error") }
        // Consume first, then snapshot + move to holding BEFORE forgetting the VK: one transaction.
        val consumeNonce = decision.consumeNonce
        val consumeAt = decision.consumeIssuedAt
        if (consumeNonce != null && consumeAt != null) cache.addConsumedNonce(vaultId, consumeNonce, consumeAt)
        moveToHolding(vaultId, reason, info, verifiedDelete = false)
        val n = when (decision.verdict) {
            io.silencelen.andvari.core.crypto.RemovalProof.Verdict.VALID ->
                LifecycleNotice(account.newItemId(), vaultId, cachedName, if (reason == "left") "left" else "removed")
            // A7 review LOW-3: a v1 proof is qualified ("sent by an older app version"), never shown as fully genuine.
            io.silencelen.andvari.core.crypto.RemovalProof.Verdict.VALID_LEGACY ->
                LifecycleNotice(account.newItemId(), vaultId, cachedName, "removed", reason = REMOVED_LEGACY)
            // A7 review MEDIUM-2: another of this user's devices already consumed this genuine proof. Calm.
            io.silencelen.andvari.core.crypto.RemovalProof.Verdict.ALREADY_RECORDED ->
                LifecycleNotice(account.newItemId(), vaultId, cachedName, if (reason == "left") "left" else "removed", reason = ALREADY_RECORDED)
            io.silencelen.andvari.core.crypto.RemovalProof.Verdict.LEFT_UNPROVEN ->
                LifecycleNotice(account.newItemId(), vaultId, cachedName, "left", reason = LEFT_UNPROVEN)
            io.silencelen.andvari.core.crypto.RemovalProof.Verdict.REPLAY_DENIED ->
                LifecycleNotice(account.newItemId(), vaultId, cachedName, "replay-denied", reason = REMOVAL_REPLAY)
            io.silencelen.andvari.core.crypto.RemovalProof.Verdict.ANOMALY ->
                LifecycleNotice(account.newItemId(), vaultId, cachedName, "anomaly")
        }
        pushNotice(n)
    }

    /** Verify the relayed delete proof under the still-held VK (spec 03 §11). `removed` / `left` go through
     *  [handleRemovalOrLeave] instead (branch A7). */
    private fun verifyRemoval(vaultId: String, reason: String, info: RemovedGrantInfo?): Boolean {
        if (info == null || reason != "deleted") return false // a bare revocation of a held vault is never "valid"
        return runCatching {
            val key = account.lifecycleKeyFor(vaultId)
            val crypto = account.cryptoProvider()
            val proof = info.deleteProof ?: return false
            val id = info.deleteId ?: return false
            LifecycleProof.verify(LifecycleProof.delete(crypto, key, vaultId, id), proof)
        }.getOrDefault(false)
    }

    /**
     * Move a removed vault's rows into the ciphertext-only holding area (design §6), then
     * drop it from the live view. Parked = this cycle's staged denials (F21) + any not-yet-
     * flushed queued mutations for the vault (they would only be denied) + anything already
     * held. Returns the parked count for the notice. The item snapshot reuses the cache's
     * ciphertext envelopes verbatim — nothing is re-encrypted, nothing plaintext at rest.
     * The pre-pull name is NOT taken: the holding record stores no plaintext name, and the
     * "Recently removed" surface re-derives it from the retained grant ([heldVaults]).
     */
    private fun moveToHolding(
        vaultId: String,
        reason: String,
        info: RemovedGrantInfo?,
        verifiedDelete: Boolean,
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

    /**
     * Drop a vault from the LIVE view: rows, queued mutations, key/role, incoming offer, and this device's liveSince.
     *
     * A7 review MEDIUM-1: the device's KEY MEMORY for the vault (the §8.2 vouch and the held-key tag) survives every
     * server-driven drop — every removal verdict, the silent resync drop — because the server could otherwise reset
     * it and re-add the vault under a key it chose (no step of root cause A re-keys a vault, so a genuine re-add
     * carries the same key). Only a drop the USER initiated on this device ([forgetKeyMemory]: their own leave or
     * delete) clears it, which keeps "leave it and ask its owner to add you again" a working recovery for vk_mismatch.
     */
    private fun hardDropLocal(vaultId: String, forgetKeyMemory: Boolean = false) {
        cache.dropVault(vaultId)
        cache.dropPending(vaultId)
        account.removeVault(vaultId)
        incomingByVault.remove(vaultId)
        cache.setLiveSince(vaultId, null)
        if (forgetKeyMemory) {
            account.forgetKeyMemory(vaultId)
            persistSet(LEGACY_AUTHORIZED_KEY, persistedSet(LEGACY_AUTHORIZED_KEY).filterNot { it.startsWith("$vaultId|") }.toSet())
            persistSet(HELD_KEYS_KEY, persistedSet(HELD_KEYS_KEY).filterNot { it.startsWith("$vaultId|") }.toSet())
        }
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
                        vaultName = account.decryptVaultName(vaultId, vault.metaBlob) ?: VAULT_NAME_FALLBACK,
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
            val name = account.decryptVaultName(vaultId, vault.metaBlob) ?: VAULT_NAME_FALLBACK
            if (verified) {
                cache.setLastVerifiedTransferSeq(vaultId, lt.seq)
                // A6b: a verified transfer to someone else ends this account's ownership evidence (only ever removes).
                if (lt.newOwnerUserId != account.userId && ownsVault(vaultId)) ownershipReleases.add(vaultId)
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
                name = h.grant?.let { account.peekVaultName(it, h.vault.metaBlob) } ?: VAULT_NAME_FALLBACK,
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
            reconcileSync(onFailure = { hardDropLocal(vaultId, forgetKeyMemory = true) })
        } finally {
            suppressDrop.remove(vaultId) // #4: never outlives the action's own reconcile
        }
        return resp.purgeAt
    }

    /** The caller's own in-grace deleted vaults — re-opens each VK from the wrappedVk it
     *  already owned so the name shows AND restore can mint its proof (ZK-clean). */
    suspend fun listDeleted(): List<DeletedVaultInfo> = api.deletedVaults().map { d ->
        var name = VAULT_NAME_FALLBACK
        runCatching {
            account.addGrant(WireGrant(d.vaultId, account.userId, "owner", d.wrappedVk, 0, null))
            name = account.decryptVaultName(d.vaultId, d.metaBlob) ?: VAULT_NAME_FALLBACK
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

    /** LEAVE (self-removal). This device initiated it → drop cleanly (no "you left" banner here). Carries a v2
     *  leave proof (root cause A §6.2, branch A7) so this member's OTHER devices can verify the leave. */
    suspend fun leaveSharedVault(vaultId: String) {
        val nonce = LifecycleProof.newNonce(account.cryptoProvider())
        val issuedAt = nowMs()
        val proof = LifecycleProof.leave(account.cryptoProvider(), account.lifecycleKeyFor(vaultId), vaultId, account.userId, nonce, issuedAt)
        api.leaveVault(vaultId, io.silencelen.andvari.core.model.VaultLeaveRequest(proofV = 2, proof = proof, nonce = nonce, issuedAt = issuedAt))
        // A6b: leaving ends this account's ownership evidence for the vault (if it had any).
        if (ownsVault(vaultId)) runCatching { accountState.update { AccountState.withoutOwned(it, vaultId, nowMs()) } }
        suppressDrop.add(vaultId)
        try {
            reconcileSync(onFailure = { hardDropLocal(vaultId, forgetKeyMemory = true) })
        } finally {
            suppressDrop.remove(vaultId) // #4: never outlives the action's own reconcile
        }
    }

    /**
     * REMOVE a member (owner; root cause A §6.2, branch A7): mints a v2 removal proof under the held VK — a fresh
     * 16-byte nonce and this device's clock — and sends it with the DELETE, so the removed member's devices can
     * attribute the removal and refuse a replay. Web twin: store.ts `removeVaultMember`.
     */
    suspend fun removeVaultMember(vaultId: String, userId: String) {
        val nonce = LifecycleProof.newNonce(account.cryptoProvider())
        val issuedAt = nowMs()
        val proof = LifecycleProof.removeV2(account.cryptoProvider(), account.lifecycleKeyFor(vaultId), vaultId, userId, nonce, issuedAt)
        api.removeVaultMember(vaultId, userId, io.silencelen.andvari.core.model.VaultMemberRemoveRequest(proof = proof, nonce = nonce, proofV = 2, issuedAt = issuedAt))
        // A6b: a removed member's pair leaves the issued-grants record (tombstoned): a later re-issue needs a human.
        runCatching { accountState.update { AccountState.withoutIssued(it, vaultId, userId, nowMs()) } }
        reconcileSync()
    }

    /** TRANSFER offer. seq = the vault's last completed transfer seq + 1 (= transferSeq+1). */
    suspend fun offerTransfer(vaultId: String, toUserId: String) {
        requireOwned(vaultId) // A6b: an owner-only action, never on the server's role label alone
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
        // A6b: this account accepted the vault, verified under its key: its own evidence of ownership.
        runCatching { accountState.update { AccountState.withOwned(it, vaultId, nowMs()) } }
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
        // INV-HOME: the gesture was minted for the source in its vault; it never runs against another vault's copy.
        if (src.vaultId != g.sourceVaultId) throw ItemChangedVaultsException()

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
        // INV-SEAL (c): the destination the user chose; the fresh id takes it as its home.
        val upload = sealFor(SealProvenance.Chosen(g.targetVaultId), g.newItemId, newDoc)
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
            // flag waits for a writer/owner on some other device. INV-WRITE-KEY: nor under a key we may not seal with.
            if (account.roleFor(item.vaultId) == "reader" || !account.canSealUnder(item.vaultId)) continue
            // INV-CONFLICT (root cause A §5.1, A1b): the twin and the home must agree with the flagged row's vault, or
            // nothing is pushed and the pull raises its wrong-vault anomaly. (INV-HOME already keeps such a row out of
            // the cache; this is the second lock, and it no longer depends on the cache being keyed by itemId.)
            val twin = cache.getItem(item.itemId)
            if (ItemHome.conflict(twin?.vaultId, item.vaultId, cache.itemHome(item.itemId)) == ItemHome.Conflict.ABORT) {
                wrongVault.note(item.vaultId)
                continue
            }
            // BOTH mutations come from decrypt(flagged), sealed under flagged.vaultId (provenance (a)).
            val doc = runCatching { account.decryptItem(item) }.getOrNull() ?: continue // undecryptable → wait
            val provenance = SealProvenance.Envelope(item.vaultId)
            val copyId = deterministicCopyId(item.itemId, item.rev)
            // PDD-1: the CORRECT copy is built from the DISPLACED (losing) value by the pushing
            // client (materializeConflictFromServerItem); this path is the FALLBACK + flag
            // clearer. If the copy is already present (push side, a peer, or a prior pass), skip
            // re-creating it and just clear the flag. If it is absent (the conflict was caused by a
            // client that didn't materialize) preserve at least this value so clearing the flag
            // doesn't erase the only trace.
            // A1b review LOW-1 (availability; web twin: the pull's per-row try/catch around materializeConflict): the
            // copy id is deterministic, so a server can pre-claim home(copyId) under another vault and make this seal
            // refuse. The refusal is right, but it is THIS ROW's verdict: count it for the wrong-vault notice and
            // carry on, never let it escape and fail this sync and every later one while the flag stands.
            try {
                val mutations = mutableListOf<Mutation>()
                if (copyId !in known && cache.getItem(copyId) == null) {
                    val copyDoc = doc.copy(name = "${doc.name} (conflict ${isoDate(item.updatedAt)})")
                    mutations += putMutation(provenance, copyId, copyDoc, 0)
                }
                mutations += putMutation(provenance, item.itemId, doc, item.rev) // clears the flag
                push(mutations)
            } catch (e: ItemChangedVaultsException) {
                wrongVault.note(item.vaultId)
            } catch (e: VaultKeyNotVerifiedException) {
                wrongVault.note(item.vaultId)
            }
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
    private suspend fun materializeConflictFromServerItem(d: Displaced) {
        val losing = d.losing
        if (account.roleFor(losing.vaultId) == "reader" || !account.canSealUnder(losing.vaultId)) return // a reader's push would be denied
        // INV-CONFLICT (A1b): the displaced value must be the item we wrote, in the vault we wrote it to and its home.
        // Its AD vault is then the vault the copy is sealed under (provenance (a)).
        if (ItemHome.serverItem(d.pushedVaultId, losing.vaultId, cache.itemHome(losing.itemId)) == ItemHome.ServerItem.ABORT) {
            wrongVault.note(losing.vaultId)
            return
        }
        val losingDoc = runCatching { account.decryptItem(losing) }.getOrNull() ?: return // held key → skip
        val copyId = deterministicCopyId(losing.itemId, d.winnerRev)
        if (cache.getItem(copyId) != null) return // already materialized
        val copyDoc = losingDoc.copy(name = "${losingDoc.name} (conflict ${isoDate(losing.updatedAt)})")
        push(listOf(putMutation(SealProvenance.Envelope(losing.vaultId), copyId, copyDoc, 0)))
    }

    /** PDD-1: a server-returned displaced value, the winner's rev, and the vault the losing put was pushed to. */
    private class Displaced(val losing: WireItem, val winnerRev: Long, val pushedVaultId: String)

    /** UUIDv4-shaped id derived from sha256("conflict|itemId|rev") — stable across retries.
     *  Delegates to the vector-pinned shared derivation (spec/test-vectors/conflictcopy.json). */
    private fun deterministicCopyId(itemId: String, rev: Long): String =
        ConflictCopy.id(account.cryptoProvider(), itemId, rev)

    /** A put sealed through [sealFor] (INV-SEAL / INV-HOME / INV-WRITE-KEY): the vault IS the provenance's. */
    private fun putMutation(provenance: SealProvenance, itemId: String, doc: ItemDoc, baseItemRev: Long): Mutation =
        Mutation(
            mutationId = account.newItemId(),
            op = "put",
            itemId = itemId,
            vaultId = provenance.vaultId,
            baseItemRev = baseItemRev,
            item = sealFor(provenance, itemId, doc),
        )

    fun deleteMutation(itemId: String, vaultId: String, baseItemRev: Long): Mutation =
        Mutation(account.newItemId(), "delete", itemId, vaultId, baseItemRev, null)

    /** Create or update an item, then reconcile. New items go to [vaultId] (default personal); an edit passes the vault
     *  its editor opened on as [vaultId] (INV-EDIT, required). */
    suspend fun save(itemId: String?, doc: ItemDoc, vaultId: String? = null) = saveWithUploads(itemId, doc, emptyList(), vaultId)

    /**
     * Blob-first save (spec 02 §6): encrypt + upload every new attachment under the
     * (possibly fresh) itemId, THEN push the item that references them. An EXISTING item
     * never changes vaults (its blob AD binds to the vault; the server enforces
     * vault_mismatch): an edit names the vault its editor was bound to when it opened
     * ([vaultId], INV-EDIT), and a home that differs now refuses the save with
     * [ItemChangedVaultsException] instead of re-targeting it.
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
    ): SaveOutcome {
        // [newItemId] (F71 review): a RETRY of a failed NEW-item save must reuse the id the
        // first attempt minted — attachments committed by that attempt are bound to it, and
        // a fresh mint would trip the push's attachment_mismatch validation forever. Used
        // only when [itemId] is null (an edit's identity is the itemId); callers keep one
        // draft id per editor session and clear it on success/cancel.
        val existing = itemId?.let { cache.getItem(it) }
        // H18: an edit to an item that exists ONLY as a queued, never-sent put (an offline
        // new-item save the list now projects). It is still the SAME new item: the server has
        // never seen it, so the newer doc simply supersedes the queued one. H37 generalizes
        // that to EVERY item with unsent queued puts — see [coalesceQueuedPuts].
        val queuedOnly = if (itemId != null && existing == null) item(itemId) else null
        // Save guard (design §6): an edit to an itemId we no longer hold must NOT silently
        // teleport into the personal vault — the item's vault may have been deleted or its
        // grant revoked mid-edit. Fail loudly; the server-side skeletal fence is the belt.
        if (itemId != null && existing == null && queuedOnly == null) {
            throw ApiException(409, "vault_state_changed", "This item is no longer here — it may have been removed or its vault deleted.")
        }
        // INV-EDIT / INV-SEAL (root cause A §5.1, A1b). An EDIT is sealed under the vault its editor was bound to when it
        // OPENED ([vaultId], provenance (b)); it is never looked up by itemId here. If the item's home is another vault
        // now, the save is refused ("reopen it"), never re-targeted. A NEW item goes to the destination the user chose
        // ([vaultId], default the personal vault, provenance (c)).
        val provenance: SealProvenance = if (itemId != null) {
            val home = cache.itemHome(itemId) ?: existing?.vaultId ?: queuedOnly?.vaultId
            when (ItemHome.edit(home, vaultId)) {
                ItemHome.Edit.UNBOUND -> throw IllegalArgumentException("an edit must name the vault its editor opened on")
                ItemHome.Edit.CHANGED_VAULTS -> throw ItemChangedVaultsException()
                ItemHome.Edit.OK -> SealProvenance.Editor(vaultId!!)
            }
        } else {
            SealProvenance.Chosen(vaultId ?: account.personalVaultId)
        }
        val effectiveVault = provenance.vaultId
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
        return syncMutex.withLock {
            // H37: the queued burst's ORIGINAL base rev wins over the cache's — see below.
            val coalescedBase = coalesceQueuedPuts(id)
            val m = putMutation(provenance, id, doc, coalescedBase ?: existing?.rev ?: 0)
            sendOrQueue(m)?.let { return@withLock it }
            reconcileAfterWrite(m)
        }
    }

    /**
     * H18 + H37 (audit 2026-09-13, spec 03 §5 "Queue coalescing"): fold this item's UNSENT
     * queued puts into the one the caller is about to enqueue, and answer the base rev that
     * one must carry. Web twin: store.ts coalesceQueuedPuts.
     *
     * WHY (H37, the bug this exists to kill). The server's conflict test is
     * `baseItemRev < existing.rev` (Service.applyPut) against a GLOBALLY monotonic rev —
     * `nextRev` is the rowid of the `changes` table, not a per-item counter. So when two
     * puts for one item sit in the queue, both minted against the same pre-offline rev r,
     * the drain lands the first at some fresh global rev G ≫ r and the second is stale BY
     * CONSTRUCTION: the server answers `conflict` and hands back the displaced value — which
     * is the user's OWN intermediate draft — and the client dutifully materializes it as
     * "<name> (conflict YYYY-MM-DD)". Editing one login twice on a train ride, or creating an
     * entry and fixing a typo before reconnecting, therefore came back as a duplicate that
     * reads to the user as a corrupt vault, and then fed Vault Health's duplicates cluster.
     * Nothing was lost — but nothing was in conflict either. Coalescing removes the false
     * premise instead of teaching the client to recognize its own drafts.
     *
     * The base rev deliberately comes from the OLDEST dropped row, NOT from the cache. If a
     * PEER's edit landed in the cache between the two offline saves, the cache's rev is that
     * peer's — sending at it would silently overwrite their change with no copy at all. The
     * original base preserves the genuine conflict (peer vs. us) while dropping the false one
     * (us vs. us).
     *
     * A fresh mutationId, never the dropped row's: reusing it would let the server's dedup
     * window replay the OLD stored result verbatim (spec 03 §5) and report `applied` for
     * content we never sent — trading a junk copy for silent loss of the newest draft.
     *
     * Scope. Only `put` rows, and only when NO queued `delete` for the same item is in the
     * way — a delete between two puts is an ordering the drain must keep as written. Staged-
     * denied rows are invisible to [VaultCache.pending] and so are never folded away: their
     * fate is F21's to decide. The residual window is the crash/lost-response one — a row
     * that actually landed but whose response we never saw is dropped here and re-sent at the
     * old base, which degrades to exactly today's conflict copy, never to loss. Called under
     * [syncMutex], so a drain cannot be sending these rows meanwhile.
     *
     * @return the oldest folded row's baseItemRev, or null when nothing was folded.
     */
    private fun coalesceQueuedPuts(itemId: String): Long? {
        val rows = cache.pending().filter { it.itemId == itemId }
        if (rows.isEmpty()) return null
        if (rows.any { it.op != "put" }) return null // a queued delete — never reorder around it
        val base = rows.first().baseItemRev
        for (q in rows) {
            cache.dequeue(q.mutationId)
            pendingDocCache.remove(q.mutationId)
        }
        return base
    }

    /**
     * H18 (audit 2026-09-13): the ONE offline verdict for a save/remove. Enqueue [m] and
     * drain. A transport failure ([IOException]) from the drain means the server never
     * answered — on a DURABLE cache the row is safely queued and already projected by
     * [items], so the write is reported as [SaveOutcome.QUEUED] and the caller closes the
     * editor exactly like the online path (the web store's success-as-QUEUED). On a
     * NON-durable cache (H17: desktop before cache consent, org-forbid mode on both
     * natives) the queue is process memory that the next lock, quit or background-lock
     * frees, so "queued" would be a false safety claim: the row is dequeued (no ghost
     * that a later same-session flush could land AFTER the user re-saved it by hand) and
     * the failure propagates for [HouseholdCopy.forSaveError]'s honest "couldn't be saved"
     * line. A server ANSWER ([ApiException]) is never an offline verdict and propagates
     * as before. Returns the outcome when the write is queued, null when it was sent.
     */
    private suspend fun sendOrQueue(m: Mutation): SaveOutcome? {
        try {
            push(listOf(m))
        } catch (e: IOException) {
            if (cache.durable && cache.pending().any { it.mutationId == m.mutationId }) return SaveOutcome.QUEUED
            cache.dequeue(m.mutationId)
            throw e
        }
        return null
    }

    /**
     * After a SENT write: the reconcile pull + denial classification, then the H03 verdict
     * for this very mutation. A transport failure of the reconcile pull is swallowed (web
     * twin: "save committed but the reconcile pull failed — local apply kept") — the write
     * landed or is staged/queued, and reporting it as "couldn't be saved" would invite the
     * duplicate re-save G23 exists to prevent; the next sync trues up. A server answer
     * from the pull (409 rev_regression, 401, …) still propagates. If the server REJECTED
     * this mutation (dangling attachment ref / over cap — dropped durably by the drain,
     * notice minted), the editor must learn it: rethrown as an [ApiException] carrying the
     * server's reason code, AFTER the pull so the list already shows the server's truth.
     */
    private suspend fun reconcileAfterWrite(m: Mutation): SaveOutcome {
        try {
            pull()
            surfaceStagedDenials()
        } catch (e: IOException) {
            // The write itself is settled; only the reconcile is missing. Never fail the save.
        }
        rejectedMutationIds.remove(m.mutationId)?.let { reason ->
            val status = if (reason == "item_attachment_quota" || reason == "body_too_large") 413 else 400
            throw ApiException(status, reason, "the server refused this write: $reason")
        }
        return SaveOutcome.APPLIED
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
        vaultId: String? = null,
    ) = syncMutex.withLock {
        // S2: the destination vault — must be the SAME vault the plan's projections came
        // from (importProjections), or the dedupe verdicts are meaningless. Null = personal.
        @Suppress("NAME_SHADOWING") val vaultId = vaultId ?: account.personalVaultId
        var done = 0
        for (chunk in items.chunked(SERVER_BATCH_MAX)) {
            push(chunk.map {
                Mutation(
                    mutationId = it.itemId, // stable id → idempotent retry of the same plan
                    op = "put", itemId = it.itemId, vaultId = vaultId, baseItemRev = 0,
                    // INV-SEAL (c): the import destination the user chose; each fresh id takes it as its home.
                    item = sealFor(SealProvenance.Chosen(vaultId), it.itemId, it.doc),
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
        // ref.size is the item author's claim (a co-member's, in a shared vault — security review
        // 2026-10). The body must be exactly the length that claim implies, and the API stops
        // reading past it, so the claim callers budget with (the backup cap, the desktop transfer
        // bound) is the bytes actually held — and the plaintext is exactly ref.size bytes.
        val bytes = api.downloadAttachment(ref.id, Attachments.wireLength(ref.size))
        if (bytes.size <= Attachments.HEADER_BYTES) throw CryptoException("attachment response truncated")
        return Attachments.decrypt(
            account.cryptoProvider(),
            Bytes.fromB64(ref.fileKey),
            bytes.copyOfRange(0, Attachments.HEADER_BYTES),
            bytes.copyOfRange(Attachments.HEADER_BYTES, bytes.size),
        )
    }

    /** Delete an item, then reconcile — [saveWithUploads]'s twin, same offline verdict
     *  (H18: QUEUED on a durable cache, [items] already hides the row). */
    suspend fun remove(itemId: String): SaveOutcome {
        val existing = cache.getItem(itemId)
        if (existing == null) {
            // H18: a queued, never-sent NEW item — the server has nothing to delete; dropping
            // the queued put(s) is the whole removal (and the projected row disappears).
            if (item(itemId) != null) syncMutex.withLock { coalesceQueuedPuts(itemId) }
            return SaveOutcome.APPLIED
        }
        return syncMutex.withLock {
            val m = deleteMutation(itemId, existing.vaultId, existing.rev)
            sendOrQueue(m)?.let { return@withLock it }
            reconcileAfterWrite(m)
        }
    }

    /** Enqueue durably, attempt to send; a failure leaves it queued for flushQueue(). */
    private suspend fun push(mutations: List<Mutation>) {
        mutations.forEach { cache.enqueue(it) }
        flushQueue()
    }

    /**
     * H19: the next batch to send — at most [SERVER_BATCH_MAX] rows AND, past the first row,
     * at most [PUSH_BODY_SOFT_CAP_BYTES] of approximate encoded size (a put's base64 blob plus
     * framing; a delete is framing only). The first row is always taken, so a lone over-cap
     * row is sent alone and refused alone — where [flushQueue] can drop exactly it.
     */
    private fun nextBatch(pending: List<Mutation>): List<Mutation> {
        val out = ArrayList<Mutation>()
        var bytes = 0L
        for (m in pending) {
            if (out.size >= SERVER_BATCH_MAX) break
            val size = approxEncodedBytes(m)
            if (out.isNotEmpty() && bytes + size > PUSH_BODY_SOFT_CAP_BYTES) break
            out.add(m)
            bytes += size
        }
        return out
    }

    private fun approxEncodedBytes(m: Mutation): Long =
        (m.item?.blob?.length?.toLong() ?: 0L) + (m.item?.attachmentIds?.size ?: 0) * 40L + 256L

    /**
     * H03/H19: is this thrown push answer a DEFINITIVE refusal of the batch as a whole — one
     * that re-sending identically can never cure? 400 (`bad_request` shapes the client itself
     * minted; on a pre-H03 server also `unknown_attachment` / `attachment_mismatch`, which
     * that server still throws batch-wide) and 413 (`body_too_large` — fired BEFORE the
     * handler, so nothing in the batch was applied; on a pre-H03 server also
     * `item_attachment_quota`). Everything else is transient or session-level and keeps the
     * rows queued: transport, 401/426 (the session/version gate), 403/409/410, 429, 5xx.
     * Both listed statuses roll back or never start the batch, so re-sending the halves is
     * safe and the server's dedup window makes it idempotent.
     */
    private fun isWholeBatchRefusal(e: ApiException): Boolean = e.status == 400 || e.status == 413

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
        val displaced = mutableListOf<Displaced>() // PDD-1: (losing serverItem, winner newRev, pushed vault)
        while (true) {
            val chunk = nextBatch(cache.pending()) // H19: count- AND byte-bounded
            if (chunk.isEmpty()) break
            val outcome = pushBatch(chunk, displaced)
            deniedCount += outcome.denied
            if (!outcome.progressed) break // defensive: no results matched (server returns one per mutation)
        }
        mintRejectedNotices()
        // Materialize AFTER draining — a re-entrant push here recurses into flushQueue; each
        // copy is a fresh item (baseRev 0) that applies cleanly, so the recursion is bounded.
        for (d in displaced) materializeConflictFromServerItem(d)
        return deniedCount
    }

    private class BatchOutcome(var denied: Int = 0, var progressed: Boolean = false)

    /**
     * Send ONE batch and settle each row's queue fate. H03/H19 (audit 2026-09-13): a
     * DEFINITIVE whole-batch refusal ([isWholeBatchRefusal]) is no longer allowed to leave
     * the batch at the head of the queue — before this, one row the server could never
     * accept (a put whose attachment rows a peer's delete had dropped; a 200-row import
     * chunk over the 8 MiB body cap) made every later sync throw at the same batch BEFORE
     * its pull, so the device stopped receiving anything until a sign-out that also wiped
     * every other queued edit. The batch is BISECTED instead: each half is re-sent (nothing
     * of a refused batch was applied, and the dedup window makes re-sends idempotent), so
     * healthy rows land in ≤ log2(n) extra requests and the refusal narrows to single rows,
     * each of which is dropped durably via [rejectRow]. A per-row `rejected` status (the
     * H03 server amendment, spec 03 §5) takes the same drop path with no bisection at all.
     */
    private suspend fun pushBatch(chunk: List<Mutation>, displaced: MutableList<Displaced>): BatchOutcome {
        val out = BatchOutcome()
        val resp = try {
            api.push(PushRequest(chunk))
        } catch (e: ApiException) {
            if (!isWholeBatchRefusal(e)) throw e
            if (chunk.size == 1) {
                rejectRow(chunk[0], e.code)
                out.progressed = true
                return out
            }
            val mid = chunk.size / 2
            val a = pushBatch(chunk.subList(0, mid), displaced)
            val b = pushBatch(chunk.subList(mid, chunk.size), displaced)
            out.denied = a.denied + b.denied
            out.progressed = a.progressed || b.progressed
            return out
        }
        val byId = resp.results.associateBy { it.mutationId }
        for (m in chunk) {
            val r = byId[m.mutationId] ?: continue
            val wasReplay = replayedMutationIds.remove(m.mutationId)
            if (r.status == "rejected") {
                // H03: the server answered for THIS row alone — it can never apply as sent
                // (its attachment refs are gone, or it is over quota). Drop it durably, tell
                // the user via the notice; the sibling rows and the pull proceed.
                rejectRow(m, r.reason ?: "rejected")
                out.progressed = true
                continue
            }
            if (r.status == "denied") {
                out.denied++
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
                if (r.status == "conflict" && m.op == "put" && si != null && nr != null) displaced += Displaced(si, nr, m.vaultId)
                // Any other definitive outcome removes it (idempotent replay returns
                // the original result).
                cache.dequeue(m.mutationId)
                pendingDocCache.remove(m.mutationId)
            }
            out.progressed = true
        }
        return out
    }

    /**
     * H03/H19: durably drop ONE definitively-refused queue row. Recorded per vault for the
     * "write-rejected" notice ([mintRejectedNotices]) and per mutationId so a direct save
     * can throw the honest editor error for its own row ([reconcileAfterWrite]). There is
     * no local revert to do here — unlike the web store, core applies nothing optimistically
     * (the [items] overlay reads the queue, so dropping the row IS the revert), and the
     * pull that follows the drain delivers the server's truth for the item.
     */
    private fun rejectRow(m: Mutation, reason: String) {
        cache.dequeue(m.mutationId)
        replayedMutationIds.remove(m.mutationId)
        pendingDocCache.remove(m.mutationId)
        rejectedMutationIds[m.mutationId] = reason
        rejectedByVault.getOrPut(m.vaultId) { mutableListOf() }.add(reason)
    }

    /** One "write-rejected" notice per vault for the rows [rejectRow] dropped this drain —
     *  the durable user-facing surface: the throw a direct save raises is often swallowed
     *  by a background sync, and a background drain has no editor to throw into. */
    private fun mintRejectedNotices() {
        if (rejectedByVault.isEmpty()) return
        for ((vid, reasons) in rejectedByVault) {
            val name = cache.vaults().find { it.vaultId == vid }
                ?.let { account.decryptVaultName(vid, it.metaBlob) } ?: VAULT_NAME_FALLBACK
            pushNotice(LifecycleNotice(account.newItemId(), vid, name, "write-rejected", parkedCount = reasons.size, reason = reasons.first()))
        }
        rejectedByVault.clear()
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
