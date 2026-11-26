package io.silencelen.andvari.core.client.items

import io.silencelen.andvari.core.client.AttachmentRef
import io.silencelen.andvari.core.client.ConflictCopy
import io.silencelen.andvari.core.client.CoreLog
import io.silencelen.andvari.core.client.CsvImport
import io.silencelen.andvari.core.client.DecryptedItemVersion
import io.silencelen.andvari.core.client.DeletedItemView
import io.silencelen.andvari.core.client.ItemDoc
import io.silencelen.andvari.core.client.ItemHome
import io.silencelen.andvari.core.client.SealProvenance
import io.silencelen.andvari.core.client.VaultCache
import io.silencelen.andvari.core.client.VaultItem
import io.silencelen.andvari.core.client.net.WireResult
import io.silencelen.andvari.core.crypto.Attachments
import io.silencelen.andvari.core.crypto.Bytes
import io.silencelen.andvari.core.crypto.CryptoProvider
import io.silencelen.andvari.core.crypto.KeysGoneException
import io.silencelen.andvari.core.model.wire.DeletedItem
import io.silencelen.andvari.core.model.wire.ItemVersion
import io.silencelen.andvari.core.model.wire.ItemUpload
import io.silencelen.andvari.core.model.wire.Mutation
import io.silencelen.andvari.core.model.wire.MutationOp
import io.silencelen.andvari.core.model.wire.MutationStatus
import io.silencelen.andvari.core.model.wire.SyncItem
import io.silencelen.andvari.core.model.wire.SyncResponse
import io.silencelen.andvari.core.model.wire.SyncVault
import io.silencelen.andvari.core.model.wire.WireErrors
import io.silencelen.andvari.core.trust.TrustGrammar
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import kotlin.concurrent.Volatile

/**
 * What must be on the server before the queue drains ([ItemEngine.beforeDrain]), given the items whose puts wait in the
 * queue: the files of such a put, which the server may have removed while it waited (it keeps an upload no item names
 * for a day), go up again first. Answers null to let the drain go, or a failure for now (no answer, the session's end,
 * a rate limit, a fault of the server) that the drain would meet too.
 */
internal typealias BeforeDrain = suspend (waitingPuts: Set<String>) -> ItemFailure?

/**
 * The item plane on the new session: pull with its cursor and resync rule, the durable outbound queue and its drain,
 * conflict copies, tombstones, trash, item history, attachments, move and copy, and the offline cache contract
 * (spec 02 §1–§8, spec 03 §4, §5, §5.1, §9). It is the item half of the old `SyncEngine`, cut free of the old account,
 * API client and wire types.
 *
 * It depends on three seams and a cache. [transport] is everything it sends or receives. [keys] is the only place a
 * vault key comes from and the only judge of what a vault allows: the personal vault from the opened account, a shared
 * vault only with a key the vault-log engine adopted (design §3.6). [gate] says whether the origin may still be talked
 * to: every sync starts by having it judge the origin's card chain (design §4.4), and nothing is sent or written
 * without asking it. This class opens no wrap and no grant, verifies no log and no card, and decides no trust.
 * [cache] is opened by the host in the namespace of this origin and this account ([ItemCacheNames]); [userId] is
 * that account.
 *
 * What it tells the trust engine: every pull's vault rows (with their served log heads), grant rows and lost grants
 * ([VaultKeySource.served]) BEFORE it reads an item of that pull, and every log head an item carried
 * ([VaultKeySource.itemHead]). What it writes into a shared vault carries that vault's verified head (spec 02 §3).
 *
 * What it never does: use a key [keys] does not offer; seal or send anything to a vault whose [VaultAccess.writable]
 * is false; keep plaintext or a key at rest; drop this device's copy of a vault because the server stopped serving it
 * (spec 02 §10.6).
 *
 * **Halted** (design §4.4, "a fork stops traffic, not reading"): once [gate] says the origin is stopped (or after
 * [halt]) nothing is sent, nothing served is accepted and nothing is written, for good; what the cache holds stays
 * readable ([hydrate], [items], [vaults], [heldItems]).
 *
 * **A server that goes backwards** (spec 05 T1): a pull answered with a rev below the cursor, or with a full snapshot
 * nobody asked for, is not applied; local newer state is kept, a `rollback` notice is raised and the sync says so.
 *
 * A host calls [hydrate] once after unlock, then [sync] on its bell or its timer, and again after any vault-log action
 * (create, accept, leave, delete, restore): the engine re-reads [keys] on every cycle.
 */
class ItemEngine(
    private val transport: ItemTransport,
    private val keys: VaultKeySource,
    private val gate: OriginGate,
    cache: VaultCache,
    private val userId: String,
    private val crypto: CryptoProvider,
    private val clock: () -> Long,
    private val log: CoreLog = CoreLog.Silent,
) {
    private val store = ItemStore(cache)
    private val codec = ItemCodec(crypto)

    /** Never leaves this class: the one way an operation stops early, turned into [ItemResult.Failed] at its boundary. */
    private class Stop(val why: ItemFailure) : Exception()

    private inline fun <T> guard(block: () -> T): ItemResult<T> = try {
        ItemResult.Ok(block())
    } catch (e: Stop) {
        ItemResult.Failed(e.why)
    }

    private fun <T> WireResult<T>.orStop(): T = when (this) {
        is WireResult.Ok -> value
        is WireResult.Refused -> throw Stop(ItemFailure.Refused(code, status, retryAfterSeconds))
        is WireResult.NoAnswer -> throw Stop(ItemFailure.Unreachable(kind))
    }

    private fun refuse(reason: ItemRefusal): Nothing = throw Stop(ItemFailure.NotAllowed(reason))

    // ---- halted (design §4.4) ----

    private var haltedFlag = false

    /** True once the origin is stopped (its card chain forked, or its pin is damaged or gone): traffic and writes are over for this engine. */
    val halted: Boolean
        get() {
            if (!haltedFlag && gate.stopped()) haltedFlag = true
            return haltedFlag
        }

    /** Stop all traffic and all writes for good; reading what the cache holds goes on. */
    fun halt() { haltedFlag = true }

    /**
     * Asked before anything is sent or written: the pin's state now, never a remembered answer. An engine that closed,
     * or whose account's keys are wiped (a lock, the end of the session), seals and sends nothing more: that is
     * [KeysGoneException], which its host answers as "locked", never as a failure of the write.
     */
    private fun live() {
        if (closedFlag || !keys.keysLive) throw KeysGoneException("the vault closed: nothing more is sealed or sent")
        if (halted) throw Stop(ItemFailure.Halted)
    }

    // ---- state ----

    /** Serializes every flush → pull → classify cycle and every queue fold: one cycle's stale pull must never judge another's denial. */
    private val syncMutex = Mutex()
    private var pullStartCounter = 0L
    private var freshestCompletedPullStart = 0L

    private val noticeList = mutableListOf<ItemNotice>()

    /** A denied mutation awaiting its verdict: only a pull that STARTED after it was staged may classify it. */
    /** [replayedFor]: why the denied mutation was a replay (see [replayedMutationIds]); null when it was sent first-hand. */
    private class StagedDenial(val mutation: Mutation, val stagedBefore: Long, val replayedFor: String? = null) {
        val wasReplay: Boolean get() = replayedFor != null
    }

    /** Index of the durable staged-denied rows ([VaultCache.markStagedDenied]), by vault. */
    private val staged = mutableMapOf<String, MutableList<StagedDenial>>()

    /**
     * Mutations re-enqueued when a vault came back: a denial of one is a calm notice. Each with why the vault had gone,
     * so the notice says what is known: the held copy's reason ([ItemNotice.DELETED], [ItemNotice.REMOVED],
     * [ItemNotice.LEFT]), or [ItemNotice.WITHHELD] for a vault the server took away with no verified reason.
     */
    private val replayedMutationIds = mutableMapOf<String, String>()

    /** Replays denied this cycle: (vault, why it had gone) → how many. */
    private val replayDeniedByVault = mutableMapOf<Pair<String, String>, Int>()

    /** Rows the server definitively refused this drain: mutationId → reason, and per vault for the notice. */
    private val rejectedMutationIds = mutableMapOf<String, String>()
    private val rejectedByVault = mutableMapOf<String, MutableList<String>>()

    /** The decrypted view of a queued put, by mutationId; pruned to the live queue on each read, never persisted. */
    private val pendingDocCache = mutableMapOf<String, VaultItem?>()

    private var wrongVault = ItemHome.Tally()

    /**
     * The vaults this engine has read this session, with the name each last decrypted to. A vault that opens later
     * gets one more decrypt pass; one that closes has its plaintext evicted ([settle]); a notice about a vault that
     * left is worded from here, since its key may be gone by then.
     */
    private val readable = HashMap<String, String>()

    /** Bulk-copy plans by (source vault | item | target), so a retry after a failure reuses the same ids. */
    private val bulkPlans = mutableMapOf<String, MovePlan>()

    /** Vaults this device just deleted or left itself: their departure raises no notice. */
    private val quietDepartures = mutableSetOf<String>()

    /**
     * [block] with [vaultId]'s key, under the guard of the account it belongs to: the key is never held here, so a lock
     * that comes between two uses leaves nothing behind, and a use after it throws.
     */
    private inline fun <T> withKey(vaultId: String, crossinline block: (ByteArray) -> T): T? = keys.withKey(vaultId) { block(it) }

    /**
     * Which vaults of a batch [keys] lists as readable, asked once per vault; the key itself is lent per use
     * ([withKey]), never held for the batch.
     */
    private inner class KeyRing {
        private val readable = HashMap<String, Boolean>()

        /** Whether [vaultId] is readable and its key is offered. */
        fun has(vaultId: String): Boolean = readable.getOrPut(vaultId) { keys.access(vaultId) != null && keys.withKey(vaultId) { true } == true }

        /** [block] under [vaultId]'s key when [has]; null otherwise. */
        fun <T> open(vaultId: String, block: (ByteArray) -> T): T? = if (has(vaultId)) keys.withKey(vaultId, block) else null

        fun wipe() = readable.clear()
    }

    /** The log heads the items of one pull carried, per vault (design §3.9): the few highest are reported. */
    private class HeadHints {
        val byVault = LinkedHashMap<String, MutableMap<Long, String>>()
        fun note(vaultId: String, doc: ItemDoc) {
            val h = ItemCodec.logHeadOf(doc) ?: return
            byVault.getOrPut(vaultId) { LinkedHashMap() }[h.seq] = h.hash
        }
    }

    // ==== reads ====

    /**
     * The working set: the cache's server-confirmed items overlaid with the outbound queue. A queued put replaces or
     * adds its row, a queued delete hides it; later queue rows win. The overlay keeps the cache's rev for an edited
     * item and stamps updatedAt with the local clock.
     */
    fun items(): List<VaultItem> = overlayPending(store.allItems()).sortedBy { it.doc.name.lowercase() }

    fun item(itemId: String): VaultItem? = overlayPending(listOfNotNull(store.getItem(itemId)), only = itemId).firstOrNull()

    /** itemIds with a queued put or delete: the list's "pending sync" mark. */
    fun pendingSyncItemIds(): Set<String> = store.pending().mapTo(LinkedHashSet()) { it.itemId }
    fun hasPendingSync(itemId: String): Boolean = store.pending().any { it.itemId == itemId }

    private fun overlayPending(base: List<VaultItem>, only: String? = null): List<VaultItem> {
        val pending = store.pending()
        if (pending.isEmpty()) {
            pendingDocCache.clear()
            return base
        }
        pendingDocCache.keys.retainAll(pending.mapTo(HashSet()) { it.mutationId })
        val byId = LinkedHashMap<String, VaultItem>(base.size)
        for (it in base) byId[it.itemId] = it
        for (m in pending) {
            if (only != null && m.itemId != only) continue
            if (m.op == MutationOp.DELETE) {
                byId.remove(m.itemId)
            } else if (m.op == MutationOp.PUT) {
                val decrypted = pendingDocCache.getOrPut(m.mutationId) {
                    val up = m.item ?: return@getOrPut null
                    if (keys.access(m.vaultId) == null) return@getOrPut null
                    val prior = byId[m.itemId] ?: store.getItem(m.itemId)
                    val row = SyncItem(m.itemId, m.vaultId, prior?.rev ?: 0, 0, clock(), false, false, up.formatVersion, up.attachmentIds, up.blob)
                    withKey(m.vaultId) { vk -> runCatching { VaultItem(m.itemId, m.vaultId, row.rev, row.updatedAt, codec.open(vk, row)) }.getOrNull() }
                }
                if (decrypted != null) byId[m.itemId] = decrypted
            }
        }
        return byId.values.toList()
    }

    /** The vaults this account may read, personal first, then by name. `type` follows the account genesis (spec 02 §4). */
    fun vaults(): List<VaultView> = store.vaults().mapNotNull { v ->
        val a = keys.access(v.vaultId) ?: return@mapNotNull null
        val name = withKey(v.vaultId) { codec.vaultName(it, v.vaultId, v.metaBlob) }
        val closedFor = closedForWriting(v.vaultId)
        VaultView(
            v.vaultId, if (a.personal) "personal" else "shared",
            if (!name.isNullOrEmpty() && name != VAULT_NAME_FALLBACK) name else if (a.personal) "Personal" else "Shared",
            a.role, a.standing, a.writable && closedFor == null, closedFor,
        )
    }.sortedWith(compareBy({ it.type != "personal" }, { it.name.lowercase() }))

    /** The account's personal vault, or null: no default save destination (design §5.3). */
    val personalVaultId: String? get() = keys.personalVaultId

    /** Persisted item envelopes (ciphertext rows), for the export planner. */
    fun envelopes(): List<SyncItem> = store.envelopes()

    /** Persisted vault rows as delivered; [vaults] is the readable view. */
    fun vaultRows(): List<SyncVault> = store.vaults()

    /**
     * The usage ledger's prune keep-set (spec 02 §8.2): every live envelope's id, readable here or not. Never built from
     * [items], which omits what this device cannot decrypt.
     */
    fun liveItemIds(): Set<String> = store.envelopes().filter { !it.deleted }.mapTo(HashSet()) { it.itemId }

    /** Every live envelope's id in [vaultId], readable here or not ("Move everything" counts what it cannot copy). */
    fun liveItemIdsIn(vaultId: String): Set<String> = store.envelopes().filter { !it.deleted && it.vaultId == vaultId }.mapTo(HashSet()) { it.itemId }

    /** Live envelopes in readable vaults whose formatVersion is newer than this client's: "N items need an app update". */
    fun needsUpdateCount(): Int {
        val open = HashMap<String, Boolean>()
        return store.envelopes().count { !it.deleted && it.formatVersion > ItemCodec.ITEM_FORMAT_VERSION && open.getOrPut(it.vaultId) { keys.access(it.vaultId) != null } }
    }

    /** Rows refused by INV-HOME (ciphertext, never applied), for diagnosis. */
    fun quarantinedItems(): List<SyncItem> = store.quarantined()

    /** The import destination's projections for the vault-aware import plan; the same vault must feed [importAll]. */
    fun importProjections(vaultId: String? = null): ItemResult<CsvImport.ImportProjections> = guard {
        val target = vaultId ?: personalOrStop()
        CsvImport.projections(items().filter { it.vaultId == target }.map { it.doc })
    }

    fun notices(): List<ItemNotice> = noticeList.toList()
    fun dismissNotice(id: String) { noticeList.removeAll { it.id == id } }
    fun clearNotices() = noticeList.clear()

    private fun notice(vaultId: String, name: String, kind: String, count: Int? = null, reason: String? = null, itemName: String? = null) {
        noticeList.add(ItemNotice(codec.freshId(), vaultId, name, kind, count, reason, itemName))
    }

    private fun nameOf(vaultId: String): String =
        store.vault(vaultId)?.let { v -> withKey(vaultId) { codec.vaultName(it, vaultId, v.metaBlob) } } ?: VAULT_NAME_FALLBACK

    /**
     * Close the cache (before its file is deleted). Every call that has not sent yet sees it ([live]): nothing more is
     * sealed or sent by this engine, whatever was waiting when it closed.
     */
    fun close() {
        closedFlag = true
        store.close()
    }

    @Volatile
    private var closedFlag = false

    /** Whether the outbound queue survives the process ([VaultCache.durable]). */
    val holdsDurableCache: Boolean get() = store.durable

    // ==== session start ====

    /**
     * Rebuild the working set from the cache after unlock, before the first [sync]: [keys] adopts what it may from the
     * cached rows, then every envelope it can read is decrypted. Sends nothing. An envelope that does not open (a
     * newer formatVersion, a vault not accepted yet) stays as ciphertext and is tried again when its vault opens.
     */
    suspend fun hydrate() = syncMutex.withLock { hydrateLocked() }

    private var hydrated = false

    private suspend fun hydrateLocked() {
        hydrated = true
        // Under a stopped origin the cache is read and never changed: ask before the first row is touched.
        val readOnly = halted
        keys.reopen(store.vaults(), store.grants())
        if (readOnly) log.warn(EVENT_HALTED, "the origin's pin is not in force: reading the cache only")
        readable.clear()
        decryptCached(null, null)
        staged.clear()
        for (m in store.stagedDenied()) staged.getOrPut(m.vaultId) { mutableListOf() }.add(StagedDenial(m, 0))
    }

    /** Decrypt the cached envelopes of every readable vault ([only]: just those vaults) and record their homes. */
    private fun decryptCached(only: Set<String>?, hints: HeadHints?) {
        val ring = KeyRing()
        try {
            for (w in store.envelopes()) {
                if (only != null && w.vaultId !in only) continue
                val readable = ring.has(w.vaultId)
                if (!admitHome(w, applies = readable && !w.deleted && w.blob != null)) {
                    if (!haltedFlag) store.deleteItem(w.itemId)
                    continue
                }
                if (w.deleted || !readable) continue
                val doc = ring.open(w.vaultId) { vk -> runCatching { codec.open(vk, w) }.getOrNull() } ?: continue
                store.upsertItem(w, VaultItem(w.itemId, w.vaultId, w.rev, w.updatedAt, doc))
                homeApplied(w)
                hints?.note(w.vaultId, doc)
            }
        } finally {
            ring.wipe()
        }
        for (v in store.vaults()) {
            if ((only == null || v.vaultId in only) && keys.access(v.vaultId) != null) {
                readable[v.vaultId] = withKey(v.vaultId) { codec.vaultName(it, v.vaultId, v.metaBlob) } ?: VAULT_NAME_FALLBACK
            }
        }
    }

    /**
     * Bring the working set in line with what [keys] allows now. A vault that is no longer readable has its plaintext
     * evicted (its ciphertext stays for the day it opens again); a vault that became readable since the last pass (an
     * accepted share, a late self-wrap) has the rows this device already holds decrypted. Sends nothing.
     */
    private fun settle(hints: HeadHints?) {
        val closed = readable.keys.filterTo(HashSet()) { keys.access(it) == null }
        if (closed.isNotEmpty()) {
            for (w in store.envelopes()) if (w.vaultId in closed && store.getItem(w.itemId) != null) store.upsertItem(w, null)
            readable.keys.removeAll(closed)
        }
        val rows = store.vaults()
        val opened = rows.map { it.vaultId }.filterTo(HashSet()) { it !in readable && keys.access(it) != null }
        if (opened.isNotEmpty()) decryptCached(opened, hints)
        // Names follow renames.
        for (v in rows) if (v.vaultId in readable && v.vaultId !in opened) withKey(v.vaultId) { codec.vaultName(it, v.vaultId, v.metaBlob) }?.let { readable[v.vaultId] = it }
    }

    // ==== the sync cycle ====

    /**
     * Push queued mutations first, then pull, THEN surface denied writes: a denied flush never aborts the pull that
     * shows why (spec 03 §4). [ItemFailure.Denied] means the cycle completed and that many writes were refused.
     */
    suspend fun sync(): ItemResult<SyncReport> = guard { syncMutex.withLock { cycle() } }

    private suspend fun cycle(): SyncReport {
        live()
        // Design §4.4: every sync judges the origin's card chain first, so a fork is noticed by ordinary use.
        if (gate.judge()) {
            haltedFlag = true
            throw Stop(ItemFailure.Halted)
        }
        // A host that never called hydrate still starts from its cache: the staged denials and the working set.
        if (!hydrated) hydrateLocked()
        pruneHolding()
        rejectedMutationIds.clear()
        flushQueue()
        val report = pull()
        surfaceStagedDenials()
        return report
    }

    private suspend fun pull(): SyncReport {
        live()
        val myStart = ++pullStartCounter
        val since = store.cursor()
        // The vaults this device was reading before the pull, with their names: notices fire only for these.
        val before = HashMap(readable)

        var resyncing = false
        var answer = transport.pull(since)
        if (answer is WireResult.Refused && answer.isResync()) {
            // Fetch the replacement snapshot FIRST; the cache is replaced only once it is in hand.
            resyncing = true
            answer = transport.pull(0)
        }
        val served = answer.orStop()
        // Rollback guards before anything is applied or reported (spec 05 T1, spec 03 §4): an older page is never
        // taken as the truth, local newer state is kept, and the person is warned once.
        // A rev is global and only grows: a snapshot below the cursor is a rollback even when a resync was demanded (H9).
        val rolledBack = when {
            served.full && since > 0 && !resyncing -> true
            served.rev < since -> false
            else -> null
        }
        if (rolledBack != null) {
            if (noticeList.none { it.kind == ItemNotice.ROLLBACK }) notice("", "", ItemNotice.ROLLBACK)
            throw Stop(ItemFailure.Rollback(unsolicitedFull = rolledBack))
        }
        val resp = sanitized(served)

        val servedIds = resp.vaults.mapTo(HashSet()) { it.vaultId }
        val vanished = if (resp.full) store.vaults().map { it.vaultId }.filterTo(HashSet()) { it !in servedIds } else emptySet()
        // A personal vault has no members (design §3.10), so no removal of it is genuine: it never counts as lost.
        val personal = keys.personalVaultId
        val lost = (resp.removedGrants.toSet() + vanished).let { if (personal != null) it - personal else it }
        personalClaimed = personal != null && personalTakenAway(resp, personal)
        // The trust engine first: logs fetched and verified, keys adopted or dropped, before any item of this pull is read.
        keys.served(ServedVaults(resp.full, resp.vaults, resp.grants, lost, resp.accountStateSeq))

        val hints = HeadHints()
        val pendingNotices = ArrayList<ItemNotice>()
        val reinstated = try {
            applyPull(resp, resyncing, before, lost, hints, pendingNotices)
        } catch (t: Throwable) {
            if (t is CancellationException) throw t
            // The cache rolled back; rebuild the in-memory working set from it so the session matches disk.
            runCatching {
                store.evictDecrypted()
                readable.clear()
                decryptCached(null, null)
            }
            wrongVault = ItemHome.Tally()
            throw t
        }
        if (myStart > freshestCompletedPullStart) {
            freshestCompletedPullStart = myStart
            latestQuota = resp.quota
        }
        noticeList.addAll(pendingNotices)
        if (personalClaimed && noticeList.none { it.kind == ItemNotice.PERSONAL_KEPT }) notice(personal ?: "", "", ItemNotice.PERSONAL_KEPT)

        settle(hints)

        if (reinstated) {
            // The parked writes are back in the durable queue. A failure here leaves them queued: the next cycle's
            // drain meets the same failure first and reports it.
            try {
                flushQueue()
            } catch (e: Stop) {
                if (e.why is ItemFailure.Halted) throw e
            }
        }
        drainReplayDenied()
        for ((vaultId, heads) in hints.byVault) {
            for ((seq, hash) in heads.entries.sortedByDescending { it.key }.take(MAX_HEAD_HINTS)) keys.itemHead(vaultId, seq, hash)
        }
        materializeOutstandingConflicts()
        surfaceWrongVault()
        return SyncReport(resp.rev, resp.full, resp.quota)
    }

    // ---- the account's own use and limits (spec 03 §14.4, "What an account is told") ----

    @Volatile
    private var latestQuota: io.silencelen.andvari.core.model.wire.QuotaUse? = null

    /**
     * The account's own use and limits as the freshest completed pull served them (a sync, or the pull after a write or
     * an import), or null when it sent none or none that can be meters. For a storage line in Settings; the check before a
     * large copy uses [roomFor], which syncs first.
     */
    fun quota(): io.silencelen.andvari.core.model.wire.QuotaUse? = latestQuota

    /**
     * The check before a large copy (spec 03 §14.4): a sync, then [QuotaCheck.room] on the `quota` its pull served. A
     * sync that completed its pull but reports writes denied ([ItemFailure.Denied], whose notices stay) still answers
     * the check; any other failure is the answer, and nothing is checked on an older value.
     */
    suspend fun roomFor(size: CopySize): ItemResult<QuotaRoom> = guard {
        syncMutex.withLock {
            val asked = pullStartCounter
            try {
                cycle()
            } catch (e: Stop) {
                if (e.why !is ItemFailure.Denied || freshestCompletedPullStart <= asked) throw e
            }
            QuotaCheck.room(latestQuota, size)
        }
    }

    /** What importing [items] writes ([CopySize]): their blob lengths exactly as [importAll] seals them, and their count. */
    fun importSize(items: List<CsvImport.PlannedItem>): CopySize =
        CopySize(items.fold(0L) { sum, it -> sum + codec.sealedLength(it.doc) }, items.size.toLong())

    /**
     * What copying every item this device shows in [vaultId] writes ([CopySize]): each item's blob length as it would be
     * sealed again (a copy keeps the document's size), each attachment's stored size once, and the count. With
     * [newVaultName], the copy goes into a new shared vault of that name ("Move everything to a new vault", design
     * §3.13), whose `metaBlob` length is [CopySize.metaBytes]. Items this device cannot read are not counted: they are
     * not copied either.
     *
     * An attachment's size is what the item's document DECLARES, and any writer of the vault chooses it:
     * each is capped at [fileMaxBytes] (the policy's limit for one file; the server refuses a larger upload),
     * every sum saturates (never negative, never a throw), and the attachments' part is [CopySize.declaredBytes], so the
     * check can say when a "short" rests on them ([QuotaRoom.Short.restsOnDeclaredSizes]).
     */
    fun vaultSize(vaultId: String, newVaultName: String? = null, fileMaxBytes: Long = DEFAULT_FILE_MAX_BYTES): CopySize {
        val shown = items().filter { it.vaultId == vaultId }
        val files = HashMap<String, Long>()
        for (item in shown) for (a in item.doc.attachments) files[a.id] = storedAttachmentBytes(minOf(a.size, fileMaxBytes))
        val docs = shown.fold(0L) { sum, it -> QuotaCheck.saturatedSum(sum, codec.sealedLength(it.doc)) }
        val declared = files.values.fold(0L, QuotaCheck::saturatedSum)
        return CopySize(QuotaCheck.saturatedSum(docs, declared), shown.size.toLong(), newVaultName != null,
            newVaultName?.let { codec.metaLength(it) } ?: 0L, declaredBytes = minOf(declared, QuotaCheck.saturatedSum(docs, declared)))
    }

    /**
     * What copying the items [docs] writes ([CopySize]), as [vaultSize] counts a vault's: each document's blob length as
     * it would be sealed again, each attachment's stored size once with its declared size capped at [fileMaxBytes]
     * ([CopySize.declaredBytes]), and the count. For a copy or a move of a few items, or of a vault's items this device
     * keeps in the holding area, into a vault the account owns; with [newVaultName], into a new shared vault of that name
     * (the rest of a "Move everything" run that already copied some items).
     */
    fun copySize(docs: List<ItemDoc>, fileMaxBytes: Long = DEFAULT_FILE_MAX_BYTES, newVaultName: String? = null): CopySize =
        sizeOf(codec, docs, fileMaxBytes, newVaultName)

    /** An attachment's stored size (spec 03 §9: its upload body less the 24-byte header); 0 for a size no file can have. */
    private fun storedAttachmentBytes(plainSize: Long): Long =
        if (plainSize <= 0 || plainSize > (1L shl 50)) 0L else Attachments.wireLength(plainSize) - Attachments.HEADER_BYTES

    /**
     * Whether this pull's answer claims the personal vault away: it names it as removed, left or
     * deleted, or a whole snapshot leaves out its vault row or this account's grant row, or it serves that grant row
     * with another key than the one this device holds, or the vault's metadata under another key. None of it can be
     * genuine, and none of it changes anything: [applyPull] keeps the vault, its key, its rows and its saves, and the
     * person is told once ([ItemNotice.PERSONAL_KEPT]).
     */
    private var personalClaimed = false

    private fun personalTakenAway(resp: SyncResponse, personal: String): Boolean {
        if (personal in resp.removedGrants || resp.removedGrantsInfo.any { it.vaultId == personal }) return true
        if (resp.full && (resp.vaults.none { it.vaultId == personal } || resp.grants.none { it.vaultId == personal && it.userId == userId })) return true
        val heldGrant = store.grants().firstOrNull { it.vaultId == personal && it.userId == userId }
        return heldGrant != null && resp.grants.any { it.vaultId == personal && it.userId == userId && it.wrappedVk != heldGrant.wrappedVk }
    }

    /** Drop every served row whose ids are not canonical UUIDs (spec 03 §5, spec 05 R18): one notice per pull. */
    private fun sanitized(resp: SyncResponse): SyncResponse {
        fun ok(id: String) = TrustGrammar.isUuid(id)
        val vaults = resp.vaults.filter { ok(it.vaultId) }
        val grants = resp.grants.filter { ok(it.vaultId) && ok(it.userId) }
        val items = resp.items.filter { ok(it.itemId) && ok(it.vaultId) }
        val removed = resp.removedGrants.filter(::ok)
        val refused = (resp.vaults.size - vaults.size) + (resp.grants.size - grants.size) + (resp.items.size - items.size) + (resp.removedGrants.size - removed.size)
        if (refused == 0) return resp
        notice("", "", ItemNotice.BAD_ID, count = refused, reason = "sync")
        return resp.copy(vaults = vaults, grants = grants, items = items, removedGrants = removed, removedGrantsInfo = resp.removedGrantsInfo.filter { ok(it.vaultId) })
    }

    /** Apply one pull in one cache transaction. Answers whether a vault came back from the holding area. */
    private fun applyPull(
        resp: SyncResponse,
        resyncing: Boolean,
        before: Map<String, String>,
        lost: Set<String>,
        hints: HeadHints,
        notices: MutableList<ItemNotice>,
    ): Boolean {
        var reinstated = false
        val ring = KeyRing()
        // What this device holds of its personal vault, read before a resync replaces the rows: no answer replaces it
        // with a row under another key, or takes its grant away.
        val personal = keys.personalVaultId
        val heldPersonal = personal?.let { store.vault(it) }
        val heldPersonalGrant = personal?.let { p -> store.grants().firstOrNull { it.vaultId == p && it.userId == userId } }
        try {
            store.atomically {
                if (resyncing) {
                    // A resync replaces the rows (spec 03 §4). What the snapshot no longer lists is kept until the
                    // trust engine has spoken: a server cannot make this device drop its copy (spec 02 §10.6).
                    val servedIds = resp.vaults.mapTo(HashSet()) { it.vaultId }
                    val keptVaults = store.vaults().filter { it.vaultId !in servedIds }
                    val keptIds = keptVaults.mapTo(HashSet()) { it.vaultId }
                    val keptGrants = store.grants().filter { it.vaultId in keptIds }
                    val keptItems = store.envelopes().filter { it.vaultId in keptIds }
                    store.clear()
                    for (v in keptVaults) store.upsertVault(v)
                    for (g in keptGrants) store.upsertGrant(g)
                    for (w in keptItems) store.upsertItem(w, ring.open(w.vaultId) { vk -> opened(vk, w) })
                }
                // Rows persist unconditionally (deltas never re-send); only this account's own grant rows are kept.
                for (g in resp.grants) {
                    if (g.userId != userId) continue
                    if (g.vaultId == personal && heldPersonalGrant != null && g.wrappedVk != heldPersonalGrant.wrappedVk) continue
                    store.upsertGrant(g)
                }
                if (heldPersonalGrant != null && store.grants().none { it.vaultId == personal && it.userId == userId }) store.upsertGrant(heldPersonalGrant)
                for (delivered in resp.vaults) {
                    if (delivered.vaultId == personal && withKey(personal) { codec.vaultMeta(it, personal, delivered.metaBlob) } == null) {
                        // Metadata the personal key does not open: not this vault's. The held row stays.
                        personalClaimed = true
                        store.upsertVault(heldPersonal ?: delivered)
                        continue
                    }
                    store.upsertVault(keepNewerMeta(delivered, notices))
                }

                // The envelopes this device holds, read once and only when a tombstone arrives: the trash opens from them.
                val heldRows by lazy(LazyThreadSafetyMode.NONE) { store.envelopes().associateBy { it.itemId } }
                // The items each held copy holds, by vault, read once and only when this answer serves an item row.
                val heldIds by lazy(LazyThreadSafetyMode.NONE) { store.heldVaults().associate { h -> h.vault.vaultId to h.items.mapTo(HashSet()) { it.itemId } } }
                // The record of served deletions of each held copy this answer touches, as it stands; written once below.
                val heldDeleted = HashMap<String, MutableSet<String>>()
                val trashed = ArrayList<SyncItem>()
                for (item in resp.items) {
                    val readable = ring.has(item.vaultId)
                    // INV-HOME first: a row under another vault than the item's home is not applied at all.
                    if (!admitHome(item, applies = readable && !item.deleted && item.blob != null)) continue
                    // A row of an item that a held copy of the same vault holds (spec 02 §10.6): a deletion is recorded with
                    // that copy, a live row takes the record out again. The copy itself keeps every item: a deletion row
                    // carries no signature, and only putting the vault back, after the person accepted, reads the record.
                    if (heldIds[item.vaultId]?.contains(item.itemId) == true) {
                        val record = heldDeleted.getOrPut(item.vaultId) { LinkedHashSet(store.heldDeleted(item.vaultId)) }
                        if (item.deleted) record += item.itemId else record -= item.itemId
                    }
                    if (item.deleted) {
                        heldRows[item.itemId]?.takeIf { it.vaultId == item.vaultId }?.let { trashed += it }
                        store.deleteItem(item.itemId)
                        continue
                    }
                    // The envelope persists even when it cannot be read here: its rev passed the cursor.
                    val decrypted = if (readable) ring.open(item.vaultId) { opened(it, item) } else null
                    store.upsertItem(item, decrypted)
                    if (decrypted != null) {
                        homeApplied(item)
                        hints.note(item.vaultId, decrypted.doc)
                    }
                }

                store.keepTrashed(trashed)
                for ((vaultId, record) in heldDeleted) store.setHeldDeleted(vaultId, record)

                // A held vault the account may use again, served again: its parked writes return to the queue.
                for (h in store.heldVaults()) {
                    val id = h.vault.vaultId
                    if (keys.departure(id) != null || keys.access(id) == null || store.vault(id) == null) continue
                    // What the server served since the copy was held rules (spec 02 §10.6). The rows of the vault this
                    // device holds unread (served while its key was not offered) are opened now, as the loop above opens
                    // a row it can read; a row that does not open stays as it is.
                    val deleted = store.heldDeleted(id)
                    for (w in store.envelopes()) {
                        if (w.vaultId != id || w.deleted || w.blob == null || store.getItem(w.itemId) != null) continue
                        if (!admitHome(w, applies = true)) continue
                        val decrypted = ring.open(id) { opened(it, w) } ?: continue
                        store.upsertItem(w, decrypted)
                        homeApplied(w)
                        hints.note(id, decrypted.doc)
                    }
                    val served = store.envelopes().mapTo(HashSet()) { it.itemId }
                    for (m in h.parked) {
                        store.enqueue(m)
                        replayedMutationIds[m.mutationId] = h.reason
                    }
                    store.removeHeld(id)
                    // The held copy puts back only an item of which this device holds no served row, readable or not, and
                    // whose deletion was not served: a member changed or deleted it meanwhile, and the copy's older
                    // version does not come back over that.
                    for (w in h.items) {
                        if (w.itemId in served || w.itemId in deleted || !admitHome(w, applies = true)) continue
                        val item = ring.open(id) { opened(it, w) } ?: continue
                        store.upsertItem(w, item)
                        homeApplied(w)
                    }
                    notices += ItemNotice(codec.freshId(), id, nameOf(id), ItemNotice.RESTORED)
                    reinstated = true
                }

                // Vaults that left. Only a reason the trust engine verified moves a copy to the holding area.
                for (v in store.vaults()) {
                    val id = v.vaultId
                    if (id == keys.personalVaultId) continue
                    val departure = keys.departure(id)
                    val wasOpen = before.containsKey(id)
                    if (departure != null) {
                        if (wasOpen) {
                            val parked = moveToHolding(id, departure)
                            if (!quietDepartures.remove(id)) notices += ItemNotice(codec.freshId(), id, before.getValue(id), departure.code, parked.takeIf { it > 0 })
                        } else {
                            dropLocal(id) // never readable here: nothing to hold
                        }
                    } else if (id in lost) {
                        if (keys.access(id) == null) {
                            dropLocal(id) // rows this device could never read, taken back
                        } else {
                            store.setTakenAway(id, true)
                            if (wasOpen) notices += ItemNotice(codec.freshId(), id, before.getValue(id), ItemNotice.WITHHELD)
                        }
                    } else if (staged[id].isNullOrEmpty() && keys.access(id)?.standing == VaultStanding.VERIFIED && store.takenAway(id)) {
                        store.setTakenAway(id, false) // back, with nothing held back to replay
                    }
                }
                store.setCursor(resp.rev)
            }
        } finally {
            ring.wipe()
        }
        return reinstated
    }

    private fun opened(vk: ByteArray, row: SyncItem): VaultItem? =
        runCatching { VaultItem(row.itemId, row.vaultId, row.rev, row.updatedAt, codec.open(vk, row)) }.getOrNull()

    /**
     * spec 02 §4 warn-and-keep-newer: a delivered metaBlob whose `metaV` regressed below the held one is a replayed
     * row; the newer local blob is kept (rev and the log head still apply). Comparable only when the key is held, a
     * previous row exists and both blobs decrypt; anything else applies the delivered row.
     */
    private fun keepNewerMeta(delivered: SyncVault, notices: MutableList<ItemNotice>): SyncVault {
        val held = store.vault(delivered.vaultId) ?: return delivered
        if (held.metaBlob == delivered.metaBlob || keys.access(delivered.vaultId) == null) return delivered
        return withKey(delivered.vaultId) { vk ->
            val heldMeta = codec.vaultMeta(vk, delivered.vaultId, held.metaBlob) ?: return@withKey delivered
            val newMeta = codec.vaultMeta(vk, delivered.vaultId, delivered.metaBlob) ?: return@withKey delivered
            if (ItemCodec.metaVOf(newMeta) < ItemCodec.metaVOf(heldMeta)) {
                log.warn(CoreLog.EVENT_VAULT_META_REPLAY, "vault ${delivered.vaultId} delivered an older metaV; keeping the newer local metadata")
                notices += ItemNotice(codec.freshId(), delivered.vaultId, "", ItemNotice.META_REPLAY)
                delivered.copy(metaBlob = held.metaBlob)
            } else delivered
        } ?: delivered
    }

    // ---- item home (spec 02 §7.2) ----

    /** INV-HOME: admit one served or cached row against `home(itemId)`; a row under another vault is quarantined. */
    private fun admitHome(item: SyncItem, applies: Boolean): Boolean =
        when (ItemHome.admit(store.itemHome(item.itemId), item.vaultId, applies)) {
            ItemHome.Admit.NEW_HOME, ItemHome.Admit.SKIP, ItemHome.Admit.HOME -> true
            ItemHome.Admit.QUARANTINE -> {
                if (!haltedFlag) store.quarantine(item)
                wrongVault.note(item.vaultId)
                false
            }
        }

    /** The first row this device APPLIED for an itemId is its home. */
    private fun homeApplied(item: SyncItem) {
        if (!haltedFlag && store.itemHome(item.itemId) == null) store.setItemHome(item.itemId, item.vaultId)
    }

    private fun surfaceWrongVault() {
        val t = wrongVault
        wrongVault = ItemHome.Tally()
        if (t.anomalies() > 0) notice(t.firstVaultId ?: "", "", ItemNotice.WRONG_VAULT, count = t.refused)
    }

    // ---- the one seal (spec 02 §7.2 INV-SEAL, INV-WRITE-KEY) ----

    private fun requireWritable(vaultId: String) {
        val a = keys.access(vaultId) ?: refuse(ItemRefusal.VAULT_NOT_OPEN)
        if (!a.writable) refuse(ItemRefusal.VAULT_READ_ONLY)
        if (closedForWriting(vaultId) != null) refuse(ItemRefusal.VAULT_CLOSED_FOR_WRITING)
    }

    // ---- vaults closed for writing by the app interface (a deletion signed and waiting) ----

    /** The marks, read once from the account's cache and then kept in step with it. */
    private var writeClosedMarks: MutableMap<String, VaultClosedReason>? = null

    private fun marks(): MutableMap<String, VaultClosedReason> =
        writeClosedMarks ?: store.writeClosed().toMutableMap().also { writeClosedMarks = it }

    /**
     * Close [vaultId] for writing on this device with [reason], or open it again with null. While it is closed, every
     * road that would put something into it or change something in it (a new item, an edit, a delete, a delete for
     * good, a restore, an import, a move or a copy into it, a move out of it, a file, a rename) is refused with
     * [ItemRefusal.VAULT_CLOSED_FOR_WRITING] before anything is sealed; a copy out stays allowed. The mark is kept in
     * the account's cache: it outlives a lock and a restart, and goes when it is cleared here or when the account's data
     * leaves the device.
     */
    fun markClosedForWriting(vaultId: String, reason: VaultClosedReason?) {
        val m = marks()
        if (reason == null) m.remove(vaultId) else m[vaultId] = reason
        store.setWriteClosed(m)
    }

    /**
     * [vaultId]'s deletion stands in its verified log (it can still be restored for a time): the server ended every
     * grant with it and refuses a write, so nothing is sealed into it on this device ([requireWritable] already refuses
     * it: it has no access). A restore in the log ends it at once.
     */
    fun vaultDeleted(vaultId: String): Boolean = vaultId != keys.personalVaultId && keys.departure(vaultId) == VaultDeparture.DELETED

    /** Why [vaultId] is closed for writing on this device, or null when it is not ([markClosedForWriting]). */
    fun closedForWriting(vaultId: String): VaultClosedReason? = marks()[vaultId]

    private fun personalOrStop(): String = keys.personalVaultId ?: refuse(ItemRefusal.NO_PERSONAL_VAULT)

    /**
     * Seal [doc] as [itemId] for a push. [provenance] names where the plaintext came from and so the only vault it may
     * be sealed under; the item must live there, or have no home yet (a fresh id, which this seal records). Never under
     * a vault whose status or role forbids the write, and always carrying that vault's verified log head.
     */
    private fun sealFor(provenance: SealProvenance, itemId: String, doc: ItemDoc): ItemUpload {
        val vaultId = provenance.vaultId
        requireWritable(vaultId)
        val home = store.itemHome(itemId)
        if (ItemHome.seal(home, vaultId) == ItemHome.Seal.REFUSE) refuse(ItemRefusal.ITEM_CHANGED_VAULTS)
        val upload = withKey(vaultId) { codec.seal(it, vaultId, itemId, ItemCodec.stamped(doc, keys.logHead(vaultId))) } ?: refuse(ItemRefusal.VAULT_NOT_OPEN)
        if (home == null) store.setItemHome(itemId, vaultId)
        return upload
    }

    private fun putMutation(provenance: SealProvenance, itemId: String, doc: ItemDoc, baseItemRev: Long): Mutation =
        Mutation(codec.freshId(), MutationOp.PUT, itemId, provenance.vaultId, baseItemRev, sealFor(provenance, itemId, doc))

    /**
     * A put of [doc] as [itemId] into [vaultId] from [baseItemRev], sealed now under [mutationId] by the one seal's rules,
     * and neither queued nor sent: for a pass that sends it itself, with no drain and no conflict copy (the one attempt
     * before a server's policy removes the copy). [isNew]: an item the editor minted the id of. Works while the engine is
     * halted for that removal; a lock or a closed engine is [KeysGoneException], as for every seal.
     */
    fun sealedPut(mutationId: String, itemId: String, doc: ItemDoc, vaultId: String, baseItemRev: Long, isNew: Boolean): ItemResult<Mutation> = guard {
        if (closedFlag || !keys.keysLive) throw KeysGoneException("the vault closed: nothing more is sealed")
        if (!TrustGrammar.isUuid(itemId)) refuse(ItemRefusal.BAD_ID)
        val provenance = if (isNew) SealProvenance.Chosen(vaultId) else SealProvenance.Editor(vaultId)
        Mutation(mutationId, MutationOp.PUT, itemId, vaultId, baseItemRev, sealFor(provenance, itemId, doc))
    }

    // ==== the holding area (spec 02 §10.6) ====

    /**
     * Move a departed vault's rows to the ciphertext-only holding area for 30 days, then drop it from the live view.
     * Parked with it: writes the server denied, writes not sent yet, and anything parked before. Answers how many.
     */
    private fun moveToHolding(vaultId: String, departure: VaultDeparture): Int {
        val prior = store.getHeld(vaultId)
        val items = store.envelopes().filter { it.vaultId == vaultId && !it.deleted }
        val denied = staged.remove(vaultId)?.map { it.mutation } ?: emptyList()
        val queued = store.pending().filter { it.vaultId == vaultId }
        val parked = ((prior?.parked ?: emptyList()) + denied + queued).distinctBy { it.mutationId }
        // A new copy starts with no served deletion recorded (the record goes with each copy; this clears one left behind).
        if (prior == null) store.setHeldDeleted(vaultId, emptyList())
        store.putHeld(
            HeldVault(
                store.vault(vaultId) ?: SyncVault(vaultId, "shared", 0, "", 0), store.grants().firstOrNull { it.vaultId == vaultId },
                items.ifEmpty { prior?.items ?: emptyList() }, departure.code, parked, clock() + HOLDING_MS,
            ),
        )
        dropLocal(vaultId)
        return parked.size
    }

    /** Drop a vault from the live view: its rows and its queued writes. */
    private fun dropLocal(vaultId: String) {
        store.dropVault(vaultId)
        store.dropPending(vaultId)
        staged.remove(vaultId)
        readable.remove(vaultId)
    }

    private fun pruneHolding() {
        val now = clock()
        for (h in store.heldVaults()) if (h.expungeAt <= now) store.atomically { store.removeHeld(h.vault.vaultId) }
    }

    /** The vaults in the holding area ("Recently removed"). */
    fun heldVaults(): List<HeldVaultView> = store.heldVaults().map { h ->
        val id = h.vault.vaultId
        val name = withKey(id) { codec.vaultName(it, id, h.vault.metaBlob) }
        HeldVaultView(
            id, name, h.reason, h.items.size, h.parked.size, h.expungeAt, readable = keys.withKey(id) { true } == true,
            ownedHere = h.grant?.let { it.userId == userId && it.role == VaultAccess.ROLE_OWNER } == true,
            addedAgain = keys.heldClosedAsMemberAgain(id),
        )
    }

    /**
     * The held items of [vaultId], decrypted for reading and copying out. Empty when the trust engine no longer offers
     * the vault's key; nothing here is ever written back under that key.
     */
    fun heldItems(vaultId: String): List<VaultItem> {
        val h = store.getHeld(vaultId) ?: return emptyList()
        return withKey(vaultId) { vk -> h.items.mapNotNull { opened(vk, it) } } ?: emptyList()
    }

    /**
     * "Remove from this device" (spec 02 §10.6): drop this device's copy of a held vault, or of a vault that is no
     * longer verified. A local action that tells the server nothing. A verified vault is left through its log instead.
     */
    fun removeFromDevice(vaultId: String): ItemResult<Unit> = guard {
        live()
        if (store.getHeld(vaultId) != null) {
            store.atomically { store.removeHeld(vaultId) }
        } else {
            if (vaultId == keys.personalVaultId || keys.access(vaultId)?.standing == VaultStanding.VERIFIED) refuse(ItemRefusal.VAULT_READ_ONLY)
            store.atomically { dropLocal(vaultId) }
        }
    }

    /** The host is about to delete or leave [vaultId] itself: its departure on the next pull raises no notice. */
    fun expectDeparture(vaultId: String) { quietDepartures.add(vaultId) }

    /**
     * The host's own delete or leave of [vaultId] did not happen (the server refused it, or it was never sent): the
     * expectation [expectDeparture] set is withdrawn, so a later departure of that vault, by anyone, is said.
     */
    fun withdrawDeparture(vaultId: String) { quietDepartures.remove(vaultId) }

    // ==== the outbound queue (spec 03 §5) ====

    /** Enqueue durably, then try to send; a failure leaves the rows queued. */
    private suspend fun push(mutations: List<Mutation>) {
        mutations.forEach { store.enqueue(it) }
        flushQueue()
    }

    /**
     * The next batch: at most [SERVER_BATCH_MAX] rows and, past the first row, at most [PUSH_BODY_SOFT_CAP_BYTES] of
     * approximate encoded size. The first row is always taken, so a lone over-cap row is refused alone. Rows for a
     * vault that is not verified right now are held back: nothing is sent to a vault whose status forbids it.
     */
    private fun nextBatch(): List<Mutation> {
        val out = ArrayList<Mutation>()
        var bytes = 0L
        val sendable = HashMap<String, Boolean>()
        for (m in store.pending()) {
            if (out.size >= SERVER_BATCH_MAX) break
            // A vault closed for writing ([markClosedForWriting]: its deletion is signed and waiting) takes nothing, not
            // even what was sealed before the mark: sent now, it would land in a vault about to be deleted. It waits,
            // drains when the mark is cleared, and is parked with the held copy if the vault goes ([waitingChanges]).
            if (!sendable.getOrPut(m.vaultId) { keys.access(m.vaultId)?.standing == VaultStanding.VERIFIED && closedForWriting(m.vaultId) == null }) continue
            val size = (m.item?.blob?.length?.toLong() ?: 0L) + (m.item?.attachmentIds?.size ?: 0) * 40L + 256L
            if (out.isNotEmpty() && bytes + size > PUSH_BODY_SOFT_CAP_BYTES) break
            out.add(m)
            bytes += size
        }
        return out
    }

    /** A displaced value the server returned, the winner's rev, and the vault the losing put was pushed to. */
    private class Displaced(val losing: SyncItem, val winnerRev: Long, val pushedVaultId: String)

    /**
     * Drain the queue in server-sized batches. A `denied` row is durably marked staged-denied and never re-pushed:
     * the following pull shows whether its vault left (parked for a return) or the denial is genuine (dropped, and
     * reported). Never stops for a denial.
     */
    /**
     * Asked before every drain of the queue, by whichever write or sync drains it, with the items whose puts wait there
     * ([BeforeDrain]). A failure it answers stops the drain as the push would have stopped, and everything stays queued.
     */
    internal var beforeDrain: BeforeDrain? = null

    private suspend fun flushQueue() {
        live()
        beforeDrain?.let { ready ->
            val puts = store.pending().filter { it.op == MutationOp.PUT }.mapTo(HashSet()) { it.itemId }
            if (puts.isNotEmpty()) ready(puts)?.let { throw Stop(it) }
            live()
        }
        val displaced = mutableListOf<Displaced>()
        var answered = false
        while (true) {
            // A halt after an answered batch ends the drain without failing it: what the server answered is settled, and
            // what remains stays queued (a write still queued says so itself, [sendOrQueue]).
            if (answered && halted && !closedFlag && keys.keysLive) {
                mintRejectedNotices()
                return
            }
            // Every batch after the first follows a wait: a lock in it ends the drain, and what is queued stays queued.
            live()
            val chunk = nextBatch()
            if (chunk.isEmpty() || !pushBatch(chunk, displaced)) break
            answered = true
        }
        mintRejectedNotices()
        // After the drain: each copy is a fresh item that applies cleanly, so the re-entrant push is bounded.
        for (d in displaced) materializeConflictFromServerItem(d)
    }

    /**
     * Send one batch and settle each row. A refusal with status 400 or 413 is a definitive refusal of the batch as
     * sent (spec 03 §5): the batch is bisected (a refused batch applied nothing, and the dedup window makes re-sends
     * idempotent) until the refusal isolates to single rows, which are dropped with a notice. Answers whether any row
     * was settled.
     */
    private suspend fun pushBatch(chunk: List<Mutation>, displaced: MutableList<Displaced>): Boolean {
        // Known as out before it is asked whether it may go, so a policy's attempt that starts meanwhile either sees it
        // (and counts its rows by its answer) or finds the engine halted before it left ([outbound]).
        val out = Outbound(chunk.mapTo(HashSet()) { it.mutationId })
        kotlinx.atomicfu.locks.synchronized(outboundLock) { outboundNow = out }
        var answer: WireResult<io.silencelen.andvari.core.model.wire.PushResponse>? = null
        try {
            try {
                live()
            } catch (e: Throwable) {
                answer = WireResult.NoAnswer(io.silencelen.andvari.core.client.net.NoAnswerKind.TRANSPORT, neverLeft = true)
                throw e
            }
            val r = transport.push(chunk)
            answer = r
            return settleBatch(chunk, r, displaced)
        } finally {
            // Told once this push's rows are settled here, so whoever counts them never races the settling.
            kotlinx.atomicfu.locks.synchronized(outboundLock) { if (outboundNow === out) outboundNow = null }
            out.done(answer)
        }
    }

    // ---- the request out (a policy's one attempt counts it, never sends it again) ----

    /**
     * A push of the queue that is out: its rows' mutation ids, and its answer once this engine has settled it. [await]
     * answers the push's own result, or null when it ended without one (cancelled, or a throw while it was out: it may
     * have arrived); a push that a halt or a lock stopped before it left answers no answer with `neverLeft`.
     */
    class Outbound internal constructor(val mutationIds: Set<String>) {
        private val answer = kotlinx.coroutines.CompletableDeferred<WireResult<io.silencelen.andvari.core.model.wire.PushResponse>?>()
        internal fun done(r: WireResult<io.silencelen.andvari.core.model.wire.PushResponse>?) { answer.complete(r) }
        suspend fun await(): WireResult<io.silencelen.andvari.core.model.wire.PushResponse>? = answer.await()
    }

    private val outboundLock = kotlinx.atomicfu.locks.SynchronizedObject()
    private var outboundNow: Outbound? = null

    /**
     * The push of the queue that is out now, if any. Once the engine is [halt]ed no other push of the queue leaves, so a
     * policy's one attempt reads this at its start: the rows it carries are that request's, counted by its answer and
     * never sent again; every other row that waits is the attempt's own.
     */
    fun outbound(): Outbound? = kotlinx.atomicfu.locks.synchronized(outboundLock) { outboundNow }

    private suspend fun settleBatch(chunk: List<Mutation>, answer: WireResult<io.silencelen.andvari.core.model.wire.PushResponse>, displaced: MutableList<Displaced>): Boolean {
        val resp = when (val r = answer) {
            is WireResult.Ok -> r.value
            is WireResult.NoAnswer -> throw Stop(ItemFailure.Unreachable(r.kind))
            is WireResult.Refused -> {
                if (r.status != 400 && r.status != 413) throw Stop(ItemFailure.Refused(r.code, r.status, r.retryAfterSeconds))
                if (chunk.size == 1) {
                    rejectRow(chunk[0], r.code)
                    return true
                }
                val mid = chunk.size / 2
                val a = pushBatch(chunk.subList(0, mid), displaced)
                val b = pushBatch(chunk.subList(mid, chunk.size), displaced)
                return a || b
            }
        }
        val byId = resp.results.associateBy { it.mutationId }
        var progressed = false
        for (m in chunk) {
            val r = byId[m.mutationId] ?: continue
            val replayedFor = replayedMutationIds.remove(m.mutationId)
            when (r.status) {
                MutationStatus.REJECTED -> rejectRow(m, r.reason ?: MutationStatus.REJECTED)
                MutationStatus.DENIED -> {
                    store.markStagedDenied(m.mutationId)
                    staged.getOrPut(m.vaultId) { mutableListOf() }.add(StagedDenial(m, pullStartCounter, replayedFor))
                }
                else -> {
                    // On a conflicting PUT the server keeps OUR value and returns the DISPLACED one: the conflict copy
                    // is built from that (spec 03 §5). A delete that lost returns the surviving winner: no copy.
                    val si = r.serverItem
                    val nr = r.newItemRev
                    // A put over a deletion: the server answers with the deletion's mark. It brought the item back and
                    // displaced no version, so no copy is made; it is said once ([noteBroughtBack]).
                    if (r.status == MutationStatus.CONFLICT && m.op == MutationOp.PUT && si?.deleted == true) {
                        noteBroughtBack(m, nr)
                    } else if (r.status == MutationStatus.CONFLICT && m.op == MutationOp.PUT && si != null && nr != null) {
                        displaced += Displaced(si, nr, m.vaultId)
                    }
                    // An OMITTED displaced value is not "nothing stored" (spec 03 §5): it is read from the item's history.
                    if (r.status == MutationStatus.CONFLICT && m.op == MutationOp.PUT && si == null && r.serverItemOmitted == true && nr != null) {
                        displacedFromHistory(m, nr)?.let { displaced += it }
                    }
                    // Any other definitive outcome, a status this client does not know included, removes the row.
                    store.dequeue(m.mutationId)
                    pendingDocCache.remove(m.mutationId)
                }
            }
            progressed = true
        }
        return progressed
    }

    /**
     * The displaced value of [m]'s conflicting put when the push result left it out: the newest archived version below
     * the winner's rev [winnerRev]. Null when the history has none (it left the history, or the read failed); then the
     * flagged row's fallback ([materializeOutstandingConflicts]) is all there is.
     */
    private suspend fun displacedFromHistory(m: Mutation, winnerRev: Long): Displaced? {
        val versions = (transport.versions(m.itemId) as? WireResult.Ok)?.value ?: return null
        val v = versions.filter { it.rev < winnerRev && it.blob.isNotEmpty() }.maxByOrNull { it.rev } ?: return null
        val row = SyncItem(m.itemId, m.vaultId, v.rev, 0, v.archivedAt, false, false, v.formatVersion, emptyList(), v.blob)
        return Displaced(row, winnerRev, m.vaultId)
    }

    /** Durably drop one definitively refused row; dropping it IS the revert, since the overlay reads the queue. */
    /**
     * The items a change of this device to which the server refused for good since the last [takeRefusedForGood]: a row it
     * rejected (dropped with a notice), or one it denied that was judged a genuine denial. In this engine's memory only.
     */
    private val refusedForGood = LinkedHashMap<String, ItemFailure>()

    /**
     * The items whose change this device sent and the server refused for good since the last call, each with the refusal
     * ([ItemFailure.Refused] for a rejected row, [ItemFailure.Denied] for a genuine denial); emptied by the call. The
     * engine's own notice says these as rejected writes; the content uses it to let go of a save it kept for one of them.
     */
    fun takeRefusedForGood(): Map<String, ItemFailure> = kotlinx.atomicfu.locks.synchronized(refusalLock) {
        when {
            refusedForGood.isEmpty() -> emptyMap()
            heldRefusals.isEmpty() -> LinkedHashMap(refusedForGood).also { refusedForGood.clear() }
            else -> {
                // The refusals of items another caller holds stay for that caller ([holdRefusals]).
                val taken = LinkedHashMap<String, ItemFailure>()
                for ((id, f) in refusedForGood) if (id !in heldRefusals) taken[id] = f
                for (id in taken.keys) refusedForGood.remove(id)
                taken
            }
        }
    }

    /**
     * [takeRefusedForGood] for [itemIds] alone: the refusals of those items, taken; every other item's stays for the
     * caller that sent it. A restore sends items under ids it minted itself and learns this way which of them the server
     * refused.
     */
    fun takeRefusedForGoodAmong(itemIds: Set<String>): Map<String, ItemFailure> = kotlinx.atomicfu.locks.synchronized(refusalLock) {
        val taken = LinkedHashMap<String, ItemFailure>()
        for (id in itemIds) refusedForGood.remove(id)?.let { taken[id] = it }
        taken
    }

    /** The items whose refusals [takeRefusedForGood] leaves for the caller that holds them ([holdRefusals]). */
    private val heldRefusals = HashSet<String>()

    /**
     * Held by every reading and writing of [refusedForGood] and [heldRefusals]: a restore holds and takes on its own
     * thread while the vault's content takes after its writes and syncs on another.
     */
    private val refusalLock = kotlinx.atomicfu.locks.SynchronizedObject()

    /**
     * From now until [releaseRefusals], a refusal of one of [itemIds] is left for the caller that sent them, which takes it
     * with [takeRefusedForGoodAmong]: a restore holds the ids of the batch it sends, so that a sync of the vault's content
     * meanwhile (the bell, "Sync now") never takes that batch's refusals for its own and lets them go.
     */
    fun holdRefusals(itemIds: Set<String>) {
        kotlinx.atomicfu.locks.synchronized(refusalLock) { heldRefusals.addAll(itemIds) }
    }

    /** The end of [holdRefusals] for [itemIds]. */
    fun releaseRefusals(itemIds: Set<String>) {
        kotlinx.atomicfu.locks.synchronized(refusalLock) { heldRefusals.removeAll(itemIds) }
    }

    private fun rejectRow(m: Mutation, reason: String) {
        store.dequeue(m.mutationId)
        replayedMutationIds.remove(m.mutationId)
        pendingDocCache.remove(m.mutationId)
        val refusal = ItemFailure.Refused(reason, if (reason == WireErrors.ITEM_ATTACHMENT_QUOTA || reason == WireErrors.BODY_TOO_LARGE) 413 else 400)
        kotlinx.atomicfu.locks.synchronized(refusalLock) { refusedForGood[m.itemId] = refusal }
        rejectedMutationIds[m.mutationId] = reason
        rejectedByVault.getOrPut(m.vaultId) { mutableListOf() }.add(reason)
    }

    private fun mintRejectedNotices() {
        for ((vaultId, reasons) in rejectedByVault) notice(vaultId, nameOf(vaultId), ItemNotice.WRITE_REJECTED, count = reasons.size, reason = reasons.first())
        rejectedByVault.clear()
    }

    private fun drainReplayDenied() {
        for ((at, n) in replayDeniedByVault) notice(at.first, nameOf(at.first), ItemNotice.REPLAY_DENIED, count = n, reason = at.second)
        replayDeniedByVault.clear()
    }

    /**
     * After the pull: a staged denial whose vault went to the holding area was parked with it. One whose vault is
     * still verified here is a genuine denial: dropped for good and reported. One whose vault is merely not verified
     * right now stays staged. An entry is classified only once a pull that STARTED after it was staged has completed.
     *
     * Every genuine denial is said by a notice per vault ([ItemNotice.WRITE_DENIED]) that names the item where it is one,
     * except the change of [write], whose own answer says it. The cycle then fails with [ItemFailure.Denied] (a sync, an
     * import); after a [write] the server applied, it fails only where that write's own change is among the denials: the
     * others are undone here and said by the notice, never by the write's answer.
     */
    private fun surfaceStagedDenials(write: Mutation? = null) {
        if (staged.isEmpty()) return
        var genuine = 0
        var ownDenied = false
        // The items whose change was denied, by vault, each named as this device held it before the change was undone.
        val deniedItems = LinkedHashMap<String, LinkedHashMap<String, String?>>()
        val iter = staged.entries.iterator()
        while (iter.hasNext()) {
            val (vaultId, entries) = iter.next()
            val (ripe, tooFresh) = entries.partition { freshestCompletedPullStart > it.stagedBefore }
            if (ripe.isEmpty()) continue
            val held = store.getHeld(vaultId)
            if (held != null) {
                store.atomically {
                    store.putHeld(HeldVault(held.vault, held.grant, held.items, held.reason, (held.parked + ripe.map { it.mutation }).distinctBy { it.mutationId }, held.expungeAt))
                    ripe.forEach { store.dequeue(it.mutation.mutationId) }
                }
            } else if (keys.access(vaultId)?.standing == VaultStanding.VERIFIED && store.takenAway(vaultId)) {
                // Denied while the server had taken the vault away with no verified reason (spec 03 §4, H10): held back
                // until now, and replayed now that it is back; a denial of the replay is judged as a replay's.
                store.atomically {
                    for (e in ripe) {
                        store.dequeue(e.mutation.mutationId)
                        store.enqueue(e.mutation)
                        replayedMutationIds[e.mutation.mutationId] = ItemNotice.WITHHELD
                    }
                    if (tooFresh.isEmpty()) store.setTakenAway(vaultId, false)
                }
            } else if (keys.access(vaultId)?.standing == VaultStanding.VERIFIED || store.vault(vaultId) == null) {
                val (replays, firstHand) = ripe.partition { it.wasReplay }
                for (e in replays) {
                    val at = vaultId to e.replayedFor!!
                    replayDeniedByVault[at] = (replayDeniedByVault[at] ?: 0) + 1
                }
                genuine += firstHand.size
                for (e in firstHand) {
                    kotlinx.atomicfu.locks.synchronized(refusalLock) { refusedForGood[e.mutation.itemId] = ItemFailure.Denied(1) }
                    if (e.mutation.mutationId == write?.mutationId) {
                        ownDenied = true
                    } else {
                        val named = deniedItems.getOrPut(vaultId) { LinkedHashMap() }
                        if (e.mutation.itemId !in named) named[e.mutation.itemId] = nameOfChange(e.mutation)
                    }
                }
                ripe.forEach { store.dequeue(it.mutation.mutationId) }
            } else {
                continue // the vault is here and not verified: no verdict yet
            }
            if (tooFresh.isEmpty()) {
                iter.remove()
            } else {
                entries.clear()
                entries.addAll(tooFresh)
            }
        }
        drainReplayDenied()
        for ((vaultId, items) in deniedItems) {
            notice(vaultId, nameOf(vaultId), ItemNotice.WRITE_DENIED, count = items.size, itemName = items.values.singleOrNull())
        }
        if (genuine > 0 && (write == null || ownDenied)) throw Stop(ItemFailure.Denied(genuine))
    }

    /**
     * The item's name as [m] would have left it (a put's own document), else as this device holds it from the server;
     * null where neither can be read. A staged row is no longer in the queue, so the overlay ([item]) does not show it.
     */
    private fun nameOfChange(m: Mutation): String? {
        val up = m.item
        val own = if (up == null || keys.access(m.vaultId) == null) null else runCatching {
            val row = SyncItem(m.itemId, m.vaultId, 0, 0, clock(), false, false, up.formatVersion, up.attachmentIds, up.blob)
            withKey(m.vaultId) { vk -> codec.open(vk, row).name }
        }.getOrNull()
        return own ?: runCatching { store.getItem(m.itemId)?.doc?.name }.getOrNull()
    }

    // ==== conflict copies (spec 03 §5, spec 02 §7.2 INV-CONFLICT) ====

    /**
     * Conflict copies derive from PERSISTED state, so a crash between the cursor advance and the copy buries nothing.
     * The copy's id is deterministic over (itemId, rev), so concurrent materializers converge. This path is the
     * fallback and the flag clearer; the correct copy is built by the pushing client from the displaced value.
     */
    private suspend fun materializeOutstandingConflicts() {
        val envelopes = store.envelopes()
        val known = envelopes.mapTo(HashSet()) { it.itemId }
        for (item in envelopes) {
            if (!item.conflict || item.deleted) continue
            // A reader must not materialize, and nothing is sealed under a vault that is not verified.
            if (keys.access(item.vaultId)?.writable != true) continue
            if (ItemHome.conflict(store.getItem(item.itemId)?.vaultId, item.vaultId, store.itemHome(item.itemId)) == ItemHome.Conflict.ABORT) {
                wrongVault.note(item.vaultId)
                continue
            }
            // BOTH mutations come from decrypt(flagged), sealed under flagged.vaultId.
            val doc = withKey(item.vaultId) { vk -> runCatching { codec.open(vk, item) }.getOrNull() } ?: continue
            val provenance = SealProvenance.Envelope(item.vaultId)
            val copyId = ConflictCopy.id(crypto, item.itemId, item.rev)
            try {
                val mutations = mutableListOf<Mutation>()
                // A row this device's own put brought back from a deletion displaced no version: its mark (an older
                // server's) is only cleared, and nothing is copied.
                if (copyId !in known && store.getItem(copyId) == null && "${item.itemId}|${item.rev}" !in broughtBack) {
                    mutations += putMutation(provenance, copyId, doc.copy(name = "${doc.name} (conflict ${isoDate(item.updatedAt)})"), 0)
                }
                mutations += putMutation(provenance, item.itemId, doc, item.rev) // clears the flag
                push(mutations)
            } catch (e: Stop) {
                // A seal this row's vault or home refuses is this row's verdict, never the sync's.
                if (e.why is ItemFailure.NotAllowed) wrongVault.note(item.vaultId) else throw e
            }
        }
    }

    /** `itemId|rev` of each item a put of this device brought back from a deletion ([noteBroughtBack]), in memory. */
    private val broughtBack = HashSet<String>()

    /**
     * [m] brought its item back from a deletion made elsewhere (the server answered it with the deletion's mark, at
     * [newItemRev]): said once, in one notice per vault that counts them and names the item when it is the only one.
     */
    private fun noteBroughtBack(m: Mutation, newItemRev: Long?) {
        if (!broughtBack.add("${m.itemId}|${newItemRev ?: "?"}")) return
        val prior = noticeList.firstOrNull { it.vaultId == m.vaultId && it.kind == ItemNotice.ITEM_BROUGHT_BACK }
        if (prior != null) noticeList.remove(prior)
        val count = (prior?.count ?: 0) + 1
        val name = if (count == 1) item(m.itemId)?.doc?.name else null
        noticeList.add(ItemNotice(codec.freshId(), m.vaultId, nameOf(m.vaultId), ItemNotice.ITEM_BROUGHT_BACK, count, itemName = name))
    }

    /** The conflict copy from the server-returned LOSING version; the flag is cleared on the reconcile pull. */
    private suspend fun materializeConflictFromServerItem(d: Displaced) {
        val losing = d.losing
        if (!TrustGrammar.isUuid(losing.itemId) || !TrustGrammar.isUuid(losing.vaultId)) return
        if (keys.access(losing.vaultId)?.writable != true) return
        // The displaced value must be the item this device wrote, in the vault it wrote it to and its home.
        if (ItemHome.serverItem(d.pushedVaultId, losing.vaultId, store.itemHome(losing.itemId)) == ItemHome.ServerItem.ABORT) {
            wrongVault.note(losing.vaultId)
            return
        }
        val losingDoc = withKey(losing.vaultId) { vk -> runCatching { codec.open(vk, losing) }.getOrNull() } ?: return
        val copyId = ConflictCopy.id(crypto, losing.itemId, d.winnerRev)
        if (store.getItem(copyId) != null) return
        try {
            push(listOf(putMutation(SealProvenance.Envelope(losing.vaultId), copyId, losingDoc.copy(name = "${losingDoc.name} (conflict ${isoDate(losing.updatedAt)})"), 0)))
        } catch (e: Stop) {
            if (e.why is ItemFailure.NotAllowed) wrongVault.note(losing.vaultId) else throw e
        }
    }

    // ==== save and delete ====

    /**
     * Create or update an item, then reconcile. A new item goes to [vaultId] (default: the personal vault). An edit
     * names the vault its editor opened on as [vaultId] (INV-EDIT); a home that differs now refuses the save instead of
     * re-targeting it. [uploads] are encrypted and uploaded first (spec 02 §6), then the item that references them.
     *
     * [draftItemId]: a retry of a failed NEW-item save reuses the id the first attempt minted, to which its uploaded
     * attachments are bound. [baseItemRev]: a save finished after a lock goes from the revision it was edited from, so
     * a change made since is kept as a conflict copy; such a put never folds the item's queued puts.
     */
    suspend fun save(
        itemId: String?,
        doc: ItemDoc,
        vaultId: String? = null,
        uploads: List<NewAttachment> = emptyList(),
        onProgress: ((done: Int, total: Int) -> Unit)? = null,
        draftItemId: String? = null,
        baseItemRev: Long? = null,
        /**
         * Told the moment this save's put is sealed and handed to the queue (before it is sent): a save that fails without
         * it never queued its change, which tells "not made" from "may or may not arrive" where the item's ids cannot (an
         * edit of an item that already had a change waiting, stopped by a halt before its own was queued).
         */
        onQueued: (() -> Unit)? = null,
    ): ItemResult<SavedItem> {
        // Whether the put was sealed and queued here: a lock before that keeps nothing of the change (LockedBeforeKept).
        var kept = false
        try {
            return saveKept(itemId, doc, vaultId, uploads, onProgress, draftItemId, baseItemRev) {
                kept = true
                onQueued?.invoke()
            }
        } catch (e: KeysGoneException) {
            if (kept || e is LockedBeforeKept) throw e
            throw LockedBeforeKept(0)
        }
    }

    private suspend fun saveKept(
        itemId: String?,
        doc: ItemDoc,
        vaultId: String?,
        uploads: List<NewAttachment>,
        onProgress: ((done: Int, total: Int) -> Unit)?,
        draftItemId: String?,
        baseItemRev: Long?,
        queued: () -> Unit,
    ): ItemResult<SavedItem> = guard {
        live()
        val existing = itemId?.let { store.getItem(it) }
        // An edit to an item that exists only as a queued, never-sent put is still the same new item.
        val queuedOnly = if (itemId != null && existing == null) item(itemId) else null
        // An edit to an item this device no longer holds must not teleport into another vault.
        if (itemId != null && existing == null && queuedOnly == null) refuse(ItemRefusal.ITEM_GONE)
        val provenance: SealProvenance = if (itemId != null) {
            val home = store.itemHome(itemId) ?: existing?.vaultId ?: queuedOnly?.vaultId
            when (ItemHome.edit(home, vaultId)) {
                ItemHome.Edit.UNBOUND -> refuse(ItemRefusal.EDIT_UNBOUND)
                ItemHome.Edit.CHANGED_VAULTS -> refuse(ItemRefusal.ITEM_CHANGED_VAULTS)
                ItemHome.Edit.OK -> SealProvenance.Editor(vaultId!!)
            }
        } else {
            SealProvenance.Chosen(vaultId ?: personalOrStop())
        }
        val target = provenance.vaultId
        requireWritable(target)
        val id = itemId ?: draftItemId ?: codec.freshId()
        if (!TrustGrammar.isUuid(id)) refuse(ItemRefusal.BAD_ID)
        if (uploads.isNotEmpty()) {
            var done = 0
            onProgress?.invoke(0, uploads.size)
            for (u in uploads) {
                live()
                val enc = Attachments.encrypt(crypto, Bytes.fromB64(u.ref.fileKey), u.data)
                uploadSealed(u.ref.id, id, target, enc.header + enc.ciphertext)
                onProgress?.invoke(++done, uploads.size)
            }
        }
        val outcome = syncMutex.withLock {
            // The uploads and the mutex are waits: a lock in them seals nothing.
            live()
            // Queue coalescing (spec 03 §5): the item's unsent puts fold into this one, which carries the OLDEST
            // dropped row's base rev under a fresh mutationId. The rows are dequeued only once the seal succeeded.
            val folded = if (baseItemRev != null) null else queuedPutsToFold(id)
            val m = putMutation(provenance, id, doc, folded?.base ?: baseItemRev ?: existing?.rev ?: 0)
            if (folded != null) dequeueFolded(folded)
            // Sealed; push queues it before its first wait.
            queued()
            sendOrQueue(m, folded) ?: reconcileAfterWrite(m)
        }
        SavedItem(id, outcome)
    }

    /**
     * Upload one attachment already encrypted under its own key. The id was minted once by the caller, so
     * `attachment_id_taken` can only mean an earlier attempt of the same save landed: that is success.
     */
    suspend fun uploadEncryptedAttachment(attachmentId: String, itemId: String, vaultId: String, sealed: ByteArray): ItemResult<Unit> = guard {
        live()
        requireWritable(vaultId)
        uploadSealed(attachmentId, itemId, vaultId, sealed)
    }

    private suspend fun uploadSealed(attachmentId: String, itemId: String, vaultId: String, sealed: ByteArray) {
        live()
        val r = transport.uploadAttachment(attachmentId, itemId, vaultId, sealed)
        if (r is WireResult.Refused && r.code == WireErrors.ATTACHMENT_ID_TAKEN) return
        r.orStop()
    }

    private class FoldedPuts(val base: Long, val rows: List<Mutation>) {
        val mutationIds: List<String> get() = rows.map { it.mutationId }
    }

    /** The item's unsent queued puts and the base rev the superseding put carries; null across a queued delete. */
    private fun queuedPutsToFold(itemId: String): FoldedPuts? {
        val rows = store.pending().filter { it.itemId == itemId }
        if (rows.isEmpty() || rows.any { it.op != MutationOp.PUT }) return null
        return FoldedPuts(rows.first().baseItemRev, rows)
    }

    private fun dequeueFolded(folded: FoldedPuts) {
        for (id in folded.mutationIds) {
            store.dequeue(id)
            pendingDocCache.remove(id)
        }
    }

    /**
     * Enqueue [m] and drain. No answer on a DURABLE cache means the row is safely queued and already shown:
     * [Written.QUEUED]. On a cache that dies with the session the row is dequeued and the failure reported, so
     * "queued" is never claimed over a queue that will not survive. Null when the write was sent.
     *
     * The same holds for a failure that is not a verdict on the row (a session the server ended, a rate limit, a server
     * fault): the drain leaves the row queued, and on a durable cache it stays there and goes at a later sync, so it is
     * answered as kept ([Written.KEPT_SESSION_ENDED], [Written.KEPT_TOO_MANY_REQUESTS], [Written.KEPT_SERVER_FAULT]),
     * never as failed. On a cache that dies with the session it is taken out too: the person was told the save failed, so it
     * must not land later out of sight, nor be counted as a change waiting to be sent, nor go at the next lock unsaid.
     * The earlier unsent puts of the item that [m] folded ([folded]) are put back as they were: the change that failed is
     * the person's latest one only, and never takes an earlier change still waiting down with it.
     */
    private suspend fun sendOrQueue(m: Mutation, folded: FoldedPuts? = null): Written? {
        try {
            push(listOf(m))
            // The drain ended at a halt before this write's batch was answered: it was not sent.
            if (halted && store.pending().any { it.mutationId == m.mutationId }) throw Stop(ItemFailure.Halted)
        } catch (e: Stop) {
            val queued = store.pending().any { it.mutationId == m.mutationId }
            if (queued && !store.durable) {
                store.dequeue(m.mutationId)
                pendingDocCache.remove(m.mutationId)
                folded?.rows?.forEach { store.enqueue(it) }
            } else if (queued) {
                // Kept in the durable queue, shown, and sent later: said as kept, with how it waits, never as failed.
                Written.keptFor(e.why)?.let { return it }
            }
            throw e
        }
        return null
    }

    /**
     * After a SENT write: the reconcile pull and the denial verdicts, then this mutation's own fate. A pull that got no
     * answer does not fail the save (the write is settled). A row the server rejected is reported with its reason. A
     * write the server applied answers as applied even where other changes are denied at this pull: those are undone
     * here and said by their own notice ([surfaceStagedDenials]); only a denial of [m] itself fails it.
     */
    private suspend fun reconcileAfterWrite(m: Mutation): Written {
        try {
            pull()
            surfaceStagedDenials(m)
        } catch (e: Stop) {
            // A halt that landed after the server answered (the copy closed for the policy's wipe, or a fork) stops only
            // the pull: the write itself is settled, and is never said as not made.
            if (e.why !is ItemFailure.Unreachable && e.why !is ItemFailure.Halted) throw e
        }
        rejectedMutationIds.remove(m.mutationId)?.let { reason ->
            throw Stop(ItemFailure.Refused(reason, if (reason == WireErrors.ITEM_ATTACHMENT_QUOTA || reason == WireErrors.BODY_TOO_LARGE) 413 else 400))
        }
        return Written.APPLIED
    }

    /** Delete an item (a tombstone, spec 02 §7), then reconcile; the same offline verdict as [save]. */
    suspend fun remove(itemId: String): ItemResult<Written> = guard {
        live()
        val existing = store.getItem(itemId)
        if (existing == null) {
            // A queued, never-sent new item: dropping its queued puts is the whole removal.
            if (item(itemId) != null) syncMutex.withLock { queuedPutsToFold(itemId)?.let { dequeueFolded(it) } }
            return@guard Written.APPLIED
        }
        requireWritable(existing.vaultId)
        syncMutex.withLock {
            // The item's unsent edits fold into the delete, as they fold into a later put (spec 03 §5): the delete goes
            // from the revision the oldest of them was made on. Sent ahead of it instead, the first edit would move the
            // item's revision past the delete's base and the server would keep the item over the delete.
            val folded = queuedPutsToFold(itemId)
            val m = Mutation(codec.freshId(), MutationOp.DELETE, itemId, existing.vaultId, folded?.base ?: existing.rev, null)
            if (folded != null) dequeueFolded(folded)
            sendOrQueue(m, folded) ?: reconcileAfterWrite(m)
        }
    }

    /**
     * Bulk import (spec 06): chunked pushes at the server's batch cap, one pull at the end. Each planned item's id
     * doubles as its mutationId, so re-running the same plan replays idempotently. [vaultId] must be the vault the
     * plan's projections came from; null is the personal vault.
     *
     * An import cut short follows the rule of a single save ([sendOrQueue]). On a DURABLE cache, a push that got no
     * answer, or that the server refused for now (the session's end, a rate limit, a server fault: [Written.keptFor]),
     * keeps the import: the rest of the plan is sealed into the queue unsent, and all of it goes at a later sync. On a
     * cache that dies with the session nothing of the import stays queued behind the failure: its rows still waiting are
     * taken out, so they are never sent later out of the person's sight, nor dropped unsaid at the next lock; a lock does
     * the same with what it finds waiting. Either way the result stays the failure, and [onStopped] hears what the import
     * came to ([ImportStopped]) before it is answered.
     */
    suspend fun importAll(
        items: List<CsvImport.PlannedItem>,
        onProgress: ((done: Int, total: Int) -> Unit)? = null,
        vaultId: String? = null,
        onStopped: ((ImportStopped) -> Unit)? = null,
    ): ItemResult<Unit> {
        // How many of [items] were sealed and queued here: a lock stops the rest, and says how many were kept.
        var kept = 0
        val ids = items.mapTo(HashSet()) { it.itemId }
        try {
            return guard {
                live()
                val target = vaultId ?: personalOrStop()
                syncMutex.withLock {
                    var done = 0
                    // The refusal for now that keeps the rest of the import on a durable cache, and how it waits.
                    var stopped: Stop? = null
                    var keptFor: Written? = null
                    for (chunk in items.chunked(SERVER_BATCH_MAX)) {
                        // A lock while the previous batch was on its way: nothing more is sealed.
                        live()
                        val batch = chunk.map { Mutation(it.itemId, MutationOp.PUT, it.itemId, target, 0, sealFor(SealProvenance.Chosen(target), it.itemId, it.doc)) }
                        // Sealed; push queues the batch before its first wait.
                        kept += batch.size
                        if (stopped != null) {
                            batch.forEach { store.enqueue(it) }
                            continue
                        }
                        try {
                            push(batch)
                        } catch (e: Stop) {
                            keptFor = if (store.durable) Written.keptFor(e.why) else null
                            if (keptFor == null) {
                                onStopped?.invoke(importStopped(ids, items.size, kept, null))
                                throw e
                            }
                            stopped = e
                            continue
                        }
                        done += chunk.size
                        onProgress?.invoke(done, items.size)
                    }
                    stopped?.let {
                        onStopped?.invoke(importStopped(ids, items.size, kept, keptFor))
                        throw it
                    }
                    // Every batch was answered: a final pull with no answer does not fail the import (the writes are
                    // settled, as a save's are; a later sync trues the list up).
                    try {
                        pull()
                    } catch (e: Stop) {
                        if (e.why !is ItemFailure.Unreachable) throw e
                    }
                    surfaceStagedDenials()
                }
            }
        } catch (e: KeysGoneException) {
            // What waits in a queue that dies with the session goes with the lock: it is said as not saved, never as kept.
            val left = kept - runCatching { takeOutOfMemoryQueue(ids) }.getOrDefault(0)
            if (left >= items.size || (e is LockedBeforeKept && left == kept)) throw e
            throw LockedBeforeKept(left)
        }
    }

    /**
     * What an import stopped after [sealed] of its [total] items came to: on a cache that dies with the session its rows
     * still waiting are taken out first ([takeOutOfMemoryQueue]); on a durable one they stay, kept as [keptFor] says.
     */
    private fun importStopped(ids: Set<String>, total: Int, sealed: Int, keptFor: Written?): ImportStopped {
        val taken = takeOutOfMemoryQueue(ids)
        val waiting = store.pending().count { it.mutationId in ids }
        return ImportStopped(sealed - taken - waiting, waiting, total - sealed + taken, if (waiting > 0) keptFor else null)
    }

    /** On a cache that dies with the session: the rows of [mutationIds] still waiting are taken out. How many. */
    private fun takeOutOfMemoryQueue(mutationIds: Set<String>): Int {
        if (store.durable) return 0
        val rows = store.pending().filter { it.mutationId in mutationIds }
        for (m in rows) {
            store.dequeue(m.mutationId)
            pendingDocCache.remove(m.mutationId)
        }
        return rows.size
    }

    // ==== attachments (spec 02 §6, spec 03 §9) ====

    /** Download and decrypt one attachment. Its body must be exactly as long as the ref says; any corruption is a failure. */
    suspend fun downloadAttachment(ref: AttachmentRef): ItemResult<ByteArray> = guard { fetchAttachment(ref) }

    private suspend fun fetchAttachment(ref: AttachmentRef): ByteArray {
        live()
        // The file key is the item document's, which a writer of a shared vault chooses: a key that is not one (not
        // base64url, the wrong length, all zeros) is damaged content, refused before anything is fetched or decrypted.
        val fileKey = ItemCodec.fileKeyOf(ref) ?: throw Stop(ItemFailure.Corrupt("content"))
        try {
            val expected = runCatching { Attachments.wireLength(ref.size) }.getOrElse { throw Stop(ItemFailure.Corrupt("size")) }
            val r = transport.downloadAttachment(ref.id, expected)
            if (r is WireResult.Refused && r.code == ItemTransport.ATTACHMENT_SIZE_MISMATCH) throw Stop(ItemFailure.Corrupt("size"))
            val bytes = r.orStop()
            if (bytes.size.toLong() != expected) throw Stop(ItemFailure.Corrupt("size"))
            // The download was a wait: a lock in it opens nothing (spec 01 §8 rule 4, a file's open sits behind this check).
            live()
            return try {
                Attachments.decrypt(crypto, fileKey, bytes.copyOfRange(0, Attachments.HEADER_BYTES), bytes.copyOfRange(Attachments.HEADER_BYTES, bytes.size))
            } catch (e: KeysGoneException) {
                // A lock is the lock's own result, never damage (spec 01 §8 rule 5).
                throw e
            } catch (e: Exception) {
                throw Stop(ItemFailure.Corrupt("content"))
            }
        } finally {
            fileKey.fill(0)
        }
    }

    // ==== item history and trash (spec 03 §4, §5.1) ====

    /** This item's archived versions (the server keeps the last 10), decrypted, newest first; unreadable ones are dropped. */
    suspend fun itemVersions(itemId: String, vaultId: String): ItemResult<List<DecryptedItemVersion>> = guard {
        live()
        val versions = transport.versions(itemId).orStop()
        withKey(vaultId) { vk ->
            if (keys.access(vaultId) == null) return@withKey emptyList()
            versions.mapNotNull { v -> runCatching { DecryptedItemVersion(v.rev, v.archivedAt, codec.openVersion(vk, vaultId, itemId, v)) }.getOrNull() }
        } ?: refuse(ItemRefusal.VAULT_NOT_OPEN)
    }

    /**
     * The document to put when an archived [version] of [itemId] is restored over the live item: every attachment ref
     * the live item no longer carries is stripped, since its blob is gone and the put would be `rejected`.
     */
    fun versionDocForRestore(itemId: String, version: ItemDoc): ItemDoc {
        val live = item(itemId)?.doc ?: return version
        val liveIds = live.attachments.mapTo(HashSet()) { it.id }
        return version.copy(attachments = version.attachments.filter { it.id in liveIds })
    }

    /**
     * The account's tombstoned items, newest deletion first. A row this device held is opened from the envelope it kept
     * when the tombstone was applied ([ItemStore.keepTrashed]), with no call. Of the rows it never held, the newest
     * [TRASH_FETCH_MAX] not yet read in this session are named from their last archived version (one call each; what
     * was read stays in memory for the session, so each opening reads further); the rest come back with
     * [DeletedItemView.notRead] and no document, and a restore reads one when it needs it ([deletedItemDoc]). A whole
     * read also prunes the kept envelopes of items no longer in the trash.
     */
    suspend fun deletedItems(): ItemResult<List<DeletedItemView>> = guard {
        live()
        val rows = trashRows()
        val listed = rows.mapTo(HashSet()) { it.itemId }
        // Kept envelopes of items no longer in the trash (restored, purged, aged out), in a vault this device reads.
        store.forgetTrashed(store.trashedIds().filter { it !in listed && store.trashed(it)?.vaultId?.let { v -> keys.access(v) } != null })
        var fetched = 0
        rows.map { d ->
            val kept = store.trashed(d.itemId)?.takeIf { it.vaultId == d.vaultId }
            val fromKept = kept?.let { row -> withKey(d.vaultId) { vk -> runCatching { codec.open(vk, row) }.getOrNull() } }
            when {
                fromKept != null -> DeletedItemView(d.itemId, d.vaultId, d.deletedAt, fromKept)
                d.itemId in trashVersions -> DeletedItemView(d.itemId, d.vaultId, d.deletedAt, openTrashVersion(d))
                fetched < TRASH_FETCH_MAX -> {
                    fetched++
                    readTrashVersion(d)
                    DeletedItemView(d.itemId, d.vaultId, d.deletedAt, openTrashVersion(d))
                }
                else -> DeletedItemView(d.itemId, d.vaultId, d.deletedAt, null, notRead = true)
            }
        }
    }

    /**
     * The document of one tombstoned item for a restore, from its kept envelope or its last archived version (one call
     * when neither is held yet); null when none can be read on this device.
     */
    suspend fun deletedItemDoc(itemId: String, vaultId: String, deletedAt: Long): ItemResult<ItemDoc?> = guard {
        live()
        val d = DeletedItem(itemId, vaultId, deletedAt)
        store.trashed(itemId)?.takeIf { it.vaultId == vaultId }?.let { row ->
            withKey(vaultId) { vk -> runCatching { codec.open(vk, row) }.getOrNull() }
        }?.let { return@guard it }
        if (itemId !in trashVersions) readTrashVersion(d)
        openTrashVersion(d)
    }

    /**
     * The newest archived version of each tombstoned item this session read, as served (ciphertext; null: the server
     * answered no version). A failed read is not recorded, so the next opening tries again.
     */
    private val trashVersions = HashMap<String, ItemVersion?>()

    private suspend fun readTrashVersion(d: DeletedItem) {
        val r = transport.versions(d.itemId)
        live()
        if (r is WireResult.Ok) trashVersions[d.itemId] = r.value.firstOrNull()
    }

    private fun openTrashVersion(d: DeletedItem): ItemDoc? {
        val newest = trashVersions[d.itemId] ?: return null
        if (keys.access(d.vaultId) == null) return null
        return withKey(d.vaultId) { vk -> runCatching { codec.openVersion(vk, d.vaultId, d.itemId, newest) }.getOrNull() }
    }

    /**
     * Every page of the deleted-items list (spec 03 §5.1): while a page is full
     * ([ItemTransport.TRASH_PAGE_ROWS]), the next one is asked for after its last row (`<deletedAt>:<itemId>`). One entry
     * per item, with its newest deletion time, newest first; rows whose ids are not UUIDs are left out, and so are rows
     * of a vault this account may not read ([VaultKeySource.access] null: another account's rows, or a vault this
     * device has not adopted yet, which the next read after a sync shows). The list exists only once its last page has
     * arrived: a page refused or unanswered fails the whole read, and so does (as [ItemTransport.TRASH_INCOMPLETE]):
     * - a page of more than [ItemTransport.TRASH_PAGE_ROWS] rows;
     * - a page whose rows are not strictly descending in `(deletedAt, itemId)`, or whose first row is not strictly after
     *   the cursor's position (the check against a cursor that loops: a page served again, or one that goes back up);
     * - a full page whose last row names no next row (the cursor is built only from a non-negative time and a uuid);
     * - one page more than [TRASH_MAX_PAGES] (a server that never ends its list).
     * Unknown is never a shorter list.
     */
    private suspend fun trashRows(): List<DeletedItem> {
        val newest = LinkedHashMap<String, DeletedItem>()
        var after: String? = null
        // The position the next row must be strictly below: the cursor's row (null before the first page).
        var bound: DeletedItem? = null
        var pages = 0
        while (true) {
            if (++pages > TRASH_MAX_PAGES) throw Stop(ItemFailure.Corrupt(ItemTransport.TRASH_INCOMPLETE))
            val page = transport.deletedItems(after).orStop()
            live()
            if (page.size > ItemTransport.TRASH_PAGE_ROWS) throw Stop(ItemFailure.Corrupt(ItemTransport.TRASH_INCOMPLETE))
            for (d in page) {
                val above = bound
                if (above != null && !trashBelow(d, above)) throw Stop(ItemFailure.Corrupt(ItemTransport.TRASH_INCOMPLETE))
                bound = d
                if (!TrustGrammar.isUuid(d.itemId) || !TrustGrammar.isUuid(d.vaultId) || keys.access(d.vaultId) == null) continue
                val held = newest[d.itemId]
                if (held == null || d.deletedAt > held.deletedAt) newest[d.itemId] = d
            }
            if (page.size < ItemTransport.TRASH_PAGE_ROWS) break
            val last = page.last()
            if (!TrustGrammar.isUuid(last.itemId) || last.deletedAt < 0) throw Stop(ItemFailure.Corrupt(ItemTransport.TRASH_INCOMPLETE))
            after = "${last.deletedAt}:${last.itemId}"
        }
        return newest.values.sortedWith(compareByDescending<DeletedItem> { it.deletedAt }.thenByDescending { it.itemId })
    }

    /** [d] is strictly after [above] in the list's order: `(deletedAt, itemId)` descending, ids compared as the server's text. */
    private fun trashBelow(d: DeletedItem, above: DeletedItem): Boolean =
        d.deletedAt < above.deletedAt || (d.deletedAt == above.deletedAt && d.itemId < above.itemId)

    /**
     * Restore a tombstoned item with [doc], re-sealed under its vault, through the dedicated route (no conflict copy),
     * then sync. Attachment refs are dropped: a deleted item's blobs went with its tombstone.
     */
    suspend fun restoreDeleted(itemId: String, vaultId: String, doc: ItemDoc): ItemResult<Unit> = guard {
        live()
        transport.restore(itemId, sealFor(SealProvenance.Envelope(vaultId), itemId, doc.copy(attachments = emptyList()))).orStop()
        // Live again: what was kept for its trash row goes (a later tombstone keeps the envelope then held).
        forgetTrashed(itemId)
        syncMutex.withLock { cycle() }
        Unit
    }

    /**
     * Keep [done], a restore or a delete for good the server answered as done, for the next whole read of the trash to
     * check. It is kept in the account's cache, so a lock or a restart between the action and that read keeps it.
     */
    fun recordTrashAction(done: TrashActionDone) = store.recordTrashDone(done)

    /** What [recordTrashAction] kept, oldest first. */
    fun trashActionsDone(): List<TrashActionDone> = store.trashDone()

    /** Forget every kept trash action: a whole read of the trash has checked them. */
    fun clearTrashActionsDone() = store.clearTrashDone()

    private fun forgetTrashed(itemId: String) {
        store.forgetTrashed(listOf(itemId))
        trashVersions.remove(itemId)
    }

    /** "Delete forever": hard-delete a tombstoned item and its versions. [vaultId] is the vault its tombstone names. */
    suspend fun purgeDeleted(itemId: String, vaultId: String): ItemResult<Unit> = guard {
        live()
        requireWritable(vaultId)
        transport.purge(itemId).orStop()
        forgetTrashed(itemId)
        Unit
    }

    /**
     * The owner's "Recently deleted" shared vaults (spec 03 §11.2), newest deletion first. The server's list is a
     * hint: a row whose id is not a UUID, or whose dates are not a grace (`purgeAt` before `deletedAt`), is dropped; a
     * row whose grace end the server did not serve (`purgeAt` empty, read as 0) is kept with no day only where the vault's
     * own mark says it is deleted (this device's verified log ends in its owner's `delete`), and dropped elsewhere as a
     * purge before the deletion; a name is read only with the key this device's trust engine still offers
     * ([VaultKeySource.keyFor]), never from the served wrap; [DeletedVault.verified] says whether this device's log shows
     * the owner's `delete`.
     */
    suspend fun deletedVaults(): ItemResult<List<DeletedVault>> = guard {
        live()
        transport.deletedVaults().orStop()
            .filter {
                TrustGrammar.isUuid(it.vaultId) && it.vaultId != keys.personalVaultId &&
                    (it.purgeAt >= it.deletedAt || (it.purgeAt == 0L && keys.departure(it.vaultId) == VaultDeparture.DELETED))
            }
            .distinctBy { it.vaultId }
            .map { d ->
                val name = withKey(d.vaultId) { vk -> runCatching { codec.vaultName(vk, d.vaultId, d.metaBlob) }.getOrNull() }
                DeletedVault(d.vaultId, name, d.deletedAt, d.purgeAt, d.deleteId, keys.departure(d.vaultId) == VaultDeparture.DELETED)
            }
            .sortedByDescending { it.deletedAt }
    }

    // ==== the breach range relay (spec 03 §8) ====

    /**
     * The breach range for [prefix], the first 5 hex characters of an item password's SHA-1, through the server's
     * k-anonymity relay; matched on this device ([io.silencelen.andvari.core.crypto.Hibp.countInRange]). Anything but
     * five hex characters is refused before anything is sent, and nothing goes out under a stopped origin.
     */
    suspend fun breachRange(prefix: String): ItemResult<String> = guard {
        live()
        if (prefix.length != 5 || prefix.any { it !in '0'..'9' && it !in 'A'..'F' && it !in 'a'..'f' }) refuse(ItemRefusal.BAD_ID)
        transport.hibpRange(prefix.uppercase()).orStop()
    }

    // ==== vault name (spec 03 §11.3) ====

    /** Rename a vault: its metadata re-sealed under its key with `metaV` + 1. A `stale_meta` resyncs and retries once. */
    suspend fun renameVault(vaultId: String, newName: String): ItemResult<Unit> = guard {
        live()
        requireWritable(vaultId)
        var retried = false
        while (true) {
            live()
            val row = store.vault(vaultId) ?: refuse(ItemRefusal.VAULT_NOT_OPEN)
            val blob = withKey(vaultId) { codec.renamedMeta(it, vaultId, row.metaBlob, newName) } ?: refuse(ItemRefusal.VAULT_NOT_OPEN)
            val r = transport.putVaultMeta(vaultId, blob, row.rev)
            if (r is WireResult.Refused && r.code == WireErrors.STALE_META && !retried) {
                retried = true
                syncMutex.withLock { cycle() }
                continue
            }
            r.orStop()
            break
        }
        reconcile()
    }

    /**
     * The reconcile sync after an operation that already committed on the server. Only a denial of some other write of
     * this device is reported; anything else is left to the next sync, which meets it again.
     */
    private suspend fun reconcile() {
        try {
            syncMutex.withLock { cycle() }
        } catch (e: Stop) {
            if (e.why is ItemFailure.Denied) throw e
        }
    }

    // ==== move and copy between vaults ====

    /**
     * Plan a move or copy of [itemId] into [targetVaultId]: a fresh item id and, per attachment, a fresh id and a
     * fresh file key, minted ONCE. A retry runs the same plan.
     */
    fun planMove(itemId: String, targetVaultId: String, deleteSource: Boolean): ItemResult<MovePlan> = guard {
        val src = store.getItem(itemId) ?: refuse(ItemRefusal.ITEM_GONE)
        planFor(src, targetVaultId, deleteSource)
    }

    private fun planFor(src: VaultItem, targetVaultId: String, deleteSource: Boolean, targetItemId: String = codec.freshId()) = MovePlan(
        codec.freshId(), src.itemId, src.vaultId, src.rev, targetVaultId, targetItemId, deleteSource,
        src.doc.attachments.map { MovedAttachment(it.id, codec.freshId(), Bytes.toB64(codec.freshFileKey()), it.name, it.size) },
    )

    /**
     * The copy leg of [plan] from [src]: attachments re-encrypted under the plan's fresh keys and uploaded, then the
     * item pushed directly (never queued) and a POSITIVE `applied` or `conflict` required. With [skipUnreadableFiles]
     * a file the server refuses to hand over is left out of the copy instead of failing it. Answers how many were left
     * out.
     */
    private suspend fun copyLeg(src: VaultItem, plan: MovePlan, onProgress: ((done: Int, total: Int) -> Unit)?, skipUnreadableFiles: Boolean): Int {
        var newDoc = src.doc
        var leftOut = 0
        if (plan.attachments.isNotEmpty()) {
            val refs = ArrayList<AttachmentRef>(plan.attachments.size)
            var done = 0
            onProgress?.invoke(0, plan.attachments.size)
            for (a in plan.attachments) {
                val srcRef = src.doc.attachments.firstOrNull { it.id == a.oldId } ?: refuse(ItemRefusal.ITEM_CHANGED)
                val plain = try {
                    fetchAttachment(srcRef)
                } catch (e: Stop) {
                    if (!skipUnreadableFiles || e.why !is ItemFailure.Refused) throw e
                    leftOut++
                    onProgress?.invoke(++done, plan.attachments.size)
                    continue
                }
                val enc = Attachments.encrypt(crypto, Bytes.fromB64(a.newFileKey), plain)
                plain.fill(0)
                uploadSealed(a.newId, plan.targetItemId, plan.targetVaultId, enc.header + enc.ciphertext)
                refs.add(AttachmentRef(a.newId, a.name, a.size, a.newFileKey))
                onProgress?.invoke(++done, plan.attachments.size)
            }
            newDoc = newDoc.copy(attachments = refs)
        }
        // The destination the person chose; the fresh id takes it as its home. The downloads were waits: a lock in them
        // seals and sends nothing.
        live()
        val upload = sealFor(SealProvenance.Chosen(plan.targetVaultId), plan.targetItemId, newDoc)
        val copy = transport.push(listOf(Mutation(codec.derivedId("gesture|${plan.planId}|copy"), MutationOp.PUT, plan.targetItemId, plan.targetVaultId, 0, upload)))
            .orStop().results.firstOrNull()
        if (copy?.status == MutationStatus.DENIED) refuse(ItemRefusal.COPY_DENIED)
        // Only `applied`, or `conflict` on a retry (our copy won), is a durable copy.
        if (copy?.status != MutationStatus.APPLIED && copy?.status != MutationStatus.CONFLICT) refuse(ItemRefusal.COPY_UNCONFIRMED)
        val now = clock()
        val row = SyncItem(plan.targetItemId, plan.targetVaultId, copy.newItemRev ?: 1, now, now, false, false, upload.formatVersion, upload.attachmentIds, upload.blob)
        store.upsertItem(row, VaultItem(plan.targetItemId, plan.targetVaultId, row.rev, now, ItemCodec.stamped(newDoc, keys.logHead(plan.targetVaultId))))
        return leftOut
    }

    /**
     * Copy the items of a vault in the holding area into the personal vault (spec 02 §10.6: a held copy "can still be
     * copied out" for 30 days), while the trust engine still offers the vault's key. Copy legs only, each under a fresh
     * item id ([personalCopyPlan]): a retry after a failure reuses the plan of a copy not yet confirmed, and a run after
     * a lock or a restart copies everything again. A file the server no longer hands over is left out of its copy and
     * counted, never silently.
     */
    suspend fun rescueHeldToPersonal(vaultId: String, onProgress: ((done: Int, total: Int) -> Unit)? = null): ItemResult<HeldRescue> = guard {
        live()
        val personal = personalOrStop()
        if (store.getHeld(vaultId) == null) refuse(ItemRefusal.VAULT_NOT_OPEN)
        if (keys.withKey(vaultId) { true } == null) refuse(ItemRefusal.VAULT_NOT_OPEN)
        requireWritable(personal)
        val sources = heldItems(vaultId)
        var copied = 0
        var leftOut = 0
        for (src in sources) {
            val key = "held|$vaultId|${src.itemId}|$personal"
            leftOut += copyLeg(src, personalCopyPlan(key, src, personal) { planFor(src, personal, deleteSource = false) }, null, skipUnreadableFiles = true)
            // Confirmed: a later copy of this vault is a new copy, never a replay of this one.
            bulkPlans.remove(key)
            copied++
            onProgress?.invoke(copied, sources.size)
        }
        reconcile()
        HeldRescue(copied, leftOut)
    }

    /**
     * The plan that copies [src] into the personal vault when a whole vault is copied there ([rescueToPersonal],
     * [rescueHeldToPersonal]): the one remembered under [key] while its copy is not confirmed and the source is at the same
     * rev (a retry then sends the same mutation, which the server answers once), else a fresh one ([fresh]) under a fresh
     * item id. A plan is forgotten once its copy is confirmed: copying the vault again makes new copies, and never replays a
     * copy the person may have deleted since (the server would answer the replay as applied and store nothing). Plans live
     * in this engine's memory only: a run after a lock or a restart copies everything again.
     */
    private inline fun personalCopyPlan(key: String, src: VaultItem, target: String, fresh: () -> MovePlan): MovePlan {
        bulkPlans[key]?.takeIf { it.sourceRev == src.rev && it.targetVaultId == target }?.let { return it }
        return fresh().also { bulkPlans[key] = it }
    }

    /**
     * The items of [fromVaultId] this device holds, by id: the held copy when the vault is in the holding area (while
     * the trust engine still offers its key), else the rows it shows of a vault still open here.
     */
    private fun heldSources(fromVaultId: String): Map<String, HeldSource> {
        val held = store.getHeld(fromVaultId)
        val base: List<VaultItem>
        val waiting: List<Mutation>
        if (held != null) {
            if (keys.withKey(fromVaultId) { true } == null) refuse(ItemRefusal.VAULT_NOT_OPEN)
            base = heldItems(fromVaultId)
            waiting = held.parked
        } else {
            base = store.allItems().filter { it.vaultId == fromVaultId }
            waiting = store.pending()
        }
        // A change this device sealed that never reached the server (queued, or parked with the held copy) is the
        // newest content of its item: it is what is copied, so it is not lost with the vault. The last one counts.
        val last = LinkedHashMap<String, Mutation>()
        for (m in waiting) if (m.vaultId == fromVaultId && (m.op == MutationOp.DELETE || (m.op == MutationOp.PUT && m.item != null))) last[m.itemId] = m
        val out = LinkedHashMap<String, HeldSource>()
        for (src in base) out[src.itemId] = HeldSource(src, null)
        for ((itemId, m) in last) {
            val prior = out[itemId]?.item
            if (m.op == MutationOp.DELETE) {
                // The person deleted it here: the copy carries the deletion, never the item. A deletion made on an
                // older revision than this device holds is one the server would have refused (someone changed the item
                // since), so the item as it is now is copied, as the server keeps it.
                if (prior != null && m.baseItemRev >= prior.rev) out[itemId] = HeldSource(prior, m.mutationId, deleted = true)
                continue
            }
            val doc = openWaiting(m, prior?.rev ?: 0) ?: continue
            out[itemId] = HeldSource(VaultItem(itemId, fromVaultId, prior?.rev ?: 0, prior?.updatedAt ?: 0, doc), m.mutationId)
        }
        return out
    }

    /**
     * One item [bringHeldInto] copies: [item] as this device holds it, and the change still waiting that it carries;
     * [deleted] when that change is the item's deletion, which the copy carries instead of the item.
     */
    private class HeldSource(val item: VaultItem, val waiting: String?, val deleted: Boolean = false)

    /** The document a waiting put [m] seals, opened under its vault's key; null when it does not open. A lock is thrown. */
    private fun openWaiting(m: Mutation, rev: Long): ItemDoc? {
        val up = m.item ?: return null
        val row = SyncItem(m.itemId, m.vaultId, rev, 0, 0, false, false, up.formatVersion, up.attachmentIds, up.blob)
        return withKey(m.vaultId) { vk ->
            try {
                codec.open(vk, row)
            } catch (e: KeysGoneException) {
                throw e
            } catch (e: Exception) {
                null
            }
        }
    }

    /**
     * The items of [vaultId] with a change this device sealed that has not reached the server: queued (a vault closed
     * for writing holds them back), or parked with the held copy once the vault left. [bringHeldInto] carries a waiting
     * put as the item's newest content, and a waiting delete as the item's deletion ([waitingDeletions]).
     */
    fun waitingChanges(vaultId: String): Set<String> =
        (store.getHeld(vaultId)?.parked ?: store.pending()).filter { it.vaultId == vaultId }.mapTo(LinkedHashSet()) { it.itemId }

    /**
     * The items of [vaultId] whose newest change this device sealed, still waiting (see [waitingChanges]), is their
     * deletion, made on the revision this device holds: [bringHeldInto] copies none of them, and deletes the earlier
     * copy a pick names ([HeldDeleted]). An item deleted on an older revision than this device holds is not one of
     * them: the server would refuse that deletion, and the item as it is now is copied. Empty when nothing can be read.
     */
    fun waitingDeletions(vaultId: String): Set<String> =
        (guard { heldSources(vaultId) } as? ItemResult.Ok)?.value?.values?.filter { it.deleted }?.mapTo(LinkedHashSet()) { it.item.itemId } ?: emptySet()

    /**
     * The id the copy of [src] (of [fromVaultId], at its rev, carrying the waiting change [waiting]) takes in
     * [targetVaultId]. It is derived, not drawn, so a second run, after a restart too, finds the copy the first one
     * made instead of making another; a newer rev, or a change waiting since, is a new copy.
     */
    private fun heldCopyId(fromVaultId: String, src: HeldSource, targetVaultId: String): String =
        codec.derivedId("held-copy|$fromVaultId|${src.item.itemId}|${src.item.rev}|$targetVaultId" + (src.waiting?.let { "|$it" } ?: ""))

    /**
     * The documents of [picks] that [bringHeldInto] would still copy into [targetVaultId] (those an earlier run has not
     * made yet), for the check before a large copy ([copySize]). Empty when nothing is left to copy, or nothing can be.
     */
    fun heldDocsToBring(fromVaultId: String, targetVaultId: String, picks: List<HeldPick>): List<ItemDoc> {
        val sources = (guard { heldSources(fromVaultId) } as? ItemResult.Ok)?.value ?: return emptyList()
        return picks.distinctBy { it.itemId }.mapNotNull { p ->
            val src = sources[p.itemId]?.takeIf { !it.deleted } ?: return@mapNotNull null
            val madeId = heldCopyId(fromVaultId, src, targetVaultId)
            src.item.doc.takeIf { store.getItem(madeId)?.vaultId != targetVaultId && !copyDeletedThere(madeId, targetVaultId) }
        }
    }

    /**
     * Bring [picks], items this device holds of [fromVaultId] (a vault deleted behind a move's back, in the holding
     * area; or one still open here), each with its files, into [targetVaultId], a vault this account may write. Copy
     * legs only: nothing of [fromVaultId] changes. Each file is re-encrypted under a fresh key; one the server no longer
     * hands over is left out of its copy and counted ([HeldCopied.filesLeftOut]), never silently.
     *
     * Every pick is checked before anything is sent: an item this device does not hold is [ItemRefusal.ITEM_GONE], an
     * earlier copy named in another vault than [targetVaultId] is [ItemRefusal.ITEM_CHANGED_VAULTS] (nothing outside the
     * target is ever deleted here). A pick's earlier copy is deleted only after its new copy is confirmed, so the item is
     * never in neither, and only at the revision the pick names ([HeldPick.replacesAtRev]): an earlier copy changed in
     * the target since (by anyone, or by this device, sent or still waiting), or one a pick names no revision for, is kept
     * live and said so ([HeldCopied.earlierKept], [HeldCopied.keptBecause]); the new copy then stands beside it.
     *
     * What is copied of an item is the newest this device holds: a change it sealed that never reached the server
     * (queued while [fromVaultId] was closed for writing, or parked with the held copy) is carried ([waitingChanges]).
     * When that change is the item's deletion ([waitingDeletions]), the person deleted it: no copy is made, and the
     * earlier copy the pick names is deleted from the target as a replaced one is (its envelope kept, so it is in the
     * target's trash; kept when it changed there since the revision the pick names, when no revision is named, or when
     * its deletion is denied). It is said to [onDeleted], and is
     * not in the answer, which lists the copies.
     *
     * Safe to run twice: a copy's id is derived from the held item and its rev ([heldCopyId]), so a copy found made is
     * not made again, and its earlier copy, already gone, is not deleted again. A copy found deleted in the target since
     * (this device saw it go) is not made again either: it is answered with [HeldCopied.madeRev] null, and an earlier copy
     * its pick names is kept. A confirmed copy's plan is forgotten, so it is never replayed. The caller syncs first (the check
     * before a large copy does), so a copy whose answer a restart lost is found too. A lock during a file's copy, or
     * between two picks, seals and sends nothing more (the lock's own exception): the pick in hand is not made at all,
     * its earlier copy stays, and [onMade] has said every pick made before it.
     */
    suspend fun bringHeldInto(
        fromVaultId: String,
        targetVaultId: String,
        picks: List<HeldPick>,
        onMade: ((HeldCopied) -> Unit)? = null,
        onProgress: ((done: Int, total: Int) -> Unit)? = null,
        onDeleted: ((HeldDeleted) -> Unit)? = null,
    ): ItemResult<List<HeldCopied>> = guard {
        live()
        if (fromVaultId == targetVaultId) refuse(ItemRefusal.VAULT_READ_ONLY)
        requireWritable(targetVaultId)
        val sources = heldSources(fromVaultId)
        val chosen = picks.distinctBy { it.itemId }.map { p ->
            val src = sources[p.itemId] ?: refuse(ItemRefusal.ITEM_GONE)
            // Where the named earlier copy lives: its row, or the home its first seal recorded (a write still queued).
            val earlierHome = p.replaces?.let { store.getItem(it)?.vaultId ?: store.itemHome(it) }
            if (earlierHome != null && earlierHome != targetVaultId) refuse(ItemRefusal.ITEM_CHANGED_VAULTS)
            p to src
        }
        val made = ArrayList<HeldCopied>(chosen.size)
        var done = 0
        for ((p, held) in chosen) {
            live()
            val src = held.item
            val madeId = heldCopyId(fromVaultId, held, targetVaultId)
            if (held.deleted) {
                // Nothing is copied of an item the person deleted; the earlier copy goes the way a replaced one goes.
                val keptBecause = p.replaces?.let { dropEarlierCopy(it, targetVaultId, madeId, p.replacesAtRev) }
                onDeleted?.invoke(HeldDeleted(src.itemId, src.rev, p.replaces, keptBecause != null, keptBecause))
                onProgress?.invoke(++done, chosen.size)
                continue
            }
            val found = store.getItem(madeId)?.takeIf { it.vaultId == targetVaultId }
            val deletedThere = found == null && copyDeletedThere(madeId, targetVaultId)
            val leftOut = if (found != null) {
                (src.doc.attachments.size - found.doc.attachments.size).coerceAtLeast(0)
            } else if (deletedThere) {
                // An earlier run made this copy and it was deleted in the target since (this device saw it go): the
                // deletion is the answer, and the copy is not made again. A put over the deleted row would bring it back
                // as a conflict, beside a conflict copy of the version that was deleted: the item twice.
                0
            } else {
                val plan = bulkPlans.getOrPut("held-copy|$madeId") { planFor(src, targetVaultId, deleteSource = false, targetItemId = madeId) }
                copyLeg(src, plan, null, skipUnreadableFiles = true).also {
                    // Confirmed: a later run finds this copy by its id, and never replays this plan over a copy the
                    // person deleted since (the server's journal would answer the replay as applied and store nothing,
                    // and this device would show a copy the server holds as deleted).
                    bulkPlans.remove("held-copy|$madeId")
                }
            }
            // Never the earlier copy for one that is not there: the item would be in neither.
            val keptBecause = p.replaces?.takeIf { it != madeId }?.let {
                if (deletedThere && store.getItem(it) != null) HeldDeleted.KEPT_CHANGED else dropEarlierCopy(it, targetVaultId, madeId, p.replacesAtRev)
            }
            val one = HeldCopied(src.itemId, src.rev, madeId, leftOut, keptBecause != null, keptBecause, store.getItem(madeId)?.rev, deletedThere)
            made += one
            onMade?.invoke(one)
            onProgress?.invoke(++done, chosen.size)
        }
        reconcile()
        made
    }

    /**
     * Delete [earlierId], the copy in [targetVaultId] that [madeId] now replaces, only at [atRev], the revision the pick
     * named ([HeldPick.replacesAtRev]): only while this device holds it at exactly that revision with no change of its own
     * waiting for it (queued, or refused and not yet said), and the deletion is pushed directly at that revision, so a
     * server that holds a newer one answers a conflict and deletes nothing. Its envelope is kept for the trash. Why it was
     * kept on purpose ([HeldDeleted.keptBecause]), or null when it went: [HeldDeleted.KEPT_NO_REVISION] when no revision
     * was named (nothing is deleted without one); [HeldDeleted.KEPT_CHANGED] when it changed in the target since (here or
     * elsewhere, seen by a sync or answered by the server as a conflict: someone's change is never deleted for a copy) or
     * is no longer in the target; [HeldDeleted.KEPT_REFUSED] when its deletion was denied or rejected. An answer with no
     * verdict, or none, stops the run; the copy is made and the next run finds it and asks again. An earlier copy no
     * longer here is gone already.
     */
    private suspend fun dropEarlierCopy(earlierId: String, targetVaultId: String, madeId: String, atRev: Long?): String? {
        val earlier = store.getItem(earlierId) ?: return null
        if (earlier.vaultId != targetVaultId) return HeldDeleted.KEPT_CHANGED
        if (atRev == null) return HeldDeleted.KEPT_NO_REVISION
        if (earlier.rev != atRev || changeWaitingHere(earlierId)) return HeldDeleted.KEPT_CHANGED
        live()
        val del = transport.push(listOf(Mutation(codec.derivedId("held-copy|$madeId|replaces|$earlierId|at|$atRev"), MutationOp.DELETE, earlierId, targetVaultId, atRev, null)))
            .orStop().results.firstOrNull()
        return when (del?.status) {
            MutationStatus.APPLIED -> {
                deleteKeepingEnvelope(earlierId)
                null
            }
            MutationStatus.CONFLICT -> HeldDeleted.KEPT_CHANGED
            MutationStatus.DENIED, MutationStatus.REJECTED -> HeldDeleted.KEPT_REFUSED
            // No verdict: the run stops here; the next one finds this copy made and asks again.
            else -> refuse(ItemRefusal.COPY_UNCONFIRMED)
        }
    }

    /**
     * Whether the copy [copyId] an earlier run made in [targetVaultId] was deleted there since, as this device saw it: its
     * envelope is in the trash this device keeps. Another device that never saw it go cannot tell.
     */
    private fun copyDeletedThere(copyId: String, targetVaultId: String): Boolean = store.trashed(copyId)?.vaultId == targetVaultId

    /** Whether a change of this device to [itemId] has not reached the server: queued, or refused and not yet said. */
    private fun changeWaitingHere(itemId: String): Boolean =
        store.pending().any { it.itemId == itemId } || store.stagedDenied().any { it.itemId == itemId }

    /** Drop [itemId]'s live row after a delete this device pushed itself, keeping its envelope for the trash's row. */
    private fun deleteKeepingEnvelope(itemId: String) = store.atomically {
        store.envelopes().firstOrNull { it.itemId == itemId }?.let { store.keepTrashed(listOf(it)) }
        store.deleteItem(itemId)
    }

    /**
     * Run [plan]: the COPY leg first (attachments re-encrypted under fresh keys), a POSITIVE `applied` or `conflict`
     * for it, and only then, for a move, the delete of the SOURCE at the rev that was copied. Both legs are pushed
     * directly, never queued: each gate reads its own leg's result. Idempotent per plan.
     *
     * Copying OUT of a vault that is frozen, failed or withheld is allowed (design §3.6); a move out of one is not,
     * and nothing is ever copied INTO one.
     */
    suspend fun runMove(plan: MovePlan, onProgress: ((done: Int, total: Int) -> Unit)? = null, finalSync: Boolean = true): ItemResult<Unit> = guard {
        live()
        val src = store.getItem(plan.sourceItemId) ?: refuse(ItemRefusal.ITEM_GONE)
        if (src.vaultId != plan.sourceVaultId) refuse(ItemRefusal.ITEM_CHANGED_VAULTS)
        requireWritable(plan.targetVaultId)
        if (plan.deleteSource) requireWritable(plan.sourceVaultId)
        copyLeg(src, plan, onProgress, skipUnreadableFiles = false)

        if (plan.deleteSource) {
            // A lock during the copy leaves the source where it is; the kept move finishes it after the unlock.
            live()
            val del = transport.push(listOf(Mutation(codec.derivedId("gesture|${plan.planId}|delete"), MutationOp.DELETE, plan.sourceItemId, plan.sourceVaultId, plan.sourceRev, null)))
                .orStop().results.firstOrNull()
            when (del?.status) {
                MutationStatus.CONFLICT -> {
                    // The source changed meanwhile: resync so the newer source shows; nothing was deleted.
                    try {
                        syncMutex.withLock { cycle() }
                    } catch (_: Stop) {
                        // The item-changed verdict stays the answer; the next sync reports anything else again.
                    }
                    refuse(ItemRefusal.ITEM_CHANGED)
                }
                MutationStatus.DENIED -> refuse(ItemRefusal.SOURCE_DELETE_DENIED)
                // The source's envelope is kept, so its trash row opens with its name and no call.
                else -> deleteKeepingEnvelope(plan.sourceItemId)
            }
        }
        if (finalSync) reconcile()
    }

    /**
     * Copy every item of [vaultId] into the personal vault: the rescue step before a delete, and the way out of a
     * vault that is no longer verified. Copy legs only; the originals are never deleted. Each copy gets a fresh item id
     * ([personalCopyPlan]): a retry after a failure reuses the plans of the copies not yet confirmed, and a run after a
     * lock or a restart copies everything again. Answers how many were copied.
     */
    suspend fun rescueToPersonal(vaultId: String, onProgress: ((done: Int, total: Int) -> Unit)? = null): ItemResult<Int> = guard {
        live()
        val personal = personalOrStop()
        val sources = store.allItems().filter { it.vaultId == vaultId }
        var copied = 0
        for (it in sources) {
            val key = "$vaultId|${it.itemId}|$personal"
            val plan = personalCopyPlan(key, it, personal) {
                when (val p = planMove(it.itemId, personal, deleteSource = false)) {
                    is ItemResult.Ok -> p.value
                    is ItemResult.Failed -> throw Stop(p.why)
                }
            }
            when (val r = runMove(plan, finalSync = false)) {
                is ItemResult.Ok -> bulkPlans.remove(key) // confirmed: a later copy of this vault is a new copy
                is ItemResult.Failed -> throw Stop(r.why)
            }
            copied++
            onProgress?.invoke(copied, sources.size)
        }
        reconcile()
        copied
    }

    private fun isoDate(epochMillis: Long): String = kotlinx.datetime.Instant.fromEpochMilliseconds(epochMillis).toString().substring(0, 10)

    companion object {
        /** The server refuses a push batch larger than this (spec 03 §5). */
        const val SERVER_BATCH_MAX = 200

        /** The server's default limit for one file (`attachmentMaxBytes`), when no policy was read: [vaultSize]'s cap. */
        const val DEFAULT_FILE_MAX_BYTES = 25L * 1024 * 1024

        /**
         * [copySize]'s count, for any [docs] and with [codec]'s lengths (the pretend item plane counts with it too): with
         * [newVaultName], into a new shared vault of that name, whose `metaBlob` is [CopySize.metaBytes].
         */
        internal fun sizeOf(codec: ItemCodec, docs: List<ItemDoc>, fileMaxBytes: Long, newVaultName: String?): CopySize {
            val files = HashMap<String, Long>()
            for (doc in docs) for (a in doc.attachments) {
                val plain = minOf(a.size, fileMaxBytes)
                files[a.id] = if (plain <= 0 || plain > (1L shl 50)) 0L else Attachments.wireLength(plain) - Attachments.HEADER_BYTES
            }
            val sealed = docs.fold(0L) { sum, doc -> QuotaCheck.saturatedSum(sum, codec.sealedLength(doc)) }
            val declared = files.values.fold(0L, QuotaCheck::saturatedSum)
            val bytes = QuotaCheck.saturatedSum(sealed, declared)
            return CopySize(bytes, docs.size.toLong(), newVaultName != null, newVaultName?.let { codec.metaLength(it) } ?: 0L, declaredBytes = minOf(declared, bytes))
        }

        /**
         * The most pages of the deleted-items list one read asks for: 16 full pages are 1,048,576 deleted items, far
         * past any real trash (the server keeps deleted items 30 days), and bound what a server that never ends its list
         * can make a device fetch (each page is also capped at 8 MiB).
         */
        const val TRASH_MAX_PAGES = 16

        /** The most rows this device never held that one opening of the trash reads (one call each), newest first. */
        const val TRASH_FETCH_MAX = 20

        /** Below the server's 8 MiB body cap: a batch is bounded by approximate encoded size as well as by count. */
        const val PUSH_BODY_SOFT_CAP_BYTES = 6L * 1024 * 1024

        /** How long a departed vault's copy stays in the holding area (spec 02 §10.6). */
        const val HOLDING_MS = 30L * 86_400_000L

        /** At most this many item-carried log heads per vault are reported per pull (the highest). */
        const val MAX_HEAD_HINTS = 4

        /** The name shown when a vault's own name is unavailable; a vault NAMED this is relabelled Personal or Shared. */
        const val VAULT_NAME_FALLBACK = "(vault)"

        /** [CoreLog] event: the engine started on an origin whose pin is forked, damaged or gone. */
        const val EVENT_HALTED = "item_engine_halted"
    }
}

/**
 * The offline cache's namespace (spec 02 §8): one cache per origin and account, so two accounts, or one account at two
 * servers, never share rows, a queue or item homes. Hosts name the cache file with [fileName].
 */
object ItemCacheNames {
    fun fileName(crypto: CryptoProvider, origin: String, userId: String): String = "vault-" + namespace(crypto, origin, userId) + ".db"

    /**
     * Every file name the cache of [userId] at [origin] may occupy: the database and the files SQLite keeps beside it
     * (a write-ahead log or a rollback journal can hold rows of the database, so they go with it).
     */
    fun files(crypto: CryptoProvider, origin: String, userId: String): List<String> {
        val db = fileName(crypto, origin, userId)
        return listOf(db, "$db-wal", "$db-shm", "$db-journal")
    }

    /**
     * Delete the cache of [userId] at [origin], for one of the person's own acts ([why]: sign-out, a forgotten server,
     * account deletion, a policy that forbids an offline copy). Never for a session the server ended: that copy stays
     * (design §4.4), and [CopyDeletion] has no value for it. [remove] deletes one file by name and answers true when it
     * is gone or was never there. Every file is tried even when one fails, and a throw counts as a failure. True when
     * nothing is left. The engine over that cache is closed first ([ItemEngine.close]). A followed move carries the
     * cache instead ([carry]).
     */
    @Suppress("UNUSED_PARAMETER")
    fun delete(crypto: CryptoProvider, origin: String, userId: String, why: CopyDeletion, remove: (fileName: String) -> Boolean): Boolean =
        files(crypto, origin, userId).map { runCatching { remove(it) }.getOrDefault(false) }.all { it }

    /**
     * A followed move from [from] to [to] (design §4.4): the cache of [userId] goes with it, so the changes it holds
     * that were not yet sent are sent from the new address. A move is not a deletion ([CopyDeletion] has no value
     * for it). [rename] moves one file from the first name to the second and answers true when it moved or the first
     * was never there; it must never replace a file already at the second name (answer false then). Every file is
     * tried; true when all of them are at the new names. The engine over the old cache is closed first. On false, the
     * host keeps what is left under the old names and tries again (the old names are still the account's), never
     * deletes it.
     */
    fun carry(crypto: CryptoProvider, from: String, to: String, userId: String, rename: (from: String, to: String) -> Boolean): Boolean =
        files(crypto, from, userId).zip(files(crypto, to, userId)).map { (a, b) -> runCatching { rename(a, b) }.getOrDefault(false) }.all { it }

    /** The prefix of the content's kept records for [userId] at [origin] ([io.silencelen.andvari.core.app.content.ContentStores]). */
    fun keptPrefix(crypto: CryptoProvider, origin: String, userId: String): String = "kept-" + namespace(crypto, origin, userId)

    private fun namespace(crypto: CryptoProvider, origin: String, userId: String): String =
        Bytes.toHexLower(crypto.sha256("$origin|$userId".encodeToByteArray())).take(32)
}
