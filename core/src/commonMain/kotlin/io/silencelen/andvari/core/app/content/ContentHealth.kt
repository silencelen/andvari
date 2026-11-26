package io.silencelen.andvari.core.app.content

import io.silencelen.andvari.core.app.ActionResult
import io.silencelen.andvari.core.app.BreachVerdicts
import io.silencelen.andvari.core.app.HealthCopy
import io.silencelen.andvari.core.app.HealthSession
import io.silencelen.andvari.core.app.HealthView
import io.silencelen.andvari.core.app.ScanProgressView
import io.silencelen.andvari.core.app.healthView
import io.silencelen.andvari.core.client.Duplicates
import io.silencelen.andvari.core.client.ItemDoc
import io.silencelen.andvari.core.client.Staleness
import io.silencelen.andvari.core.client.Strength
import io.silencelen.andvari.core.client.VaultItem
import io.silencelen.andvari.core.client.UsageLedger
import io.silencelen.andvari.core.client.VaultHealth
import io.silencelen.andvari.core.client.items.ItemResult
import io.silencelen.andvari.core.crypto.CryptoProvider
import io.silencelen.andvari.core.crypto.Hibp
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext

/**
 * Vault health for [ContentController] (design 2026-08-23), the old controller's flow over a [ContentSource]. Every
 * ranking, cluster, survivor and refusal is core's ([VaultHealth], [Duplicates], [Staleness]); this carries them to the
 * screen and writes only what they plan, each write an ordinary save or delete of the item in its own vault. A breach
 * check sends the server the first 5 hex characters of each distinct password's SHA-1 and nothing more; the match is
 * made here. The verdicts stay in memory, by item, for the life of this content (a lock forgets them).
 *
 * [roleFor] is the role this device may act with: a vault it cannot write counts as a reader's, so core's plans refuse
 * it. [save] and [remove] are the controller's item writes; each answers null or the sentence of its failure.
 */
internal class ContentHealth(
    private val source: ContentSource,
    private val crypto: CryptoProvider,
    private val host: ContentHost,
    private val roleFor: (String) -> String?,
    private val save: suspend (itemId: String, doc: ItemDoc) -> String?,
    private val remove: suspend (itemId: String) -> String?,
) {
    var health: HealthSession? = null
    private var breaches: BreachVerdicts? = null

    /** The usage ledger as last read ([readUsage]); null before the first read that worked. */
    private var usage: Map<String, UsageLedger.Entry>? = null

    /** Whether the ledger is worth reading after this sync: not yet read this unlock, or the Health screen is open. */
    val usageWanted: Boolean get() = host.usageLedger() != null && (usage == null || health != null)

    /**
     * Read the usage ledger (spec 02 §8.2) for "last used", after a completed sync (other devices record the uses). It
     * is a ranking hint: a ledger that cannot be fetched or opened leaves what was read before (none: nothing ranks by
     * use), and the screen says "not recorded" for those logins, as it does for a login never used.
     */
    suspend fun readUsage() {
        val ledger = host.usageLedger() ?: return
        val read = try {
            val sealed = ledger.fetchSealed()
            if (sealed == null) {
                emptyMap()
            } else {
                val plain = ledger.open(sealed)
                try {
                    UsageLedger.parse(plain.decodeToString())
                } finally {
                    plain.fill(0)
                }
            }
        } catch (c: CancellationException) {
            throw c
        } catch (e: Exception) {
            return
        }
        usage = read
        health?.usage = shownUsage()
    }

    /** The uses this content recorded this unlock, which the session may not have sent yet. */
    private var usedHere: Map<String, UsageLedger.Entry> = emptyMap()

    /** A use this content just recorded: Health shows it at once, before the session's batch reaches the ledger. */
    fun used(itemId: String, atMs: Long) {
        usedHere = UsageLedger.record(usedHere, itemId, atMs)
        health?.usage = shownUsage()
    }

    /** The ledger as read, with this unlock's own uses over it (both fields take the larger: [UsageLedger.merge]). */
    private fun shownUsage(): Map<String, UsageLedger.Entry> = UsageLedger.merge(usage.orEmpty(), usedHere)

    /** What [lines] last built, and from what: rebuilt only when the items, the waiting changes, the uses or the verdicts change. */
    private var linesKey: List<Any?>? = null
    private var linesBuilt: Map<String, ItemHealthLine> = emptyMap()

    /**
     * [VaultContent.itemHealth]: every login with a password, in one pass over what this device holds (core's
     * [VaultHealth] strength and reuse, the usage ledger as read, the breach verdicts of this unlock). No call is made.
     */
    fun lines(items: List<VaultItem>, pending: Set<String>): Map<String, ItemHealthLine> {
        val used = shownUsage()
        // Ids, revs and times only: nothing of a password is kept to tell whether it changed.
        val key = listOf(items.map { Triple(it.itemId, it.rev, it.updatedAt) }, pending, used, breaches)
        if (key == linesKey) return linesBuilt
        val fresh = breaches?.fresh(items, pending)
        val out = LinkedHashMap<String, ItemHealthLine>()
        for (r in VaultHealth.healthRows(items)) {
            out[r.itemId] = ItemHealthLine(r.itemId, Strength.label(r.strength), r.strength <= 1, r.reused, used[r.itemId]?.lastUsedAt, fresh?.get(r.itemId))
        }
        linesKey = key
        linesBuilt = out
        return out
    }

    private var agesKey: List<Any?>? = null
    private var agesBuilt: Map<String, LoginAgeLine> = emptyMap()

    /**
     * [VaultContent.loginAges]: every login, with or without a password, by core's [Staleness] rules (the current
     * app's staleness list, snoozed ones included and marked) and the usage ledger as read. No call is made. Rebuilt
     * when the items, the uses or the minute change: the clock decides how long ago a check was.
     */
    fun ages(items: List<VaultItem>): Map<String, LoginAgeLine> {
        val used = shownUsage()
        val now = host.wallMs()
        val key = listOf(items.map { Triple(it.itemId, it.rev, it.updatedAt) }, used, now / 60_000L)
        if (key == agesKey) return agesBuilt
        val rows = Staleness.stalenessRows(items, Staleness.StalenessOptions(lastUsedAt = { used[it]?.lastUsedAt }, now = now, includeSnoozed = true))
        val out = LinkedHashMap<String, LoginAgeLine>()
        for (r in rows) out[r.itemId] = LoginAgeLine(r.itemId, r.updatedAt, r.lastUsedAt, r.checkedAt, r.bucket, r.snoozed)
        agesKey = key
        agesBuilt = out
        return out
    }

    fun close() {
        health = null
        breaches = null
        usage = null
        usedHere = emptyMap()
        linesKey = null
        linesBuilt = emptyMap()
    }

    /** The open health screen as the vault is now; null when it is closed. A run whose login is gone ends. */
    fun view(): HealthView? {
        val h = health ?: return null
        val names = source.vaults().associate { it.vaultId to it.name }
        fun build() = healthView(h, source.items(), source.pendingSyncItemIds(), breaches, roleFor, { names[it] ?: "Shared" }, host.wallMs())
        val view = build()
        if (!h.running || view.run != null) return view
        h.queue = emptyList()
        h.index = 0
        return build()
    }

    fun open() {
        health = HealthSession().also { it.usage = shownUsage() }
    }

    suspend fun checkBreaches(published: () -> Unit, stillOpen: () -> Boolean): ActionResult {
        val h = health ?: return ActionResult.NotDone(null)
        if (h.scan != null) return ActionResult.NotDone(null)
        val items = source.items()
        val rows = VaultHealth.healthRows(items)
        if (rows.isEmpty()) return ActionResult.Ok
        // The revision each verdict is about, taken with the passwords: a sync during the check must not pair the two.
        val revs = items.associate { it.itemId to it.rev }
        val hashes = withContext(Dispatchers.Default) { rows.map { it.password }.distinct().associateWith { Hibp.sha1UpperHex(crypto, it) } }
        val byPrefix = hashes.entries.groupBy({ Hibp.prefix(it.value) }, { it.key })
        h.message = null
        h.scan = ScanProgressView(0, byPrefix.size)
        published()
        val counts = HashMap<String, Long>()
        var failed = 0
        var done = 0
        try {
            for ((prefix, passwords) in byPrefix) {
                val range = (source.breachRange(prefix) as? ItemResult.Ok)?.value
                if (!stillOpen() || health !== h) return ActionResult.NotDone(null)
                if (range == null) failed++ else for (pw in passwords) counts[pw] = Hibp.countInRange(range, hashes.getValue(pw))
                h.scan = ScanProgressView(++done, byPrefix.size)
                published()
            }
        } finally {
            h.scan = null
        }
        if (failed == byPrefix.size) {
            h.message = HealthCopy.SCAN_FAILED
        } else {
            val byItem = rows.mapNotNull { r -> counts[r.password]?.let { r.itemId to it } }.toMap()
            breaches = BreachVerdicts(byItem, byItem.keys.mapNotNull { id -> revs[id]?.let { id to it } }.toMap(), incomplete = failed > 0)
            h.message = if (failed > 0) HealthCopy.SCAN_INCOMPLETE else HealthCopy.scanDone(rows.count { (byItem[it.itemId] ?: 0L) > 0L })
        }
        return ActionResult.Ok
    }

    /** One health action: a refusal or failure is said on the health screen, where it was asked for. */
    suspend fun act(block: suspend (HealthSession) -> ActionResult): ActionResult {
        val h = health ?: return ActionResult.NotDone(null)
        val result = block(h)
        if (health === h && result is ActionResult.Failed) h.message = result.message
        return result
    }

    private fun clusterOf(signature: String): Duplicates.DuplicateCluster? =
        Duplicates.duplicateClusters(source.items(), roleFor).firstOrNull { it.signature == signature }

    /** Save the survivor core composed, then move the other copies to the trash; a failure after the survivor is partial. */
    private suspend fun runMerge(h: HealthSession, plan: Duplicates.MergePlan, success: (Int) -> String, partial: String): ActionResult {
        save(plan.survivorId, plan.doc)?.let { return ActionResult.Failed(it) }
        for (id in plan.loserIds) if (remove(id) != null) return ActionResult.Failed(partial)
        h.message = success(plan.loserIds.size)
        return ActionResult.Ok
    }

    suspend fun mergeDuplicates(signature: String): ActionResult = act { h ->
        val cluster = clusterOf(signature)
        val plan = cluster?.merge ?: return@act ActionResult.Failed(cluster?.mergeRefusal ?: HealthCopy.GROUP_CHANGED)
        runMerge(h, plan, HealthCopy::merged, HealthCopy.MERGE_DIDNT_FINISH)
    }

    suspend fun keepDuplicate(signature: String, keepId: String): ActionResult = act { h ->
        val cluster = clusterOf(signature) ?: return@act ActionResult.Failed(HealthCopy.GROUP_CHANGED)
        val plan = Duplicates.planKeep(source.items(), cluster.members.map { it.itemId }, keepId, roleFor, host.wallMs())
        val keep = plan.keep ?: return@act ActionResult.Failed(plan.keepRefusal ?: HealthCopy.GROUP_CHANGED)
        runMerge(h, keep, HealthCopy::kept, HealthCopy.KEEP_DIDNT_FINISH)
    }

    suspend fun acknowledgeCluster(signature: String, restoring: Boolean): ActionResult = act { h ->
        val cluster = clusterOf(signature) ?: return@act ActionResult.Failed(HealthCopy.GROUP_CHANGED)
        val plan = Duplicates.planDismiss(source.items(), cluster.members.map { it.itemId }, if (restoring) "" else cluster.signature, roleFor)
        val writes = plan.writes ?: return@act ActionResult.Failed(plan.dismissRefusal ?: HealthCopy.GROUP_CHANGED)
        var written = 0
        for (w in writes) {
            val failure = save(w.itemId, w.doc)
            // Nothing landed: the ordinary save failure is the honest sentence.
            if (failure != null) return@act ActionResult.Failed(if (written == 0) failure else HealthCopy.NOT_EVERY_COPY)
            written++
        }
        h.message = if (restoring) HealthCopy.BACK_ON_THE_LIST else HealthCopy.NOT_DUPLICATES
        ActionResult.Ok
    }

    fun beginRun(queue: List<String>) {
        val h = health ?: return
        if (queue.isEmpty()) return
        h.queue = queue
        h.index = 0
        h.message = null
        h.offerDelete = null
        h.offerBad = null
    }

    fun advanceRun(h: HealthSession) {
        val next = h.index + 1
        if (next < h.queue.size) {
            h.index = next
            return
        }
        h.queue = emptyList()
        h.index = 0
        h.message = HealthCopy.RUN_FINISHED
    }

    suspend fun recordCheck(itemId: String, result: String): ActionResult = act { h ->
        if (result !in HealthCopy.CHECK_RESULTS) return@act ActionResult.Failed(HealthCopy.CHOOSE_RESULT)
        val snooze = if (result == "blocked") Staleness.SNOOZE_MS else null
        val plan = Staleness.planCheck(source.items(), itemId, result, host.wallMs(), roleFor, snooze)
        val write = plan.write ?: return@act ActionResult.Failed(plan.refusal ?: HealthCopy.GROUP_CHANGED)
        h.message = null
        save(write.itemId, write.doc)?.let { return@act ActionResult.Failed(it) }
        h.offerDelete = if (result == "gone") itemId else null
        h.offerBad = if (result == "bad") itemId else null
        if (h.running && h.queue.getOrNull(h.index) == itemId) advanceRun(h)
        ActionResult.Ok
    }

    suspend fun unsnoozeLogin(itemId: String): ActionResult = act { h ->
        val plan = Staleness.planUnsnooze(source.items(), itemId, roleFor)
        val write = plan.write ?: return@act plan.refusal?.let { ActionResult.Failed(it) } ?: ActionResult.Ok
        save(write.itemId, write.doc)?.let { return@act ActionResult.Failed(it) }
        h.message = HealthCopy.BACK_ON_THE_LIST
        ActionResult.Ok
    }

    suspend fun trashGoneLogin(): ActionResult = act { h ->
        val itemId = h.offerDelete ?: return@act ActionResult.NotDone(null)
        remove(itemId)?.let { return@act ActionResult.Failed(it) }
        h.offerDelete = null
        h.message = HealthCopy.TRASHED
        ActionResult.Ok
    }
}
