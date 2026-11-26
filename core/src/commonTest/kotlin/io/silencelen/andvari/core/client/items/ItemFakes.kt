package io.silencelen.andvari.core.client.items

import io.silencelen.andvari.core.client.CsvImport
import io.silencelen.andvari.core.client.InMemoryVaultCache
import io.silencelen.andvari.core.client.ItemDoc
import io.silencelen.andvari.core.client.LoginData
import io.silencelen.andvari.core.client.VaultCache
import io.silencelen.andvari.core.client.net.NoAnswerKind
import io.silencelen.andvari.core.client.net.WireResult
import io.silencelen.andvari.core.crypto.Bytes
import io.silencelen.andvari.core.crypto.CryptoProvider
import io.silencelen.andvari.core.crypto.createCryptoProvider
import io.silencelen.andvari.core.model.wire.AttachmentMeta
import io.silencelen.andvari.core.model.wire.DeletedItem
import io.silencelen.andvari.core.model.wire.ItemUpload
import io.silencelen.andvari.core.model.wire.ItemVersion
import io.silencelen.andvari.core.model.wire.Mutation
import io.silencelen.andvari.core.model.wire.MutationResult
import io.silencelen.andvari.core.model.wire.PushResponse
import io.silencelen.andvari.core.model.wire.SyncGrant
import io.silencelen.andvari.core.model.wire.SyncItem
import io.silencelen.andvari.core.model.wire.SyncLogHead
import io.silencelen.andvari.core.model.wire.SyncResponse
import io.silencelen.andvari.core.model.wire.SyncVault
import io.silencelen.andvari.core.model.wire.WireError
import kotlinx.coroutines.runBlocking

/**
 * A scripted server behind [ItemTransport]: a queue of pull answers, a push graded the way the real server grades it
 * (a GLOBAL rev; a put conflicts when its base is below the stored row's rev, spec 03 §5), and the refusal switches the
 * drain tests need. It records everything the engine sent.
 */
class FakeItemServer : ItemTransport {
    val queue = ArrayDeque<SyncResponse>()
    val pushes = mutableListOf<List<Mutation>>()
    val pullsSince = mutableListOf<Long>()
    val syncs: Int get() = pullsSince.size
    var rev = 1L

    /** Every call answers "no answer" while true. */
    var offline = false

    /** Answer the next push, then go offline (the reconcile pull gets no answer). */
    var offlineAfterNextPush = false

    /** Per-row `rejected`: itemId → reason. */
    val rejectItems = mutableMapOf<String, String>()

    /** Per-row `denied`: every mutation into these vaults. */
    val denyVaults = mutableSetOf<String>()

    /** A batch containing any of these itemIds is refused WHOLE with `400`. */
    val refuseBatchIfContains = mutableSetOf<String>()

    /** A push whose approximate body is over this many bytes is refused with `413 body_too_large`. */
    var refuseBodyOverBytes: Long? = null

    /** Answer every push with this status and code (a `429` or a `503` in the envelope: transient, never a verdict). */
    var refuseWith: Pair<Int, String>? = null

    /** The next pull answers `410 resync_required` once. */
    var goneOnce = false

    /** Push results leave stored items out (`serverItemOmitted`, spec 03 §5), as the server does past its answer cap. */
    var omitServerItems = false

    /** With nothing queued, a pull answers every stored row newer than its cursor, as the real server does. */
    var echo = false

    /**
     * Whether a row a put brings back from a deletion is stored with the conflict mark, as an older server stored it
     * (true, the default these tests were written against); the server since 2026-11-18 stores it without the mark.
     */
    var marksBroughtBack = true

    var onUpload: (() -> Unit)? = null
    val itemRows = mutableMapOf<String, SyncItem>()
    val versions = mutableMapOf<String, MutableList<ItemVersion>>()
    val attachments = mutableMapOf<String, ByteArray>()
    val restored = mutableListOf<Pair<String, ItemUpload>>()
    val purged = mutableListOf<String>()
    val metaPuts = mutableListOf<Triple<String, String, Long?>>()
    var calls = 0

    fun applied(): Set<String> = pushes.flatten().map { it.itemId }.filter { it !in rejectItems && it !in refuseBatchIfContains }.toSet()

    private fun <T> down(): WireResult<T> = WireResult.NoAnswer(NoAnswerKind.TRANSPORT)
    private fun refused(status: Int, code: String) = WireResult.Refused(status, WireError(code, code))

    /**
     * When set, a mutation id already applied is answered from a journal, as the real server does (spec 03 §5 dedup):
     * the first answer again, nothing applied twice.
     */
    var journal = false
    private val answered = mutableMapOf<String, MutationResult>()

    private fun applyMutation(m: Mutation): MutationResult {
        if (journal) answered[m.mutationId]?.let { return it }
        return applyFresh(m).also { if (journal) answered[m.mutationId] = it }
    }

    private fun applyFresh(m: Mutation): MutationResult {
        if (m.vaultId in denyVaults) return MutationResult(m.mutationId, "denied")
        val existing = itemRows[m.itemId]
        val newRev = ++rev
        if (m.op == "delete") {
            if (existing == null || existing.deleted) return MutationResult(m.mutationId, "applied")
            if (m.baseItemRev < existing.rev) return MutationResult(m.mutationId, "conflict", existing.rev, serverItem = existing)
            existing.blob?.let { versions.getOrPut(m.itemId) { ArrayList() }.add(0, ItemVersion(existing.rev, it, existing.formatVersion, newRev)) }
            itemRows[m.itemId] = existing.copy(rev = newRev, deleted = true, blob = null, attachmentIds = emptyList())
            return MutationResult(m.mutationId, "applied", newRev)
        }
        val up = m.item ?: return MutationResult(m.mutationId, "applied", newRev)
        val conflict = existing != null && (m.baseItemRev < existing.rev || existing.deleted)
        existing?.blob?.let { versions.getOrPut(m.itemId) { ArrayList() }.add(0, ItemVersion(existing.rev, it, existing.formatVersion, newRev)) }
        // A put over a deletion is answered with the deletion's mark; the row it brings back is marked only by an older server.
        val marked = conflict && (existing?.deleted != true || marksBroughtBack)
        itemRows[m.itemId] = SyncItem(m.itemId, m.vaultId, newRev, existing?.createdAt ?: 0, newRev, false, marked, up.formatVersion, up.attachmentIds, up.blob)
        return if (conflict) MutationResult(m.mutationId, "conflict", newRev, serverItem = existing) else MutationResult(m.mutationId, "applied", newRev)
    }

    /** When set, a pull says it has begun ([pullEntered]) and waits for [pullRelease] before it answers. */
    var pullEntered: kotlinx.coroutines.CompletableDeferred<Unit>? = null
    var pullRelease: kotlinx.coroutines.CompletableDeferred<Unit>? = null

    /** Pushes into these vaults are answered with no per-mutation result at all (a malformed reply). */
    val emptyResultsVaults = mutableSetOf<String>()

    /**
     * Runs at the start of every call, with its route (`pull`, `push`, `versions`, `deletedVaults`, `deletedItems`,
     * `restore`, `purge`, `upload`, `download`, `hibp`, `meta`): a test holds a call here to land a lock in that wait.
     */
    var hold: (suspend (route: String) -> Unit)? = null

    private suspend fun called(route: String) {
        calls++
        hold?.invoke(route)
    }

    override suspend fun pull(since: Long): WireResult<SyncResponse> {
        called("pull")
        pullEntered?.let {
            pullEntered = null
            it.complete(Unit)
            pullRelease?.await()
            pullRelease = null
        }
        if (offline) return down()
        pullsSince += since
        if (goneOnce) {
            goneOnce = false
            return refused(410, "resync_required")
        }
        val resp = queue.removeFirstOrNull()
            ?: SyncResponse(rev, false, emptyList(), emptyList(), if (echo) itemRows.values.filter { it.rev > since } else emptyList(), emptyList(), emptyList(), 0, 0)
        rev = maxOf(rev, resp.rev)
        return WireResult.Ok(resp, 200)
    }

    /** When set, a push says it has begun ([pushEntered]) and waits for [pushRelease] before it is read. */
    var pushEntered: kotlinx.coroutines.CompletableDeferred<Unit>? = null
    var pushRelease: kotlinx.coroutines.CompletableDeferred<Unit>? = null

    override suspend fun push(mutations: List<Mutation>): WireResult<PushResponse> {
        called("push")
        pushEntered?.let {
            pushEntered = null
            it.complete(Unit)
            pushRelease?.await()
            pushRelease = null
        }
        if (offline) return down()
        refuseWith?.let { return refused(it.first, it.second) }
        val size = mutations.sumOf { (it.item?.blob?.length ?: 0) + 200L }
        refuseBodyOverBytes?.let { if (size > it) return refused(413, "body_too_large") }
        if (mutations.any { it.itemId in refuseBatchIfContains }) return refused(400, "unknown_attachment")
        pushes.add(mutations)
        if (offlineAfterNextPush) {
            offlineAfterNextPush = false
            offline = true
        }
        if (mutations.any { it.vaultId in emptyResultsVaults }) return WireResult.Ok(PushResponse(rev, emptyList()), 200)
        val results = mutations.map { m ->
            val reason = rejectItems[m.itemId] ?: m.item?.attachmentIds?.takeIf { checkAttachmentRefs }?.firstOrNull { it !in attachments }?.let { "unknown_attachment" }
            reason?.let { MutationResult(m.mutationId, "rejected", reason = it) } ?: applyMutation(m)
        }
            .map { if (omitServerItems && it.serverItem != null) it.copy(serverItem = null, serverItemOmitted = true) else it }
        return WireResult.Ok(PushResponse(rev, results), 200)
    }

    val versionsRead = mutableListOf<String>()

    override suspend fun versions(itemId: String): WireResult<List<ItemVersion>> {
        called("versions")
        versionsRead += itemId
        return if (offline) down() else WireResult.Ok(versions[itemId] ?: emptyList(), 200)
    }

    /** What `GET /vaults/deleted` serves. */
    val deletedVaultRows = ArrayList<io.silencelen.andvari.core.model.wire.DeletedVaultSummary>()

    override suspend fun deletedVaults(): WireResult<List<io.silencelen.andvari.core.model.wire.DeletedVaultSummary>> {
        called("deletedVaults")
        return if (offline) down() else WireResult.Ok(deletedVaultRows.toList(), 200)
    }

    /** The `after` of every deleted-items page asked for, in order (null: the first page). */
    val trashAfters = mutableListOf<String?>()

    /** When set, answers every deleted-items page instead of the stored rows: a test's scripted (or lying) server. */
    var trashPages: ((after: String?) -> WireResult<List<DeletedItem>>)? = null

    override suspend fun deletedItems(after: String?): WireResult<List<DeletedItem>> {
        called("deletedItems")
        trashAfters += after
        if (offline) return down()
        trashPages?.let { return it(after) }
        // The real server's page: newest first in (deletedAt, itemId) descending order, after the cursor's row.
        val cursor = after?.let { it.substringBefore(':').toLong() to it.substringAfter(':') }
        val rows = itemRows.values.filter { it.deleted }.map { DeletedItem(it.itemId, it.vaultId, it.updatedAt) }
            .sortedWith(compareByDescending<DeletedItem> { it.deletedAt }.thenByDescending { it.itemId })
            .filter { cursor == null || it.deletedAt < cursor.first || (it.deletedAt == cursor.first && it.itemId < cursor.second) }
        return WireResult.Ok(rows.take(ItemTransport.TRASH_PAGE_ROWS), 200)
    }

    /** The server answers a restore and a purge as done and stores nothing: the trash still lists the item. */
    var trashActionsStoreNothing = false

    override suspend fun restore(itemId: String, item: ItemUpload): WireResult<Long> {
        called("restore")
        if (offline) return down()
        restored += itemId to item
        if (trashActionsStoreNothing) return WireResult.Ok(rev, 200)
        val old = itemRows[itemId] ?: return refused(403, "no_grant")
        itemRows[itemId] = old.copy(rev = ++rev, deleted = false, formatVersion = item.formatVersion, attachmentIds = item.attachmentIds, blob = item.blob)
        return WireResult.Ok(rev, 200)
    }

    override suspend fun purge(itemId: String): WireResult<Long> {
        called("purge")
        if (offline) return down()
        purged += itemId
        if (trashActionsStoreNothing) return WireResult.Ok(rev, 200)
        itemRows.remove(itemId)
        return WireResult.Ok(++rev, 200)
    }

    /**
     * When set, a put that names a file the server does not hold is rejected `unknown_attachment` for its row, as the
     * real server does (`Items.attachmentRefReason`).
     */
    var checkAttachmentRefs = false

    /** The server's clock, for when each upload landed ([sweepOrphans]); the rig drives it. */
    var clock: () -> Long = { 0L }
    val uploadedAt = mutableMapOf<String, Long>()

    /** Every upload that landed, in order (an upload sent again is listed again). */
    val uploads = mutableListOf<String>()

    /** Every upload the server was asked for and did not refuse at its door, in order. */
    val uploadsTried = mutableListOf<String>()

    companion object {
        /** The real server keeps an upload no item names for a day (`AttachmentStore.orphanTtlMs`). */
        const val ORPHAN_TTL_MS = 24L * 60 * 60 * 1000
    }

    /**
     * The real server's sweep (`AttachmentStore.sweepOrphans`, hourly): an upload older than a day that no live item
     * names is removed. Answers the ids removed.
     */
    fun sweepOrphans(): List<String> {
        val named = itemRows.values.filter { !it.deleted }.flatMapTo(HashSet()) { it.attachmentIds }
        val gone = attachments.keys.filter { it !in named && (uploadedAt[it] ?: 0L) < clock() - ORPHAN_TTL_MS }
        gone.forEach {
            attachments.remove(it)
            uploadedAt.remove(it)
        }
        return gone
    }

    /** Answer every upload with this status and code (a `401`: the server ended the session; a `403`: a refusal for good). */
    var uploadRefuseWith: Pair<Int, String>? = null

    override suspend fun uploadAttachment(attachmentId: String, itemId: String, vaultId: String, body: ByteArray): WireResult<AttachmentMeta> {
        called("upload")
        if (offline) return down()
        uploadRefuseWith?.let { return refused(it.first, it.second) }
        onUpload?.invoke()
        uploadsTried += attachmentId
        if (attachments.containsKey(attachmentId) && !attachments.getValue(attachmentId).contentEquals(body)) return refused(400, "attachment_id_taken")
        if (!attachments.containsKey(attachmentId)) uploadedAt[attachmentId] = clock()
        attachments[attachmentId] = body
        uploads += attachmentId
        return WireResult.Ok(AttachmentMeta(attachmentId, itemId, vaultId, body.size.toLong(), "00", 0), 200)
    }

    override suspend fun downloadAttachment(attachmentId: String, expectedBytes: Long): WireResult<ByteArray> {
        called("download")
        if (offline) return down()
        val body = attachments[attachmentId] ?: return refused(403, "no_grant")
        return if (body.size.toLong() != expectedBytes) refused(0, ItemTransport.ATTACHMENT_SIZE_MISMATCH) else WireResult.Ok(body, 200)
    }

    /** The relay's answers by prefix; a prefix not here answers an empty range. */
    val ranges = mutableMapOf<String, String>()
    val rangePrefixes = mutableListOf<String>()

    override suspend fun hibpRange(prefix: String): WireResult<String> {
        called("hibp")
        if (offline) return down()
        rangePrefixes += prefix
        return WireResult.Ok(ranges[prefix] ?: "", 200)
    }

    override suspend fun putVaultMeta(vaultId: String, metaBlob: String, baseVaultRev: Long?): WireResult<Long> {
        called("meta")
        if (offline) return down()
        metaPuts += Triple(vaultId, metaBlob, baseVaultRev)
        return WireResult.Ok(++rev, 200)
    }
}

/** A [VaultKeySource] a test sets by hand: which vaults are open, with which key, role and standing. */
class FakeKeys(override var personalVaultId: String?) : VaultKeySource {
    class Entry(val key: ByteArray, var role: String, var standing: VaultStanding, var head: LogHeadStamp? = null)

    val open = HashMap<String, Entry>()

    /** Vaults that left for a verified reason; their key may stay on offer in [heldKeys]. */
    val departed = HashMap<String, VaultDeparture>()
    val heldKeys = HashMap<String, ByteArray>()
    val reports = ArrayList<ServedVaults>()
    val heads = ArrayList<Triple<String, Long, String>>()
    var reopened = 0

    /** Runs inside [served], before the engine applies the pull: what the trust engine would conclude from it. */
    var onServed: ((ServedVaults) -> Unit)? = null

    /** Every call the engine made, in order: `served`, `key:<vaultId>`, `head:<vaultId>`. */
    val trail = ArrayList<String>()

    /** False once the account locked: the guard's keys are erased (spec 01 §8 rule 2). */
    var locked = false
    override val keysLive: Boolean get() = !locked

    fun put(vaultId: String, key: ByteArray, role: String = VaultAccess.ROLE_OWNER, standing: VaultStanding = VaultStanding.VERIFIED, head: LogHeadStamp? = null) {
        open[vaultId] = Entry(key, role, standing, head)
        departed.remove(vaultId)
    }

    fun depart(vaultId: String, why: VaultDeparture, keepKey: Boolean = true) {
        open.remove(vaultId)?.let { if (keepKey) heldKeys[vaultId] = it.key }
        departed[vaultId] = why
    }

    override fun access(vaultId: String): VaultAccess? = open[vaultId]?.let { VaultAccess(vaultId, vaultId == personalVaultId, it.role, it.standing) }
    override fun <T> withKey(vaultId: String, block: (ByteArray) -> T): T? {
        trail += "key:$vaultId"
        return (open[vaultId]?.key ?: heldKeys[vaultId])?.copyOf()?.let { k -> try { block(k) } finally { k.fill(0) } }
    }
    override fun departure(vaultId: String): VaultDeparture? = departed[vaultId]
    override fun logHead(vaultId: String): LogHeadStamp? = open[vaultId]?.takeIf { it.standing == VaultStanding.VERIFIED }?.head
    override suspend fun served(report: ServedVaults) {
        trail += "served"
        reports += report
        onServed?.invoke(report)
    }
    override suspend fun reopen(vaults: List<SyncVault>, grants: List<SyncGrant>) { reopened++ }
    override suspend fun itemHead(vaultId: String, seq: Long, hash: String) {
        trail += "head:$vaultId"
        heads += Triple(vaultId, seq, hash)
    }
}

/** An [OriginGate] a test sets by hand: the pin's state, and what the next look at the card chain finds. */
class FakeGate : OriginGate {
    /** The pin is forked (or damaged, or gone). */
    var forked = false

    /** The served card chain forks: the next [judge] finds it and marks the pin. */
    var forkOnJudge = false
    var judged = 0

    /** Runs at each [judge], before it answers. */
    var onJudge: (() -> Unit)? = null

    override fun stopped(): Boolean = forked
    override suspend fun judge(): Boolean {
        judged++
        onJudge?.invoke()
        if (forkOnJudge) forked = true
        return forked
    }
}

/**
 * One account's engine over a [FakeItemServer] and [FakeKeys], past its first pull (cursor 5) with its personal vault.
 * With [trust], the engine reads every key from the key source it builds instead ([TrustBed]: the real trust engine);
 * [keys] is then not the engine's.
 */
class ItemRig(val cache: VaultCache = InMemoryVaultCache(), firstPull: Boolean = true, trust: ((ItemRig) -> VaultKeySource)? = null) {
    val crypto: CryptoProvider = createCryptoProvider()
    val codec = ItemCodec(crypto)
    val userId = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"
    val personal = "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb"
    val shared = "cccccccc-cccc-4ccc-8ccc-cccccccccccc"
    val personalKey = ByteArray(32) { 7 }
    val sharedKey = ByteArray(32) { 9 }
    val server = FakeItemServer()
    val keys = FakeKeys(personal).also { it.put(personal, personalKey) }
    var now = 1_763_164_800_000L
    val gate = FakeGate()

    /** The key source the engine reads: [keys], or the one [trust] built. */
    val source: VaultKeySource = trust?.invoke(this) ?: keys
    val engine = ItemEngine(server, source, gate, cache, userId, crypto, { now })

    /** A second engine over the same cache, server, keys and gate: the app after a restart. */
    fun restarted(log: io.silencelen.andvari.core.client.CoreLog = io.silencelen.andvari.core.client.CoreLog.Silent) =
        ItemEngine(server, source, gate, cache, userId, crypto, { now }, log)
    val doc = ItemDoc(type = "login", name = "Router", login = LoginData(username = "admin", password = "hunter2"))

    init {
        server.clock = { now }
        if (firstPull) {
            server.queue.add(response(5, full = true, vaults = listOf(vaultRow(personal, personalKey, "personal", "Personal")), grants = listOf(personalGrant)))
            runBlocking { check(engine.sync() is ItemResult.Ok) }
        }
    }

    fun id(): String = Bytes.uuidV4FromBytes(crypto.randomBytes(16))

    fun response(
        rev: Long, full: Boolean = false, vaults: List<SyncVault> = emptyList(), grants: List<SyncGrant> = emptyList(),
        items: List<SyncItem> = emptyList(), removed: List<String> = emptyList(),
    ) = SyncResponse(rev, full, vaults, grants, items, removed, emptyList(), 0, 0)

    fun vaultRow(vaultId: String, key: ByteArray, type: String, name: String, rev: Long = 1, head: SyncLogHead? = null) =
        SyncVault(vaultId, type, rev, codec.sealVaultMeta(key, vaultId, name), 0, head)

    fun grantRow(vaultId: String, role: String = "writer") = SyncGrant(vaultId, userId, role, "", 1, "grant")

    /** The account's own grant of its personal vault, which every whole snapshot of the real server carries. */
    val personalGrant: SyncGrant get() = SyncGrant(personal, userId, "owner", "personal-wrap", 1)

    /** A served item row sealed under [key] as the server would hand it over. */
    fun itemRow(itemId: String, vaultId: String, key: ByteArray, d: ItemDoc = doc, rev: Long = 6, conflict: Boolean = false): SyncItem {
        val up = ItemCodec(crypto).seal(key, vaultId, itemId, d)
        return SyncItem(itemId, vaultId, rev, 0, rev, false, conflict, up.formatVersion, up.attachmentIds, up.blob)
    }

    fun tombstone(itemId: String, vaultId: String, rev: Long) = SyncItem(itemId, vaultId, rev, 0, rev, true, false, 1, emptyList(), null)

    /** Deliver [row] on the next pull and make it the server's stored row. */
    fun serve(row: SyncItem) {
        server.itemRows[row.itemId] = row
        server.queue.add(response(maxOf(server.rev, row.rev), items = listOf(row)))
    }

    /** Open the shared vault on this device and deliver its rows. */
    fun openShared(role: String = "writer", head: LogHeadStamp? = LogHeadStamp(3, "ab".repeat(32)), items: List<SyncItem> = emptyList()) {
        keys.put(shared, sharedKey, role, VaultStanding.VERIFIED, head)
        server.queue.add(response(server.rev + 1, vaults = listOf(vaultRow(shared, sharedKey, "shared", "Family")), grants = listOf(grantRow(shared, role)), items = items))
        runBlocking { check(engine.sync() is ItemResult.Ok) }
    }

    fun planned(name: String, noteBytes: Int = 0) =
        CsvImport.PlannedItem(id(), if (noteBytes > 0) doc.copy(name = name, notes = "x".repeat(noteBytes)) else doc.copy(name = name))

    /** The plaintext name a pushed put carries. */
    fun pushedDoc(m: Mutation, key: ByteArray = personalKey): ItemDoc {
        val up = m.item!!
        return codec.open(key, SyncItem(m.itemId, m.vaultId, 0, 0, 0, false, false, up.formatVersion, up.attachmentIds, up.blob))
    }
}

fun <T> ItemResult<T>.ok(): T = when (this) {
    is ItemResult.Ok -> value
    is ItemResult.Failed -> throw AssertionError("expected Ok, got $why")
}

fun <T> ItemResult<T>.failure(): ItemFailure = when (this) {
    is ItemResult.Ok -> throw AssertionError("expected a failure, got $value")
    is ItemResult.Failed -> why
}
